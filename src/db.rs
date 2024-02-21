use crate::{
    fs::{FileBackend, StorageBackend},
    node::NodeInner,
    tx::{ReadTransaction, WriteTransaction},
    Configuration, Hash, NodeHasher, Sha256Hasher,
};
use bincode::{config, error::DecodeError, Decode, Encode};
use sha2::{Digest as _, Sha256};
use std::{
    fs::OpenOptions,
    io,
    sync::{Arc, Mutex},
};

const HEADER_MAGIC: [u8; 9] = [b's', b'p', b'a', b'c', b'e', b':', b'/', b'/', b'.'];
pub(crate) const PAGE_SIZE: usize = 4096;

#[derive(Debug, Encode, Decode, PartialEq, Eq)]
pub struct DatabaseHeader {
    pub magic: [u8; 9],
    pub version: u8,
    pub savepoint: SavePoint,
}

pub struct Database<H: NodeHasher> {
    pub(crate) header: Arc<Mutex<DatabaseHeader>>,
    pub(crate) file: Box<dyn StorageBackend>,
    pub config: Configuration<H>,
}

#[derive(Copy, Clone, Encode, Decode, Debug, Eq, PartialEq, Hash)]
pub struct SavePoint {
    pub root: Record,
    pub previous_save_point: Record,
}

#[derive(Copy, Clone, Encode, Decode, Debug, Eq, PartialEq, Hash)]
pub struct Record {
    pub offset: u64,
    pub size: u32,
}

pub const EMPTY_RECORD: Record = Record { offset: 0, size: 0 };

impl DatabaseHeader {
    pub fn new() -> Self {
        Self {
            magic: HEADER_MAGIC,
            version: 0,
            savepoint: SavePoint {
                root: EMPTY_RECORD,
                previous_save_point: EMPTY_RECORD,
            },
        }
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let config = config::standard()
            .with_fixed_int_encoding()
            .with_little_endian();
        let mut raw = bincode::encode_to_vec(self, config).unwrap();
        // add 24 bytes padding + 4 bytes checksum
        raw.extend_from_slice(&[0; 26]);
        let mut hasher = Sha256::new();
        hasher.update(&raw);
        let checksum = hasher.finalize();
        raw.extend_from_slice(&checksum[..4]);
        raw
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        // calc checksum
        let mut hasher = Sha256::new();
        hasher.update(&bytes[..60]);
        let checksum = hasher.finalize();

        if bytes[60..64] != checksum[..4] {
            return Err(DecodeError::Other("Checksum mismatch"));
        }

        let config = config::standard()
            .with_fixed_int_encoding()
            .with_little_endian();
        let (h, _) = bincode::decode_from_slice(bytes, config)?;

        Ok(h)
    }

    pub(crate) fn len(&self) -> u64 {
        if self.savepoint.is_empty() {
            return (PAGE_SIZE * 2) as u64;
        }

        let save_point_len = self.savepoint.len();
        return (save_point_len + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64 * PAGE_SIZE as u64;
    }
}

impl Database<Sha256Hasher> {
    pub fn open(path: &str) -> Result<Self, io::Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .unwrap();
        let config = Configuration::standard();
        Self::new(Box::new(FileBackend::new(file)?), config)
    }

    pub fn memory() -> Result<Self, io::Error> {
        let file = Box::new(crate::fs::MemoryBackend::new());
        let config = Configuration::standard();
        Self::new(file, config)
    }
}

impl<H: NodeHasher> Database<H> {
    pub fn new(file: Box<dyn StorageBackend>, config: Configuration<H>) -> Result<Self, io::Error> {
        let header;
        let mut has_header = false;

        if file.len()? > 0 {
            let result = Self::recover_header(&file)?;
            header = result.0;
            has_header = true;
        } else {
            header = DatabaseHeader::new();
            let bytes = header.to_bytes();
            file.set_len(bytes.len() as u64)?;
            file.write(0, &bytes)?;
            file.sync_data()?;
        }

        let db = Self {
            header: Arc::new(Mutex::new(header)),
            file,
            config,
        };

        if !has_header {
            db.write_header(&db.header.lock().unwrap())?;
        }

        Ok(db)
    }

    #[inline(always)]
    pub fn hash(&self, data: &[u8]) -> Hash {
        H::hash(data)
    }

    pub(crate) fn recover_header(
        file: &Box<dyn StorageBackend>,
    ) -> Result<(DatabaseHeader, bool), io::Error> {
        // Attempt to read from slot 0
        let bytes = file.read(0, 64)?;
        if let Ok(header) = DatabaseHeader::from_bytes(&bytes) {
            return Ok((header, false));
        }

        // Didn't work, try slot 1
        let bytes = file.read(PAGE_SIZE as u64, 64)?;
        let header = DatabaseHeader::from_bytes(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok((header, true))
    }

    pub(crate) fn write_header(&self, hdr: &DatabaseHeader) -> Result<(), io::Error> {
        // Database reserves first two pages for the metadata
        // The first page slot 0 contains the header
        // Second page slot 1 contains a backup of the header
        if self.file.len()? < PAGE_SIZE as u64 * 2 {
            self.file.set_len(PAGE_SIZE as u64 * 2)?;
        }

        let mut bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), 64);

        bytes.extend_from_slice(&[0; PAGE_SIZE - 64]);

        self.file.write(0, &bytes)?;
        self.file.sync_data()?;

        // write backup header
        self.file.write(PAGE_SIZE as u64, &bytes)?;
        self.file.sync_data()?;
        Ok(())
    }

    fn read_save_point(&self, record: Record) -> Result<SavePoint, io::Error> {
        let raw = self.file.read(record.offset, record.size as usize)?;
        let (save_point, _) = bincode::decode_from_slice(&raw, config::standard())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(save_point)
    }

    pub fn begin_write(&self) -> Result<WriteTransaction<H>, io::Error> {
        Ok(WriteTransaction::new(self))
    }

    pub fn begin_read(&self) -> Result<ReadTransaction<H>, io::Error> {
        let result = Self::recover_header(&self.file)?;
        // Use the stored configuration
        Ok(ReadTransaction::new(self, result.0.savepoint))
    }

    pub(crate) fn load_node(&self, id: Record) -> Result<NodeInner, io::Error> {
        let raw = self.file.read(id.offset, id.size as usize)?;
        let config = config::standard();
        let (inner, _): (NodeInner, usize) = bincode::decode_from_slice(&raw, config)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(inner)
    }

    pub fn iter(&self) -> SnapshotIterator<H> {
        SnapshotIterator::new(self)
    }
}

pub struct SnapshotIterator<'db, H: NodeHasher> {
    current: Option<SavePoint>,
    started: bool,
    db: &'db Database<H>,
}

impl<'db, H: NodeHasher> SnapshotIterator<'db, H> {
    pub fn new(db: &'db Database<H>) -> Self {
        SnapshotIterator {
            current: None,
            started: false,
            db,
        }
    }

    fn prev(&mut self) -> Result<Option<SavePoint>, io::Error> {
        if !self.started {
            let savepoint = Database::<H>::recover_header(&self.db.file)?.0.savepoint;
            self.current = if !savepoint.is_empty() {
                Some(savepoint)
            } else {
                None
            };
            self.started = true;
        }
        if self.current.is_none() {
            return Ok(None);
        }

        let savepoint = self.current.take().unwrap();
        if savepoint.is_empty() {
            return Ok(None);
        }
        if savepoint.is_initial() {
            return Ok(Some(savepoint));
        }
        self.current = Some(self.db.read_save_point(savepoint.previous_save_point)?);
        Ok(Some(savepoint))
    }
}

impl<'db, H: NodeHasher> Iterator for SnapshotIterator<'db, H> {
    type Item = Result<ReadTransaction<'db, H>, io::Error>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.prev() {
            Ok(Some(prev_savepoint)) => Some(Ok(ReadTransaction::new(self.db, prev_savepoint))),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

impl SavePoint {
    #[inline]
    pub fn is_initial(&self) -> bool {
        self.previous_save_point == EMPTY_RECORD
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.root == EMPTY_RECORD && self.previous_save_point == EMPTY_RECORD
    }

    #[inline]
    pub fn len(&self) -> u64 {
        return self.root.size as u64 + self.root.offset;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header() {
        let header = DatabaseHeader::new();
        let bytes = header.to_bytes();
        let header2 = DatabaseHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, header2);

        assert_eq!(bytes.len(), 64);
    }
}
