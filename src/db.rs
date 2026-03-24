use crate::{
    Result,
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
pub(crate) const CHUNK_SIZE: u64 = 4096;
pub(crate) const HEADER_SIZE: u64 = CHUNK_SIZE * 2;

#[derive(Debug, Encode, Decode, PartialEq, Eq)]
pub struct DatabaseHeader {
    pub(crate) magic: [u8; 9],
    pub(crate) version: u8,
    pub(crate) savepoint: SavePoint,
}

#[derive(Clone)]
pub struct Database<H: NodeHasher> {
    pub(crate) header: Arc<Mutex<DatabaseHeader>>,
    pub(crate) file: Arc<Box<dyn StorageBackend>>,
    pub config: Configuration<H>,
    pub(crate) path: Option<String>,
}

#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, Hash)]
pub struct SavePoint {
    pub(crate) root: Record,
    pub(crate) previous_savepoint: Record,
    pub(crate) metadata: Option<Vec<u8>>,
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
                previous_savepoint: EMPTY_RECORD,
                metadata: None,
            },
        }
    }

    pub(crate) fn serialize(&self) -> Vec<u8> {
        let config = config::standard()
            .with_fixed_int_encoding()
            .with_little_endian();

        let mut raw = bincode::encode_to_vec(self, config).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&raw);
        let checksum = hasher.finalize();
        raw.extend_from_slice(&checksum[..4]);
        raw
    }

    fn from_bytes(bytes: &[u8]) -> core::result::Result<Self, DecodeError> {
        let config = config::standard()
            .with_fixed_int_encoding()
            .with_little_endian();
        let (h, len) = bincode::decode_from_slice(bytes, config)?;

        // calc checksum
        let mut hasher = Sha256::new();
        hasher.update(&bytes[..len]);
        let expected = hasher.finalize();

        let actual = &bytes[len..len + 4];
        if &actual[..4] != &expected[..4] {
            return Err(DecodeError::Other("Checksum mismatch"));
        }

        Ok(h)
    }

    pub(crate) fn len(&self) -> u64 {

        let chunks_required = (self.savepoint.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
        std::cmp::max(chunks_required * CHUNK_SIZE, HEADER_SIZE)
    }
}

impl Database<Sha256Hasher> {
    pub fn open(path: &str) -> Result<Self> {
        Self::open_with_config(path, Configuration::standard())
    }

    pub fn open_with_config(path: &str, config: Configuration<Sha256Hasher>) -> Result<Self> {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true);

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_SHARE_READ: u32 = 0x00000001;
            opts.share_mode(FILE_SHARE_READ);
        }

        let file = opts.open(path).map_err(crate::Error::IO)?;
        let backend = FileBackend::new(file)?;
        let mut db = Self::new(Box::new(backend), config)?;
        db.path = Some(path.to_string());
        Ok(db)
    }

    pub fn open_read_only(path: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(crate::Error::IO)?;
        let config = Configuration::standard();
        let mut db = Self::new(Box::new(FileBackend::read_only(file)), config)?;
        db.path = Some(path.to_string());
        Ok(db)
    }

    pub fn memory() -> Result<Self> {
        let file = Box::new(crate::fs::MemoryBackend::new());
        let config = Configuration::standard();
        Self::new(file, config)
    }
}

impl<H: NodeHasher> Database<H> {
    pub fn new(file: Box<dyn StorageBackend>, config: Configuration<H>) -> Result<Self> {
        let header;
        let mut has_header = false;

        if file.len()? > 0 {
            let result = Self::recover_header(&file)?;
            header = result.0;
            has_header = true;
        } else {
            header = DatabaseHeader::new();
        }

        let db = Self {
            header: Arc::new(Mutex::new(header)),
            file: Arc::new(file),
            config,
            path: None,
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
    ) -> Result<(DatabaseHeader, bool)> {
        // Attempt to read from slot 0
        let mut offset = 0;
        let bytes = file.read(offset, CHUNK_SIZE as usize)?;
        if let Ok(header) = DatabaseHeader::from_bytes(&bytes) {
            return Ok((header, false));
        }

        // Didn't work, try backup
        offset = CHUNK_SIZE;
        let bytes = file.read(offset, CHUNK_SIZE as usize)?;
        let header = DatabaseHeader::from_bytes(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok((header, true))
    }

    pub(crate) fn write_header(&self, hdr: &DatabaseHeader) -> Result<()> {
        if self.file.len()? < HEADER_SIZE {
            self.file.set_len(HEADER_SIZE)?;
        }

        let bytes = hdr.serialize();
        assert!(bytes.len() <= CHUNK_SIZE as usize);

        self.file.write(0, &bytes)?;
        self.file.sync_data()?;

        // write backup header
        self.file.write(CHUNK_SIZE, &bytes)?;
        self.file.sync_data()?;
        Ok(())
    }

    fn read_save_point(&self, record: Record) -> Result<SavePoint> {
        let raw = self.file.read(record.offset, record.size as usize)?;
        let (save_point, _) = bincode::decode_from_slice(&raw, config::standard())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(save_point)
    }

    pub fn reset(&self) -> Result<()> {
        let mut header = self.header.lock().expect("acquire lock");
        *header = DatabaseHeader::new();
        self.write_header(&header)?;
        self.file.set_len(header.len())?;
        Self::cleanup_hash_indexes(&self.path, 0);
        Ok(())
    }

    /// Deletes hash index sidecar files whose root offset >= min_offset.
    /// Pass min_offset=0 to delete all index files.
    pub fn cleanup_hash_indexes(db_path: &Option<String>, min_offset: u64) {
        let db_path = match db_path {
            Some(p) => p,
            None => return,
        };
        let path = std::path::Path::new(db_path);
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => return,
        };
        let parent = path.parent().unwrap_or(std::path::Path::new("."));
        let prefix = format!("{}.", stem);
        let suffix = ".hidx.sqlite";

        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = match name.to_str() {
                    Some(s) => s,
                    None => continue,
                };
                if let Some(rest) = name_str.strip_prefix(&prefix) {
                    if let Some(offset_str) = rest.strip_suffix(suffix) {
                        if let Ok(offset) = offset_str.parse::<u64>() {
                            if offset >= min_offset {
                                let _ = std::fs::remove_file(entry.path());
                            }
                        }
                    }
                }
            }
        }
    }

    /// Keeps the `keep` most recent hash index files, deletes the rest.
    #[cfg(feature = "hash-idx")]
    pub fn prune_hash_indexes(&self, keep: usize) {
        let db_path = match &self.path {
            Some(p) => p,
            None => return,
        };
        let path = std::path::Path::new(db_path);
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => return,
        };
        let parent = path.parent().unwrap_or(std::path::Path::new("."));
        let prefix = format!("{}.", stem);
        let suffix = ".hidx.sqlite";

        let mut index_files: Vec<(u64, std::path::PathBuf)> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = match name.to_str() {
                    Some(s) => s,
                    None => continue,
                };
                if let Some(rest) = name_str.strip_prefix(&prefix) {
                    if let Some(offset_str) = rest.strip_suffix(suffix) {
                        if let Ok(offset) = offset_str.parse::<u64>() {
                            index_files.push((offset, entry.path()));
                        }
                    }
                }
            }
        }

        // Sort by offset descending (most recent first)
        index_files.sort_by(|a, b| b.0.cmp(&a.0));

        // Delete everything after the first `keep`
        for (_, path) in index_files.into_iter().skip(keep) {
            let _ = std::fs::remove_file(path);
        }
    }

    pub fn begin_write(&self) -> Result<WriteTransaction<'_, H>> {
        Ok(WriteTransaction::new(self))
    }

    pub fn begin_read(&self) -> Result<ReadTransaction<H>> {
        let (header, _) = Self::recover_header(&self.file)?;
        // Use the stored configuration
        Ok(ReadTransaction::new(self.clone(), header.savepoint))
    }

    pub(crate) fn load_node(&self, id: Record) -> Result<NodeInner> {
        let raw = self.file.read(id.offset, id.size as usize)?;
        let config = config::standard();
        let (inner, _): (NodeInner, usize) = bincode::decode_from_slice(&raw, config)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(inner)
    }

    pub fn iter(&self) -> SnapshotIterator<'_, H> {
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

    fn prev(&mut self) -> Result<Option<SavePoint>> {
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
        self.current = Some(self.db.read_save_point(savepoint.previous_savepoint)?);
        Ok(Some(savepoint))
    }
}

impl<'db, H: NodeHasher> Iterator for SnapshotIterator<'db, H> {
    type Item = Result<ReadTransaction<H>>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.prev() {
            Ok(Some(prev_savepoint)) => Some(Ok(ReadTransaction::new(self.db.clone(), prev_savepoint))),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

impl SavePoint {
    #[inline]
    pub fn is_initial(&self) -> bool {
        self.previous_savepoint == EMPTY_RECORD
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.root == EMPTY_RECORD && self.previous_savepoint == EMPTY_RECORD
    }

    #[inline]
    pub fn len(&self) -> u64 {
        let meta_size = match &self.metadata {
            None => 0,
            Some(m) =>  {
                bincode::encode_to_vec(m, config::standard()).unwrap().len()
            }
        } as u64;
        let root_size = self.root.offset + self.root.size as u64;
        let save_point_size = self.previous_savepoint.offset + self.previous_savepoint.size as u64;

        meta_size + std::cmp::max(root_size, save_point_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header() {
        let header = DatabaseHeader::new();
        let bytes = header.serialize();
        let header2 = DatabaseHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, header2);

        assert_eq!(bytes.len(), 39);
    }
}
