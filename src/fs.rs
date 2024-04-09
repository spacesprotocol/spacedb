// Uses flock on Unix and LockFile on Windows to ensure exclusive access to the database file.
// based on https://github.com/cberner/redb/tree/master/src/tree_store/page_store/file_backend
use crate::{
    db::{Record, SavePoint, EMPTY_RECORD, PAGE_SIZE},
    node::Node,
};
use bincode::config;
use std::{
    fs::File,
    io,
    ops::{Index, IndexMut, RangeFrom},
    sync::*,
};

pub trait StorageBackend {
    fn len(&self) -> Result<u64, io::Error>;
    fn set_len(&self, len: u64) -> Result<(), io::Error>;
    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, io::Error>;
    fn sync_data(&self) -> Result<(), io::Error>;
    fn write(&self, offset: u64, data: &[u8]) -> Result<(), io::Error>;
}

#[derive(Debug, Default)]
pub struct MemoryBackend(RwLock<Vec<u8>>);

#[cfg(any(unix))]
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

#[cfg(windows)]
use std::os::windows::{
    fs::FileExt,
    io::{AsRawHandle, RawHandle},
};

#[cfg(windows)]
const ERROR_LOCK_VIOLATION: i32 = 0x21;

#[cfg(windows)]
const ERROR_IO_PENDING: i32 = 997;

#[cfg(windows)]
extern "system" {
    /// <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfile>
    fn LockFile(
        file: RawHandle,
        offset_low: u32,
        offset_high: u32,
        length_low: u32,
        length_high: u32,
    ) -> i32;

    /// <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-unlockfile>
    fn UnlockFile(
        file: RawHandle,
        offset_low: u32,
        offset_high: u32,
        length_low: u32,
        length_high: u32,
    ) -> i32;
}

#[cfg(not(any(windows, unix)))]
use std::sync::Mutex;

#[cfg(any(windows, unix))]
pub struct FileBackend {
    file: File,
}

#[cfg(any(unix))]
impl FileBackend {
    pub fn new(file: File) -> Result<Self, io::Error> {
        let fd = file.as_raw_fd();
        let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Database already open",
                ))
            } else {
                Err(err.into())
            }
        } else {
            Ok(Self { file })
        }
    }
}

#[cfg(any(unix))]
impl Drop for FileBackend {
    fn drop(&mut self) {
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(any(unix))]
impl StorageBackend for FileBackend {
    fn len(&self) -> Result<u64, io::Error> {
        Ok(self.file.metadata()?.len())
    }

    fn set_len(&self, len: u64) -> Result<(), io::Error> {
        self.file.set_len(len)
    }

    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, io::Error> {
        let mut buffer = vec![0; len];
        self.file.read_exact_at(&mut buffer, offset)?;
        Ok(buffer)
    }

    fn sync_data(&self) -> Result<(), io::Error> {
        self.file.sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), io::Error> {
        self.file.write_all_at(data, offset)
    }
}

#[cfg(windows)]
impl FileBackend {
    pub fn new(file: File) -> Result<Self, DatabaseError> {
        let handle = file.as_raw_handle();
        unsafe {
            let result = LockFile(handle, 0, 0, u32::MAX, u32::MAX);

            if result == 0 {
                let err = io::Error::last_os_error();
                return if err.raw_os_error() == Some(ERROR_IO_PENDING)
                    || err.raw_os_error() == Some(ERROR_LOCK_VIOLATION)
                {
                    Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "Database already open",
                    ))
                } else {
                    Err(err.into())
                };
            }
        };

        Ok(Self { file })
    }
}

#[cfg(windows)]
impl Drop for FileBackend {
    fn drop(&mut self) {
        unsafe { UnlockFile(self.file.as_raw_handle(), 0, 0, u32::MAX, u32::MAX) };
    }
}

#[cfg(windows)]
impl StorageBackend for FileBackend {
    fn set_len(&self, len: u64) -> Result<(), io::Error> {
        self.file.set_len(len)
    }

    fn len(&self) -> Result<u64, io::Error> {
        Ok(self.file.metadata()?.len())
    }

    fn read(&self, mut offset: u64, len: usize) -> Result<Vec<u8>, io::Error> {
        let mut buffer = vec![0; len];
        let mut data_offset = 0;
        while data_offset < buffer.len() {
            let read = self.file.seek_read(&mut buffer[data_offset..], offset)?;
            offset += read as u64;
            data_offset += read;
        }
        Ok(buffer)
    }

    fn sync_data(&self) -> Result<(), io::Error> {
        self.file.sync_data()
    }

    fn write(&self, mut offset: u64, data: &[u8]) -> Result<(), io::Error> {
        let mut data_offset = 0;
        while data_offset < data.len() {
            let written = self.file.seek_write(&data[data_offset..], offset)?;
            offset += written as u64;
            data_offset += written;
        }
        Ok(())
    }
}

// We use a mutex based lock on platforms that don't support flock
#[cfg(not(any(windows, unix)))]
struct FileBackend {
    file: Mutex<File>,
}

#[cfg(not(any(windows, unix)))]
impl FileBackend {
    fn new(file: File) -> Result<Self, DatabaseError> {
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

#[cfg(not(any(windows, unix)))]
impl StorageBackend for FileBackend {
    fn set_len(&self, len: u64) -> Result<(), io::Error> {
        self.file.lock().unwrap().set_len(len)
    }

    fn len(&self) -> Result<u64, io::Error> {
        Ok(self.file.lock().unwrap().metadata()?.len())
    }

    fn sync_data(&self, eventual: bool) -> Result<(), io::Error> {
        self.file.lock().unwrap().sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), io::Error> {
        let file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)
    }

    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, io::Error> {
        let mut result = vec![0; len];
        let file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut result)?;
        Ok(result)
    }
}

impl MemoryBackend {
    fn out_of_range() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, "Index out-of-range.")
    }
}

impl MemoryBackend {
    /// Creates a new, empty memory backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// Gets a read guard for this backend.
    fn read(&self) -> RwLockReadGuard<'_, Vec<u8>> {
        self.0.read().expect("Could not acquire read lock.")
    }

    /// Gets a write guard for this backend.
    fn write(&self) -> RwLockWriteGuard<'_, Vec<u8>> {
        self.0.write().expect("Could not acquire write lock.")
    }
}

impl StorageBackend for MemoryBackend {
    fn len(&self) -> Result<u64, io::Error> {
        Ok(self.read().len() as u64)
    }

    fn set_len(&self, len: u64) -> Result<(), io::Error> {
        let mut guard = self.write();
        let len = usize::try_from(len).map_err(|_| Self::out_of_range())?;
        if guard.len() < len {
            let additional = len - guard.len();
            guard.reserve(additional);
            for _ in 0..additional {
                guard.push(0);
            }
        } else {
            guard.truncate(len);
        }

        Ok(())
    }

    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, io::Error> {
        let guard = self.read();
        let offset = usize::try_from(offset).map_err(|_| Self::out_of_range())?;
        if offset + len <= guard.len() {
            Ok(guard[offset..offset + len].to_owned())
        } else {
            Err(Self::out_of_range())
        }
    }

    fn sync_data(&self) -> Result<(), io::Error> {
        Ok(())
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), io::Error> {
        let mut guard = self.write();
        let offset = usize::try_from(offset).map_err(|_| Self::out_of_range())?;
        if offset + data.len() <= guard.len() {
            guard[offset..offset + data.len()].copy_from_slice(data);
            Ok(())
        } else {
            Err(Self::out_of_range())
        }
    }
}

pub struct WriteBuffer<'file, const SIZE: usize> {
    file: &'file Box<dyn StorageBackend>,
    buffer: Box<[u8; SIZE]>,
    len: usize,
    file_len: u64,
}

impl<'file, const SIZE: usize> WriteBuffer<'file, SIZE> {
    pub(crate) fn new(file: &'file Box<dyn StorageBackend>, file_len: u64) -> Self {
        Self {
            file,
            buffer: [0u8; SIZE].into(),
            len: 0,
            file_len,
        }
    }

    fn remaining(&self) -> usize {
        SIZE - self.len
    }

    fn tail(&mut self) -> &mut [u8] {
        &mut self.buffer[self.len..]
    }

    pub(crate) fn flush(&mut self) -> Result<(), io::Error> {
        if self.len == 0 {
            return Ok(());
        }

        let aligned_len = self.len - (self.len % PAGE_SIZE);

        // Write all full pages in one go, if any
        if aligned_len > 0 {
            self.file.set_len(self.file_len + aligned_len as u64)?;
            self.file
                .write(self.file_len, &self.buffer[0..aligned_len])?;
            self.file_len += aligned_len as u64;
        }

        // Handle the remaining data and pad to a full page
        if aligned_len < self.len {
            let remaining_len = self.len - aligned_len;
            self.buffer.copy_within(aligned_len..self.len, 0);
            self.buffer[remaining_len..PAGE_SIZE].fill(0);

            self.file.set_len(self.file_len + PAGE_SIZE as u64)?;
            self.file.write(self.file_len, &self.buffer[0..PAGE_SIZE])?;
            self.file_len += PAGE_SIZE as u64;
        }

        self.len = 0;
        Ok(())
    }

    pub fn write_save_point(&mut self, save_point: &SavePoint) -> Result<Record, io::Error> {
        let config = config::standard();
        let size =
            bincode::encode_into_slice(save_point, &mut self.tail(), config).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to encode save point: {}", e),
                )
            })?;
        let record = Record {
            offset: self.file_len + self.len as u64,
            size: size as u32,
        };

        self.len += size;
        Ok(record)
    }

    pub fn write_node(&mut self, node: &mut Node) -> Result<Record, io::Error> {
        if self.remaining() < node.mem_size() {
            self.flush()?;
        }

        let config = config::standard();

        if node.inner.is_none() {
            if node.id != EMPTY_RECORD {
                return Ok(node.id);
            }
            return Err(io::Error::new(io::ErrorKind::NotFound, "Node not found"));
        }

        let size = {
            let inner = node.inner.as_mut().unwrap();
            bincode::encode_into_slice(inner, &mut self.tail(), config).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to encode node: {}", e),
                )
            })?
        };

        let node_id = Record {
            offset: self.file_len + self.len as u64,
            size: size as u32,
        };

        self.len += size;
        Ok(node_id)
    }
}

impl<'file, const SIZE: usize> Index<usize> for WriteBuffer<'file, SIZE> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.buffer[index]
    }
}

impl<'file, const SIZE: usize> Index<std::ops::Range<usize>> for WriteBuffer<'file, SIZE> {
    type Output = [u8];

    fn index(&self, range: std::ops::Range<usize>) -> &Self::Output {
        &self.buffer[range]
    }
}

impl<'file, const SIZE: usize> IndexMut<usize> for WriteBuffer<'file, SIZE> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.buffer[index]
    }
}

impl<'file, const SIZE: usize> IndexMut<std::ops::Range<usize>> for WriteBuffer<'file, SIZE> {
    fn index_mut(&mut self, range: std::ops::Range<usize>) -> &mut Self::Output {
        &mut self.buffer[range]
    }
}

impl<'file, const SIZE: usize> Index<RangeFrom<usize>> for WriteBuffer<'file, SIZE> {
    type Output = [u8];

    fn index(&self, range: RangeFrom<usize>) -> &Self::Output {
        &self.buffer[range]
    }
}

impl<'file, const SIZE: usize> IndexMut<RangeFrom<usize>> for WriteBuffer<'file, SIZE> {
    fn index_mut(&mut self, range: RangeFrom<usize>) -> &mut Self::Output {
        &mut self.buffer[range]
    }
}
