use crate::storage::{LocalFileSystemBackend, StorageBackend, StorageResult};
use crate::storage::s3::S3Backend;

#[derive(Clone)]
pub enum AnyBackend {
    Local(LocalFileSystemBackend),
    S3(S3Backend),
}

impl AnyBackend {
    pub fn local(base_path: &str) -> Self {
        AnyBackend::Local(LocalFileSystemBackend::new(base_path))
    }

    pub fn s3(backend: S3Backend) -> Self {
        AnyBackend::S3(backend)
    }
}

impl StorageBackend for AnyBackend {
    fn read_bytes(&self, path: &str) -> StorageResult<Vec<u8>> {
        match self {
            AnyBackend::Local(b) => b.read_bytes(path),
            AnyBackend::S3(b) => b.read_bytes(path),
        }
    }

    fn write_bytes(&self, path: &str, data: &[u8]) -> StorageResult<()> {
        match self {
            AnyBackend::Local(b) => b.write_bytes(path, data),
            AnyBackend::S3(b) => b.write_bytes(path, data),
        }
    }

    fn delete_file(&self, path: &str) -> StorageResult<bool> {
        match self {
            AnyBackend::Local(b) => b.delete_file(path),
            AnyBackend::S3(b) => b.delete_file(path),
        }
    }

    fn list_files(&self, prefix: &str) -> StorageResult<Vec<String>> {
        match self {
            AnyBackend::Local(b) => b.list_files(prefix),
            AnyBackend::S3(b) => b.list_files(prefix),
        }
    }

    fn file_exists(&self, path: &str) -> StorageResult<bool> {
        match self {
            AnyBackend::Local(b) => b.file_exists(path),
            AnyBackend::S3(b) => b.file_exists(path),
        }
    }

    fn create_directory(&self, path: &str) -> StorageResult<()> {
        match self {
            AnyBackend::Local(b) => b.create_directory(path),
            AnyBackend::S3(b) => b.create_directory(path),
        }
    }
}
