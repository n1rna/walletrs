use crate::storage::crypto::EnvelopeCipher;
use crate::storage::{StorageBackend, StorageResult};

#[derive(Clone)]
pub struct EncryptingBackend<B: StorageBackend + Clone> {
    inner: B,
    cipher: EnvelopeCipher,
}

impl<B: StorageBackend + Clone> EncryptingBackend<B> {
    pub fn new(inner: B, cipher: EnvelopeCipher) -> Self {
        Self { inner, cipher }
    }
}

impl<B: StorageBackend + Clone> StorageBackend for EncryptingBackend<B> {
    fn read_bytes(&self, path: &str) -> StorageResult<Vec<u8>> {
        let blob = self.inner.read_bytes(path)?;
        self.cipher.decrypt(&blob)
    }

    fn write_bytes(&self, path: &str, data: &[u8]) -> StorageResult<()> {
        let blob = self.cipher.encrypt(data)?;
        self.inner.write_bytes(path, &blob)
    }

    fn delete_file(&self, path: &str) -> StorageResult<bool> {
        self.inner.delete_file(path)
    }

    fn list_files(&self, prefix: &str) -> StorageResult<Vec<String>> {
        self.inner.list_files(prefix)
    }

    fn file_exists(&self, path: &str) -> StorageResult<bool> {
        self.inner.file_exists(path)
    }

    fn create_directory(&self, path: &str) -> StorageResult<()> {
        self.inner.create_directory(path)
    }
}
