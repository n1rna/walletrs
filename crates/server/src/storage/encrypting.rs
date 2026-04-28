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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::crypto::EnvelopeCipher;
    use crate::storage::filesystem::LocalFileSystemBackend;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;

    fn cipher() -> EnvelopeCipher {
        let key = BASE64.encode([0x42u8; 32]);
        EnvelopeCipher::from_base64(&key).unwrap()
    }

    fn backend(dir: &tempfile::TempDir) -> EncryptingBackend<LocalFileSystemBackend> {
        let inner = LocalFileSystemBackend::new(dir.path().to_str().unwrap());
        EncryptingBackend::new(inner, cipher())
    }

    #[test]
    fn round_trip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(&dir);
        b.write_bytes("a/b/secret.bin", b"plaintext payload")
            .unwrap();
        let got = b.read_bytes("a/b/secret.bin").unwrap();
        assert_eq!(got, b"plaintext payload");
    }

    #[test]
    fn on_disk_payload_is_not_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(&dir);
        b.write_bytes("k.bin", b"top secret").unwrap();

        // Read the raw file directly — should be the envelope, not the payload.
        let raw = std::fs::read(dir.path().join("k.bin")).unwrap();
        assert_ne!(raw, b"top secret");
        assert!(
            !raw.windows(b"top secret".len()).any(|w| w == b"top secret"),
            "raw on-disk bytes contained the plaintext"
        );
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(&dir);
        b.write_bytes("k.bin", b"secret").unwrap();

        let other_key = BASE64.encode([0x55u8; 32]);
        let other_cipher = EnvelopeCipher::from_base64(&other_key).unwrap();
        let b2 = EncryptingBackend::new(
            LocalFileSystemBackend::new(dir.path().to_str().unwrap()),
            other_cipher,
        );
        assert!(b2.read_bytes("k.bin").is_err());
    }

    #[test]
    fn delete_and_exists_are_passthrough() {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(&dir);
        b.write_bytes("present.bin", b"x").unwrap();
        assert!(b.file_exists("present.bin").unwrap());
        assert!(!b.file_exists("absent.bin").unwrap());
        assert!(b.delete_file("present.bin").unwrap());
        assert!(!b.file_exists("present.bin").unwrap());
        // Deleting a missing file returns Ok(false), not an error.
        assert!(!b.delete_file("missing.bin").unwrap());
    }
}
