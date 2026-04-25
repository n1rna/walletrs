use std::io;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::storage::{StorageError, StorageResult};

const VERSION_V1: u8 = 1;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 1 + NONCE_LEN;

#[derive(Clone)]
pub struct EnvelopeCipher {
    cipher: XChaCha20Poly1305,
}

impl EnvelopeCipher {
    pub fn from_base64(encoded: &str) -> StorageResult<Self> {
        let raw = BASE64.decode(encoded.trim()).map_err(|e| {
            StorageError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("WALLETRS_KEK base64 decode: {}", e),
            ))
        })?;
        if raw.len() != 32 {
            return Err(StorageError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("WALLETRS_KEK must decode to 32 bytes, got {}", raw.len()),
            )));
        }
        let key = Key::from_slice(&raw);
        Ok(Self {
            cipher: XChaCha20Poly1305::new(key),
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> StorageResult<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher.encrypt(nonce, plaintext).map_err(|e| {
            StorageError::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("AEAD encrypt: {}", e),
            ))
        })?;

        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.push(VERSION_V1);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt(&self, blob: &[u8]) -> StorageResult<Vec<u8>> {
        if blob.len() < HEADER_LEN {
            return Err(StorageError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "ciphertext shorter than header",
            )));
        }
        let version = blob[0];
        if version != VERSION_V1 {
            return Err(StorageError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported cipher version: {}", version),
            )));
        }
        let nonce = XNonce::from_slice(&blob[1..HEADER_LEN]);
        self.cipher.decrypt(nonce, &blob[HEADER_LEN..]).map_err(|e| {
            StorageError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("AEAD decrypt: {}", e),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cipher() -> EnvelopeCipher {
        let key_b64 = BASE64.encode([0x42u8; 32]);
        EnvelopeCipher::from_base64(&key_b64).unwrap()
    }

    #[test]
    fn round_trip() {
        let c = test_cipher();
        let ct = c.encrypt(b"super secret mnemonic").unwrap();
        assert_ne!(ct, b"super secret mnemonic");
        let pt = c.decrypt(&ct).unwrap();
        assert_eq!(pt, b"super secret mnemonic");
    }

    #[test]
    fn wrong_key_fails() {
        let c1 = test_cipher();
        let ct = c1.encrypt(b"secret").unwrap();

        let other_b64 = BASE64.encode([0x55u8; 32]);
        let c2 = EnvelopeCipher::from_base64(&other_b64).unwrap();
        assert!(c2.decrypt(&ct).is_err());
    }

    #[test]
    fn truncated_fails() {
        let c = test_cipher();
        let ct = c.encrypt(b"secret").unwrap();
        assert!(c.decrypt(&ct[..HEADER_LEN]).is_err());
    }

    #[test]
    fn version_mismatch_fails() {
        let c = test_cipher();
        let mut ct = c.encrypt(b"secret").unwrap();
        ct[0] = 0xFF;
        assert!(c.decrypt(&ct).is_err());
    }

    #[test]
    fn tampered_fails() {
        let c = test_cipher();
        let mut ct = c.encrypt(b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(c.decrypt(&ct).is_err());
    }

    #[test]
    fn bad_key_length_rejected() {
        let short = BASE64.encode([0u8; 16]);
        assert!(EnvelopeCipher::from_base64(&short).is_err());
    }
}
