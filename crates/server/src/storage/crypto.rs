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

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| StorageError::Io(io::Error::other(format!("AEAD encrypt: {}", e))))?;

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
        self.cipher
            .decrypt(nonce, &blob[HEADER_LEN..])
            .map_err(|e| {
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

    // ---- property tests -------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        /// For any byte sequence (including empty) and any 32-byte key,
        /// encrypt → decrypt recovers the original plaintext exactly.
        /// Catches any future regression where a length-edge-case slips
        /// through the AEAD wrapping.
        #[test]
        fn prop_round_trip_recovers_plaintext(
            plaintext in prop::collection::vec(any::<u8>(), 0..2048),
            key_bytes in prop::array::uniform32(any::<u8>()),
        ) {
            let cipher = EnvelopeCipher::from_base64(&BASE64.encode(key_bytes))
                .expect("32-byte key always parses");
            let ct = cipher.encrypt(&plaintext).expect("encrypt");
            let pt = cipher.decrypt(&ct).expect("decrypt with the same key");
            prop_assert_eq!(pt, plaintext);
        }

        /// Two distinct encryptions of the same plaintext (random nonces)
        /// must never produce identical ciphertexts. Reuse of nonces with
        /// XChaCha20Poly1305 would be catastrophic; this property is a
        /// proxy that ensures the random nonce code path is wired.
        #[test]
        fn prop_nonces_are_distinct(
            plaintext in prop::collection::vec(any::<u8>(), 1..256),
            key_bytes in prop::array::uniform32(any::<u8>()),
        ) {
            let cipher = EnvelopeCipher::from_base64(&BASE64.encode(key_bytes))
                .expect("32-byte key always parses");
            let ct1 = cipher.encrypt(&plaintext).expect("encrypt 1");
            let ct2 = cipher.encrypt(&plaintext).expect("encrypt 2");
            prop_assert_ne!(ct1, ct2);
        }

        /// Decryption with the wrong key never succeeds for non-trivially
        /// short inputs. We restrict to plaintexts ≥ 1 byte to avoid an
        /// edge case where empty AEAD output may incidentally decode under
        /// arbitrary keys.
        #[test]
        fn prop_wrong_key_rejects(
            plaintext in prop::collection::vec(any::<u8>(), 1..256),
            key_a in prop::array::uniform32(any::<u8>()),
            key_b in prop::array::uniform32(any::<u8>()),
        ) {
            prop_assume!(key_a != key_b);
            let ca = EnvelopeCipher::from_base64(&BASE64.encode(key_a)).unwrap();
            let cb = EnvelopeCipher::from_base64(&BASE64.encode(key_b)).unwrap();
            let ct = ca.encrypt(&plaintext).unwrap();
            prop_assert!(cb.decrypt(&ct).is_err());
        }

        /// A KEK that doesn't decode to exactly 32 bytes is always
        /// rejected. Ensures the length check holds for the full domain,
        /// not just the few values in the explicit test above.
        #[test]
        fn prop_non_32_byte_key_rejected(len in (0usize..32usize).prop_union(33usize..128usize)) {
            let bytes = vec![0u8; len];
            let encoded = BASE64.encode(&bytes);
            prop_assert!(EnvelopeCipher::from_base64(&encoded).is_err());
        }
    }
}
