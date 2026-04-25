use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;

use crate::config::CONFIG;
use crate::storage::crypto::EnvelopeCipher;

use super::error::AgentError;

/// Ed25519 keypair used to identify this agent to sigvault. The private
/// half never leaves the host; only the public bytes go on the wire during
/// pairing, and only signatures over server-issued challenges go on the
/// wire on subsequent reconnects.
pub struct AgentKeypair {
    signing: SigningKey,
}

impl AgentKeypair {
    /// Generate a new keypair from the OS RNG.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self { signing }
    }

    /// Decrypt a stored private key (base64-encoded ciphertext from
    /// `EnvelopeCipher::encrypt`) using the configured KEK.
    pub fn from_encrypted_b64(encrypted_b64: &str) -> Result<Self, AgentError> {
        let cipher = envelope_cipher()?;
        let blob = BASE64.decode(encrypted_b64.trim())?;
        let plaintext = cipher
            .decrypt(&blob)
            .map_err(|e| AgentError::Cipher(e.to_string()))?;
        let bytes: [u8; SECRET_KEY_LENGTH] = plaintext.as_slice().try_into().map_err(|_| {
            AgentError::InvalidKey(format!("expected 32 bytes, got {}", plaintext.len()))
        })?;
        Ok(Self {
            signing: SigningKey::from_bytes(&bytes),
        })
    }

    /// Encrypt the private key with the configured KEK and return base64.
    pub fn encrypt_to_b64(&self) -> Result<String, AgentError> {
        let cipher = envelope_cipher()?;
        let blob = cipher
            .encrypt(&self.signing.to_bytes())
            .map_err(|e| AgentError::Cipher(e.to_string()))?;
        Ok(BASE64.encode(blob))
    }

    pub fn public_b64(&self) -> String {
        BASE64.encode(self.signing.verifying_key().as_bytes())
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Produce a 64-byte Ed25519 signature over `msg`.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing.sign(msg).to_bytes().to_vec()
    }
}

/// Verify an Ed25519 signature against a public key. Used in tests and as a
/// helper for any future server-side signature checks the agent might do.
pub fn verify(public_key: &[u8; 32], msg: &[u8], signature: &[u8]) -> Result<(), AgentError> {
    let vk =
        VerifyingKey::from_bytes(public_key).map_err(|e| AgentError::InvalidKey(e.to_string()))?;
    let sig: [u8; 64] = signature.try_into().map_err(|_| {
        AgentError::InvalidKey(format!(
            "signature must be 64 bytes, got {}",
            signature.len()
        ))
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig);
    vk.verify(msg, &signature)
        .map_err(|e| AgentError::Challenge(e.to_string()))
}

fn envelope_cipher() -> Result<EnvelopeCipher, AgentError> {
    let kek_b64 = CONFIG.kek_b64().ok_or(AgentError::MissingKek)?;
    EnvelopeCipher::from_base64(kek_b64).map_err(|e| AgentError::Cipher(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let kp = AgentKeypair::generate();
        let msg = b"hello sigvault";
        let sig = kp.sign(msg);
        assert!(verify(&kp.public_bytes(), msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let kp = AgentKeypair::generate();
        let sig = kp.sign(b"first message");
        assert!(verify(&kp.public_bytes(), b"different message", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let signer = AgentKeypair::generate();
        let other = AgentKeypair::generate();
        let sig = signer.sign(b"msg");
        assert!(verify(&other.public_bytes(), b"msg", &sig).is_err());
    }

    #[test]
    fn public_b64_is_44_chars() {
        let kp = AgentKeypair::generate();
        // 32 bytes base64-encoded == 44 chars (with padding).
        assert_eq!(kp.public_b64().len(), 44);
    }
}
