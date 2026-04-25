use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::CONFIG;

use super::error::AgentError;

/// Persisted pairing credentials. Stored as JSON at
/// `${WALLETRS_STORAGE_PATH}/agent.json` with file mode `0600` on Unix.
///
/// `private_key_encrypted` is the base64 encoding of the bytes produced by
/// `EnvelopeCipher::encrypt`, which already includes a version byte and
/// nonce. See `crate::storage::crypto`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentState {
    pub agent_id: String,
    pub endpoint: String,
    pub public_key: String,
    pub private_key_encrypted: String,
    pub paired_at: i64,
}

impl AgentState {
    pub fn path() -> PathBuf {
        PathBuf::from(CONFIG.storage_base_path()).join("agent.json")
    }

    pub fn load() -> Result<Option<Self>, AgentError> {
        let path = Self::path();
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)?;
        let parsed: Self = serde_json::from_slice(&bytes)?;
        Ok(Some(parsed))
    }

    pub fn save(&self) -> Result<(), AgentError> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self)?;
        std::fs::write(&path, bytes)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    pub fn delete() -> Result<(), AgentError> {
        let path = Self::path();
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_serde() {
        let s = AgentState {
            agent_id: "agt_abc".into(),
            endpoint: "https://sigvault.example".into(),
            public_key: "AAAA".into(),
            private_key_encrypted: "BBBB".into(),
            paired_at: 1714058400,
        };
        let bytes = serde_json::to_vec(&s).unwrap();
        let back: AgentState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(s, back);
    }
}
