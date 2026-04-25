use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("agent state I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("agent state JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("envelope cipher error: {0}")]
    Cipher(String),

    #[error("WALLETRS_KEK is required for encrypted agent state but is unset")]
    MissingKek,

    #[error("invalid Ed25519 key material: {0}")]
    InvalidKey(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("pair RPC failed: {0}")]
    Pair(String),

    #[error("authentication challenge rejected: {0}")]
    Challenge(String),

    #[error("agent loop terminated: {0}")]
    Loop(String),

    #[error("dispatcher error: {0}")]
    Dispatcher(String),
}
