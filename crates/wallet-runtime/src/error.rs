use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletRuntimeError {
    #[error("BDK error: {0}")]
    Bdk(String),
    #[error("Wallet not found")]
    NotFound,
    #[error("Invalid descriptor: {0}")]
    InvalidDescriptor(String),
    #[error("Persister error: {0}")]
    Persister(String),
    #[error("Electrum error: {0}")]
    Electrum(String),
    #[error("PSBT error: {0}")]
    Psbt(String),
    #[error("Policy path error: {0}")]
    PolicyPath(String),
    #[error(transparent)]
    Policy(#[from] policy_core::PolicyError),
}
