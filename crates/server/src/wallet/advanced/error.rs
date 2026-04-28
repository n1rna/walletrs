use thiserror::Error;

use policy_core::PolicyError;

use crate::wallet::bdk::BdkWalletError;

/// Walletrs-side wrapper around `PolicyError` plus the BDK and database
/// failure modes that the server orchestrator can hit. `policy-core` doesn't
/// know about either, so the conversions live here.
#[derive(Error, Debug)]
pub enum WalletCreationError {
    #[error("Database error: {0}")]
    Database(String),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("BDK wallet error: {0}")]
    BdkWallet(#[from] BdkWalletError),
}

impl WalletCreationError {
    /// Convenience constructor for the legacy `InvalidPolicy(String)` shape
    /// used in `build.rs` orchestration code.
    pub fn invalid_policy(msg: impl Into<String>) -> Self {
        WalletCreationError::Policy(PolicyError::InvalidPolicy(msg.into()))
    }
}
