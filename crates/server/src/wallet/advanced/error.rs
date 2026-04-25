use thiserror::Error;

use crate::wallet::bdk::BdkWalletError;

#[derive(Error, Debug)]
pub enum WalletCreationError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),
    #[error("Key management error: {0}")]
    KeyManagement(String),
    #[error("Descriptor generation error: {0}")]
    DescriptorGeneration(String),
    #[error("BDK wallet error: {0}")]
    BdkWallet(#[from] BdkWalletError),
    #[error("Liana integration error: {0}")]
    LianaIntegration(String),
}
