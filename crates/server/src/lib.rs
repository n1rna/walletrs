pub mod config;
pub mod db;
pub mod proto;
pub mod storage;
pub mod wallet;

// Re-export key components that will be used by both the server and CLI
pub use wallet::bdk::{KeyUtils, KeyGenerationResult, BdkWalletManager, BdkWalletError};

// Re-export Liana components for policy and descriptor handling
pub use liana::{
    descriptors::{LianaDescriptor, LianaPolicy, PathInfo, SinglePathLianaDesc},
    signer::HotSigner,
    spend::{create_spend, CoinSelectionRes, CreateSpendRes, SpendOutputAddress},
};