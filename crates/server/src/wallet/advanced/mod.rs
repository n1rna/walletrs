//! Advanced wallet building.
//!
//! Pure pipeline (spec → shape → descriptor → taproot metadata) lives in the
//! `policy-core` crate and is re-exported here for source-compatibility with
//! existing service code. The local `build` module is the BDK-bound
//! orchestrator that calls into `policy-core` then drives `BdkWalletManager`
//! to persist the wallet.

pub mod build;
pub mod error;

pub use policy_core::descriptor;
pub use policy_core::shape;
pub use policy_core::spec;
pub use policy_core::taproot;

pub use policy_core::{
    DescriptorPair, ManagedKey, PolicyError, PolicyPath, PolicyType, PreferredScriptType,
    RecoveryPath, ScriptKind, SpendingCondition, TaprootLeafInfo, TaprootMetadata, WalletShape,
    WalletSpec,
};

pub use build::{build_wallet, WalletBuildResult};
pub use error::WalletCreationError;
