//! Advanced wallet building.
//!
//! Pipeline:
//!
//! ```text
//! WalletSpec  →  classify()  →  WalletShape
//!     ↓                              ↓
//! validate                       descriptor::build
//!                                    ↓
//!                              DescriptorPair  →  BdkWalletManager::create
//!                                    ↓
//!                              taproot::extract  (only for TimelockedPolicy)
//!                                    ↓
//!                              WalletBuildResult
//! ```
//!
//! Each stage lives in its own module; `build_wallet` is the only function
//! callers need to wire up an end-to-end create-wallet RPC.

pub mod build;
pub mod descriptor;
pub mod error;
pub mod shape;
pub mod spec;
pub mod taproot;

#[cfg(test)]
mod tests;

pub use build::{build_wallet, WalletBuildResult};
pub use error::WalletCreationError;
pub use shape::{classify, PolicyPath, RecoveryPath, ScriptKind, WalletShape};
pub use spec::{PolicyType, PreferredScriptType, SpendingCondition, WalletSpec};
pub use taproot::{TaprootLeafInfo, TaprootMetadata};
