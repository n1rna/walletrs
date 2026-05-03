//! Pure Bitcoin wallet policy primitives.
//!
//! Pipeline:
//!
//! ```text
//! WalletSpec  →  classify()  →  WalletShape
//!     ↓                              ↓
//! validate                       descriptor::build
//!                                    ↓
//!                              DescriptorPair
//!                                    ↓
//!                              taproot::extract  (only for TimelockedPolicy)
//! ```
//!
//! Consumers wire the BDK persistence layer themselves (see `wallet-runtime`)
//! — this crate only handles spec → descriptor + taproot metadata, with no
//! tokio/async/server/DB dependencies.

pub mod descriptor;
pub mod error;
pub mod key_utils;
pub mod managed_key;
pub mod shape;
pub mod spec;
pub mod taproot;

#[cfg(test)]
mod tests;

pub use descriptor::{build as build_descriptor, DescriptorPair};
pub use error::PolicyError;
pub use key_utils::{KeyGenerationResult, KeyUtils};
pub use managed_key::ManagedKey;
pub use shape::{classify, PolicyPath, RecoveryPath, ScriptKind, WalletShape};
pub use spec::{PolicyType, PreferredScriptType, SpendingCondition, WalletSpec};
pub use taproot::{TaprootLeafInfo, TaprootMetadata};
