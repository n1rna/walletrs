//! Re-export of the `KeyUtils` API now living in `policy-core`. Kept here so
//! existing `crate::wallet::bdk::KeyUtils` imports continue to compile.

pub use policy_core::key_utils::{KeyGenerationResult, KeyUtils};
