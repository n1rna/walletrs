//! BDK 1.x wallet runtime.
//!
//! This crate sits on top of `policy-core`'s descriptor pipeline and BDK's
//! wallet machinery. It provides:
//!
//! - `runtime`: generic create/load/peek/reveal helpers parameterised over any
//!   `bdk_wallet::WalletPersister`.
//! - `signer`: PSBT signing utilities that accept key material as parameters
//!   (no database lookups, no server context).
//! - `policy_path`: Liana taproot leaf-hash → BDK policy-path resolver.
//! - `electrum`: thin wrapper around `BdkElectrumClient` for full scans and
//!   broadcast.
//! - `persister`: `InMemoryPersister`, a minimal `WalletPersister` impl useful
//!   for tests and for ephemeral local wallets.
//!
//! The walletrs server uses these primitives via its `R2BackedStore` persister
//! (which uploads BDK changesets to object storage). The sigvault-desktop
//! standalone wallet plugs in an encrypted-on-disk persister. Neither is part
//! of this crate.

pub mod electrum;
pub mod error;
pub mod persister;
pub mod policy_path;
pub mod psbt;
pub mod runtime;
pub mod signer;

pub use bdk_wallet::{ChangeSet, KeychainKind, PersistedWallet, Wallet, WalletPersister};
pub use electrum::ElectrumClient;
pub use error::WalletRuntimeError;
pub use persister::InMemoryPersister;
pub use policy_path::resolve_policy_path_from_leaf;
pub use psbt::{analyze_for_signing, PsbtSignerAnalysis};
pub use runtime::{
    create_wallet, load_wallet, peek_address, reveal_next_address, WalletDescriptors,
};
pub use signer::{add_xprv_signer, sign_psbt, SignerKind};
