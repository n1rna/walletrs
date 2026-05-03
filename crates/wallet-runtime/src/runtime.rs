use bdk_wallet::bitcoin::{Address, Network};
use bdk_wallet::{KeychainKind, PersistedWallet, Wallet, WalletPersister};

use crate::error::WalletRuntimeError;

/// External (receive) + internal (change) descriptor pair. Wraps the strings
/// that come out of `policy_core::descriptor::build`.
#[derive(Debug, Clone)]
pub struct WalletDescriptors {
    pub external: String,
    pub internal: String,
}

impl WalletDescriptors {
    pub fn new(external: impl Into<String>, internal: impl Into<String>) -> Self {
        Self {
            external: external.into(),
            internal: internal.into(),
        }
    }
}

impl From<policy_core::DescriptorPair> for WalletDescriptors {
    fn from(pair: policy_core::DescriptorPair) -> Self {
        Self {
            external: pair.external,
            internal: pair.internal,
        }
    }
}

/// Create a fresh BDK wallet from a descriptor pair, persisting the initial
/// state through the given persister. Returns the wallet handle.
pub fn create_wallet<P>(
    persister: &mut P,
    network: Network,
    descriptors: &WalletDescriptors,
) -> Result<PersistedWallet<P>, WalletRuntimeError>
where
    P: WalletPersister,
    P::Error: std::fmt::Display,
{
    if descriptors.external.is_empty() || descriptors.internal.is_empty() {
        return Err(WalletRuntimeError::InvalidDescriptor(
            "external and internal descriptors must be non-empty".to_string(),
        ));
    }

    let mut wallet = Wallet::create(descriptors.external.clone(), descriptors.internal.clone())
        .network(network)
        .create_wallet(persister)
        .map_err(|e| WalletRuntimeError::Bdk(e.to_string()))?;

    wallet
        .persist(persister)
        .map_err(|e| WalletRuntimeError::Persister(e.to_string()))?;

    Ok(wallet)
}

/// Load an existing BDK wallet from a persister. Returns `Ok(None)` when the
/// persister has no state to restore (i.e. a fresh persister).
pub fn load_wallet<P>(
    persister: &mut P,
    network: Network,
) -> Result<Option<PersistedWallet<P>>, WalletRuntimeError>
where
    P: WalletPersister,
    P::Error: std::fmt::Display,
{
    Wallet::load()
        .check_network(network)
        .load_wallet(persister)
        .map_err(|e| WalletRuntimeError::Bdk(e.to_string()))
}

/// Peek at a receive (or change) address at a specific index without
/// advancing the wallet's internal counter or persisting state.
pub fn peek_address<P>(wallet: &PersistedWallet<P>, kind: KeychainKind, index: u32) -> Address
where
    P: WalletPersister,
{
    wallet.peek_address(kind, index).address
}

/// Reveal the next unused address in the given keychain. Requires `&mut` so
/// BDK can advance the keychain index, and returns the address. The caller is
/// responsible for calling `wallet.persist(...)` to durably store the new
/// reveal index.
pub fn reveal_next_address<P>(wallet: &mut PersistedWallet<P>, kind: KeychainKind) -> Address
where
    P: WalletPersister,
{
    wallet.next_unused_address(kind).address
}
