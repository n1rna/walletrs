use serde::{Deserialize, Serialize};

/// A managed key as the wallet pipeline needs to see it: an extended public
/// key plus origin metadata. Hot xprv material, custody flags, ownership and
/// timestamps live in the consuming layer (e.g. walletrs's `StoredManagedKey`)
/// and are converted to this struct at the policy boundary via
/// `to_managed_key()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedKey {
    /// Hex BIP32 fingerprint of the master key (no brackets, no slashes).
    pub fingerprint: String,
    /// BIP32 derivation path from the master key down to the account-level
    /// xpub/tpub, in `m/...`-prefixed form.
    pub derivation_path: String,
    /// Account-level extended pubkey serialised as a string. Mainnet-form.
    pub xpub: String,
    /// Account-level extended pubkey serialised in test-network form, when
    /// available. Used in preference to `xpub` for non-mainnet wallets so the
    /// resulting descriptor encodes the correct network.
    pub tpub: Option<String>,
}

impl ManagedKey {
    pub fn new(
        fingerprint: impl Into<String>,
        derivation_path: impl Into<String>,
        xpub: impl Into<String>,
        tpub: Option<String>,
    ) -> Self {
        Self {
            fingerprint: fingerprint.into(),
            derivation_path: derivation_path.into(),
            xpub: xpub.into(),
            tpub,
        }
    }
}
