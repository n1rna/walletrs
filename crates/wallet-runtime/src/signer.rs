//! PSBT signing helpers.
//!
//! These functions are intentionally side-effect-free with respect to any
//! database or server state: callers pass in already-derived xprv material,
//! the `SignerContext` to use, and the `Wallet` (mutably). The walletrs
//! server's existing managed-key DB lookup lives outside this crate.

use std::collections::BTreeSet;
use std::str::FromStr;
use std::sync::Arc;

use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::Psbt;
use bdk_wallet::signer::{SignerContext, SignerOrdering, SignerWrapper};
use bdk_wallet::{KeychainKind, SignOptions, Wallet};

use crate::error::WalletRuntimeError;

/// Which BDK signer context to register the key under. Mirrors
/// `bdk_wallet::signer::SignerContext` but exposes only the variants the
/// walletrs/sigvault stack actually uses.
#[derive(Debug, Clone, Copy)]
pub enum SignerKind {
    SegwitV0,
    /// Taproot key-path spend (signs with the internal key).
    TaprootKeyPath,
    /// Taproot script-path spend (signs a leaf inside the script tree).
    TaprootScriptPath,
}

impl SignerKind {
    fn into_context(self) -> SignerContext {
        match self {
            SignerKind::SegwitV0 => SignerContext::Segwitv0,
            SignerKind::TaprootKeyPath => SignerContext::Tap {
                is_internal_key: true,
            },
            SignerKind::TaprootScriptPath => SignerContext::Tap {
                is_internal_key: false,
            },
        }
    }
}

/// Add a private-key signer derived from `account_xprv` (already at the
/// account level, e.g. `m/84'/1'/0'`) at the given chain/index pair. The
/// caller should know which derivations the PSBT requires; this is a
/// per-derivation primitive, not a PSBT analysis routine.
pub fn add_xprv_signer(
    wallet: &mut Wallet,
    account_xprv: &Xpriv,
    keychain: KeychainKind,
    index: u32,
    kind: SignerKind,
) -> Result<(), WalletRuntimeError> {
    let secp = Secp256k1::new();
    let chain_num = match keychain {
        KeychainKind::External => 0u32,
        KeychainKind::Internal => 1u32,
    };

    let path = DerivationPath::from_str(&format!("m/{}/{}", chain_num, index))
        .map_err(|e| WalletRuntimeError::Bdk(format!("invalid derivation path: {}", e)))?;

    let derived = account_xprv
        .derive_priv(&secp, &path)
        .map_err(|e| WalletRuntimeError::Bdk(format!("derive_priv: {}", e)))?;

    let private_key = derived.to_priv();
    let signer = SignerWrapper::new(private_key, kind.into_context());
    wallet.add_signer(keychain, SignerOrdering(200), Arc::new(signer));
    Ok(())
}

/// Register a signer for every key of `device_fingerprint` that the PSBT
/// asks for, each in the way that key signs: a taproot internal key by
/// key path, a key inside a leaf by script path, anything else as SegWit
/// v0. Returns how many signers were added.
///
/// The key's own origin decides, not the device: one device can hold the
/// internal key and, at another multipath step of the same xpub, a key in
/// a recovery leaf. `account_xprv` is the device's account-level key; the
/// last two steps of each origin path are derived from it.
pub fn add_psbt_signers(
    wallet: &mut Wallet,
    account_xprv: &Xpriv,
    psbt: &Psbt,
    device_fingerprint: &Fingerprint,
) -> Result<usize, WalletRuntimeError> {
    let secp = Secp256k1::new();
    let derive = |path: &DerivationPath| {
        let steps: Vec<ChildNumber> = path.into_iter().copied().collect();
        if steps.len() < 2 {
            return None;
        }
        account_xprv
            .derive_priv(&secp, &&steps[steps.len() - 2..])
            .ok()
            .map(|derived| derived.to_priv())
    };

    let mut seen = BTreeSet::new();
    let mut signers = Vec::new();
    for input in &psbt.inputs {
        for (xonly, (leaf_hashes, (fingerprint, path))) in &input.tap_key_origins {
            if fingerprint != device_fingerprint {
                continue;
            }
            let Some(private_key) = derive(path) else {
                continue;
            };
            if private_key.public_key(&secp).inner.x_only_public_key().0 != *xonly {
                continue;
            }
            let kind = if leaf_hashes.is_empty() {
                SignerKind::TaprootKeyPath
            } else {
                SignerKind::TaprootScriptPath
            };
            if seen.insert((private_key.public_key(&secp).inner, leaf_hashes.is_empty())) {
                signers.push((private_key, kind));
            }
        }
        for (public_key, (fingerprint, path)) in &input.bip32_derivation {
            if fingerprint != device_fingerprint {
                continue;
            }
            let Some(private_key) = derive(path) else {
                continue;
            };
            if private_key.public_key(&secp).inner != *public_key {
                continue;
            }
            if seen.insert((*public_key, false)) {
                signers.push((private_key, SignerKind::SegwitV0));
            }
        }
    }

    let added = signers.len();
    for (private_key, kind) in signers {
        let signer = SignerWrapper::new(private_key, kind.into_context());
        wallet.add_signer(
            KeychainKind::External,
            SignerOrdering(200),
            Arc::new(signer),
        );
    }
    Ok(added)
}

/// Sign all inputs of a PSBT that the wallet has signers for. Returns
/// `Ok(true)` when every input was signed, `Ok(false)` when at least one
/// input is still missing signatures. Does NOT finalize the PSBT — the
/// caller is responsible for finalisation.
pub fn sign_psbt(wallet: &Wallet, psbt: &mut Psbt) -> Result<bool, WalletRuntimeError> {
    let opts = SignOptions {
        try_finalize: false,
        ..Default::default()
    };
    wallet
        .sign(psbt, opts)
        .map_err(|e| WalletRuntimeError::Psbt(e.to_string()))
}
