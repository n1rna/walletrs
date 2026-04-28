//! PSBT signing helpers.
//!
//! These functions are intentionally side-effect-free with respect to any
//! database or server state: callers pass in already-derived xprv material,
//! the `SignerContext` to use, and the `Wallet` (mutably). The walletrs
//! server's existing managed-key DB lookup lives outside this crate.

use std::str::FromStr;
use std::sync::Arc;

use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv};
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
