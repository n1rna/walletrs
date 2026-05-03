//! PSBT inspection helpers for choosing what signers to register.
//!
//! `analyze_for_signing` walks every input of a PSBT, collects every
//! derivation index the wallet needs to sign for, and infers the
//! `SignerKind` (`SegwitV0` / `TaprootKeyPath` / `TaprootScriptPath`) for a
//! specific device fingerprint. The result tells the caller exactly which
//! `add_xprv_signer` calls to make.
//!
//! No DB / server state is involved — pure analysis over the PSBT and the
//! wallet's keychain index.

use std::collections::HashSet;

use bdk_wallet::bitcoin::bip32::{ChildNumber, Fingerprint};
use bdk_wallet::bitcoin::Psbt;
use bdk_wallet::{KeychainKind, Wallet};

use crate::signer::SignerKind;

/// Output of [`analyze_for_signing`].
#[derive(Debug, Clone)]
pub struct PsbtSignerAnalysis {
    /// `SignerContext` to register under for this device.
    pub signer_kind: SignerKind,
    /// `(keychain, address_index)` pairs the device needs to sign for, in
    /// no particular order.
    pub required_derivations: Vec<(KeychainKind, u32)>,
    /// Whether the PSBT contains any taproot inputs at all.
    pub has_taproot_inputs: bool,
    /// Whether `device_fingerprint` was found in any input's
    /// `tap_key_origins` map. When `has_taproot_inputs == true` and this is
    /// `false`, the analysis falls back to `TaprootKeyPath`.
    pub device_in_tap_origins: bool,
}

/// Analyse a PSBT for what `device_fingerprint` needs to sign:
///
/// 1. Collect derivation `(keychain, index)` pairs from each input's
///    `witness_utxo` (via `wallet.derivation_of_spk`), `bip32_derivation`,
///    and `tap_key_origins`.
/// 2. If any input has `tap_key_origins`, decide whether the device is
///    spending via the taproot key path (matched fingerprint with empty
///    `leaf_hashes`) or a script path (matched fingerprint with non-empty
///    `leaf_hashes`). Defaults to `TaprootKeyPath` when the fingerprint is
///    not found in any tap origin.
/// 3. If no input has `tap_key_origins`, the device signs as `SegwitV0`.
pub fn analyze_for_signing(
    wallet: &Wallet,
    psbt: &Psbt,
    device_fingerprint: &Fingerprint,
) -> PsbtSignerAnalysis {
    let mut required: HashSet<(KeychainKind, u32)> = HashSet::new();

    for input in &psbt.inputs {
        if let Some(utxo) = &input.witness_utxo {
            if let Some((keychain, index)) = wallet.derivation_of_spk(utxo.script_pubkey.clone()) {
                required.insert((keychain, index));
            }
        }

        for (_fp, path) in input.bip32_derivation.values() {
            if let Some((keychain, index)) = derivation_from_path(path) {
                required.insert((keychain, index));
            }
        }

        for (_leaf_hashes, (_fp, path)) in input.tap_key_origins.values() {
            if let Some((keychain, index)) = derivation_from_path(path) {
                required.insert((keychain, index));
            }
        }
    }

    let has_taproot_inputs = psbt
        .inputs
        .iter()
        .any(|input| !input.tap_key_origins.is_empty());

    let mut device_in_tap_origins = false;
    let mut device_is_internal_key = true;
    if has_taproot_inputs {
        for input in &psbt.inputs {
            for (leaf_hashes, (fp, _path)) in input.tap_key_origins.values() {
                if fp == device_fingerprint {
                    device_in_tap_origins = true;
                    if !leaf_hashes.is_empty() {
                        device_is_internal_key = false;
                    }
                }
            }
        }
    }

    let signer_kind = if has_taproot_inputs {
        if device_is_internal_key {
            SignerKind::TaprootKeyPath
        } else {
            SignerKind::TaprootScriptPath
        }
    } else {
        SignerKind::SegwitV0
    };

    PsbtSignerAnalysis {
        signer_kind,
        required_derivations: required.into_iter().collect(),
        has_taproot_inputs,
        device_in_tap_origins,
    }
}

/// Pull `(keychain, address_index)` out of a BIP32 derivation path of the
/// form `…/<chain>/<index>`. The last `ChildNumber` is the address index;
/// the second-to-last is the chain (0 = external, 1 = internal).
fn derivation_from_path(
    path: &bdk_wallet::bitcoin::bip32::DerivationPath,
) -> Option<(KeychainKind, u32)> {
    let index = path.into_iter().last().copied()?;
    let chain_number = if path.len() >= 2 {
        path[path.len() - 2]
    } else {
        ChildNumber::from_normal_idx(0).ok()?
    };
    let keychain = if u32::from(chain_number) == 0 {
        KeychainKind::External
    } else {
        KeychainKind::Internal
    };
    Some((keychain, u32::from(index)))
}
