//! Walletrs PSBT signing surface.
//!
//! Holds the server-side glue: managed-key lookup against the walletrs DB,
//! plus thin wrappers around `wallet_runtime` that translate
//! `WalletRuntimeError` into `tonic::Status`. The descriptor / shape /
//! taproot pipeline is in `policy-core`, and the BDK signer mechanics
//! (analysis, key registration, sign call, leaf-path resolution) are in
//! `wallet-runtime`.

use std::collections::BTreeMap;
use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::{Fingerprint, Xpriv};
use bdk_wallet::bitcoin::Psbt;
use bdk_wallet::{KeychainKind, Wallet};
use log::{debug, info, warn};
use tonic::Status;
use wallet_runtime::{
    add_xprv_signer, analyze_for_signing, resolve_policy_path_from_leaf as wr_resolve_path,
    sign_psbt as wr_sign_psbt, PsbtSignerAnalysis, SignerKind,
};

use crate::db;
use crate::LianaDescriptor;

/// Look up the system managed key for `device_id`, analyse the PSBT to find
/// which derivations + signer kind the device needs, and register one signer
/// per required derivation. Returns the count of signers added.
pub fn add_signers_for_psbt(
    wallet: &mut Wallet,
    psbt: &Psbt,
    wallet_id: &str,
    device_id: &str,
) -> Result<i32, Status> {
    if device_id.is_empty() {
        return Err(Status::invalid_argument("Device ID is required for signing"));
    }

    let stored_wallet = db::get_wallet(wallet_id)
        .map_err(|e| Status::internal(format!("Failed to get wallet: {}", e)))?;

    let key = db::get_managed_key(&stored_wallet.user_id, device_id, "system")
        .map_err(|e| Status::internal(format!("Failed to get key for device {}: {}", device_id, e)))?
        .ok_or_else(|| Status::not_found(format!("No system key found for device {}", device_id)))?;

    if key.key_type != "system" || !key.has_private_key_material() {
        return Err(Status::invalid_argument(format!(
            "Device {} is not a system managed key or lacks private key material",
            device_id
        )));
    }

    let device_fp = Fingerprint::from_str(&key.fingerprint).unwrap_or_default();
    let mut analysis: PsbtSignerAnalysis = analyze_for_signing(wallet, psbt, &device_fp);

    if analysis.has_taproot_inputs && !analysis.device_in_tap_origins {
        info!(
            "Device {} (fp: {}) not found in tap_key_origins, defaulting to internal key",
            device_id, key.fingerprint
        );
    } else if analysis.has_taproot_inputs {
        info!(
            "Device {} (fp: {}) detected as {} taproot key",
            device_id,
            key.fingerprint,
            match analysis.signer_kind {
                SignerKind::TaprootKeyPath => "internal (keypath)",
                SignerKind::TaprootScriptPath => "script path",
                _ => "taproot",
            }
        );
    } else {
        info!(
            "Device {} (fp: {}) detected as segwit v0 signer",
            device_id, key.fingerprint
        );
    }

    if analysis.required_derivations.is_empty() {
        warn!("No derivation paths found in PSBT - falling back to common 0..5 indices");
        for keychain in [KeychainKind::External, KeychainKind::Internal] {
            for i in 0..5 {
                analysis.required_derivations.push((keychain, i));
            }
        }
    }

    let tpriv_str = key.tpriv.as_ref().ok_or_else(|| {
        Status::internal(format!(
            "Device {} has no tpriv (account-level xpriv) stored",
            key.device_id
        ))
    })?;

    let account_xpriv = Xpriv::from_str(tpriv_str).map_err(|e| {
        Status::internal(format!(
            "Failed to parse account xpriv for device {}: {}",
            key.device_id, e
        ))
    })?;

    let mut added = 0i32;
    for (keychain, index) in &analysis.required_derivations {
        match add_xprv_signer(wallet, &account_xpriv, *keychain, *index, analysis.signer_kind) {
            Ok(()) => {
                added += 1;
                debug!(
                    "✓ Added signer for {:?}/{} from {} (kind: {:?})",
                    keychain, index, key.device_id, analysis.signer_kind
                );
            }
            Err(e) => {
                warn!("Failed to add signer at {:?}/{}: {}", keychain, index, e);
            }
        }
    }

    info!("✅ Added {} signers to wallet for signing operation", added);
    Ok(added)
}

/// Sign a PSBT in-place with the wallet's currently-registered signers.
/// Does not finalize — the caller runs miniscript's `finalize_mut` later
/// (see `service::transaction_handling::finalize_wallet_transaction`).
pub fn sign_psbt_with_taproot_support(
    wallet: &Wallet,
    psbt: &mut Psbt,
    wallet_id: &str,
) -> Result<Option<Psbt>, Status> {
    info!("=== Starting PSBT Signing Process for wallet: {} ===", wallet_id);

    let signed_all =
        wr_sign_psbt(wallet, psbt).map_err(|e| Status::internal(format!("Failed to sign PSBT: {}", e)))?;

    if !signed_all {
        warn!("⚠️ Not all inputs were signed — signers may be missing for some inputs");
    } else {
        info!("✅ BDK sign() returned signed_all_inputs: true");
    }

    Ok(Some(psbt.clone()))
}

/// Map a taproot leaf hash to the BDK policy-path indices needed to spend
/// via that leaf.
///
/// Accepts two leaf-hash forms emitted by `policy_core::taproot::extract`:
/// - `"keypath"` — the primary spends via the taproot internal key.
/// - A hex-encoded `TapLeafHash` — primary or recovery via a script leaf.
///
/// The Liana descriptor is required for hex leaf hashes so we can derive
/// the child-zero PSBT input and match leaf hashes against signer
/// fingerprints.
pub fn resolve_policy_path_from_leaf(
    wallet: &bdk_wallet::Wallet,
    leaf_hash: &str,
    liana_descriptor: Option<&LianaDescriptor>,
) -> Result<BTreeMap<String, Vec<usize>>, Status> {
    wr_resolve_path(wallet, leaf_hash, liana_descriptor)
        .map_err(|e| match e.to_string() {
            ref s if s.contains("does not match any spending path")
                || s.contains("provided but wallet has no Liana descriptor") =>
            {
                Status::invalid_argument(s.clone())
            }
            _ => Status::internal(e.to_string()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    use bdk_wallet::bitcoin::bip32::{Xpriv, Xpub};
    use bdk_wallet::bitcoin::secp256k1::Secp256k1;
    use bdk_wallet::bitcoin::Network;
    use bdk_wallet::Wallet;

    use crate::wallet::advanced::shape::WalletShape;
    use crate::wallet::advanced::{descriptor, shape, taproot};
    use crate::wallet::advanced::{
        ManagedKey, PolicyType, PreferredScriptType, SpendingCondition, WalletSpec,
    };

    fn make_key(seed: u64) -> (String, ManagedKey) {
        let mut bytes = [0u8; 64];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(Network::Testnet, &bytes).unwrap();
        let xpub = Xpub::from_priv(&secp, &xpriv);
        let fp = format!("{:08x}", xpriv.fingerprint(&secp));
        let liana_xpub = format!("[{}]{}/<0;1>/*", fp, xpub);
        (
            format!("d{}", seed),
            ManagedKey {
                fingerprint: fp,
                derivation_path: "m/84'/1'/0'".to_string(),
                xpub: liana_xpub,
                tpub: None,
            },
        )
    }

    fn build_timelocked_wallet() -> (
        Wallet,
        crate::LianaDescriptor,
        Vec<crate::wallet::advanced::TaprootLeafInfo>,
    ) {
        let (id1, k1) = make_key(1);
        let (id2, k2) = make_key(2);
        let (id3, k3) = make_key(3);

        let mut keys = std::collections::BTreeMap::new();
        keys.insert(id1, k1);
        keys.insert(id2, k2);
        keys.insert(id3, k3);

        let spec = WalletSpec {
            network: Network::Testnet,
            conditions: vec![
                SpendingCondition {
                    id: "primary".to_string(),
                    is_primary: true,
                    timelock: 0,
                    threshold: 2,
                    policy: PolicyType::Multi,
                    managed_key_ids: vec!["d1".to_string(), "d2".to_string()],
                },
                SpendingCondition {
                    id: "recovery".to_string(),
                    is_primary: false,
                    timelock: 144,
                    threshold: 1,
                    policy: PolicyType::Single,
                    managed_key_ids: vec!["d3".to_string()],
                },
            ],
            managed_keys: keys,
            preferred_script_type: PreferredScriptType::Auto,
        };

        let shape = shape::classify(&spec).unwrap();
        let (primary, primary_id, recoveries) = match &shape {
            WalletShape::TimelockedPolicy {
                primary,
                primary_id,
                recoveries,
            } => (primary.clone(), primary_id.clone(), recoveries.clone()),
            other => panic!("expected TimelockedPolicy, got {:?}", other),
        };

        let pair = descriptor::build(&shape).unwrap();
        let liana_desc = pair.liana.clone().expect("liana descriptor");

        let metadata = taproot::extract(&primary_id, &primary, &recoveries, &liana_desc).unwrap();

        let wallet = Wallet::create(pair.external.clone(), pair.internal.clone())
            .network(Network::Testnet)
            .create_wallet_no_persist()
            .expect("BDK wallet");

        (wallet, liana_desc, metadata.leaves)
    }

    #[test]
    fn primary_multisig_leaf_resolves_to_zero() {
        let (wallet, liana_desc, leaves) = build_timelocked_wallet();
        let primary = leaves
            .iter()
            .find(|l| l.spending_condition_id == "primary")
            .expect("primary leaf");
        assert_ne!(
            primary.leaf_hash, "keypath",
            "multisig primary lives in the taptree"
        );
        assert!(
            primary.leaf_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "primary leaf hash should be hex, got {}",
            primary.leaf_hash
        );

        let resolved =
            resolve_policy_path_from_leaf(&wallet, &primary.leaf_hash, Some(&liana_desc))
                .expect("resolve primary leaf");
        let path = resolved.values().next().expect("policy path entry");
        assert_eq!(path, &vec![0]);
    }

    #[test]
    fn recovery_leaf_resolves_to_one() {
        let (wallet, liana_desc, leaves) = build_timelocked_wallet();
        let recovery = leaves
            .iter()
            .find(|l| l.spending_condition_id == "recovery")
            .expect("recovery leaf");

        let resolved =
            resolve_policy_path_from_leaf(&wallet, &recovery.leaf_hash, Some(&liana_desc))
                .expect("resolve recovery leaf");
        let path = resolved.values().next().expect("policy path entry");
        assert_eq!(path, &vec![1]);
    }

    #[test]
    fn unknown_leaf_returns_invalid_argument() {
        let (wallet, liana_desc, _) = build_timelocked_wallet();
        let result = resolve_policy_path_from_leaf(&wallet, "deadbeef", Some(&liana_desc));
        assert!(result.is_err());
    }

    #[test]
    fn hex_leaf_without_descriptor_errors() {
        let (wallet, _, leaves) = build_timelocked_wallet();
        let any_leaf = &leaves[0].leaf_hash;
        let result = resolve_policy_path_from_leaf(&wallet, any_leaf, None);
        assert!(result.is_err(), "hex leaf without descriptor must error");
    }
}
