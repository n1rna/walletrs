//! Signer utilities for wallet transaction handling
//!
//! This module contains helper functions for:
//! - Adding signers to wallets based on PSBTs
//! - Signing PSBTs with taproot support
//! - Resolving policy paths for taproot spending

use crate::db;
use crate::LianaDescriptor;
use bdk_wallet::bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv};
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::psbt::Input as PsbtInput;
use bdk_wallet::bitcoin::secp256k1;
use bdk_wallet::bitcoin::Psbt;
use bdk_wallet::signer::{SignerContext, SignerOrdering, SignerWrapper};
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use hex;
use log::{debug, error, info, warn};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use tonic::Status;

/// Add signers to wallet on-demand based on the UTXOs being spent in the PSBT
/// This function analyzes the PSBT inputs, determines which keys are needed,
/// and adds only those specific signers to the wallet for this signing operation
/// Returns the number of signers successfully added
pub fn add_signers_for_psbt(
    wallet: &mut Wallet,
    psbt: &Psbt,
    wallet_id: &str,
    device_id: &str,
) -> Result<i32, Status> {
    // Validate device_id is provided
    if device_id.is_empty() {
        return Err(Status::invalid_argument(
            "Device ID is required for signing",
        ));
    }

    // Get wallet to extract user_id
    let stored_wallet = db::get_wallet(wallet_id)
        .map_err(|e| Status::internal(format!("Failed to get wallet: {}", e)))?;

    // Get the specific system managed key for the provided device_id
    let key = db::get_managed_key(&stored_wallet.user_id, device_id, "system")
        .map_err(|e| {
            Status::internal(format!("Failed to get key for device {}: {}", device_id, e))
        })?
        .ok_or_else(|| {
            Status::not_found(format!("No system key found for device {}", device_id))
        })?;

    // Verify the key is a system key with private key material
    if key.key_type != "system" || !key.has_private_key_material() {
        return Err(Status::invalid_argument(format!(
            "Device {} is not a system managed key or lacks private key material",
            device_id
        )));
    }

    info!("Using device {} for signing operation", device_id);

    // Collect all derivation paths needed from the PSBT inputs
    let mut required_derivations: HashSet<(KeychainKind, u32)> = HashSet::new();

    for (i, input) in psbt.inputs.iter().enumerate() {
        // For each input, find what derivation index was used
        if let Some(utxo) = &input.witness_utxo {
            // Try to get derivation info from the wallet for this script pubkey
            if let Some((keychain, index)) = wallet.derivation_of_spk(utxo.script_pubkey.clone()) {
                debug!("Input {} requires key at {:?}/{}", i, keychain, index);
                required_derivations.insert((keychain, index));
            }
        }

        // Also check BIP32 derivation paths in the PSBT
        for (_pk, (fingerprint, path)) in &input.bip32_derivation {
            // Path is like m/84'/1'/0'/0/5 - we want the last two components (chain/index)
            if let Some(index) = path.into_iter().last() {
                let chain_index = if path.len() >= 2 {
                    path[path.len() - 2]
                } else {
                    bdk_wallet::bitcoin::bip32::ChildNumber::from_normal_idx(0).unwrap()
                };

                let keychain = if u32::from(chain_index) == 0 {
                    KeychainKind::External
                } else {
                    KeychainKind::Internal
                };

                debug!(
                    "Input {} has BIP32 path for {:?}/{} (fingerprint: {:?})",
                    i,
                    keychain,
                    u32::from(*index),
                    fingerprint
                );
                required_derivations.insert((keychain, u32::from(*index)));
            }
        }

        // Check Taproot key origins as well
        for (_pk, (leaf_hashes, (fingerprint, path))) in &input.tap_key_origins {
            if let Some(index) = path.into_iter().last() {
                let chain_index = if path.len() >= 2 {
                    path[path.len() - 2]
                } else {
                    bdk_wallet::bitcoin::bip32::ChildNumber::from_normal_idx(0).unwrap()
                };

                let keychain = if u32::from(chain_index) == 0 {
                    KeychainKind::External
                } else {
                    KeychainKind::Internal
                };

                debug!("Input {} has Taproot origin for {:?}/{} (fingerprint: {:?}, leaf_hashes: {:?})",
                    i, keychain, u32::from(*index), fingerprint, leaf_hashes);
                required_derivations.insert((keychain, u32::from(*index)));
            }
        }
    }

    if required_derivations.is_empty() {
        warn!("No derivation paths found in PSBT - attempting to derive common addresses");
        // Add a few common derivations as fallback
        for keychain in [KeychainKind::External, KeychainKind::Internal] {
            for i in 0..5 {
                required_derivations.insert((keychain, i));
            }
        }
    }

    info!(
        "Need to add signers for {} unique derivation paths",
        required_derivations.len()
    );

    // Determine the signer context based on the PSBT input type.
    // If inputs have tap_key_origins -> taproot (check internal vs script path).
    // If inputs have bip32_derivation but no tap_key_origins -> segwit v0.
    let device_fingerprint_str = &key.fingerprint;
    let device_fp = bdk_wallet::bitcoin::bip32::Fingerprint::from_str(device_fingerprint_str)
        .unwrap_or_default();

    let is_taproot = psbt.inputs.iter().any(|input| !input.tap_key_origins.is_empty());
    let mut device_is_internal_key = true;

    if is_taproot {
        let mut found_in_origins = false;
        for input in &psbt.inputs {
            for (_pk, (leaf_hashes, (fp, _path))) in &input.tap_key_origins {
                if *fp == device_fp {
                    found_in_origins = true;
                    if !leaf_hashes.is_empty() {
                        device_is_internal_key = false;
                    }
                }
            }
        }
        if found_in_origins {
            info!(
                "Device {} (fp: {}) detected as {} taproot key",
                device_id,
                device_fingerprint_str,
                if device_is_internal_key { "internal (keypath)" } else { "script path" }
            );
        } else {
            info!(
                "Device {} (fp: {}) not found in tap_key_origins, defaulting to internal key",
                device_id, device_fingerprint_str
            );
        }
    } else {
        info!(
            "Device {} (fp: {}) detected as segwit v0 signer",
            device_id, device_fingerprint_str
        );
    }

    // Now add signers only for the specific derivations we need
    let secp = secp256k1::Secp256k1::new();
    let mut signers_added = 0;

    // Process only the single specified device key
    // Use tpriv which contains the account-level xpriv (m/84'/1'/0')
    // The xpriv field now contains the root key (m/)
    if let Some(tpriv_str) = &key.tpriv {
        match Xpriv::from_str(tpriv_str) {
            Ok(account_xpriv) => {
                debug!("Adding signers from key (fingerprint: {})", key.fingerprint);

                // Add a signer for each required derivation
                for (keychain, index) in &required_derivations {
                    // Derive the specific key needed
                    // account_xpriv is at m/84'/1'/0', we need m/84'/1'/0'/chain/index
                    let chain_num = match keychain {
                        KeychainKind::External => 0,
                        KeychainKind::Internal => 1,
                    };

                    let path = DerivationPath::from_str(&format!("m/{}/{}", chain_num, index))
                        .map_err(|e| Status::internal(format!("Invalid derivation path: {}", e)))?;

                    match account_xpriv.derive_priv(&secp, &path) {
                        Ok(derived_xpriv) => {
                            let private_key = derived_xpriv.to_priv();
                            let signer_context = if is_taproot {
                                SignerContext::Tap {
                                    is_internal_key: device_is_internal_key,
                                }
                            } else {
                                SignerContext::Segwitv0
                            };
                            let signer = SignerWrapper::new(private_key, signer_context);
                            wallet.add_signer(*keychain, SignerOrdering(200), Arc::new(signer));

                            signers_added += 1;
                            debug!(
                                "✓ Added signer for {:?}/{} from {} (is_internal_key: {})",
                                keychain, index, key.device_id, device_is_internal_key
                            );
                        }
                        Err(e) => {
                            error!("Failed to derive key at {:?}/{}: {}", keychain, index, e);
                        }
                    }
                }
            }
            Err(e) => {
                error!(
                    "Failed to parse account xpriv (tpriv) for key {}: {}",
                    key.device_id, e
                );
                return Err(Status::internal(format!(
                    "Failed to parse private key for device {}: {}",
                    key.device_id, e
                )));
            }
        }
    } else {
        return Err(Status::internal(format!(
            "Device {} has no tpriv (account-level xpriv) stored",
            key.device_id
        )));
    }

    info!(
        "✅ Added {} signers to wallet for signing operation",
        signers_added
    );
    Ok(signers_added)
}

/// Enhanced PSBT signing function that supports taproot leaf-specific signing
///
/// Signers are now added on-demand via add_signers_for_psbt() before calling this function
pub fn sign_psbt_with_taproot_support(
    wallet: &bdk_wallet::Wallet,
    psbt: &mut Psbt,
    wallet_id: &str,
) -> Result<Option<Psbt>, Status> {
    info!(
        "=== Starting PSBT Signing Process for wallet: {} ===",
        wallet_id
    );

    // DEBUG: Log PSBT details before signing
    debug!(
        "PSBT has {} inputs and {} outputs",
        psbt.unsigned_tx.input.len(),
        psbt.unsigned_tx.output.len()
    );

    // Check if this PSBT has taproot inputs and log detailed info
    let has_taproot_inputs = psbt.inputs.iter().enumerate().any(|(i, input)| {
        let is_taproot = input.tap_internal_key.is_some();
        if is_taproot {
            debug!("Input {} is Taproot:", i);
            debug!("  - tap_internal_key: {:?}", input.tap_internal_key);
            debug!("  - tap_merkle_root: {:?}", input.tap_merkle_root);
            debug!("  - tap_key_origins count: {}", input.tap_key_origins.len());
            debug!("  - tap_scripts count: {}", input.tap_scripts.len());

            // Log key origins for debugging fingerprint matching
            for (pk, (leaf_hashes, key_source)) in &input.tap_key_origins {
                debug!("  - Key origin: pk={:?}, fingerprint={:?}, derivation_path={:?}, leaf_hashes={:?}",
                    pk, key_source.0, key_source.1, leaf_hashes);
            }
        }
        is_taproot
    });

    // Sign without finalization to allow separate finalization step
    let sign_options = SignOptions {
        try_finalize: false, // Don't finalize - allow explicit finalization step
        ..Default::default()
    };

    if has_taproot_inputs {
        info!("📝 Signing Taproot PSBT without finalization (explicit finalize step required)");
    }

    // DEBUG: Check wallet's signing capabilities before signing
    debug!("Wallet network: {:?}", wallet.network());

    // Log PSBT state before signing
    debug!("=== PSBT State BEFORE Signing ===");
    for (i, input) in psbt.inputs.iter().enumerate() {
        debug!(
            "Input {}: tap_key_sig={}, tap_script_sigs count={}",
            i,
            input.tap_key_sig.is_some(),
            input.tap_script_sigs.len()
        );
    }

    // Sign the PSBT
    info!("🔐 Calling wallet.sign() with try_finalize=false...");
    match wallet.sign(psbt, sign_options) {
        Ok(signed_all) => {
            info!(
                "✅ BDK sign() returned successfully, signed_all_inputs: {}",
                signed_all
            );

            if !signed_all {
                warn!("⚠️ WARNING: Not all inputs were signed! This suggests signers might be missing or mismatched.");
            }

            // Log PSBT state after signing with detailed info
            info!("=== PSBT State AFTER Signing ===");
            let mut any_signatures = false;
            for (i, input) in psbt.inputs.iter().enumerate() {
                let has_tap_key_sig = input.tap_key_sig.is_some();
                let tap_script_sigs_count = input.tap_script_sigs.len();
                let partial_sigs_count = input.partial_sigs.len();
                let has_witness = input.final_script_witness.is_some();

                if has_tap_key_sig {
                    info!("✓ Input {}: HAS tap_key_sig (keypath spend signature)", i);
                    any_signatures = true;
                }
                if tap_script_sigs_count > 0 {
                    info!(
                        "✓ Input {}: HAS {} tap_script_sigs (script path signatures)",
                        i, tap_script_sigs_count
                    );
                    any_signatures = true;
                }
                if partial_sigs_count > 0 {
                    info!(
                        "✓ Input {}: HAS {} partial_sigs (segwit/legacy signatures)",
                        i, partial_sigs_count
                    );
                    any_signatures = true;
                }
                if has_witness {
                    info!(
                        "✓ Input {}: HAS final_script_witness (finalized signature)",
                        i
                    );
                    any_signatures = true;
                }
                if !has_tap_key_sig && tap_script_sigs_count == 0 && partial_sigs_count == 0 && !has_witness {
                    error!(
                        "✗ Input {}: NO SIGNATURES (no tap_key_sig, tap_script_sigs, partial_sigs, or witness)",
                        i
                    );
                }

                // Log detailed signature info
                if has_tap_key_sig {
                    debug!("  Input {} tap_key_sig: {:?}", i, input.tap_key_sig);
                }
                for (pk, sig) in &input.tap_script_sigs {
                    debug!("  Input {} tap_script_sig for pk {:?}: {:?}", i, pk, sig);
                }
            }

            if !any_signatures {
                error!("❌ CRITICAL: No signatures were added to any inputs!");
                error!("This indicates the signers are not properly configured or fingerprints don't match.");
            }

            Ok(Some(psbt.clone()))
        }
        Err(e) => {
            error!("❌ BDK signing failed with error: {:?}", e);
            error!("Error details: {}", e);
            Err(Status::internal(format!("Failed to sign PSBT: {}", e)))
        }
    }
}

/// Map a taproot leaf hash to the BDK policy-path indices needed to spend
/// via that leaf.
///
/// Accepts two leaf-hash forms emitted by `wallet/advanced/taproot.rs`:
/// - `"keypath"` — the primary spends via the taproot internal key. Resolves
///   to `vec![0]` regardless of the descriptor structure.
/// - A hex-encoded `TapLeafHash` — the primary or one of the recoveries
///   spends via a script leaf in the taptree. Requires a `LianaDescriptor`
///   so we can derive the child-zero PSBT input, populate `tap_key_origins`
///   via `update_psbt_in`, and match the leaf hash against each path's
///   signer fingerprints.
///
/// Returns the `policy_path` map BDK's `TxBuilder::policy_path` consumes.
/// BDK orders policy children as `[primary, recovery_1, recovery_2, …]` —
/// matching Liana's `BTreeMap<u16, _>` recovery iteration order
/// (ascending timelock) — so the primary's leaf hash always resolves to
/// `vec![0]` and the Nth recovery to `vec![N]`.
pub fn resolve_policy_path_from_leaf(
    wallet: &bdk_wallet::Wallet,
    leaf_hash: &str,
    liana_descriptor: Option<&LianaDescriptor>,
) -> Result<BTreeMap<String, Vec<usize>>, Status> {
    let external_policy = wallet
        .policies(KeychainKind::External)
        .map_err(|e| Status::internal(format!("Failed to get policies: {}", e)))?
        .ok_or_else(|| Status::internal("No external policy available"))?;

    let mut policy_path = BTreeMap::new();

    if leaf_hash == "keypath" {
        info!("Using taproot key path spending - selecting policy index 0");
        validate_policy_path(&external_policy, &[0])?;
        policy_path.insert(external_policy.id.clone(), vec![0]);
        return Ok(policy_path);
    }

    let descriptor = liana_descriptor.ok_or_else(|| {
        Status::invalid_argument(format!(
            "Leaf hash '{}' provided but wallet has no Liana descriptor",
            leaf_hash
        ))
    })?;

    let fp_to_leaves = build_fingerprint_leaf_map(descriptor)?;
    let liana_policy = descriptor.policy();

    if path_owns_leaf(liana_policy.primary_path(), leaf_hash, &fp_to_leaves) {
        info!(
            "Matched hex leaf hash '{}' to primary path (policy child index 0)",
            leaf_hash
        );
        validate_policy_path(&external_policy, &[0])?;
        policy_path.insert(external_policy.id.clone(), vec![0]);
        return Ok(policy_path);
    }

    for (recovery_idx, (_timelock, path_info)) in
        liana_policy.recovery_paths().iter().enumerate()
    {
        if path_owns_leaf(path_info, leaf_hash, &fp_to_leaves) {
            let policy_child_index = recovery_idx + 1;
            info!(
                "Matched hex leaf hash '{}' to recovery path {} (policy child index {})",
                leaf_hash, recovery_idx, policy_child_index
            );
            validate_policy_path(&external_policy, &[policy_child_index])?;
            policy_path.insert(external_policy.id.clone(), vec![policy_child_index]);
            return Ok(policy_path);
        }
    }

    Err(Status::invalid_argument(format!(
        "Leaf hash '{}' does not match any spending path in the descriptor",
        leaf_hash
    )))
}

/// Derive the descriptor at child 0, populate a default `PsbtInput` via Liana's
/// `update_psbt_in`, and read out the `tap_key_origins` map as a
/// fingerprint → leaf-hashes lookup.
fn build_fingerprint_leaf_map(
    descriptor: &LianaDescriptor,
) -> Result<HashMap<Fingerprint, HashSet<String>>, Status> {
    let secp = secp256k1::Secp256k1::verification_only();
    let child = bdk_wallet::bitcoin::bip32::ChildNumber::from_normal_idx(0)
        .map_err(|e| Status::internal(format!("Failed to build child number: {}", e)))?;
    let derived = descriptor.receive_descriptor().derive(child, &secp);

    let mut psbt_in = PsbtInput::default();
    derived.update_psbt_in(&mut psbt_in);

    let mut map: HashMap<Fingerprint, HashSet<String>> = HashMap::new();
    for (leaf_hashes, (fp, _path)) in psbt_in.tap_key_origins.values() {
        let entry = map.entry(*fp).or_default();
        for lh in leaf_hashes {
            entry.insert(hex::encode(lh.to_byte_array()));
        }
    }
    debug!("tap_key_origins fingerprint→leaf-hashes map: {:?}", map);
    Ok(map)
}

/// Returns true when at least one signer fingerprint in `path_info` is bound
/// to `leaf_hash` in the descriptor's PSBT-derived leaf map.
fn path_owns_leaf(
    path_info: &crate::PathInfo,
    leaf_hash: &str,
    fp_to_leaves: &HashMap<Fingerprint, HashSet<String>>,
) -> bool {
    let (_, fg_map) = path_info.thresh_origins();
    fg_map
        .keys()
        .any(|fp| fp_to_leaves.get(fp).is_some_and(|set| set.contains(leaf_hash)))
}

/// Sanity-check that BDK accepts the proposed policy path before we hand it to
/// the transaction builder. Surfaces structural mismatches as `Status::internal`
/// errors instead of letting them blow up later in `tx_builder.finish()`.
fn validate_policy_path(
    policy: &bdk_wallet::descriptor::Policy,
    indices: &[usize],
) -> Result<(), Status> {
    let mut probe = BTreeMap::new();
    probe.insert(policy.id.clone(), indices.to_vec());
    policy
        .get_condition(&probe)
        .map(|_| ())
        .map_err(|e| Status::internal(format!("Policy rejected path {:?}: {:?}", indices, e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    use bdk_wallet::bitcoin::bip32::{Xpriv, Xpub};
    use bdk_wallet::bitcoin::secp256k1::Secp256k1;
    use bdk_wallet::bitcoin::Network;
    use bdk_wallet::Wallet;

    use crate::db::StoredManagedKey;
    use crate::wallet::advanced::shape::WalletShape;
    use crate::wallet::advanced::{descriptor, shape, taproot};
    use crate::wallet::advanced::{
        PolicyType, PreferredScriptType, SpendingCondition, WalletSpec,
    };

    fn make_key(seed: u64) -> StoredManagedKey {
        let mut bytes = [0u8; 64];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(Network::Testnet, &bytes).unwrap();
        let xpub = Xpub::from_priv(&secp, &xpriv);
        let fp = format!("{:08x}", xpriv.fingerprint(&secp));
        let liana_xpub = format!("[{}]{}/<0;1>/*", fp, xpub);
        StoredManagedKey::new_customer_key(
            "user-1",
            &format!("d{}", seed),
            "test",
            &liana_xpub,
            &fp,
            "m/84'/1'/0'",
        )
    }

    fn build_timelocked_wallet() -> (
        Wallet,
        crate::LianaDescriptor,
        Vec<crate::wallet::advanced::TaprootLeafInfo>,
    ) {
        let k1 = make_key(1);
        let k2 = make_key(2);
        let k3 = make_key(3);

        let mut keys = BTreeMap::new();
        keys.insert(k1.device_id.clone(), k1);
        keys.insert(k2.device_id.clone(), k2);
        keys.insert(k3.device_id.clone(), k3);

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

        let metadata =
            taproot::extract(&primary_id, &primary, &recoveries, &liana_desc).unwrap();

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

        let resolved = resolve_policy_path_from_leaf(&wallet, &primary.leaf_hash, Some(&liana_desc))
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

        let resolved = resolve_policy_path_from_leaf(
            &wallet,
            &recovery.leaf_hash,
            Some(&liana_desc),
        )
        .expect("resolve recovery leaf");
        let path = resolved.values().next().expect("policy path entry");
        assert_eq!(path, &vec![1]);
    }

    #[test]
    fn unknown_leaf_returns_invalid_argument() {
        let (wallet, liana_desc, _) = build_timelocked_wallet();
        let result = resolve_policy_path_from_leaf(
            &wallet,
            "deadbeef",
            Some(&liana_desc),
        );
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
