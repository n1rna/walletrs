//! Liana taproot leaf-hash → BDK policy-path resolver.
//!
//! Lifted (with surface-level error-type changes) from
//! `walletrs/crates/server/src/wallet/signer/mod.rs`.
//!
//! Accepts two leaf-hash forms emitted by `policy_core::taproot::extract`:
//! - `"keypath"` — the primary spends via the taproot internal key. Resolves
//!   to `vec![0]` regardless of the descriptor structure.
//! - A hex-encoded `TapLeafHash` — the primary or one of the recoveries
//!   spends via a script leaf in the taptree. Requires a `LianaDescriptor` so
//!   we can derive the child-zero PSBT input, populate `tap_key_origins` via
//!   `update_psbt_in`, and match the leaf hash against each path's signer
//!   fingerprints.
//!
//! Returns the `policy_path` map BDK's `TxBuilder::policy_path` consumes.
//! BDK orders policy children as `[primary, recovery_1, recovery_2, …]` —
//! matching Liana's `BTreeMap<u16, _>` recovery iteration order (ascending
//! timelock) — so the primary's leaf hash always resolves to `vec![0]` and
//! the Nth recovery to `vec![N]`.

use std::collections::{BTreeMap, HashMap, HashSet};

use bdk_wallet::bitcoin::bip32::{ChildNumber, Fingerprint};
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::psbt::Input as PsbtInput;
use bdk_wallet::bitcoin::secp256k1;
use bdk_wallet::KeychainKind;
use liana::descriptors::{LianaDescriptor, PathInfo};

use crate::error::WalletRuntimeError;

pub fn resolve_policy_path_from_leaf(
    wallet: &bdk_wallet::Wallet,
    leaf_hash: &str,
    liana_descriptor: Option<&LianaDescriptor>,
) -> Result<BTreeMap<String, Vec<usize>>, WalletRuntimeError> {
    let external_policy = wallet
        .policies(KeychainKind::External)
        .map_err(|e| WalletRuntimeError::PolicyPath(format!("get policies: {}", e)))?
        .ok_or_else(|| WalletRuntimeError::PolicyPath("no external policy".to_string()))?;

    let mut policy_path = BTreeMap::new();

    if leaf_hash == "keypath" {
        validate_policy_path(&external_policy, &[0])?;
        policy_path.insert(external_policy.id.clone(), vec![0]);
        return Ok(policy_path);
    }

    let descriptor = liana_descriptor.ok_or_else(|| {
        WalletRuntimeError::PolicyPath(format!(
            "leaf hash '{}' provided but wallet has no Liana descriptor",
            leaf_hash
        ))
    })?;

    let fp_to_leaves = build_fingerprint_leaf_map(descriptor)?;
    let liana_policy = descriptor.policy();

    if path_owns_leaf(liana_policy.primary_path(), leaf_hash, &fp_to_leaves) {
        validate_policy_path(&external_policy, &[0])?;
        policy_path.insert(external_policy.id.clone(), vec![0]);
        return Ok(policy_path);
    }

    for (recovery_idx, (_timelock, path_info)) in liana_policy.recovery_paths().iter().enumerate() {
        if path_owns_leaf(path_info, leaf_hash, &fp_to_leaves) {
            let policy_child_index = recovery_idx + 1;
            validate_policy_path(&external_policy, &[policy_child_index])?;
            policy_path.insert(external_policy.id.clone(), vec![policy_child_index]);
            return Ok(policy_path);
        }
    }

    Err(WalletRuntimeError::PolicyPath(format!(
        "leaf hash '{}' does not match any spending path in the descriptor",
        leaf_hash
    )))
}

fn build_fingerprint_leaf_map(
    descriptor: &LianaDescriptor,
) -> Result<HashMap<Fingerprint, HashSet<String>>, WalletRuntimeError> {
    let secp = secp256k1::Secp256k1::verification_only();
    let child = ChildNumber::from_normal_idx(0)
        .map_err(|e| WalletRuntimeError::PolicyPath(format!("child number: {}", e)))?;
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
    Ok(map)
}

fn path_owns_leaf(
    path_info: &PathInfo,
    leaf_hash: &str,
    fp_to_leaves: &HashMap<Fingerprint, HashSet<String>>,
) -> bool {
    let (_, fg_map) = path_info.thresh_origins();
    fg_map.keys().any(|fp| {
        fp_to_leaves
            .get(fp)
            .is_some_and(|set| set.contains(leaf_hash))
    })
}

fn validate_policy_path(
    policy: &bdk_wallet::descriptor::Policy,
    indices: &[usize],
) -> Result<(), WalletRuntimeError> {
    let mut probe = BTreeMap::new();
    probe.insert(policy.id.clone(), indices.to_vec());
    policy
        .get_condition(&probe)
        .map(|_| ())
        .map_err(|e| WalletRuntimeError::PolicyPath(format!("policy rejected {:?}: {:?}", indices, e)))
}
