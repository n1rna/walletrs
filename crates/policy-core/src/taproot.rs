//! Spending-path metadata for timelocked-policy wallets.
//!
//! Takes a built `LianaDescriptor` plus the structured shape inputs and
//! returns, for every spending condition, the selector a client passes
//! back to spend through it.
//!
//! Taproot: the selector is the hex `TapLeafHash` of the condition's leaf,
//! found by matching the leaf's exact keys and timelock, since one signer
//! may hold a key in several conditions. Two cases have no leaf of their
//! own and use the `"keypath"` sentinel instead: a single-key primary,
//! which is the internal key, and a 1-of-n primary, where the compiler
//! makes one key the internal key and gives each of the others its own
//! leaf.
//!
//! SegWit v0: there are no leaves. The selectors are `"primary"` and
//! `"older:<blocks>"`, which the resolver maps onto the script's branches.

use std::collections::BTreeSet;

use bdk_wallet::bitcoin::bip32::ChildNumber;
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::psbt::Input as PsbtInput;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use liana::descriptors::LianaDescriptor;
use miniscript::descriptor::DescriptorPublicKey;

use crate::error::PolicyError;
use crate::shape::{PolicyPath, RecoveryPath};
use crate::spec::PolicyType;
use crate::taptree::{TapLeaf, TapTree};

#[derive(Debug, Clone)]
pub struct TaprootLeafInfo {
    pub leaf_hash: String,
    pub spending_condition_id: String,
    pub script_path: Vec<String>,
    pub timelock: Option<u16>,
    pub policy_type: PolicyType,
    pub threshold: Option<usize>,
    pub description: String,
}

#[derive(Debug, Clone, Default)]
pub struct TaprootMetadata {
    pub leaves: Vec<TaprootLeafInfo>,
    pub internal_key: Option<String>,
    pub merkle_root: Option<String>,
}

pub fn extract(
    primary_id: &str,
    primary: &PolicyPath,
    recoveries: &[RecoveryPath],
    descriptor: &LianaDescriptor,
) -> Result<TaprootMetadata, PolicyError> {
    let Some(tree) = TapTree::parse(&descriptor.to_string())? else {
        return Ok(segwit_metadata(primary_id, primary, recoveries));
    };

    let psbt_input = populate_dummy_psbt_input(descriptor)?;
    let internal_key = psbt_input
        .tap_internal_key
        .map(|k| hex::encode(k.serialize()));
    let merkle_root = psbt_input
        .tap_merkle_root
        .map(|r| hex::encode(r.to_byte_array()));

    let mut leaves = Vec::new();

    let primary_leaf_hash = match primary {
        PolicyPath::Single(_) => None,
        PolicyPath::Multi { .. } => match leaf_for(&tree, primary, None) {
            Some(leaf) => Some(leaf.leaf_hash.clone()),
            None if spread_over_key_path(&tree, primary) => None,
            None => {
                return Err(PolicyError::DescriptorGeneration(format!(
                    "Failed to extract taproot leaf hash for primary condition `{}`",
                    primary_id
                )))
            }
        },
    };
    if primary_leaf_hash.is_none() {
        leaves.push(primary_keypath_leaf(primary, primary_id));
    }

    for recovery in recoveries.iter() {
        let leaf = leaf_for(&tree, &recovery.path, Some(recovery.timelock)).ok_or_else(|| {
            PolicyError::DescriptorGeneration(format!(
                "Failed to extract taproot leaf hash for recovery condition `{}`",
                recovery.id
            ))
        })?;
        leaves.push(recovery_leaf(recovery, leaf.leaf_hash.clone()));
    }

    if let Some(leaf_hash) = primary_leaf_hash {
        leaves.push(TaprootLeafInfo {
            leaf_hash,
            spending_condition_id: primary_id.to_string(),
            script_path: Vec::new(),
            timelock: None,
            policy_type: policy_path_kind(primary),
            threshold: policy_path_threshold(primary),
            description: format_description("Primary", primary, None),
        });
    }

    Ok(TaprootMetadata {
        leaves,
        internal_key,
        merkle_root,
    })
}

/// Selector of the primary path of a SegWit v0 policy.
pub const SEGWIT_PRIMARY_SELECTOR: &str = "primary";

/// Selector of the recovery path of a SegWit v0 policy that opens after
/// `timelock` blocks.
pub fn segwit_recovery_selector(timelock: u16) -> String {
    format!("older:{}", timelock)
}

fn segwit_metadata(
    primary_id: &str,
    primary: &PolicyPath,
    recoveries: &[RecoveryPath],
) -> TaprootMetadata {
    let mut leaves = vec![TaprootLeafInfo {
        leaf_hash: SEGWIT_PRIMARY_SELECTOR.to_string(),
        spending_condition_id: primary_id.to_string(),
        script_path: Vec::new(),
        timelock: None,
        policy_type: policy_path_kind(primary),
        threshold: policy_path_threshold(primary),
        description: format_description("Primary", primary, None),
    }];
    leaves.extend(
        recoveries
            .iter()
            .map(|recovery| recovery_leaf(recovery, segwit_recovery_selector(recovery.timelock))),
    );
    TaprootMetadata {
        leaves,
        internal_key: None,
        merkle_root: None,
    }
}

fn recovery_leaf(recovery: &RecoveryPath, leaf_hash: String) -> TaprootLeafInfo {
    TaprootLeafInfo {
        leaf_hash,
        spending_condition_id: recovery.id.clone(),
        script_path: Vec::new(),
        timelock: Some(recovery.timelock),
        policy_type: policy_path_kind(&recovery.path),
        threshold: policy_path_threshold(&recovery.path),
        description: format_description("Recovery", &recovery.path, Some(recovery.timelock)),
    }
}

/// The leaf holding exactly this path's keys behind this timelock.
fn leaf_for<'a>(
    tree: &'a TapTree,
    path: &PolicyPath,
    timelock: Option<u16>,
) -> Option<&'a TapLeaf> {
    let wanted = key_set(path.keys().into_iter());
    tree.leaves
        .iter()
        .find(|leaf| leaf.timelock == timelock && key_set(leaf.keys.iter()) == wanted)
}

/// Whether the path is one key as the internal key plus one untimelocked
/// single-key leaf for each of its other keys: how the compiler lays out
/// a 1-of-n primary.
fn spread_over_key_path(tree: &TapTree, path: &PolicyPath) -> bool {
    let keys = path.keys();
    keys.contains(&&tree.internal_key)
        && keys.iter().all(|key| {
            *key == &tree.internal_key
                || tree.leaves.iter().any(|leaf| {
                    leaf.timelock.is_none() && leaf.keys.len() == 1 && &leaf.keys[0] == *key
                })
        })
}

fn key_set<'a>(keys: impl Iterator<Item = &'a DescriptorPublicKey>) -> BTreeSet<String> {
    keys.map(|key| key.to_string()).collect()
}

fn populate_dummy_psbt_input(descriptor: &LianaDescriptor) -> Result<PsbtInput, PolicyError> {
    let secp = Secp256k1::verification_only();
    let child = ChildNumber::from_normal_idx(0).map_err(|e| {
        PolicyError::DescriptorGeneration(format!("Failed to build child number: {}", e))
    })?;
    let derived = descriptor.receive_descriptor().derive(child, &secp);

    let mut psbt_input = PsbtInput::default();
    derived.update_psbt_in(&mut psbt_input);
    Ok(psbt_input)
}

fn policy_path_kind(path: &PolicyPath) -> PolicyType {
    match path {
        PolicyPath::Single(_) => PolicyType::Single,
        PolicyPath::Multi { .. } => PolicyType::Multi,
    }
}

fn policy_path_threshold(path: &PolicyPath) -> Option<usize> {
    match path {
        PolicyPath::Single(_) => None,
        PolicyPath::Multi { threshold, .. } => Some(*threshold),
    }
}

fn primary_keypath_leaf(primary: &PolicyPath, primary_id: &str) -> TaprootLeafInfo {
    TaprootLeafInfo {
        leaf_hash: "keypath".to_string(),
        spending_condition_id: primary_id.to_string(),
        script_path: Vec::new(),
        timelock: None,
        policy_type: policy_path_kind(primary),
        threshold: policy_path_threshold(primary),
        description: match primary {
            PolicyPath::Single(_) => {
                "Primary spending path (key path - immediate access)".to_string()
            }
            PolicyPath::Multi { .. } => format_description("Primary", primary, None),
        },
    }
}

fn format_description(label: &str, path: &PolicyPath, timelock: Option<u16>) -> String {
    let kind = match path {
        PolicyPath::Single(_) => "single-sig".to_string(),
        PolicyPath::Multi { threshold, keys } => format!("{}-of-{}", threshold, keys.len()),
    };
    match timelock {
        Some(t) => format!("{} path (timelock: {} blocks, {})", label, t, kind),
        None => format!("{} path ({})", label, kind),
    }
}
