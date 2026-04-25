//! Taproot leaf-hash extraction for Liana-policy wallets.
//!
//! Takes a built `LianaDescriptor` plus the structured shape inputs and
//! returns the leaf-hash, internal-key and merkle-root metadata that clients
//! need in order to drive script-path spends. The flow is:
//!
//! 1. Derive the descriptor at index 0 to get a definite-key descriptor.
//! 2. Populate a default `PsbtInput` via Liana's `update_psbt_in` — Liana
//!    fills in `tap_internal_key`, `tap_merkle_root` and a `tap_key_origins`
//!    map of `(xonly_pk -> (leaf_hashes, (fingerprint, deriv)))`.
//! 3. Walk the recovery paths in the BTreeMap iteration order (ascending
//!    timelock; matches BDK policy child indices `1..=N`) and find the leaf
//!    hash whose fingerprints intersect each path's signers.
//! 4. Add a `"keypath"` sentinel for the primary path when it spends via the
//!    taproot internal key, and a real leaf hash when the primary lives in
//!    the script tree (multisig primary).

use std::collections::{HashMap, HashSet};

use bdk_wallet::bitcoin::bip32::{ChildNumber, Fingerprint};
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::psbt::Input as PsbtInput;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;

use crate::wallet::advanced::error::WalletCreationError;
use crate::wallet::advanced::shape::{PolicyPath, RecoveryPath};
use crate::wallet::advanced::spec::PolicyType;
use crate::LianaDescriptor;

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
) -> Result<TaprootMetadata, WalletCreationError> {
    if !descriptor.is_taproot() {
        return Ok(TaprootMetadata::default());
    }

    let psbt_input = populate_dummy_psbt_input(descriptor)?;

    let internal_key = psbt_input
        .tap_internal_key
        .map(|k| hex::encode(k.serialize()));
    let merkle_root = psbt_input
        .tap_merkle_root
        .map(|r| hex::encode(r.to_byte_array()));

    let fp_to_leaves = collect_leaves_by_fingerprint(&psbt_input);
    let primary_in_taptree = matches!(primary, PolicyPath::Multi { .. });

    let mut leaves = Vec::new();

    if !primary_in_taptree {
        leaves.push(primary_keypath_leaf(primary, primary_id));
    }

    for recovery in recoveries.iter() {
        let leaf_hash = leaf_hash_for_path(&recovery.path, &fp_to_leaves).ok_or_else(|| {
            WalletCreationError::DescriptorGeneration(format!(
                "Failed to extract taproot leaf hash for recovery condition `{}`",
                recovery.id
            ))
        })?;
        leaves.push(TaprootLeafInfo {
            leaf_hash,
            spending_condition_id: recovery.id.clone(),
            script_path: Vec::new(),
            timelock: Some(recovery.timelock),
            policy_type: policy_path_kind(&recovery.path),
            threshold: policy_path_threshold(&recovery.path),
            description: format_description("Recovery", &recovery.path, Some(recovery.timelock)),
        });
    }

    if primary_in_taptree {
        let leaf_hash = leaf_hash_for_path(primary, &fp_to_leaves).ok_or_else(|| {
            WalletCreationError::DescriptorGeneration(format!(
                "Failed to extract taproot leaf hash for primary condition `{}`",
                primary_id
            ))
        })?;
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

fn populate_dummy_psbt_input(
    descriptor: &LianaDescriptor,
) -> Result<PsbtInput, WalletCreationError> {
    let secp = Secp256k1::verification_only();
    let child = ChildNumber::from_normal_idx(0).map_err(|e| {
        WalletCreationError::DescriptorGeneration(format!("Failed to build child number: {}", e))
    })?;
    let derived = descriptor.receive_descriptor().derive(child, &secp);

    let mut psbt_input = PsbtInput::default();
    derived.update_psbt_in(&mut psbt_input);
    Ok(psbt_input)
}

fn collect_leaves_by_fingerprint(psbt_input: &PsbtInput) -> HashMap<Fingerprint, HashSet<String>> {
    let mut map: HashMap<Fingerprint, HashSet<String>> = HashMap::new();
    for (leaf_hashes, (fp, _path)) in psbt_input.tap_key_origins.values() {
        let entry = map.entry(*fp).or_default();
        for lh in leaf_hashes {
            entry.insert(hex::encode(lh.to_byte_array()));
        }
    }
    map
}

fn leaf_hash_for_path(
    path: &PolicyPath,
    fp_to_leaves: &HashMap<Fingerprint, HashSet<String>>,
) -> Option<String> {
    let fingerprints = path_fingerprints(path);
    let mut intersection: Option<HashSet<String>> = None;

    for fp in &fingerprints {
        let Some(hashes) = fp_to_leaves.get(fp) else {
            continue;
        };
        intersection = Some(match intersection {
            None => hashes.clone(),
            Some(prev) => prev.intersection(hashes).cloned().collect(),
        });
    }

    intersection
        .and_then(|set| set.into_iter().min())
}

fn path_fingerprints(path: &PolicyPath) -> Vec<Fingerprint> {
    use std::str::FromStr;

    fn fp_of(key: &miniscript::descriptor::DescriptorPublicKey) -> Option<Fingerprint> {
        let key_str = key.to_string();
        let bracket_end = key_str.find(']')?;
        let inside = &key_str[1..bracket_end];
        let fp_str = inside.split('/').next()?;
        Fingerprint::from_str(fp_str).ok()
    }

    match path {
        PolicyPath::Single(k) => fp_of(k).into_iter().collect(),
        PolicyPath::Multi { keys, .. } => keys.iter().filter_map(fp_of).collect(),
    }
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
        description: "Primary spending path (key path - immediate access)".to_string(),
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
