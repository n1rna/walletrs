//! Spending-path selector → BDK policy-path resolver for timelocked
//! policies.
//!
//! The selector is what `policy_core::taproot::extract` emitted for the
//! spending condition:
//! - `"keypath"` — a taproot primary that spends via the internal key.
//!   Resolves to policy child 0.
//! - A hex-encoded `TapLeafHash` — the primary or a recovery in a taproot
//!   script leaf. BDK orders a taproot descriptor's policy children as
//!   `[key spend, leaf_0, leaf_1, …]` with the leaves in taptree order,
//!   which the policy compiler picks and which is *not* ascending
//!   timelock, so the leaf resolves to one plus its taptree position.
//! - `"primary"` / `"older:<blocks>"` — a SegWit v0 policy, which has no
//!   leaves. BDK mirrors the script's structure there, so the branch is
//!   found by walking the policy tree for the one enforcing that timelock.
//!   An empty selector and `"keypath"` also mean the primary.
//!
//! Returns the `policy_path` map BDK's `TxBuilder::policy_path` consumes.

use std::collections::BTreeMap;

use bdk_wallet::bitcoin::Sequence;
use bdk_wallet::descriptor::policy::{Policy, SatisfiableItem};
use bdk_wallet::KeychainKind;
use liana::descriptors::LianaDescriptor;
use policy_core::taproot::SEGWIT_PRIMARY_SELECTOR;

use crate::error::WalletRuntimeError;
use crate::policy_descriptor::{taptree, PolicyDescriptor, RecoveryOnlyDescriptor};

/// Resolve a leaf hash against a wallet's stored policy descriptor.
///
/// Same contract as `resolve_policy_path_from_leaf`, and additionally
/// handles recovery-only wallets (unspendable primary), whose descriptor
/// Liana cannot parse.
pub fn resolve_policy_path(
    wallet: &bdk_wallet::Wallet,
    leaf_hash: &str,
    policy_descriptor: Option<&PolicyDescriptor>,
) -> Result<BTreeMap<String, Vec<usize>>, WalletRuntimeError> {
    match policy_descriptor {
        Some(PolicyDescriptor::RecoveryOnly(desc)) => {
            resolve_recovery_only_path(wallet, leaf_hash, desc)
        }
        Some(PolicyDescriptor::Liana(desc)) => {
            resolve_policy_path_from_leaf(wallet, leaf_hash, Some(desc))
        }
        None => resolve_policy_path_from_leaf(wallet, leaf_hash, None),
    }
}

fn resolve_recovery_only_path(
    wallet: &bdk_wallet::Wallet,
    leaf_hash: &str,
    descriptor: &RecoveryOnlyDescriptor,
) -> Result<BTreeMap<String, Vec<usize>>, WalletRuntimeError> {
    if leaf_hash == "keypath" {
        return Err(WalletRuntimeError::PolicyPath(
            "leaf hash 'keypath' does not match any spending path in the descriptor: \
             the primary path is unspendable"
                .to_string(),
        ));
    }
    let child_index = descriptor.policy_child_index(leaf_hash).ok_or_else(|| {
        WalletRuntimeError::PolicyPath(format!(
            "leaf hash '{}' does not match any spending path in the descriptor",
            leaf_hash
        ))
    })?;

    let external_policy = wallet
        .policies(KeychainKind::External)
        .map_err(|e| WalletRuntimeError::PolicyPath(format!("get policies: {}", e)))?
        .ok_or_else(|| WalletRuntimeError::PolicyPath("no external policy".to_string()))?;
    validate_policy_path(&external_policy, &[child_index])?;

    let mut policy_path = BTreeMap::new();
    policy_path.insert(external_policy.id.clone(), vec![child_index]);
    Ok(policy_path)
}

pub fn resolve_policy_path_from_leaf(
    wallet: &bdk_wallet::Wallet,
    leaf_hash: &str,
    policy_descriptor: Option<&LianaDescriptor>,
) -> Result<BTreeMap<String, Vec<usize>>, WalletRuntimeError> {
    let external_policy = wallet
        .policies(KeychainKind::External)
        .map_err(|e| WalletRuntimeError::PolicyPath(format!("get policies: {}", e)))?
        .ok_or_else(|| WalletRuntimeError::PolicyPath("no external policy".to_string()))?;

    let tree = match policy_descriptor {
        Some(descriptor) => match taptree(&descriptor.to_string())? {
            Some(tree) => Some(tree),
            None => return resolve_segwit_path(&external_policy, leaf_hash),
        },
        None => None,
    };

    let mut policy_path = BTreeMap::new();

    if leaf_hash == "keypath" {
        validate_policy_path(&external_policy, &[0])?;
        policy_path.insert(external_policy.id.clone(), vec![0]);
        return Ok(policy_path);
    }

    let tree = tree.ok_or_else(|| {
        WalletRuntimeError::PolicyPath(format!(
            "leaf hash '{}' provided but wallet has no policy descriptor",
            leaf_hash
        ))
    })?;

    let child_index = tree.policy_child_index(leaf_hash).ok_or_else(|| {
        WalletRuntimeError::PolicyPath(format!(
            "leaf hash '{}' does not match any spending path in the descriptor",
            leaf_hash
        ))
    })?;
    validate_policy_path(&external_policy, &[child_index])?;
    policy_path.insert(external_policy.id.clone(), vec![child_index]);
    Ok(policy_path)
}

/// Timelock a SegWit v0 selector asks for; `None` is the primary.
fn segwit_selector_timelock(selector: &str) -> Result<Option<u16>, WalletRuntimeError> {
    if selector.is_empty() || selector == "keypath" || selector == SEGWIT_PRIMARY_SELECTOR {
        return Ok(None);
    }
    selector
        .strip_prefix("older:")
        .and_then(|blocks| blocks.parse::<u16>().ok())
        .map(Some)
        .ok_or_else(|| {
            WalletRuntimeError::PolicyPath(format!(
                "leaf hash '{}' does not match any spending path in the descriptor",
                selector
            ))
        })
}

fn resolve_segwit_path(
    policy: &Policy,
    selector: &str,
) -> Result<BTreeMap<String, Vec<usize>>, WalletRuntimeError> {
    let timelock = segwit_selector_timelock(selector)?;
    policy_path_enforcing(policy, timelock).ok_or_else(|| {
        WalletRuntimeError::PolicyPath(format!(
            "leaf hash '{}' does not match any spending path in the descriptor",
            selector
        ))
    })
}

/// A way through `policy` that enforces exactly `timelock` (`None`: no
/// relative timelock at all). Several ways can qualify, for example the
/// keys of a 1-of-n primary sitting in separate branches; they build the
/// same transaction, so the first is returned.
pub(crate) fn policy_path_enforcing(
    policy: &Policy,
    timelock: Option<u16>,
) -> Option<BTreeMap<String, Vec<usize>>> {
    let wanted = timelock.map(Sequence::from_height);
    policy_path_choices(policy).into_iter().find(|path| {
        policy
            .get_condition(path)
            .is_ok_and(|condition| condition.csv == wanted)
    })
}

/// Every way to pick branches wherever `policy` needs a choice.
fn policy_path_choices(policy: &Policy) -> Vec<BTreeMap<String, Vec<usize>>> {
    let (items, threshold) = match &policy.item {
        SatisfiableItem::Thresh { items, threshold } if policy.requires_path() => {
            (items, *threshold)
        }
        _ => return vec![BTreeMap::new()],
    };

    let mut choices = Vec::new();
    for picked in index_combinations(items.len(), threshold) {
        let mut partial = vec![BTreeMap::from([(policy.id.clone(), picked.clone())])];
        for index in &picked {
            let sub_choices = policy_path_choices(&items[*index]);
            partial = partial
                .iter()
                .flat_map(|base| {
                    sub_choices.iter().map(move |sub| {
                        let mut merged = base.clone();
                        merged.extend(sub.clone());
                        merged
                    })
                })
                .collect();
        }
        choices.extend(partial);
    }
    choices
}

/// All ascending `k`-element subsets of `0..n`.
fn index_combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    fn extend(
        start: usize,
        n: usize,
        k: usize,
        current: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if current.len() == k {
            out.push(current.clone());
            return;
        }
        for index in start..n {
            current.push(index);
            extend(index + 1, n, k, current, out);
            current.pop();
        }
    }
    let mut out = Vec::new();
    extend(0, n, k, &mut Vec::new(), &mut out);
    out
}

fn validate_policy_path(
    policy: &bdk_wallet::descriptor::Policy,
    indices: &[usize],
) -> Result<(), WalletRuntimeError> {
    let mut probe = BTreeMap::new();
    probe.insert(policy.id.clone(), indices.to_vec());
    policy.get_condition(&probe).map(|_| ()).map_err(|e| {
        WalletRuntimeError::PolicyPath(format!("policy rejected {:?}: {:?}", indices, e))
    })
}
