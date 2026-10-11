//! Taproot leaf-hash → BDK policy-path resolver for timelocked policies.
//!
//! Lifted (with surface-level error-type changes) from
//! `walletrs/crates/server/src/wallet/signer/mod.rs`.
//!
//! Accepts two leaf-hash forms emitted by `policy_core::taproot::extract`:
//! - `"keypath"` — the primary spends via the taproot internal key. Resolves
//!   to `vec![0]` regardless of the descriptor structure.
//! - A hex-encoded `TapLeafHash` — the primary or one of the recoveries
//!   spends via a script leaf in the taptree. Requires the multipath
//!   policy descriptor so the leaf can be located in the taptree.
//!
//! Returns the `policy_path` map BDK's `TxBuilder::policy_path` consumes.
//! BDK orders a taproot descriptor's policy children as `[key spend,
//! leaf_0, leaf_1, …]` with the leaves in taptree order, which the policy
//! compiler picks and which is *not* ascending timelock. A leaf hash
//! therefore resolves to one plus its position in the taptree.

use std::collections::BTreeMap;

use bdk_wallet::KeychainKind;
use liana::descriptors::LianaDescriptor;

use crate::error::WalletRuntimeError;
use crate::policy_descriptor::{taptree_leaves, PolicyDescriptor, RecoveryOnlyDescriptor, TapLeaf};

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

    let mut policy_path = BTreeMap::new();

    if leaf_hash == "keypath" {
        validate_policy_path(&external_policy, &[0])?;
        policy_path.insert(external_policy.id.clone(), vec![0]);
        return Ok(policy_path);
    }

    let descriptor = policy_descriptor.ok_or_else(|| {
        WalletRuntimeError::PolicyPath(format!(
            "leaf hash '{}' provided but wallet has no policy descriptor",
            leaf_hash
        ))
    })?;

    let leaves = taptree_leaves(&descriptor.to_string())?.unwrap_or_default();
    let child_index = TapLeaf::policy_child_index(&leaves, leaf_hash).ok_or_else(|| {
        WalletRuntimeError::PolicyPath(format!(
            "leaf hash '{}' does not match any spending path in the descriptor",
            leaf_hash
        ))
    })?;
    validate_policy_path(&external_policy, &[child_index])?;
    policy_path.insert(external_policy.id.clone(), vec![child_index]);
    Ok(policy_path)
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
