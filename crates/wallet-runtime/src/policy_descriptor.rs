//! Stored policy descriptor, as re-read when spending.
//!
//! Timelocked wallets persist their canonical multipath descriptor at
//! creation and parse it back for leaf-hash resolution, PSBT pruning and
//! spending-path enumeration. Liana's parser covers every shape with a
//! spendable primary, but rejects the *recovery-only* shape: when the
//! taproot internal key is the deterministic unspendable xpub, Liana
//! drops it from the semantic policy, finds no primary path, and returns
//! `IncompatibleDesc`. `policy-core` builds exactly that descriptor for
//! `is_unspendable` primaries, so those wallets need their own reader.
//!
//! `PolicyDescriptor::from_str` tries `RecoveryOnlyDescriptor` first,
//! which accepts only `tr(UNSPENDABLE, TREE)` where every leaf is a Liana
//! recovery path (keys behind `older`), and falls back to Liana.
//!
//! The taptree's leaf order is chosen by the miniscript policy compiler,
//! not by timelock. BDK lists the leaves as policy children in that same
//! order, so `policy_core::TapTree` is how a spending path is mapped to
//! its policy child for both variants.

use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::Fingerprint;
use bdk_wallet::bitcoin::secp256k1::PublicKey;
use bdk_wallet::bitcoin::taproot::{LeafVersion, TapLeafHash};
use liana::descriptors::{LianaDescriptor, PathInfo};
use liana::miniscript::descriptor::{Descriptor, DescriptorPublicKey};
use liana::miniscript::policy::Liftable;
use policy_core::{TapTree, BIP341_NUMS_HEX};

use crate::error::WalletRuntimeError;

/// A wallet's stored multipath policy descriptor.
#[derive(Debug, Clone)]
pub enum PolicyDescriptor {
    /// Primary path plus timelocked recoveries, as understood by Liana.
    Liana(LianaDescriptor),
    /// Unspendable primary: funds move only through timelocked recoveries.
    RecoveryOnly(RecoveryOnlyDescriptor),
}

impl PolicyDescriptor {
    pub fn as_liana(&self) -> Option<&LianaDescriptor> {
        match self {
            Self::Liana(desc) => Some(desc),
            Self::RecoveryOnly(_) => None,
        }
    }
}

impl FromStr for PolicyDescriptor {
    type Err = WalletRuntimeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Recovery-only goes first: Liana only recognises the unspendable
        // internal key when its chain code was derived from the leaf keys
        // in taptree order, and otherwise reads it as a real primary key.
        if let Ok(desc) = RecoveryOnlyDescriptor::from_str(s) {
            return Ok(Self::RecoveryOnly(desc));
        }
        // The Liana error is the one worth reporting: the recovery-only
        // reader only recognises a single narrow shape.
        LianaDescriptor::from_str(s)
            .map(Self::Liana)
            .map_err(|e| WalletRuntimeError::InvalidDescriptor(e.to_string()))
    }
}

/// One timelocked recovery leaf of a recovery-only wallet.
#[derive(Debug, Clone)]
pub struct RecoveryLeaf {
    /// Hex `TapLeafHash`, as emitted by `policy_core::taproot::extract`.
    pub leaf_hash: String,
    /// Relative timelock (CSV) in blocks.
    pub timelock: u16,
    pub threshold: usize,
    pub fingerprints: Vec<Fingerprint>,
}

/// `tr(UNSPENDABLE, TREE)` where every leaf is keys behind `older`.
#[derive(Debug, Clone)]
pub struct RecoveryOnlyDescriptor {
    /// Leaves in taptree order — the order BDK lists them as policy
    /// children, after the key-spend child at index 0.
    leaves: Vec<RecoveryLeaf>,
}

impl RecoveryOnlyDescriptor {
    pub fn leaves(&self) -> &[RecoveryLeaf] {
        &self.leaves
    }

    /// Index of the BDK policy child that spends through `leaf_hash`.
    pub fn policy_child_index(&self, leaf_hash: &str) -> Option<usize> {
        self.leaves
            .iter()
            .position(|leaf| leaf.leaf_hash.eq_ignore_ascii_case(leaf_hash))
            .map(|idx| idx + 1)
    }
}

impl FromStr for RecoveryOnlyDescriptor {
    type Err = WalletRuntimeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let desc = Descriptor::<DescriptorPublicKey>::from_str(s)
            .and_then(|desc| desc.sanity_check().map(|_| desc))
            .map_err(|e| invalid(e.to_string()))?;
        let tr = match &desc {
            Descriptor::Tr(tr) => tr,
            _ => return Err(invalid("not a taproot descriptor")),
        };
        if tr.tap_tree().is_none() {
            return Err(invalid("no recovery leaves"));
        }

        // The internal key must sit on the BIP-341 NUMS point, otherwise
        // it is a real key and this is not a recovery-only wallet. The
        // chain code is not checked: it only makes the key unique per
        // wallet, and wallets differ in the leaf order they derived it from.
        if !is_unspendable(tr.internal_key()) {
            return Err(invalid("internal key is spendable"));
        }

        let derived = derive_receive(&desc).map_err(|e| invalid(e.to_string()))?;
        let derived_tr = match &derived {
            Descriptor::Tr(tr) => tr,
            _ => return Err(invalid("not a taproot descriptor")),
        };

        let mut leaves = Vec::new();
        for ((_, ms), (_, derived_ms)) in tr.iter_scripts().zip(derived_tr.iter_scripts()) {
            let policy = ms.lift().map_err(|e| invalid(e.to_string()))?.normalized();
            let (timelock, path) =
                PathInfo::from_recovery_path(policy).map_err(|e| invalid(e.to_string()))?;
            if !path_keys(&path).iter().all(has_origin) {
                return Err(invalid("recovery key without origin"));
            }
            let (threshold, origins) = path.thresh_origins();
            let mut fingerprints: Vec<Fingerprint> = origins.into_keys().collect();
            fingerprints.sort();
            leaves.push(RecoveryLeaf {
                leaf_hash: leaf_hash(derived_ms),
                timelock,
                threshold,
                fingerprints,
            });
        }

        Ok(Self { leaves })
    }
}

fn invalid(reason: impl Into<String>) -> WalletRuntimeError {
    WalletRuntimeError::InvalidDescriptor(format!(
        "not a recovery-only descriptor: {}",
        reason.into()
    ))
}

fn is_unspendable(key: &DescriptorPublicKey) -> bool {
    let nums = PublicKey::from_str(BIP341_NUMS_HEX).expect("valid NUMS point");
    matches!(key, DescriptorPublicKey::MultiXPub(k) if k.xkey.public_key == nums)
}

/// Taptree of a stored multipath policy descriptor; `None` when it is
/// not taproot.
pub(crate) fn taptree(descriptor: &str) -> Result<Option<TapTree>, WalletRuntimeError> {
    TapTree::parse(descriptor).map_err(|e| WalletRuntimeError::InvalidDescriptor(e.to_string()))
}

/// Leaf hashes do not depend on the derivation index, but computing them
/// needs definite keys: use the receive descriptor at child 0, like
/// `policy_core::taproot::extract` does.
fn derive_receive(
    desc: &Descriptor<DescriptorPublicKey>,
) -> Result<Descriptor<liana::miniscript::DefiniteDescriptorKey>, WalletRuntimeError> {
    let receive = desc
        .clone()
        .into_single_descriptors()
        .map_err(|e| WalletRuntimeError::InvalidDescriptor(e.to_string()))?
        .into_iter()
        .next()
        .ok_or_else(|| {
            WalletRuntimeError::InvalidDescriptor("not a multipath descriptor".to_string())
        })?;
    receive
        .at_derivation_index(0)
        .map_err(|e| WalletRuntimeError::InvalidDescriptor(e.to_string()))
}

fn leaf_hash(
    ms: &liana::miniscript::Miniscript<
        liana::miniscript::DefiniteDescriptorKey,
        liana::miniscript::Tap,
    >,
) -> String {
    TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript).to_string()
}

fn path_keys(path: &PathInfo) -> Vec<DescriptorPublicKey> {
    match path {
        PathInfo::Single(key) => vec![key.clone()],
        PathInfo::Multi(_, keys) => keys.clone(),
    }
}

fn has_origin(key: &DescriptorPublicKey) -> bool {
    matches!(key, DescriptorPublicKey::MultiXPub(k) if k.origin.is_some())
}
