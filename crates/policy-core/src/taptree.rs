//! Script leaves of a multipath taproot policy descriptor, in taptree
//! order.
//!
//! The miniscript policy compiler chooses that order, not the timelocks.
//! BDK lists the leaves as policy children in the same order, after the
//! key spend at child 0, so a leaf's position here is how a spending path
//! is mapped to its policy child.

use std::str::FromStr;

use bdk_wallet::bitcoin::secp256k1::PublicKey;
use bdk_wallet::bitcoin::taproot::{LeafVersion, TapLeafHash};
use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
use miniscript::policy::Liftable;
use miniscript::{DefiniteDescriptorKey, Miniscript, Tap};

use crate::error::PolicyError;
use crate::key_utils::BIP341_NUMS_HEX;

#[derive(Debug, Clone)]
pub struct TapLeaf {
    /// Hex `TapLeafHash`.
    pub leaf_hash: String,
    /// Relative timelock the leaf enforces; `None` for a primary leaf.
    pub timelock: Option<u16>,
    /// Keys in the leaf, as written in the descriptor.
    pub keys: Vec<DescriptorPublicKey>,
}

#[derive(Debug, Clone)]
pub struct TapTree {
    pub internal_key: DescriptorPublicKey,
    pub leaves: Vec<TapLeaf>,
}

impl TapTree {
    /// Parse a multipath descriptor. `None` when it is not taproot.
    pub fn parse(descriptor: &str) -> Result<Option<TapTree>, PolicyError> {
        let desc = Descriptor::<DescriptorPublicKey>::from_str(descriptor).map_err(invalid)?;
        let tr = match &desc {
            Descriptor::Tr(tr) => tr,
            _ => return Ok(None),
        };

        // Leaf hashes do not depend on the derivation index, but computing
        // them needs definite keys: use the receive descriptor at child 0.
        let derived = desc
            .clone()
            .into_single_descriptors()
            .map_err(invalid)?
            .into_iter()
            .next()
            .ok_or_else(|| invalid("not a multipath descriptor"))?
            .at_derivation_index(0)
            .map_err(invalid)?;
        let derived_tr = match &derived {
            Descriptor::Tr(tr) => tr,
            _ => return Ok(None),
        };

        let mut leaves = Vec::new();
        for ((_, ms), (_, derived_ms)) in tr.iter_scripts().zip(derived_tr.iter_scripts()) {
            let timelock = match ms.lift().map_err(invalid)?.relative_timelocks().first() {
                Some(blocks) => Some(u16::try_from(*blocks).map_err(|_| {
                    invalid(format!("timelock of {} blocks is out of range", blocks))
                })?),
                None => None,
            };
            leaves.push(TapLeaf {
                leaf_hash: leaf_hash(derived_ms),
                timelock,
                keys: ms.iter_pk().collect(),
            });
        }
        Ok(Some(TapTree {
            internal_key: tr.internal_key().clone(),
            leaves,
        }))
    }

    /// Whether somebody can sign for the internal key: false when it sits
    /// on the BIP-341 NUMS point. The chain code is not checked; it only
    /// makes the key unique per wallet.
    pub fn has_spendable_key_path(&self) -> bool {
        let nums = PublicKey::from_str(BIP341_NUMS_HEX).expect("valid NUMS point");
        let public_key = match &self.internal_key {
            DescriptorPublicKey::Single(key) => match key.key {
                miniscript::descriptor::SinglePubKey::FullKey(pk) => Some(pk.inner),
                miniscript::descriptor::SinglePubKey::XOnly(_) => None,
            },
            DescriptorPublicKey::XPub(key) => Some(key.xkey.public_key),
            DescriptorPublicKey::MultiXPub(key) => Some(key.xkey.public_key),
        };
        public_key != Some(nums)
    }

    /// Index of the BDK policy child that spends through `leaf_hash`.
    pub fn policy_child_index(&self, leaf_hash: &str) -> Option<usize> {
        self.leaves
            .iter()
            .position(|leaf| leaf.leaf_hash.eq_ignore_ascii_case(leaf_hash))
            .map(|idx| idx + 1)
    }
}

fn leaf_hash(ms: &Miniscript<DefiniteDescriptorKey, Tap>) -> String {
    TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript).to_string()
}

fn invalid(reason: impl ToString) -> PolicyError {
    PolicyError::DescriptorGeneration(format!(
        "unreadable taproot descriptor: {}",
        reason.to_string()
    ))
}
