use std::collections::{BTreeMap, HashSet};

use bdk_wallet::bitcoin::Network;
use serde::{Deserialize, Serialize};

use crate::error::PolicyError;
use crate::managed_key::ManagedKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyType {
    Single,
    Multi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferredScriptType {
    Auto,
    Taproot,
    SegwitV0,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingCondition {
    pub id: String,
    pub is_primary: bool,
    pub timelock: u16,
    pub threshold: usize,
    pub policy: PolicyType,
    pub managed_key_ids: Vec<String>,
}

/// Validated input describing the wallet a caller wants to create.
#[derive(Debug, Clone)]
pub struct WalletSpec {
    pub network: Network,
    pub conditions: Vec<SpendingCondition>,
    pub managed_keys: BTreeMap<String, ManagedKey>,
    pub preferred_script_type: PreferredScriptType,
}

impl WalletSpec {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.conditions.is_empty() {
            return Err(PolicyError::InvalidPolicy(
                "At least one spending condition is required".to_string(),
            ));
        }

        let mut seen_ids: HashSet<&str> = HashSet::new();
        let mut primary_count = 0;

        for cond in &self.conditions {
            if cond.id.is_empty() {
                return Err(PolicyError::InvalidPolicy(
                    "Each spending condition must have an ID".to_string(),
                ));
            }
            if !seen_ids.insert(&cond.id) {
                return Err(PolicyError::InvalidPolicy(format!(
                    "Duplicate spending condition ID: {}",
                    cond.id
                )));
            }
            if cond.managed_key_ids.is_empty() {
                return Err(PolicyError::InvalidPolicy(
                    "Each condition must have at least one key".to_string(),
                ));
            }
            match cond.policy {
                PolicyType::Single => {
                    if cond.managed_key_ids.len() != 1 {
                        return Err(PolicyError::InvalidPolicy(
                            "Single policy requires exactly one key".to_string(),
                        ));
                    }
                }
                PolicyType::Multi => {
                    if cond.threshold == 0 || cond.threshold > cond.managed_key_ids.len() {
                        return Err(PolicyError::InvalidPolicy(
                            "Invalid multi-signature threshold".to_string(),
                        ));
                    }
                }
            }
            if cond.is_primary {
                primary_count += 1;
            }
        }

        if primary_count > 1 {
            return Err(PolicyError::InvalidPolicy(
                "Only one primary condition is allowed".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_keys() -> BTreeMap<String, ManagedKey> {
        BTreeMap::new()
    }

    fn cond(
        id: &str,
        primary: bool,
        timelock: u16,
        policy: PolicyType,
        threshold: usize,
        keys: &[&str],
    ) -> SpendingCondition {
        SpendingCondition {
            id: id.to_string(),
            is_primary: primary,
            timelock,
            threshold,
            policy,
            managed_key_ids: keys.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn rejects_empty_conditions() {
        let spec = WalletSpec {
            network: Network::Testnet,
            conditions: vec![],
            managed_keys: empty_keys(),
            preferred_script_type: PreferredScriptType::Auto,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_ids() {
        let spec = WalletSpec {
            network: Network::Testnet,
            conditions: vec![
                cond("a", true, 0, PolicyType::Single, 1, &["k1"]),
                cond("a", false, 144, PolicyType::Single, 1, &["k2"]),
            ],
            managed_keys: empty_keys(),
            preferred_script_type: PreferredScriptType::Auto,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn rejects_multiple_primaries() {
        let spec = WalletSpec {
            network: Network::Testnet,
            conditions: vec![
                cond("a", true, 0, PolicyType::Single, 1, &["k1"]),
                cond("b", true, 0, PolicyType::Single, 1, &["k2"]),
            ],
            managed_keys: empty_keys(),
            preferred_script_type: PreferredScriptType::Auto,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn rejects_single_with_multiple_keys() {
        let spec = WalletSpec {
            network: Network::Testnet,
            conditions: vec![cond("a", true, 0, PolicyType::Single, 1, &["k1", "k2"])],
            managed_keys: empty_keys(),
            preferred_script_type: PreferredScriptType::Auto,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn rejects_invalid_threshold() {
        let spec = WalletSpec {
            network: Network::Testnet,
            conditions: vec![cond("a", true, 0, PolicyType::Multi, 5, &["k1", "k2"])],
            managed_keys: empty_keys(),
            preferred_script_type: PreferredScriptType::Auto,
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn accepts_valid_spec() {
        let spec = WalletSpec {
            network: Network::Testnet,
            conditions: vec![
                cond("primary", true, 0, PolicyType::Single, 1, &["k1"]),
                cond("recovery", false, 144, PolicyType::Multi, 2, &["k2", "k3"]),
            ],
            managed_keys: empty_keys(),
            preferred_script_type: PreferredScriptType::Auto,
        };
        assert!(spec.validate().is_ok());
    }
}
