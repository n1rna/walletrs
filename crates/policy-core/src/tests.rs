//! Cross-module integration tests for the policy pipeline.

use std::collections::BTreeMap;
use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::{Xpriv, Xpub};
use bdk_wallet::bitcoin::secp256k1::{self, Secp256k1};
use bdk_wallet::bitcoin::Network;

use crate::descriptor;
use crate::managed_key::ManagedKey;
use crate::shape::{self, ScriptKind, WalletShape};
use crate::spec::{PolicyType, PreferredScriptType, SpendingCondition, WalletSpec};

struct Fixture {
    pub device_id: String,
    pub key: ManagedKey,
}

fn make_key(device_id: &str, seed: u64) -> Fixture {
    let mut seed_bytes = [0u8; 64];
    for (i, byte) in device_id
        .bytes()
        .chain(seed.to_le_bytes().iter().cloned())
        .enumerate()
    {
        if i < 64 {
            seed_bytes[i] = byte;
        }
    }

    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(Network::Testnet, &seed_bytes).expect("valid seed");
    let xpub = Xpub::from_priv(&secp, &xpriv);
    let fingerprint = format!("{:08x}", xpriv.fingerprint(&secp));
    let multipath_xpub = format!("[{}]{}/<0;1>/*", fingerprint, xpub);

    Fixture {
        device_id: device_id.to_string(),
        key: ManagedKey {
            fingerprint,
            derivation_path: "m/84'/1'/0'".to_string(),
            xpub: multipath_xpub,
            tpub: None,
        },
    }
}

fn keys(fixtures: &[&Fixture]) -> BTreeMap<String, ManagedKey> {
    fixtures
        .iter()
        .map(|f| (f.device_id.clone(), f.key.clone()))
        .collect()
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
        is_unspendable: false,
    }
}

#[test]
fn classifies_single_sig() {
    let f = make_key("device-1", 1);
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![cond(
            "primary",
            true,
            0,
            PolicyType::Single,
            1,
            &["device-1"],
        )],
        managed_keys: keys(&[&f]),
        preferred_script_type: PreferredScriptType::Auto,
    };

    match shape::classify(&spec).unwrap() {
        WalletShape::SingleSig {
            kind: ScriptKind::SegwitV0,
            ..
        } => (),
        other => panic!("expected SingleSig SegwitV0, got {:?}", other),
    }
}

#[test]
fn classifies_single_sig_taproot_when_preferred() {
    let f = make_key("device-1", 1);
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![cond(
            "primary",
            true,
            0,
            PolicyType::Single,
            1,
            &["device-1"],
        )],
        managed_keys: keys(&[&f]),
        preferred_script_type: PreferredScriptType::Taproot,
    };

    match shape::classify(&spec).unwrap() {
        WalletShape::SingleSig {
            kind: ScriptKind::Taproot,
            ..
        } => (),
        other => panic!("expected SingleSig Taproot, got {:?}", other),
    }
}

#[test]
fn classifies_simple_multisig() {
    let f1 = make_key("device-1", 1);
    let f2 = make_key("device-2", 2);
    let f3 = make_key("device-3", 3);
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![cond(
            "primary",
            true,
            0,
            PolicyType::Multi,
            2,
            &["device-1", "device-2", "device-3"],
        )],
        managed_keys: keys(&[&f1, &f2, &f3]),
        preferred_script_type: PreferredScriptType::Auto,
    };

    match shape::classify(&spec).unwrap() {
        WalletShape::Multisig {
            kind: ScriptKind::SegwitV0,
            threshold: 2,
            keys,
        } => assert_eq!(keys.len(), 3),
        other => panic!("expected Multisig SegwitV0, got {:?}", other),
    }
}

#[test]
fn classifies_taproot_multisig_when_preferred() {
    let f1 = make_key("device-1", 1);
    let f2 = make_key("device-2", 2);
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![cond(
            "primary",
            true,
            0,
            PolicyType::Multi,
            2,
            &["device-1", "device-2"],
        )],
        managed_keys: keys(&[&f1, &f2]),
        preferred_script_type: PreferredScriptType::Taproot,
    };

    match shape::classify(&spec).unwrap() {
        WalletShape::Multisig {
            kind: ScriptKind::Taproot,
            ..
        } => (),
        other => panic!("expected Multisig Taproot, got {:?}", other),
    }
}

#[test]
fn classifies_combined_taproot_multisig_when_all_zero_timelock() {
    let f1 = make_key("device-1", 1);
    let f2 = make_key("device-2", 2);
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![
            cond("primary", true, 0, PolicyType::Single, 1, &["device-1"]),
            cond("recovery", false, 0, PolicyType::Single, 1, &["device-2"]),
        ],
        managed_keys: keys(&[&f1, &f2]),
        preferred_script_type: PreferredScriptType::Auto,
    };

    match shape::classify(&spec).unwrap() {
        WalletShape::Multisig {
            kind: ScriptKind::Taproot,
            keys,
            ..
        } => assert_eq!(keys.len(), 2, "expected combined two-key taproot multisig"),
        other => panic!("expected combined taproot multisig, got {:?}", other),
    }
}

#[test]
fn classifies_timelocked_policy_when_primary_has_recovery() {
    let f1 = make_key("device-1", 1);
    let f2 = make_key("device-2", 2);
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![
            cond("primary", true, 0, PolicyType::Single, 1, &["device-1"]),
            cond("recovery", false, 144, PolicyType::Single, 1, &["device-2"]),
        ],
        managed_keys: keys(&[&f1, &f2]),
        preferred_script_type: PreferredScriptType::Auto,
    };

    match shape::classify(&spec).unwrap() {
        WalletShape::TimelockedPolicy { recoveries, .. } => {
            assert_eq!(recoveries.len(), 1);
            assert_eq!(recoveries[0].timelock, 144);
        }
        other => panic!("expected TimelockedPolicy, got {:?}", other),
    }
}

#[test]
fn classifies_unspendable_primary_to_nums_xpub() {
    use crate::key_utils::BIP341_NUMS_HEX;

    let f_rec = make_key("device-rec", 1);
    let unspendable = SpendingCondition {
        id: "primary".to_string(),
        is_primary: true,
        timelock: 0,
        threshold: 0,
        policy: PolicyType::Single,
        managed_key_ids: Vec::new(),
        is_unspendable: true,
    };
    let recovery = cond(
        "recovery",
        false,
        144,
        PolicyType::Single,
        1,
        &["device-rec"],
    );
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![unspendable, recovery],
        managed_keys: keys(&[&f_rec]),
        preferred_script_type: PreferredScriptType::Auto,
    };

    let shape = shape::classify(&spec).unwrap();
    match shape {
        WalletShape::TimelockedPolicy {
            primary,
            recoveries,
            ..
        } => {
            assert_eq!(recoveries.len(), 1);
            let primary_key = match primary {
                shape::PolicyPath::Single(k) => k,
                other => panic!("expected single-key primary, got {:?}", other),
            };
            // Substituted key must be the BIP-341 NUMS pubkey.
            let nums = secp256k1::PublicKey::from_str(BIP341_NUMS_HEX).unwrap();
            let inner_xpub = match primary_key {
                miniscript::descriptor::DescriptorPublicKey::XPub(x) => x.xkey,
                miniscript::descriptor::DescriptorPublicKey::MultiXPub(m) => m.xkey,
                other => panic!("unexpected key variant: {:?}", other),
            };
            assert_eq!(inner_xpub.public_key, nums);
        }
        other => panic!("expected TimelockedPolicy, got {:?}", other),
    }
}

#[test]
fn segwit_v0_timelocked_policy_builds_a_wsh_descriptor() {
    let f1 = make_key("device-1", 1);
    let f2 = make_key("device-2", 2);
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![
            cond("primary", true, 0, PolicyType::Single, 1, &["device-1"]),
            cond("recovery", false, 144, PolicyType::Single, 1, &["device-2"]),
        ],
        managed_keys: keys(&[&f1, &f2]),
        preferred_script_type: PreferredScriptType::SegwitV0,
    };
    let shape = shape::classify(&spec).unwrap();
    let (primary_id, primary, recoveries) = match &shape {
        WalletShape::SegwitTimelockedPolicy {
            primary_id,
            primary,
            recoveries,
        } => (primary_id, primary, recoveries),
        other => panic!("expected SegwitTimelockedPolicy, got {:?}", other),
    };
    let pair = descriptor::build(&shape).unwrap();
    assert!(pair.external.starts_with("wsh("));
    assert!(pair.external.contains("older(144)"));

    // No taproot leaves: conditions are selected by name and timelock.
    let policy_desc = pair.policy_descriptor.expect("policy descriptor");
    let metadata = crate::taproot::extract(primary_id, primary, recoveries, &policy_desc).unwrap();
    let selectors: Vec<(&str, &str)> = metadata
        .leaves
        .iter()
        .map(|l| (l.spending_condition_id.as_str(), l.leaf_hash.as_str()))
        .collect();
    assert_eq!(
        selectors,
        vec![("primary", "primary"), ("recovery", "older:144")]
    );
    assert!(metadata.internal_key.is_none() && metadata.merkle_root.is_none());
}

#[test]
fn segwit_v0_refuses_an_unspendable_primary() {
    let f1 = make_key("device-1", 1);
    let mut primary = cond("primary", true, 0, PolicyType::Single, 0, &[]);
    primary.is_unspendable = true;
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![
            primary,
            cond("recovery", false, 144, PolicyType::Single, 1, &["device-1"]),
        ],
        managed_keys: keys(&[&f1]),
        preferred_script_type: PreferredScriptType::SegwitV0,
    };
    let err = shape::classify(&spec).unwrap_err().to_string();
    assert!(
        err.contains("requires taproot"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn one_of_one_multi_is_a_single_key() {
    let f1 = make_key("device-1", 1);
    let f2 = make_key("device-2", 2);
    let alone = WalletSpec {
        network: Network::Testnet,
        conditions: vec![cond(
            "primary",
            true,
            0,
            PolicyType::Multi,
            1,
            &["device-1"],
        )],
        managed_keys: keys(&[&f1]),
        preferred_script_type: PreferredScriptType::Auto,
    };
    assert!(matches!(
        shape::classify(&alone).unwrap(),
        WalletShape::SingleSig {
            kind: ScriptKind::SegwitV0,
            ..
        }
    ));

    let with_recovery = WalletSpec {
        network: Network::Testnet,
        conditions: vec![
            cond("primary", true, 0, PolicyType::Multi, 1, &["device-1"]),
            cond("recovery", false, 144, PolicyType::Multi, 1, &["device-2"]),
        ],
        managed_keys: keys(&[&f1, &f2]),
        preferred_script_type: PreferredScriptType::Auto,
    };
    match shape::classify(&with_recovery).unwrap() {
        WalletShape::TimelockedPolicy {
            primary: shape::PolicyPath::Single(_),
            recoveries,
            ..
        } => assert!(matches!(recoveries[0].path, shape::PolicyPath::Single(_))),
        other => panic!("expected single-key paths, got {:?}", other),
    }
}

#[test]
fn a_device_in_several_conditions_gets_a_key_per_condition() {
    let f1 = make_key("device-1", 1);
    let f2 = make_key("device-2", 2);
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![
            cond(
                "primary",
                true,
                0,
                PolicyType::Multi,
                2,
                &["device-1", "device-2"],
            ),
            cond(
                "either",
                false,
                144,
                PolicyType::Multi,
                1,
                &["device-1", "device-2"],
            ),
            cond("alone", false, 288, PolicyType::Single, 1, &["device-1"]),
        ],
        managed_keys: keys(&[&f1, &f2]),
        preferred_script_type: PreferredScriptType::Auto,
    };
    let shape = shape::classify(&spec).unwrap();
    let (primary_id, primary, recoveries) = match &shape {
        WalletShape::TimelockedPolicy {
            primary_id,
            primary,
            recoveries,
        } => (primary_id, primary, recoveries),
        other => panic!("expected TimelockedPolicy, got {:?}", other),
    };
    let steps = |path: &shape::PolicyPath| -> Vec<String> {
        path.keys()
            .iter()
            .map(|key| {
                let key = key.to_string();
                key[key.rfind("/<").unwrap()..].to_string()
            })
            .collect()
    };
    assert_eq!(steps(primary), ["/<0;1>/*", "/<0;1>/*"]);
    assert_eq!(steps(&recoveries[0].path), ["/<2;3>/*", "/<2;3>/*"]);
    assert_eq!(steps(&recoveries[1].path), ["/<4;5>/*"]);

    // Every condition still maps to a leaf of its own, although all of
    // them hold a key of device-1.
    let pair = descriptor::build(&shape).unwrap();
    let policy_desc = pair.policy_descriptor.expect("policy descriptor");
    let leaves = crate::taproot::extract(primary_id, primary, recoveries, &policy_desc)
        .unwrap()
        .leaves;
    let mut hashes: Vec<&str> = leaves.iter().map(|l| l.leaf_hash.as_str()).collect();
    hashes.sort();
    hashes.dedup();
    assert_eq!(hashes.len(), 3);
    assert!(!hashes.contains(&"keypath"));
}

#[test]
fn key_reuse_is_refused_inside_a_condition_and_without_timelocks() {
    let f1 = make_key("device-1", 1);
    let f2 = make_key("device-2", 2);
    let twice = WalletSpec {
        network: Network::Testnet,
        conditions: vec![
            cond("primary", true, 0, PolicyType::Single, 1, &["device-1"]),
            cond(
                "recovery",
                false,
                144,
                PolicyType::Multi,
                2,
                &["device-2", "device-2"],
            ),
        ],
        managed_keys: keys(&[&f1, &f2]),
        preferred_script_type: PreferredScriptType::Auto,
    };
    let err = shape::classify(&twice).unwrap_err().to_string();
    assert!(err.contains("more than once"), "unexpected error: {}", err);

    let untimelocked = WalletSpec {
        network: Network::Testnet,
        conditions: vec![
            cond(
                "primary",
                true,
                0,
                PolicyType::Multi,
                2,
                &["device-1", "device-2"],
            ),
            cond("recovery", false, 0, PolicyType::Single, 1, &["device-1"]),
        ],
        managed_keys: keys(&[&f1, &f2]),
        preferred_script_type: PreferredScriptType::Auto,
    };
    let err = shape::classify(&untimelocked).unwrap_err().to_string();
    assert!(err.contains("timelocked"), "unexpected error: {}", err);
}

#[test]
fn descriptor_pair_for_single_sig_has_no_policy_descriptor() {
    let f = make_key("device-1", 1);
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![cond(
            "primary",
            true,
            0,
            PolicyType::Single,
            1,
            &["device-1"],
        )],
        managed_keys: keys(&[&f]),
        preferred_script_type: PreferredScriptType::Auto,
    };
    let shape = shape::classify(&spec).unwrap();
    let pair = descriptor::build(&shape).unwrap();
    assert!(pair.external.starts_with("wpkh("));
    assert!(pair.internal.starts_with("wpkh("));
    assert!(
        pair.policy_descriptor.is_none(),
        "flat shape must not produce a policy descriptor"
    );
}

#[test]
fn descriptor_pair_for_multisig_has_no_policy_descriptor() {
    let f1 = make_key("device-1", 1);
    let f2 = make_key("device-2", 2);
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![cond(
            "primary",
            true,
            0,
            PolicyType::Multi,
            2,
            &["device-1", "device-2"],
        )],
        managed_keys: keys(&[&f1, &f2]),
        preferred_script_type: PreferredScriptType::Auto,
    };
    let shape = shape::classify(&spec).unwrap();
    let pair = descriptor::build(&shape).unwrap();
    assert!(pair.external.starts_with("wsh(sortedmulti(2,"));
    assert!(pair.policy_descriptor.is_none());
}

#[test]
fn descriptor_pair_for_timelocked_policy_populates_policy_descriptor() {
    let f1 = make_key("device-1", 1);
    let f2 = make_key("device-2", 2);
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![
            cond("primary", true, 0, PolicyType::Single, 1, &["device-1"]),
            cond("recovery", false, 144, PolicyType::Single, 1, &["device-2"]),
        ],
        managed_keys: keys(&[&f1, &f2]),
        preferred_script_type: PreferredScriptType::Auto,
    };
    let shape = shape::classify(&spec).unwrap();
    let pair = descriptor::build(&shape).unwrap();
    assert!(
        pair.policy_descriptor.is_some(),
        "TimelockedPolicy shape must produce a policy descriptor"
    );
}

/// BIP-341 NUMS point the taproot multisig builder uses as internal key.
const NUMS_INTERNAL_KEY: &str =
    "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// Every `(threshold, key count)` a lone `Multi` condition must accept as a
/// flat multisig, 1-of-n included.
const K_OF_N: [(usize, usize); 4] = [(1, 2), (1, 3), (2, 2), (2, 3)];

fn k_of_n_spec(
    threshold: usize,
    key_count: usize,
    preferred_script_type: PreferredScriptType,
) -> (WalletSpec, Vec<Fixture>) {
    let fixtures: Vec<Fixture> = (1..=key_count)
        .map(|i| make_key(&format!("device-{}", i), i as u64))
        .collect();
    let ids: Vec<&str> = fixtures.iter().map(|f| f.device_id.as_str()).collect();
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![cond("primary", true, 0, PolicyType::Multi, threshold, &ids)],
        managed_keys: keys(&fixtures.iter().collect::<Vec<_>>()),
        preferred_script_type,
    };
    (spec, fixtures)
}

/// Comma-joined key expressions as they appear in the built descriptor:
/// origin carries the derivation path, multipath suffix replaced by the
/// keychain child.
fn descriptor_keys(fixtures: &[Fixture], child: u32) -> String {
    fixtures
        .iter()
        .map(|f| {
            f.key
                .xpub
                .replace(
                    &format!("[{}]", f.key.fingerprint),
                    &format!("[{}/84'/1'/0']", f.key.fingerprint),
                )
                .replace("/<0;1>/*", &format!("/{}/*", child))
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn assert_parses_as_descriptor(descriptor: &str) {
    miniscript::Descriptor::<miniscript::descriptor::DescriptorPublicKey>::from_str(descriptor)
        .unwrap_or_else(|e| panic!("descriptor {} must parse: {}", descriptor, e));
}

#[test]
fn k_of_n_segwit_v0_builds_wsh_sortedmulti() {
    for preferred in [PreferredScriptType::Auto, PreferredScriptType::SegwitV0] {
        for (threshold, key_count) in K_OF_N {
            let (spec, fixtures) = k_of_n_spec(threshold, key_count, preferred);
            spec.validate().unwrap();

            let shape = shape::classify(&spec).unwrap_or_else(|e| {
                panic!(
                    "{}-of-{} {:?} must classify: {}",
                    threshold, key_count, preferred, e
                )
            });
            match &shape {
                WalletShape::Multisig {
                    kind: ScriptKind::SegwitV0,
                    threshold: t,
                    keys,
                } => {
                    assert_eq!(*t, threshold);
                    assert_eq!(keys.len(), key_count);
                }
                other => panic!(
                    "{}-of-{} {:?}: expected Multisig SegwitV0, got {:?}",
                    threshold, key_count, preferred, other
                ),
            }

            let pair = descriptor::build(&shape).unwrap();
            assert_eq!(
                pair.external,
                format!(
                    "wsh(sortedmulti({},{}))",
                    threshold,
                    descriptor_keys(&fixtures, 0)
                )
            );
            assert_eq!(
                pair.internal,
                format!(
                    "wsh(sortedmulti({},{}))",
                    threshold,
                    descriptor_keys(&fixtures, 1)
                )
            );
            assert!(pair.policy_descriptor.is_none());
            assert_parses_as_descriptor(&pair.external);
            assert_parses_as_descriptor(&pair.internal);
        }
    }
}

#[test]
fn k_of_n_taproot_builds_tr_nums_multi_a() {
    for (threshold, key_count) in K_OF_N {
        let (spec, fixtures) = k_of_n_spec(threshold, key_count, PreferredScriptType::Taproot);
        spec.validate().unwrap();

        let shape = shape::classify(&spec).unwrap_or_else(|e| {
            panic!(
                "{}-of-{} taproot must classify: {}",
                threshold, key_count, e
            )
        });
        match &shape {
            WalletShape::Multisig {
                kind: ScriptKind::Taproot,
                threshold: t,
                keys,
            } => {
                assert_eq!(*t, threshold);
                assert_eq!(keys.len(), key_count);
            }
            other => panic!(
                "{}-of-{}: expected Multisig Taproot, got {:?}",
                threshold, key_count, other
            ),
        }

        let pair = descriptor::build(&shape).unwrap();
        assert_eq!(
            pair.external,
            format!(
                "tr({},multi_a({},{}))",
                NUMS_INTERNAL_KEY,
                threshold,
                descriptor_keys(&fixtures, 0)
            )
        );
        assert_eq!(
            pair.internal,
            format!(
                "tr({},multi_a({},{}))",
                NUMS_INTERNAL_KEY,
                threshold,
                descriptor_keys(&fixtures, 1)
            )
        );
        assert!(pair.policy_descriptor.is_none());
        assert_parses_as_descriptor(&pair.external);
        assert_parses_as_descriptor(&pair.internal);
    }
}

#[test]
fn single_sig_descriptors_unchanged() {
    for (preferred, wrapper) in [
        (PreferredScriptType::Auto, "wpkh"),
        (PreferredScriptType::SegwitV0, "wpkh"),
        (PreferredScriptType::Taproot, "tr"),
    ] {
        let f = make_key("device-1", 1);
        let spec = WalletSpec {
            network: Network::Testnet,
            conditions: vec![cond(
                "primary",
                true,
                0,
                PolicyType::Single,
                1,
                &["device-1"],
            )],
            managed_keys: keys(&[&f]),
            preferred_script_type: preferred,
        };
        let shape = shape::classify(&spec).unwrap();
        let pair = descriptor::build(&shape).unwrap();
        let fixtures = [f];
        assert_eq!(
            pair.external,
            format!("{}({})", wrapper, descriptor_keys(&fixtures, 0))
        );
        assert_eq!(
            pair.internal,
            format!("{}({})", wrapper, descriptor_keys(&fixtures, 1))
        );
        assert!(pair.policy_descriptor.is_none());
    }
}

#[test]
fn one_of_n_primary_with_timelocked_recovery_is_a_key_path_condition() {
    let f1 = make_key("device-1", 1);
    let f2 = make_key("device-2", 2);
    let f3 = make_key("device-3", 3);
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![
            cond(
                "primary",
                true,
                0,
                PolicyType::Multi,
                1,
                &["device-1", "device-2"],
            ),
            cond("recovery", false, 144, PolicyType::Single, 1, &["device-3"]),
        ],
        managed_keys: keys(&[&f1, &f2, &f3]),
        preferred_script_type: PreferredScriptType::Auto,
    };

    let shape = shape::classify(&spec).unwrap();
    let (primary_id, primary, recoveries) = match &shape {
        WalletShape::TimelockedPolicy {
            primary_id,
            primary,
            recoveries,
        } => (primary_id, primary, recoveries),
        other => panic!("expected TimelockedPolicy, got {:?}", other),
    };
    let pair = descriptor::build(&shape).unwrap();
    let policy_desc = pair.policy_descriptor.expect("policy descriptor");

    // The compiler makes one primary key the internal key and gives the
    // other a leaf of its own, so the condition has no single leaf and is
    // addressed as the key path.
    let leaves = crate::taproot::extract(primary_id, primary, recoveries, &policy_desc)
        .unwrap()
        .leaves;
    let primary_leaf = leaves
        .iter()
        .find(|l| l.spending_condition_id == "primary")
        .expect("primary leaf");
    assert_eq!(primary_leaf.leaf_hash, "keypath");
    assert_eq!(primary_leaf.threshold, Some(1));
    let recovery_leaf = leaves
        .iter()
        .find(|l| l.spending_condition_id == "recovery")
        .expect("recovery leaf");
    assert_ne!(recovery_leaf.leaf_hash, "keypath");
}
