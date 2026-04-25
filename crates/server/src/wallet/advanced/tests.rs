//! Cross-module integration tests for the advanced wallet pipeline.

use std::collections::BTreeMap;

use bdk_wallet::bitcoin::bip32::{Xpriv, Xpub};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::Network;

use crate::db::StoredManagedKey;
use crate::wallet::advanced::descriptor;
use crate::wallet::advanced::shape::{self, ScriptKind, WalletShape};
use crate::wallet::advanced::spec::{
    PolicyType, PreferredScriptType, SpendingCondition, WalletSpec,
};

struct Fixture {
    pub key: StoredManagedKey,
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
    let liana_format_xpub = format!("[{}]{}/<0;1>/*", fingerprint, xpub);

    Fixture {
        key: StoredManagedKey::new_customer_key(
            "user-test",
            device_id,
            "test key",
            &liana_format_xpub,
            &fingerprint,
            "m/84'/1'/0'",
        ),
    }
}

fn keys(fixtures: &[&Fixture]) -> BTreeMap<String, StoredManagedKey> {
    fixtures
        .iter()
        .map(|f| (f.key.device_id.clone(), f.key.clone()))
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
    }
}

#[test]
fn classifies_single_sig() {
    let f = make_key("device-1", 1);
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![cond("primary", true, 0, PolicyType::Single, 1, &["device-1"])],
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
        conditions: vec![cond("primary", true, 0, PolicyType::Single, 1, &["device-1"])],
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
fn rejects_segwit_v0_for_timelocked_policy() {
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
    assert!(shape::classify(&spec).is_err());
}

#[test]
fn descriptor_pair_for_single_sig_has_no_liana() {
    let f = make_key("device-1", 1);
    let spec = WalletSpec {
        network: Network::Testnet,
        conditions: vec![cond("primary", true, 0, PolicyType::Single, 1, &["device-1"])],
        managed_keys: keys(&[&f]),
        preferred_script_type: PreferredScriptType::Auto,
    };
    let shape = shape::classify(&spec).unwrap();
    let pair = descriptor::build(&shape).unwrap();
    assert!(pair.external.starts_with("wpkh("));
    assert!(pair.internal.starts_with("wpkh("));
    assert!(
        pair.liana.is_none(),
        "non-Liana shape must not produce a Liana descriptor"
    );
}

#[test]
fn descriptor_pair_for_multisig_has_no_liana() {
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
    assert!(pair.liana.is_none());
}

#[test]
fn descriptor_pair_for_timelocked_policy_populates_liana() {
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
        pair.liana.is_some(),
        "TimelockedPolicy shape must produce a Liana descriptor"
    );
}
