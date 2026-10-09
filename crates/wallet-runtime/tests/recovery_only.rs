//! Recovery-only wallets (unspendable primary) must be spendable through
//! their timelocked recovery path once the stored descriptor is re-read.
//!
//! Regression: Liana's parser rejects the descriptor `policy-core` builds
//! for this shape, so the wallet could receive funds but never prepare a
//! spend.

use std::collections::BTreeMap;
use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, Sequence};
use bdk_wallet::chain::BlockId;
use bdk_wallet::miniscript::psbt::PsbtExt;
use bdk_wallet::test_utils::{insert_checkpoint, receive_output_in_latest_block};
use bdk_wallet::{KeychainKind, Wallet};
use liana::descriptors::LianaDescriptor;
use policy_core::{
    build_descriptor, classify, taproot, ManagedKey, PolicyType, PreferredScriptType,
    SpendingCondition, TaprootLeafInfo, WalletShape, WalletSpec,
};
use wallet_runtime::{
    add_xprv_signer, list_spending_paths, resolve_policy_path, sign_psbt, PolicyDescriptor,
    SignerKind,
};

const ACCOUNT_PATH: &str = "m/84'/1'/0'";

struct RecoveryKey {
    device_id: String,
    account_xprv: Xpriv,
    managed: ManagedKey,
}

fn recovery_key(seed: u8) -> RecoveryKey {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Regtest, &[seed; 64]).expect("valid seed");
    let fingerprint = format!("{:08x}", master.fingerprint(&secp));
    let account_xprv = master
        .derive_priv(&secp, &DerivationPath::from_str(ACCOUNT_PATH).unwrap())
        .expect("derive account");
    let account_xpub = Xpub::from_priv(&secp, &account_xprv);
    RecoveryKey {
        device_id: format!("device-{}", seed),
        account_xprv,
        managed: ManagedKey {
            xpub: format!("[{}]{}/<0;1>/*", fingerprint, account_xpub),
            fingerprint,
            derivation_path: ACCOUNT_PATH.to_string(),
            tpub: None,
        },
    }
}

struct RecoveryOnlyWallet {
    wallet: Wallet,
    stored_descriptor: String,
    leaves: Vec<TaprootLeafInfo>,
}

/// `recoveries` is `(condition id, timelock, threshold, keys)`.
fn build_wallet(recoveries: &[(&str, u16, usize, &[&RecoveryKey])]) -> RecoveryOnlyWallet {
    let mut conditions = vec![SpendingCondition {
        id: "primary".to_string(),
        is_primary: true,
        timelock: 0,
        threshold: 0,
        policy: PolicyType::Single,
        managed_key_ids: Vec::new(),
        is_unspendable: true,
    }];
    let mut managed_keys = BTreeMap::new();
    for (id, timelock, threshold, keys) in recoveries {
        conditions.push(SpendingCondition {
            id: id.to_string(),
            is_primary: false,
            timelock: *timelock,
            threshold: *threshold,
            policy: if keys.len() == 1 {
                PolicyType::Single
            } else {
                PolicyType::Multi
            },
            managed_key_ids: keys.iter().map(|k| k.device_id.clone()).collect(),
            is_unspendable: false,
        });
        for key in keys.iter() {
            managed_keys.insert(key.device_id.clone(), key.managed.clone());
        }
    }
    let spec = WalletSpec {
        network: Network::Regtest,
        conditions,
        managed_keys,
        preferred_script_type: PreferredScriptType::Auto,
    };

    let shape = classify(&spec).expect("classify");
    let (primary_id, primary, recovery_paths) = match &shape {
        WalletShape::TimelockedPolicy {
            primary_id,
            primary,
            recoveries,
        } => (primary_id.clone(), primary.clone(), recoveries.clone()),
        other => panic!("expected TimelockedPolicy, got {:?}", other),
    };
    let pair = build_descriptor(&shape).expect("descriptor");
    let policy_desc = pair.policy_descriptor.clone().expect("policy descriptor");
    let leaves = taproot::extract(&primary_id, &primary, &recovery_paths, &policy_desc)
        .expect("taproot metadata")
        .leaves;

    let wallet = Wallet::create(pair.external, pair.internal)
        .network(Network::Regtest)
        .create_wallet_no_persist()
        .expect("BDK wallet");

    RecoveryOnlyWallet {
        wallet,
        stored_descriptor: policy_desc.to_string(),
        leaves,
    }
}

fn leaf_hash<'a>(leaves: &'a [TaprootLeafInfo], condition_id: &str) -> &'a str {
    &leaves
        .iter()
        .find(|l| l.spending_condition_id == condition_id)
        .unwrap_or_else(|| panic!("no leaf for {}", condition_id))
        .leaf_hash
}

fn block(height: u32) -> BlockId {
    BlockId {
        height,
        hash: bdk_wallet::bitcoin::hashes::Hash::hash(&height.to_le_bytes()),
    }
}

#[test]
fn stored_descriptor_is_rejected_by_liana_but_read_as_recovery_only() {
    let key = recovery_key(1);
    let built = build_wallet(&[("recovery", 10, 1, &[&key])]);

    assert!(
        LianaDescriptor::from_str(&built.stored_descriptor).is_err(),
        "Liana accepting this descriptor makes the recovery-only reader redundant"
    );

    let desc = match PolicyDescriptor::from_str(&built.stored_descriptor).expect("readable") {
        PolicyDescriptor::RecoveryOnly(desc) => desc,
        PolicyDescriptor::Liana(_) => panic!("expected the recovery-only reader"),
    };
    let leaf = &desc.leaves()[0];
    assert_eq!(desc.leaves().len(), 1);
    assert_eq!(leaf.leaf_hash, leaf_hash(&built.leaves, "recovery"));
    assert_eq!(leaf.timelock, 10);
    assert_eq!(leaf.threshold, 1);
    assert_eq!(leaf.fingerprints.len(), 1);
    assert_eq!(leaf.fingerprints[0].to_string(), key.managed.fingerprint);
}

#[test]
fn spendable_primary_still_reads_as_liana() {
    let primary = recovery_key(1);
    let recovery = recovery_key(2);
    let primary_xpub = &primary.managed.xpub;
    let origin = format!("[{}/84'/1'/0']", primary.managed.fingerprint);
    let recovery_origin = format!("[{}/84'/1'/0']", recovery.managed.fingerprint);
    let descriptor = format!(
        "tr({},and_v(v:pk({}),older(10)))",
        primary_xpub.replacen(&format!("[{}]", primary.managed.fingerprint), &origin, 1),
        recovery.managed.xpub.replacen(
            &format!("[{}]", recovery.managed.fingerprint),
            &recovery_origin,
            1
        ),
    );
    assert!(matches!(
        PolicyDescriptor::from_str(&descriptor).expect("readable"),
        PolicyDescriptor::Liana(_)
    ));
}

#[test]
fn rejects_descriptors_that_are_neither_shape() {
    let key = recovery_key(1);
    let flat = format!(
        "wpkh({})",
        key.managed.xpub.replacen(
            &format!("[{}]", key.managed.fingerprint),
            &format!("[{}/84'/1'/0']", key.managed.fingerprint),
            1
        )
    );
    assert!(PolicyDescriptor::from_str(&flat).is_err());
    assert!(PolicyDescriptor::from_str("not a descriptor").is_err());
}

#[test]
fn recovery_spend_builds_signs_and_finalizes() {
    let key = recovery_key(1);
    let mut built = build_wallet(&[("recovery", 10, 1, &[&key])]);
    let recovery_leaf = leaf_hash(&built.leaves, "recovery").to_string();

    insert_checkpoint(&mut built.wallet, block(100));
    receive_output_in_latest_block(&mut built.wallet, 100_000);
    insert_checkpoint(&mut built.wallet, block(120));

    let desc = PolicyDescriptor::from_str(&built.stored_descriptor).expect("readable");
    let policy_path =
        resolve_policy_path(&built.wallet, &recovery_leaf, Some(&desc)).expect("resolves");

    let destination = Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    let mut builder = built.wallet.build_tx();
    builder
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .add_recipient(destination.script_pubkey(), Amount::from_sat(50_000))
        .policy_path(policy_path.clone(), KeychainKind::External)
        .policy_path(policy_path, KeychainKind::Internal);
    let mut psbt = builder.finish().expect("recovery spend builds");

    assert_eq!(
        psbt.unsigned_tx.input[0].sequence,
        Sequence::from_height(10),
        "the recovery path's CSV must be committed in nSequence"
    );

    add_xprv_signer(
        &mut built.wallet,
        &key.account_xprv,
        KeychainKind::External,
        0,
        SignerKind::TaprootScriptPath,
    )
    .expect("add signer");
    sign_psbt(&built.wallet, &mut psbt).expect("sign");
    assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 1);
    assert!(
        psbt.inputs[0].tap_key_sig.is_none(),
        "nobody can sign for the unspendable internal key"
    );

    psbt.finalize_mut(&Secp256k1::new()).expect("finalizes");
    assert!(psbt.inputs[0].final_script_witness.is_some());
    psbt.extract_tx().expect("extracts");
}

#[test]
fn keypath_and_unknown_leaves_are_refused() {
    let key = recovery_key(1);
    let built = build_wallet(&[("recovery", 10, 1, &[&key])]);
    let desc = PolicyDescriptor::from_str(&built.stored_descriptor).expect("readable");

    for leaf in ["keypath", "deadbeef", ""] {
        let err = resolve_policy_path(&built.wallet, leaf, Some(&desc))
            .expect_err("no such spending path")
            .to_string();
        assert!(
            err.contains("does not match any spending path"),
            "unexpected error for {:?}: {}",
            leaf,
            err
        );
    }
}

#[test]
fn every_recovery_resolves_to_the_policy_child_carrying_its_timelock() {
    let (a, b, c) = (recovery_key(1), recovery_key(2), recovery_key(3));
    let built = build_wallet(&[("heirs", 144, 2, &[&a, &b]), ("lawyer", 1000, 1, &[&c])]);
    let desc = PolicyDescriptor::from_str(&built.stored_descriptor).expect("readable");
    let external = built
        .wallet
        .policies(KeychainKind::External)
        .unwrap()
        .expect("external policy");

    for (condition, timelock) in [("heirs", 144u32), ("lawyer", 1000)] {
        let path = resolve_policy_path(
            &built.wallet,
            leaf_hash(&built.leaves, condition),
            Some(&desc),
        )
        .expect("resolves");
        let requirements = external.get_condition(&path).expect("valid policy path");
        assert_eq!(
            requirements.csv,
            Some(Sequence::from_height(timelock as u16)),
            "{} must resolve to the policy child that enforces its own timelock",
            condition
        );
    }

    let paths = list_spending_paths(
        "timelocked",
        &built.stored_descriptor,
        &[],
        Some(external.id.as_str()),
    )
    .expect("paths");
    assert_eq!(paths.len(), 2, "no primary path to offer");
    assert_eq!(paths[0].timelock_blocks, Some(144));
    assert_eq!((paths[0].threshold, paths[0].fingerprints.len()), (2, 2));
    assert_eq!(paths[1].timelock_blocks, Some(1000));
    for path in &paths {
        let requirements = external
            .get_condition(path.policy_path.as_ref().unwrap())
            .expect("valid policy path");
        assert_eq!(
            requirements.csv,
            Some(Sequence::from_height(path.timelock_blocks.unwrap() as u16))
        );
    }
}
