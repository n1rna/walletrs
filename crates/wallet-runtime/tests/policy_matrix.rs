//! Every wallet shape `policy-core` can build must be spendable through
//! every one of its paths.
//!
//! Each row of `cases()` is built from a `WalletSpec`, funded, and then
//! spent once per spending condition with exactly that condition's
//! threshold of keys: resolve the leaf, build the PSBT, sign, finalize,
//! and check that the transaction commits to the right timelock and
//! reveals the right script. A shape that only works for some of its
//! paths fails here instead of after funds are deposited.

use std::collections::BTreeMap;
use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::taproot::{LeafVersion, TapLeafHash};
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, Psbt, Script, Sequence};
use bdk_wallet::chain::BlockId;
use bdk_wallet::miniscript::psbt::PsbtExt;
use bdk_wallet::test_utils::{insert_checkpoint, receive_output_in_latest_block};
use bdk_wallet::{KeychainKind, Wallet};
use policy_core::{
    build_descriptor, classify, taproot, ManagedKey, PolicyType, PreferredScriptType,
    SpendingCondition, TaprootLeafInfo, WalletShape, WalletSpec,
};
use wallet_runtime::{
    add_xprv_signer, list_spending_paths, resolve_policy_path, sign_psbt, PolicyDescriptor,
    SignerKind,
};

const ACCOUNT_PATH: &str = "m/84'/1'/0'";

/// One spending condition: `keys` are seeds, one key is a single-sig
/// condition and several are a `threshold`-of-n.
#[derive(Clone)]
struct Cond {
    id: &'static str,
    timelock: u16,
    threshold: usize,
    keys: Vec<u8>,
}

fn single(id: &'static str, timelock: u16, key: u8) -> Cond {
    Cond {
        id,
        timelock,
        threshold: 1,
        keys: vec![key],
    }
}

fn multi(id: &'static str, timelock: u16, threshold: usize, keys: &[u8]) -> Cond {
    Cond {
        id,
        timelock,
        threshold,
        keys: keys.to_vec(),
    }
}

struct Case {
    name: &'static str,
    script: PreferredScriptType,
    /// `None` is an unspendable primary.
    primary: Option<Cond>,
    recoveries: Vec<Cond>,
}

fn cases() -> Vec<Case> {
    use PreferredScriptType::{Auto, SegwitV0, Taproot};
    let case = |name, script, primary, recoveries| Case {
        name,
        script,
        primary,
        recoveries,
    };
    vec![
        case(
            "single-sig, segwit",
            SegwitV0,
            Some(single("primary", 0, 1)),
            vec![],
        ),
        case(
            "single-sig, taproot",
            Taproot,
            Some(single("primary", 0, 1)),
            vec![],
        ),
        case(
            "2-of-3, segwit",
            SegwitV0,
            Some(multi("primary", 0, 2, &[1, 2, 3])),
            vec![],
        ),
        case(
            "1-of-3, segwit",
            SegwitV0,
            Some(multi("primary", 0, 1, &[1, 2, 3])),
            vec![],
        ),
        case(
            "2-of-3, taproot",
            Taproot,
            Some(multi("primary", 0, 2, &[1, 2, 3])),
            vec![],
        ),
        case(
            "single primary + single recovery",
            Auto,
            Some(single("primary", 0, 1)),
            vec![single("recovery", 10, 2)],
        ),
        case(
            "single primary + multisig recovery",
            Auto,
            Some(single("primary", 0, 1)),
            vec![multi("recovery", 10, 2, &[2, 3, 4])],
        ),
        case(
            "single primary + two recoveries",
            Auto,
            Some(single("primary", 0, 1)),
            vec![single("heir", 10, 2), multi("lawyers", 20, 2, &[3, 4])],
        ),
        case(
            "multisig primary + single recovery",
            Auto,
            Some(multi("primary", 0, 2, &[1, 2, 3])),
            vec![single("recovery", 10, 4)],
        ),
        case(
            "multisig primary + multisig recovery",
            Auto,
            Some(multi("primary", 0, 2, &[1, 2, 3])),
            vec![multi("recovery", 10, 2, &[4, 5, 6])],
        ),
        case(
            "multisig primary + two recoveries",
            Auto,
            Some(multi("primary", 0, 2, &[1, 2, 3])),
            vec![multi("heirs", 10, 2, &[4, 5]), single("lawyer", 20, 6)],
        ),
        case(
            "multisig primary + three recoveries",
            Auto,
            Some(multi("primary", 0, 2, &[1, 2])),
            vec![
                single("a", 10, 3),
                multi("b", 20, 2, &[4, 5, 6]),
                single("c", 30, 7),
            ],
        ),
        case(
            "single primary + three recoveries",
            Auto,
            Some(single("primary", 0, 1)),
            vec![
                multi("a", 10, 2, &[2, 3]),
                single("b", 20, 4),
                single("c", 30, 5),
            ],
        ),
        case(
            "single primary + 1-of-3 recovery",
            Auto,
            Some(single("primary", 0, 1)),
            vec![multi("recovery", 10, 1, &[2, 3, 4])],
        ),
        case(
            "3-of-3 primary + 2-of-2 recovery",
            Auto,
            Some(multi("primary", 0, 3, &[1, 2, 3])),
            vec![multi("recovery", 10, 2, &[4, 5])],
        ),
        case(
            "unspendable primary + 1-of-2 recovery",
            Auto,
            None,
            vec![multi("recovery", 10, 1, &[1, 2])],
        ),
        case(
            "unspendable primary + three recoveries",
            Auto,
            None,
            vec![
                single("a", 10, 1),
                multi("b", 20, 2, &[2, 3, 4]),
                single("c", 30, 5),
            ],
        ),
        case(
            "unspendable primary + single recovery",
            Auto,
            None,
            vec![single("recovery", 10, 1)],
        ),
        case(
            "unspendable primary + multisig recovery",
            Auto,
            None,
            vec![multi("recovery", 10, 2, &[1, 2, 3])],
        ),
        case(
            "unspendable primary + two recoveries",
            Auto,
            None,
            vec![multi("heirs", 10, 2, &[1, 2]), single("lawyer", 20, 3)],
        ),
    ]
}

struct Key {
    device_id: String,
    account_xprv: Xpriv,
    managed: ManagedKey,
}

fn key(seed: u8) -> Key {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Regtest, &[seed; 64]).expect("valid seed");
    let fingerprint = format!("{:08x}", master.fingerprint(&secp));
    let account_xprv = master
        .derive_priv(&secp, &DerivationPath::from_str(ACCOUNT_PATH).unwrap())
        .expect("derive account");
    let account_xpub = Xpub::from_priv(&secp, &account_xprv);
    Key {
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

fn fingerprints(cond: &Cond) -> Vec<String> {
    let mut fps: Vec<String> = cond
        .keys
        .iter()
        .map(|seed| key(*seed).managed.fingerprint)
        .collect();
    fps.sort();
    fps
}

struct Built {
    wallet: Wallet,
    external: String,
    /// Stored policy descriptor and leaf metadata; `None` for flat shapes.
    policy: Option<(String, Vec<TaprootLeafInfo>)>,
}

fn spec(case: &Case) -> WalletSpec {
    let mut conditions = Vec::new();
    let mut managed_keys = BTreeMap::new();
    let mut push = |cond: &Cond, is_primary: bool| {
        conditions.push(SpendingCondition {
            id: cond.id.to_string(),
            is_primary,
            timelock: cond.timelock,
            threshold: cond.threshold,
            policy: if cond.keys.len() == 1 {
                PolicyType::Single
            } else {
                PolicyType::Multi
            },
            managed_key_ids: cond.keys.iter().map(|s| format!("device-{}", s)).collect(),
            is_unspendable: false,
        });
        for seed in &cond.keys {
            let k = key(*seed);
            managed_keys.insert(k.device_id, k.managed);
        }
    };
    if let Some(primary) = &case.primary {
        push(primary, true);
    }
    for recovery in &case.recoveries {
        push(recovery, false);
    }
    if case.primary.is_none() {
        conditions.insert(
            0,
            SpendingCondition {
                id: "primary".to_string(),
                is_primary: true,
                timelock: 0,
                threshold: 0,
                policy: PolicyType::Single,
                managed_key_ids: Vec::new(),
                is_unspendable: true,
            },
        );
    }

    WalletSpec {
        network: Network::Regtest,
        conditions,
        managed_keys,
        preferred_script_type: case.script,
    }
}

fn build(case: &Case) -> Built {
    let spec = spec(case);
    spec.validate().expect("valid spec");
    let shape = classify(&spec).expect("classify");
    let pair = build_descriptor(&shape).expect("descriptor");

    let policy = match (&shape, &pair.policy_descriptor) {
        (
            WalletShape::TimelockedPolicy {
                primary_id,
                primary,
                recoveries,
            },
            Some(desc),
        ) => {
            let leaves = taproot::extract(primary_id, primary, recoveries, desc)
                .expect("taproot metadata")
                .leaves;
            Some((desc.to_string(), leaves))
        }
        _ => None,
    };
    assert_eq!(
        policy.is_some(),
        !case.recoveries.is_empty(),
        "{}: only shapes with recoveries are timelocked policies",
        case.name
    );

    let mut wallet = Wallet::create(pair.external.clone(), pair.internal)
        .network(Network::Regtest)
        .create_wallet_no_persist()
        .expect("BDK wallet");
    insert_checkpoint(&mut wallet, block(100));
    receive_output_in_latest_block(&mut wallet, 100_000);
    insert_checkpoint(&mut wallet, block(200));

    Built {
        wallet,
        external: pair.external,
        policy,
    }
}

fn block(height: u32) -> BlockId {
    BlockId {
        height,
        hash: bdk_wallet::bitcoin::hashes::Hash::hash(&height.to_le_bytes()),
    }
}

fn spend(wallet: &mut Wallet, policy_path: Option<BTreeMap<String, Vec<usize>>>) -> Psbt {
    let destination = Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    let mut builder = wallet.build_tx();
    builder
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .add_recipient(destination.script_pubkey(), Amount::from_sat(50_000));
    if let Some(path) = policy_path {
        builder
            .policy_path(path.clone(), KeychainKind::External)
            .policy_path(path, KeychainKind::Internal);
    }
    builder.finish().expect("spend builds")
}

/// Sign with the last `threshold` keys of the condition, so a
/// multisig never passes by using more signers than it requires.
fn sign(wallet: &mut Wallet, psbt: &mut Psbt, cond: &Cond, kind: SignerKind) {
    for seed in cond.keys.iter().rev().take(cond.threshold) {
        add_xprv_signer(
            wallet,
            &key(*seed).account_xprv,
            KeychainKind::External,
            0,
            kind,
        )
        .expect("add signer");
    }
    sign_psbt(wallet, psbt).expect("sign");
}

/// Leaf revealed by a finalized taproot input: `None` for a key-path
/// spend, the hex `TapLeafHash` for a script-path spend.
fn revealed_leaf(psbt: &Psbt) -> Option<String> {
    let witness = psbt.inputs[0]
        .final_script_witness
        .as_ref()
        .expect("finalized");
    if witness.len() == 1 {
        return None;
    }
    let script = Script::from_bytes(&witness[witness.len() - 2]);
    Some(TapLeafHash::from_script(script, LeafVersion::TapScript).to_string())
}

fn spend_flat(case: &Case) {
    let primary = case.primary.as_ref().expect("flat shapes have a primary");
    let mut built = build(case);
    let kind = if !built.external.starts_with("tr(") {
        SignerKind::SegwitV0
    } else if primary.keys.len() == 1 {
        SignerKind::TaprootKeyPath
    } else {
        SignerKind::TaprootScriptPath
    };

    let mut psbt = spend(&mut built.wallet, None);
    sign(&mut built.wallet, &mut psbt, primary, kind);
    psbt.finalize_mut(&Secp256k1::new())
        .unwrap_or_else(|e| panic!("{}: does not finalize: {:?}", case.name, e));
    psbt.extract_tx().expect("extracts");
}

fn spend_policy_path(case: &Case, cond: &Cond) {
    let name = format!("{} / {}", case.name, cond.id);
    let mut built = build(case);
    let (stored, leaves) = built.policy.clone().expect("timelocked policy");
    let leaf = leaves
        .iter()
        .find(|l| l.spending_condition_id == cond.id)
        .unwrap_or_else(|| panic!("{}: no leaf metadata", name));
    let desc = PolicyDescriptor::from_str(&stored)
        .unwrap_or_else(|e| panic!("{}: stored descriptor unreadable: {}", name, e));

    let policy_path = resolve_policy_path(&built.wallet, &leaf.leaf_hash, Some(&desc))
        .unwrap_or_else(|e| panic!("{}: leaf does not resolve: {}", name, e));
    let mut psbt = spend(&mut built.wallet, Some(policy_path));

    let sequence = psbt.unsigned_tx.input[0].sequence;
    if cond.timelock == 0 {
        assert!(
            !sequence.is_relative_lock_time(),
            "{}: primary spend must not carry a relative timelock, got {}",
            name,
            sequence
        );
    } else {
        assert_eq!(
            sequence,
            Sequence::from_height(cond.timelock),
            "{}: nSequence must commit to this path's own timelock",
            name
        );
    }

    let keypath = leaf.leaf_hash == "keypath";
    let kind = if keypath {
        SignerKind::TaprootKeyPath
    } else {
        SignerKind::TaprootScriptPath
    };
    sign(&mut built.wallet, &mut psbt, cond, kind);
    if keypath {
        assert!(psbt.inputs[0].tap_key_sig.is_some(), "{}: key sig", name);
    } else {
        assert_eq!(
            psbt.inputs[0].tap_script_sigs.len(),
            cond.threshold,
            "{}: one script signature per signer",
            name
        );
    }

    psbt.finalize_mut(&Secp256k1::new())
        .unwrap_or_else(|e| panic!("{}: does not finalize: {:?}", name, e));
    assert_eq!(
        revealed_leaf(&psbt),
        (!keypath).then(|| leaf.leaf_hash.clone()),
        "{}: spend must go through this path's own leaf",
        name
    );
    psbt.extract_tx().expect("extracts");
}

/// `list_spending_paths` must offer exactly the spendable conditions, and
/// point each one at the same policy child the leaf resolver picks.
fn check_listed_paths(case: &Case) {
    let built = build(case);
    let (stored, leaves) = built.policy.clone().expect("timelocked policy");
    let desc = PolicyDescriptor::from_str(&stored).expect("readable");
    let external = built
        .wallet
        .policies(KeychainKind::External)
        .unwrap()
        .expect("external policy");
    let listed = list_spending_paths("timelocked", &stored, &[], Some(external.id.as_str()))
        .unwrap_or_else(|e| panic!("{}: paths not listed: {}", case.name, e));

    let conds: Vec<&Cond> = case.primary.iter().chain(case.recoveries.iter()).collect();
    assert_eq!(listed.len(), conds.len(), "{}: path count", case.name);

    for cond in conds {
        let name = format!("{} / {}", case.name, cond.id);
        let wanted = (cond.timelock != 0).then_some(cond.timelock as u32);
        let path = listed
            .iter()
            .find(|p| p.timelock_blocks == wanted)
            .unwrap_or_else(|| panic!("{}: not listed", name));
        let mut listed_fps = path.fingerprints.clone();
        listed_fps.sort();
        assert_eq!(listed_fps, fingerprints(cond), "{}: signers", name);
        assert_eq!(
            path.threshold as usize, cond.threshold,
            "{}: threshold",
            name
        );

        let leaf = leaves
            .iter()
            .find(|l| l.spending_condition_id == cond.id)
            .unwrap_or_else(|| panic!("{}: no leaf metadata", name));
        let resolved = resolve_policy_path(&built.wallet, &leaf.leaf_hash, Some(&desc))
            .unwrap_or_else(|e| panic!("{}: leaf does not resolve: {}", name, e));
        assert_eq!(
            path.policy_path.as_ref(),
            Some(&resolved),
            "{}: listed and resolved policy paths disagree",
            name
        );
    }
}

#[test]
fn every_shape_spends_through_every_path() {
    let mut failures = Vec::new();
    for case in cases() {
        let mut runs: Vec<(String, Box<dyn Fn() + '_>)> = Vec::new();
        if case.recoveries.is_empty() {
            runs.push((case.name.to_string(), Box::new(|| spend_flat(&case))));
        } else {
            for cond in case.primary.iter().chain(case.recoveries.iter()) {
                let case = &case;
                runs.push((
                    format!("{} / {}", case.name, cond.id),
                    Box::new(move || spend_policy_path(case, cond)),
                ));
            }
            runs.push((
                format!("{} / listed paths", case.name),
                Box::new(|| check_listed_paths(&case)),
            ));
        }
        for (name, run) in runs {
            if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
                let reason = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "panicked".to_string());
                failures.push(format!("{}: {}", name, reason));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} path(s) failed:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// Shapes that cannot be spent through every path must be refused when
/// the wallet is created, never accepted and left unspendable.
#[test]
fn unsupported_shapes_are_refused_at_creation() {
    use PreferredScriptType::{Auto, SegwitV0};
    let refused = [
        Case {
            name: "1-of-2 primary + recovery",
            script: Auto,
            primary: Some(multi("primary", 0, 1, &[1, 2])),
            recoveries: vec![single("recovery", 10, 3)],
        },
        Case {
            name: "same key in primary and recovery",
            script: Auto,
            primary: Some(single("primary", 0, 1)),
            recoveries: vec![multi("recovery", 10, 2, &[1, 2])],
        },
        Case {
            name: "two recoveries with the same timelock",
            script: Auto,
            primary: Some(single("primary", 0, 1)),
            recoveries: vec![single("a", 10, 2), single("b", 10, 3)],
        },
        Case {
            name: "segwit with a recovery",
            script: SegwitV0,
            primary: Some(single("primary", 0, 1)),
            recoveries: vec![single("recovery", 10, 2)],
        },
    ];
    for case in &refused {
        let spec = spec(case);
        let created = spec
            .validate()
            .and_then(|_| classify(&spec))
            .and_then(|shape| build_descriptor(&shape));
        assert!(created.is_err(), "{}: must be refused", case.name);
    }
}
