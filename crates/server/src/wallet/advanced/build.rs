use policy_core::{
    descriptor, shape, taproot, DescriptorPair, TaprootLeafInfo, WalletShape, WalletSpec,
};

use crate::db::StoredWallet;
use crate::wallet::advanced::error::WalletCreationError;
use crate::wallet::bdk::BdkWalletManager;

#[derive(Debug, Clone)]
pub struct WalletBuildResult {
    pub wallet_id: String,
    pub external_descriptor: String,
    pub internal_descriptor: String,
    /// Canonical multipath policy descriptor for `TimelockedPolicy` wallets.
    /// `None` for flat single-sig / multisig / taproot-multisig wallets —
    /// those have no policy descriptor to persist, and downstream code
    /// (PSBT pruning, leaf resolution in the signer) treats `None` as
    /// "skip policy-descriptor steps".
    pub policy_descriptor: Option<String>,
    pub taproot_leaf_info: Vec<TaprootLeafInfo>,
    pub merkle_root: Option<String>,
    pub internal_key: Option<String>,
}

/// Drive the full wallet-creation pipeline:
/// validate spec → classify into a `WalletShape` → build descriptors →
/// persist BDK wallet state → extract taproot metadata when applicable.
pub fn build_wallet(
    spec: &WalletSpec,
    stored_wallet: &StoredWallet,
) -> Result<WalletBuildResult, WalletCreationError> {
    if stored_wallet.wallet_id.is_empty() {
        return Err(WalletCreationError::invalid_policy("Wallet ID is required"));
    }

    spec.validate()?;
    let shape = shape::classify(spec)?;
    let DescriptorPair {
        external,
        internal,
        policy_descriptor,
    } = descriptor::build(&shape)?;

    log::info!(
        "Built wallet shape {:?} for wallet {}",
        shape_label(&shape),
        stored_wallet.wallet_id
    );

    BdkWalletManager::new(spec.network).create_wallet_with_descriptors(
        stored_wallet,
        &external,
        &internal,
    )?;

    let metadata = match (&shape, policy_descriptor.as_ref()) {
        (
            WalletShape::TimelockedPolicy {
                primary_id,
                primary,
                recoveries,
            },
            Some(desc),
        ) => taproot::extract(primary_id, primary, recoveries, desc)?,
        _ => taproot::TaprootMetadata::default(),
    };

    Ok(WalletBuildResult {
        wallet_id: stored_wallet.wallet_id.clone(),
        external_descriptor: external,
        internal_descriptor: internal,
        policy_descriptor: policy_descriptor.map(|d| d.to_string()),
        taproot_leaf_info: metadata.leaves,
        merkle_root: metadata.merkle_root,
        internal_key: metadata.internal_key,
    })
}

fn shape_label(shape: &WalletShape) -> &'static str {
    match shape {
        WalletShape::SingleSig { .. } => "SingleSig",
        WalletShape::Multisig { .. } => "Multisig",
        WalletShape::TimelockedPolicy { .. } => "TimelockedPolicy",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::sync::Once;
    use std::time::{SystemTime, UNIX_EPOCH};

    use bdk_wallet::bitcoin::bip32::{Xpriv, Xpub};
    use bdk_wallet::bitcoin::secp256k1::Secp256k1;
    use bdk_wallet::bitcoin::Network;

    use crate::db::{self, StoredWallet};
    use policy_core::{
        managed_key::ManagedKey, spec::PolicyType, spec::PreferredScriptType,
        spec::SpendingCondition, PolicyError,
    };

    // ---- env / storage bootstrap ----------------------------------------

    /// Bootstrap a process-wide tempdir backing the global `StorageManager`.
    /// Called from every test that touches `BdkWalletManager`. Idempotent and
    /// safe to call from any number of parallel tests — `Once` guarantees
    /// exactly one tempdir-allocation race winner per process.
    fn setup_test_storage() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "walletrs-build-tests-{}-{}",
                std::process::id(),
                stamp
            ));
            std::fs::create_dir_all(&dir).expect("create test storage dir");
            let _ = db::__test_init_storage_with_path(dir.to_str().expect("tempdir path is utf-8"));
        });
    }

    /// Generate a unique-per-test wallet id so parallel tests sharing the
    /// process-wide tempdir do not collide on stored objects.
    fn unique_wallet_id(prefix: &str) -> String {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{}-{}-{}", prefix, std::process::id(), stamp)
    }

    fn stored(wallet_id: &str) -> StoredWallet {
        StoredWallet::new(wallet_id, "test-user", "test", "testnet", "advanced")
    }

    // ---- key + spec builders --------------------------------------------

    fn make_key(seed: u64) -> (String, ManagedKey) {
        let mut bytes = [0u8; 64];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        // Mix in a per-process distinct prefix so tests run in different
        // processes don't accidentally produce identical wallets in the
        // same tempdir.
        bytes[8..16].copy_from_slice(&(std::process::id() as u64).to_le_bytes());

        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(Network::Testnet, &bytes).expect("valid seed");
        let xpub = Xpub::from_priv(&secp, &xpriv);
        let fp = format!("{:08x}", xpriv.fingerprint(&secp));
        let multipath_xpub = format!("[{}]{}/<0;1>/*", fp, xpub);
        (
            format!("d{}", seed),
            ManagedKey {
                fingerprint: fp,
                derivation_path: "m/84'/1'/0'".to_string(),
                xpub: multipath_xpub,
                tpub: None,
            },
        )
    }

    fn single_sig_spec() -> WalletSpec {
        let (id1, k1) = make_key(101);
        let mut keys = BTreeMap::new();
        keys.insert(id1.clone(), k1);
        WalletSpec {
            network: Network::Testnet,
            conditions: vec![SpendingCondition {
                id: "primary".into(),
                is_primary: true,
                timelock: 0,
                threshold: 1,
                policy: PolicyType::Single,
                managed_key_ids: vec![id1],
                is_unspendable: false,
            }],
            managed_keys: keys,
            preferred_script_type: PreferredScriptType::Auto,
        }
    }

    fn multisig_spec() -> WalletSpec {
        let (id1, k1) = make_key(201);
        let (id2, k2) = make_key(202);
        let (id3, k3) = make_key(203);
        let mut keys = BTreeMap::new();
        keys.insert(id1.clone(), k1);
        keys.insert(id2.clone(), k2);
        keys.insert(id3.clone(), k3);
        WalletSpec {
            network: Network::Testnet,
            conditions: vec![SpendingCondition {
                id: "primary".into(),
                is_primary: true,
                timelock: 0,
                threshold: 2,
                policy: PolicyType::Multi,
                managed_key_ids: vec![id1, id2, id3],
                is_unspendable: false,
            }],
            managed_keys: keys,
            preferred_script_type: PreferredScriptType::Auto,
        }
    }

    fn timelocked_policy_spec() -> WalletSpec {
        let (id1, k1) = make_key(301);
        let (id2, k2) = make_key(302);
        let (id3, k3) = make_key(303);
        let mut keys = BTreeMap::new();
        keys.insert(id1.clone(), k1);
        keys.insert(id2.clone(), k2);
        keys.insert(id3.clone(), k3);
        WalletSpec {
            network: Network::Testnet,
            conditions: vec![
                SpendingCondition {
                    id: "primary".into(),
                    is_primary: true,
                    timelock: 0,
                    threshold: 2,
                    policy: PolicyType::Multi,
                    managed_key_ids: vec![id1, id2],
                    is_unspendable: false,
                },
                SpendingCondition {
                    id: "recovery".into(),
                    is_primary: false,
                    timelock: 144,
                    threshold: 1,
                    policy: PolicyType::Single,
                    managed_key_ids: vec![id3],
                    is_unspendable: false,
                },
            ],
            managed_keys: keys,
            preferred_script_type: PreferredScriptType::Auto,
        }
    }

    fn unspendable_primary_spec() -> WalletSpec {
        let (id_rec, k_rec) = make_key(401);
        let mut keys = BTreeMap::new();
        keys.insert(id_rec.clone(), k_rec);
        WalletSpec {
            network: Network::Testnet,
            conditions: vec![
                SpendingCondition {
                    id: "primary".into(),
                    is_primary: true,
                    timelock: 0,
                    threshold: 0,
                    policy: PolicyType::Single,
                    managed_key_ids: Vec::new(),
                    is_unspendable: true,
                },
                SpendingCondition {
                    id: "recovery".into(),
                    is_primary: false,
                    timelock: 144,
                    threshold: 1,
                    policy: PolicyType::Single,
                    managed_key_ids: vec![id_rec],
                    is_unspendable: false,
                },
            ],
            managed_keys: keys,
            preferred_script_type: PreferredScriptType::Auto,
        }
    }

    // ---- guard tests (no storage needed) --------------------------------

    #[test]
    fn build_wallet_rejects_empty_wallet_id() {
        let spec = single_sig_spec();
        let result = build_wallet(&spec, &stored(""));
        let err = result.expect_err("empty wallet_id must be rejected");
        match err {
            WalletCreationError::Policy(PolicyError::InvalidPolicy(msg)) => {
                assert!(
                    msg.contains("Wallet ID"),
                    "error should mention wallet id, got: {}",
                    msg
                );
            }
            other => panic!("expected InvalidPolicy(Wallet ID), got {:?}", other),
        }
    }

    #[test]
    fn build_wallet_propagates_spec_validation_failure() {
        // Two primary conditions — spec.validate() rejects this.
        let (id1, k1) = make_key(501);
        let (id2, k2) = make_key(502);
        let mut keys = BTreeMap::new();
        keys.insert(id1.clone(), k1);
        keys.insert(id2.clone(), k2);
        let bad_spec = WalletSpec {
            network: Network::Testnet,
            conditions: vec![
                SpendingCondition {
                    id: "p1".into(),
                    is_primary: true,
                    timelock: 0,
                    threshold: 1,
                    policy: PolicyType::Single,
                    managed_key_ids: vec![id1],
                    is_unspendable: false,
                },
                SpendingCondition {
                    id: "p2".into(),
                    is_primary: true,
                    timelock: 0,
                    threshold: 1,
                    policy: PolicyType::Single,
                    managed_key_ids: vec![id2],
                    is_unspendable: false,
                },
            ],
            managed_keys: keys,
            preferred_script_type: PreferredScriptType::Auto,
        };
        let err = build_wallet(&bad_spec, &stored(&unique_wallet_id("bad-spec")))
            .expect_err("multi-primary spec must be rejected before persistence");
        assert!(matches!(err, WalletCreationError::Policy(_)));
    }

    #[test]
    fn build_wallet_propagates_classify_failure() {
        // SegwitV0 preferred + recovery condition is rejected by classify
        // (TimelockedPolicy requires Taproot).
        let (id1, k1) = make_key(601);
        let (id2, k2) = make_key(602);
        let mut keys = BTreeMap::new();
        keys.insert(id1.clone(), k1);
        keys.insert(id2.clone(), k2);
        let bad_spec = WalletSpec {
            network: Network::Testnet,
            conditions: vec![
                SpendingCondition {
                    id: "primary".into(),
                    is_primary: true,
                    timelock: 0,
                    threshold: 1,
                    policy: PolicyType::Single,
                    managed_key_ids: vec![id1],
                    is_unspendable: false,
                },
                SpendingCondition {
                    id: "recovery".into(),
                    is_primary: false,
                    timelock: 144,
                    threshold: 1,
                    policy: PolicyType::Single,
                    managed_key_ids: vec![id2],
                    is_unspendable: false,
                },
            ],
            managed_keys: keys,
            preferred_script_type: PreferredScriptType::SegwitV0,
        };
        let err = build_wallet(&bad_spec, &stored(&unique_wallet_id("bad-classify")))
            .expect_err("SegwitV0 + recovery should be rejected at classify");
        assert!(matches!(err, WalletCreationError::Policy(_)));
    }

    // ---- happy-path tests (need real storage) ---------------------------

    #[test]
    fn build_wallet_single_sig_succeeds_with_no_taproot_metadata() {
        setup_test_storage();
        let wallet_id = unique_wallet_id("single-sig");
        let result = build_wallet(&single_sig_spec(), &stored(&wallet_id))
            .expect("single-sig build should succeed");

        assert_eq!(result.wallet_id, wallet_id);
        assert!(
            result.external_descriptor.starts_with("wpkh("),
            "single-sig defaults to wpkh, got {}",
            result.external_descriptor
        );
        assert!(result.internal_descriptor.starts_with("wpkh("));
        assert!(
            result.policy_descriptor.is_none(),
            "flat single-sig must not produce a policy descriptor"
        );
        assert!(
            result.taproot_leaf_info.is_empty(),
            "flat single-sig has no taproot leaves"
        );
        assert!(result.merkle_root.is_none());
        assert!(result.internal_key.is_none());
    }

    #[test]
    fn build_wallet_multisig_succeeds_with_no_taproot_metadata() {
        setup_test_storage();
        let wallet_id = unique_wallet_id("multisig");
        let result = build_wallet(&multisig_spec(), &stored(&wallet_id))
            .expect("multisig build should succeed");

        assert_eq!(result.wallet_id, wallet_id);
        assert!(
            result.external_descriptor.starts_with("wsh(sortedmulti(2,"),
            "2-of-3 multisig must use wsh+sortedmulti, got: {}",
            result.external_descriptor
        );
        assert!(result.policy_descriptor.is_none());
        assert!(result.taproot_leaf_info.is_empty());
    }

    #[test]
    fn build_wallet_timelocked_policy_populates_taproot_metadata() {
        setup_test_storage();
        let wallet_id = unique_wallet_id("timelocked");
        let result = build_wallet(&timelocked_policy_spec(), &stored(&wallet_id))
            .expect("timelocked-policy build should succeed");

        assert_eq!(result.wallet_id, wallet_id);
        let policy = result
            .policy_descriptor
            .as_ref()
            .expect("TimelockedPolicy must produce a policy descriptor");
        // Smoke-check the canonical multipath shape.
        assert!(
            policy.contains("<0;1>/*"),
            "policy descriptor should be multipath, got: {}",
            policy
        );
        assert!(
            !result.taproot_leaf_info.is_empty(),
            "TimelockedPolicy must surface at least one taproot leaf"
        );
        let ids: Vec<_> = result
            .taproot_leaf_info
            .iter()
            .map(|l| l.spending_condition_id.as_str())
            .collect();
        assert!(ids.contains(&"primary"));
        assert!(ids.contains(&"recovery"));
        assert!(
            result.merkle_root.is_some(),
            "TimelockedPolicy taproot must expose a merkle root"
        );
        assert!(
            result.internal_key.is_some(),
            "TimelockedPolicy taproot must expose an internal key"
        );
    }

    #[test]
    fn build_wallet_unspendable_primary_succeeds_and_marks_recovery_path() {
        setup_test_storage();
        let wallet_id = unique_wallet_id("unspendable-primary");
        let result = build_wallet(&unspendable_primary_spec(), &stored(&wallet_id))
            .expect("unspendable-primary + recovery must build");

        // The wallet's primary leaf has the NUMS xpub substituted in; the
        // taproot metadata still has a leaf for "recovery".
        let ids: Vec<_> = result
            .taproot_leaf_info
            .iter()
            .map(|l| l.spending_condition_id.as_str())
            .collect();
        assert!(
            ids.contains(&"recovery"),
            "recovery leaf must exist when primary is unspendable, got: {:?}",
            ids
        );
        assert!(
            result.policy_descriptor.is_some(),
            "unspendable-primary path is a TimelockedPolicy and must have a descriptor"
        );
    }

    #[test]
    fn build_wallet_descriptors_match_descriptor_build_output() {
        setup_test_storage();
        let spec = timelocked_policy_spec();
        let wallet_id = unique_wallet_id("desc-match");
        let result = build_wallet(&spec, &stored(&wallet_id)).expect("build succeeds");

        // Re-derive the descriptor pair from the same spec and make sure
        // build_wallet returned exactly what the pure pipeline produces —
        // i.e. no accidental rewrapping or string mutation in the
        // orchestrator. Catches future regressions where someone wraps
        // the descriptor before returning it.
        let shape = shape::classify(&spec).expect("classify");
        let pair = descriptor::build(&shape).expect("descriptor build");
        assert_eq!(result.external_descriptor, pair.external);
        assert_eq!(result.internal_descriptor, pair.internal);
        assert_eq!(
            result.policy_descriptor,
            pair.policy_descriptor.map(|d| d.to_string())
        );
    }

    #[test]
    fn build_wallet_taproot_leaves_consistent_with_extract() {
        setup_test_storage();
        let spec = timelocked_policy_spec();
        let wallet_id = unique_wallet_id("taproot-match");
        let result = build_wallet(&spec, &stored(&wallet_id)).expect("build succeeds");

        // Re-extract taproot metadata directly from the same shape; should
        // match what build_wallet returned. Same regression-protection
        // shape as the descriptor test above.
        let shape = shape::classify(&spec).expect("classify");
        let pair = descriptor::build(&shape).expect("descriptor build");
        let policy_desc = pair.policy_descriptor.expect("policy descriptor present");
        let (primary_id, primary, recoveries) = match &shape {
            WalletShape::TimelockedPolicy {
                primary_id,
                primary,
                recoveries,
            } => (primary_id.clone(), primary.clone(), recoveries.clone()),
            other => panic!("expected TimelockedPolicy, got {:?}", other),
        };
        let direct =
            taproot::extract(&primary_id, &primary, &recoveries, &policy_desc).expect("extract");

        assert_eq!(result.taproot_leaf_info.len(), direct.leaves.len());
        for (got, want) in result.taproot_leaf_info.iter().zip(direct.leaves.iter()) {
            assert_eq!(got.spending_condition_id, want.spending_condition_id);
            assert_eq!(got.leaf_hash, want.leaf_hash);
        }
        assert_eq!(result.merkle_root, direct.merkle_root);
        assert_eq!(result.internal_key, direct.internal_key);
    }

    #[test]
    fn build_wallet_distinct_ids_persist_independently() {
        setup_test_storage();
        let spec = single_sig_spec();
        let id_a = unique_wallet_id("indep-a");
        let id_b = unique_wallet_id("indep-b");

        let a = build_wallet(&spec, &stored(&id_a)).expect("first build");
        let b = build_wallet(&spec, &stored(&id_b)).expect("second build");

        assert_eq!(a.wallet_id, id_a);
        assert_eq!(b.wallet_id, id_b);
        // Same spec → same descriptors (a fresh build is deterministic for
        // a given spec). What this asserts is that build_wallet doesn't
        // smuggle in wallet-id-dependent randomness.
        assert_eq!(a.external_descriptor, b.external_descriptor);
        assert_eq!(a.internal_descriptor, b.internal_descriptor);
    }

    #[test]
    fn build_wallet_rebuilding_same_id_overwrites_cleanly() {
        // BdkWalletManager::create_wallet_with_descriptors deletes any
        // prior local + remote state for the wallet id; a second
        // build_wallet call with the same id must therefore succeed,
        // not error out on "store already initialised".
        setup_test_storage();
        let spec = single_sig_spec();
        let wallet_id = unique_wallet_id("overwrite");

        let first = build_wallet(&spec, &stored(&wallet_id)).expect("first build");
        let second = build_wallet(&spec, &stored(&wallet_id)).expect("rebuild same id");
        assert_eq!(first.external_descriptor, second.external_descriptor);
    }

    #[test]
    fn build_wallet_no_panic_on_repeated_calls_under_concurrency() {
        // Best-effort concurrency smoke test: spawn N threads each building
        // a wallet under a unique id. Catches future regressions where
        // the per-wallet lock or storage init becomes racy.
        setup_test_storage();
        let mut handles = Vec::new();
        for i in 0..4 {
            let h = std::thread::spawn(move || {
                let id = unique_wallet_id(&format!("concurrent-{}", i));
                let spec = single_sig_spec();
                let res = build_wallet(&spec, &stored(&id));
                assert!(res.is_ok(), "concurrent build {} failed: {:?}", i, res);
            });
            handles.push(h);
        }
        for h in handles {
            h.join().expect("test thread panicked");
        }
    }
}
