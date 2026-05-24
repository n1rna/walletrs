//! Walletrs PSBT signing surface.
//!
//! Holds the server-side glue: managed-key lookup against the walletrs DB,
//! plus thin wrappers around `wallet_runtime` that translate
//! `WalletRuntimeError` into `tonic::Status`. The descriptor / shape /
//! taproot pipeline is in `policy-core`, and the BDK signer mechanics
//! (analysis, key registration, sign call, leaf-path resolution) are in
//! `wallet-runtime`.

use std::collections::BTreeMap;
use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::{Fingerprint, Xpriv};
use bdk_wallet::bitcoin::Psbt;
use bdk_wallet::{KeychainKind, Wallet};
use log::{debug, info, warn};
use tonic::Status;
use wallet_runtime::{
    add_xprv_signer, analyze_for_signing, resolve_policy_path_from_leaf as wr_resolve_path,
    sign_psbt as wr_sign_psbt, PsbtSignerAnalysis, SignerKind,
};

use crate::db;
use crate::LianaDescriptor;

/// Parse the 8-hex-character fingerprint that was persisted for a managed
/// key. A failure here is *storage corruption* (a real managed key always
/// has a valid fingerprint), not caller error, so it surfaces as
/// `Status::internal` and includes the device id so operators can find
/// the offending row.
///
/// The previous code did `unwrap_or_default()` which silently substituted
/// the zero fingerprint, causing the signer to pick the wrong derivations
/// for taproot inputs. See the regression test in this module.
pub(crate) fn parse_stored_fingerprint(
    fingerprint_hex: &str,
    device_id: &str,
) -> Result<Fingerprint, Status> {
    Fingerprint::from_str(fingerprint_hex).map_err(|e| {
        Status::internal(format!(
            "Stored fingerprint {:?} for device {} is unparseable: {}",
            fingerprint_hex, device_id, e
        ))
    })
}

/// Look up the system managed key for `device_id`, analyse the PSBT to find
/// which derivations + signer kind the device needs, and register one signer
/// per required derivation. Returns the count of signers added.
pub fn add_signers_for_psbt(
    wallet: &mut Wallet,
    psbt: &Psbt,
    wallet_id: &str,
    device_id: &str,
) -> Result<i32, Status> {
    if device_id.is_empty() {
        return Err(Status::invalid_argument(
            "Device ID is required for signing",
        ));
    }

    let stored_wallet = db::get_wallet(wallet_id)
        .map_err(|e| Status::internal(format!("Failed to get wallet: {}", e)))?;

    let key = db::get_managed_key(&stored_wallet.user_id, device_id, "system")
        .map_err(|e| {
            Status::internal(format!("Failed to get key for device {}: {}", device_id, e))
        })?
        .ok_or_else(|| {
            Status::not_found(format!("No system key found for device {}", device_id))
        })?;

    if key.key_type != "system" || !key.has_private_key_material() {
        return Err(Status::invalid_argument(format!(
            "Device {} is not a system managed key or lacks private key material",
            device_id
        )));
    }

    let device_fp = parse_stored_fingerprint(&key.fingerprint, &key.device_id)?;
    let mut analysis: PsbtSignerAnalysis = analyze_for_signing(wallet, psbt, &device_fp);

    if analysis.has_taproot_inputs && !analysis.device_in_tap_origins {
        info!(
            "Device {} (fp: {}) not found in tap_key_origins, defaulting to internal key",
            device_id, key.fingerprint
        );
    } else if analysis.has_taproot_inputs {
        info!(
            "Device {} (fp: {}) detected as {} taproot key",
            device_id,
            key.fingerprint,
            match analysis.signer_kind {
                SignerKind::TaprootKeyPath => "internal (keypath)",
                SignerKind::TaprootScriptPath => "script path",
                _ => "taproot",
            }
        );
    } else {
        info!(
            "Device {} (fp: {}) detected as segwit v0 signer",
            device_id, key.fingerprint
        );
    }

    if analysis.required_derivations.is_empty() {
        warn!("No derivation paths found in PSBT - falling back to common 0..5 indices");
        for keychain in [KeychainKind::External, KeychainKind::Internal] {
            for i in 0..5 {
                analysis.required_derivations.push((keychain, i));
            }
        }
    }

    let tpriv_str = key.tpriv.as_ref().ok_or_else(|| {
        Status::internal(format!(
            "Device {} has no tpriv (account-level xpriv) stored",
            key.device_id
        ))
    })?;

    let account_xpriv = Xpriv::from_str(tpriv_str).map_err(|e| {
        Status::internal(format!(
            "Failed to parse account xpriv for device {}: {}",
            key.device_id, e
        ))
    })?;

    let mut added = 0i32;
    for (keychain, index) in &analysis.required_derivations {
        match add_xprv_signer(
            wallet,
            &account_xpriv,
            *keychain,
            *index,
            analysis.signer_kind,
        ) {
            Ok(()) => {
                added += 1;
                debug!(
                    "✓ Added signer for {:?}/{} from {} (kind: {:?})",
                    keychain, index, key.device_id, analysis.signer_kind
                );
            }
            Err(e) => {
                warn!("Failed to add signer at {:?}/{}: {}", keychain, index, e);
            }
        }
    }

    info!("✅ Added {} signers to wallet for signing operation", added);
    Ok(added)
}

/// Sign a PSBT in-place with the wallet's currently-registered signers.
/// Does not finalize — the caller runs miniscript's `finalize_mut` later
/// (see `service::transaction_handling::finalize_wallet_transaction`).
pub fn sign_psbt_with_taproot_support(
    wallet: &Wallet,
    psbt: &mut Psbt,
    wallet_id: &str,
) -> Result<Option<Psbt>, Status> {
    info!(
        "=== Starting PSBT Signing Process for wallet: {} ===",
        wallet_id
    );

    let signed_all = wr_sign_psbt(wallet, psbt)
        .map_err(|e| Status::internal(format!("Failed to sign PSBT: {}", e)))?;

    if !signed_all {
        warn!("⚠️ Not all inputs were signed — signers may be missing for some inputs");
    } else {
        info!("✅ BDK sign() returned signed_all_inputs: true");
    }

    Ok(Some(psbt.clone()))
}

/// Map a taproot leaf hash to the BDK policy-path indices needed to spend
/// via that leaf.
///
/// Accepts two leaf-hash forms emitted by `policy_core::taproot::extract`:
/// - `"keypath"` — the primary spends via the taproot internal key.
/// - A hex-encoded `TapLeafHash` — primary or recovery via a script leaf.
///
/// The policy descriptor is required for hex leaf hashes so we can derive
/// the child-zero PSBT input and match leaf hashes against signer
/// fingerprints.
pub fn resolve_policy_path_from_leaf(
    wallet: &bdk_wallet::Wallet,
    leaf_hash: &str,
    policy_descriptor: Option<&LianaDescriptor>,
) -> Result<BTreeMap<String, Vec<usize>>, Status> {
    wr_resolve_path(wallet, leaf_hash, policy_descriptor).map_err(|e| match e.to_string() {
        ref s
            if s.contains("does not match any spending path")
                || s.contains("provided but wallet has no policy descriptor") =>
        {
            Status::invalid_argument(s.clone())
        }
        _ => Status::internal(e.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use bdk_wallet::bitcoin::bip32::{Xpriv, Xpub};
    use bdk_wallet::bitcoin::secp256k1::Secp256k1;
    use bdk_wallet::bitcoin::Network;
    use bdk_wallet::Wallet;

    use crate::wallet::advanced::shape::WalletShape;
    use crate::wallet::advanced::{descriptor, shape, taproot};
    use crate::wallet::advanced::{
        ManagedKey, PolicyType, PreferredScriptType, SpendingCondition, WalletSpec,
    };

    fn make_key(seed: u64) -> (String, ManagedKey) {
        let mut bytes = [0u8; 64];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(Network::Testnet, &bytes).unwrap();
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

    fn build_timelocked_wallet() -> (
        Wallet,
        crate::LianaDescriptor,
        Vec<crate::wallet::advanced::TaprootLeafInfo>,
    ) {
        let (id1, k1) = make_key(1);
        let (id2, k2) = make_key(2);
        let (id3, k3) = make_key(3);

        let mut keys = std::collections::BTreeMap::new();
        keys.insert(id1, k1);
        keys.insert(id2, k2);
        keys.insert(id3, k3);

        let spec = WalletSpec {
            network: Network::Testnet,
            conditions: vec![
                SpendingCondition {
                    id: "primary".to_string(),
                    is_primary: true,
                    timelock: 0,
                    threshold: 2,
                    policy: PolicyType::Multi,
                    managed_key_ids: vec!["d1".to_string(), "d2".to_string()],
                    is_unspendable: false,
                },
                SpendingCondition {
                    id: "recovery".to_string(),
                    is_primary: false,
                    timelock: 144,
                    threshold: 1,
                    policy: PolicyType::Single,
                    is_unspendable: false,
                    managed_key_ids: vec!["d3".to_string()],
                },
            ],
            managed_keys: keys,
            preferred_script_type: PreferredScriptType::Auto,
        };

        let shape = shape::classify(&spec).unwrap();
        let (primary, primary_id, recoveries) = match &shape {
            WalletShape::TimelockedPolicy {
                primary,
                primary_id,
                recoveries,
            } => (primary.clone(), primary_id.clone(), recoveries.clone()),
            other => panic!("expected TimelockedPolicy, got {:?}", other),
        };

        let pair = descriptor::build(&shape).unwrap();
        let policy_desc = pair.policy_descriptor.clone().expect("policy descriptor");

        let metadata = taproot::extract(&primary_id, &primary, &recoveries, &policy_desc).unwrap();

        let wallet = Wallet::create(pair.external.clone(), pair.internal.clone())
            .network(Network::Testnet)
            .create_wallet_no_persist()
            .expect("BDK wallet");

        (wallet, policy_desc, metadata.leaves)
    }

    #[test]
    fn primary_multisig_leaf_resolves_to_zero() {
        let (wallet, policy_desc, leaves) = build_timelocked_wallet();
        let primary = leaves
            .iter()
            .find(|l| l.spending_condition_id == "primary")
            .expect("primary leaf");
        assert_ne!(
            primary.leaf_hash, "keypath",
            "multisig primary lives in the taptree"
        );
        assert!(
            primary.leaf_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "primary leaf hash should be hex, got {}",
            primary.leaf_hash
        );

        let resolved =
            resolve_policy_path_from_leaf(&wallet, &primary.leaf_hash, Some(&policy_desc))
                .expect("resolve primary leaf");
        let path = resolved.values().next().expect("policy path entry");
        assert_eq!(path, &vec![0]);
    }

    #[test]
    fn recovery_leaf_resolves_to_one() {
        let (wallet, policy_desc, leaves) = build_timelocked_wallet();
        let recovery = leaves
            .iter()
            .find(|l| l.spending_condition_id == "recovery")
            .expect("recovery leaf");

        let resolved =
            resolve_policy_path_from_leaf(&wallet, &recovery.leaf_hash, Some(&policy_desc))
                .expect("resolve recovery leaf");
        let path = resolved.values().next().expect("policy path entry");
        assert_eq!(path, &vec![1]);
    }

    #[test]
    fn unknown_leaf_returns_invalid_argument() {
        let (wallet, policy_desc, _) = build_timelocked_wallet();
        let result = resolve_policy_path_from_leaf(&wallet, "deadbeef", Some(&policy_desc));
        let err = result.expect_err("unknown leaf must error");
        assert_eq!(
            err.code(),
            tonic::Code::InvalidArgument,
            "unknown leaf should be InvalidArgument, got: {:?} ({})",
            err.code(),
            err.message()
        );
    }

    #[test]
    fn hex_leaf_without_descriptor_returns_invalid_argument() {
        let (wallet, _, leaves) = build_timelocked_wallet();
        let any_leaf = &leaves[0].leaf_hash;
        let err = resolve_policy_path_from_leaf(&wallet, any_leaf, None)
            .expect_err("hex leaf without descriptor must error");
        // The wrapper specifically maps the "no policy descriptor" case to
        // InvalidArgument (caller forgot to provide it), not Internal.
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ---- broader leaf-resolution coverage --------------------------------

    #[test]
    fn resolve_policy_path_resolves_every_leaf_in_timelocked_wallet() {
        // Invariant: every leaf surfaced by taproot::extract must round-trip
        // through resolve_policy_path_from_leaf. If this ever fails, the
        // taproot metadata is out of sync with the descriptor's policy
        // indexing — which would silently break spending.
        let (wallet, policy_desc, leaves) = build_timelocked_wallet();
        assert!(
            leaves.len() >= 2,
            "timelocked wallet should expose >=2 leaves, got {}",
            leaves.len()
        );

        for leaf in &leaves {
            let resolved =
                resolve_policy_path_from_leaf(&wallet, &leaf.leaf_hash, Some(&policy_desc))
                    .unwrap_or_else(|e| {
                        panic!(
                            "leaf {:?} (cond {:?}) failed to resolve: {} ({:?})",
                            leaf.leaf_hash,
                            leaf.spending_condition_id,
                            e.message(),
                            e.code()
                        )
                    });
            assert!(
                !resolved.is_empty(),
                "leaf {:?} resolved to empty path map",
                leaf.leaf_hash
            );
            for (keychain_key, path) in &resolved {
                assert!(
                    !path.is_empty(),
                    "resolved policy path for keychain {} is empty",
                    keychain_key
                );
            }
        }
    }

    #[test]
    fn resolve_policy_path_rejects_empty_leaf_hash() {
        // Empty input should never be treated as a valid leaf hash — must
        // surface as an error rather than e.g. silently matching index 0.
        let (wallet, policy_desc, _) = build_timelocked_wallet();
        let result = resolve_policy_path_from_leaf(&wallet, "", Some(&policy_desc));
        assert!(
            result.is_err(),
            "empty leaf hash must error, got Ok({:?})",
            result.ok()
        );
    }

    #[test]
    fn resolve_policy_path_rejects_garbage_non_hex() {
        let (wallet, policy_desc, _) = build_timelocked_wallet();
        let result =
            resolve_policy_path_from_leaf(&wallet, "totally-not-a-leaf", Some(&policy_desc));
        let err = result.expect_err("non-hex leaf must error");
        // Could surface as InvalidArgument (parse failed → no matching path)
        // or Internal (wallet_runtime error). Either is OK; what we're
        // asserting is "no panic, returns a typed Status".
        assert!(matches!(
            err.code(),
            tonic::Code::InvalidArgument | tonic::Code::Internal
        ));
    }

    #[test]
    fn resolve_policy_path_primary_and_recovery_paths_differ() {
        // The primary leaf maps to spending-path [0]; the recovery leaf
        // maps to [1]. If these ever collide, finalization would pick the
        // wrong branch.
        let (wallet, policy_desc, leaves) = build_timelocked_wallet();
        let primary = leaves
            .iter()
            .find(|l| l.spending_condition_id == "primary")
            .expect("primary leaf");
        let recovery = leaves
            .iter()
            .find(|l| l.spending_condition_id == "recovery")
            .expect("recovery leaf");

        let p_resolved =
            resolve_policy_path_from_leaf(&wallet, &primary.leaf_hash, Some(&policy_desc))
                .expect("primary resolves");
        let r_resolved =
            resolve_policy_path_from_leaf(&wallet, &recovery.leaf_hash, Some(&policy_desc))
                .expect("recovery resolves");

        let p_path = p_resolved.values().next().expect("primary path");
        let r_path = r_resolved.values().next().expect("recovery path");
        assert_ne!(
            p_path, r_path,
            "primary and recovery must resolve to distinct policy paths, both got {:?}",
            p_path
        );
    }

    // ---- add_signers_for_psbt guard tests --------------------------------

    fn make_empty_psbt() -> Psbt {
        // Construct a minimum-viable PSBT (empty inputs + outputs) so we
        // can exercise add_signers_for_psbt's pre-DB guard checks without
        // having to mock the full wallet+UTXO graph.
        use bdk_wallet::bitcoin::absolute::LockTime;
        use bdk_wallet::bitcoin::transaction::{Transaction, Version};

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        Psbt::from_unsigned_tx(tx).expect("empty PSBT is valid")
    }

    #[test]
    fn add_signers_rejects_empty_device_id() {
        // This is the first guard in add_signers_for_psbt and runs before
        // any DB access — so we can test it without storage init.
        let (mut wallet, _, _) = build_timelocked_wallet();
        let psbt = make_empty_psbt();
        let err = add_signers_for_psbt(&mut wallet, &psbt, "test-wallet", "")
            .expect_err("empty device_id must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message().to_lowercase().contains("device"),
            "error should mention the device id, got: {}",
            err.message()
        );
    }

    // ---- parse_stored_fingerprint regressions --------------------------

    #[test]
    fn parse_stored_fingerprint_accepts_valid_hex() {
        let fp =
            parse_stored_fingerprint("d34db33f", "dev-1").expect("valid 8-hex fingerprint parses");
        // Compare via debug repr to avoid pulling in Fingerprint comparisons.
        assert_eq!(format!("{}", fp), "d34db33f");
    }

    #[test]
    fn parse_stored_fingerprint_rejects_garbage() {
        let err = parse_stored_fingerprint("not-hex!!", "dev-1")
            .expect_err("non-hex fingerprint must not parse");
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(
            err.message().contains("dev-1"),
            "error message must include the device id for triage, got: {}",
            err.message()
        );
        assert!(
            err.message().contains("not-hex!!"),
            "error message must include the offending value, got: {}",
            err.message()
        );
    }

    #[test]
    fn parse_stored_fingerprint_rejects_wrong_length() {
        // Fingerprints are exactly 4 bytes (8 hex chars).
        let err =
            parse_stored_fingerprint("ab", "dev-2").expect_err("short fingerprint must not parse");
        assert_eq!(err.code(), tonic::Code::Internal);
    }

    #[test]
    fn parse_stored_fingerprint_rejects_empty_string() {
        // Regression for the prior `unwrap_or_default()` behavior: empty
        // string used to silently become the zero fingerprint.
        let err = parse_stored_fingerprint("", "dev-3")
            .expect_err("empty fingerprint must not silently default to zero");
        assert_eq!(err.code(), tonic::Code::Internal);
    }

    #[test]
    fn parse_stored_fingerprint_does_not_silently_substitute_zero() {
        // Make absolutely sure we do NOT return the zero fingerprint on bad
        // input. This was the actual production bug.
        let bad_inputs = [
            "",
            "0",
            "00000000zz",
            "deadbeefdeadbeef", // too long
            "xyzwxyzw",
        ];
        for bad in bad_inputs {
            assert!(
                parse_stored_fingerprint(bad, "dev").is_err(),
                "input {:?} must be rejected, not silently coerced to zero",
                bad
            );
        }
    }

    // ---- property tests -------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        /// Any 4-byte fingerprint round-trips through display + parse_stored_fingerprint
        /// exactly. The serialized form is `format!("{:08x}", ...)` (8 lowercase
        /// hex chars); parsing back must give us the same display.
        #[test]
        fn prop_fingerprint_round_trips(bytes in prop::array::uniform4(any::<u8>())) {
            let fp = bdk_wallet::bitcoin::bip32::Fingerprint::from(bytes);
            let serialized = format!("{}", fp);
            let parsed = parse_stored_fingerprint(&serialized, "dev")
                .expect("self-serialized fingerprint must parse");
            prop_assert_eq!(format!("{}", parsed), serialized);
        }

        /// Any string that is *not* exactly 8 lowercase hex chars (or its
        /// uppercase equivalent) must be rejected. Catches regressions
        /// where someone accidentally accepts longer/shorter inputs.
        #[test]
        fn prop_fingerprint_rejects_wrong_length(
            s in "[^/]{0,7}|[a-fA-F0-9]{9,32}"
        ) {
            prop_assert!(
                parse_stored_fingerprint(&s, "dev").is_err(),
                "input {:?} (len {}) must not parse as a 4-byte fingerprint",
                s, s.len()
            );
        }

        /// Any string that contains non-hex characters at length 8 must
        /// also be rejected. Confirms we're not silently filtering.
        #[test]
        fn prop_fingerprint_rejects_non_hex_at_correct_length(
            // 8 chars but with at least one non-hex symbol. Use a fixed
            // pattern with a guaranteed-non-hex byte.
            prefix in "[a-fA-F0-9]{4}",
            suffix in "[a-fA-F0-9]{3}",
            bad in prop_oneof!["g", "z", "!", "_", "-"],
        ) {
            let s = format!("{}{}{}", prefix, bad, suffix);
            prop_assert_eq!(s.len(), 8);
            prop_assert!(
                parse_stored_fingerprint(&s, "dev").is_err(),
                "input {:?} (8 chars but contains {:?}) must be rejected",
                s, bad
            );
        }
    }
}
