//! Shared test helpers for `wallet::service::*` integration tests.
//!
//! Bootstraps a process-wide, tempdir-backed test environment exactly once
//! (`setup()`), then exposes builders for fixtures the various handler tests
//! need: managed keys, single-sig wallets, multisig wallets. Tests pull
//! `setup()` at the top of every test so the order of execution does not
//! matter.
//!
//! Fixtures are constructed by calling the *real* gRPC handlers (`create_*`,
//! `key_management::*`, etc.) so the helpers double as smoke coverage and
//! reflect any future signature drift instead of pinning a private API.

// Individual fixtures are used as their corresponding handler tests land;
// allowing dead_code at the module level prevents incremental landings from
// breaking the build.
#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Important runtime caveat:
//
// Any test that creates, loads, or otherwise touches a wallet via
// `BdkWalletManager` must use `#[tokio::test(flavor = "multi_thread")]`.
// The per-wallet lock in `wallet::bdk::wallet_manager::lock_wallet` calls
// `tokio::task::block_in_place`, which panics on the default
// `current_thread` runtime that `#[tokio::test]` provides. Tests that only
// hit pure handlers or storage (e.g. `key_management::*`) can stay on the
// default flavor.
// ---------------------------------------------------------------------------

use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

use tonic::Request;

use crate::config::{self, Config};
use crate::db;
use crate::proto::pb::{
    CreateCustomerManagedKeyRequest, CreateGenericWalletRequest, CreateSystemManagedKeysRequest,
    PolicyType as ProtoPolicyType, PreferredScriptType as ProtoPreferredScriptType,
    SpendingCondition as ProtoSpendingCondition,
};

use super::{key_management, wallet_creation};

/// A deterministic 32-byte KEK encoded as base64. Tests never persist
/// long-term secrets; the value here just satisfies
/// `EnvelopeCipher::from_base64`'s length check. Never use this for
/// anything outside `cfg(test)`.
pub const TEST_KEK_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// Initialise the global `CONFIG` and `STORAGE_MANAGER` exactly once per
/// test process. Safe to call from any number of parallel tests.
///
/// We use a single shared tempdir for the whole process (rather than one
/// per test) because both globals are `OnceLock`s — once seeded, they
/// cannot be replaced. Tests cooperate by using unique ids (see
/// `unique_id` below) so they never collide on stored objects.
pub fn setup() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let dir = process_tempdir();
        std::fs::create_dir_all(&dir).expect("create test storage dir");

        let mut cfg = Config::for_tests(dir.to_str().expect("tempdir utf-8"));
        cfg.kek_b64 = Some(TEST_KEK_B64.to_string());
        // Track whether *we* won the install race so a flaky bootstrap is
        // visible in the failing test rather than silently mis-configuring
        // everything downstream.
        let installed_config = config::__test_init_config(cfg);
        let _ = db::__test_init_storage_with_path(dir.to_str().expect("tempdir utf-8"));
        if !installed_config {
            // Another test (or production code path) raced ahead of us
            // before we could install the test config. Tests should always
            // call setup() first thing, so this means a non-test code path
            // touched CONFIG before any test did, which would mean the
            // suite is configured from real env vars. Surface loudly.
            log::warn!(
                "test setup(): CONFIG was already initialised — tests may run \
                 with the wrong configuration (storage path, KEK, network)"
            );
        }
    });
}

fn process_tempdir() -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "walletrs-service-tests-{}-{}",
        std::process::id(),
        stamp
    ))
}

/// Produce a unique-per-test id, prefixed for readability in failure logs.
/// Uses process-id + nanos so parallel tests inside the same process,
/// and successive runs across processes, all get distinct values.
pub fn unique_id(prefix: &str) -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}-{}-{}", prefix, std::process::id(), stamp, n)
}

// ---- managed-key fixtures --------------------------------------------------

/// Create a system managed key (server-generated xprv) via the real
/// `create_system_managed_key` RPC. Returns the fingerprint that the RPC
/// derived from the freshly-generated key, so tests that need to assert
/// against it have it on hand.
pub async fn make_system_key(user_id: &str, device_id: &str) -> String {
    setup();
    let resp =
        key_management::create_system_managed_key(Request::new(CreateSystemManagedKeysRequest {
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            key_name: String::new(),
        }))
        .await
        // Preserve the Status code + message on panic so a fixture failure tells
        // the operator *why* it failed (e.g. missing KEK, storage path
        // mis-seeded) rather than just "fixture must succeed".
        .unwrap_or_else(|e| {
            panic!(
                "create_system_managed_key fixture failed (user={}, device={}): {:?} - {}",
                user_id,
                device_id,
                e.code(),
                e.message()
            )
        });
    resp.into_inner().fingerprint
}

/// Create a customer managed key (xpub-only) via the real
/// `create_customer_managed_key` RPC. Uses a deterministic-by-seed xpub so
/// tests can rely on collision-free keys.
pub async fn make_customer_key(user_id: &str, device_id: &str, seed: u64) {
    setup();
    let (fingerprint, xpub) = test_xpub(seed);
    key_management::create_customer_managed_key(Request::new(CreateCustomerManagedKeyRequest {
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        key_name: format!("cust-{}", device_id),
        xpub,
        fingerprint,
        derivation_path: "m/84'/1'/0'".to_string(),
    }))
    .await
    .expect("create_customer_managed_key fixture must succeed");
}

/// Build a deterministic descriptor-formatted multipath xpub from `seed`.
/// Mirrors the format the descriptor builder expects (see
/// `policy_core::key_utils::format_key_for_descriptor`).
pub fn test_xpub(seed: u64) -> (String, String) {
    use bdk_wallet::bitcoin::bip32::{Xpriv, Xpub};
    use bdk_wallet::bitcoin::secp256k1::Secp256k1;
    use bdk_wallet::bitcoin::Network;

    let mut bytes = [0u8; 64];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&(std::process::id() as u64).to_le_bytes());

    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(Network::Testnet, &bytes).expect("valid seed");
    let xpub = Xpub::from_priv(&secp, &xpriv);
    let fingerprint = format!("{:08x}", xpriv.fingerprint(&secp));
    let multipath_xpub = format!("[{}]{}/<0;1>/*", fingerprint, xpub);
    (fingerprint, multipath_xpub)
}

// ---- wallet fixtures -------------------------------------------------------

/// Create a single-sig system-managed wallet via the real
/// `create_generic_wallet` RPC. Returns the wallet_id that was created.
/// The caller passes the user_id; one fresh system key is generated and
/// referenced from the wallet's single primary spending condition.
pub async fn make_single_sig_wallet(user_id: &str, wallet_id: &str, device_id: &str) {
    setup();
    let _ = make_system_key(user_id, device_id).await;

    wallet_creation::create_generic_wallet(Request::new(CreateGenericWalletRequest {
        user_id: user_id.to_string(),
        wallet_id: wallet_id.to_string(),
        spending_conditions: vec![ProtoSpendingCondition {
            id: "primary".to_string(),
            is_primary: true,
            timelock: 0,
            threshold: 1,
            policy: ProtoPolicyType::Single as i32,
            managed_key_ids: vec![device_id.to_string()],
            is_unspendable: false,
        }],
        network: "testnet".to_string(),
        preferred_script_type: ProtoPreferredScriptType::ScriptTypeAuto as i32,
    }))
    .await
    .expect("create_generic_wallet fixture must succeed");
}

/// Create a 2-of-3 segwit-v0 multisig wallet via the real RPC. All three
/// keys are system-managed so the wallet is fully self-contained for
/// sign-path tests in later phases.
pub async fn make_multisig_wallet(user_id: &str, wallet_id: &str, device_ids: [&str; 3]) {
    setup();
    for d in device_ids {
        let _ = make_system_key(user_id, d).await;
    }
    wallet_creation::create_generic_wallet(Request::new(CreateGenericWalletRequest {
        user_id: user_id.to_string(),
        wallet_id: wallet_id.to_string(),
        spending_conditions: vec![ProtoSpendingCondition {
            id: "primary".to_string(),
            is_primary: true,
            timelock: 0,
            threshold: 2,
            policy: ProtoPolicyType::Multi as i32,
            managed_key_ids: device_ids.iter().map(|s| s.to_string()).collect(),
            is_unspendable: false,
        }],
        network: "testnet".to_string(),
        preferred_script_type: ProtoPreferredScriptType::ScriptTypeAuto as i32,
    }))
    .await
    .expect("create_generic_wallet multisig fixture must succeed");
}
