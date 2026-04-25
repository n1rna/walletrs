//! Integration tests for the S3 storage backend.
//!
//! Runs against a live S3-compatible bucket (Cloudflare R2 recommended) so the
//! real network path — auth, path-style addressing, list pagination, object
//! key handling — is exercised end-to-end.
//!
//! Gated on `WALLETRS_TEST_S3_*` env vars so tests silently skip when creds
//! are absent (local dev without a test bucket should still `cargo test`).
//!
//! Every test uses a unique key prefix (`integration-tests/<uuid>/`) and tears
//! down its own objects, so parallel runs on the same bucket are safe.

use std::env;

use bdk_file_store::Store;
use bdk_wallet::{ChangeSet, Wallet};
use uuid::Uuid;

use walletrs_lib::config::S3Config;
use walletrs_lib::storage::{
    AnyBackend, EncryptingBackend, EnvelopeCipher, S3Backend, StorageBackend,
};

const BDK_STORE_MAGIC: &[u8] = b"walletrs-bdk-store-v1";
const TEST_EXTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPd1EzCPZcQSPhsotX5HvRDCivA7ASNQFmjWuTsW3WWEwUNKFAZrnD9qpz55rtyLdphqkwRZUqNWRXMfEVNPLRPvzsBMiRcDu/84'/1'/0'/0/*)";
const TEST_INTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPd1EzCPZcQSPhsotX5HvRDCivA7ASNQFmjWuTsW3WWEwUNKFAZrnD9qpz55rtyLdphqkwRZUqNWRXMfEVNPLRPvzsBMiRcDu/84'/1'/0'/1/*)";

/// Build a fresh `S3Backend` under a unique prefix. Returns `None` (and prints
/// a reason) when the environment is not configured — callers should `return`
/// from the test on `None`.
fn make_test_backend() -> Option<(S3Backend, String)> {
    let bucket = match env::var("WALLETRS_TEST_S3_BUCKET") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("skip: WALLETRS_TEST_S3_BUCKET not set");
            return None;
        }
    };

    let access_key = env::var("WALLETRS_TEST_S3_ACCESS_KEY_ID")
        .ok()
        .filter(|s| !s.is_empty());
    let secret_key = env::var("WALLETRS_TEST_S3_SECRET_ACCESS_KEY")
        .ok()
        .filter(|s| !s.is_empty());
    if access_key.is_none() || secret_key.is_none() {
        eprintln!("skip: WALLETRS_TEST_S3_{{ACCESS_KEY_ID,SECRET_ACCESS_KEY}} not set");
        return None;
    }

    let run_id = Uuid::new_v4().to_string();
    let prefix = format!("integration-tests/{}", run_id);

    let cfg = S3Config {
        endpoint: env::var("WALLETRS_TEST_S3_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty()),
        bucket,
        region: env::var("WALLETRS_TEST_S3_REGION").unwrap_or_else(|_| "auto".to_string()),
        access_key_id: access_key,
        secret_access_key: secret_key,
        prefix: prefix.clone(),
        force_path_style: env::var("WALLETRS_TEST_S3_FORCE_PATH_STYLE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true),
    };

    let backend = S3Backend::from_config(&cfg).expect("failed to build S3Backend");
    Some((backend, prefix))
}

/// Delete every object written by the test. Best-effort — logs but does not
/// fail the test on cleanup error.
fn cleanup(backend: &S3Backend) {
    match backend.list_files("") {
        Ok(keys) => {
            for key in keys {
                if let Err(e) = backend.delete_file(&key) {
                    eprintln!("cleanup: delete {}: {}", key, e);
                }
            }
        }
        Err(e) => eprintln!("cleanup: list failed: {}", e),
    }
}

#[test]
fn json_round_trip() {
    let Some((backend, _prefix)) = make_test_backend() else {
        return;
    };

    let key = "wallets/test-wallet/metadata.json";
    let payload = br#"{"wallet_id":"test-wallet","network":"regtest"}"#;

    backend.write_bytes(key, payload).expect("write");
    assert!(backend.file_exists(key).expect("exists"));

    let got = backend.read_bytes(key).expect("read");
    assert_eq!(got, payload);

    let listed = backend.list_files("wallets/").expect("list");
    assert!(
        listed.iter().any(|k| k.ends_with("metadata.json")),
        "expected metadata.json in list, got {:?}",
        listed
    );

    assert!(backend.delete_file(key).expect("delete"));
    assert!(!backend.file_exists(key).expect("exists after delete"));

    cleanup(&backend);
}

#[test]
fn missing_key_returns_not_found() {
    let Some((backend, _prefix)) = make_test_backend() else {
        return;
    };

    let err = backend
        .read_bytes("does/not/exist.json")
        .expect_err("expected not-found error");
    // StorageError::Io wraps an io::Error; the backend tags NotFound.
    let msg = err.to_string();
    assert!(
        msg.contains("NoSuchKey") || msg.contains("NotFound") || msg.contains("not found"),
        "expected not-found error, got: {}",
        msg
    );

    assert!(!backend.file_exists("does/not/exist.json").expect("exists"));
    assert!(!backend.delete_file("does/not/exist.json").expect("delete"));

    cleanup(&backend);
}

#[test]
fn list_pagination_and_prefix() {
    let Some((backend, _prefix)) = make_test_backend() else {
        return;
    };

    // Write under two disjoint prefixes; list of one must not leak the other.
    for i in 0..5 {
        backend
            .write_bytes(&format!("group-a/item-{}.bin", i), &[i as u8])
            .expect("write a");
        backend
            .write_bytes(&format!("group-b/item-{}.bin", i), &[i as u8])
            .expect("write b");
    }

    let a = backend.list_files("group-a/").expect("list a");
    assert_eq!(a.len(), 5);
    assert!(a.iter().all(|k| k.starts_with("group-a/")));

    let b = backend.list_files("group-b/").expect("list b");
    assert_eq!(b.len(), 5);
    assert!(b.iter().all(|k| k.starts_with("group-b/")));

    cleanup(&backend);
}

#[test]
fn encrypted_managed_key_round_trip() {
    let Some((s3, _prefix)) = make_test_backend() else {
        return;
    };
    let kek_b64 = match env::var("WALLETRS_TEST_KEK") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("skip: WALLETRS_TEST_KEK not set");
            return;
        }
    };

    let cipher = EnvelopeCipher::from_base64(&kek_b64).expect("cipher");
    let backend = AnyBackend::s3(s3.clone());
    let encrypting = EncryptingBackend::new(backend, cipher);

    let key = "managed_keys/user-1::device-1::system.json";
    let plaintext = br#"{"mnemonic":"abandon abandon ... about","xpriv":"tprv..."}"#;

    encrypting.write_bytes(key, plaintext).expect("enc write");

    // Raw ciphertext must not contain plaintext secrets.
    let ciphertext = s3.read_bytes(key).expect("raw read");
    assert_ne!(ciphertext, plaintext);
    assert!(
        !ciphertext.windows(8).any(|w| w == b"mnemonic"),
        "plaintext leaked into ciphertext"
    );

    let decrypted = encrypting.read_bytes(key).expect("enc read");
    assert_eq!(decrypted, plaintext);

    cleanup(&s3);
}

#[test]
fn encrypted_wrong_kek_fails() {
    let Some((s3, _prefix)) = make_test_backend() else {
        return;
    };
    let kek_b64 = match env::var("WALLETRS_TEST_KEK") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("skip: WALLETRS_TEST_KEK not set");
            return;
        }
    };

    let cipher = EnvelopeCipher::from_base64(&kek_b64).expect("cipher");
    let backend = AnyBackend::s3(s3.clone());
    let writer = EncryptingBackend::new(backend.clone(), cipher);

    let key = "managed_keys/wrong-kek-test.json";
    writer.write_bytes(key, b"secret payload").expect("write");

    // A different KEK must fail to decrypt the prior payload.
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    let other_kek = BASE64.encode([0x55u8; 32]);
    let other_cipher = EnvelopeCipher::from_base64(&other_kek).expect("cipher");
    let other = EncryptingBackend::new(backend, other_cipher);

    let err = other.read_bytes(key).expect_err("decrypt should fail");
    assert!(
        err.to_string().contains("AEAD decrypt"),
        "expected AEAD decrypt failure, got: {}",
        err
    );

    cleanup(&s3);
}

#[test]
fn bdk_store_round_trip_via_backend() {
    let Some((backend, _prefix)) = make_test_backend() else {
        return;
    };

    // Mirror R2BackedStore's flow without depending on its private constructor:
    // write the bdk_file_store bytes locally, upload, then download into a
    // fresh process-local path and verify the store reopens with the same
    // wallet state.
    let tmp_dir = env::temp_dir().join(format!("walletrs-s3-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_dir).expect("tmp dir");
    let store_path = tmp_dir.join("bdk.store");

    {
        let mut store = Store::<ChangeSet>::open_or_create_new(BDK_STORE_MAGIC, &store_path)
            .expect("open new store");
        let _wallet =
            Wallet::create(TEST_EXTERNAL_DESCRIPTOR, TEST_INTERNAL_DESCRIPTOR)
                .network(bdk_wallet::bitcoin::Network::Testnet)
                .create_wallet(&mut store)
                .expect("create wallet");
    }

    let bytes = std::fs::read(&store_path).expect("read store");
    let object_key = "wallets/round-trip/bdk.store";
    backend.write_bytes(object_key, &bytes).expect("upload");

    let downloaded = backend.read_bytes(object_key).expect("download");
    assert_eq!(downloaded, bytes);

    // Reopen the downloaded store at a fresh path; must load back to a wallet.
    let reopen_path = tmp_dir.join("bdk.store.reopened");
    std::fs::write(&reopen_path, &downloaded).expect("write reopen");

    let mut reopened = Store::<ChangeSet>::open_or_create_new(BDK_STORE_MAGIC, &reopen_path)
        .expect("reopen store");
    let loaded = Wallet::load()
        .check_network(bdk_wallet::bitcoin::Network::Testnet)
        .load_wallet(&mut reopened)
        .expect("load wallet")
        .expect("wallet present");

    assert_eq!(
        loaded.network(),
        bdk_wallet::bitcoin::Network::Testnet,
        "reopened wallet must preserve network"
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
    cleanup(&backend);
}
