// Re-export all storage models from the unified models module
pub use crate::storage::models::{StoredManagedKey, StoredPSBT, StoredSignedPSBT, StoredWallet};
use crate::{config::CONFIG, storage::StorageManager};

use std::sync::OnceLock;

static STORAGE_MANAGER: OnceLock<StorageManager> = OnceLock::new();

// Error conversion helper
fn convert_storage_error(e: crate::storage::StorageError) -> std::io::Error {
    match e {
        crate::storage::StorageError::Io(io_err) => io_err,
        _ => std::io::Error::other(format!("Storage error: {}", e)),
    }
}

pub fn get_storage_manager() -> &'static StorageManager {
    STORAGE_MANAGER.get_or_init(|| {
        // let base_path = std::env::var("WALLETRS_STORAGE_PATH").unwrap_or_else(|_| "./data".into());
        StorageManager::new(CONFIG.storage_base_path())
    })
}

/// Test-only: race to install a `StorageManager` backed by `base_path` into
/// the global `STORAGE_MANAGER` before any production code path can lazily
/// initialise it from `CONFIG.storage_base_path()`. Use this from tests
/// that need real storage (e.g. exercising `build_wallet` end-to-end) so
/// they neither depend on env-var ordering nor pollute the project's
/// `./data` directory.
///
/// Idempotent: only the *first* caller in the process actually sets the
/// manager; subsequent callers return the already-installed one. That
/// matches the semantics tests need — one shared tempdir per process,
/// tests use unique wallet ids to avoid collisions.
#[cfg(test)]
pub fn __test_init_storage_with_path(base_path: &str) -> &'static StorageManager {
    let backend = crate::storage::AnyBackend::local(base_path);
    let _ = STORAGE_MANAGER.set(StorageManager::new_with_backend(base_path, backend));
    STORAGE_MANAGER
        .get()
        .expect("storage manager must be initialised after set")
}

// STORAGE INITIALIZATION

pub fn init_all_storage() -> Result<(), std::io::Error> {
    let storage_manager = get_storage_manager();
    storage_manager
        .init_storage_dirs()
        .map_err(convert_storage_error)
}

// WALLET OPERATIONS (using StorageManager and StoredWallet)

pub fn create_wallet(
    user_id: &str,
    wallet_id: &str,
    name: &str,
    network: &str,
    wallet_type: &str,
) -> Result<StoredWallet, std::io::Error> {
    let storage_manager = get_storage_manager();

    // Create and store the wallet
    let wallet = StoredWallet::new(wallet_id, user_id, name, network, wallet_type)
        .with_storage_manager(storage_manager);
    wallet.store().map_err(convert_storage_error)?;

    Ok(wallet)
}

pub fn get_wallet(wallet_id: &str) -> Result<StoredWallet, std::io::Error> {
    let storage_manager = get_storage_manager();

    StoredWallet::query()
        .with_storage_manager(storage_manager)
        .get(wallet_id)
        .map_err(convert_storage_error)
}

pub fn get_policy_descriptor(wallet_id: &str) -> Result<Option<String>, std::io::Error> {
    let wallet = get_wallet(wallet_id)?;
    Ok(wallet.policy_descriptor)
}

pub fn wallet_exists(user_id: &str, wallet_id: &str) -> Result<bool, std::io::Error> {
    let storage_manager = get_storage_manager();
    StoredWallet::query()
        .with_storage_manager(storage_manager)
        .exists(user_id, wallet_id)
        .map_err(convert_storage_error)
}

pub fn deactivate_wallet(user_id: &str, wallet_id: &str) -> Result<(), std::io::Error> {
    let storage_manager = get_storage_manager();
    StoredWallet::query()
        .with_storage_manager(storage_manager)
        .deactivate(user_id, wallet_id)
        .map_err(convert_storage_error)
}

//
// MANAGED KEYS OPERATIONS
//

pub fn store_managed_key(managed_key: StoredManagedKey) -> Result<(), std::io::Error> {
    let storage_manager = get_storage_manager();
    managed_key
        .with_storage_manager(storage_manager)
        .store()
        .map_err(convert_storage_error)
}

pub fn get_managed_key(
    user_id: &str,
    device_id: &str,
    key_type: &str,
) -> Result<Option<StoredManagedKey>, std::io::Error> {
    let storage_manager = get_storage_manager();
    StoredManagedKey::get(storage_manager, user_id, device_id, key_type)
        .map_err(convert_storage_error)
}

pub fn list_managed_keys(
    user_id_filter: Option<&str>,
    key_type_filter: Option<&str>,
) -> Result<Vec<StoredManagedKey>, std::io::Error> {
    let storage_manager = get_storage_manager();
    StoredManagedKey::list(storage_manager, user_id_filter, key_type_filter)
        .map_err(convert_storage_error)
}

pub fn store_customer_key(
    user_id: &str,
    device_id: &str,
    key_name: &str,
    xpub: &str,
    fingerprint: &str,
    derivation_path: &str,
) -> Result<(), std::io::Error> {
    let storage_manager = get_storage_manager();
    let managed_key = StoredManagedKey::new_customer_key(
        user_id,
        device_id,
        key_name,
        xpub,
        fingerprint,
        derivation_path,
    );
    managed_key
        .with_storage_manager(storage_manager)
        .store()
        .map_err(convert_storage_error)
}

pub fn store_system_key(
    user_id: &str,
    device_id: &str,
    key_name: &str,
    xpriv: &str,
    xpub: &str,
    fingerprint: &str,
    derivation_path: &str,
    mnemonic: &str,
    tpriv: &str,
    tpub: &str,
) -> Result<(), std::io::Error> {
    let storage_manager = get_storage_manager();
    let managed_key = StoredManagedKey::new_system_key(
        user_id,
        device_id,
        key_name,
        xpriv,
        xpub,
        fingerprint,
        derivation_path,
        mnemonic,
        tpriv,
        tpub,
    );
    managed_key
        .with_storage_manager(storage_manager)
        .store()
        .map_err(convert_storage_error)
}

pub fn save_psbt(wallet_id: &str, txid: &str, psbt: &str) -> Result<(), std::io::Error> {
    let storage_manager = get_storage_manager();
    let stored_psbt = StoredPSBT::new(txid, wallet_id, psbt);
    stored_psbt
        .with_storage_manager(storage_manager)
        .store()
        .map_err(convert_storage_error)
}

pub fn save_signed_psbt(
    wallet_id: &str,
    txid: &str,
    psbt: &str,
    device_fingerprint: &str,
) -> Result<(), std::io::Error> {
    let storage_manager = get_storage_manager();
    // Check if this is a finalized PSBT based on the device_fingerprint
    let signed_psbt = if device_fingerprint == "finalized" {
        StoredSignedPSBT::new_finalized(txid, wallet_id, device_fingerprint, psbt)
    } else {
        StoredSignedPSBT::new_partial(txid, wallet_id, device_fingerprint, psbt)
    };
    signed_psbt
        .with_storage_manager(storage_manager)
        .store()
        .map_err(convert_storage_error)
}

pub fn get_original_psbt(wallet_id: &str, txid: &str) -> Result<String, std::io::Error> {
    let storage_manager = get_storage_manager();
    match StoredPSBT::get(storage_manager, wallet_id, txid).map_err(convert_storage_error)? {
        Some(stored_psbt) => Ok(stored_psbt.psbt_data),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("PSBT not found for wallet {} and txid {}", wallet_id, txid),
        )),
    }
}

pub fn get_finalized_psbt(wallet_id: &str, txid: &str) -> Result<String, std::io::Error> {
    let storage_manager = get_storage_manager();
    match StoredSignedPSBT::get_finalized_by_txid(storage_manager, wallet_id, txid)
        .map_err(convert_storage_error)?
    {
        Some(stored_psbt) => Ok(stored_psbt.psbt_data),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "Finalized PSBT not found for wallet {} and txid {}",
                wallet_id, txid
            ),
        )),
    }
}

/// List the signed PSBTs persisted for `(wallet_id, txid)`. Returns
/// `Ok(vec![])` when nothing has been stored — matching the standard
/// "list-query returns an empty list, not an error" convention. Callers
/// (e.g. `finalize_wallet_transaction`) check `is_empty()` to decide
/// whether finalization can proceed.
///
/// Earlier versions returned `NotFound` on empty; that made the handler's
/// own `is_empty()` check dead code, and pushed an unusual "missing means
/// error" semantic on what is fundamentally a list query.
pub fn get_signed_psbts(
    wallet_id: &str,
    txid: &str,
) -> Result<Vec<StoredSignedPSBT>, std::io::Error> {
    let storage_manager = get_storage_manager();
    StoredSignedPSBT::list_by_txid(storage_manager, wallet_id, txid).map_err(convert_storage_error)
}

// New unified PSBT operations
pub fn save_finalized_psbt(
    wallet_id: &str,
    txid: &str,
    psbt: &str,
    device_fingerprint: &str,
) -> Result<(), std::io::Error> {
    let storage_manager = get_storage_manager();
    let signed_psbt = StoredSignedPSBT::new_finalized(txid, wallet_id, device_fingerprint, psbt);
    signed_psbt
        .with_storage_manager(storage_manager)
        .store()
        .map_err(convert_storage_error)
}

pub fn update_psbt_status(wallet_id: &str, txid: &str, status: &str) -> Result<(), std::io::Error> {
    let storage_manager = get_storage_manager();
    StoredPSBT::update_status_in_storage(storage_manager, wallet_id, txid, status)
        .map_err(convert_storage_error)
}
