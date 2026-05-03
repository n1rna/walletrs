//! Walletrs-server-specific BDK wallet orchestrator.
//!
//! Owns the multi-tenant concerns BDK doesn't care about: per-wallet locking
//! to serialise concurrent access, walletrs's pluggable
//! `crate::storage::AnyBackend` (filesystem or S3), and uploading the BDK
//! `bdk_file_store::Store` blob to that backend after every persist via
//! `R2BackedStore`. The actual wallet construction / loading is delegated to
//! `wallet-runtime`, which has no opinion about where the BDK changeset
//! lives.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bdk_file_store::Store;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::{ChangeSet, PersistedWallet, WalletPersister};
use once_cell::sync::Lazy;
use parking_lot::{ArcMutexGuard, Mutex, RawMutex};
use thiserror::Error;
use wallet_runtime::{
    create_wallet as wr_create_wallet, load_wallet as wr_load_wallet, WalletDescriptors,
};

use crate::db::{self, StoredWallet};
use crate::storage::{AnyBackend, StorageBackend};

const BDK_STORE_MAGIC: &[u8] = b"walletrs-bdk-store-v1";

static WALLET_LOCKS: Lazy<Mutex<HashMap<String, Arc<Mutex<()>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub type WalletLockGuard = ArcMutexGuard<RawMutex, ()>;

fn lock_wallet(wallet_id: &str) -> WalletLockGuard {
    let mutex = {
        let mut registry = WALLET_LOCKS.lock();
        registry
            .entry(wallet_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };

    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(|| mutex.lock_arc())
    } else {
        mutex.lock_arc()
    }
}

#[derive(Error, Debug)]
pub enum BdkWalletError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("BDK wallet error: {0}")]
    BdkWallet(String),
    #[error("Wallet not found: {0}")]
    WalletNotFound(String),
    #[error("Invalid descriptor: {0}")]
    InvalidDescriptor(String),
    #[error("Key management error: {0}")]
    KeyManagement(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug)]
pub struct WalletCreationResult {
    pub wallet_id: String,
    pub external_descriptor: String,
    pub internal_descriptor: String,
    pub network: Network,
}

pub struct WalletLoadResult {
    pub wallet: PersistedWallet<R2BackedStore>,
    pub store: R2BackedStore,
    pub wallet_id: String,
    _lock: WalletLockGuard,
}

impl std::fmt::Debug for WalletLoadResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletLoadResult")
            .field("wallet_id", &self.wallet_id)
            .finish()
    }
}

/// Wraps a local `bdk_file_store::Store` and uploads the file to the configured
/// object-storage backend on every `persist` call, so no wallet state lives on
/// the walletrs filesystem between requests.
pub struct R2BackedStore {
    inner: Store<ChangeSet>,
    local_path: PathBuf,
    backend: AnyBackend,
    object_key: String,
}

impl WalletPersister for R2BackedStore {
    type Error = BdkWalletError;

    fn initialize(p: &mut Self) -> Result<ChangeSet, Self::Error> {
        <Store<ChangeSet> as WalletPersister>::initialize(&mut p.inner)
            .map_err(|e| BdkWalletError::Database(format!("file_store initialize: {}", e)))
    }

    fn persist(p: &mut Self, changeset: &ChangeSet) -> Result<(), Self::Error> {
        <Store<ChangeSet> as WalletPersister>::persist(&mut p.inner, changeset)
            .map_err(|e| BdkWalletError::Database(format!("file_store persist: {}", e)))?;
        p.upload()
    }
}

impl R2BackedStore {
    fn upload(&self) -> Result<(), BdkWalletError> {
        let bytes = std::fs::read(&self.local_path)?;
        self.backend
            .write_bytes(&self.object_key, &bytes)
            .map_err(|e| BdkWalletError::Storage(format!("upload {}: {}", self.object_key, e)))
    }
}

pub struct BdkWalletManager {
    network: Network,
}

impl BdkWalletManager {
    pub fn new(network: Network) -> Self {
        Self { network }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn create_wallet_with_descriptors(
        &self,
        stored_wallet: &StoredWallet,
        external_descriptor: &str,
        internal_descriptor: &str,
    ) -> Result<WalletCreationResult, BdkWalletError> {
        if stored_wallet.wallet_id.is_empty() {
            return Err(BdkWalletError::InvalidDescriptor(
                "Wallet ID cannot be empty".to_string(),
            ));
        }

        db::init_all_storage()
            .map_err(|e| BdkWalletError::Database(format!("init storage: {}", e)))?;

        let wallet_id = &stored_wallet.wallet_id;
        let _lock = lock_wallet(wallet_id);
        let backend = db::get_storage_manager().backend().clone();
        let object_key = bdk_store_object_key(wallet_id);
        let local_path = local_store_path(wallet_id);

        // Fresh create: drop any stale local or remote state so wallet-runtime's
        // create_wallet sees an empty store on its initialize() check.
        discard_local(&local_path)?;
        let _ = backend.delete_file(&object_key);

        let mut r2_store = open_backed_store(&local_path, backend, object_key)?;
        let descriptors = WalletDescriptors::new(external_descriptor, internal_descriptor);

        let _wallet = wr_create_wallet(&mut r2_store, self.network, &descriptors)
            .map_err(|e| BdkWalletError::BdkWallet(e.to_string()))?;

        Ok(WalletCreationResult {
            wallet_id: wallet_id.clone(),
            external_descriptor: external_descriptor.to_string(),
            internal_descriptor: internal_descriptor.to_string(),
            network: self.network,
        })
    }

    pub fn load_wallet(&self, wallet_id: &str) -> Result<WalletLoadResult, BdkWalletError> {
        if wallet_id.is_empty() {
            return Err(BdkWalletError::WalletNotFound(
                "Wallet ID cannot be empty".to_string(),
            ));
        }

        let lock = lock_wallet(wallet_id);

        let _db_wallet = db::get_wallet(wallet_id).map_err(|e| {
            let msg = e.to_string();
            if msg.to_lowercase().contains("not found") {
                BdkWalletError::WalletNotFound(format!("Wallet '{}' not found", wallet_id))
            } else {
                BdkWalletError::Database(format!("Failed to query wallet: {}", e))
            }
        })?;

        let backend = db::get_storage_manager().backend().clone();
        let object_key = bdk_store_object_key(wallet_id);

        if !backend
            .file_exists(&object_key)
            .map_err(|e| BdkWalletError::Storage(format!("head {}: {}", object_key, e)))?
        {
            return Err(BdkWalletError::WalletNotFound(format!(
                "BDK store for '{}' missing in storage",
                wallet_id
            )));
        }

        let local_path = local_store_path(wallet_id);
        download_to_local(&backend, &object_key, &local_path)?;

        let mut r2_store = open_backed_store(&local_path, backend, object_key)?;

        match wr_load_wallet(&mut r2_store, self.network) {
            Ok(Some(wallet)) => Ok(WalletLoadResult {
                wallet,
                store: r2_store,
                wallet_id: wallet_id.to_string(),
                _lock: lock,
            }),
            Ok(None) => Err(BdkWalletError::WalletNotFound(format!(
                "Wallet '{}' not found",
                wallet_id
            ))),
            Err(e) => Err(BdkWalletError::BdkWallet(format!(
                "Failed to load wallet '{}': {}",
                wallet_id, e
            ))),
        }
    }
}

pub fn bdk_store_object_key(wallet_id: &str) -> String {
    format!("wallets/{}/bdk.store", wallet_id)
}

fn local_store_path(wallet_id: &str) -> PathBuf {
    std::env::temp_dir()
        .join("walletrs-bdk")
        .join(format!("{}.store", wallet_id))
}

fn open_backed_store(
    local_path: &Path,
    backend: AnyBackend,
    object_key: String,
) -> Result<R2BackedStore, BdkWalletError> {
    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let inner = Store::<ChangeSet>::open_or_create_new(BDK_STORE_MAGIC, local_path)
        .map_err(|e| BdkWalletError::Database(format!("open file_store: {}", e)))?;
    Ok(R2BackedStore {
        inner,
        local_path: local_path.to_path_buf(),
        backend,
        object_key,
    })
}

fn discard_local(path: &Path) -> Result<(), BdkWalletError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(BdkWalletError::Io(e)),
    }
}

fn download_to_local(
    backend: &AnyBackend,
    object_key: &str,
    local_path: &Path,
) -> Result<(), BdkWalletError> {
    let bytes = backend
        .read_bytes(object_key)
        .map_err(|e| BdkWalletError::Storage(format!("download {}: {}", object_key, e)))?;
    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(local_path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_manager_creation() {
        let manager = BdkWalletManager::new(Network::Testnet);
        assert_eq!(manager.network(), Network::Testnet);
    }
}
