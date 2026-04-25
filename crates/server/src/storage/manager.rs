use crate::config::{StorageKind, CONFIG};
use crate::storage::models::{StoredManagedKey, StoredPSBT, StoredSignedPSBT, StoredWallet};
use crate::storage::{
    AnyBackend, EncryptingBackend, EnvelopeCipher, FileSystemPathStrategy, FileSystemStorage,
    S3Backend, ScopeType, StorageError, StorageResult,
};

pub type ManagedKeyBackend = EncryptingBackend<AnyBackend>;
pub type ManagedKeyStorage =
    FileSystemStorage<StoredManagedKey, FileSystemPathStrategy, ManagedKeyBackend>;
pub type PSBTStorage = FileSystemStorage<StoredPSBT, FileSystemPathStrategy, AnyBackend>;
pub type SignedPSBTStorage =
    FileSystemStorage<StoredSignedPSBT, FileSystemPathStrategy, AnyBackend>;
pub type WalletStorage = FileSystemStorage<StoredWallet, FileSystemPathStrategy, AnyBackend>;

#[derive(Clone)]
pub struct StorageManager {
    base_path: String,
    backend: AnyBackend,
}

impl StorageManager {
    pub fn new(base_path: &str) -> Self {
        let backend = match CONFIG.storage_kind() {
            StorageKind::Local => AnyBackend::local(base_path),
            StorageKind::S3 => {
                let cfg = CONFIG
                    .s3()
                    .expect("WALLETRS_STORAGE_KIND=s3 but S3 config missing");
                let s3 = S3Backend::from_config(cfg).expect("failed to build S3 backend");
                AnyBackend::s3(s3)
            }
        };

        Self {
            base_path: base_path.to_string(),
            backend,
        }
    }

    pub fn new_with_backend(base_path: &str, backend: AnyBackend) -> Self {
        Self {
            base_path: base_path.to_string(),
            backend,
        }
    }

    pub fn base_path(&self) -> &str {
        &self.base_path
    }

    pub fn backend(&self) -> &AnyBackend {
        &self.backend
    }

    pub fn managed_keys(&self) -> StorageResult<ManagedKeyStorage> {
        let kek = CONFIG.kek_b64().ok_or_else(|| {
            StorageError::PathGeneration(
                "WALLETRS_KEK must be set (base64 32 bytes) to access managed_keys".to_string(),
            )
        })?;
        let cipher = EnvelopeCipher::from_base64(kek)?;
        let encrypted = EncryptingBackend::new(self.backend.clone(), cipher);
        FileSystemStorage::new(
            encrypted,
            FileSystemPathStrategy::new("."),
            ScopeType::Global,
            "managed_keys",
        )
    }

    pub fn wallets(&self) -> StorageResult<WalletStorage> {
        FileSystemStorage::new(
            self.backend.clone(),
            FileSystemPathStrategy::new("."),
            ScopeType::Global,
            "wallets",
        )
    }

    pub fn psbts(&self, wallet_id: &str) -> StorageResult<PSBTStorage> {
        FileSystemStorage::new(
            self.backend.clone(),
            FileSystemPathStrategy::new("."),
            ScopeType::Wallet(wallet_id.to_string()),
            "psbts",
        )
    }

    pub fn signed_psbts(&self, wallet_id: &str) -> StorageResult<SignedPSBTStorage> {
        FileSystemStorage::new(
            self.backend.clone(),
            FileSystemPathStrategy::new("."),
            ScopeType::Wallet(wallet_id.to_string()),
            "signed_psbts",
        )
    }

    pub fn init_storage_dirs(&self) -> StorageResult<()> {
        match CONFIG.storage_kind() {
            StorageKind::Local => {
                std::fs::create_dir_all(&self.base_path).map_err(StorageError::Io)
            }
            StorageKind::S3 => Ok(()),
        }
    }
}

impl std::fmt::Debug for StorageManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageManager")
            .field("base_path", &self.base_path)
            .field("storage_kind", &CONFIG.storage_kind())
            .finish()
    }
}
