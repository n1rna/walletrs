use crate::storage::schema::{FieldSchema, FieldType, FieldValidation, IndexSchema};
use crate::storage::{IndexableStorage, Schema, Storable, Storage, StorageManager, StorageResult};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredWallet {
    pub wallet_id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub network: String,     // "mainnet", "testnet", "regtest"
    pub wallet_type: String, // "single", "multisig", "advanced", etc.
    pub liana_descriptor: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub is_active: bool,
    #[serde(skip)]
    pub _storage_manager: Option<&'static StorageManager>,
}

impl Default for StoredWallet {
    fn default() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            wallet_id: String::new(),
            user_id: String::new(),
            name: String::new(),
            description: None,
            network: "testnet".to_string(),
            wallet_type: "single".to_string(),
            liana_descriptor: None,
            created_at: now,
            updated_at: now,
            is_active: true,
            _storage_manager: None,
        }
    }
}

impl StoredWallet {
    pub fn new(
        wallet_id: &str,
        user_id: &str,
        name: &str,
        network: &str,
        wallet_type: &str,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            wallet_id: wallet_id.to_string(),
            user_id: user_id.to_string(),
            name: name.to_string(),
            description: None,
            network: network.to_string(),
            wallet_type: wallet_type.to_string(),
            liana_descriptor: None,
            created_at: now,
            updated_at: now,
            is_active: true,
            _storage_manager: None,
        }
    }

    pub fn query() -> Self {
        Self::default()
    }

    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    pub fn with_liana_descriptor(mut self, desc: &str) -> Self {
        self.liana_descriptor = Some(desc.to_string());
        self
    }

    pub fn with_storage_manager(mut self, storage_manager: &'static StorageManager) -> Self {
        self._storage_manager = Some(storage_manager);
        self
    }

    pub fn get_key_identifier(&self) -> String {
        format!("wallet::{}", self.wallet_id)
    }

    // Helper methods for common operations
    pub fn store(&self) -> StorageResult<()> {
        match self._storage_manager {
            Some(storage_manager) => {
                let storage = storage_manager.wallets()?;
                storage.store(&self.get_key_identifier(), self)
            }
            None => Err(crate::storage::StorageError::PathGeneration(
                "StorageManager not set. Use with_storage_manager() first.".to_string(),
            )),
        }
    }

    pub fn get(&self, wallet_id: &str) -> StorageResult<Self> {
        match self._storage_manager {
            Some(storage_manager) => {
                let storage = storage_manager.wallets()?;
                let key = format!("wallet::{}", wallet_id);
                match storage.get(&key)? {
                    Some(mut wallet) => {
                        wallet._storage_manager = Some(storage_manager);
                        Ok(wallet)
                    }
                    None => Err(crate::storage::StorageError::PathGeneration(
                        "Wallet not found".to_string(),
                    )),
                }
            }
            None => Err(crate::storage::StorageError::PathGeneration(
                "StorageManager not set. Use with_storage_manager() first.".to_string(),
            )),
        }
    }

    pub fn get_by_id(&self, wallet_id: &str) -> StorageResult<Self> {
        match self._storage_manager {
            Some(storage_manager) => {
                let storage = storage_manager.wallets()?;
                let results = storage.query_by_index(
                    "wallet_id",
                    &serde_json::Value::String(wallet_id.to_string()),
                )?;

                if let Some((_, mut wallet)) = results.into_iter().next() {
                    wallet._storage_manager = Some(storage_manager);
                    Ok(wallet)
                } else {
                    Err(crate::storage::StorageError::PathGeneration(
                        "Wallet not found".to_string(),
                    ))
                }
            }
            None => Err(crate::storage::StorageError::PathGeneration(
                "StorageManager not set. Use with_storage_manager() first.".to_string(),
            )),
        }
    }

    pub fn list_by_user(&self, _user_id: &str, active_only: bool) -> StorageResult<Vec<Self>> {
        match self._storage_manager {
            Some(storage_manager) => {
                let filter_fn = |wallet: &Self| {
                    if active_only && !wallet.is_active {
                        return false;
                    }
                    true
                };

                let storage = storage_manager.wallets()?;
                let results = storage.query(&filter_fn)?;
                Ok(results
                    .into_iter()
                    .map(|(_, mut value)| {
                        value._storage_manager = Some(storage_manager);
                        value
                    })
                    .collect())
            }
            None => Err(crate::storage::StorageError::PathGeneration(
                "StorageManager not set. Use with_storage_manager() first.".to_string(),
            )),
        }
    }

    pub fn exists(&self, _user_id: &str, wallet_id: &str) -> StorageResult<bool> {
        match self._storage_manager {
            Some(storage_manager) => {
                let storage = storage_manager.wallets()?;
                let key = format!("wallet::{}", wallet_id);
                storage.exists(&key)
            }
            None => Err(crate::storage::StorageError::PathGeneration(
                "StorageManager not set. Use with_storage_manager() first.".to_string(),
            )),
        }
    }

    pub fn deactivate(&self, _user_id: &str, wallet_id: &str) -> StorageResult<()> {
        match self._storage_manager {
            Some(storage_manager) => {
                let storage = storage_manager.wallets()?;
                let key = format!("wallet::{}", wallet_id);
                storage.update(&key, &|wallet| {
                    wallet.is_active = false;
                    wallet.updated_at = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                })
            }
            None => Err(crate::storage::StorageError::PathGeneration(
                "StorageManager not set. Use with_storage_manager() first.".to_string(),
            )),
        }
    }

    pub fn update_description(&mut self, description: Option<String>) -> StorageResult<()> {
        match self._storage_manager {
            Some(storage_manager) => {
                self.description = description;
                self.updated_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                let storage = storage_manager.wallets()?;
                storage.store(&self.get_key_identifier(), self)?;
                Ok(())
            }
            None => Err(crate::storage::StorageError::PathGeneration(
                "StorageManager not set. Use with_storage_manager() first.".to_string(),
            )),
        }
    }
}

impl Storable for StoredWallet {
    fn schema() -> Schema {
        Schema::new(
            "stored_wallet",
            1,
            "Wallet metadata storage with user association",
        )
        .add_field(
            FieldSchema::new(
                "wallet_id",
                FieldType::String,
                true,
                "Unique wallet identifier",
            )
            .with_validation(FieldValidation {
                min_length: Some(1),
                max_length: Some(128),
                pattern: None,
                min_value: None,
                max_value: None,
                allowed_values: None,
            }),
        )
        .add_field(
            FieldSchema::new(
                "user_id",
                FieldType::String,
                true,
                "The user ID this wallet belongs to",
            )
            .with_validation(FieldValidation {
                min_length: Some(1),
                max_length: Some(128),
                pattern: None,
                min_value: None,
                max_value: None,
                allowed_values: None,
            }),
        )
        .add_field(FieldSchema::new(
            "name",
            FieldType::String,
            true,
            "Human-readable wallet name",
        ))
        .add_field(FieldSchema::new(
            "description",
            FieldType::Optional(Box::new(FieldType::String)),
            false,
            "Optional wallet description",
        ))
        .add_field(
            FieldSchema::new(
                "network",
                FieldType::String,
                true,
                "Bitcoin network (mainnet, testnet, regtest)",
            )
            .with_validation(FieldValidation {
                min_length: None,
                max_length: None,
                pattern: None,
                min_value: None,
                max_value: None,
                allowed_values: Some(vec![
                    "mainnet".to_string(),
                    "testnet".to_string(),
                    "regtest".to_string(),
                ]),
            }),
        )
        .add_field(FieldSchema::new(
            "wallet_type",
            FieldType::String,
            true,
            "Type of wallet (single, multisig, advanced)",
        ))
        .add_field(FieldSchema::new(
            "liana_descriptor",
            FieldType::Optional(Box::new(FieldType::String)),
            false,
            "Optional Liana multipath descriptor for PSBT pruning",
        ))
        .add_field(FieldSchema::new(
            "created_at",
            FieldType::Integer,
            true,
            "Creation timestamp",
        ))
        .add_field(FieldSchema::new(
            "updated_at",
            FieldType::Integer,
            true,
            "Last update timestamp",
        ))
        .add_field(FieldSchema::new(
            "is_active",
            FieldType::Boolean,
            true,
            "Whether the wallet is active",
        ))
        .add_index(IndexSchema::new(
            "by_user_id",
            vec!["user_id"],
            false,
            "Index by user ID",
        ))
        .add_index(IndexSchema::new(
            "by_wallet_id",
            vec!["wallet_id"],
            false,
            "Index by wallet ID",
        ))
        .add_index(IndexSchema::new(
            "by_network",
            vec!["network"],
            false,
            "Index by Bitcoin network",
        ))
        .add_index(IndexSchema::new(
            "by_user_wallet",
            vec!["user_id", "wallet_id"],
            true,
            "Unique index for user/wallet combination",
        ))
        .add_index(IndexSchema::new(
            "by_active_status",
            vec!["user_id", "is_active"],
            false,
            "Index by user ID and active status",
        ))
    }

    fn validate(&self) -> Result<(), String> {
        if self.wallet_id.is_empty() {
            return Err("wallet_id cannot be empty".to_string());
        }

        if self.user_id.is_empty() {
            return Err("user_id cannot be empty".to_string());
        }

        if !["mainnet", "testnet", "regtest"].contains(&self.network.as_str()) {
            return Err("network must be 'mainnet', 'testnet', or 'regtest'".to_string());
        }

        Ok(())
    }

    fn get_indexable_fields(&self) -> HashMap<String, serde_json::Value> {
        let mut fields = HashMap::new();

        fields.insert(
            "wallet_id".to_string(),
            serde_json::Value::String(self.wallet_id.clone()),
        );
        fields.insert(
            "user_id".to_string(),
            serde_json::Value::String(self.user_id.clone()),
        );
        fields.insert(
            "name".to_string(),
            serde_json::Value::String(self.name.clone()),
        );
        fields.insert(
            "network".to_string(),
            serde_json::Value::String(self.network.clone()),
        );
        fields.insert(
            "wallet_type".to_string(),
            serde_json::Value::String(self.wallet_type.clone()),
        );
        fields.insert(
            "created_at".to_string(),
            serde_json::Value::Number(serde_json::Number::from(self.created_at)),
        );
        fields.insert(
            "updated_at".to_string(),
            serde_json::Value::Number(serde_json::Number::from(self.updated_at)),
        );
        fields.insert(
            "is_active".to_string(),
            serde_json::Value::Bool(self.is_active),
        );

        if let Some(description) = &self.description {
            fields.insert(
                "description".to_string(),
                serde_json::Value::String(description.clone()),
            );
        }

        if let Some(liana_descriptor) = &self.liana_descriptor {
            fields.insert(
                "liana_descriptor".to_string(),
                serde_json::Value::String(liana_descriptor.clone()),
            );
        }

        fields
    }
}
