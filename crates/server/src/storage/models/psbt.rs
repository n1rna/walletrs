use crate::storage::schema::{FieldSchema, FieldType, FieldValidation, IndexSchema};
use crate::storage::{Schema, Storable, Storage, StorageManager, StorageResult};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPSBT {
    pub txid: String,
    pub wallet_id: String,
    pub psbt_data: String,
    pub created_at: i64,
    pub status: String, // "draft", "partial", "finalized"
    #[serde(skip)]
    pub _storage_manager: Option<&'static StorageManager>,
}

impl StoredPSBT {
    pub fn new(txid: &str, wallet_id: &str, psbt_data: &str) -> Self {
        Self {
            txid: txid.to_string(),
            wallet_id: wallet_id.to_string(),
            psbt_data: psbt_data.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            status: "draft".to_string(),
            _storage_manager: None,
        }
    }

    pub fn new_with_status(txid: &str, wallet_id: &str, psbt_data: &str, status: &str) -> Self {
        Self {
            txid: txid.to_string(),
            wallet_id: wallet_id.to_string(),
            psbt_data: psbt_data.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            status: status.to_string(),
            _storage_manager: None,
        }
    }

    pub fn with_storage_manager(mut self, storage_manager: &'static StorageManager) -> Self {
        self._storage_manager = Some(storage_manager);
        self
    }

    // Helper methods for common operations
    pub fn store(&self) -> StorageResult<()> {
        match self._storage_manager {
            Some(storage_manager) => {
                let storage = storage_manager.psbts(&self.wallet_id)?;
                storage.store(&self.txid, self)
            }
            None => Err(crate::storage::StorageError::PathGeneration(
                "StorageManager not set. Use with_storage_manager() first.".to_string(),
            )),
        }
    }

    // Legacy method for backward compatibility
    pub fn store_with_manager(&self, storage_manager: &StorageManager) -> StorageResult<()> {
        let storage = storage_manager.psbts(&self.wallet_id)?;
        storage.store(&self.txid, self)
    }

    pub fn get(
        storage_manager: &'static StorageManager,
        wallet_id: &str,
        txid: &str,
    ) -> StorageResult<Option<Self>> {
        let storage = storage_manager.psbts(wallet_id)?;
        match storage.get(txid)? {
            Some(mut psbt) => {
                psbt._storage_manager = Some(storage_manager);
                Ok(Some(psbt))
            }
            None => Ok(None),
        }
    }

    pub fn update_status(&mut self, status: &str) -> Result<(), String> {
        if !["draft", "partial", "finalized"].contains(&status) {
            return Err("status must be 'draft', 'partial', or 'finalized'".to_string());
        }
        self.status = status.to_string();
        Ok(())
    }

    pub fn update_and_save_status(&mut self, status: &str) -> StorageResult<()> {
        self.update_status(status)
            .map_err(crate::storage::StorageError::PathGeneration)?;
        match self._storage_manager {
            Some(storage_manager) => {
                let storage = storage_manager.psbts(&self.wallet_id)?;
                storage.store(&self.txid, self)
            }
            None => Err(crate::storage::StorageError::PathGeneration(
                "StorageManager not set. Use with_storage_manager() first.".to_string(),
            )),
        }
    }

    pub fn update_status_in_storage(
        storage_manager: &StorageManager,
        wallet_id: &str,
        txid: &str,
        status: &str,
    ) -> StorageResult<()> {
        let storage = storage_manager.psbts(wallet_id)?;
        storage.update(txid, &|psbt: &mut Self| {
            let _ = psbt.update_status(status); // Ignore validation error for now
        })
    }

    pub fn is_draft(&self) -> bool {
        self.status == "draft"
    }

    pub fn is_partial(&self) -> bool {
        self.status == "partial"
    }

    pub fn is_finalized(&self) -> bool {
        self.status == "finalized"
    }

    pub fn list_by_wallet(
        storage_manager: &'static StorageManager,
        wallet_id: &str,
    ) -> StorageResult<Vec<Self>> {
        let storage = storage_manager.psbts(wallet_id)?;
        let results = storage.query(&|_| true)?; // Get all PSBTs for wallet
        Ok(results
            .into_iter()
            .map(|(_, mut value)| {
                value._storage_manager = Some(storage_manager);
                value
            })
            .collect())
    }

    pub fn list_by_status(
        storage_manager: &'static StorageManager,
        wallet_id: &str,
        status: &str,
    ) -> StorageResult<Vec<Self>> {
        let storage = storage_manager.psbts(wallet_id)?;
        let filter_fn = |psbt: &Self| psbt.status == status;
        let results = storage.query(&filter_fn)?;
        Ok(results
            .into_iter()
            .map(|(_, mut value)| {
                value._storage_manager = Some(storage_manager);
                value
            })
            .collect())
    }
}

impl Storable for StoredPSBT {
    fn schema() -> Schema {
        Schema::new("stored_psbt", 1, "Stored PSBT transaction data")
            .add_field(
                FieldSchema::new("txid", FieldType::String, true, "Transaction ID")
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
                "wallet_id",
                FieldType::String,
                true,
                "Wallet ID this transaction belongs to",
            ))
            .add_field(FieldSchema::new(
                "psbt_data",
                FieldType::String,
                true,
                "Base64 encoded PSBT data",
            ))
            .add_field(FieldSchema::new(
                "created_at",
                FieldType::Integer,
                true,
                "Creation timestamp",
            ))
            .add_field(
                FieldSchema::new("status", FieldType::String, true, "Transaction status")
                    .with_validation(FieldValidation {
                        min_length: None,
                        max_length: None,
                        pattern: None,
                        min_value: None,
                        max_value: None,
                        allowed_values: Some(vec![
                            "draft".to_string(),
                            "partial".to_string(),
                            "finalized".to_string(),
                        ]),
                    }),
            )
            .add_index(IndexSchema::new(
                "by_wallet_id",
                vec!["wallet_id"],
                false,
                "Index by wallet ID",
            ))
            .add_index(IndexSchema::new(
                "by_status",
                vec!["status"],
                false,
                "Index by transaction status",
            ))
    }

    fn validate(&self) -> Result<(), String> {
        if self.txid.is_empty() {
            return Err("txid cannot be empty".to_string());
        }

        if self.wallet_id.is_empty() {
            return Err("wallet_id cannot be empty".to_string());
        }

        if self.psbt_data.is_empty() {
            return Err("psbt_data cannot be empty".to_string());
        }

        if !["draft", "partial", "finalized"].contains(&self.status.as_str()) {
            return Err("status must be 'draft', 'partial', or 'finalized'".to_string());
        }

        Ok(())
    }

    fn get_indexable_fields(&self) -> HashMap<String, serde_json::Value> {
        let mut fields = HashMap::new();

        fields.insert(
            "txid".to_string(),
            serde_json::Value::String(self.txid.clone()),
        );
        fields.insert(
            "wallet_id".to_string(),
            serde_json::Value::String(self.wallet_id.clone()),
        );
        fields.insert(
            "status".to_string(),
            serde_json::Value::String(self.status.clone()),
        );
        fields.insert(
            "created_at".to_string(),
            serde_json::Value::Number(serde_json::Number::from(self.created_at)),
        );

        fields
    }
}
