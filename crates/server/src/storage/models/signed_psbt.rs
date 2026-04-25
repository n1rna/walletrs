use crate::storage::{Schema, Storable, Storage, StorageManager, StorageResult};
use crate::storage::schema::{FieldSchema, FieldType, IndexSchema};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSignedPSBT {
    pub txid: String,
    pub wallet_id: String,
    pub device_fingerprint: String,
    pub psbt_data: String,
    pub created_at: i64,
    pub is_finalized: bool,
    #[serde(skip)]
    pub _storage_manager: Option<&'static StorageManager>,
}

impl StoredSignedPSBT {
    pub fn new(
        txid: &str,
        wallet_id: &str,
        device_fingerprint: &str,
        psbt_data: &str,
        is_finalized: bool,
    ) -> Self {
        Self {
            txid: txid.to_string(),
            wallet_id: wallet_id.to_string(),
            device_fingerprint: device_fingerprint.to_string(),
            psbt_data: psbt_data.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            is_finalized,
            _storage_manager: None,
        }
    }

    pub fn new_partial(
        txid: &str,
        wallet_id: &str,
        device_fingerprint: &str,
        psbt_data: &str,
    ) -> Self {
        Self::new(txid, wallet_id, device_fingerprint, psbt_data, false)
    }

    pub fn new_finalized(
        txid: &str,
        wallet_id: &str,
        device_fingerprint: &str,
        psbt_data: &str,
    ) -> Self {
        Self::new(txid, wallet_id, device_fingerprint, psbt_data, true)
    }

    pub fn with_storage_manager(mut self, storage_manager: &'static StorageManager) -> Self {
        self._storage_manager = Some(storage_manager);
        self
    }

    // Helper methods for common operations
    pub fn store(&self) -> StorageResult<()> {
        match self._storage_manager {
            Some(storage_manager) => {
                let storage = storage_manager.signed_psbts(&self.wallet_id)?;
                let key = format!("{}_{}", self.txid, self.device_fingerprint);
                storage.store(&key, self)
            }
            None => Err(crate::storage::StorageError::PathGeneration(
                "StorageManager not set. Use with_storage_manager() first.".to_string()
            ))
        }
    }

    // Legacy method for backward compatibility
    pub fn store_with_manager(&self, storage_manager: &StorageManager) -> StorageResult<()> {
        let storage = storage_manager.signed_psbts(&self.wallet_id)?;
        let key = format!("{}_{}", self.txid, self.device_fingerprint);
        storage.store(&key, self)
    }

    pub fn get_by_txid_and_device(
        storage_manager: &'static StorageManager,
        wallet_id: &str,
        txid: &str,
        device_fingerprint: &str,
    ) -> StorageResult<Option<Self>> {
        let storage = storage_manager.signed_psbts(wallet_id)?;
        let key = format!("{}_{}", txid, device_fingerprint);
        match storage.get(&key)? {
            Some(mut signed_psbt) => {
                signed_psbt._storage_manager = Some(storage_manager);
                Ok(Some(signed_psbt))
            }
            None => Ok(None)
        }
    }

    pub fn list_by_txid(
        storage_manager: &'static StorageManager,
        wallet_id: &str,
        txid: &str,
    ) -> StorageResult<Vec<Self>> {
        let storage = storage_manager.signed_psbts(wallet_id)?;
        let filter_fn = |psbt: &Self| psbt.txid == txid;
        let results = storage.query(&filter_fn)?;
        Ok(results.into_iter().map(|(_, mut value)| {
            value._storage_manager = Some(storage_manager);
            value
        }).collect())
    }

    pub fn get_finalized_by_txid(
        storage_manager: &'static StorageManager,
        wallet_id: &str,
        txid: &str,
    ) -> StorageResult<Option<Self>> {
        let storage = storage_manager.signed_psbts(wallet_id)?;
        let filter_fn = |psbt: &Self| psbt.txid == txid && psbt.is_finalized;
        let results = storage.query(&filter_fn)?;
        Ok(results.into_iter().map(|(_, mut value)| {
            value._storage_manager = Some(storage_manager);
            value
        }).next())
    }

    pub fn list_by_device(
        storage_manager: &'static StorageManager,
        wallet_id: &str,
        device_fingerprint: &str,
    ) -> StorageResult<Vec<Self>> {
        let storage = storage_manager.signed_psbts(wallet_id)?;
        let filter_fn = |psbt: &Self| psbt.device_fingerprint == device_fingerprint;
        let results = storage.query(&filter_fn)?;
        Ok(results.into_iter().map(|(_, mut value)| {
            value._storage_manager = Some(storage_manager);
            value
        }).collect())
    }

    pub fn list_finalized(
        storage_manager: &'static StorageManager,
        wallet_id: &str,
    ) -> StorageResult<Vec<Self>> {
        let storage = storage_manager.signed_psbts(wallet_id)?;
        let filter_fn = |psbt: &Self| psbt.is_finalized;
        let results = storage.query(&filter_fn)?;
        Ok(results.into_iter().map(|(_, mut value)| {
            value._storage_manager = Some(storage_manager);
            value
        }).collect())
    }

    pub fn mark_finalized(&mut self) {
        self.is_finalized = true;
    }

    pub fn mark_finalized_and_save(&mut self) -> StorageResult<()> {
        self.mark_finalized();
        match self._storage_manager {
            Some(storage_manager) => {
                let storage = storage_manager.signed_psbts(&self.wallet_id)?;
                let key = format!("{}_{}", self.txid, self.device_fingerprint);
                storage.store(&key, self)
            }
            None => Err(crate::storage::StorageError::PathGeneration(
                "StorageManager not set. Use with_storage_manager() first.".to_string()
            ))
        }
    }

    pub fn get_storage_key(&self) -> String {
        format!("{}_{}", self.txid, self.device_fingerprint)
    }
}

impl Storable for StoredSignedPSBT {
    fn schema() -> Schema {
        Schema::new("stored_signed_psbt", 1, "Stored signed PSBT data from devices")
            .add_field(FieldSchema::new(
                "txid",
                FieldType::String,
                true,
                "Transaction ID"
            ))
            .add_field(FieldSchema::new(
                "wallet_id",
                FieldType::String,
                true,
                "Wallet ID this transaction belongs to"
            ))
            .add_field(FieldSchema::new(
                "device_fingerprint",
                FieldType::String,
                true,
                "Device fingerprint that signed this PSBT"
            ))
            .add_field(FieldSchema::new(
                "psbt_data",
                FieldType::String,
                true,
                "Base64 encoded signed PSBT data"
            ))
            .add_field(FieldSchema::new(
                "created_at",
                FieldType::Integer,
                true,
                "Creation timestamp"
            ))
            .add_field(FieldSchema::new(
                "is_finalized",
                FieldType::Boolean,
                true,
                "Whether this PSBT is finalized"
            ))
            .add_index(IndexSchema::new(
                "by_txid",
                vec!["txid"],
                false,
                "Index by transaction ID"
            ))
            .add_index(IndexSchema::new(
                "by_wallet_id",
                vec!["wallet_id"],
                false,
                "Index by wallet ID"
            ))
            .add_index(IndexSchema::new(
                "by_txid_and_device",
                vec!["txid", "device_fingerprint"],
                true,
                "Unique index for transaction and device combination"
            ))
    }

    fn validate(&self) -> Result<(), String> {
        if self.txid.is_empty() {
            return Err("txid cannot be empty".to_string());
        }

        if self.wallet_id.is_empty() {
            return Err("wallet_id cannot be empty".to_string());
        }

        if self.device_fingerprint.is_empty() {
            return Err("device_fingerprint cannot be empty".to_string());
        }

        if self.psbt_data.is_empty() {
            return Err("psbt_data cannot be empty".to_string());
        }

        Ok(())
    }

    fn get_indexable_fields(&self) -> HashMap<String, serde_json::Value> {
        let mut fields = HashMap::new();

        fields.insert("txid".to_string(), serde_json::Value::String(self.txid.clone()));
        fields.insert("wallet_id".to_string(), serde_json::Value::String(self.wallet_id.clone()));
        fields.insert("device_fingerprint".to_string(), serde_json::Value::String(self.device_fingerprint.clone()));
        fields.insert("created_at".to_string(), serde_json::Value::Number(serde_json::Number::from(self.created_at)));
        fields.insert("is_finalized".to_string(), serde_json::Value::Bool(self.is_finalized));

        fields
    }
}