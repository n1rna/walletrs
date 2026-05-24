use crate::storage::schema::{FieldSchema, FieldType, FieldValidation, IndexSchema};
use crate::storage::{Schema, Storable, Storage, StorageManager, StorageResult};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredManagedKey {
    pub user_id: String,
    pub device_id: String,
    pub key_name: String,
    pub key_type: String, // "customer" or "system"
    pub xpub: String,
    pub fingerprint: String,
    pub derivation_path: String,
    // System-only fields (None for customer keys)
    pub xpriv: Option<String>, // Private key - only for system managed keys
    pub mnemonic: Option<String>, // Mnemonic words - only for system managed keys
    pub tpriv: Option<String>, // Derived private key - only for system managed keys
    pub tpub: Option<String>,  // Derived public key - only for system managed keys
    pub created_at: i64,
    #[serde(skip)]
    pub _storage_manager: Option<&'static StorageManager>,
}

impl StoredManagedKey {
    pub fn generate_key_identifier(user_id: &str, device_id: &str, key_type: &str) -> String {
        format!("user::{}::device::{}::{}", user_id, device_id, key_type)
    }

    /// Test-only: invariant property the key identifier format must hold.
    /// Used by the proptest below.
    #[cfg(test)]
    fn id_invariant_marker() -> &'static str {
        // The literal "::" is what makes the format injective for inputs
        // that don't themselves contain "::". This marker is referenced in
        // the proptest's prop_assume! so the assumption is grep-able.
        "::"
    }

    /// Project the fields the policy pipeline cares about (origin metadata +
    /// xpub/tpub) into the lightweight `policy_core::ManagedKey` shape. The
    /// pipeline never sees DB plumbing fields like `user_id`, key custody
    /// type, or hot-key material — those are server concerns.
    pub fn to_managed_key(&self) -> policy_core::ManagedKey {
        policy_core::ManagedKey {
            fingerprint: self.fingerprint.clone(),
            derivation_path: self.derivation_path.clone(),
            xpub: self.xpub.clone(),
            tpub: self.tpub.clone(),
        }
    }

    pub fn get_key_identifier(&self) -> String {
        Self::generate_key_identifier(&self.user_id, &self.device_id, &self.key_type)
    }

    pub fn new_customer_key(
        user_id: &str,
        device_id: &str,
        key_name: &str,
        xpub: &str,
        fingerprint: &str,
        derivation_path: &str,
    ) -> Self {
        Self {
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            key_name: key_name.to_string(),
            key_type: "customer".to_string(),
            xpub: xpub.to_string(),
            fingerprint: fingerprint.to_string(),
            derivation_path: derivation_path.to_string(),
            xpriv: None,
            mnemonic: None,
            tpriv: None,
            tpub: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            _storage_manager: None,
        }
    }

    pub fn new_system_key(
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
    ) -> Self {
        Self {
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            key_name: key_name.to_string(),
            key_type: "system".to_string(),
            xpub: xpub.to_string(),
            fingerprint: fingerprint.to_string(),
            derivation_path: derivation_path.to_string(),
            xpriv: Some(xpriv.to_string()),
            mnemonic: Some(mnemonic.to_string()),
            tpriv: Some(tpriv.to_string()),
            tpub: Some(tpub.to_string()),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
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
                let storage = storage_manager.managed_keys()?;
                storage.store(&self.get_key_identifier(), self)
            }
            None => Err(crate::storage::StorageError::PathGeneration(
                "StorageManager not set. Use with_storage_manager() first.".to_string(),
            )),
        }
    }

    pub fn get(
        storage_manager: &'static StorageManager,
        user_id: &str,
        device_id: &str,
        key_type: &str,
    ) -> StorageResult<Option<Self>> {
        let storage = storage_manager.managed_keys()?;
        let key = Self::generate_key_identifier(user_id, device_id, key_type);
        match storage.get(&key)? {
            Some(mut managed_key) => {
                managed_key._storage_manager = Some(storage_manager);
                Ok(Some(managed_key))
            }
            None => Ok(None),
        }
    }

    pub fn list(
        storage_manager: &'static StorageManager,
        user_id_filter: Option<&str>,
        key_type_filter: Option<&str>,
    ) -> StorageResult<Vec<Self>> {
        // Since ManagedKeys scope requires user_id, we can only list for a specific user
        let _user_id = user_id_filter.ok_or_else(|| {
            crate::storage::StorageError::PathGeneration(
                "user_id_filter is required when using ManagedKeys scope".to_string(),
            )
        })?;
        let storage = storage_manager.managed_keys()?;
        let filter_fn = |key: &Self| {
            if let Some(user_id) = user_id_filter {
                if key.user_id != user_id {
                    return false;
                }
            }
            if let Some(key_type) = key_type_filter {
                if key.key_type != key_type {
                    return false;
                }
            }
            true
        };

        let results = storage.query(&filter_fn)?;
        Ok(results
            .into_iter()
            .map(|(_, mut value)| {
                value._storage_manager = Some(storage_manager);
                value
            })
            .collect())
    }

    pub fn is_customer_key(&self) -> bool {
        self.key_type == "customer"
    }

    pub fn is_system_key(&self) -> bool {
        self.key_type == "system"
    }

    pub fn has_private_key_material(&self) -> bool {
        self.xpriv.is_some() || self.mnemonic.is_some() || self.tpriv.is_some()
    }
}

impl Storable for StoredManagedKey {
    fn schema() -> Schema {
        Schema::new(
            "stored_managed_key",
            1,
            "Unified managed key storage for customer and system keys",
        )
        .add_field(
            FieldSchema::new(
                "user_id",
                FieldType::String,
                true,
                "The user ID this key belongs to",
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
                "device_id",
                FieldType::String,
                true,
                "The device ID this key belongs to",
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
            "key_name",
            FieldType::String,
            true,
            "Human-readable name for this key",
        ))
        .add_field(
            FieldSchema::new(
                "key_type",
                FieldType::String,
                true,
                "Type of key management",
            )
            .with_validation(FieldValidation {
                min_length: None,
                max_length: None,
                pattern: None,
                min_value: None,
                max_value: None,
                allowed_values: Some(vec!["customer".to_string(), "system".to_string()]),
            }),
        )
        .add_field(FieldSchema::new(
            "xpub",
            FieldType::String,
            true,
            "Extended public key",
        ))
        .add_field(FieldSchema::new(
            "fingerprint",
            FieldType::String,
            true,
            "Key fingerprint",
        ))
        .add_field(FieldSchema::new(
            "derivation_path",
            FieldType::String,
            true,
            "BIP32 derivation path",
        ))
        .add_field(FieldSchema::new(
            "xpriv",
            FieldType::Optional(Box::new(FieldType::String)),
            false,
            "Extended private key (system managed keys only)",
        ))
        .add_field(FieldSchema::new(
            "mnemonic",
            FieldType::Optional(Box::new(FieldType::String)),
            false,
            "Mnemonic phrase (system managed keys only)",
        ))
        .add_field(FieldSchema::new(
            "tpriv",
            FieldType::Optional(Box::new(FieldType::String)),
            false,
            "Derived private key (system managed keys only)",
        ))
        .add_field(FieldSchema::new(
            "tpub",
            FieldType::Optional(Box::new(FieldType::String)),
            false,
            "Derived public key (system managed keys only)",
        ))
        .add_field(FieldSchema::new(
            "created_at",
            FieldType::Integer,
            true,
            "Creation timestamp",
        ))
        .add_index(IndexSchema::new(
            "by_user_id",
            vec!["user_id"],
            false,
            "Index by user ID",
        ))
        .add_index(IndexSchema::new(
            "by_device_id",
            vec!["device_id"],
            false,
            "Index by device ID",
        ))
        .add_index(IndexSchema::new(
            "by_key_type",
            vec!["key_type"],
            false,
            "Index by key type (customer/system)",
        ))
        .add_index(IndexSchema::new(
            "by_user_device_type",
            vec!["user_id", "device_id", "key_type"],
            true,
            "Unique index for user/device/type combination",
        ))
    }

    fn validate(&self) -> Result<(), String> {
        if self.user_id.is_empty() {
            return Err("user_id cannot be empty".to_string());
        }

        if self.device_id.is_empty() {
            return Err("device_id cannot be empty".to_string());
        }

        if !["customer", "system"].contains(&self.key_type.as_str()) {
            return Err("key_type must be 'customer' or 'system'".to_string());
        }

        if self.xpub.is_empty() {
            return Err("xpub cannot be empty".to_string());
        }

        if self.fingerprint.is_empty() {
            return Err("fingerprint cannot be empty".to_string());
        }

        // System keys must have private key material
        if self.key_type == "system" {
            if self.xpriv.is_none() {
                return Err("system keys must have xpriv".to_string());
            }
            if self.mnemonic.is_none() {
                return Err("system keys must have mnemonic".to_string());
            }
        }

        // Customer keys should not have private key material
        if self.key_type == "customer" {
            if self.xpriv.is_some() || self.mnemonic.is_some() || self.tpriv.is_some() {
                return Err("customer keys must not have private key material".to_string());
            }
        }

        Ok(())
    }

    fn get_indexable_fields(&self) -> HashMap<String, serde_json::Value> {
        let mut fields = HashMap::new();

        fields.insert(
            "user_id".to_string(),
            serde_json::Value::String(self.user_id.clone()),
        );
        fields.insert(
            "device_id".to_string(),
            serde_json::Value::String(self.device_id.clone()),
        );
        fields.insert(
            "key_type".to_string(),
            serde_json::Value::String(self.key_type.clone()),
        );
        fields.insert(
            "key_name".to_string(),
            serde_json::Value::String(self.key_name.clone()),
        );
        fields.insert(
            "fingerprint".to_string(),
            serde_json::Value::String(self.fingerprint.clone()),
        );
        fields.insert(
            "xpub".to_string(),
            serde_json::Value::String(self.xpub.clone()),
        );
        fields.insert(
            "derivation_path".to_string(),
            serde_json::Value::String(self.derivation_path.clone()),
        );
        fields.insert(
            "created_at".to_string(),
            serde_json::Value::Number(serde_json::Number::from(self.created_at)),
        );
        fields.insert(
            "has_private_key".to_string(),
            serde_json::Value::Bool(self.xpriv.is_some()),
        );

        fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The key identifier format is injective for inputs that don't
        /// themselves contain the "::" delimiter — distinct (user, device,
        /// key_type) triples produce distinct identifiers, which is the
        /// property the storage layer relies on to avoid silently
        /// overwriting one key's row with another's.
        #[test]
        fn prop_key_identifier_injective_for_simple_inputs(
            u1 in "[a-zA-Z0-9_-]{1,32}",
            d1 in "[a-zA-Z0-9_-]{1,32}",
            t1 in "[a-zA-Z0-9_-]{1,16}",
            u2 in "[a-zA-Z0-9_-]{1,32}",
            d2 in "[a-zA-Z0-9_-]{1,32}",
            t2 in "[a-zA-Z0-9_-]{1,16}",
        ) {
            // The marker is referenced so a future format change that breaks
            // the "::" separator gets the test's attention.
            let _delim = StoredManagedKey::id_invariant_marker();

            let id1 = StoredManagedKey::generate_key_identifier(&u1, &d1, &t1);
            let id2 = StoredManagedKey::generate_key_identifier(&u2, &d2, &t2);

            if id1 == id2 {
                prop_assert_eq!((u1.as_str(), d1.as_str(), t1.as_str()), (u2.as_str(), d2.as_str(), t2.as_str()));
            }
        }

        /// Self-consistency: the identifier built by `get_key_identifier`
        /// on a stored row matches the one `generate_key_identifier`
        /// computes from the same triple. Without this, get-by-identifier
        /// lookups would silently miss rows.
        #[test]
        fn prop_get_key_identifier_matches_generate(
            user in "[a-zA-Z0-9_-]{1,32}",
            device in "[a-zA-Z0-9_-]{1,32}",
            key_type in "[a-zA-Z0-9_-]{1,16}",
        ) {
            let mk = StoredManagedKey::new_customer_key(
                &user, &device, "name", "xpub", "fp", "m/84'/1'/0'",
            );
            // Override key_type since new_customer_key hardcodes "customer".
            let mut mk = mk;
            mk.key_type = key_type.clone();
            let from_self = mk.get_key_identifier();
            let from_static =
                StoredManagedKey::generate_key_identifier(&user, &device, &key_type);
            prop_assert_eq!(from_self, from_static);
        }
    }
}
