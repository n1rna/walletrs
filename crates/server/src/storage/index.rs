use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::storage::{StorageResult, StorageError};
use crate::storage::traits::StorageBackend;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexCache {
    pub model_name: String,
    pub version: u32,
    pub entries: HashMap<String, IndexEntry>,
    pub secondary_indexes: HashMap<String, HashMap<serde_json::Value, Vec<String>>>,
    pub last_updated: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub key: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub fields: HashMap<String, serde_json::Value>,
}

impl IndexCache {
    pub fn new(model_name: &str) -> Self {
        Self {
            model_name: model_name.to_string(),
            version: 1,
            entries: HashMap::new(),
            secondary_indexes: HashMap::new(),
            last_updated: chrono::Utc::now().timestamp(),
        }
    }
    
    pub fn add_entry(&mut self, key: &str, fields: HashMap<String, serde_json::Value>) {
        let now = chrono::Utc::now().timestamp();
        
        let entry = IndexEntry {
            key: key.to_string(),
            created_at: now,
            updated_at: now,
            fields: fields.clone(),
        };
        
        self.entries.insert(key.to_string(), entry);
        
        for (field_name, field_value) in fields {
            self.secondary_indexes
                .entry(field_name)
                .or_insert_with(HashMap::new)
                .entry(field_value)
                .or_insert_with(Vec::new)
                .push(key.to_string());
        }
        
        self.last_updated = now;
    }
    
    pub fn update_entry(&mut self, key: &str, fields: HashMap<String, serde_json::Value>) {
        if let Some(entry) = self.entries.get(key) {
            let old_fields = entry.fields.clone();
            self.remove_from_secondary_indexes(key, &old_fields);
            
            if let Some(entry) = self.entries.get_mut(key) {
                entry.fields = fields.clone();
                entry.updated_at = chrono::Utc::now().timestamp();
            }
            
            for (field_name, field_value) in fields {
                self.secondary_indexes
                    .entry(field_name)
                    .or_insert_with(HashMap::new)
                    .entry(field_value)
                    .or_insert_with(Vec::new)
                    .push(key.to_string());
            }
            
            self.last_updated = chrono::Utc::now().timestamp();
        }
    }
    
    pub fn remove_entry(&mut self, key: &str) {
        if let Some(entry) = self.entries.remove(key) {
            self.remove_from_secondary_indexes(key, &entry.fields);
            self.last_updated = chrono::Utc::now().timestamp();
        }
    }
    
    pub fn query_by_field(&self, field_name: &str, value: &serde_json::Value) -> Vec<String> {
        self.secondary_indexes
            .get(field_name)
            .and_then(|field_index| field_index.get(value))
            .cloned()
            .unwrap_or_default()
    }
    
    pub fn list_all_keys(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }
    
    fn remove_from_secondary_indexes(&mut self, key: &str, fields: &HashMap<String, serde_json::Value>) {
        for (field_name, field_value) in fields {
            if let Some(field_index) = self.secondary_indexes.get_mut(field_name) {
                if let Some(keys) = field_index.get_mut(field_value) {
                    keys.retain(|k| k != key);
                    if keys.is_empty() {
                        field_index.remove(field_value);
                    }
                }
                if field_index.is_empty() {
                    self.secondary_indexes.remove(field_name);
                }
            }
        }
    }
}

pub struct IndexManager<B: StorageBackend> {
    backend: B,
    index_path: String,
}

impl<B: StorageBackend> IndexManager<B> {
    pub fn new(backend: B, index_path: String) -> Self {
        Self {
            backend,
            index_path,
        }
    }
    
    pub fn load_or_create_index(&self, model_name: &str) -> StorageResult<IndexCache> {
        match self.backend.read_bytes(&self.index_path) {
            Ok(data) => {
                let json_str = String::from_utf8(data)
                    .map_err(|e| StorageError::Index(format!("Invalid UTF-8 in index file: {}", e)))?;
                
                let index: IndexCache = serde_json::from_str(&json_str)
                    .map_err(|e| StorageError::Index(format!("Failed to parse index file: {}", e)))?;
                
                Ok(index)
            }
            Err(StorageError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(IndexCache::new(model_name))
            }
            Err(e) => Err(e),
        }
    }
    
    pub fn save_index(&self, index: &IndexCache) -> StorageResult<()> {
        let json_str = serde_json::to_string_pretty(index)
            .map_err(|e| StorageError::Index(format!("Failed to serialize index: {}", e)))?;
        
        if let Some(parent) = std::path::Path::new(&self.index_path).parent() {
            if let Some(parent_str) = parent.to_str() {
                self.backend.create_directory(parent_str)?;
            }
        }
        
        self.backend.write_bytes(&self.index_path, json_str.as_bytes())?;
        Ok(())
    }
}