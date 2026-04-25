use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Item not found: {0}")]
    NotFound(String),

    #[error("Schema validation error: {0}")]
    SchemaValidation(String),

    #[error("Path generation error: {0}")]
    PathGeneration(String),

    #[error("Index error: {0}")]
    Index(String),
}

pub type StorageResult<T> = Result<T, StorageError>;

pub trait Storage<T>
where
    T: Serialize + for<'de> Deserialize<'de> + Clone,
{
    fn store(&self, key: &str, item: &T) -> StorageResult<()>;

    fn get(&self, key: &str) -> StorageResult<Option<T>>;

    fn delete(&self, key: &str) -> StorageResult<bool>;

    fn list(&self) -> StorageResult<Vec<String>>;

    fn exists(&self, key: &str) -> StorageResult<bool>;

    fn query(&self, filter: &dyn Fn(&T) -> bool) -> StorageResult<Vec<(String, T)>>;

    fn update(&self, key: &str, updater: &dyn Fn(&mut T)) -> StorageResult<()>;
}

pub trait StorageBackend {
    fn read_bytes(&self, path: &str) -> StorageResult<Vec<u8>>;

    fn write_bytes(&self, path: &str, data: &[u8]) -> StorageResult<()>;

    fn delete_file(&self, path: &str) -> StorageResult<bool>;

    fn list_files(&self, prefix: &str) -> StorageResult<Vec<String>>;

    fn file_exists(&self, path: &str) -> StorageResult<bool>;

    fn create_directory(&self, path: &str) -> StorageResult<()>;
}

pub trait IndexableStorage<T>: Storage<T>
where
    T: Serialize + for<'de> Deserialize<'de> + Clone,
{
    fn get_index_entries(&self) -> StorageResult<HashMap<String, serde_json::Value>>;

    fn rebuild_index(&self) -> StorageResult<()>;

    fn query_by_index(
        &self,
        field: &str,
        value: &serde_json::Value,
    ) -> StorageResult<Vec<(String, T)>>;
}
