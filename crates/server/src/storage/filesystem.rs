use crate::storage::traits::{IndexableStorage, Storage, StorageBackend};
use crate::storage::{
    IndexCache, IndexManager, PathStrategy, ScopeType, Storable, StorageError, StorageResult,
};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct LocalFileSystemBackend {
    base_path: String,
}

impl LocalFileSystemBackend {
    pub fn new(base_path: &str) -> Self {
        Self {
            base_path: base_path.to_string(),
        }
    }
}

impl StorageBackend for LocalFileSystemBackend {
    fn read_bytes(&self, path: &str) -> StorageResult<Vec<u8>> {
        let full_path = Path::new(&self.base_path).join(path);
        fs::read(full_path).map_err(StorageError::Io)
    }

    fn write_bytes(&self, path: &str, data: &[u8]) -> StorageResult<()> {
        let full_path = Path::new(&self.base_path).join(path);

        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).map_err(StorageError::Io)?;
        }

        let mut file = fs::File::create(full_path).map_err(StorageError::Io)?;
        file.write_all(data).map_err(StorageError::Io)
    }

    fn delete_file(&self, path: &str) -> StorageResult<bool> {
        let full_path = Path::new(&self.base_path).join(path);
        match fs::remove_file(full_path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    fn list_files(&self, prefix: &str) -> StorageResult<Vec<String>> {
        let full_prefix_path = Path::new(&self.base_path).join(prefix);
        let prefix_parent = full_prefix_path.parent().ok_or_else(|| {
            StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid prefix path",
            ))
        })?;

        if !prefix_parent.exists() {
            return Ok(Vec::new());
        }

        let mut files = Vec::new();
        list_files_recursive(prefix_parent, &mut files)?;

        let prefix_str = prefix.trim_end_matches('/');
        Ok(files
            .into_iter()
            .filter(|f| f.starts_with(prefix_str))
            .collect())
    }

    fn file_exists(&self, path: &str) -> StorageResult<bool> {
        let full_path = Path::new(&self.base_path).join(path);
        Ok(full_path.exists())
    }

    fn create_directory(&self, path: &str) -> StorageResult<()> {
        let full_path = Path::new(&self.base_path).join(path);
        fs::create_dir_all(full_path).map_err(StorageError::Io)
    }
}

fn list_files_recursive(dir: &Path, files: &mut Vec<String>) -> StorageResult<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(dir).map_err(StorageError::Io)? {
        let entry = entry.map_err(StorageError::Io)?;
        let path = entry.path();

        if path.is_file() {
            if let Some(path_str) = path.to_str() {
                files.push(path_str.to_string());
            }
        } else if path.is_dir() {
            list_files_recursive(&path, files)?;
        }
    }

    Ok(())
}

pub struct FileSystemStorage<T, P, B>
where
    T: Storable,
    P: PathStrategy,
    B: StorageBackend + Clone,
{
    backend: B,
    pub path_strategy: P,
    scope: ScopeType,
    model_name: String,
    index_manager: Arc<Mutex<IndexManager<B>>>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T, P, B> FileSystemStorage<T, P, B>
where
    T: Storable,
    P: PathStrategy,
    B: StorageBackend + Clone,
{
    pub fn new(
        backend: B,
        path_strategy: P,
        scope: ScopeType,
        model_name: &str,
    ) -> StorageResult<Self> {
        let index_path = path_strategy.generate_index_path(&scope, model_name)?;
        let index_manager = Arc::new(Mutex::new(IndexManager::new(backend.clone(), index_path)));

        Ok(Self {
            backend,
            path_strategy,
            scope,
            model_name: model_name.to_string(),
            index_manager,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<T, P, B> Storage<T> for FileSystemStorage<T, P, B>
where
    T: Storable,
    P: PathStrategy,
    B: StorageBackend + Clone,
{
    fn store(&self, key: &str, item: &T) -> StorageResult<()> {
        item.validate().map_err(StorageError::SchemaValidation)?;

        let path = self
            .path_strategy
            .generate_path(&self.scope, &self.model_name, key)?;
        let json_data = serde_json::to_string_pretty(item)?;

        self.backend.write_bytes(&path, json_data.as_bytes())?;

        let indexable_fields = item.get_indexable_fields();
        let index_manager = self.index_manager.lock().unwrap();
        let mut index = index_manager.load_or_create_index(&self.model_name)?;
        index.add_entry(key, indexable_fields);
        index_manager.save_index(&index)?;

        Ok(())
    }

    fn get(&self, key: &str) -> StorageResult<Option<T>> {
        let path = self
            .path_strategy
            .generate_path(&self.scope, &self.model_name, key)?;

        match self.backend.read_bytes(&path) {
            Ok(data) => {
                let json_str = String::from_utf8(data).map_err(|e| {
                    StorageError::Serialization(serde_json::Error::io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e,
                    )))
                })?;

                let item: T = serde_json::from_str(&json_str)?;
                Ok(Some(item))
            }
            Err(StorageError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn delete(&self, key: &str) -> StorageResult<bool> {
        let path = self
            .path_strategy
            .generate_path(&self.scope, &self.model_name, key)?;
        let deleted = self.backend.delete_file(&path)?;

        if deleted {
            let index_manager = self.index_manager.lock().unwrap();
            let mut index = index_manager.load_or_create_index(&self.model_name)?;
            index.remove_entry(key);
            index_manager.save_index(&index)?;
        }

        Ok(deleted)
    }

    fn list(&self) -> StorageResult<Vec<String>> {
        let index_manager = self.index_manager.lock().unwrap();
        let index = index_manager.load_or_create_index(&self.model_name)?;
        Ok(index.list_all_keys())
    }

    fn exists(&self, key: &str) -> StorageResult<bool> {
        let path = self
            .path_strategy
            .generate_path(&self.scope, &self.model_name, key)?;
        self.backend.file_exists(&path)
    }

    fn query(&self, filter: &dyn Fn(&T) -> bool) -> StorageResult<Vec<(String, T)>> {
        let keys = self.list()?;
        let mut results = Vec::new();

        for key in keys {
            if let Some(item) = self.get(&key)? {
                if filter(&item) {
                    results.push((key, item));
                }
            }
        }

        Ok(results)
    }

    fn update(&self, key: &str, updater: &dyn Fn(&mut T)) -> StorageResult<()> {
        if let Some(mut item) = self.get(key)? {
            updater(&mut item);
            self.store(key, &item)
        } else {
            Err(StorageError::NotFound(key.to_string()))
        }
    }
}

impl<T, P, B> IndexableStorage<T> for FileSystemStorage<T, P, B>
where
    T: Storable,
    P: PathStrategy,
    B: StorageBackend + Clone,
{
    fn get_index_entries(&self) -> StorageResult<HashMap<String, serde_json::Value>> {
        let index_manager = self.index_manager.lock().unwrap();
        let index = index_manager.load_or_create_index(&self.model_name)?;

        let mut result = HashMap::new();
        for (key, entry) in &index.entries {
            result.insert(key.clone(), serde_json::to_value(&entry.fields)?);
        }

        Ok(result)
    }

    fn rebuild_index(&self) -> StorageResult<()> {
        let keys = self.list()?;
        let mut index = IndexCache::new(&self.model_name);

        for key in keys {
            if let Some(item) = self.get(&key)? {
                let indexable_fields = item.get_indexable_fields();
                index.add_entry(&key, indexable_fields);
            }
        }

        let index_manager = self.index_manager.lock().unwrap();
        index_manager.save_index(&index)?;

        Ok(())
    }

    fn query_by_index(
        &self,
        field: &str,
        value: &serde_json::Value,
    ) -> StorageResult<Vec<(String, T)>> {
        let index_manager = self.index_manager.lock().unwrap();
        let index = index_manager.load_or_create_index(&self.model_name)?;

        let keys = index.query_by_field(field, value);
        let mut results = Vec::new();

        for key in keys {
            if let Some(item) = self.get(&key)? {
                results.push((key, item));
            }
        }

        Ok(results)
    }
}
