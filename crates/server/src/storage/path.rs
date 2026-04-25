use crate::storage::{StorageError, StorageResult};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum ScopeType {
    Global,
    User(String),
    Wallet(String),
}

pub trait PathStrategy {
    fn generate_path(
        &self,
        scope: &ScopeType,
        model_name: &str,
        key: &str,
    ) -> StorageResult<String>;

    fn generate_index_path(&self, scope: &ScopeType, model_name: &str) -> StorageResult<String>;

    fn get_base_dir(&self) -> &str;

    /// Generate just the directory path for a given scope
    fn generate_scope_dir(&self, scope: &ScopeType) -> StorageResult<String>;
}

pub struct FileSystemPathStrategy {
    base_dir: String,
}

impl FileSystemPathStrategy {
    pub fn new(base_dir: &str) -> Self {
        Self {
            base_dir: base_dir.to_string(),
        }
    }
}

impl PathStrategy for FileSystemPathStrategy {
    fn get_base_dir(&self) -> &str {
        &self.base_dir
    }

    fn generate_path(
        &self,
        scope: &ScopeType,
        model_name: &str,
        key: &str,
    ) -> StorageResult<String> {
        let scope_path = self.generate_scope_dir(scope)?;

        let sanitized_model = sanitize_path_component(model_name)?;
        let sanitized_key = sanitize_path_component(key)?;

        let path = PathBuf::from(scope_path)
            .join(&sanitized_model)
            .join(format!("{}.json", sanitized_key));

        path.to_str()
            .ok_or_else(|| StorageError::PathGeneration("Invalid UTF-8 in path".to_string()))
            .map(|s| s.to_string())
    }

    fn generate_index_path(&self, scope: &ScopeType, model_name: &str) -> StorageResult<String> {
        let scope_path = self.generate_scope_dir(scope)?;

        let sanitized_model = sanitize_path_component(model_name)?;

        let path = PathBuf::from(scope_path)
            .join(&sanitized_model)
            .join("index.json");

        path.to_str()
            .ok_or_else(|| StorageError::PathGeneration("Invalid UTF-8 in index path".to_string()))
            .map(|s| s.to_string())
    }

    fn generate_scope_dir(&self, scope: &ScopeType) -> StorageResult<String> {
        let scope_path = match scope {
            ScopeType::Global => "global".to_string(),
            ScopeType::User(user_id) => format!("users/{}", sanitize_path_component(user_id)?),
            ScopeType::Wallet(wallet_id) => {
                format!("wallets/{}", sanitize_path_component(wallet_id)?)
            }
        };

        let path = PathBuf::from(&self.base_dir).join(&scope_path);
        path.to_str()
            .ok_or_else(|| {
                StorageError::PathGeneration("Invalid UTF-8 in scope dir path".to_string())
            })
            .map(|s| s.to_string())
    }
}

fn sanitize_path_component(component: &str) -> StorageResult<String> {
    if component.is_empty() {
        return Ok("".into());
    }

    if component.contains("..") || component.contains('/') || component.contains('\\') {
        return Err(StorageError::PathGeneration(format!(
            "Invalid characters in path component: {}",
            component
        )));
    }

    let sanitized = component
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == ':' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();

    Ok(sanitized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_generation() {
        let strategy = FileSystemPathStrategy::new("storage");

        assert_eq!(
            strategy
                .generate_path(
                    &ScopeType::Global,
                    "managed_keys",
                    "user::123::device::456::system"
                )
                .unwrap(),
            "storage/global/managed_keys/user::123::device::456::system.json"
        );

        assert_eq!(
            strategy
                .generate_path(&ScopeType::User("test-user".to_string()), "keys", "server")
                .unwrap(),
            "storage/users/test-user/keys/server.json"
        );

        assert_eq!(
            strategy
                .generate_index_path(&ScopeType::Global, "managed_keys")
                .unwrap(),
            "storage/global/managed_keys/index.json"
        );
    }

    #[test]
    fn test_scope_dir_generation() {
        let strategy = FileSystemPathStrategy::new("storage");

        assert_eq!(
            strategy.generate_scope_dir(&ScopeType::Global).unwrap(),
            "storage/global"
        );

        assert_eq!(
            strategy
                .generate_scope_dir(&ScopeType::User("user123".to_string()))
                .unwrap(),
            "storage/users/user123"
        );

        assert_eq!(
            strategy
                .generate_scope_dir(&ScopeType::User("test-user".to_string()))
                .unwrap(),
            "storage/users/test-user"
        );

        assert_eq!(
            strategy
                .generate_scope_dir(&ScopeType::User("user123".to_string()))
                .unwrap(),
            "storage/users/user123"
        );
    }

    #[test]
    fn test_sanitization() {
        assert_eq!(
            sanitize_path_component("valid-name_123").unwrap(),
            "valid-name_123"
        );
        assert!(sanitize_path_component("../invalid").is_err());
        assert!(sanitize_path_component("path/with/slash").is_err());
        assert_eq!(
            sanitize_path_component("name with spaces").unwrap(),
            "name_with_spaces"
        );
    }
}
