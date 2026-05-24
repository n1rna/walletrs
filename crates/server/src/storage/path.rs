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

    // ---- property tests -------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        /// Sanitization is *idempotent*: sanitize(sanitize(x)) == sanitize(x).
        /// Catches regressions where adding a new replacement rule would
        /// cause double-sanitization to drift.
        #[test]
        fn prop_sanitize_is_idempotent(s in ".*") {
            if let Ok(once) = sanitize_path_component(&s) {
                let twice = sanitize_path_component(&once)
                    .expect("once-sanitized output must itself sanitize");
                prop_assert_eq!(once, twice);
            }
        }

        /// Any successful sanitization output must be safe for use as a path
        /// component: no '/', '\\', or ".." sequence. The storage layer
        /// concatenates sanitized values into filesystem paths; a leak of
        /// any of these characters would enable directory traversal.
        #[test]
        fn prop_sanitize_output_has_no_path_escape_chars(s in ".*") {
            if let Ok(out) = sanitize_path_component(&s) {
                prop_assert!(!out.contains('/'), "output has '/': {:?}", out);
                prop_assert!(!out.contains('\\'), "output has '\\\\': {:?}", out);
                prop_assert!(!out.contains(".."), "output has '..': {:?}", out);
            }
        }

        /// Any input containing '/', '\\', or ".." must be *rejected*, not
        /// just rewritten — the function's contract is to fail loudly on
        /// would-be path-traversal inputs so a buggy caller can't smuggle
        /// them in.
        ///
        /// Note: `prop_oneof!` with `&str` arguments treats them as regex,
        /// not literals — using `Just(...)` is the easiest way to feed
        /// literal markers.
        #[test]
        fn prop_sanitize_rejects_traversal_inputs(
            base in "[a-zA-Z0-9_-]{1,16}",
            marker in prop_oneof![
                Just("/".to_string()),
                Just("\\".to_string()),
                Just("..".to_string()),
            ],
        ) {
            let bad = format!("{}{}", base, marker);
            prop_assert!(
                sanitize_path_component(&bad).is_err(),
                "input {:?} containing {:?} must be rejected",
                bad, marker
            );
        }

        /// Strings that are *already* sanitized (i.e. only the allowed
        /// alphabet, and no ".." sequence) must round-trip unchanged. The
        /// `..` substring is rejected even when individual `.` characters
        /// are in the allowed alphabet — that's the path-traversal guard.
        #[test]
        fn prop_sanitize_preserves_allowed_alphabet(
            s in "[a-zA-Z0-9_\\-:.]{1,64}"
        ) {
            prop_assume!(!s.contains(".."));
            let out = sanitize_path_component(&s).expect("allowed-alphabet input must sanitize");
            prop_assert_eq!(out, s);
        }
    }
}
