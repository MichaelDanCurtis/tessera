use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::persist::{read_to_string_opt, write_atomic};
use crate::types::{SecretPath, TesseraError};

/// A policy allow-lists scope prefixes a token may touch, e.g. `secret/galvo/`.
/// Empty allow-list = deny everything (fail-closed).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    pub allow_prefixes: Vec<String>,
}

impl Policy {
    pub fn new(prefixes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            allow_prefixes: prefixes.into_iter().map(Into::into).collect(),
        }
    }

    /// True iff `path`'s scope starts with any allowed prefix.
    pub fn allows(&self, path: &SecretPath) -> bool {
        let scope = path.scope();
        self.allow_prefixes
            .iter()
            .any(|p| scope.starts_with(p.as_str()))
    }
}

/// Persistent name→Policy store. Backed by a single JSON map file written
/// atomically on each mutation. Thread-safe via an internal `Mutex`.
pub struct PolicyStore {
    path: PathBuf,
    policies: Mutex<HashMap<String, Policy>>,
}

impl PolicyStore {
    /// Open (or create) the store at `path`, loading any existing policies.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let policies = match read_to_string_opt(&path)? {
            Some(s) if !s.trim().is_empty() => serde_json::from_str(&s).unwrap_or_default(),
            _ => HashMap::new(),
        };
        Ok(Self {
            path,
            policies: Mutex::new(policies),
        })
    }

    fn flush(&self, map: &HashMap<String, Policy>) -> std::io::Result<()> {
        let json = serde_json::to_string(map).expect("policies serialize");
        write_atomic(&self.path, &json)
    }

    pub fn put(&self, name: &str, policy: Policy) -> std::io::Result<()> {
        let mut map = self.policies.lock().unwrap();
        map.insert(name.to_string(), policy);
        self.flush(&map)
    }

    pub fn get(&self, name: &str) -> Option<Policy> {
        self.policies.lock().unwrap().get(name).cloned()
    }

    pub fn list(&self) -> Vec<String> {
        self.policies.lock().unwrap().keys().cloned().collect()
    }

    pub fn delete(&self, name: &str) -> std::io::Result<()> {
        let mut map = self.policies.lock().unwrap();
        map.remove(name);
        self.flush(&map)
    }
}

/// Maps opaque token strings to policies. Tokens are configured up front in V1
/// (no dynamic token issuance — that arrives with PKI/V1.5).
#[derive(Default)]
pub struct TokenStore {
    tokens: HashMap<String, Policy>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            tokens: HashMap::new(),
        }
    }

    pub fn insert(&mut self, token: impl Into<String>, policy: Policy) {
        self.tokens.insert(token.into(), policy);
    }

    /// Authorize `token` for `path`. `Err(InvalidToken)` if unknown,
    /// `Err(Forbidden)` if out of scope. Fail-closed on both.
    pub fn authorize(&self, token: &str, path: &SecretPath) -> Result<(), TesseraError> {
        let policy = self.tokens.get(token).ok_or(TesseraError::InvalidToken)?;
        if policy.allows(path) {
            Ok(())
        } else {
            Err(TesseraError::Forbidden(path.scope()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> TokenStore {
        let mut s = TokenStore::new();
        s.insert("galvo-tok", Policy::new(["secret/galvo/"]));
        s.insert("empty-tok", Policy::default());
        s
    }

    #[test]
    fn in_scope_path_authorized() {
        store()
            .authorize("galvo-tok", &SecretPath::new("secret", "galvo/openai"))
            .unwrap();
    }

    #[test]
    fn out_of_scope_path_forbidden() {
        let err = store()
            .authorize("galvo-tok", &SecretPath::new("secret", "femto/key"))
            .unwrap_err();
        assert_eq!(err, TesseraError::Forbidden("secret/femto/key".into()));
    }

    #[test]
    fn unknown_token_invalid() {
        assert_eq!(
            store().authorize("nope", &SecretPath::new("secret", "galvo/openai")),
            Err(TesseraError::InvalidToken)
        );
    }

    #[test]
    fn policy_store_crud_and_persist() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("policies.json");
        {
            let store = PolicyStore::open(&path).unwrap();
            store.put("galvo", Policy::new(["secret/galvo/"])).unwrap();
            store.put("femto", Policy::new(["secret/femto/"])).unwrap();
            assert_eq!(
                store.get("galvo").unwrap().allow_prefixes,
                vec!["secret/galvo/"]
            );
            let mut names = store.list();
            names.sort();
            assert_eq!(names, vec!["femto".to_string(), "galvo".to_string()]);
            store.delete("femto").unwrap();
            assert!(store.get("femto").is_none());
        }
        // reopen: galvo survives, femto stays deleted
        let store = PolicyStore::open(&path).unwrap();
        assert!(store.get("galvo").is_some());
        assert!(store.get("femto").is_none());
    }

    #[test]
    fn empty_policy_denies_everything() {
        let err = store()
            .authorize("empty-tok", &SecretPath::new("secret", "galvo/openai"))
            .unwrap_err();
        assert!(matches!(err, TesseraError::Forbidden(_)));
    }
}
