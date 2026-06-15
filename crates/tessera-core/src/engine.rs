use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::types::{SecretMetadata, SecretPath, SecretValue, TesseraError};

/// Storage seam. RustyVault and the in-memory test store both implement this.
/// Single-version semantics: write replaces, no history.
pub trait SecretEngine: Send + Sync {
    fn put(&self, path: &SecretPath, value: SecretValue) -> Result<(), TesseraError>;
    fn get(&self, path: &SecretPath) -> Result<(SecretValue, SecretMetadata), TesseraError>;
    fn delete(&self, path: &SecretPath) -> Result<(), TesseraError>;
    /// List immediate key names under `prefix` (mount+path prefix).
    fn list(&self, prefix: &SecretPath) -> Result<Vec<String>, TesseraError>;
    fn metadata(&self, path: &SecretPath) -> Result<SecretMetadata, TesseraError>;
}

/// In-memory engine for tests and the embed-vs-subprocess-independent path.
/// `created_time` is injected (no wall-clock in core) so tests are deterministic.
pub struct InMemoryEngine {
    store: Mutex<BTreeMap<String, SecretValue>>,
    created_time: String,
}

impl InMemoryEngine {
    pub fn new(created_time: impl Into<String>) -> Self {
        Self {
            store: Mutex::new(BTreeMap::new()),
            created_time: created_time.into(),
        }
    }
}

impl SecretEngine for InMemoryEngine {
    fn put(&self, path: &SecretPath, value: SecretValue) -> Result<(), TesseraError> {
        self.store.lock().unwrap().insert(path.scope(), value);
        Ok(())
    }
    fn get(&self, path: &SecretPath) -> Result<(SecretValue, SecretMetadata), TesseraError> {
        let store = self.store.lock().unwrap();
        let value = store
            .get(&path.scope())
            .cloned()
            .ok_or(TesseraError::NotFound)?;
        Ok((
            value,
            SecretMetadata {
                current_version: 1,
                created_time: self.created_time.clone(),
            },
        ))
    }
    fn delete(&self, path: &SecretPath) -> Result<(), TesseraError> {
        self.store
            .lock()
            .unwrap()
            .remove(&path.scope())
            .map(|_| ())
            .ok_or(TesseraError::NotFound)
    }
    fn list(&self, prefix: &SecretPath) -> Result<Vec<String>, TesseraError> {
        let scope_prefix = if prefix.path.is_empty() {
            format!("{}/", prefix.mount)
        } else {
            format!("{}/{}/", prefix.mount, prefix.path.trim_end_matches('/'))
        };
        let store = self.store.lock().unwrap();
        let mut keys: Vec<String> = store
            .keys()
            .filter_map(|k| k.strip_prefix(&scope_prefix))
            .filter_map(|rest| rest.split('/').next())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        keys.sort();
        keys.dedup();
        Ok(keys)
    }
    fn metadata(&self, path: &SecretPath) -> Result<SecretMetadata, TesseraError> {
        self.get(path).map(|(_, meta)| meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn val(k: &str, v: &str) -> SecretValue {
        let mut m = SecretValue::default();
        m.0.insert(k.into(), v.into());
        m
    }

    #[test]
    fn put_then_get_roundtrips() {
        let eng = InMemoryEngine::new("2026-06-14T00:00:00Z");
        let p = SecretPath::new("secret", "galvo/openai");
        eng.put(&p, val("api_key", "sk-1")).unwrap();
        let (v, meta) = eng.get(&p).unwrap();
        assert_eq!(v.0.get("api_key").unwrap(), "sk-1");
        assert_eq!(meta.current_version, 1);
    }

    #[test]
    fn get_missing_is_not_found() {
        let eng = InMemoryEngine::new("t");
        assert_eq!(
            eng.get(&SecretPath::new("secret", "nope")),
            Err(TesseraError::NotFound)
        );
    }

    #[test]
    fn list_returns_immediate_names_under_prefix() {
        let eng = InMemoryEngine::new("t");
        eng.put(&SecretPath::new("secret", "galvo/openai"), val("k", "1"))
            .unwrap();
        eng.put(&SecretPath::new("secret", "galvo/anthropic"), val("k", "2"))
            .unwrap();
        eng.put(&SecretPath::new("secret", "femto/key"), val("k", "3"))
            .unwrap();
        let keys = eng.list(&SecretPath::new("secret", "galvo")).unwrap();
        assert_eq!(keys, vec!["anthropic".to_string(), "openai".to_string()]);
    }

    #[test]
    fn delete_removes_then_missing() {
        let eng = InMemoryEngine::new("t");
        let p = SecretPath::new("secret", "galvo/openai");
        eng.put(&p, val("k", "1")).unwrap();
        eng.delete(&p).unwrap();
        assert_eq!(eng.delete(&p), Err(TesseraError::NotFound));
    }
}
