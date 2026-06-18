use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::types::{SecretPath, TesseraError};

/// Primitive async blob store. Stores exactly one opaque `Vec<u8>` per path —
/// it knows nothing about versions or metadata (that lives in `VaultStore`).
/// `RustyVaultEngine` and the in-memory test store both implement this.
#[async_trait::async_trait]
pub trait SecretEngine: Send + Sync {
    async fn get(&self, path: &SecretPath) -> Result<Option<Vec<u8>>, TesseraError>;
    async fn put(&self, path: &SecretPath, blob: Vec<u8>) -> Result<(), TesseraError>;
    async fn delete(&self, path: &SecretPath) -> Result<(), TesseraError>;
    /// List immediate key names under `prefix` (mount+path prefix), sorted + deduped.
    async fn list(&self, prefix: &SecretPath) -> Result<Vec<String>, TesseraError>;

    /// Atomic check-and-insert. Inserts `blob` at `path` only if no value
    /// currently exists there. Returns `true` if inserted (first use), `false`
    /// if a value already existed (the key is "consumed"). The check and the
    /// insert happen under a single critical section so concurrent callers see
    /// exactly one `true`.
    async fn put_if_absent(&self, path: &SecretPath, blob: Vec<u8>) -> Result<bool, TesseraError>;
}

/// In-memory blob engine for tests and the contract test. No wall-clock, no
/// version state — opaque bytes only.
#[derive(Default)]
pub struct InMemoryEngine {
    store: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl InMemoryEngine {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl SecretEngine for InMemoryEngine {
    async fn get(&self, path: &SecretPath) -> Result<Option<Vec<u8>>, TesseraError> {
        Ok(self.store.lock().unwrap().get(&path.scope()).cloned())
    }

    async fn put(&self, path: &SecretPath, blob: Vec<u8>) -> Result<(), TesseraError> {
        self.store.lock().unwrap().insert(path.scope(), blob);
        Ok(())
    }

    async fn delete(&self, path: &SecretPath) -> Result<(), TesseraError> {
        // Idempotent: removing an absent key is not an error at the blob layer.
        self.store.lock().unwrap().remove(&path.scope());
        Ok(())
    }

    async fn list(&self, prefix: &SecretPath) -> Result<Vec<String>, TesseraError> {
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

    async fn put_if_absent(&self, path: &SecretPath, blob: Vec<u8>) -> Result<bool, TesseraError> {
        use std::collections::btree_map::Entry;
        let mut store = self.store.lock().unwrap();
        match store.entry(path.scope()) {
            Entry::Occupied(_) => Ok(false),
            Entry::Vacant(slot) => {
                slot.insert(blob);
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_then_get_roundtrips_blob() {
        let eng = InMemoryEngine::new();
        let p = SecretPath::new("secret", "galvo/openai");
        eng.put(&p, b"hello-blob".to_vec()).await.unwrap();
        let got = eng.get(&p).await.unwrap();
        assert_eq!(got, Some(b"hello-blob".to_vec()));
    }

    #[tokio::test]
    async fn get_missing_is_none() {
        let eng = InMemoryEngine::new();
        let got = eng.get(&SecretPath::new("secret", "nope")).await.unwrap();
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn put_overwrites_blob() {
        let eng = InMemoryEngine::new();
        let p = SecretPath::new("secret", "galvo/openai");
        eng.put(&p, b"v1".to_vec()).await.unwrap();
        eng.put(&p, b"v2".to_vec()).await.unwrap();
        assert_eq!(eng.get(&p).await.unwrap(), Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn delete_removes_then_none() {
        let eng = InMemoryEngine::new();
        let p = SecretPath::new("secret", "galvo/openai");
        eng.put(&p, b"x".to_vec()).await.unwrap();
        eng.delete(&p).await.unwrap();
        assert_eq!(eng.get(&p).await.unwrap(), None);
    }

    #[tokio::test]
    async fn delete_missing_is_ok() {
        // Blob delete is idempotent; "missing-ness" is the store layer's concern now.
        let eng = InMemoryEngine::new();
        eng.delete(&SecretPath::new("secret", "nope"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_returns_immediate_names_under_prefix() {
        let eng = InMemoryEngine::new();
        eng.put(&SecretPath::new("secret", "galvo/openai"), b"1".to_vec())
            .await
            .unwrap();
        eng.put(&SecretPath::new("secret", "galvo/anthropic"), b"2".to_vec())
            .await
            .unwrap();
        eng.put(&SecretPath::new("secret", "femto/key"), b"3".to_vec())
            .await
            .unwrap();
        let keys = eng.list(&SecretPath::new("secret", "galvo")).await.unwrap();
        assert_eq!(keys, vec!["anthropic".to_string(), "openai".to_string()]);
    }

    #[tokio::test]
    async fn put_if_absent_inserts_first_returns_true() {
        let eng = InMemoryEngine::new();
        let p = SecretPath::new("tessera-sys", "a2e-nonce-ledger/abc");
        assert!(eng.put_if_absent(&p, b"marker".to_vec()).await.unwrap());
        assert_eq!(eng.get(&p).await.unwrap(), Some(b"marker".to_vec()));
    }

    #[tokio::test]
    async fn put_if_absent_second_returns_false_and_keeps_first() {
        let eng = InMemoryEngine::new();
        let p = SecretPath::new("tessera-sys", "a2e-nonce-ledger/abc");
        assert!(eng.put_if_absent(&p, b"first".to_vec()).await.unwrap());
        assert!(!eng.put_if_absent(&p, b"second".to_vec()).await.unwrap());
        // The original value is preserved (insert did not overwrite).
        assert_eq!(eng.get(&p).await.unwrap(), Some(b"first".to_vec()));
    }

    #[tokio::test]
    async fn put_if_absent_is_concurrent_safe_exactly_one_true() {
        // 32 concurrent inserters on the SAME key: exactly one sees `true`.
        let eng = std::sync::Arc::new(InMemoryEngine::new());
        let p = SecretPath::new("tessera-sys", "a2e-nonce-ledger/race");
        let mut handles = Vec::new();
        for _ in 0..32 {
            let eng = std::sync::Arc::clone(&eng);
            let p = p.clone();
            handles.push(tokio::spawn(async move {
                eng.put_if_absent(&p, b"x".to_vec()).await.unwrap()
            }));
        }
        let mut trues = 0;
        for h in handles {
            if h.await.unwrap() {
                trues += 1;
            }
        }
        assert_eq!(trues, 1, "exactly one inserter must win");
    }
}
