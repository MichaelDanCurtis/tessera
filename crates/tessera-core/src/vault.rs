//! `VaultStore` — the KV-v2 orchestration layer (replaces V1's `KvStore`). A single
//! concrete, non-generic type so axum has exactly one `AppState`. Every op:
//! require_unsealed → authorize → per-path atomic read-modify-write of the
//! `VersionedSecret` blob → audit. Time is injected via `Clock`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::audit::{token_hash, AuditOp, AuditRecord, AuditSink};
use crate::auth::TokenStore;
use crate::clock::Clock;
use crate::engine::SecretEngine;
use crate::seal::SealState;
use crate::types::{SecretPath, TesseraError, VersionedSecret};

pub struct VaultStore {
    engine: Arc<dyn SecretEngine>,
    seal: SealState,
    tokens: TokenStore,
    audit: Arc<dyn AuditSink>,
    clock: Arc<dyn Clock>,
    /// Per-path async locks keyed by `path.scope()`, guarding each RMW so version
    /// increments are atomic on a single node.
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl VaultStore {
    pub fn new(
        engine: Arc<dyn SecretEngine>,
        seal: SealState,
        tokens: TokenStore,
        audit: Arc<dyn AuditSink>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            engine,
            seal,
            tokens,
            audit,
            clock,
            locks: Mutex::new(HashMap::new()),
        }
    }

    pub fn seal_state(&self) -> &SealState {
        &self.seal
    }

    pub fn audit_sink(&self) -> &Arc<dyn AuditSink> {
        &self.audit
    }

    /// Seal + auth gate. On auth failure, records an `AuthFailure` audit entry and
    /// returns the error (fail-closed, before any engine touch).
    fn guard(&self, token: &str, path: &SecretPath) -> Result<(), TesseraError> {
        self.seal.require_unsealed()?;
        if let Err(e) = self.tokens.authorize(token, path) {
            self.audit.append(AuditRecord {
                op: AuditOp::AuthFailure,
                scope: path.scope(),
                token_hash: token_hash(token),
                outcome: false,
            });
            return Err(e);
        }
        Ok(())
    }

    fn record(&self, op: AuditOp, path: &SecretPath, token: &str, outcome: bool) {
        self.audit.append(AuditRecord {
            op,
            scope: path.scope(),
            token_hash: token_hash(token),
            outcome,
        });
    }

    /// Acquire (creating if absent) the per-path lock handle. The returned `Arc`
    /// guards a `tokio::sync::Mutex<()>` the caller `.lock().await`s around its RMW.
    fn path_lock(&self, path: &SecretPath) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.locks.lock().expect("locks poisoned");
        map.entry(path.scope())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Read + deserialize the `VersionedSecret` for `path`, or `None` if absent.
    async fn load(&self, path: &SecretPath) -> Result<Option<VersionedSecret>, TesseraError> {
        match self.engine.get(path).await? {
            None => Ok(None),
            Some(blob) => {
                let vs: VersionedSecret = serde_json::from_slice(&blob)
                    .map_err(|e| TesseraError::Storage(format!("decode VersionedSecret: {e}")))?;
                Ok(Some(vs))
            }
        }
    }

    /// Serialize + write the `VersionedSecret` blob for `path`.
    async fn save(&self, path: &SecretPath, vs: &VersionedSecret) -> Result<(), TesseraError> {
        let blob = serde_json::to_vec(vs)
            .map_err(|e| TesseraError::Storage(format!("encode VersionedSecret: {e}")))?;
        self.engine.put(path, blob).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::InMemoryAudit;
    use crate::auth::Policy;
    use crate::clock::FixedClock;
    use crate::engine::InMemoryEngine;

    pub(super) fn store() -> VaultStore {
        let mut tokens = TokenStore::new();
        tokens.insert("galvo-tok", Policy::new(["secret/galvo/"]));
        let seal = SealState::new(b"m".to_vec());
        seal.unseal(b"m").unwrap();
        VaultStore::new(
            Arc::new(InMemoryEngine::new()),
            seal,
            tokens,
            Arc::new(InMemoryAudit::new()),
            Arc::new(FixedClock("2026-06-14T00:00:00Z".into())),
        )
    }

    #[tokio::test]
    async fn sealed_store_refuses_before_engine() {
        let s = store();
        s.seal_state().seal();
        // read isn't defined until Task 6; assert the guard directly.
        let p = SecretPath::new("secret", "galvo/openai");
        assert_eq!(s.guard("galvo-tok", &p), Err(TesseraError::Sealed));
    }

    #[tokio::test]
    async fn out_of_scope_denied_and_audited() {
        let s = store();
        let p = SecretPath::new("secret", "femto/key");
        assert_eq!(
            s.guard("galvo-tok", &p),
            Err(TesseraError::Forbidden("secret/femto/key".into()))
        );
        let recs = s.audit_sink().records();
        assert_eq!(recs.last().unwrap().op, AuditOp::AuthFailure);
        assert!(!recs.last().unwrap().outcome);
    }

    #[tokio::test]
    async fn unknown_token_denied() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        assert_eq!(s.guard("nope", &p), Err(TesseraError::InvalidToken));
    }
}
