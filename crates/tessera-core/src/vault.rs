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
use crate::types::{SecretPath, SecretValue, TesseraError, Version, VersionMeta, VersionedSecret};

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

    pub async fn write(
        &self,
        token: &str,
        path: &SecretPath,
        value: SecretValue,
        cas: Option<u32>,
    ) -> Result<u32, TesseraError> {
        self.guard(token, path)?;
        let lock = self.path_lock(path);
        let _g = lock.lock().await;

        let now = self.clock.now_rfc3339();
        let mut vs = self
            .load(path)
            .await?
            .unwrap_or_else(|| VersionedSecret::empty(now.clone()));

        // CAS gate (per spec §5).
        let effective_cas = if vs.cas_required {
            cas.or(Some(u32::MAX))
        } else {
            cas
        };
        if let Some(want) = effective_cas {
            if want != vs.current_version {
                // includes: cas_required bare-write (want=MAX), stale, cas=0 on existing
                self.record(AuditOp::Write, path, token, false);
                return Err(TesseraError::CasMismatch);
            }
        }

        let new_version = vs.current_version + 1;
        vs.versions.insert(
            new_version,
            Version {
                data: Some(value),
                created_time: now.clone(),
                deletion_time: None,
                destroyed: false,
            },
        );
        vs.current_version = new_version;
        if vs.oldest_version == 0 {
            vs.oldest_version = new_version;
        }
        vs.updated_time = now;

        // Trim: drop data of versions older than the max_versions window.
        while vs.current_version - vs.oldest_version + 1 > vs.max_versions {
            if let Some(v) = vs.versions.get_mut(&vs.oldest_version) {
                v.data = None;
            }
            vs.oldest_version += 1;
        }

        self.save(path, &vs).await?;
        self.record(AuditOp::Write, path, token, true);
        Ok(new_version)
    }

    pub async fn read(
        &self,
        token: &str,
        path: &SecretPath,
        version: Option<u32>,
    ) -> Result<(Option<SecretValue>, VersionMeta), TesseraError> {
        self.guard(token, path)?;
        let vs = match self.load(path).await? {
            Some(vs) if vs.current_version > 0 => vs,
            _ => {
                self.record(AuditOp::Read, path, token, false);
                return Err(TesseraError::NotFound);
            }
        };
        let n = version.unwrap_or(vs.current_version);
        let ver = match vs.versions.get(&n) {
            Some(v) => v,
            None => {
                self.record(AuditOp::Read, path, token, false);
                return Err(TesseraError::NotFound);
            }
        };
        // Soft-deleted or destroyed => no value (null data), metadata still returned.
        let value = if ver.deletion_time.is_some() || ver.destroyed {
            None
        } else {
            ver.data.clone()
        };
        let meta = VersionMeta {
            version: n,
            created_time: ver.created_time.clone(),
            deletion_time: ver.deletion_time.clone(),
            destroyed: ver.destroyed,
        };
        self.record(AuditOp::Read, path, token, true);
        Ok((value, meta))
    }

    pub async fn read_metadata(
        &self,
        token: &str,
        path: &SecretPath,
    ) -> Result<VersionedSecret, TesseraError> {
        self.guard(token, path)?;
        match self.load(path).await? {
            Some(vs) if vs.current_version > 0 => {
                self.record(AuditOp::Read, path, token, true);
                Ok(vs)
            }
            _ => {
                self.record(AuditOp::Read, path, token, false);
                Err(TesseraError::NotFound)
            }
        }
    }

    pub async fn configure_metadata(
        &self,
        token: &str,
        path: &SecretPath,
        max_versions: Option<u32>,
        cas_required: Option<bool>,
    ) -> Result<(), TesseraError> {
        self.guard(token, path)?;
        let lock = self.path_lock(path);
        let _g = lock.lock().await;

        let mut vs = match self.load(path).await? {
            Some(vs) if vs.current_version > 0 => vs,
            _ => {
                self.record(AuditOp::ConfigMetadata, path, token, false);
                return Err(TesseraError::NotFound);
            }
        };
        if let Some(mv) = max_versions {
            vs.max_versions = mv.max(1);
        }
        if let Some(cr) = cas_required {
            vs.cas_required = cr;
        }
        vs.updated_time = self.clock.now_rfc3339();
        self.save(path, &vs).await?;
        self.record(AuditOp::ConfigMetadata, path, token, true);
        Ok(())
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

    fn val(v: &str) -> SecretValue {
        let mut m = SecretValue::default();
        m.0.insert("api_key".into(), v.into());
        m
    }

    #[tokio::test]
    async fn write_increments_versions_read_current_and_pinned() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        assert_eq!(s.write("galvo-tok", &p, val("v1"), None).await.unwrap(), 1);
        assert_eq!(s.write("galvo-tok", &p, val("v2"), None).await.unwrap(), 2);

        // current
        let (cur, meta) = s.read("galvo-tok", &p, None).await.unwrap();
        assert_eq!(cur.unwrap().0.get("api_key").unwrap(), "v2");
        assert_eq!(meta.version, 2);

        // pinned older
        let (old, m1) = s.read("galvo-tok", &p, Some(1)).await.unwrap();
        assert_eq!(old.unwrap().0.get("api_key").unwrap(), "v1");
        assert_eq!(m1.version, 1);
    }

    #[tokio::test]
    async fn read_missing_secret_is_not_found() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/nope");
        assert_eq!(
            s.read("galvo-tok", &p, None).await.unwrap_err(),
            TesseraError::NotFound
        );
    }

    #[tokio::test]
    async fn read_missing_version_is_not_found() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        s.write("galvo-tok", &p, val("v1"), None).await.unwrap();
        assert_eq!(
            s.read("galvo-tok", &p, Some(99)).await.unwrap_err(),
            TesseraError::NotFound
        );
    }

    #[tokio::test]
    async fn cas_correct_advances_stale_rejected() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        // cas=0 = create-only, succeeds on empty
        assert_eq!(
            s.write("galvo-tok", &p, val("v1"), Some(0)).await.unwrap(),
            1
        );
        // cas=1 matches current, advances
        assert_eq!(
            s.write("galvo-tok", &p, val("v2"), Some(1)).await.unwrap(),
            2
        );
        // stale cas=1 (current is 2) rejected, no new version
        assert_eq!(
            s.write("galvo-tok", &p, val("v3"), Some(1))
                .await
                .unwrap_err(),
            TesseraError::CasMismatch
        );
        // current still v2
        let (cur, meta) = s.read("galvo-tok", &p, None).await.unwrap();
        assert_eq!(cur.unwrap().0.get("api_key").unwrap(), "v2");
        assert_eq!(meta.version, 2);
    }

    #[tokio::test]
    async fn cas_zero_on_existing_is_mismatch() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        s.write("galvo-tok", &p, val("v1"), None).await.unwrap();
        assert_eq!(
            s.write("galvo-tok", &p, val("dup"), Some(0))
                .await
                .unwrap_err(),
            TesseraError::CasMismatch
        );
    }

    #[tokio::test]
    async fn cas_required_blocks_bare_write() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        s.write("galvo-tok", &p, val("v1"), None).await.unwrap();
        s.configure_metadata("galvo-tok", &p, None, Some(true))
            .await
            .unwrap();
        // bare write (no cas) now rejected
        assert_eq!(
            s.write("galvo-tok", &p, val("v2"), None).await.unwrap_err(),
            TesseraError::CasMismatch
        );
        // with correct cas it works
        assert_eq!(
            s.write("galvo-tok", &p, val("v2"), Some(1)).await.unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn max_versions_trims_oldest_data() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        s.write("galvo-tok", &p, val("v1"), None).await.unwrap();
        s.configure_metadata("galvo-tok", &p, Some(2), None)
            .await
            .unwrap();
        s.write("galvo-tok", &p, val("v2"), None).await.unwrap();
        s.write("galvo-tok", &p, val("v3"), None).await.unwrap(); // trims v1 data
                                                                  // v1 data dropped (reads as null), v2 + v3 retained
        let (v1, _) = s.read("galvo-tok", &p, Some(1)).await.unwrap();
        assert!(v1.is_none());
        let (v3, _) = s.read("galvo-tok", &p, None).await.unwrap();
        assert_eq!(v3.unwrap().0.get("api_key").unwrap(), "v3");
        let md = s.read_metadata("galvo-tok", &p).await.unwrap();
        assert_eq!(md.oldest_version, 2);
        assert_eq!(md.current_version, 3);
    }

    #[tokio::test]
    async fn read_metadata_reports_window_and_config() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        s.write("galvo-tok", &p, val("v1"), None).await.unwrap();
        s.write("galvo-tok", &p, val("v2"), None).await.unwrap();
        let md = s.read_metadata("galvo-tok", &p).await.unwrap();
        assert_eq!(md.current_version, 2);
        assert_eq!(md.oldest_version, 1);
        assert_eq!(md.max_versions, 10);
        assert!(!md.cas_required);
        assert_eq!(md.versions.len(), 2);
    }

    #[tokio::test]
    async fn configure_metadata_missing_secret_is_not_found() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/none");
        assert_eq!(
            s.configure_metadata("galvo-tok", &p, Some(5), None)
                .await
                .unwrap_err(),
            TesseraError::NotFound
        );
    }
}
