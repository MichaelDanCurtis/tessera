//! `VaultStore` — the KV-v2 orchestration layer (replaces V1's `KvStore`). A single
//! concrete, non-generic type so axum has exactly one `AppState`. Every op:
//! require_unsealed → authorize → per-path atomic read-modify-write of the
//! `VersionedSecret` blob → audit. Time is injected via `Clock`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::audit::{token_hash, AuditOp, AuditRecord, AuditSink};
use crate::auth::{PolicyStore, TokenStore};
use crate::clock::Clock;
use crate::engine::SecretEngine;
use crate::seal::SealState;
use crate::types::{
    SecretPath, SecretValue, TesseraError, Version, VersionMeta, VersionedSecret,
    DEFAULT_MAX_VERSIONS,
};

pub struct VaultStore {
    engine: Arc<dyn SecretEngine>,
    seal: SealState,
    tokens: TokenStore,
    policies: Arc<PolicyStore>,
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
        policies: Arc<PolicyStore>,
        audit: Arc<dyn AuditSink>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            engine,
            seal,
            tokens,
            policies,
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

    pub fn policies(&self) -> &Arc<PolicyStore> {
        &self.policies
    }

    pub fn tokens(&self) -> &TokenStore {
        &self.tokens
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Seal + auth gate. On auth failure, records an `AuthFailure` audit entry and
    /// returns the error (fail-closed, before any engine touch).
    fn guard(&self, token: &str, path: &SecretPath) -> Result<(), TesseraError> {
        self.seal.require_unsealed()?;
        let now = self.clock.now_rfc3339();
        if let Err(e) = self.tokens.authorize_at(token, path, &self.policies, &now) {
            self.audit.append(AuditRecord {
                op: AuditOp::AuthFailure,
                scope: path.scope(),
                token_hash: token_hash(token),
                outcome: false,
                timestamp: self.clock.now_rfc3339(),
                reveal: false,
            });
            return Err(e);
        }
        Ok(())
    }

    fn record(&self, op: AuditOp, path: &SecretPath, token: &str, outcome: bool) {
        self.record_inner(op, path, token, outcome, false);
    }

    /// Like `record`, but flags the entry as a reveal (operator saw plaintext).
    fn record_reveal(&self, path: &SecretPath, token: &str, outcome: bool) {
        self.record_inner(AuditOp::Read, path, token, outcome, true);
    }

    fn record_inner(
        &self,
        op: AuditOp,
        path: &SecretPath,
        token: &str,
        outcome: bool,
        reveal: bool,
    ) {
        self.audit.append(AuditRecord {
            op,
            scope: path.scope(),
            token_hash: token_hash(token),
            outcome,
            timestamp: self.clock.now_rfc3339(),
            reveal,
        });
    }

    /// Gate a non-KV action through the same seal + token policy path used by
    /// secret operations. Authorization failures are audited as `AuthFailure`.
    pub fn authorize_scope(&self, token: &str, path: &SecretPath) -> Result<(), TesseraError> {
        self.guard(token, path)
    }

    /// Record a non-KV action after its route has passed `authorize_scope`.
    pub fn record_action(&self, op: AuditOp, path: &SecretPath, token: &str, outcome: bool) {
        self.record(op, path, token, outcome);
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
                let mut vs: VersionedSecret = serde_json::from_slice(&blob)
                    .map_err(|e| TesseraError::Storage(format!("decode VersionedSecret: {e}")))?;
                // Corrupt-blob defense: a persisted record with max_versions == 0
                // would make the write-trim window (`current - oldest + 1 > 0`)
                // always true and underflow `oldest_version` past `current_version`
                // (panic in debug / infinite loop in release). Clamp to the default.
                if vs.max_versions == 0 {
                    vs.max_versions = DEFAULT_MAX_VERSIONS;
                }
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

    /// Like `read`, but records the audit entry as a REVEAL (operator saw the
    /// plaintext via the console). Returns the same value/metadata as `read`.
    pub async fn read_reveal(
        &self,
        token: &str,
        path: &SecretPath,
        version: Option<u32>,
    ) -> Result<(Option<SecretValue>, VersionMeta), TesseraError> {
        self.guard(token, path)?;
        let vs = match self.load(path).await? {
            Some(vs) if vs.current_version > 0 => vs,
            _ => {
                self.record_reveal(path, token, false);
                return Err(TesseraError::NotFound);
            }
        };
        let n = version.unwrap_or(vs.current_version);
        let ver = match vs.versions.get(&n) {
            Some(v) => v,
            None => {
                self.record_reveal(path, token, false);
                return Err(TesseraError::NotFound);
            }
        };
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
        self.record_reveal(path, token, true);
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

    pub async fn soft_delete(
        &self,
        token: &str,
        path: &SecretPath,
        versions: &[u32],
    ) -> Result<(), TesseraError> {
        self.mutate_versions(token, path, AuditOp::Delete, versions, |v, now| {
            if !v.destroyed && v.deletion_time.is_none() {
                v.deletion_time = Some(now.to_string());
            }
        })
        .await
    }

    pub async fn undelete(
        &self,
        token: &str,
        path: &SecretPath,
        versions: &[u32],
    ) -> Result<(), TesseraError> {
        self.mutate_versions(token, path, AuditOp::Undelete, versions, |v, _now| {
            // No-op on destroyed versions (data is gone for good).
            if !v.destroyed {
                v.deletion_time = None;
            }
        })
        .await
    }

    pub async fn destroy(
        &self,
        token: &str,
        path: &SecretPath,
        versions: &[u32],
    ) -> Result<(), TesseraError> {
        self.mutate_versions(token, path, AuditOp::Destroy, versions, |v, _now| {
            v.destroyed = true;
            v.data = None;
        })
        .await
    }

    /// Shared RMW for the per-version mutators (soft-delete/undelete/destroy).
    /// Absent versions are skipped (no-op, not an error). Missing secret => NotFound.
    async fn mutate_versions(
        &self,
        token: &str,
        path: &SecretPath,
        op: AuditOp,
        versions: &[u32],
        mut f: impl FnMut(&mut Version, &str),
    ) -> Result<(), TesseraError> {
        self.guard(token, path)?;
        let lock = self.path_lock(path);
        let _g = lock.lock().await;
        let mut vs = match self.load(path).await? {
            Some(vs) if vs.current_version > 0 => vs,
            _ => {
                self.record(op, path, token, false);
                return Err(TesseraError::NotFound);
            }
        };
        let now = self.clock.now_rfc3339();
        for &n in versions {
            if let Some(v) = vs.versions.get_mut(&n) {
                f(v, &now);
            }
        }
        vs.updated_time = now;
        self.save(path, &vs).await?;
        self.record(op, path, token, true);
        Ok(())
    }

    pub async fn delete_metadata(
        &self,
        token: &str,
        path: &SecretPath,
    ) -> Result<(), TesseraError> {
        self.guard(token, path)?;
        let lock = self.path_lock(path);
        let _g = lock.lock().await;
        // Engine delete is idempotent; report NotFound only if nothing was there.
        let existed = self
            .load(path)
            .await?
            .map(|vs| vs.current_version > 0)
            .unwrap_or(false);
        self.engine.delete(path).await?;
        if !existed {
            self.record(AuditOp::Delete, path, token, false);
            return Err(TesseraError::NotFound);
        }
        self.record(AuditOp::Delete, path, token, true);
        Ok(())
    }

    pub async fn list(
        &self,
        token: &str,
        prefix: &SecretPath,
    ) -> Result<Vec<String>, TesseraError> {
        // A list prefix is a directory, e.g. `secret/galvo`. Authorize against its
        // directory form (`secret/galvo/`) so a policy scoped to `secret/galvo/`
        // permits listing that subtree without granting a bare `secret/galvo` leaf.
        let dir = SecretPath::new(
            prefix.mount.clone(),
            format!("{}/", prefix.path.trim_end_matches('/')),
        );
        self.guard(token, &dir)?;
        let res = self.engine.list(prefix).await;
        self.record(AuditOp::List, prefix, token, res.is_ok());
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::InMemoryAudit;
    use crate::auth::{Policy, PolicyStore};
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
            Arc::new(PolicyStore::in_memory()),
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

    /// Build a store over a shared engine handle so a test can pre-seed a
    /// corrupt on-disk blob before exercising the store.
    fn store_with_engine(engine: Arc<InMemoryEngine>) -> VaultStore {
        let mut tokens = TokenStore::new();
        tokens.insert("galvo-tok", Policy::new(["secret/galvo/"]));
        let seal = SealState::new(b"m".to_vec());
        seal.unseal(b"m").unwrap();
        VaultStore::new(
            engine,
            seal,
            tokens,
            Arc::new(PolicyStore::in_memory()),
            Arc::new(InMemoryAudit::new()),
            Arc::new(FixedClock("2026-06-14T00:00:00Z".into())),
        )
    }

    #[tokio::test]
    async fn corrupt_max_versions_zero_is_clamped_on_load_no_underflow() {
        // A corrupted on-disk record with max_versions == 0 would make the
        // write-trim loop `current - oldest + 1 > 0` always true and underflow
        // `oldest_version += 1` past `current_version` (panic in debug / infinite
        // loop). load() must clamp max_versions to >= 1 (DEFAULT) defensively.
        let engine = Arc::new(InMemoryEngine::new());
        let p = SecretPath::new("secret", "galvo/openai");

        // Craft a record at version 1 with the poisoned max_versions == 0.
        let mut vs = VersionedSecret::empty("2026-06-14T00:00:00Z".into());
        vs.max_versions = 0;
        vs.current_version = 1;
        vs.oldest_version = 1;
        vs.versions.insert(
            1,
            Version {
                data: Some(val("seed")),
                created_time: "2026-06-14T00:00:00Z".into(),
                deletion_time: None,
                destroyed: false,
            },
        );
        let blob = serde_json::to_vec(&vs).unwrap();
        engine.put(&p, blob).await.unwrap();

        // A write must succeed without panicking or hanging.
        let s = store_with_engine(Arc::clone(&engine));
        let new_v = s.write("galvo-tok", &p, val("next"), None).await.unwrap();
        assert_eq!(new_v, 2);

        // The clamp restored a sane window.
        let md = s.read_metadata("galvo-tok", &p).await.unwrap();
        assert!(md.max_versions >= 1);
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

    #[tokio::test]
    async fn soft_delete_hides_data_undelete_restores() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        s.write("galvo-tok", &p, val("v1"), None).await.unwrap();
        s.soft_delete("galvo-tok", &p, &[1]).await.unwrap();
        let (v, meta) = s.read("galvo-tok", &p, Some(1)).await.unwrap();
        assert!(v.is_none());
        assert!(meta.deletion_time.is_some());
        s.undelete("galvo-tok", &p, &[1]).await.unwrap();
        let (v, meta) = s.read("galvo-tok", &p, Some(1)).await.unwrap();
        assert_eq!(v.unwrap().0.get("api_key").unwrap(), "v1");
        assert!(meta.deletion_time.is_none());
    }

    #[tokio::test]
    async fn destroy_removes_data_permanently_and_blocks_undelete() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        s.write("galvo-tok", &p, val("v1"), None).await.unwrap();
        s.destroy("galvo-tok", &p, &[1]).await.unwrap();
        let (v, meta) = s.read("galvo-tok", &p, Some(1)).await.unwrap();
        assert!(v.is_none());
        assert!(meta.destroyed);
        // undelete on a destroyed version is a no-op: data stays gone
        s.undelete("galvo-tok", &p, &[1]).await.unwrap();
        let (v, meta) = s.read("galvo-tok", &p, Some(1)).await.unwrap();
        assert!(v.is_none());
        assert!(meta.destroyed);
    }

    #[tokio::test]
    async fn destroy_undelete_on_absent_version_is_noop() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        s.write("galvo-tok", &p, val("v1"), None).await.unwrap();
        // versions [42] don't exist; must not 500/error
        s.destroy("galvo-tok", &p, &[42]).await.unwrap();
        s.undelete("galvo-tok", &p, &[42]).await.unwrap();
        s.soft_delete("galvo-tok", &p, &[42]).await.unwrap();
        // v1 untouched
        let (v, _) = s.read("galvo-tok", &p, Some(1)).await.unwrap();
        assert_eq!(v.unwrap().0.get("api_key").unwrap(), "v1");
    }

    #[tokio::test]
    async fn delete_metadata_wipes_all_versions() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        s.write("galvo-tok", &p, val("v1"), None).await.unwrap();
        s.write("galvo-tok", &p, val("v2"), None).await.unwrap();
        s.delete_metadata("galvo-tok", &p).await.unwrap();
        assert_eq!(
            s.read("galvo-tok", &p, None).await.unwrap_err(),
            TesseraError::NotFound
        );
    }

    #[tokio::test]
    async fn list_returns_immediate_names() {
        let s = store();
        s.write(
            "galvo-tok",
            &SecretPath::new("secret", "galvo/openai"),
            val("1"),
            None,
        )
        .await
        .unwrap();
        s.write(
            "galvo-tok",
            &SecretPath::new("secret", "galvo/anthropic"),
            val("2"),
            None,
        )
        .await
        .unwrap();
        let keys = s
            .list("galvo-tok", &SecretPath::new("secret", "galvo"))
            .await
            .unwrap();
        assert_eq!(keys, vec!["anthropic".to_string(), "openai".to_string()]);
    }

    #[tokio::test]
    async fn read_reveal_marks_audit_entry() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        s.write("galvo-tok", &p, val("v1"), None).await.unwrap();
        let (v, _m) = s.read_reveal("galvo-tok", &p, None).await.unwrap();
        assert_eq!(v.unwrap().0.get("api_key").unwrap(), "v1");
        let last = s.audit_sink().records().into_iter().last().unwrap();
        assert_eq!(last.op, AuditOp::Read);
        assert!(last.reveal, "reveal read must flag the audit entry");
    }

    /// REGRESSION (Critical fail-open): an expired dynamic token must be denied
    /// on the REAL data-plane guard path (`write`/`read`), not just when calling
    /// `authorize_at` directly. Build the store's clock PAST the token's expiry
    /// and assert the op is rejected as `InvalidToken`.
    #[tokio::test]
    async fn expired_dynamic_token_denied_through_guard() {
        // Named policy the issued token references (issue() validates the name).
        let policies = Arc::new(PolicyStore::in_memory());
        policies
            .put("galvo", Policy::new(["secret/galvo/"]))
            .unwrap();

        // Issue a dynamic token at a base instant with a 60s TTL =>
        // expires ~ 2026-06-14T00:01:00Z.
        let tokens = TokenStore::new();
        let issued = tokens
            .issue(
                vec!["galvo".into()],
                Some(60),
                "2026-06-14T00:00:00Z",
                &policies,
            )
            .unwrap();

        // Build the store's clock at a LATER instant (token already expired).
        let seal = SealState::new(b"m".to_vec());
        seal.unseal(b"m").unwrap();
        let s = VaultStore::new(
            Arc::new(InMemoryEngine::new()),
            seal,
            tokens,
            policies,
            Arc::new(InMemoryAudit::new()),
            Arc::new(FixedClock("2026-06-14T01:00:00Z".into())),
        );

        let p = SecretPath::new("secret", "galvo/openai");
        // A write through the data-plane guard MUST be denied (expired token).
        assert_eq!(
            s.write(&issued.token, &p, val("nope"), None)
                .await
                .unwrap_err(),
            TesseraError::InvalidToken
        );
    }

    #[tokio::test]
    async fn new_ops_are_audited() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        s.write("galvo-tok", &p, val("v1"), None).await.unwrap();
        s.soft_delete("galvo-tok", &p, &[1]).await.unwrap();
        s.undelete("galvo-tok", &p, &[1]).await.unwrap();
        s.destroy("galvo-tok", &p, &[1]).await.unwrap();
        let ops: Vec<_> = s.audit_sink().records().iter().map(|r| r.op).collect();
        assert!(ops.contains(&AuditOp::Delete));
        assert!(ops.contains(&AuditOp::Undelete));
        assert!(ops.contains(&AuditOp::Destroy));
    }
}
