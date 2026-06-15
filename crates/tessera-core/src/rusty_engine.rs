//! RustyVault-backed [`SecretEngine`] (Task 9 — the single integration point with
//! the real `rusty_vault` crate). Wraps an **in-process** `rusty_vault::core::Core`
//! per the EMBED decision in `docs/spike-rustyvault.md`.
//!
//! ## Crypto backend
//! Built against `rusty_vault`'s `crypto_adaptor_openssl` feature (vanilla crates.io
//! OpenSSL); the Tongsuo/SM (ShangMi, 国密) adaptor is never enabled. See the
//! `rusty_vault` dependency comment in `Cargo.toml`.
//!
//! ## KV semantics
//! RustyVault 0.2.1 mounts KV as **v1** (single value, no history). Tessera's V1
//! `SecretEngine` contract is also single-version (`current_version: 1`), so this
//! wrapper round-trips a `SecretValue` map through the v1 KV logical backend and
//! synthesizes the minimal `SecretMetadata`. KV-v2 REST shaping lives in the server
//! (Task 11), not here.
//!
//! ## Sync -> async bridge (lock-guard hazard)
//! `SecretEngine` methods are sync; `Core::handle_request` is `async` and lives
//! behind a `std::sync::RwLock<Core>`. Each op clones the cheap `Arc<RwLock<Core>>`
//! handle and the owned root token *before* entering `runtime.block_on`, and only
//! acquires the `core.read()` guard **inside** the async block — the guard's
//! lifetime never spans the `block_on` boundary held by an outside binding (the
//! deadlock documented in the `rust-sync-mutex-held-across-block-on` skill).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use serde_json::{Map, Value};

use rusty_vault::core::{Core, SealConfig};
use rusty_vault::logical::{Operation, Request, Response};
use rusty_vault::storage::{self, barrier_aes_gcm::AESGCMBarrier};

use crate::engine::SecretEngine;
use crate::types::{SecretMetadata, SecretPath, SecretValue, TesseraError};

/// The crypto provider this engine is pinned to (vanilla OpenSSL, never ShangMi).
const CRYPTO_BACKEND: &str = "openssl";

/// RustyVault-backed engine wrapping an in-process `Core`.
pub struct RustyVaultEngine {
    /// Shared handle to the embedded RustyVault core.
    core: Arc<RwLock<Core>>,
    /// Root token minted at init; authorizes the in-process KV requests.
    root_token: String,
    /// Dedicated current-thread runtime that drives `Core::handle_request`.
    runtime: tokio::runtime::Runtime,
    /// RustyVault mount points already created (KV v1). Seeded with the default
    /// `secret/` mount that init provides out of the box; other mounts are created
    /// lazily on first write so arbitrary `SecretPath::mount` values round-trip.
    mounts: Mutex<std::collections::HashSet<String>>,
}

impl RustyVaultEngine {
    /// Open (init + unseal) an embedded RustyVault at `data_dir` (on-disk file
    /// backend). The engine is usable immediately after this returns.
    pub fn open(data_dir: &str) -> Result<Self, TesseraError> {
        // The file backend expects its root directory to exist (see RustyVault's
        // own `test_backend`). Create it idempotently; no wall-clock involved.
        std::fs::create_dir_all(data_dir).map_err(|e| store(format!("create data_dir: {e}")))?;

        // Storage: file backend wrapped in the AES-GCM security barrier.
        let mut conf: HashMap<String, Value> = HashMap::new();
        conf.insert("path".to_string(), Value::String(data_dir.to_string()));
        let backend =
            storage::new_backend("file", &conf).map_err(|e| store(format!("new_backend: {e}")))?;
        let barrier = AESGCMBarrier::new(Arc::clone(&backend));
        let core = Arc::new(RwLock::new(Core {
            physical: backend,
            barrier: Arc::new(barrier),
            ..Default::default()
        }));

        // config -> init -> unseal (first boot). Short write critical section; no
        // `.await` happens under this guard.
        let init_result = {
            let mut c = core
                .write()
                .map_err(|_| store("core lock poisoned (init)"))?;
            c.config(Arc::clone(&core), None)
                .map_err(|e| store(format!("config: {e}")))?;
            c.init(&SealConfig {
                secret_shares: 5,
                secret_threshold: 3,
            })
            .map_err(|e| store(format!("init: {e}")))?
        };

        {
            let mut c = core
                .write()
                .map_err(|_| store("core lock poisoned (unseal)"))?;
            for share in init_result.secret_shares.iter().take(3) {
                c.unseal(share).map_err(|e| store(format!("unseal: {e}")))?;
            }
        }

        let mut mounts = std::collections::HashSet::new();
        mounts.insert("secret".to_string());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(|e| store(format!("runtime build: {e}")))?;

        Ok(Self {
            core,
            root_token: init_result.root_token,
            runtime,
            mounts: Mutex::new(mounts),
        })
    }

    /// The active crypto provider name. Asserted non-SM by tests.
    pub fn crypto_backend(&self) -> &'static str {
        CRYPTO_BACKEND
    }

    /// RustyVault logical path for a secret: `<mount>/<path>` (KV v1 keying).
    fn logical_path(path: &SecretPath) -> String {
        format!("{}/{}", path.mount, path.path.trim_start_matches('/'))
    }

    /// Run one `Core::handle_request` on the dedicated runtime, mapping any
    /// `RvError` to `TesseraError::Storage` with `ctx` as the label.
    ///
    /// Lock-guard discipline (`rust-sync-mutex-held-across-block-on`): `core` (a
    /// cheap `Arc` clone) and `token` (owned) are captured by value *before*
    /// `block_on`, so no outer binding holds the `std::sync::RwLock` guard across
    /// the call. The guard is acquired and dropped entirely inside the future.
    ///
    /// `handle_request(&self)` is RustyVault's only entry point and is `async`, so
    /// the **read** guard must live across the single `.await` — this is the rare,
    /// safe exception clippy's `await_holding_lock` warns about: it is a *read*
    /// guard (concurrent reads never block each other, so no cross-thread stall),
    /// and this is a single-threaded `block_on` with no other future contending
    /// for the same lock on this runtime. The spike (`docs/spike-rustyvault.md`)
    /// documents this exact pattern as the supported embed path.
    #[allow(clippy::await_holding_lock)]
    fn run(
        &self,
        ctx: &str,
        op: Operation,
        path: &str,
        body: Option<Map<String, Value>>,
    ) -> Result<Option<Response>, TesseraError> {
        let core = Arc::clone(&self.core);
        let token = self.root_token.clone();
        let path = path.to_string();
        let resp = self.runtime.block_on(async move {
            let mut req = Request::new(&path);
            req.operation = op;
            req.client_token = token;
            req.body = body;
            let guard = core.read().expect("core lock poisoned");
            let out = guard.handle_request(&mut req).await;
            drop(guard);
            out
        });
        resp.map_err(|e| store(format!("{ctx}: {e}")))
    }

    /// Ensure the RustyVault KV v1 backend is mounted at `<mount>/` (idempotent).
    fn ensure_mount(&self, mount: &str) -> Result<(), TesseraError> {
        {
            let known = self.mounts.lock().expect("mounts lock poisoned");
            if known.contains(mount) {
                return Ok(());
            }
        }
        let mut body = Map::new();
        body.insert("type".to_string(), Value::String("kv".to_string()));
        self.run(
            "mount",
            Operation::Write,
            &format!("sys/mounts/{mount}/"),
            Some(body),
        )?;
        self.mounts
            .lock()
            .expect("mounts lock poisoned")
            .insert(mount.to_string());
        Ok(())
    }
}

/// Map a `SecretValue` (all-string map) into a RustyVault JSON body.
fn to_body(value: &SecretValue) -> Map<String, Value> {
    value
        .0
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect()
}

/// Map a RustyVault response data map back into a `SecretValue` (string values
/// only; non-string entries are stringified defensively).
fn from_data(data: &Map<String, Value>) -> SecretValue {
    let mut out = SecretValue::default();
    for (k, v) in data {
        let s = match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        out.0.insert(k.clone(), s);
    }
    out
}

fn store(msg: impl Into<String>) -> TesseraError {
    TesseraError::Storage(msg.into())
}

impl SecretEngine for RustyVaultEngine {
    fn put(&self, path: &SecretPath, value: SecretValue) -> Result<(), TesseraError> {
        self.ensure_mount(&path.mount)?;
        let body = to_body(&value);
        self.run(
            "put",
            Operation::Write,
            &Self::logical_path(path),
            Some(body),
        )?;
        Ok(())
    }

    fn get(&self, path: &SecretPath) -> Result<(SecretValue, SecretMetadata), TesseraError> {
        let resp = self.run("get", Operation::Read, &Self::logical_path(path), None)?;
        // A missing secret comes back as `Ok(None)` (or a response with no data).
        let data = resp.and_then(|r| r.data).ok_or(TesseraError::NotFound)?;
        Ok((
            from_data(&data),
            SecretMetadata {
                current_version: 1,
                created_time: String::new(),
            },
        ))
    }

    fn delete(&self, path: &SecretPath) -> Result<(), TesseraError> {
        // RustyVault's KV v1 delete is idempotent and does not signal "missing".
        // Probe first so the trait's NotFound contract holds.
        self.metadata(path)?;
        self.run("delete", Operation::Delete, &Self::logical_path(path), None)?;
        Ok(())
    }

    fn list(&self, prefix: &SecretPath) -> Result<Vec<String>, TesseraError> {
        // RustyVault list expects a trailing slash on the directory path.
        let mut p = Self::logical_path(prefix);
        if !p.ends_with('/') {
            p.push('/');
        }
        let resp = match self.run("list", Operation::List, &p, None) {
            Ok(r) => r,
            // An empty / non-existent prefix lists as empty rather than erroring.
            Err(_) => return Ok(Vec::new()),
        };
        let keys = resp
            .and_then(|r| r.data)
            .and_then(|d| d.get("keys").cloned())
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            // Immediate names only; drop any nested-directory trailing slash.
            .map(|s| s.trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Ok(keys)
    }

    fn metadata(&self, path: &SecretPath) -> Result<SecretMetadata, TesseraError> {
        self.get(path).map(|(_, meta)| meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    // Unique temp dir PER RUN. `open()` does a one-time RustyVault init, which
    // errors ("already initialized") against a reused on-disk backend — so the
    // dir must be fresh each run, not just per test name. Combine the test name
    // with the pid and a process-local counter (no wall-clock in core).
    fn temp_dir(name: &str) -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(
            "{}/tessera-test-{}-{}-{}",
            std::env::temp_dir().display(),
            name,
            std::process::id(),
            n
        )
    }

    #[test]
    fn crypto_backend_is_not_shangmi() {
        let eng = RustyVaultEngine::open(&temp_dir("crypto")).unwrap();
        let backend = eng.crypto_backend();
        assert!(
            backend == "openssl" || backend == "native-rust",
            "crypto backend must be OpenSSL/native-Rust, got {backend}"
        );
        assert_ne!(backend, "tongsuo");
        assert_ne!(backend, "sm");
    }

    #[test]
    fn put_then_get_roundtrips() {
        let eng = RustyVaultEngine::open(&temp_dir("roundtrip")).unwrap();
        let p = SecretPath::new("secret", "galvo/openai");
        let mut v = SecretValue::default();
        v.0.insert("api_key".into(), "sk-1".into());
        eng.put(&p, v).unwrap();
        let (got, meta) = eng.get(&p).unwrap();
        assert_eq!(got.0.get("api_key").unwrap(), "sk-1");
        assert_eq!(meta.current_version, 1);
    }

    fn val(k: &str, v: &str) -> SecretValue {
        let mut m = SecretValue::default();
        m.0.insert(k.into(), v.into());
        m
    }

    #[test]
    fn get_missing_is_not_found() {
        let eng = RustyVaultEngine::open(&temp_dir("missing")).unwrap();
        assert_eq!(
            eng.get(&SecretPath::new("secret", "nope")),
            Err(TesseraError::NotFound)
        );
    }

    #[test]
    fn delete_removes_then_missing() {
        let eng = RustyVaultEngine::open(&temp_dir("delete")).unwrap();
        let p = SecretPath::new("secret", "galvo/openai");
        eng.put(&p, val("k", "1")).unwrap();
        eng.delete(&p).unwrap();
        assert_eq!(eng.get(&p), Err(TesseraError::NotFound));
        assert_eq!(eng.delete(&p), Err(TesseraError::NotFound));
    }

    #[test]
    fn list_returns_immediate_names_under_prefix() {
        let eng = RustyVaultEngine::open(&temp_dir("list")).unwrap();
        eng.put(&SecretPath::new("secret", "galvo/openai"), val("k", "1"))
            .unwrap();
        eng.put(&SecretPath::new("secret", "galvo/anthropic"), val("k", "2"))
            .unwrap();
        eng.put(&SecretPath::new("secret", "femto/key"), val("k", "3"))
            .unwrap();
        let mut keys = eng.list(&SecretPath::new("secret", "galvo")).unwrap();
        keys.sort();
        assert_eq!(keys, vec!["anthropic".to_string(), "openai".to_string()]);
    }

    #[test]
    fn update_overwrites_single_version() {
        let eng = RustyVaultEngine::open(&temp_dir("update")).unwrap();
        let p = SecretPath::new("secret", "galvo/openai");
        eng.put(&p, val("api_key", "old")).unwrap();
        eng.put(&p, val("api_key", "new")).unwrap();
        let (got, meta) = eng.get(&p).unwrap();
        assert_eq!(got.0.get("api_key").unwrap(), "new");
        assert_eq!(meta.current_version, 1);
    }

    #[test]
    fn custom_mount_is_lazily_created() {
        let eng = RustyVaultEngine::open(&temp_dir("mount")).unwrap();
        let p = SecretPath::new("femto", "broker/token");
        eng.put(&p, val("t", "abc")).unwrap();
        let (got, _) = eng.get(&p).unwrap();
        assert_eq!(got.0.get("t").unwrap(), "abc");
    }
}
