//! RustyVault-backed [`SecretEngine`] — the single integration point with the real
//! `rusty_vault` crate. Wraps an **in-process** `rusty_vault::core::Core` per the
//! EMBED decision in `docs/spike-rustyvault.md`.
//!
//! ## Crypto backend
//! Built against `rusty_vault`'s `crypto_adaptor_openssl` feature (vanilla crates.io
//! OpenSSL); the Tongsuo/SM (ShangMi, 国密) adaptor is never enabled.
//!
//! ## Blob storage
//! V1.1's `SecretEngine` is an opaque blob store: each path holds one `Vec<u8>`.
//! RustyVault's KV-v1 record is a JSON object, so the blob is base64-encoded into a
//! single `"blob"` field. All KV-v2 versioning lives ABOVE this, in `VaultStore`.
//!
//! ## Async over a non-`Send`, `std::sync`-bound `Core` (DEVIATION FROM PLAN)
//! The plan specified `Arc<tokio::sync::RwLock<Core>>` with `handle_request` awaited
//! directly inside the `#[async_trait]` methods. That does NOT compile against
//! `rusty_vault` 0.2.1 for two API-level reasons (see the Phase-1 report):
//!   1. `Core::config(&mut self, core: Arc<std::sync::RwLock<Core>>, …)` stores
//!      `self_ref: Option<Arc<std::sync::RwLock<Core>>>`, so `Core` is structurally
//!      bound to **`std::sync::RwLock<Core>`** — a `tokio::sync::RwLock<Core>` is a
//!      distinct type and is rejected (E0308).
//!   2. `Core::handle_request(&self)` binds a `std::sync::RwLockReadGuard`
//!      (`self.handlers.read()?`, non-`Send`) and holds it across its internal
//!      `.await`s, so the returned future is **`!Send`**. `#[async_trait]` boxes
//!      futures as `Pin<Box<dyn Future + Send>>`, so the future cannot be awaited
//!      from inside an `#[async_trait]` method (E0277).
//!
//! Resolution that keeps the LOCKED async `SecretEngine` trait intact: the embedded
//! `Core` lives behind `std::sync::RwLock` on a **dedicated single-thread Tokio
//! runtime pinned to its own OS thread**. Each async-trait method ships an
//! `EngineJob` over an mpsc channel to that thread, which drives the `!Send`
//! `handle_request` future to completion on its current-thread runtime and returns
//! the (`Send`) result via a oneshot. The async-trait methods just `.await` the
//! oneshot — Send-clean at the boundary, no `block_on` called from within an outer
//! runtime (that would panic), and `Core` stays in the `std::sync::RwLock` its own
//! API demands. Concurrency is serialized through the worker thread (acceptable for
//! V1.1; the per-path RMW lock in `VaultStore` already serializes writes).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::{mpsc, oneshot};

use rusty_vault::core::{Core, SealConfig};
use rusty_vault::logical::{Operation, Request, Response};
use rusty_vault::storage::{self, barrier_aes_gcm::AESGCMBarrier};

use crate::engine::SecretEngine;
use crate::types::{SecretPath, TesseraError};

/// The crypto provider this engine is pinned to (vanilla OpenSSL, never ShangMi).
const CRYPTO_BACKEND: &str = "openssl";

/// One request dispatched to the dedicated `Core` worker thread.
struct EngineJob {
    ctx: &'static str,
    op: Operation,
    path: String,
    body: Option<Map<String, Value>>,
    reply: oneshot::Sender<Result<Option<Response>, TesseraError>>,
}

/// RustyVault-backed engine. The embedded `Core` is owned by a dedicated OS thread
/// running a current-thread Tokio runtime; all requests are funnelled to it over
/// `tx`. See the module docs for why this indirection is required by the 0.2.1 API.
pub struct RustyVaultEngine {
    /// Channel to the dedicated `Core` worker thread.
    tx: mpsc::UnboundedSender<EngineJob>,
    /// KV-v1 mount points already created. Seeded with the default `secret/` mount;
    /// other mounts are created lazily on first write.
    mounts: Mutex<std::collections::HashSet<String>>,
}

impl RustyVaultEngine {
    /// Open an embedded RustyVault at `data_dir` (on-disk file backend) using
    /// `master_key`. (Phase-1 form: init + unseal each open. Phase 3 replaces this
    /// body with init-if-empty-else-unseal + an encrypted seal sidecar so secrets
    /// survive restart; the `_master_key` arg is wired now so the signature is final.)
    pub async fn open(data_dir: &str, master_key: &[u8]) -> Result<Self, TesseraError> {
        let data_dir = data_dir.to_string();
        let master_key = master_key.to_vec();
        // Build Core + init/unseal + spawn the worker thread on a dedicated OS thread
        // so the (non-Send) RustyVault setup never touches this async frame.
        let (ready_tx, ready_rx) = oneshot::channel::<Result<String, TesseraError>>();
        let (tx, mut rx) = mpsc::unbounded_channel::<EngineJob>();

        std::thread::Builder::new()
            .name("tessera-rustyvault".to_string())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread().build() {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(store(format!("runtime build: {e}"))));
                        return;
                    }
                };
                rt.block_on(async move {
                    let core = match build_core(&data_dir, &master_key) {
                        Ok((core, root_token)) => {
                            let _ = ready_tx.send(Ok(root_token.clone()));
                            (core, root_token)
                        }
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                            return;
                        }
                    };
                    let (core, root_token) = core;
                    while let Some(job) = rx.recv().await {
                        let mapped = handle_job(&core, &root_token, job.op, &job.path, job.body)
                            .await
                            .map_err(|e| store(format!("{}: {e}", job.ctx)));
                        let _ = job.reply.send(mapped);
                    }
                });
            })
            .map_err(|e| store(format!("spawn worker: {e}")))?;

        let root_token = ready_rx
            .await
            .map_err(|_| store("worker thread died during open"))??;
        // root_token is retained on the worker thread; we only needed open to succeed.
        let _ = root_token;

        let mut mounts = std::collections::HashSet::new();
        mounts.insert("secret".to_string());

        Ok(Self {
            tx,
            mounts: Mutex::new(mounts),
        })
    }

    /// The active crypto provider name. Asserted non-SM by tests.
    pub fn crypto_backend(&self) -> &'static str {
        CRYPTO_BACKEND
    }

    /// RustyVault logical path for a secret: `<mount>/<path>` (KV-v1 keying).
    fn logical_path(path: &SecretPath) -> String {
        format!("{}/{}", path.mount, path.path.trim_start_matches('/'))
    }

    /// Dispatch one `Core::handle_request` to the worker thread and await its reply.
    async fn run(
        &self,
        ctx: &'static str,
        op: Operation,
        path: &str,
        body: Option<Map<String, Value>>,
    ) -> Result<Option<Response>, TesseraError> {
        let (reply, reply_rx) = oneshot::channel();
        self.tx
            .send(EngineJob {
                ctx,
                op,
                path: path.to_string(),
                body,
                reply,
            })
            .map_err(|_| store("engine worker thread is gone"))?;
        reply_rx
            .await
            .map_err(|_| store("engine worker dropped the reply"))?
    }

    /// Ensure the RustyVault KV-v1 backend is mounted at `<mount>/` (idempotent).
    async fn ensure_mount(&self, mount: &str) -> Result<(), TesseraError> {
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
        )
        .await?;
        self.mounts
            .lock()
            .expect("mounts lock poisoned")
            .insert(mount.to_string());
        Ok(())
    }
}

/// Drive one `Core::handle_request` on the worker thread. The `std::sync` read
/// guard is held across the single `.await`, but the worker runs a dedicated
/// current-thread runtime with no other future contending for this lock, so there
/// is no cross-thread stall — the same safe exception V1 documented. (RustyVault's
/// `handle_request` future is itself `!Send` because it holds a `std::sync`
/// `RwLockReadGuard` over `self.handlers` across its internal awaits; keeping it on
/// this single-thread runtime is what makes the async `SecretEngine` trait
/// implementable at all — see the module docs.)
#[allow(clippy::await_holding_lock)]
async fn handle_job(
    core: &Arc<RwLock<Core>>,
    root_token: &str,
    op: Operation,
    path: &str,
    body: Option<Map<String, Value>>,
) -> Result<Option<Response>, rusty_vault::errors::RvError> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = root_token.to_string();
    req.body = body;
    let guard = core.read().expect("core lock poisoned");
    guard.handle_request(&mut req).await
}

/// Construct + config an embedded `Core`, then **init-if-empty, else unseal**,
/// returning it (in its `std::sync::RwLock`) plus the root token. Runs on the
/// worker thread, so all seal-file I/O and crypto here are synchronous.
///
/// First boot: `init`, capture the unseal shares + root token, and write an
/// AES-256-GCM-encrypted seal sidecar (`<data_dir>/tessera-seal.json.enc`, 0600).
/// Every later boot: read + decrypt that sidecar and replay the stored Shamir
/// shares to `unseal` the existing on-disk barrier (no re-`init`), reusing the
/// stored root token — so secrets persist across restart.
fn build_core(
    data_dir: &str,
    master_key: &[u8],
) -> Result<(Arc<RwLock<Core>>, String), TesseraError> {
    std::fs::create_dir_all(data_dir).map_err(|e| store(format!("create data_dir: {e}")))?;
    let seal_path = format!("{data_dir}/tessera-seal.json.enc");

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

    // config registers logical backends; required on both the init and unseal paths.
    {
        let mut c = core.write().expect("core lock poisoned (config)");
        c.config(Arc::clone(&core), None)
            .map_err(|e| store(format!("config: {e}")))?;
    }

    let root_token = if std::path::Path::new(&seal_path).exists() {
        // --- RESTART: decrypt sidecar, unseal the existing barrier with stored shares ---
        let enc = std::fs::read(&seal_path).map_err(|e| store(format!("read seal: {e}")))?;
        let plain = seal_decrypt(master_key, &enc)?;
        let material: SealMaterial = serde_json::from_slice(&plain)
            .map_err(|e| store(format!("decode seal material: {e}")))?;
        {
            let mut c = core.write().expect("core lock poisoned (unseal)");
            for share in &material.shares {
                let bytes =
                    Base64::decode_vec(share).map_err(|e| store(format!("decode share: {e}")))?;
                c.unseal(&bytes)
                    .map_err(|e| store(format!("unseal: {e}")))?;
            }
        }
        material.root_token
    } else {
        // --- FIRST BOOT: init, persist encrypted seal material, unseal ---
        let init_result = {
            let mut c = core.write().expect("core lock poisoned (init)");
            c.init(&SealConfig {
                secret_shares: 5,
                secret_threshold: 3,
            })
            .map_err(|e| store(format!("init: {e}")))?
        };
        // Persist only the shares needed to meet threshold (3 of 5).
        let shares: Vec<String> = init_result
            .secret_shares
            .iter()
            .take(3)
            .map(|s| Base64::encode_string(s))
            .collect();
        let material = SealMaterial {
            root_token: init_result.root_token.clone(),
            shares: shares.clone(),
        };
        let plain = serde_json::to_vec(&material)
            .map_err(|e| store(format!("encode seal material: {e}")))?;
        let enc = seal_encrypt(master_key, &plain)?;
        write_seal_file(&seal_path, &enc)?;

        {
            let mut c = core.write().expect("core lock poisoned (unseal)");
            for share in &shares {
                let bytes =
                    Base64::decode_vec(share).map_err(|e| store(format!("decode share: {e}")))?;
                c.unseal(&bytes)
                    .map_err(|e| store(format!("unseal: {e}")))?;
            }
        }
        init_result.root_token
    };

    Ok((core, root_token))
}

fn store(msg: impl Into<String>) -> TesseraError {
    TesseraError::Storage(msg.into())
}

/// The unseal material persisted (encrypted) in the seal sidecar.
#[derive(Serialize, Deserialize)]
struct SealMaterial {
    root_token: String,
    /// Base64-encoded unseal shares (threshold count).
    shares: Vec<String>,
}

/// Write the seal sidecar with `0600` perms (owner read/write only).
fn write_seal_file(path: &str, bytes: &[u8]) -> Result<(), TesseraError> {
    std::fs::write(path, bytes).map_err(|e| store(format!("write seal: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| store(format!("chmod seal: {e}")))?;
    }
    Ok(())
}

/// Encrypt the seal material with AES-256-GCM. The key is SHA-256(master_key); a
/// random 12-byte nonce is generated and **prepended** to the ciphertext.
/// Output layout: `nonce(12) || ciphertext+tag`.
fn seal_encrypt(master_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, TesseraError> {
    use aes_gcm::aead::{Aead, KeyInit, OsRng};
    use aes_gcm::{AeadCore, Aes256Gcm, Key};
    use sha2::{Digest, Sha256};

    let key_bytes = Sha256::digest(master_key);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| store(format!("seal encrypt: {e}")))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`seal_encrypt`]. Splits the prepended 12-byte nonce, then decrypts.
fn seal_decrypt(master_key: &[u8], blob: &[u8]) -> Result<Vec<u8>, TesseraError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
    use sha2::{Digest, Sha256};

    if blob.len() < 12 {
        return Err(store("seal blob too short"));
    }
    let (nonce_bytes, ct) = blob.split_at(12);
    let key_bytes = Sha256::digest(master_key);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    // `Nonce` is parameterized by the cipher's NonceSize (a typenum), not the
    // cipher type itself; use the AeadCore associated NonceSize for the 12-byte GCM nonce.
    let nonce = Nonce::<<Aes256Gcm as AeadCore>::NonceSize>::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| store(format!("seal decrypt: {e}")))
}

#[async_trait::async_trait]
impl SecretEngine for RustyVaultEngine {
    async fn get(&self, path: &SecretPath) -> Result<Option<Vec<u8>>, TesseraError> {
        let resp = self
            .run("get", Operation::Read, &Self::logical_path(path), None)
            .await?;
        let data = match resp.and_then(|r| r.data) {
            Some(d) => d,
            None => return Ok(None),
        };
        let b64 = match data.get("blob").and_then(Value::as_str) {
            Some(s) => s,
            None => return Ok(None),
        };
        let bytes = Base64::decode_vec(b64).map_err(|e| store(format!("blob decode: {e}")))?;
        Ok(Some(bytes))
    }

    async fn put(&self, path: &SecretPath, blob: Vec<u8>) -> Result<(), TesseraError> {
        self.ensure_mount(&path.mount).await?;
        let mut body = Map::new();
        body.insert(
            "blob".to_string(),
            Value::String(Base64::encode_string(&blob)),
        );
        self.run(
            "put",
            Operation::Write,
            &Self::logical_path(path),
            Some(body),
        )
        .await?;
        Ok(())
    }

    async fn delete(&self, path: &SecretPath) -> Result<(), TesseraError> {
        // KV-v1 delete is idempotent; "missing-ness" is the store layer's concern.
        self.run("delete", Operation::Delete, &Self::logical_path(path), None)
            .await?;
        Ok(())
    }

    async fn list(&self, prefix: &SecretPath) -> Result<Vec<String>, TesseraError> {
        let mut p = Self::logical_path(prefix);
        if !p.ends_with('/') {
            p.push('/');
        }
        let resp = match self.run("list", Operation::List, &p, None).await {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };
        let mut keys: Vec<String> = resp
            .and_then(|r| r.data)
            .and_then(|d| d.get("keys").cloned())
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .map(|s| s.trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        keys.sort();
        keys.dedup();
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    // Unique temp dir PER RUN. `open()` does a one-time RustyVault init, which
    // errors against a reused on-disk backend — so the dir must be fresh each run.
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

    const MK: &[u8] = b"test-master-key-0123456789";

    #[tokio::test]
    async fn crypto_backend_is_not_shangmi() {
        let eng = RustyVaultEngine::open(&temp_dir("crypto"), MK)
            .await
            .unwrap();
        let backend = eng.crypto_backend();
        assert!(
            backend == "openssl" || backend == "native-rust",
            "crypto backend must be OpenSSL/native-Rust, got {backend}"
        );
        assert_ne!(backend, "tongsuo");
        assert_ne!(backend, "sm");
    }

    #[tokio::test]
    async fn put_then_get_roundtrips_blob() {
        let eng = RustyVaultEngine::open(&temp_dir("roundtrip"), MK)
            .await
            .unwrap();
        let p = SecretPath::new("secret", "galvo/openai");
        eng.put(&p, b"opaque-bytes-\x00\x01\xff".to_vec())
            .await
            .unwrap();
        let got = eng.get(&p).await.unwrap();
        assert_eq!(got, Some(b"opaque-bytes-\x00\x01\xff".to_vec()));
    }

    #[tokio::test]
    async fn get_missing_is_none() {
        let eng = RustyVaultEngine::open(&temp_dir("missing"), MK)
            .await
            .unwrap();
        assert_eq!(
            eng.get(&SecretPath::new("secret", "nope")).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn delete_removes_then_none() {
        let eng = RustyVaultEngine::open(&temp_dir("delete"), MK)
            .await
            .unwrap();
        let p = SecretPath::new("secret", "galvo/openai");
        eng.put(&p, b"x".to_vec()).await.unwrap();
        eng.delete(&p).await.unwrap();
        assert_eq!(eng.get(&p).await.unwrap(), None);
        // idempotent delete
        eng.delete(&p).await.unwrap();
    }

    #[tokio::test]
    async fn list_returns_immediate_names_under_prefix() {
        let eng = RustyVaultEngine::open(&temp_dir("list"), MK).await.unwrap();
        eng.put(&SecretPath::new("secret", "galvo/openai"), b"1".to_vec())
            .await
            .unwrap();
        eng.put(&SecretPath::new("secret", "galvo/anthropic"), b"2".to_vec())
            .await
            .unwrap();
        eng.put(&SecretPath::new("secret", "femto/key"), b"3".to_vec())
            .await
            .unwrap();
        let mut keys = eng.list(&SecretPath::new("secret", "galvo")).await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["anthropic".to_string(), "openai".to_string()]);
    }

    #[tokio::test]
    async fn custom_mount_is_lazily_created() {
        let eng = RustyVaultEngine::open(&temp_dir("mount"), MK)
            .await
            .unwrap();
        let p = SecretPath::new("femto", "broker/token");
        eng.put(&p, b"abc".to_vec()).await.unwrap();
        assert_eq!(eng.get(&p).await.unwrap(), Some(b"abc".to_vec()));
    }

    #[tokio::test]
    async fn secrets_survive_reopen_same_dir_and_key() {
        let dir = temp_dir("restart");
        let p = SecretPath::new("secret", "galvo/openai");
        {
            let eng = RustyVaultEngine::open(&dir, MK).await.unwrap();
            eng.put(&p, b"persist-me".to_vec()).await.unwrap();
        } // engine dropped — simulates process exit
          // Re-open the SAME dir with the SAME master key: unseal path, not re-init.
        let eng2 = RustyVaultEngine::open(&dir, MK).await.unwrap();
        assert_eq!(eng2.get(&p).await.unwrap(), Some(b"persist-me".to_vec()));
    }

    #[tokio::test]
    async fn reopen_with_wrong_key_fails() {
        let dir = temp_dir("wrongkey");
        {
            let _eng = RustyVaultEngine::open(&dir, MK).await.unwrap();
        }
        assert!(RustyVaultEngine::open(&dir, b"a-different-master-key")
            .await
            .is_err());
    }
}

#[cfg(test)]
mod seal_tests {
    use super::{seal_decrypt, seal_encrypt};

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let mk = b"master-key-abc";
        let plaintext = br#"{"root_token":"tok","shares":["a","b"]}"#;
        let blob = seal_encrypt(mk, plaintext).unwrap();
        // nonce(12) is prepended, so the ciphertext is longer than plaintext.
        assert!(blob.len() > plaintext.len());
        let back = seal_decrypt(mk, &blob).unwrap();
        assert_eq!(back, plaintext);
    }

    #[test]
    fn wrong_master_key_fails_to_decrypt() {
        let blob = seal_encrypt(b"right-key", b"secret-material").unwrap();
        assert!(seal_decrypt(b"wrong-key", &blob).is_err());
    }
}
