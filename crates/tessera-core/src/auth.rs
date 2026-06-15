use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::audit::token_hash;
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

    /// In-memory store with no backing file (writes are no-ops). For tests
    /// and the static-token KV path where policies live inline on the token.
    pub fn in_memory() -> Self {
        Self {
            path: PathBuf::new(),
            policies: Mutex::new(HashMap::new()),
        }
    }

    fn flush(&self, map: &HashMap<String, Policy>) -> std::io::Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
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

/// Stored, persistent token record. The raw token value is NEVER stored — only
/// its blake3 hash. `accessor` is a separate, non-secret random id used for
/// listing + revocation. `expires` is an RFC-3339 instant or `None` (no TTL).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub accessor: String,
    pub token_hash: String,
    pub policies: Vec<String>,
    pub created: String,
    pub expires: Option<String>,
}

/// Non-secret metadata returned by `list_metadata` — deliberately has NO field
/// that could carry the raw token value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenMeta {
    pub accessor: String,
    pub policies: Vec<String>,
    pub created: String,
    pub expires: Option<String>,
}

/// What `issue` hands back ONCE: the raw token (shown one time) plus its
/// non-secret metadata.
#[derive(Debug, Clone)]
pub struct IssuedToken {
    pub token: String,
    pub accessor: String,
    pub policies: Vec<String>,
    pub created: String,
    pub expires: Option<String>,
}

/// Generate a random opaque id. `prefix` distinguishes tokens (`s.`) from
/// accessors (`a.`) for readability; both are 24 bytes of urlsafe base64.
fn random_id(prefix: &str) -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    use base64::Engine;
    format!(
        "{prefix}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Add seconds to an RFC-3339 `...Z` instant. Minimal: parses the fixed-width
/// `YYYY-MM-DDThh:mm:ssZ` form this codebase emits (see clock.rs::SystemClock).
fn add_seconds_rfc3339(base: &str, secs: i64) -> String {
    // Fall back to returning `base` unchanged if the shape is unexpected.
    let parse = |s: &str| -> Option<i64> {
        let b = s.as_bytes();
        if b.len() != 20 || b[19] != b'Z' {
            return None;
        }
        let n = |a: usize, z: usize| s[a..z].parse::<i64>().ok();
        let (y, mo, d) = (n(0, 4)?, n(5, 7)?, n(8, 10)?);
        let (h, mi, se) = (n(11, 13)?, n(14, 16)?, n(17, 19)?);
        // days since epoch (Howard Hinnant), inverse of clock.rs.
        let y2 = if mo <= 2 { y - 1 } else { y };
        let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
        let yoe = y2 - era * 400;
        let mp = if mo > 2 { mo - 3 } else { mo + 9 };
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        Some(days * 86_400 + h * 3600 + mi * 60 + se)
    };
    match parse(base) {
        Some(epoch) => crate::clock::SystemClock::format_epoch(epoch + secs),
        None => base.to_string(),
    }
}

/// Token store. Persists `TokenRecord`s (hash-only) to a JSON file. Supports
/// both the legacy static `insert(token, policy)` (in-memory, for tests + the
/// KV path) and dynamic `issue`/`revoke`/`list_metadata`.
pub struct TokenStore {
    path: Option<PathBuf>,
    /// accessor -> record (persistent, dynamic tokens).
    records: Mutex<HashMap<String, TokenRecord>>,
    /// Legacy in-memory token->policy map (static config tokens, not persisted).
    static_tokens: Mutex<HashMap<String, Policy>>,
}

impl Default for TokenStore {
    fn default() -> Self {
        Self {
            path: None,
            records: Mutex::new(HashMap::new()),
            static_tokens: Mutex::new(HashMap::new()),
        }
    }
}

impl TokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a persistent token store at `path`, loading existing records.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let records: HashMap<String, TokenRecord> = match read_to_string_opt(&path)? {
            Some(s) if !s.trim().is_empty() => serde_json::from_str(&s).unwrap_or_default(),
            _ => HashMap::new(),
        };
        Ok(Self {
            path: Some(path),
            records: Mutex::new(records),
            static_tokens: Mutex::new(HashMap::new()),
        })
    }

    /// Legacy: register a static token with an inline policy (config/tests).
    pub fn insert(&mut self, token: impl Into<String>, policy: Policy) {
        self.static_tokens
            .lock()
            .unwrap()
            .insert(token.into(), policy);
    }

    fn flush(&self, map: &HashMap<String, TokenRecord>) {
        if let Some(path) = &self.path {
            let json = serde_json::to_string(map).expect("tokens serialize");
            if let Err(e) = write_atomic(path, &json) {
                eprintln!("tessera: token persist failed: {e}");
            }
        }
    }

    /// Issue a new dynamic token. Returns the raw value ONCE + a non-secret
    /// accessor. `ttl_secs` of `None` => no expiry; otherwise `created + ttl`.
    pub fn issue(
        &self,
        policies: Vec<String>,
        ttl_secs: Option<i64>,
        created: &str,
        policy_store: &PolicyStore,
    ) -> Result<IssuedToken, TesseraError> {
        // Reject unknown policy names (fail-closed).
        for name in &policies {
            if policy_store.get(name).is_none() {
                return Err(TesseraError::Forbidden(format!("unknown policy: {name}")));
            }
        }
        let token = random_id("s.");
        let accessor = random_id("a.");
        let expires = ttl_secs.map(|t| add_seconds_rfc3339(created, t));
        let rec = TokenRecord {
            accessor: accessor.clone(),
            token_hash: token_hash(&token),
            policies: policies.clone(),
            created: created.to_string(),
            expires: expires.clone(),
        };
        let mut map = self.records.lock().unwrap();
        map.insert(accessor.clone(), rec);
        self.flush(&map);
        Ok(IssuedToken {
            token,
            accessor,
            policies,
            created: created.to_string(),
            expires,
        })
    }

    /// List non-secret metadata for every live dynamic token. NEVER the value.
    pub fn list_metadata(&self) -> Vec<TokenMeta> {
        self.records
            .lock()
            .unwrap()
            .values()
            .map(|r| TokenMeta {
                accessor: r.accessor.clone(),
                policies: r.policies.clone(),
                created: r.created.clone(),
                expires: r.expires.clone(),
            })
            .collect()
    }

    /// Revoke a token by accessor.
    pub fn revoke(&self, accessor: &str) -> Result<(), TesseraError> {
        let mut map = self.records.lock().unwrap();
        if map.remove(accessor).is_none() {
            return Err(TesseraError::InvalidToken);
        }
        self.flush(&map);
        Ok(())
    }

    /// Authorize `token` for `path`, resolving its policies. Checks static
    /// tokens first, then dynamic records (by hash). Fail-closed.
    pub fn authorize(
        &self,
        token: &str,
        path: &SecretPath,
        policy_store: &PolicyStore,
    ) -> Result<(), TesseraError> {
        self.authorize_at(token, path, policy_store, "")
    }

    /// Authorize as of instant `now` (RFC-3339; empty = skip expiry check, used
    /// by the legacy static-token path). Expired dynamic tokens => InvalidToken.
    pub fn authorize_at(
        &self,
        token: &str,
        path: &SecretPath,
        policy_store: &PolicyStore,
        now: &str,
    ) -> Result<(), TesseraError> {
        // 1) legacy static tokens with inline policy.
        if let Some(policy) = self.static_tokens.lock().unwrap().get(token) {
            return if policy.allows(path) {
                Ok(())
            } else {
                Err(TesseraError::Forbidden(path.scope()))
            };
        }
        // 2) dynamic records by hash.
        let hash = token_hash(token);
        let rec = {
            let map = self.records.lock().unwrap();
            map.values().find(|r| r.token_hash == hash).cloned()
        };
        let rec = rec.ok_or(TesseraError::InvalidToken)?;
        if let (false, Some(exp)) = (now.is_empty(), rec.expires.as_ref()) {
            if now >= exp.as_str() {
                return Err(TesseraError::InvalidToken);
            }
        }
        // Union of allow-prefixes across the token's policies.
        let allowed = rec.policies.iter().any(|name| {
            policy_store
                .get(name)
                .map(|p| p.allows(path))
                .unwrap_or(false)
        });
        if allowed {
            Ok(())
        } else {
            Err(TesseraError::Forbidden(path.scope()))
        }
    }

    /// Does `token` grant admin (any policy allowing the `sys/` scope)?
    pub fn is_admin(&self, token: &str, policy_store: &PolicyStore) -> bool {
        let admin_path = SecretPath::new("sys", "");
        // static admin tokens: an inline policy allowing "sys/".
        if let Some(policy) = self.static_tokens.lock().unwrap().get(token) {
            return policy.allow_prefixes.iter().any(|p| p.starts_with("sys"));
        }
        let hash = token_hash(token);
        let map = self.records.lock().unwrap();
        map.values()
            .find(|r| r.token_hash == hash)
            .map(|r| {
                r.policies.iter().any(|name| {
                    policy_store
                        .get(name)
                        .map(|p| {
                            p.allows(&admin_path)
                                || p.allow_prefixes.iter().any(|x| x.starts_with("sys"))
                        })
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
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

    fn empty_policy_store() -> PolicyStore {
        PolicyStore::in_memory()
    }

    #[test]
    fn in_scope_path_authorized() {
        store()
            .authorize(
                "galvo-tok",
                &SecretPath::new("secret", "galvo/openai"),
                &empty_policy_store(),
            )
            .unwrap();
    }

    #[test]
    fn out_of_scope_path_forbidden() {
        let err = store()
            .authorize(
                "galvo-tok",
                &SecretPath::new("secret", "femto/key"),
                &empty_policy_store(),
            )
            .unwrap_err();
        assert_eq!(err, TesseraError::Forbidden("secret/femto/key".into()));
    }

    #[test]
    fn unknown_token_invalid() {
        assert_eq!(
            store().authorize(
                "nope",
                &SecretPath::new("secret", "galvo/openai"),
                &empty_policy_store()
            ),
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
            .authorize(
                "empty-tok",
                &SecretPath::new("secret", "galvo/openai"),
                &empty_policy_store(),
            )
            .unwrap_err();
        assert!(matches!(err, TesseraError::Forbidden(_)));
    }

    #[test]
    fn token_issue_show_once_list_metadata_revoke() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("tokens.json");
        let policies = PolicyStore::open(dir.path().join("p.json")).unwrap();
        policies
            .put("galvo", Policy::new(["secret/galvo/"]))
            .unwrap();

        let issued;
        {
            let store = TokenStore::open(&path).unwrap();
            // issue returns the RAW token exactly once + a non-secret accessor
            let out = store
                .issue(
                    vec!["galvo".into()],
                    None,
                    "2026-06-14T00:00:00Z",
                    &policies,
                )
                .unwrap();
            assert!(!out.token.is_empty());
            assert!(!out.accessor.is_empty());
            assert_ne!(out.token, out.accessor, "accessor is NOT the token");
            issued = out;

            // list returns metadata by accessor — NEVER the raw token
            let metas = store.list_metadata();
            assert_eq!(metas.len(), 1);
            assert_eq!(metas[0].accessor, issued.accessor);
            assert_eq!(metas[0].policies, vec!["galvo".to_string()]);
            // the raw token value must not be reachable from metadata at all
            // (TokenMeta has no `token` field — this is a type-level guarantee).

            // the freshly-issued token authorizes against an in-scope path
            store
                .authorize(
                    &issued.token,
                    &SecretPath::new("secret", "galvo/openai"),
                    &policies,
                )
                .unwrap();

            // revoke by accessor -> subsequent authorize fails InvalidToken
            store.revoke(&issued.accessor).unwrap();
            assert_eq!(
                store.authorize(
                    &issued.token,
                    &SecretPath::new("secret", "galvo/openai"),
                    &policies
                ),
                Err(TesseraError::InvalidToken)
            );
        }
        // reopen: revoked token stays revoked (persisted)
        let store = TokenStore::open(&path).unwrap();
        assert_eq!(
            store.authorize(
                &issued.token,
                &SecretPath::new("secret", "galvo/openai"),
                &policies
            ),
            Err(TesseraError::InvalidToken)
        );
    }

    #[test]
    fn expired_token_is_invalid() {
        let dir = tempfile::TempDir::new().unwrap();
        let policies = PolicyStore::open(dir.path().join("p.json")).unwrap();
        policies
            .put("galvo", Policy::new(["secret/galvo/"]))
            .unwrap();
        let store = TokenStore::open(dir.path().join("t.json")).unwrap();
        // ttl of 0 seconds from a fixed created instant => already expired
        let out = store
            .issue(
                vec!["galvo".into()],
                Some(0),
                "2026-06-14T00:00:00Z",
                &policies,
            )
            .unwrap();
        // authorize "now" at a LATER instant rejects the expired token.
        assert_eq!(
            store.authorize_at(
                &out.token,
                &SecretPath::new("secret", "galvo/openai"),
                &policies,
                "2026-06-14T00:00:01Z"
            ),
            Err(TesseraError::InvalidToken)
        );
    }
}
