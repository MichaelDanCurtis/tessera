use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A mount + multi-segment path identifying one secret, e.g. `secret` / `galvo/openai`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretPath {
    pub mount: String,
    pub path: String,
}

impl SecretPath {
    pub fn new(mount: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            mount: mount.into(),
            path: path.into(),
        }
    }
    /// Canonical scope string used by policies + audit, e.g. `secret/galvo/openai`.
    pub fn scope(&self) -> String {
        format!("{}/{}", self.mount, self.path)
    }
}

/// The key/value material of a secret (sorted keys for deterministic output).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SecretValue(pub BTreeMap<String, String>);

/// Minimal V1 metadata (single-version semantics).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub current_version: u32,
    pub created_time: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TesseraError {
    #[error("secret not found")]
    NotFound,
    #[error("vault is sealed")]
    Sealed,
    #[error("forbidden: token not scoped for {0}")]
    Forbidden(String),
    #[error("invalid token")]
    InvalidToken,
    #[error("storage error: {0}")]
    Storage(String),
    #[error("check-and-set parameter did not match the current version")]
    CasMismatch,
}

/// One stored version of a secret. `data` is `None` once destroyed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    pub data: Option<SecretValue>,
    pub created_time: String,
    /// `Some` => soft-deleted (hidden, undeletable until undeleted).
    pub deletion_time: Option<String>,
    /// `true` => data permanently gone (tombstone remains).
    pub destroyed: bool,
}

/// The full versioned record for one path — the single blob the engine stores.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedSecret {
    pub current_version: u32,
    pub oldest_version: u32,
    pub max_versions: u32,
    pub cas_required: bool,
    pub created_time: String,
    pub updated_time: String,
    pub versions: BTreeMap<u32, Version>,
}

/// Default `max_versions`, matching Vault.
pub const DEFAULT_MAX_VERSIONS: u32 = 10;

impl VersionedSecret {
    /// A fresh record at version 0 (no versions yet) with default config.
    pub fn empty(now: String) -> Self {
        Self {
            current_version: 0,
            oldest_version: 0,
            max_versions: DEFAULT_MAX_VERSIONS,
            cas_required: false,
            created_time: now.clone(),
            updated_time: now,
            versions: BTreeMap::new(),
        }
    }
}

/// Per-read metadata projection returned alongside a read's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionMeta {
    pub version: u32,
    pub created_time: String,
    pub deletion_time: Option<String>,
    pub destroyed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_joins_mount_and_path() {
        let p = SecretPath::new("secret", "galvo/openai");
        assert_eq!(p.scope(), "secret/galvo/openai");
    }

    #[test]
    fn secret_value_serializes_sorted() {
        let mut m = SecretValue::default();
        m.0.insert("b".into(), "2".into());
        m.0.insert("a".into(), "1".into());
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, r#"{"a":"1","b":"2"}"#);
    }

    #[test]
    fn versioned_secret_roundtrips_json() {
        let mut vs = VersionedSecret::empty("2026-06-14T00:00:00Z".into());
        let mut data = SecretValue::default();
        data.0.insert("k".into(), "v".into());
        vs.current_version = 1;
        vs.oldest_version = 1;
        vs.versions.insert(
            1,
            Version {
                data: Some(data),
                created_time: "2026-06-14T00:00:00Z".into(),
                deletion_time: None,
                destroyed: false,
            },
        );
        let json = serde_json::to_vec(&vs).unwrap();
        let back: VersionedSecret = serde_json::from_slice(&json).unwrap();
        assert_eq!(back, vs);
        assert_eq!(
            back.versions
                .get(&1)
                .unwrap()
                .data
                .as_ref()
                .unwrap()
                .0
                .get("k")
                .unwrap(),
            "v"
        );
    }

    #[test]
    fn empty_uses_default_max_versions() {
        let vs = VersionedSecret::empty("t".into());
        assert_eq!(vs.max_versions, DEFAULT_MAX_VERSIONS);
        assert_eq!(vs.current_version, 0);
        assert!(vs.versions.is_empty());
    }
}
