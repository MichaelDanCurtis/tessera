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
}
