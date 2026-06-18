/// Loaded V1 server config.
pub struct Config {
    pub bind: String,
    pub master_key: Vec<u8>,
    pub data_dir: String,
    pub crypto_backend: String,
    pub admin_token: Option<String>,
    pub arc_trust_anchors: String, // raw spec, parsed in main
    pub audience: String,
    pub allow_unsigned_dev: bool,
}

// Manual Debug that REDACTS the master key. `Config` needs `Debug` for tests'
// `unwrap_err()`, but a vault must never let the master key reach a log/`dbg!`.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind", &self.bind)
            .field("master_key", &"<redacted>")
            .field("data_dir", &self.data_dir)
            .field("crypto_backend", &self.crypto_backend)
            .field(
                "admin_token",
                &self.admin_token.as_ref().map(|_| "<redacted>"),
            )
            .field("arc_trust_anchors", &self.arc_trust_anchors)
            .field("audience", &self.audience)
            .field("allow_unsigned_dev", &self.allow_unsigned_dev)
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    MissingMasterKey,
    ForbiddenCrypto(String),
}

/// Refuse to start on the SM/Tongsuo crypto suite — defense-in-depth behind the
/// engine's own pinning. Accept only openssl / native-rust.
pub fn validate_crypto(backend: &str) -> Result<(), ConfigError> {
    match backend {
        "openssl" | "native-rust" => Ok(()),
        other => Err(ConfigError::ForbiddenCrypto(other.to_string())),
    }
}

/// Build Config from a key/value getter (so tests don't touch real env).
pub fn from_getter(get: impl Fn(&str) -> Option<String>) -> Result<Config, ConfigError> {
    let master_key = get("TESSERA_MASTER_KEY")
        .filter(|s| !s.is_empty())
        .ok_or(ConfigError::MissingMasterKey)?;
    let crypto_backend = get("TESSERA_CRYPTO_BACKEND").unwrap_or_else(|| "openssl".to_string());
    validate_crypto(&crypto_backend)?;
    let admin_token = get("TESSERA_ADMIN_TOKEN").filter(|s| !s.is_empty());
    let arc_trust_anchors = get("TESSERA_ARC_TRUST_ANCHORS").unwrap_or_default();
    let audience = get("TESSERA_AUDIENCE").unwrap_or_else(|| "tessera.local".to_string());
    let allow_unsigned_dev = get("TESSERA_ALLOW_UNSIGNED_DEV")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    Ok(Config {
        bind: get("TESSERA_BIND").unwrap_or_else(|| "127.0.0.1:8200".to_string()),
        master_key: master_key.into_bytes(),
        data_dir: get("TESSERA_DATA_DIR").unwrap_or_else(|| "./data".to_string()),
        crypto_backend,
        admin_token,
        arc_trust_anchors,
        audience,
        allow_unsigned_dev,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn getter<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn rejects_shangmi_backend() {
        assert_eq!(
            validate_crypto("tongsuo"),
            Err(ConfigError::ForbiddenCrypto("tongsuo".into()))
        );
        assert_eq!(
            validate_crypto("sm"),
            Err(ConfigError::ForbiddenCrypto("sm".into()))
        );
    }

    #[test]
    fn accepts_openssl() {
        validate_crypto("openssl").unwrap();
    }

    #[test]
    fn missing_master_key_errors() {
        let err = from_getter(getter(&[])).unwrap_err();
        assert_eq!(err, ConfigError::MissingMasterKey);
    }

    #[test]
    fn forbidden_crypto_blocks_startup() {
        let err = from_getter(getter(&[
            ("TESSERA_MASTER_KEY", "k"),
            ("TESSERA_CRYPTO_BACKEND", "tongsuo"),
        ]))
        .unwrap_err();
        assert_eq!(err, ConfigError::ForbiddenCrypto("tongsuo".into()));
    }

    #[test]
    fn defaults_applied() {
        let cfg = from_getter(getter(&[("TESSERA_MASTER_KEY", "k")])).unwrap();
        assert_eq!(cfg.bind, "127.0.0.1:8200");
        assert_eq!(cfg.crypto_backend, "openssl");
    }

    #[test]
    fn admin_token_optional_and_redacted() {
        let cfg = from_getter(getter(&[
            ("TESSERA_MASTER_KEY", "k"),
            ("TESSERA_ADMIN_TOKEN", "admin-secret-xyz"),
        ]))
        .unwrap();
        assert_eq!(cfg.admin_token.as_deref(), Some("admin-secret-xyz"));
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("admin-secret-xyz"),
            "admin token must be redacted in Debug"
        );
    }

    #[test]
    fn trust_env_defaults_safe() {
        let cfg = from_getter(getter(&[("TESSERA_MASTER_KEY", "k")])).unwrap();
        assert_eq!(cfg.audience, "tessera.local");
        assert!(!cfg.allow_unsigned_dev, "prod default must be fail-closed");
        assert_eq!(cfg.arc_trust_anchors, "");
    }

    #[test]
    fn allow_unsigned_dev_parses_truthy() {
        let cfg = from_getter(getter(&[
            ("TESSERA_MASTER_KEY", "k"),
            ("TESSERA_ALLOW_UNSIGNED_DEV", "true"),
            ("TESSERA_AUDIENCE", "femto.test"),
        ]))
        .unwrap();
        assert!(cfg.allow_unsigned_dev);
        assert_eq!(cfg.audience, "femto.test");
    }

    #[test]
    fn debug_redacts_master_key() {
        let cfg = from_getter(getter(&[("TESSERA_MASTER_KEY", "super-secret-key")])).unwrap();
        let rendered = format!("{cfg:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(
            !rendered.contains("super-secret-key"),
            "master key must never appear in Debug output: {rendered}"
        );
    }
}
