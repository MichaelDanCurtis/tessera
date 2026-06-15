/// Loaded V1 server config.
#[derive(Debug)]
pub struct Config {
    pub bind: String,
    pub master_key: Vec<u8>,
    #[allow(dead_code)]
    pub data_dir: String,
    pub crypto_backend: String,
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
    Ok(Config {
        bind: get("TESSERA_BIND").unwrap_or_else(|| "127.0.0.1:8200".to_string()),
        master_key: master_key.into_bytes(),
        data_dir: get("TESSERA_DATA_DIR").unwrap_or_else(|| "./data".to_string()),
        crypto_backend,
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
}
