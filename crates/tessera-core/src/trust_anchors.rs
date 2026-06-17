//! Pinned keyId -> ed25519 public key map (the trust-plane root of trust).
//! V1 source: env `TESSERA_ARC_TRUST_ANCHORS` = comma-separated `keyId:base64pubkey`.

use crate::mandate::TrustAnchorsView;

/// Owning trust-anchor set. Wraps the borrow-only `TrustAnchorsView` used by
/// verification so callers thread one value through AppState.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    view: TrustAnchorsView,
}

impl TrustAnchors {
    /// Parse `keyId:base64pubkey` pairs, comma-separated. Empty -> empty set.
    /// Whitespace around tokens and a trailing comma are tolerated. A pair
    /// without a colon, or with a non-32-byte / non-base64 key, is an error.
    pub fn from_str_spec(spec: &str) -> Result<Self, String> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for entry in spec.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (id, b64) = entry
                .split_once(':')
                .ok_or_else(|| format!("trust anchor entry missing ':' -> {entry}"))?;
            let id = id.trim().to_string();
            let b64 = b64.trim().to_string();
            if id.is_empty() {
                return Err(format!("trust anchor entry has empty keyId -> {entry}"));
            }
            pairs.push((id, b64));
        }
        let view = TrustAnchorsView::from_pairs(&pairs)?;
        Ok(Self { view })
    }

    /// Load from a key/value getter (so tests avoid touching real env).
    pub fn from_getter(var: &str, get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        match get(var) {
            Some(spec) => Self::from_str_spec(&spec),
            None => Ok(Self::default()),
        }
    }

    /// Load from the process environment (used by `main`).
    pub fn from_env(var: &str) -> Result<Self, String> {
        Self::from_getter(var, |k| std::env::var(k).ok())
    }

    pub fn view(&self) -> &TrustAnchorsView {
        &self.view
    }
}

#[cfg(test)]
mod tests {
    use super::TrustAnchors;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::SigningKey;

    fn pub_b64(seed: u8) -> String {
        STANDARD.encode(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    #[test]
    fn parses_comma_separated_pairs() {
        let raw = format!("k1:{},k2:{}", pub_b64(1), pub_b64(2));
        let anchors = TrustAnchors::from_str_spec(&raw).unwrap();
        assert!(anchors.view().resolve("k1").is_some());
        assert!(anchors.view().resolve("k2").is_some());
        assert!(anchors.view().resolve("missing").is_none());
    }

    #[test]
    fn empty_spec_yields_empty_anchors() {
        let anchors = TrustAnchors::from_str_spec("").unwrap();
        assert!(anchors.view().is_empty());
    }

    #[test]
    fn whitespace_and_trailing_comma_tolerated() {
        let raw = format!(" k1 : {} , ", pub_b64(1));
        let anchors = TrustAnchors::from_str_spec(&raw).unwrap();
        assert!(anchors.view().resolve("k1").is_some());
    }

    #[test]
    fn malformed_pair_is_error() {
        assert!(TrustAnchors::from_str_spec("no-colon-here").is_err());
        assert!(TrustAnchors::from_str_spec("k1:not-base64!!!").is_err());
    }

    #[test]
    fn from_env_reads_named_var() {
        let raw = format!("k1:{}", pub_b64(9));
        // Use a getter closure so the test doesn't mutate process env.
        let anchors = TrustAnchors::from_getter("TESSERA_ARC_TRUST_ANCHORS", |k| {
            if k == "TESSERA_ARC_TRUST_ANCHORS" {
                Some(raw.clone())
            } else {
                None
            }
        })
        .unwrap();
        assert!(anchors.view().resolve("k1").is_some());
    }
}
