use std::collections::HashMap;

use crate::types::{SecretPath, TesseraError};

/// A policy allow-lists scope prefixes a token may touch, e.g. `secret/galvo/`.
/// Empty allow-list = deny everything (fail-closed).
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub allow_prefixes: Vec<String>,
}

impl Policy {
    pub fn new(prefixes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self { allow_prefixes: prefixes.into_iter().map(Into::into).collect() }
    }

    /// True iff `path`'s scope starts with any allowed prefix.
    pub fn allows(&self, path: &SecretPath) -> bool {
        let scope = path.scope();
        self.allow_prefixes.iter().any(|p| scope.starts_with(p.as_str()))
    }
}

/// Maps opaque token strings to policies. Tokens are configured up front in V1
/// (no dynamic token issuance — that arrives with PKI/V1.5).
#[derive(Default)]
pub struct TokenStore {
    tokens: HashMap<String, Policy>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self { tokens: HashMap::new() }
    }

    pub fn insert(&mut self, token: impl Into<String>, policy: Policy) {
        self.tokens.insert(token.into(), policy);
    }

    /// Authorize `token` for `path`. `Err(InvalidToken)` if unknown,
    /// `Err(Forbidden)` if out of scope. Fail-closed on both.
    pub fn authorize(&self, token: &str, path: &SecretPath) -> Result<(), TesseraError> {
        let policy = self.tokens.get(token).ok_or(TesseraError::InvalidToken)?;
        if policy.allows(path) {
            Ok(())
        } else {
            Err(TesseraError::Forbidden(path.scope()))
        }
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

    #[test]
    fn in_scope_path_authorized() {
        store().authorize("galvo-tok", &SecretPath::new("secret", "galvo/openai")).unwrap();
    }

    #[test]
    fn out_of_scope_path_forbidden() {
        let err = store().authorize("galvo-tok", &SecretPath::new("secret", "femto/key")).unwrap_err();
        assert_eq!(err, TesseraError::Forbidden("secret/femto/key".into()));
    }

    #[test]
    fn unknown_token_invalid() {
        assert_eq!(
            store().authorize("nope", &SecretPath::new("secret", "galvo/openai")),
            Err(TesseraError::InvalidToken)
        );
    }

    #[test]
    fn empty_policy_denies_everything() {
        let err = store().authorize("empty-tok", &SecretPath::new("secret", "galvo/openai")).unwrap_err();
        assert!(matches!(err, TesseraError::Forbidden(_)));
    }
}
