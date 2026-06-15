use crate::audit::{token_hash, AuditOp, AuditRecord, AuditSink};
use crate::auth::TokenStore;
use crate::engine::SecretEngine;
use crate::seal::SealState;
use crate::types::{SecretMetadata, SecretPath, SecretValue, TesseraError};

/// Ties together the storage engine, seal gate, auth, and audit. Every public
/// method: require_unsealed → authorize → engine op → audit (success or denial).
pub struct KvStore<E: SecretEngine, A: AuditSink> {
    engine: E,
    seal: SealState,
    tokens: TokenStore,
    audit: A,
}

impl<E: SecretEngine, A: AuditSink> KvStore<E, A> {
    pub fn new(engine: E, seal: SealState, tokens: TokenStore, audit: A) -> Self {
        Self {
            engine,
            seal,
            tokens,
            audit,
        }
    }

    pub fn seal_state(&self) -> &SealState {
        &self.seal
    }

    pub fn audit_sink(&self) -> &A {
        &self.audit
    }

    fn guard(&self, token: &str, path: &SecretPath, op: AuditOp) -> Result<(), TesseraError> {
        self.seal.require_unsealed()?;
        if let Err(e) = self.tokens.authorize(token, path) {
            self.audit.append(AuditRecord {
                op: AuditOp::AuthFailure,
                scope: path.scope(),
                token_hash: token_hash(token),
                outcome: false,
            });
            return Err(e);
        }
        // op recorded by the caller after the engine result is known
        let _ = op;
        Ok(())
    }

    fn record(&self, op: AuditOp, path: &SecretPath, token: &str, outcome: bool) {
        self.audit.append(AuditRecord {
            op,
            scope: path.scope(),
            token_hash: token_hash(token),
            outcome,
        });
    }

    pub fn write(
        &self,
        token: &str,
        path: &SecretPath,
        value: SecretValue,
    ) -> Result<(), TesseraError> {
        self.guard(token, path, AuditOp::Write)?;
        let res = self.engine.put(path, value);
        self.record(AuditOp::Write, path, token, res.is_ok());
        res
    }

    pub fn read(
        &self,
        token: &str,
        path: &SecretPath,
    ) -> Result<(SecretValue, SecretMetadata), TesseraError> {
        self.guard(token, path, AuditOp::Read)?;
        let res = self.engine.get(path);
        self.record(AuditOp::Read, path, token, res.is_ok());
        res
    }

    pub fn delete(&self, token: &str, path: &SecretPath) -> Result<(), TesseraError> {
        self.guard(token, path, AuditOp::Delete)?;
        let res = self.engine.delete(path);
        self.record(AuditOp::Delete, path, token, res.is_ok());
        res
    }

    pub fn list(&self, token: &str, prefix: &SecretPath) -> Result<Vec<String>, TesseraError> {
        self.guard(token, prefix, AuditOp::List)?;
        let res = self.engine.list(prefix);
        self.record(AuditOp::List, prefix, token, res.is_ok());
        res
    }

    pub fn metadata(&self, token: &str, path: &SecretPath) -> Result<SecretMetadata, TesseraError> {
        self.guard(token, path, AuditOp::Read)?;
        let res = self.engine.metadata(path);
        self.record(AuditOp::Read, path, token, res.is_ok());
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::InMemoryAudit;
    use crate::auth::Policy;
    use crate::engine::InMemoryEngine;

    fn store() -> KvStore<InMemoryEngine, InMemoryAudit> {
        let mut tokens = TokenStore::new();
        tokens.insert("galvo-tok", Policy::new(["secret/galvo/"]));
        let seal = SealState::new(b"m".to_vec());
        seal.unseal(b"m").unwrap();
        KvStore::new(
            InMemoryEngine::new("2026-06-14T00:00:00Z"),
            seal,
            tokens,
            InMemoryAudit::new(),
        )
    }

    fn val(v: &str) -> SecretValue {
        let mut m = SecretValue::default();
        m.0.insert("api_key".into(), v.into());
        m
    }

    #[test]
    fn write_then_read_in_scope() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        s.write("galvo-tok", &p, val("sk-1")).unwrap();
        let (v, _) = s.read("galvo-tok", &p).unwrap();
        assert_eq!(v.0.get("api_key").unwrap(), "sk-1");
    }

    #[test]
    fn out_of_scope_denied_and_audited() {
        let s = store();
        let p = SecretPath::new("secret", "femto/key");
        assert_eq!(
            s.read("galvo-tok", &p),
            Err(TesseraError::Forbidden("secret/femto/key".into()))
        );
        let recs = s.audit_sink().records();
        assert_eq!(recs.last().unwrap().op, AuditOp::AuthFailure);
        assert!(!recs.last().unwrap().outcome);
    }

    #[test]
    fn sealed_store_refuses() {
        let s = store();
        s.seal_state().seal();
        let p = SecretPath::new("secret", "galvo/openai");
        assert_eq!(
            s.write("galvo-tok", &p, val("x")),
            Err(TesseraError::Sealed)
        );
    }

    #[test]
    fn successful_ops_are_audited() {
        let s = store();
        let p = SecretPath::new("secret", "galvo/openai");
        s.write("galvo-tok", &p, val("sk-1")).unwrap();
        s.read("galvo-tok", &p).unwrap();
        let ops: Vec<_> = s.audit_sink().records().iter().map(|r| r.op).collect();
        assert_eq!(ops, vec![AuditOp::Write, AuditOp::Read]);
    }
}
