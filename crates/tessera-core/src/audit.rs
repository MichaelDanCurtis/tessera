use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// The kind of operation being audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOp {
    Read,
    Write,
    Delete,
    Undelete,
    Destroy,
    ConfigMetadata,
    List,
    AuthFailure,
}

/// One audit entry. `outcome` is true on success, false on denial/failure.
/// `timestamp` is an RFC-3339 instant from the injected `Clock`. `reveal` marks
/// a `Read` that returned plaintext to an operator via the console reveal path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub op: AuditOp,
    pub scope: String,
    pub token_hash: String,
    pub outcome: bool,
    pub timestamp: String,
    #[serde(default)]
    pub reveal: bool,
}

/// Append-only audit sink. V1 is in-memory + flush-to-writer; hash-chaining is
/// deferred. The trait lets the server swap a file-backed sink later.
pub trait AuditSink: Send + Sync {
    fn append(&self, record: AuditRecord);
    fn records(&self) -> Vec<AuditRecord>;
}

#[derive(Default)]
pub struct InMemoryAudit {
    log: Mutex<Vec<AuditRecord>>,
}

impl InMemoryAudit {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuditSink for InMemoryAudit {
    fn append(&self, record: AuditRecord) {
        self.log.lock().unwrap().push(record);
    }
    fn records(&self) -> Vec<AuditRecord> {
        self.log.lock().unwrap().clone()
    }
}

/// Hash a token for audit so the raw secret never lands in the log.
pub fn token_hash(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_is_ordered_and_readable() {
        let a = InMemoryAudit::new();
        a.append(AuditRecord {
            op: AuditOp::Write,
            scope: "secret/galvo/openai".into(),
            token_hash: token_hash("t"),
            outcome: true,
            timestamp: "t".into(),
            reveal: false,
        });
        a.append(AuditRecord {
            op: AuditOp::Read,
            scope: "secret/galvo/openai".into(),
            token_hash: token_hash("t"),
            outcome: true,
            timestamp: "t".into(),
            reveal: false,
        });
        let recs = a.records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].op, AuditOp::Write);
        assert_eq!(recs[1].op, AuditOp::Read);
    }

    #[test]
    fn record_carries_timestamp() {
        let a = InMemoryAudit::new();
        a.append(AuditRecord {
            op: AuditOp::Read,
            scope: "secret/galvo/openai".into(),
            token_hash: token_hash("t"),
            outcome: true,
            timestamp: "2026-06-14T00:00:00Z".into(),
            reveal: false,
        });
        assert_eq!(a.records()[0].timestamp, "2026-06-14T00:00:00Z");
        assert!(!a.records()[0].reveal);
    }

    #[test]
    fn token_hash_is_not_the_raw_token() {
        let h = token_hash("super-secret-token");
        assert_ne!(h, "super-secret-token");
        assert_eq!(h.len(), 64); // blake3 hex
    }
}
