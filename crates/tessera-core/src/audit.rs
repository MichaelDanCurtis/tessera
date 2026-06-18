use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::persist::{append_jsonl, read_jsonl_lines};

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
    IssueCertificate,
    TransitUnwrap,
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

/// Server-side audit read filters. All `None` = return everything (subject to
/// `limit`). `since`/`until` compare the RFC-3339 `timestamp` lexicographically,
/// which is correct for fixed-offset UTC (`...Z`) instants of equal width.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    pub prefix: Option<String>,
    pub op: Option<AuditOp>,
    pub outcome: Option<bool>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<usize>,
}

/// Append-only audit sink. V1 is in-memory + flush-to-writer; hash-chaining is
/// deferred. The trait lets the server swap a file-backed sink later.
pub trait AuditSink: Send + Sync {
    fn append(&self, record: AuditRecord);
    fn records(&self) -> Vec<AuditRecord>;

    /// Filtered, time-bounded read. Default impl filters `records()`; a sink may
    /// override for efficiency. `limit` keeps the most recent N (tail of the
    /// chronologically-ordered log).
    fn query(&self, q: &AuditQuery) -> Vec<AuditRecord> {
        let mut out: Vec<AuditRecord> = self
            .records()
            .into_iter()
            .filter(|r| {
                q.prefix
                    .as_ref()
                    .is_none_or(|p| r.scope.starts_with(p.as_str()))
            })
            .filter(|r| q.op.is_none_or(|op| r.op == op))
            .filter(|r| q.outcome.is_none_or(|o| r.outcome == o))
            .filter(|r| {
                q.since
                    .as_ref()
                    .is_none_or(|s| r.timestamp.as_str() >= s.as_str())
            })
            .filter(|r| {
                q.until
                    .as_ref()
                    .is_none_or(|u| r.timestamp.as_str() <= u.as_str())
            })
            .collect();
        if let Some(n) = q.limit {
            let drop = out.len().saturating_sub(n);
            out.drain(0..drop);
        }
        out
    }
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

/// Append-only, restart-durable audit sink. Each record is one JSON line in
/// `<data_dir>/audit.log`. On `open` it loads existing lines into memory so
/// `records()`/`query()` are O(n) in-process; every `append` also writes the
/// line to disk (flushed). Single-node; no hash-chaining yet.
pub struct FileAuditSink {
    path: PathBuf,
    log: Mutex<Vec<AuditRecord>>,
}

impl FileAuditSink {
    /// Open (or create) the audit log at `path`, loading any existing entries.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut existing = Vec::new();
        for line in read_jsonl_lines(&path)? {
            // Skip corrupt lines defensively rather than refusing to start.
            if let Ok(rec) = serde_json::from_str::<AuditRecord>(&line) {
                existing.push(rec);
            }
        }
        Ok(Self {
            path,
            log: Mutex::new(existing),
        })
    }
}

impl AuditSink for FileAuditSink {
    fn append(&self, record: AuditRecord) {
        // Best-effort durability: serialize + append to disk, then memory. A
        // disk error must not panic the request path (audit is observability,
        // not the security gate) — but it is logged to stderr.
        if let Ok(line) = serde_json::to_string(&record) {
            if let Err(e) = append_jsonl(&self.path, &line) {
                eprintln!(
                    "tessera: audit append to {} failed: {e}",
                    self.path.display()
                );
            }
        }
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

    fn rec(op: AuditOp, scope: &str, outcome: bool, ts: &str, reveal: bool) -> AuditRecord {
        AuditRecord {
            op,
            scope: scope.into(),
            token_hash: token_hash("t"),
            outcome,
            timestamp: ts.into(),
            reveal,
        }
    }

    #[test]
    fn query_filters_by_prefix_op_outcome_time_and_limit() {
        let a = InMemoryAudit::new();
        a.append(rec(
            AuditOp::Read,
            "secret/galvo/a",
            true,
            "2026-06-14T00:00:01Z",
            false,
        ));
        a.append(rec(
            AuditOp::Write,
            "secret/galvo/b",
            true,
            "2026-06-14T00:00:02Z",
            false,
        ));
        a.append(rec(
            AuditOp::Read,
            "secret/femto/c",
            false,
            "2026-06-14T00:00:03Z",
            false,
        ));

        // prefix
        let q = AuditQuery {
            prefix: Some("secret/galvo/".into()),
            ..Default::default()
        };
        assert_eq!(a.query(&q).len(), 2);
        // op
        let q = AuditQuery {
            op: Some(AuditOp::Read),
            ..Default::default()
        };
        assert_eq!(a.query(&q).len(), 2);
        // outcome
        let q = AuditQuery {
            outcome: Some(false),
            ..Default::default()
        };
        assert_eq!(a.query(&q).len(), 1);
        // since/until (string RFC-3339 compares lexicographically)
        let q = AuditQuery {
            since: Some("2026-06-14T00:00:02Z".into()),
            ..Default::default()
        };
        assert_eq!(a.query(&q).len(), 2);
        let q = AuditQuery {
            until: Some("2026-06-14T00:00:02Z".into()),
            ..Default::default()
        };
        assert_eq!(a.query(&q).len(), 2);
        // limit returns the MOST RECENT n (tail)
        let q = AuditQuery {
            limit: Some(1),
            ..Default::default()
        };
        let got = a.query(&q);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].scope, "secret/femto/c");
    }

    #[test]
    fn file_audit_sink_persists_across_reopen() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.log");
        {
            let sink = FileAuditSink::open(&path).unwrap();
            sink.append(rec(
                AuditOp::Write,
                "secret/galvo/a",
                true,
                "2026-06-14T00:00:01Z",
                false,
            ));
            sink.append(rec(
                AuditOp::Read,
                "secret/galvo/a",
                true,
                "2026-06-14T00:00:02Z",
                true,
            ));
        } // drop — simulates process exit
        let reopened = FileAuditSink::open(&path).unwrap();
        let recs = reopened.records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].op, AuditOp::Write);
        assert!(recs[1].reveal, "reveal marker survives reopen");
        // query() works on the file sink too
        let q = AuditQuery {
            op: Some(AuditOp::Read),
            ..Default::default()
        };
        assert_eq!(reopened.query(&q).len(), 1);
    }

    #[test]
    fn token_hash_is_not_the_raw_token() {
        let h = token_hash("super-secret-token");
        assert_ne!(h, "super-secret-token");
        assert_eq!(h.len(), 64); // blake3 hex
    }
}
