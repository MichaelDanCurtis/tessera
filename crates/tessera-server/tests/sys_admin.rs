//! Acceptance: admin sys-plane (audit read + token/policy CRUD) survives a
//! restart and enforces the admin gate. Mirrors persistence.rs structure.

use std::sync::Arc;

use tessera_core::audit::{AuditOp, FileAuditSink};
use tessera_core::auth::{Policy, PolicyStore, TokenStore};
use tessera_core::clock::SystemClock;
use tessera_core::rusty_engine::RustyVaultEngine;
use tessera_core::seal::SealState;
use tessera_core::types::{SecretPath, SecretValue};
use tessera_core::vault::VaultStore;

const MASTER_KEY: &[u8] = b"sys-admin-acceptance-master-key";

async fn open_store(dir: &std::path::Path) -> VaultStore {
    let engine = RustyVaultEngine::open(dir.to_str().unwrap(), MASTER_KEY)
        .await
        .expect("engine");
    let seal = SealState::new(MASTER_KEY.to_vec());
    seal.unseal(MASTER_KEY).unwrap();
    let audit = Arc::new(FileAuditSink::open(dir.join("audit.log")).unwrap());
    let policies = Arc::new(PolicyStore::open(dir.join("policies.json")).unwrap());
    let mut tokens = TokenStore::open(dir.join("tokens.json")).unwrap();
    tokens.insert("admin-tok", Policy::new(["sys/", "secret/"]));
    policies
        .put("galvo", Policy::new(["secret/galvo/"]))
        .unwrap();
    VaultStore::new(
        Arc::new(engine),
        seal,
        tokens,
        policies,
        audit,
        Arc::new(SystemClock),
    )
}

fn value(k: &str, v: &str) -> SecretValue {
    let mut sv = SecretValue::default();
    sv.0.insert(k.into(), v.into());
    sv
}

#[tokio::test]
async fn audit_and_tokens_survive_restart_and_gate_admin() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let p = SecretPath::new("secret", "galvo/openai");

    let issued_accessor;
    {
        let store = open_store(&dir).await;
        // generate audit history + a reveal
        store
            .write("admin-tok", &p, value("api_key", "v1"), None)
            .await
            .unwrap();
        store.read_reveal("admin-tok", &p, None).await.unwrap();
        // issue a dynamic token under policy "galvo"
        let now = store.clock().now_rfc3339();
        let out = store
            .tokens()
            .issue(vec!["galvo".into()], None, &now, store.policies())
            .unwrap();
        issued_accessor = out.accessor.clone();
        // admin gate: admin-tok is admin, the issued token is NOT
        assert!(store.tokens().is_admin("admin-tok", store.policies()));
        assert!(!store.tokens().is_admin(&out.token, store.policies()));
    } // drop -> process exit

    // reopen: audit history + issued token persist
    let store = open_store(&dir).await;
    let reveals: Vec<_> = store
        .audit_sink()
        .records()
        .into_iter()
        .filter(|r| r.reveal)
        .collect();
    assert_eq!(reveals.len(), 1, "the reveal entry survived restart");
    assert!(store
        .audit_sink()
        .records()
        .iter()
        .any(|r| r.op == AuditOp::Write));
    // the dynamic token's metadata persists by accessor
    assert!(store
        .tokens()
        .list_metadata()
        .iter()
        .any(|m| m.accessor == issued_accessor));
}
