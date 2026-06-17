//! Acceptance: Tessera issues authenticated SPIFFE SVID material for Femto
//! secure entities without granting callers broad sys-plane authority.

use std::sync::Arc;

use tessera_core::audit::{AuditOp, InMemoryAudit};
use tessera_core::auth::{Policy, PolicyStore, TokenStore};
use tessera_core::clock::FixedClock;
use tessera_core::engine::InMemoryEngine;
use tessera_core::seal::SealState;
use tessera_core::vault::VaultStore;
use tessera_server::app::{router, AppState, TrustConfig};

fn pki_state() -> AppState {
    let mut tokens = TokenStore::new();
    tokens.insert("pki-tok", Policy::new(["pki/spiffe/"]));
    tokens.insert("secret-tok", Policy::new(["secret/"]));
    let seal = SealState::new(b"m".to_vec());
    seal.unseal(b"m").unwrap();
    let vault = VaultStore::new(
        Arc::new(InMemoryEngine::new()),
        seal,
        tokens,
        Arc::new(PolicyStore::in_memory()),
        Arc::new(InMemoryAudit::new()),
        Arc::new(FixedClock("2026-06-14T00:00:00Z".into())),
    );
    AppState {
        vault: Arc::new(vault),
        trust: TrustConfig::dev_default(),
    }
}

async fn serve(state: AppState) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn pki_scoped_token_issues_spiffe_svid() {
    let state = pki_state();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();

    let res = client
        .post(format!("{base}/v1/pki/spiffe/issue"))
        .header("Authorization", "Bearer pki-tok")
        .json(&serde_json::json!({
            "trustDomain": "femto.local",
            "spiffeId": "spiffe://femto.local/corp2/research-alpha/run/run-123",
            "ttlSeconds": 900,
            "profile": "femto-secure-entity-v0"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body: serde_json::Value = res.json().await.unwrap();
    let data = &body["data"];
    assert_eq!(data["provider"], "tessera");
    assert_eq!(data["issuer"], "tessera-spiffe-local-ca");
    assert_eq!(data["trust_domain"], "femto.local");
    assert_eq!(
        data["spiffe_id"],
        "spiffe://femto.local/corp2/research-alpha/run/run-123"
    );
    assert_eq!(data["certificate_profile"], "femto-secure-entity-v0");
    assert_eq!(data["status"], "issued");
    assert_eq!(data["not_before"], "2026-06-14T00:00:00Z");
    assert_eq!(data["not_after"], "2026-06-14T00:15:00Z");
    assert!(data["certificate_serial"]
        .as_str()
        .unwrap()
        .starts_with("svid."));
    assert!(data["decision_id"].as_str().unwrap().starts_with("svid."));
    assert!(data["certificate_pem"]
        .as_str()
        .unwrap()
        .contains("BEGIN CERTIFICATE"));
    assert!(data["private_key_pem"]
        .as_str()
        .unwrap()
        .contains("BEGIN PRIVATE KEY"));

    let audit = state.vault.audit_sink().records();
    assert!(audit.iter().any(|r| {
        format!("{:?}", r.op) == "IssueCertificate" && r.scope == "pki/spiffe/issue" && r.outcome
    }));
}

#[tokio::test]
async fn secret_scoped_token_cannot_issue_spiffe_svid() {
    let state = pki_state();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();

    let res = client
        .post(format!("{base}/v1/pki/spiffe/issue"))
        .header("X-Vault-Token", "secret-tok")
        .json(&serde_json::json!({
            "trustDomain": "femto.local",
            "spiffeId": "spiffe://femto.local/corp2/research-alpha/run/run-123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    let audit = state.vault.audit_sink().records();
    assert!(audit
        .iter()
        .any(|r| { r.op == AuditOp::AuthFailure && r.scope == "pki/spiffe/issue" && !r.outcome }));
    assert!(!audit
        .iter()
        .any(|r| format!("{:?}", r.op) == "IssueCertificate"));
}

#[tokio::test]
async fn spiffe_issue_rejects_wrong_trust_domain() {
    let state = pki_state();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();

    let res = client
        .post(format!("{base}/v1/pki/spiffe/issue"))
        .header("X-Vault-Token", "pki-tok")
        .json(&serde_json::json!({
            "trustDomain": "femto.local",
            "spiffeId": "spiffe://other.local/corp2/research-alpha/run/run-123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);

    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(
        body["errors"][0],
        "spiffeId must be inside trustDomain femto.local"
    );

    let audit = state.vault.audit_sink().records();
    assert!(audit.iter().any(|r| {
        format!("{:?}", r.op) == "IssueCertificate" && r.scope == "pki/spiffe/issue" && !r.outcome
    }));
}
