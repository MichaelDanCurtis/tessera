//! Acceptance: Tessera issues authenticated SPIFFE SVID material for Femto
//! secure entities without granting callers broad sys-plane authority.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use tessera_core::audit::{AuditOp, InMemoryAudit};
use tessera_core::auth::{Policy, PolicyStore, TokenStore};
use tessera_core::clock::FixedClock;
use tessera_core::engine::InMemoryEngine;
use tessera_core::mandate::{canonical_signing_payload, VerifyConfig};
use tessera_core::seal::SealState;
use tessera_core::trust_anchors::TrustAnchors;
use tessera_core::vault::VaultStore;
use tessera_server::app::{router, AppState, TrustConfig};

const FIXTURE_SEED: [u8; 32] = [0x11; 32];
const FIXTURE_KEY_ID: &str = "arc-fixture-key-1";

fn fixture_anchor_spec() -> String {
    let pk = STANDARD.encode(
        SigningKey::from_bytes(&FIXTURE_SEED)
            .verifying_key()
            .to_bytes(),
    );
    format!("{FIXTURE_KEY_ID}:{pk}")
}

fn signed_issue_mandate(
    spiffe_subject: &str,
    audience: &str,
    issued: &str,
    expires: &str,
) -> Value {
    let mut m = serde_json::json!({
        "mandateId": "m-pki-1",
        "format": "a2e-execution-mandate/v0",
        "issuer": "galvo-arc",
        "subject": spiffe_subject,
        "audience": audience,
        "issuedAt": issued,
        "expiresAt": expires,
        "certifies": { "action": "execute", "workOrderHash": "sha256:beef", "idempotencyKey": "i-1" },
        "scope": { "data": [], "models": [], "runtimeClasses": ["wasm"] },
        "signature": { "alg": "ed25519", "value": "", "keyId": FIXTURE_KEY_ID }
    });
    let payload = canonical_signing_payload(&m);
    let sig = SigningKey::from_bytes(&FIXTURE_SEED).sign(&payload);
    m["signature"]["value"] = Value::String(STANDARD.encode(sig.to_bytes()));
    m
}

/// State enforcing mandates in prod mode against the fixture anchor, with the
/// clock at 2026-06-14T00:00:00Z (matches FixedClock used elsewhere).
fn pki_state_enforcing() -> AppState {
    let mut state = pki_state();
    state.trust = TrustConfig {
        anchors: Arc::new(TrustAnchors::from_str_spec(&fixture_anchor_spec()).unwrap()),
        verify: VerifyConfig {
            audience: "tessera.local".into(),
            allow_unsigned_dev: false,
        },
    };
    state
}

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

#[tokio::test]
async fn issue_with_valid_signed_mandate_succeeds() {
    let state = pki_state_enforcing();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let subject = "spiffe://example.org"; // mandate subject; requested spiffeId extends it
    let mandate = signed_issue_mandate(
        subject,
        "tessera.local",
        "2026-06-14T00:00:00Z",
        "2999-01-01T00:00:00Z",
    );

    let res = client
        .post(format!("{base}/v1/pki/spiffe/issue"))
        .header("Authorization", "Bearer pki-tok")
        .json(&serde_json::json!({
            "trustDomain": "example.org",
            "spiffeId": "spiffe://example.org/workload/a",
            "mandate": mandate
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let audit = state.vault.audit_sink().records();
    assert!(audit.iter().any(|r| r.op == AuditOp::IssueCertificate
        && r.scope.contains("mandate=m-pki-1")
        && r.outcome));
}

#[tokio::test]
async fn issue_missing_mandate_in_prod_is_rejected() {
    let state = pki_state_enforcing();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{base}/v1/pki/spiffe/issue"))
        .header("Authorization", "Bearer pki-tok")
        .json(&serde_json::json!({
            "trustDomain": "example.org",
            "spiffeId": "spiffe://example.org/workload/a"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "mandate-invalid");
}

#[tokio::test]
async fn issue_unsigned_mandate_in_dev_is_allowed() {
    // dev_default state allows unsigned-dev + no anchors.
    let state = pki_state(); // dev_default trust
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{base}/v1/pki/spiffe/issue"))
        .header("Authorization", "Bearer pki-tok")
        .json(&serde_json::json!({
            "trustDomain": "example.org",
            "spiffeId": "spiffe://example.org/workload/a"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}
