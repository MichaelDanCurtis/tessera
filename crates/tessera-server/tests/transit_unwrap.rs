//! Acceptance: Tessera owns GalvoFS destructive-boot payload unwraps behind a
//! narrow transit policy scope, rather than letting Femto derive unwrap keys.

use std::sync::Arc;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tessera_core::audit::{AuditOp, InMemoryAudit};
use tessera_core::auth::{Policy, PolicyStore, TokenStore};
use tessera_core::clock::FixedClock;
use tessera_core::engine::InMemoryEngine;
use tessera_core::seal::SealState;
use tessera_core::vault::VaultStore;
use tessera_server::app::{router, AppState};

fn transit_state() -> AppState {
    let mut tokens = TokenStore::new();
    tokens.insert("unwrap-tok", Policy::new(["transit/unwrap/"]));
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

fn transit_payload_key(key_ref: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"tessera-transit-galvofs-aes-256-gcm-v0\0");
    hasher.update(key_ref.as_bytes());
    hasher.finalize().into()
}

fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!(
        "sha256:{}",
        digest
            .iter()
            .fold(String::with_capacity(64), |mut acc, byte| {
                acc.push_str(&format!("{byte:02x}"));
                acc
            })
    )
}

fn seal_fixture(key_ref: &str, nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let key = transit_payload_key(key_ref);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    cipher.encrypt(Nonce::from_slice(nonce), plaintext).unwrap()
}

#[tokio::test]
async fn transit_scoped_token_unwraps_galvofs_payload() {
    let state = transit_state();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let key_ref = "tessera://transit/galvofs/real-secure-capsule";
    let nonce = [0x42; 12];
    let plaintext = br#"{"sealed":true,"opened":"tessera"}"#;
    let ciphertext = seal_fixture(key_ref, &nonce, plaintext);

    let res = client
        .post(format!("{base}/v1/transit/unwrap/galvofs"))
        .header("Authorization", "Bearer unwrap-tok")
        .json(&json!({
            "keyRef": key_ref,
            "cipherSuite": "aes-256-gcm",
            "nonce": "hex:424242424242424242424242",
            "ciphertextBase64": STANDARD.encode(&ciphertext),
            "ciphertextDigest": sha256_digest(&ciphertext),
            "unwrapProfile": "galvofs-destructive-boot-v0",
            "context": {
                "runId": "run-123",
                "ticketId": "ticket-123",
                "objectId": "galvofs://workspaces/ws/files/secure/payload.json",
                "spiffeId": "spiffe://femto.local/corp2/research-alpha/run/run-123",
                "trustDomain": "femto.local"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let body: Value = res.json().await.unwrap();
    let data = &body["data"];
    assert_eq!(data["provider"], "tessera");
    assert_eq!(data["key_provider"], "tessera-transit-galvofs");
    assert_eq!(data["key_ref"], key_ref);
    assert_eq!(data["cipher_suite"], "aes-256-gcm");
    assert_eq!(data["unwrap_profile"], "galvofs-destructive-boot-v0");
    assert_eq!(data["plaintext_digest"], sha256_digest(plaintext));
    assert_eq!(
        STANDARD
            .decode(data["plaintext_base64"].as_str().unwrap())
            .unwrap(),
        plaintext
    );
    assert!(data["decision_id"].as_str().unwrap().starts_with("unwrap."));
    assert_eq!(data["status"], "unwrapped");

    let audit = state.vault.audit_sink().records();
    assert!(audit.iter().any(|r| {
        r.op == AuditOp::TransitUnwrap && r.scope == "transit/unwrap/galvofs" && r.outcome
    }));
}

#[tokio::test]
async fn secret_scoped_token_cannot_unwrap_galvofs_payload() {
    let state = transit_state();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();

    let res = client
        .post(format!("{base}/v1/transit/unwrap/galvofs"))
        .header("X-Vault-Token", "secret-tok")
        .json(&json!({
            "keyRef": "tessera://transit/galvofs/real-secure-capsule",
            "cipherSuite": "aes-256-gcm",
            "nonce": "hex:424242424242424242424242",
            "ciphertextBase64": "AA==",
            "ciphertextDigest": "sha256:bad",
            "unwrapProfile": "galvofs-destructive-boot-v0",
            "context": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);

    let audit = state.vault.audit_sink().records();
    assert!(audit.iter().any(|r| {
        r.op == AuditOp::AuthFailure && r.scope == "transit/unwrap/galvofs" && !r.outcome
    }));
    assert!(!audit.iter().any(|r| r.op == AuditOp::TransitUnwrap));
}

#[tokio::test]
async fn unwrap_rejects_ciphertext_digest_mismatch() {
    let state = transit_state();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();

    let res = client
        .post(format!("{base}/v1/transit/unwrap/galvofs"))
        .header("X-Vault-Token", "unwrap-tok")
        .json(&json!({
            "keyRef": "tessera://transit/galvofs/real-secure-capsule",
            "cipherSuite": "aes-256-gcm",
            "nonce": "hex:424242424242424242424242",
            "ciphertextBase64": "AA==",
            "ciphertextDigest": "sha256:not-the-body",
            "unwrapProfile": "galvofs-destructive-boot-v0",
            "context": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);

    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["errors"][0],
        "ciphertextDigest does not match ciphertext"
    );
    let audit = state.vault.audit_sink().records();
    assert!(audit.iter().any(|r| {
        r.op == AuditOp::TransitUnwrap && r.scope == "transit/unwrap/galvofs" && !r.outcome
    }));
}
