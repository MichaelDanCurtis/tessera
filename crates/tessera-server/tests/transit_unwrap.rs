//! Acceptance: Tessera owns GalvoFS destructive-boot payload unwraps behind a
//! narrow transit policy scope, rather than letting Femto derive unwrap keys.

use std::sync::Arc;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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

fn signed_unwrap_mandate(subject: &str, audience: &str) -> Value {
    let mut m = json!({
        "mandateId": "m-transit-1",
        "format": "a2e-execution-mandate/v0",
        "issuer": "galvo-arc",
        "subject": subject,
        "audience": audience,
        "issuedAt": "2026-06-14T00:00:00Z",
        "expiresAt": "2999-01-01T00:00:00Z",
        "certifies": { "action": "execute", "workOrderHash": "sha256:beef", "idempotencyKey": "i-1" },
        "scope": { "data": [], "models": [], "runtimeClasses": ["wasm"] },
        "signature": { "alg": "ed25519", "value": "", "keyId": FIXTURE_KEY_ID }
    });
    let payload = canonical_signing_payload(&m);
    let sig = SigningKey::from_bytes(&FIXTURE_SEED).sign(&payload);
    m["signature"]["value"] = Value::String(STANDARD.encode(sig.to_bytes()));
    m
}

/// Like `signed_unwrap_mandate` but with a caller-chosen `certifies.idempotencyKey`
/// — the one-time consume nonce the unwrap ledger burns (trust-plane Phase 2).
fn signed_unwrap_mandate_idem(subject: &str, audience: &str, idem: &str) -> Value {
    let mut m = json!({
        "mandateId": "m-transit-1",
        "format": "a2e-execution-mandate/v0",
        "issuer": "galvo-arc",
        "subject": subject,
        "audience": audience,
        "issuedAt": "2026-06-14T00:00:00Z",
        "expiresAt": "2999-01-01T00:00:00Z",
        "certifies": { "action": "execute", "workOrderHash": "sha256:beef", "idempotencyKey": idem },
        "scope": { "data": [], "models": [], "runtimeClasses": ["wasm"] },
        "signature": { "alg": "ed25519", "value": "", "keyId": FIXTURE_KEY_ID }
    });
    let payload = canonical_signing_payload(&m);
    let sig = SigningKey::from_bytes(&FIXTURE_SEED).sign(&payload);
    m["signature"]["value"] = Value::String(STANDARD.encode(sig.to_bytes()));
    m
}

/// State enforcing mandates in prod mode against the fixture anchor.
fn transit_state_enforcing() -> AppState {
    let mut state = transit_state();
    state.trust = TrustConfig {
        anchors: Arc::new(TrustAnchors::from_str_spec(&fixture_anchor_spec()).unwrap()),
        verify: VerifyConfig {
            audience: "tessera.local".into(),
            allow_unsigned_dev: false,
        },
    };
    state
}

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

#[tokio::test]
async fn unwrap_with_valid_signed_mandate_succeeds() {
    let state = transit_state_enforcing();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let key_ref = "tessera://transit/galvofs/real-secure-capsule";
    let nonce = [0x42; 12];
    let plaintext = br#"{"sealed":true,"opened":"tessera"}"#;
    let ciphertext = seal_fixture(key_ref, &nonce, plaintext);
    let subject = "spiffe://femto.local/run";
    let mandate = signed_unwrap_mandate(subject, "tessera.local");

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
            "context": { "spiffeId": "spiffe://femto.local/run/run-1" },
            "mandate": mandate
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let audit = state.vault.audit_sink().records();
    assert!(audit.iter().any(|r| r.op == AuditOp::TransitUnwrap
        && r.scope.contains("mandate=m-transit-1")
        && r.outcome));
}

#[tokio::test]
async fn unwrap_missing_mandate_in_prod_is_rejected() {
    let state = transit_state_enforcing();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{base}/v1/transit/unwrap/galvofs"))
        .header("Authorization", "Bearer unwrap-tok")
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
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "mandate-invalid");
}

#[tokio::test]
async fn unwrap_audience_mismatch_is_policy_denied() {
    let state = transit_state_enforcing();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let key_ref = "tessera://transit/galvofs/real-secure-capsule";
    let nonce = [0x42; 12];
    let plaintext = br#"{"sealed":true}"#;
    let ciphertext = seal_fixture(key_ref, &nonce, plaintext);
    let subject = "spiffe://femto.local/run";
    // Signed mandate carries the WRONG audience.
    let mandate = signed_unwrap_mandate(subject, "other");

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
            "context": { "spiffeId": "spiffe://femto.local/run/run-1" },
            "mandate": mandate
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "policy-denied");
}

// One-time-unwrap ledger (trust-plane Phase 2). NOTE: these route tests use an
// InMemoryEngine (does NOT persist across a fresh `serve()`), so the durable
// restart-replay guarantee is proven at the engine level by
// `put_if_absent_survives_reopen_same_dir` in tessera-core's rusty_engine tests.

#[tokio::test]
async fn unwrap_replay_same_nonce_is_replay_detected() {
    let state = transit_state_enforcing();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let key_ref = "tessera://transit/galvofs/replay-cap";
    let nonce = [0x42; 12];
    let plaintext = br#"{"sealed":true}"#;
    let ciphertext = seal_fixture(key_ref, &nonce, plaintext);
    let mandate =
        signed_unwrap_mandate_idem("spiffe://femto.local/run", "tessera.local", "idem-replay");
    let body = json!({
        "keyRef": key_ref,
        "cipherSuite": "aes-256-gcm",
        "nonce": "hex:424242424242424242424242",
        "ciphertextBase64": STANDARD.encode(&ciphertext),
        "ciphertextDigest": sha256_digest(&ciphertext),
        "unwrapProfile": "galvofs-destructive-boot-v0",
        "context": { "spiffeId": "spiffe://femto.local/run/run-1" },
        "mandate": mandate
    });

    // First unwrap: 200.
    let r1 = client
        .post(format!("{base}/v1/transit/unwrap/galvofs"))
        .header("Authorization", "Bearer unwrap-tok")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);

    // Identical replay (same keyRef + same idempotencyKey): 403 replay-detected.
    let r2 = client
        .post(format!("{base}/v1/transit/unwrap/galvofs"))
        .header("Authorization", "Bearer unwrap-tok")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 403);
    let b2: Value = r2.json().await.unwrap();
    assert_eq!(b2["code"], "replay-detected");

    // Audit: a TransitUnwrap outcome=false replay rejection exists.
    let audit = state.vault.audit_sink().records();
    assert!(audit
        .iter()
        .any(|r| r.op == AuditOp::TransitUnwrap && !r.outcome));
}

#[tokio::test]
async fn unwrap_different_nonce_same_key_is_allowed() {
    let state = transit_state_enforcing();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let key_ref = "tessera://transit/galvofs/twononce-cap";
    let nonce = [0x42; 12];
    let plaintext = br#"{"sealed":true}"#;
    let ciphertext = seal_fixture(key_ref, &nonce, plaintext);

    for idem in ["idem-A", "idem-B"] {
        let mandate =
            signed_unwrap_mandate_idem("spiffe://femto.local/run", "tessera.local", idem);
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
                "context": { "spiffeId": "spiffe://femto.local/run/run-1" },
                "mandate": mandate
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            200,
            "distinct idempotencyKey {idem} must not be a replay"
        );
    }
}

#[tokio::test]
async fn unwrap_burns_nonce_even_when_later_step_fails() {
    let state = transit_state_enforcing();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let key_ref = "tessera://transit/galvofs/burn-cap";
    let nonce = [0x42; 12];
    let plaintext = br#"{"sealed":true}"#;
    let good_ct = seal_fixture(key_ref, &nonce, plaintext);
    let mandate =
        || signed_unwrap_mandate_idem("spiffe://femto.local/run", "tessera.local", "idem-burn");

    // Attempt 1: valid mandate, but ciphertextDigest mismatch → 400 AFTER burn.
    let r1 = client
        .post(format!("{base}/v1/transit/unwrap/galvofs"))
        .header("Authorization", "Bearer unwrap-tok")
        .json(&json!({
            "keyRef": key_ref,
            "cipherSuite": "aes-256-gcm",
            "nonce": "hex:424242424242424242424242",
            "ciphertextBase64": STANDARD.encode(&good_ct),
            "ciphertextDigest": "sha256:not-the-body",   // forces validate_request failure
            "unwrapProfile": "galvofs-destructive-boot-v0",
            "context": { "spiffeId": "spiffe://femto.local/run/run-1" },
            "mandate": mandate()
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 400);

    // Attempt 2: SAME idempotencyKey, now a fully valid body → must be replay-detected,
    // proving the nonce was burned on attempt 1's failed decrypt path.
    let r2 = client
        .post(format!("{base}/v1/transit/unwrap/galvofs"))
        .header("Authorization", "Bearer unwrap-tok")
        .json(&json!({
            "keyRef": key_ref,
            "cipherSuite": "aes-256-gcm",
            "nonce": "hex:424242424242424242424242",
            "ciphertextBase64": STANDARD.encode(&good_ct),
            "ciphertextDigest": sha256_digest(&good_ct),
            "unwrapProfile": "galvofs-destructive-boot-v0",
            "context": { "spiffeId": "spiffe://femto.local/run/run-1" },
            "mandate": mandate()
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 403);
    let b2: Value = r2.json().await.unwrap();
    assert_eq!(b2["code"], "replay-detected");
}
