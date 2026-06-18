use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tessera_core::audit::AuditOp;
use tessera_core::mandate::{
    verify_mandate, MandateError, MandateOutcome, RequestBinding, TrustRoute,
};
use tessera_core::types::{SecretPath, TesseraError};

use crate::app::AppState;

const PROVIDER: &str = "tessera";
const KEY_PROVIDER: &str = "tessera-transit-galvofs";
const SUPPORTED_CIPHER_SUITE: &str = "aes-256-gcm";
const SUPPORTED_KEY_PREFIX: &str = "tessera://transit/galvofs/";

#[derive(Debug, Deserialize)]
struct GalvoFsUnwrapRequest {
    #[serde(rename = "keyRef")]
    key_ref: String,
    #[serde(rename = "cipherSuite")]
    cipher_suite: String,
    nonce: String,
    #[serde(rename = "ciphertextBase64")]
    ciphertext_base64: String,
    #[serde(rename = "ciphertextDigest")]
    ciphertext_digest: String,
    #[serde(rename = "unwrapProfile")]
    unwrap_profile: String,
    #[serde(default)]
    context: Value,
    #[serde(default)]
    mandate: Option<Value>,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/transit/unwrap/galvofs", post(unwrap_galvofs))
}

fn token_of(headers: &HeaderMap) -> String {
    if let Some(t) = headers.get("X-Vault-Token").and_then(|v| v.to_str().ok()) {
        return t.to_string();
    }
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string()
}

fn err_response(e: TesseraError) -> (StatusCode, Json<Value>) {
    let code = match e {
        TesseraError::NotFound => StatusCode::NOT_FOUND,
        TesseraError::Sealed => StatusCode::SERVICE_UNAVAILABLE,
        TesseraError::CasMismatch => StatusCode::BAD_REQUEST,
        TesseraError::Forbidden(_) | TesseraError::InvalidToken => StatusCode::FORBIDDEN,
        TesseraError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, Json(json!({ "errors": [e.to_string()] })))
}

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "errors": [msg.into()] })),
    )
}

/// Map a mandate verification failure to its A2E HTTP status + `code` body.
/// mandate-invalid -> 400; mandate-unverifiable / policy-denied -> 403.
fn mandate_err_response(err: &MandateError) -> (StatusCode, Json<Value>) {
    let status = match err {
        MandateError::Invalid(_) => StatusCode::BAD_REQUEST,
        MandateError::Unverifiable(_) | MandateError::PolicyDenied(_) => StatusCode::FORBIDDEN,
    };
    (
        status,
        Json(json!({ "errors": [err.to_string()], "code": err.code() })),
    )
}

/// A2E replay rejection: the unwrap nonce was already consumed. 403 + the
/// `replay-detected` code, matching the A2E error model (§3.6 / §4).
fn replay_detected_response() -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(
            json!({ "errors": ["replay-detected: unwrap nonce already consumed"], "code": "replay-detected" }),
        ),
    )
}

fn transit_scope() -> SecretPath {
    SecretPath::new("transit", "unwrap/galvofs")
}

fn parse_nonce(value: &str) -> Result<[u8; 12], String> {
    let Some(hex) = value.strip_prefix("hex:") else {
        return Err("nonce must use hex:<24 hex chars>".into());
    };
    if hex.len() != 24 {
        return Err("AES-256-GCM nonce must be 12 bytes".into());
    }
    let mut nonce = [0_u8; 12];
    for (index, slot) in nonce.iter_mut().enumerate() {
        let start = index * 2;
        *slot = u8::from_str_radix(&hex[start..start + 2], 16)
            .map_err(|_| "nonce contains non-hex characters".to_string())?;
    }
    Ok(nonce)
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

fn transit_payload_key(key_ref: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"tessera-transit-galvofs-aes-256-gcm-v0\0");
    hasher.update(key_ref.as_bytes());
    hasher.finalize().into()
}

fn unwrap_decision_id(req: &GalvoFsUnwrapRequest, plaintext_digest: &str) -> String {
    let digest = blake3::hash(
        format!(
            "{}|{}|{}|{}",
            req.key_ref, req.ciphertext_digest, req.unwrap_profile, plaintext_digest
        )
        .as_bytes(),
    );
    format!("unwrap.{}", &digest.to_hex()[..24])
}

fn validate_request(req: &GalvoFsUnwrapRequest, ciphertext: &[u8]) -> Result<(), String> {
    if !req.key_ref.starts_with(SUPPORTED_KEY_PREFIX) {
        return Err(format!("keyRef must start with {SUPPORTED_KEY_PREFIX}"));
    }
    if req.cipher_suite != SUPPORTED_CIPHER_SUITE {
        return Err(format!("cipherSuite must be {SUPPORTED_CIPHER_SUITE}"));
    }
    if req.unwrap_profile.is_empty() {
        return Err("unwrapProfile must be non-empty".into());
    }
    if sha256_digest(ciphertext) != req.ciphertext_digest {
        return Err("ciphertextDigest does not match ciphertext".into());
    }
    Ok(())
}

async fn unwrap_galvofs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<GalvoFsUnwrapRequest>,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let scope = transit_scope();
    if let Err(e) = state.vault.authorize_scope(&token, &scope) {
        return err_response(e).into_response();
    }

    // Mandate verification (trust-plane §3.5) — after auth, before unwrap.
    let now = state.vault.clock().now_rfc3339();
    let binding = RequestBinding::from_unwrap_context(&req.context);
    let claims = match verify_mandate(
        req.mandate.as_ref(),
        TrustRoute::Unwrap,
        &binding,
        state.trust.anchors.view(),
        &state.trust.verify,
        &now,
    ) {
        Ok(MandateOutcome::Verified(c)) => Some(c),
        Ok(MandateOutcome::SkippedDev) => None,
        Err(e) => {
            state
                .vault
                .record_action(AuditOp::TransitUnwrap, &scope, &token, false);
            return mandate_err_response(&e).into_response();
        }
    };

    // One-time-use enforcement (trust-plane §4) — AFTER verify, BEFORE decrypt.
    // Burn-on-failure: the nonce is consumed here, so a later decrypt failure
    // cannot be retried to replay. Only engages on a VERIFIED mandate; the dev
    // SkippedDev path (no mandate) is unchanged. Spec's replacement-ticket
    // exception is out of scope — a burned nonce stays burned.
    if let Some(c) = &claims {
        // A verified mandate MUST carry a non-empty per-execution nonce.
        if c.idempotency_key.is_empty() {
            state
                .vault
                .record_action(AuditOp::TransitUnwrap, &scope, &token, false);
            return bad_request("mandate-invalid: certifies.idempotencyKey is empty")
                .into_response();
        }
        match state
            .vault
            .consume_nonce(&req.key_ref, &c.idempotency_key)
            .await
        {
            Ok(true) => { /* first use — proceed */ }
            Ok(false) => {
                state
                    .vault
                    .record_action(AuditOp::TransitUnwrap, &scope, &token, false);
                return replay_detected_response().into_response();
            }
            Err(e) => {
                // Ledger failure is fail-closed: do not decrypt if we cannot
                // record consumption (otherwise a replay could slip through).
                state
                    .vault
                    .record_action(AuditOp::TransitUnwrap, &scope, &token, false);
                return err_response(e).into_response();
            }
        }
    }

    let ciphertext = match STANDARD.decode(&req.ciphertext_base64) {
        Ok(bytes) => bytes,
        Err(_) => {
            state
                .vault
                .record_action(AuditOp::TransitUnwrap, &scope, &token, false);
            return bad_request("ciphertextBase64 must be valid base64").into_response();
        }
    };
    if let Err(e) = validate_request(&req, &ciphertext) {
        state
            .vault
            .record_action(AuditOp::TransitUnwrap, &scope, &token, false);
        return bad_request(e).into_response();
    }
    let nonce = match parse_nonce(&req.nonce) {
        Ok(nonce) => nonce,
        Err(e) => {
            state
                .vault
                .record_action(AuditOp::TransitUnwrap, &scope, &token, false);
            return bad_request(e).into_response();
        }
    };

    let key = transit_payload_key(&req.key_ref);
    let cipher = match Aes256Gcm::new_from_slice(&key) {
        Ok(cipher) => cipher,
        Err(error) => {
            state
                .vault
                .record_action(AuditOp::TransitUnwrap, &scope, &token, false);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "errors": [format!("failed to initialize AES-256-GCM: {error}")] })),
            )
                .into_response();
        }
    };
    let plaintext = match cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref()) {
        Ok(plaintext) => plaintext,
        Err(_) => {
            state
                .vault
                .record_action(AuditOp::TransitUnwrap, &scope, &token, false);
            return bad_request("ciphertext could not be unwrapped").into_response();
        }
    };

    let plaintext_digest = sha256_digest(&plaintext);
    let decision_id = unwrap_decision_id(&req, &plaintext_digest);
    let audit_scope = match &claims {
        Some(c) => SecretPath::new(
            scope.mount.clone(),
            format!("{}|mandate={}|keyId={}", scope.path, c.mandate_id, c.key_id),
        ),
        None => scope.clone(),
    };
    state
        .vault
        .record_action(AuditOp::TransitUnwrap, &audit_scope, &token, true);

    (
        StatusCode::OK,
        Json(json!({
            "data": {
                "provider": PROVIDER,
                "key_provider": KEY_PROVIDER,
                "key_ref": req.key_ref,
                "cipher_suite": req.cipher_suite,
                "unwrap_profile": req.unwrap_profile,
                "plaintext_base64": STANDARD.encode(&plaintext),
                "plaintext_digest": plaintext_digest,
                "decision_id": decision_id,
                "context": req.context,
                "status": "unwrapped"
            }
        })),
    )
        .into_response()
}
