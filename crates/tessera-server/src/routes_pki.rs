use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use rcgen::{CertificateParams, DistinguishedName, DnType, Ia5String, KeyPair, SanType};
use serde::Deserialize;
use serde_json::{json, Value};
use tessera_core::audit::AuditOp;
use tessera_core::mandate::{
    verify_mandate, MandateError, MandateOutcome, RequestBinding, TrustRoute,
};
use tessera_core::types::{SecretPath, TesseraError};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::app::AppState;

const DEFAULT_TTL_SECONDS: i64 = 3600;
const MAX_TTL_SECONDS: i64 = 86_400;
const ISSUER: &str = "tessera-spiffe-local-ca";
const PROVIDER: &str = "tessera";

#[derive(Debug, Deserialize)]
struct SpiffeIssueRequest {
    #[serde(rename = "trustDomain")]
    trust_domain: String,
    #[serde(rename = "spiffeId")]
    spiffe_id: String,
    #[serde(rename = "ttlSeconds")]
    ttl_seconds: Option<i64>,
    profile: Option<String>,
    #[serde(default)]
    mandate: Option<Value>,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/pki/spiffe/issue", post(issue_spiffe))
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

fn pki_scope() -> SecretPath {
    SecretPath::new("pki", "spiffe/issue")
}

fn validate_trust_domain(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 253 {
        return Err("trustDomain must be a non-empty DNS trust domain".into());
    }
    let valid = value.split('.').all(|part| {
        !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if valid {
        Ok(())
    } else {
        Err("trustDomain must be a non-empty DNS trust domain".into())
    }
}

fn validate_spiffe(req: &SpiffeIssueRequest) -> Result<(), String> {
    validate_trust_domain(&req.trust_domain)?;
    let expected_prefix = format!("spiffe://{}/", req.trust_domain);
    if !req.spiffe_id.starts_with(&expected_prefix) {
        return Err(format!(
            "spiffeId must be inside trustDomain {}",
            req.trust_domain
        ));
    }
    let path = &req.spiffe_id[expected_prefix.len()..];
    if path.is_empty() || path.contains('?') || path.contains('#') || path.contains(' ') {
        return Err("spiffeId must include a non-empty URI path without query or fragment".into());
    }
    let ttl = req.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    if !(1..=MAX_TTL_SECONDS).contains(&ttl) {
        return Err(format!(
            "ttlSeconds must be between 1 and {MAX_TTL_SECONDS}"
        ));
    }
    Ok(())
}

fn parse_now(now: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(now, &Rfc3339).map_err(|_| "vault clock must emit RFC3339".to_string())
}

fn issued_serial(spiffe_id: &str, not_before: &str, not_after: &str) -> String {
    let digest = blake3::hash(format!("{spiffe_id}|{not_before}|{not_after}").as_bytes());
    format!("svid.{}", &digest.to_hex()[..24])
}

fn issue_certificate(
    req: &SpiffeIssueRequest,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<(String, String), String> {
    let mut params = CertificateParams::default();
    params.not_before = not_before;
    params.not_after = not_after;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, req.spiffe_id.clone());
    params.subject_alt_names = vec![SanType::URI(
        Ia5String::try_from(req.spiffe_id.clone()).map_err(|e| format!("spiffe uri: {e}"))?,
    )];

    let key_pair = KeyPair::generate().map_err(|e| format!("certificate key: {e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("certificate issue: {e}"))?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

async fn issue_spiffe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SpiffeIssueRequest>,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let scope = pki_scope();
    if let Err(e) = state.vault.authorize_scope(&token, &scope) {
        return err_response(e).into_response();
    }

    // Mandate verification (trust-plane §3.5) — after auth, before issuance.
    let now = state.vault.clock().now_rfc3339();
    let binding = RequestBinding {
        spiffe_id: Some(req.spiffe_id.clone()),
        trust_domain: Some(req.trust_domain.clone()),
    };
    let claims = match verify_mandate(
        req.mandate.as_ref(),
        TrustRoute::Issue,
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
                .record_action(AuditOp::IssueCertificate, &scope, &token, false);
            return mandate_err_response(&e).into_response();
        }
    };

    if let Err(e) = validate_spiffe(&req) {
        state
            .vault
            .record_action(AuditOp::IssueCertificate, &scope, &token, false);
        return bad_request(e).into_response();
    }

    let not_before = state.vault.clock().now_rfc3339();
    let ttl = req.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    let not_before_dt = match parse_now(&not_before) {
        Ok(v) => v,
        Err(e) => {
            state
                .vault
                .record_action(AuditOp::IssueCertificate, &scope, &token, false);
            return bad_request(e).into_response();
        }
    };
    let not_after_dt = not_before_dt + Duration::seconds(ttl);
    let not_after = not_after_dt
        .format(&Rfc3339)
        .unwrap_or_else(|_| not_before.clone());

    let (certificate_pem, private_key_pem) =
        match issue_certificate(&req, not_before_dt, not_after_dt) {
            Ok(v) => v,
            Err(e) => {
                state
                    .vault
                    .record_action(AuditOp::IssueCertificate, &scope, &token, false);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "errors": [e] })),
                )
                    .into_response();
            }
        };
    let certificate_serial = issued_serial(&req.spiffe_id, &not_before, &not_after);
    let audit_scope = match &claims {
        Some(c) => SecretPath::new(
            scope.mount.clone(),
            format!("{}|mandate={}|keyId={}", scope.path, c.mandate_id, c.key_id),
        ),
        None => scope.clone(),
    };
    state
        .vault
        .record_action(AuditOp::IssueCertificate, &audit_scope, &token, true);

    (
        StatusCode::OK,
        Json(json!({
            "data": {
                "provider": PROVIDER,
                "issuer": ISSUER,
                "trust_domain": req.trust_domain,
                "spiffe_id": req.spiffe_id,
                "certificate_profile": req.profile.unwrap_or_else(|| "spiffe-svid-v0".to_string()),
                "certificate_serial": certificate_serial,
                "decision_id": certificate_serial,
                "not_before": not_before,
                "not_after": not_after,
                "certificate_pem": certificate_pem,
                "private_key_pem": private_key_pem,
                "status": "issued"
            }
        })),
    )
        .into_response()
}
