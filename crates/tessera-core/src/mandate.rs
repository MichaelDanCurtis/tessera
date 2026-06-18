//! A2E ExecutionMandate verification (trust-plane Phase 1).
//!
//! Pure crypto + claim checks. Tessera is the trust decision point: before
//! issuing an SVID or unwrapping a payload, the route verifies a signed mandate
//! against a pinned trust anchor. See docs/superpowers/plans/2026-06-17-*.

use serde_json::{Map, Value};

/// Produce the canonical signing payload for a mandate: the received JSON object
/// with `signature.value` blanked to `""`, all object keys recursively sorted,
/// serialized compact (separators `,` and `:`), as UTF-8 bytes.
///
/// CONTRACT: byte-identical to Galvo's
/// `json.dumps(obj_with_blanked_sig_value, sort_keys=True, separators=(",", ":"))`.
/// We operate on the lossless `serde_json::Value` (NOT a typed re-serialization)
/// so fields Tessera does not model are preserved in the signed bytes.
pub fn canonical_signing_payload(mandate: &Value) -> Vec<u8> {
    let mut cloned = mandate.clone();
    blank_signature_value(&mut cloned);
    let sorted = sort_value(&cloned);
    // serde_json::to_string emits compact `,`/`:` separators by default.
    serde_json::to_string(&sorted)
        .expect("serde_json::Value always serializes")
        .into_bytes()
}

/// Set `["signature"]["value"]` to `""` if present; no-op otherwise.
fn blank_signature_value(v: &mut Value) {
    if let Some(sig) = v.get_mut("signature") {
        if let Some(obj) = sig.as_object_mut() {
            obj.insert("value".to_string(), Value::String(String::new()));
        }
    }
}

/// Recursively rebuild every object with keys in sorted (BTree) order. Arrays
/// keep element order; scalars are unchanged.
fn sort_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let mut out = Map::new();
            for (k, val) in sorted {
                out.insert(k.clone(), sort_value(val));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_value).collect()),
        other => other.clone(),
    }
}

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::BTreeMap;

/// Mandate verification failure, mapped to A2E error codes at the route layer:
/// Invalid -> "mandate-invalid" (400), Unverifiable -> "mandate-unverifiable"
/// (403), PolicyDenied -> "policy-denied" (403).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MandateError {
    #[error("mandate-invalid: {0}")]
    Invalid(String),
    #[error("mandate-unverifiable: {0}")]
    Unverifiable(String),
    #[error("policy-denied: {0}")]
    PolicyDenied(String),
}

impl MandateError {
    /// The A2E error code string for the route response body.
    pub fn code(&self) -> &'static str {
        match self {
            MandateError::Invalid(_) => "mandate-invalid",
            MandateError::Unverifiable(_) => "mandate-unverifiable",
            MandateError::PolicyDenied(_) => "policy-denied",
        }
    }
}

/// Read-only resolver from keyId -> 32-byte ed25519 public key. The real owning
/// type `TrustAnchors` (trust_anchors.rs) derefs/exposes this; tests build it
/// directly.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchorsView {
    keys: BTreeMap<String, [u8; 32]>,
}

impl TrustAnchorsView {
    /// Build from (keyId, base64-pubkey) pairs. A bad base64 pubkey or wrong
    /// length is a CONFIG error (caller surfaces at startup), returned as Err.
    pub fn from_pairs(pairs: &[(String, String)]) -> Result<Self, String> {
        let mut keys = BTreeMap::new();
        for (id, b64) in pairs {
            let raw = STANDARD
                .decode(b64.trim())
                .map_err(|e| format!("trust anchor {id}: bad base64: {e}"))?;
            let arr: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| format!("trust anchor {id}: pubkey must be 32 bytes"))?;
            // Validate it's a parseable ed25519 key now, not at verify time.
            VerifyingKey::from_bytes(&arr)
                .map_err(|e| format!("trust anchor {id}: invalid ed25519 pubkey: {e}"))?;
            keys.insert(id.clone(), arr);
        }
        Ok(Self { keys })
    }

    pub fn resolve(&self, key_id: &str) -> Option<[u8; 32]> {
        self.keys.get(key_id).copied()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Verify the mandate's ed25519 signature against the anchored key for its
/// `signature.keyId`. Resolves the pubkey from the anchor (NEVER from any
/// `publicKey` field inside the mandate). On success returns `Ok(())`.
pub fn verify_signature(mandate: &Value, anchors: &TrustAnchorsView) -> Result<(), MandateError> {
    let sig_obj = mandate
        .get("signature")
        .and_then(Value::as_object)
        .ok_or_else(|| MandateError::Invalid("mandate has no signature object".into()))?;

    let key_id = sig_obj
        .get("keyId")
        .and_then(Value::as_str)
        .ok_or_else(|| MandateError::Invalid("signature.keyId missing".into()))?;
    let value_b64 = sig_obj
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| MandateError::Invalid("signature.value missing".into()))?;

    let pubkey_bytes = anchors
        .resolve(key_id)
        .ok_or_else(|| MandateError::Unverifiable(format!("unknown keyId {key_id}")))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| MandateError::Unverifiable(format!("anchor key parse: {e}")))?;

    let sig_bytes = STANDARD
        .decode(value_b64)
        .map_err(|_| MandateError::Unverifiable("signature.value is not base64".into()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| MandateError::Unverifiable("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_arr);

    let payload = canonical_signing_payload(mandate);
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|_| MandateError::Unverifiable("ed25519 verification failed".into()))
}

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Identity fields from the trust request used for P1-minimal binding.
#[derive(Debug, Clone, Default)]
pub struct RequestBinding {
    pub spiffe_id: Option<String>,
    pub trust_domain: Option<String>,
}

impl RequestBinding {
    /// Extract binding identity from an unwrap request's `context` object.
    pub fn from_unwrap_context(context: &Value) -> Self {
        Self {
            spiffe_id: context
                .get("spiffeId")
                .and_then(Value::as_str)
                .map(str::to_string),
            trust_domain: context
                .get("trustDomain")
                .and_then(Value::as_str)
                .map(str::to_string),
        }
    }
}

fn parse_rfc3339(s: &str) -> Result<OffsetDateTime, MandateError> {
    OffsetDateTime::parse(s, &Rfc3339)
        .map_err(|_| MandateError::Invalid(format!("timestamp not RFC3339: {s}")))
}

/// §3.5.3 window: issuedAt <= now <= expiresAt.
pub fn check_window(mandate: &Value, now_rfc3339: &str) -> Result<(), MandateError> {
    let issued = mandate
        .get("issuedAt")
        .and_then(Value::as_str)
        .ok_or_else(|| MandateError::Invalid("issuedAt missing".into()))?;
    let expires = mandate
        .get("expiresAt")
        .and_then(Value::as_str)
        .ok_or_else(|| MandateError::Invalid("expiresAt missing".into()))?;
    let issued = parse_rfc3339(issued)?;
    let expires = parse_rfc3339(expires)?;
    let now = parse_rfc3339(now_rfc3339)?;
    if now < issued {
        return Err(MandateError::Invalid("mandate not yet valid".into()));
    }
    if now > expires {
        return Err(MandateError::Invalid("mandate expired".into()));
    }
    Ok(())
}

/// §3.5.4 audience: mandate.audience == configured audience.
pub fn check_audience(mandate: &Value, configured: &str) -> Result<(), MandateError> {
    let aud = mandate
        .get("audience")
        .and_then(Value::as_str)
        .ok_or_else(|| MandateError::Invalid("audience missing".into()))?;
    if aud == configured {
        Ok(())
    } else {
        Err(MandateError::PolicyDenied(format!(
            "audience {aud} != configured {configured}"
        )))
    }
}

fn mandate_subject(mandate: &Value) -> Result<&str, MandateError> {
    mandate
        .get("subject")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| MandateError::Invalid("subject missing/empty".into()))
}

/// §3.5.5 binding for the issue route: the requested spiffeId must equal or
/// extend the mandate subject (P1-loose). Subject must be present.
pub fn check_binding_issue(mandate: &Value, req: &RequestBinding) -> Result<(), MandateError> {
    let subject = mandate_subject(mandate)?;
    let spiffe = req
        .spiffe_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| MandateError::PolicyDenied("request spiffeId missing".into()))?;
    // Exact match or a true `/`-delimited path extension — a bare prefix
    // (`{subject}-attacker`) must NOT pass (P1 binding; deepened to structured
    // cell-eligibility in P3).
    if spiffe_within_subject(spiffe, subject) {
        Ok(())
    } else {
        Err(MandateError::PolicyDenied(format!(
            "requested spiffeId {spiffe} not within mandate subject {subject}"
        )))
    }
}

/// A request SPIFFE id is "within" a mandate subject only on exact match or a
/// genuine `/`-delimited path extension — never on a bare string prefix.
fn spiffe_within_subject(spiffe: &str, subject: &str) -> bool {
    spiffe == subject || spiffe.starts_with(&format!("{subject}/"))
}

/// §3.5.5 binding for the unwrap route: if context.spiffeId is present it must
/// equal/extend the subject; if absent, P1 permits (audience + subject already
/// enforced upstream).
pub fn check_binding_unwrap(mandate: &Value, req: &RequestBinding) -> Result<(), MandateError> {
    let subject = mandate_subject(mandate)?;
    match req.spiffe_id.as_deref().filter(|s| !s.is_empty()) {
        None => Ok(()),
        Some(spiffe) => {
            if spiffe_within_subject(spiffe, subject) {
                Ok(())
            } else {
                Err(MandateError::PolicyDenied(format!(
                    "context spiffeId {spiffe} not within mandate subject {subject}"
                )))
            }
        }
    }
}

/// Verified claims surfaced to the route for audit + downstream use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MandateClaims {
    pub mandate_id: String,
    pub key_id: String,
    pub subject: String,
    pub audience: String,
}

/// Outcome of verification. `SkippedDev` is the back-compat no-mandate path
/// allowed only when `allow_unsigned_dev`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MandateOutcome {
    Verified(MandateClaims),
    SkippedDev,
}

/// Which trust route is verifying — selects the binding rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustRoute {
    Issue,
    Unwrap,
}

/// Route-independent verification config loaded from env at startup.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    pub audience: String,
    pub allow_unsigned_dev: bool,
}

/// Run §3.5 steps 1-5 over an optional received mandate. Returns the verified
/// claims, the dev-skip marker, or the first failure mapped to a MandateError.
pub fn verify_mandate(
    mandate: Option<&Value>,
    route: TrustRoute,
    binding: &RequestBinding,
    anchors: &TrustAnchorsView,
    cfg: &VerifyConfig,
    now_rfc3339: &str,
) -> Result<MandateOutcome, MandateError> {
    // Step 1: presence.
    let mandate = match mandate {
        Some(m) => m,
        None => {
            return if cfg.allow_unsigned_dev {
                Ok(MandateOutcome::SkippedDev)
            } else {
                Err(MandateError::Invalid("mandate required in prod".into()))
            };
        }
    };

    // Step 2: signature (alg gate, anchor resolve, ed25519 verify).
    let alg = mandate
        .get("signature")
        .and_then(|s| s.get("alg"))
        .and_then(Value::as_str)
        .ok_or_else(|| MandateError::Invalid("signature.alg missing".into()))?;
    match alg {
        "ed25519" => verify_signature(mandate, anchors)?,
        "unsigned-dev" if cfg.allow_unsigned_dev => { /* dev escape hatch: skip sig */ }
        "unsigned-dev" => {
            return Err(MandateError::Unverifiable(
                "unsigned-dev mandate rejected (prod)".into(),
            ));
        }
        other => {
            return Err(MandateError::Unverifiable(format!(
                "unsupported signature alg {other}"
            )));
        }
    }

    // Step 3: window.
    check_window(mandate, now_rfc3339)?;
    // Step 4: audience.
    check_audience(mandate, &cfg.audience)?;
    // Step 5: binding.
    match route {
        TrustRoute::Issue => check_binding_issue(mandate, binding)?,
        TrustRoute::Unwrap => check_binding_unwrap(mandate, binding)?,
    }

    let claims = MandateClaims {
        mandate_id: mandate
            .get("mandateId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        key_id: mandate
            .get("signature")
            .and_then(|s| s.get("keyId"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        subject: mandate
            .get("subject")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        audience: mandate
            .get("audience")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    };
    Ok(MandateOutcome::Verified(claims))
}

#[cfg(test)]
mod canonical_tests {
    use super::canonical_signing_payload;
    use serde_json::json;

    #[test]
    fn sorts_keys_recursively_blanks_sig_value_and_is_compact() {
        // Unsorted input with a nested object + array; signature.value carries
        // a real (to-be-blanked) string. Expected bytes == what Python's
        // json.dumps(sort_keys=True, separators=(",",":")) produces with
        // signature.value blanked.
        let v = json!({
            "subject": "spiffe://femto.local/run/run-1",
            "mandateId": "m-1",
            "audience": "tessera.local",
            "scope": { "runtimeClasses": ["wasm","native"], "data": [] },
            "signature": { "value": "WILL_BE_BLANKED", "alg": "ed25519", "keyId": "arc-key-1" }
        });
        let bytes = canonical_signing_payload(&v);
        let got = String::from_utf8(bytes).unwrap();
        let expected = concat!(
            "{",
            "\"audience\":\"tessera.local\",",
            "\"mandateId\":\"m-1\",",
            "\"scope\":{\"data\":[],\"runtimeClasses\":[\"wasm\",\"native\"]},",
            "\"signature\":{\"alg\":\"ed25519\",\"keyId\":\"arc-key-1\",\"value\":\"\"},",
            "\"subject\":\"spiffe://femto.local/run/run-1\"",
            "}"
        );
        assert_eq!(got, expected);
    }

    #[test]
    fn missing_signature_object_is_tolerated() {
        // A mandate with no signature key still canonicalizes (no panic); used
        // by the unsigned-dev path where signature may be absent/minimal.
        let v = json!({ "b": 2, "a": 1 });
        let got = String::from_utf8(canonical_signing_payload(&v)).unwrap();
        assert_eq!(got, "{\"a\":1,\"b\":2}");
    }
}

#[cfg(test)]
pub(crate) mod test_fixtures {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::Value;

    /// Deterministic Arc signing key for fixtures (seed is all 0x11).
    pub const FIXTURE_SEED: [u8; 32] = [0x11; 32];
    pub const FIXTURE_KEY_ID: &str = "arc-fixture-key-1";

    pub fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&FIXTURE_SEED)
    }

    pub fn fixture_pubkey_b64() -> String {
        STANDARD.encode(signing_key().verifying_key().to_bytes())
    }

    /// A minimal-but-realistic mandate Value, unsigned (signature.value == "").
    pub fn unsigned_mandate(now_subject_audience: (&str, &str, &str)) -> Value {
        let (issued_at, subject, audience) = now_subject_audience;
        serde_json::json!({
            "mandateId": "m-fixture-1",
            "format": "a2e-execution-mandate/v0",
            "issuer": "galvo-arc",
            "subject": subject,
            "audience": audience,
            "issuedAt": issued_at,
            "expiresAt": "2999-01-01T00:00:00Z",
            "certifies": {
                "action": "execute",
                "workOrderHash": "sha256:deadbeef",
                "idempotencyKey": "idem-1"
            },
            "scope": { "data": [], "models": [], "runtimeClasses": ["wasm"] },
            "signature": { "alg": "ed25519", "value": "", "keyId": FIXTURE_KEY_ID }
        })
    }

    /// Sign a mandate Value in place: compute canonical payload, ed25519-sign,
    /// set signature.value to base64(sig).
    pub fn sign_mandate(m: &mut Value) {
        let payload = super::canonical_signing_payload(m);
        let sig = signing_key().sign(&payload);
        m["signature"]["value"] = Value::String(STANDARD.encode(sig.to_bytes()));
    }
}

#[cfg(test)]
mod sig_tests {
    use super::test_fixtures::*;
    use super::{verify_signature, MandateError, TrustAnchorsView};
    use serde_json::Value;

    fn anchors() -> Vec<(String, String)> {
        vec![(FIXTURE_KEY_ID.to_string(), fixture_pubkey_b64())]
    }

    fn signed() -> Value {
        let mut m = unsigned_mandate(("2026-06-14T00:00:00Z", "spiffe://f/run/1", "tessera.local"));
        sign_mandate(&mut m);
        m
    }

    #[test]
    fn valid_signature_passes() {
        let m = signed();
        let view = TrustAnchorsView::from_pairs(&anchors()).unwrap();
        assert!(verify_signature(&m, &view).is_ok());
    }

    #[test]
    fn tampered_payload_fails() {
        let mut m = signed();
        m["subject"] = Value::String("spiffe://f/run/EVIL".into()); // change after signing
        let view = TrustAnchorsView::from_pairs(&anchors()).unwrap();
        assert!(matches!(
            verify_signature(&m, &view),
            Err(MandateError::Unverifiable(_))
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let m = signed();
        // Anchor maps the keyId to a DIFFERENT pubkey (all-0x22 seed's pubkey).
        let bad = {
            use base64::{engine::general_purpose::STANDARD, Engine};
            use ed25519_dalek::SigningKey;
            STANDARD.encode(
                SigningKey::from_bytes(&[0x22; 32])
                    .verifying_key()
                    .to_bytes(),
            )
        };
        let view = TrustAnchorsView::from_pairs(&[(FIXTURE_KEY_ID.to_string(), bad)]).unwrap();
        assert!(matches!(
            verify_signature(&m, &view),
            Err(MandateError::Unverifiable(_))
        ));
    }

    #[test]
    fn unknown_key_id_fails() {
        let m = signed();
        let view =
            TrustAnchorsView::from_pairs(&[("some-other-key".to_string(), fixture_pubkey_b64())])
                .unwrap();
        assert!(matches!(
            verify_signature(&m, &view),
            Err(MandateError::Unverifiable(_))
        ));
    }

    #[test]
    fn malformed_base64_signature_fails() {
        let mut m = signed();
        m["signature"]["value"] = Value::String("!!!not-base64!!!".into());
        let view = TrustAnchorsView::from_pairs(&anchors()).unwrap();
        assert!(matches!(
            verify_signature(&m, &view),
            Err(MandateError::Unverifiable(_))
        ));
    }
}

#[cfg(test)]
mod claim_tests {
    use super::test_fixtures::*;
    use super::{
        check_audience, check_binding_issue, check_binding_unwrap, check_window, MandateError,
        RequestBinding,
    };
    use serde_json::{json, Value};

    fn m(issued: &str, expires: &str) -> Value {
        let mut v = unsigned_mandate((issued, "spiffe://f/run/1", "tessera.local"));
        v["expiresAt"] = Value::String(expires.into());
        v
    }

    #[test]
    fn window_accepts_now_inside() {
        let v = m("2026-06-14T00:00:00Z", "2026-06-14T01:00:00Z");
        assert!(check_window(&v, "2026-06-14T00:30:00Z").is_ok());
    }
    #[test]
    fn window_rejects_not_yet_valid() {
        let v = m("2026-06-14T02:00:00Z", "2026-06-14T03:00:00Z");
        assert!(matches!(
            check_window(&v, "2026-06-14T00:30:00Z"),
            Err(MandateError::Invalid(_))
        ));
    }
    #[test]
    fn window_rejects_expired() {
        let v = m("2026-06-14T00:00:00Z", "2026-06-14T00:10:00Z");
        assert!(matches!(
            check_window(&v, "2026-06-14T00:30:00Z"),
            Err(MandateError::Invalid(_))
        ));
    }
    #[test]
    fn window_rejects_unparseable_timestamp() {
        let v = m("not-a-date", "2026-06-14T01:00:00Z");
        assert!(matches!(
            check_window(&v, "2026-06-14T00:30:00Z"),
            Err(MandateError::Invalid(_))
        ));
    }

    #[test]
    fn audience_match_ok_mismatch_denied() {
        let v = m("2026-06-14T00:00:00Z", "2999-01-01T00:00:00Z");
        assert!(check_audience(&v, "tessera.local").is_ok());
        assert!(matches!(
            check_audience(&v, "other.domain"),
            Err(MandateError::PolicyDenied(_))
        ));
    }

    #[test]
    fn issue_binding_requires_spiffe_under_subject() {
        let v = unsigned_mandate((
            "2026-06-14T00:00:00Z",
            "spiffe://femto.local/run",
            "tessera.local",
        ));
        // requested spiffeId extends subject -> ok
        let ok = RequestBinding {
            spiffe_id: Some("spiffe://femto.local/run/run-1".into()),
            trust_domain: Some("femto.local".into()),
        };
        assert!(check_binding_issue(&v, &ok).is_ok());
        // requested spiffeId unrelated -> denied
        let bad = RequestBinding {
            spiffe_id: Some("spiffe://evil.test/x".into()),
            trust_domain: Some("evil.test".into()),
        };
        assert!(matches!(
            check_binding_issue(&v, &bad),
            Err(MandateError::PolicyDenied(_))
        ));
        // bare-prefix bypass (subject + non-`/` suffix) MUST be denied — a
        // `starts_with(subject)` check would wrongly accept this.
        let prefix_attack = RequestBinding {
            spiffe_id: Some("spiffe://femto.local/run-attacker".into()),
            trust_domain: Some("femto.local".into()),
        };
        assert!(matches!(
            check_binding_issue(&v, &prefix_attack),
            Err(MandateError::PolicyDenied(_))
        ));
        // exact-match subject is allowed
        let exact = RequestBinding {
            spiffe_id: Some("spiffe://femto.local/run".into()),
            trust_domain: Some("femto.local".into()),
        };
        assert!(check_binding_issue(&v, &exact).is_ok());
    }

    #[test]
    fn unwrap_binding_context_spiffe_must_match_subject() {
        let v = unsigned_mandate((
            "2026-06-14T00:00:00Z",
            "spiffe://femto.local/run",
            "tessera.local",
        ));
        let ctx = json!({ "spiffeId": "spiffe://femto.local/run/run-1" });
        let ok = RequestBinding::from_unwrap_context(&ctx);
        assert!(check_binding_unwrap(&v, &ok).is_ok());
        let ctx_bad = json!({ "spiffeId": "spiffe://evil/x" });
        let bad = RequestBinding::from_unwrap_context(&ctx_bad);
        assert!(matches!(
            check_binding_unwrap(&v, &bad),
            Err(MandateError::PolicyDenied(_))
        ));
        // absent spiffeId in P1 is allowed (audience + subject already enforced)
        let ctx_empty = json!({});
        let empty = RequestBinding::from_unwrap_context(&ctx_empty);
        assert!(check_binding_unwrap(&v, &empty).is_ok());
    }
}

#[cfg(test)]
mod verify_tests {
    use super::test_fixtures::*;
    use super::{
        verify_mandate, MandateError, MandateOutcome, RequestBinding, TrustAnchorsView, TrustRoute,
        VerifyConfig,
    };
    use serde_json::Value;

    fn anchors() -> TrustAnchorsView {
        TrustAnchorsView::from_pairs(&[(FIXTURE_KEY_ID.to_string(), fixture_pubkey_b64())]).unwrap()
    }
    fn cfg(allow_unsigned_dev: bool) -> VerifyConfig {
        VerifyConfig {
            audience: "tessera.local".into(),
            allow_unsigned_dev,
        }
    }
    fn signed_valid() -> Value {
        let mut m = unsigned_mandate((
            "2026-06-14T00:00:00Z",
            "spiffe://femto.local/run",
            "tessera.local",
        ));
        sign_mandate(&mut m);
        m
    }
    fn binding() -> RequestBinding {
        RequestBinding {
            spiffe_id: Some("spiffe://femto.local/run/run-1".into()),
            trust_domain: Some("femto.local".into()),
        }
    }

    #[test]
    fn valid_signed_mandate_verifies_and_returns_claims() {
        let m = signed_valid();
        let out = verify_mandate(
            Some(&m),
            TrustRoute::Issue,
            &binding(),
            &anchors(),
            &cfg(false),
            "2026-06-14T00:30:00Z",
        )
        .unwrap();
        match out {
            MandateOutcome::Verified(claims) => {
                assert_eq!(claims.mandate_id, "m-fixture-1");
                assert_eq!(claims.key_id, FIXTURE_KEY_ID);
                assert_eq!(claims.audience, "tessera.local");
            }
            _ => panic!("expected Verified"),
        }
    }

    #[test]
    fn absent_mandate_in_prod_is_invalid() {
        let err = verify_mandate(
            None,
            TrustRoute::Issue,
            &binding(),
            &anchors(),
            &cfg(false),
            "2026-06-14T00:30:00Z",
        )
        .unwrap_err();
        assert!(matches!(err, MandateError::Invalid(_)));
    }

    #[test]
    fn absent_mandate_in_dev_is_skipped() {
        let out = verify_mandate(
            None,
            TrustRoute::Issue,
            &binding(),
            &anchors(),
            &cfg(true),
            "2026-06-14T00:30:00Z",
        )
        .unwrap();
        assert!(matches!(out, MandateOutcome::SkippedDev));
    }

    #[test]
    fn unsigned_dev_alg_rejected_in_prod() {
        let mut m = signed_valid();
        m["signature"]["alg"] = Value::String("unsigned-dev".into());
        m["signature"]["value"] = Value::String(String::new());
        let err = verify_mandate(
            Some(&m),
            TrustRoute::Issue,
            &binding(),
            &anchors(),
            &cfg(false),
            "2026-06-14T00:30:00Z",
        )
        .unwrap_err();
        assert!(matches!(err, MandateError::Unverifiable(_)));
    }

    #[test]
    fn unsigned_dev_alg_accepted_in_dev() {
        let mut m = unsigned_mandate((
            "2026-06-14T00:00:00Z",
            "spiffe://femto.local/run",
            "tessera.local",
        ));
        m["signature"]["alg"] = Value::String("unsigned-dev".into());
        let out = verify_mandate(
            Some(&m),
            TrustRoute::Issue,
            &binding(),
            &anchors(),
            &cfg(true),
            "2026-06-14T00:30:00Z",
        )
        .unwrap();
        assert!(matches!(out, MandateOutcome::Verified(_)));
    }

    #[test]
    fn expired_signed_mandate_is_invalid() {
        let mut m = unsigned_mandate((
            "2026-06-14T00:00:00Z",
            "spiffe://femto.local/run",
            "tessera.local",
        ));
        m["expiresAt"] = Value::String("2026-06-14T00:10:00Z".into());
        sign_mandate(&mut m);
        let err = verify_mandate(
            Some(&m),
            TrustRoute::Issue,
            &binding(),
            &anchors(),
            &cfg(false),
            "2026-06-14T00:30:00Z",
        )
        .unwrap_err();
        assert!(matches!(err, MandateError::Invalid(_)));
    }
}

#[cfg(test)]
mod build_smoke {
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

    #[test]
    fn ed25519_dalek_roundtrips() {
        let seed = [7u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk: VerifyingKey = sk.verifying_key();
        let msg = b"tessera-mandate-smoke";
        let sig = sk.sign(msg);
        assert!(vk.verify_strict(msg, &sig).is_ok());
    }
}
