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
