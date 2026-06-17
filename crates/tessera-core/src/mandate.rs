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
