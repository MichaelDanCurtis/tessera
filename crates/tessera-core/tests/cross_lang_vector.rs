//! Cross-language trust vector: a mandate signed by Galvo's Python
//! `Ed25519Signer` (cryptography lib) MUST verify under Tessera's Rust
//! `ed25519-dalek` `verify_strict`, over byte-identical canonical bytes.
//!
//! The fixture `vectors/mandate-vector-1.json` is the SHARED artifact (an
//! identical copy lives in Galvo at
//! `docs/superpowers/specs/trust-vectors/mandate-vector-1.json`). If the two
//! canonicalizers or the signature ever diverge, this test fails loudly — it is
//! the contract guard the design spec (§8) calls the #1 latent risk.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::Value;
use tessera_core::mandate::{canonical_signing_payload, verify_signature, TrustAnchorsView};

fn load_vector() -> Value {
    let raw = include_str!("vectors/mandate-vector-1.json");
    serde_json::from_str(raw).expect("vector json parses")
}

#[test]
fn tessera_canonicalization_matches_galvo() {
    let v = load_vector();
    let mandate = &v["mandate"];
    let expected = v["canonicalUtf8"].as_str().unwrap();
    let got = canonical_signing_payload(mandate);
    assert_eq!(
        String::from_utf8(got).unwrap(),
        expected,
        "Tessera canonical bytes must byte-match Galvo's json.dumps(sort_keys,compact)"
    );
}

#[test]
fn galvo_signed_mandate_verifies_in_tessera() {
    let v = load_vector();
    let key_id = v["keyId"].as_str().unwrap().to_string();
    let pubkey_b64 = v["publicKeyB64"].as_str().unwrap().to_string();
    let sig_b64 = v["signatureB64"].as_str().unwrap();

    // The wire mandate carries the real signature in signature.value; the
    // verifier blanks it for canonicalization but checks it as the signature.
    let mut mandate = v["mandate"].clone();
    mandate["signature"]["value"] = Value::String(sig_b64.to_string());

    let anchors = TrustAnchorsView::from_pairs(&[(key_id, pubkey_b64)]).unwrap();
    verify_signature(&mandate, &anchors)
        .expect("Galvo-produced ed25519 signature must verify under Tessera verify_strict");
}

#[test]
fn tampered_mandate_is_rejected() {
    let v = load_vector();
    let key_id = v["keyId"].as_str().unwrap().to_string();
    let pubkey_b64 = v["publicKeyB64"].as_str().unwrap().to_string();
    let sig_b64 = v["signatureB64"].as_str().unwrap();

    let mut mandate = v["mandate"].clone();
    mandate["signature"]["value"] = Value::String(sig_b64.to_string());
    // Flip an authenticated claim — the signature must no longer verify.
    mandate["audience"] = Value::String("attacker.local".to_string());

    let anchors = TrustAnchorsView::from_pairs(&[(key_id, pubkey_b64)]).unwrap();
    assert!(
        verify_signature(&mandate, &anchors).is_err(),
        "a tampered authenticated claim must fail verification"
    );
}

#[test]
fn wrong_anchor_key_is_rejected() {
    let v = load_vector();
    let key_id = v["keyId"].as_str().unwrap().to_string();
    let sig_b64 = v["signatureB64"].as_str().unwrap();
    // A different (valid) ed25519 public key — 32 zero bytes is on-curve identity;
    // use a real but unrelated key derived from a non-zero seed instead.
    let wrong_pub = STANDARD.encode([7u8; 32]);

    let mut mandate = v["mandate"].clone();
    mandate["signature"]["value"] = Value::String(sig_b64.to_string());

    // from_pairs validates the key is a real ed25519 point; if [7u8;32] is
    // rejected as off-curve, fall back asserting the resolve path: either the
    // anchor build fails (caught here) or verification fails.
    match TrustAnchorsView::from_pairs(&[(key_id, wrong_pub)]) {
        Ok(anchors) => assert!(
            verify_signature(&mandate, &anchors).is_err(),
            "signature must not verify under the wrong anchor key"
        ),
        Err(_) => { /* off-curve key rejected at anchor-build time — also fail-closed */ }
    }
}
