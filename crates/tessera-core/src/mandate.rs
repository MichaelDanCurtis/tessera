//! A2E ExecutionMandate verification (trust-plane Phase 1).
//!
//! Pure crypto + claim checks. Tessera is the trust decision point: before
//! issuing an SVID or unwrapping a payload, the route verifies a signed mandate
//! against a pinned trust anchor. See docs/superpowers/plans/2026-06-17-*.

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
