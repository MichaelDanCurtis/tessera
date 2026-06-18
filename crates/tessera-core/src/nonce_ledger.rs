//! One-time unwrap nonce ledger (trust-plane Phase 2). Pure helpers: derive the
//! durable ledger entry id from `(keyRef, idempotencyKey)` and build the reserved
//! `SecretPath` it lives at. The atomic check-and-insert is `SecretEngine::
//! put_if_absent`; the route enforcement + audit live in tessera-server. See
//! docs/superpowers/specs/2026-06-17-trust-plane-enforcer-design.md §4.

use crate::types::SecretPath;

/// Reserved internal mount for the ledger — NOT a KV/transit scope, so no caller
/// token can reach it (KV/transit policies never grant this mount). See the plan
/// §1.3 reachability note + R3 mount-collision check.
///
/// R3 RESOLVED: the literal mount `sys` is rejected by RustyVault as a protected
/// internal system backend ("Mount path is protected, cannot mount"), so the
/// ledger uses `tessera-sys` — a distinct, non-reserved namespace no KV/transit
/// policy grants.
pub const NONCE_LEDGER_MOUNT: &str = "tessera-sys";
/// Path prefix under the reserved mount.
pub const NONCE_LEDGER_PREFIX: &str = "a2e-nonce-ledger";

/// Derive the durable ledger entry id from the unwrap `keyRef` and the mandate's
/// per-execution `idempotencyKey` (the consume nonce). `blake3(keyRef || 0x00 ||
/// idempotencyKey)` as lowercase hex (64 chars) — domain-separated by the NUL so
/// `(a, bc)` and `(ab, c)` cannot collide.
pub fn ledger_entry_id(key_ref: &str, idempotency_key: &str) -> String {
    let mut buf = Vec::with_capacity(key_ref.len() + 1 + idempotency_key.len());
    buf.extend_from_slice(key_ref.as_bytes());
    buf.push(0u8);
    buf.extend_from_slice(idempotency_key.as_bytes());
    blake3::hash(&buf).to_hex().to_string()
}

/// The reserved `SecretPath` for a ledger entry id.
pub fn ledger_path(id: &str) -> SecretPath {
    SecretPath::new(NONCE_LEDGER_MOUNT, format!("{NONCE_LEDGER_PREFIX}/{id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_64_hex_chars_and_deterministic() {
        let a = ledger_entry_id("tessera://transit/galvofs/cap", "idem-1");
        let b = ledger_entry_id("tessera://transit/galvofs/cap", "idem-1");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_key_ref_or_nonce_changes_id() {
        let base = ledger_entry_id("cap-A", "idem-1");
        assert_ne!(base, ledger_entry_id("cap-B", "idem-1"));
        assert_ne!(base, ledger_entry_id("cap-A", "idem-2"));
    }

    #[test]
    fn nul_domain_separation_prevents_boundary_collision() {
        // ("ab","c") must NOT hash equal to ("a","bc").
        assert_ne!(ledger_entry_id("ab", "c"), ledger_entry_id("a", "bc"));
    }

    #[test]
    fn ledger_path_is_under_reserved_sys_mount() {
        let p = ledger_path("deadbeef");
        assert_eq!(p.mount, "tessera-sys");
        assert_eq!(p.scope(), "tessera-sys/a2e-nonce-ledger/deadbeef");
    }
}
