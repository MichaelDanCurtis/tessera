# Plan: Tessera Mandate-Verification Core (Trust Plane Phase 1)

**Date:** 2026-06-17
**Spec:** `../../../../Galvo/docs/superpowers/specs/2026-06-17-trust-plane-enforcer-design.md` (§3 crypto contract, §6 Phase 1, §8 testing). Implements §3.5 verification exactly.
**Repo:** `tessera` (this repo). Base branch: `codex/transit-unwrap-api` @ `e646c15`.
**Scope:** PURE Tessera-side Rust. No Galvo/Femto dependency. Fixtures are static signed vectors generated in-Rust from a known ed25519 seed. The one-time unwrap **ledger** (replay) is **Phase 2** and is explicitly OUT of scope here.

---

## Pre-flight (executor: do this first, do NOT skip)

The executor works on a **fresh branch off `codex/transit-unwrap-api`** — never commit to that branch directly (§9 of the spec). All `cargo` commands run from the repo root `/Volumes/Main External/Development/lucidity/tessera`.

```bash
cd "/Volumes/Main External/Development/lucidity/tessera"
git fetch --all
git status                       # MUST be clean before branching
git rev-parse --abbrev-ref HEAD  # expect: codex/transit-unwrap-api
git rev-parse HEAD               # expect e646c15 (or a fast-forward descendant — if newer, note it and continue)
git switch -c trust-plane/p1-mandate-verification
```

Confirm the green baseline before touching anything:

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

Expected: all pass. `cargo fmt --all -- --check` prints nothing and exits 0. **`fmt` is a SEPARATE gate** — a green `clippy` + `test` does NOT imply `fmt` is clean. Run all three after every task, and run `cargo fmt --all` (no `--check`) to auto-fix before the final gate task.

---

## Grounding facts (verified against the live repo — do not re-derive)

- **Crates:** `crates/tessera-core` (lib: `audit auth clock engine persist rusty_engine seal types vault`) and `crates/tessera-server` (lib `tessera_server` + bin). Edition **2021** (workspace `[workspace.package] edition = "2021"`), NOT 2024.
- **Deps already present in `tessera-core/Cargo.toml`:** `serde`, `serde_json`, `thiserror`, `blake3`, `base64 = "0.22.1"`, `sha2 = "0.10"`, `rand = "0.8"`, `tokio`. **`time` is NOT a direct dep of tessera-core** — it's only in `tessera-server`. We need RFC3339 window parsing in **core**, so add `time` to `tessera-core` (workspace dep already pins `time = { version = "0.3", features = ["formatting","parsing"] }`).
- **`ed25519-dalek` is absent everywhere** (grep for `ed25519`/`VerifyingKey`/`sort_keys`/`canonical`/`sort_json` returns ZERO hits). No existing canonical-JSON helper. This plan introduces both.
- **`AppState`** (`tessera-server/src/app.rs`) is `{ pub vault: Arc<VaultStore> }` and is `#[derive(Clone)]`. `router(state)` merges `routes_sys / routes_kv / routes_pki / routes_transit`. We will add a second field to `AppState` for trust config.
- **Route auth + audit pattern** (both `routes_pki.rs` and `routes_transit.rs`): `token_of(&headers)` → `state.vault.authorize_scope(&token, &scope)` (returns `Result<(), TesseraError>`, audits `AuthFailure` on denial) → work → `state.vault.record_action(AuditOp::IssueCertificate|TransitUnwrap, &scope, &token, outcome)`.
- **`err_response(e: TesseraError)`** maps a FIXED enum to HTTP and emits `{"errors":[<string>]}`. It does NOT carry an A2E error-code string. The spec's mandate error codes (`mandate-invalid` / `mandate-unverifiable` / `policy-denied`) are NEW and don't fit `TesseraError`. **Decision:** add a small local `mandate_err_response(code: &str, status, msg)` helper in each route file that emits the SAME body shape `{"errors":[msg], "code": code}` — additive, never touches `TesseraError`. HTTP status mapping: `mandate-invalid`→400, `mandate-unverifiable`→403, `policy-denied`→403.
- **`AuditRecord`** (`tessera-core/src/audit.rs`) is a fixed struct `{op, scope, token_hash, outcome, timestamp, reveal}` — no free-form field for `mandateId`/`keyId`. **Decision (P1-pragmatic):** the spec (§3.5.6) asks to "record the mandate `mandateId`/`keyId` in the audit record." Rather than widen the persisted `AuditRecord` schema (a migration risk, out of P1 scope), fold the mandate identity into the audited **scope string** suffix on success/denial: `format!("{scope}|mandate={mandateId}|keyId={keyId}")`. This keeps the existing `record_action` signature and is observable in the audit log. (A structured audit field is a documented Phase-2/later refinement.)
- **Test harness:** server route tests live in `crates/tessera-server/tests/*.rs` and spin a live server via `serve()` (binds `127.0.0.1:0`, `axum::serve(listener, router(state))`) + `reqwest`. `transit_unwrap.rs` and `pki_spiffe.rs` are the templates. `transit_state()` / a `pki` equivalent build `AppState` with `InMemoryEngine` + `FixedClock("2026-06-14T00:00:00Z")`. The new `AppState` field means EVERY existing `AppState { vault: ... }` literal in tests + `main.rs` must gain the new field — grep the whole workspace (`rg "AppState \{"`), this is a **cross-crate** change (a `cargo test -p tessera-server` alone would miss a stray literal; `--workspace` is mandatory).
- **`FixedClock(pub String)`** + `state.vault.clock().now_rfc3339()` give the "now" used by issue/unwrap. Window checks reuse this.

---

## Design contract (pin these exactly — they are the cross-language contract)

### Canonicalization (`canonical_signing_payload`)
Must produce **byte-identical** output to Galvo's `json.dumps(obj, sort_keys=True, separators=(",", ":"))` over the camelCase wire object with `signature.value` set to `""`. Rules:
1. Parse the received mandate as `serde_json::Value` (**lossless** — do NOT round-trip through a typed struct; Tessera must re-serialize the WHOLE received object so it never drops fields it doesn't model).
2. Clone the Value; set `["signature"]["value"] = Value::String("")`. Leave `signature.alg`/`signature.keyId` and every other field intact.
3. Recursively sort all object keys (Objects → `BTreeMap`-ordered by key; arrays keep order; scalars unchanged).
4. Serialize compact: no spaces, separators `,` and `:`. `serde_json::to_string` on a `Value` built from `serde_json::Map` is NOT guaranteed sorted (the `Map` is insertion-ordered unless `preserve_order` is off — and `serde_json` default Map IS `BTreeMap` only when the `preserve_order` feature is OFF). **Do not rely on that.** Implement an explicit recursive sorter that rebuilds each object as a freshly key-sorted `serde_json::Map<String, Value>` and serialize with `serde_json::to_string` (which emits compact `,`/`:` by default — verify in the test).
5. Return UTF-8 bytes (`String::into_bytes`).

> NOTE on number/escaping fidelity: Galvo signs over `model_dump(by_alias=True, exclude_none=True)` then `json.dumps`. Phase 1 fixtures are generated in-Rust, so the Rust canonicalizer defines the bytes here; the **cross-language** equality (Galvo bytes == Tessera bytes) is pinned in **Phase 3**, not this plan. We still hard-code an expected canonical string in a unit test so a regression in the sorter is caught immediately, and we keep the fixture mandate's values ASCII + integer-free-where-ambiguous to avoid float/Unicode-escape divergence surprises later.

### Signature object (§3.2)
`signature = { "alg": "ed25519", "value": <base64(64-byte sig)>, "keyId": "<arc-key-id>" }`. The verifier resolves the pubkey from `keyId` via the trust anchor map — it NEVER trusts a `publicKey` shipped inside the mandate. `alg = "unsigned-dev"` with empty `value` is valid ONLY when `allow_unsigned_dev == true`.

### Trust anchor (§3.3)
`keyId → 32-byte ed25519 public key`. Env `TESSERA_ARC_TRUST_ANCHORS` = comma-separated `keyId:base64pubkey`. Unknown `keyId` → reject (`mandate-unverifiable`).

### Verification steps (§3.5 — implement in this order)
1. **Presence:** `mandate` absent → if `allow_unsigned_dev` skip enforcement (back-compat, return `Ok(MandateOutcome::SkippedDev)`); else `mandate-invalid`.
2. **Signature:** `alg` must be `ed25519` in prod (`unsigned-dev` only when `allow_unsigned_dev`). Resolve `keyId` → anchored pubkey (unknown → `mandate-unverifiable`). ed25519-verify over `SIGNING_PAYLOAD = canonical_signing_payload(value)`. Bad sig → `mandate-unverifiable`. Malformed base64 (sig or anchor) → `mandate-unverifiable`.
3. **Window:** `issuedAt <= now <= expiresAt` (RFC3339, parsed via `time`). not-yet / expired / unparseable timestamp → `mandate-invalid`.
4. **Audience:** `mandate.audience == configured audience`. Mismatch → `policy-denied`.
5. **Binding (P1-minimal):** request identity is consistent with the mandate. For **issue**: requested `spiffeId` must start with the mandate `subject` OR `subject` must be non-empty and the requested `trustDomain` consistent (P1 loose: require `subject` present AND `audience` matched — already done — AND requested `spiffeId` not empty). For **unwrap**: if `context.spiffeId` present it must equal/extend the mandate `subject`; if absent in P1, presence of a matched audience + non-empty `subject` suffices. Mismatch → `policy-denied`.
6. On success return verified `MandateClaims { mandate_id, key_id, subject, audience }`.

---

## Tasks (TDD, green-leaving order)

Each task: write the failing test(s) FIRST, then the implementation, then run the three gates. Every code block below is COMPLETE (no `todo!()`/placeholders). Commit after each task with a scoped message.

---

### Task 1 — Add `ed25519-dalek` + `time` to `tessera-core`; confirm it builds

**Why:** core needs ed25519 verification and RFC3339 parsing. `base64` is already present (`0.22.1`); `serde_json`/`sha2`/`blake3` present; `time` is NOT a core dep yet (only server). Add both.

**Edit `crates/tessera-core/Cargo.toml`** — under `[dependencies]`, after the `rand = "0.8"` line add:

```toml
# ed25519 signature verification for A2E ExecutionMandate trust-plane (Phase 1).
# v2.x API: VerifyingKey::from_bytes(&[u8;32]) + verify_strict(msg, &Signature).
# default-features keeps `std`; we only need verification (no signing in prod core).
ed25519-dalek = "2"
# RFC3339 window checks (issuedAt <= now <= expiresAt) in mandate.rs. Workspace
# pin already carries formatting+parsing features.
time = { workspace = true }
```

Add a `[dev-dependencies]` entry for deterministic in-test signing (generate fixtures from a known seed). `ed25519-dalek` v2 `SigningKey` is gated, but the base crate exposes it; add `rand` is already a normal dep. We sign in tests using `SigningKey::from_bytes(&[u8;32])` (deterministic from a fixed seed) — this is available in the default feature set, so no extra dev-dep is required. (If a compile error says `SigningKey` needs a feature, add `ed25519-dalek = { version = "2", features = ["rand_core"] }` to dev-deps — but try the plain dep first.)

**Verify build + a trivial smoke.** Add a throwaway test to `crates/tessera-core/src/lib.rs` temporarily? No — instead create the real module file early with one smoke test. Create `crates/tessera-core/src/mandate.rs`:

```rust
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
```

Register the module — **Edit `crates/tessera-core/src/lib.rs`**, add `pub mod mandate;` in alphabetical position (after `pub mod engine;`, before `pub mod persist;`):

```rust
pub mod engine;
pub mod mandate;
pub mod persist;
```

**Gate:**
```bash
cargo test -p tessera-core mandate::build_smoke    # expect: 1 passed
cargo build --workspace
cargo fmt --all -- --check
```
Expected: the smoke test passes (proves `ed25519-dalek` resolves and links). Commit: `chore(core): add ed25519-dalek + time deps, scaffold mandate module`.

---

### Task 2 — `canonical_signing_payload` (lossless sort-keys + compact serialize)

**Write the test FIRST** in `crates/tessera-core/src/mandate.rs` (`#[cfg(test)] mod canonical_tests`):

```rust
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
```

**Then implement** in `mandate.rs` (above the test modules):

```rust
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
```

**Gate:**
```bash
cargo test -p tessera-core mandate::canonical_tests
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```
Expected: both canonical tests pass byte-exact. If `expected` mismatches, the sorter or separators are wrong — fix the impl, not the expectation. Commit: `feat(core): canonical_signing_payload for mandate ed25519 contract`.

---

### Task 3 — ed25519 signature verification + the `MandateError` type

**Test FIRST** — add a `#[cfg(test)] mod sig_tests` to `mandate.rs`. It needs an in-Rust fixture signer (deterministic seed). Put a `#[cfg(test)]` helper in the module:

```rust
#[cfg(test)]
pub(crate) mod test_fixtures {
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::Value;
    use base64::{engine::general_purpose::STANDARD, Engine};

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
            "signature": { "alg": "ed25519", "value": "", "keyId": super::FIXTURE_KEY_ID }
        })
    }

    /// Sign a mandate Value in place: compute canonical payload, ed25519-sign,
    /// set signature.value to base64(sig).
    pub fn sign_mandate(m: &mut Value) {
        let payload = super::super::canonical_signing_payload(m);
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
        assert!(matches!(verify_signature(&m, &view), Err(MandateError::Unverifiable(_))));
    }

    #[test]
    fn wrong_key_fails() {
        let m = signed();
        // Anchor maps the keyId to a DIFFERENT pubkey (all-0x22 seed's pubkey).
        let bad = {
            use ed25519_dalek::SigningKey;
            use base64::{engine::general_purpose::STANDARD, Engine};
            STANDARD.encode(SigningKey::from_bytes(&[0x22; 32]).verifying_key().to_bytes())
        };
        let view = TrustAnchorsView::from_pairs(&[(FIXTURE_KEY_ID.to_string(), bad)]).unwrap();
        assert!(matches!(verify_signature(&m, &view), Err(MandateError::Unverifiable(_))));
    }

    #[test]
    fn unknown_key_id_fails() {
        let m = signed();
        let view = TrustAnchorsView::from_pairs(&[("some-other-key".to_string(), fixture_pubkey_b64())]).unwrap();
        assert!(matches!(verify_signature(&m, &view), Err(MandateError::Unverifiable(_))));
    }

    #[test]
    fn malformed_base64_signature_fails() {
        let mut m = signed();
        m["signature"]["value"] = Value::String("!!!not-base64!!!".into());
        let view = TrustAnchorsView::from_pairs(&anchors()).unwrap();
        assert!(matches!(verify_signature(&m, &view), Err(MandateError::Unverifiable(_))));
    }
}
```

**Then implement.** Add the error type, a borrow-only anchors view (the real `TrustAnchors` type lands in Task 6; here we add a minimal `TrustAnchorsView` resolver interface so signature verification is testable in isolation), and `verify_signature`. In `mandate.rs`:

```rust
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
/// type `TrustAnchors` (Task 6) derefs/exposes this; tests build it directly.
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
```

**Gate:**
```bash
cargo test -p tessera-core mandate::sig_tests
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```
Expected: all 5 sig tests pass. Commit: `feat(core): ed25519 mandate signature verification + MandateError`.

---

### Task 4 — Window + audience + P1-minimal binding checks

**Test FIRST** — `#[cfg(test)] mod claim_tests` in `mandate.rs`:

```rust
#[cfg(test)]
mod claim_tests {
    use super::test_fixtures::*;
    use super::{check_audience, check_binding_issue, check_binding_unwrap, check_window, MandateError, RequestBinding};
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
        assert!(matches!(check_window(&v, "2026-06-14T00:30:00Z"), Err(MandateError::Invalid(_))));
    }
    #[test]
    fn window_rejects_expired() {
        let v = m("2026-06-14T00:00:00Z", "2026-06-14T00:10:00Z");
        assert!(matches!(check_window(&v, "2026-06-14T00:30:00Z"), Err(MandateError::Invalid(_))));
    }
    #[test]
    fn window_rejects_unparseable_timestamp() {
        let v = m("not-a-date", "2026-06-14T01:00:00Z");
        assert!(matches!(check_window(&v, "2026-06-14T00:30:00Z"), Err(MandateError::Invalid(_))));
    }

    #[test]
    fn audience_match_ok_mismatch_denied() {
        let v = m("2026-06-14T00:00:00Z", "2999-01-01T00:00:00Z");
        assert!(check_audience(&v, "tessera.local").is_ok());
        assert!(matches!(check_audience(&v, "other.domain"), Err(MandateError::PolicyDenied(_))));
    }

    #[test]
    fn issue_binding_requires_spiffe_under_subject() {
        let v = unsigned_mandate(("2026-06-14T00:00:00Z", "spiffe://femto.local/run", "tessera.local"));
        // requested spiffeId extends subject -> ok
        let ok = RequestBinding { spiffe_id: Some("spiffe://femto.local/run/run-1".into()), trust_domain: Some("femto.local".into()) };
        assert!(check_binding_issue(&v, &ok).is_ok());
        // requested spiffeId unrelated -> denied
        let bad = RequestBinding { spiffe_id: Some("spiffe://evil.test/x".into()), trust_domain: Some("evil.test".into()) };
        assert!(matches!(check_binding_issue(&v, &bad), Err(MandateError::PolicyDenied(_))));
    }

    #[test]
    fn unwrap_binding_context_spiffe_must_match_subject() {
        let v = unsigned_mandate(("2026-06-14T00:00:00Z", "spiffe://femto.local/run", "tessera.local"));
        let ctx = json!({ "spiffeId": "spiffe://femto.local/run/run-1" });
        let ok = RequestBinding::from_unwrap_context(&ctx);
        assert!(check_binding_unwrap(&v, &ok).is_ok());
        let ctx_bad = json!({ "spiffeId": "spiffe://evil/x" });
        let bad = RequestBinding::from_unwrap_context(&ctx_bad);
        assert!(matches!(check_binding_unwrap(&v, &bad), Err(MandateError::PolicyDenied(_))));
        // absent spiffeId in P1 is allowed (audience + subject already enforced)
        let ctx_empty = json!({});
        let empty = RequestBinding::from_unwrap_context(&ctx_empty);
        assert!(check_binding_unwrap(&v, &empty).is_ok());
    }
}
```

**Then implement** in `mandate.rs`:

```rust
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
            spiffe_id: context.get("spiffeId").and_then(Value::as_str).map(str::to_string),
            trust_domain: context.get("trustDomain").and_then(Value::as_str).map(str::to_string),
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
    if spiffe == subject || spiffe.starts_with(&format!("{subject}/")) || spiffe.starts_with(subject) {
        Ok(())
    } else {
        Err(MandateError::PolicyDenied(format!(
            "requested spiffeId {spiffe} not within mandate subject {subject}"
        )))
    }
}

/// §3.5.5 binding for the unwrap route: if context.spiffeId is present it must
/// equal/extend the subject; if absent, P1 permits (audience + subject already
/// enforced upstream).
pub fn check_binding_unwrap(mandate: &Value, req: &RequestBinding) -> Result<(), MandateError> {
    let subject = mandate_subject(mandate)?;
    match req.spiffe_id.as_deref().filter(|s| !s.is_empty()) {
        None => Ok(()),
        Some(spiffe) => {
            if spiffe == subject || spiffe.starts_with(subject) {
                Ok(())
            } else {
                Err(MandateError::PolicyDenied(format!(
                    "context spiffeId {spiffe} not within mandate subject {subject}"
                )))
            }
        }
    }
}
```

> NOTE on `starts_with(subject)`: P1 is intentionally loose (§3.5 "Loose in P1"). The `starts_with` covers subject-prefix SPIFFE paths; P3 deepens this to structured cell-eligibility. Keep the redundant `==`/`/`-suffix/`starts_with` chain readable — clippy may suggest collapsing; if so, collapse to the single `starts_with(subject)` plus an explicit comment, since a bare `starts_with` already covers equality and `/`-extension. (Pick whichever clippy accepts under `-D warnings`; behavior is identical for the test vectors.)

**Gate:**
```bash
cargo test -p tessera-core mandate::claim_tests
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```
Commit: `feat(core): mandate window/audience/binding checks`.

---

### Task 5 — Top-level `verify_mandate` orchestrator (§3.5 steps 1–5) + `MandateClaims`

**Test FIRST** — `#[cfg(test)] mod verify_tests` in `mandate.rs`:

```rust
#[cfg(test)]
mod verify_tests {
    use super::test_fixtures::*;
    use super::{verify_mandate, MandateError, MandateOutcome, RequestBinding, TrustAnchorsView, VerifyConfig, TrustRoute};
    use serde_json::Value;

    fn anchors() -> TrustAnchorsView {
        TrustAnchorsView::from_pairs(&[(FIXTURE_KEY_ID.to_string(), fixture_pubkey_b64())]).unwrap()
    }
    fn cfg(allow_unsigned_dev: bool) -> VerifyConfig {
        VerifyConfig { audience: "tessera.local".into(), allow_unsigned_dev }
    }
    fn signed_valid() -> Value {
        let mut m = unsigned_mandate(("2026-06-14T00:00:00Z", "spiffe://femto.local/run", "tessera.local"));
        sign_mandate(&mut m);
        m
    }
    fn binding() -> RequestBinding {
        RequestBinding { spiffe_id: Some("spiffe://femto.local/run/run-1".into()), trust_domain: Some("femto.local".into()) }
    }

    #[test]
    fn valid_signed_mandate_verifies_and_returns_claims() {
        let m = signed_valid();
        let out = verify_mandate(Some(&m), TrustRoute::Issue, &binding(), &anchors(), &cfg(false), "2026-06-14T00:30:00Z").unwrap();
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
        let err = verify_mandate(None, TrustRoute::Issue, &binding(), &anchors(), &cfg(false), "2026-06-14T00:30:00Z").unwrap_err();
        assert!(matches!(err, MandateError::Invalid(_)));
    }

    #[test]
    fn absent_mandate_in_dev_is_skipped() {
        let out = verify_mandate(None, TrustRoute::Issue, &binding(), &anchors(), &cfg(true), "2026-06-14T00:30:00Z").unwrap();
        assert!(matches!(out, MandateOutcome::SkippedDev));
    }

    #[test]
    fn unsigned_dev_alg_rejected_in_prod() {
        let mut m = signed_valid();
        m["signature"]["alg"] = Value::String("unsigned-dev".into());
        m["signature"]["value"] = Value::String(String::new());
        let err = verify_mandate(Some(&m), TrustRoute::Issue, &binding(), &anchors(), &cfg(false), "2026-06-14T00:30:00Z").unwrap_err();
        assert!(matches!(err, MandateError::Unverifiable(_)));
    }

    #[test]
    fn unsigned_dev_alg_accepted_in_dev() {
        let mut m = unsigned_mandate(("2026-06-14T00:00:00Z", "spiffe://femto.local/run", "tessera.local"));
        m["signature"]["alg"] = Value::String("unsigned-dev".into());
        let out = verify_mandate(Some(&m), TrustRoute::Issue, &binding(), &anchors(), &cfg(true), "2026-06-14T00:30:00Z").unwrap();
        assert!(matches!(out, MandateOutcome::Verified(_)));
    }

    #[test]
    fn expired_signed_mandate_is_invalid() {
        let mut m = unsigned_mandate(("2026-06-14T00:00:00Z", "spiffe://femto.local/run", "tessera.local"));
        m["expiresAt"] = Value::String("2026-06-14T00:10:00Z".into());
        sign_mandate(&mut m);
        let err = verify_mandate(Some(&m), TrustRoute::Issue, &binding(), &anchors(), &cfg(false), "2026-06-14T00:30:00Z").unwrap_err();
        assert!(matches!(err, MandateError::Invalid(_)));
    }
}
```

**Then implement** in `mandate.rs`:

```rust
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
        mandate_id: mandate.get("mandateId").and_then(Value::as_str).unwrap_or("").to_string(),
        key_id: mandate
            .get("signature")
            .and_then(|s| s.get("keyId"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        subject: mandate.get("subject").and_then(Value::as_str).unwrap_or("").to_string(),
        audience: mandate.get("audience").and_then(Value::as_str).unwrap_or("").to_string(),
    };
    Ok(MandateOutcome::Verified(claims))
}
```

**Gate:**
```bash
cargo test -p tessera-core mandate::verify_tests
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```
Commit: `feat(core): verify_mandate orchestrator (3.5 steps 1-5) + claims`.

---

### Task 6 — `trust_anchors.rs`: owning `TrustAnchors` + `from_env`

**Test FIRST** — create `crates/tessera-core/src/trust_anchors.rs` with `#[cfg(test)] mod tests`:

```rust
#[cfg(test)]
mod tests {
    use super::TrustAnchors;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::SigningKey;

    fn pub_b64(seed: u8) -> String {
        STANDARD.encode(SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes())
    }

    #[test]
    fn parses_comma_separated_pairs() {
        let raw = format!("k1:{},k2:{}", pub_b64(1), pub_b64(2));
        let anchors = TrustAnchors::from_str_spec(&raw).unwrap();
        assert!(anchors.view().resolve("k1").is_some());
        assert!(anchors.view().resolve("k2").is_some());
        assert!(anchors.view().resolve("missing").is_none());
    }

    #[test]
    fn empty_spec_yields_empty_anchors() {
        let anchors = TrustAnchors::from_str_spec("").unwrap();
        assert!(anchors.view().is_empty());
    }

    #[test]
    fn whitespace_and_trailing_comma_tolerated() {
        let raw = format!(" k1 : {} , ", pub_b64(1));
        let anchors = TrustAnchors::from_str_spec(&raw).unwrap();
        assert!(anchors.view().resolve("k1").is_some());
    }

    #[test]
    fn malformed_pair_is_error() {
        assert!(TrustAnchors::from_str_spec("no-colon-here").is_err());
        assert!(TrustAnchors::from_str_spec("k1:not-base64!!!").is_err());
    }

    #[test]
    fn from_env_reads_named_var() {
        let raw = format!("k1:{}", pub_b64(9));
        // Use a getter closure so the test doesn't mutate process env.
        let anchors = TrustAnchors::from_getter("TESSERA_ARC_TRUST_ANCHORS", |k| {
            if k == "TESSERA_ARC_TRUST_ANCHORS" { Some(raw.clone()) } else { None }
        })
        .unwrap();
        assert!(anchors.view().resolve("k1").is_some());
    }
}
```

**Then implement** `trust_anchors.rs`:

```rust
//! Pinned keyId -> ed25519 public key map (the trust-plane root of trust).
//! V1 source: env `TESSERA_ARC_TRUST_ANCHORS` = comma-separated `keyId:base64pubkey`.

use crate::mandate::TrustAnchorsView;

/// Owning trust-anchor set. Wraps the borrow-only `TrustAnchorsView` used by
/// verification so callers thread one value through AppState.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    view: TrustAnchorsView,
}

impl TrustAnchors {
    /// Parse `keyId:base64pubkey` pairs, comma-separated. Empty -> empty set.
    /// Whitespace around tokens and a trailing comma are tolerated. A pair
    /// without a colon, or with a non-32-byte / non-base64 key, is an error.
    pub fn from_str_spec(spec: &str) -> Result<Self, String> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for entry in spec.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (id, b64) = entry
                .split_once(':')
                .ok_or_else(|| format!("trust anchor entry missing ':' -> {entry}"))?;
            let id = id.trim().to_string();
            let b64 = b64.trim().to_string();
            if id.is_empty() {
                return Err(format!("trust anchor entry has empty keyId -> {entry}"));
            }
            pairs.push((id, b64));
        }
        let view = TrustAnchorsView::from_pairs(&pairs)?;
        Ok(Self { view })
    }

    /// Load from a key/value getter (so tests avoid touching real env).
    pub fn from_getter(
        var: &str,
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, String> {
        match get(var) {
            Some(spec) => Self::from_str_spec(&spec),
            None => Ok(Self::default()),
        }
    }

    /// Load from the process environment (used by `main`).
    pub fn from_env(var: &str) -> Result<Self, String> {
        Self::from_getter(var, |k| std::env::var(k).ok())
    }

    pub fn view(&self) -> &TrustAnchorsView {
        &self.view
    }
}
```

Register the module — **Edit `crates/tessera-core/src/lib.rs`**, add `pub mod trust_anchors;` after `pub mod types;` (or alphabetical: after `pub mod seal;`, before `pub mod types;`):

```rust
pub mod seal;
pub mod trust_anchors;
pub mod types;
```

**Gate:**
```bash
cargo test -p tessera-core trust_anchors
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```
Commit: `feat(core): TrustAnchors from_env parser (keyId:base64pubkey)`.

---

### Task 7 — Wire `AppState`: trust config from env, threaded into routes

This is a **cross-crate** change: adding a field to `AppState` breaks every `AppState { vault: ... }` literal (tests + `main.rs`). Find them first:

```bash
rg -n "AppState \{" crates/
```
(Expect hits in: `crates/tessera-server/tests/pki_spiffe.rs`, `transit_unwrap.rs`, `persistence.rs`, `sys_admin.rs`, `vault_compat.rs`, and `src/main.rs`.)

**Edit `crates/tessera-server/src/app.rs`** — add a `TrustConfig` carrying the anchors + verify config, and a field on `AppState`:

```rust
use std::sync::Arc;

use axum::Router;
use tessera_core::mandate::VerifyConfig;
use tessera_core::trust_anchors::TrustAnchors;
use tessera_core::vault::VaultStore;

/// Trust-plane configuration resolved at startup and shared (read-only) with the
/// pki + transit routes for mandate verification.
#[derive(Clone)]
pub struct TrustConfig {
    pub anchors: Arc<TrustAnchors>,
    pub verify: VerifyConfig,
}

impl TrustConfig {
    /// Dev-default: no anchors, dev audience, unsigned-dev allowed. Used by tests
    /// that don't exercise mandate enforcement, so existing route tests keep
    /// passing (no-mandate -> SkippedDev).
    pub fn dev_default() -> Self {
        Self {
            anchors: Arc::new(TrustAnchors::default()),
            verify: VerifyConfig {
                audience: "tessera.local".to_string(),
                allow_unsigned_dev: true,
            },
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub vault: Arc<VaultStore>,
    pub trust: TrustConfig,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(crate::routes_sys::routes())
        .merge(crate::routes_kv::routes())
        .merge(crate::routes_pki::routes())
        .merge(crate::routes_transit::routes())
        .with_state(state)
}
```

**Edit every test `AppState { vault: ... }` literal** to add `trust: TrustConfig::dev_default()` and import it (`use tessera_server::app::{router, AppState, TrustConfig};`). For each of the 5 test files (`pki_spiffe.rs`, `transit_unwrap.rs`, `persistence.rs`, `sys_admin.rs`, `vault_compat.rs`) — only those that build an `AppState` literal need the change; `rg` output is the authority. Example diff for `transit_unwrap.rs`:

```rust
    AppState {
        vault: Arc::new(vault),
        trust: TrustConfig::dev_default(),
    }
```

**Edit `crates/tessera-server/src/config.rs`** — extend `Config` and `from_getter` to load the three env vars. Add fields:

```rust
pub struct Config {
    pub bind: String,
    pub master_key: Vec<u8>,
    pub data_dir: String,
    pub crypto_backend: String,
    pub admin_token: Option<String>,
    pub arc_trust_anchors: String,   // raw spec, parsed in main
    pub audience: String,
    pub allow_unsigned_dev: bool,
}
```

In the `Debug` impl add the three new fields (anchors/audience are non-secret; render them plainly). In `from_getter`, after `admin_token`:

```rust
    let arc_trust_anchors = get("TESSERA_ARC_TRUST_ANCHORS").unwrap_or_default();
    let audience = get("TESSERA_AUDIENCE").unwrap_or_else(|| "tessera.local".to_string());
    let allow_unsigned_dev = get("TESSERA_ALLOW_UNSIGNED_DEV")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    Ok(Config {
        bind: get("TESSERA_BIND").unwrap_or_else(|| "127.0.0.1:8200".to_string()),
        master_key: master_key.into_bytes(),
        data_dir: get("TESSERA_DATA_DIR").unwrap_or_else(|| "./data".to_string()),
        crypto_backend,
        admin_token,
        arc_trust_anchors,
        audience,
        allow_unsigned_dev,
    })
```

Add config tests (append to `config.rs` `mod tests`):

```rust
    #[test]
    fn trust_env_defaults_safe() {
        let cfg = from_getter(getter(&[("TESSERA_MASTER_KEY", "k")])).unwrap();
        assert_eq!(cfg.audience, "tessera.local");
        assert!(!cfg.allow_unsigned_dev, "prod default must be fail-closed");
        assert_eq!(cfg.arc_trust_anchors, "");
    }

    #[test]
    fn allow_unsigned_dev_parses_truthy() {
        let cfg = from_getter(getter(&[
            ("TESSERA_MASTER_KEY", "k"),
            ("TESSERA_ALLOW_UNSIGNED_DEV", "true"),
            ("TESSERA_AUDIENCE", "femto.test"),
        ]))
        .unwrap();
        assert!(cfg.allow_unsigned_dev);
        assert_eq!(cfg.audience, "femto.test");
    }
```

**Edit `crates/tessera-server/src/main.rs`** — after building `cfg`, parse anchors and build `TrustConfig`, then add it to `AppState`:

```rust
    // Parse trust anchors at startup; a bad spec is fatal (fail-closed).
    let anchors = match tessera_core::trust_anchors::TrustAnchors::from_str_spec(&cfg.arc_trust_anchors) {
        Ok(a) => std::sync::Arc::new(a),
        Err(e) => {
            eprintln!("tessera: TESSERA_ARC_TRUST_ANCHORS invalid: {e}");
            std::process::exit(1);
        }
    };
    if anchors.view().is_empty() && !cfg.allow_unsigned_dev {
        eprintln!("tessera: WARNING no trust anchors and unsigned-dev disabled — all mandates will be rejected");
    }
    let trust = tessera_server::app::TrustConfig {
        anchors,
        verify: tessera_core::mandate::VerifyConfig {
            audience: cfg.audience.clone(),
            allow_unsigned_dev: cfg.allow_unsigned_dev,
        },
    };
```

and:

```rust
    let state = AppState {
        vault: Arc::new(vault),
        trust,
    };
```

**Gate (whole workspace — this is the cross-crate one):**
```bash
cargo build --workspace
cargo test --workspace      # all existing route tests must still pass (no-mandate -> SkippedDev via dev_default)
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```
Expected: green. If a test `AppState` literal was missed, `cargo test --workspace` (NOT `-p tessera-server` alone) surfaces an `E0063 missing field trust`. Commit: `feat(server): thread TrustConfig (anchors + verify) into AppState from env`.

---

### Task 8 — `routes_pki.rs`: parse `mandate`, verify before issuance

**Test FIRST** — add to `crates/tessera-server/tests/pki_spiffe.rs`. The harness's `AppState` builder must be parameterizable with a real `TrustConfig` (anchors + prod mode) for the enforcement tests. Add a helper that builds a state with a fixture anchor, plus tests:

```rust
// at top: imports for fixtures
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use std::sync::Arc;
use tessera_core::mandate::{canonical_signing_payload, VerifyConfig};
use tessera_core::trust_anchors::TrustAnchors;
use tessera_server::app::TrustConfig;

const FIXTURE_SEED: [u8; 32] = [0x11; 32];
const FIXTURE_KEY_ID: &str = "arc-fixture-key-1";

fn fixture_anchor_spec() -> String {
    let pk = STANDARD.encode(SigningKey::from_bytes(&FIXTURE_SEED).verifying_key().to_bytes());
    format!("{FIXTURE_KEY_ID}:{pk}")
}

fn signed_issue_mandate(spiffe_subject: &str, audience: &str, issued: &str, expires: &str) -> Value {
    let mut m = serde_json::json!({
        "mandateId": "m-pki-1",
        "format": "a2e-execution-mandate/v0",
        "issuer": "galvo-arc",
        "subject": spiffe_subject,
        "audience": audience,
        "issuedAt": issued,
        "expiresAt": expires,
        "certifies": { "action": "execute", "workOrderHash": "sha256:beef", "idempotencyKey": "i-1" },
        "scope": { "data": [], "models": [], "runtimeClasses": ["wasm"] },
        "signature": { "alg": "ed25519", "value": "", "keyId": FIXTURE_KEY_ID }
    });
    let payload = canonical_signing_payload(&m);
    let sig = SigningKey::from_bytes(&FIXTURE_SEED).sign(&payload);
    m["signature"]["value"] = Value::String(STANDARD.encode(sig.to_bytes()));
    m
}

/// State enforcing mandates in prod mode against the fixture anchor, with the
/// clock at 2026-06-14T00:00:00Z (matches FixedClock used elsewhere).
fn pki_state_enforcing() -> tessera_server::app::AppState {
    let mut state = pki_state(); // existing builder
    state.trust = TrustConfig {
        anchors: Arc::new(TrustAnchors::from_str_spec(&fixture_anchor_spec()).unwrap()),
        verify: VerifyConfig { audience: "tessera.local".into(), allow_unsigned_dev: false },
    };
    state
}
```

> If the existing `pki_state()` builder returns a value (not a literal you can mutate field-by-field), adjust: have it return `AppState` and set `.trust` after, or add `trust: TrustConfig::dev_default()` to its literal first (per Task 7) then overwrite in `pki_state_enforcing`. The `FixedClock` instant in `pki_state` is the route's "now"; the fixture mandate window (`issuedAt=2026-06-14T00:00:00Z`, `expiresAt` far future) must bracket it.

```rust
#[tokio::test]
async fn issue_with_valid_signed_mandate_succeeds() {
    let state = pki_state_enforcing();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let subject = "spiffe://example.org"; // mandate subject; requested spiffeId extends it
    let mandate = signed_issue_mandate(subject, "tessera.local", "2026-06-14T00:00:00Z", "2999-01-01T00:00:00Z");

    let res = client
        .post(format!("{base}/v1/pki/spiffe/issue"))
        .header("Authorization", "Bearer pki-tok") // whatever pki_state seeds
        .json(&serde_json::json!({
            "trustDomain": "example.org",
            "spiffeId": "spiffe://example.org/workload/a",
            "mandate": mandate
        }))
        .send().await.unwrap();
    assert_eq!(res.status(), 200);
    let audit = state.vault.audit_sink().records();
    assert!(audit.iter().any(|r| r.op == tessera_core::audit::AuditOp::IssueCertificate
        && r.scope.contains("mandate=m-pki-1") && r.outcome));
}

#[tokio::test]
async fn issue_missing_mandate_in_prod_is_rejected() {
    let state = pki_state_enforcing();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{base}/v1/pki/spiffe/issue"))
        .header("Authorization", "Bearer pki-tok")
        .json(&serde_json::json!({
            "trustDomain": "example.org",
            "spiffeId": "spiffe://example.org/workload/a"
        }))
        .send().await.unwrap();
    assert_eq!(res.status(), 400);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "mandate-invalid");
}

#[tokio::test]
async fn issue_unsigned_mandate_in_dev_is_allowed() {
    // dev_default state allows unsigned-dev + no anchors.
    let state = pki_state(); // dev_default trust
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{base}/v1/pki/spiffe/issue"))
        .header("Authorization", "Bearer pki-tok")
        .json(&serde_json::json!({
            "trustDomain": "example.org",
            "spiffeId": "spiffe://example.org/workload/a"
        }))
        .send().await.unwrap();
    assert_eq!(res.status(), 200);
}
```

> NOTE: confirm `pki_state()`'s seeded token name + trust domain in `pki_spiffe.rs` and match them in the test bodies. The audit assertion checks the folded scope suffix from the design decision (`mandate=<id>`).

**Then implement** in `crates/tessera-server/src/routes_pki.rs`:

1. Add `mandate` to the request struct:
```rust
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
```

2. Add a mandate error responder:
```rust
fn mandate_err_response(err: &tessera_core::mandate::MandateError) -> (StatusCode, Json<Value>) {
    use tessera_core::mandate::MandateError;
    let status = match err {
        MandateError::Invalid(_) => StatusCode::BAD_REQUEST,
        MandateError::Unverifiable(_) | MandateError::PolicyDenied(_) => StatusCode::FORBIDDEN,
    };
    (
        status,
        Json(json!({ "errors": [err.to_string()], "code": err.code() })),
    )
}
```

3. In `issue_spiffe`, after the `authorize_scope` block and before `validate_spiffe`, run verification. Need imports at top: `use tessera_core::mandate::{verify_mandate, MandateOutcome, RequestBinding, TrustRoute};`.

```rust
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
            // Audit the denial with the base scope; identity unknown on failure.
            state
                .vault
                .record_action(AuditOp::IssueCertificate, &scope, &token, false);
            return mandate_err_response(&e).into_response();
        }
    };
```

4. Fold mandate identity into the success audit scope. Replace the final success `record_action` with a scope that includes the claims when present:

```rust
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
```

> NOTE: the EARLIER failure-path `record_action`s in `issue_spiffe` (validate/clock/cert errors) keep using the bare `scope` — only the post-verify success record carries the mandate suffix. This satisfies §3.5.6 without widening `AuditRecord`. `SecretPath` and `scope` are already in scope in this function.

**Gate:**
```bash
cargo test -p tessera-server --test pki_spiffe
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```
Commit: `feat(server): verify ExecutionMandate before SVID issuance (pki route)`.

---

### Task 9 — `routes_transit.rs`: parse `mandate`, verify before unwrap

Same shape as Task 8, route = `Unwrap`, binding from `context`. **NO ledger** (Phase 2).

**Test FIRST** — add to `crates/tessera-server/tests/transit_unwrap.rs` an enforcing-state builder + tests. Reuse the fixture-signing helpers (copy the `FIXTURE_SEED`/`signed_*` helpers, or factor them into a shared `tests/common/mod.rs` — simplest is to duplicate the small helper in this file; a `mod.rs` is optional polish). The unwrap mandate's `subject` must match the request `context.spiffeId` per §3.5.5:

```rust
fn signed_unwrap_mandate(subject: &str, audience: &str) -> Value {
    let mut m = serde_json::json!({
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
```

Tests:
- `unwrap_with_valid_signed_mandate_succeeds`: enforcing state, real ciphertext (reuse `seal_fixture`), `context.spiffeId` = mandate subject, asserts 200 + audit scope contains `mandate=m-transit-1`.
- `unwrap_missing_mandate_in_prod_is_rejected`: enforcing state, no `mandate` → 400, `code == "mandate-invalid"`. (Place this BEFORE ciphertext validation so the missing-mandate rejection is the cause — verification runs right after `authorize_scope`, before ciphertext decode.)
- `unwrap_unsigned_mandate_in_dev_is_allowed`: dev_default state, no mandate → existing happy-path still 200 (this is effectively the existing `transit_scoped_token_unwraps_galvofs_payload` test, which must still pass unchanged).
- `unwrap_audience_mismatch_is_policy_denied`: enforcing state, signed mandate with `audience="other"` → 403, `code == "policy-denied"`.

**Then implement** in `routes_transit.rs`:

1. Add `#[serde(default)] mandate: Option<Value>` to `GalvoFsUnwrapRequest`.
2. Add the same `mandate_err_response` helper.
3. Add imports: `use tessera_core::mandate::{verify_mandate, MandateOutcome, RequestBinding, TrustRoute};`.
4. In `unwrap_galvofs`, immediately after the `authorize_scope` block (BEFORE the ciphertext base64 decode), insert:

```rust
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
```

5. Fold mandate identity into the success audit scope (mirror Task 8):

```rust
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
```
(Replace the existing final success `record_action(AuditOp::TransitUnwrap, &scope, &token, true)` line with the above.)

> The `context` is still echoed in the response body unchanged. `SecretPath` is already imported (`tessera_core::types::SecretPath`).

**Gate:**
```bash
cargo test -p tessera-server --test transit_unwrap
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```
Commit: `feat(server): verify ExecutionMandate before galvofs unwrap (transit route)`.

---

### Task 10 — Final gates + self-review

**Run the full gate trio from the repo root:**
```bash
cargo fmt --all                 # auto-fix any drift FIRST
cargo fmt --all -- --check      # now must be clean (separate gate!)
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

All three must be green. Then self-review against the spec (§3.5):

- [ ] **Step 1 presence:** absent+dev → SkippedDev; absent+prod → mandate-invalid. (verify_tests)
- [ ] **Step 2 signature:** ed25519 verified over canonical payload; unknown keyId → unverifiable; unsigned-dev gated by `allow_unsigned_dev`; key resolved from ANCHOR not inline `publicKey`. (sig_tests, verify_tests)
- [ ] **Step 3 window:** issuedAt<=now<=expiresAt; unparseable → invalid. (claim_tests)
- [ ] **Step 4 audience:** mismatch → policy-denied. (claim_tests, transit audience test)
- [ ] **Step 5 binding:** issue (spiffe within subject) + unwrap (context.spiffeId within subject, absent OK in P1). (claim_tests)
- [ ] **Canonicalization is LOSSLESS:** operates on `serde_json::Value`, not a typed round-trip; unknown fields preserved in signed bytes. (canonical_tests, design note)
- [ ] **Error codes:** mandate-invalid (400) / mandate-unverifiable (403) / policy-denied (403) returned in `code`. (route tests)
- [ ] **Audit:** mandateId/keyId folded into success audit scope. (route tests)
- [ ] **Fail-closed defaults:** `allow_unsigned_dev` defaults false; bad anchor spec is fatal at startup. (config tests, main.rs)
- [ ] **No placeholders:** grep for `todo!`/`unimplemented!`/`unreachable!` in new code → none.
- [ ] **Existing tests unaffected:** `transit_scoped_token_unwraps_galvofs_payload` + `pki_spiffe` happy paths still pass (dev_default = SkippedDev).

Type-consistency sweep: `MandateError` is the single error type, mapped to codes in ONE place (`mandate_err_response`, duplicated identically in both route files — acceptable; a shared helper in `app.rs` is optional polish). `TrustAnchorsView` is borrow-only; `TrustAnchors` owns. `verify_mandate` takes `Option<&Value>` (lossless). `RequestBinding` is the one binding-input shape.

Fix anything the review surfaces inline, re-run the gate trio, commit: `chore(trust-plane): phase-1 gates green + self-review`.

---

## Out of scope (do NOT build here)
- The one-time unwrap **ledger** / `replay-detected` / burn-on-failure (§4) — **Phase 2**.
- Galvo `Ed25519Signer` + the **cross-language** vector (Galvo bytes == Tessera bytes) — **Phase 3**.
- Femto forwarding the mandate in HTTP clients — **Phase 4**.
- SPIFFE-cert-chained anchors, key rotation tooling, structured audit field for mandateId/keyId — later.

## Definition of done
- New: `tessera-core/src/mandate.rs`, `tessera-core/src/trust_anchors.rs`; `mandate` + `trust_anchors` registered in `lib.rs`.
- Modified: `tessera-core/Cargo.toml` (+ed25519-dalek, +time), `tessera-server/src/app.rs` (TrustConfig + AppState field), `config.rs` (3 env vars), `main.rs` (anchor load + state wiring), `routes_pki.rs` + `routes_transit.rs` (mandate field + verify + audit fold), all test `AppState` literals updated.
- All on branch `trust-plane/p1-mandate-verification` off `codex/transit-unwrap-api`. `cargo test --workspace` + `cargo clippy --workspace -- -D warnings` + `cargo fmt --all -- --check` all green.
