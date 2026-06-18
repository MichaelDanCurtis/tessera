# Plan — Phase 2: Tessera one-time unwrap nonce ledger (replay protection)

**Date:** 2026-06-17
**Branch:** `trust-nonce-ledger` (off `codex/transit-unwrap-api` HEAD `b58903d`, Phase-1 mandate verification already merged)
**Worktree:** `/Volumes/Main External/Development/lucidity/tessera/.worktrees/nonce-ledger`
**Scope:** Tessera only. Pure Rust. NO changes outside `tessera/`. Edition 2021.
**Authoritative design:** `Galvo/docs/superpowers/specs/2026-06-17-trust-plane-enforcer-design.md` §4 (one-time unwrap ledger) + §7. Implement §4 exactly.

---

## 0. Goal (one paragraph)

After Phase-1 mandate verification on the `POST /v1/transit/unwrap/galvofs` route, and **before** AES-GCM decryption, enforce **one-time use**. Derive a ledger entry id from `(keyRef, consumeNonce)` where `consumeNonce` is the verified mandate's `certifies.idempotencyKey`. Perform an **atomic check-and-insert** against the persistent engine: if the id already exists → return `replay-detected` (audit outcome=false) and do not decrypt; else mark it consumed and proceed. The consume happens **before** decryption (burn-on-failure: a later decrypt failure does not un-burn the nonce — no retry-to-replay). The ledger lives under a reserved `sys` namespace in the same persistent engine as KV, so replays are rejected across restarts.

---

## 1. Grounding — verified facts (read on the codex branch, in this worktree)

These are quoted from the real source on `trust-nonce-ledger` (= `codex/transit-unwrap-api` HEAD). The executor MUST match these signatures.

### 1.1 `SecretEngine` trait + `InMemoryEngine` — `crates/tessera-core/src/engine.rs`

```rust
#[async_trait::async_trait]
pub trait SecretEngine: Send + Sync {
    async fn get(&self, path: &SecretPath) -> Result<Option<Vec<u8>>, TesseraError>;
    async fn put(&self, path: &SecretPath, blob: Vec<u8>) -> Result<(), TesseraError>;
    async fn delete(&self, path: &SecretPath) -> Result<(), TesseraError>;
    async fn list(&self, prefix: &SecretPath) -> Result<Vec<String>, TesseraError>;
}

#[derive(Default)]
pub struct InMemoryEngine {
    store: Mutex<BTreeMap<String, Vec<u8>>>,   // std::sync::Mutex
}
```

`InMemoryEngine` keys the map on `path.scope()` (e.g. `get` does `self.store.lock().unwrap().get(&path.scope())`). The `Mutex` is `std::sync::Mutex` (line 2: `use std::sync::Mutex;`). A single guard covers check+insert → atomic.

### 1.2 `RustyVaultEngine` actor plumbing — `crates/tessera-core/src/rusty_engine.rs`

The `EngineJob` carries a **single** `Operation` to the worker; the worker loop runs `handle_job` once per job. To make check-then-write atomic on the worker thread we add a **new `EngineJob` variant kind** so one job does read-then-conditional-write inside the worker arm (never two `run()` awaits from the route).

Quoted plumbing:

```rust
struct EngineJob {
    ctx: &'static str,
    op: Operation,
    path: String,
    body: Option<Map<String, Value>>,
    reply: oneshot::Sender<Result<Option<Response>, TesseraError>>,
}
```

Worker loop (inside `open`, on the dedicated OS thread):

```rust
while let Some(job) = rx.recv().await {
    let mapped = handle_job(&core, &root_token, job.op, &job.path, job.body)
        .await
        .map_err(|e| store(format!("{}: {e}", job.ctx)));
    let _ = job.reply.send(mapped);
}
```

`run()` builds one `EngineJob` and awaits the oneshot:

```rust
async fn run(&self, ctx, op, path, body) -> Result<Option<Response>, TesseraError> {
    let (reply, reply_rx) = oneshot::channel();
    self.tx.send(EngineJob { ctx, op, path: path.to_string(), body, reply })
        .map_err(|_| store("engine worker thread is gone"))?;
    reply_rx.await.map_err(|_| store("engine worker dropped the reply"))?
}
```

`handle_job` drives one `Core::handle_request`. `Self::logical_path(path)` = `<mount>/<path-trimmed>`. `ensure_mount(mount)` lazily mounts a KV-v1 backend (idempotent; seeded with `secret`). The `get` impl reads the `"blob"` field; `put` writes `{"blob": base64(blob)}`.

**Atomicity design (load-bearing):** the new `put_if_absent` must NOT be implemented as `self.get(path).await?` then `self.put(path, ...).await?` — those are two separate jobs and another job can interleave between them. Instead we change `EngineJob` to carry an enum of work kinds (`Run` = today's single op; `PutIfAbsent` = read-then-conditional-write), so the read+write pair executes inside ONE worker-thread turn, serialized against all other jobs by the single-threaded worker.

### 1.3 `SecretPath` — `crates/tessera-core/src/types.rs`

```rust
pub struct SecretPath { pub mount: String, pub path: String }
impl SecretPath {
    pub fn new(mount: impl Into<String>, path: impl Into<String>) -> Self { ... }
    pub fn scope(&self) -> String { format!("{}/{}", self.mount, self.path) }
}
```

**Reachability confirmation (the security point):** policy authorization happens in `VaultStore::guard()` → `tokens.authorize_at(token, path, ...)` against the token's policy scopes. The ledger writes go **directly to `self.engine`** from a new `VaultStore` method that does NOT call `guard()` — so the ledger path is never gated by a caller token, and (conversely) a normal KV token can never read/write it: KV routes only call `read`/`write` with a `secret`-mount `SecretPath`, and the policy scopes (`secret/…`, `transit/unwrap/…`) never include the `sys` mount. The ledger uses mount `sys`, path `a2e-nonce-ledger/{id}` → `scope() == "sys/a2e-nonce-ledger/{id}"`, unreachable by any KV/transit token. On `RustyVaultEngine` this lazily creates a `sys` KV mount via `ensure_mount` — note RustyVault already uses a `sys/mounts/...` *logical* path for mount admin, but our blob is at logical path `sys/a2e-nonce-ledger/{id}` under a KV-v1 mount named `sys`, which is a distinct namespace from RustyVault's internal `sys/` system backend... **(see §6 risk R3 — the executor MUST verify the mount name `sys` does not collide with RustyVault's reserved system backend; if it does, use mount `tessera-sys` instead).**

### 1.4 `MandateClaims` + `verify_mandate` — `crates/tessera-core/src/mandate.rs`

```rust
pub struct MandateClaims {
    pub mandate_id: String,
    pub key_id: String,
    pub subject: String,
    pub audience: String,
}
pub enum MandateOutcome { Verified(MandateClaims), SkippedDev }
pub fn verify_mandate(mandate: Option<&Value>, route, binding, anchors, cfg, now_rfc3339)
    -> Result<MandateOutcome, MandateError>;
```

**`idempotency_key` is NOT currently on `MandateClaims`.** It lives in the wire mandate at `certifies.idempotencyKey` (confirmed: `mandate.rs` fixture line ~465 `"idempotencyKey": "idem-1"`; the transit test fixture uses `"certifies": { ... "idempotencyKey": "i-1" }`; the cross-lang vector uses `idem-wo_vector_1`). Task 3 adds `idempotency_key: String` to `MandateClaims`, populated in `verify_mandate` from `mandate["certifies"]["idempotencyKey"]`.

### 1.5 Route — `crates/tessera-server/src/routes_transit.rs`

Post-verify / pre-decrypt point (verbatim region):

```rust
let claims = match verify_mandate(
    req.mandate.as_ref(), TrustRoute::Unwrap, &binding,
    state.trust.anchors.view(), &state.trust.verify, &now,
) {
    Ok(MandateOutcome::Verified(c)) => Some(c),
    Ok(MandateOutcome::SkippedDev) => None,
    Err(e) => {
        state.vault.record_action(AuditOp::TransitUnwrap, &scope, &token, false);
        return mandate_err_response(&e).into_response();
    }
};

let ciphertext = match STANDARD.decode(&req.ciphertext_base64) { ... };   // <-- ledger goes BEFORE this block
if let Err(e) = validate_request(&req, &ciphertext) { ... }
let nonce = match parse_nonce(&req.nonce) { ... };
let key = transit_payload_key(&req.key_ref);
let cipher = ...;
let plaintext = match cipher.decrypt(...) { ... };   // <-- decrypt
```

The ledger consume is inserted **immediately after `claims` is bound and before any decode/decrypt**, gated on `claims` being `Some` (a verified mandate). The route reaches the engine only via `state.vault: Arc<VaultStore>` — `VaultStore.engine` is private, so we add a method on `VaultStore`.

### 1.6 Audit — `crates/tessera-core/src/audit.rs`

`AuditOp` enum already has `TransitUnwrap`. `VaultStore::record_action(op, path, token, outcome)` appends an `AuditRecord`. The replay rejection reuses `AuditOp::TransitUnwrap` with `outcome=false` (matches §4 "a replay rejection is an auditable event (`TransitUnwrap` outcome=false)"). NO new `AuditOp` variant is required.

### 1.7 Engine impls + mocks inventory (cross-crate E0046 risk)

`grep -rn "impl SecretEngine"` → exactly two impls: `InMemoryEngine` (engine.rs:32), `RustyVaultEngine` (rusty_engine.rs:379). **No test mock impls of `SecretEngine` exist** (the grep over `crates/` for `SecretEngine` returns only Cargo.toml, vault.rs, engine.rs, rusty_engine.rs, app.rs — none define a third impl). Adding a trait method therefore requires updating exactly those two impls. `cargo test --workspace` is mandatory to catch any literal that constructs an engine in a test (none do beyond the two impls + their own `mod tests`).

### 1.8 `VaultStore` wiring — `crates/tessera-core/src/vault.rs`

`engine: Arc<dyn SecretEngine>` (private). `audit: Arc<dyn AuditSink>`. `clock: Arc<dyn Clock>` with `now_rfc3339()`. Existing pattern: `self.engine.put(path, blob).await`. We add `pub async fn consume_nonce(&self, ...) -> Result<bool, TesseraError>` that calls `self.engine.put_if_absent(&ledger_path, blob).await`. It does NOT call `guard()` (internal sys op, no caller token authz).

### 1.9 Test harness (route tests) — `crates/tessera-server/tests/transit_unwrap.rs`

Pattern to mirror: `serve(state)` binds `127.0.0.1:0`, spawns `axum::serve`, returns base URL; `reqwest::Client` drives it. `transit_state_enforcing()` builds prod-mode trust against the fixture anchor (seed `[0x11;32]`, keyId `arc-fixture-key-1`). `signed_unwrap_mandate(subject, audience)` produces a valid signed mandate with `certifies.idempotencyKey = "i-1"`. `seal_fixture(key_ref, nonce, plaintext)` AES-GCM-seals a payload. All state uses `InMemoryEngine` + `FixedClock("2026-06-14T00:00:00Z")`.

---

## 2. Design decisions (locked)

- **Ledger id:** `blake3(keyRef || "\0" || idempotencyKey)` rendered as full hex (64 chars). Helper in a new `mandate`-adjacent module. Quoted formula: `blake3::hash(&[key_ref.as_bytes(), b"\0", idempotency_key.as_bytes()].concat()).to_hex().to_string()`.
- **Ledger path:** `SecretPath::new("sys", format!("a2e-nonce-ledger/{id}"))` (subject to R3 mount-name check; fallback mount `tessera-sys`). Stored blob: a tiny JSON marker `{"consumedAt": "<now-rfc3339>", "keyRef": "<key_ref>"}` (non-empty so `get` returns `Some`; content is for forensics only — presence is the signal).
- **Atomic primitive:** `SecretEngine::put_if_absent(path, blob) -> Result<bool, TesseraError>` — `true` = inserted (first use), `false` = key already existed (replay). Atomic in BOTH impls.
- **Burn-on-failure:** consume runs before decode/decrypt. If `put_if_absent` returns `true` we proceed; a later decrypt failure leaves the nonce consumed. Spec's replacement-ticket exception is explicitly OUT OF SCOPE (burned stays burned) — documented in a code comment.
- **Skip when no mandate (dev):** when `verify_mandate` returns `SkippedDev` (dev mode, no mandate), there is no `idempotencyKey` → the ledger check is SKIPPED (back-compat: existing dev tests keep replaying). The ledger only engages on a `Verified` mandate. This matches §3.5/§4 layering (enforcement rides on a verified mandate).
- **Empty idempotencyKey guard:** if a verified mandate somehow carries an empty `certifies.idempotencyKey`, treat as `mandate-invalid` (a per-execution nonce is required to enforce one-time use). Audit outcome=false, return 400. (Defense-in-depth; real Arc mandates always populate it.)

---

## 3. Tasks (TDD, green-leaving order)

Each task: write/extend tests first (RED), implement (GREEN), then the next task compiles & passes. The trait change (Task 1) updates BOTH impls in the SAME task so the workspace never has a half-implemented trait.

Commands (run from the worktree root unless noted):
- Per-crate fast loop: `cargo test -p tessera-core` / `cargo test -p tessera-server`
- **Gate (mandatory before "done"):** `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --all -- --check` (fmt is a SEPARATE gate — a green clippy+test does NOT imply fmt is clean).

---

### Task 1 — `SecretEngine::put_if_absent` + `InMemoryEngine` atomic impl

**File:** `crates/tessera-core/src/engine.rs`

**1a. Trait method.** Add to the trait (after `list`):

```rust
    /// Atomic check-and-insert. Inserts `blob` at `path` only if no value
    /// currently exists there. Returns `true` if inserted (first use), `false`
    /// if a value already existed (the key is "consumed"). The check and the
    /// insert happen under a single critical section so concurrent callers see
    /// exactly one `true`.
    async fn put_if_absent(&self, path: &SecretPath, blob: Vec<u8>) -> Result<bool, TesseraError>;
```

**1b. `InMemoryEngine` impl.** Single `std::sync::Mutex` guard covers check+insert (use the BTreeMap `Entry` API so the guard is held across the test+insert):

```rust
    async fn put_if_absent(&self, path: &SecretPath, blob: Vec<u8>) -> Result<bool, TesseraError> {
        use std::collections::btree_map::Entry;
        let mut store = self.store.lock().unwrap();
        match store.entry(path.scope()) {
            Entry::Occupied(_) => Ok(false),
            Entry::Vacant(slot) => {
                slot.insert(blob);
                Ok(true)
            }
        }
    }
```

**1c. Tests** (append to `engine.rs` `mod tests`):

```rust
    #[tokio::test]
    async fn put_if_absent_inserts_first_returns_true() {
        let eng = InMemoryEngine::new();
        let p = SecretPath::new("sys", "a2e-nonce-ledger/abc");
        assert!(eng.put_if_absent(&p, b"marker".to_vec()).await.unwrap());
        assert_eq!(eng.get(&p).await.unwrap(), Some(b"marker".to_vec()));
    }

    #[tokio::test]
    async fn put_if_absent_second_returns_false_and_keeps_first() {
        let eng = InMemoryEngine::new();
        let p = SecretPath::new("sys", "a2e-nonce-ledger/abc");
        assert!(eng.put_if_absent(&p, b"first".to_vec()).await.unwrap());
        assert!(!eng.put_if_absent(&p, b"second".to_vec()).await.unwrap());
        // The original value is preserved (insert did not overwrite).
        assert_eq!(eng.get(&p).await.unwrap(), Some(b"first".to_vec()));
    }

    #[tokio::test]
    async fn put_if_absent_is_concurrent_safe_exactly_one_true() {
        // 32 concurrent inserters on the SAME key: exactly one sees `true`.
        let eng = std::sync::Arc::new(InMemoryEngine::new());
        let p = SecretPath::new("sys", "a2e-nonce-ledger/race");
        let mut handles = Vec::new();
        for _ in 0..32 {
            let eng = std::sync::Arc::clone(&eng);
            let p = p.clone();
            handles.push(tokio::spawn(async move {
                eng.put_if_absent(&p, b"x".to_vec()).await.unwrap()
            }));
        }
        let mut trues = 0;
        for h in handles {
            if h.await.unwrap() {
                trues += 1;
            }
        }
        assert_eq!(trues, 1, "exactly one inserter must win");
    }
```

> Note: the guard is a `std::sync::Mutex` and `put_if_absent` does no `.await` while holding it (the `Entry` block completes synchronously before the function returns), so there is no `await_holding_lock` clippy issue. `SecretPath` already derives `Clone`.

**RED→GREEN:** writing 1c before 1b fails to compile (no method); after 1a+1b, `cargo test -p tessera-core` passes.

**Verify:**
```
cargo test -p tessera-core engine
```
Expected: the three new `put_if_absent_*` tests pass alongside existing engine tests; `test result: ok.`

---

### Task 2 — `RustyVaultEngine::put_if_absent` as ONE atomic actor job + restart-survival test

**File:** `crates/tessera-core/src/rusty_engine.rs`

**2a. Make `EngineJob` carry a work-kind enum.** Replace the single-op `EngineJob` with a kind enum so the worker can run a read-then-conditional-write in one turn. Keep the existing single-op path (`Run`) untouched for `get`/`put`/`delete`/`list`/`mount`.

```rust
/// What one dispatched worker job does. `Run` is the existing single
/// `handle_request`; `PutIfAbsent` is an atomic read-then-conditional-write
/// executed entirely on the worker thread (so it is atomic w.r.t. all other
/// jobs — never two `run()` awaits from the caller, which would race).
enum JobKind {
    Run {
        op: Operation,
        path: String,
        body: Option<Map<String, Value>>,
        reply: oneshot::Sender<Result<Option<Response>, TesseraError>>,
    },
    PutIfAbsent {
        /// Logical path (already mount-prefixed via `logical_path`).
        path: String,
        /// The blob to insert if absent (already base64-wrapped body).
        body: Map<String, Value>,
        reply: oneshot::Sender<Result<bool, TesseraError>>,
    },
}

struct EngineJob {
    ctx: &'static str,
    kind: JobKind,
}
```

**2b. Update `run()`** (the existing single-op dispatcher) to wrap its work in `JobKind::Run`:

```rust
    async fn run(
        &self,
        ctx: &'static str,
        op: Operation,
        path: &str,
        body: Option<Map<String, Value>>,
    ) -> Result<Option<Response>, TesseraError> {
        let (reply, reply_rx) = oneshot::channel();
        self.tx
            .send(EngineJob {
                ctx,
                kind: JobKind::Run { op, path: path.to_string(), body, reply },
            })
            .map_err(|_| store("engine worker thread is gone"))?;
        reply_rx
            .await
            .map_err(|_| store("engine worker dropped the reply"))?
    }
```

**2c. Update the worker loop** (inside `open`) to dispatch by kind. A `PutIfAbsent` reads the existing value (Read op) and, only if absent, writes (Write op) — all on the worker thread, before the next job is pulled:

```rust
                while let Some(job) = rx.recv().await {
                    let EngineJob { ctx, kind } = job;
                    match kind {
                        JobKind::Run { op, path, body, reply } => {
                            let mapped = handle_job(&core, &root_token, op, &path, body)
                                .await
                                .map_err(|e| store(format!("{ctx}: {e}")));
                            let _ = reply.send(mapped);
                        }
                        JobKind::PutIfAbsent { path, body, reply } => {
                            let res = put_if_absent_job(&core, &root_token, &path, body)
                                .await
                                .map_err(|e| store(format!("{ctx}: {e}")));
                            let _ = reply.send(res);
                        }
                    }
                }
```

**2d. The atomic worker helper.** Add next to `handle_job`. Read the logical path; if a record with a `"blob"` field exists → `false`; else write the body and return `true`. Both ops run with the worker's `std::sync` read guard discipline already used by `handle_job` (reuse `handle_job` for both the read and the write so the `#[allow(clippy::await_holding_lock)]` discipline and `RvError`→`TesseraError` mapping are identical):

```rust
/// Atomic put-if-absent on the worker thread: one Read then a conditional
/// Write, with no other job interleaving (single-threaded worker). Returns
/// `true` if it wrote (was absent), `false` if a value already existed.
async fn put_if_absent_job(
    core: &Arc<RwLock<Core>>,
    root_token: &str,
    path: &str,
    body: Map<String, Value>,
) -> Result<bool, rusty_vault::errors::RvError> {
    // Read current value.
    let existing = handle_job(core, root_token, Operation::Read, path, None).await?;
    let already = existing
        .and_then(|r| r.data)
        .and_then(|d| d.get("blob").cloned())
        .is_some();
    if already {
        return Ok(false);
    }
    // Absent → write the marker body.
    handle_job(core, root_token, Operation::Write, path, Some(body)).await?;
    Ok(true)
}
```

**2e. Trait impl.** Implement `put_if_absent` for `RustyVaultEngine` — ensure the mount, build the base64 marker body (same `"blob"` shape as `put`), dispatch ONE `PutIfAbsent` job:

```rust
    async fn put_if_absent(&self, path: &SecretPath, blob: Vec<u8>) -> Result<bool, TesseraError> {
        self.ensure_mount(&path.mount).await?;
        let mut body = Map::new();
        body.insert(
            "blob".to_string(),
            Value::String(Base64::encode_string(&blob)),
        );
        let (reply, reply_rx) = oneshot::channel();
        self.tx
            .send(EngineJob {
                ctx: "put_if_absent",
                kind: JobKind::PutIfAbsent {
                    path: Self::logical_path(path),
                    body,
                    reply,
                },
            })
            .map_err(|_| store("engine worker thread is gone"))?;
        reply_rx
            .await
            .map_err(|_| store("engine worker dropped the reply"))?
    }
```

**2f. Tests** (append to `rusty_engine.rs` `mod tests`):

```rust
    #[tokio::test]
    async fn put_if_absent_first_true_replay_false() {
        let eng = RustyVaultEngine::open(&temp_dir("pia"), MK).await.unwrap();
        let p = SecretPath::new("sys", "a2e-nonce-ledger/abc");
        assert!(eng.put_if_absent(&p, b"marker".to_vec()).await.unwrap());
        assert!(!eng.put_if_absent(&p, b"marker2".to_vec()).await.unwrap());
        // The consumed marker is still present.
        assert_eq!(eng.get(&p).await.unwrap(), Some(b"marker".to_vec()));
    }

    #[tokio::test]
    async fn put_if_absent_survives_reopen_same_dir() {
        // A replay after a process restart must still be rejected: the ledger
        // entry persists across an engine drop+reopen against the same dir+key.
        let dir = temp_dir("pia-restart");
        let p = SecretPath::new("sys", "a2e-nonce-ledger/restart-1");
        {
            let eng = RustyVaultEngine::open(&dir, MK).await.unwrap();
            assert!(eng.put_if_absent(&p, b"marker".to_vec()).await.unwrap());
        } // engine dropped — simulates process exit
        let eng2 = RustyVaultEngine::open(&dir, MK).await.unwrap();
        // Second use AFTER restart sees the persisted entry → false (replay).
        assert!(!eng2.put_if_absent(&p, b"marker".to_vec()).await.unwrap());
    }
```

> These mirror the existing `secrets_survive_reopen_same_dir_and_key` test (same `temp_dir` + `MK` helpers, already in scope in this `mod tests`). `put_if_absent` lazily creates the `sys` mount the same way `custom_mount_is_lazily_created` exercises `femto`.

**RED→GREEN:** after 2a the file won't compile until `run()` (2b) and the worker loop (2c) are updated and the impl (2e) added — do 2a–2e together, then 2f passes.

**Verify:**
```
cargo test -p tessera-core rusty
```
Expected: `put_if_absent_first_true_replay_false` and `put_if_absent_survives_reopen_same_dir` pass with the existing rusty tests. (RustyVault tests are slower; allow ~30–60s.)

---

### Task 3 — Expose `idempotency_key` on `MandateClaims`

**File:** `crates/tessera-core/src/mandate.rs`

**3a. Add the field:**

```rust
pub struct MandateClaims {
    pub mandate_id: String,
    pub key_id: String,
    pub subject: String,
    pub audience: String,
    /// `certifies.idempotencyKey` — the per-execution one-time nonce the unwrap
    /// ledger (Phase 2) burns. Empty only on malformed mandates.
    pub idempotency_key: String,
}
```

**3b. Populate it in `verify_mandate`** (in the `MandateClaims { ... }` literal at the end of the `Verified` path):

```rust
        idempotency_key: mandate
            .get("certifies")
            .and_then(|c| c.get("idempotencyKey"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
```

**3c. Fix the existing assertions.** `verify_tests::valid_signed_mandate_verifies_and_returns_claims` constructs/asserts `MandateClaims` via pattern match on fields it names (`mandate_id`, `key_id`, `audience`) — adding a field does NOT break that match (it binds by name, not positionally). BUT any place that constructs `MandateClaims { ... }` as a literal WOULD break (E0063 missing field). Grep first:

```
grep -rn "MandateClaims {" crates/
```

The only literal construction is inside `verify_mandate` itself (3b covers it). If the grep surfaces any test literal, add `idempotency_key: "...".into()`. Add a focused assertion to the existing happy-path verify test:

```rust
        match out {
            MandateOutcome::Verified(claims) => {
                assert_eq!(claims.mandate_id, "m-fixture-1");
                assert_eq!(claims.key_id, FIXTURE_KEY_ID);
                assert_eq!(claims.audience, "tessera.local");
                assert_eq!(claims.idempotency_key, "idem-1"); // from certifies
            }
            _ => panic!("expected Verified"),
        }
```

**Verify:**
```
cargo test -p tessera-core mandate
```
Expected: all `mandate.rs` tests pass; the new `idempotency_key` assertion is green (the `unsigned_mandate` fixture sets `certifies.idempotencyKey = "idem-1"`).

---

### Task 4 — Ledger helper module (id derivation + reserved path)

**File:** NEW `crates/tessera-core/src/nonce_ledger.rs`; register in `crates/tessera-core/src/lib.rs`.

**4a. lib.rs** — add (keep alphabetical-ish, after `mandate`):

```rust
pub mod nonce_ledger;
```

**4b. The module:**

```rust
//! One-time unwrap nonce ledger (trust-plane Phase 2). Pure helpers: derive the
//! durable ledger entry id from `(keyRef, idempotencyKey)` and build the reserved
//! `SecretPath` it lives at. The atomic check-and-insert is `SecretEngine::
//! put_if_absent`; the route enforcement + audit live in tessera-server. See
//! docs/superpowers/specs/2026-06-17-trust-plane-enforcer-design.md §4.

use crate::types::SecretPath;

/// Reserved internal mount for the ledger — NOT a KV/transit scope, so no caller
/// token can reach it (KV/transit policies never grant this mount). See the plan
/// §1.3 reachability note + R3 mount-collision check.
pub const NONCE_LEDGER_MOUNT: &str = "sys";
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
        assert_eq!(p.mount, "sys");
        assert_eq!(p.scope(), "sys/a2e-nonce-ledger/deadbeef");
    }
}
```

**Verify:**
```
cargo test -p tessera-core nonce_ledger
```
Expected: 4 tests pass.

---

### Task 5 — `VaultStore::consume_nonce` + wire into the route (consume before decrypt, burn-on-failure)

**Files:** `crates/tessera-core/src/vault.rs`, `crates/tessera-server/src/routes_transit.rs`.

**5a. `VaultStore::consume_nonce`** (add to `impl VaultStore`, near `record_action`). It calls `put_if_absent` directly on the engine (no `guard()` — internal sys op), writing a small forensic marker:

```rust
    /// One-time unwrap ledger consume (trust-plane Phase 2). Atomically marks
    /// `(key_ref, idempotency_key)` consumed in the durable engine under the
    /// reserved `sys/a2e-nonce-ledger/{id}` path. Returns `Ok(true)` on first use
    /// (caller may proceed) and `Ok(false)` on replay (caller must reject). This
    /// bypasses token authz by design: the ledger is an internal namespace no
    /// caller policy can reach. Burn-on-failure is the CALLER's ordering choice
    /// (consume before decrypt) — once `true` is returned the nonce stays burned.
    pub async fn consume_nonce(
        &self,
        key_ref: &str,
        idempotency_key: &str,
    ) -> Result<bool, TesseraError> {
        let id = crate::nonce_ledger::ledger_entry_id(key_ref, idempotency_key);
        let path = crate::nonce_ledger::ledger_path(&id);
        let now = self.clock.now_rfc3339();
        // Forensic marker (presence is the signal; content is for audit only).
        let marker = serde_json::json!({ "consumedAt": now, "keyRef": key_ref });
        let blob = serde_json::to_vec(&marker)
            .map_err(|e| TesseraError::Storage(format!("encode ledger marker: {e}")))?;
        self.engine.put_if_absent(&path, blob).await
    }
```

**5b. `VaultStore` unit test** (add to `vault.rs` `mod tests`):

```rust
    #[tokio::test]
    async fn consume_nonce_first_true_replay_false_different_nonce_true() {
        let s = store();
        let key_ref = "tessera://transit/galvofs/cap";
        // First use of (cap, n1) → true.
        assert!(s.consume_nonce(key_ref, "n1").await.unwrap());
        // Replay of (cap, n1) → false.
        assert!(!s.consume_nonce(key_ref, "n1").await.unwrap());
        // Different nonce (cap, n2) → true (not a false replay).
        assert!(s.consume_nonce(key_ref, "n2").await.unwrap());
        // Different keyRef, same nonce → true.
        assert!(s.consume_nonce("tessera://transit/galvofs/other", "n1").await.unwrap());
    }
```

**5c. Route wiring** — `routes_transit.rs`. Add a `replay-detected` responder near `mandate_err_response`:

```rust
/// A2E replay rejection: the unwrap nonce was already consumed. 403 + the
/// `replay-detected` code, matching the A2E error model (§3.6 / §4).
fn replay_detected_response() -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({ "errors": ["replay-detected: unwrap nonce already consumed"], "code": "replay-detected" })),
    )
}
```

Then insert the consume step **immediately after `claims` is bound and before the `ciphertext` decode block**:

```rust
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
            return bad_request("mandate-invalid: certifies.idempotencyKey is empty").into_response();
        }
        match state.vault.consume_nonce(&req.key_ref, &c.idempotency_key).await {
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

    let ciphertext = match STANDARD.decode(&req.ciphertext_base64) {  // existing line — unchanged
```

No other route lines change. `claims` is already in scope (bound from `verify_mandate`). `AuditOp`, `bad_request`, `err_response` are already imported.

**RED→GREEN:** 5b first (needs `consume_nonce`), then 5a. The route change is exercised by Task 6's integration tests.

**Verify:**
```
cargo test -p tessera-core vault
cargo build -p tessera-server
```
Expected: `consume_nonce_first_true_...` passes; server compiles.

> macOS PyO3-style note: `tessera-server` is a normal binary/lib (no PyO3) so `cargo build -p tessera-server` links fine. If a link issue ever appears, fall back to `cargo test -p tessera-server --no-run` to typecheck.

---

### Task 6 — Route integration tests (live `serve()` + `reqwest`)

**File:** `crates/tessera-server/tests/transit_unwrap.rs` (extend; mirror existing helpers).

Add a helper that builds a full valid signed mandate with a chosen `idempotencyKey` (the existing `signed_unwrap_mandate` hardcodes `"i-1"` — add a variant), then the four scenarios.

**6a. Helper** (the consume nonce is `certifies.idempotencyKey`):

```rust
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
```

A small reusable post closure (or inline each call) builds the unwrap request body for a `key_ref` + `mandate`. Use the existing `seal_fixture`/`sha256_digest`/`transit_payload_key` helpers.

**6b. Scenario: first unwrap 200, identical replay → 403 `replay-detected`.**

```rust
#[tokio::test]
async fn unwrap_replay_same_nonce_is_replay_detected() {
    let state = transit_state_enforcing();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let key_ref = "tessera://transit/galvofs/replay-cap";
    let nonce = [0x42; 12];
    let plaintext = br#"{"sealed":true}"#;
    let ciphertext = seal_fixture(key_ref, &nonce, plaintext);
    let mandate = signed_unwrap_mandate_idem("spiffe://femto.local/run", "tessera.local", "idem-replay");
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
    let r1 = client.post(format!("{base}/v1/transit/unwrap/galvofs"))
        .header("Authorization", "Bearer unwrap-tok").json(&body).send().await.unwrap();
    assert_eq!(r1.status(), 200);

    // Identical replay (same keyRef + same idempotencyKey): 403 replay-detected.
    let r2 = client.post(format!("{base}/v1/transit/unwrap/galvofs"))
        .header("Authorization", "Bearer unwrap-tok").json(&body).send().await.unwrap();
    assert_eq!(r2.status(), 403);
    let b2: Value = r2.json().await.unwrap();
    assert_eq!(b2["code"], "replay-detected");

    // Audit: a TransitUnwrap outcome=false replay rejection exists.
    let audit = state.vault.audit_sink().records();
    assert!(audit.iter().any(|r| r.op == AuditOp::TransitUnwrap && !r.outcome));
}
```

**6c. Scenario: different `idempotencyKey`, same `keyRef` → allowed (not a false replay).**

```rust
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
        let mandate = signed_unwrap_mandate_idem("spiffe://femto.local/run", "tessera.local", idem);
        let res = client.post(format!("{base}/v1/transit/unwrap/galvofs"))
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
            })).send().await.unwrap();
        assert_eq!(res.status(), 200, "distinct idempotencyKey {idem} must not be a replay");
    }
}
```

**6d. Scenario: burn-on-failure — consume happens before decrypt.** Send a valid signed mandate but a CORRUPT ciphertext/digest so decrypt would fail; first call returns 400 (bad body) AFTER the nonce is burned; a SECOND call with a now-VALID body but the SAME `idempotencyKey` is rejected as `replay-detected` (proving the nonce burned on the failed attempt).

```rust
#[tokio::test]
async fn unwrap_burns_nonce_even_when_later_step_fails() {
    let state = transit_state_enforcing();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();
    let key_ref = "tessera://transit/galvofs/burn-cap";
    let nonce = [0x42; 12];
    let plaintext = br#"{"sealed":true}"#;
    let good_ct = seal_fixture(key_ref, &nonce, plaintext);
    let mandate = || signed_unwrap_mandate_idem("spiffe://femto.local/run", "tessera.local", "idem-burn");

    // Attempt 1: valid mandate, but ciphertextDigest mismatch → 400 AFTER burn.
    let r1 = client.post(format!("{base}/v1/transit/unwrap/galvofs"))
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
        })).send().await.unwrap();
    assert_eq!(r1.status(), 400);

    // Attempt 2: SAME idempotencyKey, now a fully valid body → must be replay-detected,
    // proving the nonce was burned on attempt 1's failed decrypt path.
    let r2 = client.post(format!("{base}/v1/transit/unwrap/galvofs"))
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
        })).send().await.unwrap();
    assert_eq!(r2.status(), 403);
    let b2: Value = r2.json().await.unwrap();
    assert_eq!(b2["code"], "replay-detected");
}
```

**6e. Restart-survival at the route level.** The route tests use `InMemoryEngine` (does NOT persist across a new `serve()`), so restart-survival is covered by the engine-level `put_if_absent_survives_reopen_same_dir` test in Task 2 (which uses the persistent `RustyVaultEngine`). Add a one-line doc comment at the top of 6b pointing to Task 2's test for the durable-restart guarantee, so a reader knows where reboot-replay is proven. (Do NOT attempt a RustyVault-backed `serve()` here — the server test harness only wires `InMemoryEngine`, and re-plumbing it is out of scope for P2.)

**Verify:**
```
cargo test -p tessera-server transit
```
Expected: the four existing transit tests + the three new ledger tests (`unwrap_replay_same_nonce_is_replay_detected`, `unwrap_different_nonce_same_key_is_allowed`, `unwrap_burns_nonce_even_when_later_step_fails`) all pass.

---

### Task 7 — Gates (mandatory, in order)

Run all three. fmt is a SEPARATE gate — clippy+test green does NOT imply fmt clean.

```
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

Expected:
- `cargo test --workspace`: all crates green (`test result: ok.` for tessera-core unit, tessera-server unit + every `tests/*.rs` integration binary). The trait change compiles across BOTH impls (Task 1+2) — no E0046.
- `cargo clippy --workspace -- -D warnings`: clean. Watch for: `await_holding_lock` (the InMemory `put_if_absent` does NOT await under the guard — fine; the RustyVault worker reuses the existing `#[allow(clippy::await_holding_lock)]` helper — fine); unused imports.
- `cargo fmt --all -- --check`: no diff. If it reports drift, run `cargo fmt --all` and re-run the check.

If any gate fails, fix and re-run ALL THREE (a fmt fix can't regress tests, but re-confirm clippy after any edit).

> Stale-toolchain caveat (from prior CI burns): if clippy finishes in ~0.1s it's cached; force with `cargo clean -p tessera-core -p tessera-server` or `touch` a changed file, and ensure `rustup show` matches CI's stable.

---

## 4. File-change summary

| File | Change |
|---|---|
| `crates/tessera-core/src/engine.rs` | `put_if_absent` trait method + `InMemoryEngine` atomic impl + 3 tests |
| `crates/tessera-core/src/rusty_engine.rs` | `JobKind` enum, `run()`/worker-loop refactor, `put_if_absent_job` helper, `RustyVaultEngine::put_if_absent` impl + 2 tests |
| `crates/tessera-core/src/mandate.rs` | `idempotency_key` field on `MandateClaims` + populate in `verify_mandate` + assertion |
| `crates/tessera-core/src/nonce_ledger.rs` | NEW — `ledger_entry_id`, `ledger_path`, consts + 4 tests |
| `crates/tessera-core/src/lib.rs` | `pub mod nonce_ledger;` |
| `crates/tessera-core/src/vault.rs` | `VaultStore::consume_nonce` + 1 test |
| `crates/tessera-server/src/routes_transit.rs` | `replay_detected_response` + consume-before-decrypt block |
| `crates/tessera-server/tests/transit_unwrap.rs` | `signed_unwrap_mandate_idem` helper + 3 integration tests |

No changes outside `tessera/`. No new crates/deps (blake3, serde_json, base64ct already present).

---

## 5. Spec-coverage self-check (§4)

| §4 requirement | Covered by |
|---|---|
| Key = `(keyRef, consumeNonce)`, nonce = `certifies.idempotencyKey` | Task 3 (expose) + Task 4 (`ledger_entry_id`) |
| Atomic check-and-insert | Task 1 (InMemory single guard) + Task 2 (one actor job) |
| Replay → `replay-detected` | Task 5 (`replay_detected_response`) + Task 6b |
| Burn-on-failure (consume before decrypt) | Task 5 ordering + Task 6d |
| Replacement-ticket exception out of scope | Documented in Task 5 comment + §2 |
| Durable / survives restart | Task 2 `put_if_absent_survives_reopen_same_dir` (RustyVault); Task 6e note |
| Audit replay rejection (`TransitUnwrap` outcome=false) | Task 5 `record_action(..., false)` + Task 6b assertion |

---

## 6. Grounding surprises & risks (executor MUST heed)

- **R1 — `MandateClaims` did NOT expose `idempotencyKey`.** Confirmed: it has only `mandate_id/key_id/subject/audience`. Task 3 adds it. It IS available + non-empty post-P1 (the wire mandate carries `certifies.idempotencyKey`; transit test fixture = `"i-1"`, mandate.rs fixture = `"idem-1"`, cross-lang vector = `idem-wo_vector_1`). The `verify_mandate` path can already see `certifies` (it's just a `Value` lookup).
- **R2 — The route reaches the engine ONLY via `state.vault` (`VaultStore`); `VaultStore.engine` is private.** There is no direct engine handle on `AppState`. Hence the ledger op is a new `VaultStore::consume_nonce` method (Task 5a) that calls `self.engine.put_if_absent` — NOT a direct engine call from the route. This also keeps the engine `dyn`-object-safe (the trait stays object-safe — `put_if_absent` has no generics).
- **R3 — `sys` mount-name collision (verify before merge).** RustyVault uses a reserved internal `sys/` *system backend* for mount admin (`ensure_mount` writes `sys/mounts/{mount}/`). Our ledger uses a KV-v1 *mount* literally named `sys` with logical path `sys/a2e-nonce-ledger/{id}`. The executor MUST confirm `RustyVaultEngine::put_if_absent` against a fresh dir actually stores+reads under mount `sys` WITHOUT colliding with the system backend (Task 2's `put_if_absent_first_true_replay_false` is the canary — if it errors with a RustyVault mount/path conflict, change `NONCE_LEDGER_MOUNT` to `"tessera-sys"` in `nonce_ledger.rs` and re-run; the InMemory + path tests don't care about the name). Pick the safe name and keep it.
- **R4 — Exactly TWO `SecretEngine` impls, NO test mocks.** Adding `put_if_absent` is a cross-crate trait change but only `InMemoryEngine` + `RustyVaultEngine` implement it. `cargo test --workspace` (Task 7) is the E0046 guard; the per-crate `cargo test -p tessera-core` already exercises both. No hidden mock to update.
- **R5 — `EngineJob` is currently single-op.** It cannot do an atomic RMW as-is; Task 2 widens it to a `JobKind` enum so check+write run in ONE worker turn. This is the load-bearing atomicity change — do NOT shortcut it with two `run()` awaits from the route (that races, defeating one-time use).
- **R6 — Dev `SkippedDev` path has no nonce.** The ledger only engages on `MandateOutcome::Verified`. Existing dev-mode transit tests (`transit_state`, `allow_unsigned_dev=true`, no mandate) keep passing and remain replayable BY DESIGN (no verified mandate → no one-time semantic). Enforcement rides on a verified mandate, per §3.5/§4.
- **R7 — fmt is a separate gate.** Per prior CI burns, run `cargo fmt --all -- --check` explicitly even after clippy+test are green.

---

## 7. Definition of done

- All three gates (Task 7) green: `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --all -- --check`.
- New tests: 3 (engine) + 2 (rusty) + 1 (mandate assertion) + 4 (nonce_ledger) + 1 (vault) + 3 (route) = 14 new test cases, all passing.
- No `todo!()`/`unimplemented!()`/placeholders. No changes outside `tessera/`.
- R3 mount-name resolved (verified `sys` works or switched to `tessera-sys`).
