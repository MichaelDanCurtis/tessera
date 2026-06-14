# Spike: RustyVault adoption (embed-vs-subprocess decision)

**Task:** Tessera T2 — investigation only (no Tessera feature code).
**Date:** 2026-06-14
**Method:** Read actual source. The published crate `rusty_vault 0.2.1` was pulled into the
local cargo registry (`cargo add rusty_vault` in `crates/tessera-core`, then removed) and its
`Cargo.toml`, `Cargo.toml.orig`, `build.rs`, `src/lib.rs`, `src/core.rs`, `src/test_utils.rs`,
`src/utils/key.rs`, `src/modules/crypto/mod.rs`, and `tests/test_default_logical.rs` were read
directly from
`~/.cargo/registry/src/index.crates.io-*/rusty_vault-0.2.1/`. The GitHub `main` `Cargo.toml`
(currently `0.3.1`) was also fetched for comparison. A consumer build was compiled and the
resulting `Cargo.lock` inspected to prove which crypto backend actually links.

> **HARD CONSTRAINT (recap):** crypto must be OpenSSL or native-Rust, **never** Tongsuo / SM
> (ShangMi / 国密). This spike's central job is to retire the risk that RustyVault forces SM in.

---

## Q1 — Crate identity

**Published on crates.io: YES.**

- Exact crate name: **`rusty_vault`** (underscore). `cargo search rustyvault` also surfaces it,
  but the package name is `rusty_vault`.
- Latest crates.io release: **`0.2.1`** (Apache-2.0). `cargo info rusty_vault` →
  `version: 0.2.1`, `repository: https://github.com/Tongsuo-Project/RustyVault`,
  `documentation: https://docs.rs/rusty_vault/latest/rusty_vault/`.
- It **is a library** (not server-only). The published manifest has both:
  ```toml
  [lib]
  name = "rusty_vault"
  path = "src/lib.rs"

  [[bin]]
  name = "rvault"
  path = "bin/rusty_vault.rs"
  ```
  `src/lib.rs` doc comment states it explicitly: *"RustyVault ... works in two ways
  independently: 1. A standalone application serving secrets management via RESTful API;
  2. A Rust crate that provides same features for other application to integrate."*

**Dependency line a consumer puts in `Cargo.toml`** (crates.io, recommended):

```toml
rusty_vault = { version = "0.2.1", default-features = false, features = ["crypto_adaptor_openssl"] }
```

(Plain `rusty_vault = "0.2.1"` also works and selects the same OpenSSL adaptor by default — see
Q2 — but pinning `default-features = false` + explicit `crypto_adaptor_openssl` is the
defensive form so a future default change can't silently pull a different backend.)

> ### Version note — DO NOT use a git dependency on `main`
> The crates.io release **0.2.1** and GitHub `main` (**0.3.1**) differ in a way that matters to
> our hard constraint. The published 0.2.1 `Cargo.toml.orig` has the Tongsuo OpenSSL fork
> `[patch.crates-io]` **commented out** (verified, lines 84–86):
> ```toml
> #[patch.crates-io]
> #openssl = { git = "https://github.com/Tongsuo-Project/rust-tongsuo.git" }
> #openssl-sys = { git = "https://github.com/Tongsuo-Project/rust-tongsuo.git" }
> ```
> The GitHub `main` manifest (0.3.1) has those `[patch.crates-io]` lines **active** at the
> workspace root. A `[patch]` only applies to the crate that owns the workspace root — a
> downstream consumer that depends on `rusty_vault` from crates.io does **not** inherit the
> patch — but depending on it as a `git` dependency on `main` would build RustyVault's own tree
> and could drag in the Tongsuo openssl-sys fork. **Use the crates.io release, not git.**

---

## Q2 — Crypto backend selection (OpenSSL/native, exclude Tongsuo/SM)

**Crypto backend IS feature-selectable, and OpenSSL is the default.** SM is NOT unconditionally
linked in the published crate. Constraint retired.

Exact `[features]` from the published `rusty_vault 0.2.1` `Cargo.toml` (verbatim):

```toml
[features]
crypto_adaptor_openssl = [
    "dep:openssl",
    "dep:openssl-sys",
]
crypto_adaptor_tongsuo = [
    "dep:openssl",
    "dep:openssl-sys",
]
default = ["crypto_adaptor_openssl"]
storage_mysql = [
    "diesel",
    "r2d2",
    "r2d2-diesel",
]
```

Published dependency lines (verbatim) — note these resolve to **vanilla crates.io openssl**,
not a fork:

```toml
[dependencies.openssl]
version = "0.10.64"
optional = true

[dependencies.openssl-sys]
version = "0.9.102"
optional = true
```

How the adaptor is chosen at compile time (`build.rs`, verbatim core logic):

```rust
#[cfg(all(feature = "crypto_adaptor_openssl", feature = "crypto_adaptor_tongsuo"))]
compile_error! { /* "Only one cryptography adapator can be enabled!" */ }

fn main() {
    if let Ok(_) = env::var("DEP_OPENSSL_TONGSUO") {
        println!("cargo:rustc-cfg=tongsuo");
    } else if cfg!(feature = "crypto_adaptor_tongsuo") {
        println!("cargo:rustc-cfg=tongsuo");
    }
    // ...
}
```

Reading of the mechanism:
- The two adaptor features are **mutually exclusive** — enabling both is a hard `compile_error!`.
- The `tongsuo` cfg (which switches SM-specific code on) is set **only** if either the
  `crypto_adaptor_tongsuo` feature is enabled, **or** the environment exposes
  `DEP_OPENSSL_TONGSUO` (which is only present when `openssl-sys` was itself built against a
  Tongsuo OpenSSL). With the vanilla crates.io `openssl-sys` and the openssl adaptor, **neither
  condition holds**, so `tongsuo` is off.
- SM-specific code paths are `#[cfg(feature = "crypto_adaptor_tongsuo")]`-gated. Verified in
  `src/utils/key.rs` (e.g. `sm4-ccm` cipher arms at lines 55–58 and the Tongsuo-only branch at
  line 91; the `#[cfg(not(feature = "crypto_adaptor_tongsuo"))]` fallback at line 101) and in
  `src/modules/crypto/mod.rs` (lines 59/61 select the adaptor module; the SM4 doctests at
  144/292 are `crypto_adaptor_tongsuo`-gated). Under the openssl adaptor those arms compile out.
  - Caveat worth knowing (not a blocker): a few `sm2`/`sm3`/`sm4-gcm` references in `key.rs`,
    `cert.rs`, `salt.rs` are **ungated** because they map to symbols that exist in *standard*
    OpenSSL ≥1.1.1 (`Nid::SM2`, `MessageDigest::sm3()`, `Cipher::sm4_gcm()`) — i.e. they resolve
    against the vanilla `openssl` crate, not against Tongsuo. They are reachable only if a caller
    explicitly asks for an `sm*` key type; Tessera's `SecretEngine` wrapper never will. The
    *Tongsuo-only* primitives (e.g. `sm4-ccm`) are the ones behind the feature gate and are not
    compiled.

### Crypto-feature decision (copy verbatim into Task 9)

- **Enable:** `crypto_adaptor_openssl`
- **Leave OFF (never enable):** `crypto_adaptor_tongsuo`
- **Set `default-features = false`** and list `crypto_adaptor_openssl` explicitly, so a future
  upstream default flip cannot silently change the backend.
- **Use the crates.io release `0.2.1`, NOT a git dependency on `main`** (avoids the active
  Tongsuo `[patch.crates-io]` in the workspace root).
- **Build/CI env:** do not set / unset `DEP_OPENSSL_TONGSUO`; link against system or vendored
  vanilla OpenSSL (whatever the standard `openssl-sys` finds). Optionally add the `vendored`
  feature of `openssl` later for hermetic builds — not required for the spike.

Exact Cargo.toml line for Task 9:
```toml
rusty_vault = { version = "0.2.1", default-features = false, features = ["crypto_adaptor_openssl"] }
```

### Proof it links vanilla OpenSSL (not Tongsuo)

A consumer build was run during this spike (`cargo build -p tessera-core` with
`rusty_vault = "0.2.1"` temporarily added). It compiled successfully, and `Cargo.lock` resolved:

```
name = "openssl"
version = "0.10.81"
source = "registry+https://github.com/rust-lang/crates.io-index"

name = "openssl-sys"
version = "0.9.117"
source = "registry+https://github.com/rust-lang/crates.io-index"
```

`grep -i tongsuo Cargo.lock` → **no matches**. Both openssl crates come from the standard
crates.io registry, confirming no Tongsuo git source is pulled. (The temporary dependency was
then removed; workspace builds clean — see footer.)

---

## Q3 — Embeddability (in-process KV write/read)

**EMBEDS CLEANLY.** RustyVault exposes a fully public in-process API; no HTTP server is required
to drive the KV secrets engine. Verified against `src/core.rs`, `src/test_utils.rs`, and the
integration test `tests/test_default_logical.rs`.

Public surface (`src/core.rs`, all `pub`):
- `pub struct Core { pub physical: Arc<dyn PhysicalBackend>, pub barrier: Arc<dyn SecurityBarrier>, ... }`
  — implements `Default`.
- `pub fn config(&mut self, core: Arc<RwLock<Core>>, config: Option<&Config>) -> Result<(), RvError>`
- `pub fn init(&mut self, seal_config: &SealConfig) -> Result<InitResult, RvError>`
- `pub fn unseal(&mut self, key: &[u8]) -> Result<bool, RvError>`
- `pub fn seal(&mut self, _token: &str) -> Result<(), RvError>`
- `pub async fn handle_request(&self, req: &mut Request) -> Result<Option<Response>, RvError>`

Supporting types (all `pub`, re-exported from `crate::{core, logical, storage}`):
`InitResult`, `SealConfig`, `logical::{Operation, Request, Response}`, `storage::{Backend,
new_backend, barrier_aes_gcm::AESGCMBarrier}`.

### Verified constructor + write/read call sequence

Distilled from `test_utils.rs` (`test_backend`, `test_rusty_vault_core_new`,
`test_rusty_vault_core_init`, `test_rusty_vault_core_unseal`, `test_write_api`, `test_read_api`)
and `tests/test_default_logical.rs` (`test_kv_logical_backend`). These are the **real** type and
method names.

```rust
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde_json::{json, Map, Value};
use rusty_vault::core::{Core, SealConfig};
use rusty_vault::logical::{Operation, Request};
use rusty_vault::storage::{self, barrier_aes_gcm::AESGCMBarrier};

// 1. Construct a storage backend (file backend shown; "path" -> a dir on disk).
let mut conf: HashMap<String, Value> = HashMap::new();
conf.insert("path".into(), Value::String("/var/lib/tessera/rv".into()));
let backend = storage::new_backend("file", &conf)?;          // Arc<dyn Backend>

// 2. Wrap it in the AES-GCM security barrier and build the Core handle.
let barrier = AESGCMBarrier::new(Arc::clone(&backend));
let core = Arc::new(RwLock::new(Core {
    physical: backend,
    barrier: Arc::new(barrier),
    ..Default::default()
}));

// 3. config -> init -> unseal (first boot). init returns root token + Shamir key shares.
let init_result = {
    let mut c = core.write().unwrap();
    c.config(Arc::clone(&core), None)?;
    c.init(&SealConfig { secret_shares: 10, secret_threshold: 5 })?
};
let root_token = init_result.root_token;
{
    let mut c = core.write().unwrap();
    for i in 0..5 { c.unseal(&init_result.secret_shares[i])?; } // up to threshold
}

// 4. Mount the kv secrets engine at "kv/" (one-time, via a sys/mounts write request).
{
    let c = core.read().unwrap();
    let mut req = Request::new("sys/mounts/kv/");
    req.operation = Operation::Write;
    req.client_token = root_token.clone();
    req.body = Some(json!({ "type": "kv" }).as_object().unwrap().clone());
    c.handle_request(&mut req).await?;
}

// 5. WRITE a secret: Operation::Write to "kv/<name>" with a JSON body.
{
    let c = core.read().unwrap();
    let mut req = Request::new("kv/my-secret");
    req.operation = Operation::Write;
    req.client_token = root_token.clone();
    req.body = Some(json!({ "foo": "bar" }).as_object().unwrap().clone());
    c.handle_request(&mut req).await?;
}

// 6. READ it back: Operation::Read; the value comes back in Response::data.
let read_resp = {
    let c = core.read().unwrap();
    let mut req = Request::new("kv/my-secret");
    req.operation = Operation::Read;
    req.client_token = root_token.clone();
    c.handle_request(&mut req).await?           // Result<Option<Response>, RvError>
};
// read_resp.unwrap().data -> Some(Map{"foo": "bar"})
```

Notes for Task 9:
- `handle_request` is `async` and takes `&self` (so it runs behind `core.read()`); `init`/
  `unseal`/`config`/`seal` are `&mut self` (need `core.write()`). The `Core` handle is shared as
  `Arc<RwLock<Core>>`. This is a `std::sync::RwLock`, not tokio's — keep critical sections short
  and do not hold the guard across `.await` (relevant skill:
  `rust-sync-mutex-held-across-block-on`). `handle_request` itself only needs a read guard.
- The integration test `tests/test_default_logical.rs::test_kv_logical_backend` exercises exactly
  this path (mount `kv` at `sys/mounts/kv/`, then `Operation::Write` `kv/secret`, then
  `Operation::Read` `kv/secret`) entirely in-process with no HTTP server — direct evidence the
  embed path is real and supported.
- This is RustyVault's KV **v1** logical backend mounted at an arbitrary path. Tessera's V1 spec
  targets KV **v2** API fidelity (`data/` + `metadata/`, versioning). That semantic gap is a
  Task 9 / Task 11 concern (Tessera's `SecretEngine` + KV-v2 routes wrap whatever RustyVault
  provides); it does **not** affect the embed-vs-subprocess decision. Flagged so Task 9 plans for
  mapping v2 semantics on top of RustyVault's v1 KV (or evaluates whether 0.2.1 ships a v2 kv
  backend type — `"type": "kv"` mounted v1 in the test).

---

## Decision

### EMBED

Task 9's `RustyVaultEngine` wraps the **in-process** `rusty_vault::core::Core` handle. RustyVault
is a published crates.io library (`rusty_vault 0.2.1`) with a fully `pub` embeddable API; no
subprocess / HTTP server is needed. Verified constructor signature and write/read sequence:

- **Construct:** build `storage::new_backend("file", &conf)` → wrap in
  `AESGCMBarrier::new(backend)` → `Core { physical, barrier, ..Default::default() }` inside
  `Arc<RwLock<Core>>`.
- **Init/unseal:** `core.config(Arc::clone(&core), None)` → `core.init(&SealConfig { secret_shares,
  secret_threshold })` (returns `InitResult { root_token, secret_shares }`) → `core.unseal(key)`
  up to threshold.
- **Mount once:** `handle_request` with `Operation::Write` to `sys/mounts/kv/`, body
  `{"type":"kv"}`.
- **Write:** `Request::new("kv/<name>")`, `req.operation = Operation::Write`, `req.client_token =
  root_token`, `req.body = Some(<map>)`, `core.handle_request(&mut req).await`.
- **Read:** same but `Operation::Read`; value in `Response::data`.

### Crypto-feature decision (verbatim for Task 9)

```toml
rusty_vault = { version = "0.2.1", default-features = false, features = ["crypto_adaptor_openssl"] }
```
- Enable `crypto_adaptor_openssl`. **Never** enable `crypto_adaptor_tongsuo`.
- Use the **crates.io 0.2.1 release** (NOT a git dep on `main`, which activates the Tongsuo
  `[patch.crates-io]` openssl fork).
- Do not set `DEP_OPENSSL_TONGSUO`; link vanilla crates.io `openssl-sys` (system or `vendored`).
- Proven: a consumer build resolved `openssl 0.10.81` + `openssl-sys 0.9.117` from crates.io,
  zero `tongsuo` source in `Cargo.lock`.

### Fallback note (no impact on the rest of the build)

Even though we chose EMBED, Tessera's own `SecretEngine` trait + `InMemoryEngine` (Tasks 4/8)
remain the substrate for all non-RustyVault tests, so the rest of the build is independent of
RustyVault. If RustyVault's KV-v1 ↔ Tessera KV-v2 mapping proves awkward in Task 9/11, the wrapper
boundary lets us swap to a native-Rust KV implementation behind `SecretEngine` without touching
the server, routes, or any other task.
