# Tessera

**The singular Lucidity Vault** — one place for secrets, certificates, and role keys across the Lucidity platform.

Tessera is a small, fast secrets vault written in Rust. It speaks a **HashiCorp-Vault-compatible KV-v2 HTTP API**, so existing Vault clients work against it largely unchanged, and it stores everything encrypted at rest using the **NIST/OpenSSL** cryptography suite (AES-256-GCM, SHA-2) — never the ShangMi/SM suite. It is built on [RustyVault](https://github.com/Tongsuo-Project/RustyVault) as the embedded storage/crypto core, with all of the higher-level behaviour (versioning, policy, audit, persistence) implemented in Tessera itself.

> **Status:** V1.1 — a restart-safe vault with full KV-v2 versioning. 68 tests green; `clippy -D warnings` and `rustfmt` clean. PKI (V1.5) and the consumer integrations are on the roadmap below.

---

## What you get

- **KV-v2 secrets** — versioned key/value secrets with the full Vault KV-v2 lifecycle: write, read any past version, roll back, soft-delete / undelete / destroy, configurable `max_versions` (default 10), and check-and-set (CAS) writes.
- **Durable** — secrets and their version history survive process restart. The vault initializes once and unseals on subsequent boots.
- **Sealed at rest** — everything on disk is encrypted; the vault's own unseal material is itself sealed under an operator-supplied **master key**. Nothing sensitive is ever written in plaintext or logged.
- **Path-scoped tokens** — every request is authenticated by a token whose policy allow-lists the secret paths it may touch. Out-of-scope access is denied **fail-closed**, before the storage engine is ever consulted.
- **Append-only audit** — every secret operation and every auth denial is recorded; raw tokens are hashed (blake3), never stored.
- **Vault-compatible** — the KV-v2 path layout and `sys/health` semantics match HashiCorp Vault closely enough that standard read-only Vault tooling works against Tessera (verified by a contract test).

---

## Quick start

Tessera needs a master key and a data directory. The master key unlocks the vault on every boot and is **never** stored inside it — supply it via an environment variable or a file readable only by the service account.

```bash
# Build
cargo build --release

# Run (development)
export TESSERA_MASTER_KEY="change-me-to-a-long-random-secret"
export TESSERA_DATA_DIR="./data"          # default: ./data
export TESSERA_BIND="127.0.0.1:8200"      # default: 127.0.0.1:8200
./target/release/tessera-server
```

Write and read a secret (KV-v2 layout, `secret` mount):

```bash
TESSERA=http://127.0.0.1:8200
TOKEN=...   # a token whose policy is scoped to secret/galvo/

# Write version 1
curl -s -X POST "$TESSERA/v1/secret/data/galvo/openai" \
  -H "X-Vault-Token: $TOKEN" -H 'content-type: application/json' \
  -d '{"data":{"api_key":"sk-..."}}'

# Read the current version
curl -s "$TESSERA/v1/secret/data/galvo/openai" -H "X-Vault-Token: $TOKEN"

# Read a specific past version
curl -s "$TESSERA/v1/secret/data/galvo/openai?version=1" -H "X-Vault-Token: $TOKEN"

# Inspect metadata (versions, timestamps, config)
curl -s "$TESSERA/v1/secret/metadata/galvo/openai" -H "X-Vault-Token: $TOKEN"
```

Auth header is `X-Vault-Token: <token>` (or `Authorization: Bearer <token>`).

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `TESSERA_MASTER_KEY` | *(required)* | Unlocks the vault on boot. Never stored on disk. |
| `TESSERA_DATA_DIR` | `./data` | On-disk storage root (encrypted barrier + seal sidecar). |
| `TESSERA_BIND` | `127.0.0.1:8200` | HTTP listen address. |
| `TESSERA_CRYPTO_BACKEND` | `openssl` | Crypto provider. Tessera **refuses to start** on a non-NIST backend (e.g. `tongsuo`/`sm`). |

---

## API surface (KV-v2)

Default mount is `secret`; `{path}` is multi-segment.

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/{mount}/data/{path}` | Write a new version. Body `{"data":{...},"options":{"cas":N}}`. |
| `GET` | `/v1/{mount}/data/{path}?version=N` | Read a version (default: current). Deleted/destroyed → `data: null`. |
| `DELETE` | `/v1/{mount}/data/{path}` | Soft-delete the latest version. |
| `POST` | `/v1/{mount}/delete/{path}` | Soft-delete specific `{"versions":[...]}`. |
| `POST` | `/v1/{mount}/undelete/{path}` | Restore soft-deleted versions. |
| `POST` | `/v1/{mount}/destroy/{path}` | Permanently destroy version data (unrecoverable). |
| `GET` | `/v1/{mount}/metadata/{path}` | Version list, timestamps, `max_versions`, `cas_required`. |
| `POST` | `/v1/{mount}/metadata/{path}` | Configure `{"max_versions":N,"cas_required":bool}`. |
| `DELETE` | `/v1/{mount}/metadata/{path}` | Delete the whole secret + all versions. |
| `GET` | `/v1/{mount}/metadata/{path}?list=true` | List secret names under a prefix. |
| `GET` | `/v1/sys/health` | `{"sealed":bool}` — `200` unsealed, `503` sealed. |
| `GET` | `/v1/sys/seal-status` | Seal state. |

**Check-and-set (CAS):** `options.cas = N` writes only if `N` equals the current version; `cas = 0` means "create only if absent." Setting `cas_required` on a secret rejects any write that omits `cas`.

---

## Architecture

Two crates in a Cargo workspace:

```
tessera-core   library — all vault logic, storage-engine-agnostic
  ├── SecretEngine   async, object-safe blob store (one Vec<u8> per path)
  │     ├── InMemoryEngine    (tests / contract)
  │     └── RustyVaultEngine  (real: rusty_vault::Core, file backend, encrypted)
  ├── VaultStore     KV-v2 orchestration: version history, CAS, delete/undelete/destroy
  ├── SealState      master-key seal/unseal gate
  ├── auth           token + path-scoped policies (fail-closed)
  └── audit          append-only log, blake3-hashed tokens

tessera-server   binary — axum HTTP service exposing the KV-v2 + sys API
```

The storage engine is a primitive **blob store**; all KV-v2 version semantics live in `VaultStore` as an atomic read-modify-write of a single `VersionedSecret` record per path. RustyVault is wrapped behind the `SecretEngine` trait so Tessera owns its own API surface and can swap internals.

**Embedding note:** `rusty_vault::Core` is bound to `std::sync` primitives and its request handler is `!Send`, so Tessera runs the `Core` on a **dedicated worker thread** with its own runtime; the async `SecretEngine` methods dispatch jobs to it over a channel. This keeps the public trait fully async without ever blocking the server's runtime.

---

## Security model

- **Encryption at rest.** Every secret is encrypted on disk with the **NIST/OpenSSL** suite (AES-256-GCM, SHA-2). The crypto backend is pinned away from the ShangMi/SM (国密) suite and the server refuses to start if a non-NIST backend is configured.
- **Master key & unseal.** RustyVault keeps its internal encryption keys *sealed*. They are protected by the operator-supplied master key, which is never written into the vault. On first boot the vault initializes and writes its unseal material into a `0600` sidecar (`tessera-seal.json.enc`) encrypted with AES-256-GCM under a key derived from the master key; on every later boot it decrypts that sidecar and unseals. A wrong master key fails closed.
- **Fail-closed access.** Every operation runs *require-unsealed → authorize → act → audit*. An out-of-scope or unauthenticated request is denied before the storage engine is touched, so it cannot even learn whether a secret exists outside its scope.
- **No secret material in logs.** Tokens are hashed before audit; the master key and unseal shares never appear in logs, errors, or `Debug` output.

> Single master key is the V1.1 model (right for a single instance). A multi-operator unseal ceremony (Shamir at the operator boundary) is a future hardening, not required for single-instance deployments.

---

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check        # separate gate — run it explicitly
```

All four are expected to be clean. The test suite includes a **restart-survival** acceptance test (secrets persist across an engine drop/reopen) and a **Vault-compatibility contract test** (the exact wire shapes a standard read-only Vault client expects).

Design docs live in the Galvo repo under `docs/superpowers/specs/` (the V1 and V1.1 design specs).

---

## Roadmap

- **V1.5 — PKI.** Tessera becomes Lucidity's internal certificate authority via RustyVault's PKI engine: internal certs, service-mesh mTLS, and role keys, self-hosted. Public/external TLS via Let's Encrypt (ACME), managed by Tessera.
- **Consumers.** A Galvo secret broker (provider keys via Tessera instead of environment variables), a KubeNyx repoint onto Tessera's Vault-compatible API, Femto capsule identity, and an egress credential broker.
- **Operator UI.** A read-first vault surface (seal state, secret paths, versions, audit — never values) exposed through the Galvo dashboard.
- **Later.** Dynamic secrets, transit (encryption-as-a-service), multi-operator unseal, hash-chained audit, multi-node storage.

---

## License

Apache-2.0.
