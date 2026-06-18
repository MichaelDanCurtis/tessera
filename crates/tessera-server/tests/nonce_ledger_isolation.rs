//! Defense-in-depth: the one-time-unwrap nonce ledger (trust-plane Phase 2) lives
//! under the reserved internal mount `tessera-sys/a2e-nonce-ledger/{id}`. A normal
//! Femto trust-op token is scoped to `transit/unwrap/` — it MUST NOT be able to
//! read a consumed-nonce ledger entry (to learn what was burned) or delete one (to
//! forge a non-replay). The ledger's isolation was previously only structural
//! (no KV/transit policy grants the `tessera-sys/` scope); these tests pin it.
//!
//! Authz runs BEFORE existence in `VaultStore` (every route guards the scope first,
//! then loads), so a scoped token hitting an unauthorized mount gets 403 Forbidden
//! — NOT 404 — even for a path that does not exist. That mirrors the sibling
//! `secret_scoped_token_cannot_unwrap_galvofs_payload` test in `transit_unwrap.rs`.

use std::sync::Arc;

use tessera_core::audit::InMemoryAudit;
use tessera_core::auth::{Policy, PolicyStore, TokenStore};
use tessera_core::clock::FixedClock;
use tessera_core::engine::InMemoryEngine;
use tessera_core::seal::SealState;
use tessera_core::vault::VaultStore;
use tessera_server::app::{router, AppState, TrustConfig};

/// A server whose only token is scoped to `transit/unwrap/` — the realistic Femto
/// trust-op scope. It grants nothing under the reserved `tessera-sys/` ledger mount.
fn unwrap_scoped_state() -> AppState {
    let mut tokens = TokenStore::new();
    tokens.insert("unwrap-tok", Policy::new(["transit/unwrap/"]));
    let seal = SealState::new(b"m".to_vec());
    seal.unseal(b"m").unwrap();
    let vault = VaultStore::new(
        Arc::new(InMemoryEngine::new()),
        seal,
        tokens,
        Arc::new(PolicyStore::in_memory()),
        Arc::new(InMemoryAudit::new()),
        Arc::new(FixedClock("2026-06-14T00:00:00Z".into())),
    );
    AppState {
        vault: Arc::new(vault),
        trust: TrustConfig::dev_default(),
    }
}

async fn serve(state: AppState) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    format!("http://{addr}")
}

/// A `transit/unwrap/`-scoped caller cannot READ a ledger entry — authz denies the
/// `tessera-sys/` scope before any existence check, so it learns nothing about which
/// nonces have been consumed.
#[tokio::test]
async fn unwrap_scoped_token_cannot_read_nonce_ledger_entry() {
    let state = unwrap_scoped_state();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!(
            "{base}/v1/tessera-sys/data/a2e-nonce-ledger/deadbeefdeadbeef"
        ))
        .header("Authorization", "Bearer unwrap-tok")
        .send()
        .await
        .unwrap();

    // 403, NOT 200 and NOT 404: the scoped policy does not cover `tessera-sys/`,
    // and authz precedes existence.
    assert_eq!(
        res.status(),
        403,
        "transit/unwrap/-scoped token must be forbidden from reading the ledger mount"
    );
}

/// The same caller cannot DELETE a ledger entry — it can't purge a consumed nonce
/// to re-enable a replay. Both the soft-delete (`/data` DELETE) and the version
/// `/delete` route must reject with 403.
#[tokio::test]
async fn unwrap_scoped_token_cannot_delete_nonce_ledger_entry() {
    let state = unwrap_scoped_state();
    let base = serve(state.clone()).await;
    let client = reqwest::Client::new();

    // Soft-delete via the KV data route.
    let del = client
        .delete(format!(
            "{base}/v1/tessera-sys/data/a2e-nonce-ledger/deadbeefdeadbeef"
        ))
        .header("Authorization", "Bearer unwrap-tok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        del.status(),
        403,
        "transit/unwrap/-scoped token must be forbidden from deleting a ledger entry"
    );
    assert_ne!(del.status(), 204, "delete must NOT have succeeded");

    // Version-delete route.
    let del_versions = client
        .post(format!(
            "{base}/v1/tessera-sys/delete/a2e-nonce-ledger/deadbeefdeadbeef"
        ))
        .header("Authorization", "Bearer unwrap-tok")
        .json(&serde_json::json!({ "versions": [1] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        del_versions.status(),
        403,
        "transit/unwrap/-scoped token must be forbidden from version-deleting a ledger entry"
    );
    assert_ne!(
        del_versions.status(),
        204,
        "version-delete must NOT have succeeded"
    );
}
