use std::sync::Arc;

use axum::Router;
use tessera_core::vault::VaultStore;

/// Server state: the `VaultStore` behind an Arc. `VaultStore` is a single concrete
/// (non-generic) type holding `Arc<dyn SecretEngine>` + `Arc<dyn AuditSink>`, so
/// `main.rs` injects `RustyVaultEngine` and tests inject `InMemoryEngine` without
/// changing this state type.
#[derive(Clone)]
pub struct AppState {
    pub vault: Arc<VaultStore>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(crate::routes_sys::routes())
        .merge(crate::routes_kv::routes())
        .with_state(state)
}
