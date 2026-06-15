use std::sync::Arc;

use axum::Router;
use tessera_core::audit::InMemoryAudit;
use tessera_core::engine::InMemoryEngine;
use tessera_core::kv::KvStore;

/// Server state: the KvStore behind an Arc. V1 uses InMemoryEngine in tests;
/// `main.rs` swaps RustyVaultEngine for production (same KvStore<_, _> shape via a boxed engine later).
pub type AppKv = KvStore<InMemoryEngine, InMemoryAudit>;

#[derive(Clone)]
pub struct AppState {
    pub kv: Arc<AppKv>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(crate::routes_sys::routes())
        .merge(crate::routes_kv::routes())
        .with_state(state)
}
