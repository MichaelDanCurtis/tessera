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

/// Server state: the `VaultStore` behind an Arc. `VaultStore` is a single concrete
/// (non-generic) type holding `Arc<dyn SecretEngine>` + `Arc<dyn AuditSink>`, so
/// `main.rs` injects `RustyVaultEngine` and tests inject `InMemoryEngine` without
/// changing this state type.
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
