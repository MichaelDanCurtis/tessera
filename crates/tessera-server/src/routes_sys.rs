use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/sys/health", get(health))
        .route("/v1/sys/seal-status", get(seal_status))
}

/// Vault-compatible health: 200 + {"sealed":false} unsealed, 503 + {"sealed":true} sealed.
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let sealed = state.kv.seal_state().is_sealed();
    let code = if sealed {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (code, Json(json!({ "sealed": sealed })))
}

async fn seal_status(State(state): State<AppState>) -> impl IntoResponse {
    let sealed = state.kv.seal_state().is_sealed();
    Json(json!({ "sealed": sealed }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{router, AppState};
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;
    use tessera_core::audit::InMemoryAudit;
    use tessera_core::auth::TokenStore;
    use tessera_core::engine::InMemoryEngine;
    use tessera_core::kv::KvStore;
    use tessera_core::seal::SealState;
    use tower::ServiceExt; // oneshot

    fn state(unseal: bool) -> AppState {
        let seal = SealState::new(b"m".to_vec());
        if unseal {
            seal.unseal(b"m").unwrap();
        }
        let kv = KvStore::new(
            InMemoryEngine::new("t"),
            seal,
            TokenStore::new(),
            InMemoryAudit::new(),
        );
        AppState { kv: Arc::new(kv) }
    }

    #[tokio::test]
    async fn health_200_when_unsealed() {
        let app = router(state(true));
        let res = app
            .oneshot(Request::get("/v1/sys/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"sealed":false}"#);
    }

    #[tokio::test]
    async fn health_503_when_sealed() {
        let app = router(state(false));
        let res = app
            .oneshot(Request::get("/v1/sys/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"sealed":true}"#);
    }
}
