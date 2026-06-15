use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::BTreeMap;

use tessera_core::types::{SecretPath, SecretValue, TesseraError};

use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/{mount}/data/{*path}", post(write).get(read).delete(delete_secret))
        .route("/v1/{mount}/metadata/{*path}", get(metadata_or_list))
}

/// Extract the token from X-Vault-Token, else Authorization: Bearer.
fn token_of(headers: &HeaderMap) -> String {
    if let Some(t) = headers.get("X-Vault-Token").and_then(|v| v.to_str().ok()) {
        return t.to_string();
    }
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string()
}

/// Map a TesseraError to a Vault-ish HTTP status + body.
fn err_response(e: TesseraError) -> (StatusCode, Json<Value>) {
    let code = match e {
        TesseraError::NotFound => StatusCode::NOT_FOUND,
        TesseraError::Sealed => StatusCode::SERVICE_UNAVAILABLE,
        TesseraError::Forbidden(_) | TesseraError::InvalidToken => StatusCode::FORBIDDEN,
        TesseraError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, Json(json!({ "errors": [e.to_string()] })))
}

async fn write(
    State(state): State<AppState>,
    Path((mount, path)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let sp = SecretPath::new(mount, path);
    // Vault KV v2 write body: {"data": {k: v, ...}}
    let mut map = BTreeMap::new();
    if let Some(obj) = body.get("data").and_then(Value::as_object) {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                map.insert(k.clone(), s.to_string());
            }
        }
    }
    match state.kv.write(&token, &sp, SecretValue(map)) {
        Ok(()) => (StatusCode::OK, Json(json!({ "data": { "version": 1 } }))).into_response(),
        Err(e) => err_response(e).into_response(),
    }
}

async fn read(
    State(state): State<AppState>,
    Path((mount, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let sp = SecretPath::new(mount, path);
    match state.kv.read(&token, &sp) {
        Ok((value, meta)) => {
            let data: BTreeMap<String, String> = value.0;
            (StatusCode::OK, Json(json!({
                "data": {
                    "data": data,
                    "metadata": { "version": meta.current_version, "created_time": meta.created_time }
                }
            }))).into_response()
        }
        Err(e) => err_response(e).into_response(),
    }
}

async fn delete_secret(
    State(state): State<AppState>,
    Path((mount, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let sp = SecretPath::new(mount, path);
    match state.kv.delete(&token, &sp) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_response(e).into_response(),
    }
}

async fn metadata_or_list(
    State(state): State<AppState>,
    Path((mount, path)): Path<(String, String)>,
    Query(q): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let sp = SecretPath::new(mount, path);
    if q.get("list").map(String::as_str) == Some("true") {
        match state.kv.list(&token, &sp) {
            Ok(keys) => (StatusCode::OK, Json(json!({ "data": { "keys": keys } }))).into_response(),
            Err(e) => err_response(e).into_response(),
        }
    } else {
        match state.kv.metadata(&token, &sp) {
            Ok(meta) => (StatusCode::OK, Json(json!({
                "data": { "current_version": meta.current_version, "created_time": meta.created_time }
            }))).into_response(),
            Err(e) => err_response(e).into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::app::{router, AppState};
    use std::sync::Arc;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tessera_core::audit::InMemoryAudit;
    use tessera_core::auth::{Policy, TokenStore};
    use tessera_core::engine::InMemoryEngine;
    use tessera_core::kv::KvStore;
    use tessera_core::seal::SealState;
    use tower::ServiceExt;

    fn state() -> AppState {
        let mut tokens = TokenStore::new();
        tokens.insert("galvo-tok", Policy::new(["secret/galvo/"]));
        let seal = SealState::new(b"m".to_vec());
        seal.unseal(b"m").unwrap();
        let kv = KvStore::new(InMemoryEngine::new("2026-06-14T00:00:00Z"), seal, tokens, InMemoryAudit::new());
        AppState { kv: Arc::new(kv) }
    }

    #[tokio::test]
    async fn write_then_read_data_path() {
        let app = router(state());
        let w = app.clone().oneshot(
            Request::post("/v1/secret/data/galvo/openai")
                .header("X-Vault-Token", "galvo-tok")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"data":{"api_key":"sk-1"}}"#)).unwrap()
        ).await.unwrap();
        assert_eq!(w.status(), StatusCode::OK);

        let r = app.oneshot(
            Request::get("/v1/secret/data/galvo/openai")
                .header("X-Vault-Token", "galvo-tok")
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let body = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["data"]["data"]["api_key"], "sk-1");
    }

    #[tokio::test]
    async fn out_of_scope_read_forbidden() {
        let app = router(state());
        let r = app.oneshot(
            Request::get("/v1/secret/data/femto/key")
                .header("X-Vault-Token", "galvo-tok")
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }
}
