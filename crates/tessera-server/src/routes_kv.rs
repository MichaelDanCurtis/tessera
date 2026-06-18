use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::BTreeMap;

use tessera_core::types::{SecretPath, SecretValue, TesseraError, VersionedSecret};

use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/{mount}/data/{*path}",
            post(write).get(read).delete(delete_latest),
        )
        .route("/v1/{mount}/delete/{*path}", post(delete_versions))
        .route("/v1/{mount}/undelete/{*path}", post(undelete_versions))
        .route("/v1/{mount}/destroy/{*path}", post(destroy_versions))
        .route(
            "/v1/{mount}/metadata/{*path}",
            get(metadata_or_list)
                .post(configure_metadata)
                .delete(delete_metadata),
        )
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
        TesseraError::CasMismatch => StatusCode::BAD_REQUEST,
        TesseraError::Forbidden(_) | TesseraError::InvalidToken => StatusCode::FORBIDDEN,
        TesseraError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, Json(json!({ "errors": [e.to_string()] })))
}

/// Parse `{"data":{...}}` into a SecretValue (string values only).
fn parse_data(body: &Value) -> SecretValue {
    let mut map = BTreeMap::new();
    if let Some(obj) = body.get("data").and_then(Value::as_object) {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                map.insert(k.clone(), s.to_string());
            }
        }
    }
    SecretValue(map)
}

/// Parse `{"versions":[...]}` into a Vec<u32>.
fn parse_versions(body: &Value) -> Vec<u32> {
    body.get("versions")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u32))
                .collect()
        })
        .unwrap_or_default()
}

async fn write(
    State(state): State<AppState>,
    Path((mount, path)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let sp = SecretPath::new(mount, path);
    let value = parse_data(&body);
    let cas = body
        .get("options")
        .and_then(|o| o.get("cas"))
        .and_then(Value::as_u64)
        .map(|n| n as u32);
    match state.vault.write(&token, &sp, value, cas).await {
        Ok(version) => (
            StatusCode::OK,
            Json(json!({ "data": { "version": version } })),
        )
            .into_response(),
        Err(e) => err_response(e).into_response(),
    }
}

async fn read(
    State(state): State<AppState>,
    Path((mount, path)): Path<(String, String)>,
    Query(q): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let sp = SecretPath::new(mount, path);
    let version = q.get("version").and_then(|v| v.parse::<u32>().ok());
    let reveal = q.get("reveal").map(String::as_str) == Some("true");
    let result = if reveal {
        state.vault.read_reveal(&token, &sp, version).await
    } else {
        state.vault.read(&token, &sp, version).await
    };
    match result {
        Ok((value, meta)) => {
            let data: Value = match value {
                Some(v) => json!(v.0),
                None => Value::Null,
            };
            (
                StatusCode::OK,
                Json(json!({
                    "data": {
                        "data": data,
                        "metadata": {
                            "version": meta.version,
                            "created_time": meta.created_time,
                            "deletion_time": meta.deletion_time,
                            "destroyed": meta.destroyed
                        }
                    }
                })),
            )
                .into_response()
        }
        Err(e) => err_response(e).into_response(),
    }
}

/// DELETE /v1/{mount}/data/{path} — soft-delete the latest version.
async fn delete_latest(
    State(state): State<AppState>,
    Path((mount, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let sp = SecretPath::new(mount, path);
    // Resolve the latest version, then soft-delete just it.
    let latest = match state.vault.read_metadata(&token, &sp).await {
        Ok(md) => md.current_version,
        Err(e) => return err_response(e).into_response(),
    };
    match state.vault.soft_delete(&token, &sp, &[latest]).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_response(e).into_response(),
    }
}

async fn delete_versions(
    State(state): State<AppState>,
    Path((mount, path)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let sp = SecretPath::new(mount, path);
    match state
        .vault
        .soft_delete(&token, &sp, &parse_versions(&body))
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_response(e).into_response(),
    }
}

async fn undelete_versions(
    State(state): State<AppState>,
    Path((mount, path)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let sp = SecretPath::new(mount, path);
    match state
        .vault
        .undelete(&token, &sp, &parse_versions(&body))
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_response(e).into_response(),
    }
}

async fn destroy_versions(
    State(state): State<AppState>,
    Path((mount, path)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let sp = SecretPath::new(mount, path);
    match state
        .vault
        .destroy(&token, &sp, &parse_versions(&body))
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_response(e).into_response(),
    }
}

/// GET /v1/{mount}/metadata/{path} (+`?list=true`) — metadata or list.
async fn metadata_or_list(
    State(state): State<AppState>,
    Path((mount, path)): Path<(String, String)>,
    Query(q): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let sp = SecretPath::new(mount, path);
    if q.get("list").map(String::as_str) == Some("true") {
        match state.vault.list(&token, &sp).await {
            Ok(keys) => (StatusCode::OK, Json(json!({ "data": { "keys": keys } }))).into_response(),
            Err(e) => err_response(e).into_response(),
        }
    } else {
        match state.vault.read_metadata(&token, &sp).await {
            Ok(md) => (StatusCode::OK, Json(metadata_body(&md))).into_response(),
            Err(e) => err_response(e).into_response(),
        }
    }
}

/// Shape the KV-v2 metadata body. `current_version` + per-version map preserved so
/// the KubeNyx contract (which asserts `current_version`) stays green.
fn metadata_body(md: &VersionedSecret) -> Value {
    let versions: BTreeMap<String, Value> = md
        .versions
        .iter()
        .map(|(n, v)| {
            (
                n.to_string(),
                json!({
                    "created_time": v.created_time,
                    "deletion_time": v.deletion_time,
                    "destroyed": v.destroyed
                }),
            )
        })
        .collect();
    json!({
        "data": {
            "current_version": md.current_version,
            "oldest_version": md.oldest_version,
            "max_versions": md.max_versions,
            "cas_required": md.cas_required,
            "created_time": md.created_time,
            "updated_time": md.updated_time,
            "versions": versions
        }
    })
}

async fn configure_metadata(
    State(state): State<AppState>,
    Path((mount, path)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let sp = SecretPath::new(mount, path);
    let max_versions = body
        .get("max_versions")
        .and_then(Value::as_u64)
        .map(|n| n as u32);
    let cas_required = body.get("cas_required").and_then(Value::as_bool);
    match state
        .vault
        .configure_metadata(&token, &sp, max_versions, cas_required)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_response(e).into_response(),
    }
}

async fn delete_metadata(
    State(state): State<AppState>,
    Path((mount, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = token_of(&headers);
    let sp = SecretPath::new(mount, path);
    match state.vault.delete_metadata(&token, &sp).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err_response(e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use crate::app::{router, AppState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tessera_core::audit::InMemoryAudit;
    use tessera_core::auth::{Policy, PolicyStore, TokenStore};
    use tessera_core::clock::FixedClock;
    use tessera_core::engine::InMemoryEngine;
    use tessera_core::seal::SealState;
    use tessera_core::vault::VaultStore;
    use tower::ServiceExt;

    fn state() -> AppState {
        let mut tokens = TokenStore::new();
        tokens.insert("galvo-tok", Policy::new(["secret/galvo/"]));
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
            trust: crate::app::TrustConfig::dev_default(),
        }
    }

    async fn body_json(res: axum::response::Response) -> serde_json::Value {
        let b = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&b).unwrap()
    }

    fn post(uri: &str, json_body: &str) -> Request<Body> {
        Request::post(uri)
            .header("X-Vault-Token", "galvo-tok")
            .header("content-type", "application/json")
            .body(Body::from(json_body.to_string()))
            .unwrap()
    }

    fn get(uri: &str) -> Request<Body> {
        Request::get(uri)
            .header("X-Vault-Token", "galvo-tok")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn write_then_read_data_path_returns_version() {
        let app = router(state());
        let w = app
            .clone()
            .oneshot(post(
                "/v1/secret/data/galvo/openai",
                r#"{"data":{"api_key":"sk-1"}}"#,
            ))
            .await
            .unwrap();
        assert_eq!(w.status(), StatusCode::OK);
        assert_eq!(body_json(w).await["data"]["version"], 1);

        let r = app
            .oneshot(get("/v1/secret/data/galvo/openai"))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let v = body_json(r).await;
        assert_eq!(v["data"]["data"]["api_key"], "sk-1");
        assert_eq!(v["data"]["metadata"]["version"], 1);
    }

    #[tokio::test]
    async fn read_pinned_version_query() {
        let app = router(state());
        app.clone()
            .oneshot(post(
                "/v1/secret/data/galvo/openai",
                r#"{"data":{"api_key":"v1"}}"#,
            ))
            .await
            .unwrap();
        app.clone()
            .oneshot(post(
                "/v1/secret/data/galvo/openai",
                r#"{"data":{"api_key":"v2"}}"#,
            ))
            .await
            .unwrap();
        let r = app
            .oneshot(get("/v1/secret/data/galvo/openai?version=1"))
            .await
            .unwrap();
        assert_eq!(body_json(r).await["data"]["data"]["api_key"], "v1");
    }

    #[tokio::test]
    async fn cas_mismatch_returns_400() {
        let app = router(state());
        app.clone()
            .oneshot(post(
                "/v1/secret/data/galvo/openai",
                r#"{"data":{"api_key":"v1"}}"#,
            ))
            .await
            .unwrap();
        // stale cas=0 on existing
        let r = app
            .oneshot(post(
                "/v1/secret/data/galvo/openai",
                r#"{"data":{"api_key":"dup"},"options":{"cas":0}}"#,
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn soft_delete_undelete_destroy_endpoints() {
        let app = router(state());
        app.clone()
            .oneshot(post(
                "/v1/secret/data/galvo/openai",
                r#"{"data":{"api_key":"v1"}}"#,
            ))
            .await
            .unwrap();
        // soft-delete v1
        let d = app
            .clone()
            .oneshot(post(
                "/v1/secret/delete/galvo/openai",
                r#"{"versions":[1]}"#,
            ))
            .await
            .unwrap();
        assert_eq!(d.status(), StatusCode::NO_CONTENT);
        let r = app
            .clone()
            .oneshot(get("/v1/secret/data/galvo/openai?version=1"))
            .await
            .unwrap();
        assert_eq!(body_json(r).await["data"]["data"], serde_json::Value::Null);
        // undelete v1
        app.clone()
            .oneshot(post(
                "/v1/secret/undelete/galvo/openai",
                r#"{"versions":[1]}"#,
            ))
            .await
            .unwrap();
        let r = app
            .clone()
            .oneshot(get("/v1/secret/data/galvo/openai?version=1"))
            .await
            .unwrap();
        assert_eq!(body_json(r).await["data"]["data"]["api_key"], "v1");
        // destroy v1
        let z = app
            .clone()
            .oneshot(post(
                "/v1/secret/destroy/galvo/openai",
                r#"{"versions":[1]}"#,
            ))
            .await
            .unwrap();
        assert_eq!(z.status(), StatusCode::NO_CONTENT);
        let r = app
            .oneshot(get("/v1/secret/data/galvo/openai?version=1"))
            .await
            .unwrap();
        let v = body_json(r).await;
        assert_eq!(v["data"]["data"], serde_json::Value::Null);
        assert_eq!(v["data"]["metadata"]["destroyed"], true);
    }

    #[tokio::test]
    async fn configure_then_metadata_reflects_config() {
        let app = router(state());
        app.clone()
            .oneshot(post(
                "/v1/secret/data/galvo/openai",
                r#"{"data":{"api_key":"v1"}}"#,
            ))
            .await
            .unwrap();
        app.clone()
            .oneshot(post(
                "/v1/secret/metadata/galvo/openai",
                r#"{"max_versions":3,"cas_required":true}"#,
            ))
            .await
            .unwrap();
        let r = app
            .oneshot(get("/v1/secret/metadata/galvo/openai"))
            .await
            .unwrap();
        let v = body_json(r).await;
        assert_eq!(v["data"]["max_versions"], 3);
        assert_eq!(v["data"]["cas_required"], true);
        assert_eq!(v["data"]["current_version"], 1);
    }

    #[tokio::test]
    async fn delete_metadata_wipes_secret() {
        let app = router(state());
        app.clone()
            .oneshot(post(
                "/v1/secret/data/galvo/openai",
                r#"{"data":{"api_key":"v1"}}"#,
            ))
            .await
            .unwrap();
        let d = app
            .clone()
            .oneshot(
                Request::delete("/v1/secret/metadata/galvo/openai")
                    .header("X-Vault-Token", "galvo-tok")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(d.status(), StatusCode::NO_CONTENT);
        let r = app
            .oneshot(get("/v1/secret/data/galvo/openai"))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn out_of_scope_read_forbidden() {
        let app = router(state());
        let r = app.oneshot(get("/v1/secret/data/femto/key")).await.unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn data_read_with_reveal_param_marks_audit_reveal() {
        let st = state();
        let app = router(st.clone());
        // seed a secret
        app.clone()
            .oneshot(post(
                "/v1/secret/data/galvo/openai",
                r#"{"data":{"api_key":"sk-1"}}"#,
            ))
            .await
            .unwrap();
        let res = app
            .oneshot(get("/v1/secret/data/galvo/openai?reveal=true"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        // the most recent audit entry is a reveal-flagged Read
        let recs = st.vault.audit_sink().records();
        assert!(
            recs.last().unwrap().reveal,
            "reveal=true must produce a reveal-flagged audit entry"
        );
    }
}
