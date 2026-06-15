use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::BTreeMap;

use tessera_core::audit::{AuditOp, AuditQuery};
use tessera_core::auth::Policy;

use crate::app::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/sys/health", get(health))
        .route("/v1/sys/seal-status", get(seal_status))
        .route("/v1/sys/audit", get(audit_read))
        .route("/v1/sys/policies", get(policy_list))
        .route(
            "/v1/sys/policies/{name}",
            put(policy_put).get(policy_get).delete(policy_delete),
        )
        .route("/v1/sys/tokens", get(token_list).post(token_create))
        .route(
            "/v1/sys/tokens/{accessor}",
            axum::routing::delete(token_revoke),
        )
}

/// Extract the token from X-Vault-Token (admin endpoints).
fn admin_token_of(headers: &HeaderMap) -> String {
    headers
        .get("X-Vault-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// 403 unless the token grants admin (sys/). Returns the token on success.
fn require_admin(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<Value>)> {
    let tok = admin_token_of(headers);
    if state.vault.tokens().is_admin(&tok, state.vault.policies()) {
        Ok(tok)
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "errors": ["not authorized"] })),
        ))
    }
}

fn parse_op(s: &str) -> Option<AuditOp> {
    serde_json::from_value(Value::String(s.to_string())).ok()
}

async fn audit_read(
    State(state): State<AppState>,
    Query(q): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    let query = AuditQuery {
        prefix: q.get("prefix").cloned(),
        op: q.get("op").and_then(|s| parse_op(s)),
        outcome: q.get("outcome").map(|s| s == "true"),
        since: q.get("since").cloned(),
        until: q.get("until").cloned(),
        limit: q.get("limit").and_then(|s| s.parse::<usize>().ok()),
    };
    let entries: Vec<Value> = state
        .vault
        .audit_sink()
        .query(&query)
        .into_iter()
        .map(|r| {
            json!({
                "timestamp": r.timestamp,
                "op": r.op,
                "scope": r.scope,
                "token_hash": r.token_hash,
                "outcome": r.outcome,
                "reveal": r.reveal,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({ "data": { "entries": entries } })),
    )
        .into_response()
}

async fn policy_put(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    let prefixes: Vec<String> = body
        .get("allow_prefixes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    match state.vault.policies().put(&name, Policy::new(prefixes)) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"errors":[e.to_string()]})),
        )
            .into_response(),
    }
}

async fn policy_get(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    match state.vault.policies().get(&name) {
        Some(p) => (
            StatusCode::OK,
            Json(json!({"data":{"name":name,"allow_prefixes":p.allow_prefixes}})),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"errors":["policy not found"]})),
        )
            .into_response(),
    }
}

async fn policy_list(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    let mut keys = state.vault.policies().list();
    keys.sort();
    (StatusCode::OK, Json(json!({ "data": { "keys": keys } }))).into_response()
}

async fn policy_delete(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    match state.vault.policies().delete(&name) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"errors":[e.to_string()]})),
        )
            .into_response(),
    }
}

async fn token_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    let policies: Vec<String> = body
        .get("policies")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let ttl = body.get("ttl").and_then(Value::as_i64);
    let now = state.vault.clock().now_rfc3339();
    match state
        .vault
        .tokens()
        .issue(policies, ttl, &now, state.vault.policies())
    {
        Ok(out) => (
            StatusCode::OK,
            Json(json!({"data":{
                "token": out.token, "accessor": out.accessor, "policies": out.policies,
                "created": out.created, "expires": out.expires,
            }})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"errors":[e.to_string()]})),
        )
            .into_response(),
    }
}

async fn token_list(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    let tokens: Vec<Value> = state
        .vault
        .tokens()
        .list_metadata()
        .into_iter()
        .map(|m| {
            json!({"accessor": m.accessor, "policies": m.policies, "created": m.created, "expires": m.expires})
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({ "data": { "tokens": tokens } })),
    )
        .into_response()
}

async fn token_revoke(
    State(state): State<AppState>,
    Path(accessor): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = require_admin(&state, &headers) {
        return resp.into_response();
    }
    match state.vault.tokens().revoke(&accessor) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({"errors":["accessor not found"]})),
        )
            .into_response(),
    }
}

/// Vault-compatible health: 200 + {"sealed":false} unsealed, 503 + {"sealed":true} sealed.
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let sealed = state.vault.seal_state().is_sealed();
    let code = if sealed {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (code, Json(json!({ "sealed": sealed })))
}

async fn seal_status(State(state): State<AppState>) -> impl IntoResponse {
    let sealed = state.vault.seal_state().is_sealed();
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
    use tessera_core::auth::{PolicyStore, TokenStore};
    use tessera_core::clock::FixedClock;
    use tessera_core::engine::InMemoryEngine;
    use tessera_core::seal::SealState;
    use tessera_core::vault::VaultStore;
    use tower::ServiceExt; // oneshot

    fn state(unseal: bool) -> AppState {
        let seal = SealState::new(b"m".to_vec());
        if unseal {
            seal.unseal(b"m").unwrap();
        }
        let vault = VaultStore::new(
            Arc::new(InMemoryEngine::new()),
            seal,
            TokenStore::new(),
            Arc::new(PolicyStore::in_memory()),
            Arc::new(InMemoryAudit::new()),
            Arc::new(FixedClock("t".into())),
        );
        AppState {
            vault: Arc::new(vault),
        }
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

    /// Build state with: an admin static token "admin-tok" (policy allows sys/),
    /// a scoped "galvo-tok" (policy allows secret/galvo/), and an in-memory audit.
    fn admin_state() -> (AppState, String) {
        let mut tokens = TokenStore::new();
        tokens.insert("admin-tok", Policy::new(["sys/"]));
        tokens.insert("galvo-tok", Policy::new(["secret/galvo/"]));
        let seal = SealState::new(b"m".to_vec());
        seal.unseal(b"m").unwrap();
        let policies = Arc::new(PolicyStore::in_memory());
        // seed a named policy so token-issue tests can reference it
        policies
            .put("galvo", Policy::new(["secret/galvo/"]))
            .unwrap();
        let vault = VaultStore::new(
            Arc::new(InMemoryEngine::new()),
            seal,
            tokens,
            policies,
            Arc::new(InMemoryAudit::new()),
            Arc::new(FixedClock("2026-06-14T00:00:00Z".into())),
        );
        (
            AppState {
                vault: Arc::new(vault),
            },
            "admin-tok".to_string(),
        )
    }

    fn admin_get(uri: &str, tok: &str) -> Request<Body> {
        Request::get(uri)
            .header("X-Vault-Token", tok)
            .body(Body::empty())
            .unwrap()
    }
    fn admin_post(uri: &str, tok: &str, body: &str) -> Request<Body> {
        Request::post(uri)
            .header("X-Vault-Token", tok)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn body_json(res: axum::response::Response) -> serde_json::Value {
        let b = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&b).unwrap()
    }

    #[tokio::test]
    async fn audit_read_requires_admin() {
        let (st, _admin) = admin_state();
        let app = router(st);
        // non-admin token -> 403
        let r = app
            .oneshot(admin_get("/v1/sys/audit", "galvo-tok"))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn policy_put_get_list_delete_roundtrip() {
        let (st, admin) = admin_state();
        let app = router(st);
        let p = app
            .clone()
            .oneshot(
                Request::put("/v1/sys/policies/billing")
                    .header("X-Vault-Token", &admin)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"allow_prefixes":["secret/billing/"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(p.status(), StatusCode::NO_CONTENT);
        let g = app
            .clone()
            .oneshot(admin_get("/v1/sys/policies/billing", &admin))
            .await
            .unwrap();
        assert_eq!(
            body_json(g).await["data"]["allow_prefixes"][0],
            "secret/billing/"
        );
        let l = app
            .clone()
            .oneshot(admin_get("/v1/sys/policies", &admin))
            .await
            .unwrap();
        let keys = body_json(l).await["data"]["keys"]
            .as_array()
            .unwrap()
            .clone();
        assert!(keys.iter().any(|k| k == "billing"));
        let d = app
            .oneshot(
                Request::delete("/v1/sys/policies/billing")
                    .header("X-Vault-Token", &admin)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(d.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn token_create_lists_accessor_never_value_and_revokes() {
        let (st, admin) = admin_state();
        let app = router(st);
        let c = app
            .clone()
            .oneshot(admin_post(
                "/v1/sys/tokens",
                &admin,
                r#"{"policies":["galvo"]}"#,
            ))
            .await
            .unwrap();
        assert_eq!(c.status(), StatusCode::OK);
        let created = body_json(c).await;
        let raw = created["data"]["token"].as_str().unwrap().to_string();
        let accessor = created["data"]["accessor"].as_str().unwrap().to_string();
        assert_ne!(raw, accessor);

        // list returns the accessor but NOT the raw token value anywhere
        let l = app
            .clone()
            .oneshot(admin_get("/v1/sys/tokens", &admin))
            .await
            .unwrap();
        let list_body = body_json(l).await;
        let list_str = list_body.to_string();
        assert!(list_str.contains(&accessor));
        assert!(
            !list_str.contains(&raw),
            "raw token value must never appear in list"
        );

        // revoke by accessor
        let d = app
            .oneshot(
                Request::delete(format!("/v1/sys/tokens/{accessor}"))
                    .header("X-Vault-Token", &admin)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(d.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn token_create_requires_admin() {
        let (st, _admin) = admin_state();
        let app = router(st);
        let c = app
            .oneshot(admin_post(
                "/v1/sys/tokens",
                "galvo-tok",
                r#"{"policies":["galvo"]}"#,
            ))
            .await
            .unwrap();
        assert_eq!(c.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn policy_write_requires_admin() {
        let (st, _admin) = admin_state();
        let app = router(st);
        let r = app
            .oneshot(
                Request::put("/v1/sys/policies/x")
                    .header("X-Vault-Token", "galvo-tok")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"allow_prefixes":["secret/x/"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }
}
