//! Verifies Tessera serves the exact endpoints KubeNyx's VaultBroker calls.
//! Shapes copied from KubeNyx/crates/sentinel-scout/src/vault.rs (self-contained).

use std::sync::Arc;

use tessera_core::audit::InMemoryAudit;
use tessera_core::auth::{Policy, PolicyStore, TokenStore};
use tessera_core::clock::FixedClock;
use tessera_core::engine::InMemoryEngine;
use tessera_core::seal::SealState;
use tessera_core::types::{SecretPath, SecretValue};
use tessera_core::vault::VaultStore;
use tessera_server::app::{router, AppState};

async fn spawn_unsealed_with_secrets() -> AppState {
    let mut tokens = TokenStore::new();
    tokens.insert("galvo-tok", Policy::new(["secret/"]));
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
    // Seed two secrets under secret/galvo so list returns both, each at version 1.
    let mut a = SecretValue::default();
    a.0.insert("api_key".into(), "1".into());
    vault
        .write(
            "galvo-tok",
            &SecretPath::new("secret", "galvo/openai"),
            a,
            None,
        )
        .await
        .unwrap();
    let mut b = SecretValue::default();
    b.0.insert("api_key".into(), "2".into());
    vault
        .write(
            "galvo-tok",
            &SecretPath::new("secret", "galvo/anthropic"),
            b,
            None,
        )
        .await
        .unwrap();
    AppState {
        vault: Arc::new(vault),
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

#[tokio::test]
async fn kubenyx_status_list_metadata_contract() {
    let base = serve(spawn_unsealed_with_secrets().await).await;
    let client = reqwest::Client::new();

    // 1. vault/status -> GET /v1/sys/health -> 200 {"sealed":false}
    let res = client
        .get(format!("{base}/v1/sys/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), r#"{"sealed":false}"#);

    // 2. vault/list_secrets -> GET /v1/secret/metadata/galvo?list=true
    let res = client
        .get(format!("{base}/v1/secret/metadata/galvo"))
        .query(&[("list", "true")])
        .header("X-Vault-Token", "galvo-tok")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    let keys: Vec<String> = body["data"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    assert_eq!(keys, vec!["anthropic".to_string(), "openai".to_string()]);

    // 3. vault/read_metadata -> GET /v1/secret/metadata/galvo/openai -> current_version:1
    let res = client
        .get(format!("{base}/v1/secret/metadata/galvo/openai"))
        .header("X-Vault-Token", "galvo-tok")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["data"]["current_version"], 1);
}

#[tokio::test]
async fn sealed_health_returns_503() {
    let state = {
        let seal = SealState::new(b"m".to_vec()); // left sealed
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
    };
    let base = serve(state).await;
    let res = reqwest::Client::new()
        .get(format!("{base}/v1/sys/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 503);
    assert_eq!(res.text().await.unwrap(), r#"{"sealed":true}"#);
}
