use std::sync::Arc;

use tessera_core::audit::InMemoryAudit;
use tessera_core::auth::TokenStore;
use tessera_core::engine::InMemoryEngine;
use tessera_core::kv::KvStore;
use tessera_core::seal::SealState;
use tessera_server::app::{router, AppState};
use tessera_server::config;

#[tokio::main]
async fn main() {
    let cfg = match config::from_getter(|k| std::env::var(k).ok()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("tessera: config error: {e:?}");
            std::process::exit(1);
        }
    };
    eprintln!("tessera: crypto backend = {}", cfg.crypto_backend);

    let seal = SealState::new(cfg.master_key.clone());
    seal.unseal(&cfg.master_key)
        .expect("master key unseals own vault");
    let kv = KvStore::new(
        InMemoryEngine::new("1970-01-01T00:00:00Z"),
        seal,
        TokenStore::new(),
        InMemoryAudit::new(),
    );
    let state = AppState { kv: Arc::new(kv) };

    let listener = tokio::net::TcpListener::bind(&cfg.bind)
        .await
        .expect("bind");
    eprintln!("tessera: listening on {}", cfg.bind);
    axum::serve(listener, router(state)).await.expect("serve");
}
