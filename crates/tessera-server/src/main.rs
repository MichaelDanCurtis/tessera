use std::sync::Arc;

use tessera_core::audit::InMemoryAudit;
use tessera_core::auth::TokenStore;
use tessera_core::clock::SystemClock;
use tessera_core::rusty_engine::RustyVaultEngine;
use tessera_core::seal::SealState;
use tessera_core::vault::VaultStore;
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

    // Persistent, restart-safe engine: init-if-empty-else-unseal against data_dir.
    let engine = match RustyVaultEngine::open(&cfg.data_dir, &cfg.master_key).await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("tessera: engine open failed: {e}");
            std::process::exit(1);
        }
    };

    // Tessera's own seal gate (independent of RustyVault's barrier) starts sealed
    // and is unsealed with the same master key so the API serves immediately.
    let seal = SealState::new(cfg.master_key.clone());
    seal.unseal(&cfg.master_key)
        .expect("master key unseals own vault");

    let vault = VaultStore::new(
        Arc::new(engine),
        seal,
        TokenStore::new(),
        Arc::new(InMemoryAudit::new()),
        Arc::new(SystemClock),
    );
    let state = AppState {
        vault: Arc::new(vault),
    };

    let listener = tokio::net::TcpListener::bind(&cfg.bind)
        .await
        .expect("bind");
    eprintln!("tessera: listening on {}", cfg.bind);
    axum::serve(listener, router(state)).await.expect("serve");
}
