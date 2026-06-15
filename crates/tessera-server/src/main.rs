use std::path::Path;
use std::sync::Arc;

use tessera_core::audit::FileAuditSink;
use tessera_core::auth::{Policy, PolicyStore, TokenStore};
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

    let data = Path::new(&cfg.data_dir);
    let audit = match FileAuditSink::open(data.join("audit.log")) {
        Ok(a) => Arc::new(a),
        Err(e) => {
            eprintln!("tessera: audit open failed: {e}");
            std::process::exit(1);
        }
    };
    let policies = match PolicyStore::open(data.join("policies.json")) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!("tessera: policy store open failed: {e}");
            std::process::exit(1);
        }
    };
    let mut tokens = match TokenStore::open(data.join("tokens.json")) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tessera: token store open failed: {e}");
            std::process::exit(1);
        }
    };

    // Seed an admin policy + static admin token from env so the Galvo proxy can
    // administer the vault out of the box. The admin token is a STATIC inline
    // token granting sys/, secret/, pki/, and transit/ so it can drive the KV,
    // trust, and unwrap paths on behalf of operators — it is never persisted.
    if let Some(admin) = &cfg.admin_token {
        policies
            .put(
                "admin",
                Policy::new(["sys/", "secret/", "pki/", "transit/"]),
            )
            .expect("seed admin policy");
        tokens.insert(
            admin.clone(),
            Policy::new(["sys/", "secret/", "pki/", "transit/"]),
        );
    }

    let vault = VaultStore::new(
        Arc::new(engine),
        seal,
        tokens,
        policies,
        audit,
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
