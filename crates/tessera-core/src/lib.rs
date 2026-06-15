//! Tessera Vault core: storage-engine-agnostic KV secrets, auth, audit, seal.
pub mod audit;
pub mod auth;
pub mod engine;
// pub mod kv;            // re-enabled? no — replaced by vault in Phase 2
pub mod rusty_engine;
pub mod seal;
pub mod types;
