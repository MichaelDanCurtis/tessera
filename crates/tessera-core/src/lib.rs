//! Tessera Vault core: storage-engine-agnostic KV secrets, auth, audit, seal.
pub mod audit;
pub mod auth;
pub mod clock;
pub mod engine;
pub mod rusty_engine;
pub mod seal;
pub mod types;
// pub mod vault;  // added in Task 5
