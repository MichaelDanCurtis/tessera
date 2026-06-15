//! Acceptance gate #1 — persistence through the FULL stack.
//!
//! Proves that secret *versions* and *history* written through a real
//! `VaultStore`-over-`RustyVaultEngine` survive an engine drop (process exit)
//! and a re-open of the SAME `data_dir` with the SAME master key. This is the
//! end-to-end counterpart to the engine-level `secrets_survive_reopen_*` unit
//! test in `tessera-core`: here the whole KV-v2 orchestration layer is exercised.

use std::sync::Arc;

use tessera_core::audit::InMemoryAudit;
use tessera_core::auth::{Policy, TokenStore};
use tessera_core::clock::SystemClock;
use tessera_core::rusty_engine::RustyVaultEngine;
use tessera_core::seal::SealState;
use tessera_core::types::{SecretPath, SecretValue};
use tessera_core::vault::VaultStore;

const MASTER_KEY: &[u8] = b"persistence-acceptance-master-key";

/// Build a `VaultStore` backed by a real `RustyVaultEngine` over `data_dir`,
/// unsealed with `MASTER_KEY`, with a scoped token `tok` policy-allowed on
/// `secret/`.
async fn open_store(data_dir: &str) -> VaultStore {
    let engine = RustyVaultEngine::open(data_dir, MASTER_KEY)
        .await
        .expect("engine open");
    let seal = SealState::new(MASTER_KEY.to_vec());
    seal.unseal(MASTER_KEY).expect("unseal");
    let mut tokens = TokenStore::new();
    tokens.insert("tok", Policy::new(["secret/"]));
    VaultStore::new(
        Arc::new(engine),
        seal,
        tokens,
        Arc::new(InMemoryAudit::new()),
        Arc::new(SystemClock),
    )
}

fn value(k: &str, v: &str) -> SecretValue {
    let mut sv = SecretValue::default();
    sv.0.insert(k.into(), v.into());
    sv
}

#[tokio::test]
async fn versions_survive_engine_restart() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let data_dir = tmp.path().to_str().expect("utf8 path").to_string();
    let path = SecretPath::new("secret", "galvo/openai");

    // Phase A: write the secret TWICE through the full stack (two versions),
    // then drop the VaultStore + engine to simulate process exit.
    {
        let store = open_store(&data_dir).await;
        let v1 = store
            .write("tok", &path, value("api_key", "first"), None)
            .await
            .expect("write v1");
        assert_eq!(v1, 1, "first write is version 1");
        let v2 = store
            .write("tok", &path, value("api_key", "second"), None)
            .await
            .expect("write v2");
        assert_eq!(v2, 2, "second write is version 2");
    } // store + engine dropped here — barrier sealed, in-memory state gone.

    // Phase B: re-open the SAME data_dir with the SAME master key (unseal path,
    // not re-init) and prove the history survived.
    let store = open_store(&data_dir).await;

    // current read -> the second value
    let (current, current_meta) = store
        .read("tok", &path, None)
        .await
        .expect("read current after restart");
    assert_eq!(
        current,
        Some(value("api_key", "second")),
        "current read returns the second value after restart"
    );
    assert_eq!(current_meta.version, 2, "current is version 2");

    // version=1 read -> the first value
    let (first, first_meta) = store
        .read("tok", &path, Some(1))
        .await
        .expect("read version 1 after restart");
    assert_eq!(
        first,
        Some(value("api_key", "first")),
        "version=1 read returns the first value after restart"
    );
    assert_eq!(first_meta.version, 1, "explicit read is version 1");

    // metadata -> current_version == 2 (full history intact)
    let meta = store
        .read_metadata("tok", &path)
        .await
        .expect("read_metadata after restart");
    assert_eq!(
        meta.current_version, 2,
        "metadata reports current_version 2 after restart"
    );
    assert!(
        meta.versions.contains_key(&1) && meta.versions.contains_key(&2),
        "both versions 1 and 2 present in metadata after restart"
    );
}
