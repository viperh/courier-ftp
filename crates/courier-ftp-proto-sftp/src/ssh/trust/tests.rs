//! [`TrustStoreVerifier`] against the in-process server
//! ([`super::super::test_server`]); trust prompts are answered through the
//! event bus.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::VecDeque,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use courier_ftp_core::{
    Error, Result,
    events::{self, CoreEvent, PromptKind, PromptResponse, SessionId, TrustDecision},
    model::{HostKeyFingerprint, LogonType},
    net::HostPort,
    settings::Settings,
    trust::{HostKey, HostKeyStore, KnownHost, MemoryHostKeyStore, known_hosts},
};
use pretty_assertions::assert_eq;
use secrecy::SecretString;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use super::{super::test_server, *};
use crate::ssh::{SshContext, SshOptions, SshSession, connect};

const PASSWORD: &str = "pw";

/// The `TrustHostKey` prompts the fake UI saw.
type Seen = Arc<Mutex<Vec<PromptKind>>>;

/// A UI answering trust prompts with `answers` in order (`None` = close the
/// dialog without answering).
fn spawn_ui(mut rx: events::EventReceiver, answers: Vec<Option<TrustDecision>>) -> Seen {
    let seen = Seen::default();
    let out = Arc::clone(&seen);
    let mut answers: VecDeque<_> = answers.into();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let CoreEvent::Prompt(req) = event {
                out.lock().unwrap().push(req.kind.clone());
                if let Some(Some(decision)) = answers.pop_front() {
                    let _ = req.reply.send(PromptResponse::Trust(decision));
                }
            }
        }
    });
    seen
}

async fn server() -> SocketAddr {
    test_server::start(test_server::Policy {
        password: Some(PASSWORD),
        ..test_server::Policy::default()
    })
    .await
    .0
}

/// Connect to `addr` with `verifier`, answering prompts with `answers`.
async fn connect_with(
    addr: SocketAddr,
    verifier: &TrustStoreVerifier,
    answers: Vec<Option<TrustDecision>>,
) -> (Result<SshSession>, Vec<PromptKind>) {
    let (tx, rx) = events::channel(4);
    let seen = spawn_ui(rx, answers);
    let mut settings = Settings::default();
    settings.connection.timeout_secs = 5;
    let opts = SshOptions::new(
        HostPort::from(addr),
        LogonType::Normal {
            user: "bob".into(),
            password: SecretString::from(PASSWORD.to_owned()),
        },
        &settings,
    );
    let ctx = SshContext::new(SessionId::next(), tx, Arc::new(verifier.clone()));
    let result = connect(&opts, &ctx, &CancellationToken::new()).await;
    if let Ok(session) = &result {
        session.disconnect().await.unwrap();
    }
    let prompts = seen.lock().unwrap().clone();
    (result, prompts)
}

/// The test server's key as a core key.
fn server_key() -> HostKey {
    host_key_of(&test_server::host_key()).unwrap()
}

/// Another Ed25519 key (32 bytes of `seed`).
fn other_key(seed: u8) -> HostKey {
    let mut blob = Vec::new();
    for field in [&b"ssh-ed25519"[..], &[seed; 32][..]] {
        blob.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        blob.extend_from_slice(field);
    }
    HostKey::from_blob(blob).unwrap()
}

fn host_key_prompt(
    kind: &PromptKind,
) -> (String, HostKeyFingerprint, Option<HostKeyFingerprint>, bool) {
    match kind {
        PromptKind::TrustHostKey {
            host,
            key,
            known,
            can_remember,
        } => (host.clone(), key.clone(), known.clone(), *can_remember),
        other => panic!("not a host key prompt: {other:?}"),
    }
}

fn write_known_hosts(dir: &Path, lines: &[String]) -> Vec<PathBuf> {
    let path = dir.join("known_hosts");
    std::fs::write(&path, lines.join("\n")).unwrap();
    vec![path, dir.join("missing_known_hosts")]
}

fn no_known_hosts(dir: &Path) -> Vec<PathBuf> {
    vec![dir.join("known_hosts")]
}

#[test]
fn russh_keys_convert_with_the_same_fingerprint() {
    let key = test_server::host_key();
    assert_eq!(
        format!("{} {}", server_key().algorithm(), server_key().sha256()),
        super::super::hostkey::describe_key(&key)
    );
    assert_eq!(server_key().bits(), Some(256));
}

#[tokio::test]
async fn first_connect_prompts_and_always_makes_the_next_one_silent() {
    let addr = server().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryHostKeyStore::new());
    let verifier = TrustStoreVerifier::new(store.clone(), no_known_hosts(dir.path()));

    let (result, prompts) = connect_with(addr, &verifier, vec![Some(TrustDecision::Always)]).await;
    result.unwrap();
    assert_eq!(prompts.len(), 1);
    let (host, key, known, can_remember) = host_key_prompt(&prompts[0]);
    assert_eq!(host, addr.to_string());
    assert_eq!(key, server_key().fingerprint());
    assert!(key.sha256.starts_with("SHA256:"));
    assert!(key.md5.as_deref().unwrap().starts_with("MD5:"));
    assert_eq!(known, None);
    assert!(can_remember);

    let stored = store.list().await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].host, "127.0.0.1");
    assert_eq!(stored[0].port, addr.port());
    assert_eq!(stored[0].key, server_key());

    // A fresh verifier (no session memory) over the same store: silent.
    let verifier = TrustStoreVerifier::new(store, no_known_hosts(dir.path()));
    let (result, prompts) = connect_with(addr, &verifier, vec![]).await;
    result.unwrap();
    assert!(prompts.is_empty(), "{prompts:?}");
}

#[tokio::test]
async fn a_changed_key_prompts_with_both_fingerprints_and_cancel_fails() {
    let addr = server().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryHostKeyStore::new());
    let old = other_key(9);
    store
        .remember(KnownHost::new(
            "127.0.0.1",
            addr.port(),
            old.clone(),
            OffsetDateTime::now_utc(),
        ))
        .await
        .unwrap();
    let verifier = TrustStoreVerifier::new(store.clone(), no_known_hosts(dir.path()));

    let (result, prompts) = connect_with(addr, &verifier, vec![Some(TrustDecision::Reject)]).await;
    let err = result.unwrap_err();
    assert!(
        matches!(&err, Error::HostKey(m) if m.contains("rejected")),
        "{err:?}"
    );
    assert_eq!(prompts.len(), 1);
    let (_, key, known, _) = host_key_prompt(&prompts[0]);
    assert_eq!(key, server_key().fingerprint());
    assert_eq!(known, Some(old.fingerprint()));
    // Nothing changed in the store.
    assert_eq!(store.list().await.unwrap()[0].key, old);

    // "Always" replaces the old key.
    let (result, _) = connect_with(addr, &verifier, vec![Some(TrustDecision::Always)]).await;
    result.unwrap();
    let stored = store.list().await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].key, server_key());
}

#[tokio::test]
async fn a_hashed_known_hosts_entry_matches_silently() {
    let addr = server().await;
    let dir = tempfile::tempdir().unwrap();
    let key = server_key();
    let host = known_hosts::hash_host_name(
        &format!("[127.0.0.1]:{}", addr.port()),
        b"0123456789abcdefghij",
    );
    let paths = write_known_hosts(
        dir.path(),
        &[
            "# comment".to_owned(),
            format!("{host} {} {}", key.algorithm(), key.to_base64()),
        ],
    );
    let store = Arc::new(MemoryHostKeyStore::new());
    let verifier = TrustStoreVerifier::new(store.clone(), paths);
    let (result, prompts) = connect_with(addr, &verifier, vec![]).await;
    result.unwrap();
    assert!(prompts.is_empty(), "{prompts:?}");
    // known_hosts is trusted, not copied.
    assert!(store.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_revoked_key_is_rejected_without_a_prompt() {
    let addr = server().await;
    let dir = tempfile::tempdir().unwrap();
    let key = server_key();
    let paths = write_known_hosts(
        dir.path(),
        &[format!(
            "@revoked * {} {}",
            key.algorithm(),
            key.to_base64()
        )],
    );
    let store = Arc::new(MemoryHostKeyStore::new());
    // Even a stored trust doesn't override the revocation.
    store
        .remember(KnownHost::new(
            "127.0.0.1",
            addr.port(),
            key,
            OffsetDateTime::now_utc(),
        ))
        .await
        .unwrap();
    let verifier = TrustStoreVerifier::new(store, paths);
    let (result, prompts) = connect_with(addr, &verifier, vec![Some(TrustDecision::Always)]).await;
    let err = result.unwrap_err();
    assert!(
        matches!(&err, Error::HostKey(m) if m.contains("revoked")),
        "{err:?}"
    );
    assert!(prompts.is_empty(), "{prompts:?}");
}

#[tokio::test]
async fn vault_locked_offers_only_trust_once_which_lasts_for_the_session() {
    let addr = server().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryHostKeyStore::locked());
    let verifier = TrustStoreVerifier::new(store.clone(), no_known_hosts(dir.path()));

    // A UI that answers "Always" anyway: treated as "once".
    let (result, prompts) = connect_with(addr, &verifier, vec![Some(TrustDecision::Always)]).await;
    result.unwrap();
    let (_, _, known, can_remember) = host_key_prompt(&prompts[0]);
    assert_eq!(known, None);
    assert!(!can_remember);
    assert!(store.list().await.unwrap().is_empty());

    // Same verifier (a clone shares the session trust): silent.
    let (result, prompts) = connect_with(addr, &verifier.clone(), vec![]).await;
    result.unwrap();
    assert!(prompts.is_empty(), "{prompts:?}");

    // After clearing (or in a new run) it asks again.
    verifier.clear_session_trust();
    let (result, prompts) = connect_with(addr, &verifier, vec![Some(TrustDecision::Once)]).await;
    result.unwrap();
    assert_eq!(prompts.len(), 1);
}

#[tokio::test]
async fn vault_locked_still_trusts_known_hosts() {
    let addr = server().await;
    let dir = tempfile::tempdir().unwrap();
    let key = server_key();
    let paths = write_known_hosts(
        dir.path(),
        &[format!(
            "[127.0.0.1]:{} {} {}",
            addr.port(),
            key.algorithm(),
            key.to_base64()
        )],
    );
    let verifier = TrustStoreVerifier::new(Arc::new(MemoryHostKeyStore::locked()), paths);
    let (result, prompts) = connect_with(addr, &verifier, vec![]).await;
    result.unwrap();
    assert!(prompts.is_empty(), "{prompts:?}");
}

#[tokio::test]
async fn a_changed_known_hosts_key_prompts_as_a_warning() {
    let addr = server().await;
    let dir = tempfile::tempdir().unwrap();
    let old = other_key(3);
    let paths = write_known_hosts(
        dir.path(),
        &[format!(
            "[127.0.0.1]:{} {} {}",
            addr.port(),
            old.algorithm(),
            old.to_base64()
        )],
    );
    let verifier = TrustStoreVerifier::new(Arc::new(MemoryHostKeyStore::new()), paths);
    let (result, prompts) = connect_with(addr, &verifier, vec![Some(TrustDecision::Reject)]).await;
    assert!(matches!(result.unwrap_err(), Error::HostKey(_)));
    let (_, _, known, _) = host_key_prompt(&prompts[0]);
    assert_eq!(known, Some(old.fingerprint()));
}

#[tokio::test]
async fn closing_the_prompt_cancels() {
    let addr = server().await;
    let dir = tempfile::tempdir().unwrap();
    let verifier = TrustStoreVerifier::new(
        Arc::new(MemoryHostKeyStore::new()),
        no_known_hosts(dir.path()),
    );
    let (result, prompts) = connect_with(addr, &verifier, vec![None]).await;
    assert!(matches!(result.unwrap_err(), Error::Cancelled));
    assert_eq!(prompts.len(), 1);
}
