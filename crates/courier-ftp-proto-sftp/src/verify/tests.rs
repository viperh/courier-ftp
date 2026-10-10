#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use courier_ftp_core::{
    events::{
        CoreEvent, EventSender, HostKeyPrompt, LogKind, PromptKind, PromptRequest, PromptResponse,
        SessionId, channel,
    },
    settings::DebugLevel,
    trust::MemoryHostKeyStore,
};
use pretty_assertions::assert_eq;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::known_hosts::{Marker, fingerprint_md5};

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/known_hosts/",
            $name
        ))
    };
}

const ED25519: &str = fixture!("ed25519.pub");
const ECDSA: &str = fixture!("ecdsa.pub");
const RSA: &str = fixture!("rsa.pub");

/// Another (made-up) Ed25519 public key.
fn other_ed25519() -> String {
    let mut blob = Vec::new();
    blob.extend_from_slice(&11_u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32_u32.to_be_bytes());
    blob.extend_from_slice(&[7; 32]);
    format!("ssh-ed25519 {}", STANDARD.encode(blob))
}

fn server_key(pub_line: &str) -> ServerKey {
    let mut parts = pub_line.split_whitespace();
    let key_type = parts.next().unwrap().to_owned();
    let b64 = parts.next().unwrap().to_owned();
    let blob = key_blob(&b64).unwrap();
    ServerKey {
        key_type,
        bits: 256,
        blob_base64: b64,
        fingerprint_sha256: fingerprint_sha256(&blob),
        fingerprint_md5: fingerprint_md5(&blob),
    }
}

fn stored(host: &str, port: u16, pub_line: &str) -> KnownHost {
    let k = server_key(pub_line);
    KnownHost {
        id: KnownHostId::new_v7(),
        host: host.to_owned(),
        port,
        key_type: k.key_type,
        public_key: k.blob_base64,
        added_at: OffsetDateTime::UNIX_EPOCH,
        comment: None,
    }
}

fn openssh_entry(pattern: &str, pub_line: &str, marker: Marker, line: usize) -> OpenSshEntry {
    let k = server_key(pub_line);
    OpenSshEntry {
        host_pattern: pattern.to_owned(),
        key_type: k.key_type,
        public_key: k.blob_base64,
        marker,
        source: PathBuf::from("/etc/ssh/ssh_known_hosts"),
        line,
    }
}

fn matches(entries: &[OpenSshEntry]) -> OpenSshMatches {
    lookup(entries, "h", 22)
}

fn decide_with(
    key: &str,
    store: &[KnownHost],
    session_trusted: bool,
    openssh: &[OpenSshEntry],
) -> Decision {
    let key = server_key(key);
    let openssh = matches(openssh);
    decide(&DecisionInput {
        key: &key,
        store,
        session_trusted,
        openssh: &openssh,
    })
}

/// AC1, AC6.
#[test]
fn decide_table() {
    let ed = server_key(ED25519);
    let other = other_ed25519();
    let plain = |pub_line: &str, line| openssh_entry("h", pub_line, Marker::None, line);
    let revoked = openssh_entry("*", ED25519, Marker::Revoked, 9);
    let store_ed = stored("h", 22, ED25519);
    let store_other = stored("h", 22, &other);
    let store_ecdsa = stored("h", 22, ECDSA);

    // Row 1: revoked → reject, no prompt.
    let d = decide_with(ED25519, &[], false, std::slice::from_ref(&revoked));
    assert_eq!(
        d,
        Decision::Reject(format!(
            "The host key {} is marked @revoked in /etc/ssh/ssh_known_hosts",
            ed.fingerprint_sha256
        ))
    );
    // Row 2: stored.
    assert_eq!(
        decide_with(ED25519, std::slice::from_ref(&store_ed), false, &[]),
        Decision::Accept(AcceptedBy::Store)
    );
    // Row 3: session.
    assert_eq!(
        decide_with(ED25519, &[], true, &[]),
        Decision::Accept(AcceptedBy::Session)
    );
    // Row 4: store has another key of this type.
    assert_eq!(
        decide_with(ED25519, std::slice::from_ref(&store_other), false, &[]),
        Decision::AskChanged {
            old: vec![OldKey {
                fingerprint_sha256: store_other.fingerprint_sha256(),
                source: OldKeySource::Vault {
                    id: store_other.id.0,
                    added_at: store_other.added_at,
                },
            }]
        }
    );
    // Row 5: OpenSSH file has it.
    assert_eq!(
        decide_with(ED25519, &[], false, &[plain(ED25519, 3)]),
        Decision::Accept(AcceptedBy::OpenSshFile(PathBuf::from(
            "/etc/ssh/ssh_known_hosts"
        )))
    );
    // Row 6: OpenSSH file has another key of this type.
    let other_fp = server_key(&other).fingerprint_sha256;
    assert_eq!(
        decide_with(ED25519, &[], false, &[plain(&other, 4)]),
        Decision::AskChanged {
            old: vec![OldKey {
                fingerprint_sha256: other_fp.clone(),
                source: OldKeySource::OpenSshFile {
                    path: PathBuf::from("/etc/ssh/ssh_known_hosts"),
                    line: 4,
                },
            }]
        }
    );
    // Row 7: unknown; other types listed store first, without duplicates.
    assert_eq!(
        decide_with(
            ED25519,
            std::slice::from_ref(&store_ecdsa),
            false,
            &[plain(RSA, 5), plain(ECDSA, 6)]
        ),
        Decision::AskUnknown {
            other_known_types: vec!["ecdsa-sha2-nistp256".into(), "ssh-rsa".into()]
        }
    );
    assert_eq!(
        decide_with(ED25519, &[], false, &[]),
        Decision::AskUnknown {
            other_known_types: vec![]
        }
    );

    // Precedence: the store wins over a conflicting OpenSSH file (row 4 before 5).
    assert!(matches!(
        decide_with(
            ED25519,
            std::slice::from_ref(&store_other),
            false,
            &[plain(ED25519, 3)]
        ),
        Decision::AskChanged { .. }
    ));
    // …and the other way round: a stored key wins over another key in the file.
    assert_eq!(
        decide_with(
            ED25519,
            std::slice::from_ref(&store_ed),
            false,
            &[plain(&other, 3)]
        ),
        Decision::Accept(AcceptedBy::Store)
    );
    // Session trust beats a changed store entry (row 3 before 4).
    assert_eq!(
        decide_with(ED25519, std::slice::from_ref(&store_other), true, &[]),
        Decision::Accept(AcceptedBy::Session)
    );
    // Revoked beats stored and session trust (AC6).
    assert!(matches!(
        decide_with(ED25519, std::slice::from_ref(&store_ed), true, &[revoked]),
        Decision::Reject(_)
    ));
    // A revocation of another key does not matter.
    assert_eq!(
        decide_with(
            ED25519,
            std::slice::from_ref(&store_ed),
            false,
            &[openssh_entry("*", RSA, Marker::Revoked, 1)]
        ),
        Decision::Accept(AcceptedBy::Store)
    );
    // RSA signature names are the RSA key type.
    let mut rsa_store = stored("h", 22, RSA);
    rsa_store.key_type = "rsa-sha2-512".into();
    assert_eq!(
        decide_with(RSA, &[rsa_store], false, &[]),
        Decision::Accept(AcceptedBy::Store)
    );
    // A key of another type in the store is not a change.
    assert!(matches!(
        decide_with(ED25519, &[store_ecdsa], false, &[]),
        Decision::AskUnknown { .. }
    ));
}

// ---------------------------------------------------------------- scripted UI

/// Forwards prompts to the test and records log lines.
struct Ui {
    events: EventSender,
    prompts: mpsc::UnboundedReceiver<PromptRequest>,
    log: Arc<Mutex<Vec<(LogKind, String)>>>,
    session: SessionId,
}

fn ui() -> Ui {
    let (events, mut rx) = channel(DebugLevel::Debug);
    let (tx, prompts) = mpsc::unbounded_channel();
    let log = Arc::new(Mutex::new(Vec::new()));
    let lines = Arc::clone(&log);
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CoreEvent::Prompt(req) => {
                    let _ = tx.send(req);
                }
                CoreEvent::Log(m) => lines.lock().unwrap().push((m.kind, m.text)),
                _ => {}
            }
        }
    });
    Ui {
        events,
        prompts,
        log,
        session: SessionId::next(),
    }
}

impl Ui {
    async fn next_prompt(&mut self) -> (PromptRequest, HostKeyPrompt) {
        let req = tokio::time::timeout(Duration::from_secs(5), self.prompts.recv())
            .await
            .expect("a prompt")
            .unwrap();
        let PromptKind::TrustHostKey(p) = req.kind.clone() else {
            panic!("not a host key prompt: {:?}", req.kind);
        };
        (req, p)
    }

    fn no_prompt(&mut self) {
        assert!(self.prompts.try_recv().is_err(), "unexpected prompt");
    }

    fn has_line(&self, kind: LogKind, needle: &str) -> bool {
        self.log
            .lock()
            .unwrap()
            .iter()
            .any(|(k, t)| *k == kind && t.contains(needle))
    }
}

fn verifier(store: Arc<dyn HostKeyStore>, session: Arc<SessionTrust>) -> Arc<TrustVerifier> {
    Arc::new(TrustVerifier::new(
        store,
        session,
        Arc::new(OpenSshKnownHosts::disabled()),
    ))
}

async fn verify_in_task(
    v: &Arc<TrustVerifier>,
    ui: &Ui,
    pub_line: &str,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<HostKeyVerdict> {
    let v = Arc::clone(v);
    let events = ui.events.clone();
    let session = ui.session;
    let key = server_key(pub_line);
    tokio::spawn(async move {
        let ctx = VerifyCtx {
            session,
            events: &events,
            cancel: &cancel,
        };
        v.verify("H.example", 22, &key, &ctx).await
    })
}

async fn verify_now(v: &Arc<TrustVerifier>, ui: &Ui, pub_line: &str) -> HostKeyVerdict {
    let cancel = CancellationToken::new();
    let ctx = VerifyCtx {
        session: ui.session,
        events: &ui.events,
        cancel: &cancel,
    };
    v.verify("H.example", 22, &server_key(pub_line), &ctx).await
}

/// Let the UI task drain the events sent so far.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// AC2, AC4.
#[tokio::test]
async fn always_trust_adds_and_replaces_same_type() {
    let mut ui = ui();
    let store: Arc<dyn HostKeyStore> = Arc::new(MemoryHostKeyStore::persistent_for_tests());
    let v = verifier(Arc::clone(&store), Arc::default());

    // Unknown → exactly one prompt → AlwaysTrust adds one entry.
    let task = verify_in_task(&v, &ui, ED25519, CancellationToken::new()).await;
    let (req, p) = ui.next_prompt().await;
    assert_eq!(p.host, "H.example");
    assert_eq!(p.port, 22);
    assert_eq!(p.key_type, "ssh-ed25519");
    assert_eq!(p.fingerprint_sha256, server_key(ED25519).fingerprint_sha256);
    assert!(p.fingerprint_md5.starts_with("MD5:"));
    assert_eq!(p.changed, None);
    assert!(p.can_save);
    req.respond(PromptResponse::HostKey(TrustAnswer::AlwaysTrust));
    assert_eq!(task.await.unwrap(), HostKeyVerdict::Accept);
    let all = store.list();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].host, "h.example");
    assert_eq!(all[0].public_key, server_key(ED25519).blob_base64);
    settle().await;
    assert!(ui.has_line(
        LogKind::Status,
        "The server's host key is unknown. Fingerprint: SHA256:"
    ));

    // A new process (fresh SessionTrust) connects without a prompt.
    let v2 = verifier(Arc::clone(&store), Arc::default());
    assert_eq!(verify_now(&v2, &ui, ED25519).await, HostKeyVerdict::Accept);
    settle().await;
    ui.no_prompt();
    assert!(ui.has_line(LogKind::Debug(3), "is trusted (vault)"));

    // The server's key changes; an ECDSA entry of the host stays untouched.
    store
        .add(stored("h.example", 22, ECDSA), vec![])
        .await
        .unwrap();
    let old_id = store
        .list()
        .iter()
        .find(|e| e.key_type == "ssh-ed25519")
        .unwrap()
        .id;
    let other = other_ed25519();
    let v3 = verifier(Arc::clone(&store), Arc::default());
    let task = verify_in_task(&v3, &ui, &other, CancellationToken::new()).await;
    let (req, p) = ui.next_prompt().await;
    let old = p.changed.expect("a changed-key prompt");
    assert_eq!(old.len(), 1);
    assert_eq!(
        old[0].fingerprint_sha256,
        server_key(ED25519).fingerprint_sha256
    );
    assert!(matches!(old[0].source, OldKeySource::Vault { id, .. } if id == old_id.0));
    req.respond(PromptResponse::HostKey(TrustAnswer::AlwaysTrust));
    assert_eq!(task.await.unwrap(), HostKeyVerdict::Accept);
    let types: Vec<(String, String)> = store
        .list()
        .into_iter()
        .map(|e| (e.key_type, e.public_key))
        .collect();
    assert_eq!(
        types,
        [
            (
                "ecdsa-sha2-nistp256".to_owned(),
                server_key(ECDSA).blob_base64
            ),
            ("ssh-ed25519".to_owned(), server_key(&other).blob_base64),
        ]
    );
    settle().await;
    assert!(ui.has_line(
        LogKind::Error,
        "WARNING: the host key of H.example:22 has changed!"
    ));

    // Changed again → Reject fails with the changed-key reason.
    let v4 = verifier(Arc::clone(&store), Arc::default());
    let task = verify_in_task(&v4, &ui, ED25519, CancellationToken::new()).await;
    let (req, _) = ui.next_prompt().await;
    req.respond(PromptResponse::HostKey(TrustAnswer::Reject));
    assert_eq!(
        task.await.unwrap(),
        HostKeyVerdict::Reject(REJECTED_CHANGED.to_owned())
    );
    assert_eq!(store.list().len(), 2);
}

/// AC3.
#[tokio::test]
async fn trust_once_only_session() {
    let mut ui = ui();
    let store: Arc<dyn HostKeyStore> = Arc::new(MemoryHostKeyStore::persistent_for_tests());
    let session = Arc::new(SessionTrust::default());
    let v = verifier(Arc::clone(&store), Arc::clone(&session));
    let task = verify_in_task(&v, &ui, ED25519, CancellationToken::new()).await;
    let (req, _) = ui.next_prompt().await;
    req.respond(PromptResponse::HostKey(TrustAnswer::TrustOnce));
    assert_eq!(task.await.unwrap(), HostKeyVerdict::Accept);
    assert!(store.list().is_empty(), "no store write");

    // Same process: silent.
    assert_eq!(verify_now(&v, &ui, ED25519).await, HostKeyVerdict::Accept);
    settle().await;
    ui.no_prompt();
    assert!(ui.has_line(LogKind::Debug(3), "is trusted (session)"));

    // A fresh SessionTrust asks again.
    let v2 = verifier(Arc::clone(&store), Arc::default());
    let task = verify_in_task(&v2, &ui, ED25519, CancellationToken::new()).await;
    let (req, _) = ui.next_prompt().await;
    req.respond(PromptResponse::HostKey(TrustAnswer::Reject));
    assert_eq!(
        task.await.unwrap(),
        HostKeyVerdict::Reject(REJECTED_UNKNOWN.to_owned())
    );
}

/// AC7.
#[tokio::test]
async fn always_trust_without_persist_is_trust_once() {
    let mut ui = ui();
    let store: Arc<dyn HostKeyStore> = Arc::new(MemoryHostKeyStore::new());
    let session = Arc::new(SessionTrust::default());
    let v = verifier(Arc::clone(&store), Arc::clone(&session));
    let task = verify_in_task(&v, &ui, ED25519, CancellationToken::new()).await;
    let (req, p) = ui.next_prompt().await;
    assert!(!p.can_save);
    req.respond(PromptResponse::HostKey(TrustAnswer::AlwaysTrust));
    assert_eq!(task.await.unwrap(), HostKeyVerdict::Accept);
    assert!(store.list().is_empty());
    let k = server_key(ED25519);
    assert!(session.contains("h.example", 22, &k.key_type, &k.blob_base64));
}

#[tokio::test]
async fn dropped_reply_rejects() {
    let mut ui = ui();
    let v = verifier(Arc::new(MemoryHostKeyStore::new()), Arc::default());
    let task = verify_in_task(&v, &ui, ED25519, CancellationToken::new()).await;
    let (req, _) = ui.next_prompt().await;
    drop(req);
    assert_eq!(
        task.await.unwrap(),
        HostKeyVerdict::Reject(REJECTED_UNKNOWN.to_owned())
    );
    // `Cancel` from the UI is a rejection too.
    let task = verify_in_task(&v, &ui, ED25519, CancellationToken::new()).await;
    let (req, _) = ui.next_prompt().await;
    req.respond(PromptResponse::Cancel);
    assert_eq!(
        task.await.unwrap(),
        HostKeyVerdict::Reject(REJECTED_UNKNOWN.to_owned())
    );
    settle().await;
    assert!(ui.has_line(LogKind::Error, REJECTED_UNKNOWN));
}

/// AC8.
#[tokio::test(start_paused = true)]
async fn concurrent_verifications_share_one_prompt() {
    for (answer, want) in [
        (TrustAnswer::TrustOnce, HostKeyVerdict::Accept),
        (
            TrustAnswer::Reject,
            HostKeyVerdict::Reject(REJECTED_UNKNOWN.to_owned()),
        ),
    ] {
        let mut ui = ui();
        let v = verifier(Arc::new(MemoryHostKeyStore::new()), Arc::default());
        let mut tasks = Vec::new();
        for _ in 0..4 {
            tasks.push(verify_in_task(&v, &ui, ED25519, CancellationToken::new()).await);
        }
        let (req, _) = ui.next_prompt().await;
        settle().await;
        ui.no_prompt();
        req.respond(PromptResponse::HostKey(answer));
        for t in tasks {
            assert_eq!(t.await.unwrap(), want);
        }
        settle().await;
        ui.no_prompt();
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_asker_hands_prompt_to_next_waiter() {
    let mut ui = ui();
    let v = verifier(Arc::new(MemoryHostKeyStore::new()), Arc::default());
    let first = CancellationToken::new();
    let a = verify_in_task(&v, &ui, ED25519, first.clone()).await;
    let (req_a, _) = ui.next_prompt().await;
    let b = verify_in_task(&v, &ui, ED25519, CancellationToken::new()).await;
    settle().await;
    ui.no_prompt();

    first.cancel();
    assert_eq!(
        a.await.unwrap(),
        HostKeyVerdict::Reject(CANCELLED.to_owned())
    );
    assert!(req_a.is_withdrawn());
    // The waiter asks now.
    let (req_b, _) = ui.next_prompt().await;
    req_b.respond(PromptResponse::HostKey(TrustAnswer::TrustOnce));
    assert_eq!(b.await.unwrap(), HostKeyVerdict::Accept);

    // A waiter whose own token fires gives up without asking.
    let v = verifier(Arc::new(MemoryHostKeyStore::new()), Arc::default());
    let a = verify_in_task(&v, &ui, ED25519, CancellationToken::new()).await;
    let (req_a, _) = ui.next_prompt().await;
    let token = CancellationToken::new();
    let b = verify_in_task(&v, &ui, ED25519, token.clone()).await;
    settle().await;
    token.cancel();
    assert_eq!(
        b.await.unwrap(),
        HostKeyVerdict::Reject(CANCELLED.to_owned())
    );
    req_a.respond(PromptResponse::HostKey(TrustAnswer::TrustOnce));
    assert_eq!(a.await.unwrap(), HostKeyVerdict::Accept);
    settle().await;
    ui.no_prompt();
}

/// A store whose writes fail.
#[derive(Debug)]
struct FailingStore;

#[async_trait]
impl HostKeyStore for FailingStore {
    fn lookup(&self, _: &str, _: u16) -> Vec<KnownHost> {
        Vec::new()
    }
    fn list(&self) -> Vec<KnownHost> {
        Vec::new()
    }
    fn can_persist(&self) -> bool {
        true
    }
    async fn add(&self, _: KnownHost, _: Vec<KnownHostId>) -> Result<(), Error> {
        Err(Error::Vault("disk full".into()))
    }
    async fn remove(&self, _: KnownHostId) -> Result<(), Error> {
        Err(Error::Vault("disk full".into()))
    }
}

#[tokio::test]
async fn store_add_failure_still_accepts_and_logs() {
    let mut ui = ui();
    let v = verifier(Arc::new(FailingStore), Arc::default());
    let task = verify_in_task(&v, &ui, ED25519, CancellationToken::new()).await;
    let (req, _) = ui.next_prompt().await;
    req.respond(PromptResponse::HostKey(TrustAnswer::AlwaysTrust));
    assert_eq!(task.await.unwrap(), HostKeyVerdict::Accept);
    settle().await;
    assert!(ui.has_line(LogKind::Error, "Could not save the host key: "));
    assert!(ui.has_line(LogKind::Error, "disk full"));
}

/// AC12: removing a key (and clearing the session trust) makes the next connect ask.
#[tokio::test]
async fn remove_and_clear_session_prompts_again() {
    let mut ui = ui();
    let store: Arc<dyn HostKeyStore> = Arc::new(MemoryHostKeyStore::persistent_for_tests());
    let session = Arc::new(SessionTrust::default());
    let v = verifier(Arc::clone(&store), Arc::clone(&session));
    let task = verify_in_task(&v, &ui, ED25519, CancellationToken::new()).await;
    let (req, _) = ui.next_prompt().await;
    req.respond(PromptResponse::HostKey(TrustAnswer::AlwaysTrust));
    assert_eq!(task.await.unwrap(), HostKeyVerdict::Accept);
    // "Forget host" (T68).
    for e in store.lookup("h.example", 22) {
        store.remove(e.id).await.unwrap();
    }
    session.clear();
    let task = verify_in_task(&v, &ui, ED25519, CancellationToken::new()).await;
    let (req, _) = ui.next_prompt().await;
    req.respond(PromptResponse::HostKey(TrustAnswer::Reject));
    assert!(matches!(task.await.unwrap(), HostKeyVerdict::Reject(_)));
}

/// AC6 through the verifier, and OpenSSH acceptance and key types.
#[tokio::test]
async fn openssh_revoked_accepted_and_known_types() {
    let mut ui = ui();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("known_hosts");
    let ed = ED25519.split_whitespace().nth(1).unwrap();
    let ecdsa = ECDSA.split_whitespace().nth(1).unwrap();
    let rsa = RSA.split_whitespace().nth(1).unwrap();
    std::fs::write(
        &file,
        format!(
            "h.example ecdsa-sha2-nistp256 {ecdsa}\n\
             h.example ssh-rsa {rsa}\n\
             @revoked * ssh-ed25519 {ed}\n"
        ),
    )
    .unwrap();
    let store: Arc<dyn HostKeyStore> = Arc::new(MemoryHostKeyStore::persistent_for_tests());
    store
        .add(stored("h.example", 22, ED25519), vec![])
        .await
        .unwrap();
    let v = Arc::new(TrustVerifier::new(
        Arc::clone(&store),
        Arc::default(),
        Arc::new(OpenSshKnownHosts::with_paths(vec![file.clone()])),
    ));
    // Revoked beats the store, no prompt.
    let r = verify_now(&v, &ui, ED25519).await;
    assert!(
        matches!(&r, HostKeyVerdict::Reject(why) if why.contains("is marked @revoked in")),
        "{r:?}"
    );
    // The file's ECDSA key is accepted.
    assert_eq!(verify_now(&v, &ui, ECDSA).await, HostKeyVerdict::Accept);
    settle().await;
    ui.no_prompt();
    assert!(ui.has_line(LogKind::Debug(3), &format!("({})", file.display())));
    // Store first, then the file, no duplicates.
    assert_eq!(
        v.known_key_types("H.EXAMPLE.", 22),
        ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]
    );
    assert!(v.known_key_types("h.example", 2222).is_empty());
    assert!(format!("{v:?}").contains("TrustVerifier"));
}
