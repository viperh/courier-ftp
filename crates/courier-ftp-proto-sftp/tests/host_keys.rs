//! T21 integration tests: `SshConnection::connect` with the real `TrustVerifier`
//! against the in-process russh server (`ssh::testing::TestServer`), with a UI that
//! hands the host-key prompts to the test.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use courier_ftp_core::{
    Error,
    events::{
        CoreEvent, HostKeyPrompt, OldKeySource, PromptKind, PromptRequest, PromptResponse,
        SessionId, SessionLog, TrustAnswer, channel,
    },
    net::{NetOpts, ProxyConfig, Purpose},
    secret::SecretString,
    settings::{DebugLevel, Settings},
    trust::{HostKeyStore, KnownHost, KnownHostId, MemoryHostKeyStore, SessionTrust},
};
use courier_ftp_proto_sftp::{
    known_hosts::OpenSshKnownHosts,
    ssh::{
        ServerKey, SshConnectParams, SshConnection, SshLogon,
        testing::{TestServer, TestServerConfig},
    },
    verify::{REJECTED_CHANGED, TrustVerifier},
};
use russh::keys::{PrivateKey, PublicKey, ssh_key::private::Ed25519Keypair};
use time::OffsetDateTime;
use tokio::{sync::mpsc, task::JoinHandle};

// ---------------------------------------------------------------- harness

/// The UI: host-key prompts go to the test, log lines are recorded.
struct Ui {
    log: SessionLog,
    prompts: mpsc::UnboundedReceiver<PromptRequest>,
    lines: Arc<Mutex<Vec<String>>>,
}

fn ui() -> Ui {
    let (events, mut rx) = channel(DebugLevel::Debug);
    let (tx, prompts) = mpsc::unbounded_channel();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&lines);
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CoreEvent::Prompt(req) => {
                    let _ = tx.send(req);
                }
                CoreEvent::Log(m) => seen.lock().unwrap().push(m.text),
                _ => {}
            }
        }
    });
    Ui {
        log: SessionLog {
            events,
            session: SessionId::next(),
        },
        prompts,
        lines,
    }
}

impl Ui {
    async fn next_prompt(&mut self) -> (PromptRequest, HostKeyPrompt) {
        let req = tokio::time::timeout(Duration::from_secs(10), self.prompts.recv())
            .await
            .expect("a prompt")
            .unwrap();
        let PromptKind::TrustHostKey(p) = req.kind.clone() else {
            panic!("not a host key prompt: {:?}", req.kind);
        };
        (req, p)
    }

    /// No prompt arrives within `wait`.
    async fn no_prompt(&mut self, wait: Duration) {
        if let Ok(Some(req)) = tokio::time::timeout(wait, self.prompts.recv()).await {
            panic!("unexpected prompt: {:?}", req.kind);
        }
    }

    fn has_line(&self, needle: &str) -> bool {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains(needle))
    }
}

fn password_server(host_keys: Vec<PrivateKey>) -> TestServerConfig {
    TestServerConfig {
        methods: vec!["password"],
        password: Some("secret".into()),
        host_keys,
        ..TestServerConfig::default()
    }
}

fn params(server: &TestServer) -> SshConnectParams {
    SshConnectParams {
        host: "127.0.0.1".into(),
        port: server.port(),
        user: "alice".into(),
        logon: SshLogon::Normal,
        password: Some(SecretString::from("secret")),
        key: None,
        key_passphrase: None,
        key_label: String::new(),
        try_agent_first: false,
        can_save: false,
        net: NetOpts::from_settings(&Settings::default(), Purpose::Control, ProxyConfig::Direct),
        timeout: Duration::from_secs(10),
        keepalive: None,
    }
}

fn verifier(
    store: &Arc<dyn HostKeyStore>,
    session: &Arc<SessionTrust>,
    openssh: OpenSshKnownHosts,
) -> Arc<TrustVerifier> {
    Arc::new(TrustVerifier::new(
        Arc::clone(store),
        Arc::clone(session),
        Arc::new(openssh),
    ))
}

fn connect(
    server: &TestServer,
    v: &Arc<TrustVerifier>,
    ui: &Ui,
) -> JoinHandle<Result<SshConnection, Error>> {
    let p = params(server);
    let v = Arc::clone(v);
    let log = ui.log.clone();
    tokio::spawn(async move {
        SshConnection::connect(p, v, None, &log, tokio_util::sync::CancellationToken::new()).await
    })
}

fn persistent() -> Arc<dyn HostKeyStore> {
    Arc::new(MemoryHostKeyStore::persistent_for_tests())
}

fn other_ed25519() -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[43; 32]))
}

fn ecdsa_key() -> PrivateKey {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("keys")
        .join("id_ecdsa_p256");
    courier_ftp_proto_sftp::keys::decode(&std::fs::read_to_string(path).unwrap(), None).unwrap()
}

fn info(key: &PublicKey) -> ServerKey {
    ServerKey::from_public_key(key)
}

fn known(port: u16, key: &PublicKey) -> KnownHost {
    let k = info(key);
    KnownHost {
        id: KnownHostId::new_v7(),
        host: "127.0.0.1".into(),
        port,
        key_type: k.key_type,
        public_key: k.blob_base64,
        added_at: OffsetDateTime::UNIX_EPOCH,
        comment: None,
    }
}

fn openssh_line(port: u16, key: &PublicKey) -> String {
    let k = info(key);
    format!("[127.0.0.1]:{port} {} {}\n", k.key_type, k.blob_base64)
}

// ---------------------------------------------------------------- tests

/// AC2.
#[tokio::test]
async fn loopback_unknown_always_then_silent() {
    let server = TestServer::start(password_server(vec![])).await;
    let mut ui = ui();
    let store = persistent();
    let v = verifier(&store, &Arc::default(), OpenSshKnownHosts::disabled());
    let task = connect(&server, &v, &ui);
    let (req, p) = ui.next_prompt().await;
    let expected = info(server.host_key());
    assert_eq!(p.host, "127.0.0.1");
    assert_eq!(p.port, server.port());
    assert_eq!(p.key_type, "ssh-ed25519");
    assert_eq!(p.bits, 256);
    assert_eq!(p.fingerprint_sha256, expected.fingerprint_sha256);
    assert_eq!(p.fingerprint_md5, expected.fingerprint_md5);
    assert_eq!(p.changed, None);
    assert!(p.can_save);
    req.respond(PromptResponse::HostKey(TrustAnswer::AlwaysTrust));
    let conn = task.await.unwrap().unwrap();
    assert!(conn.is_open());
    assert_eq!(
        conn.info().host_key_fingerprint,
        expected.fingerprint_sha256
    );
    ui.no_prompt(Duration::from_millis(100)).await;
    assert_eq!(store.list().len(), 1, "one entry, nothing replaced");
    assert_eq!(store.list()[0].port, server.port());

    // A new process: fresh SessionTrust, same store → no prompt.
    let v2 = verifier(&store, &Arc::default(), OpenSshKnownHosts::disabled());
    let conn = connect(&server, &v2, &ui).await.unwrap().unwrap();
    assert!(conn.is_open());
    ui.no_prompt(Duration::from_millis(100)).await;
    assert!(ui.has_line("is trusted (vault)"));
}

/// AC3.
#[tokio::test]
async fn loopback_trust_once_same_process_silent() {
    let server = TestServer::start(password_server(vec![])).await;
    let mut ui = ui();
    let store = persistent();
    let session: Arc<SessionTrust> = Arc::default();
    let v = verifier(&store, &session, OpenSshKnownHosts::disabled());
    let task = connect(&server, &v, &ui);
    let (req, _) = ui.next_prompt().await;
    req.respond(PromptResponse::HostKey(TrustAnswer::TrustOnce));
    task.await.unwrap().unwrap();
    assert!(store.list().is_empty(), "no store write");

    // Same process (another verifier sharing the SessionTrust, like T41's extra
    // connections): silent.
    let v2 = verifier(&store, &session, OpenSshKnownHosts::disabled());
    connect(&server, &v2, &ui).await.unwrap().unwrap();
    ui.no_prompt(Duration::from_millis(100)).await;

    // A fresh SessionTrust asks again.
    let v3 = verifier(&store, &Arc::default(), OpenSshKnownHosts::disabled());
    let task = connect(&server, &v3, &ui);
    let (req, _) = ui.next_prompt().await;
    req.respond(PromptResponse::HostKey(TrustAnswer::TrustOnce));
    task.await.unwrap().unwrap();
}

/// AC4.
#[tokio::test]
async fn loopback_changed_key_prompt_reject_and_replace() {
    let server = TestServer::start(password_server(vec![other_ed25519()])).await;
    let mut ui = ui();
    let store = persistent();
    // The host's old key (the default test key) is stored, plus an ECDSA key.
    let old = known(
        server.port(),
        &courier_ftp_proto_sftp::ssh::testing::host_key()
            .public_key()
            .clone(),
    );
    let ecdsa = known(server.port(), ecdsa_key().public_key());
    store.add(old.clone(), vec![]).await.unwrap();
    store.add(ecdsa.clone(), vec![]).await.unwrap();

    // Reject.
    let v = verifier(&store, &Arc::default(), OpenSshKnownHosts::disabled());
    let task = connect(&server, &v, &ui);
    let (req, p) = ui.next_prompt().await;
    let changed = p.changed.clone().expect("changed-key prompt");
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].fingerprint_sha256, old.fingerprint_sha256());
    assert!(matches!(changed[0].source, OldKeySource::Vault { id, .. } if id == old.id.0));
    assert_eq!(
        p.fingerprint_sha256,
        info(server.host_key()).fingerprint_sha256
    );
    req.respond(PromptResponse::HostKey(TrustAnswer::Reject));
    let err = task.await.unwrap().unwrap_err();
    assert!(
        matches!(&err, Error::HostKey(why) if why == REJECTED_CHANGED),
        "{err:?}"
    );
    assert!(ui.has_line("WARNING: the host key of 127.0.0.1:"));

    // Replace.
    let v = verifier(&store, &Arc::default(), OpenSshKnownHosts::disabled());
    let task = connect(&server, &v, &ui);
    let (req, p) = ui.next_prompt().await;
    assert!(p.changed.is_some());
    req.respond(PromptResponse::HostKey(TrustAnswer::AlwaysTrust));
    task.await.unwrap().unwrap();
    let new = info(server.host_key());
    let ed: Vec<KnownHost> = store
        .list()
        .into_iter()
        .filter(|e| e.key_type == "ssh-ed25519")
        .collect();
    assert_eq!(ed.len(), 1);
    assert_eq!(ed[0].public_key, new.blob_base64);
    assert!(
        store.list().iter().any(|e| e.id == ecdsa.id),
        "other types kept"
    );
}

/// AC6.
#[tokio::test]
async fn loopback_revoked_never_prompts() {
    let server = TestServer::start(password_server(vec![])).await;
    let mut ui = ui();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("ssh_known_hosts");
    let k = info(server.host_key());
    std::fs::write(
        &file,
        format!("@revoked * {} {}\n", k.key_type, k.blob_base64),
    )
    .unwrap();
    let store = persistent();
    store
        .add(known(server.port(), server.host_key()), vec![])
        .await
        .unwrap();
    let session: Arc<SessionTrust> = Arc::default();
    session.insert("127.0.0.1", server.port(), &k.key_type, &k.blob_base64);
    let v = verifier(
        &store,
        &session,
        OpenSshKnownHosts::with_paths(vec![file.clone()]),
    );
    let err = connect(&server, &v, &ui).await.unwrap().unwrap_err();
    assert!(
        matches!(&err, Error::HostKey(why) if why.contains("is marked @revoked in")
            && why.contains(&k.fingerprint_sha256)),
        "{err:?}"
    );
    ui.no_prompt(Duration::from_millis(100)).await;
}

/// AC9.
#[tokio::test]
async fn loopback_known_type_preferred() {
    let ecdsa = ecdsa_key();
    let server = TestServer::start(password_server(vec![
        courier_ftp_proto_sftp::ssh::testing::host_key(),
        ecdsa.clone(),
    ]))
    .await;
    let mut ui = ui();
    let store = persistent();
    store
        .add(known(server.port(), ecdsa.public_key()), vec![])
        .await
        .unwrap();
    let v = verifier(&store, &Arc::default(), OpenSshKnownHosts::disabled());
    let conn = connect(&server, &v, &ui).await.unwrap().unwrap();
    ui.no_prompt(Duration::from_millis(100)).await;
    assert_eq!(conn.info().host_key_algorithm, "ecdsa-sha2-nistp256");
    assert_eq!(
        conn.info().host_key_fingerprint,
        info(ecdsa.public_key()).fingerprint_sha256
    );

    // Without a stored key the client's default order (ed25519 first) applies.
    let v = verifier(
        &persistent(),
        &Arc::default(),
        OpenSshKnownHosts::disabled(),
    );
    let task = connect(&server, &v, &ui);
    let (req, p) = ui.next_prompt().await;
    assert_eq!(p.key_type, "ssh-ed25519");
    req.respond(PromptResponse::HostKey(TrustAnswer::Reject));
    assert!(task.await.unwrap().is_err());
}

fn snapshot(path: &Path) -> (Vec<u8>, SystemTime) {
    (
        std::fs::read(path).unwrap(),
        std::fs::metadata(path).unwrap().modified().unwrap(),
    )
}

/// AC10.
#[tokio::test]
async fn loopback_openssh_file_untouched() {
    let server = TestServer::start(password_server(vec![])).await;
    let changed = TestServer::start(password_server(vec![other_ed25519()])).await;
    let mut ui = ui();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("known_hosts");
    // The first server's key; the second server's entry is a different key.
    let default_key = courier_ftp_proto_sftp::ssh::testing::host_key();
    let text = format!(
        "# a comment\n{}{}",
        openssh_line(server.port(), server.host_key()),
        openssh_line(changed.port(), default_key.public_key()),
    );
    std::fs::write(&file, text).unwrap();
    let before = snapshot(&file);

    let store = persistent();
    let v = verifier(
        &store,
        &Arc::default(),
        OpenSshKnownHosts::with_paths(vec![file.clone()]),
    );
    // Accepted from the file, nothing stored.
    let conn = connect(&server, &v, &ui).await.unwrap().unwrap();
    assert!(conn.is_open());
    ui.no_prompt(Duration::from_millis(100)).await;
    assert!(store.list().is_empty());
    assert!(ui.has_line(&format!("({})", file.display())));

    // A changed key against the file → changed prompt naming the file line → reject.
    let task = connect(&changed, &v, &ui);
    let (req, p) = ui.next_prompt().await;
    let old = p.changed.clone().expect("changed-key prompt");
    assert_eq!(
        old[0].source,
        OldKeySource::OpenSshFile {
            path: file.clone(),
            line: 3
        }
    );
    req.respond(PromptResponse::HostKey(TrustAnswer::Reject));
    assert!(task.await.unwrap().is_err());

    // …and accepted with "Always trust": stored in the store, never in the file.
    let task = connect(&changed, &v, &ui);
    let (req, _) = ui.next_prompt().await;
    req.respond(PromptResponse::HostKey(TrustAnswer::AlwaysTrust));
    task.await.unwrap().unwrap();
    assert_eq!(store.list().len(), 1);

    assert_eq!(snapshot(&file), before, "content and mtime unchanged");
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        1,
        "no new files"
    );

    // Disabled: the file is not read, so the first server is unknown again.
    let v = verifier(
        &persistent(),
        &Arc::default(),
        OpenSshKnownHosts::disabled(),
    );
    let task = connect(&server, &v, &ui);
    let (req, _) = ui.next_prompt().await;
    req.respond(PromptResponse::HostKey(TrustAnswer::Reject));
    assert!(task.await.unwrap().is_err());
}

/// AC8.
#[tokio::test]
async fn loopback_four_parallel_connects_one_prompt() {
    let server = TestServer::start(password_server(vec![])).await;
    for (answer, ok) in [(TrustAnswer::TrustOnce, true), (TrustAnswer::Reject, false)] {
        let mut ui = ui();
        let v = verifier(
            &persistent(),
            &Arc::default(),
            OpenSshKnownHosts::disabled(),
        );
        let tasks: Vec<_> = (0..4).map(|_| connect(&server, &v, &ui)).collect();
        let (req, _) = ui.next_prompt().await;
        // Give the other three connections time to reach the host-key check.
        ui.no_prompt(Duration::from_millis(500)).await;
        req.respond(PromptResponse::HostKey(answer));
        for t in tasks {
            let r = t.await.unwrap();
            assert_eq!(r.is_ok(), ok, "{r:?}");
            if let Err(e) = r {
                assert!(matches!(e, Error::HostKey(_)), "{e:?}");
            }
        }
        ui.no_prompt(Duration::from_millis(100)).await;
    }
}
