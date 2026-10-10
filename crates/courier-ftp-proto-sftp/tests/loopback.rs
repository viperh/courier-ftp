//! T20 integration tests: `SshConnection::connect` against the in-process russh server
//! (`ssh::testing::TestServer` on 127.0.0.1), with a scripted UI answering the T04
//! prompts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use courier_ftp_core::{
    Error,
    events::{
        CoreEvent, LogKind, LogMessage, PromptId, PromptKind, PromptRequest, PromptResponse,
        SessionId, SessionLog, channel,
    },
    model::{KeySource, LocalPath},
    net::{HostPort, NetOpts, ProxyConfig, Purpose},
    secret::SecretString,
    settings::{DebugLevel, Settings},
};
use courier_ftp_proto_sftp::{
    agent::AgentConnector,
    ssh::{
        HostKeyVerdict, HostKeyVerifier, InsecureAcceptAnyHostKey, ServerKey, SshConnectParams,
        SshConnection, SshLogon, UnverifiedHostKeys, VerifyCtx,
        testing::{KbdRound, TestServer, TestServerConfig, legacy_preferences},
    },
};
use russh::keys::PublicKey;
use tokio::task::JoinHandle;

// ---------------------------------------------------------------- the scripted UI

/// How the UI answers one prompt.
#[derive(Debug, Clone)]
enum Answer {
    Secret(&'static str),
    Fields(Vec<&'static str>),
    Cancel,
    /// Never answer (the request stays open).
    Hold,
}

#[derive(Debug, Default)]
struct UiState {
    prompts: Vec<(PromptId, PromptKind)>,
    logs: Vec<LogMessage>,
    accepted: Vec<PromptId>,
    /// `Debug` of every event, for the canary scan.
    dump: String,
    held: Vec<PromptRequest>,
}

#[derive(Clone)]
struct Ui(Arc<Mutex<UiState>>);

impl Ui {
    fn state(&self) -> std::sync::MutexGuard<'_, UiState> {
        self.0.lock().unwrap()
    }

    fn prompts(&self) -> Vec<PromptKind> {
        self.state()
            .prompts
            .iter()
            .map(|(_, k)| k.clone())
            .collect()
    }

    fn accepted(&self) -> Vec<PromptId> {
        self.state().accepted.clone()
    }

    fn prompt_ids(&self) -> Vec<PromptId> {
        self.state().prompts.iter().map(|(i, _)| *i).collect()
    }

    fn lines(&self) -> Vec<(LogKind, String)> {
        self.state()
            .logs
            .iter()
            .map(|l| (l.kind, l.text.clone()))
            .collect()
    }

    fn status_lines(&self) -> Vec<String> {
        self.lines()
            .into_iter()
            .filter(|(k, _)| *k == LogKind::Status)
            .map(|(_, t)| t)
            .collect()
    }

    fn has_line(&self, text: &str) -> bool {
        self.lines().iter().any(|(_, t)| t.contains(text))
    }

    async fn wait_for_prompt(&self) {
        let start = Instant::now();
        while self.state().prompts.is_empty() {
            assert!(start.elapsed() < Duration::from_secs(10), "no prompt");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

struct Harness {
    log: SessionLog,
    ui: Ui,
    _task: JoinHandle<()>,
}

fn harness(script: Vec<Answer>) -> Harness {
    let (events, mut rx) = channel(DebugLevel::Debug);
    let ui = Ui(Arc::new(Mutex::new(UiState::default())));
    let state = ui.clone();
    let task = tokio::spawn(async move {
        let mut script = VecDeque::from(script);
        while let Some(event) = rx.recv().await {
            let mut s = state.0.lock().unwrap();
            s.dump.push_str(&format!("{event:?}\n"));
            match event {
                CoreEvent::Log(msg) => s.logs.push(msg),
                CoreEvent::CredentialAccepted { prompt_id, .. } => s.accepted.push(prompt_id),
                CoreEvent::Prompt(req) => {
                    s.prompts.push((req.id, req.kind.clone()));
                    match script.pop_front().unwrap_or(Answer::Cancel) {
                        Answer::Secret(v) => {
                            req.respond(PromptResponse::Secret {
                                value: SecretString::from(v),
                                remember_session: false,
                                save_in_vault: false,
                            });
                        }
                        Answer::Fields(v) => {
                            req.respond(PromptResponse::Answers(
                                v.into_iter().map(SecretString::from).collect(),
                            ));
                        }
                        Answer::Cancel => {
                            req.respond(PromptResponse::Cancel);
                        }
                        Answer::Hold => s.held.push(req),
                    }
                }
                _ => {}
            }
        }
    });
    Harness {
        log: SessionLog {
            events,
            session: SessionId::next(),
        },
        ui,
        _task: task,
    }
}

// ---------------------------------------------------------------- helpers

fn keys_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("keys")
}

fn public_of(name: &str, pass: Option<&str>) -> PublicKey {
    let text = std::fs::read_to_string(keys_dir().join(name)).unwrap();
    courier_ftp_proto_sftp::keys::decode(&text, pass)
        .unwrap()
        .public_key()
        .clone()
}

fn params(server: &TestServer, logon: SshLogon) -> SshConnectParams {
    SshConnectParams {
        host: "127.0.0.1".into(),
        port: server.port(),
        user: "alice".into(),
        logon,
        password: None,
        key: None,
        key_passphrase: None,
        key_label: String::new(),
        try_agent_first: false,
        can_save: true,
        net: NetOpts::from_settings(&Settings::default(), Purpose::Control, ProxyConfig::Direct),
        timeout: Duration::from_secs(10),
        keepalive: None,
    }
}

fn insecure() -> Arc<dyn HostKeyVerifier> {
    Arc::new(InsecureAcceptAnyHostKey)
}

async fn connect(
    p: SshConnectParams,
    h: &Harness,
    agent: Option<Arc<dyn AgentConnector>>,
) -> Result<SshConnection, Error> {
    let r = SshConnection::connect(
        p,
        insecure(),
        agent,
        &h.log,
        tokio_util::sync::CancellationToken::new(),
    )
    .await;
    settle().await;
    r
}

/// Let the UI task drain the events sent so far.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

fn password_server(pw: &str) -> TestServerConfig {
    TestServerConfig {
        methods: vec!["password"],
        password: Some(pw.to_owned()),
        ..TestServerConfig::default()
    }
}

// ---------------------------------------------------------------- AC2

#[tokio::test]
async fn loopback_password_auth() {
    let server = TestServer::start(password_server("secret")).await;
    let h = harness(vec![]);
    let mut p = params(&server, SshLogon::Normal);
    p.password = Some(SecretString::from("secret"));
    let conn = connect(p, &h, None).await.unwrap();
    assert!(conn.is_open());
    assert_eq!(conn.info().auth_method, "password");
    // AC13 (in-process): an AEAD cipher with an implicit MAC.
    assert!(
        conn.info().cipher.ends_with("-gcm@openssh.com"),
        "{:?}",
        conn.info()
    );
    assert_eq!(conn.info().mac, "(implicit)");
    assert!(conn.info().server_version.starts_with("SSH-2.0-"));
    assert!(conn.info().host_key_fingerprint.starts_with("SHA256:"));
    assert_eq!(conn.info().compression, "none");
    assert!(h.ui.prompts().is_empty());
    assert_eq!(server.users(), ["alice"]);
    // The SFTP subsystem channel (used by T22).
    let _stream = conn.open_subsystem("sftp").await.unwrap();
    assert!(conn.open_subsystem("nope").await.is_err());
    assert!(h.ui.has_line("Authenticated using password."));
    assert!(h.ui.has_line("Using username \"alice\"."));
    assert!(h.ui.has_line("Server version: SSH-2.0-"));
    conn.disconnect().await;

    // Wrong stored password: exactly three prompts with `retry`, then Auth.
    let h = harness(vec![
        Answer::Secret("w1"),
        Answer::Secret("w2"),
        Answer::Secret("w3"),
    ]);
    let mut p = params(&server, SshLogon::Normal);
    p.password = Some(SecretString::from("wrong"));
    let err = connect(p, &h, None).await.unwrap_err();
    assert!(
        matches!(&err, Error::Auth(m) if m.starts_with("Permission denied")),
        "{err}"
    );
    let prompts = h.ui.prompts();
    assert_eq!(prompts.len(), 3);
    for (i, kind) in prompts.iter().enumerate() {
        let PromptKind::Password(pp) = kind else {
            panic!("{kind:?}")
        };
        assert!(pp.retry);
        assert_eq!(usize::from(pp.attempt), i + 1);
        assert_eq!(pp.max_attempts, 3);
        assert_eq!(pp.target, format!("alice@127.0.0.1:{}", server.port()));
        assert!(pp.can_save);
    }
    assert!(h.ui.accepted().is_empty());
    assert!(
        h.ui.lines()
            .iter()
            .any(|(k, t)| *k == LogKind::Error && t.starts_with("Permission denied"))
    );

    // A typed password that works is reported as accepted.
    let h = harness(vec![Answer::Secret("bad"), Answer::Secret("secret")]);
    connect(params(&server, SshLogon::AskForPassword), &h, None)
        .await
        .unwrap();
    let ids = h.ui.prompt_ids();
    assert_eq!(h.ui.accepted(), [ids[1]]);
}

// ---------------------------------------------------------------- AC3

#[tokio::test]
async fn loopback_kbd_two_rounds() {
    let server = TestServer::start(TestServerConfig {
        methods: vec!["keyboard-interactive"],
        kbd: vec![
            KbdRound {
                name: "Login\u{1b}[2J".into(),
                instructions: "Enter your \u{9b}31mpassword".into(),
                prompts: vec![("Password: ".into(), false)],
                expect: vec!["pw".into()],
            },
            KbdRound::single("Verification code: ", "424242"),
        ],
        ..TestServerConfig::default()
    })
    .await;
    let h = harness(vec![
        Answer::Fields(vec!["pw"]),
        Answer::Fields(vec!["424242"]),
    ]);
    let conn = connect(params(&server, SshLogon::Interactive), &h, None)
        .await
        .unwrap();
    assert_eq!(conn.info().auth_method, "keyboard-interactive");
    let prompts = h.ui.prompts();
    assert_eq!(prompts.len(), 2);
    let PromptKind::KeyboardInteractive(first) = &prompts[0] else {
        panic!()
    };
    assert_eq!(first.host, format!("127.0.0.1:{}", server.port()));
    assert_eq!(first.name, "Login");
    assert_eq!(first.instructions, "Enter your password");
    assert_eq!(first.prompts.len(), 1);
    assert_eq!(first.prompts[0].text, "Password:");
    assert!(!first.prompts[0].echo);
    let PromptKind::KeyboardInteractive(second) = &prompts[1] else {
        panic!()
    };
    assert_eq!(second.prompts[0].text, "Verification code:");
    // Both answers led to the success.
    assert_eq!(h.ui.accepted(), h.ui.prompt_ids());
    assert_eq!(
        server.requests(),
        ["none", "kbd", "kbd-answer", "kbd-answer"]
    );
}

// ---------------------------------------------------------------- AC4

#[tokio::test]
async fn loopback_keyfile_every_fixture() {
    let authorized = vec![
        public_of("id_ed25519", None),
        public_of("id_ecdsa_p256", None),
        public_of("id_rsa4096", None),
        public_of("id_ed25519_enc", Some("fixture")),
    ];
    let server = TestServer::start(TestServerConfig {
        methods: vec!["publickey"],
        authorized,
        ..TestServerConfig::default()
    })
    .await;
    let list = std::fs::read_to_string(keys_dir().join("fingerprints.txt")).unwrap();
    let names: Vec<&str> = list.lines().filter_map(|l| l.split(' ').next()).collect();
    assert_eq!(names.len(), 13);
    for name in names {
        let encrypted = name.contains("_enc");
        let h = harness(if encrypted {
            vec![Answer::Secret("fixture")]
        } else {
            vec![]
        });
        let mut p = params(&server, SshLogon::KeyFile);
        let path = keys_dir().join(name);
        p.key = Some(KeySource::Path(LocalPath::new(path.clone())));
        p.key_label = path.display().to_string();
        let conn = connect(p, &h, None)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(conn.info().auth_method, "publickey", "{name}");
        let prompts = h.ui.prompts();
        assert_eq!(prompts.len(), usize::from(encrypted), "{name}");
        if encrypted {
            let PromptKind::KeyPassphrase(pp) = &prompts[0] else {
                panic!("{name}")
            };
            assert_eq!(pp.key_label, path.display().to_string());
            assert!(!pp.retry);
            assert_eq!(h.ui.accepted(), h.ui.prompt_ids(), "{name}");
        }
        // RSA keys sign with rsa-sha2-512 (russh's server advertises it in
        // server-sig-algs; the algorithm is in the "Trying public key" line).
        if name.contains("rsa") {
            assert!(
                h.ui.status_lines()
                    .iter()
                    .any(|l| l.starts_with("Trying public key")
                        && l.contains("(rsa-sha2-512 SHA256:")),
                "{name}: {:?}",
                h.ui.status_lines()
            );
        }
        conn.disconnect().await;
    }

    // A vault key (inline text) is labelled "vault key of <site>".
    let h = harness(vec![Answer::Secret("fixture")]);
    let mut p = params(&server, SshLogon::KeyFile);
    let text = std::fs::read_to_string(keys_dir().join("id_ed25519_enc")).unwrap();
    p.key = Some(KeySource::Inline(SecretString::from(text)));
    p.key_label = "vault key of Work".into();
    connect(p, &h, None).await.unwrap();
    let PromptKind::KeyPassphrase(pp) = &h.ui.prompts()[0] else {
        panic!()
    };
    assert_eq!(pp.key_label, "vault key of Work");
}

#[tokio::test]
async fn loopback_wrong_passphrase_sends_no_publickey() {
    let server = TestServer::start(TestServerConfig {
        methods: vec!["publickey"],
        authorized: vec![public_of("id_ed25519_enc", Some("fixture"))],
        ..TestServerConfig::default()
    })
    .await;
    let h = harness(vec![
        Answer::Secret("x"),
        Answer::Secret("y"),
        Answer::Secret("z"),
    ]);
    let mut p = params(&server, SshLogon::KeyFile);
    p.key = Some(KeySource::Path(LocalPath::new(
        keys_dir().join("id_ed25519_enc"),
    )));
    p.key_label = "work key".into();
    let err = connect(p, &h, None).await.unwrap_err();
    assert!(
        matches!(&err, Error::Auth(m) if m == "Wrong passphrase for key work key (3 attempts)"),
        "{err}"
    );
    assert_eq!(h.ui.prompts().len(), 3);
    assert_eq!(server.publickey_requests(), 0);

    // A missing or bad key file fails before any network I/O.
    let h = harness(vec![]);
    let mut p = params(&server, SshLogon::KeyFile);
    p.key = Some(KeySource::Path(LocalPath::new(keys_dir().join("missing"))));
    p.key_label = "missing".into();
    let err = connect(p, &h, None).await.unwrap_err();
    assert!(
        matches!(&err, Error::InvalidInput(m) if m.starts_with("Could not read key file missing"))
    );
    let mut p = params(&server, SshLogon::KeyFile);
    p.key = Some(KeySource::Path(LocalPath::new(
        keys_dir().join("fingerprints.txt"),
    )));
    let err = connect(p, &h, None).await.unwrap_err();
    assert!(matches!(&err, Error::InvalidInput(m) if m.starts_with("Not a private key format")));
}

// ---------------------------------------------------------------- AC7

#[cfg(unix)]
#[tokio::test]
async fn loopback_agent_auth_unix() {
    use courier_ftp_proto_sftp::agent::testing::{UnixSocketAgent, UnreachableAgent};

    let text = std::fs::read_to_string(keys_dir().join("id_ed25519")).unwrap();
    let key = courier_ftp_proto_sftp::keys::decode(&text, None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let agent = UnixSocketAgent::start(dir.path().join("agent.sock"), std::slice::from_ref(&key))
        .await
        .unwrap();
    let server = TestServer::start(TestServerConfig {
        methods: vec!["publickey", "password"],
        authorized: vec![key.public_key().clone()],
        password: Some("pw".into()),
        ..TestServerConfig::default()
    })
    .await;
    let connector: Arc<dyn AgentConnector> = Arc::new(agent.connector());

    // The Agent logon.
    let h = harness(vec![]);
    let conn = connect(
        params(&server, SshLogon::Agent),
        &h,
        Some(Arc::clone(&connector)),
    )
    .await
    .unwrap();
    assert_eq!(conn.info().auth_method, "publickey");
    assert!(
        h.ui.status_lines()
            .iter()
            .any(|l| l.starts_with("Trying agent key \"") && l.contains("(ssh-ed25519 SHA256:")),
        "{:?}",
        h.ui.status_lines()
    );

    // try_agent_first: the agent key works before the password is needed.
    let h = harness(vec![]);
    let mut p = params(&server, SshLogon::AskForPassword);
    p.try_agent_first = true;
    let conn = connect(p, &h, Some(connector)).await.unwrap();
    assert_eq!(conn.info().auth_method, "publickey");
    assert!(h.ui.prompts().is_empty());

    // An unreachable agent is skipped with a Status line.
    let h = harness(vec![]);
    let mut p = params(&server, SshLogon::Normal);
    p.try_agent_first = true;
    p.password = Some(SecretString::from("pw"));
    let conn = connect(p, &h, Some(Arc::new(UnreachableAgent)))
        .await
        .unwrap();
    assert_eq!(conn.info().auth_method, "password");
    assert!(
        h.ui.status_lines()
            .contains(&"No SSH agent available".to_owned())
    );
}

// ---------------------------------------------------------------- AC10, AC11

#[tokio::test]
async fn loopback_handshake_timeout_silent_server() {
    let server = TestServer::start(TestServerConfig {
        silent: true,
        ..TestServerConfig::default()
    })
    .await;
    let h = harness(vec![]);
    let mut p = params(&server, SshLogon::AskForPassword);
    p.timeout = Duration::from_secs(1);
    let start = Instant::now();
    let err = SshConnection::connect(
        p,
        insecure(),
        None,
        &h.log,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap_err();
    let elapsed = start.elapsed();
    settle().await;
    assert!(matches!(err, Error::Timeout), "{err}");
    assert!(
        elapsed >= Duration::from_secs(1) && elapsed <= Duration::from_millis(1500),
        "{elapsed:?}"
    );
    assert!(h.ui.has_line("Connection timed out during the SSH handshake"));
}

#[derive(Debug)]
struct SlowVerifier(Duration);

#[async_trait]
impl HostKeyVerifier for SlowVerifier {
    async fn verify(&self, _: &str, _: u16, _: &ServerKey, _: &VerifyCtx<'_>) -> HostKeyVerdict {
        tokio::time::sleep(self.0).await;
        HostKeyVerdict::Accept
    }
}

#[tokio::test]
async fn loopback_prompt_time_not_counted() {
    let server = TestServer::start(password_server("secret")).await;
    let h = harness(vec![]);
    let mut p = params(&server, SshLogon::Normal);
    p.password = Some(SecretString::from("secret"));
    p.timeout = Duration::from_secs(1);
    let conn = SshConnection::connect(
        p,
        Arc::new(SlowVerifier(Duration::from_secs(3))),
        None,
        &h.log,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(conn.is_open());
}

#[tokio::test]
async fn loopback_host_key_rejected() {
    let server = TestServer::start(password_server("secret")).await;
    let h = harness(vec![]);
    let mut p = params(&server, SshLogon::Normal);
    p.password = Some(SecretString::from("secret"));
    let err = SshConnection::connect(
        p,
        Arc::new(UnverifiedHostKeys),
        None,
        &h.log,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, Error::HostKey(m) if m == "host key verification is not available yet"),
        "{err}"
    );
    assert!(server.requests().is_empty());
}

// ---------------------------------------------------------------- AC9

/// Run `connect` and fire the token when `trigger` resolves; the result must be
/// `Cancelled` within 100 ms of the cancel.
async fn cancel_after<F>(p: SshConnectParams, h: &Harness, trigger: F)
where
    F: std::future::Future<Output = ()>,
{
    let cancel = tokio_util::sync::CancellationToken::new();
    let connect = SshConnection::connect(p, insecure(), None, &h.log, cancel.clone());
    tokio::pin!(connect);
    tokio::select! {
        r = &mut connect => panic!("finished before the cancel: {:?}", r.err()),
        () = trigger => {}
    }
    let fired = Instant::now();
    cancel.cancel();
    let err = connect.await.unwrap_err();
    let elapsed = fired.elapsed();
    assert!(matches!(err, Error::Cancelled), "{err}");
    assert!(elapsed < Duration::from_millis(100), "{elapsed:?}");
    settle().await;
}

#[tokio::test]
async fn loopback_cancel_at_each_stage() {
    // TCP connect: through an HTTP proxy that accepts and never answers.
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let _hold = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = proxy.accept().await {
            held.push(s);
        }
    });
    let server = TestServer::start(password_server("secret")).await;
    let h = harness(vec![]);
    let mut p = params(&server, SshLogon::Normal);
    p.net.proxy = ProxyConfig::Http {
        proxy: HostPort::new("127.0.0.1", proxy_port),
        auth: None,
    };
    cancel_after(p, &h, tokio::time::sleep(Duration::from_millis(200))).await;

    // Handshake: a silent server.
    let silent = TestServer::start(TestServerConfig {
        silent: true,
        ..TestServerConfig::default()
    })
    .await;
    let h = harness(vec![]);
    cancel_after(
        params(&silent, SshLogon::Normal),
        &h,
        tokio::time::sleep(Duration::from_millis(200)),
    )
    .await;
    assert!(h.ui.has_line("Connection cancelled"));

    // An auth request the server answers slowly.
    let slow = TestServer::start(TestServerConfig {
        auth_delay: Duration::from_secs(5),
        ..password_server("secret")
    })
    .await;
    let h = harness(vec![]);
    let mut p = params(&slow, SshLogon::Normal);
    p.password = Some(SecretString::from("secret"));
    let slow_ref = &slow;
    cancel_after(p, &h, async move {
        while !slow_ref.requests().contains(&"password".to_owned()) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;

    // A pending prompt; the UI sees the request withdrawn.
    let h = harness(vec![Answer::Hold]);
    let ui = h.ui.clone();
    cancel_after(params(&server, SshLogon::AskForPassword), &h, async move {
        ui.wait_for_prompt().await
    })
    .await;
    assert!(h.ui.state().held.iter().all(PromptRequest::is_withdrawn));

    // An already-fired token: no request reaches the server.
    let before = server.requests().len();
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();
    let err = SshConnection::connect(
        params(&server, SshLogon::AskForPassword),
        insecure(),
        None,
        &h.log,
        cancel,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Cancelled));
    assert_eq!(server.requests().len(), before);
}

// ---------------------------------------------------------------- AC14

#[tokio::test]
async fn loopback_banner_sanitized() {
    let mut banner =
        String::from("\u{1b}[1;31mWelcome\u{1b}[0m to \u{9b}2Jthe \u{202e}server\u{7}\n");
    banner.push_str("\u{1b}]0;evil title\u{7}second line\n");
    for i in 0..60 {
        banner.push_str(&format!("line {i}\n"));
    }
    let server = TestServer::start(TestServerConfig {
        banner: Some(banner),
        ..password_server("secret")
    })
    .await;
    let h = harness(vec![]);
    let mut p = params(&server, SshLogon::Normal);
    p.password = Some(SecretString::from("secret"));
    connect(p, &h, None).await.unwrap();
    let lines = h.ui.status_lines();
    assert!(
        lines.contains(&"Welcome to the server".to_owned()),
        "{lines:?}"
    );
    assert!(lines.contains(&"second line".to_owned()));
    assert!(lines.contains(&"line 37".to_owned()));
    assert!(!lines.contains(&"line 38".to_owned()), "capped at 40 lines");
    for (_, text) in h.ui.lines() {
        assert!(
            !text.chars().any(|c| c.is_control()
                || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')),
            "{text:?}"
        );
    }

    // One huge line is cut at 4096 characters.
    let server = TestServer::start(TestServerConfig {
        banner: Some("x".repeat(10_000)),
        ..password_server("secret")
    })
    .await;
    let h = harness(vec![]);
    let mut p = params(&server, SshLogon::Normal);
    p.password = Some(SecretString::from("secret"));
    connect(p, &h, None).await.unwrap();
    let long =
        h.ui.status_lines()
            .into_iter()
            .find(|l| l.starts_with("xxx"))
            .unwrap();
    assert_eq!(long.chars().count(), 4097);
    assert!(long.ends_with('…'));
}

// ---------------------------------------------------------------- AC16

#[tokio::test]
async fn loopback_no_secrets_in_logs() {
    const PW: &str = "CANARY-PW-t20-1a2b";
    const OTP: &str = "CANARY-OTP-t20-3c4d";
    const PP: &str = "CANARY-PP-t20-5d1c";

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let server = TestServer::start(TestServerConfig {
        methods: vec!["password", "keyboard-interactive", "publickey"],
        password: Some(PW.into()),
        kbd: vec![
            KbdRound::single("Password: ", PW),
            KbdRound::single("Verification code: ", OTP),
        ],
        authorized: vec![public_of("id_ed25519", None)],
        ..TestServerConfig::default()
    })
    .await;
    let mut dumps = String::new();

    // Stored password, then a wrong typed one and the right one.
    let h = harness(vec![Answer::Secret(PW)]);
    let mut p = params(&server, SshLogon::Normal);
    p.password = Some(SecretString::from(PW));
    connect(p, &h, None).await.unwrap();
    let h2 = harness(vec![
        Answer::Secret("CANARY-PW-wrong-9z"),
        Answer::Secret(PW),
    ]);
    connect(params(&server, SshLogon::AskForPassword), &h2, None)
        .await
        .unwrap();
    // Keyboard-interactive with password and OTP.
    let h3 = harness(vec![Answer::Fields(vec![PW]), Answer::Fields(vec![OTP])]);
    connect(params(&server, SshLogon::Interactive), &h3, None)
        .await
        .unwrap();
    // A key with a canary passphrase.
    let h4 = harness(vec![Answer::Secret(PP)]);
    let mut p = params(&server, SshLogon::KeyFile);
    p.key = Some(KeySource::Path(LocalPath::new(
        keys_dir().join("canary_ed25519_pkcs8_enc.pem"),
    )));
    p.key_label = "canary key".into();
    connect(p, &h4, None).await.unwrap();
    // Let the UI tasks drain.
    tokio::time::sleep(Duration::from_millis(50)).await;
    for hh in [&h, &h2, &h3, &h4] {
        dumps.push_str(&hh.ui.state().dump);
        for (_, line) in hh.ui.lines() {
            dumps.push_str(&line);
            dumps.push('\n');
        }
    }
    let traced = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
    assert!(!traced.is_empty());
    assert!(dumps.contains("Authenticated using"));
    for canary in [PW, OTP, PP, "CANARY-PW-wrong-9z"] {
        assert!(!traced.contains(canary), "{canary} in tracing output");
        assert!(
            !dumps.contains(canary),
            "{canary} in the session log / events"
        );
    }
}

// ---------------------------------------------------------------- disconnects

#[tokio::test]
async fn loopback_server_disconnect_while_prompting() {
    let server = TestServer::start(TestServerConfig {
        methods: vec!["password"],
        disconnect_after_none: Some((Duration::from_millis(300), 2, "login grace time".into())),
        ..TestServerConfig::default()
    })
    .await;
    let h = harness(vec![Answer::Hold]);
    let err = connect(params(&server, SshLogon::AskForPassword), &h, None)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Connection(m) if m == "The server closed the connection while waiting for your answer"),
        "{err}"
    );
    assert_eq!(h.ui.prompts().len(), 1);
}

#[tokio::test]
async fn loopback_too_many_connections_disconnect() {
    for (code, limit) in [(12, true), (11, false)] {
        let server = TestServer::start(TestServerConfig {
            methods: vec!["password"],
            disconnect_after_none: Some((Duration::ZERO, code, "\u{1b}[1mtoo many".into())),
            ..TestServerConfig::default()
        })
        .await;
        let h = harness(vec![Answer::Hold, Answer::Hold, Answer::Hold]);
        let mut p = params(&server, SshLogon::Normal);
        p.password = Some(SecretString::from("wrong"));
        let err = connect(p, &h, None).await.unwrap_err();
        if limit {
            assert!(
                matches!(&err, Error::ConnectionLimit(m) if m == "too many"),
                "{err}"
            );
        } else {
            assert!(matches!(err, Error::Connection(_)), "{err}");
        }
    }
}

// ---------------------------------------------------------------- AC13 (in-process)

#[tokio::test]
async fn loopback_no_common_cipher() {
    let server = TestServer::start(TestServerConfig {
        preferred: Some(legacy_preferences()),
        ..password_server("secret")
    })
    .await;
    let h = harness(vec![]);
    let err = connect(params(&server, SshLogon::AskForPassword), &h, None)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Connection(m) if m.starts_with("No common cipher: server offers aes128-cbc")),
        "{err}"
    );
}

#[tokio::test]
async fn loopback_keepalive_detects_dead_link_end_cause() {
    // A closed connection reports why it ended.
    let server = TestServer::start(TestServerConfig {
        disconnect_after_none: None,
        ..password_server("secret")
    })
    .await;
    let h = harness(vec![]);
    let mut p = params(&server, SshLogon::Normal);
    p.password = Some(SecretString::from("secret"));
    p.keepalive = Some(Duration::from_secs(30));
    let conn = connect(p, &h, None).await.unwrap();
    assert!(conn.end_cause().is_none());
    server.shutdown().await;
    let start = Instant::now();
    while conn.is_open() && start.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!conn.is_open());
    assert_eq!(
        conn.end_cause().as_deref(),
        Some("Server closed the connection: server shutting down")
    );
}
