//! Connection and authentication against the in-process server
//! ([`super::test_server`]); prompts are answered through the event bus.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use courier_ftp_core::{
    Error, Result,
    backend::SecurityInfo,
    events::{self, CoreEvent, EventReceiver, LogKind, PromptKind, PromptResponse, SessionId},
    model::{LocalPath, LogonType},
    net::HostPort,
    settings::Settings,
};
use pretty_assertions::assert_eq;
use russh::{
    MethodKind,
    keys::{PrivateKey, PublicKey},
};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

use super::{
    test_server::{self, KbdRound, Policy},
    *,
};

const PASSWORD: &str = "CANARY-pw-s3cret";
const PASSPHRASE: &str = "fixture";

// ---------------------------------------------------------------- the fake UI

/// How the fake UI answers the next prompt.
#[derive(Debug, Clone)]
enum Reply {
    Secret(&'static str),
    Answers(Vec<&'static str>),
    /// Drop the request (the user closed the dialog).
    Dismiss,
    /// Never answer.
    Hang,
}

/// What the fake UI saw.
#[derive(Debug, Default)]
struct Seen {
    prompts: Vec<PromptKind>,
    logs: Vec<(LogKind, String)>,
}

#[derive(Clone)]
struct Ui {
    seen: Arc<Mutex<Seen>>,
}

impl Ui {
    fn prompts(&self) -> Vec<PromptKind> {
        self.seen.lock().unwrap().prompts.clone()
    }

    fn logs(&self) -> Vec<(LogKind, String)> {
        self.seen.lock().unwrap().logs.clone()
    }

    /// Wait (up to 5 s) until a log line containing `want` arrived: events
    /// reach the UI task after `connect` returns.
    async fn wait_log(&self, want: &str) {
        for _ in 0..500 {
            if self.log_text().contains(want) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no log line {want:?} in\n{}", self.log_text());
    }

    fn log_text(&self) -> String {
        self.logs()
            .iter()
            .map(|(_, t)| t.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn spawn_ui(mut rx: EventReceiver, replies: Vec<Reply>) -> Ui {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let ui = Ui {
        seen: Arc::clone(&seen),
    };
    let mut replies: VecDeque<Reply> = replies.into();
    tokio::spawn(async move {
        let mut hung = Vec::new();
        while let Some(event) = rx.recv().await {
            match event {
                CoreEvent::Log(m) => seen.lock().unwrap().logs.push((m.kind, m.text)),
                CoreEvent::Prompt(req) => {
                    seen.lock().unwrap().prompts.push(req.kind.clone());
                    let response = match replies.pop_front() {
                        Some(Reply::Secret(s)) => {
                            PromptResponse::Secret(SecretString::from(s.to_owned()))
                        }
                        Some(Reply::Answers(a)) => PromptResponse::Answers(
                            a.into_iter()
                                .map(|s| SecretString::from(s.to_owned()))
                                .collect(),
                        ),
                        Some(Reply::Hang) => {
                            hung.push(req);
                            continue;
                        }
                        Some(Reply::Dismiss) | None => continue,
                    };
                    let _ = req.reply.send(response);
                }
                _ => {}
            }
        }
    });
    ui
}

struct Setup {
    opts: SshOptions,
    ctx: SshContext,
    ui: Ui,
}

fn setup(addr: std::net::SocketAddr, logon: LogonType, replies: Vec<Reply>) -> Setup {
    let (tx, rx) = events::channel(4);
    let ui = spawn_ui(rx, replies);
    let mut settings = Settings::default();
    settings.connection.timeout_secs = 5;
    let opts = SshOptions::new(HostPort::from(addr), logon, &settings);
    let ctx = SshContext::new(
        SessionId::next(),
        tx,
        Arc::new(AcceptAnyHostKey::insecure_for_tests()),
    );
    Setup { opts, ctx, ui }
}

async fn run(s: &Setup) -> Result<SshSession> {
    connect(&s.opts, &s.ctx, &CancellationToken::new()).await
}

fn normal(password: &str) -> LogonType {
    LogonType::Normal {
        user: "bob".into(),
        password: SecretString::from(password.to_owned()),
    }
}

fn keys_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/keys")
}

fn public(name: &str) -> PublicKey {
    let text = std::fs::read_to_string(keys_dir().join(name)).unwrap();
    PublicKey::from_openssh(text.trim()).unwrap()
}

fn key_file(name: &str) -> LogonType {
    LogonType::KeyFile {
        user: "bob".into(),
        path: LocalPath::new(keys_dir().join(name)),
    }
}

fn methods(m: &[MethodKind]) -> Vec<MethodKind> {
    m.to_vec()
}

fn assert_no_secrets(ui: &Ui) {
    let text = ui.log_text();
    for secret in [PASSWORD, PASSPHRASE, "123456", "654321"] {
        assert!(!text.contains(secret), "secret {secret:?} logged:\n{text}");
    }
}

// ---------------------------------------------------------------- password

#[tokio::test]
async fn password_logs_in_and_reports_the_session() {
    let (addr, seen) = test_server::start(Policy {
        password: Some(PASSWORD),
        banner: Some("Welcome to\r\nthe \u{1b}[31mtest\u{1b}[0m server\r\n"),
        ..Policy::default()
    })
    .await;
    let s = setup(addr, normal(PASSWORD), vec![]);
    let session = run(&s).await.unwrap();
    assert_eq!(session.user(), "bob");
    assert!(session.server_version().starts_with("SSH-2.0-"));
    let SecurityInfo::Ssh {
        kex,
        cipher,
        host_key,
        ..
    } = session.security_info()
    else {
        panic!("not ssh");
    };
    assert!(!kex.is_empty() && !cipher.is_empty());
    assert_eq!(host_key, hostkey::describe_key(&test_server::host_key()));
    session.disconnect().await.unwrap();

    assert_eq!(*seen.lock().unwrap(), vec!["none", "password"]);
    assert!(s.ui.prompts().is_empty());
    s.ui.wait_log("Connected to 127.0.0.1:").await;
    let logs = s.ui.log_text();
    for want in [
        "Using username \"bob\".",
        "Server version: SSH-2.0-",
        "Authenticating with password",
        "Welcome to",
        "the test server",
        "Connected to 127.0.0.1:",
    ] {
        assert!(logs.contains(want), "missing {want:?} in\n{logs}");
    }
    assert!(
        s.ui.logs()
            .iter()
            .any(|(k, t)| *k == LogKind::Debug(3) && t.starts_with("Negotiated: kex ")),
        "{logs}"
    );
    assert_no_secrets(&s.ui);
}

#[tokio::test]
async fn a_rejected_stored_password_fails_listing_the_accepted_methods() {
    let (addr, _) = test_server::start(Policy {
        password: Some("other"),
        ..Policy::default()
    })
    .await;
    let s = setup(addr, normal(PASSWORD), vec![]);
    let err = run(&s).await.unwrap_err();
    let Error::Auth(msg) = &err else {
        panic!("{err:?}");
    };
    assert!(msg.contains("server rejected password"), "{msg}");
    assert!(
        msg.contains("publickey, password, keyboard-interactive"),
        "{msg}"
    );
    // Normal never asks.
    assert!(s.ui.prompts().is_empty());
    s.ui.wait_log("authentication failed").await;
    assert_no_secrets(&s.ui);
}

#[tokio::test]
async fn normal_answers_a_keyboard_interactive_password_prompt_itself() {
    let (addr, seen) = test_server::start(Policy {
        methods: methods(&[MethodKind::KeyboardInteractive]),
        kbd: vec![KbdRound {
            instructions: "",
            prompts: vec![("Password: ", false)],
            expect: vec![PASSWORD],
        }],
        ..Policy::default()
    })
    .await;
    let s = setup(addr, normal(PASSWORD), vec![]);
    run(&s).await.unwrap();
    assert!(s.ui.prompts().is_empty());
    assert_eq!(*seen.lock().unwrap(), vec!["none", "kbd", "kbd-answer"]);
}

#[tokio::test]
async fn normal_asks_other_keyboard_interactive_prompts() {
    let (addr, _) = test_server::start(Policy {
        methods: methods(&[MethodKind::KeyboardInteractive]),
        kbd: vec![
            KbdRound {
                instructions: "",
                prompts: vec![("Password: ", false)],
                expect: vec![PASSWORD],
            },
            KbdRound {
                instructions: "Second factor",
                prompts: vec![("Verification code: ", true)],
                expect: vec!["123456"],
            },
        ],
        ..Policy::default()
    })
    .await;
    let s = setup(addr, normal(PASSWORD), vec![Reply::Answers(vec!["123456"])]);
    run(&s).await.unwrap();
    let prompts = s.ui.prompts();
    assert_eq!(prompts.len(), 1);
    let PromptKind::KeyboardInteractive {
        instructions,
        prompts,
        ..
    } = &prompts[0]
    else {
        panic!("{prompts:?}");
    };
    assert_eq!(instructions, "Second factor");
    assert_eq!(prompts, &vec![("Verification code:".to_owned(), true)]);
    assert_no_secrets(&s.ui);
}

#[tokio::test]
async fn ask_for_password_prompts_retries_and_remembers() {
    let (addr, seen) = test_server::start(Policy {
        password: Some(PASSWORD),
        ..Policy::default()
    })
    .await;
    let logon = LogonType::AskForPassword { user: "bob".into() };
    let mut s = setup(
        addr,
        logon,
        vec![Reply::Secret("wrong"), Reply::Secret(PASSWORD)],
    );
    let cache = CredentialCache::new();
    s.ctx.credentials = Some(cache.clone());
    run(&s).await.unwrap();
    let prompts = s.ui.prompts();
    assert_eq!(prompts.len(), 2);
    assert!(
        matches!(&prompts[0], PromptKind::Password { for_ } if for_.starts_with("bob@127.0.0.1:"))
    );
    assert_eq!(*seen.lock().unwrap(), vec!["none", "password", "password"]);
    s.ui.wait_log("Password rejected").await;

    // Remembered for the session: no prompt on reconnect.
    run(&s).await.unwrap();
    assert_eq!(s.ui.prompts().len(), 2);
    assert_no_secrets(&s.ui);
}

#[tokio::test]
async fn ask_for_password_gives_up_after_three_tries() {
    let (addr, seen) = test_server::start(Policy {
        password: Some(PASSWORD),
        ..Policy::default()
    })
    .await;
    let logon = LogonType::AskForPassword { user: "bob".into() };
    let s = setup(
        addr,
        logon,
        vec![Reply::Secret("a"), Reply::Secret("b"), Reply::Secret("c")],
    );
    let err = run(&s).await.unwrap_err();
    assert!(
        matches!(&err, Error::Auth(m) if m.contains("server rejected password")),
        "{err:?}"
    );
    assert_eq!(s.ui.prompts().len(), PASSWORD_TRIES);
    assert_eq!(seen.lock().unwrap().len(), 1 + PASSWORD_TRIES);
}

// ---------------------------------------------------------------- keyboard-interactive

#[tokio::test]
async fn interactive_answers_multiple_prompts_and_two_rounds() {
    let (addr, seen) = test_server::start(Policy {
        methods: methods(&[MethodKind::KeyboardInteractive]),
        kbd: vec![
            KbdRound {
                instructions: "Log in",
                prompts: vec![("Password: ", false), ("Favourite colour: ", true)],
                expect: vec![PASSWORD, "blue"],
            },
            KbdRound {
                instructions: "",
                prompts: vec![("OTP: ", false)],
                expect: vec!["654321"],
            },
        ],
        ..Policy::default()
    })
    .await;
    let logon = LogonType::Interactive { user: "bob".into() };
    let s = setup(
        addr,
        logon,
        vec![
            Reply::Answers(vec![PASSWORD, "blue"]),
            Reply::Answers(vec!["654321"]),
        ],
    );
    run(&s).await.unwrap();
    let prompts = s.ui.prompts();
    assert_eq!(prompts.len(), 2);
    let PromptKind::KeyboardInteractive { prompts: first, .. } = &prompts[0] else {
        panic!()
    };
    assert_eq!(
        first,
        &vec![
            ("Password:".to_owned(), false),
            ("Favourite colour:".to_owned(), true)
        ]
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec!["none", "kbd", "kbd-answer", "kbd-answer"]
    );
    assert_no_secrets(&s.ui);
}

#[tokio::test]
async fn interactive_falls_back_to_a_password_prompt() {
    let (addr, _) = test_server::start(Policy {
        methods: methods(&[MethodKind::Password]),
        password: Some(PASSWORD),
        ..Policy::default()
    })
    .await;
    let logon = LogonType::Interactive { user: "bob".into() };
    let s = setup(addr, logon, vec![Reply::Secret(PASSWORD)]);
    run(&s).await.unwrap();
    assert!(matches!(s.ui.prompts()[..], [PromptKind::Password { .. }]));
}

#[tokio::test]
async fn two_factor_password_then_keyboard_interactive() {
    let (addr, seen) = test_server::start(Policy {
        methods: methods(&[MethodKind::Password]),
        password: Some(PASSWORD),
        two_factor: true,
        kbd: vec![KbdRound {
            instructions: "",
            prompts: vec![("Verification code: ", false)],
            expect: vec!["123456"],
        }],
        ..Policy::default()
    })
    .await;
    let s = setup(addr, normal(PASSWORD), vec![Reply::Answers(vec!["123456"])]);
    run(&s).await.unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        vec!["none", "password", "kbd", "kbd-answer"]
    );
    s.ui.wait_log("Partial success").await;
}

// ---------------------------------------------------------------- key files

#[tokio::test]
async fn key_files_of_every_type_log_in() {
    for (file, public_file) in [
        ("ed25519", "ed25519.pub"),
        ("rsa", "rsa.pub"),
        ("ecdsa", "ecdsa.pub"),
        ("rsa_pem", "rsa_pem.pub"),
        ("ecdsa_pem", "ecdsa_pem.pub"),
        ("rsa_pkcs8", "rsa_pkcs8.pub"),
    ] {
        let (addr, seen) = test_server::start(Policy {
            authorized: vec![public(public_file)],
            ..Policy::default()
        })
        .await;
        let s = setup(addr, key_file(file), vec![]);
        run(&s).await.unwrap_or_else(|e| panic!("{file}: {e}"));
        assert!(s.ui.prompts().is_empty(), "{file}");
        assert!(
            seen.lock()
                .unwrap()
                .iter()
                .any(|r| r.starts_with("publickey:")),
            "{file}"
        );
        s.ui.wait_log("Authenticating with public key").await;
    }
}

#[tokio::test]
async fn encrypted_keys_ask_for_the_passphrase() {
    for (file, key) in [
        ("ed25519_enc", public("ed25519_enc.pub")),
        (
            "ppk/v3_ed25519_enc.ppk",
            ppk_public("v3_ed25519_enc.ppk").await,
        ),
        (
            "ppk/v2_rsa2048_enc.ppk",
            ppk_public("v2_rsa2048_enc.ppk").await,
        ),
    ] {
        let (addr, _) = test_server::start(Policy {
            authorized: vec![key],
            ..Policy::default()
        })
        .await;
        let mut s = setup(addr, key_file(file), vec![Reply::Secret(PASSPHRASE)]);
        let cache = CredentialCache::new();
        s.ctx.credentials = Some(cache);
        run(&s).await.unwrap_or_else(|e| panic!("{file}: {e}"));
        let prompts = s.ui.prompts();
        assert!(
            matches!(&prompts[..], [PromptKind::KeyPassphrase { path }] if path.as_path().ends_with(file)),
            "{file}: {prompts:?}"
        );
        // The passphrase is remembered for the session.
        run(&s).await.unwrap();
        assert_eq!(s.ui.prompts().len(), 1, "{file}");
        assert_no_secrets(&s.ui);
    }
}

async fn ppk_public(name: &str) -> PublicKey {
    let text = std::fs::read_to_string(keys_dir().join("ppk").join(name)).unwrap();
    let file = KeyFile::from_text(name, SecretString::from(text)).unwrap();
    let pass = SecretString::from(PASSPHRASE.to_owned());
    file.decode(Some(&pass)).await.unwrap().public_key().clone()
}

#[tokio::test]
async fn a_wrong_passphrase_is_asked_again_up_to_three_times() {
    let (addr, seen) = test_server::start(Policy {
        authorized: vec![public("ed25519_enc.pub")],
        ..Policy::default()
    })
    .await;
    let s = setup(
        addr,
        key_file("ed25519_enc"),
        vec![Reply::Secret("x"), Reply::Secret("y"), Reply::Secret("z")],
    );
    let err = run(&s).await.unwrap_err();
    assert!(
        matches!(&err, Error::Auth(m) if m.contains("wrong passphrase")),
        "{err:?}"
    );
    assert_eq!(s.ui.prompts().len(), PASSPHRASE_TRIES);
    // Nothing was offered to the server.
    assert_eq!(*seen.lock().unwrap(), vec!["none"]);
    assert_eq!(
        s.ui.logs()
            .iter()
            .filter(|(_, t)| t.starts_with("Wrong passphrase"))
            .count(),
        PASSPHRASE_TRIES - 1
    );

    // Wrong, then right.
    let s = setup(
        addr,
        key_file("ed25519_enc"),
        vec![Reply::Secret("x"), Reply::Secret(PASSPHRASE)],
    );
    run(&s).await.unwrap();
    assert_eq!(s.ui.prompts().len(), 2);
}

#[tokio::test]
async fn a_rejected_key_fails_with_the_accepted_methods() {
    let (addr, _) = test_server::start(Policy {
        methods: methods(&[MethodKind::PublicKey, MethodKind::Password]),
        ..Policy::default()
    })
    .await;
    let s = setup(addr, key_file("ed25519"), vec![]);
    let err = run(&s).await.unwrap_err();
    assert!(
        matches!(&err, Error::Auth(m) if m.contains("server rejected the key") && m.contains("publickey, password")),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_missing_key_file_is_an_auth_error() {
    let (addr, _) = test_server::start(Policy::default()).await;
    let s = setup(addr, key_file("does-not-exist"), vec![]);
    let err = run(&s).await.unwrap_err();
    assert!(
        matches!(&err, Error::Auth(m) if m.contains("cannot read key file")),
        "{err:?}"
    );
}

#[tokio::test]
async fn key_text_overrides_the_logon_key() {
    let (addr, _) = test_server::start(Policy {
        authorized: vec![public("ecdsa.pub")],
        ..Policy::default()
    })
    .await;
    let mut s = setup(addr, normal("unused"), vec![]);
    s.opts.key = Some(KeyInput::Text {
        label: "vault key".into(),
        text: SecretString::from(std::fs::read_to_string(keys_dir().join("ecdsa")).unwrap()),
    });
    run(&s).await.unwrap();
    s.ui.wait_log("public key \"vault key\"").await;
}

// ---------------------------------------------------------------- agent

fn test_key(seed: u8) -> PrivateKey {
    PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(
        &[seed; 32],
    ))
}

fn offered(seen: &test_server::Seen) -> usize {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|r| r.starts_with("publickey:"))
        .count()
}

#[tokio::test]
async fn agent_tries_each_identity() {
    // The agent's identity order is not fixed: the right key is offered first
    // or second.
    let wanted = test_key(2);
    let (addr, seen) = test_server::start(Policy {
        authorized: vec![wanted.public_key().clone()],
        ..Policy::default()
    })
    .await;
    let agent = agent::InProcessAgent::start(&[test_key(1), wanted])
        .await
        .unwrap();
    let mut s = setup(addr, LogonType::Agent { user: "bob".into() }, vec![]);
    s.ctx.agent = Arc::new(agent);
    run(&s).await.unwrap();
    let n = offered(&seen);
    assert!((1..=2).contains(&n), "{n}");
    s.ui.wait_log("Connected to").await;
    assert_eq!(
        s.ui.logs()
            .iter()
            .filter(|(_, t)| t.starts_with("Authenticating with agent key"))
            .count(),
        n
    );

    // No key fits: every identity is offered, then a clean failure.
    let (addr, seen) = test_server::start(Policy::default()).await;
    let mut s = setup(addr, LogonType::Agent { user: "bob".into() }, vec![]);
    s.ctx.agent = Arc::new(
        agent::InProcessAgent::start(&[test_key(1), test_key(3)])
            .await
            .unwrap(),
    );
    let err = run(&s).await.unwrap_err();
    assert!(
        matches!(&err, Error::Auth(m) if m.contains("server rejected every agent key")),
        "{err:?}"
    );
    assert_eq!(offered(&seen), 2);
}

#[tokio::test]
async fn an_empty_or_missing_agent_fails_cleanly() {
    let (addr, _) = test_server::start(Policy::default()).await;
    let mut s = setup(addr, LogonType::Agent { user: "bob".into() }, vec![]);
    s.ctx.agent = Arc::new(agent::InProcessAgent::start(&[]).await.unwrap());
    let err = run(&s).await.unwrap_err();
    assert!(
        matches!(&err, Error::Auth(m) if m.contains("no keys")),
        "{err:?}"
    );

    #[derive(Debug)]
    struct NoAgent;
    #[async_trait]
    impl AgentConnector for NoAgent {
        async fn connect(&self) -> std::result::Result<agent::Agent, String> {
            Err("no SSH agent is running".into())
        }
    }
    s.ctx.agent = Arc::new(NoAgent);
    let err = run(&s).await.unwrap_err();
    assert!(
        matches!(&err, Error::Auth(m) if m.contains("no SSH agent")),
        "{err:?}"
    );
}

#[tokio::test]
async fn try_agent_first_offers_agent_keys_before_the_password() {
    let (addr, seen) = test_server::start(Policy {
        password: Some(PASSWORD),
        ..Policy::default()
    })
    .await;
    let mut s = setup(addr, normal(PASSWORD), vec![]);
    s.ctx.agent = Arc::new(agent::InProcessAgent::start(&[test_key(5)]).await.unwrap());
    run(&s).await.unwrap();
    assert_eq!(*seen.lock().unwrap(), vec!["none", "password"]);

    s.opts.try_agent_first = true;
    seen.lock().unwrap().clear();
    run(&s).await.unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        vec!["none", "publickey:ssh-ed25519", "password"]
    );
}

// ---------------------------------------------------------------- host key, errors

#[derive(Debug)]
struct Verifier(fn() -> Result<bool>);

#[async_trait]
impl HostKeyVerifier for Verifier {
    async fn verify(&self, ctx: HostKeyContext<'_>, key: &PublicKey) -> Result<bool> {
        assert_eq!(key.key_data(), test_server::host_key().key_data());
        assert_eq!(ctx.host.host, "127.0.0.1");
        (self.0)()
    }
}

#[tokio::test]
async fn the_host_key_verifier_decides() {
    let (addr, seen) = test_server::start(Policy {
        password: Some(PASSWORD),
        ..Policy::default()
    })
    .await;
    let mut s = setup(addr, normal(PASSWORD), vec![]);
    s.ctx.verifier = Arc::new(Verifier(|| Ok(false)));
    let err = run(&s).await.unwrap_err();
    assert!(
        matches!(&err, Error::HostKey(m) if m.contains("rejected")),
        "{err:?}"
    );

    s.ctx.verifier = Arc::new(Verifier(|| Err(Error::Cancelled)));
    assert!(matches!(run(&s).await.unwrap_err(), Error::Cancelled));
    // Authentication never started.
    assert!(seen.lock().unwrap().is_empty());

    s.ctx.verifier = Arc::new(Verifier(|| Ok(true)));
    run(&s).await.unwrap();
}

#[tokio::test]
async fn ftp_only_logon_types_are_invalid() {
    let (addr, _) = test_server::start(Policy::default()).await;
    let s = setup(addr, LogonType::Anonymous, vec![]);
    assert!(matches!(run(&s).await.unwrap_err(), Error::InvalidInput(_)));
}

#[tokio::test]
async fn a_dismissed_prompt_cancels() {
    let (addr, _) = test_server::start(Policy {
        password: Some(PASSWORD),
        ..Policy::default()
    })
    .await;
    let s = setup(
        addr,
        LogonType::AskForPassword { user: "bob".into() },
        vec![Reply::Dismiss],
    );
    assert!(matches!(run(&s).await.unwrap_err(), Error::Cancelled));
}

#[tokio::test]
async fn cancelling_aborts_a_pending_prompt() {
    let (addr, _) = test_server::start(Policy {
        password: Some(PASSWORD),
        ..Policy::default()
    })
    .await;
    let s = setup(
        addr,
        LogonType::AskForPassword { user: "bob".into() },
        vec![Reply::Hang],
    );
    let cancel = CancellationToken::new();
    let task = {
        let (opts, ctx, cancel) = (s.opts.clone(), s.ctx.clone(), cancel.clone());
        tokio::spawn(async move { connect(&opts, &ctx, &cancel).await })
    };
    // Wait until the prompt is up, then cancel.
    for _ in 0..500 {
        if !s.ui.prompts().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(s.ui.prompts().len(), 1);
    cancel.cancel();
    let err = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(err, Error::Cancelled), "{err:?}");
}

#[tokio::test]
async fn a_silent_server_times_out() {
    // Accepts TCP, never sends an SSH banner.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let mut s = setup(addr, normal(PASSWORD), vec![]);
    s.opts.timeout = Duration::from_millis(300);
    let started = std::time::Instant::now();
    let err = run(&s).await.unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn a_closed_port_is_a_connection_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let s = setup(addr, normal(PASSWORD), vec![]);
    assert!(matches!(run(&s).await.unwrap_err(), Error::Connection(_)));
}

#[test]
fn client_config_follows_the_settings() {
    let mut settings = Settings::default();
    settings.connection.timeout_secs = 20;
    settings.connection.keepalive_interval_secs = 30;
    let opts = SshOptions::new(HostPort::new("h", 22), normal("x"), &settings);
    let config = opts.client_config();
    assert_eq!(config.keepalive_interval, Some(Duration::from_secs(30)));
    assert_eq!(config.keepalive_max, KEEPALIVE_MAX);
    assert_eq!(config.inactivity_timeout, Some(Duration::from_secs(120)));
    settings.connection.keepalive = false;
    let opts = SshOptions::new(HostPort::new("h", 22), normal("x"), &settings);
    assert_eq!(opts.client_config().inactivity_timeout, None);
    assert!(!format!("{opts:?}").contains("CANARY"));
}

// ---------------------------------------------------------------- canaries

/// `target/tmp`, derived from this test binary's path
/// (`target/<profile>/deps/<bin>`), where `scripts/canary-scan.sh` looks.
fn target_tmp() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.ancestors().nth(3).unwrap().join("tmp")
}

/// T91 §5: a password and a keyboard-interactive code planted as canaries
/// never reach the trace-level log of a full SSH login, nor the session log.
/// The log is left in `target/tmp/canary-ssh/` for `scripts/canary-scan.sh`
/// (CI job `canary`), and also checked here.
#[tokio::test]
async fn canary_secrets_stay_out_of_trace_logs() {
    const SSH_PW: &str = "CANARY-PW-ssh-4e1d";
    const CODE: &str = "CANARY-TOTP-8c27";

    let dir = target_tmp().join("canary-ssh");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("courier-ftp.log");
    let file = std::fs::File::create(&log_path).unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_target(false)
        .with_file(true)
        .with_line_number(true)
        .with_writer(Mutex::new(file))
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    // russh logs through `log`; forward it, as the binary's subscriber does.
    // Records go to each thread's own subscriber, so other tests stay out.
    let _ = tracing_log::LogTracer::builder()
        .with_max_level(tracing_log::log::LevelFilter::Trace)
        .init();

    let (addr, seen) = test_server::start(Policy {
        methods: methods(&[MethodKind::Password]),
        password: Some(SSH_PW),
        two_factor: true,
        kbd: vec![KbdRound {
            instructions: "",
            prompts: vec![("Verification code: ", false)],
            expect: vec![CODE],
        }],
        ..Policy::default()
    })
    .await;
    let s = setup(addr, normal(SSH_PW), vec![Reply::Answers(vec![CODE])]);
    let session = run(&s).await.unwrap();
    session.disconnect().await.unwrap();
    s.ui.wait_log("Partial success").await;
    drop(guard);
    assert_eq!(
        *seen.lock().unwrap(),
        vec!["none", "password", "kbd", "kbd-answer"]
    );

    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(log.contains("TRACE") || log.contains("DEBUG"), "{log}");
    let session_log = s.ui.log_text();
    for canary in [SSH_PW, CODE, "CANARY"] {
        assert!(!log.contains(canary), "{canary} in the trace log");
        assert!(!session_log.contains(canary), "{canary} in the session log");
    }
}
