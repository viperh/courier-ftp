//! `ControlConnection` and login state machine against the scripted [`FakeServer`]
//! (paused time).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    io,
    sync::{Arc, Mutex},
};

use courier_ftp_core::{
    events::{
        CoreEvent, EventReceiver, LogKind, LogMessage, PasswordPrompt, PasswordPurpose, PromptId,
        PromptKind, PromptResponse, SecretCacheKey, SessionId, channel,
    },
    model::{LogonType, Protocol},
    net::{ProxyConfig, Purpose},
    settings::DebugLevel,
};
use tokio::task::JoinHandle;

use super::*;
use crate::{
    login::{LoginPromptInfo, LoginScript, LoginStep, LoginTarget, StepKind, StepValue},
    testing::{FakeServer, Step},
};

// ---- harness ------------------------------------------------------------------------

#[derive(Default)]
struct Seen {
    logs: Vec<LogMessage>,
    prompts: Vec<(PromptId, PasswordPrompt)>,
    accepted: Vec<PromptId>,
}

/// Plays the UI: answers password prompts (`None` → cancel) and records events.
struct Ui {
    log: SessionLog,
    seen: Arc<Mutex<Seen>>,
    _task: JoinHandle<()>,
}

impl Ui {
    fn new(answer: Option<&'static str>) -> Self {
        let (events, rx) = channel(DebugLevel::Debug);
        let seen = Arc::new(Mutex::new(Seen::default()));
        let task = tokio::spawn(drive(rx, answer, Arc::clone(&seen)));
        Self {
            log: SessionLog {
                events,
                session: SessionId::next(),
            },
            seen,
            _task: task,
        }
    }

    async fn settle(&self) {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    async fn lines(&self, kind: LogKind) -> Vec<String> {
        self.settle().await;
        let seen = self.seen.lock().unwrap();
        seen.logs
            .iter()
            .filter(|m| m.kind == kind)
            .map(|m| m.text.clone())
            .collect()
    }

    async fn prompts(&self) -> Vec<(PromptId, PasswordPrompt)> {
        self.settle().await;
        self.seen.lock().unwrap().prompts.clone()
    }

    async fn accepted(&self) -> Vec<PromptId> {
        self.settle().await;
        self.seen.lock().unwrap().accepted.clone()
    }
}

async fn drive(mut rx: EventReceiver, answer: Option<&'static str>, seen: Arc<Mutex<Seen>>) {
    while let Some(event) = rx.recv().await {
        match event {
            CoreEvent::Log(m) => seen.lock().unwrap().logs.push(m),
            CoreEvent::Prompt(req) => {
                if let PromptKind::Password(p) = &req.kind {
                    seen.lock().unwrap().prompts.push((req.id, p.clone()));
                }
                let response = match answer {
                    Some(v) => PromptResponse::Secret {
                        value: SecretString::from(v),
                        remember_session: false,
                        save_in_vault: false,
                    },
                    None => PromptResponse::Cancel,
                };
                req.respond(response);
            }
            CoreEvent::CredentialAccepted { prompt_id, .. } => {
                seen.lock().unwrap().accepted.push(prompt_id);
            }
            _ => {}
        }
    }
}

fn params(log: &SessionLog, charset: Charset) -> ControlParams {
    ControlParams {
        target: HostPort::new("fake.test", 21),
        server_name: "fake.test".into(),
        net: NetOpts {
            timeout: Duration::from_secs(20),
            prefer_ipv6: false,
            allow_ipv6: true,
            purpose: Purpose::Control,
            socket_buffer: None,
            proxy: ProxyConfig::Direct,
        },
        charset,
        timeout: Duration::from_secs(20),
        keepalive_command: KeepaliveCommand::Noop,
        log: log.clone(),
    }
}

fn token() -> CancellationToken {
    CancellationToken::new()
}

async fn open_with(
    script: Vec<Step>,
    ui: &Ui,
    charset: Charset,
) -> (ControlConnection, FakeServer) {
    let (server, io) = FakeServer::duplex(script);
    let (conn, greeting) = ControlConnection::from_stream(io, params(&ui.log, charset), &token())
        .await
        .unwrap();
    assert_eq!(greeting.code(), 220);
    (conn, server)
}

async fn open(script: Vec<Step>, ui: &Ui) -> (ControlConnection, FakeServer) {
    open_with(script, ui, Charset::Auto).await
}

/// Greeting + `script`.
fn with_greeting(script: Vec<Step>) -> Vec<Step> {
    let mut s = vec![Step::Reply("220 Welcome")];
    s.extend(script);
    s
}

fn prompt_info() -> LoginPromptInfo {
    LoginPromptInfo {
        target: "alice@fake.test:21".into(),
        cache_key: SecretCacheKey::Password {
            protocol: Protocol::Ftp,
            host: "fake.test".into(),
            port: 21,
            user: "alice".into(),
        },
        can_save: true,
    }
}

fn script_for(logon: &LogonType) -> LoginScript {
    LoginScript::for_logon(Some("alice"), logon, prompt_info()).unwrap()
}

fn normal(pw: &str) -> LogonType {
    LogonType::Normal {
        password: Some(SecretString::from(pw)),
    }
}

async fn finish(conn: ControlConnection, server: FakeServer) {
    drop(conn);
    server.finish().await;
}

// ---- login (AC4, AC5) -------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn login_normal_331_230() {
    let ui = Ui::new(None);
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice"),
            Step::Reply("331 Password required"),
            Step::ExpectSecret {
                verb: "PASS",
                value: "s3cret",
            },
            Step::Reply("230 Logged in"),
        ]),
        &ui,
    )
    .await;
    assert_eq!(conn.state(), ControlState::Greeting);
    conn.login(script_for(&normal("s3cret")), &token())
        .await
        .unwrap();
    assert_eq!(conn.state(), ControlState::Ready);
    assert!(ui.prompts().await.is_empty());
    let cmds = ui.lines(LogKind::Command).await;
    assert_eq!(cmds, ["USER alice", "PASS ****"]);
    assert!(
        ui.lines(LogKind::Status)
            .await
            .contains(&"Logged in".to_owned())
    );
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn login_anonymous_sends_default_password() {
    let ui = Ui::new(None);
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER anonymous"),
            Step::Reply("331 Please specify the password."),
            Step::Expect("PASS anonymous@example.com"),
            Step::Reply("230 Login successful."),
        ]),
        &ui,
    )
    .await;
    let script = LoginScript::for_logon(None, &LogonType::Anonymous, prompt_info()).unwrap();
    conn.login(script, &token()).await.unwrap();
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn login_230_after_user_skips_pass() {
    let ui = Ui::new(Some("never-asked"));
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice"),
            Step::Reply("230 No password needed"),
        ]),
        &ui,
    )
    .await;
    conn.login(script_for(&LogonType::AskForPassword), &token())
        .await
        .unwrap();
    assert!(
        ui.prompts().await.is_empty(),
        "no prompt when USER gets 230"
    );
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn login_332_sends_acct() {
    let ui = Ui::new(None);
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice"),
            Step::Reply("331 Password required"),
            Step::ExpectSecret {
                verb: "PASS",
                value: "pw",
            },
            Step::Reply("332 Need account"),
            Step::ExpectSecret {
                verb: "ACCT",
                value: "acc-1",
            },
            Step::Reply("230 Logged in"),
        ]),
        &ui,
    )
    .await;
    let logon = LogonType::Account {
        password: Some(SecretString::from("pw")),
        account: Some(SecretString::from("acc-1")),
    };
    conn.login(script_for(&logon), &token()).await.unwrap();
    assert_eq!(
        ui.lines(LogKind::Command).await,
        ["USER alice", "PASS ****", "ACCT ****"]
    );
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn login_account_not_sent_without_332() {
    let ui = Ui::new(None);
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice"),
            Step::Reply("331 Password required"),
            Step::ExpectPrefix("PASS "),
            Step::Reply("230 Logged in"),
        ]),
        &ui,
    )
    .await;
    let logon = LogonType::Account {
        password: Some(SecretString::from("pw")),
        account: None,
    };
    conn.login(script_for(&logon), &token()).await.unwrap();
    assert!(ui.prompts().await.is_empty());
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn login_332_without_account_prompts_for_it() {
    let ui = Ui::new(Some("typed-acct"));
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice"),
            Step::Reply("331 Password required"),
            Step::ExpectPrefix("PASS "),
            Step::Reply("332 Need account"),
            Step::ExpectSecret {
                verb: "ACCT",
                value: "typed-acct",
            },
            Step::Reply("202 Superfluous"),
        ]),
        &ui,
    )
    .await;
    conn.login(script_for(&normal("pw")), &token())
        .await
        .unwrap();
    let prompts = ui.prompts().await;
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].1.purpose, PasswordPurpose::Account);
    assert_eq!(
        prompts[0].1.cache_key,
        SecretCacheKey::Account {
            host: "fake.test".into(),
            port: 21,
            user: "alice".into()
        }
    );
    assert_eq!(conn.take_prompted_account().unwrap().expose(), "typed-acct");
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn login_ask_password_prompts_only_after_331() {
    let ui = Ui::new(Some("typed-pw"));
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice"),
            Step::Delay(Duration::from_secs(1)),
            Step::Reply("331 Password required"),
            Step::ExpectSecret {
                verb: "PASS",
                value: "typed-pw",
            },
            Step::Reply("230 Logged in"),
        ]),
        &ui,
    )
    .await;
    conn.login(script_for(&LogonType::Interactive), &token())
        .await
        .unwrap();
    let prompts = ui.prompts().await;
    assert_eq!(prompts.len(), 1);
    let p = &prompts[0].1;
    assert_eq!(p.purpose, PasswordPurpose::Login);
    assert_eq!(p.target, "alice@fake.test:21");
    assert!(!p.retry && p.attempt == 1 && p.max_attempts == 1 && p.can_save);
    // The prompt came after USER was answered with 331.
    let commands = ui.lines(LogKind::Command).await;
    assert_eq!(commands, ["USER alice", "PASS ****"]);
    assert_eq!(conn.take_prompted_password().unwrap().expose(), "typed-pw");
    assert!(conn.take_prompted_password().is_none());
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn login_normal_without_password_prompts() {
    let ui = Ui::new(Some("typed"));
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice"),
            Step::Reply("331 Password required"),
            Step::ExpectSecret {
                verb: "PASS",
                value: "typed",
            },
            Step::Reply("230 Logged in"),
        ]),
        &ui,
    )
    .await;
    conn.login(script_for(&LogonType::Normal { password: None }), &token())
        .await
        .unwrap();
    assert_eq!(ui.prompts().await.len(), 1);
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn login_prompt_cancelled_returns_cancelled() {
    let ui = Ui::new(None);
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice"),
            Step::Reply("331 Password required"),
        ]),
        &ui,
    )
    .await;
    let err = conn
        .login(script_for(&LogonType::AskForPassword), &token())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Cancelled), "{err:?}");
    assert!(ui.accepted().await.is_empty());
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn login_prompt_accepted_emits_credential_accepted() {
    let ui = Ui::new(Some("typed"));
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice"),
            Step::Reply("331 Password required"),
            Step::ExpectPrefix("PASS "),
            Step::Reply("230 Logged in"),
        ]),
        &ui,
    )
    .await;
    conn.login(script_for(&LogonType::AskForPassword), &token())
        .await
        .unwrap();
    let prompts = ui.prompts().await;
    assert_eq!(ui.accepted().await, [prompts[0].0]);
    finish(conn, server).await;

    // A rejected password confirms nothing.
    let ui = Ui::new(Some("wrong"));
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice"),
            Step::Reply("331 Password required"),
            Step::ExpectPrefix("PASS "),
            Step::Reply("530 Login incorrect."),
        ]),
        &ui,
    )
    .await;
    let err = conn
        .login(script_for(&LogonType::AskForPassword), &token())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Auth(ref t) if t == "Login incorrect."),
        "{err:?}"
    );
    assert_eq!(ui.prompts().await.len(), 1);
    assert!(ui.accepted().await.is_empty());
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn login_530_is_auth_error() {
    let ui = Ui::new(None);
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice"),
            Step::Reply("331 Password required"),
            Step::ExpectPrefix("PASS "),
            Step::Reply("530 Login incorrect."),
        ]),
        &ui,
    )
    .await;
    let err = conn
        .login(script_for(&normal("bad")), &token())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Auth(_)), "{err:?}");
    assert!(!err.is_transient());
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn login_430_and_other_codes() {
    for (reply, check) in [
        ("430 Invalid user or password", "auth"),
        ("550 Denied", "auth"),
        ("451 Try later", "protocol"),
        ("421 Timeout.", "connection"),
    ] {
        let ui = Ui::new(None);
        let (mut conn, server) = open(
            with_greeting(vec![Step::Expect("USER alice"), Step::Reply(reply)]),
            &ui,
        )
        .await;
        let err = conn
            .login(script_for(&normal("x")), &token())
            .await
            .unwrap_err();
        assert_eq!(err.code(), check, "{reply}: {err:?}");
        finish(conn, server).await;
    }
}

#[tokio::test(start_paused = true)]
async fn login_530_too_many_connections_is_connection_limit() {
    let ui = Ui::new(None);
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice"),
            Step::Reply("530 Sorry, too many connections from your IP"),
        ]),
        &ui,
    )
    .await;
    let err = conn
        .login(script_for(&normal("x")), &token())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::ConnectionLimit(_)), "{err:?}");
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn login_incomplete_when_last_reply_not_2xx() {
    let ui = Ui::new(None);
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice"),
            Step::Reply("331 Password required"),
            Step::ExpectPrefix("PASS "),
            Step::Reply("350 What now"),
        ]),
        &ui,
    )
    .await;
    let err = conn
        .login(script_for(&normal("x")), &token())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Auth(ref t) if t.starts_with("login incomplete")),
        "{err:?}"
    );
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn login_proxy_steps_map_to_proxy_errors() {
    let ui = Ui::new(None);
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER proxyuser"),
            Step::Reply("331 Password required"),
            Step::ExpectSecret {
                verb: "PASS",
                value: "ppw",
            },
            Step::Reply("230 Proxy login ok"),
            Step::Expect("SITE target.example"),
            Step::Reply("530 Cannot connect"),
        ]),
        &ui,
    )
    .await;
    let script = LoginScript {
        steps: vec![
            LoginStep::new(
                StepKind::User,
                StepValue::Plain("proxyuser".into()),
                LoginTarget::Proxy,
            ),
            LoginStep::new(
                StepKind::Pass,
                StepValue::Secret(SecretString::from("ppw")),
                LoginTarget::Proxy,
            ),
            LoginStep::new(
                StepKind::Other("SITE"),
                StepValue::Plain("target.example".into()),
                LoginTarget::Server,
            ),
        ],
        prompt: None,
    };
    let err = conn.login(script, &token()).await.unwrap_err();
    assert!(
        matches!(err, Error::Proxy(ref t) if t.starts_with("FTP proxy could not connect")),
        "{err:?}"
    );
    finish(conn, server).await;

    let ui = Ui::new(None);
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER proxyuser"),
            Step::Reply("530 Bad proxy user"),
        ]),
        &ui,
    )
    .await;
    let script = LoginScript {
        steps: vec![LoginStep::new(
            StepKind::User,
            StepValue::Plain("proxyuser".into()),
            LoginTarget::Proxy,
        )],
        prompt: None,
    };
    let err = conn.login(script, &token()).await.unwrap_err();
    assert!(
        matches!(err, Error::Proxy(ref t) if t.starts_with("FTP proxy login failed")),
        "{err:?}"
    );
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn login_line_step_sends_verbatim_with_masked_log() {
    let ui = Ui::new(None);
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice@target pw1"),
            Step::Reply("230 ok"),
        ]),
        &ui,
    )
    .await;
    let script = LoginScript {
        steps: vec![LoginStep {
            kind: StepKind::User,
            value: StepValue::Line(SecretString::from("USER alice@target pw1")),
            log_text: "USER alice@target ****".into(),
            target: LoginTarget::Server,
        }],
        prompt: None,
    };
    conn.login(script, &token()).await.unwrap();
    assert_eq!(ui.lines(LogKind::Command).await, ["USER alice@target ****"]);
    finish(conn, server).await;
}

#[test]
fn login_script_for_logon_rules() {
    let info = prompt_info;
    assert!(matches!(
        LoginScript::for_logon(None, &normal("x"), info()),
        Err(Error::InvalidInput(ref m)) if m == "user name required"
    ));
    assert!(matches!(
        LoginScript::for_logon(Some(""), &LogonType::AskForPassword, info()),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        LoginScript::for_logon(Some("a"), &LogonType::Agent, info()),
        Err(Error::InvalidInput(ref m)) if m.contains("SFTP only")
    ));
    let s = LoginScript::for_logon(Some("a"), &normal("CANARY-PW-x"), info()).unwrap();
    assert_eq!(s.steps.len(), 2);
    assert_eq!(s.steps[1].log_text, "PASS ****");
    let dbg = format!("{s:?}");
    assert!(!dbg.contains("CANARY"), "{dbg}");
}

// ---- greeting (AC5) ------------------------------------------------------------------

async fn greeting_error(script: Vec<Step>) -> Error {
    let ui = Ui::new(None);
    let (server, io) = FakeServer::duplex(script);
    let err = ControlConnection::from_stream(io, params(&ui.log, Charset::Auto), &token())
        .await
        .unwrap_err();
    server.finish().await;
    err
}

#[tokio::test(start_paused = true)]
async fn greeting_421_too_many_is_connection_limit() {
    let err = greeting_error(vec![Step::Reply(
        "421 Too many connections (8) from this IP",
    )])
    .await;
    assert!(matches!(err, Error::ConnectionLimit(_)), "{err:?}");
}

#[tokio::test(start_paused = true)]
async fn greeting_421_other_text_is_connection() {
    let err = greeting_error(vec![Step::Reply("421 Service not available, closing")]).await;
    assert!(
        matches!(err, Error::Connection(ref t) if t.contains("closing")),
        "{err:?}"
    );
    let err = greeting_error(vec![Step::Reply("500 What?")]).await;
    assert!(
        matches!(err, Error::Connection(ref t) if t.starts_with("unexpected greeting")),
        "{err:?}"
    );
    let err = greeting_error(vec![Step::Close]).await;
    assert!(
        matches!(err, Error::Connection(ref t) if t == "connection closed by server"),
        "{err:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn greeting_120_then_220_succeeds() {
    let ui = Ui::new(None);
    let (conn, server) = open(
        vec![
            Step::Reply("120 Service ready in 2 minutes"),
            Step::Delay(Duration::from_secs(5)),
            Step::Reply("220-Welcome\r\n to the test\r\n220 Ready"),
        ],
        &ui,
    )
    .await;
    assert_eq!(conn.greeting().text(), "Welcome\n to the test\nReady");
    assert!(
        ui.lines(LogKind::Status)
            .await
            .contains(&"Server busy, ready in 2 minutes".to_owned())
    );
    let responses = ui.lines(LogKind::Response).await;
    assert_eq!(responses[0], "120 Service ready in 2 minutes");
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn greeting_too_many_120_fails() {
    let err = greeting_error(vec![
        Step::Reply("120 a"),
        Step::Reply("120 b"),
        Step::Reply("120 c"),
        Step::Reply("120 d"),
        Step::Reply("120 e"),
        Step::Reply("120 f"),
    ])
    .await;
    assert!(matches!(err, Error::Connection(_)), "{err:?}");
}

// ---- after login --------------------------------------------------------------------

async fn logged_in(mut script: Vec<Step>, ui: &Ui) -> (ControlConnection, FakeServer) {
    let mut full = vec![
        Step::Reply("220 Welcome"),
        Step::Expect("USER alice"),
        Step::Reply("230 Logged in"),
    ];
    full.append(&mut script);
    let (mut conn, server) = open(full, ui).await;
    conn.login(script_for(&normal("x")), &token())
        .await
        .unwrap();
    (conn, server)
}

#[tokio::test(start_paused = true)]
async fn reply_421_after_login_is_connection() {
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(
        vec![
            Step::Expect("NOOP"),
            Step::Reply("421 Timeout - closing control connection"),
        ],
        &ui,
    )
    .await;
    let err = conn.send(Command::new("NOOP"), &token()).await.unwrap_err();
    assert!(
        matches!(err, Error::Connection(ref t) if t.contains("Timeout")),
        "{err:?}"
    );
    assert_eq!(conn.state(), ControlState::Broken);
    let again = conn.send(Command::new("NOOP"), &token()).await.unwrap_err();
    assert!(matches!(again, Error::Connection(ref t) if t == "connection lost"));
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn unsolicited_421_before_command_is_connection_error() {
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(vec![Step::Reply("421 Idle timeout")], &ui).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    let err = conn.send(Command::new("NOOP"), &token()).await.unwrap_err();
    assert!(
        matches!(err, Error::Connection(ref t) if t == "Idle timeout"),
        "{err:?}"
    );
    // NOOP was never written (the server would have failed on the extra line).
    assert!(
        !ui.lines(LogKind::Command)
            .await
            .contains(&"NOOP".to_owned())
    );
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn unsolicited_other_reply_is_discarded() {
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(
        vec![
            Step::Reply("200 Stray"),
            Step::Delay(Duration::from_millis(5)),
            Step::Expect("NOOP"),
            Step::Reply("200 NOOP ok"),
        ],
        &ui,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    let r = conn.send(Command::new("NOOP"), &token()).await.unwrap();
    assert_eq!(r.text(), "NOOP ok");
    assert!(
        ui.lines(LogKind::Debug(3))
            .await
            .contains(&"unexpected reply discarded".to_owned())
    );
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn send_skips_preliminary_replies() {
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(
        vec![
            Step::Expect("SITE X"),
            Step::Reply("150 working"),
            Step::Reply("110 marker"),
            Step::Reply("200 done"),
        ],
        &ui,
    )
    .await;
    let r = conn
        .send(Command::new("SITE").arg("X").unwrap(), &token())
        .await
        .unwrap();
    assert_eq!(r.code(), 200);
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn send_expect_maps_unexpected_code() {
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(
        vec![Step::Expect("CWD /x"), Step::Reply("550 No such directory")],
        &ui,
    )
    .await;
    let err = conn
        .send_expect(Command::new("CWD").arg("/x").unwrap(), &[250], &token())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Protocol { code: Some(550), ref message } if message == "No such directory"),
        "{err:?}"
    );
    assert_eq!(conn.state(), ControlState::Ready);
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn malformed_reply_breaks_connection() {
    for bad in [b"hello there\r\n".to_vec(), {
        let mut v = b"200 ".to_vec();
        v.resize(70 * 1024, b'x');
        v
    }] {
        let ui = Ui::new(None);
        let (mut conn, server) =
            logged_in(vec![Step::Expect("NOOP"), Step::RawBytes(bad)], &ui).await;
        let err = conn.send(Command::new("NOOP"), &token()).await.unwrap_err();
        assert!(matches!(err, Error::Protocol { code: None, .. }), "{err:?}");
        assert_eq!(conn.state(), ControlState::Broken);
        assert!(
            ui.lines(LogKind::Error)
                .await
                .contains(&"Invalid reply from server".to_owned())
        );
        finish(conn, server).await;
    }
}

#[tokio::test(start_paused = true)]
async fn split_reply_bytes_are_reassembled() {
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(
        vec![
            Step::Expect("STAT"),
            Step::RawBytes(b"211-Sta".to_vec()),
            Step::Delay(Duration::from_secs(1)),
            Step::RawBytes(b"tus\r\n line\r\n2".to_vec()),
            Step::Delay(Duration::from_secs(1)),
            Step::RawBytes(b"11 End\r\n".to_vec()),
        ],
        &ui,
    )
    .await;
    let r = conn.send(Command::new("STAT"), &token()).await.unwrap();
    assert_eq!(r.lines, ["211-Status", " line", "211 End"]);
    finish(conn, server).await;
}

// ---- negotiate (AC6, AC7) ---------------------------------------------------------

const FEAT_UTF8_MLST: &str = "211-Features:\r\n MDTM\r\n MLST size*;type*;modify*;UNIX.mode*;perm;unique*;\r\n UTF8\r\n211 End";

#[tokio::test(start_paused = true)]
async fn negotiate_without_feat_uses_defaults() {
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(
        vec![
            Step::Expect("SYST"),
            Step::Reply("500 SYST not understood"),
            Step::Expect("FEAT"),
            Step::Reply("500 FEAT not understood"),
        ],
        &ui,
    )
    .await;
    conn.negotiate(&token()).await.unwrap();
    assert_eq!(conn.features(), &Features::default());
    assert!(!conn.features().feat_supported);
    assert_eq!(conn.syst(), None);
    assert_eq!(conn.state(), ControlState::Ready);
    assert!(
        ui.lines(LogKind::Status)
            .await
            .contains(&"Server does not support non-ASCII characters.".to_owned())
    );
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn negotiate_sends_opts_utf8_only_when_advertised() {
    // Auto + UTF8 advertised → OPTS UTF8 ON; failure ignored.
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(
        vec![
            Step::Expect("SYST"),
            Step::Reply("215 UNIX Type: L8"),
            Step::Expect("FEAT"),
            Step::Reply("211-Features:\r\n UTF8\r\n211 End"),
            Step::Expect("OPTS UTF8 ON"),
            Step::Reply("501 No"),
        ],
        &ui,
    )
    .await;
    conn.negotiate(&token()).await.unwrap();
    assert_eq!(conn.syst(), Some("UNIX Type: L8"));
    assert!(conn.features().utf8);
    finish(conn, server).await;

    // Utf8 charset, no UTF8 in FEAT → nothing sent, no "non-ASCII" warning.
    let ui = Ui::new(None);
    let (server, io) = FakeServer::duplex(vec![
        Step::Reply("220 Welcome"),
        Step::Expect("SYST"),
        Step::Reply("215 UNIX"),
        Step::Expect("FEAT"),
        Step::Reply("211-Features:\r\n MDTM\r\n211 End"),
    ]);
    let (mut conn, _) =
        ControlConnection::from_stream(io, params(&ui.log, Charset::Utf8), &token())
            .await
            .unwrap();
    conn.negotiate(&token()).await.unwrap();
    assert!(
        !ui.lines(LogKind::Status)
            .await
            .contains(&"Server does not support non-ASCII characters.".to_owned())
    );
    finish(conn, server).await;

    // Custom charset: never, even when advertised.
    let ui = Ui::new(None);
    let (server, io) = FakeServer::duplex(vec![
        Step::Reply("220 Welcome"),
        Step::Expect("SYST"),
        Step::Reply("215 UNIX"),
        Step::Expect("FEAT"),
        Step::Reply("211-Features:\r\n UTF8\r\n211 End"),
    ]);
    let charset = Charset::Custom(encoding_rs::WINDOWS_1252);
    let (mut conn, _) = ControlConnection::from_stream(io, params(&ui.log, charset), &token())
        .await
        .unwrap();
    conn.negotiate(&token()).await.unwrap();
    assert_eq!(conn.encoding().name(), "windows-1252");
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn negotiate_sends_opts_mlst_with_advertised_facts() {
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(
        vec![
            Step::Expect("SYST"),
            Step::Reply("215 UNIX Type: L8"),
            Step::Expect("FEAT"),
            Step::Reply(FEAT_UTF8_MLST),
            Step::Expect("OPTS UTF8 ON"),
            Step::Reply("200 OK"),
            Step::Expect("OPTS MLST type;size;modify;perm;unix.mode;"),
            Step::Reply("200 MLST OPTS type;size;modify;perm;UNIX.mode;"),
        ],
        &ui,
    )
    .await;
    conn.negotiate(&token()).await.unwrap();
    let f = conn.features();
    assert!(f.mlsd && f.mdtm && f.utf8);
    // UTF8 confirmed: invalid bytes no longer switch the session.
    assert!(!conn.encoding().is_switched());
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn charset_auto_switches_on_invalid_utf8_reply() {
    let ui = Ui::new(None);
    let (mut conn, server) = open(
        vec![
            Step::RawBytes(b"220 Willkommen auf dem Server f\xfcr Tests\r\n".to_vec()),
            Step::ExpectRaw(b"CWD /d\xfcr".to_vec()),
            Step::Reply("250 ok"),
        ],
        &ui,
    )
    .await;
    assert_eq!(
        conn.greeting().text(),
        "Willkommen auf dem Server für Tests"
    );
    assert!(conn.encoding().is_switched());
    assert!(
        ui.lines(LogKind::Status)
            .await
            .contains(&"Server does not use UTF-8, switching to windows-1252".to_owned())
    );
    // Commands are encoded in windows-1252 from now on.
    let err = conn
        .send(Command::new("CWD").arg("/日本").unwrap(), &token())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
    conn.send(Command::new("CWD").arg("/dür").unwrap(), &token())
        .await
        .unwrap();
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn custom_charset_unmappable_is_invalid_input_and_nothing_written() {
    let ui = Ui::new(None);
    let charset = Charset::Custom(encoding_rs::WINDOWS_1252);
    let (mut conn, server) = open_with(
        vec![
            Step::Reply("220 Welcome"),
            Step::Expect("NOOP"),
            Step::Reply("200 ok"),
        ],
        &ui,
        charset,
    )
    .await;
    let err = conn
        .send(Command::new("RETR").arg("日本.txt").unwrap(), &token())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
    assert_eq!(conn.state(), ControlState::Greeting);
    conn.send(Command::new("NOOP"), &token()).await.unwrap();
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn crlf_in_user_or_password_rejected_before_writing() {
    for (user, pw) in [("al\r\nice", "x"), ("alice", "p\nw"), ("alice", "p\0w")] {
        let ui = Ui::new(None);
        let script = if user == "alice" {
            vec![
                Step::Reply("220 Welcome"),
                Step::Expect("USER alice"),
                Step::Reply("331 pw"),
            ]
        } else {
            vec![Step::Reply("220 Welcome")]
        };
        let (mut conn, server) = open(script, &ui).await;
        let s = LoginScript::for_logon(Some(user), &normal(pw), prompt_info()).unwrap();
        let err = conn.login(s, &token()).await.unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
        finish(conn, server).await;
    }
}

#[tokio::test(start_paused = true)]
async fn iac_doubled_on_the_wire() {
    let ui = Ui::new(None);
    let charset = Charset::Custom(encoding_rs::WINDOWS_1252);
    let (server, io) = FakeServer::duplex(vec![
        Step::Reply("220 Welcome"),
        Step::ExpectRaw(b"CWD a\xff\xffb".to_vec()),
        Step::Reply("250 ok"),
    ]);
    let (mut conn, _) = ControlConnection::from_stream(io, params(&ui.log, charset), &token())
        .await
        .unwrap();
    conn.send(Command::new("CWD").arg("aÿb").unwrap(), &token())
        .await
        .unwrap();
    finish(conn, server).await;
}

// ---- timeouts and cancellation (AC10, AC11) -----------------------------------------

#[tokio::test(start_paused = true)]
async fn inactivity_timeout_fires_after_20s() {
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(
        vec![
            Step::Expect("NOOP"),
            Step::Delay(Duration::from_secs(25)),
            Step::Reply("200 late"),
        ],
        &ui,
    )
    .await;
    let start = tokio::time::Instant::now();
    let err = conn.send(Command::new("NOOP"), &token()).await.unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err:?}");
    assert_eq!(start.elapsed().as_secs(), 20);
    assert_eq!(conn.state(), ControlState::Broken);
    assert!(
        ui.lines(LogKind::Error)
            .await
            .contains(&"Connection timed out after 20 seconds of inactivity".to_owned())
    );
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn trickling_server_does_not_time_out() {
    let ui = Ui::new(None);
    let mut script = vec![Step::Expect("STAT")];
    for chunk in ["2", "11", "-x", "\r\n", "2", "11 ", "done", "\r", "\n"] {
        script.push(Step::Delay(Duration::from_secs(15)));
        script.push(Step::RawBytes(chunk.as_bytes().to_vec()));
    }
    let (mut conn, server) = logged_in(script, &ui).await;
    let start = tokio::time::Instant::now();
    let r = conn.send(Command::new("STAT"), &token()).await.unwrap();
    assert_eq!(r.lines, ["211-x", "211 done"]);
    assert!(start.elapsed() >= Duration::from_secs(135));
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn cancel_during_reply_returns_cancelled_and_breaks_connection() {
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(
        vec![Step::Expect("NOOP"), Step::Delay(Duration::from_secs(10))],
        &ui,
    )
    .await;
    let cancel = token();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        trigger.cancel();
    });
    let start = tokio::time::Instant::now();
    let err = conn.send(Command::new("NOOP"), &cancel).await.unwrap_err();
    assert!(matches!(err, Error::Cancelled), "{err:?}");
    assert!(start.elapsed() < Duration::from_millis(1100));
    assert_eq!(conn.state(), ControlState::Broken);
    let next = conn.send(Command::new("NOOP"), &token()).await.unwrap_err();
    assert!(
        matches!(next, Error::Connection(ref t) if t == "connection lost"),
        "{next:?}"
    );
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn dropped_command_future_breaks_connection() {
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(
        vec![Step::Expect("NOOP"), Step::Delay(Duration::from_secs(10))],
        &ui,
    )
    .await;
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        conn.send(Command::new("NOOP"), &token()),
    )
    .await;
    assert_eq!(conn.state(), ControlState::Busy);
    let err = conn.send(Command::new("NOOP"), &token()).await.unwrap_err();
    assert!(matches!(err, Error::Connection(_)), "{err:?}");
    assert_eq!(conn.state(), ControlState::Broken);
    finish(conn, server).await;
}

// ---- pwd, raw command, keep-alive, quit (AC12–AC14) ----------------------------------

#[tokio::test(start_paused = true)]
async fn pwd_command_returns_path() {
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(
        vec![
            Step::Expect("PWD"),
            Step::Reply(r#"257 "/a ""b"" c" is current"#),
            Step::Expect("PWD"),
            Step::Reply("550 no"),
        ],
        &ui,
    )
    .await;
    assert_eq!(conn.pwd(&token()).await.unwrap(), r#"/a "b" c"#);
    assert!(matches!(
        conn.pwd(&token()).await,
        Err(Error::Protocol {
            code: Some(550),
            ..
        })
    ));
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn raw_command_refused_verbs_table() {
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(
        vec![
            Step::Expect("SITE HELP"),
            Step::Reply("214-The following SITE commands are recognized\r\n CHMOD UMASK\r\n214 Direct comments to root"),
            Step::Expect("cwd /tmp"),
            Step::Reply("250 ok"),
            Step::Expect("TYPE A"),
            Step::Reply("200 ok"),
        ],
        &ui,
    )
    .await;
    for verb in REFUSED_RAW_VERBS {
        for line in [
            verb.to_owned(),
            format!("{} arg", verb.to_ascii_lowercase()),
        ] {
            let err = conn.raw_command(&line, &token()).await.unwrap_err();
            assert!(
                matches!(err, Error::InvalidInput(ref m) if *m == format!("use the normal UI for {verb}")),
                "{line}: {err:?}"
            );
        }
    }
    assert!(matches!(
        conn.raw_command("SITE a\r\nDELE x", &token()).await,
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        conn.raw_command("  ", &token()).await,
        Err(Error::InvalidInput(_))
    ));
    let r = conn.raw_command("SITE HELP", &token()).await.unwrap();
    assert_eq!(r.code(), 214);
    assert_eq!(r.lines.len(), 3);
    conn.set_current_type(Some(TransferType::Binary));
    conn.raw_command("cwd /tmp", &token()).await.unwrap();
    assert!(conn.take_cwd_invalidated());
    assert!(!conn.take_cwd_invalidated());
    conn.raw_command("TYPE A", &token()).await.unwrap();
    assert_eq!(conn.current_type(), None);
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn keepalive_variants_send_expected_commands() {
    // noop
    let ui = Ui::new(None);
    let (mut conn, server) =
        logged_in(vec![Step::Expect("NOOP"), Step::Reply("200 NOOP ok")], &ui).await;
    conn.keepalive(&token()).await.unwrap();
    finish(conn, server).await;

    // random: 100 seeded calls; reproduce the choices to build the script.
    let seed = 42;
    let mut rng = fastrand::Rng::with_seed(seed);
    let choices: Vec<usize> = (0..100).map(|_| rng.usize(0..3)).collect();
    for c in 0..3 {
        assert!(choices.contains(&c), "seed must exercise every command");
    }
    let mut script = Vec::new();
    for c in &choices {
        match c {
            0 => script.extend([Step::Expect("NOOP"), Step::Reply("200 ok")]),
            1 => script.extend([Step::Expect("PWD"), Step::Reply("257 \"/\"")]),
            _ => script.extend([Step::Expect("TYPE A"), Step::Reply("200 Type A")]),
        }
    }
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(script, &ui).await;
    conn.keepalive_command = KeepaliveCommand::Random;
    conn.seed_keepalive_rng(seed);
    conn.set_current_type(Some(TransferType::Ascii));
    for _ in 0..100 {
        conn.keepalive(&token()).await.unwrap();
    }
    assert_eq!(conn.current_type(), Some(TransferType::Ascii));
    finish(conn, server).await;

    // Unknown type → TYPE I.
    let ui = Ui::new(None);
    let seed = (0u64..)
        .find(|s| fastrand::Rng::with_seed(*s).usize(0..3) == 2)
        .unwrap();
    let (mut conn, server) =
        logged_in(vec![Step::Expect("TYPE I"), Step::Reply("200 Type I")], &ui).await;
    conn.keepalive_command = KeepaliveCommand::Random;
    conn.seed_keepalive_rng(seed);
    conn.keepalive(&token()).await.unwrap();
    assert_eq!(conn.current_type(), Some(TransferType::Binary));
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn keepalive_skipped_during_transfer() {
    let ui = Ui::new(None);
    let (mut conn, server) = logged_in(vec![], &ui).await;
    conn.mark_transfer_open(true);
    assert_eq!(conn.state(), ControlState::TransferOpen);
    for _ in 0..3 {
        conn.keepalive(&token()).await.unwrap();
    }
    assert!(matches!(
        conn.send(Command::new("NOOP"), &token()).await,
        Err(Error::Internal(_))
    ));
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn keepalive_421_is_connection_error() {
    let ui = Ui::new(None);
    let (mut conn, server) =
        logged_in(vec![Step::Expect("NOOP"), Step::Reply("421 bye")], &ui).await;
    assert!(matches!(
        conn.keepalive(&token()).await,
        Err(Error::Connection(_))
    ));
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn quit_waits_at_most_2s() {
    let ui = Ui::new(None);
    let (conn, server) = logged_in(
        vec![Step::Expect("QUIT"), Step::Delay(Duration::from_secs(60))],
        &ui,
    )
    .await;
    let start = tokio::time::Instant::now();
    conn.quit().await;
    assert!(start.elapsed() <= Duration::from_secs(2));
    assert!(start.elapsed() >= Duration::from_secs(2));
    server.finish().await;
    assert!(
        ui.lines(LogKind::Debug(3))
            .await
            .contains(&"no reply to QUIT".to_owned())
    );
}

#[tokio::test(start_paused = true)]
async fn quit_with_221_closes_quickly() {
    let ui = Ui::new(None);
    let (conn, server) =
        logged_in(vec![Step::Expect("QUIT"), Step::Reply("221 Goodbye")], &ui).await;
    let start = tokio::time::Instant::now();
    conn.quit().await;
    assert!(start.elapsed() < Duration::from_millis(10));
    let t = server.finish().await;
    assert_eq!(t.received.last().map(String::as_str), Some("QUIT"));
}

#[tokio::test(start_paused = true)]
async fn upgrade_stream_swaps_io() {
    let ui = Ui::new(None);
    let (mut conn, server) = open(
        with_greeting(vec![Step::Expect("NOOP"), Step::Reply("200 ok")]),
        &ui,
    )
    .await;
    let mut called = false;
    conn.upgrade_stream(|io| {
        called = true;
        async move { Ok(io) }
    })
    .await
    .unwrap();
    assert!(called);
    conn.send(Command::new("NOOP"), &token()).await.unwrap();
    let err = conn
        .upgrade_stream(|_io| async { Err(Error::Tls("handshake failed".into())) })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Tls(_)));
    assert_eq!(conn.state(), ControlState::Broken);
    finish(conn, server).await;
}

#[tokio::test(start_paused = true)]
async fn upgrade_stream_refuses_unread_data() {
    let ui = Ui::new(None);
    let (mut conn, server) = open(with_greeting(vec![]), &ui).await;
    conn.pending
        .push_back(Reply::new(ReplyCode::from_const(200), vec!["200 x".into()]));
    let err = conn
        .upgrade_stream(|io| async { Ok(io) })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Protocol { code: None, .. }), "{err:?}");
    finish(conn, server).await;
}

#[tokio::test]
async fn connect_over_tcp_sets_addresses() {
    let ui = Ui::new(None);
    let (server, addr) = FakeServer::tcp(vec![
        Step::Reply("220 tcp ready"),
        Step::Expect("QUIT"),
        Step::Reply("221 bye"),
    ])
    .await;
    let mut p = params(&ui.log, Charset::Auto);
    p.target = HostPort::new(addr.ip().to_string(), addr.port());
    let (conn, greeting) = ControlConnection::connect(p, None, &token()).await.unwrap();
    assert_eq!(greeting.text(), "tcp ready");
    assert_eq!(conn.peer_addr(), Some(addr));
    assert!(conn.local_addr().is_some());
    conn.quit().await;
    server.finish().await;
}

#[tokio::test]
async fn connect_runs_pre_greeting_hook() {
    struct Hook(Arc<Mutex<bool>>);
    #[async_trait]
    impl StreamUpgrade for Hook {
        async fn upgrade(&self, io: BoxedIo) -> Result<BoxedIo> {
            *self.0.lock().unwrap() = true;
            Ok(io)
        }
    }
    let ui = Ui::new(None);
    let (server, addr) = FakeServer::tcp(vec![Step::Reply("220 ready")]).await;
    let mut p = params(&ui.log, Charset::Auto);
    p.target = HostPort::new(addr.ip().to_string(), addr.port());
    let flag = Arc::new(Mutex::new(false));
    let hook = Hook(Arc::clone(&flag));
    let (conn, _) = ControlConnection::connect(p, Some(&hook), &token())
        .await
        .unwrap();
    assert!(*flag.lock().unwrap());
    finish(conn, server).await;
}

// ---- secrets (AC9) ------------------------------------------------------------------

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn canary_password_never_logged() {
    const CANARY: &str = "CANARY-PW-3b9f1c";
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    // Callsite interest is cached process-wide; tests running in parallel can
    // leave it stale, so recompute it now that this subscriber is the default.
    tracing::callsite::rebuild_interest_cache();

    let ui = Ui::new(Some(CANARY));
    let (mut conn, server) = open(
        with_greeting(vec![
            Step::Expect("USER alice"),
            Step::Reply("331 Password required"),
            Step::ExpectSecret {
                verb: "PASS",
                value: CANARY,
            },
            Step::Reply("332 Need account"),
            Step::ExpectSecret {
                verb: "ACCT",
                value: CANARY,
            },
            Step::Reply("230 Logged in"),
            Step::Expect("NOOP"),
            Step::Reply("200 ok"),
        ]),
        &ui,
    )
    .await;
    let logon = LogonType::Account {
        password: Some(SecretString::from(CANARY)),
        account: None,
    };
    let script = script_for(&logon);
    let mut debug = format!("{script:?} {:?}", script.steps);
    conn.login(script, &token()).await.unwrap();
    conn.send(Command::new("NOOP"), &token()).await.unwrap();
    debug.push_str(&format!("{conn:?}"));
    let pass = Command::new("PASS")
        .secret(SecretString::from(CANARY))
        .unwrap();
    debug.push_str(&format!("{pass:?} {}", pass.log_text()));
    let transcript = {
        drop(conn);
        server.finish().await
    };
    debug.push_str(&format!("{transcript:?} {transcript}"));
    ui.settle().await;
    let logs: Vec<String> = ui
        .seen
        .lock()
        .unwrap()
        .logs
        .iter()
        .map(|m| format!("{m:?}"))
        .collect();
    assert!(logs.iter().any(|l| l.contains("PASS ****")));
    assert!(logs.iter().any(|l| l.contains("ACCT ****")));
    for l in &logs {
        assert!(!l.contains(CANARY), "log line leaks the canary: {l}");
    }
    assert!(!debug.contains(CANARY), "Debug leaks the canary: {debug}");
    let traced = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    assert!(traced.contains("ftp"), "tracing captured nothing: {traced}");
    assert!(
        !traced.contains(CANARY),
        "tracing leaks the canary: {traced}"
    );
}
