//! Control connection tests against a scripted fake FTP server on 127.0.0.1.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use courier_ftp_core::{
    Error,
    backend::TransferType,
    events::{self, CoreEvent, EventReceiver, LogKind, PromptKind, PromptResponse, SessionId},
    model::{Charset, LogonType},
    net::HostPort,
    settings::Settings,
};
use pretty_assertions::assert_eq;
use secrecy::SecretString;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use super::*;

/// One step of a fake server script.
#[derive(Debug, Clone)]
enum Step {
    /// Write these bytes.
    Send(Vec<u8>),
    /// Read one line and compare it (without the CRLF).
    Expect(Vec<u8>),
    /// Read one line; it must be one of these.
    ExpectOneOf(Vec<&'static str>),
    /// Wait.
    Sleep(Duration),
    /// Close the connection now.
    Close,
}

fn send(text: &str) -> Step {
    Step::Send(text.as_bytes().to_vec())
}

fn expect(line: &str) -> Step {
    Step::Expect(line.as_bytes().to_vec())
}

/// `cmd` answered with `reply` (CRLF added to each line).
fn exchange(cmd: &str, reply: &[&str]) -> [Step; 2] {
    let mut text = String::new();
    for line in reply {
        text.push_str(line);
        text.push_str("\r\n");
    }
    [expect(cmd), send(&text)]
}

struct FakeServer {
    host: HostPort,
    task: JoinHandle<Vec<Vec<u8>>>,
}

impl FakeServer {
    /// Serve one connection with `script`, then keep it open until the
    /// client closes it (or 10 s pass).
    async fn start(script: Vec<Step>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (read, mut write) = socket.into_split();
            let mut read = BufReader::new(read);
            let mut received = Vec::new();
            for step in script {
                match step {
                    Step::Send(bytes) => {
                        if write.write_all(&bytes).await.is_err() {
                            return received;
                        }
                    }
                    Step::Expect(want) => {
                        let line = read_line(&mut read).await;
                        assert_eq!(
                            String::from_utf8_lossy(&line),
                            String::from_utf8_lossy(&want),
                            "fake server got an unexpected command"
                        );
                        assert_eq!(line, want);
                        received.push(line);
                    }
                    Step::ExpectOneOf(options) => {
                        let line = read_line(&mut read).await;
                        let text = String::from_utf8_lossy(&line).into_owned();
                        assert!(options.contains(&text.as_str()), "unexpected {text:?}");
                        received.push(line);
                    }
                    Step::Sleep(d) => tokio::time::sleep(d).await,
                    Step::Close => return received,
                }
            }
            // Hold the connection open until the client goes away; record
            // anything else it sends.
            let _ = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let mut line = Vec::new();
                    match read.read_until(b'\n', &mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            trim_crlf(&mut line);
                            received.push(line);
                        }
                    }
                }
            })
            .await;
            received
        });
        Self {
            host: HostPort::new("127.0.0.1", port),
            task,
        }
    }

    /// Every line the server received, after the client is gone. Fails the
    /// test if the server's script failed.
    async fn finish(self) -> Vec<String> {
        let lines = tokio::time::timeout(Duration::from_secs(15), self.task)
            .await
            .expect("fake server did not finish")
            .expect("fake server script failed");
        lines
            .into_iter()
            .map(|l| String::from_utf8_lossy(&l).into_owned())
            .collect()
    }
}

async fn read_line(read: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Vec<u8> {
    let mut line = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), read.read_until(b'\n', &mut line))
        .await
        .expect("fake server waited too long for a command")
        .unwrap();
    assert!(line.ends_with(b"\r\n"), "command without CRLF: {line:?}");
    trim_crlf(&mut line);
    line
}

fn trim_crlf(line: &mut Vec<u8>) {
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
}

fn normal(user: &str, password: &str) -> LogonType {
    LogonType::Normal {
        user: user.into(),
        password: SecretString::from(password.to_owned()),
    }
}

fn options(server: &FakeServer, logon: LogonType) -> FtpOptions {
    let mut opts = FtpOptions::new(server.host.clone(), logon, &Settings::default());
    opts.timeout = Duration::from_secs(5);
    opts
}

fn context() -> (FtpContext, EventReceiver) {
    let (tx, rx) = events::channel(4);
    (FtpContext::new(SessionId::next(), tx), rx)
}

/// Every log line of `kind` so far.
fn logs(rx: &mut EventReceiver, kind: LogKind) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(event) = rx.try_recv() {
        if let CoreEvent::Log(msg) = event
            && msg.kind == kind
        {
            out.push(msg.text);
        }
    }
    out
}

/// Every log line so far, any kind.
fn all_logs(rx: &mut EventReceiver) -> Vec<(LogKind, String)> {
    let mut out = Vec::new();
    while let Some(event) = rx.try_recv() {
        if let CoreEvent::Log(msg) = event {
            out.push((msg.kind, msg.text));
        }
    }
    out
}

const GREETING: &str = "220-Welcome to the fake server\r\n220 Ready\r\n";

/// The steps after a successful login: SYST, FEAT (`feat` lines), PWD.
fn after_login(feat: &[&str], extra: Vec<Step>, cwd: &str) -> Vec<Step> {
    let mut steps = Vec::new();
    steps.extend(exchange("SYST", &["215 UNIX Type: L8"]));
    steps.extend(exchange("FEAT", feat));
    steps.extend(extra);
    steps.extend(exchange(
        "PWD",
        &[&format!("257 {cwd} is current directory")],
    ));
    steps
}

/// A connection logged in with a minimal script (no features), for tests
/// of later commands. `more` runs after the start sequence.
async fn logged_in(more: Vec<Step>) -> (ControlConnection, FakeServer, EventReceiver) {
    let mut script = vec![send("220 hi\r\n")];
    script.extend(exchange("USER bob", &["331 Password required"]));
    script.extend(exchange("PASS pw", &["230 Logged in"]));
    script.extend(after_login(&["500 FEAT not understood"], vec![], "\"/\""));
    script.extend(more);
    let server = FakeServer::start(script).await;
    let (ctx, rx) = context();
    let conn = connect(&options(&server, normal("bob", "pw")), ctx)
        .await
        .unwrap();
    (conn, server, rx)
}

// ----- login sequences ------------------------------------------------------

#[tokio::test]
async fn normal_login_with_feat_utf8_and_clnt() {
    let mut script = vec![send(GREETING)];
    script.extend(exchange("USER bob", &["331 Password required for bob"]));
    script.extend(exchange("PASS hunter2", &["230 User logged in"]));
    script.extend(after_login(
        &[
            "211-Features:",
            " MDTM",
            " REST STREAM",
            " SIZE",
            " MLST type*;size*;modify*;",
            " UTF8",
            " CLNT",
            " EPSV",
            "211 End",
        ],
        [
            exchange("CLNT courier-ftp", &["200 Noted"]),
            exchange("OPTS UTF8 ON", &["200 Always in UTF8 mode"]),
        ]
        .concat(),
        "\"/home/bob\"",
    ));
    let server = FakeServer::start(script).await;
    let (ctx, mut rx) = context();
    let conn = connect(&options(&server, normal("bob", "hunter2")), ctx)
        .await
        .unwrap();

    assert_eq!(conn.syst(), Some("UNIX Type: L8"));
    assert_eq!(conn.cwd(), Some("/home/bob"));
    let f = conn.features();
    assert!(f.feat_supported && f.mdtm && f.rest_stream && f.size && f.mlsd);
    assert!(f.utf8 && f.clnt && f.epsv && !f.eprt);
    assert_eq!(conn.charset(), Charset::Auto);
    assert_eq!(conn.effective_charset(), Charset::Utf8);
    assert_eq!(conn.welcome().unwrap().code, 220);
    assert!(conn.peer_addr().is_some() && conn.local_addr().is_some());

    let log = all_logs(&mut rx);
    let commands: Vec<&str> = log
        .iter()
        .filter(|(k, _)| *k == LogKind::Command)
        .map(|(_, t)| t.as_str())
        .collect();
    assert_eq!(
        commands,
        vec![
            "USER bob",
            "PASS ****",
            "SYST",
            "FEAT",
            "CLNT courier-ftp",
            "OPTS UTF8 ON",
            "PWD"
        ]
    );
    assert!(
        log.iter().all(|(_, t)| !t.contains("hunter2")),
        "password leaked into the log"
    );
    assert!(log.contains(&(LogKind::Response, "220-Welcome to the fake server".into())));
    assert!(log.contains(&(LogKind::Response, " MLST type*;size*;modify*;".into())));
    assert!(log.contains(&(LogKind::Status, "Logged in".into())));
    assert!(log.contains(&(LogKind::Status, "Connection established".into())));

    conn.quit().await;
    let received = server.finish().await;
    assert_eq!(received.last().map(String::as_str), Some("QUIT"));
}

#[tokio::test]
async fn anonymous_login_without_feat() {
    let mut script = vec![send("220 ftp.example.com\r\n")];
    script.extend(exchange("USER anonymous", &["331 Send e-mail as password"]));
    script.extend(exchange("PASS anonymous@example.com", &["230 Welcome"]));
    script.extend(exchange("SYST", &["502 Not implemented"]));
    script.extend(exchange("FEAT", &["500 Unknown command"]));
    script.extend(exchange("PWD", &["257 \"/\""]));
    let server = FakeServer::start(script).await;
    let (ctx, mut rx) = context();
    let conn = connect(&options(&server, LogonType::Anonymous), ctx)
        .await
        .unwrap();
    assert_eq!(conn.syst(), None);
    assert_eq!(conn.features(), &Features::default());
    assert_eq!(conn.effective_charset(), Charset::Auto);
    assert_eq!(conn.cwd(), Some("/"));
    assert!(logs(&mut rx, LogKind::Status).contains(&"The server does not support FEAT".into()));
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn account_login_sends_acct_when_asked() {
    let mut script = vec![send("220 hi\r\n")];
    script.extend(exchange("USER bob", &["331 Password required"]));
    script.extend(exchange("PASS pw", &["332 Need account for login"]));
    script.extend(exchange("ACCT billing-42", &["230 Logged in"]));
    script.extend(after_login(&["211 No features"], vec![], "\"/\""));
    let server = FakeServer::start(script).await;
    let (ctx, mut rx) = context();
    let logon = LogonType::Account {
        user: "bob".into(),
        password: SecretString::from("pw"),
        account: "billing-42".into(),
    };
    let conn = connect(&options(&server, logon), ctx).await.unwrap();
    assert!(conn.features().feat_supported);
    let commands = logs(&mut rx, LogKind::Command);
    assert!(commands.contains(&"ACCT ****".into()), "{commands:?}");
    assert!(commands.iter().all(|c| !c.contains("billing-42")));
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn account_logon_skips_acct_when_not_asked() {
    let mut script = vec![send("220 hi\r\n")];
    script.extend(exchange("USER bob", &["331 Password required"]));
    script.extend(exchange("PASS pw", &["230 Logged in"]));
    script.extend(after_login(&["211 No features"], vec![], "\"/\""));
    let server = FakeServer::start(script).await;
    let (ctx, _rx) = context();
    let logon = LogonType::Account {
        user: "bob".into(),
        password: SecretString::from("pw"),
        account: "acct".into(),
    };
    let conn = connect(&options(&server, logon), ctx).await.unwrap();
    drop(conn);
    let received = server.finish().await;
    assert!(received.iter().all(|l| !l.starts_with("ACCT")));
}

#[tokio::test]
async fn logged_in_straight_after_user() {
    let mut script = vec![send("220 hi\r\n")];
    script.extend(exchange("USER bob", &["230 No password needed"]));
    script.extend(after_login(&["211 No features"], vec![], "\"/\""));
    let server = FakeServer::start(script).await;
    let (ctx, mut rx) = context();
    let conn = connect(&options(&server, normal("bob", "pw")), ctx)
        .await
        .unwrap();
    assert!(
        !logs(&mut rx, LogKind::Command)
            .iter()
            .any(|c| c.starts_with("PASS"))
    );
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn account_required_but_not_configured() {
    let mut script = vec![send("220 hi\r\n")];
    script.extend(exchange("USER bob", &["331 Password required"]));
    script.extend(exchange("PASS pw", &["332 Need account"]));
    let server = FakeServer::start(script).await;
    let (ctx, _rx) = context();
    let err = connect(&options(&server, normal("bob", "pw")), ctx)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Auth(m) if m.contains("ACCT")),
        "{err:?}"
    );
    server.finish().await;
}

#[tokio::test]
async fn wrong_password_is_an_auth_error() {
    let mut script = vec![send("220 hi\r\n")];
    script.extend(exchange("USER bob", &["331 Password required"]));
    script.extend(exchange("PASS nope", &["530 Login incorrect."]));
    let server = FakeServer::start(script).await;
    let (ctx, _rx) = context();
    let err = connect(&options(&server, normal("bob", "nope")), ctx)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Auth(m) if m == "Login incorrect."),
        "{err:?}"
    );
    server.finish().await;
}

#[tokio::test]
async fn asks_for_the_password_before_connecting() {
    let mut script = vec![send("220 hi\r\n")];
    script.extend(exchange("USER bob", &["331 Password required"]));
    script.extend(exchange("PASS typed-secret", &["230 Logged in"]));
    script.extend(after_login(&["211 No features"], vec![], "\"/\""));
    let server = FakeServer::start(script).await;
    let (tx, mut rx) = events::channel(4);
    let ctx = FtpContext::new(SessionId::next(), tx);
    let opts = options(&server, LogonType::AskForPassword { user: "bob".into() });
    let ui = tokio::spawn(async move {
        let mut asked = Vec::new();
        while let Some(event) = rx.recv().await {
            match event {
                CoreEvent::Prompt(req) => {
                    asked.push(req.kind.clone());
                    let _ = req
                        .reply
                        .send(PromptResponse::Secret(SecretString::from("typed-secret")));
                }
                CoreEvent::Log(msg) => assert!(!msg.text.contains("typed-secret")),
                _ => {}
            }
        }
        asked
    });
    let conn = connect(&opts, ctx).await.unwrap();
    drop(conn);
    server.finish().await;
    let asked = ui.await.unwrap();
    assert!(
        matches!(&asked[..], [PromptKind::Password { for_ }] if for_.starts_with("bob@127.0.0.1:")),
        "{asked:?}"
    );
}

#[tokio::test]
async fn ssh_only_logon_types_are_refused() {
    let (ctx, _rx) = context();
    let opts = FtpOptions::new(
        HostPort::new("127.0.0.1", 1),
        LogonType::Agent { user: "bob".into() },
        &Settings::default(),
    );
    assert!(matches!(
        connect(&opts, ctx).await,
        Err(Error::InvalidInput(_))
    ));
}

#[tokio::test]
async fn custom_login_script_masks_secrets() {
    // An FTP proxy style script (T15): USER %s / PASS %w / SITE %h / USER %u / PASS %p,
    // plus a custom line carrying the proxy password.
    let mut script = vec![send("220 proxy ready\r\n")];
    script.extend(exchange("USER proxyuser", &["331 Password"]));
    script.extend(exchange("PASS proxypw", &["230 Proxy login ok"]));
    script.extend(exchange("SITE real.example.com", &["220 Connected"]));
    script.extend(exchange("LOGIN proxypw now", &["200 OK"]));
    script.extend(exchange("USER bob", &["331 Password"]));
    script.extend(exchange("PASS pw", &["230 Logged in"]));
    let server = FakeServer::start(script).await;
    let (ctx, mut rx) = context();
    let mut conn = ControlConnection::connect_tcp(&options(&server, LogonType::Anonymous), ctx)
        .await
        .unwrap();
    conn.read_greeting().await.unwrap();
    let script = LoginScript::new(vec![
        LoginStep::User("proxyuser".into()),
        LoginStep::Pass(SecretString::from("proxypw")),
        LoginStep::Command("SITE real.example.com".into()),
        LoginStep::SecretCommand {
            line: SecretString::from("LOGIN proxypw now"),
            secrets: vec![SecretString::from("proxypw")],
        },
        LoginStep::User("bob".into()),
        LoginStep::Pass(SecretString::from("pw")),
    ]);
    conn.login(&script).await.unwrap();
    let commands = logs(&mut rx, LogKind::Command);
    assert_eq!(
        commands,
        vec![
            "USER proxyuser",
            "PASS ****",
            "SITE real.example.com",
            "LOGIN **** now",
            "USER bob",
            "PASS ****"
        ]
    );
    drop(conn);
    server.finish().await;
}

// ----- greeting -------------------------------------------------------------

#[tokio::test]
async fn busy_greeting_then_ready() {
    let mut script = vec![send("120 Ready in 1 minute\r\n"), send("220 Ready\r\n")];
    script.extend(exchange("USER anonymous", &["230 ok"]));
    script.extend(after_login(&["211 No features"], vec![], "\"/\""));
    let server = FakeServer::start(script).await;
    let (ctx, _rx) = context();
    let conn = connect(&options(&server, LogonType::Anonymous), ctx)
        .await
        .unwrap();
    assert_eq!(conn.welcome().unwrap().lines, vec!["220 Ready"]);
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn greeting_421_is_a_connection_error() {
    let server = FakeServer::start(vec![send("421 Too many users\r\n")]).await;
    let (ctx, mut rx) = context();
    let err = connect(&options(&server, LogonType::Anonymous), ctx)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Connection(m) if m.contains("Too many users")),
        "{err:?}"
    );
    assert!(err.is_transient());
    assert!(logs(&mut rx, LogKind::Response).contains(&"421 Too many users".into()));
    server.finish().await;
}

#[tokio::test]
async fn unexpected_greeting_is_a_protocol_error() {
    let server = FakeServer::start(vec![send("230 What?\r\n")]).await;
    let (ctx, _rx) = context();
    let err = connect(&options(&server, LogonType::Anonymous), ctx)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Protocol {
                code: Some(230),
                ..
            }
        ),
        "{err:?}"
    );
    server.finish().await;
}

// ----- commands -------------------------------------------------------------

#[tokio::test]
async fn crlf_injection_is_rejected_before_sending() {
    let (mut conn, server, _rx) = logged_in(exchange("NOOP", &["200 ok"]).to_vec()).await;
    for bad in ["CWD a\r\nDELE b", "CWD a\nb", "CWD a\rb", "CWD a\0b"] {
        assert!(
            matches!(conn.send(bad).await, Err(Error::InvalidInput(_))),
            "{bad:?}"
        );
        assert!(matches!(
            conn.raw_command(bad).await,
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(
            conn.write_command(bad).await,
            Err(Error::InvalidInput(_))
        ));
    }
    assert!(conn.is_connected());
    // The next command is the first thing the server sees after login.
    assert_eq!(conn.send("NOOP").await.unwrap().code, 200);
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn send_expect_and_preliminary_replies() {
    let mut more = Vec::new();
    more.extend(exchange("MKD x", &["550 Exists"]));
    more.extend(exchange(
        "STAT",
        &["150 Working", "211-Status:", " fine", "211 End"],
    ));
    more.extend(exchange("RETR f", &["150 Opening"]));
    more.push(Step::Sleep(Duration::from_millis(50)));
    more.push(send("226 Done\r\n"));
    more.extend(exchange("NOOP", &["200 ok"]));
    let (mut conn, server, _rx) = logged_in(more).await;
    let err = conn.send_expect("MKD x", &[257]).await.unwrap_err();
    assert!(matches!(
        err,
        Error::Protocol {
            code: Some(550),
            ..
        }
    ));
    let stat = conn.send("STAT").await.unwrap();
    assert_eq!(stat.code, 211);
    assert_eq!(stat.inner_lines(), &[" fine".to_owned()]);
    // The low-level pair sees the 150 (T11).
    conn.write_command("RETR f").await.unwrap();
    assert_eq!(conn.outstanding(), 1);
    assert_eq!(conn.read_reply().await.unwrap().code, 150);
    assert_eq!(conn.outstanding(), 1);
    assert_eq!(conn.read_reply().await.unwrap().code, 226);
    assert_eq!(conn.outstanding(), 0);
    conn.send_expect("NOOP", &[200]).await.unwrap();
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn raw_command_returns_all_replies_and_refuses_data_commands() {
    let mut more = Vec::new();
    more.extend(exchange(
        "SITE HELP",
        &["214-Commands:", " CHMOD UMASK", "214 End"],
    ));
    more.extend(exchange("TYPE A", &["200 ok"]));
    more.extend(exchange("TYPE I", &["200 ok"]));
    more.extend(exchange("CWD /x", &["250 ok"]));
    let (mut conn, server, mut rx) = logged_in(more).await;
    for refused in ["LIST", "retr file", "PASV", "AUTH TLS", " ", ""] {
        assert!(
            matches!(conn.raw_command(refused).await, Err(Error::InvalidInput(_))),
            "{refused:?}"
        );
    }
    assert!(
        logs(&mut rx, LogKind::Error)
            .iter()
            .any(|e| e.contains("LIST needs a data connection"))
    );
    let replies = conn.raw_command("SITE HELP").await.unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].lines.len(), 3);
    // A raw TYPE makes the tracked type unknown, so set_type sends again.
    conn.raw_command("TYPE A").await.unwrap();
    assert_eq!(conn.transfer_type(), None);
    conn.set_type(TransferType::Binary).await.unwrap();
    conn.set_type(TransferType::Binary).await.unwrap(); // not sent again
    assert_eq!(conn.transfer_type(), Some(TransferType::Binary));
    assert_eq!(conn.cwd(), Some("/"));
    conn.raw_command("CWD /x").await.unwrap();
    assert_eq!(conn.cwd(), None);
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn custom_charset_encodes_commands_and_decodes_replies() {
    let mut script = vec![send("220 hi\r\n")];
    script.extend(exchange("USER anonymous", &["230 ok"]));
    script.extend(exchange("SYST", &["215 UNIX"]));
    // A server announcing UTF8 doesn't switch a fixed charset.
    script.extend(exchange("FEAT", &["211-x", " UTF8", "211 x"]));
    script.push(Step::Expect(b"PWD".to_vec()));
    script.push(Step::Send(b"257 \"/caf\xe9\" is cwd\r\n".to_vec()));
    script.push(Step::Expect(b"CWD /caf\xe9".to_vec()));
    script.push(send("250 ok\r\n"));
    let server = FakeServer::start(script).await;
    let (ctx, _rx) = context();
    let mut opts = options(&server, LogonType::Anonymous);
    opts.charset = Charset::Custom(encoding_rs::WINDOWS_1252);
    let mut conn = connect(&opts, ctx).await.unwrap();
    assert_eq!(conn.cwd(), Some("/café"));
    assert_eq!(conn.effective_charset(), opts.charset);
    conn.send_expect("CWD /café", &[250]).await.unwrap();
    drop(conn);
    server.finish().await;
}

// ----- keep-alive and disconnect -------------------------------------------

#[tokio::test]
async fn keepalive_commands() {
    let mut more = Vec::new();
    more.extend(exchange("NOOP", &["200 ok"]));
    more.extend(exchange("PWD", &["257 \"/srv\""]));
    more.extend(exchange("TYPE I", &["200 ok"]));
    for _ in 0..8 {
        more.push(Step::ExpectOneOf(vec!["NOOP", "PWD", "TYPE I"]));
        more.push(send("257 \"/srv\"\r\n"));
    }
    let (mut conn, server, _rx) = logged_in(more).await;
    conn.keepalive_with(KeepaliveCommand::Noop).await.unwrap();
    conn.keepalive_with(KeepaliveCommand::Pwd).await.unwrap();
    assert_eq!(conn.cwd(), Some("/srv"));
    conn.keepalive_with(KeepaliveCommand::Type).await.unwrap();
    assert_eq!(conn.transfer_type(), Some(TransferType::Binary));
    for _ in 0..8 {
        // The server answers 257 to everything; `TYPE I` then counts as failed
        // but that is ignored.
        conn.keepalive().await.unwrap();
    }
    assert!(conn.idle_for() < Duration::from_secs(5));
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn keepalive_does_nothing_during_a_transfer() {
    let mut more = exchange("RETR f", &["150 Opening"]).to_vec();
    more.push(send("226 Done\r\n"));
    let (mut conn, server, _rx) = logged_in(more).await;
    conn.write_command("RETR f").await.unwrap();
    conn.keepalive().await.unwrap();
    assert_eq!(conn.read_reply().await.unwrap().code, 150);
    assert_eq!(conn.read_reply().await.unwrap().code, 226);
    drop(conn);
    let received = server.finish().await;
    assert_eq!(received.last().map(String::as_str), Some("RETR f"));
}

#[test]
fn keepalive_setting() {
    assert_eq!(
        KeepaliveCommand::from_setting("noop"),
        KeepaliveCommand::Noop
    );
    assert_eq!(KeepaliveCommand::from_setting("PWD"), KeepaliveCommand::Pwd);
    assert_eq!(
        KeepaliveCommand::from_setting(" Type "),
        KeepaliveCommand::Type
    );
    assert_eq!(
        KeepaliveCommand::from_setting("random"),
        KeepaliveCommand::Random
    );
}

#[tokio::test]
async fn quit_gives_up_after_two_seconds() {
    // The server reads QUIT but never answers.
    let (conn, server, mut rx) = logged_in(vec![expect("QUIT")]).await;
    let start = std::time::Instant::now();
    conn.quit().await;
    let took = start.elapsed();
    assert!(took >= QUIT_WAIT - Duration::from_millis(100), "{took:?}");
    assert!(took < QUIT_WAIT + Duration::from_secs(2), "{took:?}");
    assert!(logs(&mut rx, LogKind::Status).contains(&"Disconnected from server".into()));
    server.finish().await;
}

// ----- errors, timeouts, cancellation --------------------------------------

#[tokio::test]
async fn reply_421_mid_session_closes_the_connection() {
    let more = exchange("NOOP", &["421 Timeout, closing control connection"]).to_vec();
    let (mut conn, server, _rx) = logged_in(more).await;
    let err = conn.send("NOOP").await.unwrap_err();
    assert!(
        matches!(&err, Error::Connection(m) if m.contains("closing")),
        "{err:?}"
    );
    assert!(!conn.is_connected());
    assert!(matches!(conn.send("NOOP").await, Err(Error::Connection(_))));
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn idle_timeout_is_an_error_and_closes() {
    // The server reads NOOP and goes silent.
    let (mut conn, server, mut rx) = logged_in(vec![expect("NOOP")]).await;
    conn.timeout = Duration::from_millis(300);
    let start = std::time::Instant::now();
    let err = conn.send("NOOP").await.unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err:?}");
    assert!(start.elapsed() < Duration::from_secs(3));
    assert!(!conn.is_connected());
    assert!(
        logs(&mut rx, LogKind::Error)
            .iter()
            .any(|e| e.contains("timed out after 0.3 seconds of inactivity"))
    );
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn timeout_counts_inactivity_not_total_time() {
    // A slow multi-line reply: 6 lines 150 ms apart (900 ms in total) with a
    // 500 ms inactivity timeout.
    let mut more = vec![expect("STAT"), send("211-Status\r\n")];
    for i in 0..5 {
        more.push(Step::Sleep(Duration::from_millis(150)));
        more.push(send(&format!(" line {i}\r\n")));
    }
    more.push(send("211 End\r\n"));
    let (mut conn, server, _rx) = logged_in(more).await;
    conn.timeout = Duration::from_millis(500);
    let reply = conn.send("STAT").await.unwrap();
    assert_eq!(reply.lines.len(), 7);
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn connection_token_cancels_the_greeting_wait() {
    let server = FakeServer::start(vec![Step::Sleep(Duration::from_secs(5))]).await;
    let (ctx, _rx) = context();
    let cancel = ctx.cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
    });
    let start = std::time::Instant::now();
    let err = connect(&options(&server, LogonType::Anonymous), ctx)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Cancelled), "{err:?}");
    assert!(start.elapsed() < Duration::from_secs(2));
    drop(server);
}

#[tokio::test]
async fn cancelled_command_reply_is_skipped_by_the_next_command() {
    let mut more = vec![expect("STAT -l /big")];
    more.push(Step::Sleep(Duration::from_millis(300)));
    more.push(send("213-Status\r\n big listing\r\n213 End\r\n"));
    more.extend(exchange("NOOP", &["200 NOOP ok"]));
    let (mut conn, server, _rx) = logged_in(more).await;
    let cancel = CancellationToken::new();
    let c = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        c.cancel();
    });
    let err = conn.send_with("STAT -l /big", &cancel).await.unwrap_err();
    assert!(matches!(err, Error::Cancelled));
    assert!(conn.is_connected());
    assert_eq!(conn.outstanding(), 1);
    // The late 213 is read and dropped; NOOP gets its own reply.
    let reply = conn.send("NOOP").await.unwrap();
    assert_eq!(reply.code, 200);
    assert_eq!(conn.outstanding(), 0);
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn oversized_reply_line_is_a_protocol_error() {
    let mut more = vec![expect("NOOP"), send("200 ")];
    more.push(Step::Send(vec![b'a'; MAX_LINE + 10]));
    let (mut conn, server, _rx) = logged_in(more).await;
    let err = conn.send("NOOP").await.unwrap_err();
    assert!(
        matches!(&err, Error::Protocol { code: None, message } if message.contains("longer")),
        "{err:?}"
    );
    assert!(!conn.is_connected());
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn malformed_reply_is_a_protocol_error() {
    let more = exchange("NOOP", &["hello there"]).to_vec();
    let (mut conn, server, _rx) = logged_in(more).await;
    let err = conn.send("NOOP").await.unwrap_err();
    assert!(matches!(err, Error::Protocol { code: None, .. }), "{err:?}");
    assert!(!conn.is_connected());
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn eof_mid_reply_is_a_connection_error() {
    let more = vec![expect("STAT"), send("211-Status\r\n half"), Step::Close];
    let (mut conn, server, _rx) = logged_in(more).await;
    let err = conn.send("STAT").await.unwrap_err();
    assert!(
        matches!(&err, Error::Connection(m) if m.contains("closed")),
        "{err:?}"
    );
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn control_characters_are_removed_from_logged_replies() {
    let more = vec![
        expect("NOOP"),
        send("200 ok\x1b[31m red\x07\t\u{202e}x\r\n"),
    ];
    let (mut conn, server, mut rx) = logged_in(more).await;
    let _ = logs(&mut rx, LogKind::Response);
    let reply = conn.send("NOOP").await.unwrap();
    assert_eq!(reply.lines[0], "200 ok\x1b[31m red\x07\t\u{202e}x");
    assert_eq!(logs(&mut rx, LogKind::Response), vec!["200 ok[31m red x"]);
    drop(conn);
    server.finish().await;
}

// ----- stream upgrade (T12) -------------------------------------------------

#[tokio::test]
async fn upgrade_swaps_the_stream() {
    let mut more = exchange("AUTH TLS", &["234 Proceed"]).to_vec();
    more.extend(exchange("NOOP", &["200 still here"]));
    let (mut conn, server, _rx) = logged_in(more).await;
    conn.send_expect("AUTH TLS", &[234]).await.unwrap();
    // An identity "upgrade": the stream comes back unchanged.
    conn.upgrade_stream(|s| async move { Ok(s) }).await.unwrap();
    assert_eq!(conn.send("NOOP").await.unwrap().code, 200);
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn upgrade_refuses_bytes_received_before_the_handshake() {
    // An injected reply right behind the 234 (STARTTLS command injection).
    let more = vec![expect("AUTH TLS"), send("234 Proceed\r\n230 injected\r\n")];
    let (mut conn, server, _rx) = logged_in(more).await;
    conn.send_expect("AUTH TLS", &[234]).await.unwrap();
    // Make sure the injected bytes have arrived and are buffered.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut probe = [0u8; 64];
    if let Some(stream) = conn.stream.as_mut()
        && let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(500), stream.read(&mut probe)).await
    {
        conn.parser.feed(&probe[..n]);
    }
    let err = conn
        .upgrade_stream(|s| async move { Ok(s) })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Protocol { .. }), "{err:?}");
    assert!(!conn.is_connected());
    drop(conn);
    server.finish().await;
}

#[tokio::test]
async fn failed_upgrade_closes_the_connection() {
    let more = exchange("AUTH TLS", &["234 Proceed"]).to_vec();
    let (mut conn, server, _rx) = logged_in(more).await;
    conn.send_expect("AUTH TLS", &[234]).await.unwrap();
    let err = conn
        .upgrade_stream(|_s| async move { Err(Error::Tls("handshake failed".into())) })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Tls(_)));
    assert!(!conn.is_connected());
    server.finish().await;
}

// ----- duplex stream --------------------------------------------------------

#[tokio::test]
async fn works_over_any_stream() {
    let (client, mut server) = tokio::io::duplex(1024);
    let (ctx, _rx) = context();
    let mut conn =
        ControlConnection::new(Box::new(client), ctx, Duration::from_secs(5), Charset::Auto);
    let srv = tokio::spawn(async move {
        server.write_all(b"220 duplex\r\n").await.unwrap();
        let mut buf = [0u8; 64];
        let n = server.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"NOOP\r\n");
        // A reply split into tiny writes.
        for b in b"200-a\r\n200 b\r\n" {
            server.write_all(&[*b]).await.unwrap();
            server.flush().await.unwrap();
        }
        server
    });
    assert_eq!(conn.read_greeting().await.unwrap().code, 220);
    let reply = conn.send("NOOP").await.unwrap();
    assert_eq!(reply.lines, vec!["200-a", "200 b"]);
    assert_eq!(conn.peer_addr(), None);
    let _server = srv.await.unwrap();
}

#[test]
fn login_script_for_logon_types() {
    let script = LoginScript::for_logon(&LogonType::Anonymous, None).unwrap();
    assert!(matches!(&script.steps()[0], LoginStep::User(u) if u == "anonymous"));
    assert_eq!(format!("{:?}", script.steps()[1]), "Pass(****)");
    assert!(matches!(
        LoginScript::for_logon(&LogonType::AskForPassword { user: "a".into() }, None),
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(
        LoginScript::for_logon(
            &LogonType::Account {
                user: "a".into(),
                password: SecretString::from("p"),
                account: "c".into()
            },
            None
        )
        .unwrap()
        .steps()
        .len(),
        3
    );
}
