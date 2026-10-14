//! Harness self-test (no Docker): the real `FtpBackend` against
//! [`TinyFtpd`], the backend conformance suite over plain FTP with `LIST`
//! listings (the server has no `MLSD`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use courier_ftp_core::{
    backend::{Backend, ConnectInfo, conformance},
    events::{self, SessionId},
    model::{FtpEncryption, LogonType, Protocol, ServerAddress},
    settings::Settings,
    trust::MemoryCertTrustStore,
};
use courier_ftp_e2e::TinyFtpd;
use courier_ftp_proto_ftp::{backend::FtpBackendFactory, tls::TlsTrust};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

const USER: &str = "courier";
const PASSWORD: &str = "tiny-password";

fn backend(port: u16, password: &str) -> impl Backend {
    let (tx, mut rx) = events::channel(4);
    // Nothing here prompts; drain the events so the channel never fills.
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let mut settings = Settings::default();
    settings.connection.timeout_secs = 10;
    let trust = Arc::new(TlsTrust::with_system_verifier(
        Arc::new(MemoryCertTrustStore::new()),
        None,
    ));
    let factory = FtpBackendFactory::new(settings, trust);
    let mut address = ServerAddress::new(Protocol::Ftp, "127.0.0.1");
    address.port = port;
    let mut info = ConnectInfo::new(
        address,
        LogonType::Normal {
            user: USER.into(),
            password: SecretString::from(password.to_owned()),
        },
    );
    info.encryption = Some(FtpEncryption::PlainOnly);
    factory.create_ftp(&info, SessionId::next(), tx)
}

#[tokio::test(flavor = "multi_thread")]
async fn ftp_backend_passes_conformance_against_tiny_ftpd() {
    let root = tempfile::tempdir().unwrap();
    let server = TinyFtpd::start(root.path(), USER, PASSWORD).unwrap();
    let mut b = backend(server.port(), PASSWORD);
    b.connect(CancellationToken::new()).await.unwrap();
    let home = b.home_dir().await.unwrap();
    let base = home.join("conformance").unwrap();
    b.mkdir(&base).await.unwrap();
    conformance::run(&mut b, &base).await;
    b.rmdir(&base).await.unwrap();
    b.disconnect().await.unwrap();
    // Everything happened inside the served directory.
    assert!(root.path().read_dir().unwrap().next().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_password_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let server = TinyFtpd::start(root.path(), USER, PASSWORD).unwrap();
    let mut b = backend(server.port(), "wrong");
    let err = b.connect(CancellationToken::new()).await.unwrap_err();
    assert!(err.to_string().to_lowercase().contains("login"), "{err}");
}

/// An SFTP server reached with FTP (a port other than 22 without
/// `sftp://`): the error says what happened instead of "malformed reply".
#[tokio::test(flavor = "multi_thread")]
async fn an_ssh_server_reached_with_ftp_says_to_use_sftp() {
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        sock.write_all(b"SSH-2.0-Go\r\n").await.unwrap();
        // Keep the socket open like an SSH server waiting for the client.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });
    let mut b = backend(port, PASSWORD);
    let err = b.connect(CancellationToken::new()).await.unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("SSH server") && text.contains("sftp://"),
        "{text}"
    );
}

/// A password typed at a prompt is remembered for the run: a second
/// connection (as the transfer engine opens) doesn't ask again. A
/// remembered password the server rejects is forgotten.
#[tokio::test(flavor = "multi_thread")]
async fn a_typed_password_is_asked_once_per_run() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use courier_ftp_core::{
        backend::SessionPasswords,
        events::{CoreEvent, PromptKind, PromptResponse},
    };

    let root = tempfile::tempdir().unwrap();
    let server = TinyFtpd::start(root.path(), USER, PASSWORD).unwrap();
    let passwords = SessionPasswords::new();
    let trust = Arc::new(TlsTrust::with_system_verifier(
        Arc::new(MemoryCertTrustStore::new()),
        None,
    ));
    let mut settings = Settings::default();
    settings.connection.timeout_secs = 10;
    let factory = FtpBackendFactory::new(settings, trust).with_session_passwords(passwords.clone());
    let mut address = ServerAddress::new(Protocol::Ftp, "127.0.0.1");
    address.port = server.port();
    let mut info = ConnectInfo::new(address, LogonType::AskForPassword { user: USER.into() });
    info.encryption = Some(FtpEncryption::PlainOnly);

    let asked = Arc::new(AtomicUsize::new(0));
    let connect = |answer: &'static str| {
        let (tx, mut rx) = events::channel(4);
        let asked = Arc::clone(&asked);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let CoreEvent::Prompt(req) = event
                    && matches!(req.kind, PromptKind::Password { .. })
                {
                    asked.fetch_add(1, Ordering::SeqCst);
                    let _ = req.reply.send(PromptResponse::Secret(SecretString::from(
                        answer.to_owned(),
                    )));
                }
            }
        });
        factory.create_ftp(&info, SessionId::next(), tx)
    };

    let mut first = connect(PASSWORD);
    first.connect(CancellationToken::new()).await.unwrap();
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    let mut second = connect(PASSWORD);
    second.connect(CancellationToken::new()).await.unwrap();
    assert_eq!(asked.load(Ordering::SeqCst), 1, "asked again");

    // The server's password changes: the remembered one fails once and is
    // forgotten, so the next connection asks.
    passwords.put(
        &format!("{USER}@127.0.0.1:{}", server.port()),
        SecretString::from("stale".to_owned()),
    );
    let mut stale = connect(PASSWORD);
    assert!(stale.connect(CancellationToken::new()).await.is_err());
    let mut fresh = connect(PASSWORD);
    fresh.connect(CancellationToken::new()).await.unwrap();
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}
