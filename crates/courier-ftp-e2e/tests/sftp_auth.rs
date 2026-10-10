//! SSH authentication against a real OpenSSH server in Docker (T20):
//! `atmoz/sftp` with a password user whose `authorized_keys` holds the T20
//! fixture keys (`crates/courier-ftp-proto-sftp/tests/keys/`, test-only).
//!
//! `COURIER_E2E=1 cargo test -p courier-ftp-e2e --test sftp_auth -- --ignored`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{path::PathBuf, sync::Arc, time::Duration};

use courier_ftp_core::{
    Error,
    events::{self, CoreEvent, PromptResponse, SessionId},
    model::{LocalPath, LogonType},
    net::HostPort,
    settings::Settings,
};
use courier_ftp_e2e::require_docker;
use courier_ftp_proto_sftp::ssh::{
    self, AcceptAnyHostKey, KeyFile, SshContext, SshOptions, agent::InProcessAgent,
};
use secrecy::SecretString;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, Mount},
    runners::AsyncRunner,
};
use tokio_util::sync::CancellationToken;

const USER: &str = "courier";
const PASSWORD: &str = "e2e-password";
const PASSPHRASE: &str = "fixture";

fn keys() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../courier-ftp-proto-sftp/tests/keys")
        .canonicalize()
        .unwrap()
}

/// Public keys put into the user's `authorized_keys`.
const AUTHORIZED: &[&str] = &[
    "ed25519.pub",
    "ed25519_enc.pub",
    "rsa.pub",
    "rsa_enc.pub",
    "ecdsa.pub",
    "ecdsa_enc.pub",
    "ppk/src_ed25519.pub",
    "ppk/src_ecdsa256.pub",
    "ppk/src_rsa2048.pub",
];

struct Server {
    _container: ContainerAsync<GenericImage>,
    host: HostPort,
}

async fn start() -> Server {
    let mut request = GenericImage::new("atmoz/sftp", "alpine")
        .with_exposed_port(22.tcp())
        .with_cmd([format!("{USER}:{PASSWORD}:1001")]);
    for (i, name) in AUTHORIZED.iter().enumerate() {
        let host = keys().join(name);
        request = request.with_mount(Mount::bind_mount(
            host.to_string_lossy().into_owned(),
            format!("/home/{USER}/.ssh/keys/key{i}.pub"),
        ));
    }
    let container = request.start().await.unwrap();
    let host = container.get_host().await.unwrap().to_string();
    let port = container.get_host_port_ipv4(22.tcp()).await.unwrap();
    let server = Server {
        _container: container,
        host: HostPort::new(host, port),
    };
    // sshd takes a moment after the container starts: poll with a real login.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        match login(&server, password(), &[]).await {
            Ok(()) => break,
            Err(err) if tokio::time::Instant::now() < deadline => {
                eprintln!("waiting for sshd: {err}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(err) => panic!("sshd never accepted the login: {err}"),
        }
    }
    server
}

fn password() -> LogonType {
    LogonType::Normal {
        user: USER.into(),
        password: SecretString::from(PASSWORD.to_owned()),
    }
}

fn key_file(name: &str) -> LogonType {
    LogonType::KeyFile {
        user: USER.into(),
        path: LocalPath::new(keys().join(name)),
    }
}

/// Log in with `logon`, answering prompts with `answers` in order.
async fn login(server: &Server, logon: LogonType, answers: &[&str]) -> Result<(), Error> {
    login_with(server, logon, answers, None).await
}

async fn login_with(
    server: &Server,
    logon: LogonType,
    answers: &[&str],
    agent: Option<InProcessAgent>,
) -> Result<(), Error> {
    let (tx, mut rx) = events::channel(4);
    let answers: Vec<String> = answers.iter().map(|s| (*s).to_owned()).collect();
    tokio::spawn(async move {
        let mut answers = answers.into_iter();
        while let Some(event) = rx.recv().await {
            if let CoreEvent::Prompt(req) = event
                && let Some(answer) = answers.next()
            {
                let _ = req
                    .reply
                    .send(PromptResponse::Secret(SecretString::from(answer)));
            }
        }
    });
    let mut settings = Settings::default();
    settings.connection.timeout_secs = 10;
    let opts = SshOptions::new(server.host.clone(), logon, &settings);
    let mut ctx = SshContext::new(
        SessionId::next(),
        tx,
        Arc::new(AcceptAnyHostKey::insecure_for_tests()),
    );
    if let Some(agent) = agent {
        ctx.agent = Arc::new(agent);
    }
    let session = ssh::connect(&opts, &ctx, &CancellationToken::new()).await?;
    assert!(session.server_version().contains("OpenSSH"));
    session.disconnect().await
}

#[tokio::test]
#[ignore = "needs Docker: COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored"]
async fn openssh_accepts_every_auth_method() {
    require_docker!();
    let server = start().await;

    // Password (start() logged in with it already), and a wrong one.
    let wrong = LogonType::Normal {
        user: USER.into(),
        password: SecretString::from("nope".to_owned()),
    };
    let err = login(&server, wrong, &[]).await.unwrap_err();
    assert!(
        matches!(&err, Error::Auth(m) if m.contains("publickey")),
        "{err:?}"
    );

    // Asked password.
    let ask = LogonType::AskForPassword { user: USER.into() };
    login(&server, ask, &[PASSWORD]).await.unwrap();

    // Key files: OpenSSH (plain and encrypted), PPK v2/v3.
    for (name, answers) in [
        ("ed25519", &[][..]),
        ("ed25519_enc", &[PASSPHRASE][..]),
        ("rsa", &[][..]),
        ("rsa_enc", &[PASSPHRASE][..]),
        ("ecdsa", &[][..]),
        ("ecdsa_enc", &[PASSPHRASE][..]),
        ("ppk/v2_ed25519.ppk", &[][..]),
        ("ppk/v3_ed25519_enc.ppk", &[PASSPHRASE][..]),
        ("ppk/v2_rsa2048_enc.ppk", &[PASSPHRASE][..]),
        ("ppk/v3_rsa2048.ppk", &[][..]),
        ("ppk/v3_ecdsa256_enc.ppk", &[PASSPHRASE][..]),
    ] {
        login(&server, key_file(name), answers)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }

    // Wrong passphrase three times: a clean failure.
    let err = login(&server, key_file("ed25519_enc"), &["x", "y", "z"])
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Auth(m) if m.contains("wrong passphrase")),
        "{err:?}"
    );

    // Agent.
    let key = KeyFile::read(&LocalPath::new(keys().join("ecdsa")))
        .await
        .unwrap()
        .decode(None)
        .await
        .unwrap();
    let agent = InProcessAgent::start(&[key]).await.unwrap();
    login_with(
        &server,
        LogonType::Agent { user: USER.into() },
        &[],
        Some(agent),
    )
    .await
    .unwrap();
}
