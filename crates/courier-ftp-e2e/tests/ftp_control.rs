//! The FTP control connection (T10) against a real vsftpd in Docker
//! (`delfer/alpine-ftp-server`): login, `SYST`, `FEAT`, `OPTS UTF8`, `PWD`,
//! keep-alive, raw commands and `QUIT`. T76 replaces the image with the
//! project's own vsftpd/ProFTPD/Pure-FTPd fixtures.
//!
//! `COURIER_E2E=1 cargo test -p courier-ftp-e2e --test ftp_control -- --ignored`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use courier_ftp_core::{
    Error,
    events::{self, SessionId},
    model::{Charset, LogonType},
    net::HostPort,
    settings::Settings,
};
use courier_ftp_e2e::require_docker;
use courier_ftp_proto_ftp::control::{self, ControlConnection, FtpContext, FtpOptions};
use secrecy::SecretString;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt, core::IntoContainerPort, runners::AsyncRunner,
};

const USER: &str = "courier";
const PASSWORD: &str = "e2e-password";

struct Server {
    _container: ContainerAsync<GenericImage>,
    host: HostPort,
}

fn logon(password: &str) -> LogonType {
    LogonType::Normal {
        user: USER.into(),
        password: SecretString::from(password.to_owned()),
    }
}

async fn login(server: &Server, logon: LogonType) -> Result<ControlConnection, Error> {
    let (tx, _rx) = events::channel(4);
    let mut settings = Settings::default();
    settings.connection.timeout_secs = 10;
    let opts = FtpOptions::new(server.host.clone(), logon, &settings);
    control::connect(&opts, FtpContext::new(SessionId::next(), tx)).await
}

async fn start() -> Server {
    let container = GenericImage::new("delfer/alpine-ftp-server", "latest")
        .with_exposed_port(21.tcp())
        .with_env_var("USERS", format!("{USER}|{PASSWORD}"))
        .start()
        .await
        .unwrap();
    let host = container.get_host().await.unwrap().to_string();
    let port = container.get_host_port_ipv4(21.tcp()).await.unwrap();
    let server = Server {
        _container: container,
        host: HostPort::new(host, port),
    };
    // vsftpd takes a moment after the container starts: poll with a login.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        match login(&server, logon(PASSWORD)).await {
            Ok(conn) => {
                conn.quit().await;
                break;
            }
            Err(err) if tokio::time::Instant::now() < deadline => {
                eprintln!("waiting for vsftpd: {err}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(err) => panic!("vsftpd never accepted the login: {err}"),
        }
    }
    server
}

#[tokio::test]
#[ignore = "needs Docker: COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored"]
async fn vsftpd_control_connection() {
    require_docker!();
    let server = start().await;

    let mut conn = login(&server, logon(PASSWORD)).await.unwrap();
    assert!(
        conn.syst().unwrap_or_default().contains("UNIX"),
        "{:?}",
        conn.syst()
    );
    let f = conn.features();
    assert!(
        f.feat_supported && f.size && f.mdtm && f.epsv && f.rest_stream,
        "{f:?}"
    );
    if f.utf8 {
        assert_eq!(conn.effective_charset(), Charset::Utf8);
    }
    assert!(
        conn.cwd().unwrap_or_default().starts_with('/'),
        "{:?}",
        conn.cwd()
    );

    for _ in 0..5 {
        conn.keepalive().await.unwrap();
    }
    let stat = conn.raw_command("STAT").await.unwrap();
    assert!(stat.last().is_some_and(|r| r.is_ok()), "{stat:?}");
    assert!(matches!(
        conn.raw_command("LIST").await,
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        conn.send("NOOP\r\nDELE x").await,
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(conn.send("NOOP").await.unwrap().code, 200);
    conn.quit().await;

    let err = login(&server, logon("wrong")).await.unwrap_err();
    assert!(matches!(err, Error::Auth(_)), "{err:?}");
}
