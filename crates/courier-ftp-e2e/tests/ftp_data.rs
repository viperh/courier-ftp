//! FTP data connections (T11) against a real vsftpd in Docker
//! (`delfer/alpine-ftp-server`): passive mode with the passive port range
//! mapped 1:1 to the host (`ADDRESS=127.0.0.1`), and on Linux active mode
//! with the container on the host network (the server must be able to
//! connect back to us).
//!
//! `COURIER_E2E=1 cargo test -p courier-ftp-e2e --test ftp_data -- --ignored`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use courier_ftp_core::{
    backend::TransferType,
    events::{self, SessionId},
    model::LogonType,
    net::{HostPort, NetOpts},
    settings::{FtpTransferMode, Settings},
};
use courier_ftp_e2e::require_docker;
use courier_ftp_proto_ftp::{
    control::{self, ControlConnection, FtpContext, FtpOptions},
    data::{DataOpen, DataOptions, DataSession, finish},
};
use secrecy::SecretString;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt, core::IntoContainerPort, runners::AsyncRunner,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const USER: &str = "courier";
const PASSWORD: &str = "e2e-password";
/// Passive ports, mapped to the same host ports.
const PASV_PORTS: std::ops::RangeInclusive<u16> = 31100..=31104;

fn logon() -> LogonType {
    LogonType::Normal {
        user: USER.into(),
        password: SecretString::from(PASSWORD.to_owned()),
    }
}

fn settings() -> Settings {
    let mut s = Settings::default();
    s.connection.timeout_secs = 10;
    s
}

async fn login(host: &HostPort) -> courier_ftp_core::Result<ControlConnection> {
    let (tx, _rx) = events::channel(4);
    let opts = FtpOptions::new(host.clone(), logon(), &settings());
    control::connect(&opts, FtpContext::new(SessionId::next(), tx)).await
}

/// Log in, retrying while vsftpd starts.
async fn wait_for(host: &HostPort) -> ControlConnection {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        match login(host).await {
            Ok(conn) => return conn,
            Err(err) if tokio::time::Instant::now() < deadline => {
                eprintln!("waiting for vsftpd: {err}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(err) => panic!("vsftpd never accepted the login: {err}"),
        }
    }
}

fn data_session(host: &HostPort, mode: FtpTransferMode) -> DataSession {
    let s = settings();
    DataSession::new(DataOptions::new(
        &s,
        Some(mode),
        host.clone(),
        &NetOpts::from_settings(&s),
        Duration::from_secs(10),
    ))
}

async fn round_trip(conn: &mut ControlConnection, data: &mut DataSession, name: &str) {
    let bytes: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
    conn.set_type(TransferType::Binary).await.unwrap();
    let cancel = CancellationToken::new();
    let DataOpen::Stream(mut w) = data
        .open(conn, &format!("STOR {name}"), None, &cancel)
        .await
        .unwrap()
    else {
        panic!("STOR refused");
    };
    let flags = w.flags();
    w.write_all(&bytes).await.unwrap();
    w.shutdown().await.unwrap();
    drop(w);
    finish(conn, &flags, true).await.unwrap();

    // Resume from the middle.
    let DataOpen::Stream(mut r) = data
        .open(conn, &format!("RETR {name}"), Some(100_000), &cancel)
        .await
        .unwrap()
    else {
        panic!("RETR refused");
    };
    let flags = r.flags();
    let mut got = Vec::new();
    r.read_to_end(&mut got).await.unwrap();
    drop(r);
    finish(conn, &flags, false).await.unwrap();
    assert_eq!(got, bytes[100_000..]);

    // Abort mid-transfer, then the control connection still works.
    let DataOpen::Stream(mut r) = data
        .open(conn, &format!("RETR {name}"), None, &cancel)
        .await
        .unwrap()
    else {
        panic!("RETR refused");
    };
    let flags = r.flags();
    let mut buf = [0u8; 100];
    r.read_exact(&mut buf).await.unwrap();
    drop(r);
    let _ = finish(conn, &flags, false).await;
    assert!(conn.pwd().await.is_ok());
    assert_eq!(conn.send(&format!("DELE {name}")).await.unwrap().code, 250);
}

#[tokio::test]
#[ignore = "needs Docker: COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored"]
async fn vsftpd_passive_mode() {
    require_docker!();
    let mut image = GenericImage::new("delfer/alpine-ftp-server", "latest")
        .with_exposed_port(21.tcp())
        .with_env_var("USERS", format!("{USER}|{PASSWORD}"))
        .with_env_var("ADDRESS", "127.0.0.1")
        .with_env_var("MIN_PORT", PASV_PORTS.start().to_string())
        .with_env_var("MAX_PORT", PASV_PORTS.end().to_string());
    for port in PASV_PORTS {
        image = image.with_mapped_port(port, port.tcp());
    }
    let port = courier_ftp_e2e::free_port();
    image = image.with_mapped_port(port, 21.tcp());
    let _container: ContainerAsync<GenericImage> = image.start().await.unwrap();
    let host = HostPort::new("127.0.0.1", port);
    let mut conn = wait_for(&host).await;
    let mut data = data_session(&host, FtpTransferMode::Passive);
    round_trip(&mut conn, &mut data, "passive.bin").await;
    assert_eq!(data.mode(), FtpTransferMode::Passive);
    conn.quit().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs Docker: COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored"]
async fn vsftpd_active_mode() {
    require_docker!();
    // Host network: vsftpd listens on the host's port 21 and connects back
    // to our listener on 127.0.0.1.
    let _container: ContainerAsync<GenericImage> =
        GenericImage::new("delfer/alpine-ftp-server", "latest")
            .with_env_var("USERS", format!("{USER}|{PASSWORD}"))
            .with_env_var("MIN_PORT", "31110")
            .with_env_var("MAX_PORT", "31114")
            .with_network("host")
            .start()
            .await
            .unwrap();
    let host = HostPort::new("127.0.0.1", 21);
    let mut conn = wait_for(&host).await;
    let mut data = data_session(&host, FtpTransferMode::Active);
    round_trip(&mut conn, &mut data, "active.bin").await;
    assert_eq!(data.mode(), FtpTransferMode::Active);
    conn.quit().await;
}
