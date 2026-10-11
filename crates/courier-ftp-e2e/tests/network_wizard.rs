//! The network configuration wizard's test (T72) against a real vsftpd in
//! Docker (`delfer/alpine-ftp-server`):
//!
//! - on Linux, with the container on the host network, both passive and
//!   active mode work;
//! - with the container on its own network (passive ports mapped 1:1), the
//!   server can't connect back to the address we announce, which is what a
//!   blocked active port looks like: passive ✔, active ✘ with the fix.
//!
//! `COURIER_E2E=1 cargo test -p courier-ftp-e2e --test network_wizard -- --ignored`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use courier_ftp_core::{
    events::{self, SessionId},
    model::LogonType,
    net::HostPort,
    settings::Settings,
};
use courier_ftp_e2e::require_docker;
use courier_ftp_proto_ftp::{
    control::{self, FtpContext, FtpOptions},
    probe::{self, ProbeOptions, ProbeReport, ProbeStep, Recommendation, StepStatus},
};
use secrecy::SecretString;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt, core::IntoContainerPort, runners::AsyncRunner,
};

const USER: &str = "courier";
const PASSWORD: &str = "e2e-password";
/// Passive ports, mapped to the same host ports.
const PASV_PORTS: std::ops::RangeInclusive<u16> = 31120..=31124;

fn options(host: &HostPort) -> FtpOptions {
    let mut s = Settings::default();
    s.connection.timeout_secs = 10;
    FtpOptions::new(
        host.clone(),
        LogonType::Normal {
            user: USER.into(),
            password: SecretString::from(PASSWORD.to_owned()),
        },
        &s,
    )
}

/// Wait until vsftpd accepts a login.
async fn wait_for(host: &HostPort) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let (tx, _rx) = events::channel(4);
        match control::connect(&options(host), FtpContext::new(SessionId::next(), tx)).await {
            Ok(conn) => return conn.quit().await,
            Err(err) if tokio::time::Instant::now() < deadline => {
                eprintln!("waiting for vsftpd: {err}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(err) => panic!("vsftpd never accepted the login: {err}"),
        }
    }
}

async fn run(host: &HostPort) -> ProbeReport {
    let (tx, _rx) = events::channel(64);
    probe::run(
        &options(host),
        FtpContext::new(SessionId::next(), tx),
        &Settings::default(),
        &ProbeOptions::with_timeout(Duration::from_secs(10)),
        |_| {},
    )
    .await
}

fn status(report: &ProbeReport, step: ProbeStep) -> StepStatus {
    report.get(step).unwrap().status
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs Docker: COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored"]
async fn vsftpd_passive_and_active_work() {
    require_docker!();
    let _container: ContainerAsync<GenericImage> =
        GenericImage::new("delfer/alpine-ftp-server", "latest")
            .with_env_var("USERS", format!("{USER}|{PASSWORD}"))
            .with_env_var("MIN_PORT", "31130")
            .with_env_var("MAX_PORT", "31134")
            .with_network("host")
            .start()
            .await
            .unwrap();
    let host = HostPort::new("127.0.0.1", 21);
    wait_for(&host).await;
    let report = run(&host).await;
    assert_eq!(
        status(&report, ProbeStep::Connect),
        StepStatus::Ok,
        "{report:#?}"
    );
    assert_eq!(
        status(&report, ProbeStep::Passive),
        StepStatus::Ok,
        "{report:#?}"
    );
    assert_eq!(
        status(&report, ProbeStep::Active),
        StepStatus::Ok,
        "{report:#?}"
    );
    assert_eq!(report.recommendation(), Recommendation::Passive);
}

#[tokio::test]
#[ignore = "needs Docker: COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored"]
async fn vsftpd_blocked_active_port() {
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
    wait_for(&host).await;
    let report = run(&host).await;
    assert_eq!(
        status(&report, ProbeStep::Passive),
        StepStatus::Ok,
        "{report:#?}"
    );
    // The server is in another network namespace: whatever we announce,
    // it can't connect back (vsftpd refuses the foreign PORT address or
    // fails to connect).
    let active = report.get(ProbeStep::Active).unwrap();
    assert_eq!(active.status, StepStatus::Failed, "{report:#?}");
    assert!(
        active
            .advice
            .as_deref()
            .is_some_and(|a| a.contains("passive mode")),
        "{active:?}"
    );
    assert_eq!(report.recommendation(), Recommendation::Passive);
}
