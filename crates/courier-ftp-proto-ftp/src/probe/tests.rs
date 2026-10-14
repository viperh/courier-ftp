//! The wizard's test against the in-process server (no external hosts):
//! passive and active working, a blocked active port, a blocked passive
//! port, a server announcing another address, login failures,
//! cancellation, and NAT detection on both sides.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use courier_ftp_core::{
    events::{self, SessionId},
    model::LogonType,
    net::HostPort,
};
use pretty_assertions::assert_eq;
use secrecy::SecretString;

use super::*;
use crate::test_server::{ServerConfig, TestServer};

fn options(server: &TestServer, password: &str) -> FtpOptions {
    let mut opts = FtpOptions::new(
        HostPort::from(server.addr),
        LogonType::Normal {
            user: "bob".into(),
            password: SecretString::from(password.to_owned()),
        },
        &Settings::default(),
    );
    opts.timeout = Duration::from_secs(5);
    opts.net.timeout = Duration::from_secs(5);
    opts
}

async fn probe_with(
    server: &TestServer,
    settings: &Settings,
    password: &str,
    cancel: Option<CancellationToken>,
) -> (ProbeReport, Vec<ProbeEvent>) {
    let (tx, _rx) = events::channel(64);
    let mut ctx = FtpContext::new(SessionId::next(), tx);
    if let Some(cancel) = cancel {
        ctx.cancel = cancel;
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let report = run(
        &options(server, password),
        ctx,
        settings,
        &ProbeOptions::with_timeout(Duration::from_secs(5)),
        move |e| sink.lock().unwrap().push(e),
    )
    .await;
    let seen = seen.lock().unwrap().clone();
    (report, seen)
}

async fn probe(config: ServerConfig) -> (ProbeReport, TestServer) {
    let server = TestServer::start(config).await;
    server.put("/home/bob/readme.txt", b"hello");
    let (report, _) = probe_with(&server, &Settings::default(), "secret", None).await;
    (report, server)
}

fn statuses(report: &ProbeReport) -> Vec<(ProbeStep, StepStatus)> {
    report.steps.iter().map(|s| (s.step, s.status)).collect()
}

fn step(report: &ProbeReport, step: ProbeStep) -> &StepResult {
    report.get(step).unwrap()
}

#[tokio::test]
async fn passive_and_active_both_work() {
    let server = TestServer::start(ServerConfig::default()).await;
    server.put("/home/bob/readme.txt", b"hello");
    let (report, events) = probe_with(&server, &Settings::default(), "secret", None).await;
    assert_eq!(
        statuses(&report),
        [
            (ProbeStep::Connect, StepStatus::Ok),
            (ProbeStep::PassiveAddress, StepStatus::Ok),
            (ProbeStep::Passive, StepStatus::Ok),
            (ProbeStep::ExternalAddress, StepStatus::Ok),
            (ProbeStep::Active, StepStatus::Ok),
        ],
        "{report:#?}"
    );
    assert!(
        step(&report, ProbeStep::Passive)
            .detail
            .contains("Passive mode works")
    );
    assert!(
        step(&report, ProbeStep::ExternalAddress)
            .detail
            .contains("local network")
    );
    assert_eq!(report.recommendation(), Recommendation::Passive);
    // Every step is announced, then reported, in order.
    let started: Vec<ProbeStep> = events
        .iter()
        .filter_map(|e| match e {
            ProbeEvent::Started(s) => Some(*s),
            ProbeEvent::Finished(_) => None,
        })
        .collect();
    assert_eq!(started, ProbeStep::ALL);
    assert!(matches!(events[0], ProbeEvent::Started(ProbeStep::Connect)));
    assert!(matches!(&events[1], ProbeEvent::Finished(r) if r.step == ProbeStep::Connect));
    // The commands: a bare PASV, then EPSV + LIST, EPRT + LIST.
    let cmds: Vec<String> = server
        .commands()
        .into_iter()
        .filter(|c| {
            ["PASV", "EPSV", "EPRT", "PORT", "LIST"]
                .contains(&c.split(' ').next().unwrap_or_default())
        })
        .collect();
    assert_eq!(cmds.len(), 5, "{cmds:?}");
    assert_eq!(cmds[0], "PASV");
    assert_eq!(cmds[1], "EPSV");
    assert_eq!(cmds[2], "LIST");
    assert!(cmds[3].starts_with("EPRT |1|127.0.0.1|"), "{cmds:?}");
    assert_eq!(cmds[4], "LIST");
    assert!(server.commands().contains(&"QUIT".to_owned()));
}

#[tokio::test]
async fn a_blocked_active_port_is_reported_with_the_fix() {
    let (report, _server) = probe(ServerConfig {
        active_blocked: true,
        ..ServerConfig::default()
    })
    .await;
    let active = step(&report, ProbeStep::Active);
    assert_eq!(active.status, StepStatus::Failed, "{report:#?}");
    assert!(
        active.detail.contains("could not connect back"),
        "{active:?}"
    );
    let advice = active.advice.as_deref().unwrap();
    assert!(advice.starts_with("Active mode failed: the server could not connect back."));
    assert!(advice.contains("use passive mode"));
    assert!(report.passive_works());
    assert!(!report.active_works());
    assert_eq!(report.recommendation(), Recommendation::Passive);
}

/// An in-process stand-in for an IP lookup service on 127.0.0.1: answers
/// every request with `response`. Returns its URL and the request count.
async fn fake_lookup(response: &'static str) -> (String, Arc<Mutex<usize>>) {
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/ip", listener.local_addr().unwrap());
    let hits = Arc::new(Mutex::new(0usize));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            *counter.lock().unwrap() += 1;
            let mut buf = [0u8; 1024];
            let _ = tcp.read(&mut buf).await;
            let _ = tcp.write_all(response.as_bytes()).await;
        }
    });
    (url, hits)
}

#[tokio::test]
async fn the_ip_lookup_url_is_tested() {
    let (url, hits) =
        fake_lookup("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n203.0.113.7\n").await;
    let server = TestServer::start(ServerConfig::default()).await;
    let mut settings = Settings::default();
    settings.ftp.active_external_ip = ExternalIp::FromUrl(url);
    let (report, _) = probe_with(&server, &settings, "secret", None).await;
    let ext = step(&report, ProbeStep::ExternalAddress);
    assert_eq!(ext.status, StepStatus::Ok, "{report:#?}");
    assert!(ext.detail.contains("returned 203.0.113.7"), "{ext:?}");
    assert!(*hits.lock().unwrap() >= 1);
    // A local server still gets the local address.
    assert!(report.active_works(), "{report:#?}");
}

#[tokio::test]
async fn a_failing_ip_lookup_is_reported() {
    let (url, _) = fake_lookup("HTTP/1.0 500 Internal Server Error\r\n\r\n").await;
    let server = TestServer::start(ServerConfig::default()).await;
    let mut settings = Settings::default();
    settings.ftp.active_external_ip = ExternalIp::FromUrl(url);
    let (report, _) = probe_with(&server, &settings, "secret", None).await;
    let ext = step(&report, ProbeStep::ExternalAddress);
    assert_eq!(ext.status, StepStatus::Warning, "{report:#?}");
    assert!(ext.detail.contains("IP lookup failed"), "{ext:?}");
    assert!(ext.advice.as_deref().unwrap().contains("lookup URL"));
    assert!(report.active_works(), "{report:#?}");
}

#[tokio::test]
async fn a_blocked_active_port_range_names_the_ports_to_forward() {
    let server = TestServer::start(ServerConfig {
        active_blocked: true,
        ..ServerConfig::default()
    })
    .await;
    let mut settings = Settings::default();
    settings.ftp.active_port_range = Some((50_000, 50_100));
    let (report, _) = probe_with(&server, &settings, "secret", None).await;
    let advice = step(&report, ProbeStep::Active).advice.clone().unwrap();
    assert!(advice.contains("forward TCP ports 50000-50100"), "{advice}");
}

#[tokio::test]
async fn the_active_port_range_is_used() {
    let server = TestServer::start(ServerConfig::default()).await;
    // A free range: bind a port and use it and the next few.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut settings = Settings::default();
    settings.ftp.active_port_range = Some((port, port.saturating_add(3)));
    let (report, _) = probe_with(&server, &settings, "secret", None).await;
    assert!(report.active_works(), "{report:#?}");
    let eprt = server
        .commands()
        .into_iter()
        .find(|c| c.starts_with("EPRT"))
        .unwrap();
    let announced: u16 = eprt
        .trim_end_matches('|')
        .rsplit('|')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!((port..=port + 3).contains(&announced), "{eprt}");
}

#[tokio::test]
async fn a_blocked_passive_port_suggests_active_mode() {
    let (report, _server) = probe(ServerConfig {
        epsv_feat: false,
        pasv_dead_port: true,
        ..ServerConfig::default()
    })
    .await;
    let passive = step(&report, ProbeStep::Passive);
    assert_eq!(passive.status, StepStatus::Failed, "{report:#?}");
    assert!(
        passive
            .advice
            .as_deref()
            .unwrap()
            .contains("Try active mode"),
        "{passive:?}"
    );
    assert!(report.active_works());
    assert_eq!(report.recommendation(), Recommendation::Active);
}

#[tokio::test]
async fn a_server_refusing_passive_mode() {
    let (report, _server) = probe(ServerConfig {
        refuse_epsv: true,
        refuse_pasv: true,
        ..ServerConfig::default()
    })
    .await;
    assert_eq!(
        step(&report, ProbeStep::PassiveAddress).status,
        StepStatus::Ok,
        "EPSV is announced, so a refused PASV alone is fine"
    );
    let passive = step(&report, ProbeStep::Passive);
    assert_eq!(passive.status, StepStatus::Failed);
    assert!(
        passive.detail.contains("refused passive mode"),
        "{passive:?}"
    );
    assert_eq!(report.recommendation(), Recommendation::Active);
}

#[tokio::test]
async fn neither_mode_working() {
    let (report, _server) = probe(ServerConfig {
        epsv_feat: false,
        pasv_dead_port: true,
        active_blocked: true,
        ..ServerConfig::default()
    })
    .await;
    assert_eq!(report.recommendation(), Recommendation::Neither);
}

#[tokio::test]
async fn a_server_announcing_another_passive_address() {
    // EPSV still works (it carries no address).
    let (report, _server) = probe(ServerConfig {
        pasv_ip: Some(Ipv4Addr::new(10, 9, 8, 7)),
        ..ServerConfig::default()
    })
    .await;
    let address = step(&report, ProbeStep::PassiveAddress);
    assert_eq!(address.status, StepStatus::Warning, "{report:#?}");
    assert!(address.detail.contains("10.9.8.7"), "{address:?}");
    assert!(report.passive_works());
}

#[tokio::test]
async fn a_wrong_password_skips_the_rest() {
    let server = TestServer::start(ServerConfig::default()).await;
    let (report, _) = probe_with(&server, &Settings::default(), "wrong", None).await;
    let connect = step(&report, ProbeStep::Connect);
    assert_eq!(connect.status, StepStatus::Failed);
    assert_eq!(
        connect.advice.as_deref(),
        Some("Check the user name and password.")
    );
    assert_eq!(report.steps.len(), 5);
    assert!(
        report.steps[1..]
            .iter()
            .all(|s| s.status == StepStatus::Skipped && s.detail == "Not run: could not log in.")
    );
    assert_eq!(report.recommendation(), Recommendation::Unknown);
}

#[tokio::test]
async fn nothing_listening() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut opts = FtpOptions::new(
        HostPort::new("127.0.0.1", port),
        LogonType::Anonymous,
        &Settings::default(),
    );
    opts.timeout = Duration::from_secs(5);
    opts.net.timeout = Duration::from_secs(5);
    let (tx, _rx) = events::channel(16);
    let report = run(
        &opts,
        FtpContext::new(SessionId::next(), tx),
        &Settings::default(),
        &ProbeOptions::default(),
        |_| {},
    )
    .await;
    let connect = step(&report, ProbeStep::Connect);
    assert_eq!(connect.status, StepStatus::Failed, "{connect:?}");
    assert!(
        connect
            .advice
            .as_deref()
            .unwrap()
            .contains("address and port")
    );
}

#[tokio::test]
async fn cancelled_before_it_starts() {
    let server = TestServer::start(ServerConfig::default()).await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let (report, _) = probe_with(&server, &Settings::default(), "secret", Some(cancel)).await;
    assert!(
        report.steps.iter().all(|s| s.status == StepStatus::Skipped),
        "{report:#?}"
    );
    assert_eq!(report.steps[1].detail, "Cancelled.");
}

// ---- NAT detection

fn sock(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[test]
fn server_behind_nat() {
    let public_peer = sock("203.0.114.5:21");
    // A private PASV address from a public server: NAT.
    let r = analyze_pasv("192.168.1.10:5000".parse().unwrap(), public_peer, true);
    assert_eq!(r.status, StepStatus::Warning);
    assert!(r.detail.contains("behind NAT"), "{r:?}");
    assert!(r.detail.contains("192.168.1.10"));
    assert!(r.advice.as_deref().unwrap().contains("is on"));
    let r = analyze_pasv("192.168.1.10:5000".parse().unwrap(), public_peer, false);
    assert!(r.advice.as_deref().unwrap().starts_with("Turn on"));
    // Its own address: fine.
    let r = analyze_pasv("203.0.114.5:5000".parse().unwrap(), public_peer, false);
    assert_eq!(r.status, StepStatus::Ok);
    // IPv4-mapped peer counts as the same address.
    let r = analyze_pasv(
        "203.0.114.5:5000".parse().unwrap(),
        sock("[::ffff:203.0.114.5]:21"),
        false,
    );
    assert_eq!(r.status, StepStatus::Ok, "{r:?}");
    // 0.0.0.0 is always replaced.
    let r = analyze_pasv("0.0.0.0:5000".parse().unwrap(), public_peer, false);
    assert_eq!(r.status, StepStatus::Ok);
    // A LAN server announcing another LAN address: no NAT, but odd.
    let r = analyze_pasv("10.0.0.7:5000".parse().unwrap(), sock("10.0.0.5:21"), true);
    assert_eq!(r.status, StepStatus::Warning);
    assert!(!r.detail.contains("NAT"), "{r:?}");
}

#[test]
fn client_behind_nat() {
    let local: IpAddr = "192.168.1.20".parse().unwrap();
    let public_local: IpAddr = "198.51.99.20".parse().unwrap();
    let public_peer: IpAddr = "203.0.114.5".parse().unwrap();
    let lan_peer: IpAddr = "192.168.1.1".parse().unwrap();

    // Ask the OS behind NAT: the private address would be announced.
    let r = analyze_external(local, public_peer, &ExternalIp::Auto, None);
    assert_eq!(r.status, StepStatus::Warning);
    assert!(r.detail.contains("behind NAT"), "{r:?}");
    assert!(r.advice.as_deref().unwrap().contains("Use this IP"));
    // Not behind NAT.
    let r = analyze_external(public_local, public_peer, &ExternalIp::Auto, None);
    assert_eq!(r.status, StepStatus::Ok);
    // A LAN server gets the local address whatever the setting.
    let fixed = ExternalIp::Fixed("198.51.99.1".parse().unwrap());
    let r = analyze_external(local, lan_peer, &fixed, None);
    assert_eq!(r.status, StepStatus::Ok);
    assert!(r.detail.contains("local network"));
    // A fixed address behind NAT: announced, with the forwarding hint.
    let r = analyze_external(local, public_peer, &fixed, None);
    assert_eq!(r.status, StepStatus::Ok);
    assert!(r.detail.contains("198.51.99.1 is announced"));
    assert!(r.advice.is_some());
    // From a URL: the lookup's answer tells whether there is NAT.
    let url = ExternalIp::FromUrl("http://127.0.0.1:1/ip".into());
    let r = analyze_external(local, public_peer, &url, Some(Ok(public_local)));
    assert_eq!(r.status, StepStatus::Ok);
    assert!(r.detail.contains("behind NAT"), "{r:?}");
    let r = analyze_external(public_local, public_peer, &url, Some(Ok(public_local)));
    assert!(r.detail.contains("no NAT"), "{r:?}");
    let r = analyze_external(local, public_peer, &url, Some(Err("timed out".into())));
    assert_eq!(r.status, StepStatus::Failed);
    // IPv6 has no NAT.
    let r = analyze_external(
        "2001:db8::2".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        &ExternalIp::Auto,
        None,
    );
    assert_eq!(r.status, StepStatus::Ok);
}
