//! Direct dials: real loopback connections, Status lines, Happy Eyeballs timing,
//! timeout, cancellation and drop (mock dialers under paused time).

use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::{drain, echo_server, opts, round_trip, session_log};
use crate::{
    Error,
    events::LogKind,
    net::{
        HostPort, ProxyConfig, Purpose, connect_tcp,
        dial::{cancellable, race},
        local_addr_for,
    },
};

#[tokio::test]
async fn direct_connect_ipv4_ipv6_and_hostname() {
    let (log, _rx) = session_log();
    let v4 = echo_server("127.0.0.1:0").await.unwrap();
    let mut s = connect_tcp(
        &HostPort::new("127.0.0.1", v4.port()),
        &opts(ProxyConfig::Direct),
        CancellationToken::new(),
        &log,
    )
    .await
    .unwrap();
    round_trip(&mut s, b"hello v4").await;
    assert_eq!(s.peer_addr(), v4);
    assert_eq!(s.target_ip(), Some(v4.ip()));
    assert!(!s.is_proxied());
    assert_eq!(local_addr_for(&s).ip(), v4.ip());
    s.set_socket_buffer(256 * 1024);
    round_trip(&mut s, b"after buffer change").await;

    let mut by_name = connect_tcp(
        &HostPort::new("localhost", v4.port()),
        &opts(ProxyConfig::Direct),
        CancellationToken::new(),
        &log,
    )
    .await
    .unwrap();
    round_trip(&mut by_name, b"hello localhost").await;

    match echo_server("[::1]:0").await {
        None => eprintln!("skipped ::1: this host has no IPv6 loopback"),
        Some(v6) => {
            let mut s = connect_tcp(
                &HostPort::new("::1", v6.port()),
                &opts(ProxyConfig::Direct),
                CancellationToken::new(),
                &log,
            )
            .await
            .unwrap();
            round_trip(&mut s, b"hello v6").await;
            assert_eq!(s.target_ip(), Some(v6.ip()));
        }
    }
}

#[tokio::test]
async fn data_purpose_and_buffer_options() {
    let (log, _rx) = session_log();
    let v4 = echo_server("127.0.0.1:0").await.unwrap();
    let mut o = opts(ProxyConfig::Direct);
    o.purpose = Purpose::Data;
    o.socket_buffer = Some(4 * 1024 * 1024);
    let mut s = connect_tcp(
        &HostPort::new("127.0.0.1", v4.port()),
        &o,
        CancellationToken::new(),
        &log,
    )
    .await
    .unwrap();
    round_trip(&mut s, b"data").await;
}

#[tokio::test]
async fn status_lines_logged() {
    let (log, mut rx) = session_log();
    let v4 = echo_server("127.0.0.1:0").await.unwrap();
    let mut o = opts(ProxyConfig::Direct);
    o.allow_ipv6 = false;
    let _s = connect_tcp(
        &HostPort::new("localhost", v4.port()),
        &o,
        CancellationToken::new(),
        &log,
    )
    .await
    .unwrap();
    let seen = drain(&mut rx);
    assert_eq!(
        seen.status(),
        [
            "Resolving address of localhost".to_owned(),
            format!("Connecting to 127.0.0.1:{}...", v4.port()),
            "Connection established".to_owned(),
        ]
    );
}

#[tokio::test]
async fn refused_connection_is_connection_error() {
    let (log, mut rx) = session_log();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let err = connect_tcp(
        &HostPort::new("127.0.0.1", port),
        &opts(ProxyConfig::Direct),
        CancellationToken::new(),
        &log,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, Error::Connection(m) if m.starts_with(&format!("could not connect to 127.0.0.1:{port}: "))),
        "{err:?}"
    );
    assert!(err.is_transient());
    let seen = drain(&mut rx);
    assert!(
        seen.logs.iter().any(|(k, t)| *k == LogKind::Debug(2)
            && t.starts_with(&format!("Connection attempt to 127.0.0.1:{port} failed: "))),
        "{seen:?}"
    );
}

#[tokio::test]
async fn unresolvable_host_is_connection_error() {
    let (log, _rx) = session_log();
    let err = connect_tcp(
        &HostPort::new("does-not-exist.invalid", 21),
        &opts(ProxyConfig::Direct),
        CancellationToken::new(),
        &log,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, Error::Connection(m) if m == "could not resolve does-not-exist.invalid")
            || matches!(err, Error::Timeout),
        "{err:?}"
    );
}

/// A mock attempt: hang forever, or succeed after a delay.
#[derive(Clone, Copy)]
enum Plan {
    Hang,
    SucceedAfter(Duration),
}

/// Records attempt start times (virtual time) and plays the plans.
#[derive(Clone)]
struct Mock {
    plans: Vec<(SocketAddr, Plan)>,
    started: Arc<Mutex<Vec<(SocketAddr, Duration)>>>,
    t0: Instant,
}

impl Mock {
    fn new(plans: &[(SocketAddr, Plan)]) -> Self {
        Self {
            plans: plans.to_vec(),
            started: Arc::default(),
            t0: Instant::now(),
        }
    }

    fn dial(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<SocketAddr>> + Send + 'static {
        self.started.lock().unwrap().push((addr, self.t0.elapsed()));
        let plan = self
            .plans
            .iter()
            .find(|(a, _)| *a == addr)
            .map_or(Plan::Hang, |(_, p)| *p);
        async move {
            match plan {
                Plan::Hang => std::future::pending().await,
                Plan::SucceedAfter(d) => {
                    tokio::time::sleep(d).await;
                    Ok(addr)
                }
            }
        }
    }

    fn started(&self) -> Vec<(SocketAddr, Duration)> {
        self.started.lock().unwrap().clone()
    }
}

fn a(last: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, last], 21))
}

fn target() -> HostPort {
    HostPort::new("ftp.example.com", 21)
}

#[tokio::test(start_paused = true)]
async fn happy_eyeballs_stagger_250ms() {
    let (log, mut rx) = session_log();
    let mock = Mock::new(&[
        (a(1), Plan::Hang),
        (a(2), Plan::SucceedAfter(Duration::from_millis(10))),
    ]);
    let t0 = Instant::now();
    let (won, addr) = race(
        &target(),
        &[a(1), a(2)],
        Duration::from_secs(20),
        &log,
        |x| mock.dial(x),
    )
    .await
    .unwrap();
    assert_eq!((won, addr), (a(2), a(2)));
    assert_eq!(t0.elapsed(), Duration::from_millis(260));
    assert_eq!(
        mock.started(),
        [(a(1), Duration::ZERO), (a(2), Duration::from_millis(250))]
    );
    assert_eq!(
        drain(&mut rx).status(),
        [
            "Connecting to 192.0.2.1:21...",
            "Connecting to 192.0.2.2:21..."
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn dial_timeout_returns_timeout() {
    let (log, mut rx) = session_log();
    let mock = Mock::new(&[(a(1), Plan::Hang), (a(2), Plan::Hang)]);
    let t0 = Instant::now();
    let err = race(
        &target(),
        &[a(1), a(2)],
        Duration::from_secs(5),
        &log,
        |x| mock.dial(x),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err:?}");
    let elapsed = t0.elapsed();
    assert!(
        elapsed >= Duration::from_millis(4900) && elapsed <= Duration::from_millis(5100),
        "{elapsed:?}"
    );
    assert_eq!(mock.started().len(), 2);
    assert_eq!(
        drain(&mut rx).status().last().copied(),
        Some("Connection timed out after 5 seconds")
    );
}

#[tokio::test(start_paused = true)]
async fn cancel_token_returns_cancelled() {
    let (log, _rx) = session_log();
    let mock = Mock::new(&[(a(1), Plan::Hang)]);
    let cancel = CancellationToken::new();
    let firer = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        firer.cancel();
    });
    let t0 = Instant::now();
    let err = cancellable(
        &cancel,
        race(&target(), &[a(1)], Duration::from_secs(20), &log, |x| {
            mock.dial(x)
        }),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Cancelled), "{err:?}");
    assert!(
        t0.elapsed() <= Duration::from_millis(1100),
        "{:?}",
        t0.elapsed()
    );
}

/// A proxy that accepts and never answers: the dial hangs in the handshake.
async fn silent_proxy() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            held.push(s);
        }
    });
    addr
}

fn via_silent(addr: SocketAddr) -> ProxyConfig {
    ProxyConfig::Http {
        proxy: HostPort::new("127.0.0.1", addr.port()),
        auth: None,
    }
}

#[tokio::test]
async fn cancel_token_cancels_a_real_handshake() {
    let (log, _rx) = session_log();
    let proxy = silent_proxy().await;
    let cancel = CancellationToken::new();
    let firer = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        firer.cancel();
    });
    let t0 = std::time::Instant::now();
    let err = connect_tcp(&target(), &opts(via_silent(proxy)), cancel, &log)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Cancelled), "{err:?}");
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
}

#[tokio::test]
async fn dropped_dial_leaves_no_tasks() {
    let (log, _rx) = session_log();
    let proxy = silent_proxy().await;
    tokio::task::yield_now().await;
    let metrics = tokio::runtime::Handle::current().metrics();
    let baseline = metrics.num_alive_tasks();
    let o = opts(via_silent(proxy));
    let t = target();
    let dial = connect_tcp(&t, &o, CancellationToken::new(), &log);
    let res = tokio::time::timeout(Duration::from_millis(200), dial).await;
    assert!(res.is_err(), "the handshake should still hang");
    // The future is dropped by `timeout`; nothing it started may still run.
    assert_eq!(metrics.num_alive_tasks(), baseline);
}

#[tokio::test]
#[ignore = "depends on the CI network (blackhole address)"]
async fn blackhole_connect_times_out() {
    let (log, _rx) = session_log();
    let mut o = opts(ProxyConfig::Direct);
    o.timeout = Duration::from_secs(2);
    let t0 = std::time::Instant::now();
    let err = connect_tcp(
        &HostPort::new("10.255.255.1", 9),
        &o,
        CancellationToken::new(),
        &log,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err:?}");
    let elapsed = t0.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1900) && elapsed <= Duration::from_millis(2500),
        "{elapsed:?}"
    );
}
