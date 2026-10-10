//! The transfer sequence against the scripted [`FakeServer`] over loopback TCP (real
//! time: paused time would fire the timeouts while loopback I/O is in flight).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use courier_ftp_core::{
    events::{CoreEvent, LogKind, LogMessage, SessionId, channel},
    model::Charset,
    net::{HostPort, NetOpts, ProxyConfig, Purpose},
    settings::{DebugLevel, KeepaliveCommand},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};

use super::*;
use crate::{
    active::REJECTED_PEER,
    control::{ControlParams, Phase},
    data::DEFAULT_SOCKET_BUFFER,
    passive::{DIFFERENT_REPLACED, UNROUTABLE_REPLACED},
    testing::{FakeServer, Step, Transcript, pattern_bytes},
};

// ---- harness --------------------------------------------------------------------------

struct Env {
    conn: ControlConnection,
    server: FakeServer,
    logs: Arc<Mutex<Vec<LogMessage>>>,
    _task: JoinHandle<()>,
}

impl Env {
    async fn new(script: Vec<Step>) -> Self {
        Self::on(SocketAddr::from(([127, 0, 0, 1], 0)), script)
            .await
            .expect("loopback")
    }

    /// `None` when `bind` is not available (no IPv6 loopback).
    async fn on(bind: SocketAddr, script: Vec<Step>) -> Option<Self> {
        let mut full = vec![Step::Reply("220 fake ready")];
        full.extend(script);
        let (server, addr) = FakeServer::tcp_on(bind, full).await.ok()?;
        let (events, mut rx) = channel(DebugLevel::Debug);
        let logs = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&logs);
        let task = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let CoreEvent::Log(m) = event {
                    sink.lock().unwrap().push(m);
                }
            }
        });
        let log = SessionLog {
            events,
            session: SessionId::next(),
        };
        let p = ControlParams {
            target: HostPort::new(addr.ip().to_string(), addr.port()),
            server_name: "fake.test".into(),
            net: net_opts(),
            charset: Charset::Auto,
            timeout: Duration::from_secs(5),
            keepalive_command: KeepaliveCommand::Noop,
            log,
        };
        let (mut conn, _) = ControlConnection::connect(p, None, &CancellationToken::new())
            .await
            .expect("connect");
        conn.phase = Phase::Ready;
        Some(Self {
            conn,
            server,
            logs,
            _task: task,
        })
    }

    fn data<'a>(&'a mut self, cfg: &'a DataConfig, state: &'a mut DataState) -> FtpData<'a> {
        FtpData {
            ctrl: &mut self.conn,
            cfg,
            state,
        }
    }

    async fn lines(&self, kind: LogKind) -> Vec<String> {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        self.logs
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.kind == kind)
            .map(|m| m.text.clone())
            .collect()
    }

    async fn all_lines(&self) -> Vec<String> {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        self.logs
            .lock()
            .unwrap()
            .iter()
            .map(|m| m.text.clone())
            .collect()
    }

    async fn done(self) -> Transcript {
        drop(self.conn);
        self.server.finish().await
    }
}

fn net_opts() -> NetOpts {
    NetOpts {
        timeout: Duration::from_secs(3),
        prefer_ipv6: false,
        allow_ipv6: true,
        purpose: Purpose::Data,
        socket_buffer: None,
        proxy: ProxyConfig::Direct,
    }
}

fn cfg() -> DataConfig {
    DataConfig {
        mode: DataMode::Passive,
        fallback_to_active: false,
        ignore_unroutable_pasv_ip: true,
        external_ip: ActiveExternalIp::Auto,
        no_external_ip_on_local: true,
        port_range: None,
        through_generic_proxy: false,
        net: net_opts(),
        control_host: "127.0.0.1".into(),
        timeout: Duration::from_secs(5),
        socket_buffer: DEFAULT_SOCKET_BUFFER,
    }
}

fn active_cfg() -> DataConfig {
    DataConfig {
        mode: DataMode::Active,
        ..cfg()
    }
}

fn token() -> CancellationToken {
    CancellationToken::new()
}

fn retr(path: &str) -> TransferCommand {
    TransferCommand::Retr {
        path: path.into(),
        offset: 0,
        range_len: None,
    }
}

/// open + read to EOF + finish.
async fn download(d: &mut FtpData<'_>, cmd: TransferCommand, ty: TransferType) -> Vec<u8> {
    let mut s = d.open(cmd, ty, None, &token()).await.expect("open");
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.expect("read");
    d.finish(Some(s), &token()).await.expect("finish");
    out
}

/// A served download: `150`, the bytes, close, `226`.
fn serve(bytes: Vec<u8>) -> Vec<Step> {
    vec![
        Step::Reply("150 Opening BINARY mode data connection"),
        Step::SendData(bytes),
        Step::CloseData,
        Step::Reply("226 Transfer complete"),
    ]
}

fn script(parts: Vec<Vec<Step>>) -> Vec<Step> {
    parts.into_iter().flatten().collect()
}

fn type_i() -> Vec<Step> {
    vec![
        Step::Expect("TYPE I"),
        Step::Reply("200 Switching to Binary mode."),
    ]
}

fn port_line(t: &Transcript) -> String {
    t.received
        .iter()
        .find(|l| l.starts_with("PORT ") || l.starts_with("EPRT "))
        .cloned()
        .unwrap_or_else(|| panic!("no PORT/EPRT\n{t}"))
}

/// A port number that nothing listens on.
async fn closed_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

// ---- TYPE -----------------------------------------------------------------------------

#[tokio::test]
async fn ensure_type_sends_type_only_on_change() {
    let mut e = Env::new(vec![
        Step::Expect("TYPE I"),
        Step::Reply("200 Switching to Binary mode."),
        Step::Expect("TYPE A"),
        Step::Reply("200 Switching to ASCII mode."),
        Step::Expect("TYPE I"),
        Step::Reply("504 nope"),
    ])
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    d.ensure_type(TransferType::Binary, &token()).await.unwrap();
    d.ensure_type(TransferType::Binary, &token()).await.unwrap();
    d.ensure_type(TransferType::Ascii, &token()).await.unwrap();
    d.ensure_type(TransferType::Ascii, &token()).await.unwrap();
    assert_eq!(d.ctrl.current_type(), Some(TransferType::Ascii));
    let err = d
        .ensure_type(TransferType::Binary, &token())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Protocol {
                code: Some(504),
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(d.ctrl.current_type(), None);
    e.done().await;
}

#[tokio::test]
async fn ascii_resume_refused() {
    let mut e = Env::new(vec![]).await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let cmd = TransferCommand::Retr {
        path: "a.txt".into(),
        offset: 10,
        range_len: None,
    };
    let err = d
        .open(cmd, TransferType::Ascii, None, &token())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Unsupported(m) if m == "resume is not possible in ASCII mode"),
        "{err:?}"
    );
    assert!(
        e.lines(LogKind::Status)
            .await
            .iter()
            .any(|l| l.contains("ASCII mode"))
    );
    e.done().await;
}

#[tokio::test]
async fn ascii_download_and_upload_convert_line_ends() {
    let mut e = Env::new(script(vec![
        vec![
            Step::Expect("TYPE A"),
            Step::Reply("200 Switching to ASCII mode."),
            Step::EpsvListen,
            Step::Expect("RETR a.txt"),
        ],
        serve(b"one\r\ntwo\r\n".to_vec()),
        vec![
            Step::EpsvListen,
            Step::Expect("STOR b.txt"),
            Step::Reply("150 Ok to send data."),
            Step::RecvData(if cfg!(windows) {
                b"x\ny\r\n".to_vec()
            } else {
                b"x\r\ny\r\n".to_vec()
            }),
            Step::Reply("226 Transfer complete."),
        ],
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let got = download(&mut d, retr("a.txt"), TransferType::Ascii).await;
    let want: &[u8] = if cfg!(windows) {
        b"one\r\ntwo\r\n"
    } else {
        b"one\ntwo\n"
    };
    assert_eq!(got, want);
    let stor = TransferCommand::Stor {
        path: "b.txt".into(),
        offset: 0,
    };
    let mut s = d
        .open(stor, TransferType::Ascii, None, &token())
        .await
        .unwrap();
    s.write_all(b"x\ny\r\n").await.unwrap();
    d.finish(Some(s), &token()).await.unwrap();
    e.done().await;
}

// ---- modes ----------------------------------------------------------------------------

#[tokio::test]
async fn retr_via_epsv() {
    let body = pattern_bytes(0, 300_000);
    let mut e = Env::new(script(vec![
        type_i(),
        vec![Step::EpsvListen, Step::Expect("RETR file.bin")],
        serve(body.clone()),
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let got = download(&mut d, retr("file.bin"), TransferType::Binary).await;
    assert_eq!(got.len(), body.len());
    assert!(got == body);
    assert_eq!(d.ctrl.state(), ControlState::Ready);
    e.done().await;
}

#[tokio::test]
async fn retr_via_pasv_when_epsv_rejected() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::Expect("EPSV"),
            Step::Reply("500 Unknown command."),
            Step::PasvListen,
            Step::Expect("RETR one"),
        ],
        serve(b"first".to_vec()),
        // Remembered: the second transfer goes straight to PASV.
        vec![Step::PasvListen, Step::Expect("RETR two")],
        serve(b"second".to_vec()),
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    assert_eq!(
        download(&mut d, retr("one"), TransferType::Binary).await,
        b"first"
    );
    assert_eq!(
        download(&mut d, retr("two"), TransferType::Binary).await,
        b"second"
    );
    assert!(st.epsv_failed);
    e.done().await;
}

#[tokio::test]
async fn retr_via_port() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![Step::ExpectPortThenConnect, Step::Expect("RETR file")],
        serve(b"active data".to_vec()),
    ]))
    .await;
    let cfg = active_cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    assert_eq!(
        download(&mut d, retr("file"), TransferType::Binary).await,
        b"active data"
    );
    let t = e.done().await;
    assert!(port_line(&t).starts_with("PORT 127,0,0,1,"), "{t}");
}

#[tokio::test]
async fn port_refused_falls_back_to_eprt() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::ExpectPrefix("PORT 127,0,0,1,"),
            Step::Reply("502 PORT not implemented"),
            Step::ExpectPortThenConnect,
            Step::Expect("RETR file"),
        ],
        serve(b"x".to_vec()),
    ]))
    .await;
    let cfg = active_cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    assert_eq!(
        download(&mut d, retr("file"), TransferType::Binary).await,
        b"x"
    );
    let t = e.done().await;
    assert!(
        t.received
            .iter()
            .any(|l| l.starts_with("EPRT |1|127.0.0.1|")),
        "{t}"
    );
}

#[tokio::test]
async fn retr_via_eprt_ipv6_loopback() {
    let Some(mut e) = Env::on(
        "[::1]:0".parse().unwrap(),
        script(vec![
            type_i(),
            vec![Step::ExpectPortThenConnect, Step::Expect("RETR v6")],
            serve(b"over ipv6".to_vec()),
        ]),
    )
    .await
    else {
        eprintln!("skipped: no IPv6 loopback");
        return;
    };
    let cfg = active_cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    assert_eq!(
        download(&mut d, retr("v6"), TransferType::Binary).await,
        b"over ipv6"
    );
    let t = e.done().await;
    assert!(port_line(&t).starts_with("EPRT |2|::1|"), "{t}");
}

#[tokio::test]
async fn retr_via_epsv_ipv6_loopback() {
    let Some(mut e) = Env::on(
        "[::1]:0".parse().unwrap(),
        script(vec![
            type_i(),
            vec![Step::EpsvListen, Step::Expect("RETR v6")],
            serve(b"passive ipv6".to_vec()),
        ]),
    )
    .await
    else {
        eprintln!("skipped: no IPv6 loopback");
        return;
    };
    let cfg = cfg();
    // EPSV is mandatory over IPv6, even after it "failed" for IPv4.
    let mut st = DataState {
        epsv_failed: true,
        ..DataState::default()
    };
    let mut d = e.data(&cfg, &mut st);
    assert_eq!(
        download(&mut d, retr("v6"), TransferType::Binary).await,
        b"passive ipv6"
    );
    e.done().await;
}

// ---- PASV address rules ---------------------------------------------------------------

fn pasv_as(ip: Ipv4Addr, path: &'static str) -> Vec<Step> {
    vec![
        Step::Expect("EPSV"),
        Step::Reply("502 EPSV not implemented"),
        Step::PasvListenAs(ip),
        Step::Expect(path),
    ]
}

#[tokio::test]
async fn pasv_unroutable_ip_replaced_by_peer() {
    let mut e = Env::new(script(vec![
        type_i(),
        pasv_as(Ipv4Addr::new(10, 1, 2, 3), "RETR f"),
        serve(b"ok".to_vec()),
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    assert_eq!(
        download(&mut d, retr("f"), TransferType::Binary).await,
        b"ok"
    );
    let status = e.lines(LogKind::Status).await;
    assert!(
        status.iter().any(|l| l == UNROUTABLE_REPLACED),
        "{status:?}"
    );
    e.done().await;
}

#[tokio::test]
async fn pasv_unroutable_kept_when_setting_off() {
    // 127.0.0.2 is unroutable and differs from the peer (127.0.0.1); nothing listens
    // there, so keeping the address makes the data connection fail.
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::Expect("EPSV"),
            Step::Reply("502 EPSV not implemented"),
            Step::PasvListenAs(Ipv4Addr::new(127, 0, 0, 2)),
        ],
    ]))
    .await;
    let mut cfg = cfg();
    cfg.ignore_unroutable_pasv_ip = false;
    cfg.net.timeout = Duration::from_millis(500);
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let err = d
        .open(retr("f"), TransferType::Binary, None, &token())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Connection(_) | Error::Timeout),
        "{err:?}"
    );
    let lines = e.all_lines().await;
    assert!(!lines.iter().any(|l| l == UNROUTABLE_REPLACED), "{lines:?}");
    assert!(lines.iter().any(|l| l.contains("127.0.0.2")), "{lines:?}");
    e.done().await;
}

#[tokio::test]
async fn pasv_foreign_routable_ip_replaced() {
    let mut e = Env::new(script(vec![
        type_i(),
        pasv_as(Ipv4Addr::new(203, 0, 113, 9), "RETR f"),
        serve(b"ok".to_vec()),
    ]))
    .await;
    let mut cfg = cfg();
    cfg.ignore_unroutable_pasv_ip = false;
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    assert_eq!(
        download(&mut d, retr("f"), TransferType::Binary).await,
        b"ok"
    );
    let status = e.lines(LogKind::Status).await;
    assert!(status.iter().any(|l| l == DIFFERENT_REPLACED), "{status:?}");
    e.done().await;
}

#[tokio::test]
async fn invalid_pasv_reply_is_protocol_227() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::Expect("EPSV"),
            Step::Reply("502 no"),
            Step::Expect("PASV"),
            Step::Reply("227 Entering Passive Mode (1,2,3,4,5)"),
        ],
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let err = d
        .open(retr("f"), TransferType::Binary, None, &token())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Protocol {
                code: Some(227),
                ..
            }
        ),
        "{err:?}"
    );
    e.done().await;
}

// ---- fallback -------------------------------------------------------------------------

#[tokio::test]
async fn passive_failure_falls_back_to_active_and_remembers() {
    let dead = closed_port().await;
    let [p1, p2] = dead.to_be_bytes();
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::Expect("EPSV"),
            Step::Reply("502 EPSV not implemented"),
            Step::Expect("PASV"),
            Step::ReplyText(format!("227 Entering Passive Mode (127,0,0,1,{p1},{p2})")),
            Step::ExpectPortThenConnect,
            Step::Expect("RETR one"),
        ],
        serve(b"first".to_vec()),
        vec![Step::ExpectPortThenConnect, Step::Expect("RETR two")],
        serve(b"second".to_vec()),
    ]))
    .await;
    let mut cfg = cfg();
    cfg.fallback_to_active = true;
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    assert_eq!(
        download(&mut d, retr("one"), TransferType::Binary).await,
        b"first"
    );
    assert!(d.state.use_active);
    assert_eq!(
        download(&mut d, retr("two"), TransferType::Binary).await,
        b"second"
    );
    let status = e.lines(LogKind::Status).await;
    assert_eq!(
        status.iter().filter(|l| *l == FALLBACK_STATUS).count(),
        1,
        "{status:?}"
    );
    e.done().await;
}

#[tokio::test]
async fn passive_failure_without_fallback_is_an_error() {
    let dead = closed_port().await;
    let [p1, p2] = dead.to_be_bytes();
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::Expect("EPSV"),
            Step::Reply("502 EPSV not implemented"),
            Step::Expect("PASV"),
            Step::ReplyText(format!("227 Entering Passive Mode (127,0,0,1,{p1},{p2})")),
        ],
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let err = d
        .open(retr("f"), TransferType::Binary, None, &token())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Connection(m) if m.starts_with("Failed to open data connection")),
        "{err:?}"
    );
    assert!(!st.use_active);
    e.done().await;
}

// ---- active ---------------------------------------------------------------------------

#[tokio::test]
async fn active_port_range_respected() {
    let lo = 41_000 + fastrand::u16(0..20_000);
    let hi = lo + 9;
    let mut e = Env::new(script(vec![
        type_i(),
        vec![Step::ExpectPortThenConnect, Step::Expect("RETR f")],
        serve(b"r".to_vec()),
    ]))
    .await;
    let mut cfg = active_cfg();
    cfg.port_range = Some((lo, hi));
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    assert_eq!(
        download(&mut d, retr("f"), TransferType::Binary).await,
        b"r"
    );
    let t = e.done().await;
    let line = port_line(&t);
    let addr = parse_pasv(line.trim_start_matches("PORT ")).unwrap();
    assert!(
        (lo..=hi).contains(&addr.port()),
        "{line} not in {lo}..={hi}"
    );
}

#[tokio::test]
async fn active_port_range_exhausted() {
    let blocker = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = blocker.local_addr().unwrap().port();
    let err = bind_listener(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some((port, port)),
        DEFAULT_SOCKET_BUFFER,
    )
    .unwrap_err();
    assert!(
        matches!(&err, Error::Connection(m) if m.starts_with("no free port in active mode port range")),
        "{err:?}"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn active_rejects_foreign_peer() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::ExpectPortThenConnect,
            Step::Expect("RETR f"),
            Step::DataConnectFrom(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        ],
        serve(b"legit".to_vec()),
    ]))
    .await;
    let cfg = active_cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    assert_eq!(
        download(&mut d, retr("f"), TransferType::Binary).await,
        b"legit"
    );
    let status = e.lines(LogKind::Status).await;
    assert!(status.iter().any(|l| l == REJECTED_PEER), "{status:?}");
    e.done().await;
}

#[tokio::test]
async fn active_through_proxy_unsupported() {
    let mut e = Env::new(vec![]).await;
    let mut cfg = active_cfg();
    cfg.through_generic_proxy = true;
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    d.ctrl.set_current_type(Some(TransferType::Binary));
    let err = d
        .open(retr("f"), TransferType::Binary, None, &token())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Unsupported(m) if m == ACTIVE_THROUGH_PROXY),
        "{err:?}"
    );
    let errors = e.lines(LogKind::Error).await;
    assert!(
        errors.iter().any(|l| l == ACTIVE_THROUGH_PROXY),
        "{errors:?}"
    );
    e.done().await;
}

#[tokio::test]
async fn active_server_never_connects_times_out_and_resyncs() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::ExpectPrefix("PORT "),
            Step::Reply("200 PORT command successful."),
            Step::Expect("RETR f"),
            Step::Reply("150 Opening data connection"),
            Step::ExpectAbor,
            Step::Reply("426 Failure"),
            Step::Reply("226 ABOR successful"),
            Step::Expect("NOOP"),
            Step::Reply("200 NOOP ok."),
        ],
    ]))
    .await;
    let mut cfg = active_cfg();
    cfg.timeout = Duration::from_millis(300);
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let err = d
        .open(retr("f"), TransferType::Binary, None, &token())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Connection(m) if m == "server did not connect to the data port"),
        "{err:?}"
    );
    assert_eq!(d.ctrl.state(), ControlState::Ready);
    e.done().await;
}

/// A one-shot-per-request HTTP server answering `body`; counts requests.
async fn ip_server(body: &'static str) -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/ip", listener.local_addr().unwrap());
    let count = Arc::new(AtomicUsize::new(0));
    let hits = Arc::clone(&count);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            hits.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0u8; 4096];
            let _ = s.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.shutdown().await;
        }
    });
    (url, count)
}

#[tokio::test]
async fn active_external_ip_from_url_cached_once() {
    let (url, hits) = ip_server("203.0.113.7\n").await;
    let mut e = Env::new(script(vec![
        type_i(),
        vec![Step::ExpectPortThenConnect, Step::Expect("RETR a")],
        serve(b"a".to_vec()),
        vec![Step::ExpectPortThenConnect, Step::Expect("RETR b")],
        serve(b"b".to_vec()),
    ]))
    .await;
    let mut cfg = active_cfg();
    cfg.no_external_ip_on_local = false;
    cfg.external_ip = ActiveExternalIp::FromUrl(url);
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    assert_eq!(
        download(&mut d, retr("a"), TransferType::Binary).await,
        b"a"
    );
    assert_eq!(
        download(&mut d, retr("b"), TransferType::Binary).await,
        b"b"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(st.external_ip_cache, Some("203.0.113.7".parse().unwrap()));
    let t = e.done().await;
    let ports: Vec<_> = t
        .received
        .iter()
        .filter(|l| l.starts_with("PORT "))
        .collect();
    assert_eq!(ports.len(), 2, "{t}");
    assert!(
        ports.iter().all(|l| l.starts_with("PORT 203,0,113,7,")),
        "{t}"
    );
}

#[tokio::test]
async fn active_external_ip_url_failure_uses_local() {
    let url = format!("http://127.0.0.1:{}/ip", closed_port().await);
    let mut e = Env::new(script(vec![
        type_i(),
        vec![Step::ExpectPortThenConnect, Step::Expect("RETR a")],
        serve(b"a".to_vec()),
    ]))
    .await;
    let mut cfg = active_cfg();
    cfg.no_external_ip_on_local = false;
    cfg.external_ip = ActiveExternalIp::FromUrl(url);
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    assert_eq!(
        download(&mut d, retr("a"), TransferType::Binary).await,
        b"a"
    );
    let status = e.lines(LogKind::Status).await;
    assert!(status.iter().any(|l| l == EXTERNAL_IP_FAILED), "{status:?}");
    let t = e.done().await;
    assert!(port_line(&t).starts_with("PORT 127,0,0,1,"), "{t}");
}

#[tokio::test]
async fn active_local_peer_uses_local_ip_when_setting_on() {
    let (url, hits) = ip_server("198.51.100.1").await;
    for (setting, external, want) in [
        (
            true,
            ActiveExternalIp::Fixed("203.0.113.5".parse().unwrap()),
            "PORT 127,0,0,1,",
        ),
        (true, ActiveExternalIp::FromUrl(url), "PORT 127,0,0,1,"),
        (
            false,
            ActiveExternalIp::Fixed("203.0.113.5".parse().unwrap()),
            "PORT 203,0,113,5,",
        ),
    ] {
        let mut e = Env::new(script(vec![
            type_i(),
            vec![Step::ExpectPortThenConnect, Step::Expect("RETR a")],
            serve(b"a".to_vec()),
        ]))
        .await;
        let mut cfg = active_cfg();
        cfg.no_external_ip_on_local = setting;
        cfg.external_ip = external;
        let mut st = DataState::default();
        let mut d = e.data(&cfg, &mut st);
        assert_eq!(
            download(&mut d, retr("a"), TransferType::Binary).await,
            b"a"
        );
        let t = e.done().await;
        assert!(port_line(&t).starts_with(want), "{want}\n{t}");
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "no URL request on a local peer"
    );
}

// ---- ranges, REST, finish -------------------------------------------------------------

fn abor_ok() -> Vec<Step> {
    vec![
        Step::ExpectAbor,
        Step::Reply("426 Failure writing network stream."),
        Step::Reply("226 ABOR successful."),
        Step::Expect("NOOP"),
        Step::Reply("200 NOOP ok."),
    ]
}

fn pwd() -> Vec<Step> {
    vec![
        Step::Expect("PWD"),
        Step::Reply("257 \"/\" is the current directory"),
    ]
}

#[tokio::test]
async fn retr_range_len_stops_after_n_bytes_and_aborts() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::EpsvListen,
            Step::Expect("RETR big"),
            Step::Reply("150 Opening BINARY mode data connection"),
            Step::SendPattern {
                offset: 0,
                len: 1024 * 1024,
            },
        ],
        abor_ok(),
        pwd(),
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let cmd = TransferCommand::Retr {
        path: "big".into(),
        offset: 0,
        range_len: Some(100 * 1024),
    };
    let mut s = d
        .open(cmd, TransferType::Binary, None, &token())
        .await
        .unwrap();
    let mut got = Vec::new();
    s.read_to_end(&mut got).await.unwrap();
    assert_eq!(got.len(), 100 * 1024);
    assert_eq!(s.bytes_transferred(), 100 * 1024);
    assert!(got == pattern_bytes(0, 100 * 1024));
    d.finish(Some(s), &token()).await.unwrap();
    assert_eq!(d.ctrl.state(), ControlState::Ready);
    assert_eq!(d.ctrl.pwd(&token()).await.unwrap(), "/");
    e.done().await;
}

#[tokio::test]
async fn retr_range_len_reaching_file_end_reads_226() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::EpsvListen,
            Step::Expect("RETR small"),
            Step::Reply("150 Opening BINARY mode data connection"),
            Step::SendPattern {
                offset: 0,
                len: 1000,
            },
            Step::CloseData,
            Step::Reply("226 Transfer complete."),
        ],
        pwd(),
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let cmd = TransferCommand::Retr {
        path: "small".into(),
        offset: 0,
        range_len: Some(1000),
    };
    let mut s = d
        .open(cmd, TransferType::Binary, None, &token())
        .await
        .unwrap();
    let mut got = Vec::new();
    s.read_to_end(&mut got).await.unwrap();
    assert_eq!(got.len(), 1000);
    d.finish(Some(s), &token()).await.unwrap();
    assert_eq!(d.ctrl.pwd(&token()).await.unwrap(), "/");
    e.done().await;
}

#[tokio::test]
async fn rest_resume_download_over_4gib_offset() {
    const OFFSET: u64 = 5_368_709_120;
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::EpsvListen,
            Step::Expect("REST 5368709120"),
            Step::Reply("350 Restarting at 5368709120. Send STORE or RETRIEVE."),
            Step::Expect("RETR huge.iso"),
            Step::Reply("150 Opening BINARY mode data connection"),
            Step::SendPattern {
                offset: OFFSET,
                len: 70_000,
            },
            Step::CloseData,
            Step::Reply("226 Transfer complete."),
        ],
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let cmd = TransferCommand::Retr {
        path: "huge.iso".into(),
        offset: OFFSET,
        range_len: None,
    };
    let got = download(&mut d, cmd, TransferType::Binary).await;
    // The tail lands at OFFSET of the local file: byte-identical to the server's.
    assert!(got == pattern_bytes(OFFSET, 70_000));
    assert_eq!(st.rest_supported, Some(true));
    e.done().await;
}

#[tokio::test]
async fn rest_resume_upload_byte_identical() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::EpsvListen,
            Step::Expect("REST 1000"),
            Step::Reply("350 Restart position accepted (1000)."),
            Step::Expect("STOR up.bin"),
            Step::Reply("150 Ok to send data."),
            Step::RecvData(pattern_bytes(1000, 200_000)),
            Step::Reply("226 Transfer complete."),
        ],
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let cmd = TransferCommand::Stor {
        path: "up.bin".into(),
        offset: 1000,
    };
    let mut s = d
        .open(cmd, TransferType::Binary, None, &token())
        .await
        .unwrap();
    s.write_all(&pattern_bytes(1000, 200_000)).await.unwrap();
    assert_eq!(s.bytes_transferred(), 200_000);
    d.finish(Some(s), &token()).await.unwrap();
    e.done().await;
}

#[tokio::test]
async fn rest_unsupported_reports_unsupported() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::EpsvListen,
            Step::Expect("REST 100"),
            Step::Reply("502 REST not implemented"),
        ],
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let cmd = TransferCommand::Retr {
        path: "f".into(),
        offset: 100,
        range_len: None,
    };
    let err = d
        .open(cmd.clone(), TransferType::Binary, None, &token())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Unsupported(m) if m == "server does not support resuming"),
        "{err:?}"
    );
    assert_eq!(d.state.rest_supported, Some(false));
    // Known now: refused without a round trip.
    let err = d
        .open(cmd, TransferType::Binary, None, &token())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
    assert_eq!(d.ctrl.state(), ControlState::Ready);
    e.done().await;
}

#[tokio::test]
async fn final_226_before_data_eof_is_ok() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::EpsvListen,
            Step::Expect("RETR race"),
            Step::Reply("150 Opening BINARY mode data connection"),
            Step::SendData(pattern_bytes(0, 50_000)),
            Step::Reply("226 Transfer complete."),
            Step::Delay(Duration::from_millis(100)),
            Step::SendData(pattern_bytes(50_000, 50_000)),
            Step::CloseData,
        ],
        pwd(),
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let got = download(&mut d, retr("race"), TransferType::Binary).await;
    assert!(got == pattern_bytes(0, 100_000));
    assert_eq!(d.ctrl.pwd(&token()).await.unwrap(), "/");
    e.done().await;
}

#[tokio::test]
async fn transfer_error_reply_keeps_control_ready() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::EpsvListen,
            Step::Expect("RETR missing"),
            Step::Reply("550 Failed to open file."),
        ],
        pwd(),
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let err = d
        .open(retr("missing"), TransferType::Binary, None, &token())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Protocol {
                code: Some(550),
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(d.ctrl.state(), ControlState::Ready);
    assert_eq!(d.ctrl.pwd(&token()).await.unwrap(), "/");
    e.done().await;
}

// ---- abort ----------------------------------------------------------------------------

#[tokio::test]
async fn abort_variants_leave_control_usable() {
    let variants: [&[&'static str]; 4] = [
        &[
            "426 Connection closed; transfer aborted.",
            "226 ABOR command successful.",
        ],
        &["226 Transfer complete."],
        &["225 ABOR command successful."],
        &["500 Unknown command."],
    ];
    for replies in variants {
        let mut steps = script(vec![
            type_i(),
            vec![
                Step::EpsvListen,
                Step::Expect("RETR big"),
                Step::Reply("150 Opening BINARY mode data connection"),
                Step::SendPattern {
                    offset: 0,
                    len: 8 * 1024 * 1024,
                },
                Step::ExpectAbor,
            ],
        ]);
        steps.extend(replies.iter().copied().map(Step::Reply));
        steps.extend([Step::Expect("NOOP"), Step::Reply("200 NOOP ok.")]);
        steps.extend(pwd());
        let mut e = Env::new(steps).await;
        let cfg = cfg();
        let mut st = DataState::default();
        let mut d = e.data(&cfg, &mut st);
        let mut s = d
            .open(retr("big"), TransferType::Binary, None, &token())
            .await
            .unwrap();
        let mut buf = vec![0u8; 32 * 1024];
        let n = s.read(&mut buf).await.unwrap();
        assert!(n > 0);
        // Cancelled mid-stream: the caller drops the stream, then finishes.
        drop(s);
        let started = Instant::now();
        let err = d.finish(None, &token()).await.unwrap_err();
        assert!(matches!(err, Error::Cancelled), "{err:?}");
        assert_eq!(d.ctrl.pwd(&token()).await.unwrap(), "/", "{replies:?}");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{replies:?}: {:?}",
            started.elapsed()
        );
        e.done().await;
    }
}

#[tokio::test]
async fn cancel_during_read_listing_aborts() {
    let mut e = Env::new(script(vec![
        vec![
            Step::EpsvListen,
            Step::Expect("LIST"),
            Step::Reply("150 Here comes the directory listing."),
            Step::SendData(b"partial line\r\n".to_vec()),
            Step::Delay(Duration::from_millis(300)),
        ],
        abor_ok(),
        pwd(),
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let cancel = token();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        trigger.cancel();
    });
    let err = d
        .read_listing(TransferCommand::List { args: None }, None, &cancel)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Cancelled), "{err:?}");
    assert_eq!(d.ctrl.pwd(&token()).await.unwrap(), "/");
    e.done().await;
}

#[tokio::test]
async fn abort_without_200_marks_broken() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::EpsvListen,
            Step::Expect("RETR big"),
            Step::Reply("150 Opening BINARY mode data connection"),
            Step::SendData(pattern_bytes(0, 1000)),
            Step::ExpectAbor,
            Step::Reply("426 Failure."),
            Step::Reply("226 ABOR successful."),
            Step::Expect("NOOP"),
            Step::Reply("500 What?"),
        ],
    ]))
    .await;
    let mut cfg = cfg();
    cfg.timeout = Duration::from_millis(300);
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let s = d
        .open(retr("big"), TransferType::Binary, None, &token())
        .await
        .unwrap();
    let err = d.abort(Some(s)).await.unwrap_err();
    assert!(matches!(err, Error::Connection(_)), "{err:?}");
    assert_eq!(d.ctrl.state(), ControlState::Broken);
    e.done().await;
}

// ---- limits ---------------------------------------------------------------------------

#[tokio::test]
async fn listing_over_64mib_rejected() {
    let mut e = Env::new(script(vec![
        vec![
            Step::EpsvListen,
            Step::Expect("LIST -a"),
            Step::Reply("150 Here comes the directory listing."),
            Step::SendPattern {
                offset: 0,
                len: MAX_LISTING_BYTES as u64 + 128 * 1024,
            },
        ],
        abor_ok(),
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let err = d
        .read_listing(
            TransferCommand::List {
                args: Some("-a".into()),
            },
            None,
            &token(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Protocol { code: None, message } if message == "directory listing too large"),
        "{err:?}"
    );
    assert_eq!(d.ctrl.state(), ControlState::Ready);
    e.done().await;
}

#[tokio::test]
async fn listing_read_whole_and_empty() {
    let mut e = Env::new(script(vec![
        vec![
            Step::EpsvListen,
            Step::Expect("MLSD"),
            Step::Reply("150 Here comes the directory listing."),
            Step::SendData(b"type=file;size=1; a\r\n".to_vec()),
            Step::CloseData,
            Step::Reply("226 Directory send OK."),
            // An empty directory on some servers: 226 without 150.
            Step::EpsvListen,
            Step::Expect("LIST"),
            Step::Reply("226 Transfer done (but failed to open directory)."),
        ],
        pwd(),
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let got = d
        .read_listing(TransferCommand::Mlsd, None, &token())
        .await
        .unwrap();
    assert_eq!(got, b"type=file;size=1; a\r\n");
    let empty = d
        .read_listing(TransferCommand::List { args: None }, None, &token())
        .await
        .unwrap();
    assert!(empty.is_empty());
    assert_eq!(d.ctrl.pwd(&token()).await.unwrap(), "/");
    e.done().await;
}

#[tokio::test]
async fn second_open_rejected() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![Step::EpsvListen, Step::Expect("RETR one")],
        serve(b"data".to_vec()),
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let mut s = d
        .open(retr("one"), TransferType::Binary, None, &token())
        .await
        .unwrap();
    assert_eq!(d.ctrl.state(), ControlState::TransferOpen);
    let err = d
        .open(retr("two"), TransferType::Binary, None, &token())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::InvalidInput(m) if m == "a transfer is already in progress"),
        "{err:?}"
    );
    let mut got = Vec::new();
    s.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"data");
    d.finish(Some(s), &token()).await.unwrap();
    e.done().await;
}

#[tokio::test]
async fn data_inactivity_timeout() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::EpsvListen,
            Step::Expect("RETR slow"),
            Step::Reply("150 Opening BINARY mode data connection"),
            Step::SendData(b"some".to_vec()),
            Step::Delay(Duration::from_millis(700)),
        ],
        abor_ok(),
    ]))
    .await;
    let mut cfg = cfg();
    cfg.timeout = Duration::from_millis(300);
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let mut s = d
        .open(retr("slow"), TransferType::Binary, None, &token())
        .await
        .unwrap();
    let mut got = Vec::new();
    let err = s.read_to_end(&mut got).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(err.to_string(), "Data connection timed out");
    assert_eq!(got, b"some");
    let err = d.finish(Some(s), &token()).await.unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err:?}");
    assert_eq!(d.ctrl.state(), ControlState::Ready);
    e.done().await;
}

#[tokio::test]
async fn upload_data_failure_reports_server_reply() {
    let mut e = Env::new(script(vec![
        type_i(),
        vec![
            Step::EpsvListen,
            Step::Expect("STOR full.bin"),
            Step::Reply("150 Ok to send data."),
            Step::SendData(Vec::new()), // accept, then close at once
            Step::CloseData,
            Step::Reply("452 Insufficient storage space."),
        ],
        pwd(),
    ]))
    .await;
    let cfg = cfg();
    let mut st = DataState::default();
    let mut d = e.data(&cfg, &mut st);
    let cmd = TransferCommand::Stor {
        path: "full.bin".into(),
        offset: 0,
    };
    let mut s = d
        .open(cmd, TransferType::Binary, None, &token())
        .await
        .unwrap();
    let chunk = pattern_bytes(0, 64 * 1024);
    let mut failed = false;
    for _ in 0..1024 {
        if s.write_all(&chunk).await.is_err() {
            failed = true;
            break;
        }
    }
    assert!(failed, "writes to a closed data connection must fail");
    let err = d.finish(Some(s), &token()).await.unwrap_err();
    assert!(
        matches!(
            err,
            Error::Protocol {
                code: Some(452),
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(d.ctrl.pwd(&token()).await.unwrap(), "/");
    e.done().await;
}
