//! `SessionHandle` tests on paused time with `MockServer` (T03 AC3–AC6, AC8).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::mock::{MockOp, MockServer, test_context_with};
use super::*;
use crate::Error;
use crate::events::{CoreEvent, DisconnectReason, EventReceiver, LogKind};
use crate::model::RemotePath;
use crate::settings::Settings;

fn settings(retries: u8, delay: u32) -> Settings {
    let mut s = Settings::default();
    s.connection.retries = retries;
    s.connection.retry_delay_secs = delay;
    s.connection.keepalive = true;
    s.connection.keepalive_interval_secs = 30;
    s
}

fn session_with(
    server: &MockServer,
    s: Settings,
    opts: SessionOptions,
) -> (SessionHandle, EventReceiver) {
    let (ctx, rx) = test_context_with(s);
    let b = Box::new(server.backend(ctx.clone()));
    (SessionHandle::new(b, ctx, opts, "test@mock".into()), rx)
}

fn session(server: &MockServer) -> (SessionHandle, EventReceiver) {
    session_with(server, settings(2, 5), SessionOptions::default())
}

fn home() -> RemotePath {
    RemotePath::parse("/home/test").unwrap()
}

fn conn_err() -> Error {
    Error::Connection("connection reset by mock".into())
}

/// Pending events as short names; log lines as `log:<text>` (Status/Error only).
fn drain(rx: &mut EventReceiver) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(ev) = rx.try_recv() {
        let s = match ev {
            CoreEvent::Log(m) => match m.kind {
                LogKind::Status | LogKind::Error => format!("log:{}", m.text),
                _ => continue,
            },
            CoreEvent::SessionOpened { .. } => "SessionOpened".into(),
            CoreEvent::SessionClosed { .. } => "SessionClosed".into(),
            CoreEvent::Connecting { .. } => "Connecting".into(),
            CoreEvent::Connected { .. } => "Connected".into(),
            CoreEvent::Disconnected { reason, .. } => match reason {
                DisconnectReason::Requested => "Disconnected(Requested)".into(),
                DisconnectReason::Lost(_) => "Disconnected(Lost)".into(),
                DisconnectReason::Failed(_) => "Disconnected(Failed)".into(),
            },
            CoreEvent::CapabilitiesChanged { .. } => "CapabilitiesChanged".into(),
            other => format!("{other:?}"),
        };
        out.push(s);
    }
    out
}

fn events_only(v: &[String]) -> Vec<&str> {
    v.iter()
        .filter(|s| !s.starts_with("log:"))
        .map(String::as_str)
        .collect()
}

#[tokio::test(start_paused = true)]
async fn reconnect_once_on_connection_lost() {
    let server = MockServer::new();
    let (h, _rx) = session(&server);
    let c = CancellationToken::new();
    h.connect(&c).await.unwrap();
    assert_eq!(h.state(), SessionState::Connected);
    server.drop_connections();
    h.list(&home(), &c).await.unwrap();
    assert_eq!(server.calls(MockOp::Connect), 2);
    assert_eq!(h.state(), SessionState::Connected);

    // A loss reported by the operation itself (not seen up front) also reconnects.
    server.fail_next(MockOp::List, conn_err);
    h.list(&home(), &c).await.unwrap();
    assert_eq!(server.calls(MockOp::Connect), 3);
    assert_eq!(server.calls(MockOp::List), 3);
}

#[tokio::test(start_paused = true)]
async fn second_consecutive_loss_surfaces() {
    let server = MockServer::new();
    let (h, _rx) = session(&server);
    let c = CancellationToken::new();
    h.connect(&c).await.unwrap();
    server.fail_next(MockOp::List, conn_err);
    server.fail_next(MockOp::List, conn_err);
    let res = h.list(&home(), &c).await;
    assert!(matches!(res, Err(Error::Connection(_))), "{res:?}");
    assert_eq!(server.calls(MockOp::Connect), 2);
    assert_eq!(server.calls(MockOp::List), 2);
    assert_eq!(h.state(), SessionState::Disconnected);
    // The next operation reconnects lazily.
    h.list(&home(), &c).await.unwrap();
    assert_eq!(h.state(), SessionState::Connected);
}

#[tokio::test(start_paused = true)]
async fn no_reconnect_when_disabled() {
    let server = MockServer::new();
    let opts = SessionOptions {
        reconnect: false,
        ..SessionOptions::default()
    };
    let (h, _rx) = session_with(&server, settings(2, 5), opts);
    let c = CancellationToken::new();
    h.connect(&c).await.unwrap();
    server.fail_next(MockOp::Stat, conn_err);
    let res = h.stat(&home(), &c).await;
    assert!(matches!(res, Err(Error::Connection(_))), "{res:?}");
    assert_eq!(server.calls(MockOp::Connect), 1);
    assert_eq!(server.calls(MockOp::Stat), 1);
    assert_eq!(h.state(), SessionState::Disconnected);
}

#[tokio::test(start_paused = true)]
async fn retried_mkdir_already_exists_is_success() {
    let server = MockServer::new();
    let (h, _rx) = session(&server);
    let c = CancellationToken::new();
    h.connect(&c).await.unwrap();
    let dir = home().join("d").unwrap();
    // Pretend the first attempt created the directory before the connection dropped.
    server.add_dir("/home/test/d");
    server.fail_next(MockOp::Mkdir, conn_err);
    h.mkdir(&dir, &c).await.unwrap();
    assert_eq!(server.calls(MockOp::Mkdir), 2);
    // Without a reconnect, AlreadyExists is reported.
    let res = h.mkdir(&dir, &c).await;
    assert!(matches!(res, Err(Error::AlreadyExists(_))), "{res:?}");
}

#[tokio::test(start_paused = true)]
async fn retried_remove_not_found_is_success() {
    let server = MockServer::new();
    let (h, _rx) = session(&server);
    let c = CancellationToken::new();
    h.connect(&c).await.unwrap();
    let gone = home().join("gone").unwrap();
    server.fail_next(MockOp::RemoveFile, conn_err);
    h.remove_file(&gone, &c).await.unwrap();
    server.fail_next(MockOp::Rmdir, conn_err);
    h.rmdir(&gone, &c).await.unwrap();
    // Without a reconnect, NotFound is reported.
    let res = h.remove_file(&gone, &c).await;
    assert!(matches!(res, Err(Error::NotFound(_))), "{res:?}");
    let res = h.rmdir(&gone, &c).await;
    assert!(matches!(res, Err(Error::NotFound(_))), "{res:?}");
}

#[tokio::test(start_paused = true)]
async fn connect_retries_transient_errors_with_delay() {
    let server = MockServer::new();
    let (h, mut rx) = session(&server);
    for _ in 0..3 {
        server.fail_next(MockOp::Connect, conn_err);
    }
    let start = Instant::now();
    let task = {
        let h = h.clone();
        tokio::spawn(async move { h.connect(&CancellationToken::new()).await })
    };
    let at = |secs: f64| start + Duration::from_secs_f64(secs);
    tokio::time::sleep_until(at(0.1)).await;
    assert_eq!(server.calls(MockOp::Connect), 1);
    tokio::time::sleep_until(at(4.9)).await;
    assert_eq!(server.calls(MockOp::Connect), 1);
    tokio::time::sleep_until(at(5.1)).await;
    assert_eq!(server.calls(MockOp::Connect), 2);
    tokio::time::sleep_until(at(9.9)).await;
    assert_eq!(server.calls(MockOp::Connect), 2);
    tokio::time::sleep_until(at(10.1)).await;
    assert_eq!(server.calls(MockOp::Connect), 3);
    let res = task.await.unwrap();
    assert!(matches!(res, Err(Error::Connection(_))), "{res:?}");
    assert_eq!(server.calls(MockOp::Connect), 3);
    assert!(matches!(h.state(), SessionState::Failed(_)));

    let ev = drain(&mut rx);
    let logs: Vec<&str> = ev.iter().filter_map(|s| s.strip_prefix("log:")).collect();
    assert_eq!(
        logs,
        [
            "Connection attempt failed with \"connection error: connection reset by mock\".",
            "Waiting to retry... (2 attempts left)",
            "Connection attempt failed with \"connection error: connection reset by mock\".",
            "Waiting to retry... (1 attempt left)",
            "Connection attempt failed with \"connection error: connection reset by mock\".",
            "Could not connect to server",
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn connect_does_not_retry_auth_or_limit() {
    type MakeError = fn() -> Error;
    let makers: [(&str, MakeError); 3] = [
        ("auth", || Error::Auth("530 Login incorrect".into())),
        ("host-key", || Error::HostKey("mismatch".into())),
        ("limit", || Error::ConnectionLimit("421 too many".into())),
    ];
    for (what, make) in makers {
        let server = MockServer::new();
        let (h, _rx) = session(&server);
        server.fail_next(MockOp::Connect, make);
        let start = Instant::now();
        let res = h.connect(&CancellationToken::new()).await;
        assert!(res.is_err(), "{what}");
        assert_eq!(server.calls(MockOp::Connect), 1, "{what}");
        assert!(start.elapsed() < Duration::from_secs(1), "{what}");
        assert!(matches!(h.state(), SessionState::Failed(_)), "{what}");
    }
}

#[tokio::test(start_paused = true)]
async fn connect_limit_reported_as_connection_limit() {
    let server = MockServer::new();
    server.set_max_connections(Some(1));
    let (first, _rx1) = session(&server);
    let (second, _rx2) = session(&server);
    let c = CancellationToken::new();
    first.connect(&c).await.unwrap();
    let res = second.connect(&c).await;
    assert!(matches!(res, Err(Error::ConnectionLimit(_))), "{res:?}");
    assert_eq!(
        server.calls(MockOp::Connect),
        2,
        "no retry for ConnectionLimit"
    );
    assert_eq!(server.connections(), 1);
    assert_eq!(server.peak_connections(), 1);
}

#[tokio::test(start_paused = true)]
async fn cancel_interrupts_slow_operation() {
    let server = MockServer::new();
    let (h, _rx) = session(&server);
    let c = CancellationToken::new();
    h.connect(&c).await.unwrap();
    server.set_latency(Duration::from_secs(10));
    let cancel = CancellationToken::new();
    let task = {
        let (h, cancel) = (h.clone(), cancel.clone());
        tokio::spawn(async move { h.list(&home(), &cancel).await })
    };
    let start = Instant::now();
    tokio::time::sleep(Duration::from_secs(1)).await;
    cancel.cancel();
    let res = task.await.unwrap();
    assert!(matches!(res, Err(Error::Cancelled)), "{res:?}");
    assert!(
        start.elapsed() <= Duration::from_millis(1050),
        "{:?}",
        start.elapsed()
    );
    // A cancelled token fails fast even before the backend is reached.
    assert!(matches!(
        h.stat(&home(), &cancel).await,
        Err(Error::Cancelled)
    ));
    server.set_latency(Duration::ZERO);
    h.list(&home(), &c).await.unwrap();
    assert_eq!(h.state(), SessionState::Connected);
}

#[tokio::test(start_paused = true)]
async fn keepalive_fires_after_idle_interval() {
    let server = MockServer::new();
    let (h, _rx) = session(&server);
    h.connect(&CancellationToken::new()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(29)).await;
    assert_eq!(server.calls(MockOp::Keepalive), 0);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(server.calls(MockOp::Keepalive), 1);
    assert_eq!(h.state(), SessionState::Connected);
}

#[tokio::test(start_paused = true)]
async fn keepalive_not_sent_when_disabled_or_busy_recently() {
    let server = MockServer::new();
    let mut s = settings(2, 5);
    s.connection.keepalive = false;
    let (h, _rx) = session_with(&server, s, SessionOptions::default());
    h.connect(&CancellationToken::new()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(100)).await;
    assert_eq!(server.calls(MockOp::Keepalive), 0);

    // Activity resets the idle timer.
    let server = MockServer::new();
    let (h, _rx) = session(&server);
    let c = CancellationToken::new();
    h.connect(&c).await.unwrap();
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_secs(20)).await;
        h.stat(&home(), &c).await.unwrap();
    }
    assert_eq!(server.calls(MockOp::Keepalive), 0);
}

#[tokio::test(start_paused = true)]
async fn keepalive_skipped_while_locked() {
    let server = MockServer::new();
    let (h, _rx) = session(&server);
    let mut guard = h.lock(&CancellationToken::new()).await.unwrap();
    assert!(guard.is_connected(), "lock() connects first");
    tokio::time::sleep(Duration::from_secs(70)).await;
    assert_eq!(server.calls(MockOp::Keepalive), 0);
    guard.stat(&home()).await.unwrap();
    drop(guard);
    assert_eq!(server.calls(MockOp::Keepalive), 0);
}

#[tokio::test(start_paused = true)]
async fn keepalive_task_stops_when_handle_dropped() {
    let server = MockServer::new();
    let (h, mut rx) = session(&server);
    h.connect(&CancellationToken::new()).await.unwrap();
    let task = h.take_keepalive_task().expect("keep-alive task");
    let weak = h.weak_inner();
    let clone = h.clone();
    drop(h);
    assert!(weak.upgrade().is_some(), "a clone keeps the session");
    drop(clone);
    assert_eq!(weak.strong_count(), 0);
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("task finished within one tick")
        .unwrap();
    // The backend was disconnected politely in a detached task.
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(server.calls(MockOp::Disconnect), 1);
    assert_eq!(server.connections(), 0);
    assert!(drain(&mut rx).contains(&"SessionClosed".to_owned()));
}

#[tokio::test(start_paused = true)]
async fn keepalive_failure_marks_disconnected_and_next_op_reconnects() {
    let server = MockServer::new();
    let (h, mut rx) = session(&server);
    let c = CancellationToken::new();
    h.connect(&c).await.unwrap();
    drain(&mut rx);
    server.fail_next(MockOp::Keepalive, conn_err);
    tokio::time::sleep(Duration::from_secs(31)).await;
    assert_eq!(server.calls(MockOp::Keepalive), 1);
    assert_eq!(h.state(), SessionState::Disconnected);
    assert_eq!(server.calls(MockOp::Connect), 1, "no automatic reconnect");
    let ev = drain(&mut rx);
    assert!(ev.contains(&"Disconnected(Lost)".to_owned()), "{ev:?}");
    assert!(ev.contains(&"log:Connection lost".to_owned()), "{ev:?}");

    let mut states = h.watch_state();
    h.list(&home(), &c).await.unwrap();
    assert_eq!(server.calls(MockOp::Connect), 2);
    assert_eq!(*states.borrow_and_update(), SessionState::Connected);
    assert_eq!(
        events_only(&drain(&mut rx)),
        ["Connecting", "Connected"],
        "lazy reconnect"
    );
}

#[tokio::test(start_paused = true)]
async fn session_events_sequence() {
    let server = MockServer::new();
    let (h, mut rx) = session(&server);
    let c = CancellationToken::new();
    assert_eq!(events_only(&drain(&mut rx)), ["SessionOpened"]);

    h.connect(&c).await.unwrap();
    assert_eq!(events_only(&drain(&mut rx)), ["Connecting", "Connected"]);

    server.drop_connections();
    h.list(&home(), &c).await.unwrap();
    let ev = drain(&mut rx);
    assert_eq!(
        events_only(&ev),
        ["Disconnected(Lost)", "Connecting", "Connected"]
    );
    assert!(ev.contains(&"log:Connection lost, reconnecting".to_owned()));

    h.disconnect().await.unwrap();
    assert_eq!(events_only(&drain(&mut rx)), ["Disconnected(Requested)"]);
    assert_eq!(h.state(), SessionState::Disconnected);

    server.fail_next(MockOp::Connect, || Error::Auth("530".into()));
    assert!(h.connect(&c).await.is_err());
    assert_eq!(
        events_only(&drain(&mut rx)),
        ["Connecting", "Disconnected(Failed)"]
    );

    drop(h);
    assert_eq!(events_only(&drain(&mut rx)), ["SessionClosed"]);
}

#[tokio::test(start_paused = true)]
async fn capabilities_change_is_reported() {
    let server = MockServer::new();
    let (h, mut rx) = session(&server);
    let c = CancellationToken::new();
    h.connect(&c).await.unwrap();
    assert!(h.capabilities().chmod);
    assert_eq!(h.security_info().summary, "mock");
    drain(&mut rx);
    let mut caps = h.capabilities();
    caps.chmod = false;
    let server = server.with_capabilities(caps);
    h.stat(&home(), &c).await.unwrap();
    assert!(!h.capabilities().chmod);
    assert_eq!(events_only(&drain(&mut rx)), ["CapabilitiesChanged"]);
    drop(server);
}
