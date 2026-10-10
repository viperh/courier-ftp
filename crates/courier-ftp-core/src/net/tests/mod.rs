//! Tests of the network layer (T07): unit, property and in-process integration tests
//! (fake HTTP CONNECT / SOCKS proxies on `127.0.0.1:0`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod canary;
mod dial;
mod http;
mod props;
mod socks;
mod unit;

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use super::{NetOpts, ProxyConfig, Purpose};
use crate::{
    events::{CoreEvent, EventReceiver, LogKind, PromptResponse, SessionId, SessionLog, channel},
    secret::SecretString,
    settings::DebugLevel,
};

/// Options with a 5 s timeout, IPv4 first, control purpose.
pub(super) fn opts(proxy: ProxyConfig) -> NetOpts {
    NetOpts {
        timeout: Duration::from_secs(5),
        prefer_ipv6: false,
        allow_ipv6: true,
        purpose: Purpose::Control,
        socket_buffer: None,
        proxy,
    }
}

/// A session log at debug level 4 and its receiver.
pub(super) fn session_log() -> (SessionLog, EventReceiver) {
    let (events, rx) = channel(DebugLevel::Debug);
    (
        SessionLog {
            events,
            session: SessionId::next(),
        },
        rx,
    )
}

/// Everything the UI side saw.
#[derive(Debug, Default)]
pub(super) struct Seen {
    pub logs: Vec<(LogKind, String)>,
    pub prompts: usize,
    pub accepted: usize,
}

impl Seen {
    pub(super) fn status(&self) -> Vec<&str> {
        self.logs
            .iter()
            .filter(|(k, _)| *k == LogKind::Status)
            .map(|(_, t)| t.as_str())
            .collect()
    }

    pub(super) fn all_text(&self) -> String {
        self.logs
            .iter()
            .map(|(_, t)| t.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Drains the events already queued.
pub(super) fn drain(rx: &mut EventReceiver) -> Seen {
    let mut seen = Seen::default();
    while let Some(ev) = rx.try_recv() {
        record(&mut seen, ev, None);
    }
    seen
}

fn record(seen: &mut Seen, ev: CoreEvent, answer: Option<&str>) {
    match ev {
        CoreEvent::Log(m) => seen.logs.push((m.kind, m.text)),
        CoreEvent::Prompt(req) => {
            seen.prompts += 1;
            let response = match answer {
                Some(pw) => PromptResponse::Secret {
                    value: SecretString::from(pw),
                    remember_session: false,
                    save_in_vault: false,
                },
                None => PromptResponse::Cancel,
            };
            req.respond(response);
        }
        CoreEvent::CredentialAccepted { .. } => seen.accepted += 1,
        _ => {}
    }
}

/// A task playing the UI: answers every prompt with `answer` (or Cancel) and records
/// everything until the senders are gone.
pub(super) fn ui(mut rx: EventReceiver, answer: Option<&'static str>) -> JoinHandle<Seen> {
    tokio::spawn(async move {
        let mut seen = Seen::default();
        while let Some(ev) = rx.recv().await {
            record(&mut seen, ev, answer);
        }
        seen
    })
}

/// Copies everything read back to the writer until EOF.
pub(super) async fn echo(mut s: TcpStream) {
    let mut buf = [0_u8; 1024];
    loop {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if s.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// An echo server on `bind`; `None` when the address cannot be bound (no IPv6).
pub(super) async fn echo_server(bind: &str) -> Option<SocketAddr> {
    let listener = TcpListener::bind(bind).await.ok()?;
    let addr = listener.local_addr().ok()?;
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            tokio::spawn(echo(s));
        }
    });
    Some(addr)
}

/// Sends `data` and expects it echoed.
pub(super) async fn round_trip<S>(s: &mut S, data: &[u8])
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    s.write_all(data).await.unwrap();
    let mut got = vec![0_u8; data.len()];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(got, data);
}

/// Requests seen by a fake proxy, one entry per connection.
pub(super) type Recorded = Arc<Mutex<Vec<Vec<u8>>>>;

/// Starts a fake proxy: for each connection, `serve(stream, index, recorded)` runs.
pub(super) async fn fake_proxy<F, Fut>(serve: F) -> (SocketAddr, Recorded)
where
    F: Fn(TcpStream, usize, Recorded) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let recorded = Recorded::default();
    let rec = recorded.clone();
    tokio::spawn(async move {
        let mut index = 0;
        while let Ok((s, _)) = listener.accept().await {
            tokio::spawn(serve(s, index, rec.clone()));
            index += 1;
        }
    });
    (addr, recorded)
}

/// Reads exactly `n` bytes (empty on EOF).
pub(super) async fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0_u8; n];
    match s.read_exact(&mut buf).await {
        Ok(_) => buf,
        Err(_) => Vec::new(),
    }
}

/// Reads up to and including `delim` (or EOF).
pub(super) async fn read_until(s: &mut TcpStream, delim: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = [0_u8; 1];
    while !out.ends_with(delim) {
        match s.read(&mut b).await {
            Ok(0) | Err(_) => break,
            Ok(_) => out.push(b[0]),
        }
    }
    out
}
