//! A TCP proxy in front of the test server that can cut the network:
//! `Up` forwards, `Down` drops every connection, `DropResponses` forwards
//! requests but throws the server's answers away and closes (the server
//! committed, the client never hears back), `DropPushResponses` does that
//! only for pushes (`POST …/changes`).
#![allow(dead_code, unreachable_pub, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// What the proxy does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Up = 0,
    Down = 1,
    DropResponses = 2,
    DropPushResponses = 3,
}

/// A running proxy.
pub struct Proxy {
    /// `http://127.0.0.1:<port>`.
    pub url: String,
    mode: Arc<AtomicU8>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn mode_of(m: &AtomicU8) -> Mode {
    match m.load(Ordering::SeqCst) {
        0 => Mode::Up,
        1 => Mode::Down,
        2 => Mode::DropResponses,
        _ => Mode::DropPushResponses,
    }
}

impl Proxy {
    /// A proxy to `upstream` (`http://host:port`).
    pub async fn start(upstream: &str) -> Self {
        let target: SocketAddr = upstream.trim_start_matches("http://").parse().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicU8::new(Mode::Up as u8));
        let m = Arc::clone(&mode);
        let task = tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    return;
                };
                if mode_of(&m) == Mode::Down {
                    drop(client);
                    continue;
                }
                let m = Arc::clone(&m);
                tokio::spawn(async move {
                    let Ok(server) = TcpStream::connect(target).await else {
                        return;
                    };
                    pipe(client, server, m).await;
                });
            }
        });
        Self { url, mode, task }
    }

    /// Switches the mode (affects open connections at their next chunk).
    pub fn set(&self, mode: Mode) {
        self.mode.store(mode as u8, Ordering::SeqCst);
    }
}

async fn pipe(client: TcpStream, server: TcpStream, mode: Arc<AtomicU8>) {
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();
    let m1 = Arc::clone(&mode);
    let pushing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let p1 = Arc::clone(&pushing);
    let up = async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if mode_of(&m1) == Mode::Down {
                break;
            }
            if buf[..n].starts_with(b"POST ") {
                let head = String::from_utf8_lossy(&buf[..n.min(256)]).into_owned();
                let line = head.lines().next().unwrap_or("");
                p1.store(line.contains("/changes"), Ordering::SeqCst);
            } else if buf[..n].starts_with(b"GET ") {
                p1.store(false, Ordering::SeqCst);
            }
            if sw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = sw.shutdown().await;
    };
    let down = async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match sr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            match mode_of(&mode) {
                Mode::Up => {}
                Mode::DropPushResponses if !pushing.load(Ordering::SeqCst) => {}
                _ => break,
            }
            if cw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = cw.shutdown().await;
    };
    // Either direction ending tears the connection down.
    tokio::select! {
        () = up => {}
        () = down => {}
    }
}
