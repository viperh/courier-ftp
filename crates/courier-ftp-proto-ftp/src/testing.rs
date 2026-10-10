//! A scripted fake FTP server for tests (feature `test-util`; T10–T15, T72, T76).
//!
//! The script is a list of [`Step`]s run in order against one client connection,
//! either over an in-memory duplex ([`FakeServer::duplex`]) or loopback TCP
//! ([`FakeServer::tcp`]). A mismatch panics inside the server task with
//! `expected X, got Y` and the transcript; [`FakeServer::finish`] re-raises that panic
//! and asserts the client sent nothing after the script ended.
//!
//! After the last step the server keeps the connection open until the client closes it,
//! so drop (or `quit()`) the client before calling `finish`.
//!
//! Data connections (T11, TCP servers only): [`Step::PasvListen`]/[`Step::EpsvListen`]
//! open a loopback listener and announce it; [`Step::ExpectPortThenConnect`] reads the
//! client's `PORT`/`EPRT` and connects to the announced port. The data socket is
//! accepted/connected lazily by the first data step ([`Step::SendData`],
//! [`Step::RecvData`], …), like a real server that only touches it after `150`.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpSocket, TcpStream},
    task::JoinHandle,
};

use crate::{
    active::{format_port, parse_eprt},
    control::BoxedIo,
    passive::parse_pasv,
};

/// How long the fake server waits for a data connection before panicking.
const DATA_WAIT: Duration = Duration::from_secs(10);

/// Deterministic test content: byte `i` of a "file" is `i % 251`. `offset..offset+len`.
pub fn pattern_bytes(offset: u64, len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| ((offset + i) % 251) as u8)
        .collect()
}

/// One scripted server action.
#[derive(Debug, Clone)]
pub enum Step {
    /// Write `"<text>\r\n"` (multi-line replies: embed `\r\n`).
    Reply(&'static str),
    /// Write exact bytes (split replies, garbage, Telnet sequences).
    RawBytes(Vec<u8>),
    /// The next client line must equal this.
    Expect(&'static str),
    /// The next client line, as raw bytes without CRLF (Telnet IAC doubling and the
    /// session charset not undone), must equal this.
    ExpectRaw(Vec<u8>),
    /// The next client line must start with this (e.g. `"PASS "`).
    ExpectPrefix(&'static str),
    /// The next client line must be `"<verb> <value>"` (secrets; the transcript masks
    /// the value).
    ExpectSecret {
        /// `PASS`, `ACCT`.
        verb: &'static str,
        /// The expected secret.
        value: &'static str,
    },
    /// Sleep (use with `tokio::time::pause`).
    Delay(Duration),
    /// Close the connection (later steps are not run).
    Close,
    /// Write `"<text>\r\n"` (built at run time, e.g. with a port number).
    ReplyText(String),
    /// Expect `PASV`, listen on the control connection's local IP, reply
    /// `227 Entering Passive Mode (…)` with that address.
    PasvListen,
    /// As [`PasvListen`](Self::PasvListen), but the `227` names this IP (the listener
    /// stays on the local IP: address-rule tests).
    PasvListenAs(Ipv4Addr),
    /// Expect `EPSV`, listen on the control connection's local IP (IPv4 or IPv6),
    /// reply `229 Entering Extended Passive Mode (|||port|)`.
    EpsvListen,
    /// Expect `PORT …` or `EPRT …`, reply `200`; the data connection then goes to the
    /// announced port on the control connection's peer IP (the client's real address,
    /// whatever IP it announced).
    ExpectPortThenConnect,
    /// Connect to the active-mode port from this source IP (e.g. `127.0.0.2`) and wait
    /// until the client closes that connection (it must reject it).
    DataConnectFrom(IpAddr),
    /// Write these bytes on the data connection (errors ignored: the client may abort).
    SendData(Vec<u8>),
    /// Write [`pattern_bytes`]`(offset, len)` in 64 KiB pieces (errors ignored).
    SendPattern {
        /// Offset of the first byte in the pattern.
        offset: u64,
        /// Number of bytes.
        len: u64,
    },
    /// Read the data connection to EOF; it must equal these bytes.
    RecvData(Vec<u8>),
    /// Close the data connection (and the passive listener).
    CloseData,
    /// The next client line must be `ABOR`; then the data connection is dropped.
    ExpectAbor,
}

/// What happened on the server side.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Transcript {
    /// Lines received from the client (secrets of `ExpectSecret` steps masked).
    pub received: Vec<String>,
    /// What the server wrote (lossy UTF-8).
    pub sent: Vec<String>,
}

impl fmt::Display for Transcript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "client sent:")?;
        for l in &self.received {
            writeln!(f, "  > {l}")?;
        }
        writeln!(f, "server sent:")?;
        for l in &self.sent {
            writeln!(f, "  < {}", l.trim_end())?;
        }
        Ok(())
    }
}

/// A running scripted server.
#[derive(Debug)]
pub struct FakeServer {
    task: JoinHandle<Transcript>,
}

impl FakeServer {
    /// Runs `script` over an in-memory duplex; returns the client end.
    pub fn duplex(script: Vec<Step>) -> (Self, BoxedIo) {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let task = tokio::spawn(run(server, script, Data::new(None, None)));
        (Self { task }, Box::new(client))
    }

    /// Runs `script` on the first connection accepted on a loopback port.
    pub async fn tcp(script: Vec<Step>) -> (Self, SocketAddr) {
        Self::tcp_on(SocketAddr::from(([127, 0, 0, 1], 0)), script)
            .await
            .expect("bind loopback")
    }

    /// Runs `script` on the first connection accepted on `bind` (e.g. `[::1]:0`).
    ///
    /// # Errors
    ///
    /// The bind failed (e.g. no IPv6 loopback).
    pub async fn tcp_on(
        bind: SocketAddr,
        script: Vec<Step>,
    ) -> std::io::Result<(Self, SocketAddr)> {
        let listener = TcpListener::bind(bind).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            let local = stream.local_addr().expect("local addr");
            run(stream, script, Data::new(Some(local), Some(peer))).await
        });
        Ok((Self { task }, addr))
    }

    /// Waits for the script to end (the client must have closed the connection, unless
    /// the script ended with [`Step::Close`]). Panics with the server's message on a
    /// mismatch; asserts the script was consumed completely.
    pub async fn finish(self) -> Transcript {
        match self.task.await {
            Ok(t) => t,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => panic!("fake server task failed: {e}"),
        }
    }
}

/// The fake server's data-connection state.
struct Data {
    ctrl_local: Option<SocketAddr>,
    ctrl_peer: Option<SocketAddr>,
    listener: Option<TcpListener>,
    connect_to: Option<SocketAddr>,
    stream: Option<TcpStream>,
}

impl Data {
    fn new(ctrl_local: Option<SocketAddr>, ctrl_peer: Option<SocketAddr>) -> Self {
        Self {
            ctrl_local,
            ctrl_peer,
            listener: None,
            connect_to: None,
            stream: None,
        }
    }

    async fn listen(&mut self, t: &Transcript) -> SocketAddr {
        let ip = self
            .ctrl_local
            .unwrap_or_else(|| panic!("data steps need FakeServer::tcp\n{t}"))
            .ip();
        let listener = TcpListener::bind(SocketAddr::new(ip, 0))
            .await
            .expect("bind data listener");
        let addr = listener.local_addr().expect("listener addr");
        self.listener = Some(listener);
        self.connect_to = None;
        addr
    }

    /// The data connection, accepted or connected on first use.
    async fn stream(&mut self, t: &Transcript) -> &mut TcpStream {
        if self.stream.is_none() {
            let stream = if let Some(listener) = self.listener.take() {
                match tokio::time::timeout(DATA_WAIT, listener.accept()).await {
                    Ok(Ok((s, _))) => s,
                    Ok(Err(e)) => panic!("data accept failed: {e}\n{t}"),
                    Err(_) => panic!("the client never opened the data connection\n{t}"),
                }
            } else if let Some(addr) = self.connect_to.take() {
                match tokio::time::timeout(DATA_WAIT, TcpStream::connect(addr)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => panic!("data connect to {addr} failed: {e}\n{t}"),
                    Err(_) => panic!("data connect to {addr} timed out\n{t}"),
                }
            } else {
                panic!("no data connection prepared (PASV/EPSV/PORT step missing)\n{t}")
            };
            self.stream = Some(stream);
        }
        self.stream.as_mut().expect("just set")
    }

    fn close(&mut self) {
        self.stream = None;
        self.listener = None;
        self.connect_to = None;
    }
}

async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    script: Vec<Step>,
    mut data: Data,
) -> Transcript {
    let mut t = Transcript::default();
    let mut io = BufReader::new(stream);
    let total = script.len();
    for (i, step) in script.into_iter().enumerate() {
        match step {
            Step::Reply(text) => {
                let line = format!("{text}\r\n");
                write(&mut io, line.as_bytes(), &mut t).await;
            }
            Step::RawBytes(bytes) => write(&mut io, &bytes, &mut t).await,
            Step::Expect(want) => {
                let got = read_line(&mut io, &t, want).await;
                t.received.push(got.clone());
                assert!(got == want, "expected {want:?}, got {got:?}\n{t}");
            }
            Step::ExpectRaw(want) => {
                let got = read_raw(&mut io, &t, &String::from_utf8_lossy(&want)).await;
                t.received.push(String::from_utf8_lossy(&got).into_owned());
                assert!(got == want, "expected {want:?}, got {got:?}\n{t}");
            }
            Step::ExpectPrefix(want) => {
                let got = read_line(&mut io, &t, want).await;
                t.received.push(got.clone());
                assert!(
                    got.starts_with(want),
                    "expected {want:?}…, got {got:?}\n{t}"
                );
            }
            Step::ExpectSecret { verb, value } => {
                let want = format!("{verb} {value}");
                let got = read_line(&mut io, &t, &format!("{verb} ****")).await;
                let ok = got == want;
                t.received.push(if ok {
                    format!("{verb} ****")
                } else {
                    format!("{got} (mismatch)")
                });
                assert!(ok, "expected {verb} <secret>, got another line\n{t}");
            }
            Step::Delay(d) => tokio::time::sleep(d).await,
            Step::ReplyText(text) => {
                let line = format!("{text}\r\n");
                write(&mut io, line.as_bytes(), &mut t).await;
            }
            Step::PasvListen | Step::PasvListenAs(_) => {
                let got = read_line(&mut io, &t, "PASV").await;
                t.received.push(got.clone());
                assert!(got == "PASV", "expected \"PASV\", got {got:?}\n{t}");
                let addr = data.listen(&t).await;
                let SocketAddr::V4(local) = addr else {
                    panic!("PASV over IPv6\n{t}");
                };
                let announced = match step {
                    Step::PasvListenAs(ip) => SocketAddrV4::new(ip, local.port()),
                    _ => local,
                };
                let line = format!(
                    "227 Entering Passive Mode ({}).\r\n",
                    format_port(announced)
                );
                write(&mut io, line.as_bytes(), &mut t).await;
            }
            Step::EpsvListen => {
                let got = read_line(&mut io, &t, "EPSV").await;
                t.received.push(got.clone());
                assert!(got == "EPSV", "expected \"EPSV\", got {got:?}\n{t}");
                let addr = data.listen(&t).await;
                let line = format!(
                    "229 Entering Extended Passive Mode (|||{}|)\r\n",
                    addr.port()
                );
                write(&mut io, line.as_bytes(), &mut t).await;
            }
            Step::ExpectPortThenConnect => {
                let got = read_line(&mut io, &t, "PORT/EPRT").await;
                t.received.push(got.clone());
                let port = if let Some(arg) = got.strip_prefix("PORT ") {
                    parse_pasv(arg).map(|a| a.port()).ok()
                } else if let Some(arg) = got.strip_prefix("EPRT ") {
                    parse_eprt(arg).map(|a| a.port()).ok()
                } else {
                    None
                };
                let Some(port) = port else {
                    panic!("expected PORT/EPRT, got {got:?}\n{t}");
                };
                let peer = data
                    .ctrl_peer
                    .unwrap_or_else(|| panic!("data steps need FakeServer::tcp\n{t}"));
                data.listener = None;
                data.connect_to = Some(SocketAddr::new(peer.ip(), port));
                write(&mut io, b"200 PORT command successful.\r\n", &mut t).await;
            }
            Step::DataConnectFrom(src) => {
                let addr = data
                    .connect_to
                    .unwrap_or_else(|| panic!("DataConnectFrom without PORT/EPRT\n{t}"));
                let sock = if src.is_ipv4() {
                    TcpSocket::new_v4()
                } else {
                    TcpSocket::new_v6()
                }
                .expect("socket");
                sock.bind(SocketAddr::new(src, 0)).expect("bind source IP");
                let mut foreign = sock.connect(addr).await.expect("foreign connect");
                let mut sink = Vec::new();
                let closed = tokio::time::timeout(DATA_WAIT, foreign.read_to_end(&mut sink)).await;
                assert!(
                    closed.is_ok(),
                    "the client kept a data connection from {src} open\n{t}"
                );
            }
            Step::SendData(bytes) => {
                let s = data.stream(&t).await;
                let _ = s.write_all(&bytes).await;
                let _ = s.flush().await;
            }
            Step::SendPattern { offset, len } => {
                let s = data.stream(&t).await;
                let mut sent = 0u64;
                while sent < len {
                    let n = (len - sent).min(64 * 1024);
                    let chunk = pattern_bytes(offset + sent, n as usize);
                    if s.write_all(&chunk).await.is_err() {
                        break;
                    }
                    sent += n;
                }
                let _ = s.flush().await;
            }
            Step::RecvData(want) => {
                let s = data.stream(&t).await;
                let mut got = Vec::new();
                match tokio::time::timeout(DATA_WAIT, s.read_to_end(&mut got)).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => panic!("data read failed: {e}\n{t}"),
                    Err(_) => panic!("the client never closed the upload\n{t}"),
                }
                if got != want {
                    let first = got.iter().zip(&want).position(|(a, b)| a != b);
                    panic!(
                        "upload mismatch: got {} bytes, want {}, first difference at {first:?}\n{t}",
                        got.len(),
                        want.len()
                    );
                }
            }
            Step::CloseData => {
                if let Some(mut s) = data.stream.take() {
                    let _ = s.shutdown().await;
                }
                data.close();
            }
            Step::ExpectAbor => {
                let got = read_line(&mut io, &t, "ABOR").await;
                t.received.push(got.clone());
                assert!(got == "ABOR", "expected \"ABOR\", got {got:?}\n{t}");
                data.close();
            }
            Step::Close => {
                let _ = io.get_mut().shutdown().await;
                assert!(i + 1 == total, "steps after Close are never run\n{t}");
                return t;
            }
        }
    }
    // Script done: wait for the client to close; it must not send anything else.
    let mut extra = Vec::new();
    loop {
        let mut line = Vec::new();
        match io.read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => extra.push(clean(&line)),
        }
    }
    assert!(
        extra.is_empty(),
        "client sent {extra:?} after the end of the script\n{t}"
    );
    t
}

async fn write<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut BufReader<S>,
    bytes: &[u8],
    t: &mut Transcript,
) {
    t.sent.push(String::from_utf8_lossy(bytes).into_owned());
    // The client may already be gone (tests of early failures).
    let _ = io.get_mut().write_all(bytes).await;
    let _ = io.get_mut().flush().await;
}

async fn read_line<S: AsyncRead + Unpin>(
    io: &mut BufReader<S>,
    t: &Transcript,
    want: &str,
) -> String {
    clean(&read_raw(io, t, want).await)
}

/// The next line without its CRLF.
async fn read_raw<S: AsyncRead + Unpin>(
    io: &mut BufReader<S>,
    t: &Transcript,
    want: &str,
) -> Vec<u8> {
    let mut line = Vec::new();
    match io.read_until(b'\n', &mut line).await {
        Ok(0) => panic!("expected {want:?}, got end of stream\n{t}"),
        Ok(_) => {
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            line
        }
        Err(e) => panic!("expected {want:?}, got read error {e}\n{t}"),
    }
}

/// Strips CRLF; undoes the Telnet IAC doubling; lossy UTF-8.
fn clean(line: &[u8]) -> String {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut out = Vec::with_capacity(line.len());
    let mut iter = line.iter().peekable();
    while let Some(&b) = iter.next() {
        out.push(b);
        if b == 0xFF && iter.peek() == Some(&&0xFF) {
            iter.next();
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
