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

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::{fmt, net::SocketAddr, time::Duration};

use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    task::JoinHandle,
};

use crate::control::BoxedIo;

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
        let task = tokio::spawn(run(server, script));
        (Self { task }, Box::new(client))
    }

    /// Runs `script` on the first connection accepted on a loopback port.
    pub async fn tcp(script: Vec<Step>) -> (Self, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            run(stream, script).await
        });
        (Self { task }, addr)
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

async fn run<S: AsyncRead + AsyncWrite + Unpin>(stream: S, script: Vec<Step>) -> Transcript {
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
