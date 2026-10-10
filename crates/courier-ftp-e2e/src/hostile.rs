//! [`HostileFtpd`]: a scripted, deliberately misbehaving FTP server in-process (tokio,
//! `127.0.0.1:0`, no Docker).
//!
//! It accepts any login and serves exactly what its [`HostileScript`] says: a banner
//! that may contain escape sequences, raw listing lines sent verbatim (names with
//! `..`, `/`, NUL, ESC, …), files, an absurd `SIZE`, a forged `227` reply. Feature
//! tasks use it to prove the client neutralises hostile input (T13, T42, T53, T55, T91).
//!
//! Speaks `USER PASS SYST FEAT PWD CWD TYPE PASV EPSV LIST MLSD NLST SIZE MDTM RETR
//! QUIT`; everything else gets `502`.

use std::{net::SocketAddr, sync::Arc};

use parking_lot::Mutex;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use crate::{E2eError, Result};

/// What a [`HostileFtpd`] serves.
#[derive(Debug, Clone)]
pub struct HostileScript {
    /// The text after `220 ` in the greeting (may contain ESC sequences).
    pub banner: String,
    /// `FEAT` lines (without the leading space).
    pub feat: Vec<String>,
    /// Raw `LIST`/`MLSD`/`NLST` lines, sent verbatim, each followed by `\r\n`.
    pub listing: Vec<String>,
    /// `RETR` name → bytes.
    pub files: Vec<(String, Vec<u8>)>,
    /// `SIZE` reply override (e.g. `u64::MAX`); else the file's real size.
    pub reported_size: Option<u64>,
    /// Raw `227` reply text override (the whole line without CRLF).
    pub pasv_reply: Option<String>,
}

impl Default for HostileScript {
    fn default() -> Self {
        Self {
            banner: "courier-ftp-e2e hostile server".into(),
            feat: vec!["UTF8".into(), "SIZE".into(), "MDTM".into(), "EPSV".into()],
            listing: Vec::new(),
            files: Vec::new(),
            reported_size: None,
            pasv_reply: None,
        }
    }
}

/// A scripted FTP server on `127.0.0.1`. Stops when dropped.
#[derive(Debug)]
pub struct HostileFtpd {
    addr: SocketAddr,
    commands: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl HostileFtpd {
    /// Start serving `script`.
    ///
    /// # Errors
    /// The listener could not be bound.
    pub async fn start(script: HostileScript) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let commands = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(script);
        let log = Arc::clone(&commands);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let script = Arc::clone(&script);
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let _ = serve(stream, &script, &log).await;
                });
            }
        });
        Ok(Self {
            addr,
            commands,
            task,
        })
    }

    /// The control address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every command line received so far (all connections), `PASS` masked as `****`.
    pub fn commands(&self) -> Vec<String> {
        self.commands.lock().clone()
    }
}

impl Drop for HostileFtpd {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Mask the argument of `PASS` (any case).
pub(crate) fn mask_pass(line: &str) -> String {
    let (verb, _) = split_command(line);
    if verb == "PASS" {
        "PASS ****".into()
    } else {
        line.to_owned()
    }
}

/// `(UPPERCASE verb, argument)`.
pub(crate) fn split_command(line: &str) -> (String, &str) {
    let (verb, arg) = line.split_once(' ').unwrap_or((line, ""));
    (verb.to_ascii_uppercase(), arg)
}

async fn reply(w: &mut (impl AsyncWriteExt + Unpin), text: &str) -> std::io::Result<()> {
    w.write_all(text.as_bytes()).await?;
    w.write_all(b"\r\n").await?;
    w.flush().await
}

async fn accept_data(listener: &TcpListener) -> std::io::Result<TcpStream> {
    tokio::time::timeout(crate::timeout(), listener.accept())
        .await
        .map_err(|_| std::io::Error::other("no data connection"))?
        .map(|(s, _)| s)
}

async fn serve(
    stream: TcpStream,
    script: &HostileScript,
    log: &Mutex<Vec<String>>,
) -> std::io::Result<()> {
    let (r, mut w) = stream.into_split();
    let mut lines = BufReader::new(r);
    reply(&mut w, &format!("220 {}", script.banner)).await?;
    let mut data: Option<TcpListener> = None;
    let mut line = Vec::new();
    loop {
        line.clear();
        if lines.read_until(b'\n', &mut line).await? == 0 {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches(['\r', '\n']);
        log.lock().push(mask_pass(text));
        let (verb, arg) = split_command(text);
        match verb.as_str() {
            "USER" => reply(&mut w, "331 Password required").await?,
            "PASS" => reply(&mut w, "230 Logged in").await?,
            "SYST" => reply(&mut w, "215 UNIX Type: L8").await?,
            "FEAT" => {
                let mut text = String::from("211-Features:\r\n");
                for f in &script.feat {
                    text.push_str(&format!(" {f}\r\n"));
                }
                text.push_str("211 End");
                reply(&mut w, &text).await?;
            }
            "PWD" => reply(&mut w, "257 \"/\" is the current directory").await?,
            "CWD" => reply(&mut w, "250 OK").await?,
            "TYPE" => reply(&mut w, "200 Type set").await?,
            "PASV" => {
                let l = TcpListener::bind(("127.0.0.1", 0)).await?;
                let port = l.local_addr()?.port();
                data = Some(l);
                let text = script.pasv_reply.clone().unwrap_or_else(|| {
                    format!(
                        "227 Entering Passive Mode (127,0,0,1,{},{})",
                        port >> 8,
                        port & 0xff
                    )
                });
                reply(&mut w, &text).await?;
            }
            "EPSV" => {
                let l = TcpListener::bind(("127.0.0.1", 0)).await?;
                let port = l.local_addr()?.port();
                data = Some(l);
                reply(
                    &mut w,
                    &format!("229 Entering Extended Passive Mode (|||{port}|)"),
                )
                .await?;
            }
            "LIST" | "MLSD" | "NLST" => {
                let Some(l) = data.take() else {
                    reply(&mut w, "425 Use PASV or EPSV first").await?;
                    continue;
                };
                reply(&mut w, "150 Here comes the listing").await?;
                let mut conn = accept_data(&l).await?;
                for entry in &script.listing {
                    conn.write_all(entry.as_bytes()).await?;
                    conn.write_all(b"\r\n").await?;
                }
                conn.shutdown().await?;
                drop(conn);
                reply(&mut w, "226 Transfer complete").await?;
            }
            "SIZE" => match find(script, arg) {
                Some(bytes) => {
                    let size = script.reported_size.unwrap_or(bytes.len() as u64);
                    reply(&mut w, &format!("213 {size}")).await?;
                }
                None if script.reported_size.is_some() => {
                    let size = script.reported_size.unwrap_or_default();
                    reply(&mut w, &format!("213 {size}")).await?;
                }
                None => reply(&mut w, "550 No such file").await?,
            },
            "MDTM" => reply(&mut w, "213 20240101000000").await?,
            "RETR" => {
                let Some(bytes) = find(script, arg) else {
                    reply(&mut w, "550 No such file").await?;
                    continue;
                };
                let Some(l) = data.take() else {
                    reply(&mut w, "425 Use PASV or EPSV first").await?;
                    continue;
                };
                reply(&mut w, "150 Opening data connection").await?;
                let mut conn = accept_data(&l).await?;
                conn.write_all(bytes).await?;
                conn.shutdown().await?;
                drop(conn);
                reply(&mut w, "226 Transfer complete").await?;
            }
            "QUIT" => {
                reply(&mut w, "221 Bye").await?;
                return Ok(());
            }
            _ => reply(&mut w, "502 Command not implemented").await?,
        }
    }
}

fn find<'a>(script: &'a HostileScript, name: &str) -> Option<&'a [u8]> {
    let name = name.trim_start_matches('/');
    script
        .files
        .iter()
        .find(|(n, _)| n.trim_start_matches('/') == name)
        .map(|(_, b)| b.as_slice())
}

/// A minimal FTP client for the harness self-tests: login, `PASV` + `LIST`/`RETR`.
#[derive(Debug)]
pub struct MiniFtpClient {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
    /// The greeting line.
    pub greeting: String,
}

impl MiniFtpClient {
    /// Connect and read the greeting.
    ///
    /// # Errors
    /// I/O failed.
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let (r, writer) = stream.into_split();
        let mut client = Self {
            reader: BufReader::new(r),
            writer,
            greeting: String::new(),
        };
        client.greeting = client.read_reply().await?;
        Ok(client)
    }

    /// Read one (possibly multi-line) reply; returns its last line.
    ///
    /// # Errors
    /// I/O failed or the connection closed.
    pub async fn read_reply(&mut self) -> Result<String> {
        let mut first: Option<String> = None;
        loop {
            let mut line = Vec::new();
            let n =
                tokio::time::timeout(crate::timeout(), self.reader.read_until(b'\n', &mut line))
                    .await
                    .map_err(|_| E2eError::new("no reply"))??;
            if n == 0 {
                return Err(E2eError::new("connection closed"));
            }
            let text = String::from_utf8_lossy(&line)
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            let code = text.get(..3).map(str::to_owned);
            match &first {
                None if text.as_bytes().get(3) == Some(&b'-') => first = code,
                None => return Ok(text),
                Some(c) if Some(c) == code.as_ref() && text.as_bytes().get(3) == Some(&b' ') => {
                    return Ok(text);
                }
                Some(_) => {}
            }
        }
    }

    /// Send `line` and read the reply.
    ///
    /// # Errors
    /// I/O failed.
    pub async fn cmd(&mut self, line: &str) -> Result<String> {
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\r\n").await?;
        self.read_reply().await
    }

    /// `USER` + `PASS`; returns the final reply.
    ///
    /// # Errors
    /// I/O failed.
    pub async fn login(&mut self, user: &str, pass: &str) -> Result<String> {
        let r = self.cmd(&format!("USER {user}")).await?;
        if r.starts_with("331") {
            self.cmd(&format!("PASS {pass}")).await
        } else {
            Ok(r)
        }
    }

    /// `PASV`, then `verb` (e.g. `"LIST"`, `"RETR small.bin"`); returns the data
    /// bytes and the final reply.
    ///
    /// # Errors
    /// I/O failed or a reply was negative.
    pub async fn pasv_transfer(&mut self, verb: &str) -> Result<(Vec<u8>, String)> {
        use tokio::io::AsyncReadExt;
        let r = self.cmd("PASV").await?;
        let addr = crate::ftp_proxy::parse_pasv(&r)
            .ok_or_else(|| E2eError::new(format!("bad PASV reply {r:?}")))?;
        let mut data = TcpStream::connect(addr).await?;
        let r = self.cmd(verb).await?;
        if !r.starts_with("150") && !r.starts_with("125") {
            return Err(E2eError::new(format!("{verb}: {r}")));
        }
        let mut bytes = Vec::new();
        tokio::time::timeout(crate::timeout(), data.read_to_end(&mut bytes))
            .await
            .map_err(|_| E2eError::new("data connection stalled"))??;
        let done = self.read_reply().await?;
        Ok((bytes, done))
    }
}
