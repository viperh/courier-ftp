//! An in-process FTP server with an in-memory file system, for the data
//! connection, FTPS and backend tests (T11, T12, T14).
//!
//! It implements enough of RFC 959/2428/3659 to behave like a real server:
//! login, `SYST`, `FEAT`, `PWD`/`CWD`/`CDUP`, `TYPE` (ASCII converts LF ↔
//! CRLF), `PASV`/`EPSV`/`PORT`/`EPRT`, `REST`, `RETR`/`STOR`/`APPE`,
//! `LIST`/`NLST`/`MLSD`/`MLST`, `SIZE`, `MDTM` (query and set), `MFMT`,
//! `MKD`/`RMD`/`DELE`, `RNFR`/`RNTO`, `SITE CHMOD`, `ABOR` (also during a
//! transfer), and with [`ServerConfig::tls`] `AUTH TLS`, `PBSZ`, `PROT` and
//! implicit TLS. Behaviour switches in [`ServerConfig`] let tests force
//! fallbacks (no `EPSV`, refused `PASV`, unroutable `PASV` address, …).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::question_mark,
    dead_code
)]

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use courier_ftp_core::model::RemotePath;
use time::{OffsetDateTime, macros::format_description};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

/// A stream the server talks over (TCP or TLS).
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type BoxIo = Box<dyn Io>;

/// TLS for the server (T12).
#[derive(Clone)]
pub(crate) struct ServerTls {
    pub(crate) acceptor: tokio_rustls::TlsAcceptor,
    /// TLS from the first byte (implicit FTPS).
    pub(crate) implicit: bool,
    /// Refuse data connections that don't resume the control session
    /// (vsftpd `require_ssl_reuse=YES`).
    pub(crate) require_reuse: bool,
    /// Answer `PROT P` with an error.
    pub(crate) refuse_prot_p: bool,
}

/// What the server does.
#[derive(Clone)]
pub(crate) struct ServerConfig {
    pub(crate) user: String,
    pub(crate) password: String,
    pub(crate) syst: String,
    /// `MLSD`/`MLST` supported and announced.
    pub(crate) mlst: bool,
    /// `EPSV` announced in `FEAT`.
    pub(crate) epsv_feat: bool,
    /// `EPSV` answered with `500`.
    pub(crate) refuse_epsv: bool,
    /// `PASV` answered with `502`.
    pub(crate) refuse_pasv: bool,
    /// `EPRT` answered with `500`.
    pub(crate) refuse_eprt: bool,
    /// The address `PASV` announces instead of the listener's.
    pub(crate) pasv_ip: Option<Ipv4Addr>,
    /// `PASV`/`EPSV` announce a port nobody listens on.
    pub(crate) pasv_dead_port: bool,
    pub(crate) rest_stream: bool,
    pub(crate) mfmt: bool,
    /// `SITE CHMOD` works (else `500`).
    pub(crate) chmod: bool,
    /// `MDTM YYYYMMDDHHMMSS path` sets the time.
    pub(crate) mdtm_set: bool,
    /// Bytes per write on data connections.
    pub(crate) chunk: usize,
    /// Pause between data chunks.
    pub(crate) data_delay: Option<Duration>,
    /// Error texts like vsftpd ("Delete operation failed") instead of
    /// telling ones ("No such file or directory").
    pub(crate) vague_errors: bool,
    pub(crate) tls: Option<ServerTls>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            user: "bob".into(),
            password: "secret".into(),
            syst: "UNIX Type: L8".into(),
            mlst: true,
            epsv_feat: true,
            refuse_epsv: false,
            refuse_pasv: false,
            refuse_eprt: false,
            pasv_ip: None,
            pasv_dead_port: false,
            rest_stream: true,
            mfmt: true,
            chmod: true,
            mdtm_set: false,
            chunk: 16 * 1024,
            data_delay: None,
            vague_errors: false,
            tls: None,
        }
    }
}

/// One file system node.
#[derive(Debug, Clone)]
pub(crate) enum Node {
    Dir {
        mode: u32,
        mtime: OffsetDateTime,
    },
    File {
        data: Vec<u8>,
        mode: u32,
        mtime: OffsetDateTime,
    },
    /// A large file whose byte at offset `i` is `i % 251` (for > 4 GiB
    /// offsets without the memory).
    Virtual {
        size: u64,
    },
}

impl Node {
    pub(crate) fn file(data: &[u8]) -> Self {
        Node::File {
            data: data.to_vec(),
            mode: 0o644,
            mtime: OffsetDateTime::now_utc(),
        }
    }

    fn dir() -> Self {
        Node::Dir {
            mode: 0o755,
            mtime: OffsetDateTime::now_utc(),
        }
    }

    fn is_dir(&self) -> bool {
        matches!(self, Node::Dir { .. })
    }

    fn size(&self) -> u64 {
        match self {
            Node::Dir { .. } => 0,
            Node::File { data, .. } => data.len() as u64,
            Node::Virtual { size } => *size,
        }
    }

    fn mode(&self) -> u32 {
        match self {
            Node::Dir { mode, .. } | Node::File { mode, .. } => *mode,
            Node::Virtual { .. } => 0o444,
        }
    }

    fn mtime(&self) -> OffsetDateTime {
        match self {
            Node::Dir { mtime, .. } | Node::File { mtime, .. } => *mtime,
            Node::Virtual { .. } => OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// The bytes from `offset` on.
    fn bytes_from(&self, offset: u64) -> Vec<u8> {
        match self {
            Node::File { data, .. } => data
                .get(
                    usize::try_from(offset)
                        .unwrap_or(usize::MAX)
                        .min(data.len())..,
                )
                .unwrap_or_default()
                .to_vec(),
            Node::Virtual { size } => (offset..*size).map(|i| (i % 251) as u8).collect(),
            Node::Dir { .. } => Vec::new(),
        }
    }
}

/// The server's state, shared with the test.
#[derive(Debug, Default)]
pub(crate) struct State {
    pub(crate) fs: BTreeMap<String, Node>,
    /// Every command line received, all connections (PASS masked).
    pub(crate) commands: Vec<String>,
    /// Data connections: (was TLS, was resumed).
    pub(crate) data_tls: Vec<(bool, bool)>,
    /// Logins so far.
    pub(crate) logins: usize,
}

/// A running server.
pub(crate) struct TestServer {
    pub(crate) addr: SocketAddr,
    pub(crate) state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    /// Start on 127.0.0.1 with `config` and a file system holding `/` and
    /// `/home/bob`.
    pub(crate) async fn start(config: ServerConfig) -> Self {
        Self::start_on("127.0.0.1:0".parse().unwrap(), config).await
    }

    /// Start on `bind`.
    pub(crate) async fn start_on(bind: SocketAddr, config: ServerConfig) -> Self {
        let listener = TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut state = State::default();
        state.fs.insert("/".into(), Node::dir());
        state.fs.insert("/home".into(), Node::dir());
        state.fs.insert("/home/bob".into(), Node::dir());
        let state = Arc::new(Mutex::new(state));
        let shared = Arc::clone(&state);
        let config = Arc::new(config);
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, peer)) = listener.accept().await else {
                    return;
                };
                let state = Arc::clone(&shared);
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    let local = tcp.local_addr().unwrap();
                    let stream: BoxIo = match &config.tls {
                        Some(tls) if tls.implicit => match tls.acceptor.accept(tcp).await {
                            Ok(s) => Box::new(s),
                            Err(_) => return,
                        },
                        _ => Box::new(tcp),
                    };
                    let implicit = config.tls.as_ref().is_some_and(|t| t.implicit);
                    let mut session = Session {
                        stream,
                        buf: Vec::new(),
                        config,
                        state,
                        local,
                        peer,
                        cwd: "/home/bob".into(),
                        user_ok: false,
                        logged_in: false,
                        ascii: false,
                        rest: 0,
                        rnfr: None,
                        passive: None,
                        active: None,
                        tls: implicit,
                        prot_p: false,
                    };
                    session.run().await;
                });
            }
        });
        Self { addr, state, task }
    }

    /// Add a file.
    pub(crate) fn put(&self, path: &str, data: &[u8]) {
        self.state
            .lock()
            .unwrap()
            .fs
            .insert(path.into(), Node::file(data));
    }

    /// Add a node.
    pub(crate) fn put_node(&self, path: &str, node: Node) {
        self.state.lock().unwrap().fs.insert(path.into(), node);
    }

    /// Add a directory.
    pub(crate) fn mkdir(&self, path: &str) {
        self.put_node(path, Node::dir());
    }

    /// A file's contents.
    pub(crate) fn get(&self, path: &str) -> Option<Vec<u8>> {
        match self.state.lock().unwrap().fs.get(path) {
            Some(Node::File { data, .. }) => Some(data.clone()),
            _ => None,
        }
    }

    /// Every command received so far.
    pub(crate) fn commands(&self) -> Vec<String> {
        self.state.lock().unwrap().commands.clone()
    }

    /// Data connections so far: (TLS, resumed).
    pub(crate) fn data_tls(&self) -> Vec<(bool, bool)> {
        self.state.lock().unwrap().data_tls.clone()
    }
}

/// How a data transfer ended.
enum Outcome {
    Done,
    /// The client sent `ABOR` during the transfer.
    Aborted,
    /// The data connection failed.
    Failed,
    /// The control connection went away.
    Gone,
}

struct Session {
    stream: BoxIo,
    buf: Vec<u8>,
    config: Arc<ServerConfig>,
    state: Arc<Mutex<State>>,
    local: SocketAddr,
    peer: SocketAddr,
    cwd: String,
    user_ok: bool,
    logged_in: bool,
    ascii: bool,
    rest: u64,
    rnfr: Option<String>,
    passive: Option<TcpListener>,
    active: Option<SocketAddr>,
    tls: bool,
    prot_p: bool,
}

impl Session {
    async fn send(&mut self, line: &str) -> bool {
        let mut bytes = line.as_bytes().to_vec();
        bytes.extend_from_slice(b"\r\n");
        self.stream.write_all(&bytes).await.is_ok() && self.stream.flush().await.is_ok()
    }

    /// The next command line, `None` when the client is gone.
    async fn read_line(&mut self) -> Option<String> {
        loop {
            if let Some(i) = self.buf.iter().position(|b| *b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=i).collect();
                while matches!(line.last(), Some(b'\r' | b'\n')) {
                    line.pop();
                }
                return Some(String::from_utf8_lossy(&line).into_owned());
            }
            let mut chunk = [0u8; 1024];
            match self.stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    fn resolve(&self, arg: &str) -> String {
        RemotePath::new(&self.cwd)
            .join_path(arg)
            .as_str()
            .to_owned()
    }

    fn not_found(&self, what: &str) -> String {
        if self.config.vague_errors {
            format!("550 {what} operation failed.")
        } else {
            "550 No such file or directory".to_owned()
        }
    }

    async fn run(&mut self) {
        if !self.send("220 Fake FTP server ready").await {
            return;
        }
        while let Some(line) = self.read_line().await {
            let (verb, arg) = match line.split_once(' ') {
                Some((v, a)) => (v.to_ascii_uppercase(), a.to_owned()),
                None => (line.to_ascii_uppercase(), String::new()),
            };
            let logged = if verb == "PASS" {
                "PASS ****".to_owned()
            } else {
                line.clone()
            };
            self.state.lock().unwrap().commands.push(logged);
            if !self.handle(&verb, &arg).await {
                return;
            }
        }
    }

    /// Handle one command; `false` ends the session.
    #[allow(clippy::too_many_lines)]
    async fn handle(&mut self, verb: &str, arg: &str) -> bool {
        let public = matches!(
            verb,
            "USER" | "PASS" | "QUIT" | "AUTH" | "PBSZ" | "PROT" | "FEAT" | "SYST" | "NOOP"
        );
        if !public && !self.logged_in {
            return self.send("530 Please login with USER and PASS").await;
        }
        let reply: String = match verb {
            "USER" => {
                self.user_ok = arg == self.config.user;
                "331 Please specify the password.".into()
            }
            "PASS" => {
                if self.user_ok && arg == self.config.password {
                    self.logged_in = true;
                    self.state.lock().unwrap().logins += 1;
                    "230 Login successful.".into()
                } else {
                    "530 Login incorrect.".into()
                }
            }
            "QUIT" => {
                self.send("221 Goodbye.").await;
                return false;
            }
            "SYST" => format!("215 {}", self.config.syst),
            "NOOP" => "200 NOOP ok.".into(),
            "FEAT" => {
                let mut lines = vec!["211-Features:".to_owned()];
                if self.config.epsv_feat {
                    lines.push(" EPSV".into());
                    lines.push(" EPRT".into());
                }
                lines.push(" MDTM".into());
                lines.push(" SIZE".into());
                lines.push(" UTF8".into());
                if self.config.rest_stream {
                    lines.push(" REST STREAM".into());
                }
                if self.config.mlst {
                    lines.push(" MLST type*;size*;modify*;UNIX.mode*;".into());
                }
                if self.config.mfmt {
                    lines.push(" MFMT".into());
                }
                if self.config.tls.is_some() {
                    lines.push(" AUTH TLS".into());
                    lines.push(" PBSZ".into());
                    lines.push(" PROT".into());
                }
                lines.push("211 End".into());
                for l in &lines[..lines.len() - 1] {
                    if !self.send(l).await {
                        return false;
                    }
                }
                lines.last().cloned().unwrap_or_default()
            }
            "OPTS" | "CLNT" => "200 Ok.".into(),
            "AUTH" => match &self.config.tls {
                Some(tls) if !self.tls && arg.eq_ignore_ascii_case("TLS") => {
                    let acceptor = tls.acceptor.clone();
                    if !self.send("234 Proceed with negotiation.").await {
                        return false;
                    }
                    let plain =
                        std::mem::replace(&mut self.stream, Box::new(tokio::io::duplex(1).0));
                    match acceptor.accept(plain).await {
                        Ok(s) => {
                            self.stream = Box::new(s);
                            self.tls = true;
                            return true;
                        }
                        Err(_) => return false,
                    }
                }
                _ => "504 Unknown AUTH type.".into(),
            },
            "PBSZ" => {
                if self.tls {
                    "200 PBSZ set to 0.".into()
                } else {
                    "503 PBSZ needs a secure connection.".into()
                }
            }
            "PROT" => {
                if !self.tls {
                    "503 PROT needs a secure connection.".into()
                } else if arg.eq_ignore_ascii_case("P") {
                    if self.config.tls.as_ref().is_some_and(|t| t.refuse_prot_p) {
                        "536 PROT P not supported.".into()
                    } else {
                        self.prot_p = true;
                        "200 PROT now Private.".into()
                    }
                } else if arg.eq_ignore_ascii_case("C") {
                    self.prot_p = false;
                    "200 PROT now Clear.".into()
                } else {
                    "504 Bad PROT.".into()
                }
            }
            "PWD" | "XPWD" => format!(
                "257 \"{}\" is the current directory",
                self.cwd.replace('"', "\"\"")
            ),
            "CWD" | "XCWD" => {
                let path = self.resolve(arg);
                if self
                    .state
                    .lock()
                    .unwrap()
                    .fs
                    .get(&path)
                    .is_some_and(Node::is_dir)
                {
                    self.cwd = path;
                    "250 Directory successfully changed.".into()
                } else if self.config.vague_errors {
                    "550 Failed to change directory.".into()
                } else {
                    "550 No such file or directory".into()
                }
            }
            "CDUP" | "XCUP" => {
                self.cwd = RemotePath::new(&self.cwd)
                    .parent()
                    .unwrap_or_default()
                    .as_str()
                    .to_owned();
                "250 Directory successfully changed.".into()
            }
            "TYPE" => match arg.to_ascii_uppercase().as_str() {
                "A" | "A N" => {
                    self.ascii = true;
                    "200 Switching to ASCII mode.".into()
                }
                "I" | "L 8" => {
                    self.ascii = false;
                    "200 Switching to Binary mode.".into()
                }
                _ => "504 Bad TYPE.".into(),
            },
            "PASV" => {
                if self.config.refuse_pasv {
                    "502 PASV not implemented.".into()
                } else {
                    let ip = match self.local.ip() {
                        IpAddr::V4(v4) => v4,
                        IpAddr::V6(_) => return self.send("522 Use EPSV.").await,
                    };
                    let port = self.listen().await;
                    let ip = self.config.pasv_ip.unwrap_or(ip);
                    let [a, b, c, d] = ip.octets();
                    format!(
                        "227 Entering Passive Mode ({a},{b},{c},{d},{},{}).",
                        port >> 8,
                        port & 0xff
                    )
                }
            }
            "EPSV" => {
                if self.config.refuse_epsv {
                    "500 Unknown command.".into()
                } else {
                    let port = self.listen().await;
                    format!("229 Entering Extended Passive Mode (|||{port}|)")
                }
            }
            "PORT" => {
                let n: Vec<u16> = arg
                    .split(',')
                    .filter_map(|p| p.trim().parse().ok())
                    .collect();
                if n.len() == 6 {
                    let ip = Ipv4Addr::new(n[0] as u8, n[1] as u8, n[2] as u8, n[3] as u8);
                    self.active = Some(SocketAddr::new(IpAddr::V4(ip), n[4] << 8 | n[5]));
                    self.passive = None;
                    "200 PORT command successful.".into()
                } else {
                    "501 Illegal PORT command.".into()
                }
            }
            "EPRT" => {
                if self.config.refuse_eprt {
                    "500 Unknown command.".into()
                } else {
                    let parts: Vec<&str> = arg.split('|').collect();
                    match (parts.get(2), parts.get(3)) {
                        (Some(ip), Some(port)) => match (ip.parse::<IpAddr>(), port.parse::<u16>())
                        {
                            (Ok(ip), Ok(port)) => {
                                self.active = Some(SocketAddr::new(ip, port));
                                self.passive = None;
                                "200 EPRT command successful.".into()
                            }
                            _ => "501 Bad EPRT.".into(),
                        },
                        _ => "501 Bad EPRT.".into(),
                    }
                }
            }
            "REST" => match arg.parse::<u64>() {
                Ok(n) => {
                    self.rest = n;
                    format!("350 Restart position accepted ({n}).")
                }
                Err(_) => "501 Bad REST.".into(),
            },
            "RETR" => return self.retr(arg).await,
            "STOR" | "APPE" => return self.store(arg, verb == "APPE").await,
            "LIST" | "NLST" | "MLSD" => return self.list(verb, arg).await,
            "MLST" => {
                if !self.config.mlst {
                    "500 Unknown command.".into()
                } else {
                    let path = self.resolve(if arg.is_empty() { "." } else { arg });
                    let node = self.state.lock().unwrap().fs.get(&path).cloned();
                    match node {
                        Some(node) => {
                            let facts = mlsd_facts(&node);
                            for l in [format!("250-Listing {path}"), format!(" {facts} {path}")] {
                                if !self.send(&l).await {
                                    return false;
                                }
                            }
                            "250 End".into()
                        }
                        None => self.not_found("MLST"),
                    }
                }
            }
            "SIZE" => {
                let path = self.resolve(arg);
                match self.state.lock().unwrap().fs.get(&path) {
                    Some(n) if !n.is_dir() => format!("213 {}", n.size()),
                    _ => "550 Could not get file size.".into(),
                }
            }
            "MDTM" => {
                let set = arg
                    .split_once(' ')
                    .filter(|(t, _)| t.len() == 14 && t.bytes().all(|b| b.is_ascii_digit()));
                match set {
                    Some((t, p)) if self.config.mdtm_set => self.set_time(t, p),
                    _ => {
                        let path = self.resolve(arg);
                        match self.state.lock().unwrap().fs.get(&path) {
                            Some(n) if !n.is_dir() => format!("213 {}", fmt_time(n.mtime())),
                            _ => "550 Could not get file modification time.".into(),
                        }
                    }
                }
            }
            "MFMT" if self.config.mfmt => match arg.split_once(' ') {
                Some((t, p)) => self.set_time(t, p),
                None => "501 Bad MFMT.".into(),
            },
            "MKD" | "XMKD" => {
                let path = self.resolve(arg);
                let mut state = self.state.lock().unwrap();
                let parent = RemotePath::new(&path).parent().unwrap_or_default();
                if state.fs.contains_key(&path) {
                    if self.config.vague_errors {
                        "550 Create directory operation failed.".into()
                    } else {
                        "550 File exists".into()
                    }
                } else if !state.fs.get(parent.as_str()).is_some_and(Node::is_dir) {
                    if self.config.vague_errors {
                        "550 Create directory operation failed.".into()
                    } else {
                        "550 No such file or directory".into()
                    }
                } else {
                    state.fs.insert(path.clone(), Node::dir());
                    format!("257 \"{path}\" created")
                }
            }
            "RMD" | "XRMD" => {
                let path = self.resolve(arg);
                let mut state = self.state.lock().unwrap();
                let prefix = format!("{path}/");
                if !state.fs.get(&path).is_some_and(Node::is_dir) {
                    self.not_found("Remove directory")
                } else if state.fs.keys().any(|k| k.starts_with(&prefix)) {
                    if self.config.vague_errors {
                        "550 Remove directory operation failed.".into()
                    } else {
                        "550 Directory not empty".into()
                    }
                } else {
                    state.fs.remove(&path);
                    "250 Remove directory operation successful.".into()
                }
            }
            "DELE" => {
                let path = self.resolve(arg);
                let mut state = self.state.lock().unwrap();
                match state.fs.get(&path) {
                    Some(n) if !n.is_dir() => {
                        state.fs.remove(&path);
                        "250 Delete operation successful.".into()
                    }
                    _ => self.not_found("Delete"),
                }
            }
            "RNFR" => {
                let path = self.resolve(arg);
                if self.state.lock().unwrap().fs.contains_key(&path) {
                    self.rnfr = Some(path);
                    "350 Ready for RNTO.".into()
                } else if self.config.vague_errors {
                    "550 RNFR command failed.".into()
                } else {
                    "550 No such file or directory".into()
                }
            }
            "RNTO" => match self.rnfr.take() {
                None => "503 RNFR required first.".into(),
                Some(from) => {
                    let to = self.resolve(arg);
                    let mut state = self.state.lock().unwrap();
                    let moved: Vec<(String, Node)> = state
                        .fs
                        .iter()
                        .filter(|(k, _)| **k == from || k.starts_with(&format!("{from}/")))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    for (k, _) in &moved {
                        state.fs.remove(k);
                    }
                    for (k, v) in moved {
                        let new = format!("{to}{}", &k[from.len()..]);
                        state.fs.insert(new, v);
                    }
                    "250 Rename successful.".into()
                }
            },
            "SITE" => {
                let mut words = arg.splitn(3, ' ');
                let sub = words.next().unwrap_or_default().to_ascii_uppercase();
                if sub == "CHMOD" && self.config.chmod {
                    let mode = words.next().and_then(|m| u32::from_str_radix(m, 8).ok());
                    let path = self.resolve(words.next().unwrap_or_default());
                    let mut state = self.state.lock().unwrap();
                    match (mode, state.fs.get_mut(&path)) {
                        (Some(m), Some(Node::File { mode, .. } | Node::Dir { mode, .. })) => {
                            *mode = m;
                            "200 SITE CHMOD command ok.".into()
                        }
                        _ => "550 SITE CHMOD command failed.".into(),
                    }
                } else {
                    "500 Unknown SITE command.".into()
                }
            }
            "ABOR" => "225 No transfer to ABOR.".into(),
            _ => "500 Unknown command.".into(),
        };
        self.send(&reply).await
    }

    fn set_time(&self, t: &str, p: &str) -> String {
        let format = format_description!("[year][month][day][hour][minute][second]");
        let Ok(parsed) = time::PrimitiveDateTime::parse(t, &format) else {
            return "501 Bad time.".into();
        };
        let path = self.resolve(p);
        let mut state = self.state.lock().unwrap();
        match state.fs.get_mut(&path) {
            Some(Node::File { mtime, .. } | Node::Dir { mtime, .. }) => {
                *mtime = parsed.assume_utc();
                format!("213 Modify={t}; {p}")
            }
            _ => "550 No such file or directory".into(),
        }
    }

    /// Bind a passive listener; the port to announce.
    async fn listen(&mut self) -> u16 {
        let listener = TcpListener::bind(SocketAddr::new(self.local.ip(), 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        self.active = None;
        if self.config.pasv_dead_port {
            // Announce a port that is closed again at once.
            drop(listener);
            self.passive = None;
            return port;
        }
        self.passive = Some(listener);
        port
    }

    /// The data connection for a transfer command (after the `150`).
    async fn data_connection(&mut self) -> Option<BoxIo> {
        let tcp = if let Some(listener) = self.passive.take() {
            let (tcp, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
                .await
                .ok()?
                .ok()?;
            tcp
        } else if let Some(addr) = self.active.take() {
            TcpStream::connect(addr).await.ok()?
        } else {
            return None;
        };
        if self.prot_p
            && let Some(tls) = self.config.tls.clone()
        {
            let stream = tls.acceptor.accept(tcp).await.ok()?;
            let resumed =
                stream.get_ref().1.handshake_kind() == Some(rustls::HandshakeKind::Resumed);
            self.state.lock().unwrap().data_tls.push((true, resumed));
            if tls.require_reuse && !resumed {
                return None;
            }
            Some(Box::new(stream))
        } else {
            self.state.lock().unwrap().data_tls.push((false, false));
            Some(Box::new(tcp))
        }
    }

    async fn open_data(&mut self) -> Option<BoxIo> {
        if self.passive.is_none() && self.active.is_none() {
            self.send("425 Use PORT or PASV first.").await;
            return None;
        }
        if !self.send("150 Opening data connection.").await {
            return None;
        }
        match self.data_connection().await {
            Some(d) => Some(d),
            None => {
                self.send("425 Failed to establish connection.").await;
                None
            }
        }
    }

    /// Send `data` over `conn`, watching the control connection for `ABOR`.
    async fn send_data(&mut self, mut conn: BoxIo, data: Vec<u8>) -> Outcome {
        let chunk = self.config.chunk.max(1);
        let delay = self.config.data_delay;
        let write = async {
            for piece in data.chunks(chunk) {
                if conn.write_all(piece).await.is_err() {
                    return false;
                }
                if let Some(d) = delay {
                    tokio::time::sleep(d).await;
                }
            }
            conn.shutdown().await.is_ok()
        };
        tokio::pin!(write);
        loop {
            tokio::select! {
                ok = &mut write => return if ok { Outcome::Done } else { Outcome::Failed },
                line = self.read_line() => match line {
                    None => return Outcome::Gone,
                    Some(l) if l.trim().eq_ignore_ascii_case("ABOR") => {
                        self.state.lock().unwrap().commands.push(l);
                        return Outcome::Aborted;
                    }
                    Some(l) => {
                        self.state.lock().unwrap().commands.push(l);
                    }
                }
            }
        }
    }

    async fn finish_send(&mut self, outcome: Outcome) -> bool {
        match outcome {
            Outcome::Done => self.send("226 Transfer complete.").await,
            Outcome::Failed => self.send("426 Failure writing network stream.").await,
            Outcome::Aborted => {
                self.send("426 Transfer aborted.").await && self.send("226 ABOR successful.").await
            }
            Outcome::Gone => false,
        }
    }

    async fn retr(&mut self, arg: &str) -> bool {
        let path = self.resolve(arg);
        let node = self.state.lock().unwrap().fs.get(&path).cloned();
        let offset = std::mem::take(&mut self.rest);
        let node = match node {
            Some(n) if !n.is_dir() => n,
            _ => {
                let r = if self.config.vague_errors {
                    "550 Failed to open file.".to_owned()
                } else {
                    "550 No such file or directory".to_owned()
                };
                return self.send(&r).await;
            }
        };
        let mut data = node.bytes_from(offset);
        if self.ascii {
            data = to_crlf(&data);
        }
        let Some(conn) = self.open_data().await else {
            return true;
        };
        let outcome = self.send_data(conn, data).await;
        self.finish_send(outcome).await
    }

    async fn store(&mut self, arg: &str, append: bool) -> bool {
        let path = self.resolve(arg);
        let offset = std::mem::take(&mut self.rest);
        let parent = RemotePath::new(&path).parent().unwrap_or_default();
        if !self
            .state
            .lock()
            .unwrap()
            .fs
            .get(parent.as_str())
            .is_some_and(Node::is_dir)
        {
            return self.send("553 Could not create file.").await;
        }
        let Some(mut conn) = self.open_data().await else {
            return true;
        };
        let mut received = Vec::new();
        let mut read = Box::pin(async {
            let mut buf = [0u8; 8192];
            loop {
                match conn.read(&mut buf).await {
                    Ok(0) => return true,
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                    // A TLS client that doesn't send close_notify.
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return true,
                    Err(_) => return false,
                }
            }
        });
        let outcome = loop {
            tokio::select! {
                ok = &mut read => break if ok { Outcome::Done } else { Outcome::Failed },
                line = self.read_line() => match line {
                    None => break Outcome::Gone,
                    Some(l) if l.trim().eq_ignore_ascii_case("ABOR") => {
                        self.state.lock().unwrap().commands.push(l);
                        break Outcome::Aborted;
                    }
                    Some(l) => self.state.lock().unwrap().commands.push(l),
                }
            }
        };
        // Close our side cleanly (TLS close_notify) once the client is done.
        drop(read);
        let _ = tokio::time::timeout(Duration::from_secs(2), conn.shutdown()).await;
        drop(conn);
        if matches!(outcome, Outcome::Done | Outcome::Aborted) {
            let mut data = received;
            if self.ascii {
                data = from_crlf(&data);
            }
            let mut state = self.state.lock().unwrap();
            let existing = match state.fs.get(&path) {
                Some(Node::File { data, .. }) => data.clone(),
                _ => Vec::new(),
            };
            let new = if append {
                [existing, data].concat()
            } else if offset > 0 {
                let mut base = existing;
                let off = usize::try_from(offset).unwrap();
                base.resize(base.len().max(off), 0);
                let end = off + data.len();
                if base.len() < end {
                    base.resize(end, 0);
                }
                base[off..end].copy_from_slice(&data);
                base
            } else {
                data
            };
            state.fs.insert(path, Node::file(&new));
        }
        self.finish_send(outcome).await
    }

    async fn list(&mut self, verb: &str, arg: &str) -> bool {
        if verb == "MLSD" && !self.config.mlst {
            return self.send("500 Unknown command.").await;
        }
        let arg = arg
            .split_whitespace()
            .filter(|w| !w.starts_with('-'))
            .collect::<Vec<_>>()
            .join(" ");
        let dir = self.resolve(if arg.is_empty() { "." } else { &arg });
        let is_dir = self
            .state
            .lock()
            .unwrap()
            .fs
            .get(&dir)
            .is_some_and(Node::is_dir);
        if !is_dir {
            let reply = self.not_found("List");
            return self.send(&reply).await;
        }
        let entries: Vec<(String, Node)> = {
            let state = self.state.lock().unwrap();
            let prefix = if dir == "/" {
                "/".to_owned()
            } else {
                format!("{dir}/")
            };
            state
                .fs
                .iter()
                .filter(|(k, _)| {
                    k.starts_with(&prefix)
                        && k.len() > prefix.len()
                        && !k[prefix.len()..].contains('/')
                })
                .map(|(k, v)| (k[prefix.len()..].to_owned(), v.clone()))
                .collect()
        };
        let mut text = String::new();
        for (name, node) in &entries {
            match verb {
                "NLST" => text.push_str(name),
                "MLSD" => {
                    text.push_str(&mlsd_facts(node));
                    text.push(' ');
                    text.push_str(name);
                }
                _ => text.push_str(&ls_line(name, node)),
            }
            text.push_str("\r\n");
        }
        let Some(conn) = self.open_data().await else {
            return true;
        };
        let outcome = self.send_data(conn, text.into_bytes()).await;
        self.finish_send(outcome).await
    }
}

fn fmt_time(t: OffsetDateTime) -> String {
    let format = format_description!("[year][month][day][hour][minute][second]");
    t.format(&format).unwrap()
}

fn mlsd_facts(node: &Node) -> String {
    let kind = if node.is_dir() { "dir" } else { "file" };
    format!(
        "type={kind};size={};modify={};UNIX.mode={:04o};",
        node.size(),
        fmt_time(node.mtime()),
        node.mode()
    )
}

fn ls_line(name: &str, node: &Node) -> String {
    let mode = node.mode();
    let mut perms = String::from(if node.is_dir() { "d" } else { "-" });
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 7;
        perms.push(if bits & 4 != 0 { 'r' } else { '-' });
        perms.push(if bits & 2 != 0 { 'w' } else { '-' });
        perms.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    let t = node.mtime();
    let format = format_description!("[month repr:short] [day padding:space] [year]");
    format!(
        "{perms}    1 1000     1000     {:>8} {} {name}",
        node.size(),
        t.format(&format).unwrap()
    )
}

fn to_crlf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

fn from_crlf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\r' && data.get(i + 1) == Some(&b'\n') {
            i += 1;
            continue;
        }
        out.push(data[i]);
        i += 1;
    }
    out
}
