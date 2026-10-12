//! [`TinyFtpd`]: a small FTP server for tests that run without Docker.
//!
//! It serves a real directory over plain FTP on `127.0.0.1` (passive mode
//! only), from its own thread and tokio runtime, so both async tests and the
//! blocking [`PtyApp`](crate::PtyApp) tests can use it, and the real
//! `courier-ftp` binary can connect to it from another process.
//!
//! Commands: `USER`/`PASS`, `SYST`, `FEAT`, `OPTS`, `PWD`, `CWD`/`CDUP`,
//! `TYPE` (ASCII converts LF ↔ CRLF), `MODE`/`STRU`, `PASV`/`EPSV`, `REST`,
//! `LIST`/`NLST`, `RETR`, `STOR`/`APPE`, `SIZE`, `MDTM`, `MKD`/`RMD`/`DELE`,
//! `RNFR`/`RNTO`, `SITE CHMOD` (Unix), `NOOP`, `ABOR`, `QUIT`. No `MLSD`:
//! listings are `ls -l` lines, which is also what the hostile mode fakes.
//!
//! **Hostile mode** ([`Hostile`]) is the "malicious server" of the e2e
//! scenarios: every `LIST` answers the given raw lines (names with `../`,
//! `/`, escape sequences, NUL, absurd sizes), every `RETR` sends the same
//! payload, and uploads are refused. Paths never leave the served directory
//! in either mode.

use std::{
    io::SeekFrom,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use time::{OffsetDateTime, macros::format_description};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, tcp::OwnedWriteHalf},
    sync::oneshot,
};

use crate::{E2eError, Result};

/// How long the server waits for the client's data connection.
const DATA_ACCEPT_TIMEOUT: Duration = Duration::from_secs(20);

/// What a hostile server sends instead of real listings and files.
#[derive(Debug, Clone, Default)]
pub struct Hostile {
    /// Raw `LIST` lines (without line ends), sent for every directory.
    pub listing: Vec<Vec<u8>>,
    /// What every `RETR` sends.
    pub payload: Vec<u8>,
}

/// Server settings.
#[derive(Debug, Clone)]
pub struct FtpdConfig {
    /// The only user.
    pub user: String,
    /// Their password.
    pub password: String,
    /// Fake listings and files instead of the directory.
    pub hostile: Option<Hostile>,
}

impl FtpdConfig {
    /// A normal server for `user` / `password`.
    pub fn new(user: &str, password: &str) -> Self {
        Self {
            user: user.to_owned(),
            password: password.to_owned(),
            hostile: None,
        }
    }
}

/// A running server. Stopped when dropped.
#[derive(Debug)]
pub struct TinyFtpd {
    addr: SocketAddr,
    config: FtpdConfig,
    commands: Arc<Mutex<Vec<String>>>,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TinyFtpd {
    /// Serve `root` to `user` / `password`.
    ///
    /// # Errors
    /// The port could not be bound or the runtime could not start.
    pub fn start(root: &Path, user: &str, password: &str) -> Result<Self> {
        Self::start_with(root, FtpdConfig::new(user, password))
    }

    /// Serve `root` with `config`.
    ///
    /// # Errors
    /// The port could not be bound or the runtime could not start.
    pub fn start_with(root: &Path, config: FtpdConfig) -> Result<Self> {
        let root = root.canonicalize()?;
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        std_listener.set_nonblocking(true)?;
        let addr = std_listener.local_addr()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let commands = Arc::new(Mutex::new(Vec::new()));
        let (stop, stopped) = oneshot::channel::<()>();
        let shared = Arc::new(Shared {
            root,
            config: config.clone(),
            commands: Arc::clone(&commands),
        });
        let thread = std::thread::Builder::new()
            .name("tiny-ftpd".into())
            .spawn(move || {
                runtime.block_on(async move {
                    let Ok(listener) = TcpListener::from_std(std_listener) else {
                        return;
                    };
                    let accept = async {
                        loop {
                            let Ok((tcp, _)) = listener.accept().await else {
                                return;
                            };
                            let shared = Arc::clone(&shared);
                            tokio::spawn(async move {
                                let _ = Session::new(shared).run(tcp).await;
                            });
                        }
                    };
                    tokio::select! {
                        () = accept => {}
                        _ = stopped => {}
                    }
                });
            })
            .map_err(|e| E2eError::new(format!("tiny-ftpd thread: {e}")))?;
        Ok(Self {
            addr,
            config,
            commands,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// Where it listens.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// `ftp://user:password@127.0.0.1:port`, for the quickconnect bar.
    pub fn url(&self) -> String {
        format!(
            "ftp://{}:{}@127.0.0.1:{}",
            self.config.user,
            self.config.password,
            self.port()
        )
    }

    /// Every command line received so far, all connections (`PASS` masked).
    pub fn commands(&self) -> Vec<String> {
        self.commands
            .lock()
            .map(|c| c.clone())
            .unwrap_or_default()
    }
}

impl Drop for TinyFtpd {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Shared {
    root: PathBuf,
    config: FtpdConfig,
    commands: Arc<Mutex<Vec<String>>>,
}

struct Session {
    shared: Arc<Shared>,
    /// The virtual working directory (`/` is the served root).
    cwd: String,
    user_ok: bool,
    logged_in: bool,
    ascii: bool,
    rest: u64,
    rnfr: Option<PathBuf>,
    passive: Option<TcpListener>,
}

/// `path` (absolute or relative to `cwd`) normalised; `..` stops at `/`.
fn virtual_path(cwd: &str, path: &str) -> String {
    let joined = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("{cwd}/{path}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    format!("/{}", parts.join("/"))
}

/// An `ls -l` line for `meta` named `name`.
fn ls_line(name: &str, meta: &std::fs::Metadata) -> String {
    let kind = if meta.is_dir() { 'd' } else { '-' };
    let mode = mode_bits(meta);
    let mut perms = String::with_capacity(9);
    for shift in [6_u32, 3, 0] {
        let bits = (mode >> shift) & 7;
        perms.push(if bits & 4 != 0 { 'r' } else { '-' });
        perms.push(if bits & 2 != 0 { 'w' } else { '-' });
        perms.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    let mtime = mtime_of(meta);
    let date = if (OffsetDateTime::now_utc() - mtime).whole_days().abs() < 180 {
        mtime.format(format_description!(
            "[month repr:short] [day padding:space] [hour]:[minute]"
        ))
    } else {
        mtime.format(format_description!(
            "[month repr:short] [day padding:space]  [year]"
        ))
    }
    .unwrap_or_default();
    format!(
        "{kind}{perms}    1 ftp      ftp      {:>10} {date} {name}",
        if meta.is_dir() { 4096 } else { meta.len() }
    )
}

#[cfg(unix)]
fn mode_bits(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_bits(meta: &std::fs::Metadata) -> u32 {
    match (meta.is_dir(), meta.permissions().readonly()) {
        (true, _) => 0o755,
        (false, true) => 0o444,
        (false, false) => 0o644,
    }
}

fn mtime_of(meta: &std::fs::Metadata) -> OffsetDateTime {
    meta.modified()
        .map(OffsetDateTime::from)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn to_ascii(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 16);
    for &b in data {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

fn from_ascii(data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .filter(|&(i, &b)| !(b == b'\r' && data.get(i + 1) == Some(&b'\n')))
        .map(|(_, &b)| b)
        .collect()
}

/// Write one reply (`"230 Logged in."`, or several lines for multi-line
/// replies).
async fn reply(w: &mut OwnedWriteHalf, text: &str) -> std::io::Result<()> {
    w.write_all(text.as_bytes()).await?;
    w.write_all(b"\r\n").await?;
    w.flush().await
}

impl Session {
    fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            cwd: "/".into(),
            user_ok: false,
            logged_in: false,
            ascii: false,
            rest: 0,
            rnfr: None,
            passive: None,
        }
    }

    fn hostile(&self) -> Option<&Hostile> {
        self.shared.config.hostile.as_ref()
    }

    /// The real path of virtual `path` (never outside the root).
    fn real(&self, path: &str) -> (String, PathBuf) {
        let v = virtual_path(&self.cwd, path);
        let mut real = self.shared.root.clone();
        for part in v.split('/').filter(|p| !p.is_empty()) {
            real.push(part);
        }
        (v, real)
    }

    fn record(&self, line: &str) {
        let shown = if line.len() >= 4 && line[..4].eq_ignore_ascii_case("PASS") {
            "PASS ****".to_owned()
        } else {
            line.to_owned()
        };
        if let Ok(mut c) = self.shared.commands.lock() {
            c.push(shown);
        }
    }

    async fn run(mut self, tcp: TcpStream) -> std::io::Result<()> {
        let (r, mut w) = tcp.into_split();
        let mut r = BufReader::new(r);
        reply(&mut w, "220 courier-ftp-e2e tiny ftpd").await?;
        let mut line = Vec::new();
        loop {
            line.clear();
            if r.read_until(b'\n', &mut line).await? == 0 {
                return Ok(());
            }
            let text = String::from_utf8_lossy(&line);
            let text = text.trim_end_matches(['\r', '\n']);
            self.record(text);
            let (verb, arg) = match text.split_once(' ') {
                Some((v, a)) => (v.to_ascii_uppercase(), a.to_owned()),
                None => (text.to_ascii_uppercase(), String::new()),
            };
            if verb == "QUIT" {
                reply(&mut w, "221 Bye.").await?;
                return Ok(());
            }
            self.command(&verb, &arg, &mut w).await?;
        }
    }

    async fn command(&mut self, verb: &str, arg: &str, w: &mut OwnedWriteHalf) -> std::io::Result<()> {
        let public = matches!(verb, "USER" | "PASS" | "FEAT" | "SYST" | "NOOP" | "OPTS" | "CLNT");
        if !public && !self.logged_in {
            return reply(w, "530 Please log in with USER and PASS.").await;
        }
        let answer = match verb {
            "USER" => {
                self.user_ok = arg == self.shared.config.user;
                self.logged_in = false;
                "331 Please specify the password.".to_owned()
            }
            "PASS" => {
                if self.user_ok && arg == self.shared.config.password {
                    self.logged_in = true;
                    "230 Login successful.".to_owned()
                } else {
                    "530 Login incorrect.".to_owned()
                }
            }
            "SYST" => "215 UNIX Type: L8".to_owned(),
            "FEAT" => "211-Features:\r\n EPSV\r\n PASV\r\n SIZE\r\n MDTM\r\n REST STREAM\r\n UTF8\r\n211 End"
                .to_owned(),
            "NOOP" => "200 NOOP ok.".to_owned(),
            "OPTS" | "CLNT" | "MODE" | "STRU" => "200 Ok.".to_owned(),
            "PWD" | "XPWD" => format!("257 \"{}\" is the current directory", self.cwd),
            "CWD" | "XCWD" => {
                let (v, real) = self.real(arg);
                if self.hostile().is_some() || real.is_dir() {
                    self.cwd = v;
                    "250 Directory successfully changed.".to_owned()
                } else {
                    "550 Failed to change directory.".to_owned()
                }
            }
            "CDUP" | "XCUP" => {
                self.cwd = virtual_path(&self.cwd, "..");
                "250 Directory successfully changed.".to_owned()
            }
            "TYPE" => {
                self.ascii = arg.eq_ignore_ascii_case("A") || arg.eq_ignore_ascii_case("A N");
                format!("200 Switching to {} mode.", if self.ascii { "ASCII" } else { "Binary" })
            }
            "PASV" | "EPSV" => {
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let port = listener.local_addr()?.port();
                self.passive = Some(listener);
                if verb == "PASV" {
                    format!(
                        "227 Entering Passive Mode (127,0,0,1,{},{}).",
                        port >> 8,
                        port & 0xff
                    )
                } else {
                    format!("229 Entering Extended Passive Mode (|||{port}|)")
                }
            }
            "PORT" | "EPRT" => "502 Active mode is not supported.".to_owned(),
            "REST" => match arg.parse::<u64>() {
                Ok(n) => {
                    self.rest = n;
                    format!("350 Restart position accepted ({n}).")
                }
                Err(_) => "501 Bad REST.".to_owned(),
            },
            "LIST" | "NLST" => return self.list(verb, arg, w).await,
            "RETR" => return self.retr(arg, w).await,
            "STOR" | "APPE" => return self.store(arg, verb == "APPE", w).await,
            "SIZE" => match (self.hostile(), self.real(arg).1) {
                (Some(h), _) => format!("213 {}", h.payload.len()),
                (None, real) => match std::fs::metadata(real) {
                    Ok(m) if m.is_file() => format!("213 {}", m.len()),
                    _ => "550 Could not get file size.".to_owned(),
                },
            },
            "MDTM" => match std::fs::metadata(self.real(arg).1) {
                Ok(m) if m.is_file() && self.hostile().is_none() => format!(
                    "213 {}",
                    mtime_of(&m)
                        .format(format_description!(
                            "[year][month][day][hour][minute][second]"
                        ))
                        .unwrap_or_default()
                ),
                _ => "550 Could not get file modification time.".to_owned(),
            },
            _ if self.hostile().is_some() => "550 Permission denied.".to_owned(),
            "MKD" | "XMKD" => {
                let (v, real) = self.real(arg);
                match std::fs::create_dir(real) {
                    Ok(()) => format!("257 \"{v}\" created"),
                    Err(_) => "550 Create directory operation failed.".to_owned(),
                }
            }
            "RMD" | "XRMD" => match std::fs::remove_dir(self.real(arg).1) {
                Ok(()) => "250 Remove directory operation successful.".to_owned(),
                Err(_) => "550 Remove directory operation failed.".to_owned(),
            },
            "DELE" => {
                let real = self.real(arg).1;
                match real.is_file().then(|| std::fs::remove_file(&real)) {
                    Some(Ok(())) => "250 Delete operation successful.".to_owned(),
                    _ => "550 No such file or directory.".to_owned(),
                }
            }
            "RNFR" => {
                let real = self.real(arg).1;
                if real.exists() {
                    self.rnfr = Some(real);
                    "350 Ready for RNTO.".to_owned()
                } else {
                    "550 No such file or directory.".to_owned()
                }
            }
            "RNTO" => match self.rnfr.take() {
                Some(from) => match std::fs::rename(from, self.real(arg).1) {
                    Ok(()) => "250 Rename successful.".to_owned(),
                    Err(_) => "550 Rename failed.".to_owned(),
                },
                None => "503 RNFR required first.".to_owned(),
            },
            "SITE" => self.site(arg),
            "ABOR" => "225 No transfer to ABOR.".to_owned(),
            _ => "502 Command not implemented.".to_owned(),
        };
        reply(w, &answer).await
    }

    #[cfg(unix)]
    fn site(&self, arg: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let mut parts = arg.splitn(3, ' ');
        let (Some(cmd), Some(mode), Some(path)) = (parts.next(), parts.next(), parts.next()) else {
            return "501 Bad SITE command.".to_owned();
        };
        if !cmd.eq_ignore_ascii_case("CHMOD") {
            return "500 Unknown SITE command.".to_owned();
        }
        let Ok(mode) = u32::from_str_radix(mode, 8) else {
            return "501 Bad mode.".to_owned();
        };
        match std::fs::set_permissions(self.real(path).1, std::fs::Permissions::from_mode(mode)) {
            Ok(()) => "200 SITE CHMOD command ok.".to_owned(),
            Err(_) => "550 SITE CHMOD command failed.".to_owned(),
        }
    }

    #[cfg(not(unix))]
    fn site(&self, _arg: &str) -> String {
        "500 Unknown SITE command.".to_owned()
    }

    /// Accept the data connection (after `150`).
    async fn data(&mut self, w: &mut OwnedWriteHalf) -> std::io::Result<Option<TcpStream>> {
        let Some(listener) = self.passive.take() else {
            reply(w, "425 Use PASV or EPSV first.").await?;
            return Ok(None);
        };
        reply(w, "150 Here comes the data.").await?;
        match tokio::time::timeout(DATA_ACCEPT_TIMEOUT, listener.accept()).await {
            Ok(Ok((tcp, _))) => Ok(Some(tcp)),
            _ => {
                reply(w, "425 Failed to establish connection.").await?;
                Ok(None)
            }
        }
    }

    async fn send_data(&mut self, data: &[u8], w: &mut OwnedWriteHalf) -> std::io::Result<()> {
        let Some(mut tcp) = self.data(w).await? else {
            return Ok(());
        };
        let sent = async {
            tcp.write_all(data).await?;
            tcp.shutdown().await
        }
        .await;
        drop(tcp);
        match sent {
            Ok(()) => reply(w, "226 Transfer complete.").await,
            Err(_) => reply(w, "426 Connection closed; transfer aborted.").await,
        }
    }

    async fn list(&mut self, verb: &str, arg: &str, w: &mut OwnedWriteHalf) -> std::io::Result<()> {
        // Options like `-a` are not paths.
        let path = arg
            .split(' ')
            .filter(|a| !a.starts_with('-') && !a.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let mut out = Vec::new();
        if let Some(h) = self.hostile() {
            for line in &h.listing {
                out.extend_from_slice(line);
                out.extend_from_slice(b"\r\n");
            }
        } else {
            let real = self.real(&path).1;
            let mut entries: Vec<(String, std::fs::Metadata)> = match std::fs::read_dir(&real) {
                Ok(dir) => dir
                    .flatten()
                    .filter_map(|e| Some((e.file_name().into_string().ok()?, e.metadata().ok()?)))
                    .collect(),
                Err(_) if real.is_file() => std::fs::metadata(&real)
                    .map(|m| {
                        let name = real
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        vec![(name, m)]
                    })
                    .unwrap_or_default(),
                Err(_) => {
                    self.passive = None;
                    return reply(w, "550 No such directory.").await;
                }
            };
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, meta) in entries {
                let line = if verb == "NLST" {
                    name
                } else {
                    ls_line(&name, &meta)
                };
                out.extend_from_slice(line.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
        }
        self.send_data(&out, w).await
    }

    async fn retr(&mut self, arg: &str, w: &mut OwnedWriteHalf) -> std::io::Result<()> {
        let offset = std::mem::take(&mut self.rest);
        let data = match self.hostile() {
            Some(h) => h.payload.clone(),
            None => {
                let real = self.real(arg).1;
                match tokio::fs::read(&real).await {
                    Ok(d) if real.is_file() => d,
                    _ => {
                        self.passive = None;
                        return reply(w, "550 Failed to open file.").await;
                    }
                }
            }
        };
        let data = data
            .get(usize::try_from(offset).unwrap_or(usize::MAX).min(data.len())..)
            .unwrap_or_default();
        let data = if self.ascii {
            to_ascii(data)
        } else {
            data.to_vec()
        };
        self.send_data(&data, w).await
    }

    async fn store(&mut self, arg: &str, append: bool, w: &mut OwnedWriteHalf) -> std::io::Result<()> {
        let offset = std::mem::take(&mut self.rest);
        let real = self.real(arg).1;
        if real.is_dir() || !real.parent().is_some_and(Path::is_dir) {
            self.passive = None;
            return reply(w, "553 Could not create file.").await;
        }
        let Some(mut tcp) = self.data(w).await? else {
            return Ok(());
        };
        let mut data = Vec::new();
        if tcp.read_to_end(&mut data).await.is_err() {
            return reply(w, "426 Connection closed; transfer aborted.").await;
        }
        if self.ascii {
            data = from_ascii(&data);
        }
        let written = async {
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .append(append)
                .truncate(!append && offset == 0)
                .open(&real)
                .await?;
            if offset > 0 && !append {
                file.set_len(offset).await?;
                file.seek(SeekFrom::Start(offset)).await?;
            }
            file.write_all(&data).await?;
            file.flush().await
        }
        .await;
        match written {
            Ok(()) => reply(w, "226 Transfer complete.").await,
            Err(_) => reply(w, "451 Local error writing the file.").await,
        }
    }
}

/// The modification time of `path` as the server reports it (for tests that
/// compare).
pub fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_paths_stay_inside_the_root() {
        assert_eq!(virtual_path("/", "a/b"), "/a/b");
        assert_eq!(virtual_path("/a", "../../.."), "/");
        assert_eq!(virtual_path("/a", "/x/./y/../z"), "/x/z");
        assert_eq!(virtual_path("/a/b", ".."), "/a");
    }

    #[test]
    fn ascii_round_trip() {
        assert_eq!(to_ascii(b"a\nb\n"), b"a\r\nb\r\n");
        assert_eq!(from_ascii(b"a\r\nb\r\n\r"), b"a\nb\n\r");
    }
}
