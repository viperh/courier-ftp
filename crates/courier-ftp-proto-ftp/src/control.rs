//! The FTP control connection (T10): greeting, commands and replies, feature
//! negotiation, keep-alive, custom commands and disconnect.
//!
//! Every wait is bounded by the inactivity timeout (`connection.timeout_secs`: no byte
//! received for that long → [`Error::Timeout`]) and races the operation's
//! [`CancellationToken`]; cancellation mid-reply leaves the reply state unknown, so the
//! connection becomes [`ControlState::Broken`] and every later command fails at once with
//! `Error::Connection("connection lost")` (T03's `SessionHandle` then reconnects).

use std::{
    collections::VecDeque, fmt, future::Future, net::SocketAddr, pin::Pin, task::Poll,
    time::Duration,
};

use async_trait::async_trait;
use courier_ftp_core::{
    Error, Result,
    events::SessionLog,
    model::{Charset, TransferType},
    net::{CancellationToken, HostPort, NetOpts, connect_tcp},
    secret::SecretString,
    settings::KeepaliveCommand,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    command::Command,
    encoding::{DecodeNote, SessionEncoding},
    features::{Features, parse_feat},
    reply::{Reply, ReplyCode, ReplyParser, parse_pwd},
};

/// Any byte stream the control connection runs over (TCP, TLS-over-TCP, test duplex).
pub trait ControlIo: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> ControlIo for T {}

/// A boxed [`ControlIo`].
pub type BoxedIo = Box<dyn ControlIo>;

/// Hook to wrap a raw stream before the greeting (implicit FTPS, T12).
#[async_trait]
pub trait StreamUpgrade: Send + Sync {
    /// Wraps `io` (e.g. a TLS handshake).
    async fn upgrade(&self, io: BoxedIo) -> Result<BoxedIo>;
}

/// Everything needed to open one control connection.
#[derive(Debug)]
pub struct ControlParams {
    /// Host + port actually dialled (proxy host for T15).
    pub target: HostPort,
    /// Name used for TLS verification and log lines.
    pub server_name: String,
    /// From T07 (timeouts, proxy, IPv6 preference).
    pub net: NetOpts,
    /// The site charset (T02).
    pub charset: Charset,
    /// Inactivity timeout (`connection.timeout_secs`).
    pub timeout: Duration,
    /// `ftp.send_keepalive_command` (T05).
    pub keepalive_command: KeepaliveCommand,
    /// Session id + event bus (T04).
    pub log: SessionLog,
}

/// Where the connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlState {
    /// Greeting read, not logged in yet (explicit TLS happens here).
    Greeting,
    /// A login script is running (or failed).
    LoggingIn,
    /// Logged in, idle.
    Ready,
    /// A command is in flight.
    Busy,
    /// A data transfer is open (T11): only `ABOR` may be written.
    TransferOpen,
    /// Unusable (421, timeout, EOF, protocol error, cancellation mid-reply).
    Broken,
    /// `quit()` ran.
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Greeting,
    LoggingIn,
    Ready,
}

/// Maximum `120` replies accepted before the `220` greeting.
const MAX_BUSY_GREETINGS: usize = 5;
/// Maximum unexpected `1xx` replies skipped for one non-transfer command.
const MAX_PRELIMINARY: usize = 8;
/// How long `quit()` waits in total.
const QUIT_WAIT: Duration = Duration::from_secs(2);
/// Read buffer size.
const READ_BUF: usize = 16 * 1024;

/// Commands the custom-command box refuses (FEATURES §4): they would desynchronise the
/// session state.
pub const REFUSED_RAW_VERBS: [&str; 24] = [
    "LIST", "NLST", "MLSD", "RETR", "STOR", "STOU", "APPE", "REST", "PORT", "EPRT", "LPRT", "PASV",
    "EPSV", "LPSV", "ABOR", "AUTH", "PBSZ", "PROT", "CCC", "REIN", "USER", "PASS", "ACCT", "QUIT",
];

/// MLST facts requested with `OPTS MLST`, in this order (intersected with FEAT).
const WANTED_MLST_FACTS: [&str; 9] = [
    "type",
    "size",
    "modify",
    "perm",
    "unix.mode",
    "unix.owner",
    "unix.group",
    "unix.ownername",
    "unix.groupname",
];

/// "too many connections" texts of 421/530 replies (case-insensitive).
pub(crate) fn is_too_many(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    ["too many", "maximum", "connections", "limit"]
        .iter()
        .any(|p| t.contains(p))
}

fn lost() -> Error {
    Error::Connection("connection lost".into())
}

enum ReadOutcome {
    Data(usize),
    Eof,
    Failed(std::io::Error),
    TimedOut,
    Cancelled,
}

/// The FTP command channel.
pub struct ControlConnection {
    io: Option<BoxedIo>,
    parser: ReplyParser,
    pending: VecDeque<Reply>,
    buf: Box<[u8]>,
    encoding: SessionEncoding,
    features: Features,
    syst: Option<String>,
    greeting: Reply,
    pub(crate) phase: Phase,
    busy: bool,
    transfer_open: bool,
    broken: bool,
    closed: bool,
    current_type: Option<TransferType>,
    timeout: Duration,
    keepalive_command: KeepaliveCommand,
    pub(crate) log: SessionLog,
    server_name: String,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    rng: fastrand::Rng,
    pub(crate) prompted_password: Option<SecretString>,
    pub(crate) prompted_account: Option<SecretString>,
    cwd_invalidated: bool,
}

impl fmt::Debug for ControlConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlConnection")
            .field("session", &self.log.session)
            .field("state", &self.state())
            .field("encoding", &self.encoding.name())
            .field("syst", &self.syst)
            .field("current_type", &self.current_type)
            .field("peer_addr", &self.peer_addr)
            .finish_non_exhaustive()
    }
}

impl ControlConnection {
    /// TCP connect (T07) and read the greeting. Implicit FTPS (T12) passes a hook that
    /// wraps the stream in TLS before the greeting is read.
    ///
    /// # Errors
    ///
    /// T07's connect errors, the hook's error, `Timeout`, `Cancelled`, and the greeting
    /// errors of [`from_stream`](Self::from_stream).
    pub async fn connect(
        p: ControlParams,
        pre_greeting: Option<&dyn StreamUpgrade>,
        cancel: &CancellationToken,
    ) -> Result<(Self, Reply)> {
        let stream = connect_tcp(&p.target, &p.net, cancel.clone(), &p.log).await?;
        let peer = stream.peer_addr();
        let local = stream.local_addr();
        let mut io: BoxedIo = Box::new(stream);
        if let Some(hook) = pre_greeting {
            io = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(Error::Cancelled),
                r = hook.upgrade(io) => r?,
            };
        }
        p.log.status("Waiting for welcome message...");
        Self::start(io, p, Some(peer), Some(local), cancel).await
    }

    /// Same as [`connect`](Self::connect), over an existing stream (tests, T15 proxies
    /// through T07).
    ///
    /// # Errors
    ///
    /// `Timeout`, `Cancelled`, `Connection` (EOF, `421`, unexpected greeting),
    /// `ConnectionLimit` (`421` "too many connections"), `Protocol` (malformed reply).
    pub async fn from_stream(
        io: BoxedIo,
        p: ControlParams,
        cancel: &CancellationToken,
    ) -> Result<(Self, Reply)> {
        p.log
            .status("Connection established, waiting for welcome message...");
        Self::start(io, p, None, None, cancel).await
    }

    async fn start(
        io: BoxedIo,
        p: ControlParams,
        peer_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
        cancel: &CancellationToken,
    ) -> Result<(Self, Reply)> {
        let encoding = SessionEncoding::new(p.charset);
        let mut conn = Self {
            io: Some(io),
            parser: ReplyParser::new(encoding.line_decoder()),
            pending: VecDeque::new(),
            buf: vec![0; READ_BUF].into_boxed_slice(),
            encoding,
            features: Features::default(),
            syst: None,
            greeting: Reply::new(ReplyCode::GREETING, Vec::new()),
            phase: Phase::Greeting,
            busy: false,
            transfer_open: false,
            broken: false,
            closed: false,
            current_type: None,
            timeout: p.timeout,
            keepalive_command: p.keepalive_command,
            log: p.log,
            server_name: p.server_name,
            peer_addr,
            local_addr,
            rng: fastrand::Rng::new(),
            prompted_password: None,
            prompted_account: None,
            cwd_invalidated: false,
        };
        let mut busy = 0;
        let greeting = loop {
            let reply = conn.read_reply_inner(cancel).await?;
            match reply.code() {
                120 if busy < MAX_BUSY_GREETINGS => {
                    busy += 1;
                    let text = reply.text();
                    let minutes: String = text
                        .chars()
                        .skip_while(|c| !c.is_ascii_digit())
                        .take_while(char::is_ascii_digit)
                        .collect();
                    if minutes.is_empty() {
                        conn.log.status(format!("Server busy: {text}"));
                    } else {
                        conn.log
                            .status(format!("Server busy, ready in {minutes} minutes"));
                    }
                }
                220 => break reply,
                421 => {
                    conn.mark_broken();
                    let text = reply.text();
                    return Err(if is_too_many(&text) {
                        Error::ConnectionLimit(text)
                    } else {
                        Error::Connection(text)
                    });
                }
                _ => {
                    conn.mark_broken();
                    return Err(Error::Connection(format!(
                        "unexpected greeting: {}",
                        reply.text()
                    )));
                }
            }
        };
        conn.greeting = greeting.clone();
        tracing::info!(session = conn.log.session.get(), "ftp session connected");
        tracing::debug!(server = %conn.server_name, "ftp greeting received");
        Ok((conn, greeting))
    }

    // ---- state ------------------------------------------------------------------------

    /// The current state.
    pub fn state(&self) -> ControlState {
        if self.closed {
            ControlState::Closed
        } else if self.broken {
            ControlState::Broken
        } else if self.busy {
            ControlState::Busy
        } else if self.transfer_open {
            ControlState::TransferOpen
        } else {
            match self.phase {
                Phase::Greeting => ControlState::Greeting,
                Phase::LoggingIn => ControlState::LoggingIn,
                Phase::Ready => ControlState::Ready,
            }
        }
    }

    /// Fails with `Connection("connection lost")` on a broken or closed connection, and
    /// on one whose previous command future was dropped mid-flight (reply state unknown).
    fn ensure_usable(&mut self) -> Result<()> {
        if self.busy {
            self.mark_broken();
        }
        if self.closed || self.broken || self.io.is_none() {
            return Err(lost());
        }
        Ok(())
    }

    /// T11 guard: a data transfer is open (only `ABOR` may be written).
    #[allow(dead_code)] // T11 (data connections) is the caller.
    pub(crate) fn mark_transfer_open(&mut self, open: bool) {
        self.transfer_open = open;
    }

    /// The connection can no longer be used.
    pub(crate) fn mark_broken(&mut self) {
        self.broken = true;
    }

    /// The parsed `FEAT` reply (default until [`negotiate`](Self::negotiate)).
    pub fn features(&self) -> &Features {
        &self.features
    }

    /// The `SYST` reply text (`UNIX Type: L8`), if the server answered `215`.
    pub fn syst(&self) -> Option<&str> {
        self.syst.as_deref()
    }

    /// The `220` greeting.
    pub fn greeting(&self) -> &Reply {
        &self.greeting
    }

    /// The server's address; `None` over a test duplex.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// Our end of the TCP connection (T11 active mode); `None` over a test duplex.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// The tracked `TYPE` (T11 sends `TYPE` only when it changes).
    pub fn current_type(&self) -> Option<TransferType> {
        self.current_type
    }

    /// Sets the tracked `TYPE`.
    pub fn set_current_type(&mut self, t: Option<TransferType>) {
        self.current_type = t;
    }

    /// The session encoding.
    pub fn encoding(&self) -> &SessionEncoding {
        &self.encoding
    }

    /// The name used for TLS verification and log lines.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// The session log (T11/T14 log through it).
    pub fn session_log(&self) -> &SessionLog {
        &self.log
    }

    /// True once after a raw `CWD`/`CDUP` (T14 then re-issues its cached directory).
    pub fn take_cwd_invalidated(&mut self) -> bool {
        std::mem::take(&mut self.cwd_invalidated)
    }

    /// The password the user typed during the last login, if one was asked
    /// (`AskForPassword` keeps it for the backend instance, T14).
    pub fn take_prompted_password(&mut self) -> Option<SecretString> {
        self.prompted_password.take()
    }

    /// The account (`ACCT`) the user typed during the last login, if one was asked.
    pub fn take_prompted_account(&mut self) -> Option<SecretString> {
        self.prompted_account.take()
    }

    /// Seeds the keep-alive RNG (tests).
    #[doc(hidden)]
    pub fn seed_keepalive_rng(&mut self, seed: u64) {
        self.rng = fastrand::Rng::with_seed(seed);
    }

    // ---- reading ----------------------------------------------------------------------

    /// One read with the inactivity timeout and the cancellation token.
    async fn read_more(&mut self, cancel: &CancellationToken) -> Result<()> {
        let timeout = self.timeout;
        let outcome = {
            let Some(io) = self.io.as_mut() else {
                return Err(lost());
            };
            let buf = &mut self.buf[..];
            tokio::select! {
                biased;
                () = cancel.cancelled() => ReadOutcome::Cancelled,
                r = tokio::time::timeout(timeout, io.read(buf)) => match r {
                    Err(_) => ReadOutcome::TimedOut,
                    Ok(Ok(0)) => ReadOutcome::Eof,
                    Ok(Ok(n)) => ReadOutcome::Data(n),
                    Ok(Err(e)) => ReadOutcome::Failed(e),
                },
            }
        };
        match outcome {
            ReadOutcome::Data(n) => self.feed(n),
            ReadOutcome::Eof => {
                self.mark_broken();
                Err(Error::Connection("connection closed by server".into()))
            }
            ReadOutcome::Failed(e) => {
                self.mark_broken();
                Err(Error::Connection(format!("read error: {e}")))
            }
            ReadOutcome::TimedOut => {
                self.mark_broken();
                self.log.error(format!(
                    "Connection timed out after {} seconds of inactivity",
                    timeout.as_secs()
                ));
                Err(Error::Timeout)
            }
            ReadOutcome::Cancelled => {
                self.mark_broken();
                Err(Error::Cancelled)
            }
        }
    }

    /// Parses `self.buf[..n]`.
    fn feed(&mut self, n: usize) -> Result<()> {
        let result = self.parser.push(&self.buf[..n]);
        for note in self.parser.take_notes() {
            match note {
                DecodeNote::SwitchedToFallback => self.log.status(note.message()),
                DecodeNote::InvalidUtf8 => self.log.debug(1, note.message()),
            }
        }
        match result {
            Ok(replies) => {
                self.pending.extend(replies);
                Ok(())
            }
            Err(e) => {
                self.mark_broken();
                self.log.error("Invalid reply from server");
                Err(e.into())
            }
        }
    }

    fn log_reply(&self, reply: &Reply) {
        for line in &reply.lines {
            self.log.response(line);
        }
    }

    pub(crate) async fn read_reply_inner(&mut self, cancel: &CancellationToken) -> Result<Reply> {
        loop {
            if let Some(reply) = self.pending.pop_front() {
                self.log_reply(&reply);
                return Ok(reply);
            }
            if self.broken || self.closed {
                return Err(lost());
            }
            self.read_more(cancel).await?;
        }
    }

    /// Reads the next reply (T11: after [`write_command`](Self::write_command)).
    ///
    /// # Errors
    ///
    /// `Connection` (lost, EOF), `Timeout`, `Cancelled`, `Protocol` (malformed reply).
    pub async fn read_reply(&mut self, cancel: &CancellationToken) -> Result<Reply> {
        self.ensure_usable()?;
        self.read_reply_inner(cancel).await
    }

    /// Consumes replies that arrived without a command: `421` → the connection closes
    /// (`Error::Connection`); anything else is logged and dropped.
    async fn drain_unsolicited(&mut self) -> Result<()> {
        let mut eof = false;
        for _ in 0..16 {
            let polled = {
                let Some(io) = self.io.as_mut() else {
                    return Err(lost());
                };
                let mut rb = ReadBuf::new(&mut self.buf[..]);
                let r = std::future::poll_fn(|cx| {
                    Poll::Ready(match Pin::new(&mut *io).poll_read(cx, &mut rb) {
                        Poll::Ready(r) => Some(r),
                        Poll::Pending => None,
                    })
                })
                .await;
                r.map(|r| r.map(|()| rb.filled().len()))
            };
            match polled {
                None => break,
                Some(Ok(0)) => {
                    eof = true;
                    break;
                }
                Some(Ok(n)) => self.feed(n)?,
                Some(Err(e)) => {
                    self.mark_broken();
                    return Err(Error::Connection(format!("read error: {e}")));
                }
            }
        }
        while let Some(reply) = self.pending.pop_front() {
            self.log_reply(&reply);
            if reply.code() == 421 {
                self.mark_broken();
                return Err(Error::Connection(reply.text()));
            }
            self.log.debug(3, "unexpected reply discarded");
        }
        if eof {
            self.mark_broken();
            return Err(Error::Connection("connection closed by server".into()));
        }
        Ok(())
    }

    // ---- writing ----------------------------------------------------------------------

    async fn write_inner(&mut self, cmd: &Command, cancel: &CancellationToken) -> Result<()> {
        // Encoding errors (unmappable characters) leave the connection usable.
        let bytes = cmd.encode(&self.encoding)?;
        self.log.command(&cmd.log_text());
        tracing::debug!(verb = %cmd.verb(), "ftp command");
        let timeout = self.timeout;
        let outcome = {
            let Some(io) = self.io.as_mut() else {
                return Err(lost());
            };
            let write = async {
                io.write_all(&bytes).await?;
                io.flush().await
            };
            tokio::select! {
                biased;
                () = cancel.cancelled() => Err(Error::Cancelled),
                r = tokio::time::timeout(timeout, write) => match r {
                    Err(_) => Err(Error::Timeout),
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(Error::Connection(format!("write error: {e}"))),
                },
            }
        };
        if outcome.is_err() {
            self.mark_broken();
        }
        outcome
    }

    /// Sends without waiting (T11: RETR/STOR, and ABOR while a transfer is open).
    ///
    /// # Errors
    ///
    /// `InvalidInput` (unmappable character; nothing written), `Connection`, `Timeout`.
    pub async fn write_command(&mut self, cmd: Command) -> Result<()> {
        self.ensure_usable()?;
        self.write_inner(&cmd, &CancellationToken::new()).await
    }

    /// Sends one command and returns its final reply, whatever the code (`421` marks the
    /// connection broken but is returned). Skips up to 8 `1xx` replies.
    pub(crate) async fn send_raw(
        &mut self,
        cmd: Command,
        cancel: &CancellationToken,
    ) -> Result<Reply> {
        self.ensure_usable()?;
        if self.transfer_open {
            return Err(Error::Internal(
                "command sent while a data transfer is open".into(),
            ));
        }
        self.busy = true;
        let result = self.exchange(&cmd, cancel).await;
        self.busy = false;
        let reply = result?;
        if reply.code() == 421 {
            self.mark_broken();
        }
        Ok(reply)
    }

    async fn exchange(&mut self, cmd: &Command, cancel: &CancellationToken) -> Result<Reply> {
        self.drain_unsolicited().await?;
        self.write_inner(cmd, cancel).await?;
        let mut skipped = 0;
        loop {
            let reply = self.read_reply_inner(cancel).await?;
            if !reply.is_preliminary() {
                return Ok(reply);
            }
            if skipped == MAX_PRELIMINARY {
                self.mark_broken();
                return Err(Error::Protocol {
                    code: Some(reply.code()),
                    message: "too many preliminary replies".into(),
                });
            }
            skipped += 1;
            self.log.debug(3, "unexpected preliminary reply skipped");
        }
    }

    /// Sends one command and returns its final reply (skips up to 8 unexpected 1xx
    /// replies). Never fails on 4xx/5xx — the caller interprets the code — except `421`
    /// (service closing): `Error::Connection(text)`.
    ///
    /// # Errors
    ///
    /// `InvalidInput` (bad argument; nothing written), `Connection`, `Timeout`,
    /// `Cancelled`, `Protocol` (malformed reply), `Internal` (transfer open).
    pub async fn send(&mut self, cmd: Command, cancel: &CancellationToken) -> Result<Reply> {
        let reply = self.send_raw(cmd, cancel).await?;
        if reply.code() == 421 {
            return Err(Error::Connection(reply.text()));
        }
        Ok(reply)
    }

    /// `send` + check: a code not in `expected` becomes `Error::Protocol { code, text }`.
    ///
    /// # Errors
    ///
    /// As [`send`](Self::send), plus `Protocol` for an unexpected code.
    pub async fn send_expect(
        &mut self,
        cmd: Command,
        expected: &[u16],
        cancel: &CancellationToken,
    ) -> Result<Reply> {
        let reply = self.send(cmd, cancel).await?;
        if expected.contains(&reply.code()) {
            Ok(reply)
        } else {
            Err(Error::Protocol {
                code: Some(reply.code()),
                message: reply.text(),
            })
        }
    }

    // ---- session commands ---------------------------------------------------------------

    /// SYST, FEAT, `OPTS UTF8 ON` and `OPTS MLST`; fills [`features`](Self::features) and
    /// [`syst`](Self::syst). `PWD` is not part of it (T14 calls [`pwd`](Self::pwd)).
    ///
    /// # Errors
    ///
    /// As [`send`](Self::send) (only connection-level failures; the replies' codes are
    /// interpreted, never errors).
    pub async fn negotiate(&mut self, cancel: &CancellationToken) -> Result<()> {
        let syst = self.send(Command::new("SYST"), cancel).await?;
        self.syst = (syst.code() == 215).then(|| syst.first_line_text().trim().to_owned());

        let feat = self.send(Command::new("FEAT"), cancel).await?;
        self.features = parse_feat(&feat);

        if self.encoding.wants_utf8() {
            if self.features.utf8 {
                self.encoding.confirm_utf8();
                // Any reply accepted (some servers are always in UTF-8 mode).
                self.send(Command::new("OPTS").arg("UTF8 ON")?, cancel)
                    .await?;
            } else if self.encoding.charset() == Charset::Auto {
                self.log
                    .status("Server does not support non-ASCII characters.");
            }
        }

        if let Some(facts) = &self.features.mlst {
            let wanted: String = WANTED_MLST_FACTS
                .iter()
                .filter(|w| facts.iter().any(|f| f.name == **w))
                .map(|w| format!("{w};"))
                .collect();
            if !wanted.is_empty() {
                // Failure just means the server's default facts.
                self.send(Command::new("OPTS").arg(format!("MLST {wanted}"))?, cancel)
                    .await?;
            }
        }
        Ok(())
    }

    /// `PWD` → the server path as returned (T14 converts it to a `RemotePath`).
    ///
    /// # Errors
    ///
    /// As [`send`](Self::send); `Protocol` for a code other than 257 or an empty path.
    pub async fn pwd(&mut self, cancel: &CancellationToken) -> Result<String> {
        let reply = self
            .send_expect(Command::new("PWD"), &[257], cancel)
            .await?;
        parse_pwd(&reply)
    }

    /// Keep-alive (T03 `SessionHandle` calls it after `keepalive_interval_secs` idle):
    /// `NOOP`, or with `random` a uniform choice of `NOOP`, `PWD` or `TYPE` (the current
    /// type, `TYPE I` if unknown). Nothing is sent while a transfer is open. Any reply is
    /// accepted.
    ///
    /// # Errors
    ///
    /// `Connection` (421, lost), `Timeout`, `Cancelled`.
    pub async fn keepalive(&mut self, cancel: &CancellationToken) -> Result<()> {
        if self.transfer_open && !self.broken && !self.closed {
            return Ok(());
        }
        let choice = match self.keepalive_command {
            KeepaliveCommand::Noop => 0,
            KeepaliveCommand::Random => self.rng.usize(0..3),
        };
        match choice {
            0 => {
                self.send(Command::new("NOOP"), cancel).await?;
            }
            1 => {
                self.send(Command::new("PWD"), cancel).await?;
            }
            _ => {
                let t = self.current_type.unwrap_or(TransferType::Binary);
                let arg = if t == TransferType::Ascii { "A" } else { "I" };
                let reply = self.send(Command::new("TYPE").arg(arg)?, cancel).await?;
                self.current_type = reply.is_ok().then_some(t);
            }
        }
        Ok(())
    }

    /// A user-entered custom command (FEATURES §4), sent verbatim. Returns the whole
    /// reply (any code). After `CWD`/`CDUP`/`TYPE` the tracked directory/type become
    /// unknown.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for an empty line, CR/LF/NUL, or a verb that needs the normal UI
    /// ([`REFUSED_RAW_VERBS`]) — nothing is sent; otherwise as [`send`](Self::send).
    pub async fn raw_command(&mut self, line: &str, cancel: &CancellationToken) -> Result<Reply> {
        let cmd = Command::line(line.trim())?;
        let verb = cmd.verb();
        if REFUSED_RAW_VERBS.contains(&verb.as_str()) {
            return Err(Error::InvalidInput(format!("use the normal UI for {verb}")));
        }
        let reply = self.send(cmd, cancel).await?;
        match verb.as_str() {
            "CWD" | "CDUP" | "XCWD" | "XCUP" => self.cwd_invalidated = true,
            "TYPE" => self.current_type = None,
            _ => {}
        }
        Ok(reply)
    }

    /// `QUIT`, wait ≤ 2 s for any reply, shut the stream down (TLS `close_notify`, T12)
    /// and drop it. Never fails; problems are logged at `Debug(3)`.
    pub async fn quit(mut self) {
        let deadline = tokio::time::Instant::now() + QUIT_WAIT;
        if self.ensure_usable().is_ok() && !self.transfer_open {
            let token = CancellationToken::new();
            let quit = async {
                self.write_inner(&Command::new("QUIT"), &token).await?;
                self.read_reply_inner(&token).await
            };
            let result = tokio::time::timeout_at(deadline, quit).await;
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => self.log.debug(3, format!("QUIT failed: {e}")),
                Err(_) => self.log.debug(3, "no reply to QUIT"),
            }
        }
        if let Some(mut io) = self.io.take() {
            let result = tokio::time::timeout_at(deadline, io.shutdown()).await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => self.log.debug(3, format!("shutdown failed: {e}")),
                Err(_) => self.log.debug(3, "shutdown timed out"),
            }
        }
        self.closed = true;
        tracing::info!(session = self.log.session.get(), "ftp session closed");
    }

    /// TLS upgrade (T12): takes the stream out, gives it back wrapped. Only in `Ready`/
    /// `Greeting` with no buffered unread bytes.
    ///
    /// # Errors
    ///
    /// `Connection` (lost), `Protocol` (wrong state or unread bytes), or the upgrade's
    /// own error (the connection is then broken).
    pub async fn upgrade_stream<F, Fut>(&mut self, f: F) -> Result<()>
    where
        F: FnOnce(BoxedIo) -> Fut,
        Fut: Future<Output = Result<BoxedIo>>,
    {
        self.ensure_usable()?;
        if self.transfer_open || self.phase == Phase::LoggingIn {
            return Err(Error::Protocol {
                code: None,
                message: "TLS upgrade in the wrong connection state".into(),
            });
        }
        if self.parser.has_partial() || !self.pending.is_empty() {
            return Err(Error::Protocol {
                code: None,
                message: "unread data from the server before the TLS handshake".into(),
            });
        }
        let io = self.io.take().ok_or_else(lost)?;
        self.busy = true;
        let result = f(io).await;
        self.busy = false;
        match result {
            Ok(io) => {
                self.io = Some(io);
                Ok(())
            }
            Err(e) => {
                self.mark_broken();
                Err(e)
            }
        }
    }
}

impl ReplyCode {
    /// Placeholder until the greeting is read.
    const GREETING: Self = Self::from_const(220);
}

#[cfg(test)]
mod tests;
