//! The FTP control connection (T10): replies, commands, login, `FEAT`,
//! keep-alive and disconnect. RFC 959, 2389 (`FEAT`), 2640 (`UTF8`), 3659.
//!
//! # Opening a session
//!
//! [`connect`] runs the whole start sequence (FTPS steps per
//! [`FtpOptions::encryption`], T12, see [`crate::tls`]):
//!
//! 1. asks for the password first when the logon type wants one
//!    (`Prompt(Password)`), so no prompt is ever open while a connection
//!    waits;
//! 2. TCP through [`courier_ftp_core::net::connect_tcp`] (DNS, IPv6, Happy
//!    Eyeballs, the generic HTTP/SOCKS proxy);
//! 3. implicit FTPS: the TLS handshake ([`ControlConnection::start_tls`]);
//!    then the greeting (`220`; `120` means "wait", the next reply is read);
//!    explicit FTPS: `AUTH TLS` and the handshake
//!    ([`ControlConnection::auth_tls`]) — before any FTP proxy login;
//! 4. the login script ([`LoginScript`], `USER` → `331` → `PASS` → `332` →
//!    `ACCT`, `230` straight after `USER` accepted), or the FTP proxy's
//!    script ([`crate::proxy`], T15; the TCP connection then goes to the
//!    proxy);
//! 5. `SYST`, `FEAT` (parsed into [`Features`]; `500` keeps the defaults),
//!    `CLNT` when announced, `OPTS UTF8 ON` when `UTF8` is announced and the
//!    charset is Auto or UTF-8 (its failure is ignored);
//! 6. on TLS connections `PBSZ 0` + `PROT P`
//!    ([`ControlConnection::protect_data`]);
//! 7. `PWD` (a failure there is logged, not fatal).
//!
//! Each step is also a public method, so later tasks can insert theirs:
//! implicit FTPS (T12) wraps the stream before [`ControlConnection::new`],
//! explicit FTPS sends `AUTH TLS` after [`ControlConnection::read_greeting`]
//! and swaps the stream with [`ControlConnection::upgrade_stream`], and FTP
//! proxies (T15) pass their own [`LoginScript`] to
//! [`ControlConnection::login`].
//!
//! # Commands and replies
//!
//! - [`ControlConnection::send`] / [`send_with`](ControlConnection::send_with)
//!   send a command and return its final reply; `1xx` replies are logged and
//!   skipped. [`send_expect`](ControlConnection::send_expect) also turns an
//!   unexpected code into an error.
//! - For data commands (T11) the low-level pair
//!   [`write_command`](ControlConnection::write_command) and
//!   [`read_reply`](ControlConnection::read_reply) returns every reply,
//!   including the `150`, so the caller can stream data between them.
//! - A command line containing CR, LF or NUL is refused with
//!   [`Error::InvalidInput`] before anything is sent (no command injection
//!   through file names).
//! - Every command is logged as [`LogKind::Command`], masked by
//!   [`mask_command`] (`PASS ****`,
//!   `ACCT ****`); every reply line as [`LogKind::Response`], with control
//!   characters removed.
//!
//! # Timeouts, cancellation and errors
//!
//! - The timeout is FileZilla's: *no data received* for
//!   [`FtpOptions::timeout`] (`connection.timeout_secs`), not total duration.
//!   It gives [`Error::Timeout`] and closes the connection.
//! - Every wait also ends when the connection's token
//!   ([`FtpContext::cancel`]) or the per-call token fires, with
//!   [`Error::Cancelled`]. A cancelled wait leaves the command's reply unread;
//!   the next command first reads and discards it, so the connection stays in
//!   step.
//! - `421` at any point, end of stream and I/O errors give
//!   [`Error::Connection`] and close the connection (the session handle can
//!   reconnect). Malformed or oversized replies give [`Error::Protocol`] and
//!   close it too. Once closed, every call fails with [`Error::Connection`].
//!
//! # Stream type
//!
//! The connection owns a [`BoxedStream`] (`Box<dyn ControlStream>`), any
//! `AsyncRead + AsyncWrite + Unpin + Send` value: a `TcpStream`, a TLS stream
//! over it, or a `tokio::io::duplex` half in tests. The reply parser keeps its
//! own buffer, so the stream can be replaced between replies.

mod features;
mod login;
mod pwd;
mod reply;
mod secure;

use std::{
    borrow::Cow,
    hash::BuildHasher,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use courier_ftp_core::{
    Error, Result,
    backend::{ConnectInfo, ProxyChoice, TransferType},
    events::{
        EventSender, LogKind, PromptKind, PromptResponse, SessionId, mask_command, mask_secrets,
    },
    model::{Charset, FtpEncryption, LogonType},
    net::{HostPort, NetOpts, connect_tcp},
    settings::Settings,
};
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[doc(hidden)]
pub use self::reply::fuzz_reply_parser;
pub use self::{
    features::Features,
    login::{ANONYMOUS_PASSWORD, LoginScript, LoginStep},
    pwd::parse_quoted_path,
    reply::{MAX_LINE, MAX_REPLY_BYTES, Reply, ReplyError, ReplyParser},
};
use crate::{
    proxy::FtpProxyConfig,
    tls::{TlsSession, TlsTrust},
};

/// How long [`ControlConnection::quit`] waits for the `221`.
pub const QUIT_WAIT: Duration = Duration::from_secs(2);

/// How many `120` ("service ready in n minutes") greetings are waited out.
pub const MAX_BUSY_GREETINGS: usize = 10;

/// The name sent with `CLNT` when the server announces it.
pub const CLIENT_NAME: &str = "courier-ftp";

/// Commands [`ControlConnection::raw_command`] refuses because they need a
/// data connection, which only the normal operations set up.
pub const DATA_COMMANDS: &[&str] = &[
    "LIST", "NLST", "MLSD", "RETR", "STOR", "STOU", "APPE", "PASV", "EPSV", "PORT", "EPRT", "LPSV",
    "LPRT", "SPSV",
];

/// Commands [`ControlConnection::raw_command`] refuses because they change
/// the connection's encryption behind its back.
pub const TLS_COMMANDS: &[&str] = &["AUTH", "CCC", "PBSZ", "PROT"];

/// A byte stream the control connection can run over.
pub trait ControlStream: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static> ControlStream for T {}

/// The control connection's stream: TCP, TLS over TCP (T12), or a test
/// stream.
pub type BoxedStream = Box<dyn ControlStream>;

/// Where a connection reports and what cancels it.
#[derive(Debug, Clone)]
pub struct FtpContext {
    /// The session the log lines belong to.
    pub session: SessionId,
    /// The event bus (log lines, prompts).
    pub events: EventSender,
    /// Cancels everything on this connection (tab closed, disconnect).
    pub cancel: CancellationToken,
}

impl FtpContext {
    /// A context with a fresh cancellation token.
    pub fn new(session: SessionId, events: EventSender) -> Self {
        Self {
            session,
            events,
            cancel: CancellationToken::new(),
        }
    }
}

/// What to connect to and how to log in.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FtpOptions {
    /// The server.
    pub host: HostPort,
    /// How to log in.
    pub logon: LogonType,
    /// The site's file name charset.
    pub charset: Charset,
    /// TCP options: connect timeout, IPv6 preference, generic proxy.
    pub net: NetOpts,
    /// Longest time without receiving anything while a reply is awaited
    /// (`connection.timeout_secs`).
    pub timeout: Duration,
    /// Sent with `CLNT` when the server announces it; `None` never sends it.
    pub client_name: Option<String>,
    /// The FTP proxy (T15): the control connection goes to its server and
    /// logs in with its script. `None` connects to `host` directly.
    pub ftp_proxy: Option<FtpProxyConfig>,
    /// FTPS mode (T12). [`FtpOptions::new`] uses
    /// [`FtpEncryption::PlainOnly`]; [`FtpOptions::from_connect_info`] the
    /// site's mode.
    pub encryption: FtpEncryption,
    /// Certificate trust for FTPS; `None` uses a locked in-memory store
    /// (every unknown certificate is asked about, nothing is remembered).
    pub tls: Option<Arc<TlsTrust>>,
}

impl FtpOptions {
    /// Options for `host` and `logon` with the timeout and proxies from
    /// `settings` (without proxy passwords: see
    /// [`set_ftp_proxy_password`](Self::set_ftp_proxy_password)). An FTP proxy
    /// wins over a generic one (settings validation never keeps both).
    pub fn new(host: HostPort, logon: LogonType, settings: &Settings) -> Self {
        let ftp_proxy = FtpProxyConfig::from_settings(&settings.proxy.ftp_proxy);
        Self {
            host,
            logon,
            charset: Charset::Auto,
            net: NetOpts::from_settings(settings).bypass_proxy(ftp_proxy.is_some()),
            timeout: Duration::from_secs(settings.connection.timeout_secs.max(1)),
            client_name: Some(CLIENT_NAME.to_owned()),
            ftp_proxy,
            encryption: FtpEncryption::PlainOnly,
            tls: None,
        }
    }

    /// Options for a [`ConnectInfo`]: its address, logon, charset and proxy
    /// choice.
    pub fn from_connect_info(info: &ConnectInfo, settings: &Settings) -> Self {
        let mut opts = Self::new(HostPort::from(&info.address), info.logon.clone(), settings);
        opts.charset = info.charset;
        opts.encryption = info.ftp_encryption().unwrap_or_default();
        if info.proxy == ProxyChoice::Bypass {
            opts.net = opts.net.bypass_proxy(true);
            opts.ftp_proxy = None;
        }
        opts
    }

    /// Set the FTP proxy password (from the vault item
    /// [`FtpProxyConfig::password_ref`]). Does nothing without an FTP proxy.
    pub fn set_ftp_proxy_password(&mut self, password: SecretString) {
        if let Some(proxy) = self.ftp_proxy.as_mut() {
            proxy.password = Some(password);
        }
    }

    /// Where the control connection goes: the FTP proxy, or the server.
    pub fn control_target(&self) -> &HostPort {
        self.ftp_proxy.as_ref().map_or(&self.host, |p| &p.server)
    }

    /// The login script: the FTP proxy's, or the normal one for the logon
    /// type. `password` answers the password prompt.
    ///
    /// # Errors
    ///
    /// See [`LoginScript::for_logon`] and [`FtpProxyConfig::login_script`].
    pub fn login_script(&self, password: Option<SecretString>) -> Result<LoginScript> {
        match &self.ftp_proxy {
            Some(proxy) => proxy.login_script(&self.host, &self.logon, password),
            None => LoginScript::for_logon(&self.logon, password),
        }
    }
}

/// Which command [`ControlConnection::keepalive_with`] sends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum KeepaliveCommand {
    /// One of `NOOP`, `PWD`, `TYPE` at random, like FileZilla: some servers
    /// and NATs don't count `NOOP` as activity.
    #[default]
    Random,
    /// `NOOP`.
    Noop,
    /// `PWD`.
    Pwd,
    /// `TYPE` with the current transfer type (so nothing changes).
    Type,
}

impl KeepaliveCommand {
    /// From the `ftp.send_keepalive_command` setting: `NOOP`, `PWD` or `TYPE`
    /// (case-insensitive); anything else is [`KeepaliveCommand::Random`].
    pub fn from_setting(value: &str) -> Self {
        match value.trim().to_ascii_uppercase().as_str() {
            "NOOP" => Self::Noop,
            "PWD" => Self::Pwd,
            "TYPE" => Self::Type,
            _ => Self::Random,
        }
    }
}

/// Open a logged-in control connection: the whole start sequence described
/// in the [module docs](self).
///
/// # Errors
///
/// [`Error::Cancelled`], [`Error::Timeout`], [`Error::Connection`] (also for
/// `421`), [`Error::Auth`] for a rejected login, [`Error::InvalidInput`] for
/// SSH-only logon types, [`Error::Protocol`] for an unexpected greeting or a
/// broken reply.
pub async fn connect(opts: &FtpOptions, ctx: FtpContext) -> Result<ControlConnection> {
    let password = ask_password(opts, &ctx).await?;
    let script = opts.login_script(password)?;
    let mut conn = ControlConnection::connect_tcp(opts, ctx).await?;
    let tls = match opts.encryption {
        FtpEncryption::PlainOnly => None,
        _ => Some(Arc::new(TlsSession::new(
            opts.tls.clone().unwrap_or_else(|| {
                Arc::new(TlsTrust::new(Arc::new(
                    courier_ftp_core::trust::MemoryCertTrustStore::locked(),
                )))
            }),
            // The TLS peer is whoever the control connection talks to (the
            // FTP proxy when one is used: AUTH TLS goes before its login).
            opts.control_target(),
        )?)),
    };
    if let (FtpEncryption::RequireImplicit, Some(tls)) = (opts.encryption, &tls) {
        conn.start_tls(Arc::clone(tls)).await?;
    }
    conn.read_greeting().await?;
    if let (
        encryption @ (FtpEncryption::ExplicitIfAvailable | FtpEncryption::RequireExplicit),
        Some(tls),
    ) = (opts.encryption, tls)
    {
        conn.auth_tls(encryption, tls).await?;
    }
    if let Some(proxy) = &opts.ftp_proxy {
        conn.log(
            LogKind::Status,
            format!("Logging in through the FTP proxy ({})", proxy.kind),
        );
    }
    conn.login(&script).await?;
    conn.negotiate(opts.client_name.as_deref()).await?;
    conn.protect_data(opts.encryption).await?;
    match conn.pwd().await {
        Ok(_) => {}
        Err(err @ (Error::Cancelled | Error::Timeout | Error::Connection(_))) => return Err(err),
        Err(err) => conn.log(
            LogKind::Error,
            format!("Could not read the current directory: {err}"),
        ),
    }
    Ok(conn)
}

/// The password for logon types that ask for it, asked before connecting.
async fn ask_password(opts: &FtpOptions, ctx: &FtpContext) -> Result<Option<SecretString>> {
    let (LogonType::AskForPassword { user } | LogonType::Interactive { user }) = &opts.logon else {
        return Ok(None);
    };
    let answer = ctx
        .events
        .ask(
            Some(ctx.session),
            PromptKind::Password {
                for_: format!("{user}@{}", opts.host),
            },
            &ctx.cancel,
        )
        .await?;
    match answer {
        PromptResponse::Secret(password) => Ok(Some(password)),
        _ => Err(Error::Cancelled),
    }
}

/// The result of one read from the stream.
enum ReadOutcome {
    Data(usize),
    Eof,
    Io(std::io::Error),
    Timeout,
    Cancelled,
}

/// An FTP control connection. See the [module docs](self).
pub struct ControlConnection {
    /// `None` once closed.
    stream: Option<BoxedStream>,
    parser: ReplyParser,
    ctx: FtpContext,
    timeout: Duration,
    charset: Charset,
    /// The server announced `UTF8` (Auto then decodes and encodes UTF-8).
    utf8: bool,
    features: Features,
    syst: Option<String>,
    welcome: Option<Reply>,
    cwd: Option<String>,
    transfer_type: Option<TransferType>,
    /// Commands sent whose final (non-`1xx`) reply hasn't been read.
    outstanding: u32,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    last_activity: Instant,
    keepalive_count: u64,
    /// TLS on the control connection (T12).
    tls: Option<Arc<TlsSession>>,
    /// `PROT P` accepted: data connections use TLS.
    prot_private: bool,
}

impl std::fmt::Debug for ControlConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlConnection")
            .field("session", &self.ctx.session)
            .field("connected", &self.stream.is_some())
            .field("charset", &self.charset)
            .field("utf8", &self.utf8)
            .field("features", &self.features)
            .field("syst", &self.syst)
            .field("cwd", &self.cwd)
            .field("transfer_type", &self.transfer_type)
            .field("outstanding", &self.outstanding)
            .finish_non_exhaustive()
    }
}

impl ControlConnection {
    /// A control connection over an already open `stream` (a TLS stream for
    /// implicit FTPS, a test stream). Nothing is read or sent yet; call
    /// [`read_greeting`](Self::read_greeting) next.
    pub fn new(stream: BoxedStream, ctx: FtpContext, timeout: Duration, charset: Charset) -> Self {
        Self {
            stream: Some(stream),
            parser: ReplyParser::new(),
            ctx,
            timeout: timeout.max(Duration::from_millis(1)),
            charset,
            utf8: false,
            features: Features::default(),
            syst: None,
            welcome: None,
            cwd: None,
            transfer_type: None,
            outstanding: 0,
            peer_addr: None,
            local_addr: None,
            last_activity: Instant::now(),
            keepalive_count: 0,
            tls: None,
            prot_private: false,
        }
    }

    /// Open the TCP connection to [`FtpOptions::control_target`] (the
    /// server, or the FTP proxy) through
    /// [`connect_tcp`] and wrap it. Records the socket's peer and local
    /// addresses for the data connections (T11).
    ///
    /// # Errors
    ///
    /// The errors of [`connect_tcp`].
    pub async fn connect_tcp(opts: &FtpOptions, ctx: FtpContext) -> Result<Self> {
        let tcp = connect_tcp(
            opts.control_target(),
            &opts.net,
            &ctx.cancel,
            &ctx.events,
            ctx.session,
        )
        .await?;
        let peer = tcp.peer_addr().ok();
        let local = tcp.local_addr().ok();
        let mut conn = Self::new(Box::new(tcp), ctx, opts.timeout, opts.charset);
        conn.peer_addr = peer;
        conn.local_addr = local;
        Ok(conn)
    }

    // ----- accessors -------------------------------------------------------

    /// The session the connection logs under.
    pub fn session(&self) -> SessionId {
        self.ctx.session
    }

    /// The event bus.
    pub fn events(&self) -> &EventSender {
        &self.ctx.events
    }

    /// The connection's cancellation token.
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.ctx.cancel
    }

    /// The inactivity timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Whether the connection is still open (not closed by an error, a
    /// timeout, `421` or [`close`](Self::close)).
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// What the server announced in `FEAT`.
    pub fn features(&self) -> &Features {
        &self.features
    }

    /// The `SYST` reply text (`UNIX Type: L8`), a hint for the listing
    /// parsers (T13).
    pub fn syst(&self) -> Option<&str> {
        self.syst.as_deref()
    }

    /// The `220` greeting.
    pub fn welcome(&self) -> Option<&Reply> {
        self.welcome.as_ref()
    }

    /// The working directory from the last `PWD`, in the server's own syntax
    /// (`/home/bob`, `DISK$USER:[BOB]`). T14 translates it into a
    /// `RemotePath`. Cleared by a raw `CWD`/`CDUP`.
    pub fn cwd(&self) -> Option<&str> {
        self.cwd.as_deref()
    }

    /// The site's configured charset.
    pub fn charset(&self) -> Charset {
        self.charset
    }

    /// The charset in effect: [`Charset::Utf8`] when the site says Auto and
    /// the server announced `UTF8`, else the configured one. Listings (T13)
    /// decode with this.
    pub fn effective_charset(&self) -> Charset {
        match self.charset {
            Charset::Auto if self.utf8 => Charset::Utf8,
            other => other,
        }
    }

    /// The transfer type last set with `TYPE`, `None` before the first.
    pub fn transfer_type(&self) -> Option<TransferType> {
        self.transfer_type
    }

    /// The socket's peer address (the proxy's when a generic proxy is used),
    /// `None` for non-TCP streams.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// The socket's local address, `None` for non-TCP streams.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Set the addresses (when the stream was opened by the caller).
    pub fn set_addrs(&mut self, peer: Option<SocketAddr>, local: Option<SocketAddr>) {
        self.peer_addr = peer;
        self.local_addr = local;
    }

    /// How long nothing was sent or received; the keep-alive scheduler
    /// (T14) sends [`keepalive`](Self::keepalive) when this exceeds the
    /// interval.
    pub fn idle_for(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Commands whose final reply hasn't been read yet (a transfer in
    /// progress, or a cancelled wait).
    pub fn outstanding(&self) -> u32 {
        self.outstanding
    }

    // ----- logging ---------------------------------------------------------

    fn log(&self, kind: LogKind, text: impl Into<String>) {
        self.ctx.events.log(self.ctx.session, kind, text);
    }

    fn log_reply(&self, reply: &Reply) {
        if self.ctx.events.enabled(LogKind::Response) {
            for line in &reply.lines {
                self.log(LogKind::Response, log_safe(line).into_owned());
            }
        }
    }

    // ----- low level -------------------------------------------------------

    /// Close the connection without `QUIT`. Every later call fails with
    /// [`Error::Connection`].
    pub fn close(&mut self) {
        self.stream = None;
        self.outstanding = 0;
    }

    fn not_connected() -> Error {
        Error::Connection("not connected".into())
    }

    /// Send one command without reading its reply. Use with
    /// [`read_reply`](Self::read_reply) when the replies matter one by one
    /// (data commands, `ABOR`); [`send`](Self::send) is the normal way.
    ///
    /// Unlike `send`, this does not first read replies left over from a
    /// cancelled command.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] when `cmd` contains CR, LF or NUL (nothing is
    /// sent); [`Error::Connection`], [`Error::Timeout`] or
    /// [`Error::Cancelled`] when writing fails (the connection is closed).
    pub async fn write_command(&mut self, cmd: &str) -> Result<()> {
        self.write_command_inner(cmd, mask_command(cmd), None).await
    }

    /// [`write_command`](Self::write_command) with a per-call cancellation
    /// token.
    ///
    /// # Errors
    ///
    /// As [`write_command`](Self::write_command).
    pub async fn write_command_with(
        &mut self,
        cmd: &str,
        cancel: &CancellationToken,
    ) -> Result<()> {
        self.write_command_inner(cmd, mask_command(cmd), Some(cancel))
            .await
    }

    async fn write_command_inner(
        &mut self,
        cmd: &str,
        log_text: Cow<'_, str>,
        cancel: Option<&CancellationToken>,
    ) -> Result<()> {
        check_command(cmd)?;
        let charset = self.effective_charset();
        let timeout = self.timeout;
        let Some(stream) = self.stream.as_mut() else {
            return Err(Self::not_connected());
        };
        self.ctx
            .events
            .log(self.ctx.session, LogKind::Command, log_text.into_owned());
        let mut bytes = Zeroizing::new(encode(cmd, charset));
        bytes.extend_from_slice(b"\r\n");
        let write = async {
            stream.write_all(&bytes).await?;
            stream.flush().await
        };
        let local = cancel.cloned().unwrap_or_default();
        let result = tokio::select! {
            biased;
            () = either_cancelled(&local, &self.ctx.cancel) => Err(Error::Cancelled),
            r = tokio::time::timeout(timeout, write) => match r {
                Err(_) => Err(Error::Timeout),
                Ok(Err(err)) => Err(Error::Connection(format!("could not send: {err}"))),
                Ok(Ok(())) => Ok(()),
            },
        };
        match result {
            Ok(()) => {
                self.outstanding = self.outstanding.saturating_add(1);
                self.last_activity = Instant::now();
                Ok(())
            }
            Err(err) => {
                // A partly written command leaves the server out of step.
                self.fail(&err);
                Err(err)
            }
        }
    }

    /// Close after a fatal error and log it.
    fn fail(&mut self, err: &Error) {
        let text = match err {
            Error::Timeout => format!(
                "Connection timed out after {} seconds of inactivity",
                self.timeout.as_secs_f32()
            ),
            Error::Cancelled => "Interrupted by user".to_owned(),
            other => other.to_string(),
        };
        self.log(LogKind::Error, text);
        self.close();
    }

    /// Read the next reply, whatever its code (`1xx` included).
    ///
    /// # Errors
    ///
    /// [`Error::Timeout`] when nothing arrives for the timeout,
    /// [`Error::Cancelled`], [`Error::Connection`] for end of stream, I/O
    /// errors and `421` (the reply is logged first), [`Error::Protocol`] for
    /// a malformed or oversized reply. All but `Cancelled` close the
    /// connection.
    pub async fn read_reply(&mut self) -> Result<Reply> {
        self.read_reply_inner(None).await
    }

    /// [`read_reply`](Self::read_reply) with a per-call cancellation token.
    ///
    /// # Errors
    ///
    /// As [`read_reply`](Self::read_reply).
    pub async fn read_reply_with(&mut self, cancel: &CancellationToken) -> Result<Reply> {
        self.read_reply_inner(Some(cancel)).await
    }

    async fn read_reply_inner(&mut self, cancel: Option<&CancellationToken>) -> Result<Reply> {
        match self.read_reply_soft(cancel, None).await? {
            Some(reply) => Ok(reply),
            None => Err(Error::Timeout),
        }
    }

    /// Read the next reply, waiting at most `wait` for it without treating
    /// a timeout as fatal: `Ok(None)` when nothing complete arrived in time
    /// (the connection stays open). Used after `ABOR` (T11), where servers
    /// differ in how many replies they send.
    ///
    /// # Errors
    ///
    /// As [`read_reply`](Self::read_reply), except that running out of
    /// `wait` is not an error.
    pub async fn read_reply_within(&mut self, wait: Duration) -> Result<Option<Reply>> {
        self.read_reply_soft(None, Some(wait)).await
    }

    /// Forget replies still owed by the server (after an `ABOR` whose second
    /// reply never came), so the next command doesn't wait for them.
    pub fn discard_outstanding(&mut self) {
        self.outstanding = 0;
    }

    async fn read_reply_soft(
        &mut self,
        cancel: Option<&CancellationToken>,
        soft: Option<Duration>,
    ) -> Result<Option<Reply>> {
        let local = cancel.cloned().unwrap_or_default();
        let deadline = soft.map(|d| tokio::time::Instant::now() + d);
        loop {
            match self.parser.next_reply(self.effective_charset()) {
                Ok(Some(reply)) => return self.got_reply(reply).map(Some),
                Ok(None) => {}
                Err(err) => {
                    let err = Error::from(err);
                    self.fail(&err);
                    return Err(err);
                }
            }
            let mut buf = [0u8; 4096];
            let Some(stream) = self.stream.as_mut() else {
                return Err(Self::not_connected());
            };
            let wait = match deadline {
                Some(d) => d
                    .saturating_duration_since(tokio::time::Instant::now())
                    .min(self.timeout),
                None => self.timeout,
            };
            let outcome = tokio::select! {
                biased;
                () = either_cancelled(&local, &self.ctx.cancel) => ReadOutcome::Cancelled,
                r = tokio::time::timeout(wait, stream.read(&mut buf)) => match r {
                    Err(_) => ReadOutcome::Timeout,
                    Ok(Err(err)) => ReadOutcome::Io(err),
                    Ok(Ok(0)) => ReadOutcome::Eof,
                    Ok(Ok(n)) => ReadOutcome::Data(n),
                },
            };
            let err = match outcome {
                ReadOutcome::Data(n) => {
                    self.last_activity = Instant::now();
                    self.parser.feed(buf.get(..n).unwrap_or_default());
                    continue;
                }
                // The reply stays unread; the next `send` reads it first.
                ReadOutcome::Cancelled => return Err(Error::Cancelled),
                ReadOutcome::Timeout if deadline.is_some() => return Ok(None),
                ReadOutcome::Timeout => Error::Timeout,
                ReadOutcome::Eof => Error::Connection("the server closed the connection".into()),
                ReadOutcome::Io(err) => Error::Connection(format!("could not receive: {err}")),
            };
            self.fail(&err);
            return Err(err);
        }
    }

    fn got_reply(&mut self, reply: Reply) -> Result<Reply> {
        self.log_reply(&reply);
        if !reply.is_preliminary() {
            self.outstanding = self.outstanding.saturating_sub(1);
        }
        if reply.code == 421 {
            let err = reply.to_error();
            self.fail(&err);
            return Err(err);
        }
        Ok(reply)
    }

    /// Read and discard the replies of commands sent earlier whose waits
    /// were cancelled.
    async fn drain(&mut self, cancel: Option<&CancellationToken>) -> Result<()> {
        while self.outstanding > 0 {
            let reply = self.read_reply_inner(cancel).await?;
            tracing::debug!(code = reply.code, "skipped a late reply");
        }
        Ok(())
    }

    /// Read replies until a final (non-`1xx`) one.
    async fn read_final(&mut self, cancel: Option<&CancellationToken>) -> Result<Reply> {
        loop {
            let reply = self.read_reply_inner(cancel).await?;
            if !reply.is_preliminary() {
                return Ok(reply);
            }
        }
    }

    async fn exchange(
        &mut self,
        cmd: &str,
        log_text: Cow<'_, str>,
        cancel: Option<&CancellationToken>,
    ) -> Result<Reply> {
        check_command(cmd)?;
        self.drain(cancel).await?;
        self.write_command_inner(cmd, log_text, cancel).await?;
        self.read_final(cancel).await
    }

    // ----- commands --------------------------------------------------------

    /// Send `cmd` and return its final reply (`1xx` replies are logged and
    /// skipped). Error replies (`4xx`/`5xx`) are returned, not turned into
    /// errors, except `421`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] for CR/LF/NUL in `cmd`; otherwise as
    /// [`read_reply`](Self::read_reply).
    pub async fn send(&mut self, cmd: &str) -> Result<Reply> {
        self.exchange(cmd, mask_command(cmd), None).await
    }

    /// [`send`](Self::send) with a per-call cancellation token.
    ///
    /// # Errors
    ///
    /// As [`send`](Self::send).
    pub async fn send_with(&mut self, cmd: &str, cancel: &CancellationToken) -> Result<Reply> {
        self.exchange(cmd, mask_command(cmd), Some(cancel)).await
    }

    /// [`send`](Self::send), failing with [`Reply::to_error`] unless the
    /// final reply's code is one of `codes`.
    ///
    /// # Errors
    ///
    /// As [`send`](Self::send), plus [`Error::Protocol`] (or
    /// [`Error::Connection`] for `421`) for any other code.
    pub async fn send_expect(&mut self, cmd: &str, codes: &[u16]) -> Result<Reply> {
        let reply = self.send(cmd).await?;
        if codes.contains(&reply.code) {
            Ok(reply)
        } else {
            Err(reply.to_error())
        }
    }

    /// Send a command that contains a secret, logged with `secrets` replaced
    /// by `****` (and `PASS`/`ACCT` arguments masked).
    async fn send_secret(&mut self, cmd: &str, secrets: &[&str]) -> Result<Reply> {
        let masked = mask_secrets(cmd, secrets);
        let log_text = mask_command(&masked).into_owned();
        self.exchange(cmd, Cow::Owned(log_text), None).await
    }

    /// Read the greeting: `220` is accepted, `120` ("ready in n minutes") is
    /// logged and the next reply read.
    ///
    /// # Errors
    ///
    /// [`Error::Connection`] for `421` (too many users) or a server that
    /// stays busy; [`Error::Protocol`] for any other code; the errors of
    /// [`read_reply`](Self::read_reply).
    pub async fn read_greeting(&mut self) -> Result<Reply> {
        self.log(LogKind::Status, "Waiting for welcome message...");
        for _ in 0..MAX_BUSY_GREETINGS {
            let reply = self.read_reply().await?;
            match reply.code {
                120 => self.log(
                    LogKind::Status,
                    "The server is busy; waiting until it is ready",
                ),
                220 => {
                    self.welcome = Some(reply.clone());
                    return Ok(reply);
                }
                _ => {
                    let err = if reply.is_err() {
                        reply.to_error()
                    } else {
                        Error::Protocol {
                            code: Some(reply.code),
                            message: format!("unexpected greeting: {}", reply.text()),
                        }
                    };
                    self.fail(&err);
                    return Err(err);
                }
            }
        }
        let err = Error::Connection("the server stayed busy (120)".into());
        self.fail(&err);
        Err(err)
    }

    /// Run a login script (see [`LoginStep`] for how replies are handled).
    /// Logs `Logged in` on success.
    ///
    /// # Errors
    ///
    /// [`Error::Auth`] for `530`/`532` or when the server wants an account
    /// and the script has none; [`Error::Connection`] for `421`;
    /// [`Error::Protocol`] for other unexpected replies.
    pub async fn login(&mut self, script: &LoginScript) -> Result<()> {
        let mut logged_in = false;
        let mut skip_auth = false;
        let mut needs_account = false;
        for step in script.steps() {
            let reply = match step {
                LoginStep::User(user) => {
                    skip_auth = false;
                    needs_account = false;
                    let reply = self.send(&format!("USER {user}")).await?;
                    match reply.code {
                        230 => skip_auth = true,
                        331 => {}
                        332 => needs_account = true,
                        _ => return Err(login_error(&reply)),
                    }
                    reply
                }
                LoginStep::Pass(password) => {
                    if skip_auth {
                        continue;
                    }
                    let cmd = Zeroizing::new(format!("PASS {}", password.expose_secret()));
                    let reply = self.send_secret(&cmd, &[password.expose_secret()]).await?;
                    match reply.code {
                        230 | 202 => skip_auth = true,
                        332 => needs_account = true,
                        _ => return Err(login_error(&reply)),
                    }
                    reply
                }
                LoginStep::Acct(account) => {
                    if skip_auth {
                        continue;
                    }
                    let cmd = Zeroizing::new(format!("ACCT {}", account.expose_secret()));
                    let reply = self.send_secret(&cmd, &[account.expose_secret()]).await?;
                    match reply.code {
                        230 | 202 => {
                            skip_auth = true;
                            needs_account = false;
                        }
                        _ => return Err(login_error(&reply)),
                    }
                    reply
                }
                LoginStep::Command(cmd) => {
                    skip_auth = false;
                    let reply = self.send(cmd).await?;
                    if !(reply.is_ok() || reply.is_intermediate()) {
                        return Err(login_error(&reply));
                    }
                    reply
                }
                LoginStep::SecretCommand { line, secrets } => {
                    skip_auth = false;
                    let secrets: Vec<&str> = secrets.iter().map(|s| s.expose_secret()).collect();
                    let reply = self.send_secret(line.expose_secret(), &secrets).await?;
                    if !(reply.is_ok() || reply.is_intermediate()) {
                        return Err(login_error(&reply));
                    }
                    reply
                }
            };
            // Skipped steps don't get here, so a `230` stays in effect.
            logged_in = match step {
                LoginStep::Command(_) | LoginStep::SecretCommand { .. } => reply.is_ok(),
                _ => matches!(reply.code, 230 | 202),
            };
        }
        if !logged_in {
            let message = if needs_account {
                "the server asks for an account (ACCT); set the logon type to Account"
            } else {
                "the server did not confirm the login"
            };
            self.log(LogKind::Error, message);
            return Err(Error::Auth(message.into()));
        }
        self.log(LogKind::Status, "Logged in");
        Ok(())
    }

    /// `SYST`, `FEAT`, then `CLNT <client_name>` when announced and `OPTS
    /// UTF8 ON` when `UTF8` is announced and the charset is Auto or UTF-8.
    /// Failure replies to any of them are tolerated.
    ///
    /// # Errors
    ///
    /// Only connection-level errors ([`Error::Connection`],
    /// [`Error::Timeout`], [`Error::Cancelled`], [`Error::Protocol`] for a
    /// broken reply).
    pub async fn negotiate(&mut self, client_name: Option<&str>) -> Result<()> {
        let syst = self.send("SYST").await?;
        if syst.code == 215 {
            self.syst = Some(syst.first_line_text().trim().to_owned());
        }
        let feat = self.send("FEAT").await?;
        self.features = Features::parse(&feat);
        if !self.features.feat_supported {
            self.log(LogKind::Status, "The server does not support FEAT");
        }
        if self.features.clnt
            && let Some(name) = client_name.filter(|n| check_command(n).is_ok())
        {
            self.send(&format!("CLNT {name}")).await?;
        }
        if self.features.utf8 && matches!(self.charset, Charset::Auto | Charset::Utf8) {
            self.send("OPTS UTF8 ON").await?;
            self.utf8 = true;
            if self.charset == Charset::Auto {
                self.log(
                    LogKind::Status,
                    "The server supports UTF-8; file names are UTF-8",
                );
            }
        }
        Ok(())
    }

    /// `PWD`: the working directory in the server's syntax, also kept as
    /// [`cwd`](Self::cwd).
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] for a reply other than `257` or one without a
    /// path; the errors of [`send`](Self::send).
    pub async fn pwd(&mut self) -> Result<String> {
        let reply = self.send("PWD").await?;
        if reply.code != 257 {
            return Err(reply.to_error());
        }
        let path = parse_quoted_path(&reply.text()).ok_or_else(|| Error::Protocol {
            code: Some(257),
            message: "no directory in the PWD reply".into(),
        })?;
        self.cwd = Some(path.clone());
        Ok(path)
    }

    /// Set the transfer type with `TYPE A`/`TYPE I`, only when it differs
    /// from the current one.
    ///
    /// # Errors
    ///
    /// The server's error reply as [`Error::Protocol`]; the errors of
    /// [`send`](Self::send).
    pub async fn set_type(&mut self, transfer_type: TransferType) -> Result<()> {
        if self.transfer_type == Some(transfer_type) {
            return Ok(());
        }
        let reply = self.send(type_command(transfer_type)).await?;
        if !reply.is_ok() {
            return Err(reply.to_error());
        }
        self.transfer_type = Some(transfer_type);
        Ok(())
    }

    /// Send a harmless command so idle connections aren't dropped:
    /// [`KeepaliveCommand::Random`]. Does nothing while a command is
    /// outstanding (a transfer in progress).
    ///
    /// # Errors
    ///
    /// Connection-level errors; error replies are ignored.
    pub async fn keepalive(&mut self) -> Result<()> {
        self.keepalive_with(KeepaliveCommand::Random).await
    }

    /// [`keepalive`](Self::keepalive) with a chosen command.
    ///
    /// # Errors
    ///
    /// As [`keepalive`](Self::keepalive).
    pub async fn keepalive_with(&mut self, which: KeepaliveCommand) -> Result<()> {
        if self.outstanding > 0 {
            return Ok(());
        }
        self.keepalive_count = self.keepalive_count.wrapping_add(1);
        let which = match which {
            KeepaliveCommand::Random => {
                match std::collections::hash_map::RandomState::new().hash_one(self.keepalive_count)
                    % 3
                {
                    0 => KeepaliveCommand::Noop,
                    1 => KeepaliveCommand::Pwd,
                    _ => KeepaliveCommand::Type,
                }
            }
            other => other,
        };
        match which {
            KeepaliveCommand::Pwd => match self.pwd().await {
                Ok(_) | Err(Error::Protocol { .. }) => {}
                Err(err) => return Err(err),
            },
            KeepaliveCommand::Type => {
                // The current type again, so nothing changes.
                let t = self.transfer_type.unwrap_or_default();
                let reply = self.send(type_command(t)).await?;
                if reply.is_ok() {
                    self.transfer_type = Some(t);
                }
            }
            KeepaliveCommand::Noop | KeepaliveCommand::Random => {
                self.send("NOOP").await?;
            }
        }
        Ok(())
    }

    /// A user-typed command (§4 custom commands), sent verbatim after the
    /// CR/LF check. Returns every reply it produced (`1xx` ones and the
    /// final one).
    ///
    /// Commands that need a data connection ([`DATA_COMMANDS`]) or change the
    /// encryption ([`TLS_COMMANDS`]) are refused with a message saying what
    /// to use instead. A raw `TYPE` forgets the tracked transfer type and a
    /// raw `CWD`/`CDUP` the working directory.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] for an empty, refused or CR/LF-containing
    /// command; otherwise as [`send`](Self::send).
    pub async fn raw_command(&mut self, cmd: &str) -> Result<Vec<Reply>> {
        let cmd = cmd.trim_matches(' ');
        check_command(cmd)?;
        let verb = cmd
            .split_ascii_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if verb.is_empty() {
            return Err(Error::InvalidInput("empty command".into()));
        }
        let refusal = if DATA_COMMANDS.contains(&verb.as_str()) {
            Some(format!(
                "{verb} needs a data connection; use the file list and transfer queue instead"
            ))
        } else if TLS_COMMANDS.contains(&verb.as_str()) {
            Some(format!(
                "{verb} would change the connection's encryption; set the encryption in the site settings instead"
            ))
        } else {
            None
        };
        if let Some(message) = refusal {
            self.log(LogKind::Error, message.clone());
            return Err(Error::InvalidInput(message));
        }
        match verb.as_str() {
            "TYPE" => self.transfer_type = None,
            "CWD" | "CDUP" | "XCWD" | "XCUP" => self.cwd = None,
            _ => {}
        }
        self.drain(None).await?;
        self.write_command(cmd).await?;
        let mut replies = Vec::new();
        loop {
            let reply = self.read_reply().await?;
            let done = !reply.is_preliminary();
            replies.push(reply);
            if done {
                return Ok(replies);
            }
        }
    }

    /// Replace the stream (TLS upgrade after `AUTH TLS`, T12). `upgrade`
    /// gets the current stream and returns the new one; if it fails the
    /// connection is closed.
    ///
    /// Refused (and the connection closed) when bytes arrived after the
    /// last reply or a reply is still outstanding: plain-text data must not
    /// leak into the protected stream (STARTTLS command injection).
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] for buffered or outstanding data,
    /// [`Error::Connection`] when not connected, and whatever `upgrade`
    /// returns.
    pub async fn upgrade_stream<F, Fut>(&mut self, upgrade: F) -> Result<()>
    where
        F: FnOnce(BoxedStream) -> Fut,
        Fut: Future<Output = Result<BoxedStream>>,
    {
        if !self.parser.is_idle() || self.outstanding > 0 {
            let err = Error::Protocol {
                code: None,
                message: "the server sent data before the TLS handshake".into(),
            };
            self.fail(&err);
            return Err(err);
        }
        let stream = self.stream.take().ok_or_else(Self::not_connected)?;
        match upgrade(stream).await {
            Ok(stream) => {
                self.stream = Some(stream);
                self.last_activity = Instant::now();
                Ok(())
            }
            Err(err) => {
                self.fail(&err);
                Err(err)
            }
        }
    }

    /// `QUIT`, wait up to [`QUIT_WAIT`] for `221`, then close the socket.
    /// Never fails: the connection is gone afterwards either way.
    pub async fn quit(mut self) {
        if self.stream.is_none() {
            return;
        }
        let bye = async {
            self.write_command("QUIT").await?;
            loop {
                let reply = self.read_reply().await?;
                if reply.code == 221 || (!reply.is_preliminary() && self.outstanding == 0) {
                    return Ok::<(), Error>(());
                }
            }
        };
        let _ = tokio::time::timeout(QUIT_WAIT, bye).await;
        if let Some(mut stream) = self.stream.take() {
            let _ = tokio::time::timeout(Duration::from_secs(1), stream.shutdown()).await;
        }
        self.log(LogKind::Status, "Disconnected from server");
    }
}

/// `TYPE A` or `TYPE I`.
fn type_command(t: TransferType) -> &'static str {
    match t {
        TransferType::Ascii => "TYPE A",
        TransferType::Binary => "TYPE I",
    }
}

/// The error for a rejected login step.
fn login_error(reply: &Reply) -> Error {
    match reply.code {
        530 | 532 => Error::Auth(reply.text()),
        _ => reply.to_error(),
    }
}

/// Refuse command lines that would smuggle a second command (CR, LF) or that
/// servers treat as a string terminator (NUL).
///
/// # Errors
///
/// [`Error::InvalidInput`].
pub fn check_command(cmd: &str) -> Result<()> {
    if cmd.contains(['\r', '\n', '\0']) {
        return Err(Error::InvalidInput(
            "a command or file name must not contain line breaks or NUL characters".into(),
        ));
    }
    Ok(())
}

/// The bytes of `cmd` in `charset` (UTF-8 for Auto and UTF-8).
fn encode(cmd: &str, charset: Charset) -> Vec<u8> {
    match charset {
        Charset::Custom(enc) => enc.encode(cmd).0.into_owned(),
        Charset::Auto | Charset::Utf8 => cmd.as_bytes().to_vec(),
    }
}

/// Wait until either token fires.
async fn either_cancelled(a: &CancellationToken, b: &CancellationToken) {
    tokio::select! {
        () = a.cancelled() => {}
        () = b.cancelled() => {}
    }
}

/// Server text made safe for the log: control characters removed (tabs
/// become spaces), bidi overrides dropped.
fn log_safe(line: &str) -> Cow<'_, str> {
    let bad =
        |c: char| c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
    if !line.chars().any(bad) {
        return Cow::Borrowed(line);
    }
    Cow::Owned(
        line.chars()
            .filter_map(|c| match c {
                '\t' => Some(' '),
                c if bad(c) => None,
                c => Some(c),
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests;
