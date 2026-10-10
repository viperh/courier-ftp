//! The transfer sequence (T11 §1–§9): `TYPE`, passive/active data connection setup
//! with the session's fallback memory, `REST`, the transfer command and its `1xx`
//! reply, the final reply, `ABOR` + resync, and whole listings.
//!
//! ```text
//! ensure_type(t)                         # TYPE A | TYPE I, only if changed
//! [passive: EPSV/PASV + TCP connect]   [active: listen + PORT/EPRT]
//! [REST <offset>]                        # 350
//! RETR | STOR | APPE | LIST | MLSD       # 125/150 → stream; 226/250 → empty
//! [active: accept]  [TLS hook (T12) after the 1xx]
//! … bytes …
//! finish(): shutdown (uploads), final 226/250
//! ```

use std::{
    net::{IpAddr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use courier_ftp_core::{
    Error, Result,
    events::SessionLog,
    model::TransferType,
    net::{
        CancellationToken, HostPort, NetOpts, ProxyConfig, Purpose, connect_tcp, http_get_small,
    },
    settings::ActiveExternalIp,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use crate::{
    active::{accept_checked, bind_listener, format_eprt, format_port},
    ascii::{AsciiDecode, AsciiEncode},
    command::Command,
    control::{ControlConnection, ControlState},
    data::{
        DataConfig, DataIo, DataMode, DataState, DataStream, DataTlsHook, Direction, RawData,
        StreamIo, TransferCommand,
    },
    passive::{choose_pasv_ip, is_unroutable, parse_epsv, parse_pasv},
    reply::Reply,
};

/// Listings are read into memory up to this size.
pub const MAX_LISTING_BYTES: usize = 64 * 1024 * 1024;
/// Grace per reply after `ABOR`.
const ABOR_GRACE: Duration = Duration::from_secs(2);
/// Replies read after `ABOR` (the transfer's and the `ABOR`'s own).
const ABOR_MAX_REPLIES: usize = 3;
/// Replies skipped while waiting for the resync `NOOP`'s `200`.
const RESYNC_MAX_REPLIES: usize = 8;
/// After a ranged read hit its limit: how long to wait for the data's EOF.
const RANGE_EOF_WAIT: Duration = Duration::from_millis(200);
/// External IP lookup timeout and body cap.
const EXTERNAL_IP_TIMEOUT: Duration = Duration::from_secs(10);
const EXTERNAL_IP_MAX_BODY: usize = 1024;

/// Status line after a successful passive → active fallback.
pub const FALLBACK_STATUS: &str = "Passive mode failed, using active mode for this session";
/// Error for active mode through an HTTP or SOCKS proxy.
pub const ACTIVE_THROUGH_PROXY: &str =
    "active mode FTP does not work through an HTTP or SOCKS proxy; use passive mode";
/// Status line when the external IP lookup failed.
pub const EXTERNAL_IP_FAILED: &str =
    "Warning: Failed to retrieve external IP address, using local address";

/// A passive attempt's failure: `Fallback` errors may be retried in active mode.
enum PassiveError {
    Fallback(Error),
    Fatal(Error),
}

impl From<Error> for PassiveError {
    fn from(e: Error) -> Self {
        Self::Fatal(e)
    }
}

/// What the wait for the transfer command's reply produced.
enum Started {
    /// `125`/`150`: the transfer runs.
    Open,
    /// `226`/`250` without `1xx`: an empty transfer.
    Empty,
}

fn protocol(reply: &Reply) -> Error {
    Error::Protocol {
        code: Some(reply.code()),
        message: reply.text(),
    }
}

/// Session-level data operations (T14): a short-lived borrow bundle.
#[derive(Debug)]
pub struct FtpData<'a> {
    /// The logged-in control connection.
    pub ctrl: &'a mut ControlConnection,
    /// The session policy.
    pub cfg: &'a DataConfig,
    /// The session's learned state.
    pub state: &'a mut DataState,
}

impl FtpData<'_> {
    fn log(&self) -> SessionLog {
        self.ctrl.session_log().clone()
    }

    /// Sends `TYPE A`/`TYPE I` only when it differs from `ctrl.current_type()`.
    ///
    /// # Errors
    ///
    /// As `ControlConnection::send`; `Protocol` when the server refuses the type (the
    /// tracked type becomes unknown).
    pub async fn ensure_type(&mut self, t: TransferType, cancel: &CancellationToken) -> Result<()> {
        if self.ctrl.current_type() == Some(t) {
            return Ok(());
        }
        let arg = match t {
            TransferType::Ascii => "A",
            TransferType::Binary => "I",
        };
        let reply = self
            .ctrl
            .send(Command::new("TYPE").arg(arg)?, cancel)
            .await?;
        if reply.is_ok() {
            self.ctrl.set_current_type(Some(t));
            Ok(())
        } else {
            self.ctrl.set_current_type(None);
            Err(protocol(&reply))
        }
    }

    /// Opens the data connection, sends `REST` (offset > 0) and the command, waits for
    /// `125`/`150` and applies the TLS hook. The control stays `TransferOpen` until
    /// [`finish`](Self::finish) or [`abort`](Self::abort). `ty = Ascii` converts line
    /// ends of file transfers ([`crate::ascii`]).
    ///
    /// # Errors
    ///
    /// `InvalidInput` (a transfer is already open), `Unsupported` (ASCII resume, `REST`
    /// refused, active mode through a proxy or refused), `Connection`/`Timeout` (data
    /// connection), `Protocol` (bad `227`/`229`, 4xx/5xx replies), `Cancelled` (after
    /// the abort sequence).
    pub async fn open(
        &mut self,
        cmd: TransferCommand,
        ty: TransferType,
        tls: Option<&dyn DataTlsHook>,
        cancel: &CancellationToken,
    ) -> Result<DataStream> {
        self.precheck(&cmd, Some(ty))?;
        self.ensure_type(ty, cancel).await?;
        let ascii = ty == TransferType::Ascii && cmd.is_file();
        self.open_any(&cmd, ascii, tls, cancel).await
    }

    /// After the stream reached EOF (download) or was written completely (upload; the
    /// shutdown — TLS `close_notify` + TCP FIN — happens here if the caller did not):
    /// reads the final `226`/`250`. A stream that was dropped (`None`) or not read to
    /// the end runs the abort sequence and returns `Cancelled`. Ranged reads that hit
    /// their limit abort and count as success.
    ///
    /// # Errors
    ///
    /// `Protocol` (`426`/`451`/4xx transient, 5xx), `Timeout` (data inactivity),
    /// `Connection` (data or control failure), `Cancelled`.
    pub async fn finish(
        &mut self,
        stream: Option<DataStream>,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let Some(mut s) = stream else {
            self.abort(None).await?;
            return Err(Error::Cancelled);
        };
        if s.completed {
            return Ok(());
        }
        let log = self.log();
        if s.timed_out {
            drop(s);
            log.error("Data connection timed out");
            self.abort_sequence().await?;
            return Err(Error::Timeout);
        }
        if let Some(e) = s.failed.take() {
            drop(s);
            log.error(format!("Data connection failed: {e}"));
            // The server usually explains (426, 451, 452, 552…): wait briefly for its
            // final reply before falling back to ABOR.
            let never = CancellationToken::new();
            if let Ok(reply) = tokio::time::timeout(ABOR_GRACE, self.ctrl.read_reply(&never)).await
            {
                let reply = match reply {
                    Ok(r) => r,
                    Err(err) => {
                        self.ctrl.mark_transfer_open(false);
                        return Err(err);
                    }
                };
                if !reply.is_preliminary() {
                    self.ctrl.mark_transfer_open(false);
                    return Err(if reply.is_ok() {
                        Error::Connection(format!("data connection failed: {e}"))
                    } else {
                        protocol(&reply)
                    });
                }
            }
            self.abort_sequence().await?;
            return Err(Error::Connection(format!("data connection failed: {e}")));
        }
        match s.direction {
            Direction::Download => {
                if s.range_hit && !s.eof && !s.data_ends_within(RANGE_EOF_WAIT).await {
                    let bytes = s.bytes;
                    drop(s);
                    log.debug(
                        3,
                        format!("Requested range of {bytes} bytes read, aborting"),
                    );
                    return self.abort_sequence().await;
                }
                if !s.is_complete() {
                    drop(s);
                    self.abort_sequence().await?;
                    return Err(Error::Cancelled);
                }
            }
            Direction::Upload => {
                if !s.shut_down {
                    let result = tokio::select! {
                        biased;
                        () = cancel.cancelled() => None,
                        r = s.shutdown() => Some(r),
                    };
                    let shutdown = match result {
                        None => Err(Error::Cancelled),
                        Some(Ok(())) => Ok(()),
                        Some(Err(_)) if s.timed_out => Err(Error::Timeout),
                        Some(Err(e)) => {
                            Err(Error::Connection(format!("data connection failed: {e}")))
                        }
                    };
                    if let Err(e) = shutdown {
                        drop(s);
                        self.abort_sequence().await?;
                        return Err(e);
                    }
                }
            }
        }
        log.debug(3, format!("{} bytes transferred", s.bytes));
        drop(s);
        let never = CancellationToken::new();
        let reply = tokio::select! {
            biased;
            () = cancel.cancelled() => None,
            r = self.ctrl.read_reply(&never) => Some(r),
        };
        let Some(reply) = reply else {
            self.abort_sequence().await?;
            return Err(Error::Cancelled);
        };
        self.ctrl.mark_transfer_open(false);
        let reply = reply?;
        match reply.code() {
            200..=299 => Ok(()),
            _ => Err(protocol(&reply)),
        }
    }

    /// The `ABOR` sequence + resync (§8): closes the data socket, writes `ABOR`, reads
    /// up to three replies (2 s grace each), then `NOOP` until its `200`. Leaves the
    /// control `Ready`, or `Broken` when it could not resynchronise. Without an open
    /// transfer it only drops `stream`.
    ///
    /// # Errors
    ///
    /// `Connection` (could not resynchronise, connection lost).
    pub async fn abort(&mut self, stream: Option<DataStream>) -> Result<()> {
        let open = self.ctrl.state() == ControlState::TransferOpen;
        drop(stream);
        if open {
            self.abort_sequence().await
        } else {
            Ok(())
        }
    }

    /// Whole listing in memory (cap [`MAX_LISTING_BYTES`]), for T13. Read in whatever
    /// type is current (no `TYPE` round trip, no conversion).
    ///
    /// # Errors
    ///
    /// As [`open`](Self::open) and [`finish`](Self::finish); `Protocol { code: None }`
    /// "directory listing too large".
    pub async fn read_listing(
        &mut self,
        cmd: TransferCommand,
        tls: Option<&dyn DataTlsHook>,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>> {
        self.precheck(&cmd, None)?;
        let mut s = self.open_any(&cmd, false, tls, cancel).await?;
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let read = tokio::select! {
                biased;
                () = cancel.cancelled() => None,
                r = s.read(&mut buf) => Some(r),
            };
            match read {
                None => {
                    drop(s);
                    self.abort_sequence().await?;
                    return Err(Error::Cancelled);
                }
                Some(Ok(0)) => break,
                Some(Ok(n)) => {
                    if out.len() + n > MAX_LISTING_BYTES {
                        drop(s);
                        self.log().error("Directory listing too large");
                        self.abort_sequence().await?;
                        return Err(Error::Protocol {
                            code: None,
                            message: "directory listing too large".into(),
                        });
                    }
                    out.extend_from_slice(&buf[..n]);
                }
                Some(Err(_)) => break, // `finish` reports the recorded failure.
            }
        }
        self.finish(Some(s), cancel).await?;
        Ok(out)
    }

    // ---- open -------------------------------------------------------------------------

    fn precheck(&mut self, cmd: &TransferCommand, ty: Option<TransferType>) -> Result<()> {
        if self.ctrl.state() == ControlState::TransferOpen {
            return Err(Error::InvalidInput(
                "a transfer is already in progress".into(),
            ));
        }
        if self.state.rest_supported.is_none() && self.ctrl.features().rest_stream {
            self.state.rest_supported = Some(true);
        }
        if cmd.offset() > 0 {
            if ty == Some(TransferType::Ascii) {
                self.log().status(
                    "Resume is not possible in ASCII mode, the file has to be transferred again",
                );
                return Err(Error::Unsupported(
                    "resume is not possible in ASCII mode".into(),
                ));
            }
            if self.state.rest_supported == Some(false) {
                return Err(Error::Unsupported(
                    "server does not support resuming".into(),
                ));
            }
        }
        Ok(())
    }

    async fn open_any(
        &mut self,
        cmd: &TransferCommand,
        ascii: bool,
        tls: Option<&dyn DataTlsHook>,
        cancel: &CancellationToken,
    ) -> Result<DataStream> {
        if self.cfg.mode == DataMode::Active || self.state.use_active {
            return self.open_active(cmd, ascii, tls, cancel).await;
        }
        match self.open_passive(cmd, ascii, tls, cancel).await {
            Ok(s) => Ok(s),
            Err(PassiveError::Fatal(e)) => Err(e),
            Err(PassiveError::Fallback(e)) => {
                if !self.cfg.fallback_to_active || self.cfg.through_generic_proxy {
                    return Err(e);
                }
                let log = self.log();
                log.debug(3, format!("Passive mode failed ({e}), trying active mode"));
                tracing::info!(
                    session = log.session.get(),
                    "ftp data connection fell back to active mode"
                );
                let s = self.open_active(cmd, ascii, tls, cancel).await?;
                self.state.use_active = true;
                log.status(FALLBACK_STATUS);
                Ok(s)
            }
        }
    }

    // ---- passive ----------------------------------------------------------------------

    async fn open_passive(
        &mut self,
        cmd: &TransferCommand,
        ascii: bool,
        tls: Option<&dyn DataTlsHook>,
        cancel: &CancellationToken,
    ) -> Result<DataStream, PassiveError> {
        let target = self.passive_target(cancel).await?;
        let log = self.log();
        log.debug(3, format!("Data connection to {target}"));
        tracing::debug!(target = %target, "ftp data connection (passive)");
        let stream = match connect_tcp(&target, &self.cfg.net, cancel.clone(), &log).await {
            Ok(s) => s,
            Err(Error::Cancelled) => return Err(PassiveError::Fatal(Error::Cancelled)),
            Err(e @ Error::Timeout) => {
                log.error("Failed to open data connection");
                tracing::info!(session = log.session.get(), "ftp data connection failed");
                return Err(PassiveError::Fallback(e));
            }
            Err(Error::Connection(m)) => {
                log.error("Failed to open data connection");
                tracing::info!(session = log.session.get(), "ftp data connection failed");
                return Err(PassiveError::Fallback(Error::Connection(format!(
                    "Failed to open data connection: {m}"
                ))));
            }
            Err(e) => return Err(PassiveError::Fatal(e)),
        };
        stream.set_socket_buffer(self.cfg.socket_buffer);
        let raw = RawData::Dialed(stream);
        self.send_rest(cmd, cancel).await?;
        match self.start_command(cmd, cancel).await {
            Ok(Started::Open) => Ok(self.wrap(raw, cmd, ascii, tls).await?),
            Ok(Started::Empty) => Ok(DataStream::empty(direction(cmd))),
            Err(
                e @ Error::Protocol {
                    code: Some(425), ..
                },
            ) => Err(PassiveError::Fallback(e)),
            Err(e) => Err(PassiveError::Fatal(e)),
        }
    }

    /// `EPSV` (or `PASV`) and the address to dial.
    async fn passive_target(
        &mut self,
        cancel: &CancellationToken,
    ) -> Result<HostPort, PassiveError> {
        let peer = self.ctrl.peer_addr();
        let ipv6 = peer.is_some_and(|p| p.ip().to_canonical().is_ipv6());
        let feats = self.ctrl.features();
        let try_epsv = ipv6 || (!self.state.epsv_failed && (feats.epsv || !feats.feat_supported));
        if try_epsv {
            let reply = self.ctrl.send(Command::new("EPSV"), cancel).await?;
            match reply.code() {
                229 => {
                    let port = parse_epsv(&reply.text()).map_err(|_| Error::Protocol {
                        code: Some(229),
                        message: "Invalid passive mode reply".into(),
                    })?;
                    return Ok(self.epsv_target(peer, port));
                }
                500 | 501 | 502 | 504 => {
                    self.state.epsv_failed = true;
                    if ipv6 {
                        return Err(PassiveError::Fallback(protocol(&reply)));
                    }
                }
                _ => return Err(PassiveError::Fallback(protocol(&reply))),
            }
        }
        if self.state.pasv_failed {
            return Err(PassiveError::Fallback(Error::Unsupported(
                "server does not support passive mode".into(),
            )));
        }
        let reply = self.ctrl.send(Command::new("PASV"), cancel).await?;
        match reply.code() {
            227 => {
                let addr = parse_pasv(&reply.text()).map_err(|_| Error::Protocol {
                    code: Some(227),
                    message: "Invalid passive mode reply".into(),
                })?;
                Ok(self.pasv_target(peer, addr))
            }
            500..=599 => {
                self.state.pasv_failed = true;
                Err(PassiveError::Fallback(protocol(&reply)))
            }
            _ => Err(PassiveError::Fallback(protocol(&reply))),
        }
    }

    fn epsv_target(&self, peer: Option<SocketAddr>, port: u16) -> HostPort {
        match peer {
            Some(peer) if !self.cfg.through_generic_proxy => {
                HostPort::new(peer.ip().to_canonical().to_string(), port)
            }
            _ => HostPort::new(self.cfg.control_host.clone(), port),
        }
    }

    fn pasv_target(&self, peer: Option<SocketAddr>, addr: SocketAddrV4) -> HostPort {
        if self.cfg.through_generic_proxy {
            return HostPort::new(self.cfg.control_host.clone(), addr.port());
        }
        let Some(peer) = peer else {
            return HostPort::new(addr.ip().to_string(), addr.port());
        };
        let (ip, status) = choose_pasv_ip(
            *addr.ip(),
            peer.ip().to_canonical(),
            self.cfg.ignore_unroutable_pasv_ip,
        );
        if let Some(line) = status {
            self.ctrl.session_log().status(line);
        }
        HostPort::new(ip.to_string(), addr.port())
    }

    // ---- active -----------------------------------------------------------------------

    async fn open_active(
        &mut self,
        cmd: &TransferCommand,
        ascii: bool,
        tls: Option<&dyn DataTlsHook>,
        cancel: &CancellationToken,
    ) -> Result<DataStream> {
        let log = self.log();
        if self.cfg.through_generic_proxy {
            log.error(ACTIVE_THROUGH_PROXY);
            return Err(Error::Unsupported(ACTIVE_THROUGH_PROXY.into()));
        }
        let (Some(local), peer) = (self.ctrl.local_addr(), self.ctrl.peer_addr()) else {
            return Err(Error::Unsupported(
                "active mode needs a direct TCP control connection".into(),
            ));
        };
        let local_ip = local.ip().to_canonical();
        let listener = bind_listener(local_ip, self.cfg.port_range, self.cfg.socket_buffer)?;
        let port = listener
            .local_addr()
            .map_err(|e| {
                Error::Connection(format!("could not listen for the data connection: {e}"))
            })?
            .port();
        let peer_ip = peer.map(|p| p.ip().to_canonical());
        let ip = self.advertised_ip(local_ip, peer_ip, cancel).await?;
        log.debug(
            3,
            format!(
                "Listening for the data connection on {}",
                SocketAddr::new(local_ip, port)
            ),
        );
        self.send_port(SocketAddr::new(ip, port), cancel).await?;
        self.send_rest(cmd, cancel).await?;
        let raw = self.start_active(cmd, &listener, peer_ip, cancel).await?;
        drop(listener);
        match raw {
            Some(raw) => self.wrap(RawData::Accepted(raw), cmd, ascii, tls).await,
            None => Ok(DataStream::empty(direction(cmd))),
        }
    }

    /// The address put into `PORT`/`EPRT` (§3).
    async fn advertised_ip(
        &mut self,
        local: IpAddr,
        peer: Option<IpAddr>,
        cancel: &CancellationToken,
    ) -> Result<IpAddr> {
        let log = self.log();
        if self.cfg.no_external_ip_on_local && peer.is_none_or(is_unroutable) {
            return Ok(local);
        }
        match &self.cfg.external_ip {
            ActiveExternalIp::Auto => Ok(local),
            ActiveExternalIp::Fixed(ip) => {
                if ip.is_ipv4() == local.is_ipv4() {
                    Ok(*ip)
                } else {
                    log.status(
                        "Warning: The external IP address has the wrong address family, using local address",
                    );
                    Ok(local)
                }
            }
            ActiveExternalIp::FromUrl(url) => {
                if let Some(ip) = self.state.external_ip_cache {
                    return Ok(ip);
                }
                let opts = NetOpts {
                    timeout: EXTERNAL_IP_TIMEOUT,
                    prefer_ipv6: local.is_ipv6(),
                    allow_ipv6: true,
                    purpose: Purpose::Data,
                    socket_buffer: None,
                    proxy: ProxyConfig::Direct,
                };
                log.status("Retrieving external IP address");
                let lookup = async {
                    tokio::time::timeout(
                        EXTERNAL_IP_TIMEOUT,
                        http_get_small(url, &opts, &log, EXTERNAL_IP_MAX_BODY),
                    )
                    .await
                };
                let body = tokio::select! {
                    biased;
                    () = cancel.cancelled() => return Err(Error::Cancelled),
                    r = lookup => r,
                };
                let ip = match body {
                    Ok(Ok(body)) => body
                        .trim()
                        .parse::<IpAddr>()
                        .ok()
                        .map(|ip| ip.to_canonical())
                        .filter(|ip| ip.is_ipv4() == local.is_ipv4()),
                    Ok(Err(e)) => {
                        log.debug(3, format!("External IP lookup failed: {e}"));
                        None
                    }
                    Err(_) => None,
                };
                match ip {
                    Some(ip) => {
                        self.state.external_ip_cache = Some(ip);
                        log.debug(3, format!("External IP address is {ip}"));
                        Ok(ip)
                    }
                    None => {
                        log.status(EXTERNAL_IP_FAILED);
                        Ok(local)
                    }
                }
            }
        }
    }

    /// `PORT` (IPv4, `EPRT |1|` as the fallback) or `EPRT |2|` (IPv6) → `200`.
    async fn send_port(&mut self, addr: SocketAddr, cancel: &CancellationToken) -> Result<()> {
        match addr {
            SocketAddr::V4(v4) => {
                let reply = self
                    .ctrl
                    .send(Command::new("PORT").arg(format_port(v4))?, cancel)
                    .await?;
                match reply.code() {
                    200..=299 => return Ok(()),
                    500..=502 => {}
                    _ => return Err(protocol(&reply)),
                }
                if !self.state.eprt_failed {
                    let reply = self
                        .ctrl
                        .send(Command::new("EPRT").arg(format_eprt(addr))?, cancel)
                        .await?;
                    if reply.is_ok() {
                        return Ok(());
                    }
                    self.state.eprt_failed = true;
                }
                Err(Error::Unsupported("server refused active mode".into()))
            }
            SocketAddr::V6(_) => {
                let reply = self
                    .ctrl
                    .send(Command::new("EPRT").arg(format_eprt(addr))?, cancel)
                    .await?;
                match reply.code() {
                    200..=299 => Ok(()),
                    500 | 501 | 502 | 522 => Err(Error::Unsupported(
                        "server does not support active mode over IPv6".into(),
                    )),
                    _ => Err(protocol(&reply)),
                }
            }
        }
    }

    /// Sends the command and waits for its `1xx` reply while accepting the server's
    /// connection (bounded by the timeout). `None` = empty transfer.
    async fn start_active(
        &mut self,
        cmd: &TransferCommand,
        listener: &TcpListener,
        peer_ip: Option<IpAddr>,
        cancel: &CancellationToken,
    ) -> Result<Option<tokio::net::TcpStream>> {
        enum Event {
            Cancelled,
            Reply(Result<Reply>),
            Accepted(Result<tokio::net::TcpStream>),
            TimedOut,
        }
        let log = self.log();
        self.ctrl.write_command(command_for(cmd)?).await?;
        let deadline = tokio::time::Instant::now() + self.cfg.timeout;
        let never = CancellationToken::new();
        let mut accepted = None;
        let mut started = false;
        while accepted.is_none() || !started {
            let event = tokio::select! {
                biased;
                () = cancel.cancelled() => Event::Cancelled,
                r = self.ctrl.read_reply(&never), if !started => Event::Reply(r),
                a = accept_checked(listener, peer_ip, &log), if accepted.is_none() => Event::Accepted(a),
                () = tokio::time::sleep_until(deadline), if accepted.is_none() => Event::TimedOut,
            };
            match event {
                Event::Cancelled => {
                    drop(accepted);
                    self.abort_sequence().await?;
                    return Err(Error::Cancelled);
                }
                Event::Reply(r) => match self.classify_start(r?)? {
                    Started::Open => started = true,
                    Started::Empty => return Ok(None),
                },
                Event::Accepted(a) => accepted = Some(a?),
                Event::TimedOut => {
                    log.error("Server did not connect to the data port");
                    tracing::info!(session = log.session.get(), "ftp data connection failed");
                    self.abort_sequence().await?;
                    return Err(Error::Connection(
                        "server did not connect to the data port".into(),
                    ));
                }
            }
        }
        Ok(accepted)
    }

    // ---- shared steps ---------------------------------------------------------------------

    /// `REST <offset>` → `350` (§6).
    async fn send_rest(&mut self, cmd: &TransferCommand, cancel: &CancellationToken) -> Result<()> {
        let offset = cmd.offset();
        if offset == 0 {
            return Ok(());
        }
        let reply = self
            .ctrl
            .send(Command::new("REST").arg(offset.to_string())?, cancel)
            .await?;
        match reply.code() {
            350 => {
                self.state.rest_supported = Some(true);
                Ok(())
            }
            500 | 501 | 502 | 504 => {
                self.state.rest_supported = Some(false);
                Err(Error::Unsupported(
                    "server does not support resuming".into(),
                ))
            }
            _ => Err(protocol(&reply)),
        }
    }

    /// Writes the transfer command and waits for its first reply (cancellation runs the
    /// abort sequence).
    async fn start_command(
        &mut self,
        cmd: &TransferCommand,
        cancel: &CancellationToken,
    ) -> Result<Started> {
        self.ctrl.write_command(command_for(cmd)?).await?;
        let never = CancellationToken::new();
        let reply = tokio::select! {
            biased;
            () = cancel.cancelled() => None,
            r = self.ctrl.read_reply(&never) => Some(r),
        };
        let Some(reply) = reply else {
            self.abort_sequence().await?;
            return Err(Error::Cancelled);
        };
        self.classify_start(reply?)
    }

    fn classify_start(&mut self, reply: Reply) -> Result<Started> {
        match reply.code() {
            125 | 150 => {
                self.ctrl.mark_transfer_open(true);
                Ok(Started::Open)
            }
            100..=199 => {
                // Other preliminary replies (e.g. 110) still mean the transfer starts.
                self.ctrl.mark_transfer_open(true);
                Ok(Started::Open)
            }
            226 | 250 => Ok(Started::Empty),
            _ => Err(protocol(&reply)),
        }
    }

    /// TLS hook (after the `1xx`) and the ASCII adapter.
    async fn wrap(
        &mut self,
        raw: RawData,
        cmd: &TransferCommand,
        ascii: bool,
        tls: Option<&dyn DataTlsHook>,
    ) -> Result<DataStream> {
        let io = match tls {
            None => DataIo::Plain(raw),
            Some(hook) => match hook.wrap(raw).await {
                Ok(io) => io,
                Err(e) => {
                    self.abort_sequence().await?;
                    return Err(e);
                }
            },
        };
        let dir = direction(cmd);
        let io = match (ascii, dir) {
            (false, _) => StreamIo::Plain(io),
            (true, Direction::Download) => StreamIo::Decode(AsciiDecode::new(io)),
            (true, Direction::Upload) => StreamIo::Encode(AsciiEncode::new(io)),
        };
        let range = match cmd {
            TransferCommand::Retr { range_len, .. } => *range_len,
            _ => None,
        };
        Ok(DataStream::new(io, dir, range, self.cfg.timeout))
    }

    /// §8: `ABOR`, up to three replies (2 s grace each), `NOOP` until `200`.
    async fn abort_sequence(&mut self) -> Result<()> {
        let log = self.log();
        log.debug(3, "Aborting transfer");
        let never = CancellationToken::new();
        if let Err(e) = self.ctrl.write_command(Command::new("ABOR")).await {
            self.ctrl.mark_transfer_open(false);
            self.ctrl.mark_broken();
            return Err(e);
        }
        for _ in 0..ABOR_MAX_REPLIES {
            match tokio::time::timeout(ABOR_GRACE, self.ctrl.read_reply(&never)).await {
                Err(_) => {
                    log.debug(3, "No further reply to ABOR");
                    break;
                }
                Ok(Err(e)) => {
                    self.ctrl.mark_transfer_open(false);
                    return Err(e);
                }
                Ok(Ok(reply)) => {
                    log.debug(3, format!("ABOR: reply {} read", reply.code()));
                    // 1xx/4xx belong to the transfer; anything else answers ABOR.
                    if !matches!(reply.code(), 100..=199 | 400..=499) {
                        break;
                    }
                }
            }
        }
        self.ctrl.mark_transfer_open(false);
        self.ctrl.write_command(Command::new("NOOP")).await?;
        let deadline = tokio::time::Instant::now() + self.cfg.timeout;
        for _ in 0..RESYNC_MAX_REPLIES {
            match tokio::time::timeout_at(deadline, self.ctrl.read_reply(&never)).await {
                Err(_) => break,
                Ok(Err(e)) => return Err(e),
                Ok(Ok(reply)) if reply.code() == 200 => {
                    log.debug(3, "Control connection resynchronised");
                    return Ok(());
                }
                Ok(Ok(reply)) => {
                    log.debug(
                        3,
                        format!("Skipped reply {} while resynchronising", reply.code()),
                    );
                }
            }
        }
        self.ctrl.mark_broken();
        log.debug(3, "Could not resynchronise the control connection");
        Err(Error::Connection(
            "could not resynchronise the control connection after ABOR".into(),
        ))
    }
}

fn direction(cmd: &TransferCommand) -> Direction {
    if cmd.is_upload() {
        Direction::Upload
    } else {
        Direction::Download
    }
}

/// The command line (without `REST`).
fn command_for(cmd: &TransferCommand) -> Result<Command> {
    Ok(match cmd {
        TransferCommand::List { args: None } => Command::new("LIST"),
        TransferCommand::List { args: Some(a) } => Command::new("LIST").arg(a.clone())?,
        TransferCommand::Mlsd => Command::new("MLSD"),
        TransferCommand::Retr { path, .. } => Command::new("RETR").arg(path.clone())?,
        TransferCommand::Stor { path, .. } => Command::new("STOR").arg(path.clone())?,
        TransferCommand::Appe { path } => Command::new("APPE").arg(path.clone())?,
    })
}

#[cfg(test)]
mod tests;
