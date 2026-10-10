//! FTP data connections (T11): passive and active mode, the transfer
//! command sequence, completion and abort.
//!
//! # Opening a data connection
//!
//! [`DataSession::open`] runs the whole sequence for one data command
//! (`RETR`, `STOR`, `APPE`, `LIST`, `MLSD`, …):
//!
//! 1. **Passive** (default): `EPSV` when the server announces it or the
//!    control connection is IPv6, else `PASV`; a `500`/`502` to `EPSV` falls
//!    back to `PASV` for the rest of the session. The data connection is
//!    opened *before* the command is sent (some servers need that), through
//!    [`connect_tcp`], so it uses the generic proxy too. With
//!    `passive_ignore_unroutable_ip`, a private/loopback/`0.0.0.0` address in
//!    the `227` reply while the control peer is public is replaced by the
//!    control peer's address (logged).
//! 2. **Active**: a listener on the control connection's local address (a
//!    port from `active_port_range`, else any); the address announced is the
//!    local one, a fixed one or one fetched once per session from an
//!    IP-echo URL ([`ExternalIp`]); local peers always get the local
//!    address. `EPRT` (`|1|` IPv4, `|2|` IPv6), falling back to `PORT` for
//!    IPv4 when `EPRT` is refused. The server's connection is accepted with
//!    the timeout, and only from the control peer's address (no FTP bounce).
//!    Through an HTTP/SOCKS proxy active mode is [`Error::Unsupported`].
//! 3. **Fallback**: when passive mode fails (refused, or the data connection
//!    can't be opened) and `fallback_to_active` is on, the same command is
//!    retried once in active mode and active mode is kept for the session.
//! 4. `REST n` when resuming (must be answered with `350`), then the
//!    command; `125`/`150` means data follows. A final `2xx` straight away
//!    (some servers, for an empty listing) gives [`DataOpen::Done`]; an error
//!    reply gives [`DataOpen::Refused`] so the caller can map it (`550` →
//!    not found…).
//! 5. FTPS (T12): with `PROT P` the data connection is wrapped in TLS after
//!    the `150` (also in active mode, where we stay the TLS client), resuming
//!    the control connection's TLS session.
//!
//! # Completing and aborting
//!
//! The caller streams through the returned [`DataStream`], then calls
//! [`finish`]: after EOF (read) or a clean shutdown (write) it reads the
//! final reply (`226`/`250`; a `226` that arrived while data was still
//! flowing simply waits in the reply buffer). If the stream was dropped
//! early — the transfer was cancelled — `finish` sends `ABOR` and reads the
//! `426` + `226` pair (or whatever the server sends), so the control
//! connection stays usable, and returns [`Error::Cancelled`].
//!
//! # Transfer type and ASCII
//!
//! [`ControlConnection::set_type`] sends `TYPE` only when it changes;
//! `courier_ftp_core::backend::decide_transfer_type` picks it per file. The
//! [`ascii`] adapters convert line endings while streaming. Resume is not
//! offered for ASCII transfers (the byte offsets differ on both sides).

pub mod addr;
pub mod ascii;
mod external_ip;
mod stream;

use std::{
    net::{IpAddr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use courier_ftp_core::{
    Error, Result,
    events::LogKind,
    net::{HostPort, NetOpts, connect_tcp, ensure_active_mode_allowed},
    settings::{ExternalIp, FtpTransferMode, Settings},
};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use self::addr::{eprt_command, is_routable, parse_epsv, parse_pasv, port_command};
pub use self::stream::{DataStream, SHUTDOWN_DRAIN, TransferFlags};
use crate::control::{BoxedStream, ControlConnection, Reply};

/// How long [`finish`] waits for the second reply after `ABOR` once the
/// first has arrived (servers send one or two).
pub const ABORT_SECOND_REPLY: Duration = Duration::from_secs(2);

/// How data connections are opened: the `ftp.*` settings plus the
/// connection's network options.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DataOptions {
    /// Passive or active.
    pub mode: FtpTransferMode,
    /// Retry in active mode when passive fails.
    pub fallback_to_active: bool,
    /// The address announced in active mode.
    pub external_ip: ExternalIp,
    /// Local ports for active mode (inclusive), or any.
    pub port_range: Option<(u16, u16)>,
    /// Replace unroutable `PASV` addresses with the control peer's.
    pub ignore_unroutable: bool,
    /// Network options for data connections (no `TCP_NODELAY`, the proxy).
    pub net: NetOpts,
    /// The server as the user named it (for `EPSV` through a proxy).
    pub host: HostPort,
    /// Inactivity timeout on data connections.
    pub timeout: Duration,
}

impl DataOptions {
    /// Options from `settings.ftp`, with `mode` overriding the transfer mode
    /// when the site sets one, for the server `host` reached with `net`.
    pub fn new(
        settings: &Settings,
        mode: Option<FtpTransferMode>,
        host: HostPort,
        net: &NetOpts,
        timeout: Duration,
    ) -> Self {
        let ftp = &settings.ftp;
        Self {
            mode: mode.unwrap_or(ftp.transfer_mode),
            fallback_to_active: ftp.fallback_to_active,
            external_ip: ftp.active_external_ip.clone(),
            port_range: ftp.active_port_range,
            ignore_unroutable: ftp.passive_ignore_unroutable_ip,
            net: net.clone().for_data(),
            host,
            timeout,
        }
    }
}

/// The result of [`DataSession::open`].
#[derive(Debug)]
pub enum DataOpen {
    /// `150`/`125`: the data connection is ready.
    Stream(DataStream),
    /// The server answered the command with an error (`550`, `425`, …).
    Refused(Reply),
    /// The server answered with a final `2xx` without sending data.
    Done(Reply),
}

/// Why passive mode didn't work.
enum PassiveError {
    /// The connection itself failed (timeout, lost, cancelled): no fallback.
    Fatal(Error),
    /// The server refused `PASV`/`EPSV` or the data connection couldn't be
    /// opened: active mode may work.
    Failed(Error),
}

/// The prepared data channel before the command is sent.
enum Prepared {
    Passive(TcpStream),
    Active(TcpListener),
}

/// Data connection state for one session (it outlives reconnects: a
/// learned fallback to active mode is kept).
#[derive(Debug)]
pub struct DataSession {
    opts: DataOptions,
    mode: FtpTransferMode,
    epsv_refused: bool,
    eprt_refused: bool,
    external_ip: Option<IpAddr>,
}

impl DataSession {
    /// A session with `opts`.
    pub fn new(opts: DataOptions) -> Self {
        Self {
            mode: opts.mode,
            opts,
            epsv_refused: false,
            eprt_refused: false,
            external_ip: None,
        }
    }

    /// The options.
    pub fn options(&self) -> &DataOptions {
        &self.opts
    }

    /// The mode in use (active after a fallback).
    pub fn mode(&self) -> FtpTransferMode {
        self.mode
    }

    /// Open a data connection for `cmd`, with `REST rest` first when
    /// resuming. See the [module docs](self).
    ///
    /// # Errors
    ///
    /// Connection-level errors of the control connection; [`Error::Timeout`]
    /// / [`Error::Connection`] when the data connection can't be opened
    /// (also after the fallback); [`Error::Unsupported`] for active mode
    /// through a proxy or a server that refuses `REST`; [`Error::Tls`] when
    /// the data connection's TLS fails.
    pub async fn open(
        &mut self,
        conn: &mut ControlConnection,
        cmd: &str,
        rest: Option<u64>,
        cancel: &CancellationToken,
    ) -> Result<DataOpen> {
        let prepared = match self.mode {
            FtpTransferMode::Passive => match self.passive(conn, cancel).await {
                Ok(tcp) => Prepared::Passive(tcp),
                Err(PassiveError::Fatal(err)) => return Err(err),
                Err(PassiveError::Failed(err)) if self.opts.fallback_to_active => {
                    if self.opts.net.proxy.is_some() {
                        return Err(err);
                    }
                    conn.events().log(
                        conn.session(),
                        LogKind::Status,
                        format!("Passive mode failed ({err}); trying active mode for this session"),
                    );
                    self.mode = FtpTransferMode::Active;
                    Prepared::Active(self.active(conn, cancel).await?)
                }
                Err(PassiveError::Failed(err)) => return Err(err),
            },
            FtpTransferMode::Active => Prepared::Active(self.active(conn, cancel).await?),
        };
        if let Some(offset) = rest {
            let reply = conn.send_with(&format!("REST {offset}"), cancel).await?;
            if reply.code != 350 {
                return Err(match reply.code {
                    500 | 502 | 504 => Error::Unsupported("the server does not support REST"),
                    _ => reply.to_error(),
                });
            }
        }
        conn.write_command_with(cmd, cancel).await?;
        let reply = loop {
            let reply = conn.read_reply_with(cancel).await?;
            match reply.code {
                125 | 150 => break reply,
                // Other 1xx (rare): keep waiting.
                100..=199 => {}
                200..=299 => return Ok(DataOpen::Done(reply)),
                _ => return Ok(DataOpen::Refused(reply)),
            }
        };
        tracing::debug!(code = reply.code, "data connection accepted");
        let tcp = match prepared {
            Prepared::Passive(tcp) => tcp,
            Prepared::Active(listener) => match self.accept(conn, listener, cancel).await {
                Ok(tcp) => tcp,
                Err(err) => {
                    abort_after_failed_open(conn).await;
                    return Err(err);
                }
            },
        };
        let stream: BoxedStream = Box::new(tcp);
        let tls = false;
        Ok(DataOpen::Stream(DataStream::new(
            stream,
            self.opts.timeout,
            conn.cancel_token().clone(),
            tls,
        )))
    }

    /// `EPSV`/`PASV` and the data connection.
    async fn passive(
        &mut self,
        conn: &mut ControlConnection,
        cancel: &CancellationToken,
    ) -> std::result::Result<TcpStream, PassiveError> {
        let fatal = |err: Error| match err {
            err @ (Error::Cancelled | Error::Timeout | Error::Connection(_)) => {
                PassiveError::Fatal(err)
            }
            other => PassiveError::Failed(other),
        };
        let peer = conn.peer_addr();
        let ipv6 = peer.is_some_and(|p| p.is_ipv6());
        let via_proxy = self.opts.net.proxy.is_some();
        let mut target = None;
        if !self.epsv_refused && (conn.features().epsv || ipv6) {
            let reply = conn.send_with("EPSV", cancel).await.map_err(fatal)?;
            match reply.code {
                229 => {
                    let port = parse_epsv(&reply.text()).ok_or_else(|| {
                        PassiveError::Failed(Error::Protocol {
                            code: Some(229),
                            message: format!("cannot parse the EPSV reply: {}", reply.text()),
                        })
                    })?;
                    target = Some(match (via_proxy, peer) {
                        (false, Some(peer)) => HostPort::from(SocketAddr::new(peer.ip(), port)),
                        _ => HostPort::new(self.opts.host.host.clone(), port),
                    });
                }
                500 | 501 | 502 | 504 if !ipv6 => {
                    self.epsv_refused = true;
                }
                _ => return Err(PassiveError::Failed(reply.to_error())),
            }
        }
        let target = match target {
            Some(t) => t,
            None => {
                let reply = conn.send_with("PASV", cancel).await.map_err(fatal)?;
                if reply.code != 227 {
                    return Err(PassiveError::Failed(reply.to_error()));
                }
                let addr = parse_pasv(&reply.text()).ok_or_else(|| {
                    PassiveError::Failed(Error::Protocol {
                        code: Some(227),
                        message: format!("cannot parse the PASV reply: {}", reply.text()),
                    })
                })?;
                let (target, replaced) = pasv_target(
                    addr,
                    peer,
                    via_proxy,
                    &self.opts.host,
                    self.opts.ignore_unroutable,
                );
                if replaced {
                    conn.events().log(
                        conn.session(),
                        LogKind::Status,
                        format!(
                            "Server sent passive reply with unroutable address {}; using the server address instead",
                            addr.ip()
                        ),
                    );
                }
                target
            }
        };
        let result = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(Error::Cancelled),
            r = connect_tcp(&target, &self.opts.net, conn.cancel_token(), conn.events(), conn.session()) => r,
        };
        result.map_err(|err| match err {
            Error::Cancelled => PassiveError::Fatal(Error::Cancelled),
            other => PassiveError::Failed(other),
        })
    }

    /// Bind the listener and send `EPRT`/`PORT`.
    async fn active(
        &mut self,
        conn: &mut ControlConnection,
        cancel: &CancellationToken,
    ) -> Result<TcpListener> {
        ensure_active_mode_allowed(&self.opts.net, conn.events(), conn.session())?;
        let local = conn.local_addr().ok_or(Error::Unsupported(
            "active mode needs a TCP control connection",
        ))?;
        let listener = bind_listener(local.ip(), self.opts.port_range).await?;
        let port = listener.local_addr()?.port();
        let ip = self.announce_ip(conn, local.ip(), cancel).await?;
        let addr = SocketAddr::new(ip, port);
        let mut done = false;
        if addr.is_ipv6() || !self.eprt_refused {
            let reply = conn.send_with(&eprt_command(addr), cancel).await?;
            match reply.code {
                200..=299 => done = true,
                500 | 501 | 502 | 504 if addr.is_ipv4() => self.eprt_refused = true,
                _ => return Err(reply.to_error()),
            }
        }
        if !done && let SocketAddr::V4(v4) = addr {
            let reply = conn.send_with(&port_command(v4), cancel).await?;
            if !reply.is_ok() {
                return Err(reply.to_error());
            }
        }
        Ok(listener)
    }

    /// The address to announce in active mode.
    async fn announce_ip(
        &mut self,
        conn: &ControlConnection,
        local: IpAddr,
        cancel: &CancellationToken,
    ) -> Result<IpAddr> {
        let peer_is_local = conn.peer_addr().is_none_or(|p| !is_routable(p.ip()));
        if local.is_ipv6() || peer_is_local {
            return Ok(local);
        }
        match &self.opts.external_ip {
            ExternalIp::Auto => Ok(local),
            ExternalIp::Fixed(ip) => Ok(*ip),
            ExternalIp::FromUrl(url) => {
                if let Some(ip) = self.external_ip {
                    return Ok(ip);
                }
                let fetched = tokio::select! {
                    biased;
                    () = cancel.cancelled() => Err(Error::Cancelled),
                    r = external_ip::fetch(url, &self.opts, conn.cancel_token(), conn.events(), conn.session()) => r,
                };
                match fetched {
                    Ok(ip) => {
                        conn.events().log(
                            conn.session(),
                            LogKind::Status,
                            format!("External IP address for active mode: {ip}"),
                        );
                        self.external_ip = Some(ip);
                        Ok(ip)
                    }
                    Err(Error::Cancelled) => Err(Error::Cancelled),
                    Err(err) => {
                        conn.events().log(
                            conn.session(),
                            LogKind::Error,
                            format!(
                                "Could not get the external IP address ({err}); using the local address"
                            ),
                        );
                        Ok(local)
                    }
                }
            }
        }
    }

    /// Accept the server's connection: only from the control peer, within
    /// the timeout.
    async fn accept(
        &self,
        conn: &ControlConnection,
        listener: TcpListener,
        cancel: &CancellationToken,
    ) -> Result<TcpStream> {
        let expected = conn.peer_addr().map(|p| canonical(p.ip()));
        let wait = async {
            loop {
                let (tcp, from) = listener.accept().await?;
                if expected.is_none_or(|ip| ip == canonical(from.ip())) {
                    tcp.set_nodelay(false).ok();
                    return Ok::<_, Error>(tcp);
                }
                conn.events().log(
                    conn.session(),
                    LogKind::Error,
                    format!("Refused a data connection from {from}: not the server's address"),
                );
            }
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(Error::Cancelled),
            () = conn.cancel_token().cancelled() => Err(Error::Cancelled),
            r = tokio::time::timeout(self.opts.timeout, wait) => match r {
                Ok(r) => r,
                Err(_) => {
                    conn.events().log(
                        conn.session(),
                        LogKind::Error,
                        "The server did not open the data connection (active mode)",
                    );
                    Err(Error::Timeout)
                }
            },
        }
    }
}

/// Where to open the data connection for the `227` address `addr`, and
/// whether the address was replaced: `0.0.0.0` always is, an unroutable
/// address is when `ignore_unroutable` is on and the control peer is
/// public. The replacement is the control peer's address, or the server's
/// name behind a proxy (whose peer address is the proxy).
pub fn pasv_target(
    addr: SocketAddrV4,
    peer: Option<SocketAddr>,
    via_proxy: bool,
    host: &HostPort,
    ignore_unroutable: bool,
) -> (HostPort, bool) {
    let ip = IpAddr::V4(*addr.ip());
    let control_public = match (via_proxy, peer) {
        (false, Some(peer)) => is_routable(peer.ip()),
        // A host name counts as public.
        _ => host.ip().is_none_or(is_routable),
    };
    let replace = ip.is_unspecified() || (ignore_unroutable && !is_routable(ip) && control_public);
    if replace {
        let host = match (via_proxy, peer) {
            (false, Some(peer)) => peer.ip().to_string(),
            _ => host.host.clone(),
        };
        (HostPort::new(host, addr.port()), true)
    } else {
        (HostPort::from(SocketAddr::new(ip, addr.port())), false)
    }
}

/// IPv4-mapped IPv6 addresses as IPv4, for comparisons.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// A listener on `ip`, on a port from `range` (tried from a random start)
/// or any port.
async fn bind_listener(ip: IpAddr, range: Option<(u16, u16)>) -> Result<TcpListener> {
    let Some((low, high)) = range.filter(|(l, h)| l <= h && *l > 0) else {
        return Ok(TcpListener::bind(SocketAddr::new(ip, 0)).await?);
    };
    let count = u32::from(high - low) + 1;
    let start = {
        use std::hash::BuildHasher;
        let n = std::collections::hash_map::RandomState::new().hash_one(std::time::Instant::now());
        u32::try_from(n % u64::from(count)).unwrap_or(0)
    };
    let mut last = None;
    for i in 0..count {
        let offset = (start + i) % count;
        let port = low.saturating_add(u16::try_from(offset).unwrap_or(0));
        match TcpListener::bind(SocketAddr::new(ip, port)).await {
            Ok(l) => return Ok(l),
            Err(err) => last = Some(err),
        }
    }
    Err(Error::Connection(format!(
        "no free port in the active mode range {low}-{high}: {}",
        last.map_or_else(|| "none".to_owned(), |e| e.to_string())
    )))
}

/// After the server accepted a command but the data connection failed:
/// `ABOR` so the control connection gets back in step.
async fn abort_after_failed_open(conn: &mut ControlConnection) {
    if let Err(err) = abort(conn).await {
        tracing::debug!(%err, "abort after a failed data connection");
    }
}

/// Complete a transfer: the final reply after EOF / shutdown, or `ABOR`
/// when the stream was dropped early. `flags` come from the transfer's
/// [`DataStream`]; `upload` says which completion to check.
///
/// Returns the final reply when it is a `2xx`.
///
/// # Errors
///
/// [`Error::Cancelled`] after an abort; the error reply (as
/// [`Reply::to_error`]) when the server reports a failed transfer;
/// connection-level errors.
pub async fn finish(
    conn: &mut ControlConnection,
    flags: &TransferFlags,
    upload: bool,
) -> Result<Reply> {
    let complete = if upload {
        flags.shut_down()
    } else {
        flags.eof()
    };
    if !complete || flags.error().is_some() {
        if let Some(err) = flags.error() {
            conn.events().log(
                conn.session(),
                LogKind::Error,
                format!("Transfer failed: {err}"),
            );
        }
        abort(conn).await?;
        return Err(match flags.error() {
            Some(err) if err.contains("no data transferred") => Error::Timeout,
            Some(err) if !err.contains("cancelled") => Error::Connection(err),
            _ => Error::Cancelled,
        });
    }
    let reply = loop {
        let reply = conn.read_reply().await?;
        if !reply.is_preliminary() {
            break reply;
        }
    };
    if reply.is_ok() {
        Ok(reply)
    } else {
        Err(reply.to_error())
    }
}

/// Send `ABOR` and read what the server sends back (`426` + `226`, or one
/// reply), leaving the control connection usable.
///
/// # Errors
///
/// Connection-level errors.
pub async fn abort(conn: &mut ControlConnection) -> Result<()> {
    if conn.outstanding() == 0 {
        return Ok(());
    }
    conn.events()
        .log(conn.session(), LogKind::Status, "Aborting the transfer");
    conn.write_command("ABOR").await?;
    let mut first = true;
    while conn.outstanding() > 0 {
        let wait = if first {
            conn.timeout()
        } else {
            ABORT_SECOND_REPLY
        };
        match conn.read_reply_within(wait).await? {
            Some(reply) if reply.is_preliminary() => {}
            Some(_) => first = false,
            None => {
                conn.discard_outstanding();
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
