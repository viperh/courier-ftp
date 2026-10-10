//! [`connect_tcp`]: DNS, address filtering and ordering, Happy Eyeballs, the timeout,
//! cancellation and socket options; proxies are handed to [`super::proxy`].

use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use super::{
    HostPort, NetOpts, NetStream, Purpose,
    happy::{STAGGER, happy_eyeballs, interleave},
    proxy::{self, ProxyConfig},
    stream::set_buffers,
};
use crate::{Error, Result, events::SessionLog};

/// TCP keep-alive: idle time before the first probe.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
/// TCP keep-alive: interval between probes.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// `DebugLevel::Info` as the `Debug(n)` log level.
const DEBUG_INFO: u8 = 2;

/// Dial `target` with `opts`, logging Status/debug lines to `log`.
///
/// Returns [`Error::Cancelled`] as soon as `cancel` fires; dropping the future cancels
/// too (nothing is spawned).
///
/// # Errors
///
/// [`Error::Connection`] (DNS failure, every address refused or unreachable, proxy
/// unreachable), [`Error::Timeout`], [`Error::Proxy`] (handshake refused or invalid),
/// [`Error::Unsupported`] (SOCKS4 to an IPv6 target), [`Error::InvalidInput`]
/// (invalid proxy settings), [`Error::Cancelled`].
pub async fn connect_tcp(
    target: &HostPort,
    opts: &NetOpts,
    cancel: CancellationToken,
    log: &SessionLog,
) -> Result<NetStream> {
    let result = cancellable(&cancel, connect_inner(target, opts, log)).await;
    match &result {
        Ok(stream) => {
            tracing::info!(
                session = log.session.get(),
                proxy = opts.proxy.kind(),
                "connection established"
            );
            tracing::debug!(
                target = %target,
                peer = %stream.peer_addr(),
                "connection established"
            );
        }
        Err(err) => {
            tracing::info!(
                session = log.session.get(),
                proxy = opts.proxy.kind(),
                code = err.code(),
                "connection failed"
            );
        }
    }
    result
}

/// Runs `fut` until it ends or `cancel` fires ([`Error::Cancelled`]); the future is
/// dropped on cancellation.
pub(crate) async fn cancellable<T>(
    cancel: &CancellationToken,
    fut: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(Error::Cancelled),
        r = fut => r,
    }
}

async fn connect_inner(target: &HostPort, opts: &NetOpts, log: &SessionLog) -> Result<NetStream> {
    if matches!(opts.proxy, ProxyConfig::Direct) {
        let (tcp, addr) = dial_direct(target, opts, log).await?;
        log.status("Connection established");
        return NetStream::new(tcp, Vec::new(), Some(addr.ip())).map_err(Error::from);
    }
    proxy::connect_via_proxy(target, opts, log).await
}

/// DNS, filtering, ordering and the race to `target` (no proxy), then the socket
/// options. Does not log "Connection established" (the caller does).
pub(crate) async fn dial_direct(
    target: &HostPort,
    opts: &NetOpts,
    log: &SessionLog,
) -> Result<(TcpStream, SocketAddr)> {
    let addrs = resolve(target, opts.timeout, log).await?;
    let ordered = order_addrs(&addrs, opts.prefer_ipv6, opts.allow_ipv6, &target.host)?;
    let (tcp, addr) = race(target, &ordered, opts.timeout, log, |addr| async move {
        TcpStream::connect(addr).await
    })
    .await?;
    apply_socket_options(&tcp, opts.purpose, opts.socket_buffer);
    Ok((tcp, addr))
}

/// Resolve `target` (IP literals skip DNS) under `timeout`; never cached.
pub(crate) async fn resolve(
    target: &HostPort,
    timeout: Duration,
    log: &SessionLog,
) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, target.port)]);
    }
    log.status(format!("Resolving address of {}", target.host));
    let lookup = tokio::net::lookup_host((target.host.as_str(), target.port));
    let addrs: Vec<SocketAddr> = match tokio::time::timeout(timeout, lookup).await {
        Err(_) => return Err(timed_out(timeout, log)),
        Ok(Err(err)) => {
            tracing::debug!(host = %target.host, %err, "DNS lookup failed");
            log.debug(
                DEBUG_INFO,
                format!("Lookup of {} failed: {err}", target.host),
            );
            Vec::new()
        }
        Ok(Ok(it)) => it.collect(),
    };
    if addrs.is_empty() {
        return Err(Error::Connection(format!(
            "could not resolve {}",
            target.host
        )));
    }
    Ok(addrs)
}

/// Drop IPv6 addresses unless `allow_ipv6`, then interleave the families (IPv6 first
/// when `prefer_ipv6`).
pub(crate) fn order_addrs(
    addrs: &[SocketAddr],
    prefer_ipv6: bool,
    allow_ipv6: bool,
    host: &str,
) -> Result<Vec<SocketAddr>> {
    let kept: Vec<SocketAddr> = addrs
        .iter()
        .copied()
        .filter(|a| allow_ipv6 || a.is_ipv4())
        .collect();
    if kept.is_empty() {
        return Err(Error::Connection(format!(
            "no IPv4 address for {host} and IPv6 is disabled"
        )));
    }
    Ok(interleave(&kept, prefer_ipv6))
}

/// The Happy Eyeballs race over `addrs` (already ordered), bounded by `timeout`, with
/// a Status line per attempt and a debug line per failure. `dial` opens one attempt.
pub(crate) async fn race<S, F, Fut>(
    target: &HostPort,
    addrs: &[SocketAddr],
    timeout: Duration,
    log: &SessionLog,
    dial: F,
) -> Result<(S, SocketAddr)>
where
    S: Send + 'static,
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<S>> + Send + 'static,
{
    let attempt = |addr: SocketAddr| {
        log.status(format!("Connecting to {addr}..."));
        let fut = dial(addr);
        let log = log.clone();
        async move {
            let result = fut.await;
            if let Err(err) = &result {
                log.debug(
                    DEBUG_INFO,
                    format!("Connection attempt to {addr} failed: {err}"),
                );
            }
            result
        }
    };
    match tokio::time::timeout(timeout, happy_eyeballs(addrs, STAGGER, attempt)).await {
        Err(_) => Err(timed_out(timeout, log)),
        Ok(Ok(won)) => Ok(won),
        Ok(Err(failure)) => {
            let first = failure
                .first()
                .map_or_else(|| "no address".to_owned(), |(_, err)| err.to_string());
            Err(Error::Connection(format!(
                "could not connect to {}: {first}",
                target.authority()
            )))
        }
    }
}

/// Logs the Status line of a timeout and returns [`Error::Timeout`].
pub(crate) fn timed_out(timeout: Duration, log: &SessionLog) -> Error {
    log.status(format!(
        "Connection timed out after {} seconds",
        timeout.as_secs()
    ));
    Error::Timeout
}

/// `TCP_NODELAY` for control connections, keep-alive, buffer sizes. Failures are only
/// traced: none of them prevents the connection from working.
fn apply_socket_options(tcp: &TcpStream, purpose: Purpose, buffer: Option<usize>) {
    if purpose == Purpose::Control
        && let Err(err) = tcp.set_nodelay(true)
    {
        tracing::debug!(%err, "set TCP_NODELAY failed");
    }
    let keepalive = TcpKeepalive::new().with_time(KEEPALIVE_IDLE);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "netbsd",
    ))]
    let keepalive = keepalive.with_interval(KEEPALIVE_INTERVAL);
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "netbsd",
    )))]
    let _ = KEEPALIVE_INTERVAL;
    if let Err(err) = SockRef::from(tcp).set_tcp_keepalive(&keepalive) {
        tracing::debug!(%err, "set SO_KEEPALIVE failed");
    }
    if let Some(bytes) = buffer {
        set_buffers(tcp, bytes);
    }
}
