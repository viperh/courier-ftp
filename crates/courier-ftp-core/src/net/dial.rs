//! DNS, address ordering, Happy Eyeballs and socket options.

use std::{net::SocketAddr, time::Duration};

use socket2::{SockRef, TcpKeepalive};
use tokio::{net::TcpStream, task::JoinSet};
use tokio_util::sync::CancellationToken;

use super::{HostPort, NetOpts};
use crate::{
    Error, Result,
    events::{EventSender, LogKind, SessionId},
};

/// Resolve `target` and connect to the first address that answers.
pub(super) async fn dial(
    target: &HostPort,
    opts: &NetOpts,
    cancel: &CancellationToken,
    log: &EventSender,
    session: SessionId,
) -> Result<TcpStream> {
    let addrs = resolve(target, opts, cancel, log, session).await?;
    let stream = connect_any(&addrs, opts, cancel, log, session).await?;
    configure(&stream, opts, log, session);
    Ok(stream)
}

async fn resolve(
    target: &HostPort,
    opts: &NetOpts,
    cancel: &CancellationToken,
    log: &EventSender,
    session: SessionId,
) -> Result<Vec<SocketAddr>> {
    if let Some(ip) = target.ip() {
        return Ok(vec![SocketAddr::new(ip, target.port)]);
    }
    log.log(
        session,
        LogKind::Status,
        format!("Resolving address of {}", target.host),
    );
    let lookup = tokio::net::lookup_host((target.host.as_str(), target.port));
    let result = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(Error::Cancelled),
        r = tokio::time::timeout(opts.timeout, lookup) => r,
    };
    let addrs: Vec<SocketAddr> = match result {
        Err(_) => {
            log.log(
                session,
                LogKind::Error,
                format!("Resolving {} timed out", target.host),
            );
            return Err(Error::Timeout);
        }
        Ok(Err(err)) => {
            let msg = format!("could not resolve {}: {err}", target.host);
            log.log(session, LogKind::Error, msg.clone());
            return Err(Error::Connection(msg));
        }
        Ok(Ok(addrs)) => addrs.collect(),
    };
    if addrs.is_empty() {
        let msg = format!("{} has no addresses", target.host);
        log.log(session, LogKind::Error, msg.clone());
        return Err(Error::Connection(msg));
    }
    Ok(order(addrs, opts.prefer_ipv6))
}

/// Order addresses for connecting (RFC 8305 §4): duplicates removed, the
/// preferred family first, then alternating between the families, keeping the
/// resolver's order within each family.
pub(super) fn order(addrs: Vec<SocketAddr>, prefer_ipv6: bool) -> Vec<SocketAddr> {
    let mut seen = Vec::with_capacity(addrs.len());
    for a in addrs {
        if !seen.contains(&a) {
            seen.push(a);
        }
    }
    let (preferred, other): (Vec<_>, Vec<_>) =
        seen.into_iter().partition(|a| a.is_ipv6() == prefer_ipv6);
    let mut out = Vec::with_capacity(preferred.len() + other.len());
    let mut p = preferred.into_iter();
    let mut o = other.into_iter();
    loop {
        match (p.next(), o.next()) {
            (None, None) => break,
            (a, b) => out.extend(a.into_iter().chain(b)),
        }
    }
    out
}

/// One attempt, bounded by `timeout`.
async fn attempt(addr: SocketAddr, timeout: Duration) -> (SocketAddr, Result<TcpStream>) {
    let result = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Err(_) => Err(Error::Timeout),
        Ok(Err(err)) => Err(Error::Io(err)),
        Ok(Ok(stream)) => Ok(stream),
    };
    (addr, result)
}

/// Happy Eyeballs over `addrs` (already ordered, not empty).
pub(super) async fn connect_any(
    addrs: &[SocketAddr],
    opts: &NetOpts,
    cancel: &CancellationToken,
    log: &EventSender,
    session: SessionId,
) -> Result<TcpStream> {
    // Dropping the set (on success, error or cancel) aborts the attempts still
    // running.
    let mut running = JoinSet::new();
    let mut pending = addrs.iter().copied();
    let mut next = pending.next();
    let mut last_err: Option<Error> = None;
    loop {
        if let Some(addr) = next.take() {
            log.log(session, LogKind::Status, format!("Connecting to {addr}..."));
            running.spawn(attempt(addr, opts.timeout));
            next = pending.next();
        }
        if running.is_empty() {
            break;
        }
        let stagger = async {
            if next.is_some() {
                tokio::time::sleep(opts.attempt_delay).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(Error::Cancelled),
            joined = running.join_next() => match joined {
                Some(Ok((_, Ok(stream)))) => return Ok(stream),
                Some(Ok((addr, Err(err)))) => {
                    log.log(
                        session,
                        LogKind::Error,
                        format!("Connection attempt to {addr} failed: {err}"),
                    );
                    last_err = Some(match err {
                        Error::Io(io) => Error::Connection(format!("{addr}: {io}")),
                        other => other,
                    });
                }
                Some(Err(join)) => {
                    last_err = Some(Error::Connection(format!("connection attempt failed: {join}")));
                }
                None => {}
            },
            () = stagger => {}
        }
    }
    Err(last_err.unwrap_or_else(|| Error::Connection("no address to connect to".into())))
}

/// `TCP_NODELAY` and keep-alive. Failures are only logged: the connection works
/// without them.
fn configure(stream: &TcpStream, opts: &NetOpts, log: &EventSender, session: SessionId) {
    if let Err(err) = stream.set_nodelay(opts.nodelay) {
        log.log(
            session,
            LogKind::Debug(1),
            format!("Could not set TCP_NODELAY: {err}"),
        );
    }
    if let Some(idle) = opts.tcp_keepalive {
        let keepalive = TcpKeepalive::new().with_time(idle);
        if let Err(err) = SockRef::from(stream).set_tcp_keepalive(&keepalive) {
            log.log(
                session,
                LogKind::Debug(1),
                format!("Could not enable TCP keep-alive: {err}"),
            );
        }
    }
}
