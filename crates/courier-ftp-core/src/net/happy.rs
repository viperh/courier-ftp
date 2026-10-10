//! Address ordering and Happy Eyeballs (RFC 8305), copied from sverb
//! (`sverb-conn/src/ssh/tcp.rs`) with a configurable first family.
//!
//! [`happy_eyeballs`] is generic over the dialer so its timing is unit-tested with a
//! mock under paused time.

use std::{future::Future, io, net::SocketAddr, pin::Pin, time::Duration};

use futures::{StreamExt, stream::FuturesUnordered};

/// Delay before starting the next attempt while earlier ones are still pending.
pub const STAGGER: Duration = Duration::from_millis(250);

/// Order addresses for Happy Eyeballs: alternate the families, starting with IPv6 when
/// `ipv6_first`, else IPv4; each family keeps the resolver's order (RFC 8305 §4).
pub fn interleave(addrs: &[SocketAddr], ipv6_first: bool) -> Vec<SocketAddr> {
    let (v6, v4): (Vec<SocketAddr>, Vec<SocketAddr>) = addrs.iter().partition(|a| a.is_ipv6());
    let (first, second) = if ipv6_first { (v6, v4) } else { (v4, v6) };
    let mut out = Vec::with_capacity(addrs.len());
    let (mut a, mut b) = (first.into_iter(), second.into_iter());
    loop {
        match (a.next(), b.next()) {
            (None, None) => break,
            (x, y) => out.extend(x.into_iter().chain(y)),
        }
    }
    out
}

/// Why no attempt connected.
#[derive(Debug)]
pub struct DialFailure {
    /// Each attempted address with its error, in the order the attempts failed.
    pub errors: Vec<(SocketAddr, io::Error)>,
}

impl DialFailure {
    /// The first error.
    pub fn first(&self) -> Option<&(SocketAddr, io::Error)> {
        self.errors.first()
    }
}

type Attempt<S> = Pin<Box<dyn Future<Output = (SocketAddr, io::Result<S>)> + Send>>;

/// Race connection attempts to `addrs` (already ordered) with a `stagger` between
/// starts: the next attempt starts after `stagger` if nothing has connected yet, or at
/// once when an attempt fails. `dial` starts one attempt. Returns the first stream that
/// connects and its address; the other attempts are dropped. Dropping the returned
/// future cancels every attempt (nothing is spawned).
///
/// # Errors
///
/// Every attempt failed (or `addrs` was empty).
pub async fn happy_eyeballs<S, F, Fut>(
    addrs: &[SocketAddr],
    stagger: Duration,
    dial: F,
) -> Result<(S, SocketAddr), DialFailure>
where
    S: Send + 'static,
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<S>> + Send + 'static,
{
    let mut pending = addrs.iter().copied();
    let mut running: FuturesUnordered<Attempt<S>> = FuturesUnordered::new();
    let mut errors = Vec::new();
    let start = |addr: SocketAddr, running: &mut FuturesUnordered<Attempt<S>>| {
        let fut = dial(addr);
        running.push(Box::pin(async move { (addr, fut.await) }));
    };
    match pending.next() {
        Some(addr) => start(addr, &mut running),
        None => return Err(DialFailure { errors }),
    }
    let timer = tokio::time::sleep(stagger);
    tokio::pin!(timer);
    let mut more = addrs.len() > 1;
    loop {
        tokio::select! {
            Some((addr, result)) = running.next() => match result {
                Ok(stream) => return Ok((stream, addr)),
                Err(err) => {
                    errors.push((addr, err));
                    // A failure starts the next attempt at once.
                    match pending.next() {
                        Some(next) => {
                            start(next, &mut running);
                            timer.as_mut().reset(tokio::time::Instant::now() + stagger);
                        }
                        None => {
                            more = false;
                            if running.is_empty() {
                                return Err(DialFailure { errors });
                            }
                        }
                    }
                }
            },
            () = &mut timer, if more => {
                match pending.next() {
                    Some(next) => {
                        start(next, &mut running);
                        timer.as_mut().reset(tokio::time::Instant::now() + stagger);
                    }
                    None => more = false,
                }
            }
        }
    }
}
