//! Active mode (T11): `PORT` (RFC 959) / `EPRT` (RFC 2428 §2) arguments, the data
//! listener (port range, backlog 1) and the accept check against the control peer
//! (anti-bounce).

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
};

use courier_ftp_core::{Error, Result, events::SessionLog};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::passive::{AddrParseError, same_ip};

/// Status line for a data connection from an address other than the control peer.
pub(crate) const REJECTED_PEER: &str = "Warning: rejected data connection from unexpected address";

/// The `PORT` argument: `h1,h2,h3,h4,p1,p2`.
pub fn format_port(addr: SocketAddrV4) -> String {
    let [a, b, c, d] = addr.ip().octets();
    let [p1, p2] = addr.port().to_be_bytes();
    format!("{a},{b},{c},{d},{p1},{p2}")
}

/// The `EPRT` argument: `|1|a.b.c.d|port|` or `|2|v6|port|` (RFC 5952 text form).
pub fn format_eprt(addr: SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => format!("|1|{}|{}|", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("|2|{}|{}|", v6.ip(), v6.port()),
    }
}

/// Parses an `EPRT` argument (`<d>proto<d>addr<d>port<d>`, any printable delimiter;
/// protocol 1 = IPv4, 2 = IPv6; port 1–65535). Used by tests and the fake server.
///
/// # Errors
///
/// Wrong field count, unknown protocol, an address of the wrong family, or a bad port.
pub fn parse_eprt(arg: &str) -> Result<SocketAddr, AddrParseError> {
    let arg = arg.trim();
    let d = arg
        .chars()
        .next()
        .ok_or(AddrParseError("empty EPRT argument"))?;
    if !d.is_ascii_graphic() || d.is_ascii_alphanumeric() || d == '.' || d == ':' {
        return Err(AddrParseError("invalid EPRT delimiter"));
    }
    let fields: Vec<&str> = arg.split(d).collect();
    let [first, proto, addr, port, last] = fields.as_slice() else {
        return Err(AddrParseError("wrong number of EPRT fields"));
    };
    if !first.is_empty() || !last.is_empty() {
        return Err(AddrParseError("wrong number of EPRT fields"));
    }
    let ip: IpAddr = match *proto {
        "1" => addr
            .parse::<Ipv4Addr>()
            .map(IpAddr::V4)
            .map_err(|_| AddrParseError("invalid IPv4 address in EPRT"))?,
        "2" => addr
            .parse::<Ipv6Addr>()
            .map(IpAddr::V6)
            .map_err(|_| AddrParseError("invalid IPv6 address in EPRT"))?,
        _ => return Err(AddrParseError("unknown EPRT network protocol")),
    };
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AddrParseError("invalid EPRT port"));
    }
    match port.parse::<u16>() {
        Ok(p) if p != 0 => Ok(SocketAddr::new(ip, p)),
        _ => Err(AddrParseError("invalid EPRT port")),
    }
}

/// Binds the active-mode listener on `ip` (the control connection's local IP).
/// `range = Some((lo, hi))`: every port of the range once, starting at a random one;
/// `None`: an ephemeral port. Backlog 1; the socket buffers are requested before
/// `listen` so accepted sockets inherit them.
///
/// # Errors
///
/// `Connection("no free port in active mode port range lo–hi")`, or the bind error.
pub(crate) fn bind_listener(
    ip: IpAddr,
    range: Option<(u16, u16)>,
    socket_buffer: usize,
) -> Result<TcpListener> {
    let bind_one = |port: u16| -> io::Result<TcpListener> {
        let sock = if ip.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        let size = u32::try_from(socket_buffer).unwrap_or(u32::MAX);
        if let Err(err) = sock.set_recv_buffer_size(size) {
            tracing::debug!(%err, "set SO_RCVBUF on the data listener failed");
        }
        if let Err(err) = sock.set_send_buffer_size(size) {
            tracing::debug!(%err, "set SO_SNDBUF on the data listener failed");
        }
        sock.bind(SocketAddr::new(ip, port))?;
        sock.listen(1)
    };
    match range {
        None => bind_one(0).map_err(|e| {
            Error::Connection(format!("could not listen for the data connection: {e}"))
        }),
        Some((lo, hi)) => {
            let (lo, hi) = (lo.min(hi), lo.max(hi));
            let count = u32::from(hi) - u32::from(lo) + 1;
            let start = fastrand::u32(0..count);
            for i in 0..count {
                let offset = (start + i) % count;
                let Ok(port) = u16::try_from(u32::from(lo) + offset) else {
                    continue;
                };
                if port == 0 {
                    continue;
                }
                match bind_one(port) {
                    Ok(listener) => return Ok(listener),
                    Err(err) => tracing::debug!(%err, port, "active mode port busy"),
                }
            }
            Err(Error::Connection(format!(
                "no free port in active mode port range {lo}–{hi}"
            )))
        }
    }
}

/// Accepts until a connection comes from `expected` (the control peer IP; `None` →
/// any); others are closed with a Status line. Runs until the caller stops polling.
///
/// # Errors
///
/// `Connection` when `accept` itself fails.
pub(crate) async fn accept_checked(
    listener: &TcpListener,
    expected: Option<IpAddr>,
    log: &SessionLog,
) -> Result<TcpStream> {
    loop {
        let (stream, from) = listener
            .accept()
            .await
            .map_err(|e| Error::Connection(format!("accepting the data connection failed: {e}")))?;
        match expected {
            Some(ip) if !same_ip(ip, from.ip()) => {
                log.status(REJECTED_PEER);
                log.debug(3, format!("data connection from {from} rejected"));
                tracing::debug!(%from, "data connection from unexpected address rejected");
                drop(stream);
            }
            _ => {
                log.debug(3, format!("Data connection accepted from {from}"));
                return Ok(stream);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn eprt_formats_ipv4_and_ipv6() {
        let v4: SocketAddr = "192.0.2.7:50069".parse().unwrap();
        assert_eq!(format_eprt(v4), "|1|192.0.2.7|50069|");
        let v6: SocketAddr = "[2001:db8::7]:50069".parse().unwrap();
        assert_eq!(format_eprt(v6), "|2|2001:db8::7|50069|");
        assert_eq!(parse_eprt("|1|192.0.2.7|50069|"), Ok(v4));
        assert_eq!(parse_eprt("!2!2001:db8::7!50069!"), Ok(v6));
        assert!(parse_eprt("|1|2001:db8::7|50069|").is_err());
        assert!(parse_eprt("|3|192.0.2.7|50069|").is_err());
        assert!(parse_eprt("|1|192.0.2.7|0|").is_err());
        assert!(parse_eprt("|1|192.0.2.7|65536|").is_err());
        assert!(parse_eprt("|1|192.0.2.7|50069").is_err());
    }

    #[test]
    fn port_formats_high_port() {
        let addr = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 7), 50069);
        assert_eq!(format_port(addr), "192,0,2,7,195,149");
        let max = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 65535);
        assert_eq!(format_port(max), "10,0,0,1,255,255");
    }
}
