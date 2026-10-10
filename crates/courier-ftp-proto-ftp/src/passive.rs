//! Passive mode (T11): the `227` (`PASV`, RFC 959) and `229` (`EPSV`, RFC 2428 §3)
//! reply parsers, the unroutable-address table and the PASV address rules that keep a
//! hostile server from making the client connect to third-party or internal hosts.
//!
//! The parsers are pure and fuzzed (`fuzz/fuzz_targets/ftp_pasv.rs` →
//! [`fuzz_pasv_epsv`]).

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
};

use crate::active::{format_eprt, format_port, parse_eprt};

/// A malformed `227`/`229` reply or `EPRT` argument (the reason is a static text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrParseError(pub &'static str);

impl fmt::Display for AddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for AddrParseError {}

/// Status line when an unroutable PASV address is replaced by the server address.
pub(crate) const UNROUTABLE_REPLACED: &str =
    "Server sent passive reply with unroutable address. Using server address instead.";
/// Status line when a different routable PASV address is replaced.
pub(crate) const DIFFERENT_REPLACED: &str =
    "Server sent a passive reply with a different address. Using server address instead.";

/// Parses a `227` reply text: the first run of six comma-separated decimal numbers
/// (spaces allowed around the commas), each 0–255; port = `p1 * 256 + p2`, never 0.
/// Accepts `(h1,h2,h3,h4,p1,p2)`, `=h1,…` and bare variants.
///
/// # Errors
///
/// Fewer than six numbers, a value over 255, or port 0.
pub fn parse_pasv(text: &str) -> Result<SocketAddrV4, AddrParseError> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let starts_run = bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_digit());
        if starts_run && let Some(nums) = numbers_at(bytes, i) {
            if nums.iter().any(|&n| n > 255) {
                return Err(AddrParseError("value over 255 in passive mode reply"));
            }
            let [a, b, c, d, p1, p2] = nums.map(|n| n as u8);
            let port = u16::from(p1) * 256 + u16::from(p2);
            if port == 0 {
                return Err(AddrParseError("port 0 in passive mode reply"));
            }
            return Ok(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port));
        }
        i += 1;
    }
    Err(AddrParseError("no address in passive mode reply"))
}

/// Six comma-separated numbers starting at `start` (a digit), or `None`. Numbers with
/// more than three digits are returned as 1000 (over 255).
fn numbers_at(bytes: &[u8], start: usize) -> Option<[u32; 6]> {
    let mut out = [0u32; 6];
    let mut i = start;
    for (k, slot) in out.iter_mut().enumerate() {
        if k > 0 {
            while bytes.get(i) == Some(&b' ') {
                i += 1;
            }
            if bytes.get(i) != Some(&b',') {
                return None;
            }
            i += 1;
            while bytes.get(i) == Some(&b' ') {
                i += 1;
            }
        }
        let digits_start = i;
        let mut value: u32 = 0;
        while let Some(&b) = bytes.get(i).filter(|b| b.is_ascii_digit()) {
            if i - digits_start < 3 {
                value = value * 10 + u32::from(b - b'0');
            } else {
                value = 1000;
            }
            i += 1;
        }
        if i == digits_start {
            return None;
        }
        *slot = value;
    }
    Some(out)
}

/// Parses a `229` reply text: `(<d><d><d><port><d>)` after the first `(`, where `d` is
/// the same printable non-digit ASCII character four times (`|` by convention) and
/// `port` is 1–65535 in at most five decimal digits.
///
/// # Errors
///
/// No `(`, mismatched or invalid delimiters, a missing `)`, or an invalid port.
pub fn parse_epsv(text: &str) -> Result<u16, AddrParseError> {
    let open = text
        .find('(')
        .ok_or(AddrParseError("no '(' in extended passive mode reply"))?;
    let rest = &text.as_bytes()[open + 1..];
    let d = *rest
        .first()
        .ok_or(AddrParseError("truncated extended passive mode reply"))?;
    if !(33..=126).contains(&d) || d.is_ascii_digit() {
        return Err(AddrParseError(
            "invalid delimiter in extended passive mode reply",
        ));
    }
    if rest.get(1) != Some(&d) || rest.get(2) != Some(&d) {
        return Err(AddrParseError(
            "mismatched delimiters in extended passive mode reply",
        ));
    }
    let digits: Vec<u8> = rest
        .iter()
        .skip(3)
        .take_while(|b| b.is_ascii_digit())
        .copied()
        .collect();
    if digits.is_empty() || digits.len() > 5 {
        return Err(AddrParseError(
            "invalid port in extended passive mode reply",
        ));
    }
    let after = 3 + digits.len();
    if rest.get(after) != Some(&d) {
        return Err(AddrParseError(
            "mismatched delimiters in extended passive mode reply",
        ));
    }
    if rest.get(after + 1) != Some(&b')') {
        return Err(AddrParseError("no ')' in extended passive mode reply"));
    }
    let port: u32 = digits
        .iter()
        .fold(0, |acc, b| acc * 10 + u32::from(b - b'0'));
    match u16::try_from(port) {
        Ok(p) if p != 0 => Ok(p),
        _ => Err(AddrParseError(
            "invalid port in extended passive mode reply",
        )),
    }
}

/// Private, loopback, link-local, shared (CGNAT), benchmark, reserved and unspecified
/// addresses: `0/8`, `10/8`, `100.64/10`, `127/8`, `169.254/16`, `172.16/12`,
/// `192.168/16`, `198.18/15`, `240/4`; IPv6 `::`, `::1`, `fc00::/7`, `fe80::/10` (an
/// IPv4-mapped IPv6 address is judged as IPv4).
pub fn is_unroutable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => unroutable_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => unroutable_v4(v4),
            None => unroutable_v6(v6),
        },
    }
}

fn unroutable_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 0
        || a == 10
        || (a == 100 && (64..=127).contains(&b))
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240
}

fn unroutable_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_unspecified()
        || ip.is_loopback()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
}

/// The same address, comparing an IPv4-mapped IPv6 address with its IPv4 form.
pub(crate) fn same_ip(a: IpAddr, b: IpAddr) -> bool {
    a.to_canonical() == b.to_canonical()
}

/// Which IP to connect to for a `227` reply naming `pasv`, when the control connection's
/// peer is `peer` (no generic proxy). Returns the IP and the Status line to log when the
/// address was replaced.
///
/// - equal to the peer → the PASV IP;
/// - unroutable and `ignore_unroutable` off → the PASV IP (FileZilla behaviour);
/// - anything else → the peer IP (unroutable, or a different address: anti-bounce).
pub(crate) fn choose_pasv_ip(
    pasv: Ipv4Addr,
    peer: IpAddr,
    ignore_unroutable: bool,
) -> (IpAddr, Option<&'static str>) {
    let pasv_ip = IpAddr::V4(pasv);
    if same_ip(pasv_ip, peer) {
        return (pasv_ip, None);
    }
    if is_unroutable(pasv_ip) {
        if ignore_unroutable {
            (peer, Some(UNROUTABLE_REPLACED))
        } else {
            (pasv_ip, None)
        }
    } else {
        (peer, Some(DIFFERENT_REPLACED))
    }
}

/// Fuzz/property entry point (T91 §7 "PASV/EPSV parser"): runs `data` (lossy UTF-8)
/// through [`parse_pasv`], [`parse_epsv`] and [`parse_eprt`]; whatever parses must
/// survive a format → parse round trip. Must never panic.
#[doc(hidden)]
pub fn fuzz_pasv_epsv(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    if let Ok(addr) = parse_pasv(&text) {
        assert_eq!(parse_pasv(&format_port(addr)), Ok(addr), "PASV round trip");
    }
    if let Ok(port) = parse_epsv(&text) {
        let again = format!("229 Entering Extended Passive Mode (|||{port}|)");
        assert_eq!(parse_epsv(&again), Ok(port), "EPSV round trip");
    }
    if let Ok(addr) = parse_eprt(&text) {
        assert_eq!(
            parse_eprt(&format_eprt(addr)),
            Ok(SocketAddr::new(addr.ip(), addr.port())),
            "EPRT round trip"
        );
    }
}

#[cfg(test)]
mod tests;
