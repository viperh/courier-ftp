//! Data connection addresses: `PASV`/`EPSV` reply parsing, `PORT`/`EPRT`
//! formatting (RFC 959, RFC 2428) and the "is this address routable" test
//! behind `passive_ignore_unroutable_ip`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

/// The address in a `227` reply: the first `h1,h2,h3,h4,p1,p2` group anywhere
/// in the text (servers differ in brackets and spacing:
/// `227 Entering Passive Mode (192,168,1,2,19,137)`,
/// `227 =192,168,1,2,19,137`, `227 Ok 192, 168, 1, 2, 19, 137`).
///
/// `None` when no group of six numbers 0–255 is found.
pub fn parse_pasv(text: &str) -> Option<SocketAddrV4> {
    // Split the text into runs of digits; look for six numbers separated
    // only by commas and spaces.
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // A group starts at a number not preceded by a digit or by a comma
        // (which would make it the middle of a longer list).
        let before = bytes.get(..i).unwrap_or_default();
        let prev = before.iter().rev().find(|b| **b != b' ');
        if bytes.get(i).is_some_and(u8::is_ascii_digit)
            && !before.last().is_some_and(u8::is_ascii_digit)
            && prev != Some(&b',')
            && let Some(addr) = six_numbers(text.get(i..)?)
        {
            return Some(addr);
        }
        i += 1;
    }
    None
}

/// Six comma-separated numbers 0–255 at the start of `s`.
fn six_numbers(s: &str) -> Option<SocketAddrV4> {
    let mut nums = [0u8; 6];
    let mut rest = s;
    for (n, slot) in nums.iter_mut().enumerate() {
        if n > 0 {
            rest = rest.trim_start_matches(' ');
            rest = rest.strip_prefix(',')?;
            rest = rest.trim_start_matches(' ');
        }
        let len = rest.bytes().take_while(u8::is_ascii_digit).count();
        if len == 0 || len > 3 {
            return None;
        }
        *slot = rest.get(..len)?.parse().ok()?;
        rest = rest.get(len..)?;
    }
    // A seventh number would mean this isn't the address.
    if rest.trim_start_matches(' ').starts_with(',') {
        return None;
    }
    let [a, b, c, d, p1, p2] = nums;
    let port = u16::from(p1) << 8 | u16::from(p2);
    Some(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
}

/// The port in a `229` reply: `229 Entering Extended Passive Mode
/// (|||6446|)`. The delimiter is whatever character follows the `(`
/// (RFC 2428 recommends `|`); the network address fields must be empty.
///
/// `None` without a well-formed group, for port 0 or a port above 65535.
pub fn parse_epsv(text: &str) -> Option<u16> {
    let start = text.find('(')?;
    let inner = text.get(start + 1..)?;
    let end = inner.find(')')?;
    let inner = inner.get(..end)?;
    let mut chars = inner.chars();
    let delim = chars.next()?;
    if delim.is_ascii_alphanumeric() {
        return None;
    }
    let parts: Vec<&str> = inner.split(delim).collect();
    // `|||6446|` splits into ["", "", "", "6446", ""].
    let ["", "", "", port, ""] = parts.as_slice() else {
        return None;
    };
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) || port.len() > 5 {
        return None;
    }
    let port: u32 = port.parse().ok()?;
    u16::try_from(port).ok().filter(|p| *p != 0)
}

/// `PORT h1,h2,h3,h4,p1,p2`.
pub fn port_command(addr: SocketAddrV4) -> String {
    let [a, b, c, d] = addr.ip().octets();
    let port = addr.port();
    format!("PORT {a},{b},{c},{d},{},{}", port >> 8, port & 0xff)
}

/// `EPRT |1|ip|port|` or `EPRT |2|ipv6|port|`.
pub fn eprt_command(addr: SocketAddr) -> String {
    let family = match addr.ip() {
        IpAddr::V4(_) => 1,
        IpAddr::V6(_) => 2,
    };
    format!("EPRT |{family}|{}|{}|", addr.ip(), addr.port())
}

/// Whether `ip` can be reached from the internet: not private, loopback,
/// link-local, unspecified (`0.0.0.0`), CGNAT, documentation or unique local.
pub fn is_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                // 100.64.0.0/10, carrier-grade NAT.
                || (a == 100 && (64..128).contains(&b))
                || a == 0)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_routable(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique local, fe80::/10 link-local.
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn pasv_replies() {
        let addr = |s: &str| SocketAddrV4::new(s.parse().unwrap(), 5001);
        let cases: &[(&str, Option<SocketAddrV4>)] = &[
            (
                "Entering Passive Mode (192,168,1,2,19,137)",
                Some(addr("192.168.1.2")),
            ),
            (
                "Entering Passive Mode 192,168,1,2,19,137",
                Some(addr("192.168.1.2")),
            ),
            ("=192,168,1,2,19,137", Some(addr("192.168.1.2"))),
            ("Ok (10, 0, 0, 1, 19, 137).", Some(addr("10.0.0.1"))),
            (
                "Passive mode on port 21 (10,0,0,1,19,137)",
                Some(addr("10.0.0.1")),
            ),
            ("(0,0,0,0,19,137)", Some(addr("0.0.0.0"))),
            ("Entering Passive Mode (192,168,1,2,19)", None),
            ("Entering Passive Mode (192,168,1,256,19,137)", None),
            ("Entering Passive Mode (192,168,1,2,19,1370)", None),
            ("(1,2,3,4,5,6,7)", None),
            ("no numbers here", None),
            ("", None),
        ];
        for (text, want) in cases {
            assert_eq!(parse_pasv(text), *want, "{text}");
        }
        assert_eq!(parse_pasv("(127,0,0,1,255,255)").unwrap().port(), 65535);
    }

    #[test]
    fn epsv_replies() {
        let cases: &[(&str, Option<u16>)] = &[
            ("Entering Extended Passive Mode (|||6446|)", Some(6446)),
            ("Entering Extended Passive Mode (!!!6446!)", Some(6446)),
            ("ok (|||65535|) done", Some(65535)),
            ("(|||65536|)", None),
            ("(|||99999999|)", None),
            ("(|||0|)", None),
            ("(|||-1|)", None),
            ("(|1|1.2.3.4|6446|)", None),
            ("(||6446|)", None),
            ("(|||6446)", None),
            ("|||6446|", None),
            ("(1116446|)", None),
            ("()", None),
        ];
        for (text, want) in cases {
            assert_eq!(parse_epsv(text), *want, "{text}");
        }
    }

    #[test]
    fn port_and_eprt_commands() {
        assert_eq!(
            port_command("192.168.1.2:5001".parse().unwrap()),
            "PORT 192,168,1,2,19,137"
        );
        assert_eq!(
            eprt_command("192.168.1.2:5001".parse().unwrap()),
            "EPRT |1|192.168.1.2|5001|"
        );
        assert_eq!(
            eprt_command("[2001:db8::1]:5001".parse().unwrap()),
            "EPRT |2|2001:db8::1|5001|"
        );
    }

    #[test]
    fn routable_addresses() {
        for ip in [
            "10.1.2.3",
            "192.168.0.1",
            "172.16.5.4",
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_routable(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "203.0.114.1", "2a00:1450::1", "::ffff:8.8.8.8"] {
            assert!(is_routable(ip.parse().unwrap()), "{ip}");
        }
    }
}
