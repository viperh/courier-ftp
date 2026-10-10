//! [`ServerAddress`] and [`ServerUrl`], with URL parsing.

use std::{fmt, str::FromStr};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use super::{Protocol, RemotePath};
use crate::{Error, Result};

/// Where to connect: protocol, host, port and (optionally) user.
///
/// Displays as a URL with an explicit port, `sftp://user@host:22`, and parses
/// back from that form ([`FromStr`]). Parsing also accepts the forms the
/// quickconnect bar and the command line take (see [`ServerUrl`]), but rejects
/// URLs with a path or password: use [`ServerUrl`] for those.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerAddress {
    /// The protocol.
    pub protocol: Protocol,
    /// Host name or IP address. IPv6 literals are stored without brackets.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// User name, when part of the address.
    pub user: Option<String>,
}

impl ServerAddress {
    /// An address on the protocol's default port, without a user.
    pub fn new(protocol: Protocol, host: impl Into<String>) -> Self {
        Self {
            protocol,
            host: host.into(),
            port: protocol.default_port(),
            user: None,
        }
    }

    /// The protocol's well-known port (see [`Protocol::default_port`]).
    pub fn default_port(&self) -> u16 {
        self.protocol.default_port()
    }

    /// `host:port`, with brackets around IPv6 literals, for socket addresses and
    /// log lines.
    pub fn host_port(&self) -> String {
        format!("{}:{}", bracket_host(&self.host), self.port)
    }
}

impl fmt::Display for ServerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://", self.protocol.scheme())?;
        if let Some(user) = &self.user {
            write!(f, "{}@", encode(user, USERINFO_SAFE))?;
        }
        write!(f, "{}", self.host_port())
    }
}

impl FromStr for ServerAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let url = ServerUrl::from_str(s)?;
        if url.path.is_some() {
            return Err(Error::InvalidInput(format!(
                "`{s}` contains a path; a server address can't"
            )));
        }
        if url.password.is_some() {
            return Err(Error::InvalidInput(
                "a server address can't contain a password".into(),
            ));
        }
        Ok(url.address)
    }
}

/// A server URL as typed into quickconnect or passed on the command line:
/// an address plus an optional password and starting path.
///
/// Accepted forms:
///
/// - `ftp://`, `ftpes://` (explicit FTPS), `ftps://` (implicit FTPS) and `sftp://`
///   URLs: `scheme://[user[:password]@]host[:port][/path]`;
/// - a bare `host` or `host:port`. The protocol follows the port the way
///   FileZilla's quickconnect does: 22 means SFTP, 990 implicit FTPS, anything
///   else FTP.
///
/// IPv6 literals go in brackets (`sftp://[::1]:2222`); a bare literal without a
/// port (`::1`) is also accepted. User, password and path are percent-decoded;
/// the user is split from the host at the *last* `@`, so `me@corp@host` works.
///
/// [`Display`](fmt::Display) never shows the password.
#[derive(Debug, Clone)]
pub struct ServerUrl {
    /// Protocol, host, port and user.
    pub address: ServerAddress,
    /// The password, if the URL contained one.
    pub password: Option<SecretString>,
    /// The directory to open after connecting, if given.
    pub path: Option<RemotePath>,
}

impl PartialEq for ServerUrl {
    /// Compares address and path; passwords are not compared.
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.path == other.path
    }
}

impl fmt::Display for ServerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)?;
        if let Some(path) = &self.path {
            write!(f, "{}", encode(path.as_str(), PATH_SAFE))?;
        }
        Ok(())
    }
}

impl FromStr for ServerUrl {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        let s = input.trim();
        if s.is_empty() {
            return Err(Error::InvalidInput("empty server address".into()));
        }
        let (scheme, rest) = match s.find("://") {
            Some(i) => (Some(Protocol::from_scheme(&s[..i])?), &s[i + 3..]),
            None => (None, s),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], Some(&rest[i..])),
            None => (rest, None),
        };
        let (userinfo, hostport) = match authority.rfind('@') {
            Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
            None => (None, authority),
        };
        let (user, password) = match userinfo {
            None => (None, None),
            Some(info) => match info.split_once(':') {
                Some((u, p)) => (Some(decode(u)?), Some(decode(p)?)),
                None => (Some(decode(info)?), None),
            },
        };
        let (host, port) = split_host_port(hostport)?;
        if host.is_empty() {
            return Err(Error::InvalidInput(format!("`{input}` has no host")));
        }
        if host.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(Error::InvalidInput(format!("`{host}` is not a valid host")));
        }
        let protocol = match (scheme, port) {
            (Some(p), _) => p,
            (None, Some(22)) => Protocol::Sftp,
            (None, Some(990)) => Protocol::FtpsImplicit,
            (None, _) => Protocol::Ftp,
        };
        let path = path.map(decode).transpose()?.map(RemotePath::new);
        Ok(Self {
            address: ServerAddress {
                protocol,
                host,
                port: port.unwrap_or(protocol.default_port()),
                user: user.filter(|u| !u.is_empty()),
            },
            password: password.map(SecretString::from),
            path,
        })
    }
}

fn split_host_port(s: &str) -> Result<(String, Option<u16>)> {
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| Error::InvalidInput(format!("`{s}`: missing `]`")))?;
        let host = &rest[..end];
        let port = match &rest[end + 1..] {
            "" => None,
            p => Some(parse_port(p.strip_prefix(':').ok_or_else(|| {
                Error::InvalidInput(format!("`{s}`: expected `:port` after `]`"))
            })?)?),
        };
        return Ok((host.to_owned(), port));
    }
    if s.matches(':').count() > 1 {
        // A bare IPv6 literal; there is no way to tell a port apart.
        return Ok((s.to_owned(), None));
    }
    match s.split_once(':') {
        Some((host, port)) => Ok((host.to_owned(), Some(parse_port(port)?))),
        None => Ok((s.to_owned(), None)),
    }
}

fn parse_port(s: &str) -> Result<u16> {
    match s.parse::<u16>() {
        Ok(0) | Err(_) => Err(Error::InvalidInput(format!("`{s}` is not a valid port"))),
        Ok(port) => Ok(port),
    }
}

fn bracket_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// Bytes (besides alphanumerics) that stay unencoded in the user part.
const USERINFO_SAFE: &[u8] = b"-._~!$&'()*+,;=";
/// Bytes (besides alphanumerics) that stay unencoded in a path.
const PATH_SAFE: &[u8] = b"-._~!$&'()*+,;=:@/";

fn encode(s: &str, safe: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || safe.contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| Error::InvalidInput(format!("bad percent-escape in `{s}`")))?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out)
        .map_err(|_| Error::InvalidInput(format!("`{s}` does not decode to UTF-8")))
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use secrecy::ExposeSecret;

    use super::*;

    fn addr(protocol: Protocol, host: &str, port: u16, user: Option<&str>) -> ServerAddress {
        ServerAddress {
            protocol,
            host: host.into(),
            port,
            user: user.map(Into::into),
        }
    }

    #[test]
    fn round_trips_for_all_protocols() {
        for p in Protocol::ALL {
            for a in [
                ServerAddress::new(p, "example.com"),
                addr(p, "example.com", 2121, Some("bob")),
                addr(p, "::1", 2222, Some("me@corp")),
                addr(p, "10.0.0.1", 21, Some("a:b c/%")),
                addr(p, "ünï.example", 22, Some("jöhn")),
            ] {
                let shown = a.to_string();
                assert_eq!(shown.parse::<ServerAddress>().unwrap(), a, "{shown}");
            }
        }
    }

    #[test]
    fn display_form() {
        assert_eq!(
            addr(Protocol::Sftp, "host", 22, Some("user")).to_string(),
            "sftp://user@host:22"
        );
        assert_eq!(
            addr(Protocol::FtpsImplicit, "::1", 990, None).to_string(),
            "ftps://[::1]:990"
        );
        assert_eq!(
            addr(Protocol::Ftp, "h", 21, Some("me@corp")).to_string(),
            "ftp://me%40corp@h:21"
        );
    }

    #[test]
    fn schemes_and_default_ports() {
        let cases = [
            ("ftp://h", Protocol::Ftp, 21),
            ("ftpes://h", Protocol::FtpsExplicit, 21),
            ("ftps://h", Protocol::FtpsImplicit, 990),
            ("sftp://h", Protocol::Sftp, 22),
            ("SFTP://h", Protocol::Sftp, 22),
        ];
        for (input, protocol, port) in cases {
            assert_eq!(
                input.parse::<ServerAddress>().unwrap(),
                addr(protocol, "h", port, None)
            );
        }
    }

    #[test]
    fn bare_hosts() {
        assert_eq!(
            "h".parse::<ServerAddress>().unwrap(),
            addr(Protocol::Ftp, "h", 21, None)
        );
        assert_eq!(
            "h:2121".parse::<ServerAddress>().unwrap(),
            addr(Protocol::Ftp, "h", 2121, None)
        );
        assert_eq!(
            "h:22".parse::<ServerAddress>().unwrap(),
            addr(Protocol::Sftp, "h", 22, None)
        );
        assert_eq!(
            "h:990".parse::<ServerAddress>().unwrap(),
            addr(Protocol::FtpsImplicit, "h", 990, None)
        );
        assert_eq!(
            "::1".parse::<ServerAddress>().unwrap(),
            addr(Protocol::Ftp, "::1", 21, None)
        );
        assert_eq!(
            "[fe80::1]:2222".parse::<ServerAddress>().unwrap(),
            addr(Protocol::Ftp, "fe80::1", 2222, None)
        );
    }

    #[test]
    fn ipv6_literal_with_port() {
        assert_eq!(
            "sftp://[::1]:2222".parse::<ServerAddress>().unwrap(),
            addr(Protocol::Sftp, "::1", 2222, None)
        );
    }

    #[test]
    fn user_split_at_last_at_and_percent_decoded() {
        assert_eq!(
            "ftp://me@corp@h"
                .parse::<ServerAddress>()
                .unwrap()
                .user
                .as_deref(),
            Some("me@corp")
        );
        assert_eq!(
            "ftp://me%40corp@h"
                .parse::<ServerAddress>()
                .unwrap()
                .user
                .as_deref(),
            Some("me@corp")
        );
        assert_eq!("ftp://@h".parse::<ServerAddress>().unwrap().user, None);
    }

    #[test]
    fn url_with_password_and_path() {
        let url: ServerUrl = "sftp://bob:s%3Acret@h:2200/var/www/my%20site"
            .parse()
            .unwrap();
        assert_eq!(url.address, addr(Protocol::Sftp, "h", 2200, Some("bob")));
        assert_eq!(
            url.password.as_ref().map(|p| p.expose_secret().to_owned()),
            Some("s:cret".to_owned())
        );
        assert_eq!(url.path, Some(RemotePath::new("/var/www/my site")));
        assert_eq!(url.to_string(), "sftp://bob@h:2200/var/www/my%20site");
        assert_eq!(url.to_string().parse::<ServerUrl>().unwrap(), url);
        assert!(!format!("{url:?}").contains("s:cret"));
    }

    #[test]
    fn address_rejects_path_and_password() {
        assert!("sftp://h/dir".parse::<ServerAddress>().is_err());
        assert!("sftp://u:p@h".parse::<ServerAddress>().is_err());
    }

    #[test]
    fn invalid_input() {
        for bad in [
            "",
            "   ",
            "http://h",
            "ftp://",
            "ftp://h:0",
            "ftp://h:99999",
            "ftp://h:port",
            "ftp://[::1",
            "ftp://[::1]x",
            "ftp://us%zzer@h",
            "ftp://us%ffer@h",
            "ftp://ho st",
        ] {
            assert!(bad.parse::<ServerUrl>().is_err(), "{bad:?}");
        }
    }
}
