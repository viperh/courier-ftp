//! Protocols, server addresses and URL parsing/printing ([`ServerAddress`],
//! [`ParsedUrl`]).
//!
//! URL grammar: `[scheme://][userinfo@]host[:port][/path]`, schemes `sftp`, `ftp`,
//! `ftpes` (explicit TLS required) and `ftps` (implicit TLS). Without a scheme, port 22
//! means SFTP and anything else FTP with explicit TLS if available (FileZilla's
//! quickconnect default). `FtpEncryption::PlainOnly` has no scheme of its own: it prints
//! as `ftp://` and parses back as `ExplicitIfAvailable` (the one value that does not
//! round-trip).

use std::fmt;
use std::str::FromStr;

use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Serialize};

use crate::model::RemotePath;
use crate::secret::SecretString;
use crate::{Error, Result};

/// Maximum length of a URL accepted by [`ParsedUrl::parse`], in bytes.
const MAX_URL_LEN: usize = 2048;

/// Maximum length of a host name, in bytes.
const MAX_HOST_LEN: usize = 253;

/// Escaped in the user and password of a printed URL.
const USERINFO_ESCAPES: &AsciiSet = &CONTROLS
    .add(b'%')
    .add(b'@')
    .add(b':')
    .add(b'/')
    .add(b'?')
    .add(b'#')
    .add(b' ');

/// Escaped in each path component of a printed URL.
const PATH_ESCAPES: &AsciiSet = &CONTROLS.add(b'%').add(b'?').add(b'#').add(b' ');

/// The file transfer protocol of a server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    /// FTP, optionally with TLS (see [`FtpEncryption`]).
    Ftp,
    /// SFTP over SSH.
    Sftp,
}

/// FileZilla's four FTP encryption modes (§1). Ignored for SFTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FtpEncryption {
    /// Plain FTP only (never TLS).
    PlainOnly,
    /// `AUTH TLS` when the server offers it, plain otherwise.
    #[default]
    ExplicitIfAvailable,
    /// `AUTH TLS` required (`ftpes://`).
    RequireExplicit,
    /// TLS from the first byte, port 990 (`ftps://`).
    RequireImplicit,
}

/// Where to connect. No secrets: passwords live in `LogonType`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerAddress {
    /// FTP or SFTP.
    pub protocol: Protocol,
    /// Always `ExplicitIfAvailable` when protocol is Sftp (normalised by `new`).
    pub encryption: FtpEncryption,
    /// Hostname, IPv4 or IPv6 literal, stored WITHOUT brackets.
    pub host: String,
    /// None = protocol default (see `effective_port`). Never Some(0).
    pub port: Option<u16>,
    /// None = not given (anonymous FTP, or asked later).
    pub user: Option<String>,
}

/// Rejects CR, LF and NUL in a user name or password (they would let a URL inject FTP
/// commands). The message never echoes the value.
fn check_credential(what: &str, value: &str) -> Result<()> {
    if value.contains(['\r', '\n', '\0']) {
        return Err(Error::InvalidInput(format!(
            "{what} contains a line break or NUL"
        )));
    }
    Ok(())
}

impl ServerAddress {
    /// Validates host (non-empty, ≤ 253 bytes, no whitespace, control chars, '/', '@', or
    /// '[' ']' — brackets are stripped by the URL parser before this), port != 0 and user
    /// (no CR, LF or NUL; an empty user becomes `None`); normalises encryption for SFTP.
    ///
    /// Errors: `InvalidInput`.
    pub fn new(
        protocol: Protocol,
        encryption: FtpEncryption,
        host: impl Into<String>,
        port: Option<u16>,
        user: Option<String>,
    ) -> Result<Self> {
        let host = host.into();
        if host.is_empty() {
            return Err(Error::InvalidInput("empty host".into()));
        }
        if host.len() > MAX_HOST_LEN {
            return Err(Error::InvalidInput(format!(
                "host is longer than {MAX_HOST_LEN} bytes"
            )));
        }
        if host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '@' | '[' | ']'))
        {
            return Err(Error::InvalidInput(format!(
                "invalid host \"{}\"",
                host.escape_debug()
            )));
        }
        if port == Some(0) {
            return Err(Error::InvalidInput("port must be 1-65535".into()));
        }
        if let Some(u) = &user {
            check_credential("user name", u)?;
        }
        let user = user.filter(|u| !u.is_empty());
        let encryption = match protocol {
            Protocol::Sftp => FtpEncryption::ExplicitIfAvailable,
            Protocol::Ftp => encryption,
        };
        Ok(Self {
            protocol,
            encryption,
            host,
            port,
            user,
        })
    }

    /// 22 for SFTP, 990 for `RequireImplicit`, otherwise 21.
    pub fn default_port(&self) -> u16 {
        match (self.protocol, self.encryption) {
            (Protocol::Sftp, _) => 22,
            (Protocol::Ftp, FtpEncryption::RequireImplicit) => 990,
            (Protocol::Ftp, _) => 21,
        }
    }

    /// `port`, or the protocol default.
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.default_port())
    }

    /// Scheme for this address: "sftp", "ftp", "ftpes", "ftps" (PlainOnly prints "ftp").
    pub fn scheme(&self) -> &'static str {
        match (self.protocol, self.encryption) {
            (Protocol::Sftp, _) => "sftp",
            (Protocol::Ftp, FtpEncryption::PlainOnly | FtpEncryption::ExplicitIfAvailable) => "ftp",
            (Protocol::Ftp, FtpEncryption::RequireExplicit) => "ftpes",
            (Protocol::Ftp, FtpEncryption::RequireImplicit) => "ftps",
        }
    }

    /// `scheme://[user@]host[:port][/path]`. The user (and password) are
    /// percent-encoded, the host is bracketed when it contains ':', the port is printed
    /// when set or when `force_port`. Never contains a password unless `opts.password`
    /// is given.
    pub fn to_url(&self, opts: &UrlOptions<'_>) -> String {
        let mut url = String::with_capacity(16 + self.host.len());
        url.push_str(self.scheme());
        url.push_str("://");
        let user = self.user.as_deref().filter(|u| !u.is_empty());
        if user.is_some() || opts.password.is_some() {
            if let Some(u) = user {
                url.extend(utf8_percent_encode(u, USERINFO_ESCAPES));
            }
            if let Some(pw) = opts.password {
                url.push(':');
                url.extend(utf8_percent_encode(pw.expose(), USERINFO_ESCAPES));
            }
            url.push('@');
        }
        if self.host.contains(':') {
            url.push('[');
            url.push_str(&self.host);
            url.push(']');
        } else {
            url.push_str(&self.host);
        }
        if let Some(port) = self.port.or(opts.force_port.then(|| self.default_port())) {
            url.push(':');
            url.push_str(&port.to_string());
        }
        if let Some(path) = opts.path {
            if path.is_root() {
                url.push('/');
            }
            for c in path.components() {
                url.push('/');
                url.extend(utf8_percent_encode(c, PATH_ESCAPES));
            }
        }
        url
    }

    /// Key for caches, history dedup and connection pools (T33, T41, T46).
    pub fn identity(&self) -> ServerIdentity {
        ServerIdentity {
            protocol: self.protocol,
            host: self.host.to_lowercase(),
            port: self.effective_port(),
            user: self.user.clone().unwrap_or_default(),
        }
    }
}

impl fmt::Display for ServerAddress {
    /// `to_url(&UrlOptions::default())`, e.g. "sftp://alice@example.com:2222".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_url(&UrlOptions::default()))
    }
}

impl FromStr for ServerAddress {
    type Err = Error;

    /// [`ParsedUrl::parse`], rejecting input that carries a password (`InvalidInput`) and
    /// dropping the path.
    fn from_str(s: &str) -> Result<Self> {
        let parsed = ParsedUrl::parse(s)?;
        if parsed.password.is_some() {
            return Err(Error::InvalidInput(
                "the address must not contain a password".into(),
            ));
        }
        Ok(parsed.address)
    }
}

/// protocol + lowercase host + effective port + user (empty when none). Encryption is NOT
/// part of it (plain and TLS sessions to one server see the same files).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServerIdentity {
    /// FTP or SFTP.
    pub protocol: Protocol,
    /// Lowercase host.
    pub host: String,
    /// Effective port.
    pub port: u16,
    /// User name, "" when none.
    pub user: String,
}

/// Options for [`ServerAddress::to_url`].
#[derive(Debug, Default)]
pub struct UrlOptions<'a> {
    /// Include this password (T62 "copy URL with password").
    pub password: Option<&'a SecretString>,
    /// Append this path.
    pub path: Option<&'a RemotePath>,
    /// Include the port even when `port` is None (prints the default port).
    pub force_port: bool,
}

/// Result of parsing a URL or bare host typed by the user (T58 quickconnect, T70 CLI).
pub struct ParsedUrl {
    /// Where to connect.
    pub address: ServerAddress,
    /// The password from the URL (T70 warns when present).
    pub password: Option<SecretString>,
    /// Initial remote directory.
    pub path: Option<RemotePath>,
}

impl fmt::Debug for ParsedUrl {
    /// The password prints as `[REDACTED]`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedUrl")
            .field("address", &self.address)
            .field("password", &self.password.as_ref())
            .field("path", &self.path)
            .finish()
    }
}

/// Percent-decodes `s`. Errors on '%' not followed by two hex digits and on invalid UTF-8.
fn decode(what: &str, s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let ok = b.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit);
            if !ok {
                return Err(Error::InvalidInput(format!(
                    "invalid percent escape in the {what}"
                )));
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    percent_decode_str(s)
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| Error::InvalidInput(format!("the {what} is not valid UTF-8")))
}

/// The scheme prefix of `s` (before "://"), if `s` starts with a syntactically valid one.
fn split_scheme(s: &str) -> Option<(&str, &str)> {
    let idx = s.find("://")?;
    let scheme = &s[..idx];
    let mut chars = scheme.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    valid.then(|| (scheme, &s[idx + 3..]))
}

fn parse_port(s: &str) -> Result<u16> {
    let invalid = || Error::InvalidInput("port must be 1-65535".into());
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    match s.parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => Err(invalid()),
    }
}

/// Splits `host[:port]`, `[v6][:port]` or (without a scheme) a bare IPv6 literal.
fn split_host_port(hostport: &str, has_scheme: bool) -> Result<(&str, Option<u16>)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(Error::InvalidInput(
                "missing ']' after the IPv6 address".into(),
            ));
        };
        let host = &rest[..end];
        let after = &rest[end + 1..];
        return match after.strip_prefix(':') {
            Some(p) => Ok((host, Some(parse_port(p)?))),
            None if after.is_empty() => Ok((host, None)),
            None => Err(Error::InvalidInput("unexpected text after ']'".into())),
        };
    }
    match hostport.matches(':').count() {
        0 => Ok((hostport, None)),
        1 => {
            let (h, p) = hostport.split_once(':').unwrap_or((hostport, ""));
            Ok((h, Some(parse_port(p)?)))
        }
        _ if !has_scheme => Ok((hostport, None)),
        _ => Err(Error::InvalidInput(
            "IPv6 addresses must be in brackets".into(),
        )),
    }
}

impl ParsedUrl {
    /// Parses `[scheme://][userinfo@]host[:port][/path]` after trimming ASCII
    /// whitespace. See the module docs for schemes and defaults.
    ///
    /// `userinfo` is split at the last '@' before the host and into user and password at
    /// its first ':'. User, password and path are percent-decoded; the host is not.
    /// Never panics on any input.
    ///
    /// Errors: `InvalidInput` for input over 2048 bytes, an unsupported scheme, a bad
    /// host, a port outside 1–65535, invalid percent escapes, user or password with CR,
    /// LF or NUL, or an invalid path. Messages never echo the password.
    pub fn parse(input: &str) -> Result<Self> {
        if input.len() > MAX_URL_LEN {
            return Err(Error::InvalidInput(format!(
                "URL is longer than {MAX_URL_LEN} bytes"
            )));
        }
        let s = input.trim_matches(|c: char| c.is_ascii_whitespace());
        if s.is_empty() {
            return Err(Error::InvalidInput("empty address".into()));
        }
        let (scheme, rest) = match split_scheme(s) {
            Some((scheme, rest)) => {
                let pe = match scheme.to_ascii_lowercase().as_str() {
                    "sftp" => (Protocol::Sftp, FtpEncryption::ExplicitIfAvailable),
                    "ftp" => (Protocol::Ftp, FtpEncryption::ExplicitIfAvailable),
                    "ftpes" => (Protocol::Ftp, FtpEncryption::RequireExplicit),
                    "ftps" => (Protocol::Ftp, FtpEncryption::RequireImplicit),
                    _ => return Err(Error::InvalidInput("unsupported scheme".into())),
                };
                (Some(pe), rest)
            }
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
            Some(ui) => {
                let (u, p) = match ui.split_once(':') {
                    Some((u, p)) => (u, Some(p)),
                    None => (ui, None),
                };
                let user = decode("user name", u)?;
                check_credential("user name", &user)?;
                let password = match p {
                    Some(p) => {
                        let pw = SecretString::from(decode("password", p)?);
                        check_credential("password", pw.expose())?;
                        Some(pw)
                    }
                    None => None,
                };
                ((!user.is_empty()).then_some(user), password)
            }
        };
        let (host, port) = split_host_port(hostport, scheme.is_some())?;
        let (protocol, encryption) = scheme.unwrap_or(if port == Some(22) {
            (Protocol::Sftp, FtpEncryption::ExplicitIfAvailable)
        } else {
            (Protocol::Ftp, FtpEncryption::ExplicitIfAvailable)
        });
        let address = ServerAddress::new(protocol, encryption, host, port, user)?;
        let path = match path {
            Some(p) => Some(RemotePath::parse(&decode("path", p)?)?),
            None => None,
        };
        Ok(Self {
            address,
            password,
            path,
        })
    }
}

/// Fuzz body (T91 §7 `url_parse`, also run by `prop_url_parse_never_panics`): parses
/// arbitrary bytes as lossy UTF-8; when that succeeds, the printed URL (with password and
/// path) must parse back to the same values.
#[doc(hidden)]
pub fn fuzz_url_parse(data: &[u8]) {
    let input = String::from_utf8_lossy(data);
    let Ok(parsed) = ParsedUrl::parse(&input) else {
        return;
    };
    let opts = UrlOptions {
        password: parsed.password.as_ref(),
        path: parsed.path.as_ref(),
        force_port: false,
    };
    let url = parsed.address.to_url(&opts);
    if url.len() > MAX_URL_LEN {
        // Percent-encoding can grow a valid input past the limit.
        return;
    }
    let again = match ParsedUrl::parse(&url) {
        Ok(p) => p,
        Err(e) => panic!("{url:?} printed from {input:?} does not parse: {e}"),
    };
    assert_eq!(again.address, parsed.address, "{url:?}");
    assert_eq!(again.path, parsed.path, "{url:?}");
    let same_password = match (&again.password, &parsed.password) {
        (Some(a), Some(b)) => a.ct_eq(b),
        (None, None) => true,
        _ => false,
    };
    assert!(same_password, "password changed in {url:?}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> ParsedUrl {
        ParsedUrl::parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}"))
    }

    fn addr(
        p: Protocol,
        e: FtpEncryption,
        host: &str,
        port: Option<u16>,
        user: Option<&str>,
    ) -> ServerAddress {
        ServerAddress::new(p, e, host, port, user.map(str::to_owned))
            .unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn url_parse_table() {
        use FtpEncryption::*;
        use Protocol::*;
        // (input, protocol, encryption, host, port, user, password, path, effective port)
        #[allow(clippy::type_complexity)]
        let rows: Vec<(
            &str,
            Protocol,
            FtpEncryption,
            &str,
            Option<u16>,
            Option<&str>,
            Option<&str>,
            Option<&str>,
            u16,
        )> = vec![
            (
                "sftp://[::1]:2222",
                Sftp,
                ExplicitIfAvailable,
                "::1",
                Some(2222),
                None,
                None,
                None,
                2222,
            ),
            (
                "ftp://a%40b.com@h",
                Ftp,
                ExplicitIfAvailable,
                "h",
                None,
                Some("a@b.com"),
                None,
                None,
                21,
            ),
            (
                "ftps://h",
                Ftp,
                RequireImplicit,
                "h",
                None,
                None,
                None,
                None,
                990,
            ),
            (
                "ftpes://u:p%3Aw@h/x%20y",
                Ftp,
                RequireExplicit,
                "h",
                None,
                Some("u"),
                Some("p:w"),
                Some("/x y"),
                21,
            ),
            (
                "h:22",
                Sftp,
                ExplicitIfAvailable,
                "h",
                Some(22),
                None,
                None,
                None,
                22,
            ),
            (
                "h",
                Ftp,
                ExplicitIfAvailable,
                "h",
                None,
                None,
                None,
                None,
                21,
            ),
            (
                "h:2121",
                Ftp,
                ExplicitIfAvailable,
                "h",
                Some(2121),
                None,
                None,
                None,
                2121,
            ),
            (
                "sftp://h",
                Sftp,
                ExplicitIfAvailable,
                "h",
                None,
                None,
                None,
                None,
                22,
            ),
            (
                "SFTP://alice@Example.COM:2222/home/a/",
                Sftp,
                ExplicitIfAvailable,
                "Example.COM",
                Some(2222),
                Some("alice"),
                None,
                Some("/home/a"),
                2222,
            ),
            (
                "sftp://h/",
                Sftp,
                ExplicitIfAvailable,
                "h",
                None,
                None,
                None,
                Some("/"),
                22,
            ),
            (
                "  ftp://h  ",
                Ftp,
                ExplicitIfAvailable,
                "h",
                None,
                None,
                None,
                None,
                21,
            ),
            (
                "a@b.com@host",
                Ftp,
                ExplicitIfAvailable,
                "host",
                None,
                Some("a@b.com"),
                None,
                None,
                21,
            ),
            (
                "u:pa:ss@h",
                Ftp,
                ExplicitIfAvailable,
                "h",
                None,
                Some("u"),
                Some("pa:ss"),
                None,
                21,
            ),
            (
                "@h",
                Ftp,
                ExplicitIfAvailable,
                "h",
                None,
                None,
                None,
                None,
                21,
            ),
            (
                ":pw@h",
                Ftp,
                ExplicitIfAvailable,
                "h",
                None,
                None,
                Some("pw"),
                None,
                21,
            ),
            (
                "::1",
                Ftp,
                ExplicitIfAvailable,
                "::1",
                None,
                None,
                None,
                None,
                21,
            ),
            (
                "[2001:db8::1]:22",
                Sftp,
                ExplicitIfAvailable,
                "2001:db8::1",
                Some(22),
                None,
                None,
                None,
                22,
            ),
            (
                "ftps://[2001:db8::1]:990/",
                Ftp,
                RequireImplicit,
                "2001:db8::1",
                Some(990),
                None,
                None,
                Some("/"),
                990,
            ),
            (
                "192.168.1.2:21",
                Ftp,
                ExplicitIfAvailable,
                "192.168.1.2",
                Some(21),
                None,
                None,
                None,
                21,
            ),
            (
                "ftp://h/a/../b%2Fc",
                Ftp,
                ExplicitIfAvailable,
                "h",
                None,
                None,
                None,
                Some("/b/c"),
                21,
            ),
            (
                "ftp://%C3%A4@h",
                Ftp,
                ExplicitIfAvailable,
                "h",
                None,
                Some("ä"),
                None,
                None,
                21,
            ),
        ];
        for (input, proto, enc, host, port, user, pw, path, eff) in rows {
            let p = parse(input);
            assert_eq!(p.address.protocol, proto, "{input}");
            assert_eq!(p.address.encryption, enc, "{input}");
            assert_eq!(p.address.host, host, "{input}");
            assert_eq!(p.address.port, port, "{input}");
            assert_eq!(p.address.user.as_deref(), user, "{input}");
            assert_eq!(p.password.as_ref().map(|s| s.expose()), pw, "{input}");
            assert_eq!(p.path.as_ref().map(RemotePath::as_str), path, "{input}");
            assert_eq!(p.address.effective_port(), eff, "{input}");
        }
    }

    #[test]
    fn url_parse_rejects_invalid() {
        let long = format!("ftp://{}", "a".repeat(2048));
        for bad in [
            "http://h",
            "ftp://h:0",
            "ftp://h:65536",
            "ftp://h:",
            "ftp://h:+22",
            "ftp://h:22a",
            "",
            "   ",
            "ftp://",
            "ftp://u@",
            "ftp://::1",
            "ftp://[::1",
            "ftp://[::1]x",
            "ftp://h h",
            "ftp://%zz@h",
            "ftp://u%@h",
            "ftp://%ff@h",
            "ftp://u%0D%0ADELE@h",
            "ftp://u:p%0A@h",
            "ftp://h/a%00b",
            "ftp://h/%e",
            long.as_str(),
        ] {
            assert!(
                matches!(ParsedUrl::parse(bad), Err(Error::InvalidInput(_))),
                "{bad:?} should fail"
            );
        }
    }

    #[test]
    fn url_errors_never_echo_password() {
        for bad in [
            "ftp://u:s3cr%zzet@h",
            "ftp://u:s3cret%0A@h",
            "ftp://u:s3cret@h:0",
            "ftp://u:s3cret@h h",
        ] {
            let Err(e) = ParsedUrl::parse(bad) else {
                panic!("{bad:?} should fail")
            };
            assert!(!e.to_string().contains("s3cr"), "{e}");
        }
    }

    #[test]
    fn url_printing_rules() {
        let a = addr(
            Protocol::Sftp,
            FtpEncryption::RequireImplicit,
            "example.com",
            Some(2222),
            Some("alice"),
        );
        assert_eq!(a.encryption, FtpEncryption::ExplicitIfAvailable);
        assert_eq!(a.to_string(), "sftp://alice@example.com:2222");
        let a = addr(
            Protocol::Ftp,
            FtpEncryption::RequireExplicit,
            "::1",
            None,
            Some("a@b:c/d e%"),
        );
        assert_eq!(a.to_string(), "ftpes://a%40b%3Ac%2Fd%20e%25@[::1]");
        let pw = SecretString::from("p:w@");
        let path = RemotePath::parse("/x y/a?b#c%").unwrap_or_else(|e| panic!("{e}"));
        let opts = UrlOptions {
            password: Some(&pw),
            path: Some(&path),
            force_port: true,
        };
        assert_eq!(
            a.to_url(&opts),
            "ftpes://a%40b%3Ac%2Fd%20e%25:p%3Aw%40@[::1]:21/x%20y/a%3Fb%23c%25"
        );
        let a = addr(Protocol::Ftp, FtpEncryption::PlainOnly, "h", None, None);
        assert_eq!(a.to_string(), "ftp://h");
        let root = RemotePath::root();
        assert_eq!(
            a.to_url(&UrlOptions {
                path: Some(&root),
                ..UrlOptions::default()
            }),
            "ftp://h/"
        );
        let a = addr(
            Protocol::Ftp,
            FtpEncryption::RequireImplicit,
            "h",
            None,
            None,
        );
        assert_eq!(
            a.to_url(&UrlOptions {
                force_port: true,
                ..UrlOptions::default()
            }),
            "ftps://h:990"
        );
        assert_eq!(a.scheme(), "ftps");
        // PlainOnly does not round-trip (documented).
        let plain = addr(Protocol::Ftp, FtpEncryption::PlainOnly, "h", None, None);
        assert_eq!(
            parse(&plain.to_string()).address.encryption,
            FtpEncryption::ExplicitIfAvailable
        );
    }

    #[test]
    fn server_address_display_never_contains_password() {
        let p = parse("ftp://user:hunter2@example.com:2121/dir");
        assert_eq!(p.password.as_ref().map(|s| s.expose()), Some("hunter2"));
        let shown = p.address.to_string();
        assert_eq!(shown, "ftp://user@example.com:2121");
        assert!(!shown.contains("hunter2"));
        assert!(!format!("{:?}", p.address).contains("hunter2"));
        assert!(
            "ftp://user:hunter2@example.com"
                .parse::<ServerAddress>()
                .is_err()
        );
        let a: ServerAddress = "sftp://u@h/dir".parse().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            a,
            addr(
                Protocol::Sftp,
                FtpEncryption::ExplicitIfAvailable,
                "h",
                None,
                Some("u")
            )
        );
    }

    #[test]
    fn server_identity_ignores_encryption_and_host_case() {
        let a = addr(
            Protocol::Ftp,
            FtpEncryption::PlainOnly,
            "Example.COM",
            None,
            Some("u"),
        );
        let b = addr(
            Protocol::Ftp,
            FtpEncryption::RequireExplicit,
            "example.com",
            Some(21),
            Some("u"),
        );
        assert_eq!(a.identity(), b.identity());
        assert_eq!(a.identity().host, "example.com");
        assert_eq!(a.identity().port, 21);
        let c = addr(
            Protocol::Ftp,
            FtpEncryption::RequireImplicit,
            "example.com",
            None,
            Some("u"),
        );
        assert_ne!(a.identity(), c.identity()); // effective port 990
        let d = addr(
            Protocol::Sftp,
            FtpEncryption::ExplicitIfAvailable,
            "example.com",
            Some(21),
            Some("u"),
        );
        assert_ne!(b.identity(), d.identity());
        let anon = addr(Protocol::Ftp, FtpEncryption::PlainOnly, "h", None, None);
        assert_eq!(anon.identity().user, "");
    }

    #[test]
    fn server_address_new_validates() {
        let new = |host: &str, port, user: Option<&str>| {
            ServerAddress::new(
                Protocol::Ftp,
                FtpEncryption::default(),
                host,
                port,
                user.map(str::to_owned),
            )
        };
        for bad in ["", "a b", "a/b", "u@h", "[::1]", "a\tb", "a\u{7f}"] {
            assert!(
                matches!(new(bad, None, None), Err(Error::InvalidInput(_))),
                "{bad:?}"
            );
        }
        assert!(new(&"a".repeat(254), None, None).is_err());
        assert!(new(&"a".repeat(253), None, None).is_ok());
        assert!(new("h", Some(0), None).is_err());
        assert!(new("h", None, Some("a\r\nb")).is_err());
        assert_eq!(new("h", None, Some("")).ok().and_then(|a| a.user), None);
        assert_eq!(FtpEncryption::default(), FtpEncryption::ExplicitIfAvailable);
    }

    #[test]
    fn server_address_serde_fields() {
        let a = addr(
            Protocol::Sftp,
            FtpEncryption::ExplicitIfAvailable,
            "h",
            Some(22),
            Some("u"),
        );
        let json = serde_json::to_string(&a).unwrap_or_default();
        assert_eq!(
            json,
            r#"{"protocol":"sftp","encryption":"explicit-if-available","host":"h","port":22,"user":"u"}"#
        );
        assert_eq!(serde_json::from_str::<ServerAddress>(&json).ok(), Some(a));
    }

    #[test]
    fn parsed_url_debug_redacted() {
        let p = parse("ftp://u:CANARY-77@h/x");
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("CANARY-77"), "{dbg}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(dbg.contains("RemotePath(\"/x\")"), "{dbg}");
        let opts = UrlOptions {
            password: p.password.as_ref(),
            ..UrlOptions::default()
        };
        assert!(!format!("{opts:?}").contains("CANARY-77"));
    }

    #[test]
    fn fuzz_body_accepts_table_rows() {
        for s in [
            "ftp://user@example.com:21/pub",
            "sftp://example.com/home/u",
            "ftps://[2001:db8::1]:990/",
            "example.com",
            "\u{0}\u{ff}",
            "ftp://u:p@h/%3F",
        ] {
            fuzz_url_parse(s.as_bytes());
        }
        fuzz_url_parse(b"\xff\xfe");
    }
}
