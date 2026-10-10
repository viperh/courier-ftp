//! [`Protocol`] and [`FtpEncryption`].

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// The protocol of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// Plain FTP, upgraded to TLS when the server offers it (`ftp://`). The exact
    /// behaviour is the site's [`FtpEncryption`].
    Ftp,
    /// FTP with explicit TLS (`AUTH TLS`) required (`ftpes://`).
    FtpsExplicit,
    /// FTP over implicit TLS, TLS from the first byte (`ftps://`, port 990).
    FtpsImplicit,
    /// SFTP over SSH (`sftp://`).
    Sftp,
}

impl Protocol {
    /// Every protocol, in the order the Site Manager lists them.
    pub const ALL: [Protocol; 4] = [
        Protocol::Ftp,
        Protocol::FtpsExplicit,
        Protocol::FtpsImplicit,
        Protocol::Sftp,
    ];

    /// The well-known port: 21 for FTP and explicit FTPS, 990 for implicit FTPS,
    /// 22 for SFTP.
    pub fn default_port(self) -> u16 {
        match self {
            Protocol::Ftp | Protocol::FtpsExplicit => 21,
            Protocol::FtpsImplicit => 990,
            Protocol::Sftp => 22,
        }
    }

    /// The URL scheme: `ftp`, `ftpes`, `ftps` or `sftp`.
    pub fn scheme(self) -> &'static str {
        match self {
            Protocol::Ftp => "ftp",
            Protocol::FtpsExplicit => "ftpes",
            Protocol::FtpsImplicit => "ftps",
            Protocol::Sftp => "sftp",
        }
    }

    /// The protocol for a URL scheme (case-insensitive).
    pub fn from_scheme(scheme: &str) -> Result<Self> {
        Protocol::ALL
            .into_iter()
            .find(|p| p.scheme().eq_ignore_ascii_case(scheme))
            .ok_or_else(|| Error::InvalidInput(format!("unknown protocol `{scheme}://`")))
    }

    /// Whether this is one of the FTP variants.
    pub fn is_ftp(self) -> bool {
        !matches!(self, Protocol::Sftp)
    }

    /// The encryption mode this protocol implies, for FTP variants.
    pub fn default_encryption(self) -> Option<FtpEncryption> {
        match self {
            Protocol::Ftp => Some(FtpEncryption::ExplicitIfAvailable),
            Protocol::FtpsExplicit => Some(FtpEncryption::RequireExplicit),
            Protocol::FtpsImplicit => Some(FtpEncryption::RequireImplicit),
            Protocol::Sftp => None,
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Protocol::Ftp => "FTP",
            Protocol::FtpsExplicit => "FTPS (explicit)",
            Protocol::FtpsImplicit => "FTPS (implicit)",
            Protocol::Sftp => "SFTP",
        })
    }
}

impl FromStr for Protocol {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Protocol::from_scheme(s)
    }
}

/// FileZilla's four FTP encryption modes (Site Manager, General tab).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FtpEncryption {
    /// Never use TLS ("Only use plain FTP (insecure)").
    PlainOnly,
    /// Try `AUTH TLS`, fall back to plain FTP if the server refuses
    /// ("Use explicit FTP over TLS if available"; FileZilla's default).
    #[default]
    ExplicitIfAvailable,
    /// `AUTH TLS` must succeed ("Require explicit FTP over TLS").
    RequireExplicit,
    /// TLS from the first byte ("Require implicit FTP over TLS").
    RequireImplicit,
}

impl FtpEncryption {
    /// The protocol to use for this mode.
    pub fn protocol(self) -> Protocol {
        match self {
            FtpEncryption::PlainOnly | FtpEncryption::ExplicitIfAvailable => Protocol::Ftp,
            FtpEncryption::RequireExplicit => Protocol::FtpsExplicit,
            FtpEncryption::RequireImplicit => Protocol::FtpsImplicit,
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn default_ports() {
        assert_eq!(Protocol::Ftp.default_port(), 21);
        assert_eq!(Protocol::FtpsExplicit.default_port(), 21);
        assert_eq!(Protocol::FtpsImplicit.default_port(), 990);
        assert_eq!(Protocol::Sftp.default_port(), 22);
    }

    #[test]
    fn schemes_round_trip() {
        for p in Protocol::ALL {
            assert_eq!(Protocol::from_scheme(p.scheme()).unwrap(), p);
        }
        assert_eq!(Protocol::from_scheme("SFTP").unwrap(), Protocol::Sftp);
        assert!(Protocol::from_scheme("http").is_err());
    }

    #[test]
    fn encryption_maps_to_protocol() {
        for p in [
            Protocol::Ftp,
            Protocol::FtpsExplicit,
            Protocol::FtpsImplicit,
        ] {
            assert_eq!(p.default_encryption().unwrap().protocol(), p);
        }
        assert_eq!(Protocol::Sftp.default_encryption(), None);
        assert_eq!(FtpEncryption::PlainOnly.protocol(), Protocol::Ftp);
    }
}
