//! [`ConnectInfo`] and [`BackendFactory`].

use time::Duration;

use super::Backend;
use crate::{
    events::{EventSender, SessionId},
    model::{Charset, FtpEncryption, LocalPath, LogonType, PathStyle, ServerAddress},
    settings::FtpTransferMode,
};

/// Everything needed to open a session.
///
/// Quickconnect builds one directly; the Site Manager (T31) converts a saved
/// site into one.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectInfo {
    /// Protocol, host, port and user.
    pub address: ServerAddress,
    /// How to log in.
    pub logon: LogonType,
    /// FTP encryption mode; `None` uses the protocol's default.
    pub encryption: Option<FtpEncryption>,
    /// File name charset.
    pub charset: Charset,
    /// Force the server type instead of detecting it (`SYST`).
    pub server_type: Option<PathStyle>,
    /// Added to every timestamp the server reports (Site Manager → Advanced).
    pub timezone_offset: Duration,
    /// Passive/active override; `None` uses the settings.
    pub transfer_mode: Option<FtpTransferMode>,
    /// Whether the configured proxies apply.
    pub proxy: ProxyChoice,
    /// Maximum connections to this server; `None` uses the settings.
    pub connection_limit: Option<u32>,
    /// The private key for key-based SFTP logins, when not in `logon`.
    pub key: Option<KeySource>,
}

impl ConnectInfo {
    /// Connect info with the defaults for everything but address and logon.
    pub fn new(address: ServerAddress, logon: LogonType) -> Self {
        Self {
            address,
            logon,
            encryption: None,
            charset: Charset::Auto,
            server_type: None,
            timezone_offset: Duration::ZERO,
            transfer_mode: None,
            proxy: ProxyChoice::UseSettings,
            connection_limit: None,
            key: None,
        }
    }

    /// The effective FTP encryption mode.
    pub fn ftp_encryption(&self) -> Option<FtpEncryption> {
        self.encryption
            .or_else(|| self.address.protocol.default_encryption())
    }
}

/// Whether a session goes through the configured proxies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ProxyChoice {
    /// The generic proxy and, for FTP, the FTP proxy from the settings.
    #[default]
    UseSettings,
    /// Connect directly (Site Manager "Bypass proxy").
    Bypass,
}

/// Where a private key comes from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeySource {
    /// A key file on disk.
    File(LocalPath),
    /// An SSH key stored in the vault, by item id (T30).
    Vault(String),
}

/// Creates backends. The `courier-ftp` binary implements it by matching on the
/// protocol, so the core never names the protocol crates.
pub trait BackendFactory: Send + Sync {
    /// A new, not yet connected backend for `info`. It reports through `events`
    /// under `session`.
    fn create(
        &self,
        info: &ConnectInfo,
        session: SessionId,
        events: EventSender,
    ) -> Box<dyn Backend>;
}
