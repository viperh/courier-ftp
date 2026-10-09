//! [`ConnectInfo`]: everything needed to open sessions to one server.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::{Charset, KeySource, LogonType, RemotePath, ServerAddress, ServerTypeOverride};
use crate::secret::SecretString;
use crate::{Error, Result};

/// Largest accepted server time zone offset, in minutes (± 24 h).
const MAX_TZ_OFFSET_MINUTES: i32 = 1440;
/// Largest per-site connection limit.
const MAX_LIMIT_CONNECTIONS: u8 = 10;

/// Everything needed to open sessions to one server.
///
/// Built by T58 (quickconnect), T31 (saved site) and T70 (command line); shared as
/// `Arc<ConnectInfo>` by every session to that server (browsing + transfer workers).
/// Holds secrets, so it is neither `Clone` nor `Serialize`, and its `Debug` is redacted.
pub struct ConnectInfo {
    /// Where to connect; includes the user and the FTP encryption.
    pub address: ServerAddress,
    /// Logon method and secrets. `KeySource::VaultItem` must already be resolved to
    /// `Inline`.
    pub logon: LogonType,
    /// Tab/log title: site name or "user@host".
    pub label: String,
    /// The vault item of the saved site; None for quickconnect/CLI.
    pub site_id: Option<uuid::Uuid>,
    /// Filename/command encoding.
    pub charset: Charset,
    /// Forced path style, or Auto.
    pub server_type: ServerTypeOverride,
    /// Server time zone offset for LIST times, −1440..=1440 (T13).
    pub timezone_offset_minutes: i32,
    /// FTP active/passive override.
    pub transfer_mode: TransferModeOverride,
    /// Use the configured proxy, or bypass it.
    pub proxy: ProxyChoice,
    /// Generic proxy password from the vault (proxy.generic.password_ref), if any.
    pub proxy_password: Option<SecretString>,
    /// FTP proxy password (proxy.ftp_proxy.password_ref), if any (T15).
    pub ftp_proxy_password: Option<SecretString>,
    /// Per-site connection limit, 1..=10 (T31, T41). None = global limits only.
    pub limit_connections: Option<u8>,
    /// CWD after login (site default remote dir, URL path, bookmark).
    pub initial_remote_dir: Option<RemotePath>,
    /// SFTP: try the SSH agent before the configured method (T20).
    pub try_agent_first: bool,
}

impl ConnectInfo {
    /// Defaults for everything except address and logon (quickconnect). The label is
    /// `"user@host"` (or the host when there is no user).
    pub fn quick(address: ServerAddress, logon: LogonType) -> Self {
        let label = match &address.user {
            Some(user) => format!("{user}@{}", address.host),
            None => address.host.clone(),
        };
        Self {
            address,
            logon,
            label,
            site_id: None,
            charset: Charset::Auto,
            server_type: ServerTypeOverride::Auto,
            timezone_offset_minutes: 0,
            transfer_mode: TransferModeOverride::Default,
            proxy: ProxyChoice::Default,
            proxy_password: None,
            ftp_proxy_password: None,
            limit_connections: None,
            initial_remote_dir: None,
            try_agent_first: false,
        }
    }

    /// Checks the combination.
    ///
    /// # Errors
    ///
    /// `InvalidInput`: logon not valid for the protocol, unresolved
    /// `KeySource::VaultItem`, `limit_connections` 0 or > 10, time zone offset out of
    /// −1440..=1440.
    pub fn validate(&self) -> Result<()> {
        let protocol = self.address.protocol;
        if !self.logon.is_valid_for(protocol) {
            return Err(Error::InvalidInput(format!(
                "logon type {:?} is not valid for {protocol:?}",
                self.logon.kind()
            )));
        }
        if let LogonType::KeyFile {
            key: KeySource::VaultItem(_),
            ..
        } = self.logon
        {
            return Err(Error::InvalidInput(
                "the vault key item was not resolved".into(),
            ));
        }
        if let Some(n) = self.limit_connections
            && !(1..=MAX_LIMIT_CONNECTIONS).contains(&n)
        {
            return Err(Error::InvalidInput(format!(
                "connection limit {n} is out of range 1-{MAX_LIMIT_CONNECTIONS}"
            )));
        }
        if !(-MAX_TZ_OFFSET_MINUTES..=MAX_TZ_OFFSET_MINUTES).contains(&self.timezone_offset_minutes)
        {
            return Err(Error::InvalidInput(format!(
                "time zone offset {} minutes is out of range",
                self.timezone_offset_minutes
            )));
        }
        Ok(())
    }
}

impl fmt::Debug for ConnectInfo {
    /// Secrets print as `[REDACTED]`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectInfo")
            .field("address", &self.address)
            .field("logon", &self.logon)
            .field("label", &self.label)
            .field("site_id", &self.site_id)
            .field("charset", &self.charset)
            .field("server_type", &self.server_type)
            .field("timezone_offset_minutes", &self.timezone_offset_minutes)
            .field("transfer_mode", &self.transfer_mode)
            .field("proxy", &self.proxy)
            // `SecretString`'s own Debug prints `[REDACTED]`.
            .field("proxy_password", &self.proxy_password)
            .field("ftp_proxy_password", &self.ftp_proxy_password)
            .field("limit_connections", &self.limit_connections)
            .field("initial_remote_dir", &self.initial_remote_dir)
            .field("try_agent_first", &self.try_agent_first)
            .finish()
    }
}

/// Site "Transfer mode" (FTP): use the global setting, or force active/passive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransferModeOverride {
    /// `ftp.transfer_mode` from the settings.
    #[default]
    Default,
    /// Force active mode.
    Active,
    /// Force passive mode.
    Passive,
}

/// Site "Bypass proxy" (T31). Default = use `settings.proxy` (generic or FTP proxy).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyChoice {
    /// Use the configured proxy.
    #[default]
    Default,
    /// Connect directly.
    Bypass,
}
