//! [`SshLogon`] and [`SshConnectParams`]: what one SSH connect needs, built from the
//! core `ConnectInfo` and `Settings` (T20).

use std::time::Duration;

use courier_ftp_core::{
    Error,
    backend::{ConnectInfo, ProxyChoice},
    model::{KeySource, LogonType},
    net::{NetOpts, ProxyConfig, Purpose},
    secret::SecretString,
    settings::Settings,
};

/// The SFTP-relevant logon types (T02 `LogonType` minus Anonymous/Account).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshLogon {
    /// Stored password (or asked when not stored), then keyboard-interactive.
    Normal,
    /// Asked on every connect.
    AskForPassword,
    /// Keyboard-interactive, every info request shown to the user.
    Interactive,
    /// Public key from a key file or the vault.
    KeyFile,
    /// SSH agent / Pageant.
    Agent,
}

/// The message for logon types SFTP can't use.
pub const NOT_FOR_SFTP: &str = "Anonymous and Account logons are not available for SFTP";

impl SshLogon {
    /// The SFTP logon for `t`.
    ///
    /// # Errors
    /// `Error::InvalidInput` for `Anonymous` and `Account` (not valid for SFTP).
    pub fn from_logon_type(t: &LogonType) -> Result<Self, Error> {
        match t {
            LogonType::Normal { .. } => Ok(Self::Normal),
            LogonType::AskForPassword => Ok(Self::AskForPassword),
            LogonType::Interactive => Ok(Self::Interactive),
            LogonType::KeyFile { .. } => Ok(Self::KeyFile),
            LogonType::Agent => Ok(Self::Agent),
            LogonType::Anonymous | LogonType::Account { .. } => {
                Err(Error::InvalidInput(NOT_FOR_SFTP.to_owned()))
            }
        }
    }
}

/// Everything needed to open one SSH connection. Built by T22 from `ConnectInfo` +
/// `Settings` ([`SshConnectParams::from_connect_info`]).
#[derive(Debug)]
pub struct SshConnectParams {
    /// As configured (not the resolved IP).
    pub host: String,
    /// Default 22.
    pub port: u16,
    /// `ServerAddress.user` (required for SFTP).
    pub user: String,
    /// The logon type.
    pub logon: SshLogon,
    /// `Normal { password }`: the stored password; otherwise `None`.
    pub password: Option<SecretString>,
    /// `LogonType::KeyFile` key: `Path` or `Inline` (a `VaultItem` here → InvalidInput).
    pub key: Option<KeySource>,
    /// `LogonType::KeyFile` passphrase (stored in the vault). Tried before prompting.
    pub key_passphrase: Option<SecretString>,
    /// Shown in passphrase prompts and the log: the path, or "vault key of &lt;label&gt;".
    pub key_label: String,
    /// `ConnectInfo.try_agent_first` (FileZilla "try agent first"; the T91 §8 approval
    /// is already done by the binary).
    pub try_agent_first: bool,
    /// T04 `can_save` for password/passphrase prompts (set by T22).
    pub can_save: bool,
    /// T07: proxy, IPv6 preference, connect timeout.
    pub net: NetOpts,
    /// `connection.timeout_secs` (default 20 s): handshake and each auth request.
    pub timeout: Duration,
    /// `connection.keepalive ? keepalive_interval_secs : None` (default 30 s).
    pub keepalive: Option<Duration>,
}

fn dup(s: Option<&SecretString>) -> Option<SecretString> {
    s.map(|s| SecretString::from(s.expose()))
}

impl SshConnectParams {
    /// The parameters for `info` (secrets copied with `LogonType::duplicate`).
    ///
    /// # Errors
    /// `Error::InvalidInput` for Anonymous/Account logons, a missing user, an
    /// unresolved `KeySource::VaultItem`, or a bad proxy configuration.
    pub fn from_connect_info(
        info: &ConnectInfo,
        settings: &Settings,
        can_save: bool,
    ) -> Result<Self, Error> {
        let logon = SshLogon::from_logon_type(&info.logon)?;
        let user = info
            .address
            .user
            .clone()
            .filter(|u| !u.is_empty())
            .ok_or_else(|| Error::InvalidInput("SFTP needs a user name".to_owned()))?;
        let (password, key, key_passphrase, key_label) = match info.logon.duplicate() {
            LogonType::Normal { password } => (password, None, None, String::new()),
            LogonType::KeyFile { key, passphrase } => {
                let label = match &key {
                    KeySource::Path(p) => p.as_path().display().to_string(),
                    KeySource::Inline(_) => format!("vault key of {}", info.label),
                    KeySource::VaultItem(_) => {
                        return Err(Error::InvalidInput(
                            "the vault key item was not resolved".to_owned(),
                        ));
                    }
                };
                (None, Some(key), passphrase, label)
            }
            _ => (None, None, None, String::new()),
        };
        let proxy = ProxyConfig::from_settings(
            &settings.proxy.generic,
            info.proxy == ProxyChoice::Bypass,
            dup(info.proxy_password.as_ref()),
        )?;
        let conn = &settings.connection;
        Ok(Self {
            host: info.address.host.clone(),
            port: info.address.effective_port(),
            user,
            logon,
            password,
            key,
            key_passphrase,
            key_label,
            try_agent_first: info.try_agent_first,
            can_save,
            net: NetOpts::from_settings(settings, Purpose::Control, proxy),
            timeout: Duration::from_secs(u64::from(conn.timeout_secs.max(1))),
            keepalive: conn
                .keepalive
                .then(|| Duration::from_secs(u64::from(conn.keepalive_interval_secs.max(1)))),
        })
    }

    /// Checks done before any network I/O: a user, a resolved key source for `KeyFile`.
    ///
    /// # Errors
    /// `Error::InvalidInput`.
    pub fn validate(&self) -> Result<(), Error> {
        if self.user.is_empty() {
            return Err(Error::InvalidInput("SFTP needs a user name".to_owned()));
        }
        if self.logon == SshLogon::KeyFile {
            match &self.key {
                None => {
                    return Err(Error::InvalidInput(
                        "No key file is configured for this site".to_owned(),
                    ));
                }
                Some(KeySource::VaultItem(_)) => {
                    return Err(Error::InvalidInput(
                        "the vault key item was not resolved".to_owned(),
                    ));
                }
                Some(_) => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use courier_ftp_core::model::{FtpEncryption, LocalPath, Protocol, ServerAddress};

    use super::*;

    fn info(logon: LogonType, user: Option<&str>) -> ConnectInfo {
        let address = ServerAddress::new(
            Protocol::Sftp,
            FtpEncryption::ExplicitIfAvailable,
            "web01.example.com",
            None,
            user.map(str::to_owned),
        )
        .unwrap();
        ConnectInfo::quick(address, logon)
    }

    #[test]
    fn anonymous_and_account_are_invalid_input() {
        for logon in [
            LogonType::Anonymous,
            LogonType::Account {
                password: None,
                account: None,
            },
        ] {
            let err = SshLogon::from_logon_type(&logon).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidInput(m) if m == NOT_FOR_SFTP),
                "{err}"
            );
            let err = SshConnectParams::from_connect_info(
                &info(logon, Some("alice")),
                &Settings::default(),
                false,
            )
            .unwrap_err();
            assert!(matches!(err, Error::InvalidInput(_)));
        }
        assert_eq!(
            SshLogon::from_logon_type(&LogonType::Interactive).unwrap(),
            SshLogon::Interactive
        );
    }

    #[test]
    fn params_reject_missing_user_and_unresolved_vault_key() {
        let s = Settings::default();
        let err =
            SshConnectParams::from_connect_info(&info(LogonType::AskForPassword, None), &s, false)
                .unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
        let vault = LogonType::KeyFile {
            key: KeySource::VaultItem(uuid::Uuid::nil()),
            passphrase: None,
        };
        let err = SshConnectParams::from_connect_info(&info(vault, Some("alice")), &s, false)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[test]
    fn params_copy_settings_and_secrets() {
        let mut s = Settings::default();
        s.connection.timeout_secs = 7;
        s.connection.keepalive_interval_secs = 11;
        let logon = LogonType::Normal {
            password: Some(SecretString::from("pw")),
        };
        let mut ci = info(logon, Some("alice"));
        ci.try_agent_first = true;
        let p = SshConnectParams::from_connect_info(&ci, &s, true).unwrap();
        assert_eq!(p.host, "web01.example.com");
        assert_eq!(p.port, 22);
        assert_eq!(p.user, "alice");
        assert_eq!(p.logon, SshLogon::Normal);
        assert_eq!(p.password.as_ref().map(SecretString::expose), Some("pw"));
        assert!(p.try_agent_first && p.can_save);
        assert_eq!(p.timeout, Duration::from_secs(7));
        assert_eq!(p.keepalive, Some(Duration::from_secs(11)));
        assert!(p.validate().is_ok());
        s.connection.keepalive = false;
        assert_eq!(
            SshConnectParams::from_connect_info(&ci, &s, false)
                .unwrap()
                .keepalive,
            None
        );

        let key = LogonType::KeyFile {
            key: KeySource::Path(LocalPath::new("/keys/id")),
            passphrase: Some(SecretString::from("pp")),
        };
        let p = SshConnectParams::from_connect_info(&info(key, Some("bob")), &s, false).unwrap();
        assert_eq!(p.logon, SshLogon::KeyFile);
        assert_eq!(
            p.key_label,
            std::path::Path::new("/keys/id").display().to_string()
        );
        assert_eq!(
            p.key_passphrase.as_ref().map(SecretString::expose),
            Some("pp")
        );
        let inline = LogonType::KeyFile {
            key: KeySource::Inline(SecretString::from("text")),
            passphrase: None,
        };
        let mut ci = info(inline, Some("bob"));
        ci.label = "My site".into();
        let p = SshConnectParams::from_connect_info(&ci, &s, false).unwrap();
        assert_eq!(p.key_label, "vault key of My site");
    }
}
