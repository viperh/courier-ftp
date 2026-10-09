//! Logon types with their secrets ([`LogonType`], [`LogonKind`], [`KeySource`]).
//!
//! The user name lives in `ServerAddress.user`; `LogonType` carries only the method and
//! its secrets. There is no separate `Credentials` type: "credentials" in other tasks
//! means `ServerAddress.user` + `LogonType`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::{LocalPath, Protocol};
use crate::secret::{REDACTED, SecretString};

/// Copies an optional secret (re-wrapped, so the copy is zeroized independently).
fn dup(s: &Option<SecretString>) -> Option<SecretString> {
    s.as_ref().map(|s| SecretString::from(s.expose()))
}

/// What an optional secret prints as in `Debug`: `Some([REDACTED])` or `None` (the
/// secret's own `Debug` redacts it).
fn redacted(s: &Option<SecretString>) -> Option<&SecretString> {
    s.as_ref()
}

/// FileZilla's logon types (§2) with their secrets. No `Clone`/`Serialize` (secrets);
/// persisted through T31's item mapping, not serde. Copy with [`LogonType::duplicate`].
pub enum LogonType {
    /// FTP only: USER anonymous / PASS anonymous@example.com.
    Anonymous,
    /// Password stored; None = not stored (vault.store_passwords off) → asked at connect.
    Normal {
        /// The stored password, if any.
        password: Option<SecretString>,
    },
    /// Asked on every connect (Prompt::Password, T04).
    AskForPassword,
    /// Keyboard-interactive (SFTP) / password asked in a dialog (FTP).
    Interactive,
    /// SFTP public key.
    KeyFile {
        /// Where the private key comes from.
        key: KeySource,
        /// The key passphrase, if stored.
        passphrase: Option<SecretString>,
    },
    /// FTP with ACCT.
    Account {
        /// The stored password, if any.
        password: Option<SecretString>,
        /// The stored account (ACCT), if any.
        account: Option<SecretString>,
    },
    /// SFTP via ssh-agent / Pageant.
    Agent,
}

impl LogonType {
    /// The field-less discriminant.
    pub fn kind(&self) -> LogonKind {
        match self {
            Self::Anonymous => LogonKind::Anonymous,
            Self::Normal { .. } => LogonKind::Normal,
            Self::AskForPassword => LogonKind::AskForPassword,
            Self::Interactive => LogonKind::Interactive,
            Self::KeyFile { .. } => LogonKind::KeyFile,
            Self::Account { .. } => LogonKind::Account,
            Self::Agent => LogonKind::Agent,
        }
    }

    /// Deep copy (re-wraps secrets). Explicit instead of `Clone` so copies are visible in
    /// review.
    pub fn duplicate(&self) -> Self {
        match self {
            Self::Anonymous => Self::Anonymous,
            Self::Normal { password } => Self::Normal {
                password: dup(password),
            },
            Self::AskForPassword => Self::AskForPassword,
            Self::Interactive => Self::Interactive,
            Self::KeyFile { key, passphrase } => Self::KeyFile {
                key: key.duplicate(),
                passphrase: dup(passphrase),
            },
            Self::Account { password, account } => Self::Account {
                password: dup(password),
                account: dup(account),
            },
            Self::Agent => Self::Agent,
        }
    }

    /// Valid for this protocol? Anonymous/Account: FTP only; KeyFile/Agent: SFTP only;
    /// the others: both.
    pub fn is_valid_for(&self, protocol: Protocol) -> bool {
        self.kind().is_valid_for(protocol)
    }
}

impl fmt::Debug for LogonType {
    /// Secrets print as `[REDACTED]`, e.g. `Normal { password: Some([REDACTED]) }`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => f.write_str("Anonymous"),
            Self::Normal { password } => f
                .debug_struct("Normal")
                .field("password", &redacted(password))
                .finish(),
            Self::AskForPassword => f.write_str("AskForPassword"),
            Self::Interactive => f.write_str("Interactive"),
            Self::KeyFile { key, passphrase } => f
                .debug_struct("KeyFile")
                .field("key", key)
                .field("passphrase", &redacted(passphrase))
                .finish(),
            Self::Account { password, account } => f
                .debug_struct("Account")
                .field("password", &redacted(password))
                .field("account", &redacted(account))
                .finish(),
            Self::Agent => f.write_str("Agent"),
        }
    }
}

/// Field-less discriminant of [`LogonType`] for settings, the UI and T70 `--logontype`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogonKind {
    /// See [`LogonType::Anonymous`].
    Anonymous,
    /// See [`LogonType::Normal`].
    Normal,
    /// See [`LogonType::AskForPassword`].
    AskForPassword,
    /// See [`LogonType::Interactive`].
    Interactive,
    /// See [`LogonType::KeyFile`].
    KeyFile,
    /// See [`LogonType::Account`].
    Account,
    /// See [`LogonType::Agent`].
    Agent,
}

impl LogonKind {
    /// Anonymous/Account: FTP only; KeyFile/Agent: SFTP only; the others: both.
    pub fn is_valid_for(self, protocol: Protocol) -> bool {
        match self {
            Self::Anonymous | Self::Account => protocol == Protocol::Ftp,
            Self::KeyFile | Self::Agent => protocol == Protocol::Sftp,
            Self::Normal | Self::AskForPassword | Self::Interactive => true,
        }
    }
}

/// Where an SSH private key comes from (T31 §7).
pub enum KeySource {
    /// A key file on this device (device-local value, T91 §8 approval applies when synced).
    Path(LocalPath),
    /// An `ssh-key` item in the vault (T81); resolved to `Inline` when building ConnectInfo.
    VaultItem(uuid::Uuid),
    /// Key text (OpenSSH/PEM/PPK) already loaded from the vault.
    Inline(SecretString),
}

impl KeySource {
    /// Deep copy (re-wraps an inline key).
    pub fn duplicate(&self) -> Self {
        match self {
            Self::Path(p) => Self::Path(p.clone()),
            Self::VaultItem(id) => Self::VaultItem(*id),
            Self::Inline(s) => Self::Inline(SecretString::from(s.expose())),
        }
    }
}

impl fmt::Debug for KeySource {
    /// `Inline` prints as `Inline([REDACTED])`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(p) => f.debug_tuple("Path").field(p).finish(),
            Self::VaultItem(id) => f.debug_tuple("VaultItem").field(id).finish(),
            Self::Inline(_) => write!(f, "Inline({REDACTED})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "CANARY-5e1f";

    fn s() -> Option<SecretString> {
        Some(SecretString::from(CANARY))
    }

    #[test]
    fn logon_debug_is_redacted() {
        let cases = [
            LogonType::Normal { password: s() },
            LogonType::Account {
                password: s(),
                account: s(),
            },
            LogonType::KeyFile {
                key: KeySource::Inline(SecretString::from(CANARY)),
                passphrase: s(),
            },
        ];
        for l in &cases {
            for dbg in [format!("{l:?}"), format!("{l:#?}")] {
                assert!(!dbg.contains(CANARY), "{dbg}");
                assert!(dbg.contains(REDACTED), "{dbg}");
            }
        }
        assert_eq!(
            format!("{:?}", cases[0]),
            "Normal { password: Some([REDACTED]) }"
        );
        assert_eq!(
            format!("{:?}", LogonType::Normal { password: None }),
            "Normal { password: None }"
        );
        assert_eq!(
            format!("{:?}", KeySource::Inline(SecretString::from(CANARY))),
            "Inline([REDACTED])"
        );
        assert!(format!("{:?}", KeySource::Path(LocalPath::new("/k"))).contains("/k"));
        assert_eq!(format!("{:?}", LogonType::Agent), "Agent");
    }

    #[test]
    fn logon_type_valid_for_protocol() {
        assert!(!LogonType::Anonymous.is_valid_for(Protocol::Sftp));
        assert!(LogonType::Anonymous.is_valid_for(Protocol::Ftp));
        assert!(!LogonType::Agent.is_valid_for(Protocol::Ftp));
        assert!(LogonType::Agent.is_valid_for(Protocol::Sftp));
        let key = LogonType::KeyFile {
            key: KeySource::VaultItem(uuid::Uuid::nil()),
            passphrase: None,
        };
        assert!(!key.is_valid_for(Protocol::Ftp) && key.is_valid_for(Protocol::Sftp));
        let acct = LogonType::Account {
            password: None,
            account: None,
        };
        assert!(acct.is_valid_for(Protocol::Ftp) && !acct.is_valid_for(Protocol::Sftp));
        for l in [
            LogonType::Normal { password: None },
            LogonType::AskForPassword,
            LogonType::Interactive,
        ] {
            assert!(
                l.is_valid_for(Protocol::Ftp) && l.is_valid_for(Protocol::Sftp),
                "{l:?}"
            );
        }
    }

    #[test]
    fn logon_duplicate_copies_secrets() {
        let l = LogonType::KeyFile {
            key: KeySource::Inline(SecretString::from("key")),
            passphrase: s(),
        };
        let d = l.duplicate();
        assert_eq!(d.kind(), LogonKind::KeyFile);
        let LogonType::KeyFile {
            key: KeySource::Inline(k),
            passphrase: Some(p),
        } = d
        else {
            panic!("wrong variant");
        };
        assert_eq!(k.expose(), "key");
        assert_eq!(p.expose(), CANARY);
        let a = LogonType::Account {
            password: s(),
            account: None,
        }
        .duplicate();
        assert!(matches!(
            a,
            LogonType::Account {
                password: Some(_),
                account: None
            }
        ));
        assert_eq!(
            serde_json::to_string(&LogonKind::AskForPassword)
                .ok()
                .as_deref(),
            Some("\"ask-for-password\"")
        );
    }
}
