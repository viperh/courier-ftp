//! [`LogonType`]: how to log in, with secrets that never show in `Debug`.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::LocalPath;

/// How to authenticate, as in FileZilla's Site Manager "Logon Type".
///
/// Passwords are [`SecretString`]s: zeroized on drop and printed as `****` by
/// `Debug`. They do serialize in clear text, because the only place credentials
/// are persisted is inside an encrypted vault item (D4, T31); never serialize
/// a `LogonType` anywhere else.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LogonType {
    /// User `anonymous`, with an e-mail-like password FileZilla style.
    Anonymous,
    /// User name and saved password.
    Normal {
        /// User name.
        user: String,
        /// Password.
        #[serde(with = "secret")]
        password: SecretString,
    },
    /// User name saved; the password is asked for on every connect.
    AskForPassword {
        /// User name.
        user: String,
    },
    /// Every prompt (password, keyboard-interactive, OTP) is asked
    /// interactively.
    Interactive {
        /// User name.
        user: String,
    },
    /// SFTP public-key login with a key file (OpenSSH or PuTTY `.ppk`).
    KeyFile {
        /// User name.
        user: String,
        /// The private key file.
        path: LocalPath,
    },
    /// FTP `USER`/`PASS`/`ACCT`.
    Account {
        /// User name.
        user: String,
        /// Password.
        #[serde(with = "secret")]
        password: SecretString,
        /// The `ACCT` value.
        account: String,
    },
    /// SFTP login through a running SSH agent (or Pageant).
    Agent {
        /// User name.
        user: String,
    },
}

impl LogonType {
    /// The user name to log in with (`anonymous` for [`LogonType::Anonymous`]).
    pub fn user(&self) -> &str {
        match self {
            LogonType::Anonymous => "anonymous",
            LogonType::Normal { user, .. }
            | LogonType::AskForPassword { user }
            | LogonType::Interactive { user }
            | LogonType::KeyFile { user, .. }
            | LogonType::Account { user, .. }
            | LogonType::Agent { user } => user,
        }
    }

    /// The saved password, if this logon type has one.
    pub fn password(&self) -> Option<&SecretString> {
        match self {
            LogonType::Normal { password, .. } | LogonType::Account { password, .. } => {
                Some(password)
            }
            _ => None,
        }
    }

    /// Whether connecting needs the user to type something (a password or
    /// interactive answers).
    pub fn needs_prompt(&self) -> bool {
        matches!(
            self,
            LogonType::AskForPassword { .. } | LogonType::Interactive { .. }
        )
    }
}

const MASK: &str = "****";

impl fmt::Debug for LogonType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogonType::Anonymous => f.write_str("Anonymous"),
            LogonType::Normal { user, .. } => f
                .debug_struct("Normal")
                .field("user", user)
                .field("password", &MASK)
                .finish(),
            LogonType::AskForPassword { user } => f
                .debug_struct("AskForPassword")
                .field("user", user)
                .finish(),
            LogonType::Interactive { user } => {
                f.debug_struct("Interactive").field("user", user).finish()
            }
            LogonType::KeyFile { user, path } => f
                .debug_struct("KeyFile")
                .field("user", user)
                .field("path", path)
                .finish(),
            LogonType::Account { user, account, .. } => f
                .debug_struct("Account")
                .field("user", user)
                .field("password", &MASK)
                .field("account", account)
                .finish(),
            LogonType::Agent { user } => f.debug_struct("Agent").field("user", user).finish(),
        }
    }
}

/// Serde helpers for [`SecretString`] fields that are persisted inside the vault.
mod secret {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        secret: &SecretString,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(secret.expose_secret())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SecretString, D::Error> {
        String::deserialize(deserializer).map(SecretString::from)
    }
}

impl PartialEq for LogonType {
    /// Plain (not constant-time) comparison, including passwords: this is
    /// for tests and change detection of saved sites, not for authentication.
    fn eq(&self, other: &Self) -> bool {
        let pw = |a: &SecretString, b: &SecretString| a.expose_secret() == b.expose_secret();
        match (self, other) {
            (LogonType::Anonymous, LogonType::Anonymous) => true,
            (
                LogonType::Normal {
                    user: a,
                    password: pa,
                },
                LogonType::Normal {
                    user: b,
                    password: pb,
                },
            ) => a == b && pw(pa, pb),
            (LogonType::AskForPassword { user: a }, LogonType::AskForPassword { user: b })
            | (LogonType::Interactive { user: a }, LogonType::Interactive { user: b })
            | (LogonType::Agent { user: a }, LogonType::Agent { user: b }) => a == b,
            (
                LogonType::KeyFile { user: a, path: pa },
                LogonType::KeyFile { user: b, path: pb },
            ) => a == b && pa == pb,
            (
                LogonType::Account {
                    user: a,
                    password: pa,
                    account: aa,
                },
                LogonType::Account {
                    user: b,
                    password: pb,
                    account: ab,
                },
            ) => a == b && aa == ab && pw(pa, pb),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    const SECRET: &str = "CANARY-PW-hunter2";

    #[test]
    fn debug_masks_passwords() {
        let normal = LogonType::Normal {
            user: "bob".into(),
            password: SECRET.into(),
        };
        let shown = format!("{normal:?}");
        assert!(shown.contains("****"), "{shown}");
        assert!(!shown.contains(SECRET), "{shown}");
        assert!(shown.contains("bob"));

        let account = LogonType::Account {
            user: "bob".into(),
            password: SECRET.into(),
            account: "acct".into(),
        };
        let shown = format!("{account:#?}");
        assert!(!shown.contains(SECRET), "{shown}");
        assert!(shown.contains("****"));
    }

    #[test]
    fn users_and_passwords() {
        assert_eq!(LogonType::Anonymous.user(), "anonymous");
        let normal = LogonType::Normal {
            user: "bob".into(),
            password: SECRET.into(),
        };
        assert_eq!(normal.user(), "bob");
        assert_eq!(normal.password().map(|p| p.expose_secret()), Some(SECRET));
        assert!(LogonType::Agent { user: "x".into() }.password().is_none());
        assert!(LogonType::AskForPassword { user: "x".into() }.needs_prompt());
        assert!(!normal.needs_prompt());
    }

    #[test]
    fn serde_round_trip() {
        for logon in [
            LogonType::Anonymous,
            LogonType::Normal {
                user: "bob".into(),
                password: SECRET.into(),
            },
            LogonType::KeyFile {
                user: "deploy".into(),
                path: LocalPath::new("/home/me/.ssh/id_ed25519"),
            },
            LogonType::Account {
                user: "u".into(),
                password: "p".into(),
                account: "a".into(),
            },
        ] {
            let json = serde_json::to_string(&logon).unwrap();
            assert_eq!(serde_json::from_str::<LogonType>(&json).unwrap(), logon);
        }
    }
}
