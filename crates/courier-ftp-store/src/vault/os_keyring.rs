//! The OS keyring behind [`KeyringStore`]: the `keyring` crate (macOS
//! Keychain, Windows Credential Manager, Secret Service on Linux through
//! pure-Rust zbus).
//!
//! Tests never use [`OsKeyring`]: they inject
//! `courier_ftp_core::vault::MemKeyring`. The binary picks the keyring with
//! [`keyring_from_env`], so `COURIER_FTP_KEYRING=off` (set by PTY tests and CI)
//! keeps the real keyring out of the way.

use std::sync::Arc;

use courier_ftp_core::vault::{KeyringStore, NoKeyring};

/// Environment switch: `off` (or `0`, `none`, `disabled`, `false`) disables
/// keyring unlock.
pub const KEYRING_ENV: &str = "COURIER_FTP_KEYRING";

/// The platform keyring.
#[cfg(feature = "os-keyring")]
#[derive(Debug, Clone, Copy, Default)]
pub struct OsKeyring;

#[cfg(feature = "os-keyring")]
mod imp {
    use courier_ftp_core::vault::{KEYRING_SERVICE, KeyringError, KeyringStore};
    use zeroize::Zeroizing;

    use super::OsKeyring;

    fn err(e: &keyring::Error) -> KeyringError {
        KeyringError(e.to_string())
    }

    fn entry(account: &str) -> Result<keyring::Entry, KeyringError> {
        keyring::Entry::new(KEYRING_SERVICE, account).map_err(|e| err(&e))
    }

    impl KeyringStore for OsKeyring {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError> {
            match entry(account)?.get_secret() {
                Ok(secret) => Ok(Some(Zeroizing::new(secret))),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(err(&e)),
            }
        }

        fn set(&self, account: &str, secret: &[u8]) -> Result<(), KeyringError> {
            entry(account)?.set_secret(secret).map_err(|e| err(&e))
        }

        fn delete(&self, account: &str) -> Result<(), KeyringError> {
            match entry(account)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(err(&e)),
            }
        }
    }
}

fn is_off(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "off" | "0" | "none" | "disabled" | "false"
    )
}

/// The keyring the binary uses: [`OsKeyring`], or [`NoKeyring`] when
/// [`KEYRING_ENV`] is `off` or the build has no `os-keyring` feature.
pub fn keyring_from_env() -> Arc<dyn KeyringStore> {
    let off = std::env::var(KEYRING_ENV).is_ok_and(|v| is_off(&v));
    if off {
        tracing::debug!("keyring unlock disabled by {KEYRING_ENV}");
        return Arc::new(NoKeyring);
    }
    #[cfg(feature = "os-keyring")]
    {
        Arc::new(OsKeyring)
    }
    #[cfg(not(feature = "os-keyring"))]
    {
        tracing::debug!("keyring unlock unavailable: built without the os-keyring feature");
        Arc::new(NoKeyring)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_values() {
        for v in ["off", "OFF", " 0 ", "none", "disabled", "false"] {
            assert!(is_off(v), "{v}");
        }
        for v in ["on", "1", ""] {
            assert!(!is_off(v), "{v}");
        }
    }
}
