//! The OS keyring (`keyring` crate: Secret Service, macOS Keychain, Windows Credential
//! Manager) behind core's [`KeyringStore`] (T30; sverb `services/vault/os_keyring.rs`,
//! D13).
//!
//! Tests never use [`OsKeyring`]: core tests inject `MemKeyring`, and the PTY tests set
//! `COURIER_FTP_KEYRING=off` (or `file:<dir>` in `test-hooks` builds) so they never
//! touch the real keyring.

#![allow(dead_code, reason = "the unlock screens (T60) build the vault engine")]

use std::sync::Arc;

use courier_ftp_core::vault::{KEYRING_SERVICE, KeyringError, KeyringStore, NoKeyring};
use zeroize::Zeroizing;

/// Environment switch: unset → [`OsKeyring`]; `off`/`0`/`none`/`disabled`/`false` →
/// [`NoKeyring`]; `file:<dir>` → `FileKeyring` in `test-hooks` builds only.
pub(crate) const KEYRING_ENV: &str = "COURIER_FTP_KEYRING";

/// The platform keyring.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct OsKeyring;

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

/// The keyring the binary uses, from `COURIER_FTP_KEYRING`.
pub(crate) fn keyring_from_env() -> Arc<dyn KeyringStore> {
    keyring_from_value(std::env::var(KEYRING_ENV).ok().as_deref())
}

/// [`keyring_from_env`] for a given value (testable without touching the environment).
pub(crate) fn keyring_from_value(value: Option<&str>) -> Arc<dyn KeyringStore> {
    let Some(value) = value.map(str::trim) else {
        return Arc::new(OsKeyring);
    };
    if let Some(dir) = value.strip_prefix("file:") {
        #[cfg(feature = "test-hooks")]
        {
            return Arc::new(FileKeyring::new(std::path::PathBuf::from(dir)));
        }
        #[cfg(not(feature = "test-hooks"))]
        {
            let _ = dir;
            tracing::warn!(
                "{KEYRING_ENV}=file: needs a test-hooks build; keyring unlock is disabled"
            );
            return Arc::new(NoKeyring);
        }
    }
    let off = matches!(
        value.to_ascii_lowercase().as_str(),
        "off" | "0" | "none" | "disabled" | "false"
    );
    if off {
        Arc::new(NoKeyring)
    } else {
        Arc::new(OsKeyring)
    }
}

/// A keyring kept as files in a directory — **`test-hooks` builds only**, never in
/// release builds. One file per account (named by the account's hex encoding, mode
/// `0600` on Unix) holding the raw secret. The PTY tests (T76) use it to unlock by
/// keyring without the real OS keyring.
#[cfg(feature = "test-hooks")]
#[derive(Debug, Clone)]
pub(crate) struct FileKeyring {
    dir: std::path::PathBuf,
}

#[cfg(feature = "test-hooks")]
impl FileKeyring {
    /// A keyring in `dir` (created on the first write).
    pub(crate) fn new(dir: std::path::PathBuf) -> Self {
        Self { dir }
    }

    fn path(&self, account: &str) -> std::path::PathBuf {
        let name: String = account.bytes().map(|b| format!("{b:02x}")).collect();
        self.dir.join(name)
    }
}

#[cfg(feature = "test-hooks")]
impl KeyringStore for FileKeyring {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeyringError> {
        match std::fs::read(self.path(account)) {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(KeyringError(e.to_string())),
        }
    }

    fn set(&self, account: &str, secret: &[u8]) -> Result<(), KeyringError> {
        use std::io::Write as _;
        std::fs::create_dir_all(&self.dir).map_err(|e| KeyringError(e.to_string()))?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut f = opts
            .open(self.path(account))
            .map_err(|e| KeyringError(e.to_string()))?;
        f.write_all(secret).map_err(|e| KeyringError(e.to_string()))
    }

    fn delete(&self, account: &str) -> Result<(), KeyringError> {
        match std::fs::remove_file(self.path(account)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KeyringError(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(k: &Arc<dyn KeyringStore>) -> String {
        let dbg = format!("{k:?}");
        dbg.split([' ', '(', '{'])
            .next()
            .unwrap_or_default()
            .to_owned()
    }

    #[test]
    fn env_off_is_no_keyring() {
        for v in ["off", "0", "none", "disabled", "false", " OFF "] {
            assert_eq!(kind(&keyring_from_value(Some(v))), "NoKeyring", "{v}");
        }
        assert_eq!(kind(&keyring_from_value(None)), "OsKeyring");
        assert_eq!(kind(&keyring_from_value(Some("on"))), "OsKeyring");
    }

    #[test]
    fn env_file_requires_test_hooks() {
        let k = keyring_from_value(Some("file:/nonexistent/courier-keyring"));
        if cfg!(feature = "test-hooks") {
            assert_eq!(kind(&k), "FileKeyring");
        } else {
            assert_eq!(kind(&k), "NoKeyring");
        }
    }

    #[cfg(feature = "test-hooks")]
    #[test]
    fn file_keyring_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        use courier_ftp_core::secret::SecretString;
        use courier_ftp_core::trust::{MemoryHostKeyStore, SwitchableHostKeyStore};
        use courier_ftp_core::vault::{Argon2Cost, LockReason, VaultEngine, VaultOptions};

        let dir = tempfile::tempdir()?;
        let kr_dir = dir.path().join("keyring");
        let spec = format!("file:{}", kr_dir.display());
        let k = keyring_from_value(Some(&spec));
        assert!(k.probe());
        k.set("a", b"secret")?;
        assert_eq!(k.get("a")?.map(|s| s.to_vec()), Some(b"secret".to_vec()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(kr_dir.join("61"))?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        k.delete("a")?;
        k.delete("a")?;
        assert_eq!(k.get("a")?.map(|s| s.to_vec()), None);

        // Keyring unlock across two engine instances (two processes in the PTY tests).
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let db = dir.path().join("courier-ftp.db");
        let opts = || VaultOptions {
            cost: Argon2Cost::TEST,
            ..VaultOptions::default()
        };
        let host_keys = || {
            Arc::new(SwitchableHostKeyStore::new(Arc::new(
                MemoryHostKeyStore::new(),
            )))
        };
        rt.block_on(async {
            let store = courier_ftp_store::Store::open(&db)?;
            let a = VaultEngine::new(store, keyring_from_value(Some(&spec)), opts(), host_keys());
            a.initialize(
                SecretString::from("correct horse battery staple violin"),
                true,
            )
            .await?;
            a.lock(LockReason::Shutdown).await;
            drop(a);
            let store = courier_ftp_store::Store::open(&db)?;
            let b = VaultEngine::new(store, keyring_from_value(Some(&spec)), opts(), host_keys());
            b.unlock_with_keyring().await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
        Ok(())
    }
}
