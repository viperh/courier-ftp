//! [`TestHome`]: a temporary `COURIER_FTP_HOME` (`config/`, `data/`, `cache/`).
//!
//! Child processes get [`TestHome::env`]: this home, no OS keyring, debug logging, a
//! UTF-8 xterm. The harness never touches the real home.
//!
//! Vault helpers (T30): [`TestHome::with_vault`], [`TestHome::vault`],
//! [`TestHome::trust_host_key`] and [`TestHome::list`] use the real vault engine with
//! `Argon2Cost::TEST`. `add_site`, `add_bookmark` and `trust_cert` arrive with their
//! item views (T31, T33, T12).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use courier_ftp_core::model::item::{ItemBody, ItemId, ItemKind};
use courier_ftp_core::secret::SecretString;
use courier_ftp_core::trust::{
    HostKeyStore as _, KnownHost, KnownHostId, MemoryHostKeyStore, SwitchableHostKeyStore,
};
use courier_ftp_core::vault::{Argon2Cost, LockReason, NoKeyring, VaultEngine, VaultOptions};

use crate::{E2eError, Result, diag};

/// The vault database inside the data directory.
pub const VAULT_DB: &str = "courier-ftp.db";

fn vault_err(e: impl std::fmt::Display) -> E2eError {
    E2eError::new(format!("vault: {e}"))
}

/// The master password of every `TestHome` vault (from T30).
pub const MASTER_PASSWORD: &str = "correct horse battery staple violin";

/// The settings file in the config directory.
const SETTINGS_FILE: &str = "config.json";

/// A temporary `COURIER_FTP_HOME`. Deleted on drop unless it is kept
/// ([`TestHome::kept`]) or the test is failing (then its path is dumped).
#[derive(Debug)]
pub struct TestHome {
    dir: PathBuf,
    // Owns the temp dir for `new()`; `None` for kept homes.
    tmp: Option<tempfile::TempDir>,
}

impl TestHome {
    /// An empty home in a fresh temp directory, deleted on drop.
    ///
    /// # Errors
    /// The directories could not be created.
    pub fn new() -> Result<Self> {
        let tmp = tempfile::Builder::new()
            .prefix("courier-ftp-e2e-home-")
            .tempdir()?;
        let home = Self {
            dir: tmp.path().to_path_buf(),
            tmp: Some(tmp),
        };
        home.create_dirs()?;
        Ok(home)
    }

    /// A home kept after the run under `root/<name>-<uuid>`. Pass
    /// `env!("CARGO_TARGET_TMPDIR")` so the canary scan finds it (T91).
    ///
    /// # Errors
    /// The directories could not be created.
    pub fn kept(root: &Path, name: &str) -> Result<Self> {
        if name.is_empty() || name.contains(['/', '\\']) {
            return Err(E2eError::new(format!("bad kept home name {name:?}")));
        }
        let dir = root.join(format!("{name}-{}", uuid::Uuid::new_v4().simple()));
        let home = Self { dir, tmp: None };
        home.create_dirs()?;
        Ok(home)
    }

    fn create_dirs(&self) -> Result<()> {
        for d in [self.config_dir(), self.data_dir(), self.cache_dir()] {
            std::fs::create_dir_all(d)?;
        }
        Ok(())
    }

    /// The `COURIER_FTP_HOME` directory.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// `<home>/config` (`config.json`, keybindings).
    pub fn config_dir(&self) -> PathBuf {
        self.dir.join("config")
    }

    /// `<home>/data` (vault, logs).
    pub fn data_dir(&self) -> PathBuf {
        self.dir.join("data")
    }

    /// `<home>/cache`.
    pub fn cache_dir(&self) -> PathBuf {
        self.dir.join("cache")
    }

    /// Environment for child processes: `COURIER_FTP_HOME`, `COURIER_FTP_KEYRING=off`,
    /// `COURIER_FTP_TEST_ARGON2=test` (the `test-hooks` binary creates and re-wraps
    /// vaults with `Argon2Cost::TEST`, T60), `COURIER_FTP_LOG_LEVEL=debug`,
    /// `TERM=xterm-256color`, `LANG=C.UTF-8`.
    pub fn env(&self) -> Vec<(String, String)> {
        vec![
            ("COURIER_FTP_HOME".into(), self.dir.display().to_string()),
            ("COURIER_FTP_KEYRING".into(), "off".into()),
            ("COURIER_FTP_TEST_ARGON2".into(), "test".into()),
            ("COURIER_FTP_LOG_LEVEL".into(), "debug".into()),
            ("TERM".into(), "xterm-256color".into()),
            ("LANG".into(), "C.UTF-8".into()),
        ]
    }

    /// `<data>/courier-ftp.db`.
    pub fn vault_db(&self) -> PathBuf {
        self.data_dir().join(VAULT_DB)
    }

    /// `new()` plus an initialised vault ([`MASTER_PASSWORD`], `Argon2Cost::TEST`),
    /// locked again afterwards.
    ///
    /// # Errors
    /// The directories or the vault could not be created.
    pub async fn with_vault() -> Result<Self> {
        let home = Self::new()?;
        let engine = home.engine().await?;
        engine
            .initialize(SecretString::from(MASTER_PASSWORD), false)
            .await
            .map_err(vault_err)?;
        engine.lock(LockReason::Shutdown).await;
        Ok(home)
    }

    async fn engine(&self) -> Result<VaultEngine> {
        let path = self.vault_db();
        let store = tokio::task::spawn_blocking(move || courier_ftp_store::Store::open(path))
            .await
            .map_err(vault_err)?
            .map_err(vault_err)?;
        Ok(VaultEngine::new(
            store,
            Arc::new(NoKeyring),
            VaultOptions {
                cost: Argon2Cost::TEST,
                ..VaultOptions::default()
            },
            Arc::new(SwitchableHostKeyStore::new(Arc::new(
                MemoryHostKeyStore::new(),
            ))),
        ))
    }

    /// The vault of this home, unlocked with [`MASTER_PASSWORD`]. Drop it (or lock it)
    /// before starting a child process that writes the vault.
    ///
    /// # Errors
    /// No vault ([`TestHome::with_vault`]), or the vault could not be opened.
    pub async fn vault(&self) -> Result<VaultEngine> {
        let engine = self.engine().await?;
        engine
            .unlock(SecretString::from(MASTER_PASSWORD))
            .await
            .map_err(vault_err)?;
        Ok(engine)
    }

    /// Trusts an OpenSSH public key line (`<type> <base64> [comment]`) for `host:port`
    /// in the vault (a `known-host` item, T21).
    ///
    /// # Errors
    /// A malformed key line, or a vault error.
    pub async fn trust_host_key(
        &self,
        host: &str,
        port: u16,
        openssh_public: &str,
    ) -> Result<ItemId> {
        let mut parts = openssh_public.split_whitespace();
        let (Some(key_type), Some(blob)) = (parts.next(), parts.next()) else {
            return Err(E2eError::new("expected `<type> <base64> [comment]`"));
        };
        let engine = self.vault().await?;
        let id = KnownHostId::new_v7();
        let entry = KnownHost {
            id,
            host: courier_ftp_core::trust::normalize_host(host),
            port,
            key_type: key_type.to_owned(),
            public_key: blob.to_owned(),
            added_at: time_now(),
            comment: Some("added by the e2e harness".into()),
        };
        engine
            .host_key_store()
            .add(entry, Vec::new())
            .await
            .map_err(vault_err)?;
        engine.lock(LockReason::Shutdown).await;
        Ok(ItemId::from_uuid(id.0))
    }

    /// Every live item of `kind` with its full body.
    ///
    /// # Errors
    /// A vault error.
    pub async fn list(&self, kind: ItemKind) -> Result<Vec<(ItemId, ItemBody)>> {
        let engine = self.vault().await?;
        let mut out = Vec::new();
        for id in engine.item_ids(kind).map_err(vault_err)? {
            if let Some(b) = engine.get_body(id).await.map_err(vault_err)? {
                out.push((id, b.body));
            }
        }
        engine.lock(LockReason::Shutdown).await;
        Ok(out)
    }

    /// Merge `json` (an object) over `<config>/config.json` (created when missing):
    /// objects merge recursively, everything else replaces.
    ///
    /// # Errors
    /// `json` or the existing file is not an object, or I/O failed.
    pub fn write_settings(&self, json: serde_json::Value) -> Result<()> {
        let path = self.config_dir().join(SETTINGS_FILE);
        let mut current = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| E2eError::new(format!("{}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                serde_json::Value::Object(serde_json::Map::new())
            }
            Err(e) => return Err(e.into()),
        };
        if !current.is_object() || !json.is_object() {
            return Err(E2eError::new("settings must be JSON objects"));
        }
        merge(&mut current, json);
        let text = serde_json::to_string_pretty(&current)
            .map_err(|e| E2eError::new(format!("settings JSON: {e}")))?;
        std::fs::write(&path, text)?;
        Ok(())
    }
}

fn time_now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

fn merge(into: &mut serde_json::Value, from: serde_json::Value) {
    match (into, from) {
        (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
            for (k, v) in b {
                match a.get_mut(&k) {
                    Some(slot) => merge(slot, v),
                    None => {
                        a.insert(k, v);
                    }
                }
            }
        }
        (slot, v) => *slot = v,
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        if diag::failing() {
            diag::dump("COURIER_FTP_HOME (kept)", &self.dir.display().to_string());
            if let Some(tmp) = self.tmp.take() {
                let _ = tmp.keep();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vault_helpers() {
        let home = TestHome::with_vault().await.unwrap();
        assert!(home.vault_db().exists());
        let id = home
            .trust_host_key(
                "Example.org",
                2222,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA user@host",
            )
            .await
            .unwrap();
        let hosts = home.list(ItemKind::KnownHost).await.unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].0, id);
        let engine = home.vault().await.unwrap();
        let found = engine.host_key_store().lookup("example.org", 2222);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key_type, "ssh-ed25519");
    }

    #[test]
    fn new_home_has_dirs_and_is_removed() {
        let home = TestHome::new().unwrap();
        let path = home.path().to_path_buf();
        assert!(home.config_dir().is_dir() && home.data_dir().is_dir());
        assert!(home.cache_dir().is_dir());
        let env = home.env();
        assert!(env.contains(&("COURIER_FTP_KEYRING".into(), "off".into())));
        assert!(env.contains(&("COURIER_FTP_HOME".into(), path.display().to_string())));
        drop(home);
        assert!(!path.exists());
    }

    #[test]
    fn kept_home_survives_drop() {
        let root = tempfile::tempdir().unwrap();
        let home = TestHome::kept(root.path(), "scenario").unwrap();
        let path = home.path().to_path_buf();
        assert!(path.starts_with(root.path()));
        drop(home);
        assert!(path.join("config").is_dir());
        assert!(TestHome::kept(root.path(), "a/b").is_err());
    }

    #[test]
    fn write_settings_merges() {
        let home = TestHome::new().unwrap();
        home.write_settings(serde_json::json!({"ui": {"theme": "x", "a": 1}}))
            .unwrap();
        home.write_settings(serde_json::json!({"ui": {"a": 2}, "b": true}))
            .unwrap();
        let text = std::fs::read_to_string(home.config_dir().join("config.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"ui": {"theme": "x", "a": 2}, "b": true})
        );
        assert!(home.write_settings(serde_json::json!([1])).is_err());
    }
}
