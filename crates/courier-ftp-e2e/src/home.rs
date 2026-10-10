//! [`TestHome`]: a temporary `COURIER_FTP_HOME` (`config/`, `data/`, `cache/`).
//!
//! Child processes get [`TestHome::env`]: this home, no OS keyring, debug logging, a
//! UTF-8 xterm. The harness never touches the real home.
//!
//! The vault helpers of the spec (`with_vault`, `vault`, `add_site`, `add_bookmark`,
//! `trust_host_key`, `trust_cert`, `list`) arrive with the vault and item tasks (T30,
//! T31, T33, T21, T12); until then a home has no vault.

use std::path::{Path, PathBuf};

use crate::{E2eError, Result, diag};

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
    /// `COURIER_FTP_LOG_LEVEL=debug`, `TERM=xterm-256color`, `LANG=C.UTF-8`.
    pub fn env(&self) -> Vec<(String, String)> {
        vec![
            ("COURIER_FTP_HOME".into(), self.dir.display().to_string()),
            ("COURIER_FTP_KEYRING".into(), "off".into()),
            ("COURIER_FTP_LOG_LEVEL".into(), "debug".into()),
            ("TERM".into(), "xterm-256color".into()),
            ("LANG".into(), "C.UTF-8".into()),
        ]
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
