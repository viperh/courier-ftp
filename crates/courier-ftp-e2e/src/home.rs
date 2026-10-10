//! [`TestHome`]: a temporary `COURIER_FTP_HOME`.
//!
//! Run the binary with [`TestHome::env`], or point config code at
//! [`TestHome::config_dir`] / [`TestHome::data_dir`]. The vault (cheap Argon2,
//! no OS keyring) and helpers that write sites, bookmarks and trusted keys
//! through the vault engine arrive with T30/T31.

use std::path::{Path, PathBuf};

use crate::{Result, diag};

/// A temporary `COURIER_FTP_HOME`, deleted on drop (kept, and its path printed,
/// when the test is failing).
#[derive(Debug)]
pub struct TestHome {
    dir: PathBuf,
    keep: bool,
}

fn unique_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!(
        "courier-ftp-e2e-home-{}-{nanos}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

impl TestHome {
    /// A new, empty home under the system temp directory.
    ///
    /// # Errors
    /// The directories could not be created.
    pub fn new() -> Result<Self> {
        Self::new_in(&std::env::temp_dir())
    }

    /// A new home under `base`. Tests whose artifacts the canary scan should
    /// see pass `env!("CARGO_TARGET_TMPDIR")` (CONTRIBUTING.md, "Canary secrets").
    ///
    /// # Errors
    /// The directories could not be created.
    pub fn new_in(base: &Path) -> Result<Self> {
        let dir = base.join(unique_name());
        std::fs::create_dir_all(dir.join("config"))?;
        std::fs::create_dir_all(dir.join("data"))?;
        Ok(Self { dir, keep: false })
    }

    /// The home directory (`COURIER_FTP_HOME`).
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Where the binary reads `config.json` from.
    pub fn config_dir(&self) -> PathBuf {
        self.dir.join("config")
    }

    /// Where the binary writes its log and data.
    pub fn data_dir(&self) -> PathBuf {
        self.dir.join("data")
    }

    /// The environment to run the binary in this home: `COURIER_FTP_HOME` set,
    /// and the variables that would override it removed (`None`).
    pub fn env(&self) -> Vec<(&'static str, Option<String>)> {
        vec![
            ("COURIER_FTP_HOME", Some(self.dir.display().to_string())),
            ("COURIER_FTP_CONFIG", None),
            ("COURIER_FTP_DATA", None),
            ("COURIER_FTP_KEYRING", Some("off".to_owned())),
        ]
    }

    /// Write `config.json` (as the user would).
    ///
    /// # Errors
    /// Writing failed.
    pub fn write_config(&self, json: &str) -> Result<()> {
        std::fs::write(self.config_dir().join("config.json"), json)?;
        Ok(())
    }

    /// The application log the binary wrote, if any: the newest daily file
    /// `courier-ftp.<YYYY-MM-DD>.log` (T71).
    pub fn log(&self) -> Option<String> {
        let mut files: Vec<_> = std::fs::read_dir(self.data_dir())
            .ok()?
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("courier-ftp.") && n.ends_with(".log"))
            })
            .collect();
        files.sort();
        std::fs::read_to_string(files.last()?).ok()
    }

    /// Keep the directory after the test (for debugging).
    pub fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        if diag::failing() || self.keep {
            let log = self
                .log()
                .map(|l| diag::tail(&l, 40))
                .unwrap_or_else(|| "(no log file)".to_owned());
            diag::dump(
                "test home",
                &format!("kept at {}\nlog:\n{log}", self.dir.display()),
            );
            return;
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
