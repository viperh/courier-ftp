//! Where courier-ftp keeps its files on disk.
//!
//! [`AppPaths`] is resolved once at startup and passed to whatever needs it.
//! The order for each directory is:
//!
//! 1. `COURIER_FTP_CONFIG` / `COURIER_FTP_DATA`: this one directory, as given.
//! 2. `COURIER_FTP_HOME=P`: `P/config` and `P/data` (used by tests and CI to
//!    keep everything under one root).
//! 3. The platform's per-user directories (XDG on Linux, `~/Library` on macOS,
//!    `%APPDATA%` / `%LOCALAPPDATA%` on Windows).
//! 4. `./.config` and `./.data` if the platform directories are unknown.
//!
//! Empty variables count as unset. The environment is injected into
//! [`AppPaths::resolve`], so tests never touch the process environment.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

/// Overrides both the config and the data directory (`P/config`, `P/data`).
pub const HOME_ENV: &str = "COURIER_FTP_HOME";
/// Overrides the config directory; wins over [`HOME_ENV`].
pub const CONFIG_ENV: &str = "COURIER_FTP_CONFIG";
/// Overrides the data directory; wins over [`HOME_ENV`].
pub const DATA_ENV: &str = "COURIER_FTP_DATA";

/// Reverse-domain qualifier, organisation and application name used to find
/// the platform's per-user directories.
const APP_QUALIFIER: &str = "com";
const APP_ORGANIZATION: &str = "viperh";
const APP_NAME: &str = "courier-ftp";

/// The platform's default config and data directories, before any override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultDirs {
    /// Default config directory.
    pub config: PathBuf,
    /// Default data directory.
    pub data: PathBuf,
}

impl DefaultDirs {
    /// The per-user directories of the current platform, or `./.config` and
    /// `./.data` when they cannot be determined (no home directory).
    pub fn platform() -> Self {
        match directories::ProjectDirs::from(APP_QUALIFIER, APP_ORGANIZATION, APP_NAME) {
            Some(dirs) => Self {
                config: dirs.config_local_dir().to_path_buf(),
                data: dirs.data_local_dir().to_path_buf(),
            },
            None => Self {
                config: PathBuf::from(".").join(".config"),
                data: PathBuf::from(".").join(".data"),
            },
        }
    }
}

/// The resolved courier-ftp directories. See the [module docs](self).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    config_dir: PathBuf,
    data_dir: PathBuf,
}

impl AppPaths {
    /// Resolve from the real process environment and platform directories.
    pub fn from_env() -> Self {
        Self::resolve(|key| std::env::var_os(key), DefaultDirs::platform())
    }

    /// Resolve with an injected environment lookup and default directories.
    pub fn resolve(env: impl Fn(&str) -> Option<OsString>, defaults: DefaultDirs) -> Self {
        let var = |key: &str| env(key).filter(|v| !v.is_empty()).map(PathBuf::from);
        let home = var(HOME_ENV);
        let config_dir = var(CONFIG_ENV)
            .or_else(|| home.as_ref().map(|h| h.join("config")))
            .unwrap_or(defaults.config);
        let data_dir = var(DATA_ENV)
            .or_else(|| home.as_ref().map(|h| h.join("data")))
            .unwrap_or(defaults.data);
        Self {
            config_dir,
            data_dir,
        }
    }

    /// Directory for user configuration files.
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// Directory for application data: logs, the vault, the queue.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use pretty_assertions::assert_eq;

    use super::*;

    fn defaults() -> DefaultDirs {
        DefaultDirs {
            config: PathBuf::from("/default/config"),
            data: PathBuf::from("/default/data"),
        }
    }

    fn resolve(vars: &[(&str, &str)]) -> AppPaths {
        let map: HashMap<String, OsString> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        AppPaths::resolve(|key| map.get(key).cloned(), defaults())
    }

    #[test]
    fn no_variables_use_platform_defaults() {
        let paths = resolve(&[]);
        assert_eq!(paths.config_dir(), Path::new("/default/config"));
        assert_eq!(paths.data_dir(), Path::new("/default/data"));
    }

    #[test]
    fn home_redirects_config_and_data() {
        let paths = resolve(&[(HOME_ENV, "/tmp/home")]);
        assert_eq!(paths.config_dir(), Path::new("/tmp/home/config"));
        assert_eq!(paths.data_dir(), Path::new("/tmp/home/data"));
    }

    #[test]
    fn specific_variables_win_over_home() {
        let paths = resolve(&[
            (HOME_ENV, "/tmp/home"),
            (CONFIG_ENV, "/etc/cf"),
            (DATA_ENV, "/var/cf"),
        ]);
        assert_eq!(paths.config_dir(), Path::new("/etc/cf"));
        assert_eq!(paths.data_dir(), Path::new("/var/cf"));
    }

    #[test]
    fn one_specific_variable_keeps_home_for_the_other() {
        let paths = resolve(&[(HOME_ENV, "/tmp/home"), (DATA_ENV, "/var/cf")]);
        assert_eq!(paths.config_dir(), Path::new("/tmp/home/config"));
        assert_eq!(paths.data_dir(), Path::new("/var/cf"));
    }

    #[test]
    fn empty_variables_count_as_unset() {
        let paths = resolve(&[(HOME_ENV, ""), (CONFIG_ENV, "")]);
        assert_eq!(paths, AppPaths::resolve(|_| None, defaults()));
    }
}
