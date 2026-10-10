//! Where courier-ftp keeps its files on disk.
//!
//! [`AppPaths`] is resolved once in `main` and passed explicitly to whatever needs
//! it; the core and the other libraries never read the environment. The order for
//! each directory (first match wins):
//!
//! 1. the CLI flag (`--config-dir` / `--data-dir`, from T70 on);
//! 2. `COURIER_FTP_CONFIG` (config) / `COURIER_FTP_DATA` (data); the cache dir has
//!    no variable of its own;
//! 3. `COURIER_FTP_HOME=P`: `P/config`, `P/data`, `P/cache` (tests and CI use this);
//! 4. the platform's per-user directories (`directories::ProjectDirs`);
//! 5. otherwise [`PathsError::NoHome`].
//!
//! Empty values count as unset; relative values are made absolute against the
//! current directory. Resolving creates nothing: [`AppPaths::ensure_dirs`] does.

#[cfg(test)]
use std::collections::HashMap;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

/// Relocates every courier-ftp directory: `P/config`, `P/data`, `P/cache`.
pub(crate) const HOME_ENV: &str = "COURIER_FTP_HOME";
/// Override only the config directory (wins over `HOME_ENV`).
pub(crate) const CONFIG_ENV: &str = "COURIER_FTP_CONFIG";
/// Override only the data directory (wins over `HOME_ENV`).
pub(crate) const DATA_ENV: &str = "COURIER_FTP_DATA";

/// Reverse-domain qualifier, organisation and application name used to find the
/// platform's per-user directories.
const APP_QUALIFIER: &str = "com";
const APP_ORGANIZATION: &str = "viperh";
const APP_NAME: &str = "courier-ftp";

/// Source of environment variables, injectable for tests.
pub(crate) trait Env {
    /// The variable's value; `None` when unset **or empty**.
    fn var_os(&self, name: &str) -> Option<OsString>;
}

/// The process environment.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SystemEnv;

impl Env for SystemEnv {
    fn var_os(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name).filter(|v| !v.is_empty())
    }
}

/// A fixed map, for tests.
#[cfg(test)]
#[derive(Debug, Default, Clone)]
pub(crate) struct MapEnv(pub HashMap<String, OsString>);

#[cfg(test)]
impl Env for MapEnv {
    fn var_os(&self, name: &str) -> Option<OsString> {
        self.0.get(name).filter(|v| !v.is_empty()).cloned()
    }
}

/// The resolved directories. Built once in `main` and passed explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppPaths {
    /// Config files (`config.json` etc., D10).
    pub config_dir: PathBuf,
    /// Vault DB (T30/T82), logs and crash reports (T71/T91).
    pub data_dir: PathBuf,
    /// Disposable files: edit temp copies (T63). `$COURIER_FTP_HOME/cache` or
    /// `ProjectDirs::cache_dir()`.
    pub cache_dir: PathBuf,
}

/// Why the directories could not be resolved.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PathsError {
    /// Neither an override nor the platform's home directory is available.
    #[error(
        "could not determine your home directory; set COURIER_FTP_HOME to the directory courier-ftp should use"
    )]
    NoHome,
    /// A relative override could not be made absolute.
    #[error("{var} ({}) could not be made absolute: {source}", path.display())]
    NotAbsolute {
        /// The variable (or flag) the value came from.
        var: &'static str,
        /// The value as given.
        path: PathBuf,
        /// Why `std::path::absolute` failed.
        #[source]
        source: std::io::Error,
    },
}

impl AppPaths {
    /// Precedence per directory: CLI flag (T70; `None` until then) >
    /// `COURIER_FTP_CONFIG` / `COURIER_FTP_DATA` > `COURIER_FTP_HOME/{config,data,cache}` >
    /// `directories::ProjectDirs::from("com", "viperh", "courier-ftp")`
    /// (`config_local_dir`, `data_local_dir`, `cache_dir`). Creates nothing.
    pub(crate) fn resolve(
        cli_config: Option<&Path>,
        cli_data: Option<&Path>,
        env: &dyn Env,
    ) -> Result<Self, PathsError> {
        Self::resolve_with(cli_config, cli_data, env, || platform_dirs(env))
    }

    /// [`Self::resolve`] with the platform lookup injected, so tests can simulate a
    /// host without a home directory.
    fn resolve_with(
        cli_config: Option<&Path>,
        cli_data: Option<&Path>,
        env: &dyn Env,
        platform: impl Fn() -> Option<[PathBuf; 3]>,
    ) -> Result<Self, PathsError> {
        let flag = |var: &'static str, p: Option<&Path>| {
            p.filter(|p| !p.as_os_str().is_empty())
                .map(|p| absolute(var, p))
                .transpose()
        };
        let var = |name: &'static str| {
            env.var_os(name)
                .map(|v| absolute(name, Path::new(&v)))
                .transpose()
        };

        let home = var(HOME_ENV)?;
        let from_home = |sub: &str| home.as_ref().map(|h| h.join(sub));
        let config = match flag("--config-dir", cli_config)? {
            Some(p) => Some(p),
            None => var(CONFIG_ENV)?.or_else(|| from_home("config")),
        };
        let data = match flag("--data-dir", cli_data)? {
            Some(p) => Some(p),
            None => var(DATA_ENV)?.or_else(|| from_home("data")),
        };
        let cache = from_home("cache");

        match (config, data, cache) {
            (Some(config_dir), Some(data_dir), Some(cache_dir)) => Ok(Self {
                config_dir,
                data_dir,
                cache_dir,
            }),
            (config, data, cache) => {
                let [p_config, p_data, p_cache] = platform().ok_or(PathsError::NoHome)?;
                Ok(Self {
                    config_dir: config.unwrap_or(p_config),
                    data_dir: data.unwrap_or(p_data),
                    cache_dir: cache.unwrap_or(p_cache),
                })
            }
        }
    }

    /// Create the three directories (Unix mode `0o700` on creation). Called only on
    /// paths that start the TUI (not for `--version` / `generate`, T70).
    pub(crate) fn ensure_dirs(&self) -> std::io::Result<()> {
        for dir in [&self.config_dir, &self.data_dir, &self.cache_dir] {
            if dir.is_dir() {
                continue;
            }
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder.create(dir)?;
        }
        Ok(())
    }
}

/// `std::path::absolute`, with the source of the value in the error.
fn absolute(var: &'static str, path: &Path) -> Result<PathBuf, PathsError> {
    std::path::absolute(path).map_err(|source| PathsError::NotAbsolute {
        var,
        path: path.to_path_buf(),
        source,
    })
}

/// The platform's config, data and cache directories, or `None` without a home
/// directory.
///
/// On Unix an unset or empty `HOME` counts as "no home directory": `directories`
/// would otherwise fall back to the password database, and `env -i courier-ftp`
/// must not silently write into the account's real home (T01 AC6).
fn platform_dirs(env: &dyn Env) -> Option<[PathBuf; 3]> {
    if cfg!(unix) && env.var_os("HOME").is_none() {
        return None;
    }
    directories::ProjectDirs::from(APP_QUALIFIER, APP_ORGANIZATION, APP_NAME).map(|d| {
        [
            d.config_local_dir().to_path_buf(),
            d.data_local_dir().to_path_buf(),
            d.cache_dir().to_path_buf(),
        ]
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn env(vars: &[(&str, &str)]) -> MapEnv {
        MapEnv(
            vars.iter()
                .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
                .collect(),
        )
    }

    fn platform() -> Option<[PathBuf; 3]> {
        Some([
            PathBuf::from("/platform/config"),
            PathBuf::from("/platform/data"),
            PathBuf::from("/platform/cache"),
        ])
    }

    /// Values from variables and flags go through `std::path::absolute`, which on
    /// Windows turns `/h` into `<current drive>:\h`.
    fn abs(p: &str) -> PathBuf {
        std::path::absolute(p).unwrap()
    }

    fn resolve(vars: &[(&str, &str)]) -> AppPaths {
        AppPaths::resolve_with(None, None, &env(vars), platform).unwrap()
    }

    #[test]
    fn paths_home_sets_both() {
        let paths = resolve(&[(HOME_ENV, "/h")]);
        assert_eq!(paths.config_dir, abs("/h/config"));
        assert_eq!(paths.data_dir, abs("/h/data"));
        assert_eq!(paths.cache_dir, abs("/h/cache"));
    }

    #[test]
    fn paths_env_wins_over_home() {
        let paths = resolve(&[(HOME_ENV, "/h"), (CONFIG_ENV, "/c")]);
        assert_eq!(paths.config_dir, abs("/c"));
        assert_eq!(paths.data_dir, abs("/h/data"));
        assert_eq!(paths.cache_dir, abs("/h/cache"));

        let paths = resolve(&[(HOME_ENV, "/h"), (DATA_ENV, "/d")]);
        assert_eq!(paths.config_dir, abs("/h/config"));
        assert_eq!(paths.data_dir, abs("/d"));
    }

    #[test]
    fn paths_cli_wins_over_env() {
        let paths = AppPaths::resolve_with(
            Some(Path::new("/flag-c")),
            Some(Path::new("/flag-d")),
            &env(&[(CONFIG_ENV, "/c"), (DATA_ENV, "/d")]),
            platform,
        )
        .unwrap();
        assert_eq!(paths.config_dir, abs("/flag-c"));
        assert_eq!(paths.data_dir, abs("/flag-d"));
        assert_eq!(paths.cache_dir, Path::new("/platform/cache"));
    }

    #[test]
    fn paths_empty_values_are_unset() {
        let paths = resolve(&[(HOME_ENV, ""), (CONFIG_ENV, ""), (DATA_ENV, "")]);
        assert_eq!(paths, resolve(&[]));
        assert_eq!(paths.config_dir, Path::new("/platform/config"));
        assert_eq!(paths.data_dir, Path::new("/platform/data"));
        assert_eq!(paths.cache_dir, Path::new("/platform/cache"));
    }

    #[test]
    fn paths_relative_home_is_made_absolute() {
        let cwd = std::env::current_dir().unwrap();
        let paths = resolve(&[(HOME_ENV, "rel")]);
        assert_eq!(paths.config_dir, cwd.join("rel").join("config"));
        assert_eq!(paths.data_dir, cwd.join("rel").join("data"));
        assert_eq!(paths.cache_dir, cwd.join("rel").join("cache"));
    }

    #[test]
    fn paths_no_home_is_an_error() {
        let err = AppPaths::resolve_with(None, None, &MapEnv::default(), || None).unwrap_err();
        assert!(matches!(err, PathsError::NoHome), "{err:?}");
        assert!(err.to_string().contains(HOME_ENV));

        // The cache dir has no variable of its own, so CONFIG + DATA are not enough.
        let err = AppPaths::resolve_with(
            None,
            None,
            &env(&[(CONFIG_ENV, "/c"), (DATA_ENV, "/d")]),
            || None,
        )
        .unwrap_err();
        assert!(matches!(err, PathsError::NoHome), "{err:?}");

        // COURIER_FTP_HOME alone is.
        assert!(AppPaths::resolve_with(None, None, &env(&[(HOME_ENV, "/h")]), || None).is_ok());
    }

    #[test]
    fn paths_platform_needs_home_variable_on_unix() {
        if cfg!(unix) {
            assert_eq!(platform_dirs(&MapEnv::default()), None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn paths_resolve_creates_nothing_and_ensure_creates_0700() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path().join("home");
        let vars = env(&[(HOME_ENV, home.to_str().unwrap())]);
        let paths = AppPaths::resolve(None, None, &vars).unwrap();
        assert!(!home.exists());
        assert!(std::fs::read_dir(tmp.path()).unwrap().next().is_none());

        paths.ensure_dirs().unwrap();
        for dir in [&paths.config_dir, &paths.data_dir, &paths.cache_dir] {
            let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", dir.display());
        }
        // Idempotent on existing directories.
        paths.ensure_dirs().unwrap();
    }
}
