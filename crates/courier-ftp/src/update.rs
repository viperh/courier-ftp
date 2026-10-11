//! The update check (T74): at most once every [`CHECK_INTERVAL`], ask GitHub
//! for the newest release and tell the user when it is newer than this
//! build. Nothing is downloaded or installed.
//!
//! The check runs in the background and never delays startup. Failures are
//! logged at debug level only. The request carries nothing about the user:
//! no cookies, no tokens, only a `User-Agent` naming the program and its
//! version (GitHub's API requires one).
//!
//! The last check time and its result are kept in `update-check.json` in the
//! data directory, so a release found earlier is still announced on the
//! starts in between.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// Where releases are published (the CD workflow uploads to GitHub releases).
pub(crate) const RELEASES_API: &str = "https://api.github.com/repos/viperh/courier-ftp";
/// How often the check runs.
pub(crate) const CHECK_INTERVAL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// The whole request, connecting included.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(10);
/// The state file, in the data directory.
const STATE_FILE: &str = "update-check.json";
/// Responses larger than this are not read.
const MAX_BODY: usize = 4 * 1024 * 1024;
/// Releases looked at when prereleases count.
const RELEASES_PAGE: u32 = 30;
/// Environment variable that turns the check off (for packagers).
pub(crate) const OPT_OUT_ENV: &str = "COURIER_FTP_NO_UPDATE_CHECK";

/// Whether [`OPT_OUT_ENV`] turns the check off: set to anything but empty,
/// `0`, `false` or `no`.
pub(crate) fn env_opt_out() -> bool {
    std::env::var_os(OPT_OUT_ENV).is_some_and(|v| opt_out_value(&v.to_string_lossy()))
}

fn opt_out_value(v: &str) -> bool {
    let v = v.trim();
    !(v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("no"))
}

// --- versions ---

/// A semantic version (`1.2.3`, `v1.3.0-rc.1`); build metadata is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<PreId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PreId {
    Num(u64),
    Alpha(String),
}

impl Ord for PreId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match (self, other) {
            (PreId::Num(a), PreId::Num(b)) => a.cmp(b),
            (PreId::Alpha(a), PreId::Alpha(b)) => a.cmp(b),
            // Numeric identifiers sort before alphanumeric ones.
            (PreId::Num(_), PreId::Alpha(_)) => Ordering::Less,
            (PreId::Alpha(_), PreId::Num(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for PreId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Version {
    /// Parse `1.2.3`, with an optional leading `v`, prerelease (`-rc.1`) and
    /// build metadata (`+abc`, ignored). `None` for anything else.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let s = s
            .strip_prefix('v')
            .or_else(|| s.strip_prefix('V'))
            .unwrap_or(s);
        let s = s.split_once('+').map_or(s, |(v, _)| v);
        let (core, pre) = match s.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (s, None),
        };
        let mut parts = core.split('.');
        let num = |p: Option<&str>| -> Option<u64> {
            let p = p?;
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse().ok()
        };
        let major = num(parts.next())?;
        let minor = num(parts.next())?;
        let patch = num(parts.next())?;
        if parts.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => Vec::new(),
            Some(pre) => pre
                .split('.')
                .map(|id| {
                    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    {
                        None
                    } else if id.bytes().all(|b| b.is_ascii_digit()) {
                        id.parse().ok().map(PreId::Num)
                    } else {
                        Some(PreId::Alpha(id.to_owned()))
                    }
                })
                .collect::<Option<Vec<_>>>()?,
        };
        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }

    /// Whether this is a prerelease (`1.3.0-rc.1`).
    pub(crate) fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // A release is newer than its prereleases.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        for (i, id) in self.pre.iter().enumerate() {
            f.write_str(if i == 0 { "-" } else { "." })?;
            match id {
                PreId::Num(n) => write!(f, "{n}")?,
                PreId::Alpha(a) => f.write_str(a)?,
            }
        }
        Ok(())
    }
}

// --- releases ---

/// The fields of a GitHub release the check reads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct Release {
    pub(crate) tag_name: String,
    #[serde(default)]
    pub(crate) html_url: String,
    #[serde(default)]
    pub(crate) prerelease: bool,
    #[serde(default)]
    pub(crate) draft: bool,
}

/// A newer release than this build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UpdateInfo {
    /// `1.3.0` (no leading `v`).
    pub(crate) version: String,
    /// The release page.
    pub(crate) url: String,
}

impl UpdateInfo {
    /// "Update available: v1.3.0 — `url`", for the status bar and Help.
    pub(crate) fn notice(&self) -> String {
        if self.url.is_empty() {
            format!("Update available: v{}", self.version)
        } else {
            format!("Update available: v{} — {}", self.version, self.url)
        }
    }
}

/// The newest of `releases` that is newer than `current`, skipping drafts
/// and, unless `prereleases`, prereleases.
pub(crate) fn newest(
    current: &Version,
    releases: &[Release],
    prereleases: bool,
) -> Option<UpdateInfo> {
    releases
        .iter()
        .filter(|r| !r.draft)
        .filter_map(|r| Some((Version::parse(&r.tag_name)?, r)))
        .filter(|(v, r)| prereleases || !(r.prerelease || v.is_prerelease()))
        .filter(|(v, _)| v > current)
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(v, r)| UpdateInfo {
            version: v.to_string(),
            url: r.html_url.clone(),
        })
}

/// Where releases come from: GitHub in the app, a fake in tests.
#[async_trait::async_trait]
pub(crate) trait ReleaseSource: Send + Sync {
    /// The latest release, or with `prereleases` the most recent releases
    /// (prereleases included).
    async fn releases(&self, prereleases: bool) -> Result<Vec<Release>, String>;
}

/// The GitHub releases API of a repository.
pub(crate) struct GithubReleases {
    /// `https://api.github.com/repos/<owner>/<repo>` (tests: a local server).
    base: String,
    client: reqwest::Client,
}

impl GithubReleases {
    /// A source for the repository API at `base`; every request gives up
    /// after `timeout`.
    pub(crate) fn new(base: &str, timeout: Duration) -> Result<Self, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls_platform_verifier::Verifier::new(Arc::clone(&provider))
            .map_err(|e| format!("OS certificate store: {e}"))?;
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS setup: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .user_agent(concat!("courier-ftp/", env!("CARGO_PKG_VERSION")))
            .use_preconfigured_tls(tls)
            // Direct, like every other connection without a configured proxy:
            // `HTTP(S)_PROXY` from the environment is not used.
            .no_proxy()
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            client,
        })
    }

    async fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        let mut response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("HTTP {}", response.status()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if body.len() + chunk.len() > MAX_BODY {
                return Err("response too large".into());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

#[async_trait::async_trait]
impl ReleaseSource for GithubReleases {
    async fn releases(&self, prereleases: bool) -> Result<Vec<Release>, String> {
        if prereleases {
            let body = self
                .get(&format!("{}/releases?per_page={RELEASES_PAGE}", self.base))
                .await?;
            serde_json::from_slice(&body).map_err(|e| e.to_string())
        } else {
            let body = self.get(&format!("{}/releases/latest", self.base)).await?;
            let release: Release = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
            Ok(vec![release])
        }
    }
}

// --- scheduling ---

/// What the last check found, saved in the data directory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct State {
    /// When the last check succeeded (seconds since the Unix epoch).
    pub(crate) last_check: Option<u64>,
    /// The newer release it found, if any.
    pub(crate) latest: Option<UpdateInfo>,
}

impl State {
    fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, path: &Path) {
        let result = serde_json::to_vec_pretty(self)
            .map_err(std::io::Error::other)
            .and_then(|json| {
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                std::fs::write(path, json)
            });
        if let Err(err) = result {
            debug!(%err, "update check: saving the state failed");
        }
    }
}

/// Whether a check is due: never checked, the interval passed, or the clock
/// went backwards.
pub(crate) fn due(last_check: Option<u64>, now: u64, interval: Duration) -> bool {
    match last_check {
        None => true,
        Some(last) => now < last || now - last >= interval.as_secs(),
    }
}

/// How the check runs.
#[derive(Clone)]
pub(crate) struct Checker {
    /// `interface.check_updates`, `--no-update-check` and
    /// [`OPT_OUT_ENV`] together.
    pub(crate) enabled: bool,
    /// `interface.check_prereleases`.
    pub(crate) prereleases: bool,
    /// This build's version.
    pub(crate) current: String,
    /// The state file.
    pub(crate) state_path: PathBuf,
    pub(crate) interval: Duration,
    /// Gives up on the request after this long (on top of the client's own
    /// timeout).
    pub(crate) timeout: Duration,
}

impl Checker {
    /// The check for this build, keeping its state in `data_dir`.
    pub(crate) fn new(data_dir: &Path) -> Self {
        Self {
            enabled: true,
            prereleases: false,
            current: env!("CARGO_PKG_VERSION").to_owned(),
            state_path: data_dir.join(STATE_FILE),
            interval: CHECK_INTERVAL,
            timeout: TIMEOUT,
        }
    }

    /// Run the check: ask `source` when it is due, otherwise reuse what the
    /// last check found. `None` when disabled, up to date, or on failure.
    /// `source` is never called when the check is disabled.
    pub(crate) async fn run(
        &self,
        source: &dyn ReleaseSource,
        now: SystemTime,
        cancel: &CancellationToken,
    ) -> Option<UpdateInfo> {
        if !self.enabled {
            return None;
        }
        let current = Version::parse(&self.current)?;
        let now = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let state = State::load(&self.state_path);
        // A saved result still counts if it's newer than this build (the
        // user may have upgraded since) and of an allowed kind.
        let cached = || {
            state.latest.as_ref().and_then(|info| {
                let v = Version::parse(&info.version)?;
                (v > current && (self.prereleases || !v.is_prerelease())).then(|| info.clone())
            })
        };
        if !due(state.last_check, now, self.interval) {
            return cached();
        }
        let fetched = tokio::select! {
            () = cancel.cancelled() => return None,
            r = tokio::time::timeout(self.timeout, source.releases(self.prereleases)) => r,
        };
        match fetched {
            Ok(Ok(releases)) => {
                let latest = newest(&current, &releases, self.prereleases);
                State {
                    last_check: Some(now),
                    latest: latest.clone(),
                }
                .save(&self.state_path);
                latest
            }
            Ok(Err(err)) => {
                debug!(%err, "update check failed");
                cached()
            }
            Err(_) => {
                debug!("update check timed out");
                cached()
            }
        }
    }
}

/// Makes the release source when the check starts (not at startup: the
/// TLS setup reads the OS trust store).
pub(crate) type SourceFactory =
    Arc<dyn Fn() -> Result<Arc<dyn ReleaseSource>, String> + Send + Sync>;

/// What the app needs to run the check.
#[derive(Clone)]
pub(crate) struct Hook {
    /// Where the state file goes.
    pub(crate) data_dir: PathBuf,
    pub(crate) source: SourceFactory,
}

impl Hook {
    /// The real check: GitHub releases of this project.
    pub(crate) fn github(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            source: Arc::new(|| {
                GithubReleases::new(RELEASES_API, TIMEOUT)
                    .map(|s| Arc::new(s) as Arc<dyn ReleaseSource>)
            }),
        }
    }
}

#[cfg(test)]
mod tests;
