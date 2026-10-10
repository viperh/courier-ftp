//! End-to-end test harness for courier-ftp (T76, sverb parity).
//!
//! Not published. The workspace layering and `unsafe` checks also live here, in
//! `tests/workspace_metadata.rs` and `tests/forbid_unsafe.rs`.
//!
//! # Pieces
//! - [`Sshd`], [`Ftpd`], [`ProxyServer`]: OpenSSH, FTP/FTPS (vsftpd, proftpd,
//!   pure-ftpd) and HTTP/SOCKS proxy servers in Docker (via `testcontainers`). Each is
//!   one image built from `tests/fixtures/<name>/` with runtime-selected profiles
//!   ([`SshdProfile`], [`FtpdProfile`], [`ProxyProfile`]). Containers are reached by
//!   their bridge IP; no host port is published.
//! - [`Toxiproxy`]: network faults (latency, bandwidth, cut connections) in front of a
//!   container, controlled over its HTTP API.
//! - [`HostileFtpd`]: a scripted, deliberately misbehaving FTP server in-process (no
//!   Docker): escape sequences in the banner, `..`/`/`/NUL in names, absurd sizes.
//! - [`FtpRelayProxy`]: an in-process FTP proxy (`USER u@host`, `SITE`, `OPEN`) for the
//!   FTP proxy types (T15).
//! - [`keys`] and [`files`]: the committed, **test-only** fixture keys and CA, the user
//!   names and passwords of the images, and the deterministic fixture tree.
//! - [`TestHome`]: a temporary `COURIER_FTP_HOME` and the environment for child
//!   processes (no OS keyring, debug logging).
//! - [`Headless`]: one session through a [`BackendFactory`](courier_ftp_core::backend::BackendFactory),
//!   [`SessionHandle`](courier_ftp_core::backend::SessionHandle) and the event bus,
//!   without a TUI.
//! - [`PtyApp`]: the real `courier-ftp` binary in a PTY; keys are sent as chords
//!   (`"ctrl-q"`, `"F5"`, `"g g"`), the screen is read through a `vt100` emulator.
//! - [`diag`]: failure diagnostics. When a test panics, live harness objects dump the
//!   container log tail, the last screen and the message-log tail into the test output.
//!
//! # Running
//! Container tests are `#[ignore]`d so `cargo test` stays fast and Docker-free:
//!
//! ```text
//! cargo test --workspace                                       # fast suite, no Docker
//! COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored     # Linux with Docker
//! COURIER_E2E=1 cargo test -p courier-ftp-e2e --test harness_docker -- --ignored
//! ```
//!
//! Every container test starts with [`require_docker!`], which returns early with
//! `skipped: …` on stderr unless `COURIER_E2E=1` is set, the host is Linux and Docker
//! answers. On CI (`CI=true`) with `COURIER_E2E=1`, an unreachable Docker daemon is a
//! failure instead. Prebuilt images can be passed as `COURIER_E2E_{SSHD,FTPD,PROXY}_IMAGE`
//! (`name:tag`); otherwise each image is built once per test process, tagged with a hash
//! of its fixture directory. The harness self-tests that need no Docker
//! ([`HostileFtpd`], [`FtpRelayProxy`], [`PtyApp`] against the local binary) run in
//! the normal suite.
//!
//! # Reliability rules
//! - No fixed sleeps: every wait polls with a limit ([`poll_until`], [`timeout`]: 10 s,
//!   20 s on CI). Readiness checks poll every 100 ms, the PTY reader every 20 ms.
//! - Each test starts its own containers (and network when it needs more than one),
//!   so tests are parallel-safe. Containers are removed when their handle drops, also
//!   on panic.
//! - Every harness object dumps its diagnostics from `Drop` when the test is failing
//!   ([`diag::failing`]).

pub mod diag;
pub mod docker;
pub mod files;
pub mod ftp_proxy;
pub mod ftpd;
pub mod home;
pub mod hostile;
pub mod keys;
pub mod proxy;
pub mod pty;
pub mod session;
pub mod sshd;
pub mod toxi;

use std::{fmt, future::Future, time::Duration};

pub use docker::{ExecOutput, TestNetwork};
pub use ftp_proxy::{FtpRelayMode, FtpRelayProxy};
pub use ftpd::{CertVariant, Ftpd, FtpdOptions, FtpdProfile};
pub use home::{MASTER_PASSWORD, TestHome};
pub use hostile::{HostileFtpd, HostileScript};
pub use proxy::{ProxyProfile, ProxyServer};
pub use pty::{PtyApp, PtyOptions, Screen, courier_ftp_binary};
pub use session::{E2eBackendFactory, Headless, HeadlessOptions, PromptPolicy};
pub use sshd::{Sshd, SshdOptions, SshdProfile};
pub use toxi::{Toxic, ToxicProxy, Toxiproxy};

/// The polling timeout for every wait: 10 s locally, 20 s on CI.
pub fn timeout() -> Duration {
    if on_ci() {
        Duration::from_secs(20)
    } else {
        Duration::from_secs(10)
    }
}

/// Whether the tests run on CI: `CI` is set to anything but `""`, `"false"`, `"0"`.
pub fn on_ci() -> bool {
    std::env::var("CI").is_ok_and(|v| ci_value(&v))
}

fn ci_value(v: &str) -> bool {
    !v.is_empty() && v != "false" && v != "0"
}

/// Whether the Docker e2e tests were asked for: `COURIER_E2E` is `1` or `true`
/// (case-insensitive).
pub fn e2e_requested() -> bool {
    std::env::var("COURIER_E2E").is_ok_and(|v| e2e_value(&v))
}

fn e2e_value(v: &str) -> bool {
    v == "1" || v.eq_ignore_ascii_case("true")
}

/// Why a container test must be skipped, or `None` to run it.
///
/// - `COURIER_E2E` unset: skip (`COURIER_E2E=1` opts in).
/// - Not Linux: skip (containers are reached by their bridge IP).
/// - Docker does not answer `GET /_ping` within 5 s: skip locally; **panic on CI**, so a
///   broken CI setup never passes silently.
pub async fn docker_skip_reason() -> Option<String> {
    docker_skip_reason_with(
        e2e_requested(),
        cfg!(target_os = "linux"),
        on_ci(),
        docker::ping_docker(),
    )
    .await
}

/// [`docker_skip_reason`] with every input injected (unit-tested).
async fn docker_skip_reason_with(
    requested: bool,
    linux: bool,
    ci: bool,
    ping: impl Future<Output = Result<()>>,
) -> Option<String> {
    if !requested {
        return Some("set COURIER_E2E=1 to run the Docker e2e tests".into());
    }
    if !linux {
        return Some(
            "the e2e suite needs a Linux Docker host: containers are reached by their bridge IP"
                .into(),
        );
    }
    match ping.await {
        Ok(()) => None,
        Err(e) if ci => panic!("COURIER_E2E=1 on CI but Docker is unavailable: {e}"),
        Err(e) => Some(format!("Docker is unavailable ({e})")),
    }
}

/// Return early from a container test (with `skipped: <reason>` on stderr) unless the
/// e2e suite is enabled and Docker is reachable. See [`docker_skip_reason`].
#[macro_export]
macro_rules! require_docker {
    () => {
        if let Some(reason) = $crate::docker_skip_reason().await {
            eprintln!("skipped: {reason}");
            return;
        }
    };
}

/// Poll `probe` every `every` until it returns `Some`, or fail after `limit`.
///
/// The only place in the harness (besides the PTY reader loop) that sleeps. The error
/// carries the `Debug` form of the last probe result as `last`; probes that want a
/// more useful `last` (a log tail, a screen) record it themselves.
///
/// # Errors
/// [`WaitError`] when `limit` passed without `Some`.
pub async fn poll_until<T, F, Fut>(
    what: &str,
    limit: Duration,
    every: Duration,
    mut probe: F,
) -> std::result::Result<T, WaitError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let started = tokio::time::Instant::now();
    loop {
        if let Some(v) = probe().await {
            return Ok(v);
        }
        let waited = started.elapsed();
        if waited >= limit {
            return Err(WaitError {
                what: what.to_owned(),
                waited,
                last: String::new(),
            });
        }
        tokio::time::sleep(every.min(limit - waited)).await;
    }
}

/// A harness failure (Docker, the image build, a timeout, I/O). `Debug` is the same as
/// `Display`, so `unwrap()` output stays readable.
#[derive(Clone, PartialEq, Eq)]
pub struct E2eError(pub String);

impl E2eError {
    /// An error with `msg`.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl fmt::Display for E2eError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// The Debug form is what `unwrap()` prints: keep multi-line dumps readable.
impl fmt::Debug for E2eError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for E2eError {}

impl From<testcontainers::TestcontainersError> for E2eError {
    fn from(e: testcontainers::TestcontainersError) -> Self {
        Self(format!("testcontainers: {e}"))
    }
}

impl From<std::io::Error> for E2eError {
    fn from(e: std::io::Error) -> Self {
        Self(format!("io: {e}"))
    }
}

impl From<WaitError> for E2eError {
    fn from(e: WaitError) -> Self {
        Self(e.to_string())
    }
}

/// A wait that ran out of time; carries the last observed state (screen, log tail).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitError {
    /// What was waited for.
    pub what: String,
    /// How long.
    pub waited: Duration,
    /// The last observed state.
    pub last: String,
}

impl fmt::Display for WaitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "timed out after {:?} waiting for {}",
            self.waited, self.what
        )?;
        if !self.last.is_empty() {
            write!(f, "\n--- last state ---\n{}", self.last.trim_end())?;
        }
        Ok(())
    }
}

impl std::error::Error for WaitError {}

/// Harness result.
pub type Result<T, E = E2eError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    async fn ping_fails() -> Result<()> {
        Err(E2eError::new("injected ping failure"))
    }

    #[test]
    fn skip_reason_without_opt_in() {
        let reason = rt().block_on(docker_skip_reason_with(false, true, true, ping_fails()));
        assert!(reason.unwrap().contains("COURIER_E2E=1"));
        // Opted in, Docker answers: run.
        let run = rt().block_on(docker_skip_reason_with(true, true, true, async { Ok(()) }));
        assert_eq!(run, None);
        // Not Linux: skip with the reason.
        let reason = rt().block_on(docker_skip_reason_with(true, false, true, ping_fails()));
        assert!(reason.unwrap().contains("Linux"));
    }

    #[test]
    fn skip_reason_panics_on_ci_without_docker() {
        let result = std::panic::catch_unwind(|| {
            rt().block_on(docker_skip_reason_with(true, true, true, ping_fails()))
        });
        let payload = result.expect_err("must panic on CI");
        let msg = payload
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_default();
        assert!(msg.contains("Docker is unavailable"), "{msg}");
        assert!(msg.contains("injected ping failure"), "{msg}");
    }

    #[test]
    fn skip_reason_skips_locally_without_docker() {
        let reason = rt().block_on(docker_skip_reason_with(true, true, false, ping_fails()));
        let reason = reason.unwrap();
        assert!(reason.contains("Docker is unavailable"), "{reason}");
    }

    #[test]
    fn env_values() {
        assert!(ci_value("true") && ci_value("1") && ci_value("yes"));
        assert!(!ci_value("") && !ci_value("false") && !ci_value("0"));
        assert!(e2e_value("1") && e2e_value("TRUE") && e2e_value("true"));
        assert!(!e2e_value("0") && !e2e_value("yes") && !e2e_value(""));
    }

    #[test]
    fn poll_until_returns_value_or_times_out() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let mut n = 0;
        let got = rt.block_on(poll_until(
            "n reaches 3",
            Duration::from_secs(1),
            Duration::from_millis(100),
            || {
                n += 1;
                let v = (n >= 3).then_some(n);
                async move { v }
            },
        ));
        assert_eq!(got.unwrap(), 3);
        let err = rt
            .block_on(poll_until(
                "never",
                Duration::from_millis(250),
                Duration::from_millis(100),
                || async { None::<()> },
            ))
            .unwrap_err();
        assert_eq!(err.what, "never");
        assert!(err.waited >= Duration::from_millis(250));
        assert!(err.to_string().contains("waiting for never"));
    }
}
