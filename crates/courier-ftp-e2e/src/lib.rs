//! End-to-end test harness for courier-ftp (T76), modelled on sverb's.
//!
//! Not published. The workspace layering checks also live here, in
//! `tests/workspace_metadata.rs`, and the `unsafe` policy check in
//! `tests/forbid_unsafe.rs`.
//!
//! # Pieces
//! - [`TestHome`]: a temporary `COURIER_FTP_HOME` for running the binary or the
//!   config code against. The vault (cheap Argon2) and helpers that write sites,
//!   bookmarks and trusted keys arrive with T30/T31.
//! - [`diag`]: failure diagnostics. When a test panics, live harness objects dump
//!   what they know (container logs, the last screen) to the test output.
//! - Docker plumbing: [`require_docker!`], [`docker_skip_reason`], [`ping_docker`].
//!
//! Later stages add, as their features land: FTP fixture images and profiles
//! (vsftpd, ProFTPD, Pure-FTPd; T14), the OpenSSH fixture (T20/T22), proxies and
//! toxiproxy (T15/T41b), the sync server (T84+), `Headless` (sessions without a
//! TUI) and `PtyApp` (the real binary in a PTY, from T60).
//!
//! # Running
//! Container tests are `#[ignore]`d so `cargo test` stays fast and Docker-free:
//!
//! ```text
//! COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored
//! ```
//!
//! Every container test starts with [`require_docker!`], which returns early with
//! a skip message unless `COURIER_E2E=1` is set and Docker answers. On CI
//! (`CI=true`) a missing Docker daemon is a failure instead, so a broken CI setup
//! never passes silently. The harness self-tests that need no Docker run in the
//! normal suite.
//!
//! # Reliability rules
//! No fixed sleeps: everything polls with a timeout ([`timeout`]: 10 s, 20 s on
//! CI). Each test starts its own containers, so tests are parallel-safe.

pub mod diag;
pub mod home;

use std::{fmt, future::Future, time::Duration};

pub use home::TestHome;

/// The default polling timeout: 10 s locally, 20 s on CI (`CI` set).
pub fn timeout() -> Duration {
    if on_ci() {
        Duration::from_secs(20)
    } else {
        Duration::from_secs(10)
    }
}

/// A TCP port that is free on the host right now, for mapping a container
/// port explicitly. Once any port is mapped with `with_mapped_port`,
/// testcontainers no longer publishes the other exposed ports by itself.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or_else(|e| panic!("no free local port: {e}"))
}

/// Whether the tests run on CI (`CI` is set to anything but `false`/`0`).
pub fn on_ci() -> bool {
    std::env::var("CI").is_ok_and(|v| !v.is_empty() && v != "false" && v != "0")
}

/// Whether e2e tests were asked for (`COURIER_E2E=1`).
pub fn e2e_requested() -> bool {
    std::env::var("COURIER_E2E").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Check that the Docker daemon answers.
///
/// # Errors
/// Connecting or pinging failed (or took longer than 5 s).
pub async fn ping_docker() -> Result<()> {
    let docker = testcontainers::bollard::Docker::connect_with_defaults()
        .map_err(|e| E2eError::new(format!("connect: {e}")))?;
    tokio::time::timeout(Duration::from_secs(5), docker.ping())
        .await
        .map_err(|_| E2eError::new("ping timed out"))?
        .map_err(|e| E2eError::new(format!("ping: {e}")))?;
    Ok(())
}

/// Why a container test should be skipped, or `None` to run it.
///
/// - `COURIER_E2E` unset: skip (`COURIER_E2E=1` opts in).
/// - Docker does not answer a ping: skip locally; **panic on CI**.
pub async fn docker_skip_reason() -> Option<String> {
    if !e2e_requested() {
        return Some("set COURIER_E2E=1 to run the docker e2e tests".into());
    }
    match ping_docker().await {
        Ok(()) => None,
        Err(e) if on_ci() => panic!("COURIER_E2E=1 on CI but Docker is unavailable: {e}"),
        Err(e) => Some(format!("Docker is unavailable ({e})")),
    }
}

/// Return early from a container test (with a message on stderr) unless the e2e
/// suite is enabled and Docker is reachable. See [`docker_skip_reason`].
#[macro_export]
macro_rules! require_docker {
    () => {
        if let Some(reason) = $crate::docker_skip_reason().await {
            eprintln!("skipped: {reason}");
            return;
        }
    };
}

/// Poll `check` until it returns `Some`, or fail after [`timeout`]. The only way
/// tests wait: never a fixed sleep.
///
/// # Errors
/// `check` kept returning `None`; the error names `what` was awaited.
pub async fn wait_for<T, F, Fut>(what: &str, mut check: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let limit = timeout();
    let start = tokio::time::Instant::now();
    loop {
        if let Some(v) = check().await {
            return Ok(v);
        }
        if start.elapsed() >= limit {
            return Err(E2eError::new(format!(
                "timed out after {limit:?} waiting for {what}"
            )));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A harness failure (Docker, an image build, a timeout, I/O).
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

/// Harness result.
pub type Result<T, E = E2eError> = std::result::Result<T, E>;
