//! Docker plumbing shared by the container fixtures: the daemon ping, fixture image
//! builds (tagged with a hash of the fixture directory), container IP lookup, `exec`,
//! logs and user-defined networks.
//!
//! Containers are reached by their bridge IP (on the default bridge or on a
//! [`TestNetwork`]); no port is published on the host.

use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    bollard::Docker,
    core::{ExecCommand, WaitFor, logs::LogFrame},
    runners::AsyncRunner,
};
use tokio::{net::TcpStream, sync::OnceCell};

use crate::{E2eError, Result, diag, keys};

/// How long a fixture image build may take.
pub const IMAGE_BUILD_LIMIT: Duration = Duration::from_secs(600);

/// The fixture images built from `tests/fixtures/<name>/`.
pub const FIXTURE_IMAGES: [&str; 3] = ["sshd", "ftpd", "proxy"];

fn connect() -> Result<Docker> {
    Docker::connect_with_defaults().map_err(|e| E2eError::new(format!("docker connect: {e}")))
}

/// Ping the Docker daemon (`DOCKER_HOST` or the default socket), `GET /_ping` with a
/// 5 s limit.
///
/// # Errors
/// The daemon is not reachable.
pub async fn ping_docker() -> Result<()> {
    let docker = connect()?;
    tokio::time::timeout(Duration::from_secs(5), docker.ping())
        .await
        .map_err(|_| E2eError::new("ping timed out after 5 s"))?
        .map_err(|e| E2eError::new(format!("ping: {e}")))?;
    Ok(())
}

/// A short hash of a fixture directory: SHA-256 over (relative path, mode, bytes) of
/// every file under `dir`, sorted by path; the first 16 hex digits.
///
/// # Errors
/// A file could not be read.
pub fn fixture_hash(dir: &Path) -> Result<String> {
    let mut files = Vec::new();
    collect(dir, &mut files)?;
    let mut entries: Vec<(String, PathBuf)> = files
        .into_iter()
        .map(|f| {
            let rel = f
                .strip_prefix(dir)
                .unwrap_or(&f)
                .to_string_lossy()
                .replace('\\', "/");
            (rel, f)
        })
        .collect();
    entries.sort();
    let mut hasher = Sha256::new();
    for (rel, file) in entries {
        hasher.update(rel.as_bytes());
        hasher.update([0]);
        hasher.update(file_mode(&file)?.to_be_bytes());
        hasher.update(std::fs::read(&file)?);
        hasher.update([0]);
    }
    Ok(hex::encode(&hasher.finalize()[..8]))
}

#[cfg(unix)]
fn file_mode(path: &Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(std::fs::metadata(path)?.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn file_mode(path: &Path) -> Result<u32> {
    Ok(u32::from(std::fs::metadata(path)?.permissions().readonly()))
}

fn collect(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            collect(&entry?.path(), out)?;
        }
    } else {
        out.push(path.to_owned());
    }
    Ok(())
}

/// One image build per process: `Ok((name, tag))` or the error text.
type ImageCell = OnceCell<std::result::Result<(String, String), String>>;

fn image_env_var(which: &str) -> String {
    format!("COURIER_E2E_{}_IMAGE", which.to_ascii_uppercase())
}

/// `(name, tag)` of fixture image `which` (`"sshd"`, `"ftpd"`, `"proxy"`): the
/// override `COURIER_E2E_<WHICH>_IMAGE=name:tag`, else `courier-ftp-e2e-<which>:<hash>`
/// built from `tests/fixtures/<which>/` with `docker build` once per process (skipped
/// when the image already exists; 600 s limit).
///
/// # Errors
/// Unknown fixture, or the build failed.
pub async fn image(which: &str) -> Result<(String, String)> {
    static CELLS: OnceLock<Mutex<HashMap<String, Arc<ImageCell>>>> = OnceLock::new();
    if !FIXTURE_IMAGES.contains(&which) {
        return Err(E2eError::new(format!(
            "unknown fixture image {which:?} (expected one of {FIXTURE_IMAGES:?})"
        )));
    }
    let cell = Arc::clone(
        CELLS
            .get_or_init(Mutex::default)
            .lock()
            .entry(which.to_owned())
            .or_default(),
    );
    cell.get_or_init(|| async { build_image(which).await.map_err(|e| e.0) })
        .await
        .clone()
        .map_err(E2eError)
}

/// Split `name:tag` (a registry port is not a tag: `host:5000/name` → `latest`).
fn split_image(image: &str) -> (String, String) {
    match image.rsplit_once(':') {
        Some((name, tag)) if !tag.contains('/') => (name.to_owned(), tag.to_owned()),
        _ => (image.to_owned(), "latest".to_owned()),
    }
}

async fn build_image(which: &str) -> Result<(String, String)> {
    if let Ok(image) = std::env::var(image_env_var(which))
        && !image.is_empty()
    {
        return Ok(split_image(&image));
    }
    let dir = keys::fixtures_dir().join(which);
    let name = format!("courier-ftp-e2e-{which}");
    let tag = fixture_hash(&dir)?;
    let full = format!("{name}:{tag}");
    if connect()?.inspect_image(&full).await.is_ok() {
        return Ok((name, tag));
    }
    let mut cmd = tokio::process::Command::new("docker");
    cmd.args(["build", "--quiet", "-t", &full])
        .arg(&dir)
        .kill_on_drop(true);
    let out = tokio::time::timeout(IMAGE_BUILD_LIMIT, cmd.output())
        .await
        .map_err(|_| {
            E2eError::new(format!(
                "building {full} took longer than {IMAGE_BUILD_LIMIT:?}"
            ))
        })?
        .map_err(|e| E2eError::new(format!("running `docker build` for {full}: {e}")))?;
    if !out.status.success() {
        return Err(E2eError::new(format!(
            "`docker build -t {full} {}` failed ({}):\n{}",
            dir.display(),
            out.status,
            diag::tail(&String::from_utf8_lossy(&out.stderr), 60)
        )));
    }
    Ok((name, tag))
}

/// A user-defined bridge network `cftp-e2e-<uuid>`. Containers join it by name
/// (`network: Some(net.name().into())` in their options); `testcontainers` creates it
/// with the first container and removes it with the last one. Dropping the handle also
/// removes it (best effort), in case no container used it.
#[derive(Debug)]
pub struct TestNetwork {
    name: String,
}

impl TestNetwork {
    /// A fresh, unique network name (requires a reachable daemon).
    ///
    /// # Errors
    /// Docker is unavailable.
    pub async fn new() -> Result<Self> {
        ping_docker().await?;
        Ok(Self {
            name: format!("cftp-e2e-{}", uuid::Uuid::new_v4().simple()),
        })
    }

    /// The network name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker")
            .args(["network", "rm", &self.name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// The result of an `exec` in a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// Exit code (`-1` if Docker did not report one in time).
    pub code: i64,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl ExecOutput {
    /// Whether the command exited with 0.
    pub fn success(&self) -> bool {
        self.code == 0
    }
}

/// How to start a fixture container.
#[derive(Debug, Clone)]
pub(crate) struct FixtureSpec {
    /// Image `(name, tag)`.
    pub image: (String, String),
    /// What the container is (for diagnostics), e.g. `"ftpd vsftpd-plain"`.
    pub label: String,
    /// Environment.
    pub env: Vec<(String, String)>,
    /// Network to join (default bridge when `None`).
    pub network: Option<String>,
    /// Capabilities to add.
    pub cap_add: Vec<String>,
}

/// A running fixture container: its IP on its network, logs, `exec`. Removed when
/// dropped; when the test is failing, the last 200 log lines are dumped first.
pub(crate) struct Fixture {
    container: ContainerAsync<GenericImage>,
    label: String,
    ip: IpAddr,
    collected: Arc<Mutex<Vec<u8>>>,
}

impl std::fmt::Debug for Fixture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fixture")
            .field("id", &self.container.id())
            .field("label", &self.label)
            .field("ip", &self.ip)
            .finish_non_exhaustive()
    }
}

impl Fixture {
    /// Start the container and look up its IP (not waiting for any service).
    pub(crate) async fn start(spec: FixtureSpec) -> Result<Self> {
        let (name, tag) = spec.image;
        let collected = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&collected);
        let mut req = GenericImage::new(name, tag)
            .with_wait_for(WaitFor::Nothing)
            .with_container_name(format!("cftp-e2e-{}", uuid::Uuid::new_v4().simple()))
            .with_startup_timeout(Duration::from_secs(120))
            .with_log_consumer(move |frame: &LogFrame| {
                let bytes = match frame {
                    LogFrame::StdOut(b) | LogFrame::StdErr(b) => b,
                };
                sink.lock().extend_from_slice(bytes);
            });
        for (k, v) in spec.env {
            req = req.with_env_var(k, v);
        }
        for cap in spec.cap_add {
            req = req.with_cap_add(cap);
        }
        if let Some(network) = &spec.network {
            req = req.with_network(network.clone());
        }
        let container = req
            .start()
            .await
            .map_err(|e| E2eError::new(format!("starting {}: {e}", spec.label)))?;
        let ip = container_ip(container.id(), spec.network.as_deref()).await?;
        Ok(Self {
            container,
            label: spec.label,
            ip,
            collected,
        })
    }

    /// The container IP on its network.
    pub(crate) fn ip(&self) -> IpAddr {
        self.ip
    }

    /// The container id.
    pub(crate) fn id(&self) -> &str {
        self.container.id()
    }

    /// Run `argv` in the container.
    pub(crate) async fn exec_argv(&self, argv: &[&str]) -> Result<ExecOutput> {
        let mut res = self
            .container
            .exec(ExecCommand::new(argv.iter().copied()))
            .await?;
        let stdout = String::from_utf8_lossy(&res.stdout_to_vec().await?).into_owned();
        let stderr = String::from_utf8_lossy(&res.stderr_to_vec().await?).into_owned();
        let res = &res;
        let code = crate::poll_until(
            "exec exit code",
            crate::timeout(),
            Duration::from_millis(20),
            || async move { res.exit_code().await.ok().flatten() },
        )
        .await
        .unwrap_or(-1);
        Ok(ExecOutput {
            code,
            stdout,
            stderr,
        })
    }

    /// `sh -c cmd` as `user`.
    pub(crate) async fn exec_as(&self, user: &str, cmd: &str) -> Result<ExecOutput> {
        self.exec_argv(&["runuser", "-u", user, "--", "sh", "-c", cmd])
            .await
    }

    /// `sh -c cmd` as root.
    pub(crate) async fn exec_root(&self, cmd: &str) -> Result<ExecOutput> {
        self.exec_argv(&["sh", "-c", cmd]).await
    }

    /// `sha256sum` of a file in the container (hex).
    pub(crate) async fn sha256_of(&self, path: &str) -> Result<String> {
        let out = self.exec_argv(&["sha256sum", "--", path]).await?;
        out.stdout
            .split_whitespace()
            .next()
            .filter(|h| h.len() == 64 && out.success())
            .map(str::to_owned)
            .ok_or_else(|| E2eError::new(format!("sha256sum {path}: {out:?}")))
    }

    /// The complete log (stdout and stderr).
    pub(crate) async fn logs(&self) -> Result<String> {
        let out = self.container.stdout_to_vec().await?;
        let err = self.container.stderr_to_vec().await?;
        Ok(format!(
            "{}{}",
            String::from_utf8_lossy(&out),
            String::from_utf8_lossy(&err)
        ))
    }

    /// Stop the container (SIGTERM, SIGKILL after 5 s).
    pub(crate) async fn stop(&self) -> Result<()> {
        Ok(self.container.stop_with_timeout(Some(5)).await?)
    }

    /// Start a stopped container again; its IP is looked up again.
    pub(crate) async fn start_again(&mut self, network: Option<&str>) -> Result<()> {
        self.container.start().await?;
        self.ip = container_ip(self.container.id(), network).await?;
        Ok(())
    }

    /// Dump the last 200 log lines ([`diag::dump`]).
    pub(crate) fn dump_logs(&self) {
        let logs = docker_cli_logs(self.container.id())
            .unwrap_or_else(|| String::from_utf8_lossy(&self.collected.lock()).into_owned());
        diag::dump(
            &format!("docker logs {} ({}, {})", self.label, self.ip, self.id()),
            &diag::tail(&logs, 200),
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if diag::failing() {
            self.dump_logs();
        }
    }
}

/// `docker logs <id>` through the CLI (usable from `Drop`).
fn docker_cli_logs(id: &str) -> Option<String> {
    let out = std::process::Command::new("docker")
        .args(["logs", "--tail", "400", id])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ))
}

/// The IP of container `id` on `network` (or on its only/first network).
async fn container_ip(id: &str, network: Option<&str>) -> Result<IpAddr> {
    let docker = connect()?;
    let info = docker
        .inspect_container(id, None)
        .await
        .map_err(|e| E2eError::new(format!("inspect {id}: {e}")))?;
    let networks = info
        .network_settings
        .and_then(|s| s.networks)
        .unwrap_or_default();
    let entry = match network {
        Some(n) => networks.get(n),
        None => networks.get("bridge").or_else(|| networks.values().next()),
    };
    let ip = entry
        .and_then(|e| e.ip_address.clone())
        .filter(|ip| !ip.is_empty())
        .ok_or_else(|| {
            E2eError::new(format!(
                "container {id} has no IP on {network:?} (networks: {:?})",
                networks.keys().collect::<Vec<_>>()
            ))
        })?;
    ip.parse()
        .map_err(|e| E2eError::new(format!("container {id} IP {ip:?}: {e}")))
}

/// The gateway (the runner, seen from the container) of container `id`'s network.
pub(crate) async fn gateway_ip(id: &str) -> Result<IpAddr> {
    let docker = connect()?;
    let info = docker
        .inspect_container(id, None)
        .await
        .map_err(|e| E2eError::new(format!("inspect {id}: {e}")))?;
    info.network_settings
        .and_then(|s| s.networks)
        .and_then(|n| n.into_values().find_map(|e| e.gateway))
        .and_then(|g| g.parse().ok())
        .ok_or_else(|| E2eError::new(format!("container {id} has no gateway")))
}

/// Connect to `addr` and read the first line the server sends (2 s limits).
pub(crate) async fn read_banner(addr: std::net::SocketAddr) -> std::io::Result<String> {
    use tokio::io::AsyncReadExt;
    let mut stream = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
        .await
        .map_err(|_| std::io::Error::other("connect timed out"))??;
    let mut buf = vec![0_u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .map_err(|_| std::io::Error::other("no banner"))??;
    Ok(String::from_utf8_lossy(&buf[..n]).trim().to_owned())
}

/// Poll `addr` every 100 ms until its banner satisfies `ok` ([`crate::timeout`]).
pub(crate) async fn wait_banner(
    fixture: &Fixture,
    addr: std::net::SocketAddr,
    ok: impl Fn(&str) -> bool,
) -> Result<String> {
    let last = Mutex::new(String::new());
    let (last_ref, ok) = (&last, &ok);
    let got = crate::poll_until(
        &format!("a banner from {} at {addr}", fixture.label),
        crate::timeout(),
        Duration::from_millis(100),
        || async move {
            match read_banner(addr).await {
                Ok(b) if ok(&b) => Some(b),
                Ok(b) => {
                    *last_ref.lock() = format!("unexpected banner {b:?}");
                    None
                }
                Err(e) => {
                    *last_ref.lock() = e.to_string();
                    None
                }
            }
        },
    )
    .await;
    got.map_err(|mut e| {
        e.last = format!(
            "{}\n--- container log ---\n{}",
            last.lock(),
            diag::tail(&String::from_utf8_lossy(&fixture.collected.lock()), 40)
        );
        e.into()
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn fixture_hash_changes_with_content_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("Dockerfile"), b"FROM x\n").unwrap();
        std::fs::write(dir.path().join("sub/run.sh"), b"#!/bin/sh\n").unwrap();
        let h0 = fixture_hash(dir.path()).unwrap();
        assert_eq!(h0.len(), 16);
        assert_eq!(h0, fixture_hash(dir.path()).unwrap(), "stable");

        std::fs::write(dir.path().join("sub/run.sh"), b"#!/bin/sh\n#").unwrap();
        let h1 = fixture_hash(dir.path()).unwrap();
        assert_ne!(h0, h1, "content change");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let p = dir.path().join("sub/run.sh");
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode ^ 0o100)).unwrap();
            assert_ne!(h1, fixture_hash(dir.path()).unwrap(), "mode change");
        }
    }

    #[test]
    fn image_override_splits_name_and_tag() {
        assert_eq!(
            split_image("courier-ftp-e2e-sshd:ci"),
            ("courier-ftp-e2e-sshd".into(), "ci".into())
        );
        assert_eq!(split_image("plain"), ("plain".into(), "latest".into()));
        assert_eq!(
            split_image("localhost:5000/img"),
            ("localhost:5000/img".into(), "latest".into())
        );
        assert_eq!(image_env_var("ftpd"), "COURIER_E2E_FTPD_IMAGE");
    }
}
