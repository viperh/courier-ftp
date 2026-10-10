//! **Tests only** (`test-util`): an in-process SFTP v3 server over a temporary
//! directory (T22, T76).
//!
//! - [`SftpTestServer`]: the T20 russh [`TestServer`] with this SFTP server behind its
//!   `sftp` subsystem (password logon, any host key accepted by the test verifier);
//! - [`duplex_sftp_pair`]: the same SFTP server over an in-memory duplex stream (no
//!   SSH), for paused-time pipelining tests.
//!
//! The server is not russh-sftp's: that one answers one request at a time, which
//! hides pipelining. This one handles each request on arrival and sends the reply
//! [`SftpTestKnobs::per_request_latency`] later, so the in-flight depth a client
//! achieves is visible ([`ServerStats`]). Paths are chroot-like: `/` is the temporary
//! directory, `/scratch` exists and is empty.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use courier_ftp_core::{
    backend::{BackendContext, ConnectInfo},
    events::{EventReceiver, SessionId, channel as event_channel},
    model::{FtpEncryption, LogonType, Protocol, ServerAddress},
    secret::SecretString,
    settings::{DebugLevel, Settings},
};
use russh_sftp::{
    client::{Config, RawSftpSession},
    protocol::{FileAttributes, StatusCode},
};
use tempfile::TempDir;

use crate::{
    backend::{ServerLimits, SftpBackend},
    convert::SftpOp,
    ssh::{
        InsecureAcceptAnyHostKey,
        testing::{SubsystemHook, TestServer, TestServerConfig},
    },
};

mod server;

pub use server::normalize;

/// The test user.
pub const USER: &str = "tester";
/// The test user's password.
pub const PASSWORD: &str = "test-password";

/// Fault injection and behaviour switches (shared by every connection of a server;
/// change them at run time through [`ServerStats`]).
#[derive(Debug, Clone)]
pub struct SftpTestKnobs {
    /// Each reply leaves this long after its request arrived. Default 0.
    pub per_request_latency: Duration,
    /// Short reads: no READ answer is longer than this.
    pub max_read_len: Option<u32>,
    /// Per-READ caps, cycled (`reads % len`); for short-read property tests.
    pub read_caps: Vec<u32>,
    /// Advertise and serve `posix-rename@openssh.com`. Default true.
    pub advertise_posix_rename: bool,
    /// Advertise and answer `limits@openssh.com`.
    pub advertise_limits: Option<ServerLimits>,
    /// The next request of this operation fails with this status (one shot).
    pub fail_next: Option<(SftpOp, StatusCode)>,
    /// The next request of this operation is answered with a reply of the wrong type
    /// (one shot).
    pub bogus_reply_next: Option<SftpOp>,
    /// Record every READ/WRITE (offset, length).
    pub record_requests: bool,
    /// Names added to every real directory listing (hostile names).
    pub inject_names: Vec<String>,
    /// Virtual directories `path → (entry count, with longnames)`, generated on the fly.
    pub synthetic_dirs: HashMap<String, (u64, bool)>,
    /// Names per READDIR reply. Default 100 (OpenSSH).
    pub readdir_batch: usize,
    /// Owner and group shown in longnames.
    pub owner: String,
    pub group: String,
}

impl Default for SftpTestKnobs {
    fn default() -> Self {
        Self {
            per_request_latency: Duration::ZERO,
            max_read_len: None,
            read_caps: Vec::new(),
            advertise_posix_rename: true,
            advertise_limits: None,
            fail_next: None,
            bogus_reply_next: None,
            record_requests: false,
            inject_names: Vec::new(),
            synthetic_dirs: HashMap::new(),
            readdir_batch: 100,
            owner: "alice".to_owned(),
            group: "staff".to_owned(),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct StatsInner {
    pub(crate) record: bool,
    pub(crate) counts: HashMap<&'static str, u64>,
    pub(crate) reads: Vec<(u64, u32)>,
    pub(crate) writes: Vec<(u64, u32)>,
    pub(crate) reads_in_flight: u64,
    pub(crate) writes_in_flight: u64,
    pub(crate) bytes_in_flight: u64,
    pub(crate) max_reads_in_flight: u64,
    pub(crate) max_writes_in_flight: u64,
    pub(crate) max_bytes_in_flight: u64,
    pub(crate) max_read_len: u32,
    pub(crate) max_write_len: u32,
    pub(crate) closed: Vec<String>,
    pub(crate) extended: Vec<String>,
    pub(crate) setstats: Vec<FileAttributes>,
    pub(crate) connections_ended: u64,
}

#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) knobs: Mutex<SftpTestKnobs>,
    pub(crate) stats: Mutex<StatsInner>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What the server saw, and the live knobs.
#[derive(Debug, Clone)]
pub struct ServerStats {
    shared: Arc<Shared>,
}

impl ServerStats {
    fn new(knobs: SftpTestKnobs) -> Self {
        let record = knobs.record_requests;
        Self {
            shared: Arc::new(Shared {
                knobs: Mutex::new(knobs),
                stats: Mutex::new(StatsInner {
                    record,
                    ..StatsInner::default()
                }),
            }),
        }
    }

    /// Change the knobs.
    pub fn set_knobs(&self, f: impl FnOnce(&mut SftpTestKnobs)) {
        let mut k = lock(&self.shared.knobs);
        f(&mut k);
        lock(&self.shared.stats).record = k.record_requests;
    }

    /// The next `op` request fails with `code`.
    pub fn fail_next(&self, op: SftpOp, code: StatusCode) {
        self.set_knobs(|k| k.fail_next = Some((op, code)));
    }

    /// Requests seen of a wire type (`"READ"`, `"RENAME"`, `"EXTENDED"`, …).
    pub fn count(&self, packet: &str) -> u64 {
        lock(&self.shared.stats)
            .counts
            .get(packet)
            .copied()
            .unwrap_or(0)
    }

    /// Recorded READs `(offset, len)` (with `record_requests`).
    pub fn reads(&self) -> Vec<(u64, u32)> {
        lock(&self.shared.stats).reads.clone()
    }

    /// Recorded WRITEs `(offset, len)` (with `record_requests`).
    pub fn writes(&self) -> Vec<(u64, u32)> {
        lock(&self.shared.stats).writes.clone()
    }

    /// Most READs in flight at once (received, reply not yet sent).
    pub fn max_reads_in_flight(&self) -> u64 {
        lock(&self.shared.stats).max_reads_in_flight
    }

    /// Most WRITEs in flight at once.
    pub fn max_writes_in_flight(&self) -> u64 {
        lock(&self.shared.stats).max_writes_in_flight
    }

    /// Most READ lengths + WRITE payload bytes in flight at once.
    pub fn max_bytes_in_flight(&self) -> u64 {
        lock(&self.shared.stats).max_bytes_in_flight
    }

    /// Largest READ length requested.
    pub fn max_read_len(&self) -> u32 {
        lock(&self.shared.stats).max_read_len
    }

    /// Largest WRITE payload.
    pub fn max_write_len(&self) -> u32 {
        lock(&self.shared.stats).max_write_len
    }

    /// Handles named in CLOSE requests.
    pub fn closed(&self) -> Vec<String> {
        lock(&self.shared.stats).closed.clone()
    }

    /// `EXTENDED` request names.
    pub fn extended(&self) -> Vec<String> {
        lock(&self.shared.stats).extended.clone()
    }

    /// The attributes of every SETSTAT.
    pub fn setstats(&self) -> Vec<FileAttributes> {
        lock(&self.shared.stats).setstats.clone()
    }

    /// Clear the counters (not the knobs).
    pub fn reset(&self) {
        let mut s = lock(&self.shared.stats);
        let record = s.record;
        *s = StatsInner {
            record,
            ..StatsInner::default()
        };
    }
}

/// An SFTP server over one end of an in-memory duplex stream, serving `root`; the
/// other end is a (not yet initialised) client session. The server tasks run on the
/// current runtime (paused time works).
pub fn duplex_sftp_pair(knobs: SftpTestKnobs, root: &Path) -> (RawSftpSession, ServerStats) {
    let stats = ServerStats::new(knobs);
    let raw = duplex_session(&stats, root, 20);
    (raw, stats)
}

/// Another client session on the same server state as `stats`.
pub fn duplex_session(stats: &ServerStats, root: &Path, timeout_secs: u64) -> RawSftpSession {
    let (client, server) = tokio::io::duplex(1024 * 1024);
    server::serve(server, root.to_path_buf(), Arc::clone(&stats.shared));
    RawSftpSession::new_with_config(
        client,
        Config {
            request_timeout_secs: timeout_secs,
            max_packet_len: 270_336,
            ..Config::default()
        },
    )
}

/// A backend attached (no SSH) to a duplex SFTP server over `root`: `connect` is not
/// used; the session starts like after the subsystem request.
pub async fn duplex_backend(
    knobs: SftpTestKnobs,
    root: &Path,
    settings: Settings,
) -> (
    SftpBackend,
    ServerStats,
    courier_ftp_core::events::EventReceiver,
) {
    let timeout = u64::from(settings.connection.timeout_secs.max(1));
    let stats = ServerStats::new(knobs);
    let raw = duplex_session(&stats, root, timeout);
    let (ctx, rx) = test_context_with(settings);
    let address = ServerAddress::new(
        Protocol::Sftp,
        FtpEncryption::ExplicitIfAvailable,
        "duplex.invalid",
        None,
        Some(USER.to_owned()),
    )
    .unwrap();
    let info = ConnectInfo::quick(address, LogonType::Normal { password: None });
    let mut b = SftpBackend::new(
        Arc::new(info),
        ctx,
        Arc::new(InsecureAcceptAnyHostKey),
        None,
    );
    b.attach(raw).await.unwrap();
    (b, stats, rx)
}

/// The russh test server with the SFTP server behind `sftp`, over a temp directory.
#[derive(Debug)]
pub struct SftpTestServer {
    ssh: Mutex<Option<TestServer>>,
    addr: std::net::SocketAddr,
    root: TempDir,
    stats: ServerStats,
}

impl SftpTestServer {
    /// Start on `127.0.0.1:0`.
    pub async fn start(knobs: SftpTestKnobs) -> Self {
        Self::spawn(knobs)
    }

    /// As [`start`](Self::start), from synchronous code inside a runtime.
    pub fn spawn(knobs: SftpTestKnobs) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("scratch")).unwrap();
        let stats = ServerStats::new(knobs);
        let hook_root: PathBuf = root.path().to_path_buf();
        let hook_shared = Arc::clone(&stats.shared);
        let hook = SubsystemHook(Arc::new(move |stream| {
            server::serve(stream, hook_root.clone(), Arc::clone(&hook_shared));
        }));
        let ssh = TestServer::spawn(TestServerConfig {
            methods: vec!["password"],
            password: Some(PASSWORD.to_owned()),
            sftp: Some(hook),
            ..TestServerConfig::default()
        });
        Self {
            addr: ssh.addr(),
            ssh: Mutex::new(Some(ssh)),
            root,
            stats,
        }
    }

    /// The listening address.
    pub fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }

    /// The directory behind `/`.
    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// The local path of a remote path.
    pub fn local(&self, remote: &str) -> PathBuf {
        let mut p = self.root.path().to_path_buf();
        for c in normalize(remote).split('/').filter(|c| !c.is_empty()) {
            p.push(c);
        }
        p
    }

    /// Statistics and live knobs.
    pub fn stats(&self) -> &ServerStats {
        &self.stats
    }

    /// The SSH-level requests the russh server saw (T20 `TestServer::requests`).
    pub fn ssh_requests(&self) -> Vec<String> {
        lock(&self.ssh)
            .as_ref()
            .map(TestServer::requests)
            .unwrap_or_default()
    }

    /// Drop every open connection abruptly (TCP closed, no SSH disconnect); the server
    /// keeps accepting new ones.
    pub fn drop_connections(&self) {
        if let Some(ssh) = lock(&self.ssh).as_ref() {
            ssh.abort_connections();
        }
    }

    /// Kill the server: stop accepting and drop every connection (TCP closed, no
    /// SSH disconnect).
    pub fn kill(&self) {
        drop(lock(&self.ssh).take());
    }

    /// `sftp://tester@127.0.0.1:<port>` with the password.
    pub fn connect_info(&self) -> ConnectInfo {
        let address = ServerAddress::new(
            Protocol::Sftp,
            FtpEncryption::ExplicitIfAvailable,
            "127.0.0.1",
            Some(self.addr.port()),
            Some(USER.to_owned()),
        )
        .unwrap();
        ConnectInfo::quick(
            address,
            LogonType::Normal {
                password: Some(SecretString::from(PASSWORD)),
            },
        )
    }

    /// A backend for this server (host key accepted without verification).
    pub fn backend(&self, ctx: BackendContext) -> SftpBackend {
        SftpBackend::new(
            Arc::new(self.connect_info()),
            ctx,
            Arc::new(InsecureAcceptAnyHostKey),
            None,
        )
    }

    /// A backend with default settings and a throwaway event bus.
    pub fn backend_default(&self) -> SftpBackend {
        self.backend_with(Settings::default())
    }

    /// A backend with `settings`.
    pub fn backend_with(&self, settings: Settings) -> SftpBackend {
        let (ctx, rx) = test_context_with(settings);
        drain(rx);
        self.backend(ctx)
    }
}

/// A backend context for `settings` (core's `mock::test_context_with`, which needs
/// core's `test-util`).
pub fn test_context_with(settings: Settings) -> (BackendContext, EventReceiver) {
    let (events, rx) = event_channel(DebugLevel::Debug);
    let (_tx, settings) = tokio::sync::watch::channel(Arc::new(settings));
    (
        BackendContext {
            session: SessionId::next(),
            events,
            settings,
        },
        rx,
    )
}

/// Keep the receiver alive (prompts would otherwise be cancelled) and discard events.
fn drain(mut rx: EventReceiver) {
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
}
