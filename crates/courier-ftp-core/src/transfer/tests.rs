//! Engine tests: mock servers with artificial latency and paused tokio time,
//! plus a real-filesystem round trip.

use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use pretty_assertions::assert_eq;
use time::OffsetDateTime;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::{
    Result,
    backend::{Backend, BackendFactory, ConnectInfo, MockServer, WriteMode},
    events::{
        self, CoreEvent, EventReceiver, EventSender, QueueStats, SessionId, TransferId,
        TransferProgress, TransferState,
    },
    local::{LocalBackend, local_to_remote},
    model::{Direction, LocalPath, LogonType, Protocol, RemotePath, ServerAddress},
    queue::{ItemState, NewItem, Priority, Queue, QueueItem, QueueList, QueueServer, SharedQueue},
    settings::Settings,
};

// ------------------------------------------------------------------ fixtures

/// Routes connections to one mock server per host name.
struct Servers(HashMap<String, MockServer>);

impl BackendFactory for Servers {
    fn create(&self, info: &ConnectInfo, _: SessionId, _: EventSender) -> Box<dyn Backend> {
        Box::new(self.0[&info.address.host].backend())
    }
}

/// Quickconnect servers with optional per-host limits.
#[derive(Default)]
struct Resolver {
    limits: HashMap<String, u32>,
}

#[async_trait]
impl ServerResolver for Resolver {
    async fn resolve(&self, server: &QueueServer, _: &CancellationToken) -> Result<ConnectInfo> {
        match server {
            QueueServer::Quick { address, .. } => {
                Ok(ConnectInfo::new(address.clone(), LogonType::Anonymous))
            }
            QueueServer::Site(_) => unreachable!(),
        }
    }

    fn connection_limit(&self, server: &QueueServer) -> Option<u32> {
        match server {
            QueueServer::Quick { address, .. } => self.limits.get(&address.host).copied(),
            QueueServer::Site(_) => None,
        }
    }
}

fn server(host: &str) -> QueueServer {
    QueueServer::Quick {
        address: ServerAddress::new(Protocol::Sftp, host),
        password: None,
    }
}

fn base() -> PathBuf {
    std::env::temp_dir().join("courier-ftp-t41")
}

fn local_path(name: &str) -> LocalPath {
    LocalPath::new(base().join(name))
}

/// The key of a local file in the mock "local" server.
fn local_key(name: &str) -> String {
    local_to_remote(&base().join(name))
        .unwrap()
        .as_str()
        .to_owned()
}

fn remote_key(name: &str) -> String {
    format!("/r/{name}")
}

/// Deterministic test data.
fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x.to_le_bytes()[0]
        })
        .collect()
}

fn test_settings() -> Settings {
    let mut s = Settings::default();
    s.connection.keepalive = false;
    s.connection.retries = 2;
    s.connection.retry_delay_secs = 5;
    s.transfers.max_concurrent = 4;
    // Test files have no extension, which `Auto` would send as ASCII (no
    // resume).
    s.file_types.default_type = crate::settings::TransferTypeChoice::Binary;
    s
}

/// What the event collector keeps.
#[derive(Debug, Clone)]
enum Rec {
    Progress(TransferProgress),
    State(TransferId, TransferState),
    Finished(QueueStats),
    Log(String),
}

struct Harness {
    queue: SharedQueue,
    handle: EngineHandle,
    local: MockServer,
    remotes: HashMap<String, MockServer>,
    records: Arc<Mutex<Vec<(Instant, Rec)>>>,
    changes: Arc<AtomicUsize>,
    engine: tokio::task::JoinHandle<()>,
}

fn collect(mut rx: EventReceiver, records: Arc<Mutex<Vec<(Instant, Rec)>>>) {
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let rec = match event {
                CoreEvent::TransferProgress(p) => Rec::Progress(p),
                CoreEvent::TransferStateChanged { id, state } => Rec::State(id, state),
                CoreEvent::QueueFinished { stats } => Rec::Finished(stats),
                CoreEvent::Log(m) => Rec::Log(m.text),
                _ => continue,
            };
            records.lock().unwrap().push((Instant::now(), rec));
        }
    });
}

fn harness_with(
    hosts: &[&str],
    settings: Settings,
    resolver: Resolver,
    customize: impl FnOnce(EngineBuilder) -> EngineBuilder,
) -> Harness {
    let remotes: HashMap<String, MockServer> = hosts
        .iter()
        .map(|h| ((*h).to_owned(), MockServer::new()))
        .collect();
    for r in remotes.values() {
        r.add_dir("/r");
    }
    let local = MockServer::new();
    local.add_dir(&local_key(""));
    let queue: SharedQueue = Arc::new(Mutex::new(Queue::default()));
    let (tx, rx) = events::channel(2);
    let records = Arc::new(Mutex::new(Vec::new()));
    collect(rx, Arc::clone(&records));
    let changes = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&changes);
    let builder = TransferEngine::builder(
        Arc::clone(&queue),
        Arc::new(Servers(remotes.clone())),
        Arc::new(resolver),
        tx,
    )
    .settings(settings)
    .local_backends(Arc::new(local.clone()))
    .on_queue_changed(move || {
        counter.fetch_add(1, Ordering::Relaxed);
    });
    let (engine, handle) = customize(builder).build();
    Harness {
        queue,
        handle,
        local,
        remotes,
        records,
        changes,
        engine: engine.spawn(),
    }
}

fn harness(hosts: &[&str], settings: Settings) -> Harness {
    harness_with(hosts, settings, Resolver::default(), |b| b)
}

impl Harness {
    fn remote(&self, host: &str) -> &MockServer {
        &self.remotes[host]
    }

    fn download(&self, host: &str, name: &str, data: &[u8]) -> TransferId {
        self.remote(host).add_file(&remote_key(name), data);
        self.add(NewItem::file(
            server(host),
            Direction::Download,
            local_path(name),
            RemotePath::new(remote_key(name)),
            Some(data.len() as u64),
        ))
    }

    fn upload(&self, host: &str, name: &str, data: &[u8]) -> TransferId {
        self.local.add_file(&local_key(name), data);
        self.add(NewItem::file(
            server(host),
            Direction::Upload,
            local_path(name),
            RemotePath::new(remote_key(name)),
            Some(data.len() as u64),
        ))
    }

    fn add(&self, item: NewItem) -> TransferId {
        self.queue
            .lock()
            .unwrap()
            .add(item, OffsetDateTime::UNIX_EPOCH)
    }

    fn item(&self, id: TransferId) -> Option<QueueItem> {
        self.queue.lock().unwrap().get(id).cloned()
    }

    fn records(&self) -> Vec<(Instant, Rec)> {
        self.records.lock().unwrap().clone()
    }

    fn finished(&self) -> Option<QueueStats> {
        self.records().into_iter().find_map(|(_, r)| match r {
            Rec::Finished(s) => Some(s),
            _ => None,
        })
    }

    /// When each item became active, in order.
    fn starts(&self) -> Vec<(Instant, TransferId)> {
        self.records()
            .into_iter()
            .filter_map(|(t, r)| match r {
                Rec::State(id, TransferState::Active) => Some((t, id)),
                _ => None,
            })
            .collect()
    }

    fn progress_of(&self, id: TransferId) -> u64 {
        match self.item(id).map(|i| i.state) {
            Some(ItemState::Active { progress }) => progress.bytes,
            _ => 0,
        }
    }

    async fn wait_finished(&self) -> QueueStats {
        until(|| self.finished().is_some()).await;
        self.finished().unwrap()
    }

    async fn shutdown(self) {
        self.handle.shutdown();
        tokio::time::timeout(Duration::from_secs(30), self.engine)
            .await
            .expect("engine did not shut down")
            .unwrap();
    }
}

/// Waits (in tokio time) until `cond` holds.
async fn until(mut cond: impl FnMut() -> bool) {
    for _ in 0..200_000 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("condition not reached");
}

// ------------------------------------------------------------------ tests

#[test]
fn too_many_connections_detection() {
    assert!(is_too_many_connections(&crate::Error::reply(
        421,
        "Too many connections (8) from this IP"
    )));
    assert!(is_too_many_connections(&crate::Error::reply(
        530,
        "Sorry, the maximum number of clients (5) for this user are already connected."
    )));
    assert!(!is_too_many_connections(&crate::Error::reply(
        421,
        "Timeout - closing control connection"
    )));
    assert!(!is_too_many_connections(&crate::Error::reply(
        530,
        "Login incorrect."
    )));
}

#[tokio::test(start_paused = true)]
async fn downloads_and_uploads_are_byte_identical() {
    let h = harness(&["a"], test_settings());
    let sizes = [0, 1, 1000, BUFFER_SIZE, BUFFER_SIZE * 3 + 17];
    let mut expected = Vec::new();
    for (i, size) in sizes.iter().enumerate() {
        let down = pattern(*size, i as u32 + 1);
        let up = pattern(*size, i as u32 + 100);
        h.download("a", &format!("down{i}"), &down);
        h.upload("a", &format!("up{i}"), &up);
        expected.push((format!("down{i}"), down, format!("up{i}"), up));
    }
    h.handle.start();
    let stats = h.wait_finished().await;
    for (down_name, down, up_name, up) in &expected {
        assert_eq!(
            h.local.read_file(&local_key(down_name)).as_ref(),
            Some(down)
        );
        assert_eq!(
            h.remote("a").read_file(&remote_key(up_name)).as_ref(),
            Some(up)
        );
    }
    let total: usize = sizes.iter().sum::<usize>() * 2;
    assert_eq!(stats.files_ok, 10);
    assert_eq!(stats.files_failed, 0);
    assert_eq!(stats.bytes, total as u64);
    let q = h.queue.lock().unwrap().clone();
    assert_eq!(q.count(QueueList::Successful), 10);
    assert_eq!(q.count(QueueList::Queued), 0);
    assert!(
        !q.is_processing(),
        "processing stops when the queue finishes"
    );
    assert!(
        h.changes.load(Ordering::Relaxed) >= 10,
        "persister notified"
    );
    // Consecutive transfers reused the pooled connections.
    assert!(h.remote("a").connects() <= 4);
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn global_limit_is_never_exceeded() {
    let mut settings = test_settings();
    settings.transfers.max_concurrent = 3;
    let h = harness(&["a"], settings);
    h.remote("a")
        .set_latency(Duration::from_millis(20))
        .set_stream_pace(16 * 1024, Duration::from_millis(10));
    for i in 0..12 {
        h.download("a", &format!("f{i}"), &pattern(200_000, i));
    }
    let mut status = h.handle.watch_status();
    let peak_active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::clone(&peak_active);
    tokio::spawn(async move {
        while status.changed().await.is_ok() {
            let active = status.borrow().active;
            peak.fetch_max(active, Ordering::Relaxed);
        }
    });
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_ok, 12);
    assert_eq!(h.remote("a").peak_streams(), 3);
    assert!(h.remote("a").peak_connections() <= 3);
    assert_eq!(peak_active.load(Ordering::Relaxed), 3);
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn per_server_and_direction_limits() {
    let mut settings = test_settings();
    settings.transfers.max_concurrent = 4;
    settings.transfers.max_uploads = 1;
    let resolver = Resolver {
        limits: HashMap::from([("a".to_owned(), 1)]),
    };
    let h = harness_with(&["a", "b", "c"], settings, resolver, |b| b);
    for host in ["a", "b", "c"] {
        h.remote(host)
            .set_stream_pace(16 * 1024, Duration::from_millis(10));
    }
    h.local
        .set_stream_pace(16 * 1024, Duration::from_millis(10));
    for i in 0..3 {
        h.download("a", &format!("a{i}"), &pattern(100_000, i));
        h.upload("c", &format!("c{i}"), &pattern(100_000, i + 10));
    }
    for i in 0..4 {
        h.download("b", &format!("b{i}"), &pattern(100_000, i + 20));
    }
    let mut status = h.handle.watch_status();
    let peak_active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::clone(&peak_active);
    tokio::spawn(async move {
        while status.changed().await.is_ok() {
            let active = status.borrow().active;
            peak.fetch_max(active, Ordering::Relaxed);
        }
    });
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_ok, 10);
    assert_eq!(h.remote("a").peak_connections(), 1, "site limit");
    assert_eq!(h.remote("c").peak_streams(), 1, "upload limit");
    assert!(peak_active.load(Ordering::Relaxed) <= 4, "global limit");
    assert_eq!(peak_active.load(Ordering::Relaxed), 4);
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn priority_then_queue_order() {
    let mut settings = test_settings();
    settings.transfers.max_concurrent = 1;
    let h = harness(&["a"], settings);
    let ids: Vec<TransferId> = (0..5)
        .map(|i| h.download("a", &format!("f{i}"), b"data"))
        .collect();
    {
        let mut q = h.queue.lock().unwrap();
        q.set_priority(&[ids[1]], Priority::Low);
        q.set_priority(&[ids[2]], Priority::Highest);
        q.set_priority(&[ids[3]], Priority::High);
        q.set_priority(&[ids[4]], Priority::High);
    }
    h.handle.start();
    h.wait_finished().await;
    let order: Vec<TransferId> = h.starts().into_iter().map(|(_, id)| id).collect();
    assert_eq!(order, [ids[2], ids[3], ids[4], ids[0], ids[1]]);
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn transient_failure_is_retried_and_resumes_at_offset() {
    let h = harness(&["a"], test_settings());
    let data = pattern(1_000_000, 7);
    h.remote("a")
        .set_stream_pace(64 * 1024, Duration::from_millis(10))
        .fail_stream_after(300_000, io::ErrorKind::ConnectionReset);
    let id = h.download("a", "big", &data);
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_ok, 1);
    assert_eq!(h.local.read_file(&local_key("big")), Some(data));
    assert_eq!(h.remote("a").read_offsets(), [0, 300_000]);
    assert_eq!(
        h.local.write_modes(),
        [WriteMode::Truncate, WriteMode::ResumeAt(300_000)]
    );
    assert_eq!(h.item(id).unwrap().attempts, 1);
    let starts = h.starts();
    assert_eq!(starts.len(), 2);
    let gap = starts[1].0 - starts[0].0;
    assert!(
        gap >= Duration::from_secs(5),
        "retry delay respected: {gap:?}"
    );
    assert!(
        h.records()
            .iter()
            .any(|(_, r)| matches!(r, Rec::Log(t) if t.contains("retrying in 5 s")))
    );
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn permanent_failure_is_not_retried() {
    let h = harness(&["a"], test_settings());
    let id = h.download("a", "f", b"data");
    h.remote("a")
        .fail_next(crate::Error::reply(550, "Permission denied"));
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_failed, 1);
    let item = h.item(id).unwrap();
    assert_eq!(item.attempts, 1);
    match item.state {
        ItemState::Failed { error } => assert!(error.contains("550"), "{error}"),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(h.starts().len(), 1);
    assert_eq!(h.queue.lock().unwrap().count(QueueList::Failed), 1);
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn retries_back_off_then_fail_with_the_last_error() {
    let h = harness(&["a"], test_settings());
    let id = h.download("a", "f", b"data");
    for i in 0..3 {
        h.remote("a")
            .fail_connect(crate::Error::Connection(format!("refused {i}")));
    }
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_failed, 1);
    let starts: Vec<Instant> = h.starts().into_iter().map(|(t, _)| t).collect();
    assert_eq!(starts.len(), 3, "1 + connection.retries attempts");
    let gaps = [starts[1] - starts[0], starts[2] - starts[1]];
    assert!(gaps[0] >= Duration::from_secs(5) && gaps[0] < Duration::from_secs(6));
    assert!(gaps[1] >= Duration::from_secs(10) && gaps[1] < Duration::from_secs(11));
    let item = h.item(id).unwrap();
    assert_eq!(item.attempts, 3);
    assert_eq!(
        item.state,
        ItemState::Failed {
            error: "connection failed: refused 2".into()
        }
    );
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn cancel_stops_quickly_and_keeps_the_session() {
    let h = harness(&["a"], test_settings());
    let data = pattern(1_000_000, 3);
    h.remote("a")
        .set_stream_pace(16 * 1024, Duration::from_millis(10));
    let id = h.download("a", "f", &data);
    h.handle.start();
    until(|| h.progress_of(id) > 100_000).await;
    let cancelled_at = Instant::now();
    h.handle.cancel(id);
    let status = h.handle.watch_status();
    until(|| {
        let s = status.borrow();
        s.active == 0 && s.tasks == 0
    })
    .await;
    assert!(cancelled_at.elapsed() < Duration::from_secs(1));
    assert_eq!(h.item(id).unwrap().state, ItemState::Paused);
    assert_eq!(h.remote("a").open_streams(), 0);
    assert_eq!(
        h.remote("a").open_connections(),
        1,
        "session kept for reuse"
    );
    let partial = h.local.read_file(&local_key("f")).unwrap().len() as u64;
    assert!(partial > 0);

    // Only a paused item is left: the run counts as finished.
    until(|| h.finished().is_some()).await;
    h.records.lock().unwrap().clear();
    h.queue.lock().unwrap().resume(&[id]);
    h.handle.start();
    h.wait_finished().await;
    assert_eq!(h.local.read_file(&local_key("f")), Some(data));
    assert_eq!(h.remote("a").connects(), 1, "the pooled session was reused");
    assert_eq!(h.remote("a").read_offsets(), [0, partial]);
    assert_eq!(
        h.item(id).unwrap().attempts,
        0,
        "cancelling isn't an attempt"
    );
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn pause_all_holds_transfers_and_resume_all_continues() {
    let h = harness(&["a"], test_settings());
    let data = pattern(500_000, 5);
    h.remote("a")
        .set_stream_pace(16 * 1024, Duration::from_millis(10));
    let id = h.download("a", "f", &data);
    h.handle.start();
    until(|| h.progress_of(id) > 50_000).await;
    h.handle.pause_all();
    until(|| h.handle.status().paused).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let held = h.local.read_file(&local_key("f")).unwrap().len();
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(h.local.read_file(&local_key("f")).unwrap().len(), held);
    assert!(h.item(id).unwrap().state.is_active());
    h.handle.resume_all();
    h.wait_finished().await;
    assert_eq!(h.local.read_file(&local_key("f")), Some(data));
    assert_eq!(h.starts().len(), 1, "the transfer continued, not restarted");
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn progress_is_reported_at_most_10_hz() {
    let h = harness(&["a"], test_settings());
    let size = 2_000_000;
    h.remote("a")
        .set_stream_pace(8 * 1024, Duration::from_millis(5));
    let id = h.download("a", "f", &pattern(size, 9));
    h.handle.start();
    h.wait_finished().await;
    let progress: Vec<(Instant, TransferProgress)> = h
        .records()
        .into_iter()
        .filter_map(|(t, r)| match r {
            Rec::Progress(p) if p.id == id => Some((t, p)),
            _ => None,
        })
        .collect();
    let first = progress.first().unwrap().0;
    let last = progress.last().unwrap();
    let secs = (last.0 - first).as_secs_f64();
    #[allow(clippy::cast_precision_loss)]
    let n = progress.len() as f64;
    assert!(n >= 5.0, "{n} reports");
    assert!(n <= secs * 10.0 + 3.0, "{n} reports in {secs} s");
    assert_eq!(last.1.bytes_done, size as u64);
    assert_eq!(last.1.total, Some(size as u64));
    let mid = &progress[progress.len() / 2].1;
    // 8 KiB per 5 ms ≈ 1.6 MB/s.
    assert!(
        (1_400_000..1_800_000).contains(&mid.speed_bps),
        "{}",
        mid.speed_bps
    );
    assert!(mid.eta.is_some());
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn too_many_connections_lowers_the_limit_without_burning_attempts() {
    let h = harness(&["a"], test_settings());
    h.remote("a")
        .set_max_connections(2)
        .set_latency(Duration::from_millis(10))
        .set_stream_pace(16 * 1024, Duration::from_millis(10));
    for i in 0..6 {
        h.download("a", &format!("f{i}"), &pattern(100_000, i));
    }
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_ok, 6);
    assert_eq!(stats.files_failed, 0);
    let q = h.queue.lock().unwrap().clone();
    assert!(q.items(QueueList::Successful).all(|i| i.attempts == 0));
    assert_eq!(h.remote("a").peak_connections(), 2);
    assert!(
        h.records()
            .iter()
            .any(|(_, r)| matches!(r, Rec::Log(t) if t.contains("at most 2")))
    );
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_dead_pooled_connection_is_reconnected() {
    let h = harness(&["a"], test_settings());
    h.download("a", "one", b"first");
    h.handle.start();
    h.wait_finished().await;
    assert_eq!(h.remote("a").open_connections(), 1);
    h.records.lock().unwrap().clear();

    // The server dropped the idle connection.
    h.remote("a")
        .fail_next(crate::Error::Connection("idle timeout".into()));
    let id = h.download("a", "two", b"second");
    h.handle.start();
    h.wait_finished().await;
    assert_eq!(h.local.read_file(&local_key("two")).unwrap(), b"second");
    assert_eq!(h.item(id).unwrap().attempts, 0);
    assert_eq!(h.remote("a").connects(), 2);
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn stop_cancels_everything_without_leaking_tasks() {
    let mut settings = test_settings();
    settings.transfers.max_concurrent = 2;
    let h = harness(&["a"], settings);
    h.remote("a")
        .set_stream_pace(16 * 1024, Duration::from_millis(10));
    let ids: Vec<TransferId> = (0..3)
        .map(|i| h.download("a", &format!("f{i}"), &pattern(1_000_000, i)))
        .collect();
    h.handle.start();
    until(|| h.progress_of(ids[0]) > 50_000).await;
    let stopped_at = Instant::now();
    h.handle.stop();
    let status = h.handle.watch_status();
    until(|| status.borrow().tasks == 0 && status.borrow().active == 0).await;
    assert!(stopped_at.elapsed() < Duration::from_secs(1));
    let s = h.handle.status();
    assert!(!s.processing);
    for id in &ids {
        assert_eq!(h.item(*id).unwrap().state, ItemState::Queued);
    }
    assert_eq!(h.remote("a").open_streams(), 0);
    // Nothing starts while stopped.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(h.starts().len(), 2);
    assert!(h.finished().is_none());

    let remote = h.remote("a").clone();
    h.shutdown().await;
    assert_eq!(remote.open_connections(), 0, "shutdown closes the pool");
}

#[tokio::test(start_paused = true)]
async fn idle_connections_close_after_30_seconds() {
    let h = harness(&["a"], test_settings());
    h.download("a", "f", b"x");
    h.handle.start();
    h.wait_finished().await;
    assert_eq!(h.remote("a").open_connections(), 1);
    tokio::time::sleep(Duration::from_secs(29)).await;
    assert_eq!(h.remote("a").open_connections(), 1);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(h.remote("a").open_connections(), 0);
    assert_eq!(h.handle.status().tasks, 0);
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn disk_full_fails_permanently_and_pauses_the_queue() {
    let mut settings = test_settings();
    settings.transfers.max_concurrent = 1;
    let h = harness(&["a"], settings);
    h.local.fail_stream_after(1000, io::ErrorKind::StorageFull);
    let first = h.download("a", "f1", &pattern(5000, 1));
    let second = h.download("a", "f2", &pattern(5000, 2));
    h.handle.start();
    until(|| h.handle.status().paused).await;
    tokio::time::sleep(Duration::from_secs(30)).await;
    let item = h.item(first).unwrap();
    assert_eq!(item.attempts, 1);
    match item.state {
        ItemState::Failed { error } => assert!(error.starts_with("local disk is full"), "{error}"),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(h.item(second).unwrap().state, ItemState::Queued);
    assert_eq!(h.starts().len(), 1);
    h.handle.resume_all();
    h.wait_finished().await;
    assert!(h.local.read_file(&local_key("f2")).is_some());
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn local_permission_error_is_a_clear_permanent_failure() {
    let h = harness(&["a"], test_settings());
    let id = h.download("a", "f", b"data");
    h.local.fail_next(crate::Error::PermissionDenied);
    h.handle.start();
    h.wait_finished().await;
    let item = h.item(id).unwrap();
    assert_eq!(
        item.state,
        ItemState::Failed {
            error: "local file: permission denied".into()
        }
    );
    assert_eq!(h.starts().len(), 1);
    h.shutdown().await;
}

/// Skips `skip*` files that exist and renames `ren*` ones.
struct TestPolicy;

#[async_trait]
impl ExistsPolicy for TestPolicy {
    async fn decide(
        &self,
        ctx: ExistsContext<'_>,
        _: &CancellationToken,
    ) -> Result<ExistsDecision> {
        let Some(target) = ctx.target else {
            return Ok(ExistsDecision::Overwrite);
        };
        Ok(if target.name.starts_with("skip") {
            ExistsDecision::Skip
        } else if target.name.starts_with("ren") {
            ExistsDecision::Rename {
                name: format!("{} (1)", target.name),
            }
        } else if ctx.can_resume && target.size < ctx.source.size {
            ExistsDecision::Resume {
                offset: target.size.unwrap_or(0),
            }
        } else {
            ExistsDecision::Overwrite
        })
    }
}

#[tokio::test(start_paused = true)]
async fn exists_policy_hook_decides() {
    let h = harness_with(&["a"], test_settings(), Resolver::default(), |b| {
        b.exists_policy(Arc::new(TestPolicy))
    });
    h.local.add_file(&local_key("skip"), b"old");
    h.local.add_file(&local_key("ren"), b"old");
    h.local.add_file(&local_key("res"), b"0123");
    let skip = h.download("a", "skip", b"new");
    h.download("a", "ren", b"new");
    h.download("a", "res", b"0123456789");
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_skipped, 1);
    assert_eq!(stats.files_ok, 2);
    assert!(h.item(skip).is_none(), "skipped items leave the queue");
    assert!(
        h.records()
            .iter()
            .any(|(_, r)| matches!(r, Rec::State(id, TransferState::Skipped) if *id == skip))
    );
    assert_eq!(h.local.read_file(&local_key("skip")).unwrap(), b"old");
    assert_eq!(h.local.read_file(&local_key("ren")).unwrap(), b"old");
    assert_eq!(h.local.read_file(&local_key("ren (1)")).unwrap(), b"new");
    assert_eq!(h.local.read_file(&local_key("res")).unwrap(), b"0123456789");
    assert!(h.remote("a").read_offsets().contains(&4));
    assert_eq!(stats.bytes, 3 + 6);
    h.shutdown().await;
}

/// Counts what passes through and caps chunks at 1000 bytes.
#[derive(Default)]
struct CountingLimiter {
    bytes: AtomicU64,
    largest: AtomicU64,
    settings_seen: AtomicU32,
}

#[async_trait]
impl RateLimiter for CountingLimiter {
    async fn acquire(&self, _: Direction, bytes: usize) {
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.largest.fetch_max(bytes as u64, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    fn chunk_size(&self, _: Direction, _: usize) -> usize {
        1000
    }

    fn settings_changed(&self, _: &crate::settings::TransferSettings) {
        self.settings_seen.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test(start_paused = true)]
async fn rate_limiter_hook_sees_every_chunk() {
    let limiter = Arc::new(CountingLimiter::default());
    let l = Arc::clone(&limiter);
    let h = harness_with(&["a"], test_settings(), Resolver::default(), |b| {
        b.rate_limiter(l)
    });
    h.download("a", "f", &pattern(10_500, 1));
    h.upload("a", "g", &pattern(2_000, 2));
    h.handle.settings_changed(test_settings());
    h.handle.start();
    h.wait_finished().await;
    assert_eq!(limiter.bytes.load(Ordering::Relaxed), 12_500);
    assert_eq!(limiter.largest.load(Ordering::Relaxed), 1000);
    assert_eq!(
        limiter.settings_seen.load(Ordering::Relaxed),
        2,
        "build + command"
    );
    h.shutdown().await;
}

/// Expands a placeholder into the files of its remote directory.
struct ListExpander;

#[async_trait]
impl DirExpander for ListExpander {
    async fn expand(
        &self,
        item: &QueueItem,
        remote: &mut dyn Backend,
        _: &mut dyn Backend,
        cancel: &CancellationToken,
    ) -> Result<Vec<NewItem>> {
        let listing = remote.list(&item.remote, cancel.clone()).await?;
        Ok(listing
            .entries
            .into_iter()
            .map(|e| {
                NewItem::file(
                    item.server.clone(),
                    item.direction,
                    item.local.join(&e.name),
                    item.remote.join(&e.name).unwrap(),
                    e.size,
                )
            })
            .collect())
    }
}

fn placeholder(host: &str) -> NewItem {
    let mut item = NewItem::file(
        server(host),
        Direction::Download,
        local_path("dir"),
        RemotePath::new("/r/dir"),
        None,
    );
    item.is_dir_placeholder = true;
    item
}

#[tokio::test(start_paused = true)]
async fn placeholders_wait_without_an_expander() {
    let h = harness(&["a"], test_settings());
    let dir = h.add(placeholder("a"));
    h.download("a", "f", b"x");
    h.handle.start();
    until(|| h.queue.lock().unwrap().count(QueueList::Successful) == 1).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(h.item(dir).unwrap().state, ItemState::Queued);
    assert!(
        h.finished().is_some(),
        "a parked placeholder doesn't block the finish"
    );
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn dir_expander_hook_replaces_placeholders() {
    let h = harness_with(&["a"], test_settings(), Resolver::default(), |b| {
        b.dir_expander(Arc::new(ListExpander))
    });
    h.remote("a")
        .add_file("/r/dir/x", b"xx")
        .add_file("/r/dir/y", b"yyy");
    h.local.add_dir(&local_key("dir"));
    h.add(placeholder("a"));
    h.handle.start();
    let stats = h.wait_finished().await;
    assert_eq!(stats.files_ok, 2);
    let y = local_to_remote(&base().join("dir").join("y")).unwrap();
    assert_eq!(h.local.read_file(y.as_str()).unwrap(), b"yyy");
    h.shutdown().await;
}

/// The "remote" side is a directory on the real filesystem.
struct LocalRemote;

impl BackendFactory for LocalRemote {
    fn create(&self, _: &ConnectInfo, _: SessionId, _: EventSender) -> Box<dyn Backend> {
        Box::new(LocalBackend::new())
    }
}

#[tokio::test]
async fn real_files_round_trip_byte_identical() {
    let tmp = tempfile::tempdir().unwrap();
    let local_dir = tmp.path().join("local");
    let remote_dir = tmp.path().join("remote");
    std::fs::create_dir_all(&local_dir).unwrap();
    std::fs::create_dir_all(&remote_dir).unwrap();
    let sizes = [0usize, 10, BUFFER_SIZE + 1, 1_000_000];
    for (i, size) in sizes.iter().enumerate() {
        std::fs::write(local_dir.join(format!("up{i}")), pattern(*size, i as u32)).unwrap();
        std::fs::write(
            remote_dir.join(format!("down{i}")),
            pattern(*size, 50 + i as u32),
        )
        .unwrap();
    }
    // The existing target is overwritten (truncated), not appended to.
    std::fs::write(local_dir.join("down3"), vec![1u8; 2_000_000]).unwrap();

    let queue: SharedQueue = Arc::new(Mutex::new(Queue::default()));
    let (tx, mut rx) = events::channel(2);
    let mut settings = test_settings();
    settings.transfers.preserve_timestamps = true;
    let (engine, handle) = TransferEngine::builder(
        Arc::clone(&queue),
        Arc::new(LocalRemote),
        Arc::new(Resolver::default()),
        tx,
    )
    .settings(settings)
    .build();
    let task = engine.spawn();
    {
        let mut q = queue.lock().unwrap();
        for i in 0..sizes.len() {
            let remote = |name: String| local_to_remote(&remote_dir.join(name)).unwrap();
            q.add(
                NewItem::file(
                    server("fs"),
                    Direction::Upload,
                    LocalPath::new(local_dir.join(format!("up{i}"))),
                    remote(format!("up{i}")),
                    None,
                ),
                OffsetDateTime::UNIX_EPOCH,
            );
            q.add(
                NewItem::file(
                    server("fs"),
                    Direction::Download,
                    LocalPath::new(local_dir.join(format!("down{i}"))),
                    remote(format!("down{i}")),
                    None,
                ),
                OffsetDateTime::UNIX_EPOCH,
            );
        }
    }
    handle.start();
    let stats = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(CoreEvent::QueueFinished { stats }) = rx.recv().await {
                return stats;
            }
        }
    })
    .await
    .expect("queue did not finish");
    assert_eq!(stats.files_ok, 8, "{stats:?}");
    for i in 0..sizes.len() {
        let up_src = std::fs::read(local_dir.join(format!("up{i}"))).unwrap();
        let up_dst = std::fs::read(remote_dir.join(format!("up{i}"))).unwrap();
        assert!(up_src == up_dst, "upload {i} differs");
        let down_src = std::fs::read(remote_dir.join(format!("down{i}"))).unwrap();
        let down_dst = std::fs::read(local_dir.join(format!("down{i}"))).unwrap();
        assert!(down_src == down_dst, "download {i} differs");
    }
    // The local backend reports mtimes in milliseconds.
    let mtime = |p: PathBuf| {
        std::fs::metadata(p)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    };
    assert_eq!(
        mtime(remote_dir.join("down1")),
        mtime(local_dir.join("down1")),
        "preserve_timestamps"
    );
    handle.shutdown();
    task.await.unwrap();
}
