//! T42 tests: the `decide` table, renaming, the policy's ask flow and
//! remembered answers, and engine-level runs (apply to all across workers,
//! rename, a 5 GiB resume past 4 GiB).

use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
    },
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use pretty_assertions::assert_eq;
use time::{OffsetDateTime, macros::datetime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::*;
use crate::{
    backend::{
        Backend, BackendFactory, Capabilities, ConnectInfo, Listing, MockServer, ReadStream,
        TransferOpts, WriteStream,
    },
    events::{self, CoreEvent, EventReceiver, EventSender, QueueStats},
    local::local_to_remote,
    model::{LocalPath, Precision, Protocol, ServerAddress, Timestamp},
    queue::{NewItem, Queue, QueueItem, QueueServer, SharedQueue},
    settings::{Settings, TransferSettings, TransferTypeChoice},
    transfer::{LocalBackendFactory, QuickResolver, TransferEngine},
};

// ------------------------------------------------------------ decide table

const T: OffsetDateTime = datetime!(2026-05-01 12:00:30 UTC);

fn entry(size: Option<u64>, time: Option<OffsetDateTime>, precision: Precision) -> Entry {
    let mut e = Entry::file("f.txt", 0);
    e.size = size;
    e.modified = time.map(|t| Timestamp::new(t, precision));
    e
}

/// Every action against every kind of target.
#[test]
fn decide_table() {
    use Decision::{AskUser as A, Rename as R, Skip as S};
    const C: Decision = Decision::Transfer {
        mode: WriteMode::Create,
    };
    const O: Decision = Decision::Transfer {
        mode: WriteMode::Truncate,
    };
    const RES: Decision = Decision::Transfer {
        mode: WriteMode::ResumeAt(40),
    };
    let hour = time::Duration::hours(1);
    let source = entry(Some(100), Some(T), Precision::Second);
    let targets: [(&str, Option<Entry>); 8] = [
        ("missing", None),
        ("smaller", Some(entry(Some(40), Some(T), Precision::Second))),
        ("equal", Some(entry(Some(100), Some(T), Precision::Second))),
        ("larger", Some(entry(Some(200), Some(T), Precision::Second))),
        (
            "older",
            Some(entry(Some(100), Some(T - hour), Precision::Second)),
        ),
        (
            "newer",
            Some(entry(Some(100), Some(T + hour), Precision::Second)),
        ),
        (
            "unknown size",
            Some(entry(None, Some(T), Precision::Second)),
        ),
        (
            "unknown time",
            Some(entry(Some(100), None, Precision::Second)),
        ),
    ];
    use ExistsAction as E;
    #[rustfmt::skip]
    let table: [(ExistsAction, [Decision; 8]); 8] = [
        //                           missing smaller equal larger older newer ?size ?time
        (E::Ask,                           [C, A,   A, A, A, A, A, A]),
        (E::Overwrite,                     [C, O,   O, O, O, O, O, O]),
        (E::OverwriteIfNewer,              [C, S,   S, S, O, S, S, O]),
        (E::OverwriteIfSizeDiffers,        [C, O,   S, O, S, S, O, S]),
        (E::OverwriteIfNewerOrSizeDiffers, [C, O,   S, O, O, S, O, O]),
        (E::Resume,                        [C, RES, S, S, S, S, A, S]),
        (E::Rename,                        [C, R,   R, R, R, R, R, R]),
        (E::Skip,                          [C, S,   S, S, S, S, S, S]),
    ];
    for (action, expected) in table {
        for ((label, target), want) in targets.iter().zip(expected) {
            assert_eq!(
                decide(&source, target.as_ref(), action, true),
                want,
                "{action:?} with target {label}"
            );
        }
    }
}

#[test]
fn resume_falls_back_to_overwrite_when_impossible() {
    let source = entry(Some(100), None, Precision::Second);
    let partial = entry(Some(40), None, Precision::Second);
    let empty = entry(Some(0), None, Precision::Second);
    let overwrite = Decision::Transfer {
        mode: WriteMode::Truncate,
    };
    assert_eq!(
        decide(&source, Some(&partial), ExistsAction::Resume, false),
        overwrite
    );
    assert_eq!(
        decide(&source, Some(&empty), ExistsAction::Resume, true),
        overwrite
    );
    // A source of unknown size: ask.
    let unknown = entry(None, None, Precision::Second);
    assert_eq!(
        decide(&unknown, Some(&partial), ExistsAction::Resume, true),
        Decision::AskUser
    );
}

#[test]
fn newer_compares_at_the_coarser_precision() {
    // Same minute, the source carries seconds the target's listing lacks.
    let source = entry(Some(1), Some(T), Precision::Second);
    let target = entry(
        Some(1),
        Some(datetime!(2026-05-01 12:00 UTC)),
        Precision::Minute,
    );
    assert_eq!(is_newer(&source, &target), Some(false));
    assert_eq!(
        decide(&source, Some(&target), ExistsAction::OverwriteIfNewer, true),
        Decision::Skip
    );
    // A day-precision target: anything later that day is not newer.
    let day = entry(
        Some(1),
        Some(datetime!(2026-05-01 0:00 UTC)),
        Precision::Day,
    );
    assert_eq!(is_newer(&source, &day), Some(false));
    let next_day = entry(
        Some(1),
        Some(datetime!(2026-05-02 9:00 UTC)),
        Precision::Second,
    );
    assert_eq!(is_newer(&next_day, &day), Some(true));
}

#[test]
fn numbered_names() {
    assert_eq!(numbered_name("a.txt", 1), "a (1).txt");
    assert_eq!(numbered_name("archive.tar.gz", 2), "archive.tar (2).gz");
    assert_eq!(numbered_name(".bashrc", 3), ".bashrc (3)");
    assert_eq!(numbered_name("README", 10), "README (10)");
}

#[tokio::test]
async fn first_free_name_skips_taken_names() {
    let server = MockServer::new();
    server.add_file("/d/a.txt", b"0");
    server.add_file("/d/a (1).txt", b"1");
    server.add_file("/d/a (3).txt", b"3");
    let mut b = server.backend();
    let cancel = CancellationToken::new();
    b.connect(cancel.clone()).await.unwrap();
    let dir = RemotePath::new("/d");
    let t = Duration::from_secs(5);
    assert_eq!(
        first_free_name(&mut b, &dir, "a.txt", t, &cancel)
            .await
            .unwrap(),
        "a (2).txt"
    );
    assert_eq!(
        first_free_name(&mut b, &dir, "new.txt", t, &cancel)
            .await
            .unwrap(),
        "new.txt"
    );
}

// ------------------------------------------------------------ policy

fn quick(host: &str) -> QueueServer {
    QueueServer::Quick {
        address: ServerAddress::new(Protocol::Sftp, host),
        password: None,
    }
}

fn item(host: &str, direction: Direction, on_exists: Option<ExistsAction>) -> QueueItem {
    let mut q = Queue::default();
    let mut new = NewItem::file(
        quick(host),
        direction,
        LocalPath::new("/tmp/f.txt"),
        RemotePath::new("/r/f.txt"),
        Some(100),
    );
    new.on_exists = on_exists;
    let id = q.add(new, OffsetDateTime::UNIX_EPOCH);
    q.get(id).cloned().unwrap()
}

fn ask_settings() -> TransferSettings {
    TransferSettings {
        on_exists_download: ExistsAction::Ask,
        on_exists_upload: ExistsAction::Ask,
        ..TransferSettings::default()
    }
}

/// Answers every file-exists prompt with `answer` after `delay`, counting
/// prompts. `None` drops the prompt unanswered.
fn responder(
    mut rx: EventReceiver,
    answer: Option<FileExistsAnswer>,
    delay: Duration,
) -> Arc<AtomicUsize> {
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let CoreEvent::Prompt(req) = event {
                assert!(matches!(req.kind, PromptKind::FileExists { .. }));
                seen.fetch_add(1, AtomicOrdering::SeqCst);
                tokio::time::sleep(delay).await;
                if let Some(a) = answer.clone() {
                    let _ = req.reply.send(PromptResponse::FileExists(a));
                }
            }
        }
    });
    count
}

async fn run_policy(
    policy: &FileExistsPolicy,
    item: &QueueItem,
    settings: &TransferSettings,
    target: Option<&Entry>,
) -> Result<ExistsDecision> {
    let source = entry(Some(100), Some(T), Precision::Second);
    let ctx = ExistsContext {
        item,
        source: &source,
        target,
        target_caps: Capabilities::default(),
        can_resume: true,
        settings,
    };
    policy.decide(ctx, &CancellationToken::new()).await
}

fn existing(size: u64) -> Entry {
    entry(Some(size), Some(T), Precision::Second)
}

fn remember(action: ExistsAction, apply_to: ApplyTo) -> FileExistsAnswer {
    FileExistsAnswer {
        apply_to,
        ..FileExistsAnswer::once(action)
    }
}

#[tokio::test]
async fn missing_targets_and_directories() {
    let (tx, _rx) = events::channel(2);
    let policy = FileExistsPolicy::new(tx);
    let s = ask_settings();
    let i = item("a", Direction::Download, None);
    assert_eq!(
        run_policy(&policy, &i, &s, None).await.unwrap(),
        ExistsDecision::Overwrite
    );
    let dir = Entry::dir("f.txt");
    assert!(matches!(
        run_policy(&policy, &i, &s, Some(&dir)).await,
        Err(Error::InvalidInput(_))
    ));
}

#[tokio::test]
async fn settings_default_then_item_override() {
    let (tx, _rx) = events::channel(2);
    let policy = FileExistsPolicy::new(tx);
    let s = TransferSettings {
        on_exists_download: ExistsAction::Skip,
        on_exists_upload: ExistsAction::Overwrite,
        ..TransferSettings::default()
    };
    let t = existing(40);
    let down = item("a", Direction::Download, None);
    let up = item("a", Direction::Upload, None);
    assert_eq!(
        run_policy(&policy, &down, &s, Some(&t)).await.unwrap(),
        ExistsDecision::Skip
    );
    assert_eq!(
        run_policy(&policy, &up, &s, Some(&t)).await.unwrap(),
        ExistsDecision::Overwrite
    );
    let resume = item("a", Direction::Download, Some(ExistsAction::Resume));
    assert_eq!(
        run_policy(&policy, &resume, &s, Some(&t)).await.unwrap(),
        ExistsDecision::Resume { offset: 40 }
    );
    // `Ask` as an item override falls through to the setting.
    let ask = item("a", Direction::Download, Some(ExistsAction::Ask));
    assert_eq!(
        run_policy(&policy, &ask, &s, Some(&t)).await.unwrap(),
        ExistsDecision::Skip
    );
}

#[tokio::test(start_paused = true)]
async fn concurrent_asks_show_one_prompt_for_apply_to_all() {
    let (tx, rx) = events::channel(2);
    let prompts = responder(
        rx,
        Some(remember(ExistsAction::Overwrite, ApplyTo::AllInQueue)),
        Duration::from_millis(500),
    );
    let policy = Arc::new(FileExistsPolicy::new(tx));
    let s = ask_settings();
    let t = existing(40);
    let tasks: Vec<_> = (0..5)
        .map(|_| {
            let policy = Arc::clone(&policy);
            let s = s.clone();
            let t = t.clone();
            tokio::spawn(async move {
                let i = item("a", Direction::Download, None);
                run_policy(&policy, &i, &s, Some(&t)).await.unwrap()
            })
        })
        .collect();
    for task in tasks {
        assert_eq!(task.await.unwrap(), ExistsDecision::Overwrite);
    }
    assert_eq!(prompts.load(AtomicOrdering::SeqCst), 1);
    // Forgotten when the queue run ends.
    policy.queue_finished();
    let i = item("a", Direction::Download, None);
    run_policy(&policy, &i, &s, Some(&t)).await.unwrap();
    assert_eq!(prompts.load(AtomicOrdering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn session_answers_and_their_filters() {
    let (tx, rx) = events::channel(2);
    let answer = FileExistsAnswer {
        same_direction_only: true,
        same_server_only: true,
        ..remember(ExistsAction::Skip, ApplyTo::AllInSession)
    };
    let prompts = responder(rx, Some(answer), Duration::ZERO);
    let policy = FileExistsPolicy::new(tx);
    let s = ask_settings();
    let t = existing(40);
    let down_a = item("a", Direction::Download, None);
    assert_eq!(
        run_policy(&policy, &down_a, &s, Some(&t)).await.unwrap(),
        ExistsDecision::Skip
    );
    policy.queue_finished();
    run_policy(&policy, &down_a, &s, Some(&t)).await.unwrap();
    assert_eq!(
        prompts.load(AtomicOrdering::SeqCst),
        1,
        "kept for the session"
    );
    // Another direction or server asks again.
    run_policy(&policy, &item("a", Direction::Upload, None), &s, Some(&t))
        .await
        .unwrap();
    assert_eq!(prompts.load(AtomicOrdering::SeqCst), 2);
    run_policy(&policy, &item("b", Direction::Download, None), &s, Some(&t))
        .await
        .unwrap();
    assert_eq!(prompts.load(AtomicOrdering::SeqCst), 3);
}

#[tokio::test(start_paused = true)]
async fn answered_rename_and_resume() {
    let s = ask_settings();
    let i = item("a", Direction::Download, None);
    let t = existing(40);

    let (tx, rx) = events::channel(2);
    let answer = FileExistsAnswer {
        new_name: Some("other.txt".into()),
        ..FileExistsAnswer::once(ExistsAction::Rename)
    };
    responder(rx, Some(answer), Duration::ZERO);
    let policy = FileExistsPolicy::new(tx);
    assert_eq!(
        run_policy(&policy, &i, &s, Some(&t)).await.unwrap(),
        ExistsDecision::Rename {
            name: "other.txt".into()
        }
    );

    let (tx, rx) = events::channel(2);
    let answer = FileExistsAnswer {
        new_name: Some("../escape".into()),
        ..FileExistsAnswer::once(ExistsAction::Rename)
    };
    responder(rx, Some(answer), Duration::ZERO);
    let policy = FileExistsPolicy::new(tx);
    assert!(run_policy(&policy, &i, &s, Some(&t)).await.is_err());

    // Automatic rename starts from the target's name.
    let (tx, rx) = events::channel(2);
    responder(
        rx,
        Some(FileExistsAnswer::once(ExistsAction::Rename)),
        Duration::ZERO,
    );
    let policy = FileExistsPolicy::new(tx);
    assert_eq!(
        run_policy(&policy, &i, &s, Some(&t)).await.unwrap(),
        ExistsDecision::Rename {
            name: "f.txt".into()
        }
    );

    // Resume against a target of unknown size can't resume: skipped.
    let (tx, rx) = events::channel(2);
    responder(
        rx,
        Some(FileExistsAnswer::once(ExistsAction::Resume)),
        Duration::ZERO,
    );
    let policy = FileExistsPolicy::new(tx);
    let unknown = entry(None, Some(T), Precision::Second);
    assert_eq!(
        run_policy(&policy, &i, &s, Some(&unknown)).await.unwrap(),
        ExistsDecision::Skip
    );
    assert_eq!(
        run_policy(&policy, &i, &s, Some(&t)).await.unwrap(),
        ExistsDecision::Resume { offset: 40 }
    );
}

#[tokio::test(start_paused = true)]
async fn a_dismissed_prompt_skips() {
    let (tx, rx) = events::channel(2);
    let prompts = responder(rx, None, Duration::ZERO);
    let policy = FileExistsPolicy::new(tx);
    let i = item("a", Direction::Download, None);
    assert_eq!(
        run_policy(&policy, &i, &ask_settings(), Some(&existing(1)))
            .await
            .unwrap(),
        ExistsDecision::Skip
    );
    assert_eq!(prompts.load(AtomicOrdering::SeqCst), 1);
}

// ------------------------------------------------------------ engine level

fn base() -> PathBuf {
    std::env::temp_dir().join("courier-ftp-t42")
}

fn local_key(name: &str) -> String {
    local_to_remote(&base().join(name))
        .unwrap()
        .as_str()
        .to_owned()
}

fn engine_settings() -> Settings {
    let mut s = Settings::default();
    s.connection.keepalive = false;
    s.file_types.default_type = TransferTypeChoice::Binary;
    s.transfers.max_concurrent = 4;
    s.transfers.on_exists_download = ExistsAction::Ask;
    s
}

async fn wait_finished(
    rx: &mut EventReceiver,
    prompts: &mut Vec<events::PromptRequest>,
) -> QueueStats {
    tokio::time::timeout(Duration::from_secs(600), async {
        loop {
            match rx.recv().await {
                Some(CoreEvent::QueueFinished { stats }) => return stats,
                Some(CoreEvent::Prompt(req)) => prompts.push(req),
                Some(_) => {}
                None => panic!("event channel closed"),
            }
        }
    })
    .await
    .expect("queue did not finish")
}

fn download(queue: &SharedQueue, name: &str, size: u64) {
    queue.lock().unwrap().add(
        NewItem::file(
            quick("mock"),
            Direction::Download,
            LocalPath::new(base().join(name)),
            RemotePath::new(format!("/r/{name}")),
            Some(size),
        ),
        OffsetDateTime::UNIX_EPOCH,
    );
}

/// Four workers hit existing targets at once: one prompt, and its "apply
/// to all" answer is used by the others.
#[tokio::test(start_paused = true)]
async fn engine_apply_to_all_across_workers() {
    let remote = MockServer::new();
    let local = MockServer::new();
    local.add_dir(&local_key(""));
    let queue: SharedQueue = Arc::new(StdMutex::new(Queue::default()));
    for i in 0..6 {
        let name = format!("f{i}");
        remote.add_file(&format!("/r/{name}"), b"new contents");
        local.add_file(&local_key(&name), b"old");
        download(&queue, &name, 12);
    }
    let (tx, mut rx) = events::channel(2);
    let policy = Arc::new(FileExistsPolicy::new(tx.clone()));
    let (engine, handle) = TransferEngine::builder(
        Arc::clone(&queue),
        Arc::new(remote.clone()),
        Arc::new(QuickResolver::new(None)),
        tx,
    )
    .settings(engine_settings())
    .local_backends(Arc::new(local.clone()))
    .exists_policy(policy)
    .build();
    let task = engine.spawn();
    handle.start();
    // Answer the first prompt late, so the other workers are waiting.
    let first = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(CoreEvent::Prompt(req)) = rx.recv().await {
                return req;
            }
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    first
        .reply
        .send(PromptResponse::FileExists(remember(
            ExistsAction::Overwrite,
            ApplyTo::AllInQueue,
        )))
        .unwrap();
    let mut later = Vec::new();
    let stats = wait_finished(&mut rx, &mut later).await;
    assert!(later.is_empty(), "only one prompt");
    assert_eq!(stats.files_ok, 6);
    for i in 0..6 {
        assert_eq!(
            local.read_file(&local_key(&format!("f{i}"))).unwrap(),
            b"new contents"
        );
    }
    handle.shutdown();
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn engine_rename_never_overwrites() {
    let remote = MockServer::new();
    let local = MockServer::new();
    local.add_dir(&local_key(""));
    remote.add_file("/r/f.txt", b"new");
    local.add_file(&local_key("f.txt"), b"old");
    local.add_file(&local_key("f (1).txt"), b"old 1");
    let queue: SharedQueue = Arc::new(StdMutex::new(Queue::default()));
    download(&queue, "f.txt", 3);
    let (tx, mut rx) = events::channel(2);
    let mut settings = engine_settings();
    settings.transfers.on_exists_download = ExistsAction::Rename;
    let (engine, handle) = TransferEngine::builder(
        Arc::clone(&queue),
        Arc::new(remote.clone()),
        Arc::new(QuickResolver::new(None)),
        tx.clone(),
    )
    .settings(settings)
    .local_backends(Arc::new(local.clone()))
    .exists_policy(Arc::new(FileExistsPolicy::new(tx)))
    .build();
    let task = engine.spawn();
    handle.start();
    let stats = wait_finished(&mut rx, &mut Vec::new()).await;
    assert_eq!(stats.files_ok, 1);
    assert_eq!(local.read_file(&local_key("f.txt")).unwrap(), b"old");
    assert_eq!(local.read_file(&local_key("f (1).txt")).unwrap(), b"old 1");
    assert_eq!(local.read_file(&local_key("f (2).txt")).unwrap(), b"new");
    assert!(local.write_modes().iter().all(|m| *m == WriteMode::Create));
    handle.shutdown();
    task.await.unwrap();
}

/// The worker refuses a download target that leaves its directory, and
/// sanitizes the file name (T91).
#[tokio::test(start_paused = true)]
async fn engine_downloads_stay_in_the_target_dir() {
    let remote = MockServer::new();
    let local = MockServer::new();
    local.add_dir(&local_key("sub"));
    remote.add_file("/r/x", b"evil");
    remote.add_file("/r/ok", b"fine");
    let queue: SharedQueue = Arc::new(StdMutex::new(Queue::default()));
    let add = |local_path: PathBuf, remote_path: &str| {
        queue.lock().unwrap().add(
            NewItem::file(
                quick("mock"),
                Direction::Download,
                LocalPath::new(local_path),
                RemotePath::new(remote_path),
                Some(4),
            ),
            OffsetDateTime::UNIX_EPOCH,
        )
    };
    let bad = add(base().join("sub").join("..").join("x"), "/r/x");
    // A name with a NUL (or, on Windows, `?`) is stored with `_`.
    let odd = if cfg!(windows) { "a?b" } else { "a\0b" };
    add(base().join("sub").join(odd), "/r/ok");
    let (tx, mut rx) = events::channel(2);
    let (engine, handle) = TransferEngine::builder(
        Arc::clone(&queue),
        Arc::new(remote.clone()),
        Arc::new(QuickResolver::new(None)),
        tx,
    )
    .settings(engine_settings())
    .local_backends(Arc::new(local.clone()))
    .build();
    let task = engine.spawn();
    handle.start();
    let stats = wait_finished(&mut rx, &mut Vec::new()).await;
    assert_eq!((stats.files_ok, stats.files_failed), (1, 1));
    assert!(!local.exists(&local_key("x")));
    let failed = queue.lock().unwrap().get(bad).cloned().unwrap();
    assert!(
        matches!(&failed.state, crate::queue::ItemState::Failed { error } if error.contains("leaves its directory")),
        "{:?}",
        failed.state
    );
    assert_eq!(
        local
            .read_file(&local_key(&format!("sub/{}", "a_b")))
            .unwrap(),
        b"fine"
    );
    handle.shutdown();
    task.await.unwrap();
}

// ------------------------------------------------------------ 5 GiB resume

const GIB: u64 = 1 << 30;

/// Byte `i` of the synthetic big file.
fn big_byte(i: u64) -> u8 {
    (i % 251) as u8 ^ (i >> 32) as u8
}

#[derive(Default)]
struct SparseState {
    /// Path → size. Contents are always `big_byte`.
    files: HashMap<RemotePath, u64>,
    write_modes: Vec<WriteMode>,
    read_offsets: Vec<u64>,
    /// Bytes that didn't match `big_byte` at their position.
    mismatches: u64,
}

/// A backend whose files exist only as sizes, so a 5 GiB file costs
/// nothing; writers check each byte against `big_byte`.
#[derive(Clone, Default)]
struct Sparse(Arc<StdMutex<SparseState>>);

struct SparseBackend(Sparse);

struct SparseReader {
    pos: u64,
    end: u64,
}

impl AsyncRead for SparseReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = (self.end - self.pos).min(buf.remaining() as u64);
        let start = self.pos;
        let bytes: Vec<u8> = (start..start + n).map(big_byte).collect();
        buf.put_slice(&bytes);
        self.pos += n;
        Poll::Ready(Ok(()))
    }
}

struct SparseWriter {
    server: Sparse,
    path: RemotePath,
    pos: u64,
}

impl AsyncWrite for SparseWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let start = self.pos;
        let bad = buf
            .iter()
            .zip(start..)
            .filter(|(b, i)| **b != big_byte(*i))
            .count() as u64;
        self.pos += buf.len() as u64;
        let mut st = self.server.0.lock().unwrap();
        st.mismatches += bad;
        let size = st.files.entry(self.path.clone()).or_default();
        *size = (*size).max(self.pos);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl Backend for SparseBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            resume_download: true,
            resume_upload: true,
            ..Capabilities::default()
        }
    }
    fn address(&self) -> Option<&ServerAddress> {
        None
    }
    async fn connect(&mut self, _: CancellationToken) -> Result<()> {
        Ok(())
    }
    async fn disconnect(&mut self) -> Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn home_dir(&mut self) -> Result<RemotePath> {
        Ok(RemotePath::root())
    }
    async fn list(&mut self, _: &RemotePath, _: CancellationToken) -> Result<Listing> {
        Err(Error::Unsupported("list"))
    }
    async fn stat(&mut self, path: &RemotePath) -> Result<Entry> {
        let st = self.0.0.lock().unwrap();
        st.files
            .get(path)
            .map(|size| Entry::file(path.file_name().unwrap_or_default(), *size))
            .ok_or_else(|| Error::NotFound(path.clone()))
    }
    async fn mkdir(&mut self, _: &RemotePath) -> Result<()> {
        Err(Error::Unsupported("mkdir"))
    }
    async fn rmdir(&mut self, _: &RemotePath) -> Result<()> {
        Err(Error::Unsupported("rmdir"))
    }
    async fn remove_file(&mut self, _: &RemotePath) -> Result<()> {
        Err(Error::Unsupported("remove"))
    }
    async fn rename(&mut self, _: &RemotePath, _: &RemotePath) -> Result<()> {
        Err(Error::Unsupported("rename"))
    }
    async fn chmod(&mut self, _: &RemotePath, _: u32) -> Result<()> {
        Err(Error::Unsupported("chmod"))
    }
    async fn set_mtime(&mut self, _: &RemotePath, _: OffsetDateTime) -> Result<()> {
        Err(Error::Unsupported("set_mtime"))
    }
    async fn open_read(
        &mut self,
        path: &RemotePath,
        offset: u64,
        _: &TransferOpts,
    ) -> Result<ReadStream> {
        let mut st = self.0.0.lock().unwrap();
        st.read_offsets.push(offset);
        let end = *st
            .files
            .get(path)
            .ok_or_else(|| Error::NotFound(path.clone()))?;
        Ok(Box::new(SparseReader { pos: offset, end }))
    }
    async fn open_write(
        &mut self,
        path: &RemotePath,
        mode: WriteMode,
        _: &TransferOpts,
    ) -> Result<WriteStream> {
        let mut st = self.0.0.lock().unwrap();
        st.write_modes.push(mode);
        let pos = match mode {
            WriteMode::ResumeAt(n) => n,
            _ => 0,
        };
        st.files.insert(path.clone(), pos);
        Ok(Box::new(SparseWriter {
            server: self.0.clone(),
            path: path.clone(),
            pos,
        }))
    }
    async fn finish_transfer(&mut self) -> Result<()> {
        Ok(())
    }
    async fn raw_command(&mut self, _: &str) -> Result<String> {
        Err(Error::Unsupported("raw"))
    }
    async fn keepalive(&mut self) -> Result<()> {
        Ok(())
    }
}

impl BackendFactory for Sparse {
    fn create(&self, _: &ConnectInfo, _: events::SessionId, _: EventSender) -> Box<dyn Backend> {
        Box::new(SparseBackend(self.clone()))
    }
}

impl LocalBackendFactory for Sparse {
    fn create(&self) -> Box<dyn Backend> {
        Box::new(SparseBackend(self.clone()))
    }
}

#[tokio::test]
async fn resume_a_5_gib_file_past_4_gib() {
    let size = 5 * GIB;
    let have = 5 * GIB - 3 * 1024 * 1024 + 17; // > 4 GiB, odd offset
    let sparse = Sparse::default();
    let local_target = RemotePath::new(local_key("big"));
    {
        let mut st = sparse.0.lock().unwrap();
        st.files.insert(RemotePath::new("/r/big"), size);
        st.files.insert(local_target.clone(), have);
    }
    let queue: SharedQueue = Arc::new(StdMutex::new(Queue::default()));
    download(&queue, "big", size);
    let (tx, mut rx) = events::channel(2);
    let mut settings = engine_settings();
    settings.transfers.on_exists_download = ExistsAction::Resume;
    let (engine, handle) = TransferEngine::builder(
        Arc::clone(&queue),
        Arc::new(sparse.clone()),
        Arc::new(QuickResolver::new(None)),
        tx.clone(),
    )
    .settings(settings)
    .local_backends(Arc::new(sparse.clone()))
    .exists_policy(Arc::new(FileExistsPolicy::new(tx)))
    .build();
    let task = engine.spawn();
    handle.start();
    let stats = wait_finished(&mut rx, &mut Vec::new()).await;
    assert_eq!(stats.files_ok, 1, "{stats:?}");
    assert_eq!(stats.bytes, size - have);
    {
        let st = sparse.0.lock().unwrap();
        assert_eq!(st.read_offsets, [have]);
        assert_eq!(st.write_modes, [WriteMode::ResumeAt(have)]);
        assert_eq!(st.files[&local_target], size);
        assert_eq!(st.mismatches, 0);
    }
    handle.shutdown();
    task.await.unwrap();
}
