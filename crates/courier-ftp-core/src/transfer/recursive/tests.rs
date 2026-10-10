//! T43 tests: generated mock trees (100 000 files, symlink loops), the
//! in-memory mock server, and the local backend on temp dirs.

use std::{
    collections::HashSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use pretty_assertions::assert_eq;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::{
    Error, Result,
    backend::{
        Backend, BackendFactory, Capabilities, ConnectInfo, Listing, MockBackend, MockServer,
        ReadStream, TransferOpts, WriteMode, WriteStream,
    },
    events::{self, CoreEvent, EventReceiver, EventSender, LogKind, SessionId},
    filters::{AppliesTo, Condition, Filter, FilterEngine, FilterScope, MatchMode, StringOp},
    local::{LocalBackend, local_to_remote},
    model::{
        Direction, Entry, EntryKind, LocalPath, LogonType, Protocol, RemotePath, ServerAddress,
    },
    queue::{NewItem, Queue, QueueItem, QueueServer},
    settings::{EmptyDirs, Settings},
    transfer::{DirExpander, ServerResolver, TransferEngine},
};

// ------------------------------------------------------------------ fixtures

fn p(s: &str) -> RemotePath {
    RemotePath::new(s)
}

fn sid() -> SessionId {
    SessionId(7)
}

fn name_filter(value: &str) -> FilterEngine {
    let f = Filter {
        name: format!("no {value}"),
        applies_to: AppliesTo::Both,
        match_mode: MatchMode::All,
        case_sensitive: false,
        conditions: vec![Condition::Name {
            op: StringOp::Contains,
            value: value.into(),
        }],
        scope: FilterScope::Both,
    };
    let (engine, warnings) = FilterEngine::new([&f]);
    assert!(warnings.is_empty());
    engine
}

/// A generated tree under `/t`: directories above `depth` have `dirs`
/// subdirectories `d0…`, the deepest ones `files` files `f0…`. With `link`,
/// every directory also holds a symlink `up` to a directory with that
/// target (resolved when listed). Nothing is held in memory.
struct TreeBackend {
    address: ServerAddress,
    depth: usize,
    dirs: usize,
    files: usize,
    link: Option<&'static str>,
    lists: Arc<AtomicU64>,
}

impl TreeBackend {
    fn new(depth: usize, dirs: usize, files: usize) -> Self {
        Self {
            address: ServerAddress::new(Protocol::Sftp, "tree.invalid"),
            depth,
            dirs,
            files,
            link: None,
            lists: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The real path (links resolved) and its depth below `/t`.
    fn resolve(&self, path: &RemotePath) -> Option<usize> {
        let mut real: Vec<String> = Vec::new();
        for c in path.components() {
            if c == "up" {
                let target = self.link?;
                let base = RemotePath::new(format!("/{}", real.join("/")));
                let resolved = base.join_path(target);
                real = resolved.components().map(str::to_owned).collect();
            } else {
                real.push(c.to_owned());
            }
        }
        let mut it = real.iter();
        if it.next().map(String::as_str) != Some("t") {
            return None;
        }
        let rest: Vec<_> = it.collect();
        rest.iter()
            .all(|c| c.starts_with('d'))
            .then_some(rest.len())
            .filter(|d| *d <= self.depth)
    }

    fn entries(&self, depth: usize) -> Vec<Entry> {
        let mut out = Vec::new();
        if depth < self.depth {
            out.extend((0..self.dirs).map(|i| Entry::dir(format!("d{i}"))));
        } else {
            out.extend((0..self.files).map(|i| Entry::file(format!("f{i}"), 1)));
        }
        if let Some(target) = self.link {
            out.push(Entry::new(
                "up",
                EntryKind::Symlink {
                    target: Some(target.into()),
                    target_kind: Some(Box::new(EntryKind::Dir)),
                },
            ));
        }
        out
    }
}

#[async_trait]
impl Backend for TreeBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }
    fn address(&self) -> Option<&ServerAddress> {
        Some(&self.address)
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
    async fn list(&mut self, dir: &RemotePath, _: CancellationToken) -> Result<Listing> {
        self.lists.fetch_add(1, Ordering::Relaxed);
        let depth = self
            .resolve(dir)
            .ok_or_else(|| Error::NotFound(dir.clone()))?;
        Ok(Listing {
            dir: dir.clone(),
            entries: self.entries(depth),
            fetched_at: Instant::now(),
            raw: None,
        })
    }
    async fn stat(&mut self, path: &RemotePath) -> Result<Entry> {
        self.resolve(path)
            .map(|_| Entry::dir(path.file_name().unwrap_or("/")))
            .ok_or_else(|| Error::NotFound(path.clone()))
    }
    async fn mkdir(&mut self, _: &RemotePath) -> Result<()> {
        Err(Error::Unsupported("tree"))
    }
    async fn rmdir(&mut self, _: &RemotePath) -> Result<()> {
        Err(Error::Unsupported("tree"))
    }
    async fn remove_file(&mut self, _: &RemotePath) -> Result<()> {
        Err(Error::Unsupported("tree"))
    }
    async fn rename(&mut self, _: &RemotePath, _: &RemotePath) -> Result<()> {
        Err(Error::Unsupported("tree"))
    }
    async fn chmod(&mut self, _: &RemotePath, _: u32) -> Result<()> {
        Err(Error::Unsupported("tree"))
    }
    async fn set_mtime(&mut self, _: &RemotePath, _: OffsetDateTime) -> Result<()> {
        Err(Error::Unsupported("tree"))
    }
    async fn open_read(&mut self, _: &RemotePath, _: u64, _: &TransferOpts) -> Result<ReadStream> {
        Err(Error::Unsupported("tree"))
    }
    async fn open_write(
        &mut self,
        _: &RemotePath,
        _: WriteMode,
        _: &TransferOpts,
    ) -> Result<WriteStream> {
        Err(Error::Unsupported("tree"))
    }
    async fn finish_transfer(&mut self) -> Result<()> {
        Ok(())
    }
    async fn raw_command(&mut self, _: &str) -> Result<String> {
        Err(Error::Unsupported("tree"))
    }
    async fn keepalive(&mut self) -> Result<()> {
        Ok(())
    }
}

/// A mock connection that refuses to remove some paths and records every
/// remove / rmdir / chmod in order.
struct Faulty {
    inner: MockBackend,
    refuse: HashSet<String>,
    ops: Arc<Mutex<Vec<String>>>,
}

impl Faulty {
    fn new(server: &MockServer, refuse: &[&str]) -> Self {
        Self {
            inner: server.backend(),
            refuse: refuse.iter().map(|s| (*s).to_owned()).collect(),
            ops: Arc::default(),
        }
    }

    fn record(&self, op: &str, path: &RemotePath) -> Result<()> {
        self.ops.lock().unwrap().push(format!("{op} {path}"));
        if self.refuse.contains(path.as_str()) {
            Err(Error::PermissionDenied)
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl Backend for Faulty {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }
    fn address(&self) -> Option<&ServerAddress> {
        self.inner.address()
    }
    async fn connect(&mut self, c: CancellationToken) -> Result<()> {
        self.inner.connect(c).await
    }
    async fn disconnect(&mut self) -> Result<()> {
        self.inner.disconnect().await
    }
    fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }
    async fn home_dir(&mut self) -> Result<RemotePath> {
        self.inner.home_dir().await
    }
    async fn list(&mut self, dir: &RemotePath, c: CancellationToken) -> Result<Listing> {
        self.inner.list(dir, c).await
    }
    async fn stat(&mut self, path: &RemotePath) -> Result<Entry> {
        self.inner.stat(path).await
    }
    async fn mkdir(&mut self, path: &RemotePath) -> Result<()> {
        self.inner.mkdir(path).await
    }
    async fn rmdir(&mut self, path: &RemotePath) -> Result<()> {
        self.record("rmdir", path)?;
        self.inner.rmdir(path).await
    }
    async fn remove_file(&mut self, path: &RemotePath) -> Result<()> {
        self.record("rm", path)?;
        self.inner.remove_file(path).await
    }
    async fn rename(&mut self, a: &RemotePath, b: &RemotePath) -> Result<()> {
        self.inner.rename(a, b).await
    }
    async fn chmod(&mut self, path: &RemotePath, mode: u32) -> Result<()> {
        self.record(&format!("chmod {mode:o}"), path)?;
        self.inner.chmod(path, mode).await
    }
    async fn set_mtime(&mut self, path: &RemotePath, t: OffsetDateTime) -> Result<()> {
        self.inner.set_mtime(path, t).await
    }
    async fn open_read(
        &mut self,
        path: &RemotePath,
        o: u64,
        t: &TransferOpts,
    ) -> Result<ReadStream> {
        self.inner.open_read(path, o, t).await
    }
    async fn open_write(
        &mut self,
        path: &RemotePath,
        m: WriteMode,
        t: &TransferOpts,
    ) -> Result<WriteStream> {
        self.inner.open_write(path, m, t).await
    }
    async fn finish_transfer(&mut self) -> Result<()> {
        self.inner.finish_transfer().await
    }
    async fn raw_command(&mut self, cmd: &str) -> Result<String> {
        self.inner.raw_command(cmd).await
    }
    async fn keepalive(&mut self) -> Result<()> {
        self.inner.keepalive().await
    }
}

/// /r/tree with files, a nested dir, an empty dir and a `.log` file.
fn mock_tree() -> MockServer {
    let s = MockServer::new();
    s.add_dir("/r")
        .add_dir("/r/tree")
        .add_file("/r/tree/a.txt", b"aaa")
        .add_file("/r/tree/b.log", b"bb")
        .add_dir("/r/tree/sub")
        .add_file("/r/tree/sub/c.txt", b"c")
        .add_dir("/r/tree/sub/deep")
        .add_file("/r/tree/sub/deep/d.txt", b"dd")
        .add_dir("/r/tree/empty")
        .add_dir("/r/tree/logs.log")
        .add_file("/r/tree/logs.log/e.txt", b"e");
    s
}

async fn connected(server: &MockServer) -> MockBackend {
    let mut b = server.backend();
    b.connect(CancellationToken::new()).await.unwrap();
    b
}

fn dir_target(path: &str) -> Target {
    let path = p(path);
    let name = path.file_name().unwrap_or("/").to_owned();
    Target::new(path, Entry::dir(name))
}

async fn collect(
    walker: &mut Walker,
    backend: &mut dyn Backend,
    cancel: &CancellationToken,
) -> Vec<WalkEvent> {
    let mut out = Vec::new();
    while let Some(e) = walker.next(backend, cancel).await.unwrap() {
        out.push(e);
    }
    out
}

fn describe(events: &[WalkEvent]) -> Vec<String> {
    events
        .iter()
        .map(|e| match e {
            WalkEvent::File { path, .. } => format!("file {path}"),
            WalkEvent::Symlink { path, .. } => format!("link {path}"),
            WalkEvent::EnterDir { path, .. } => format!("enter {path}"),
            WalkEvent::LeaveDir { path, complete, .. } => format!("leave {path} {complete}"),
        })
        .collect()
}

fn drain(rx: &mut EventReceiver) -> Vec<CoreEvent> {
    let mut out = Vec::new();
    while let Some(e) = rx.try_recv() {
        out.push(e);
    }
    out
}

// ---------------------------------------------------------------- the walker

#[tokio::test]
async fn walk_is_depth_first_with_pre_and_post_order() {
    let server = mock_tree();
    let mut b = connected(&server).await;
    let mut opts = WalkOptions::remote(sid());
    opts.filter = name_filter(".log");
    let mut w = Walker::new(vec![dir_target("/r/tree")], opts);
    let events = collect(&mut w, &mut b, &CancellationToken::new()).await;
    assert_eq!(
        describe(&events),
        [
            "enter /r/tree",
            "file /r/tree/a.txt",
            "enter /r/tree/empty",
            "leave /r/tree/empty true",
            "enter /r/tree/sub",
            "file /r/tree/sub/c.txt",
            "enter /r/tree/sub/deep",
            "file /r/tree/sub/deep/d.txt",
            "leave /r/tree/sub/deep true",
            "leave /r/tree/sub true",
            // b.log and logs.log/ were filtered: not complete.
            "leave /r/tree false",
        ]
    );
    let s = w.summary();
    assert_eq!((s.dirs, s.files, s.filtered), (4, 3, 2));
}

#[tokio::test]
async fn hundred_thousand_files_with_bounded_memory() {
    // 10^4 leaf directories × 10 files = 100 000 files, 11 111 directories.
    let mut tree = TreeBackend::new(4, 10, 10);
    let lists = Arc::clone(&tree.lists);
    let mut w = Walker::new(vec![dir_target("/t")], WalkOptions::remote(sid()));
    let cancel = CancellationToken::new();
    let (mut files, mut max_live) = (0u64, 0usize);
    while let Some(e) = w.next(&mut tree, &cancel).await.unwrap() {
        if matches!(e, WalkEvent::File { .. }) {
            files += 1;
        }
        max_live = max_live.max(w.live_entries());
    }
    assert_eq!(files, 100_000);
    assert_eq!(w.summary().dirs, 11_111);
    assert_eq!(lists.load(Ordering::Relaxed), 11_111);
    // Only the listings along the current path are held: depth × fan-out.
    assert!(max_live <= 5 * 10, "max live entries {max_live}");
    assert!((max_live..=5 * 10).contains(&w.peak_live_entries()));
    assert_eq!(w.live_entries(), 0);
}

#[tokio::test]
async fn remote_symlink_loops_do_not_hang() {
    for target in ["..", "/t", "."] {
        let mut tree = TreeBackend::new(2, 2, 1);
        tree.link = Some(target);
        let mut opts = WalkOptions::remote(sid());
        opts.follow_symlinks = true;
        let mut w = Walker::new(vec![dir_target("/t")], opts);
        let cancel = CancellationToken::new();
        let events =
            tokio::time::timeout(Duration::from_secs(10), collect(&mut w, &mut tree, &cancel))
                .await
                .unwrap_or_else(|_| panic!("walk with link {target} hung"));
        let files = events
            .iter()
            .filter(|e| matches!(e, WalkEvent::File { .. }))
            .count();
        assert_eq!(files, 4, "link {target}");
        assert!(w.summary().loops > 0, "link {target}");
    }
}

#[tokio::test]
async fn unfollowed_symlinks_are_reported_not_descended() {
    let mut tree = TreeBackend::new(1, 1, 1);
    tree.link = Some("..");
    let mut w = Walker::new(vec![dir_target("/t")], WalkOptions::remote(sid()));
    let events = collect(&mut w, &mut tree, &CancellationToken::new()).await;
    assert_eq!(
        describe(&events),
        [
            "enter /t",
            "enter /t/d0",
            "file /t/d0/f0",
            "link /t/d0/up",
            "leave /t/d0 true",
            "link /t/up",
            "leave /t true",
        ]
    );
}

#[tokio::test]
async fn depth_limit_stops_undetectable_loops() {
    // A link whose target the server doesn't report can't be checked.
    let mut tree = TreeBackend::new(1, 1, 1);
    tree.link = Some("..");
    let mut opts = WalkOptions::remote(sid());
    opts.follow_symlinks = true;
    opts.loop_check = LoopCheck::Native; // paths don't exist locally: no ids
    opts.max_depth = 5;
    let mut w = Walker::new(vec![dir_target("/t")], opts);
    let _ = collect(&mut w, &mut tree, &CancellationToken::new()).await;
    assert!(w.summary().skipped_count > 0);
    assert!(
        w.summary()
            .skipped
            .iter()
            .any(|s| s.reason.contains("levels deep")),
        "{:?}",
        w.summary().skipped
    );
}

#[tokio::test]
async fn unreadable_subdirectory_is_skipped_and_listed() {
    let server = mock_tree();
    let mut b = connected(&server).await;
    // Every list after the first fails once: /r/tree/empty is skipped.
    let mut w = Walker::new(vec![dir_target("/r/tree")], WalkOptions::remote(sid()));
    let cancel = CancellationToken::new();
    let mut events = Vec::new();
    while let Some(e) = w.next(&mut b, &cancel).await.unwrap() {
        if matches!(&e, WalkEvent::EnterDir { path, .. } if path.as_str() == "/r/tree/empty") {
            server.fail_next(Error::PermissionDenied);
        }
        events.push(e);
    }
    let s = w.summary();
    assert_eq!(s.skipped_count, 1);
    assert_eq!(s.skipped[0].path, p("/r/tree/empty"));
    assert!(describe(&events).contains(&"leave /r/tree/empty false".to_owned()));
    // The rest was walked.
    assert!(describe(&events).contains(&"file /r/tree/sub/deep/d.txt".to_owned()));
}

#[tokio::test]
async fn cancellation_and_progress() {
    let (tx, mut rx) = events::channel(2);
    let mut tree = TreeBackend::new(3, 10, 10);
    let mut opts = WalkOptions::remote(sid());
    opts.events = Some(tx);
    let mut w = Walker::new(vec![dir_target("/t")], opts);
    let cancel = CancellationToken::new();
    let mut n = 0;
    let err = loop {
        match w.next(&mut tree, &cancel).await {
            Ok(Some(_)) => {
                n += 1;
                if n == 50 {
                    cancel.cancel();
                }
            }
            Ok(None) => panic!("not cancelled"),
            Err(e) => break e,
        }
    };
    assert!(matches!(err, Error::Cancelled));
    let progress: Vec<_> = drain(&mut rx)
        .into_iter()
        .filter_map(|e| match e {
            CoreEvent::RecursiveProgress(p) => Some(p),
            _ => None,
        })
        .collect();
    assert!(!progress.is_empty());
    let last = progress.last().unwrap();
    assert!(last.finished);
    assert_eq!(last.session, sid());
}

#[tokio::test]
async fn walker_uses_and_fills_the_listing_cache() {
    let server = mock_tree();
    let mut b = connected(&server).await;
    let cache = crate::cache::ListingCache::new(&Default::default(), None);
    let mut opts = WalkOptions::remote(sid());
    opts.cache = Some(cache.clone());
    let mut w = Walker::new(vec![dir_target("/r/tree")], opts.clone());
    let _ = collect(&mut w, &mut b, &CancellationToken::new()).await;
    assert!(cache.get(b.address(), &p("/r/tree/sub/deep")).is_some());
    // Walking again from the cache doesn't list.
    opts.use_cached = true;
    let calls = server.calls();
    let mut w = Walker::new(vec![dir_target("/r/tree")], opts);
    let events = collect(&mut w, &mut b, &CancellationToken::new()).await;
    assert_eq!(server.calls(), calls);
    assert_eq!(events.len(), 15);
}

#[cfg(unix)]
#[tokio::test]
async fn local_symlink_loop_does_not_hang() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(root.join("a/b")).unwrap();
    std::fs::write(root.join("a/b/f"), b"x").unwrap();
    std::os::unix::fs::symlink(&root, root.join("a/b/to_root")).unwrap();
    std::os::unix::fs::symlink("..", root.join("a/up")).unwrap();
    std::fs::create_dir(tmp.path().join("other")).unwrap();
    std::fs::write(tmp.path().join("other/g"), b"y").unwrap();
    std::os::unix::fs::symlink(tmp.path().join("other"), root.join("other")).unwrap();

    let mut b = LocalBackend::new();
    let cancel = CancellationToken::new();
    b.connect(cancel.clone()).await.unwrap();
    let mut opts = WalkOptions::local(sid());
    opts.follow_symlinks = true;
    let target = Target::new(local_to_remote(&root).unwrap(), Entry::dir("root"));
    let mut w = Walker::new(vec![target.clone()], opts);
    let events = tokio::time::timeout(Duration::from_secs(10), collect(&mut w, &mut b, &cancel))
        .await
        .expect("hung");
    let files: Vec<_> = describe(&events)
        .into_iter()
        .filter(|e| e.starts_with("file"))
        .collect();
    // f once, and g through the followed (non-loop) link.
    assert_eq!(files.len(), 2, "{files:?}");
    assert_eq!(w.summary().loops, 2);

    // Without following: links are reported, not descended.
    let mut w = Walker::new(vec![target], WalkOptions::local(sid()));
    let events = collect(&mut w, &mut b, &cancel).await;
    let links = describe(&events)
        .into_iter()
        .filter(|e| e.starts_with("link"))
        .count();
    assert_eq!(links, 3);
    assert_eq!(w.summary().loops, 0);
}

// ------------------------------------------------------------------- delete

#[tokio::test]
async fn delete_removes_everything_bottom_up() {
    let server = mock_tree();
    let mut b = Faulty::new(&server, &[]);
    b.connect(CancellationToken::new()).await.unwrap();
    let ops = Arc::clone(&b.ops);
    let report = delete_recursive(
        &mut b,
        vec![dir_target("/r/tree")],
        WalkOptions::remote(sid()),
        &CancellationToken::new(),
    )
    .await;
    assert!(report.is_complete(), "{report:?}");
    assert_eq!((report.files, report.dirs), (5, 5));
    assert!(!server.exists("/r/tree"));
    assert!(server.exists("/r"));
    // Every directory goes after everything inside it.
    let ops = ops.lock().unwrap().clone();
    for (i, op) in ops.iter().enumerate() {
        if let Some(dir) = op.strip_prefix("rmdir ") {
            let prefix = format!("{dir}/");
            assert!(
                ops[i..].iter().all(|later| !later.contains(&prefix)),
                "{op} before its contents: {ops:?}"
            );
        }
    }
    assert_eq!(ops.last().unwrap(), "rmdir /r/tree");
}

#[tokio::test]
async fn delete_partial_failure_reports_what_remains() {
    let server = mock_tree();
    let mut b = Faulty::new(&server, &["/r/tree/sub/c.txt"]);
    b.connect(CancellationToken::new()).await.unwrap();
    let report = delete_recursive(
        &mut b,
        vec![dir_target("/r/tree")],
        WalkOptions::remote(sid()),
        &CancellationToken::new(),
    )
    .await;
    assert!(report.stopped.is_none());
    let remaining: Vec<_> = report.problems.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(remaining, ["/r/tree/sub/c.txt", "/r/tree/sub", "/r/tree"]);
    assert_eq!(report.problem_count, 3);
    assert!(report.problems[0].reason.contains("permission denied"));
    // Everything else is gone, including the sibling deep/ below sub/.
    assert!(server.exists("/r/tree/sub/c.txt"));
    assert!(!server.exists("/r/tree/sub/deep"));
    assert!(!server.exists("/r/tree/a.txt"));
    assert!(!server.exists("/r/tree/empty"));
}

#[tokio::test]
async fn delete_leaves_filtered_entries_and_their_directories() {
    let server = mock_tree();
    let mut b = connected(&server).await;
    let (tx, mut rx) = events::channel(2);
    let mut opts = WalkOptions::remote(sid());
    opts.filter = name_filter(".log");
    opts.events = Some(tx);
    let report = delete_recursive(
        &mut b,
        vec![dir_target("/r/tree")],
        opts,
        &CancellationToken::new(),
    )
    .await;
    assert!(server.exists("/r/tree/b.log"));
    assert!(
        server.exists("/r/tree/logs.log/e.txt"),
        "filtered dir untouched"
    );
    assert!(!server.exists("/r/tree/sub"));
    assert_eq!(report.walk.filtered, 2);
    assert_eq!(report.problems.len(), 1);
    assert_eq!(report.problems[0].path, p("/r/tree"));
    let logs: Vec<String> = drain(&mut rx)
        .into_iter()
        .filter_map(|e| match e {
            CoreEvent::Log(m) => Some(m.text),
            _ => None,
        })
        .collect();
    assert!(
        logs.iter()
            .any(|l| l.contains("2 entries excluded by filters")),
        "{logs:?}"
    );
    assert!(
        logs.iter()
            .any(|l| l.starts_with("Deleted 3 files and 3 directories")),
        "{logs:?}"
    );
}

#[tokio::test]
async fn delete_patches_the_listing_cache() {
    let server = mock_tree();
    let mut b = connected(&server).await;
    let cache = crate::cache::ListingCache::new(&Default::default(), None);
    let listing = b.list(&p("/r"), CancellationToken::new()).await.unwrap();
    cache.put(b.address(), listing);
    let mut opts = WalkOptions::remote(sid());
    opts.cache = Some(cache.clone());
    let report = delete_recursive(
        &mut b,
        vec![dir_target("/r/tree")],
        opts,
        &CancellationToken::new(),
    )
    .await;
    assert!(report.is_complete());
    let r = cache.get(b.address(), &p("/r")).unwrap();
    assert!(r.entries.is_empty(), "{r:?}");
    assert!(cache.get(b.address(), &p("/r/tree/sub")).is_none());
}

#[tokio::test]
async fn delete_is_cancellable_mid_way() {
    let server = mock_tree();
    let mut b = connected(&server).await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let report = delete_recursive(
        &mut b,
        vec![dir_target("/r/tree")],
        WalkOptions::remote(sid()),
        &cancel,
    )
    .await;
    assert!(matches!(report.stopped, Some(Error::Cancelled)));
    assert!(server.exists("/r/tree/a.txt"));
}

#[cfg(unix)]
#[tokio::test]
async fn delete_never_follows_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let doomed = tmp.path().join("doomed");
    let keep = tmp.path().join("keep");
    std::fs::create_dir_all(doomed.join("x")).unwrap();
    std::fs::create_dir_all(&keep).unwrap();
    std::fs::write(keep.join("precious"), b"!").unwrap();
    std::fs::write(doomed.join("x/f"), b"f").unwrap();
    std::os::unix::fs::symlink(&keep, doomed.join("x/link")).unwrap();
    let mut b = LocalBackend::new();
    let cancel = CancellationToken::new();
    b.connect(cancel.clone()).await.unwrap();
    let mut opts = WalkOptions::local(sid());
    opts.follow_symlinks = true; // ignored by delete
    let report = delete_recursive(
        &mut b,
        vec![Target::new(
            local_to_remote(&doomed).unwrap(),
            Entry::dir("doomed"),
        )],
        opts,
        &cancel,
    )
    .await;
    assert!(report.is_complete(), "{report:?}");
    assert!(!doomed.exists());
    assert!(keep.join("precious").exists());
}

// -------------------------------------------------------------------- chmod

#[test]
fn chmod_tristate_masks() {
    assert_eq!(apply_mask(0o644, 0o755, 0o7777), 0o755);
    assert_eq!(apply_mask(0o644, 0o100, 0o100), 0o744);
    assert_eq!(apply_mask(0o4755, 0o000, 0o4022), 0o755);
    assert_eq!(apply_mask(0o777, 0o000, 0o077), 0o700);

    let mut spec = ChmodSpec::exact(0);
    spec.mask = 0;
    spec.set_bit(0o100, Some(true)); // owner x on
    spec.set_bit(0o002, Some(false)); // world w off
    spec.set_bit(0o040, None); // group r unchanged
    assert_eq!((spec.mode, spec.mask), (0o100, 0o102));
    assert_eq!(spec.compute(Some(0o646)), Some(0o744));
    assert_eq!(spec.compute(Some(0o600)), Some(0o700));
    // Unknown old mode: only a full rwx mask gives an answer.
    assert_eq!(spec.compute(None), None);
    assert_eq!(ChmodSpec::exact(0o750).compute(None), Some(0o750));
    let mut rwx = ChmodSpec::exact(0o640);
    rwx.set_bit(0o4000, None);
    assert_eq!(rwx.compute(None), Some(0o640));
    assert_eq!(rwx.compute(Some(0o4777)), Some(0o4640));
}

fn mode_of(server: &MockServer, path: &str) -> u32 {
    let mut b = server.backend();
    futures_block(async move {
        b.connect(CancellationToken::new()).await.unwrap();
        b.stat(&p(path))
            .await
            .unwrap()
            .permissions
            .unwrap()
            .bits()
            .unwrap()
    })
}

fn futures_block<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chmod_apply_to_files_dirs_and_all() {
    let cancel = CancellationToken::new();
    // Files only, owner x on: dirs keep 755, files 744.
    let server = mock_tree();
    let mut b = connected(&server).await;
    let mut spec = ChmodSpec::exact(0);
    spec.mask = 0;
    spec.set_bit(0o100, Some(true));
    spec.recurse = true;
    spec.apply_to = ApplyTo::FilesOnly;
    let r = chmod_recursive(
        &mut b,
        vec![dir_target("/r/tree")],
        spec,
        WalkOptions::remote(sid()),
        &cancel,
    )
    .await;
    assert!(r.is_complete(), "{r:?}");
    assert_eq!((r.files, r.dirs), (5, 0));
    assert_eq!(mode_of(&server, "/r/tree/sub/deep/d.txt"), 0o744);
    assert_eq!(mode_of(&server, "/r/tree/sub"), 0o755);

    // Dirs only, world r+x off (others unchanged).
    let mut spec = ChmodSpec::exact(0);
    spec.mask = 0;
    spec.set_bit(0o004, Some(false));
    spec.set_bit(0o001, Some(false));
    spec.recurse = true;
    spec.apply_to = ApplyTo::DirsOnly;
    let r = chmod_recursive(
        &mut b,
        vec![dir_target("/r/tree")],
        spec,
        WalkOptions::remote(sid()),
        &cancel,
    )
    .await;
    assert_eq!((r.files, r.dirs), (0, 5));
    assert_eq!(mode_of(&server, "/r/tree"), 0o750);
    assert_eq!(mode_of(&server, "/r/tree/sub/deep"), 0o750);
    assert_eq!(mode_of(&server, "/r/tree/a.txt"), 0o744);

    // All, exact 600 with a filter: logs.log/ and b.log untouched. 600
    // takes the owner's x away: directories are changed after listing.
    let mut b = Faulty::new(&server, &[]);
    b.connect(cancel.clone()).await.unwrap();
    let ops = Arc::clone(&b.ops);
    let mut spec = ChmodSpec::exact(0o600);
    spec.recurse = true;
    let mut opts = WalkOptions::remote(sid());
    opts.filter = name_filter(".log");
    let r = chmod_recursive(&mut b, vec![dir_target("/r/tree")], spec, opts, &cancel).await;
    assert!(r.is_complete(), "{r:?}");
    assert_eq!((r.files, r.dirs), (3, 4));
    assert_eq!(mode_of(&server, "/r/tree/b.log"), 0o744);
    assert_eq!(mode_of(&server, "/r/tree/logs.log"), 0o750);
    assert_eq!(mode_of(&server, "/r/tree/sub/c.txt"), 0o600);
    assert_eq!(ops.lock().unwrap().last().unwrap(), "chmod 600 /r/tree");

    // Without recursion only the selection changes.
    let mut b = connected(&server).await;
    let r = chmod_recursive(
        &mut b,
        vec![dir_target("/r/tree/sub")],
        ChmodSpec::exact(0o711),
        WalkOptions::remote(sid()),
        &cancel,
    )
    .await;
    assert_eq!((r.files, r.dirs), (0, 1));
    assert_eq!(mode_of(&server, "/r/tree/sub"), 0o711);
    assert_eq!(mode_of(&server, "/r/tree/sub/deep"), 0o600);
}

#[tokio::test]
async fn chmod_leaves_unknown_permissions_and_symlinks_alone() {
    let mut tree = TreeBackend::new(1, 1, 1);
    tree.link = Some("..");
    let mut spec = ChmodSpec::exact(0);
    spec.mask = 0;
    spec.set_bit(0o200, Some(true));
    spec.recurse = true;
    let r = chmod_recursive(
        &mut tree,
        vec![dir_target("/t")],
        spec,
        WalkOptions::remote(sid()),
        &CancellationToken::new(),
    )
    .await;
    // Tree entries carry no permissions: 3 left unchanged with a reason, 2
    // links skipped, nothing chmodded.
    assert_eq!((r.files, r.dirs), (0, 0));
    assert_eq!(r.unchanged, 5);
    assert_eq!(r.problem_count, 3);
    assert!(r.problems.iter().all(|p| p.reason.contains("unknown")));
}

// ----------------------------------------------------------------- expander

fn quick() -> QueueServer {
    QueueServer::Quick {
        address: ServerAddress::new(Protocol::Sftp, "mock.invalid"),
        password: None,
    }
}

fn queued(item: NewItem) -> QueueItem {
    let mut q = Queue::default();
    let id = q.add(item, OffsetDateTime::UNIX_EPOCH);
    q.get(id).unwrap().clone()
}

fn settings() -> Settings {
    let mut s = Settings::default();
    s.connection.keepalive = false;
    s.file_types.default_type = crate::settings::TransferTypeChoice::Binary;
    s
}

fn names(items: &[NewItem]) -> Vec<String> {
    items
        .iter()
        .map(|i| {
            let name = i.remote.file_name().unwrap_or("").to_owned();
            if i.is_dir_placeholder {
                format!("{name}/")
            } else {
                name
            }
        })
        .collect()
}

#[tokio::test]
async fn expander_lists_one_level_with_filters() {
    let tmp = tempfile::tempdir().unwrap();
    let server = mock_tree();
    let mut remote = connected(&server).await;
    let mut local = LocalBackend::new();
    let cancel = CancellationToken::new();
    local.connect(cancel.clone()).await.unwrap();
    let (tx, mut rx) = events::channel(2);
    let expander = RecursiveExpander::new(&settings()).with_events(tx, sid());
    expander.set_filters(FilterEngine::default(), name_filter(".log"));

    let target = tmp.path().join("dl/tree");
    let mut top = dir_placeholder(
        quick(),
        Direction::Download,
        LocalPath::new(&target),
        p("/r/tree"),
    );
    top.priority = crate::queue::Priority::High;
    let children = expander
        .expand(&queued(top), &mut remote, &mut local, &cancel)
        .await
        .unwrap();
    assert_eq!(names(&children), ["a.txt", "empty/", "sub/"]);
    assert_eq!(children[0].local, LocalPath::new(target.join("a.txt")));
    assert_eq!(children[0].size, Some(3));
    assert!(
        children
            .iter()
            .all(|c| c.priority == crate::queue::Priority::High)
    );
    // The level has a file: its directory (and missing parents) exist.
    assert!(target.is_dir());
    let logs: Vec<_> = drain(&mut rx)
        .into_iter()
        .filter_map(|e| match e {
            CoreEvent::Log(m) if m.kind == LogKind::Status => Some(m.text),
            _ => None,
        })
        .collect();
    assert_eq!(logs, ["2 entries in /r/tree excluded by filters"]);

    // An empty directory is created with `create`, not with `skip`.
    let empty = children[1].clone();
    let got = expander
        .expand(&queued(empty.clone()), &mut remote, &mut local, &cancel)
        .await
        .unwrap();
    assert!(got.is_empty());
    assert!(target.join("empty").is_dir());
    std::fs::remove_dir(target.join("empty")).unwrap();
    let mut s = settings();
    s.transfers.empty_dirs = EmptyDirs::Skip;
    expander.apply_settings(&s);
    expander
        .expand(&queued(empty), &mut remote, &mut local, &cancel)
        .await
        .unwrap();
    assert!(!target.join("empty").exists());
    // A level with only a subdirectory isn't created by itself.
    server.add_dir("/r/only").add_dir("/r/only/inner");
    let only = dir_placeholder(
        quick(),
        Direction::Download,
        LocalPath::new(tmp.path().join("only")),
        p("/r/only"),
    );
    let got = expander
        .expand(&queued(only), &mut remote, &mut local, &cancel)
        .await
        .unwrap();
    assert_eq!(names(&got), ["inner/"]);
    assert!(!tmp.path().join("only").exists());
}

#[tokio::test]
async fn expander_uploads_create_remote_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("up");
    std::fs::create_dir_all(src.join("nested")).unwrap();
    std::fs::write(src.join("one"), b"1").unwrap();
    std::fs::write(src.join("skip.log"), b"x").unwrap();
    let server = MockServer::new();
    let mut remote = connected(&server).await;
    let mut local = LocalBackend::new();
    let cancel = CancellationToken::new();
    local.connect(cancel.clone()).await.unwrap();
    let expander = RecursiveExpander::new(&settings());
    expander.set_filters(name_filter(".log"), FilterEngine::default());
    let item = dir_placeholder(
        quick(),
        Direction::Upload,
        LocalPath::new(&src),
        p("/a/b/up"),
    );
    let got = expander
        .expand(&queued(item), &mut remote, &mut local, &cancel)
        .await
        .unwrap();
    assert_eq!(names(&got), ["one", "nested/"]);
    assert_eq!(got[1].remote, p("/a/b/up/nested"));
    assert_eq!(got[1].local, LocalPath::new(src.join("nested")));
    assert!(server.exists("/a/b/up"), "mkdir -p");
}

#[cfg(unix)]
#[tokio::test]
async fn expander_skips_local_symlink_loops() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("up");
    std::fs::create_dir_all(src.join("a")).unwrap();
    std::fs::write(src.join("a/f"), b"1").unwrap();
    std::os::unix::fs::symlink("..", src.join("a/loop")).unwrap();
    std::os::unix::fs::symlink(src.join("a/f"), src.join("a/flink")).unwrap();
    let server = MockServer::new();
    let mut remote = connected(&server).await;
    let mut local = LocalBackend::new();
    let cancel = CancellationToken::new();
    local.connect(cancel.clone()).await.unwrap();

    let mut s = settings();
    s.transfers.follow_symlinks = true;
    let expander = RecursiveExpander::new(&s);
    let item = dir_placeholder(
        quick(),
        Direction::Upload,
        LocalPath::new(src.join("a")),
        p("/x/a"),
    );
    let got = expander
        .expand(&queued(item.clone()), &mut remote, &mut local, &cancel)
        .await
        .unwrap();
    // The link to a file is a file; the loop isn't followed.
    assert_eq!(names(&got), ["f", "flink"]);

    // Not following: the link to a directory is left out too.
    s.transfers.follow_symlinks = false;
    expander.apply_settings(&s);
    let got = expander
        .expand(&queued(item), &mut remote, &mut local, &cancel)
        .await
        .unwrap();
    assert_eq!(names(&got), ["f", "flink"]);
}

#[tokio::test]
async fn expander_follows_remote_links_but_not_loops() {
    let mut tree = TreeBackend::new(2, 1, 1);
    tree.link = Some("..");
    let tmp = tempfile::tempdir().unwrap();
    let mut local = LocalBackend::new();
    let cancel = CancellationToken::new();
    local.connect(cancel.clone()).await.unwrap();
    let mut s = settings();
    s.transfers.follow_symlinks = true;
    let expander = RecursiveExpander::new(&s);
    // Expand the whole tree like the engine would, breadth by placeholders.
    let mut pending = vec![dir_placeholder(
        quick(),
        Direction::Download,
        LocalPath::new(tmp.path().join("t")),
        p("/t"),
    )];
    let mut files = Vec::new();
    let mut rounds = 0;
    while let Some(item) = pending.pop() {
        rounds += 1;
        assert!(rounds < 100, "loop not detected");
        for child in expander
            .expand(&queued(item), &mut tree, &mut local, &cancel)
            .await
            .unwrap()
        {
            if child.is_dir_placeholder {
                pending.push(child);
            } else {
                files.push(child.remote.to_string());
            }
        }
    }
    assert_eq!(files, ["/t/d0/d0/f0"]);
}

// ------------------------------------------------------------ with the engine

struct Resolver;

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
}

struct Factory(MockServer);

impl BackendFactory for Factory {
    fn create(&self, _: &ConnectInfo, _: SessionId, _: EventSender) -> Box<dyn Backend> {
        Box::new(self.0.backend())
    }
}

#[tokio::test]
async fn engine_downloads_a_tree_through_placeholders() {
    let tmp = tempfile::tempdir().unwrap();
    let server = mock_tree();
    let queue = Arc::new(Mutex::new(Queue::default()));
    let (tx, mut rx) = events::channel(2);
    let s = settings();
    let expander = RecursiveExpander::new(&s);
    expander.set_filters(FilterEngine::default(), name_filter(".log"));
    let (engine, handle) = TransferEngine::builder(
        Arc::clone(&queue),
        Arc::new(Factory(server.clone())),
        Arc::new(Resolver),
        tx,
    )
    .settings(s)
    .dir_expander(Arc::new(expander))
    .build();
    let task = engine.spawn();
    let target = tmp.path().join("tree");
    queue.lock().unwrap().add(
        dir_placeholder(
            quick(),
            Direction::Download,
            LocalPath::new(&target),
            p("/r/tree"),
        ),
        OffsetDateTime::UNIX_EPOCH,
    );
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
    assert_eq!(stats.files_ok, 3, "{stats:?}");
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"aaa");
    assert_eq!(std::fs::read(target.join("sub/deep/d.txt")).unwrap(), b"dd");
    assert!(target.join("empty").is_dir());
    assert!(!target.join("b.log").exists());
    assert!(!target.join("logs.log").exists());
    handle.shutdown();
    task.await.unwrap();
}

#[test]
fn thousands_are_grouped() {
    assert_eq!(group_thousands(0), "0");
    assert_eq!(group_thousands(999), "999");
    assert_eq!(group_thousands(1234), "1 234");
    assert_eq!(group_thousands(1_234_567), "1 234 567");
}

#[test]
fn placeholder_helper() {
    let item = dir_placeholder(quick(), Direction::Upload, LocalPath::new("/l"), p("/r"));
    assert!(item.is_dir_placeholder);
    assert_eq!(item.size, None);
}
