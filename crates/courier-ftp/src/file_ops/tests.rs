//! T62: the operations against the core's `MockServer` and the local
//! filesystem, with the listing cache patched as they go.

use std::time::Duration;

use courier_ftp_core::{
    backend::{Backend, MockServer},
    events::{self, CoreEvent, EventReceiver},
    model::Permissions,
    settings::CacheSettings,
    transfer::recursive::ApplyTo,
};
use pretty_assertions::assert_eq;

use super::*;

fn ctx(place: Place, server: Option<ServerAddress>) -> (OpCtx, EventReceiver) {
    let (events, rx) = events::channel(0);
    let cache = ListingCache::new(&CacheSettings::default(), Some(events.clone()));
    (
        OpCtx {
            place,
            server,
            session: SessionId(7),
            cache,
            events,
            timeout: Duration::from_secs(10),
            cancel: CancellationToken::new(),
            filter: FilterEngine::default(),
        },
        rx,
    )
}

async fn remote(server: &MockServer) -> (OpCtx, EventReceiver) {
    let handle = Arc::new(SessionHandle::new(Box::new(server.backend()), None));
    handle.connect(CancellationToken::new()).await.unwrap();
    let address = handle.lock().await.address().cloned();
    ctx(Place::Remote(handle), address)
}

/// List `dir` into the cache, as a pane would.
async fn cached(ctx: &OpCtx, dir: &str) {
    let mut guard = ctx.guard().await.unwrap();
    ctx.cache
        .list_with(
            guard.backend(),
            &RemotePath::new(dir),
            true,
            CancellationToken::new(),
        )
        .await
        .unwrap();
}

fn cached_names(ctx: &OpCtx, dir: &str) -> Vec<String> {
    let mut names: Vec<String> = ctx
        .cache
        .get(ctx.server.as_ref(), &RemotePath::new(dir))
        .expect("cached")
        .entries
        .into_iter()
        .map(|e| e.name)
        .collect();
    names.sort();
    names
}

fn updated(rx: &mut EventReceiver) -> Vec<String> {
    let mut dirs = Vec::new();
    while let Some(event) = rx.try_recv() {
        if let CoreEvent::ListingUpdated { session, dir } = event {
            assert_eq!(session, SessionId(7));
            dirs.push(dir.to_string());
        }
    }
    dirs
}

fn rename(from: &str, to: &str) -> Rename {
    Rename {
        from: RemotePath::new(from),
        to: RemotePath::new(to),
    }
}

fn target(path: &str, entry: Entry) -> Target {
    Target::new(RemotePath::new(path), entry)
}

#[tokio::test]
async fn mkdir_creates_parents_and_patches_the_cache() {
    let server = MockServer::new();
    server.add_dir("/srv");
    let (ctx, mut rx) = remote(&server).await;
    cached(&ctx, "/srv").await;
    mkdir_p(&ctx, &RemotePath::new("/srv/a/b/c")).await.unwrap();
    assert!(server.exists("/srv/a/b/c"));
    assert_eq!(cached_names(&ctx, "/srv"), ["a"]);
    assert_eq!(updated(&mut rx), ["/srv"]);
    // Again: it exists.
    let again = mkdir_p(&ctx, &RemotePath::new("/srv/a/b/c")).await;
    assert!(matches!(again, Err(Error::AlreadyExists)), "{again:?}");
    // A file in the way.
    server.add_file("/srv/f", b"x");
    let blocked = mkdir_p(&ctx, &RemotePath::new("/srv/f/sub")).await;
    assert!(
        matches!(&blocked, Err(Error::InvalidInput(m)) if m.contains("not a directory")),
        "{blocked:?}"
    );
}

#[tokio::test]
async fn rename_asks_before_replacing_a_file() {
    let server = MockServer::new();
    server.add_file("/srv/a.txt", b"new");
    server.add_file("/srv/b.txt", b"old");
    server.add_dir("/srv/dir");
    let (ctx, mut rx) = remote(&server).await;
    cached(&ctx, "/srv").await;

    let report = rename_all(&ctx, vec![rename("/srv/a.txt", "/srv/b.txt")], false)
        .await
        .unwrap();
    assert_eq!(report.conflicts, [rename("/srv/a.txt", "/srv/b.txt")]);
    assert!(report.done.is_empty());
    assert_eq!(server.read_file("/srv/b.txt").unwrap(), b"old");

    // Confirmed: the mock (like the local filesystem) refuses to replace,
    // so the old file is removed first.
    let report = rename_all(&ctx, vec![rename("/srv/a.txt", "/srv/b.txt")], true)
        .await
        .unwrap();
    assert_eq!(report.done, [rename("/srv/a.txt", "/srv/b.txt")]);
    assert_eq!(server.read_file("/srv/b.txt").unwrap(), b"new");
    assert!(!server.exists("/srv/a.txt"));
    assert_eq!(cached_names(&ctx, "/srv"), ["b.txt", "dir"]);
    assert!(updated(&mut rx).contains(&"/srv".to_owned()));

    // A directory is never replaced.
    let report = rename_all(&ctx, vec![rename("/srv/b.txt", "/srv/dir")], true)
        .await
        .unwrap();
    assert_eq!(report.failed.len(), 1, "{report:?}");
    assert!(server.exists("/srv/b.txt"));
}

#[tokio::test]
async fn move_into_another_directory_moves_cached_listings() {
    let server = MockServer::new();
    server.add_file("/srv/www/index.html", b"x");
    server.add_dir("/srv/archive");
    let (ctx, _rx) = remote(&server).await;
    cached(&ctx, "/srv").await;
    cached(&ctx, "/srv/archive").await;
    cached(&ctx, "/srv/www").await;
    let report = rename_all(&ctx, vec![rename("/srv/www", "/srv/archive/www")], false)
        .await
        .unwrap();
    assert_eq!(report.done.len(), 1);
    assert!(server.exists("/srv/archive/www/index.html"));
    assert_eq!(cached_names(&ctx, "/srv"), ["archive"]);
    assert_eq!(cached_names(&ctx, "/srv/archive"), ["www"]);
    assert_eq!(cached_names(&ctx, "/srv/archive/www"), ["index.html"]);
    // Into itself.
    let report = rename_all(&ctx, vec![rename("/srv/archive", "/srv/archive/x")], false)
        .await
        .unwrap();
    assert_eq!(report.failed.len(), 1);
}

#[tokio::test]
async fn recursive_delete_reports_progress_and_patches_the_cache() {
    let server = MockServer::new();
    server.add_file("/srv/keep.txt", b"k");
    for i in 0..20 {
        server.add_file(&format!("/srv/tree/d{}/f{i}", i % 4), b"x");
    }
    let (ctx, mut rx) = remote(&server).await;
    cached(&ctx, "/srv").await;
    let report = delete(&ctx, vec![target("/srv/tree", Entry::dir("tree"))]).await;
    assert!(report.is_complete(), "{report:?}");
    assert_eq!((report.files, report.dirs), (20, 5));
    assert!(!server.exists("/srv/tree"));
    assert_eq!(cached_names(&ctx, "/srv"), ["keep.txt"]);
    let mut finished = false;
    while let Some(event) = rx.try_recv() {
        if let CoreEvent::RecursiveProgress(p) = event {
            assert_eq!(p.session, SessionId(7));
            finished |= p.finished;
        }
    }
    assert!(finished, "a final progress event");
    let summary = OpSummary::from(&report);
    assert_eq!((summary.files, summary.dirs), (20, 5));
    assert!(!summary.cancelled);
}

#[tokio::test]
async fn cancelled_delete_stops() {
    let server = MockServer::new();
    server.add_file("/srv/tree/a", b"x");
    let (ctx, _rx) = remote(&server).await;
    ctx.cancel.cancel();
    let report = delete(&ctx, vec![target("/srv/tree", Entry::dir("tree"))]).await;
    assert!(OpSummary::from(&report).cancelled, "{report:?}");
    assert!(server.exists("/srv/tree/a"));
}

#[tokio::test]
async fn chmod_recursive_files_only() {
    let server = MockServer::new();
    server.add_file("/srv/www/a.html", b"x");
    server.add_file("/srv/www/css/b.css", b"x");
    let (ctx, _rx) = remote(&server).await;
    cached(&ctx, "/srv/www").await;
    let mut dir = Entry::dir("www");
    dir.permissions = Some(Permissions::from_mode(0o040_755));
    let spec = ChmodSpec {
        mode: 0o600,
        mask: 0o777,
        recurse: true,
        apply_to: ApplyTo::FilesOnly,
    };
    let report = chmod(&ctx, vec![target("/srv/www", dir)], spec).await;
    assert!(report.is_complete(), "{report:?}");
    assert_eq!((report.files, report.dirs), (2, 0));
    let mode = |p: &str| {
        let server = server.clone();
        let p = p.to_owned();
        async move {
            let mut b = server.backend();
            b.connect(CancellationToken::new()).await.unwrap();
            b.stat(&RemotePath::new(p))
                .await
                .unwrap()
                .permissions
                .unwrap()
                .bits()
                .unwrap()
        }
    };
    assert_eq!(mode("/srv/www/a.html").await, 0o600);
    assert_eq!(mode("/srv/www/css/b.css").await, 0o600);
    assert_eq!(mode("/srv/www").await, 0o755, "directories left alone");
    let cached = ctx
        .cache
        .get(ctx.server.as_ref(), &RemotePath::new("/srv/www"))
        .unwrap();
    let a = cached.entries.iter().find(|e| e.name == "a.html").unwrap();
    assert_eq!(
        a.permissions.as_ref().and_then(Permissions::bits),
        Some(0o600)
    );
}

#[tokio::test]
async fn local_operations() {
    let tmp = tempfile::tempdir().unwrap();
    let base = courier_ftp_core::local::local_to_remote(tmp.path()).unwrap();
    let (ctx, _rx) = ctx(Place::Local, None);
    cached(&ctx, base.as_str()).await;
    let nested = base.join_path("x/y");
    mkdir_p(&ctx, &nested).await.unwrap();
    assert!(tmp.path().join("x/y").is_dir());
    assert_eq!(cached_names(&ctx, base.as_str()), ["x"]);
    std::fs::write(tmp.path().join("a"), b"a").unwrap();
    std::fs::write(tmp.path().join("b"), b"b").unwrap();
    let r = Rename {
        from: base.join("a").unwrap(),
        to: base.join("b").unwrap(),
    };
    let report = rename_all(&ctx, vec![r.clone()], false).await.unwrap();
    assert_eq!(report.conflicts, std::slice::from_ref(&r));
    let report = rename_all(&ctx, vec![r], true).await.unwrap();
    assert_eq!(report.done.len(), 1, "{report:?}");
    assert_eq!(std::fs::read(tmp.path().join("b")).unwrap(), b"a");
    let report = delete(
        &ctx,
        vec![Target::new(base.join("x").unwrap(), Entry::dir("x"))],
    )
    .await;
    assert!(report.is_complete(), "{report:?}");
    assert!(!tmp.path().join("x").exists());
    assert_eq!(
        stat(&ctx, &base.join("b").unwrap())
            .await
            .unwrap()
            .map(|e| e.name),
        Some("b".to_owned())
    );
    assert_eq!(stat(&ctx, &base.join("zz").unwrap()).await.unwrap(), None);
}
