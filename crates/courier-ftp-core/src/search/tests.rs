//! T49 tests: searches over the in-memory mock server and over temp
//! directories with the local backend.

use std::time::{Duration, Instant, SystemTime};

use pretty_assertions::assert_eq;
use time::macros::datetime;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::{
    backend::{Backend, MockServer},
    cache::ListingCache,
    events::SessionId,
    filters::{DateOp, NumOp, StringOp},
    local::local_to_remote,
    model::{Direction, Protocol, ServerAddress},
    queue::QueueServer,
    settings::CacheSettings,
};

fn sid() -> SessionId {
    SessionId(9)
}

fn p(s: &str) -> RemotePath {
    RemotePath::new(s)
}

fn name(op: StringOp, value: &str) -> Condition {
    Condition::Name {
        op,
        value: value.into(),
    }
}

fn remote_query(root: &str, conditions: Vec<Condition>) -> SearchQuery {
    SearchQuery {
        conditions,
        ..SearchQuery::new(SearchRoot::Remote(p(root)))
    }
}

/// `/srv` with a small site.
fn site() -> MockServer {
    let s = MockServer::new();
    s.add_dir("/srv")
        .add_file("/srv/index.html", b"<html>")
        .add_file("/srv/README.md", b"readme")
        .add_file("/srv/css/site.css", b"body{}")
        .add_file("/srv/css/old/site.css", b"x")
        .add_file("/srv/img/logo.png", &[0u8; 2048])
        .add_file("/srv/img/big.png", &[0u8; 10_000])
        .add_dir("/srv/img/empty")
        .add_file("/outside.css", b"no");
    s
}

/// Drain a handle: (hits, final event).
async fn drain(handle: &mut SearchHandle) -> (Vec<SearchHit>, SearchEvent) {
    let mut hits = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(10), handle.recv())
            .await
            .expect("search hung")
        {
            Some(SearchEvent::Found(hit)) => hits.push(hit),
            Some(SearchEvent::Progress(_)) => {}
            Some(last) => return (hits, last),
            None => panic!("channel closed without a final event"),
        }
    }
}

fn paths(hits: &[SearchHit]) -> Vec<String> {
    let mut v: Vec<String> = hits.iter().map(|h| h.path.to_string()).collect();
    v.sort();
    v
}

async fn run_remote(server: &MockServer, query: SearchQuery) -> (Vec<SearchHit>, SearchSummary) {
    let mut handle = spawn_search(
        Box::new(server.backend()),
        query,
        SearchOptions::remote(sid()),
    )
    .unwrap();
    match drain(&mut handle).await {
        (hits, SearchEvent::Done(summary)) => (hits, summary),
        (_, other) => panic!("unexpected end: {other:?}"),
    }
}

// ------------------------------------------------------------------ matching

#[tokio::test]
async fn finds_files_by_name_below_the_root_only() {
    let server = site();
    let mut q = remote_query("/srv", vec![name(StringOp::EndsWith, ".css")]);
    q.search_type = SearchType::Files;
    let (hits, summary) = run_remote(&server, q).await;
    assert_eq!(paths(&hits), ["/srv/css/old/site.css", "/srv/css/site.css"]);
    assert_eq!(summary.matches, 2);
    // /srv, css, css/old, img, img/empty
    assert_eq!(summary.dirs_scanned, 5);
    assert_eq!(summary.entries_scanned, 10);
    assert!(!summary.cancelled && !summary.truncated);
    assert_eq!(hits[0].relative(&p("/srv")), Some("css/old/site.css"));
}

#[tokio::test]
async fn search_type_and_no_conditions() {
    let server = site();
    let mut q = remote_query("/srv", vec![]);
    q.search_type = SearchType::Dirs;
    let (hits, _) = run_remote(&server, q.clone()).await;
    // The root itself is never a result.
    assert_eq!(
        paths(&hits),
        ["/srv/css", "/srv/css/old", "/srv/img", "/srv/img/empty"]
    );
    q.search_type = SearchType::Both;
    let (hits, _) = run_remote(&server, q.clone()).await;
    assert_eq!(hits.len(), 10);
    q.search_type = SearchType::Dirs;
    q.conditions = vec![name(StringOp::Contains, "s")];
    let (hits, _) = run_remote(&server, q).await;
    assert_eq!(paths(&hits), ["/srv/css"]);
}

#[tokio::test]
async fn conditions_combine_with_all_and_any() {
    let server = site();
    let conditions = vec![
        Condition::Path {
            op: StringOp::Contains,
            value: "/img/".into(),
        },
        Condition::Size {
            op: NumOp::Greater,
            value: 4096,
        },
    ];
    let mut q = remote_query("/srv", conditions);
    q.search_type = SearchType::Files;
    q.match_mode = MatchMode::All;
    let (hits, _) = run_remote(&server, q.clone()).await;
    assert_eq!(paths(&hits), ["/srv/img/big.png"]);
    q.match_mode = MatchMode::Any;
    let (hits, _) = run_remote(&server, q).await;
    assert_eq!(paths(&hits), ["/srv/img/big.png", "/srv/img/logo.png"]);
}

#[tokio::test]
async fn case_sensitivity_and_regex() {
    let server = site();
    let mut q = remote_query("/srv", vec![name(StringOp::Equals, "readme.md")]);
    let (hits, _) = run_remote(&server, q.clone()).await;
    assert_eq!(paths(&hits), ["/srv/README.md"]);
    q.case_sensitive = true;
    let (hits, _) = run_remote(&server, q.clone()).await;
    assert!(hits.is_empty());
    q.conditions = vec![name(StringOp::Matches, r"^[a-z]+\.png$")];
    let (hits, _) = run_remote(&server, q.clone()).await;
    assert_eq!(paths(&hits), ["/srv/img/big.png", "/srv/img/logo.png"]);

    q.conditions = vec![name(StringOp::Matches, "(unclosed")];
    assert!(matches!(q.validate(), Err(Error::InvalidInput(_))));
    let err = spawn_search(Box::new(server.backend()), q, SearchOptions::remote(sid()));
    assert!(matches!(err, Err(Error::InvalidInput(_))));
}

#[tokio::test]
async fn local_search_with_dates_sizes_and_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(root.join("logs/2023")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    let files = [
        ("logs/2023/a.log", 10, datetime!(2023-06-01 12:00 UTC)),
        ("logs/b.log", 5000, datetime!(2024-03-10 12:00 UTC)),
        ("src/main.rs", 300, datetime!(2024-03-12 12:00 UTC)),
    ];
    for (rel, size, mtime) in files {
        let path = root.join(rel);
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(size).unwrap();
        f.set_modified(SystemTime::from(mtime)).unwrap();
    }
    let local = |conditions, match_mode| SearchQuery {
        conditions,
        match_mode,
        search_type: SearchType::Files,
        ..SearchQuery::new(SearchRoot::Local(LocalPath::new(&root)))
    };
    let run = |q: SearchQuery| async move {
        let mut handle = spawn_local_search(q, SearchOptions::local(sid())).unwrap();
        let (hits, last) = drain(&mut handle).await;
        assert!(matches!(last, SearchEvent::Done(_)), "{last:?}");
        let mut names: Vec<String> = hits.iter().map(|h| h.entry.name.clone()).collect();
        names.sort();
        (names, hits)
    };
    let after_2024 = Condition::Date {
        op: DateOp::After,
        value: datetime!(2024-01-01 0:00 UTC),
    };
    let (names, hits) = run(local(vec![after_2024.clone()], MatchMode::All)).await;
    assert_eq!(names, ["b.log", "main.rs"]);
    // Local hits convert back to native paths.
    let native = hits
        .iter()
        .find(|h| h.entry.name == "main.rs")
        .unwrap()
        .local_path()
        .unwrap();
    assert_eq!(native.as_path(), root.join("src/main.rs"));

    let log = name(StringOp::EndsWith, ".log");
    let (names, _) = run(local(vec![after_2024.clone(), log.clone()], MatchMode::All)).await;
    assert_eq!(names, ["b.log"]);
    let (names, _) = run(local(vec![after_2024, log], MatchMode::Any)).await;
    assert_eq!(names, ["a.log", "b.log", "main.rs"]);
    let small = Condition::Size {
        op: NumOp::Less,
        value: 1000,
    };
    let in_logs = Condition::Path {
        op: StringOp::Contains,
        value: "logs".into(),
    };
    let (names, _) = run(local(vec![small, in_logs], MatchMode::All)).await;
    assert_eq!(names, ["a.log"]);

    let relative = SearchQuery::new(SearchRoot::Local(LocalPath::new("relative/dir")));
    assert!(matches!(relative.validate(), Err(Error::InvalidInput(_))));
}

// ------------------------------------------------------------ streaming, cancel

/// A tree of `dirs` directories with `files` files each under `/t`.
fn wide(dirs: usize, files: usize) -> MockServer {
    let s = MockServer::new();
    s.add_dir("/t");
    for d in 0..dirs {
        for f in 0..files {
            s.add_file(&format!("/t/d{d:03}/f{f}.txt"), b"x");
        }
    }
    s
}

#[tokio::test]
async fn results_stream_before_the_search_finishes() {
    let server = wide(30, 3);
    server.set_latency(Duration::from_millis(20));
    let mut handle = spawn_search(
        Box::new(server.backend()),
        remote_query("/t", vec![name(StringOp::EndsWith, ".txt")]),
        SearchOptions::remote(sid()),
    )
    .unwrap();
    let first = loop {
        match handle.recv().await.unwrap() {
            SearchEvent::Found(hit) => break hit,
            SearchEvent::Progress(_) => {}
            other => panic!("ended before a result: {other:?}"),
        }
    };
    assert_eq!(first.path, p("/t/d000/f0.txt"));
    // 31 listings at 20 ms each are still ahead.
    assert!(!handle.is_finished());
    let (rest, last) = drain(&mut handle).await;
    assert_eq!(rest.len(), 89);
    let SearchEvent::Done(summary) = last else {
        panic!("{last:?}")
    };
    assert_eq!(summary.matches, 90);
}

#[tokio::test]
async fn progress_reports_scanned_directories() {
    let server = wide(10, 1);
    server.set_latency(Duration::from_millis(30));
    let mut handle = spawn_search(
        Box::new(server.backend()),
        remote_query("/t", vec![name(StringOp::Equals, "nothing")]),
        SearchOptions::remote(sid()),
    )
    .unwrap();
    let mut progress = Vec::new();
    let summary = loop {
        match handle.recv().await.unwrap() {
            SearchEvent::Progress(pr) => progress.push(pr),
            SearchEvent::Done(s) => break s,
            other => panic!("{other:?}"),
        }
    };
    assert!(progress.len() >= 2, "{progress:?}");
    assert!(
        progress
            .windows(2)
            .all(|w| w[0].dirs_scanned <= w[1].dirs_scanned)
    );
    assert!(progress.iter().all(|p| p.matches == 0));
    assert_eq!(summary.dirs_scanned, 11);
    assert_eq!(summary.matches, 0);
}

#[tokio::test]
async fn cancel_stops_within_a_second_even_mid_listing() {
    let server = wide(20, 2);
    // A tiny channel keeps the walk in step with this receiver.
    let mut opts = SearchOptions::remote(sid());
    opts.channel_capacity = 1;
    let mut handle =
        spawn_search(Box::new(server.backend()), remote_query("/t", vec![]), opts).unwrap();
    // Let a few results through, then make the server hang on every call.
    let mut seen = 0;
    while seen < 3 {
        if let Some(SearchEvent::Found(_)) = handle.recv().await {
            seen += 1;
        }
    }
    server.set_latency(Duration::from_secs(3600));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let started = Instant::now();
    handle.cancel();
    let (_, last) = drain(&mut handle).await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    let SearchEvent::Done(summary) = last else {
        panic!("{last:?}")
    };
    assert!(summary.cancelled);
    assert!(summary.matches >= 3);
    assert!(handle.recv().await.is_none());
}

#[tokio::test]
async fn cancel_while_connecting() {
    let server = site();
    server.set_latency(Duration::from_secs(3600));
    let mut handle = spawn_search(
        Box::new(server.backend()),
        remote_query("/srv", vec![]),
        SearchOptions::remote(sid()),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let started = Instant::now();
    handle.cancel();
    let (hits, last) = drain(&mut handle).await;
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(hits.is_empty());
    assert!(matches!(
        last,
        SearchEvent::Done(SearchSummary {
            cancelled: true,
            ..
        })
    ));
}

#[tokio::test]
async fn dropping_the_handle_cancels() {
    let server = wide(5, 1);
    server.set_latency(Duration::from_secs(3600));
    let handle = spawn_search(
        Box::new(server.backend()),
        remote_query("/t", vec![]),
        SearchOptions::remote(sid()),
    )
    .unwrap();
    let token = handle.cancel_token().clone();
    drop(handle);
    assert!(token.is_cancelled());
}

#[tokio::test]
async fn result_limit_truncates() {
    let server = wide(10, 5);
    let mut opts = SearchOptions::remote(sid());
    opts.max_results = Some(7);
    let mut handle = spawn_search(
        Box::new(server.backend()),
        remote_query("/t", vec![name(StringOp::BeginsWith, "f")]),
        opts,
    )
    .unwrap();
    let (hits, last) = drain(&mut handle).await;
    assert_eq!(hits.len(), 7);
    let SearchEvent::Done(summary) = last else {
        panic!("{last:?}")
    };
    assert!(summary.truncated);
    assert_eq!(summary.matches, 7);
}

// ------------------------------------------------------------ sessions, cache, errors

#[tokio::test]
async fn runs_on_its_own_session_and_closes_it() {
    let server = site();
    // The browsing session stays connected and usable throughout.
    let mut browsing = server.backend();
    browsing.connect(CancellationToken::new()).await.unwrap();
    assert_eq!(server.open_connections(), 1);
    let fresh = server.backend();
    assert!(!fresh.is_connected());
    let mut handle = spawn_search(
        Box::new(fresh),
        remote_query("/srv", vec![]),
        SearchOptions::remote(sid()),
    )
    .unwrap();
    let (hits, _) = drain(&mut handle).await;
    assert_eq!(hits.len(), 10);
    assert_eq!(server.connects(), 2);
    // Wait for the task to disconnect its session.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !handle.is_finished() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(server.open_connections(), 1);
    assert!(
        browsing
            .list(&p("/srv"), CancellationToken::new())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn uses_and_fills_the_listing_cache() {
    let server = site();
    let cache = ListingCache::new(&CacheSettings::default(), None);
    let mut opts = SearchOptions::remote(sid());
    opts.walk.cache = Some(cache.clone());
    let addr = server.backend().address().cloned();

    let mut handle = spawn_search(
        Box::new(server.backend()),
        remote_query("/srv", vec![]),
        opts.clone(),
    )
    .unwrap();
    let (first, _) = drain(&mut handle).await;
    assert!(cache.get(addr.as_ref(), &p("/srv/css/old")).is_some());
    let calls = server.calls();

    // Second search: every directory comes from the cache.
    let mut handle = spawn_search(
        Box::new(server.backend()),
        remote_query("/srv", vec![]),
        opts,
    )
    .unwrap();
    let (second, _) = drain(&mut handle).await;
    assert_eq!(paths(&first), paths(&second));
    let listing_calls = server.calls() - calls;
    // Only connect / disconnect, no listings.
    assert!(listing_calls <= 2, "{listing_calls} calls");
}

#[cfg(unix)]
#[tokio::test]
async fn unlistable_subdirectories_are_skipped_and_reported() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(root.join("locked")).unwrap();
    std::fs::create_dir_all(root.join("open")).unwrap();
    std::fs::write(root.join("locked/a.txt"), b"x").unwrap();
    std::fs::write(root.join("open/b.txt"), b"x").unwrap();
    let mode = |m| std::fs::Permissions::from_mode(m);
    std::fs::set_permissions(root.join("locked"), mode(0o000)).unwrap();
    if std::fs::read_dir(root.join("locked")).is_ok() {
        // Running as root: permissions don't apply.
        std::fs::set_permissions(root.join("locked"), mode(0o755)).unwrap();
        return;
    }
    let mut q = SearchQuery::new(SearchRoot::Local(LocalPath::new(&root)));
    q.search_type = SearchType::Files;
    let mut handle = spawn_local_search(q, SearchOptions::local(sid())).unwrap();
    let (hits, last) = drain(&mut handle).await;
    std::fs::set_permissions(root.join("locked"), mode(0o755)).unwrap();
    let SearchEvent::Done(summary) = last else {
        panic!("{last:?}")
    };
    let names: Vec<_> = hits.iter().map(|h| h.entry.name.as_str()).collect();
    assert_eq!(names, ["b.txt"]);
    assert_eq!(summary.skipped_count, 1);
    assert_eq!(summary.skipped[0].path.file_name(), Some("locked"));
}

#[tokio::test]
async fn missing_root_is_an_error() {
    let server = site();
    let mut handle = spawn_search(
        Box::new(server.backend()),
        remote_query("/nope", vec![]),
        SearchOptions::remote(sid()),
    )
    .unwrap();
    let (hits, last) = drain(&mut handle).await;
    assert!(hits.is_empty());
    assert!(matches!(last, SearchEvent::Error(_)), "{last:?}");
}

#[tokio::test]
async fn failed_connect_is_an_error() {
    let server = site();
    server.fail_connect(Error::Auth("denied".into()));
    let mut handle = spawn_search(
        Box::new(server.backend()),
        remote_query("/srv", vec![]),
        SearchOptions::remote(sid()),
    )
    .unwrap();
    let (_, last) = drain(&mut handle).await;
    assert!(
        matches!(last, SearchEvent::Error(Error::Auth(_))),
        "{last:?}"
    );
}

#[tokio::test]
async fn search_on_a_borrowed_session() {
    let server = site();
    let mut b = server.backend();
    let cancel = CancellationToken::new();
    b.connect(cancel.clone()).await.unwrap();
    let (tx, mut rx) = mpsc::channel(64);
    let last = search(
        &mut b,
        &remote_query("/srv", vec![name(StringOp::Contains, "logo")]),
        SearchOptions::remote(sid()),
        &tx,
        &cancel,
    )
    .await
    .unwrap();
    drop(tx);
    let mut hits = Vec::new();
    while let Some(ev) = rx.recv().await {
        if let SearchEvent::Found(h) = ev {
            hits.push(h);
        }
    }
    assert_eq!(paths(&hits), ["/srv/img/logo.png"]);
    assert!(matches!(
        last,
        SearchEvent::Done(SearchSummary { matches: 1, .. })
    ));
    assert!(b.is_connected());
}

// ------------------------------------------------------------ result actions

fn quick() -> QueueServer {
    QueueServer::Quick {
        address: ServerAddress::new(Protocol::Sftp, "mock.invalid"),
        password: None,
    }
}

fn hit(path: &str, entry: Entry) -> SearchHit {
    SearchHit {
        path: p(path),
        entry,
    }
}

#[test]
fn download_keeps_structure_or_flattens() {
    let hits = vec![
        hit("/srv/css/site.css", Entry::file("site.css", 6)),
        hit("/srv/css/old/site.css", Entry::file("site.css", 1)),
        hit("/srv/a/Site.css", Entry::file("Site.css", 2)),
        hit("/srv/img", Entry::dir("img")),
        // Inside the selected directory: brought by it.
        hit("/srv/img/logo.png", Entry::file("logo.png", 2048)),
        hit("/srv/.env", Entry::file(".env", 1)),
        hit("/srv/x/.env", Entry::file(".env", 1)),
    ];
    let target = LocalPath::new(std::env::temp_dir().join("dl"));
    let t = |rel: &str| {
        let mut l = target.clone();
        for c in rel.split('/') {
            l = l.join(c);
        }
        l
    };

    let items = download_items(
        &quick(),
        &p("/srv"),
        &hits,
        &target,
        ResultLayout::KeepStructure,
        None,
    );
    let got: Vec<_> = items
        .iter()
        .map(|i| {
            (
                i.remote.to_string(),
                i.local.clone(),
                i.is_dir_placeholder,
                i.size,
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![
            (
                "/srv/css/site.css".into(),
                t("css/site.css"),
                false,
                Some(6)
            ),
            (
                "/srv/css/old/site.css".into(),
                t("css/old/site.css"),
                false,
                Some(1)
            ),
            ("/srv/a/Site.css".into(), t("a/Site.css"), false, Some(2)),
            ("/srv/img".into(), t("img"), true, None),
            ("/srv/.env".into(), t(".env"), false, Some(1)),
            ("/srv/x/.env".into(), t("x/.env"), false, Some(1)),
        ]
    );
    assert!(items.iter().all(|i| i.direction == Direction::Download));

    let items = download_items(
        &quick(),
        &p("/srv"),
        &hits,
        &target,
        ResultLayout::Flatten,
        None,
    );
    let got: Vec<_> = items.iter().map(|i| i.local.clone()).collect();
    assert_eq!(
        got,
        vec![
            t("site.css"),
            t("site (2).css"),
            // Case-insensitive collision.
            t("Site (3).css"),
            t("img"),
            t(".env"),
            t(".env (2)"),
        ]
    );
}

#[test]
fn download_replaces_invalid_characters() {
    let hits = vec![hit("/srv/a:b/c?.txt", Entry::file("c?.txt", 1))];
    let target = LocalPath::new(std::env::temp_dir());
    let items = download_items(
        &quick(),
        &p("/srv"),
        &hits,
        &target,
        ResultLayout::KeepStructure,
        Some('_'),
    );
    let want = crate::local::sanitize_local_name("c?.txt", '_');
    assert_eq!(
        items[0].local,
        target
            .join(crate::local::sanitize_local_name("a:b", '_'))
            .join(want)
    );
}

#[test]
fn upload_maps_local_hits_to_the_remote_target() {
    let base = std::env::temp_dir().join("up-root");
    let root = local_to_remote(&base).unwrap();
    let file = local_to_remote(&base.join("sub").join("f.txt")).unwrap();
    let dir = local_to_remote(&base.join("d")).unwrap();
    let hits = vec![
        SearchHit {
            path: file,
            entry: Entry::file("f.txt", 3),
        },
        SearchHit {
            path: dir,
            entry: Entry::dir("d"),
        },
    ];
    let items = upload_items(
        &quick(),
        &root,
        &hits,
        &p("/www"),
        ResultLayout::KeepStructure,
    );
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].remote, p("/www/sub/f.txt"));
    assert_eq!(items[0].local.as_path(), base.join("sub").join("f.txt"));
    assert_eq!(items[0].direction, Direction::Upload);
    assert_eq!(items[1].remote, p("/www/d"));
    assert!(items[1].is_dir_placeholder);
    let items = upload_items(&quick(), &root, &hits, &p("/www"), ResultLayout::Flatten);
    assert_eq!(items[0].remote, p("/www/f.txt"));
}

#[tokio::test]
async fn delete_selected_results() {
    let server = site();
    let mut handle = spawn_search(
        Box::new(server.backend()),
        remote_query("/srv", vec![name(StringOp::Contains, "s")]),
        SearchOptions::remote(sid()),
    )
    .unwrap();
    let (hits, _) = drain(&mut handle).await;
    // css (dir), css/site.css, css/old/site.css: the files are inside css.
    assert_eq!(
        paths(&hits),
        ["/srv/css", "/srv/css/old/site.css", "/srv/css/site.css"]
    );
    assert_eq!(delete_targets(&hits).len(), 1);
    let mut b = server.backend();
    let cancel = CancellationToken::new();
    b.connect(cancel.clone()).await.unwrap();
    let report = delete_results(&mut b, &hits, WalkOptions::remote(sid()), &cancel).await;
    assert!(report.is_complete(), "{report:?}");
    assert!(!server.exists("/srv/css"));
    assert!(server.exists("/srv/img/logo.png"));
}
