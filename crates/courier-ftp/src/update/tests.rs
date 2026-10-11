//! T74 update check tests. Nothing here touches the network: the HTTP tests
//! use an in-process server on 127.0.0.1.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use pretty_assertions::assert_eq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;

use super::*;

fn v(s: &str) -> Version {
    Version::parse(s).unwrap_or_else(|| panic!("{s} should parse"))
}

#[test]
fn versions_compare_numerically() {
    assert!(v("v1.2.3") < v("1.10.0"));
    assert!(v("1.10.0") > v("1.9.9"));
    assert!(v("2.0.0") > v("1.99.99"));
    assert_eq!(v("v1.2.3"), v("1.2.3"));
    assert_eq!(v("1.2.3+build.7"), v("1.2.3"));
    assert_eq!(v("V0.1.0").to_string(), "0.1.0");
}

#[test]
fn prereleases_sort_before_their_release() {
    assert!(v("1.3.0-rc.1") < v("1.3.0"));
    assert!(v("1.3.0-rc.1") > v("1.2.9"));
    assert!(v("1.3.0-alpha") < v("1.3.0-alpha.1"));
    assert!(v("1.3.0-alpha.1") < v("1.3.0-beta"));
    assert!(v("1.3.0-beta.2") < v("1.3.0-beta.11"));
    assert!(v("1.3.0-1") < v("1.3.0-alpha"));
    assert!(v("1.3.0-rc.1").is_prerelease());
    assert!(!v("1.3.0").is_prerelease());
    assert_eq!(v("v1.3.0-rc.1").to_string(), "1.3.0-rc.1");
}

#[test]
fn bad_versions_are_rejected() {
    for bad in [
        "",
        "v",
        "1",
        "1.2",
        "1.2.3.4",
        "1.x.3",
        "nightly",
        "1.2.3-",
        "1.2.3-a..b",
        " -1.2.3",
    ] {
        assert_eq!(Version::parse(bad), None, "{bad:?}");
    }
}

fn release(tag: &str, prerelease: bool) -> Release {
    Release {
        tag_name: tag.into(),
        html_url: format!("https://github.com/viperh/courier-ftp/releases/tag/{tag}"),
        prerelease,
        draft: false,
    }
}

#[test]
fn newest_skips_prereleases_unless_asked() {
    let current = v("1.2.3");
    let releases = vec![
        release("v1.3.0", false),
        release("v1.4.0-rc.1", true),
        release("v1.2.0", false),
        release("nightly", true),
        Release {
            draft: true,
            ..release("v9.0.0", false)
        },
    ];
    assert_eq!(
        newest(&current, &releases, false).map(|u| u.version),
        Some("1.3.0".into())
    );
    assert_eq!(
        newest(&current, &releases, true).map(|u| u.version),
        Some("1.4.0-rc.1".into())
    );
    // A prerelease tag not flagged as such still counts as one.
    assert_eq!(
        newest(&current, &[release("v1.4.0-beta", false)], false),
        None
    );
    // Up to date.
    assert_eq!(newest(&v("1.3.0"), &releases, false), None);
    // On a prerelease build, the final release is newer.
    assert_eq!(
        newest(&v("1.3.0-rc.2"), &releases, false).map(|u| u.version),
        Some("1.3.0".into())
    );
}

#[test]
fn notice_names_version_and_page() {
    let info = UpdateInfo {
        version: "1.3.0".into(),
        url: "https://example.invalid/r".into(),
    };
    assert_eq!(
        info.notice(),
        "Update available: v1.3.0 — https://example.invalid/r"
    );
}

#[test]
fn checks_are_due_once_a_week() {
    let week = CHECK_INTERVAL.as_secs();
    assert!(due(None, 1_000, CHECK_INTERVAL));
    assert!(!due(Some(1_000), 1_000, CHECK_INTERVAL));
    assert!(!due(Some(1_000), 1_000 + week - 1, CHECK_INTERVAL));
    assert!(due(Some(1_000), 1_000 + week, CHECK_INTERVAL));
    // The clock went backwards: check again.
    assert!(due(Some(1_000), 999, CHECK_INTERVAL));
}

#[test]
fn env_opt_out_values() {
    for on in ["1", "true", "yes", "anything"] {
        assert!(opt_out_value(on), "{on}");
    }
    for off in ["", " ", "0", "false", "FALSE", "no"] {
        assert!(!opt_out_value(off), "{off:?}");
    }
}

/// A source that must not be called.
struct Panics;

#[async_trait::async_trait]
impl ReleaseSource for Panics {
    async fn releases(&self, _: bool) -> Result<Vec<Release>, String> {
        panic!("the update check must not touch the network here");
    }
}

/// A source answering from a list, counting calls.
struct Fixed {
    result: Result<Vec<Release>, String>,
    calls: Mutex<Vec<bool>>,
}

impl Fixed {
    fn new(result: Result<Vec<Release>, String>) -> Self {
        Self {
            result,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<bool> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl ReleaseSource for Fixed {
    async fn releases(&self, prereleases: bool) -> Result<Vec<Release>, String> {
        self.calls.lock().unwrap().push(prereleases);
        self.result.clone()
    }
}

/// Never answers.
struct Hangs;

#[async_trait::async_trait]
impl ReleaseSource for Hangs {
    async fn releases(&self, _: bool) -> Result<Vec<Release>, String> {
        std::future::pending().await
    }
}

fn checker(dir: &tempfile::TempDir) -> Checker {
    Checker {
        current: "1.2.3".into(),
        ..Checker::new(dir.path())
    }
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

const T0: u64 = 1_800_000_000;

#[tokio::test]
async fn disabled_check_never_calls_the_source() {
    let dir = tempfile::tempdir().unwrap();
    let c = Checker {
        enabled: false,
        ..checker(&dir)
    };
    assert_eq!(
        c.run(&Panics, at(T0), &CancellationToken::new()).await,
        None
    );
    assert!(!c.state_path.exists());
}

#[tokio::test]
async fn check_respects_the_interval() {
    let dir = tempfile::tempdir().unwrap();
    let c = checker(&dir);
    let cancel = CancellationToken::new();
    let source = Fixed::new(Ok(vec![release("v1.3.0", false)]));
    let found = c.run(&source, at(T0), &cancel).await;
    assert_eq!(found.as_ref().map(|u| u.version.as_str()), Some("1.3.0"));
    assert_eq!(source.calls(), vec![false]);
    assert_eq!(
        State::load(&c.state_path),
        State {
            last_check: Some(T0),
            latest: found.clone(),
        }
    );

    // A day later: not due, the saved result is announced again.
    assert_eq!(c.run(&Panics, at(T0 + 86_400), &cancel).await, found);
    // After upgrading to it, the saved result is old news.
    let upgraded = Checker {
        current: "1.3.0".into(),
        ..checker(&dir)
    };
    assert_eq!(upgraded.run(&Panics, at(T0 + 86_400), &cancel).await, None);

    // A week later: due again.
    let later = Fixed::new(Ok(vec![release("v1.2.3", false)]));
    let week = CHECK_INTERVAL.as_secs();
    assert_eq!(c.run(&later, at(T0 + week), &cancel).await, None);
    assert_eq!(later.calls().len(), 1);
    assert_eq!(State::load(&c.state_path).last_check, Some(T0 + week));
}

#[tokio::test]
async fn failures_are_silent_and_retried_next_start() {
    let dir = tempfile::tempdir().unwrap();
    let c = checker(&dir);
    let cancel = CancellationToken::new();
    let failing = Fixed::new(Err("connection refused".into()));
    assert_eq!(c.run(&failing, at(T0), &cancel).await, None);
    // Nothing recorded: the next start tries again.
    assert_eq!(State::load(&c.state_path), State::default());
    let ok = Fixed::new(Ok(vec![release("v1.3.0", false)]));
    assert!(c.run(&ok, at(T0 + 60), &cancel).await.is_some());
    assert_eq!(ok.calls().len(), 1);
}

#[tokio::test]
async fn prerelease_setting_is_passed_and_filters_the_saved_result() {
    let dir = tempfile::tempdir().unwrap();
    let cancel = CancellationToken::new();
    let pre = Checker {
        prereleases: true,
        ..checker(&dir)
    };
    let source = Fixed::new(Ok(vec![
        release("v1.3.0", false),
        release("v1.4.0-rc.1", true),
    ]));
    let found = pre.run(&source, at(T0), &cancel).await;
    assert_eq!(source.calls(), vec![true]);
    assert_eq!(found.map(|u| u.version), Some("1.4.0-rc.1".into()));
    // Prereleases turned off again: the saved prerelease isn't announced.
    assert_eq!(checker(&dir).run(&Panics, at(T0 + 60), &cancel).await, None);
}

#[tokio::test]
async fn check_times_out_and_can_be_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let c = Checker {
        timeout: Duration::from_millis(50),
        ..checker(&dir)
    };
    assert_eq!(c.run(&Hangs, at(T0), &CancellationToken::new()).await, None);
    let cancel = CancellationToken::new();
    cancel.cancel();
    let c = Checker {
        timeout: Duration::from_secs(3600),
        ..checker(&dir)
    };
    assert_eq!(c.run(&Hangs, at(T0), &cancel).await, None);
}

// --- HTTP, against an in-process server on 127.0.0.1 ---

/// Serves `body` with `status` to every request; records each request head.
async fn fake_github(status: &'static str, body: String) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&head).into_owned());
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    (format!("http://{addr}/repos/viperh/courier-ftp"), seen)
}

#[tokio::test]
async fn github_latest_release_is_fetched_without_personal_data() {
    let body = r#"{"tag_name":"v1.3.0","html_url":"https://github.com/viperh/courier-ftp/releases/tag/v1.3.0","prerelease":false,"draft":false,"name":"1.3.0","body":"notes","assets":[]}"#;
    let (base, seen) = fake_github("200 OK", body.into()).await;
    let source = GithubReleases::new(&base, Duration::from_secs(30)).unwrap();
    let releases = source.releases(false).await.unwrap();
    assert_eq!(releases, vec![release("v1.3.0", false)]);

    let requests = seen.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    let head = requests[0].to_ascii_lowercase();
    assert!(
        head.starts_with("get /repos/viperh/courier-ftp/releases/latest http/1.1\r\n"),
        "{head}"
    );
    // Only these headers: no cookies, tokens or anything about the user.
    let mut names: Vec<&str> = head
        .lines()
        .skip(1)
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':').map(|(n, _)| n.trim()))
        .collect();
    names.sort_unstable();
    assert_eq!(names, vec!["accept", "host", "user-agent"], "{head}");
    assert!(
        head.contains(&format!(
            "user-agent: courier-ftp/{}",
            env!("CARGO_PKG_VERSION")
        )),
        "{head}"
    );
}

#[tokio::test]
async fn github_release_list_is_used_for_prereleases() {
    let body = r#"[{"tag_name":"v1.4.0-rc.1","html_url":"u1","prerelease":true},{"tag_name":"v1.3.0","html_url":"u2"}]"#;
    let (base, seen) = fake_github("200 OK", body.into()).await;
    let source = GithubReleases::new(&base, Duration::from_secs(30)).unwrap();
    let releases = source.releases(true).await.unwrap();
    assert_eq!(releases.len(), 2);
    assert!(releases[0].prerelease);
    let head = seen.lock().unwrap()[0].clone();
    assert!(
        head.starts_with(&format!(
            "GET /repos/viperh/courier-ftp/releases?per_page={RELEASES_PAGE} "
        )),
        "{head}"
    );
}

#[tokio::test]
async fn github_errors_are_reported() {
    let (base, _) = fake_github("404 Not Found", r#"{"message":"Not Found"}"#.into()).await;
    let source = GithubReleases::new(&base, Duration::from_secs(30)).unwrap();
    let err = source.releases(false).await.unwrap_err();
    assert!(err.contains("404"), "{err}");

    let (base, _) = fake_github("200 OK", "not json".into()).await;
    let source = GithubReleases::new(&base, Duration::from_secs(30)).unwrap();
    assert!(source.releases(false).await.is_err());
}

#[tokio::test]
async fn github_request_times_out() {
    // Accepts, never answers.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    let source =
        GithubReleases::new(&format!("http://{addr}/r"), Duration::from_millis(200)).unwrap();
    let started = std::time::Instant::now();
    assert!(source.releases(false).await.is_err());
    assert!(started.elapsed() < Duration::from_secs(30));
}

#[tokio::test]
async fn end_to_end_check_against_the_fake_server() {
    let body = r#"{"tag_name":"v99.0.0","html_url":"https://github.com/viperh/courier-ftp/releases/tag/v99.0.0"}"#;
    let (base, _) = fake_github("200 OK", body.into()).await;
    let source = GithubReleases::new(&base, Duration::from_secs(30)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let found = Checker::new(dir.path())
        .run(&source, SystemTime::now(), &CancellationToken::new())
        .await;
    assert_eq!(
        found.map(|u| u.notice()),
        Some(
            "Update available: v99.0.0 — https://github.com/viperh/courier-ftp/releases/tag/v99.0.0"
                .into()
        )
    );
}
