//! Harness self-tests that need no Docker; they run in the normal suite.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use courier_ftp_core::{
    backend::{Backend, conformance},
    local::{LocalBackend, local_to_remote},
};
use courier_ftp_e2e::{TestHome, diag, timeout, wait_for};

#[test]
fn timeout_is_longer_on_ci() {
    // Can't change `CI` safely in-process; check the value matches the
    // environment we run in.
    let expected = if courier_ftp_e2e::on_ci() { 20 } else { 10 };
    assert_eq!(timeout(), Duration::from_secs(expected));
}

#[tokio::test]
async fn require_docker_skips_without_opt_in() {
    if courier_ftp_e2e::e2e_requested() {
        return; // the opt-in is set: nothing to check here
    }
    let reason = courier_ftp_e2e::docker_skip_reason().await;
    assert!(reason.is_some_and(|r| r.contains("COURIER_E2E=1")));
}

#[test]
fn test_home_layout_and_cleanup() {
    let path;
    {
        let home = TestHome::new_in(std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))).unwrap();
        path = home.path().to_path_buf();
        assert!(home.config_dir().is_dir() && home.data_dir().is_dir());
        home.write_config(r#"{"settings": {}}"#).unwrap();
        assert!(home.config_dir().join("config.json").is_file());
        let env = home.env();
        assert!(env.contains(&("COURIER_FTP_HOME", Some(path.display().to_string()))));
        assert!(env.contains(&("COURIER_FTP_CONFIG", None)));
        assert!(home.log().is_none());
    }
    assert!(!path.exists(), "a passing test removes its home");
}

#[test]
fn failing_tests_keep_their_home_and_dump_it() {
    let (result, dumps) = diag::capture(|| {
        let home = TestHome::new_in(std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))).unwrap();
        std::fs::write(home.data_dir().join("courier-ftp.log"), "line 1\nline 2\n").unwrap();
        let path = home.path().to_path_buf();
        std::panic::panic_any(path);
    });
    let path = *result
        .unwrap_err()
        .downcast::<std::path::PathBuf>()
        .unwrap();
    assert!(path.exists(), "kept for debugging");
    assert_eq!(dumps.len(), 1);
    assert!(
        dumps[0].contains("test home") && dumps[0].contains("line 2"),
        "{dumps:?}"
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn tail_keeps_the_last_lines() {
    let text: String = (1..=10).map(|i| format!("{i}\n")).collect();
    let t = diag::tail(&text, 3);
    assert!(
        t.starts_with("[… 7 earlier lines]") && t.ends_with("8\n9\n10"),
        "{t}"
    );
}

#[tokio::test]
async fn wait_for_polls_until_ready() {
    let start = tokio::time::Instant::now();
    let value = wait_for("the third poll", {
        let mut n = 0;
        move || {
            n += 1;
            let ready = n >= 3;
            async move { ready.then_some(n) }
        }
    })
    .await
    .unwrap();
    assert_eq!(value, 3);
    assert!(start.elapsed() < timeout());
}

#[tokio::test(start_paused = true)]
async fn wait_for_times_out_with_a_message() {
    let err = wait_for("never", || async { None::<()> })
        .await
        .unwrap_err();
    assert!(err.0.contains("waiting for never"), "{err}");
}

/// The backend conformance suite runs here too, against a home directory
/// like the e2e scenarios use; T76 later adds FTP and SFTP servers.
#[tokio::test]
async fn local_backend_conformance_in_a_test_home() {
    let home = TestHome::new_in(std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))).unwrap();
    let base = home.data_dir().join("conformance");
    std::fs::create_dir(&base).unwrap();
    let base = local_to_remote(&base.canonicalize().unwrap()).unwrap();
    let mut backend = LocalBackend::new();
    assert!(backend.address().is_none());
    conformance::run(&mut backend, &base).await;
}
