//! PTY tests of the app shell (T50) and the keymap (T51) against the real binary.
//! No Docker; they run in the normal suite.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use courier_ftp_e2e::{PtyApp, PtyOptions, Screen, TestHome};

fn launch(home: &TestHome) -> PtyApp {
    let mut app = PtyApp::launch(home, PtyOptions::default()).unwrap();
    app.wait_for_text("Local").unwrap();
    app.wait_for_text("NORMAL").unwrap();
    app
}

fn status_row(s: &Screen) -> &str {
    s.rows
        .iter()
        .rev()
        .find(|r| !r.trim().is_empty())
        .map_or("", String::as_str)
}

/// T50: start with a temp `COURIER_FTP_HOME`, `ctrl-q` quits with status 0 and the
/// terminal is restored (no alternate screen). AC10, AC14.
#[test]
fn e2e_pty_starts_and_quits() {
    let home = TestHome::new().unwrap();
    let mut app = launch(&home);
    assert!(app.alternate_screen());
    let status = app.quit().unwrap();
    assert!(status.success(), "{status:?}");
    assert!(!app.alternate_screen(), "the alternate screen was not left");
    let raw = String::from_utf8_lossy(app.raw_output());
    assert!(
        raw.contains("\x1b[?1049l"),
        "no alternate-screen exit sequence"
    );
}

/// T50: 60×16 is compact (the status bar says so), 120×40 is the full layout again.
#[test]
fn e2e_pty_resize_to_compact_and_back() {
    let home = TestHome::new().unwrap();
    let mut app = launch(&home);
    app.resize(60, 16).unwrap();
    app.wait_for_screen("the compact layout", |s| {
        status_row(s).contains("compact") && !s.contains("Message log")
    })
    .unwrap();
    app.resize(120, 40).unwrap();
    app.wait_for_screen("the full layout", |s| {
        !status_row(s).contains("compact")
            && s.contains("Message log")
            && s.contains("Local")
            && s.contains("Remote")
            && s.contains("Queue")
    })
    .unwrap();
    assert!(app.quit().unwrap().success());
}

/// Send `first`, wait like a slow typist, then `second` (one two-key sequence).
fn slow_sequence(app: &mut PtyApp, first: &str, second: &str) {
    app.send_keys(first).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    app.send_keys(second).unwrap();
}

/// T51: sequences and function keys through a real terminal, with 500 ms between the
/// keys of a sequence. AC1, AC2, AC12.
#[test]
fn e2e_pty_sequences_and_fkeys() {
    let home = TestHome::new().unwrap();
    let mut app = launch(&home);

    // A two-key sequence typed slowly reaches its action (T61 implements it).
    slow_sequence(&mut app, "ctrl-x", "d");
    app.wait_for_text("Disconnect the current tab is not available yet")
        .unwrap();

    // `tab` moves the focus to the other side.
    app.send_keys("tab").unwrap();
    app.wait_for_text("▶Remote").unwrap();

    // `f1` opens the help overlay, `esc` closes it.
    app.send_keys("F1").unwrap();
    app.wait_for_text("Help: key bindings").unwrap();
    app.send_keys("esc").unwrap();
    app.wait_for_screen("the help overlay to close", |s| {
        !s.contains("Help: key bindings") && s.contains("▶Remote")
    })
    .unwrap();

    // `ctrl-x l` (ClearLog, T55) and `ctrl-x j` (toggle the queue pane).
    slow_sequence(&mut app, "ctrl-x", "l");
    app.wait_for_text("Log cleared").unwrap();
    assert!(app.screen().contains("Queue"));
    slow_sequence(&mut app, "ctrl-x", "j");
    app.wait_for_screen("the queue pane to hide", |s| !s.contains("Queue"))
        .unwrap();
    slow_sequence(&mut app, "ctrl-x", "j");
    app.wait_for_text("Queue").unwrap();

    assert!(app.quit().unwrap().success());
}
