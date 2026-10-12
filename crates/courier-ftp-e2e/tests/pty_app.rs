//! The real binary in a pseudo-terminal against [`TinyFtpd`] (no Docker):
//! first run → create the vault → quickconnect → save as site → quit →
//! start with `--site` → unlock → connected without a password prompt.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use courier_ftp_e2e::{PtyApp, PtyOptions, TestHome, TinyFtpd};

const MASTER: &str = "correct horse battery staple violin";
const USER: &str = "alice";
const PASSWORD: &str = "pty-site-password";

/// Quit with `Ctrl-q` (nothing is transferring, so the app doesn't ask).
fn quit(app: &mut PtyApp) {
    app.send_keys("ctrl-q").unwrap();
    let status = app.wait_exit().unwrap();
    assert!(status.success(), "exit status {status:?}");
}

#[test]
fn saved_site_connects_after_restart_without_a_password_prompt() {
    let served = tempfile::tempdir().unwrap();
    std::fs::write(served.path().join("hello.txt"), "hello from tiny ftpd\n").unwrap();
    let server = TinyFtpd::start(served.path(), USER, PASSWORD).unwrap();
    let home = TestHome::new().unwrap();

    // Run 1: create the vault, connect, save the connection as a site.
    let mut app = PtyApp::launch(&home, PtyOptions::default()).unwrap();
    app.wait_for_text("Create your vault").unwrap();
    app.send_text(MASTER).unwrap();
    app.send_keys("tab").unwrap();
    app.send_text(MASTER).unwrap();
    app.send_keys("enter").unwrap();
    app.wait_for_text("Vault created").unwrap();

    app.send_keys("ctrl-k").unwrap();
    app.send_text(&format!(
        "ftp://{USER}:{PASSWORD}@127.0.0.1:{}",
        server.port()
    ))
    .unwrap();
    app.send_keys("enter").unwrap();
    app.wait_for_text("hello.txt").unwrap();

    app.send_keys("ctrl-x a").unwrap();
    app.wait_for_text("(new, not saved)").unwrap();
    let screen = app
        .send_keys("ctrl-s")
        .and_then(|()| app.wait_for_text("Saved"))
        .unwrap();
    assert!(!screen.contains(PASSWORD), "password on screen:\n{screen}");
    // Esc leaves the editor for the tree, a second Esc closes the manager.
    app.send_keys("esc esc").unwrap();
    app.wait_for_screen("the Site Manager closed", |s| !s.contains("Site Manager"))
        .unwrap();
    quit(&mut app);
    drop(app);

    // Run 2: `--site` waits for the unlock, then connects with the stored
    // password: no password prompt.
    let opts = PtyOptions {
        args: vec!["--site".into(), "127.0.0.1".into()],
        ..PtyOptions::default()
    };
    let mut app = PtyApp::launch(&home, opts).unwrap();
    app.wait_for_text("Unlock").unwrap();
    app.send_text(MASTER).unwrap();
    app.send_keys("enter").unwrap();
    let screen = app.wait_for_text("hello.txt").unwrap();
    assert!(!screen.contains("Password for"), "{screen}");
    assert!(!screen.contains(PASSWORD), "password on screen:\n{screen}");
    // The server saw two logins with the stored password.
    let logins = server
        .commands()
        .iter()
        .filter(|c| c.starts_with("PASS"))
        .count();
    assert_eq!(logins, 2, "{:?}", server.commands());
    quit(&mut app);
}
