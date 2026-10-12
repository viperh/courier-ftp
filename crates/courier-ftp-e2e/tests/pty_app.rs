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

/// A malicious server: listings with `../`, absolute paths, escape
/// sequences and absurd sizes. Downloading everything must keep every file
/// inside the target folder, and nothing the server sent may reach the
/// terminal as a raw escape sequence.
#[test]
#[ignore = "work in progress (T76): a dialog stops the transfer queue in this run"]
fn hostile_server_names_stay_inside_the_target_and_off_the_terminal() {
    use courier_ftp_e2e::{FtpdConfig, Hostile};

    let base = tempfile::tempdir().unwrap();
    let target = base.path().join("target");
    let outside = base.path().join("outside");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let served = tempfile::tempdir().unwrap();
    let line = |name: &str| {
        format!("-rw-r--r--    1 ftp      ftp            12 Jan 01  2024 {name}").into_bytes()
    };
    let hostile = Hostile {
        listing: vec![
            line("safe.txt"),
            line("../escape.txt"),
            line(&format!("{}/abs.txt", outside.display())),
            line("title\x1b]0;pwned\x07.txt"),
            line("color\x1b[31mEVIL\x1b[0m.txt"),
            b"-rw-r--r-- 1 ftp ftp 99999999999999999999999 Jan 01 2024 huge.txt".to_vec(),
            b"total garbage that is no listing line".to_vec(),
        ],
        payload: b"hostile data".to_vec(),
    };
    let mut config = FtpdConfig::new(USER, PASSWORD);
    config.hostile = Some(hostile);
    let server = TinyFtpd::start_with(served.path(), config).unwrap();
    let home = TestHome::new().unwrap();

    let opts = PtyOptions {
        args: vec![
            "--no-vault".into(),
            "--local".into(),
            target.display().to_string(),
            format!("ftp://{USER}@127.0.0.1:{}", server.port()),
        ],
        ..PtyOptions::default()
    };
    let mut app = PtyApp::launch(&home, opts).unwrap();
    // The URL has no password: it is asked for.
    app.wait_for_text("Password").unwrap();
    app.send_text(PASSWORD).unwrap();
    app.send_keys("enter").unwrap();
    app.wait_for_text("safe.txt").unwrap();

    // Select everything in the remote list and copy it to the local side.
    app.send_keys("ctrl-a F5").unwrap();
    app.wait_for_screen("safe.txt downloaded", |_| target.join("safe.txt").is_file())
        .unwrap();
    // Let the other transfers finish or fail.
    app.wait_for_screen("the queue settles", |s| !s.contains("Transferring"))
        .unwrap();

    // Nothing outside the target folder.
    let outside_entries: Vec<_> = std::fs::read_dir(&outside).unwrap().collect();
    assert!(outside_entries.is_empty(), "{outside_entries:?}");
    let base_entries: Vec<String> = std::fs::read_dir(base.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(base_entries.len(), 2, "{base_entries:?}");
    for entry in std::fs::read_dir(&target).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(
            !name.contains('\x1b') && !name.contains('/') && name != ".." && name != ".",
            "unsafe local name {name:?}"
        );
    }
    // The server's escape sequences never reached the terminal.
    let raw = String::from_utf8_lossy(app.raw_output()).into_owned();
    assert!(
        !raw.contains("\x1b]0;pwned"),
        "title sequence reached the terminal"
    );
    assert!(
        !raw.contains("\x1b[31mEVIL"),
        "colour sequence reached the terminal"
    );
    quit(&mut app);
}
