//! PTY tests of the vault screens (T60) against the real binary: first run, quit,
//! restart, wrong and right password; keyring unlock (test-hooks `FileKeyring`);
//! lock and unlock. No Docker; they run in the normal suite.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use courier_ftp_e2e::{MASTER_PASSWORD, PtyApp, PtyOptions, TestHome};

fn panes(app: &mut PtyApp, what: &str) {
    app.wait_for_screen(what, |s| {
        s.contains("Local") && !s.contains("Unlock") && !s.contains("Welcome")
    })
    .unwrap();
}

/// The first-run form: password, confirmation, Enter.
fn create_vault(app: &mut PtyApp, tick_keyring: bool) {
    let s = app.wait_for_text("Welcome to courier-ftp").unwrap();
    assert!(
        !s.contains("Local"),
        "no pane before the vault exists:\n{}",
        s.text()
    );
    app.send_text(MASTER_PASSWORD).unwrap();
    app.send_keys("tab").unwrap();
    app.send_text(MASTER_PASSWORD).unwrap();
    if tick_keyring {
        app.wait_for_text("Also unlock with the system keyring")
            .unwrap();
        app.send_keys("tab").unwrap();
        app.send_keys("space").unwrap();
        app.wait_for_text("[x] Also unlock").unwrap();
    }
    app.send_keys("enter").unwrap();
}

/// T60 AC1, AC4: create the vault, quit, restart, a wrong password, the right one.
#[test]
fn first_run_create_vault_quit_unlock() {
    let home = TestHome::new().unwrap();
    let mut app = PtyApp::launch(&home, PtyOptions::default()).unwrap();
    let s = app.wait_for_text("Welcome to courier-ftp").unwrap();
    assert!(
        !s.contains("system keyring"),
        "COURIER_FTP_KEYRING=off: no keyring checkbox"
    );
    create_vault(&mut app, false);
    panes(&mut app, "the file panes after first run");
    assert!(app.quit().unwrap().success());
    assert!(home.vault_db().exists());

    let mut app = PtyApp::launch(&home, PtyOptions::default()).unwrap();
    let s = app.wait_for_text("Unlock courier-ftp").unwrap();
    assert!(!s.contains("Local"), "{}", s.text());
    app.send_text("not the password").unwrap();
    app.send_keys("enter").unwrap();
    app.wait_for_text("Wrong password (1 failed attempt)")
        .unwrap();
    app.unlock().unwrap();
    assert!(app.quit().unwrap().success());
}

/// T60 AC2: with keyring unlock enabled the next start unlocks without a prompt.
#[test]
fn keyring_unlock_skips_the_prompt() {
    let home = TestHome::new().unwrap();
    let keyring = format!("file:{}", home.path().join("keyring").display());
    let opts = || PtyOptions {
        env: vec![("COURIER_FTP_KEYRING".into(), keyring.clone())],
        ..PtyOptions::default()
    };
    let mut app = PtyApp::launch(&home, opts()).unwrap();
    create_vault(&mut app, true);
    panes(&mut app, "the file panes after first run");
    assert!(app.quit().unwrap().success());

    let mut app = PtyApp::launch(&home, opts()).unwrap();
    panes(&mut app, "the file panes without a prompt");
    assert!(app.quit().unwrap().success());

    // `--no-keyring` asks for the password.
    let mut app = PtyApp::launch(
        &home,
        PtyOptions {
            args: vec!["--no-keyring".into()],
            ..opts()
        },
    )
    .unwrap();
    app.unlock().unwrap();
    assert!(app.quit().unwrap().success());
}

/// T60 AC7: `ctrl-x ctrl-l` locks (the overlay hides the panes), the password unlocks.
#[test]
fn lock_and_unlock() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let home = rt.block_on(TestHome::with_vault()).unwrap();
    let mut app = PtyApp::launch(&home, PtyOptions::default()).unwrap();
    app.unlock().unwrap();
    app.send_keys("ctrl-x").unwrap();
    std::thread::sleep(Duration::from_millis(200));
    app.send_keys("ctrl-l").unwrap();
    app.wait_for_screen("the lock overlay", |s| {
        s.contains("Vault locked") && !s.contains("Local")
    })
    .unwrap();
    app.unlock().unwrap();
    // Locked again, `ctrl-q` quits at once.
    app.send_keys("ctrl-x").unwrap();
    std::thread::sleep(Duration::from_millis(200));
    app.send_keys("ctrl-l").unwrap();
    app.wait_for_text("Vault locked").unwrap();
    assert!(app.quit().unwrap().success());
}
