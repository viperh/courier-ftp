//! T60: the vault flows through the app with synthetic key events, a real
//! engine over a temporary directory, an in-memory keyring and cheap Argon2
//! (`Argon2Cost::TEST`, dev-only feature `insecure-test-ksf`).

use std::{path::Path, sync::Arc, time::Duration};

use courier_ftp_core::{
    backend::MockServer,
    settings::SymbolMode,
    trust::{HostKeyStore, HostKeyStoreSlot, MemoryHostKeyStore},
    vault::{AutoLock, KeyringStore, MemKeyring, VaultState},
};
use courier_ftp_crypto::kdf::Argon2Cost;
use courier_ftp_proto_sftp::ssh::CredentialCache;
use courier_ftp_store::{Store, vault::VaultEngine};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};

use super::*;
use crate::{ui::VaultPage, vault::VaultOpener};

const STRONG: &str = "correct horse battery staple violin";
const OTHER: &str = "purple elephant marmalade trombone";

struct Rig {
    /// Boxed: `App` is large, and the test futures hold a `Rig`.
    app: Box<App>,
    host_keys: Arc<HostKeyStoreSlot>,
}

fn opener(dir: &Path, keyring: &MemKeyring) -> VaultOpener {
    let dir = dir.to_path_buf();
    let keyring = keyring.clone();
    Arc::new(move || {
        let store = Store::open_in_dir(&dir)
            .map_err(|e| courier_ftp_core::vault::VaultError::Storage(e.to_string()))?;
        let keyring: Arc<dyn KeyringStore> = Arc::new(keyring.clone());
        Ok(VaultEngine::new(store, keyring, Argon2Cost::TEST))
    })
}

fn config() -> Config {
    let mut config = Config::builtin();
    config.settings.interface.unicode_symbols = SymbolMode::Unicode;
    config.settings.logging.show_timestamps = false;
    config.settings.connection.keepalive = false;
    config
}

/// A started app with a vault in `dir` (one "program run").
async fn start(dir: &Path, keyring: &MemKeyring, config: Config) -> Rig {
    let host_keys = Arc::new(HostKeyStoreSlot::new(
        Arc::new(MemoryHostKeyStore::locked()),
    ));
    let app = App::with_backends(config, Arc::new(MockServer::new()), 4.0, 60.0).with_vault(
        opener(dir, keyring),
        Arc::clone(&host_keys),
        CredentialCache::new(),
    );
    let mut rig = Rig {
        app: Box::new(app),
        host_keys,
    };
    rig.app.start_vault();
    rig.settle().await;
    rig
}

impl Rig {
    /// Run actions, core events and vault results until nothing happens for
    /// a moment and no vault operation is still running. Opening the store
    /// and Argon2 can take seconds on a slow CI runner, so an idle gap alone
    /// is not enough.
    async fn settle(&mut self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let app = &mut self.app;
        loop {
            tokio::select! {
                Some(action) = app.action_rx.recv() => app.dispatch(action).unwrap(),
                Some(event) = app.events_rx.recv() => app.screen.handle_core(event),
                Some(msg) = app.vault_rx.recv() => app.vault_message(msg),
                () = tokio::time::sleep(Duration::from_millis(150)) => {
                    let busy = app.screen.vault_view().is_some_and(VaultView::is_busy)
                        || app.vault.as_ref().is_some_and(|v| v.phase == Phase::Opening);
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "vault operation still running after 30 s"
                    );
                    if !busy {
                        break;
                    }
                }
            }
        }
    }

    fn key(&mut self, code: KeyCode) {
        self.app
            .handle_key_event(KeyEvent::new(code, KeyModifiers::NONE))
            .unwrap();
    }

    fn alt(&mut self, c: char) {
        self.app
            .handle_key_event(KeyEvent::new(KeyCode::Char(c), KeyModifiers::ALT))
            .unwrap();
    }

    fn ctrl_x(&mut self, c: char) {
        self.app
            .handle_key_event(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::CONTROL))
            .unwrap();
        self.key(KeyCode::Char(c));
    }

    fn typed(&mut self, text: &str) {
        for c in text.chars() {
            self.key(KeyCode::Char(c));
        }
    }

    async fn submit(&mut self) {
        self.key(KeyCode::Enter);
        self.settle().await;
    }

    fn page(&self) -> Option<VaultPage> {
        self.app.screen.vault_view().map(VaultView::page)
    }

    fn shown(&self) -> bool {
        self.app.screen.vault_shown()
    }

    fn phase(&self) -> Option<Phase> {
        self.app.vault.as_ref().map(|v| v.phase)
    }

    fn engine(&self) -> VaultEngine {
        self.app.vault.as_ref().unwrap().engine().unwrap().clone()
    }

    fn screen(&mut self, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| self.app.screen.draw(f)).unwrap();
        terminal.backend().to_string()
    }

    /// First run: type and confirm `password`, optionally tick the keyring
    /// box, create.
    async fn create(&mut self, password: &str, keyring: bool) {
        assert_eq!(self.page(), Some(VaultPage::Create));
        self.typed(password);
        self.key(KeyCode::Tab);
        self.typed(password);
        if keyring {
            self.key(KeyCode::Tab);
            self.key(KeyCode::Char(' '));
        }
        self.submit().await;
    }

    async fn unlock(&mut self, password: &str) {
        assert_eq!(self.page(), Some(VaultPage::Unlock));
        self.typed(password);
        self.submit().await;
    }
}

#[tokio::test]
async fn first_run_then_every_start_asks_for_the_password() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let mut rig = start(dir.path(), &keyring, config()).await;
    assert!(rig.shown());
    assert_eq!(rig.phase(), Some(Phase::Uninitialised));
    let text = rig.screen(80, 24);
    assert!(text.contains("Create your vault"), "{text}");
    assert!(text.contains("🔐 locked"), "{text}");

    // Too weak: no vault is created.
    rig.create("password123", false).await;
    assert_eq!(rig.page(), Some(VaultPage::Create));
    assert!(rig.screen(80, 24).contains("Too weak"));
    assert_eq!(
        rig.engine().status().await.unwrap().state,
        VaultState::Uninitialised
    );
    assert_eq!(rig.engine().kdf_runs(), 0);

    // Strong: created and unlocked; panes back, "Always trust" available.
    drop(rig);
    let mut fresh = start(dir.path(), &keyring, config()).await;
    fresh.create(STRONG, false).await;
    assert_eq!(fresh.phase(), Some(Phase::Unlocked));
    assert!(!fresh.shown());
    let text = fresh.screen(120, 40);
    assert!(text.contains("Local:"), "{text}");
    assert!(!text.contains("🔐 locked"), "{text}");
    assert!(text.contains("Vault created"), "{text}");
    assert!(!text.contains(STRONG), "{text}");
    assert!(fresh.host_keys.can_remember().await);
    drop(fresh);

    // Every later start shows the unlock view.
    for _ in 0..2 {
        let mut rig = start(dir.path(), &keyring, config()).await;
        assert_eq!(rig.page(), Some(VaultPage::Unlock));
        assert!(rig.shown());
        assert!(!rig.host_keys.can_remember().await);
        rig.unlock(STRONG).await;
        assert_eq!(rig.phase(), Some(Phase::Unlocked));
        assert!(!rig.shown());
        assert!(rig.host_keys.can_remember().await);
    }
}

async fn initialised(dir: &Path, keyring: &MemKeyring, enable_keyring: bool) {
    let rig = start(dir, keyring, config()).await;
    rig.engine()
        .initialize(&secrecy::SecretString::from(STRONG), enable_keyring)
        .await
        .unwrap();
}

#[tokio::test]
async fn wrong_password_clears_the_field_and_backoff_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    initialised(dir.path(), &keyring, false).await;
    let mut rig = start(dir.path(), &keyring, config()).await;

    for _ in 0..5 {
        rig.unlock("not the password").await;
    }
    assert_eq!(rig.phase(), Some(Phase::Locked));
    let text = rig.screen(80, 24);
    assert!(text.contains("Wrong master password."), "{text}");
    assert!(
        text.contains("5 failed attempts · next try in 1 s"),
        "{text}"
    );
    assert!(!text.contains("••"), "field cleared: {text}");

    // Unlock is refused during the backoff (Argon2 doesn't even run).
    let runs = rig.engine().kdf_runs();
    rig.unlock(STRONG).await;
    assert_eq!(rig.engine().kdf_runs(), runs);
    assert!(rig.screen(80, 24).contains("try again in"));

    // A restart keeps the count (persisted by the engine).
    let mut again = start(dir.path(), &keyring, config()).await;
    assert!(again.screen(80, 24).contains("5 failed attempts"));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    again.unlock(STRONG).await;
    assert_eq!(again.phase(), Some(Phase::Unlocked));
}

#[tokio::test]
async fn keyring_unlocks_silently_and_falls_back_to_the_prompt() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let mut rig = start(dir.path(), &keyring, config()).await;
    // The keyring works, so the checkbox is offered.
    assert!(rig.screen(80, 24).contains("Unlock with system keyring"));
    rig.create(STRONG, true).await;
    assert_eq!(rig.phase(), Some(Phase::Unlocked));
    assert!(rig.engine().status().await.unwrap().keyring_enabled);
    drop(rig);

    // Next start: no prompt at all.
    let rig = start(dir.path(), &keyring, config()).await;
    assert_eq!(rig.phase(), Some(Phase::Unlocked));
    assert!(!rig.shown());
    drop(rig);

    // Keyring broken: the password view with the reason.
    keyring.set_unavailable(true);
    let mut rig = start(dir.path(), &keyring, config()).await;
    assert_eq!(rig.phase(), Some(Phase::Locked));
    assert_eq!(rig.page(), Some(VaultPage::Unlock));
    let text = rig.screen(80, 24);
    assert!(text.contains("Keyring unavailable"), "{text}");
    rig.unlock(STRONG).await;
    assert_eq!(rig.phase(), Some(Phase::Unlocked));
}

#[tokio::test]
async fn forgot_password_resets_through_the_keyring() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    initialised(dir.path(), &keyring, true).await;
    // Simulate a failing silent unlock so the prompt shows.
    keyring.set_unavailable(true);
    let mut rig = start(dir.path(), &keyring, config()).await;
    keyring.set_unavailable(false);
    assert_eq!(rig.page(), Some(VaultPage::Unlock));
    rig.alt('f');
    assert_eq!(rig.page(), Some(VaultPage::Forgot));
    rig.key(KeyCode::Enter);
    assert_eq!(rig.page(), Some(VaultPage::Reset));
    rig.typed(OTHER);
    rig.key(KeyCode::Tab);
    rig.typed(OTHER);
    rig.submit().await;
    assert_eq!(rig.phase(), Some(Phase::Unlocked));
    assert!(rig.screen(120, 40).contains("New master password set"));
    drop(rig);

    // The new password works, the old one doesn't.
    keyring.set_unavailable(true);
    let rig = start(dir.path(), &keyring, config()).await;
    let engine = rig.engine();
    assert!(
        engine
            .verify_password(&secrecy::SecretString::from(STRONG))
            .await
            .is_err()
    );
    engine
        .verify_password(&secrecy::SecretString::from(OTHER))
        .await
        .unwrap();
}

#[tokio::test]
async fn forgot_password_without_recovery_starts_a_new_vault_keeping_the_old_db() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    initialised(dir.path(), &keyring, false).await;
    let mut rig = start(dir.path(), &keyring, config()).await;
    rig.alt('f');
    assert!(
        rig.screen(80, 24)
            .contains("There is no way to recover a forgotten master password")
    );
    rig.key(KeyCode::Down);
    rig.key(KeyCode::Enter);
    assert_eq!(rig.page(), Some(VaultPage::NewVault));
    rig.key(KeyCode::Left);
    rig.submit().await;
    assert_eq!(rig.page(), Some(VaultPage::Create));
    let moved: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("courier-ftp.db.moved-") && !n.ends_with("-wal"))
        .filter(|n| !n.ends_with("-shm"))
        .collect();
    assert_eq!(moved.len(), 1, "{moved:?}");
    let text = rig.screen(80, 30);
    assert!(text.contains("The old database was moved to"), "{text}");
    rig.create(OTHER, false).await;
    assert_eq!(rig.phase(), Some(Phase::Unlocked));
}

#[tokio::test]
async fn lock_key_covers_the_panes_and_unlock_restores_them() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    initialised(dir.path(), &keyring, false).await;
    let mut rig = start(dir.path(), &keyring, config()).await;
    rig.unlock(STRONG).await;
    assert!(rig.host_keys.can_remember().await);

    rig.ctrl_x('v');
    rig.settle().await;
    assert_eq!(rig.phase(), Some(Phase::Locked));
    assert!(rig.shown());
    assert!(!rig.host_keys.can_remember().await);
    assert!(!rig.engine().is_unlocked().await);
    assert_eq!(rig.engine().live_keys(), 0);
    let text = rig.screen(80, 24);
    assert!(!text.contains("Local:"), "panes hidden: {text}");
    assert!(text.contains("🔐 locked"), "{text}");
    insta::assert_snapshot!("vault_lock_overlay_80x24", text);

    // Keys go to the overlay, not the panes.
    rig.key(KeyCode::Char('j'));
    assert!(rig.screen(80, 24).contains("•"));
    rig.key(KeyCode::Backspace);

    rig.unlock(STRONG).await;
    assert_eq!(rig.phase(), Some(Phase::Unlocked));
    assert!(rig.screen(80, 24).contains("Local:"));
}

#[tokio::test]
async fn auto_lock_after_idle_and_lock_disconnects() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    initialised(dir.path(), &keyring, false).await;
    let mut cfg = config();
    cfg.settings.vault.auto_lock_minutes = 1;
    cfg.settings.vault.lock_disconnects = true;
    let mut rig = start(dir.path(), &keyring, cfg).await;
    rig.unlock(STRONG).await;
    rig.app.dispatch(Action::Tick).unwrap();
    assert_eq!(rig.phase(), Some(Phase::Unlocked));

    // Pretend the last key press was two minutes ago.
    let past = tokio::time::Instant::now()
        .checked_sub(Duration::from_secs(120))
        .unwrap();
    rig.app.vault.as_mut().unwrap().auto_lock = AutoLock::new(1, false, past);
    rig.app.dispatch(Action::Tick).unwrap();
    rig.settle().await;
    assert_eq!(rig.phase(), Some(Phase::Locked));
    let text = rig.screen(80, 24);
    assert!(
        text.contains("Locked after 1 minutes without input."),
        "{text}"
    );
}

#[tokio::test]
async fn continue_without_vault_then_unlock_later() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    initialised(dir.path(), &keyring, false).await;
    let mut rig = start(dir.path(), &keyring, config()).await;
    rig.alt('c');
    rig.settle().await;
    assert!(!rig.shown());
    assert_eq!(rig.phase(), Some(Phase::Locked));
    let text = rig.screen(120, 40);
    assert!(text.contains("Local:"), "{text}");
    assert!(text.contains("🔐 locked"), "{text}");
    assert!(text.contains("Continuing without the vault"), "{text}");

    // The Site Manager offers to unlock.
    rig.app.dispatch(Action::SiteManager).unwrap();
    assert!(rig.app.screen.has_modal());
    assert!(
        rig.screen(120, 40)
            .contains("The vault is locked. Unlock it")
    );
    rig.key(KeyCode::Enter);
    rig.settle().await;
    assert!(rig.shown());
    rig.unlock(STRONG).await;
    assert_eq!(rig.phase(), Some(Phase::Unlocked));

    // <Ctrl-x><u> when already unlocked just says so.
    rig.ctrl_x('u');
    rig.settle().await;
    assert!(rig.screen(120, 40).contains("already unlocked"));
}

#[tokio::test]
async fn busy_database_offers_retry() {
    let dir = tempfile::tempdir().unwrap();
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let ok = opener(dir.path(), &MemKeyring::new());
    let flag = Arc::clone(&fail);
    let flaky: VaultOpener = Arc::new(move || {
        if flag.load(std::sync::atomic::Ordering::SeqCst) {
            Err(courier_ftp_core::vault::VaultError::Busy)
        } else {
            ok()
        }
    });
    let host_keys = Arc::new(HostKeyStoreSlot::new(
        Arc::new(MemoryHostKeyStore::locked()),
    ));
    let app = App::with_backends(config(), Arc::new(MockServer::new()), 4.0, 60.0).with_vault(
        flaky,
        host_keys,
        CredentialCache::new(),
    );
    let mut rig = Rig {
        app: Box::new(app),
        host_keys: Arc::new(HostKeyStoreSlot::new(
            Arc::new(MemoryHostKeyStore::locked()),
        )),
    };
    rig.app.start_vault();
    rig.settle().await;
    assert_eq!(rig.page(), Some(VaultPage::Unavailable));
    assert!(rig.screen(80, 24).contains("The database is busy"));
    fail.store(false, std::sync::atomic::Ordering::SeqCst);
    rig.submit().await;
    assert_eq!(rig.page(), Some(VaultPage::Create));
}

// ------------------------------------------------------------------ T33 history

impl Rig {
    /// Run until `done` holds (30 s cap), not just until things are idle.
    async fn until(&mut self, what: &str, done: impl Fn(&App) -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while !done(&self.app) {
            assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
            self.settle().await;
        }
    }

    async fn quickconnect(&mut self, url: &str) {
        self.app.dispatch(Action::FocusQuickconnect).unwrap();
        for c in ['e', 'u'] {
            self.app
                .handle_key_event(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
                .unwrap();
        }
        self.app.screen.handle_paste(url);
        self.key(KeyCode::Enter);
        self.settle().await;
    }

    fn history_len(app: &App) -> Option<usize> {
        app.screen.quickconnect().history().map(<[_]>::len)
    }

    fn connected(app: &App) -> bool {
        app.remote.as_ref().is_some_and(|r| r.connected)
    }
}

#[tokio::test]
async fn quickconnect_history_is_saved_picked_and_cleared() {
    use courier_ftp_core::{model::item::ItemKind, vault::ItemVault};

    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let mut rig = start(dir.path(), &keyring, config()).await;
    rig.create(STRONG, false).await;
    rig.until("history loaded", |a| Rig::history_len(a) == Some(0))
        .await;

    // A successful connect is recorded, with the typed password.
    rig.quickconnect("sftp://alice:s3cret@mock.invalid").await;
    rig.until("history recorded", |a| Rig::history_len(a) == Some(1))
        .await;
    let item = rig.app.screen.quickconnect().history().unwrap()[0].clone();
    assert_eq!(item.label, "sftp://alice@mock.invalid");
    assert!(item.request.info.logon.password().is_some());
    let stored = rig.engine().list(ItemKind::HistoryEntry).await.unwrap();
    assert_eq!(stored.len(), 1);

    // The dropdown lists it without the password; picking it connects.
    rig.app.dispatch(Action::Disconnect).unwrap();
    rig.settle().await;
    rig.app.dispatch(Action::QuickconnectHistory).unwrap();
    let text = rig.screen(100, 30);
    assert!(text.contains("Connection history"), "{text}");
    assert!(text.contains("sftp://alice@mock.invalid"), "{text}");
    assert!(text.contains("Clear history"), "{text}");
    assert!(!text.contains("s3cret"), "{text}");
    rig.key(KeyCode::Enter);
    rig.until("connected from history", Rig::connected).await;
    assert_eq!(
        rig.app.remote.as_ref().unwrap().info.address.host,
        "mock.invalid"
    );

    // Locked: the history is gone from the bar.
    rig.ctrl_x('v');
    rig.settle().await;
    assert_eq!(Rig::history_len(&rig.app), None);
    rig.unlock(STRONG).await;
    rig.until("history reloaded", |a| Rig::history_len(a) == Some(1))
        .await;

    // "Clear history" is the last entry.
    rig.app.dispatch(Action::QuickconnectHistory).unwrap();
    rig.key(KeyCode::Down);
    rig.key(KeyCode::Enter);
    rig.until("history cleared", |a| Rig::history_len(a) == Some(0))
        .await;
    assert!(
        rig.engine()
            .list(ItemKind::HistoryEntry)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn locked_vault_explains_the_missing_history() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    initialised(dir.path(), &keyring, false).await;
    let mut rig = start(dir.path(), &keyring, config()).await;
    rig.alt('c');
    rig.settle().await;
    rig.app.dispatch(Action::QuickconnectHistory).unwrap();
    let text = rig.screen(120, 40);
    assert!(text.contains("unlock it"), "{text}");
    // A connect while locked isn't saved anywhere.
    rig.quickconnect("sftp://bob:pw@mock.invalid").await;
    rig.until("connected", Rig::connected).await;
    assert_eq!(Rig::history_len(&rig.app), None);
}
