//! T90: the sync screens through the app against a real `courier-ftp-server`
//! running in-process (in-memory store, plain HTTP on loopback), with real
//! vault engines (cheap Argon2) and the cheap OPAQUE KSF. Everything is
//! driven with key events: register with the recovery words, log in on a
//! second device with the duplicate preview, see a change arrive, devices,
//! lock and unlock, "Forgot password?" with the recovery key, TOTP, log out.
#![cfg(feature = "sync")]

use std::{collections::HashMap, net::SocketAddr, num::NonZeroU32, path::Path, time::Duration};

use courier_ftp_core::{
    model::{
        Protocol,
        item::{ItemId, Site},
    },
    vault::{ItemVaultExt, MemKeyring},
};
use courier_ftp_crypto::opaque::CourierKsf;
use courier_ftp_server::{
    AppState, Config, app as server_app,
    auth::{AuthRuntime, AuthStore, Clock as _, ManualClock, store::mem::MemStore},
    middleware::rate_limit::{LoginLimits, RateLimiters},
    serve,
};
use courier_ftp_sync::{AccountConfig, EngineConfig};
use crossterm::event::KeyCode;
use pretty_assertions::assert_eq;

use super::vault_tests::{Rig, STRONG, config, start};
use super::*;
use crate::ui::{
    VaultPage,
    sync::{SyncPage, TeamPage},
};

const EMAIL: &str = "alice@example.test";
/// The second device's own master password before it logs in.
const OTHER: &str = "purple elephant marmalade trombone";
/// The password set with the recovery key.
const NEW: &str = "obsidian marmalade galaxy accordion";
/// The server's one-time setup token.
const SETUP_TOKEN: &str = "setup-token-0123456789";

/// A running in-process server.
struct Server {
    url: String,
    state: AppState,
    clock: Arc<ManualClock>,
    /// The in-memory store (the teams test swaps a member's keys).
    mem: Arc<MemStore>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let env: HashMap<String, String> = HashMap::from([
            (
                "COURIER_SERVER_SECRET".into(),
                "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1".into(),
            ),
            (
                "COURIER_PUBLIC_URL".into(),
                "https://sync.example.test".into(),
            ),
        ]);
        let cfg = Config::from_sources(None, |k| env.get(k).cloned()).unwrap();
        let n = NonZeroU32::new(100_000).unwrap();
        let limits = RateLimiters::new(LoginLimits {
            per_email_per_minute: n,
            per_ip_per_minute: n,
        });
        let mem = Arc::new(MemStore::new());
        let pool =
            courier_ftp_server::db::connect_lazy("postgres://courier@127.0.0.1:1/unreachable")
                .unwrap();
        let clock = Arc::new(ManualClock::new());
        let auth = AuthRuntime::new(AuthStore::Memory(mem.clone()), clock.clone());
        let state = AppState::with_auth(cfg, pool, limits, auth);
        serve::startup_checks(&state).await.unwrap();
        // Registration needs a token, as on a fresh server.
        mem.with_data(|d| d.set_setup_token(SETUP_TOKEN));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router =
            server_app::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Self {
            url: format!("http://{addr}"),
            state,
            clock,
            mem,
            task,
        }
    }

    /// The recovery code the server would mail.
    async fn recovery_code(&self) -> String {
        courier_ftp_server::routes::account::issue_recovery_code(
            self.state.auth().store(),
            EMAIL,
            self.clock.now(),
        )
        .await
        .unwrap()
        .unwrap()
    }

    /// The current TOTP code for a base32 secret, by the server's clock.
    fn totp(&self, secret_base32: &str) -> String {
        let secret = base32_decode(secret_base32);
        let now = u64::try_from(self.clock.now().timestamp()).unwrap();
        courier_ftp_server::auth::totp::code_at(&secret, now)
    }
}

/// RFC 4648 base32 without padding (the TOTP secret).
fn base32_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let v = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            other => panic!("not base32: {other}"),
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).unwrap());
        }
    }
    out
}

/// A device: an app over its own data directory, using the cheap KSF.
async fn device(dir: &Path, name: &str, password: &str) -> Rig {
    let mut rig = start(dir, &MemKeyring::new(), config()).await;
    rig.cheap_sync(name);
    rig.create(password, false).await;
    rig.until("sites loaded", |a| a.site_snapshot.is_some())
        .await;
    rig
}

impl Rig {
    fn cheap_sync(&mut self, name: &str) {
        let mut cfg = AccountConfig::new(name);
        cfg.ksf = Arc::new(CourierKsf::insecure_for_tests());
        cfg.http_timeout = Duration::from_secs(10);
        let mut engine = EngineConfig::from_settings(&self.app.settings.sync);
        engine.push_debounce = Duration::from_millis(50);
        self.app
            .vault
            .as_mut()
            .unwrap()
            .sync
            .as_mut()
            .unwrap()
            .set_config(cfg, engine);
    }

    fn sync_page(&self) -> Option<SyncPage> {
        self.app
            .screen
            .sync_view()
            .map(crate::ui::sync::SyncView::page)
    }

    fn sync_note(&self) -> Option<String> {
        self.app
            .screen
            .sync_view()
            .and_then(|v| v.note().map(str::to_owned))
    }

    fn sync_error(&self) -> Option<String> {
        self.app
            .screen
            .sync_view()
            .and_then(|v| v.error().map(str::to_owned))
    }

    fn status_segment(&self) -> Option<String> {
        self.app
            .vault
            .as_ref()
            .and_then(|v| v.sync.as_ref())
            .and_then(|s| s.segment())
            .map(|(text, _)| text)
    }

    fn site_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .app
            .site_snapshot
            .as_ref()
            .map(|s| s.tree.sites().map(|s| s.name.clone()).collect())
            .unwrap_or_default();
        names.sort();
        names
    }

    async fn add_site(&self, name: &str, host: &str) {
        let mut site = Site::new(name, Protocol::Sftp, host);
        site.user = "deploy".to_owned();
        self.engine()
            .put_view(ItemId::new(), None, site)
            .await
            .unwrap();
    }

    async fn open_panel(&mut self) {
        self.ctrl_x('y');
        self.settle().await;
        assert_eq!(self.sync_page(), Some(SyncPage::Overview));
    }

    /// Fill the focused form: server URL (pasted), email, then `rest`
    /// fields after skipping `skip` of them.
    fn account_form(&mut self, server: &Server, password: &str, skip_before_password: usize) {
        self.app.screen.handle_paste(&server.url);
        self.key(KeyCode::Tab);
        self.typed(EMAIL);
        for _ in 0..=skip_before_password {
            self.key(KeyCode::Tab);
        }
        self.typed(password);
    }

    /// Register this device's vault through the wizard; returns the words.
    async fn register(&mut self, server: &Server) -> String {
        self.open_panel().await;
        let text = self.screen(80, 24);
        assert!(text.contains("not connected to a sync server"), "{text}");
        self.key(KeyCode::Enter);
        assert_eq!(self.sync_page(), Some(SyncPage::Register));
        // Server, email, device (default), master password.
        self.account_form(server, STRONG, 1);
        self.key(KeyCode::Enter);
        self.settle().await;
        assert_eq!(
            self.sync_page(),
            Some(SyncPage::Words),
            "{:?}",
            self.sync_error()
        );
        let (phrase, numbers) = self.app.screen.sync_view().unwrap().shown_phrase().unwrap();
        let text = self.screen(80, 24);
        assert!(text.contains("shown only once"), "{text}");
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);
        assert!(text.contains(words[0]), "{text}");

        // Tick, Continue, type the three words.
        self.key(KeyCode::Char(' '));
        self.key(KeyCode::Tab);
        self.key(KeyCode::Enter);
        assert_eq!(self.sync_page(), Some(SyncPage::Confirm));
        // A wrong word first.
        self.typed("wrong");
        self.key(KeyCode::Tab);
        self.typed(words[numbers[1] - 1]);
        self.key(KeyCode::Tab);
        self.typed(words[numbers[2] - 1]);
        self.key(KeyCode::Enter);
        self.settle().await;
        assert_eq!(self.sync_page(), Some(SyncPage::Confirm));
        assert!(self.sync_error().unwrap().contains("don't match"));
        for n in numbers {
            self.typed(words[n - 1]);
            self.key(KeyCode::Tab);
        }
        self.key(KeyCode::Enter);
        self.settle().await;
        // The server wants a token: the words stay valid, add it and retry.
        assert_eq!(
            self.sync_page(),
            Some(SyncPage::Token),
            "{:?}",
            self.sync_error()
        );
        assert!(self.sync_error().unwrap().contains("invite"));
        self.key(KeyCode::Right);
        self.key(KeyCode::Tab);
        self.typed(SETUP_TOKEN);
        self.key(KeyCode::Enter);
        self.settle().await;
        assert_eq!(
            self.sync_page(),
            Some(SyncPage::Overview),
            "{:?}",
            self.sync_error()
        );
        assert!(
            self.sync_note().unwrap().contains("Account created"),
            "{:?}",
            self.sync_note()
        );
        // The words are gone from the screens.
        assert_eq!(self.app.screen.sync_view().unwrap().shown_phrase(), None);
        // No two consecutive recovery words side by side (numbers between
        // them are ignored). Single words are no proof: "add" is part of
        // "address", and "now" is an ordinary word in the app's own text.
        let screen = self.screen(80, 24);
        let tokens: Vec<&str> = screen
            .split(|c: char| !c.is_ascii_alphabetic())
            .filter(|t| !t.is_empty())
            .collect();
        for pair in words.windows(2) {
            assert!(
                !tokens.windows(2).any(|t| t == pair),
                "recovery words {pair:?} still on screen:\n{screen}"
            );
        }
        phrase
    }

    async fn until_synced(&mut self) {
        self.until("synced", |a| {
            a.vault
                .as_ref()
                .and_then(|v| v.sync.as_ref())
                .and_then(|s| s.segment())
                .is_some_and(|(t, _)| t == "⟳ synced")
        })
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_then_log_in_on_a_second_device_and_sync() {
    let server = Server::start().await;
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

    // Device A registers with a site already in its vault.
    let mut a = device(dir_a.path(), "laptop", STRONG).await;
    a.add_site("alpha", "alpha.example.com").await;
    a.register(&server).await;
    a.until_synced().await;
    let text = a.screen(120, 30);
    assert!(text.contains("⟳ synced"), "{text}");
    assert!(text.contains(EMAIL), "{text}");
    a.key(KeyCode::Esc);
    assert_eq!(a.sync_page(), None);

    // Device B has its own password and a duplicate of "alpha".
    let mut b = device(dir_b.path(), "desktop", OTHER).await;
    b.add_site("alpha here", "alpha.example.com").await;
    b.add_site("beta", "beta.example.com").await;
    b.open_panel().await;
    b.key(KeyCode::Down);
    b.key(KeyCode::Enter);
    assert_eq!(b.sync_page(), Some(SyncPage::Login));
    // Server, email, account password (TOTP and device name stay).
    b.account_form(&server, STRONG, 0);
    b.key(KeyCode::Enter);
    b.settle().await;
    assert_eq!(
        b.sync_page(),
        Some(SyncPage::LoginConfirm),
        "{:?}",
        b.sync_error()
    );
    let text = b.screen(80, 24);
    assert!(text.contains("master password will be changed"), "{text}");
    assert!(text.contains("alpha here"), "{text}");
    assert!(text.contains("keep both"), "{text}");
    // Keep the account's copy of the duplicate, then log in.
    b.key(KeyCode::Left);
    assert!(b.screen(80, 24).contains("keep account"));
    b.key(KeyCode::Tab);
    b.key(KeyCode::Enter);
    b.settle().await;
    assert_eq!(
        b.sync_page(),
        Some(SyncPage::Overview),
        "{:?}",
        b.sync_error()
    );
    assert!(
        b.sync_note().unwrap().contains("Logged in"),
        "{:?}",
        b.sync_note()
    );
    b.until("account sites shown", |a| {
        a.site_snapshot.as_ref().is_some_and(|s| {
            let names: Vec<_> = s.tree.sites().map(|s| s.name.as_str()).collect();
            names.contains(&"alpha") && names.contains(&"beta")
        })
    })
    .await;
    assert_eq!(b.site_names(), ["alpha", "beta"]);
    b.until_synced().await;

    // A change on A reaches B's Site Manager by itself.
    a.add_site("gamma", "gamma.example.com").await;
    b.until("change from the other device", |app| {
        app.site_snapshot
            .as_ref()
            .is_some_and(|s| s.tree.sites().any(|s| s.name == "gamma"))
    })
    .await;
    a.until("beta on A", |app| {
        app.site_snapshot
            .as_ref()
            .is_some_and(|s| s.tree.sites().any(|s| s.name == "beta"))
    })
    .await;

    // Devices: both, this one marked.
    b.key(KeyCode::Down);
    b.key(KeyCode::Enter);
    b.settle().await;
    assert_eq!(b.sync_page(), Some(SyncPage::Devices));
    let text = b.screen(80, 24);
    assert!(text.contains("laptop"), "{text}");
    assert!(text.contains("desktop"), "{text}");
    assert!(text.contains("★ this device"), "{text}");
    b.key(KeyCode::Esc);
    b.settle().await;

    // Lock stops the engine; unlocking (with the account password, now
    // B's master password) starts it again. (The panel takes every key,
    // so it is closed first; an auto-lock closes it.)
    b.key(KeyCode::Esc);
    assert_eq!(b.sync_page(), None);
    b.ctrl_x('v');
    b.settle().await;
    assert_eq!(b.sync_page(), None);
    assert_eq!(b.status_segment(), None);
    assert!(!b.screen(120, 30).contains('⟳'));
    b.unlock(STRONG).await;
    b.until_synced().await;

    // B logs out; its sites stay.
    b.open_panel().await;
    b.key(KeyCode::Down);
    b.key(KeyCode::Down);
    b.key(KeyCode::Enter);
    assert_eq!(b.sync_page(), Some(SyncPage::Account));
    for _ in 0..4 {
        b.key(KeyCode::Down);
    }
    b.key(KeyCode::Enter);
    assert!(b.screen(80, 24).contains("Log out of sync on this device?"));
    b.key(KeyCode::Left);
    b.key(KeyCode::Enter);
    b.settle().await;
    assert!(
        b.sync_note().unwrap().contains("Logged out"),
        "{:?}",
        b.sync_note()
    );
    assert_eq!(b.status_segment(), None);
    assert_eq!(b.site_names(), ["alpha", "beta", "gamma"]);

    // A revokes the logged-out device from its devices screen.
    a.open_panel().await;
    a.key(KeyCode::Down);
    a.key(KeyCode::Enter);
    a.settle().await;
    let text = a.screen(80, 24);
    assert!(text.contains("desktop"), "{text}");
    a.key(KeyCode::Down);
    a.key(KeyCode::Char('d'));
    // The platform is the test machine's own (`std::env::consts::OS`).
    let prompt = format!("Revoke “desktop” ({})?", std::env::consts::OS);
    let text = a.screen(80, 24);
    assert!(text.contains(&prompt), "{text}");
    a.key(KeyCode::Left);
    a.key(KeyCode::Enter);
    a.settle().await;
    a.until("device list refreshed", |app| {
        app.screen
            .sync_view()
            .is_some_and(|v| v.page() == SyncPage::Devices && !v.is_busy())
    })
    .await;
    let text = a.screen(80, 24);
    assert!(text.contains("laptop"), "{text}");
    assert!(!text.contains("desktop"), "{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forgot_password_resets_it_with_the_recovery_key() {
    let server = Server::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut a = device(dir.path(), "laptop", STRONG).await;
    a.add_site("alpha", "alpha.example.com").await;
    let phrase = a.register(&server).await;
    a.until_synced().await;
    a.key(KeyCode::Esc);

    // Locked, password forgotten.
    a.ctrl_x('v');
    a.settle().await;
    let page = |r: &Rig| r.app.screen.vault_view().map(crate::ui::VaultView::page);
    assert_eq!(page(&a), Some(VaultPage::Unlock));
    a.alt('f');
    assert_eq!(page(&a), Some(VaultPage::Forgot));
    let text = a.screen(80, 24);
    assert!(text.contains("recovery key (24 words)"), "{text}");
    a.key(KeyCode::Enter);
    assert_eq!(page(&a), Some(VaultPage::Recover));
    // Server and email are filled in from this device's account.
    let text = a.screen(80, 24);
    assert!(text.contains(&server.url), "{text}");
    assert!(text.contains(EMAIL), "{text}");

    a.alt('s');
    a.settle().await;
    assert!(a.screen(80, 24).contains("recovery code was sent"));

    // Wrong words first: refused, still locked.
    let code = server.recovery_code().await;
    a.key(KeyCode::Tab);
    a.key(KeyCode::Tab);
    a.typed(&code);
    a.key(KeyCode::Tab);
    a.app.screen.handle_paste(&"abandon ".repeat(24));
    a.key(KeyCode::Tab);
    a.typed(NEW);
    a.key(KeyCode::Tab);
    a.typed(NEW);
    a.alt('r');
    a.settle().await;
    assert_eq!(page(&a), Some(VaultPage::Recover));
    assert_eq!(a.app.vault.as_ref().unwrap().phase, Phase::Locked);

    // The right words: unlocked with the new password, sync running.
    a.key(KeyCode::BackTab);
    a.key(KeyCode::BackTab);
    a.ctrl(KeyCode::Char('u'));
    a.app.screen.handle_paste(&phrase);
    a.alt('r');
    a.settle().await;
    assert_eq!(a.app.vault.as_ref().unwrap().phase, Phase::Unlocked);
    a.until_synced().await;
    assert_eq!(a.site_names(), ["alpha"]);

    // The new password is the master password from now on.
    a.ctrl_x('v');
    a.settle().await;
    a.unlock(NEW).await;
    assert_eq!(a.app.vault.as_ref().unwrap().phase, Phase::Unlocked);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_factor_on_and_off() {
    let server = Server::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut a = device(dir.path(), "laptop", STRONG).await;
    a.register(&server).await;
    a.until_synced().await;

    // Account → Enable two-factor.
    a.key(KeyCode::Down);
    a.key(KeyCode::Down);
    a.key(KeyCode::Enter);
    a.key(KeyCode::Down);
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(
        a.sync_page(),
        Some(SyncPage::TotpSetup),
        "{:?}",
        a.sync_error()
    );
    let secret = a.app.screen.sync_view().unwrap().totp_secret().unwrap();
    let text = a.screen(160, 48);
    assert!(text.contains('█'), "{text}");
    // A wrong code is refused.
    a.typed("000000");
    a.key(KeyCode::Enter);
    a.settle().await;
    assert!(a.sync_error().is_some());
    a.ctrl(KeyCode::Char('u'));
    a.typed(&server.totp(&secret));
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(
        a.sync_page(),
        Some(SyncPage::Account),
        "{:?}",
        a.sync_error()
    );
    assert!(a.sync_note().unwrap().contains("is on"));

    // Disable it again with the next code.
    server.clock.advance(chrono::TimeDelta::seconds(30));
    a.key(KeyCode::Down);
    a.key(KeyCode::Down);
    a.key(KeyCode::Enter);
    assert_eq!(a.sync_page(), Some(SyncPage::TotpDisable));
    a.typed(&server.totp(&secret));
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(
        a.sync_page(),
        Some(SyncPage::Account),
        "{:?}",
        a.sync_error()
    );
    assert!(a.sync_note().unwrap().contains("is off"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_server_must_be_https_unless_on_loopback_and_errors_show() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = device(dir.path(), "laptop", STRONG).await;
    a.open_panel().await;
    a.key(KeyCode::Enter);
    a.app.screen.handle_paste("http://sync.example.test");
    a.key(KeyCode::Tab);
    a.typed(EMAIL);
    a.key(KeyCode::Tab);
    a.key(KeyCode::Tab);
    a.typed(STRONG);
    a.key(KeyCode::Enter);
    a.settle().await;
    // Stays on the form; nothing was sent.
    assert_eq!(a.sync_page(), Some(SyncPage::Register));
    assert!(a.screen(80, 24).contains("https"));

    // A server that isn't there: the error is shown on the form (the
    // refused URL field has the focus).
    a.ctrl(KeyCode::Char('u'));
    a.app.screen.handle_paste("http://127.0.0.1:9");
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(a.sync_page(), Some(SyncPage::Register));
    assert!(a.sync_error().is_some());

    // A wrong master password is caught before anything is created.
    let server = Server::start().await;
    a.ctrl(KeyCode::Char('u'));
    a.app.screen.handle_paste(&server.url);
    a.key(KeyCode::Tab);
    a.key(KeyCode::Tab);
    a.key(KeyCode::Tab);
    a.ctrl(KeyCode::Char('u'));
    a.typed(OTHER);
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(a.sync_page(), Some(SyncPage::Register));
    assert!(
        a.sync_error().unwrap().contains("Wrong master password"),
        "{:?}",
        a.sync_error()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn password_changed_on_another_device_asks_to_log_in_again() {
    let server = Server::start().await;
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let mut a = device(dir_a.path(), "laptop", STRONG).await;
    a.register(&server).await;
    a.until_synced().await;
    let mut b = device(dir_b.path(), "desktop", STRONG).await;
    b.open_panel().await;
    b.key(KeyCode::Down);
    b.key(KeyCode::Enter);
    b.account_form(&server, STRONG, 0);
    b.key(KeyCode::Enter);
    b.settle().await;
    assert_eq!(
        b.sync_page(),
        Some(SyncPage::LoginConfirm),
        "{:?}",
        b.sync_error()
    );
    // Same password and no duplicates: nothing to choose.
    assert!(!b.screen(80, 24).contains("will be changed"));
    b.key(KeyCode::Enter);
    b.settle().await;
    b.until_synced().await;
    b.key(KeyCode::Esc);

    // A changes the password (Account → Change the password).
    a.key(KeyCode::Down);
    a.key(KeyCode::Down);
    a.key(KeyCode::Enter);
    a.key(KeyCode::Enter);
    assert_eq!(a.sync_page(), Some(SyncPage::ChangePassword));
    a.typed(STRONG);
    a.key(KeyCode::Tab);
    a.typed(NEW);
    a.key(KeyCode::Tab);
    a.typed("not the same");
    a.key(KeyCode::Enter);
    a.settle().await;
    assert!(a.screen(80, 24).contains("don't match"));
    a.ctrl(KeyCode::Char('u'));
    a.typed(NEW);
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(
        a.sync_page(),
        Some(SyncPage::Account),
        "{:?}",
        a.sync_error()
    );
    assert!(a.sync_note().unwrap().contains("Password changed"));

    // B notices, says so, and logs in again with the new password.
    b.until("login needed", |app| {
        app.vault
            .as_ref()
            .and_then(|v| v.sync.as_ref())
            .and_then(|s| s.segment())
            .is_some_and(|(t, _)| t == "⟳ login needed")
    })
    .await;
    assert!(b.screen(160, 30).contains("⟳ login needed"));
    b.open_panel().await;
    assert!(b.screen(80, 24).contains("› Log in again"));
    b.key(KeyCode::Enter);
    assert_eq!(b.sync_page(), Some(SyncPage::Login));
    let text = b.screen(80, 24);
    assert!(text.contains(&server.url) && text.contains(EMAIL), "{text}");
    b.key(KeyCode::Tab);
    b.key(KeyCode::Tab);
    b.typed(NEW);
    b.key(KeyCode::Enter);
    b.settle().await;
    assert_eq!(
        b.sync_page(),
        Some(SyncPage::LoginConfirm),
        "{:?}",
        b.sync_error()
    );
    b.key(KeyCode::Enter);
    b.settle().await;
    assert!(
        b.sync_note().unwrap().contains("Logged in"),
        "{:?}",
        b.sync_note()
    );
    b.until_synced().await;

    // Both devices now unlock with the new password.
    for rig in [&mut a, &mut b] {
        while rig.sync_page().is_some() {
            rig.key(KeyCode::Esc);
        }
        rig.ctrl_x('v');
        rig.settle().await;
        rig.unlock(NEW).await;
        assert_eq!(rig.app.vault.as_ref().unwrap().phase, Phase::Unlocked);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settings_sync_page_opens_the_panel_and_password_changes_go_through_sync() {
    use crate::ui::settings::{Section, SettingsRequest};
    let server = Server::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut a = device(dir.path(), "laptop", STRONG).await;
    a.register(&server).await;
    a.until_synced().await;
    a.key(KeyCode::Esc);

    // Settings → Sync → "Account, devices and recovery…".
    a.app.dispatch(Action::Settings).unwrap();
    a.settle().await;
    for _ in 0..30 {
        if a.app.screen.settings_view().unwrap().section() == Section::Sync {
            break;
        }
        a.key(KeyCode::Down);
    }
    assert_eq!(
        a.app.screen.settings_view().unwrap().section(),
        Section::Sync
    );
    let text = a.screen(110, 36);
    assert!(text.contains("Upload delay"), "{text}");
    a.key(KeyCode::Enter);
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(a.sync_page(), Some(SyncPage::Overview));
    let text = a.screen(110, 36);
    assert!(text.contains(EMAIL), "{text}");
    // Esc goes back to the settings screen.
    a.key(KeyCode::Esc);
    assert_eq!(a.sync_page(), None);
    assert!(a.app.screen.settings_view().is_some());

    // A local-only password change would split the vault from the account.
    a.app.settings_request(&SettingsRequest::ChangePassword {
        old: secrecy::SecretString::from(STRONG.to_owned()),
        new: secrecy::SecretString::from(NEW.to_owned()),
    });
    a.settle().await;
    let (message, _) = a
        .app
        .screen
        .settings_view()
        .unwrap()
        .message()
        .cloned()
        .unwrap();
    assert!(message.contains("sync account"), "{message}");
    a.key(KeyCode::Esc);
    a.settle().await;
    while a.app.screen.settings_view().is_some() {
        a.key(KeyCode::Esc);
        a.settle().await;
    }
    a.ctrl_x('v');
    a.settle().await;
    a.unlock(STRONG).await;
    assert_eq!(a.app.vault.as_ref().unwrap().phase, Phase::Unlocked);
}

// ---------------------------------------------------------------- teams (T90 §5, §6)

const BOB: &str = "bob@example.test";

impl Rig {
    fn team_page(&self) -> Option<TeamPage> {
        self.app
            .screen
            .sync_view()
            .and_then(crate::ui::sync::SyncView::team_page)
    }

    async fn close_panel(&mut self) {
        for _ in 0..10 {
            if self.sync_page().is_none() {
                return;
            }
            self.key(KeyCode::Esc);
            self.settle().await;
        }
        panic!("the sync panel did not close");
    }

    async fn close_site_manager(&mut self) {
        for _ in 0..5 {
            if self.app.screen.site_manager().is_none() {
                return;
            }
            self.key(KeyCode::Esc);
            self.settle().await;
        }
        panic!("the Site Manager did not close");
    }

    /// Move the selection (`› `) of the list on screen to the row with
    /// `needle`.
    fn select(&mut self, needle: &str) {
        for _ in 0..20 {
            self.key(KeyCode::Up);
        }
        for _ in 0..20 {
            let text = self.screen(120, 40);
            if text.contains(&format!("› {needle}")) {
                return;
            }
            self.key(KeyCode::Down);
        }
        panic!("no row with {needle}: {}", self.screen(120, 40));
    }

    /// Sync panel → Teams and shared vaults.
    async fn open_teams(&mut self) {
        self.close_panel().await;
        self.open_panel().await;
        for _ in 0..3 {
            self.key(KeyCode::Down);
        }
        self.key(KeyCode::Enter);
        self.settle().await;
        assert_eq!(
            self.team_page(),
            Some(TeamPage::Orgs),
            "{:?}",
            self.sync_error()
        );
    }

    /// Teams → `team` → menu item `item` (0 members, 1 vaults, 2 invite,
    /// 3 audit log).
    async fn open_team_item(&mut self, team: &str, item: usize) {
        self.open_teams().await;
        self.select(team);
        self.key(KeyCode::Enter);
        assert_eq!(self.team_page(), Some(TeamPage::Org));
        for _ in 0..item {
            self.key(KeyCode::Down);
        }
        self.key(KeyCode::Enter);
        self.settle().await;
    }

    /// Register with a team invite link as the token (the invite is
    /// accepted with the registration).
    async fn register_with_invite(&mut self, server: &Server, email: &str, link: &str) {
        self.open_panel().await;
        self.key(KeyCode::Enter);
        assert_eq!(self.sync_page(), Some(SyncPage::Register));
        self.app.screen.handle_paste(&server.url);
        self.key(KeyCode::Tab);
        self.typed(email);
        self.key(KeyCode::Tab);
        self.key(KeyCode::Tab);
        self.typed(STRONG);
        self.key(KeyCode::Tab);
        self.key(KeyCode::Tab);
        self.app.screen.handle_paste(link);
        self.key(KeyCode::Enter);
        self.settle().await;
        assert_eq!(
            self.sync_page(),
            Some(SyncPage::Words),
            "{:?}",
            self.sync_error()
        );
        let (phrase, numbers) = self.app.screen.sync_view().unwrap().shown_phrase().unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        self.key(KeyCode::Char(' '));
        self.key(KeyCode::Tab);
        self.key(KeyCode::Enter);
        for n in numbers {
            self.typed(words[n - 1]);
            self.key(KeyCode::Tab);
        }
        self.key(KeyCode::Enter);
        self.settle().await;
        assert_eq!(
            self.sync_page(),
            Some(SyncPage::Overview),
            "{:?}",
            self.sync_error()
        );
        assert!(
            self.sync_note().unwrap().contains("Account created"),
            "{:?}",
            self.sync_note()
        );
    }

    fn has_site(app: &App, name: &str) -> bool {
        app.site_snapshot
            .as_ref()
            .is_some_and(|s| s.tree.sites().any(|s| s.name == name))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn teams_share_a_vault_read_only_verify_keys_and_remove_a_member() {
    use courier_ftp_crypto::{account::generate_account_keys, keys::os_rng};

    let server = Server::start().await;
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let mut a = device(dir_a.path(), "alice-laptop", STRONG).await;
    a.register(&server).await;
    a.until_synced().await;

    // Alice creates a team…
    a.open_teams().await;
    assert!(a.screen(100, 30).contains("not in a team yet"));
    a.key(KeyCode::Char('n'));
    assert_eq!(a.team_page(), Some(TeamPage::NewOrg));
    a.typed("Ops");
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(a.team_page(), Some(TeamPage::Orgs), "{:?}", a.sync_error());
    assert!(a.sync_note().unwrap().contains("Team “Ops” created"));
    let text = a.screen(100, 30);
    assert!(text.contains("Ops") && text.contains("owner"), "{text}");

    // …invites Bob by email (no mail server here: the link is shown)…
    a.key(KeyCode::Enter);
    assert_eq!(a.team_page(), Some(TeamPage::Org));
    a.key(KeyCode::Down);
    a.key(KeyCode::Down);
    a.key(KeyCode::Enter);
    assert_eq!(a.team_page(), Some(TeamPage::Invite));
    a.typed(BOB);
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(
        a.team_page(),
        Some(TeamPage::InviteLink),
        "{:?}",
        a.sync_error()
    );
    let link = a.app.screen.sync_view().unwrap().invite_link().unwrap();
    assert!(link.contains("/invite/"), "{link}");
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(a.team_page(), Some(TeamPage::Members));
    let text = a.screen(100, 30);
    assert!(text.contains(EMAIL) && text.contains("(you)"), "{text}");

    // …and creates a shared vault.
    a.key(KeyCode::Esc);
    a.key(KeyCode::Down);
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(a.team_page(), Some(TeamPage::Vaults));
    a.key(KeyCode::Char('n'));
    a.typed("Ops servers");
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(
        a.team_page(),
        Some(TeamPage::Vaults),
        "{:?}",
        a.sync_error()
    );
    let text = a.screen(100, 30);
    assert!(
        text.contains("Ops servers") && text.contains("manage"),
        "{text}"
    );

    // The Site Manager shows the vaults as roots; Alice adds a site to the
    // team vault.
    a.close_panel().await;
    a.until("vault roots", |app| app.vault_roots.len() == 2)
        .await;
    let team_vault = a.app.vault_roots[1].id;
    a.ctrl(KeyCode::Char('s'));
    a.settle().await;
    let text = a.screen(120, 30);
    assert!(text.contains("Personal"), "{text}");
    assert!(text.contains("Team: Ops servers"), "{text}");
    a.key(KeyCode::Down);
    a.key(KeyCode::Char('n'));
    a.ctrl(KeyCode::Char('u'));
    a.typed("deploy box");
    a.key(KeyCode::Enter);
    a.typed("deploy.example.com");
    for _ in 0..3 {
        a.key(KeyCode::Tab); // port, logon type, user
    }
    a.typed("deploy");
    a.ctrl(KeyCode::Char('s'));
    a.settle().await;
    let text = a.screen(120, 30);
    assert!(text.contains("Saved"), "{text}");
    let site = a
        .snapshot()
        .tree
        .sites()
        .find(|s| s.name == "deploy box")
        .cloned()
        .unwrap();
    assert_eq!(site.vault, Some(team_vault));
    a.close_site_manager().await;

    // Bob registers with the invite link: he is in the team at once.
    let mut b = device(dir_b.path(), "bob-laptop", STRONG).await;
    b.register_with_invite(&server, BOB, &link).await;
    b.until_synced().await;
    b.open_teams().await;
    let text = b.screen(100, 30);
    assert!(text.contains("Ops") && text.contains("member"), "{text}");

    // A second team: Bob joins it with a pasted link.
    a.open_teams().await;
    a.key(KeyCode::Char('n'));
    a.typed("Infra");
    a.key(KeyCode::Enter);
    a.settle().await;
    a.select("Infra");
    a.key(KeyCode::Enter);
    a.key(KeyCode::Down);
    a.key(KeyCode::Down);
    a.key(KeyCode::Enter);
    a.key(KeyCode::Enter);
    a.settle().await;
    let infra_link = a.app.screen.sync_view().unwrap().invite_link().unwrap();
    b.key(KeyCode::Char('a'));
    assert_eq!(b.team_page(), Some(TeamPage::Accept));
    b.app.screen.handle_paste(&infra_link);
    b.key(KeyCode::Enter);
    b.settle().await;
    assert_eq!(b.team_page(), Some(TeamPage::Orgs), "{:?}", b.sync_error());
    assert!(
        b.sync_note().unwrap().contains("You joined “Infra”"),
        "{:?}",
        b.sync_note()
    );
    assert!(b.screen(100, 30).contains("Infra"));

    // Alice gives Bob read access to the vault.
    a.open_team_item("Ops", 1).await;
    assert_eq!(a.team_page(), Some(TeamPage::Vaults));
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(a.team_page(), Some(TeamPage::VaultMembers));
    a.select(BOB);
    assert!(a.screen(120, 40).contains("no access"));
    a.key(KeyCode::Right);
    a.settle().await;
    assert!(
        a.sync_note()
            .unwrap_or_default()
            .contains("can now use (read only)"),
        "{:?} {:?}",
        a.sync_note(),
        a.sync_error()
    );
    assert!(a.screen(120, 40).contains("‹ read ›"));

    // The audit log has it all.
    a.open_team_item("Ops", 3).await;
    assert_eq!(a.team_page(), Some(TeamPage::Audit));
    let text = a.screen(120, 40);
    for kind in ["invite.sent", "invite.accepted", "vault.created"] {
        assert!(text.contains(kind), "{kind}: {text}");
    }

    // Bob gets the vault (a toast says so) and sees the site with 🔒; he
    // can't change it.
    b.close_panel().await;
    b.until("the shared site", |app| Rig::has_site(app, "deploy box"))
        .await;
    b.until("read-only vault root", |app| {
        app.vault_roots.len() == 2 && app.vault_roots[1].read_only
    })
    .await;
    assert!(b.screen(160, 48).contains("given access"));
    b.ctrl(KeyCode::Char('s'));
    b.settle().await;
    let text = b.screen(140, 30);
    assert!(text.contains("Team: Ops servers 🔒"), "{text}");
    assert!(text.contains("deploy box 🔒"), "{text}");
    // Personal (empty), the team root, the site.
    b.key(KeyCode::Down);
    b.key(KeyCode::Down);
    let text = b.screen(140, 30);
    assert!(
        text.contains("🔒 read-only (Team: Ops servers is shared with you"),
        "{text}"
    );
    b.key(KeyCode::Tab);
    b.typed("zzz");
    b.ctrl(KeyCode::Char('s'));
    assert!(
        b.screen(140, 30).contains("is read-only for you"),
        "{}",
        b.screen(140, 30)
    );
    b.key(KeyCode::Esc);
    b.key(KeyCode::Char('x'));
    assert!(b.screen(140, 30).contains("is read-only for you"));
    b.settle().await;
    let shared = b
        .snapshot()
        .tree
        .sites()
        .find(|s| s.name == "deploy box")
        .cloned()
        .unwrap();
    assert_eq!(shared.host, "deploy.example.com");
    assert!(b.engine().is_vault_read_only(shared.vault.unwrap()).await);
    b.close_site_manager().await;

    // Safety numbers: the same on both sides; Alice marks Bob verified.
    a.open_team_item("Ops", 0).await;
    a.select(BOB);
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(
        a.team_page(),
        Some(TeamPage::Safety),
        "{:?}",
        a.sync_error()
    );
    let number_a = a.app.screen.sync_view().unwrap().safety_number().unwrap();
    b.open_team_item("Ops", 0).await;
    b.select(EMAIL);
    b.key(KeyCode::Enter);
    b.settle().await;
    let number_b = b.app.screen.sync_view().unwrap().safety_number().unwrap();
    assert_eq!(number_a, number_b);
    assert_eq!(number_a.chars().filter(char::is_ascii_digit).count(), 60);
    b.close_panel().await;
    a.key(KeyCode::Left);
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(a.team_page(), Some(TeamPage::Members));
    assert!(a.sync_note().unwrap().contains("marked verified"));
    assert!(a.screen(120, 40).contains("✔ verified"));

    // The server swaps Bob's keys: Alice's member list warns, and raising
    // his access is refused with the key-change warning until she accepts.
    let fake = generate_account_keys(&mut os_rng()).public();
    server.mem.with_data(|d| {
        let bob = *d.users.iter().find(|(_, u)| u.email == BOB).unwrap().0;
        let row = d.account_keys.get_mut(&bob).unwrap();
        row.x25519_pub = fake.x25519.to_vec();
        row.ed25519_pub = fake.ed25519.to_vec();
    });
    a.key(KeyCode::Char('r'));
    a.settle().await;
    let text = a.screen(120, 40);
    assert!(text.contains("⚠ key changed"), "{text}");
    assert!(text.contains("A member's key changed"), "{text}");
    a.key(KeyCode::Esc);
    a.key(KeyCode::Down);
    a.key(KeyCode::Enter);
    a.settle().await;
    a.key(KeyCode::Enter);
    a.settle().await;
    a.select(BOB);
    a.key(KeyCode::Right);
    a.settle().await;
    assert_eq!(
        a.team_page(),
        Some(TeamPage::KeyChanged),
        "{:?}",
        a.sync_error()
    );
    let text = a.screen(120, 40);
    assert!(
        text.contains("changed since this device first saw them"),
        "{text}"
    );
    assert_ne!(
        a.app.screen.sync_view().unwrap().safety_number().unwrap(),
        number_a,
        "the new key's number"
    );
    a.key(KeyCode::Left);
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(a.team_page(), Some(TeamPage::VaultMembers));
    assert!(
        a.sync_note().unwrap().contains("is accepted"),
        "{:?}",
        a.sync_note()
    );

    // Removing Bob rotates the vault key (toasts say so); the vault leaves
    // Bob's device.
    a.key(KeyCode::Esc);
    a.settle().await;
    a.key(KeyCode::Esc);
    a.key(KeyCode::Enter);
    a.settle().await;
    assert_eq!(a.team_page(), Some(TeamPage::Members));
    a.select(BOB);
    a.key(KeyCode::Char('x'));
    assert!(
        a.screen(120, 40)
            .contains("Remove bob@example.test from “Ops”?")
    );
    a.key(KeyCode::Left);
    a.key(KeyCode::Enter);
    a.settle().await;
    assert!(
        a.sync_note()
            .unwrap()
            .contains("the key of 1 vault was rotated"),
        "{:?} {:?}",
        a.sync_note(),
        a.sync_error()
    );
    let text = a.screen(120, 40);
    assert!(
        !text
            .lines()
            .any(|l| l.contains(BOB) && l.contains("member")),
        "{text}"
    );
    a.close_panel().await;
    let text = a.screen(160, 48);
    assert!(text.contains("was rotated"), "{text}");
    b.until("the vault left Bob's device", |app| {
        !Rig::has_site(app, "deploy box") && app.vault_roots.is_empty()
    })
    .await;
    let text = b.screen(160, 48);
    assert!(text.contains("was revoked"), "{text}");
}
