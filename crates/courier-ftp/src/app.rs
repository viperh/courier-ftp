use courier_ftp_core::{
    backend::{Backend, BackendFactory, ConnectInfo, Listing, SessionHandle},
    cache::ListingCache,
    events::{self, EventReceiver, EventSender, LogKind, SessionId},
    local::LocalBackend,
    model::{RemotePath, ServerAddress},
    settings::{LoggingSettings, Settings},
    sites::History,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crossterm::event::KeyEvent;
use ratatui::prelude::Rect;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{
    action::{Action, ConnectRequest, Connected},
    backends::Backends,
    config::Config,
    keymap::{Feed, KeyBindings, Sequencer},
    tui::{Event, Tui},
    ui::{KeyOutcome, MainScreen, Side, Theme, VaultFacts, VaultRequest, VaultView},
    vault::{Phase, Vault, VaultMsg},
};

/// The application: the event loop that ties the terminal, the
/// [`MainScreen`] and the core together.
///
/// One `tokio::select!` waits on terminal events, the action channel and the
/// core's event bus (T04). Work that touches the filesystem or network runs in
/// spawned tasks that report back with an [`Action`], so drawing never waits
/// on I/O.
pub(crate) struct App {
    keybindings: KeyBindings,
    tick_rate: f64,
    frame_rate: f64,
    screen: MainScreen,
    should_quit: bool,
    should_suspend: bool,
    sequencer: Sequencer,
    action_tx: mpsc::UnboundedSender<Action>,
    action_rx: mpsc::UnboundedReceiver<Action>,
    events_tx: EventSender,
    events_rx: EventReceiver,
    /// The session id of the local pane, for log lines.
    local_session: SessionId,
    /// Directory listings, shared by every pane (T46).
    cache: ListingCache,
    settings: Settings,
    /// Creates a backend for each connection (T03).
    backends: Arc<dyn BackendFactory>,
    /// The remote pane's connection.
    remote: Option<Remote>,
    /// The last connection of this run, without its password, for
    /// [`Action::Reconnect`].
    last_connect: Option<ConnectRequest>,
    /// The vault (T60); `None` in tests that don't need one.
    vault: Option<Vault>,
    vault_tx: mpsc::UnboundedSender<VaultMsg>,
    vault_rx: mpsc::UnboundedReceiver<VaultMsg>,
    /// The quickconnect history (T33); `None` while the vault is locked.
    history: Option<History>,
    /// Session log file and raw listings (T71).
    diag: crate::diagnostics::Diagnostics,
}

/// The remote pane's connection (one tab until T61).
struct Remote {
    session: SessionId,
    info: ConnectInfo,
    handle: Arc<SessionHandle>,
    /// Cancels the connection attempt, its prompts and running listings.
    cancel: CancellationToken,
    /// Whether `connect` finished; listings wait for it.
    connected: bool,
    /// Turn synchronized browsing / directory comparison on once connected.
    sync_browsing: bool,
    compare: bool,
    /// The login to add to the quickconnect history once connected (with
    /// the typed password; the vault drops it unless
    /// `vault.store_passwords`).
    record: Option<ConnectInfo>,
}

/// `alice@host` (with the port when it isn't the protocol's default), for
/// titles and dialogs.
fn server_label(a: &ServerAddress) -> String {
    let mut out = String::new();
    if let Some(user) = &a.user {
        out.push_str(user);
        out.push('@');
    }
    if a.host.contains(':') {
        out.push_str(&format!("[{}]", a.host));
    } else {
        out.push_str(&a.host);
    }
    if a.port != a.default_port() {
        out.push_str(&format!(":{}", a.port));
    }
    out
}

/// Input modes. Keybindings and styles in `config/default.json` are keyed by
/// these names, so adding a variant here means adding a section there too.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum Mode {
    /// Global bindings, active whenever no text field or dialog has the keys.
    #[default]
    Normal,
    /// A file list has focus (falls back to `Normal`).
    FileList,
    /// The queue has focus (falls back to `Normal`).
    Queue,
    /// The message log has focus (falls back to `Normal`).
    Log,
    /// Typing a pane's quick filter (T53).
    Filter,
    /// A text field (quickconnect) has focus.
    Input,
    /// A dialog is open.
    Dialog,
}

impl Mode {
    /// Whether keys not bound in this mode are looked up in `Normal`.
    pub(crate) fn falls_back_to_normal(self) -> bool {
        matches!(self, Mode::FileList | Mode::Queue | Mode::Log)
    }
}

impl App {
    pub(crate) fn new(tick_rate: f64, frame_rate: f64) -> color_eyre::Result<Self> {
        let config = Config::new()?;
        let backends = Backends::new(&config.settings);
        // Kept before the factory moves into the app: the vault swaps the
        // host key store and clears the credential cache.
        let host_keys = Arc::clone(&backends.host_keys);
        let credentials = backends.credentials.clone();
        let certs = Arc::clone(&backends.certs);
        let ftp = backends.ftp.clone();
        let proxy_password = match &config.settings.proxy.ftp_proxy {
            courier_ftp_core::settings::FtpProxy::None => None,
            courier_ftp_core::settings::FtpProxy::UserAtHost(p)
            | courier_ftp_core::settings::FtpProxy::Site(p)
            | courier_ftp_core::settings::FtpProxy::Open(p)
            | courier_ftp_core::settings::FtpProxy::Custom { server: p, .. } => {
                p.password_ref.clone()
            }
        };
        let app = Self::with_backends(config, Arc::new(backends), tick_rate, frame_rate);
        let opener = crate::vault::opener(crate::config::get_data_dir());
        let mut app = app.with_vault(opener, host_keys, credentials);
        if let Some(vault) = app.vault.as_mut() {
            vault.set_ftp(certs, ftp, proxy_password);
        }
        Ok(app)
    }

    /// Give the app a vault: it starts locked, the panes covered by the
    /// vault view until the vault is unlocked or skipped.
    pub(crate) fn with_vault(
        mut self,
        opener: crate::vault::VaultOpener,
        host_keys: Arc<courier_ftp_core::trust::HostKeyStoreSlot>,
        credentials: courier_ftp_proto_sftp::ssh::CredentialCache,
    ) -> Self {
        self.vault = Some(Vault::new(
            opener,
            host_keys,
            credentials,
            &self.settings.vault,
            self.vault_tx.clone(),
        ));
        let unicode = crate::ui::unicode_symbols(&self.settings);
        self.screen.set_vault_view(VaultView::opening(unicode));
        self.screen.set_vault_locked(true);
        self
    }

    /// An app using `backends` for connections (tests pass a mock server).
    pub(crate) fn with_backends(
        config: Config,
        backends: Arc<dyn BackendFactory>,
        tick_rate: f64,
        frame_rate: f64,
    ) -> Self {
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let (events_tx, events_rx) = events::channel(config.settings.logging.level);
        let theme = Theme::new(
            config.styles.0.get(&Mode::Normal),
            Theme::no_color_requested(),
        );
        let local_session = SessionId::next();
        let sequencer = Sequencer::new(Duration::from_millis(
            config.settings.interface.key_sequence_timeout_ms,
        ));
        let cache = ListingCache::new(&config.settings.cache, Some(events_tx.clone()));
        for warning in &config.settings_warnings {
            events_tx.log(local_session, LogKind::Error, format!("config: {warning}"));
        }
        let mut screen = MainScreen::new(config.clone(), theme);
        screen.set_action_tx(action_tx.clone());
        let (vault_tx, vault_rx) = mpsc::unbounded_channel();
        let offset = time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC);
        let mut app = Self {
            keybindings: config.keybindings.clone(),
            tick_rate,
            frame_rate,
            screen,
            should_quit: false,
            should_suspend: false,
            sequencer,
            action_tx,
            action_rx,
            events_tx,
            events_rx,
            local_session,
            cache,
            settings: config.settings.clone(),
            backends,
            remote: None,
            last_connect: None,
            vault: None,
            vault_tx,
            vault_rx,
            history: None,
            diag: crate::diagnostics::Diagnostics::new(offset),
        };
        app.apply_logging(&config.settings.logging);
        app
    }

    /// Apply the `logging.*` settings (at start, and when the settings
    /// screen changes them, T68): debug level, raw listings, session log.
    pub(crate) fn apply_logging(&mut self, logging: &LoggingSettings) {
        self.events_tx.set_log_level(logging.level);
        self.events_tx.set_raw_listing(logging.show_raw_listing);
        if let Some(problem) = self.diag.apply(logging, &crate::config::get_data_dir()) {
            self.events_tx
                .log(self.local_session, LogKind::Error, problem);
        }
        self.settings.logging = logging.clone();
    }

    /// `--debug-level`: this run's debug level (0–4), not saved.
    pub(crate) fn set_debug_level(&mut self, level: u8) {
        let mut logging = self.settings.logging.clone();
        logging.level = level.min(4);
        self.apply_logging(&logging);
    }

    /// A status line in the message log (startup warnings).
    pub(crate) fn log_status(&self, text: &str) {
        self.events_tx
            .log(self.local_session, LogKind::Status, text);
    }

    pub(crate) async fn run(&mut self) -> color_eyre::Result<()> {
        let mut tui = Tui::new()?
            .tick_rate(self.tick_rate)
            .frame_rate(self.frame_rate)
            .paste(true);
        tui.enter()?;
        self.events_tx.log(
            self.local_session,
            LogKind::Status,
            format!("courier-ftp {} ready", env!("CARGO_PKG_VERSION")),
        );
        self.list(Side::Local, None, false, false);
        self.start_vault();

        loop {
            tokio::select! {
                event = tui.next_event() => match event {
                    Some(event) => self.handle_event(event)?,
                    None => self.should_quit = true,
                },
                Some(action) = self.action_rx.recv() => {
                    self.handle_action(&mut tui, action)?;
                }
                Some(event) = self.events_rx.recv() => self.core_event(event),
                Some(msg) = self.vault_rx.recv() => self.vault_message(msg),
            }
            while let Ok(action) = self.action_rx.try_recv() {
                self.handle_action(&mut tui, action)?;
            }
            if self.should_suspend {
                tui.suspend()?;
                self.action_tx.send(Action::Resume)?;
                self.action_tx.send(Action::ClearScreen)?;
                tui.enter()?;
            } else if self.should_quit {
                tui.stop()?;
                break;
            }
        }
        tui.exit()?;
        if let Some(log) = self.diag.session_log() {
            log.flush_timeout(Duration::from_secs(1));
        }
        Ok(())
    }

    fn handle_event(&mut self, event: Event) -> color_eyre::Result<()> {
        let tx = &self.action_tx;
        match event {
            Event::Quit => tx.send(Action::Quit)?,
            Event::Tick => tx.send(Action::Tick)?,
            Event::Render => tx.send(Action::Render)?,
            Event::Resize(x, y) => tx.send(Action::Resize(x, y))?,
            Event::Key(key) => self.handle_key_event(key)?,
            Event::Paste(text) => self.screen.handle_paste(&text),
            _ => {}
        }
        Ok(())
    }

    /// Keys go to the screen first (modal, then focused region); what it
    /// doesn't take goes through the sequence matcher and the keymap of the
    /// current mode.
    fn handle_key_event(&mut self, key: KeyEvent) -> color_eyre::Result<()> {
        if let Some(vault) = &mut self.vault {
            vault.on_input();
        }
        if self.screen.handle_key(key) == KeyOutcome::Consumed {
            self.sequencer.reset();
            for request in self.screen.take_vault_requests() {
                self.vault_request(request);
            }
            for next in self.screen.take_actions() {
                self.action_tx.send(next)?;
            }
        } else {
            let mode = self.screen.mode();
            match self
                .sequencer
                .feed(&self.keybindings, mode, key, Instant::now())
            {
                Feed::Action(action) => {
                    debug!("Got action: {action:?}");
                    self.action_tx.send(action)?;
                }
                Feed::Pending | Feed::Unbound => {}
            }
        }
        self.screen
            .set_pending_keys(self.sequencer.pending_display());
        Ok(())
    }

    fn handle_action(&mut self, tui: &mut Tui, action: Action) -> color_eyre::Result<()> {
        match &action {
            Action::ClearScreen => tui.terminal.clear()?,
            Action::Resize(w, h) => {
                tui.resize(Rect::new(0, 0, *w, *h))?;
                self.render(tui)?;
            }
            Action::Render => self.render(tui)?,
            _ => {}
        }
        self.dispatch(action)
    }

    /// Apply an action that doesn't need the terminal.
    fn dispatch(&mut self, action: Action) -> color_eyre::Result<()> {
        if !matches!(action, Action::Tick | Action::Render) {
            debug!("{action}");
        }
        match &action {
            Action::Tick => {
                self.sequencer.expire(Instant::now());
                self.screen
                    .set_pending_keys(self.sequencer.pending_display());
                if let Some(reason) = self.vault.as_mut().and_then(Vault::tick) {
                    self.lock_vault(Some(reason));
                }
            }
            Action::LockVault => match self.vault.as_ref().map(|v| v.phase) {
                None => self.screen.flash("No vault"),
                Some(Phase::Unlocked) => self.lock_vault(None),
                Some(Phase::Opening) => {}
                Some(_) => self.screen.show_vault(true),
            },
            Action::UnlockVault => match self.vault.as_ref().map(|v| v.phase) {
                None => self.screen.flash("No vault"),
                Some(Phase::Unlocked) => self.screen.flash("The vault is already unlocked"),
                Some(_) => self.screen.show_vault(true),
            },
            Action::SiteManager | Action::Bookmarks
                if self
                    .vault
                    .as_ref()
                    .is_some_and(|v| v.phase != Phase::Unlocked) =>
            {
                self.offer_unlock(if matches!(action, Action::SiteManager) {
                    "the Site Manager"
                } else {
                    "bookmarks"
                });
            }
            // No transfers exist yet, so nothing needs confirming (T41 adds the
            // "transfers are running, quit anyway?" dialog).
            Action::Quit => self.should_quit = true,
            Action::Suspend => self.should_suspend = true,
            Action::Resume => self.should_suspend = false,
            Action::Connect { request, replace } => {
                self.connect((**request).clone(), *replace);
            }
            Action::Connected { session, result } => self.connected(*session, result),
            Action::RemoteListingLoaded {
                session,
                dir,
                tree,
                result,
            } => {
                if self.current_session() == Some(*session) {
                    self.action_tx.send(if *tree {
                        Action::TreeListingLoaded {
                            side: Side::Remote,
                            dir: dir.clone(),
                            result: result.clone(),
                        }
                    } else {
                        Action::ListingLoaded {
                            side: Side::Remote,
                            result: result.clone(),
                        }
                    })?;
                }
            }
            Action::Disconnect => {
                if self.remote.is_some() {
                    self.disconnect();
                } else {
                    self.screen.flash("Not connected");
                }
            }
            Action::Reconnect => match self.last_connect.clone().or_else(|| {
                // Nothing this run: the most recent history entry.
                let history = self.screen.quickconnect_mut().history()?;
                history.first().map(|item| item.request.clone())
            }) {
                Some(request) => self.start_connect(request),
                None => self.screen.flash("No server to reconnect to"),
            },
            Action::QuickconnectHistory => self.show_history(),
            Action::HistoryPicked(request) => {
                self.screen.quickconnect_mut().fill(request);
                self.connect((**request).clone(), false);
            }
            Action::ClearHistory => self.clear_history(),
            Action::HistoryLoaded(items) => {
                if self.history.is_some() {
                    self.screen
                        .quickconnect_mut()
                        .set_history(Some(items.clone()));
                }
            }
            Action::ListDir { side, dir, force } => {
                self.list(*side, Some(dir.clone()), *force, false);
            }
            Action::TreeListDir { side, dir } => self.list(*side, Some(dir.clone()), false, true),
            Action::MakeDir { side, dir } => self.make_dir(*side, dir.clone()),
            Action::CopyToClipboard(text) => {
                if let Err(e) = crate::clipboard::copy(text) {
                    tracing::warn!("clipboard: {e}");
                }
            }
            Action::ListingLoaded {
                side,
                result: Ok(listing),
            } => self.diag.listing_shown(*side, listing),
            Action::ShowRawListing => match self.diag.raw_listing_viewer(self.screen.active_side())
            {
                Ok(viewer) => self.screen.push_modal(Box::new(viewer)),
                Err(why) => self.screen.flash(why),
            },
            Action::SaveLogText(text) => {
                let suggested = crate::diagnostics::default_save_path(
                    &crate::config::get_data_dir(),
                    time::OffsetDateTime::now_utc(),
                );
                let modal = crate::diagnostics::save_log_dialog(
                    text.clone(),
                    &suggested,
                    self.action_tx.clone(),
                );
                self.screen.push_modal(modal);
            }
            Action::LogSaved { path, result } => {
                let (kind, text) = match result {
                    Ok(()) => (LogKind::Status, format!("Log saved to {}", path.display())),
                    Err(e) => (
                        LogKind::Error,
                        format!("Could not save the log to {}: {e}", path.display()),
                    ),
                };
                self.events_tx.log(self.local_session, kind, text.clone());
                self.screen.flash(&text);
            }
            Action::Error(err) => {
                // Errors name paths and hosts: debug only (T91 §4).
                tracing::debug!(error = %err, "action failed");
                self.events_tx
                    .log(self.local_session, LogKind::Error, err.clone());
            }
            _ => {}
        }
        if let Some(next) = self.screen.update(&action) {
            self.action_tx.send(next)?;
        }
        for next in self.screen.take_actions() {
            self.action_tx.send(next)?;
        }
        Ok(())
    }

    /// List `dir` (the home directory when `None`) in the background, through
    /// the listing cache unless `force`. For the file list (the pane shows a
    /// spinner until [`Action::ListingLoaded`] arrives) or, with `tree`, for
    /// the directory tree ([`Action::TreeListingLoaded`]).
    fn list(&mut self, side: Side, dir: Option<RemotePath>, force: bool, tree: bool) {
        if side == Side::Remote {
            if let Some(dir) = dir {
                self.list_remote(dir, force, tree);
            }
            return;
        }
        if !tree {
            self.screen.pane_mut(side).busy = true;
        }
        let tx = self.action_tx.clone();
        let cache = self.cache.clone();
        tokio::spawn(async move {
            let mut backend = LocalBackend::new();
            let cancel = CancellationToken::new();
            let requested = dir.clone();
            let result = async {
                backend.connect(cancel.clone()).await?;
                let dir = match dir {
                    Some(dir) => dir,
                    None => backend.home_dir().await?,
                };
                cache.list_with(&mut backend, &dir, force, cancel).await
            }
            .await
            .map_err(|e| e.to_string());
            let _ = tx.send(match requested.filter(|_| tree) {
                Some(dir) => Action::TreeListingLoaded { side, dir, result },
                None => Action::ListingLoaded { side, result },
            });
        });
    }

    /// Create `dir` on `side` in the background; [`Action::DirMade`] reports
    /// the result. The parent's cached listing is dropped.
    fn make_dir(&mut self, side: Side, dir: RemotePath) {
        let tx = self.action_tx.clone();
        let cache = self.cache.clone();
        match side {
            Side::Local => {
                tokio::spawn(async move {
                    let mut backend = LocalBackend::new();
                    let cancel = CancellationToken::new();
                    let result = async {
                        backend.connect(cancel).await?;
                        backend.mkdir(&dir).await
                    }
                    .await
                    .map_err(|e| e.to_string());
                    if let Some(parent) = dir.parent() {
                        cache.invalidate(None, &parent);
                    }
                    let _ = tx.send(Action::DirMade { side, dir, result });
                });
            }
            Side::Remote => {
                let Some(remote) = self.remote.as_ref().filter(|r| r.connected) else {
                    let _ = tx.send(Action::DirMade {
                        side,
                        dir,
                        result: Err("Not connected".to_owned()),
                    });
                    return;
                };
                let handle = Arc::clone(&remote.handle);
                let cancel = remote.cancel.clone();
                let server = remote.info.address.clone();
                tokio::spawn(async move {
                    let result = handle.mkdir(&dir, &cancel).await.map_err(|e| e.to_string());
                    if let Some(parent) = dir.parent() {
                        cache.invalidate(Some(&server), &parent);
                    }
                    let _ = tx.send(Action::DirMade { side, dir, result });
                });
            }
        }
    }

    fn current_session(&self) -> Option<SessionId> {
        self.remote.as_ref().map(|r| r.session)
    }

    /// List `dir` on the remote connection, through the cache unless
    /// `force`, for the file list or (with `tree`) the directory tree.
    fn list_remote(&mut self, dir: RemotePath, force: bool, tree: bool) {
        let Some(remote) = self.remote.as_ref().filter(|r| r.connected) else {
            if tree {
                self.screen
                    .tree_mut(Side::Remote)
                    .loaded(&dir, &Err("Not connected".to_owned()));
            } else {
                self.screen.pane_mut(Side::Remote).busy = false;
            }
            return;
        };
        let session = remote.session;
        let handle = Arc::clone(&remote.handle);
        let cancel = remote.cancel.clone();
        let server = remote.info.address.clone();
        let cache = self.cache.clone();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let result = match cache.get(Some(&server), &dir).filter(|_| !force) {
                Some(hit) => Ok(hit),
                None => handle
                    .list(&dir, &cancel)
                    .await
                    .inspect(|listing| cache.put(Some(&server), listing.clone())),
            }
            .map_err(|e| e.to_string());
            let _ = tx.send(Action::RemoteListingLoaded {
                session,
                dir,
                tree,
                result,
            });
        });
    }

    /// Something from the core's event bus. A patched cached listing (T46)
    /// also refreshes the directory tree of its side.
    pub(crate) fn core_event(&mut self, event: events::CoreEvent) {
        if let events::CoreEvent::Log(msg) = &event {
            self.diag.record(msg);
        }
        if let events::CoreEvent::ListingUpdated { session, dir } = &event {
            let side = if self.current_session() == Some(*session) {
                Side::Remote
            } else {
                Side::Local
            };
            self.screen.tree_mut(side).invalidate(dir);
        }
        self.screen.handle_core(event);
    }

    /// Quickconnect: connect the remote pane, asking first when that closes
    /// a connection (unless `replace`).
    fn connect(&mut self, request: ConnectRequest, replace: bool) {
        let Some(remote) = self.remote.as_ref().filter(|_| !replace) else {
            self.start_connect(request);
            return;
        };
        let (modal, rx) = crate::ui::dialog::confirm(
            "Replace connection",
            &format!(
                "Disconnect from {} and connect to {}?",
                server_label(&remote.info.address),
                server_label(&request.info.address)
            ),
            true,
        );
        self.screen.push_modal(modal);
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            if let Ok(true) = rx.await {
                let _ = tx.send(Action::Connect {
                    request: Box::new(request),
                    replace: true,
                });
            }
        });
    }

    /// Close any connection and open one for `request` in the background;
    /// [`Action::Connected`] reports the result.
    fn start_connect(&mut self, request: ConnectRequest) {
        if self.remote.is_some() {
            self.disconnect();
        }
        let session = SessionId::next();
        let c = &self.settings.connection;
        let keepalive = c
            .keepalive
            .then(|| Duration::from_secs(c.keepalive_interval_secs.max(1)));
        let backend = self
            .backends
            .create(&request.info, session, self.events_tx.clone());
        let handle = Arc::new(SessionHandle::new(backend, keepalive));
        let cancel = CancellationToken::new();
        self.remote = Some(Remote {
            session,
            info: request.info.clone(),
            handle: Arc::clone(&handle),
            cancel: cancel.clone(),
            connected: false,
            sync_browsing: request.sync_browsing,
            compare: request.compare,
            record: Some(request.info.clone()),
        });
        self.last_connect = Some(request.without_password());
        self.screen
            .remote_connecting(server_label(&request.info.address));

        let tx = self.action_tx.clone();
        let events = self.events_tx.clone();
        let cache = self.cache.clone();
        let server = request.info.address.clone();
        let start = request.path;
        tokio::spawn(async move {
            let result = async {
                handle.connect(cancel.clone()).await?;
                let info = handle.lock().await.session_info();
                let listing = match start {
                    Some(dir) => match handle.list(&dir, &cancel).await {
                        Ok(listing) => listing,
                        Err(e) => {
                            events.log(session, LogKind::Error, format!("{dir}: {e}"));
                            first_listing(&handle, &cancel).await?
                        }
                    },
                    None => first_listing(&handle, &cancel).await?,
                };
                cache.put(Some(&server), listing.clone());
                Ok::<_, courier_ftp_core::Error>(Box::new(Connected { info, listing }))
            }
            .await
            .map_err(|e| e.to_string());
            let _ = tx.send(Action::Connected { session, result });
        });
    }

    /// A connection attempt finished; results of replaced attempts are
    /// dropped.
    fn connected(&mut self, session: SessionId, result: &Result<Box<Connected>, String>) {
        let Some(remote) = self.remote.as_mut().filter(|r| r.session == session) else {
            return;
        };
        match result {
            Ok(connected) => {
                remote.connected = true;
                let (sync, compare) = (remote.sync_browsing, remote.compare);
                let case_sensitive = courier_ftp_core::compare::names_case_sensitive(
                    remote.info.server_type.unwrap_or_default(),
                    courier_ftp_core::model::item::ServerType::default(),
                );
                self.diag.listing_shown(Side::Remote, &connected.listing);
                let record = remote.record.take();
                self.screen.remote_connected(connected);
                self.screen.connected_view(sync, compare, case_sensitive);
                if let Some(info) = record {
                    self.record_history(info);
                }
            }
            Err(e) => {
                let label = server_label(&remote.info.address);
                self.events_tx.log(
                    session,
                    LogKind::Error,
                    format!("Could not connect to {label}"),
                );
                self.remote = None;
                self.screen.remote_disconnected(Some(e.clone()));
            }
        }
    }

    /// Close the remote connection (in the background) and empty the pane.
    fn disconnect(&mut self) {
        let Some(remote) = self.remote.take() else {
            return;
        };
        remote.cancel.cancel();
        self.diag.forget(Side::Remote);
        self.cache.clear_server(Some(&remote.info.address));
        self.events_tx.log(
            remote.session,
            LogKind::Status,
            format!("Disconnected from {}", server_label(&remote.info.address)),
        );
        let handle = remote.handle;
        tokio::spawn(async move {
            let _ = handle.disconnect().await;
        });
        self.screen.remote_disconnected(None);
    }

    /// Add a successful quickconnect login to the history (vault unlocked
    /// only), then reload the dropdown.
    fn record_history(&mut self, info: ConnectInfo) {
        let Some(history) = self.history.clone() else {
            return;
        };
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = history.record(&info).await {
                debug!(error = %e, "quickconnect history not saved");
            }
            load_history(&history, &tx).await;
        });
    }

    /// The `[▾]` button: pick a history entry or clear the history.
    fn show_history(&mut self) {
        let Some(items) = self.screen.quickconnect_mut().history().map(<[_]>::to_vec) else {
            self.screen.flash(
                "The connection history is kept in the vault: unlock it (<Ctrl-x><u>) to see it",
            );
            return;
        };
        if items.is_empty() {
            self.screen.flash("No connection history yet");
            return;
        }
        let mut options: Vec<String> = items.iter().map(|i| i.label.clone()).collect();
        options.push("Clear history".to_owned());
        let (modal, rx) = crate::ui::dialog::choose("Connection history", options);
        self.screen.push_modal(modal);
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            if let Ok(Some(i)) = rx.await {
                let _ = tx.send(match items.get(i) {
                    Some(item) => Action::HistoryPicked(Box::new(item.request.clone())),
                    None => Action::ClearHistory,
                });
            }
        });
    }

    /// "Clear history" in the history dropdown.
    fn clear_history(&mut self) {
        let Some(history) = self.history.clone() else {
            return;
        };
        let tx = self.action_tx.clone();
        let events = self.events_tx.clone();
        let session = self.local_session;
        tokio::spawn(async move {
            match history.clear().await {
                Ok(_) => events.log(session, LogKind::Status, "Connection history cleared"),
                Err(e) => events.log(
                    session,
                    LogKind::Error,
                    format!("Could not clear the connection history: {e}"),
                ),
            }
            load_history(&history, &tx).await;
        });
    }

    /// Open the vault database (at start).
    pub(crate) fn start_vault(&mut self) {
        if let Some(vault) = &mut self.vault {
            vault.open(false);
        }
    }

    fn vault_facts(&mut self) -> VaultFacts {
        self.screen
            .vault_view_mut()
            .map(|v| v.facts())
            .unwrap_or_default()
    }

    /// The vault view asked for something.
    fn vault_request(&mut self, request: VaultRequest) {
        let Some(vault) = &mut self.vault else {
            return;
        };
        match request {
            VaultRequest::Create { password, keyring } => vault.create(password, keyring),
            VaultRequest::Unlock(password) => vault.unlock(password),
            VaultRequest::Reset(password) => vault.reset_with_keyring(password),
            VaultRequest::Retry => {
                vault.open(false);
                if let Some(view) = self.screen.vault_view_mut() {
                    view.set_busy(Some("Opening the vault…"));
                }
            }
            VaultRequest::NewVault => vault.open(true),
            VaultRequest::Skip => {
                self.screen.show_vault(false);
                self.events_tx.log(
                    self.local_session,
                    LogKind::Status,
                    "Continuing without the vault: quickconnect only, nothing is saved. \
                     Unlock with <Ctrl-x><u>.",
                );
            }
            VaultRequest::Quit => self.should_quit = true,
        }
    }

    /// A background vault call finished.
    pub(crate) fn vault_message(&mut self, msg: VaultMsg) {
        use courier_ftp_core::vault::VaultState;
        let now = Instant::now();
        let Some(vault) = &mut self.vault else {
            return;
        };
        match msg {
            VaultMsg::Opened(Ok(opened)) => {
                let crate::vault::Opened {
                    engine,
                    status,
                    keyring_available,
                    moved_aside,
                } = *opened;
                vault.opened(engine);
                let facts = VaultFacts {
                    keyring_enabled: status.keyring_enabled,
                    keyring_available,
                    sync_account: false,
                };
                let keyring_first = status.state == VaultState::Locked && status.keyring_enabled;
                match status.state {
                    VaultState::Uninitialised => vault.phase = Phase::Uninitialised,
                    VaultState::Locked => vault.phase = Phase::Locked,
                    VaultState::Unlocked => vault.on_unlocked(),
                }
                if keyring_first {
                    vault.unlock_with_keyring();
                }
                if status.state == VaultState::Unlocked {
                    self.vault_unlocked(None);
                    return;
                }
                let Some(view) = self.screen.vault_view_mut() else {
                    return;
                };
                if status.state == VaultState::Uninitialised {
                    view.show_create(facts);
                } else {
                    view.show_unlock(facts, status.backoff.failures, status.retry_after, now);
                }
                view.set_note(
                    moved_aside.map(|p| format!("The old database was moved to {}.", p.display())),
                );
                if keyring_first {
                    view.set_busy(Some("Unlocking with the system keyring…"));
                }
            }
            VaultMsg::Opened(Err(e)) => {
                vault.phase = Phase::Unavailable;
                // The error may name the database path: details at debug (T91 §4).
                tracing::warn!("vault unavailable");
                tracing::debug!(error = %e, "vault unavailable");
                if let Some(view) = self.screen.vault_view_mut() {
                    view.show_unavailable(e.to_string());
                }
            }
            VaultMsg::Created(result) => match result {
                Ok(report) => {
                    vault.on_unlocked();
                    if let Some(reason) = report.keyring_error {
                        self.events_tx.log(
                            self.local_session,
                            LogKind::Error,
                            format!("Keyring unlock could not be enabled: {reason}"),
                        );
                    }
                    self.vault_unlocked(Some("Vault created"));
                }
                Err(e) => {
                    if let Some(view) = self.screen.vault_view_mut() {
                        view.set_error(Some(e.to_string()));
                    }
                }
            },
            VaultMsg::Unlocked { keyring, result } => match result {
                Ok(report) => {
                    vault.on_unlocked();
                    if report.undecryptable > 0 {
                        self.events_tx.log(
                            self.local_session,
                            LogKind::Error,
                            format!(
                                "{} vault items could not be decrypted and were skipped",
                                report.undecryptable
                            ),
                        );
                    }
                    self.vault_unlocked(Some(if keyring {
                        "Vault unlocked with the system keyring"
                    } else {
                        "Vault unlocked"
                    }));
                }
                Err(e) if keyring => {
                    tracing::info!(error = %e, "keyring unlock failed; asking for the password");
                    if let Some(view) = self.screen.vault_view_mut() {
                        view.set_busy(None);
                        view.set_note(Some(format!(
                            "Keyring unavailable ({e}); enter the master password."
                        )));
                    }
                }
                Err(e) => {
                    if let Some(view) = self.screen.vault_view_mut() {
                        view.unlock_failed(&e, now);
                    }
                }
            },
            VaultMsg::Reset(result) => match result {
                Ok(_) => {
                    vault.on_unlocked();
                    self.vault_unlocked(Some("New master password set; vault unlocked"));
                }
                Err(e) => {
                    if let Some(view) = self.screen.vault_view_mut() {
                        view.set_error(Some(e.to_string()));
                    }
                }
            },
        }
    }

    /// The vault is unlocked: hide the view, update the status bar.
    fn vault_unlocked(&mut self, message: Option<&str>) {
        if let Some(engine) = self.vault.as_ref().and_then(Vault::engine) {
            let history = History::new(Arc::new(engine.clone()), Arc::new(engine.store().clone()));
            let tx = self.action_tx.clone();
            let loader = history.clone();
            tokio::spawn(async move { load_history(&loader, &tx).await });
            self.history = Some(history);
        }
        self.screen.show_vault(false);
        self.screen.set_vault_locked(false);
        if let Some(view) = self.screen.vault_view_mut() {
            view.set_busy(None);
            view.set_note(None);
        }
        if let Some(message) = message {
            self.events_tx
                .log(self.local_session, LogKind::Status, message);
            self.screen.flash(message);
        }
    }

    /// Lock the vault (`<Ctrl-x><v>` or auto-lock): the unlock view covers
    /// the panes; with `vault.lock_disconnects` the connection closes too.
    fn lock_vault(&mut self, reason: Option<courier_ftp_core::vault::LockReason>) {
        use courier_ftp_core::vault::LockReason;
        let Some(vault) = &mut self.vault else {
            return;
        };
        vault.lock();
        self.history = None;
        self.screen.quickconnect_mut().set_history(None);
        let facts = self.vault_facts();
        let now = Instant::now();
        let note = reason.map(|r| match r {
            LockReason::Idle => format!(
                "Locked after {} minutes without input.",
                self.settings.vault.auto_lock_minutes
            ),
            LockReason::Suspend => "Locked because the system was suspended.".to_owned(),
        });
        if let Some(view) = self.screen.vault_view_mut() {
            view.show_unlock(facts, 0, None, now);
            view.set_note(note);
        }
        self.screen.show_vault(true);
        self.screen.set_vault_locked(true);
        self.events_tx
            .log(self.local_session, LogKind::Status, "Vault locked");
        self.screen.flash("Vault locked");
        if self.settings.vault.lock_disconnects && self.remote.is_some() {
            self.disconnect();
        }
    }

    /// Site Manager, bookmarks and history need the vault: offer to unlock.
    fn offer_unlock(&mut self, what: &str) {
        let (modal, rx) = crate::ui::dialog::confirm(
            "Vault locked",
            &format!("The vault is locked. Unlock it to use {what}?"),
            true,
        );
        self.screen.push_modal(modal);
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            if let Ok(true) = rx.await {
                let _ = tx.send(Action::UnlockVault);
            }
        });
    }

    fn render(&mut self, tui: &mut Tui) -> color_eyre::Result<()> {
        tui.draw(|frame| self.screen.draw(frame))?;
        Ok(())
    }
}

/// Read the history and hand it to the quickconnect bar.
async fn load_history(history: &History, tx: &mpsc::UnboundedSender<Action>) {
    match history.list().await {
        Ok(entries) => {
            let items = entries.iter().map(crate::ui::HistoryItem::new).collect();
            let _ = tx.send(Action::HistoryLoaded(items));
        }
        Err(e) => debug!(error = %e, "quickconnect history not loaded"),
    }
}

/// The home directory's listing.
async fn first_listing(
    handle: &SessionHandle,
    cancel: &CancellationToken,
) -> courier_ftp_core::Result<Listing> {
    let home = handle.home_dir(cancel).await?;
    handle.list(&home, cancel).await
}

#[cfg(test)]
mod log_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod vault_tests;
