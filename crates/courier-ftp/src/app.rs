use courier_ftp_core::{
    backend::{Backend, BackendFactory, ConnectInfo, Listing, SessionHandle},
    cache::ListingCache,
    events::{self, EventReceiver, EventSender, LogKind, SessionId},
    local::LocalBackend,
    model::{RemotePath, ServerAddress},
    settings::Settings,
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
use tracing::{debug, info};

use crate::{
    action::{Action, ConnectRequest, Connected},
    backends::Backends,
    config::Config,
    keymap::{Feed, KeyBindings, Sequencer},
    tui::{Event, Tui},
    ui::{KeyOutcome, MainScreen, Side, Theme},
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
        let backends = Arc::new(Backends::new(&config.settings));
        Ok(Self::with_backends(config, backends, tick_rate, frame_rate))
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
        events_tx.set_raw_listing(config.settings.logging.show_raw_listing);
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
        Self {
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
        }
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
        self.list(Side::Local, None, false);

        loop {
            tokio::select! {
                event = tui.next_event() => match event {
                    Some(event) => self.handle_event(event)?,
                    None => self.should_quit = true,
                },
                Some(action) = self.action_rx.recv() => {
                    self.handle_action(&mut tui, action)?;
                }
                Some(event) = self.events_rx.recv() => self.screen.handle_core(event),
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
        if self.screen.handle_key(key) == KeyOutcome::Consumed {
            self.sequencer.reset();
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
                    info!("Got action: {action:?}");
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
            Action::RemoteListingLoaded { session, result } => {
                if self.current_session() == Some(*session) {
                    self.action_tx.send(Action::ListingLoaded {
                        side: Side::Remote,
                        result: result.clone(),
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
            Action::Reconnect => match self.last_connect.clone() {
                Some(request) => self.start_connect(request),
                None => self.screen.flash("No server to reconnect to"),
            },
            Action::ListDir { side, dir, force } => {
                self.list(*side, Some(dir.clone()), *force);
            }
            Action::CopyToClipboard(text) => {
                if let Err(e) = crate::clipboard::copy(text) {
                    tracing::warn!("clipboard: {e}");
                }
            }
            Action::Error(err) => {
                tracing::error!(?err);
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
    /// the listing cache unless `force`; the pane shows a spinner until
    /// [`Action::ListingLoaded`] arrives.
    fn list(&mut self, side: Side, dir: Option<RemotePath>, force: bool) {
        if side == Side::Remote {
            if let Some(dir) = dir {
                self.list_remote(dir, force);
            }
            return;
        }
        self.screen.pane_mut(side).busy = true;
        let tx = self.action_tx.clone();
        let cache = self.cache.clone();
        tokio::spawn(async move {
            let mut backend = LocalBackend::new();
            let cancel = CancellationToken::new();
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
            let _ = tx.send(Action::ListingLoaded { side, result });
        });
    }

    fn current_session(&self) -> Option<SessionId> {
        self.remote.as_ref().map(|r| r.session)
    }

    /// List `dir` on the remote connection, through the cache unless
    /// `force`.
    fn list_remote(&mut self, dir: RemotePath, force: bool) {
        let Some(remote) = self.remote.as_ref().filter(|r| r.connected) else {
            self.screen.pane_mut(Side::Remote).busy = false;
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
            let _ = tx.send(Action::RemoteListingLoaded { session, result });
        });
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
                self.screen.remote_connected(connected);
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

    fn render(&mut self, tui: &mut Tui) -> color_eyre::Result<()> {
        tui.draw(|frame| self.screen.draw(frame))?;
        Ok(())
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
mod tests;
