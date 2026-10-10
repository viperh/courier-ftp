//! The application: event loop, key routing, focus, modals, the core event bridge,
//! layout toggles and rendering (T50).

pub(crate) mod status;
pub(crate) mod vault;

use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use courier_ftp_core::{
    events::{self, CoreEvent, EventReceiver, EventSender, SessionId, SessionPurpose},
    settings::{InterfaceSettings, Layout, Settings, SettingsStore},
};
use ratatui::{Frame, Terminal, backend::Backend, layout::Size};
use serde::{Deserialize, Serialize};
use strum::EnumIter;
use tokio::{
    sync::mpsc,
    time::{Instant, sleep_until},
};
use tracing::{debug, trace, warn};

use crate::{
    action::Action,
    components::{
        DrawCx, KeyOutcome,
        dialog::{ConfirmOpts, confirm, problems},
        help::HelpOverlay,
        main_screen::{
            MainScreen,
            layout::{Region, ScreenLayout},
        },
        message_log::MessageLogPane,
        modal::ModalStack,
        prompts::{
            PendingCredentials, PromptAnswered, PromptEnv, PromptOrigin, PromptQueue, PromptTick,
            SecretCache, UiFocusState, answer_from_cache, queue::WITHDRAWN_MESSAGE,
        },
        status_bar::{self, MessageLevel, pretty_keys},
        which_key,
    },
    config::{Config, check_settings_not_shadowed},
    keymap::{
        chord::{KeyChord, display_sequence},
        resolver::{KeyResolver, Resolution},
    },
    runtime::{Runner, TaskId, TaskOwner},
    tui::{Event, Tui},
    ui::{
        clipboard::{Clipboard, ClipboardHandle},
        symbols::{Symbols, TermEnv},
        theme::Theme,
    },
};

mod panes;

/// Key tables. Keybindings in `config/config.json` (this crate) are keyed by these
/// names, so adding a variant means adding a section there too.
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    EnumIter,
)]
pub(crate) enum Mode {
    /// Global table; consulted last in every non-modal chain.
    #[default]
    Normal,
    /// A file list pane has focus (T53).
    FileList,
    /// A directory tree has focus (T54).
    Tree,
    /// Message log (T55).
    Log,
    /// Queue pane (T56).
    Queue,
    /// Site Manager tree (T59); full-screen modal.
    SiteManager,
    /// Typing a pane quick filter (T53).
    Filter,
    /// A single-line text field outside dialogs (quickconnect T58, `:` line T62, log
    /// search T55).
    Input,
    /// A modal is open (T52); the only table consulted then.
    Dialog,
}

impl Mode {
    /// Tables consulted for a key, highest priority first: `Dialog` → `[Dialog]`;
    /// `SiteManager` → `[SiteManager]`; `Normal` → `[Normal]`; any other mode m →
    /// `[m, Normal]`.
    pub(crate) fn chain(self) -> &'static [Mode] {
        match self {
            Mode::Normal => &[Mode::Normal],
            Mode::Dialog => &[Mode::Dialog],
            Mode::SiteManager => &[Mode::SiteManager],
            Mode::FileList => &[Mode::FileList, Mode::Normal],
            Mode::Tree => &[Mode::Tree, Mode::Normal],
            Mode::Log => &[Mode::Log, Mode::Normal],
            Mode::Queue => &[Mode::Queue, Mode::Normal],
            Mode::Filter => &[Mode::Filter, Mode::Normal],
            Mode::Input => &[Mode::Input, Mode::Normal],
        }
    }
}

/// Delay between the last layout change and saving the settings.
const SAVE_DEBOUNCE: Duration = Duration::from_secs(1);
/// A region shows its spinner after being busy this long.
const SPINNER_DELAY: Duration = Duration::from_millis(150);
/// Actions dispatched per loop iteration before input is read again.
const DRAIN_LIMIT: usize = 256;

/// The application.
pub(crate) struct App {
    config: Arc<Config>,
    settings: SettingsStore,
    tick_rate: f64,
    frame_rate: f64,
    resolver: KeyResolver,
    pub(crate) runner: Runner,
    events: EventReceiver,
    /// The sending half of the core bus, handed to backends and the engine (T03, T41).
    events_tx: EventSender,
    /// Core prompts and the visible prompt dialog (T69).
    pub(crate) prompts: PromptQueue,
    /// "Remember for this session" secrets (T69).
    pub(crate) secret_cache: SecretCache,
    /// Typed secrets waiting for `CredentialAccepted` (T69).
    pub(crate) pending_credentials: PendingCredentials,
    /// What each open session is for (prompt origin, T69).
    session_purposes: HashMap<SessionId, SessionPurpose>,
    /// The vault is locked (T60 sets it through [`Self::set_vault_locked`]).
    vault_locked: bool,
    pub(crate) main: MainScreen,
    pub(crate) modals: ModalStack,
    term_env: TermEnv,
    /// The clipboard shared with components (T55 log, T62 Copy URL, T71 CopyLog).
    #[cfg_attr(not(test), expect(dead_code, reason = "read by T62 and T71"))]
    clipboard: ClipboardHandle,
    theme: Theme,
    symbols: Symbols,
    action_tx: mpsc::UnboundedSender<Action>,
    action_rx: mpsc::UnboundedReceiver<Action>,
    should_quit: bool,
    should_suspend: bool,
    needs_clear: bool,
    dirty: bool,
    render_requested: bool,
    started: Instant,
    last_frame: Option<u128>,
    save_task: Option<TaskId>,
    /// Bumped by every scheduled save; an older save that reaches the disk later skips
    /// its write, so the newest settings always win.
    save_generation: Arc<std::sync::atomic::AtomicU64>,
    pub(crate) draw_count: u64,
    problems: Vec<String>,
    first_frame_done: bool,
    /// Listing cache, local backend context and listing tasks of the panes (T53).
    pub(crate) panes: crate::components::file_list::service::PaneService,
    /// What the status bar shows besides settings and keys (T57).
    pub(crate) status_sources: status::StatusSources,
    /// Vault state: lock, vault screen, mode (T60). No key material.
    pub(crate) vault: vault::VaultUi,
    /// The vault service (T60); `None` with `--no-vault` and in most tests.
    vault_service: Option<crate::services::vault::VaultService>,
    /// Auto-lock, unlock countdown and quit-disarm timers (T60).
    vault_timers: crate::timers::Timers<vault::VaultTimer>,
    /// Resume-from-sleep detection (T30/T60).
    suspend: courier_ftp_core::vault::SuspendDetector,
    /// Sessions a lock asked to close (`vault.lock_disconnects`); T61 closes them.
    #[cfg_attr(not(test), allow(dead_code, reason = "read by connection tabs (T61)"))]
    pub(crate) disconnect_requests: Vec<SessionId>,
    /// Every vault effect sent (tests).
    #[cfg(test)]
    pub(crate) vault_effects: Vec<vault::VaultEffect>,
    /// Launch intents run (tests).
    #[cfg(test)]
    pub(crate) launched: Vec<vault::LaunchIntent>,
    /// A simulated wall-clock jump (tests: resume from sleep).
    #[cfg(test)]
    pub(crate) wall_jump: Duration,
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App")
            .field("main", &self.main)
            .field("modals", &self.modals)
            .finish_non_exhaustive()
    }
}

impl App {
    /// The app for `config`, in the terminal environment `term_env`.
    pub(crate) fn new(config: Config, tick_rate: f64, frame_rate: f64, term_env: TermEnv) -> Self {
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let config = Arc::new(config);
        let settings =
            SettingsStore::new(config.settings.clone(), config.config.config_dir.clone());
        let (events_tx, events) = events::channel(config.settings.logging.level);
        let (resolver, keymap_problems) = KeyResolver::from_config(&config);
        let mut problems: Vec<String> = config.config_problems.clone();
        problems.extend(keymap_problems.iter().map(ToString::to_string));
        problems.extend(
            config
                .settings_warnings
                .iter()
                .map(|w| format!("settings.{}: replaced by the default", w.path)),
        );
        let interface = config.settings.interface.clone();
        let (theme, theme_warnings) =
            Theme::load(interface.theme, &config.styles, term_env.no_color);
        problems.extend(theme_warnings);
        for p in &problems {
            warn!("configuration problem: {p}");
        }
        let symbols = Symbols::resolve(interface.unicode_symbols, &term_env);
        let clipboard = Clipboard::from_env(&term_env).into_handle();
        let log = MessageLogPane::new(Arc::clone(&clipboard), &config.settings.logging);
        let pane_service = panes::pane_service(&settings, &events_tx);
        let action_tx_timers = action_tx.clone();
        let mut app = Self {
            runner: Runner::new(action_tx.clone()),
            main: MainScreen::new(&interface, Box::new(log)),
            clipboard,
            config,
            settings,
            tick_rate,
            frame_rate,
            resolver,
            events,
            events_tx,
            prompts: PromptQueue::default(),
            secret_cache: SecretCache::default(),
            pending_credentials: PendingCredentials::default(),
            session_purposes: HashMap::new(),
            vault_locked: false,
            modals: ModalStack::new(action_tx.clone()),
            term_env,
            theme,
            symbols,
            action_tx,
            action_rx,
            should_quit: false,
            should_suspend: false,
            needs_clear: false,
            dirty: true,
            render_requested: false,
            started: Instant::now(),
            last_frame: None,
            save_task: None,
            save_generation: Arc::default(),
            draw_count: 0,
            problems,
            first_frame_done: false,
            panes: pane_service,
            status_sources: status::StatusSources::default(),
            vault: vault::VaultUi::default(),
            vault_service: None,
            vault_timers: crate::timers::Timers::new(action_tx_timers),
            suspend: courier_ftp_core::vault::SuspendDetector::new(),
            disconnect_requests: Vec::new(),
            #[cfg(test)]
            vault_effects: Vec::new(),
            #[cfg(test)]
            launched: Vec::new(),
            #[cfg(test)]
            wall_jump: Duration::ZERO,
        };
        app.prompts.set_env(PromptEnv::from_settings(&interface));
        app.install_panes();
        app
    }

    /// The core bus sender (backends, transfer engine).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "handed to backends (T03, T06, T41)")
    )]
    pub(crate) fn events_sender(&self) -> &EventSender {
        &self.events_tx
    }

    /// The action channel (dialog widgets that wake the app, T52).
    #[cfg_attr(not(test), allow(dead_code, reason = "used by tests and T53–T71"))]
    pub(crate) fn action_sender(&self) -> mpsc::UnboundedSender<Action> {
        self.action_tx.clone()
    }

    /// The shared clipboard.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by T62 and T71"))]
    pub(crate) fn clipboard(&self) -> &ClipboardHandle {
        &self.clipboard
    }

    /// Registers handlers and initialises every component.
    pub(crate) fn init_components(&mut self, size: Size) -> color_eyre::Result<()> {
        self.main.set_size(size);
        let tx = self.action_tx.clone();
        let config = Arc::clone(&self.config);
        for c in self.main.components_mut() {
            c.register_action_handler(tx.clone())?;
            c.register_config_handler(Arc::clone(&config))?;
            c.init(size)?;
        }
        Ok(())
    }

    /// Runs until the user quits. No task outlives this.
    pub(crate) async fn run(&mut self) -> color_eyre::Result<()> {
        let mut tui = Tui::new()?
            .tick_rate(self.tick_rate)
            .frame_rate(self.frame_rate)
            .paste(true);
        tui.enter()?;
        let size = tui.size()?;
        self.init_components(size)?;
        self.start_panes();
        let hook = crate::test_hooks::from_env();
        if let Some(crate::test_hooks::TestHook::ExitAfter(after)) = hook {
            let tx = self.action_tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(after).await;
                let _ = tx.send(Action::QuitConfirmed);
            });
        }

        loop {
            let deadline = self.key_deadline();
            tokio::select! {
                biased;
                ev = tui.next_event() => match ev {
                    Some(ev) => self.handle_terminal_event(ev)?,
                    None => self.should_quit = true,
                },
                Some(ev) = self.events.recv() => self.handle_core_event(ev)?,
                () = sleep_until(deadline.unwrap_or_else(Instant::now)), if deadline.is_some() => {
                    self.on_key_timeout(Instant::now());
                }
                Some(action) = self.action_rx.recv() => self.dispatch(action)?,
            }
            self.drain_actions(DRAIN_LIMIT)?;
            if self.needs_clear {
                self.needs_clear = false;
                tui.terminal.clear()?;
                self.dirty = true;
            }
            if self.render_requested {
                self.render_requested = false;
                self.render_if_needed(&mut tui.terminal)?;
                if hook == Some(crate::test_hooks::TestHook::ExitAfterPanes)
                    && self.draw_count > 0
                    && !self.vault_hides_panes()
                {
                    self.should_quit = true;
                }
            }
            if self.should_suspend {
                self.should_suspend = false;
                tui.suspend()?;
                self.queue(Action::Resume);
                self.queue(Action::ClearScreen);
                tui.enter()?;
            }
            if self.should_quit {
                self.finish().await;
                tui.stop()?;
                break;
            }
        }
        tui.exit()?;
        Ok(())
    }

    /// Saves pending settings and stops every task.
    pub(crate) async fn finish(&mut self) {
        if self.save_task.take().is_some() {
            // Newer than any save still in flight: those skip their write.
            self.save_generation
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let res = Self::save_now(
                self.settings.current(),
                self.settings.config_dir().to_path_buf(),
                None,
            )
            .await;
            if let Err(e) = res {
                debug!(reason = %e, "settings save failed");
                warn!("could not save settings on exit");
            }
        }
        self.runner.shutdown().await;
    }

    /// The user asked to quit and nothing blocks it.
    #[cfg_attr(not(test), expect(dead_code, reason = "read by the harness"))]
    pub(crate) fn should_quit(&self) -> bool {
        self.should_quit
    }

    fn queue(&self, action: Action) {
        // The receiver lives in `self`, so this cannot fail.
        let _ = self.action_tx.send(action);
    }

    /// Dispatches up to `limit` queued actions; returns how many.
    pub(crate) fn drain_actions(&mut self, limit: usize) -> color_eyre::Result<usize> {
        let mut n = 0;
        while n < limit {
            let Ok(action) = self.action_rx.try_recv() else {
                break;
            };
            self.dispatch(action)?;
            n += 1;
        }
        Ok(n)
    }

    /// Handles the pending core events without waiting; returns how many.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by the harness"))]
    pub(crate) fn drain_core_events(&mut self) -> color_eyre::Result<usize> {
        let mut n = 0;
        while let Some(ev) = self.events.try_recv() {
            self.handle_core_event(ev)?;
            n += 1;
        }
        Ok(n)
    }

    /// A terminal event.
    pub(crate) fn handle_terminal_event(&mut self, ev: Event) -> color_eyre::Result<()> {
        match ev {
            Event::Key(k) => self.handle_key(KeyChord::from_key_event(k))?,
            Event::Paste(text) => self.handle_paste(&text)?,
            Event::Resize(w, h) => self.dispatch(Action::Resize(w, h))?,
            Event::Tick => self.dispatch(Action::Tick)?,
            Event::Render => self.dispatch(Action::Render)?,
            Event::Quit => self.dispatch(Action::Quit)?,
            Event::Init
            | Event::Error
            | Event::Closed
            | Event::FocusGained
            | Event::FocusLost
            | Event::Mouse(_) => {}
        }
        Ok(())
    }

    /// The key table in effect.
    pub(crate) fn mode(&mut self) -> Mode {
        if self.prompts.is_visible() {
            return Mode::Dialog;
        }
        self.base_mode()
    }

    /// The key table in effect without the prompt dialog.
    fn base_mode(&mut self) -> Mode {
        if let Some(top) = self.modals.top() {
            return top.key_mode();
        }
        self.main
            .focused_mut()
            .map_or(Mode::Normal, |c| c.key_mode())
    }

    /// When the key resolver needs a wake-up (sequence timeout or which-key popup).
    pub(crate) fn key_deadline(&self) -> Option<Instant> {
        self.resolver.deadline()
    }

    /// The key resolver's deadline passed.
    pub(crate) fn on_key_timeout(&mut self, now: Instant) {
        if self.resolver.on_timeout(now) {
            self.dirty = true;
        }
    }

    /// The keys of a pending sequence (`"ctrl-x"`).
    #[cfg_attr(not(test), expect(dead_code, reason = "read by the harness"))]
    pub(crate) fn pending_keys(&self) -> Option<String> {
        self.resolver.pending_display()
    }

    /// Routes one key (first match wins): a pending sequence the key continues (or `esc`
    /// cancels), the top modal, the focused component's raw key handler, then the
    /// keymap.
    pub(crate) fn handle_key(&mut self, key: KeyChord) -> color_eyre::Result<()> {
        self.dirty = true;
        let now = Instant::now();
        self.main.status_bar_mut().on_key(now);
        if self.vault_on_input(&vault::InputEvent::Key(key)) {
            return Ok(());
        }
        if self.prompts.is_visible() {
            // The prompt dialog takes every key (T69).
            self.resolver.clear();
            if let Some(answered) = self.prompts.handle_key(key, now) {
                self.on_prompt_answered(answered);
            }
            if let Some(n) = self.prompts.take_notice() {
                self.status(n);
            }
            self.run_prompt_tick();
            return Ok(());
        }
        self.prompts.note_key(now);
        self.route_key(key, now)?;
        self.run_prompt_tick();
        Ok(())
    }

    /// [`Self::handle_key`] without the prompt dialog.
    fn route_key(&mut self, key: KeyChord, now: Instant) -> color_eyre::Result<()> {
        let mode = self.mode();
        if self.resolver.is_pending() {
            if self.resolver.takes(key, mode, now) {
                let r = self.resolver.resolve(key, mode, now);
                return self.apply_resolution(r);
            }
            // The key does not continue the sequence: drop it and route the key alone.
            self.resolver.clear();
        }
        if let Some(top) = self.modals.top_mut() {
            match top.handle_key(key)? {
                KeyOutcome::Consumed(a) => {
                    if let Some(a) = a {
                        self.queue(a);
                    }
                    self.modals.close_done();
                }
                KeyOutcome::Ignored => {
                    let r = self.resolver.resolve(key, mode, now);
                    self.apply_resolution(r)?;
                }
            }
            return Ok(());
        }
        let Some(focused) = self.main.focused_mut() else {
            return Ok(());
        };
        match focused.handle_key(key)? {
            KeyOutcome::Consumed(a) => {
                if let Some(a) = a {
                    self.queue(a);
                }
            }
            KeyOutcome::Ignored => {
                let r = self.resolver.resolve(key, mode, now);
                self.apply_resolution(r)?;
            }
        }
        Ok(())
    }

    /// Runs a resolved key: to the top modal while one is open, else to [`Self::dispatch`].
    fn apply_resolution(&mut self, r: Resolution) -> color_eyre::Result<()> {
        let Resolution::Action(a) = r else {
            return Ok(());
        };
        trace!(action = %a, "key action");
        if let Some(top) = self.modals.top_mut() {
            if let Some(out) = top.update(&a)? {
                self.queue(out);
            }
            self.modals.close_done();
            return Ok(());
        }
        self.dispatch(a)
    }

    /// Bracketed paste: to the top modal, else to the focused component.
    pub(crate) fn handle_paste(&mut self, text: &str) -> color_eyre::Result<()> {
        self.dirty = true;
        if self.vault_on_input(&vault::InputEvent::Paste(text)) {
            return Ok(());
        }
        if self.prompts.is_visible() {
            self.prompts.handle_paste(text);
            if let Some(n) = self.prompts.take_notice() {
                self.status(n);
            }
            return Ok(());
        }
        let outcome = if let Some(top) = self.modals.top_mut() {
            let o = top.handle_paste(text)?;
            self.modals.close_done();
            o
        } else if let Some(c) = self.main.focused_mut() {
            c.handle_paste(text)?
        } else {
            KeyOutcome::Ignored
        };
        if let KeyOutcome::Consumed(Some(a)) = outcome {
            self.queue(a);
        }
        Ok(())
    }

    /// A core event: prompts go to the prompt queue (answered from the session cache
    /// when possible), everything else to the components.
    pub(crate) fn handle_core_event(&mut self, ev: CoreEvent) -> color_eyre::Result<()> {
        self.dirty = true;
        match &ev {
            CoreEvent::SessionOpened {
                session, purpose, ..
            } => {
                self.session_purposes.insert(*session, *purpose);
            }
            CoreEvent::SessionClosed { session } => {
                self.session_purposes.remove(session);
                self.pending_credentials.on_session_ended(*session);
            }
            CoreEvent::Disconnected { session, .. } => {
                self.pending_credentials.on_session_ended(*session);
            }
            CoreEvent::CredentialAccepted { prompt_id, .. } => {
                if let Some(save) = self
                    .pending_credentials
                    .on_accepted(*prompt_id, &mut self.secret_cache)
                {
                    self.queue(Action::SaveCredential(save));
                }
            }
            _ => {}
        }
        if let CoreEvent::Prompt(req) = ev {
            if let Some(req) = answer_from_cache(req, &self.secret_cache) {
                let origin = self.prompt_origin(req.session);
                // Opened by the next tick (rule 4), so prompts arriving together are
                // shown foreground first.
                self.prompts.push(req, origin, Instant::now());
            }
            return Ok(());
        }
        for a in self.main.on_core_event(&ev)? {
            self.queue(a);
        }
        Ok(())
    }

    /// Rule 1: prompts of a browsing session are foreground (there is one tab until
    /// T61, so every browsing session is the active tab's); sessions opened for
    /// transfers, searches or anything else are background. A session the app has not
    /// seen open counts as foreground.
    fn prompt_origin(&self, session: SessionId) -> PromptOrigin {
        match self.session_purposes.get(&session) {
            None | Some(SessionPurpose::Browse) => PromptOrigin::Foreground,
            Some(_) => PromptOrigin::Background,
        }
    }

    /// Applies the prompt queue's auto-open rules and updates the badge.
    pub(crate) fn run_prompt_tick(&mut self) {
        let now = Instant::now();
        let ui = UiFocusState {
            mode: self.base_mode(),
            other_dialog_open: !self.modals.is_empty(),
            vault_locked: self.vault_locked,
        };
        for t in self.prompts.tick(now, &ui) {
            if let PromptTick::Withdrawn(_) = t {
                self.notify(MessageLevel::Info, WITHDRAWN_MESSAGE);
            }
            self.dirty = true;
        }
        let badge = self.prompts.badge(self.symbols.unicode);
        if badge != self.status_sources.prompts_badge {
            self.status_sources.prompts_badge = badge;
            self.dirty = true;
        }
    }

    fn on_prompt_answered(&mut self, a: PromptAnswered) {
        self.dirty = true;
        debug!(
            prompt_id = a.id.get(),
            kind = a.kind,
            session = a.session.get(),
            delivered = a.delivered,
            "prompt answered"
        );
        if !a.delivered {
            self.notify(MessageLevel::Info, WITHDRAWN_MESSAGE);
            return;
        }
        if let Some(p) = a.pending {
            self.pending_credentials.insert(a.id, p);
        }
    }

    /// The vault was locked or unlocked (T30/T60): locking hides the visible prompt
    /// (it opens again after unlocking) and forgets the session's secrets.
    pub(crate) fn set_vault_locked(&mut self, locked: bool) {
        self.vault_locked = locked;
        self.prompts.set_suspended(locked);
        if locked {
            self.secret_cache.clear();
        }
        self.run_prompt_tick();
        self.dirty = true;
    }

    fn status(&mut self, text: impl Into<String>) {
        self.main.set_status(text.into(), false, Instant::now());
        self.dirty = true;
    }

    /// A key hint for `action` in the Normal table (`Ctrl-l`), or `fallback`.
    fn key_hint(&self, action: &str, fallback: &str) -> String {
        let keys = self
            .resolver
            .keymap()
            .bindings_for(&[Mode::Normal])
            .into_iter()
            .find(|r| r.action.to_string() == action)
            .map_or_else(|| fallback.to_owned(), |r| display_sequence(&r.keys));
        pretty_keys(&keys)
    }

    /// Focuses `region`, or explains why it is hidden. Hidden log, queue and
    /// quickconnect can be focused in compact mode (focusing shows them there).
    fn focus_or_explain(&mut self, region: Region) {
        let layout = self.main.layout();
        if matches!(layout, ScreenLayout::TooSmall { .. }) || self.main.is_focusable(region) {
            self.main.set_focus(region);
            self.dirty = true;
            return;
        }
        let interface = self.settings.current().interface.clone();
        if region.is_tree() {
            if layout.is_compact() && interface.show_tree {
                // Trees are not drawn in compact mode: show that side's list.
                let list = if region.is_local() {
                    Region::LocalList
                } else {
                    Region::RemoteList
                };
                self.main.set_focus(list);
                self.dirty = true;
            } else {
                let key = self.key_hint("ToggleTree", "ctrl-e");
                self.status(format!("Directory trees are hidden ({key} shows them)"));
            }
            return;
        }
        let (action, fallback) = match region {
            Region::Log => ("ToggleLog", "ctrl-l"),
            Region::Queue => ("ToggleQueuePane", "ctrl-x j"),
            Region::Quickconnect => ("ToggleQuickconnect", "ctrl-x q"),
            _ => return,
        };
        let key = self.key_hint(action, fallback);
        self.status(format!("{} is hidden ({key} shows it)", region.name()));
    }

    fn change_interface(&mut self, edit: impl FnOnce(&mut InterfaceSettings)) {
        self.settings.set_transient(|s| edit(&mut s.interface));
        let current = self.settings.current();
        self.main.set_options(&current.interface);
        self.symbols = Symbols::resolve(current.interface.unicode_symbols, &self.term_env);
        self.prompts
            .set_env(PromptEnv::from_settings(&current.interface));
        self.dirty = true;
        self.schedule_save();
        self.notify_panes_settings();
    }

    /// Writes `settings`. With `generation`, skips the write when a newer save has been
    /// scheduled since. Writes are serialized, so they cannot finish out of order.
    async fn save_now(
        settings: Arc<Settings>,
        dir: PathBuf,
        generation: Option<(Arc<std::sync::atomic::AtomicU64>, u64)>,
    ) -> Result<(), String> {
        static SAVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        crate::runtime::spawn_blocking(move || {
            let _serial = SAVE_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((current, mine)) = generation
                && current.load(std::sync::atomic::Ordering::SeqCst) != mine
            {
                return Ok(());
            }
            check_settings_not_shadowed(&dir).map_err(|e| e.to_string())?;
            settings.save_user(&dir).map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())?
    }

    /// Whether a debounced settings save is still waiting or writing (tests).
    #[cfg(test)]
    pub(crate) fn save_pending(&self) -> bool {
        self.save_task.is_some()
    }

    /// Saves the settings 1 s after the last change (each change restarts the wait).
    fn schedule_save(&mut self) {
        if let Some(id) = self.save_task.take() {
            self.runner.cancel(id);
        }
        let settings = Arc::clone(&self.settings.current());
        let dir = self.settings.config_dir().to_path_buf();
        let mine = self
            .save_generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let generation = Some((Arc::clone(&self.save_generation), mine));
        let id = self.runner.spawn(TaskOwner::App, move |token| async move {
            tokio::select! {
                // Superseded by a newer change (or shutdown, which saves itself).
                () = token.cancelled() => Action::SettingsSaved(Ok(())),
                () = tokio::time::sleep(SAVE_DEBOUNCE) => {
                    Action::SettingsSaved(Self::save_now(settings, dir, generation).await)
                }
            }
        });
        self.save_task = Some(id);
    }

    fn other_side(&self) -> Region {
        let f = self.main.focus();
        if f.is_local() {
            Region::RemoteList
        } else if f.is_remote() {
            Region::LocalList
        } else {
            self.main.last_list()
        }
    }

    /// Handles one action.
    pub(crate) fn dispatch(&mut self, action: Action) -> color_eyre::Result<()> {
        if action.is_bindable() {
            trace!(action = %action, "dispatch");
        }
        match action {
            Action::Tick => {
                if self
                    .main
                    .status_bar_mut()
                    .update(&Action::Tick, Instant::now())
                {
                    self.dirty = true;
                }
                let mut out = Vec::new();
                for c in self.main.components_mut() {
                    out.extend(c.update(&Action::Tick)?);
                }
                if !self.modals.is_empty() {
                    // Dialog timers: progress, withdrawn prompts, spinners.
                    out.extend(self.modals.poll_all(Instant::now()));
                    self.dirty = true;
                }
                self.pending_credentials.expire(Instant::now());
                self.vault_on_tick();
                self.run_prompt_tick();
                for a in out {
                    self.dirty = true;
                    self.queue(a);
                }
            }
            Action::Wake => {
                if let Some(c) = self.main.focused_mut() {
                    c.update(&Action::Wake)?;
                }
                for a in self.modals.poll_all(Instant::now()) {
                    self.queue(a);
                }
                self.dirty = true;
            }
            Action::Render => self.render_requested = true,
            Action::Resize(w, h) => {
                self.main.set_size(Size::new(w, h));
                self.dirty = true;
            }
            Action::Resume => self.dirty = true,
            Action::ClearScreen | Action::Redraw => {
                self.needs_clear = true;
                self.dirty = true;
            }
            Action::Error(e) => {
                debug!(error = %e, "component error");
                warn!("component error (details at debug level)");
                self.main.set_status(e, true, Instant::now());
                self.dirty = true;
            }
            Action::StatusMessage(m) => self.status(m),
            Action::Vault(ev) => self.on_vault(ev),
            Action::VaultTimer(kind) => self.vault_on_timer(kind),
            Action::VaultRequest(effect) => self.send_vault(effect),
            Action::LockVault => {
                if self.vault.active && self.vault.mode == vault::VaultMode::Normal {
                    self.lock_vault();
                } else if self.vault.active {
                    self.notify(MessageLevel::Info, "The vault is locked");
                } else {
                    self.notify(MessageLevel::Info, "There is no vault (--no-vault)");
                }
            }
            Action::Pane(req) => self.handle_pane_request(req),
            Action::PaneInput(id, input) => self.route_pane_input(id, input),
            Action::StatusNotice(level, m) => self.notify(level, &m),
            Action::CycleTransferType => self.cycle_transfer_type(),
            Action::ToggleSpeedLimit => self.toggle_speed_limit(),
            Action::ServerInfo => self.open_server_info(),
            Action::CertificateChain => self.open_certificate_chain(),
            Action::OpenNextPrompt => {
                if self.prompts.open_next(Instant::now()) {
                    self.run_prompt_tick();
                } else if self.prompts.is_visible() {
                    self.status("The prompt is already open");
                } else {
                    self.status("No prompts are waiting");
                }
            }
            Action::SaveCredential(req) => {
                // T31 writes it into the site item.
                debug!(field = ?req.field, "save credential requested");
                self.notify(
                    MessageLevel::Warning,
                    "Saving credentials in the vault is not available yet",
                );
            }
            Action::FocusRegion(r) => self.focus_or_explain(r),
            Action::TaskFinished(id) => {
                self.runner.finished(id);
                if self.save_task == Some(id) {
                    self.save_task = None;
                }
                self.dirty = true;
            }
            Action::SettingsSaved(res) => {
                if let Err(reason) = res {
                    debug!(%reason, "settings save failed");
                    warn!("could not save settings");
                    self.main.set_status(
                        format!("Could not save settings: {reason}"),
                        true,
                        Instant::now(),
                    );
                    self.dirty = true;
                }
            }
            Action::QuitConfirmed => {
                self.modals.close_all();
                self.should_quit = true;
            }
            Action::Help => {
                let mode = self.mode();
                let rows = self.resolver.keymap().bindings_for(mode.chain());
                self.modals.push_modal(Box::new(HelpOverlay::new(&rows)));
                self.dirty = true;
            }
            Action::Quit => {
                let blockers = self.main.quit_blockers();
                if blockers.is_empty() {
                    self.modals.close_all();
                    self.should_quit = true;
                } else {
                    let mut text = "Quit courier-ftp?\n".to_owned();
                    for b in &blockers {
                        text.push_str(&format!("\n{} {b}", self.symbols.bullet));
                    }
                    let dialog =
                        confirm("Quit", &text, ConfirmOpts::danger("Quit")).confirm_on_quit();
                    self.modals.push_then(dialog, |yes| {
                        (yes == Some(true)).then_some(Action::QuitConfirmed)
                    });
                    self.dirty = true;
                }
            }
            Action::Suspend => {
                self.vault_on_suspend();
                if cfg!(windows) {
                    self.status("Suspend is not supported on Windows");
                } else {
                    self.should_suspend = true;
                }
            }
            Action::Cancel => {
                let owner = TaskOwner::Region(self.main.focus());
                if let Some(c) = self.main.focused_mut()
                    && let Some(a) = c.update(&Action::Cancel)?
                {
                    self.queue(a);
                }
                if self.runner.is_busy(owner) {
                    self.runner.cancel_owner(owner);
                    self.status("Cancelling…");
                } else {
                    let quit = quit_hint(&self.key_hint_all("Quit"));
                    self.status(format!("Nothing to cancel — press {quit} to quit"));
                }
            }
            Action::FocusOtherSide => {
                let target = self.other_side();
                self.focus_or_explain(target);
            }
            Action::FocusNextRegion => {
                self.main.focus_next();
                self.dirty = true;
            }
            Action::FocusLog | Action::FocusRegion6 => self.focus_or_explain(Region::Log),
            Action::FocusQueue | Action::FocusRegion7 => self.focus_or_explain(Region::Queue),
            Action::FocusFiles => {
                let list = self.main.last_list();
                self.focus_or_explain(list);
            }
            Action::FocusRegion1 => self.focus_or_explain(Region::Quickconnect),
            Action::FocusRegion2 => self.focus_or_explain(Region::LocalTree),
            Action::FocusRegion3 => self.focus_or_explain(Region::LocalList),
            Action::FocusRegion4 => self.focus_or_explain(Region::RemoteTree),
            Action::FocusRegion5 => self.focus_or_explain(Region::RemoteList),
            Action::ToggleLog => self.change_interface(|i| i.show_log = !i.show_log),
            Action::ToggleQueuePane => self.change_interface(|i| i.show_queue = !i.show_queue),
            Action::ToggleTree => self.change_interface(|i| i.show_tree = !i.show_tree),
            Action::ToggleQuickconnect => {
                self.change_interface(|i| i.show_quickconnect = !i.show_quickconnect);
            }
            Action::SwapPanes => self.change_interface(|i| i.swap_panes = !i.swap_panes),
            Action::LayoutClassic => self.change_interface(|i| i.layout = Layout::Classic),
            Action::LayoutExplorer => self.change_interface(|i| i.layout = Layout::Explorer),
            Action::LayoutWidescreen => self.change_interface(|i| i.layout = Layout::Widescreen),
            other => self.route_to_components(other)?,
        }
        // The focus moved away from where a pending sequence started: drop it.
        if let Some(m) = self.resolver.pending_mode()
            && m != self.mode()
        {
            self.resolver.clear();
            self.dirty = true;
        }
        Ok(())
    }

    /// Every key bound to `action` in the Normal table, as hints.
    fn key_hint_all(&self, action: &str) -> Vec<String> {
        self.resolver
            .keymap()
            .bindings_for(&[Mode::Normal])
            .into_iter()
            .filter(|r| r.action.to_string() == action)
            .map(|r| pretty_keys(&display_sequence(&r.keys)))
            .collect()
    }

    /// A bindable action the app does not handle itself: to the focused component if
    /// it lists the action in `handled_actions`, else to every component that does,
    /// else "… is not available yet".
    fn route_to_components(&mut self, action: Action) -> color_eyre::Result<()> {
        let handles = |c: &dyn crate::components::Component| {
            c.handled_actions().iter().any(|a| a.same_variant(&action))
        };
        if let Some(c) = self.main.focused_mut()
            && handles(&*c)
        {
            if let Some(out) = c.update(&action)? {
                self.queue(out);
            }
            return Ok(());
        }
        let mut handled = false;
        let mut outs = Vec::new();
        for c in self.main.components_mut() {
            if handles(&*c) {
                handled = true;
                outs.extend(c.update(&action)?);
            }
        }
        for out in outs {
            self.queue(out);
        }
        if !handled {
            let what = action
                .meta()
                .map_or_else(|| action.to_string(), |m| m.description.to_owned());
            self.status(format!("{what} is not available yet"));
        }
        Ok(())
    }

    /// Draws the whole screen (main screen, then modals).
    pub(crate) fn draw(&mut self, frame: &mut Frame) {
        if self.vault_hides_panes() {
            // Locked: nothing decrypted (and no server data) is drawn (T60).
            self.render_vault(frame);
            return;
        }
        let now = Instant::now();
        let elapsed_ms = now.duration_since(self.started).as_millis();
        let mode = self.mode();
        let pending = self.resolver.pending_display().unwrap_or_default();
        let mut hints = status_bar::key_hints(self.resolver.keymap(), mode);
        if self.main.layout().is_compact() {
            // T50: the bar says so while panes are hidden (first hint, dropped last).
            hints.insert(0, status_bar::compact_hint());
        }
        let info = self.status_info(&pending, &hints);
        let busy_components = self.main.busy_regions();
        let runner = &self.runner;
        let symbols = &self.symbols;
        let spinner = |r: Region| {
            let task_busy = runner
                .busy_since(TaskOwner::Region(r))
                .is_some_and(|since| now.duration_since(since) > SPINNER_DELAY);
            (task_busy || busy_components.contains(&r)).then(|| symbols.spinner_frame(elapsed_ms))
        };
        let errors = self
            .main
            .draw(frame, &self.theme, &self.symbols, now, &info, &spinner);
        let cx = DrawCx {
            theme: &self.theme,
            symbols: &self.symbols,
            focused: true,
            now,
            spinner: None,
        };
        let area = frame.area();
        let mut errors = errors;
        if let Err(e) = self.modals.draw(frame, area, &cx) {
            errors.push(Action::Error(format!("Failed to draw: {e}")));
        }
        self.prompts.render(frame, area, &cx);
        if let (Some(entries), Some(prefix)) = (
            self.resolver.which_key(now),
            self.resolver.pending_display(),
        ) {
            which_key::draw(frame, area, &prefix, &entries, &self.theme, &self.symbols);
        }
        // Vault forms over the unlocked app (change password, …) (T60).
        self.render_vault(frame);
        for e in errors {
            self.queue(e);
        }
    }

    /// Draws a frame if something changed, or if a spinner or status message is
    /// animating and its frame changed. Returns whether it drew.
    pub(crate) fn render_if_needed<B: Backend>(
        &mut self,
        terminal: &mut Terminal<B>,
    ) -> color_eyre::Result<bool> {
        let now = Instant::now();
        let frame_no = now.duration_since(self.started).as_millis() / 100;
        let animating = self.runner.any_visible_busy()
            || !self.main.busy_regions().is_empty()
            || self.main.status().is_some_and(|m| now < m.until);
        if !(self.dirty || (animating && self.last_frame != Some(frame_no))) {
            return Ok(false);
        }
        self.dirty = false;
        self.last_frame = Some(frame_no);
        terminal
            .draw(|f| self.draw(f))
            .map_err(|e| color_eyre::eyre::eyre!("terminal draw failed: {e}"))?;
        self.draw_count += 1;
        if !self.first_frame_done {
            self.first_frame_done = true;
            if !self.problems.is_empty() {
                let n = self.problems.len();
                let s = if n == 1 { "" } else { "s" };
                self.status(format!("{n} configuration problem{s} — see the log"));
                self.modals
                    .push_then(problems(self.problems.clone()), |_| None);
            }
        }
        Ok(true)
    }
}

/// "F10 or Ctrl-q" from the Quit bindings.
fn quit_hint(all: &[String]) -> String {
    if all.is_empty() {
        return "F10".to_owned();
    }
    let mut v = all.to_vec();
    // Function keys first, as in the docs.
    v.sort_by_key(|k| !k.starts_with('F'));
    v.join(" or ")
}
