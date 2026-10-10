//! [`MainScreen`]: the courier-ftp main window (T50).

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use courier_ftp_core::{
    backend::Listing,
    events::{CoreEvent, PromptRequest},
    filters::FilterEngine,
    settings::InterfaceSettings,
};
use crossterm::event::KeyEvent;
use ratatui::Frame;
use tokio::sync::mpsc::UnboundedSender;

use super::{
    Side,
    file_list::{Effect, FileList},
    focus::Region,
    layout::{self, LayoutOptions, Regions, Visibility},
    log::LogPane,
    modal::{HelpOverlay, Modal, ModalOutcome, prompt_modal},
    panes,
    quickconnect::{QuickKey, Quickconnect},
    status::{self, StatusState},
    theme::Theme,
    vault::{VaultRequest, VaultView},
};
use crate::{
    action::{Action, Connected},
    app::Mode,
    config::Config,
    keymap::key_to_string,
    ui::dialog::message,
};

/// Actions the focused pane handles itself (navigation, search, selection).
fn is_pane_action(action: &Action) -> bool {
    matches!(
        action,
        Action::CursorDown
            | Action::CursorUp
            | Action::PageDown
            | Action::PageUp
            | Action::HalfPageDown
            | Action::HalfPageUp
            | Action::Top
            | Action::Bottom
            | Action::QuickFilter
            | Action::SearchNext
            | Action::SearchPrev
            | Action::VisualSelect
            | Action::CopySelection
            | Action::ClearLog
            | Action::ToggleWrap
            | Action::ToggleLogAll
            | Action::ToggleErrorsOnly
            | Action::ScrollLeft
            | Action::ScrollRight
    )
}

/// Actions the focused file list handles.
fn is_list_action(action: &Action) -> bool {
    matches!(
        action,
        Action::CursorDown
            | Action::CursorUp
            | Action::PageDown
            | Action::PageUp
            | Action::HalfPageDown
            | Action::HalfPageUp
            | Action::Top
            | Action::Bottom
            | Action::ParentDir
            | Action::Open
            | Action::HistoryBack
            | Action::HistoryForward
            | Action::ToggleSelect
            | Action::VisualSelect
            | Action::SelectAll
            | Action::InvertSelection
            | Action::SelectPattern
            | Action::DeselectPattern
            | Action::SortName
            | Action::SortSize
            | Action::SortModified
            | Action::SortPermissions
            | Action::SortOwner
            | Action::ToggleHidden
            | Action::QuickFilter
            | Action::EditAddress
            | Action::ColumnMenu
    )
}

/// Status bar hints: the first key of a few common actions, preferring
/// single function keys.
fn hints(config: &Config) -> Vec<(String, String)> {
    let Some(normal) = config.keybindings.0.get(&Mode::Normal) else {
        return Vec::new();
    };
    [
        (Action::Help, "help"),
        (Action::Copy, "copy"),
        (Action::Mkdir, "mkdir"),
        (Action::Delete, "delete"),
        (Action::Quit, "quit"),
    ]
    .into_iter()
    .filter_map(|(action, label)| {
        let mut keys: Vec<_> = normal
            .iter()
            .filter(|(_, a)| **a == action)
            .map(|(k, _)| k)
            .filter(|k| k.len() == 1)
            .collect();
        keys.sort_by_key(|k| {
            (
                !matches!(k[0].code, crossterm::event::KeyCode::F(_)),
                key_to_string(&k[0]),
            )
        });
        keys.first()
            .map(|k| (key_to_string(&k[0]), label.to_owned()))
    })
    .collect()
}

/// How long the user must not press a key before a queued prompt opens by
/// itself, so a key meant for the file list can't answer a dialog that
/// popped up under it.
pub(crate) const PROMPT_IDLE: Duration = Duration::from_secs(1);

/// What the screen did with a key.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeyOutcome {
    /// Handled here (a modal or the focused region took it).
    Consumed,
    /// Not handled; look it up in the keymap of the current [`Mode`].
    NotHandled,
}

/// The main window: regions, focus, the modal stack.
pub(crate) struct MainScreen {
    config: Config,
    theme: Theme,
    opts: LayoutOptions,
    focus: Region,
    pub(crate) local: FileList,
    pub(crate) remote: FileList,
    log: LogPane,
    quickconnect: Quickconnect,
    modals: Vec<Box<dyn Modal>>,
    tick: u64,
    /// The regions of the last frame, for focus checks.
    last: Regions,
    status: StatusState,
    /// For dialogs that answer later (they send their result as an action).
    action_tx: Option<UnboundedSender<Action>>,
    /// Actions the panes asked for, taken by the app after each event.
    outbox: Vec<Action>,
    /// Questions from the core waiting for their turn (T69). One prompt is
    /// shown at a time; see [`MainScreen::pump_prompts`].
    prompts: VecDeque<PromptRequest>,
    /// When the user last pressed a key.
    last_key: Option<Instant>,
    /// The vault screens (T60), when this app has a vault.
    vault: Option<VaultView>,
    /// Whether the vault view covers the panes (unlock view, lock overlay).
    vault_shown: bool,
    /// What the vault view asked for, taken by the app after each key.
    vault_requests: Vec<VaultRequest>,
}

impl MainScreen {
    pub(crate) fn new(config: Config, theme: Theme) -> Self {
        let ui: &InterfaceSettings = &config.settings.interface;
        let mut status = StatusState::new(status::unicode_enabled(ui.unicode_symbols));
        status.transfer_type = config.settings.file_types.default_type;
        status.speed_limit = config.settings.transfers.speed_limit_enabled;
        status.download_limit_kib = config.settings.transfers.download_limit_kib;
        status.upload_limit_kib = config.settings.transfers.upload_limit_kib;
        status.hints = hints(&config);
        let log = LogPane::new(
            config.settings.logging.log_lines,
            config.settings.logging.show_timestamps,
            time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC),
        );
        let opts = LayoutOptions {
            layout: ui.layout,
            swap_panes: ui.swap_panes,
            visible: Visibility {
                quickconnect: ui.show_quickconnect,
                log: ui.show_log,
                queue: ui.show_queue,
                tree: ui.show_tree,
            },
            compact_side: Side::Local,
        };
        let filters = &config.settings.filters;
        let (local_filters, mut warnings) = FilterEngine::from_settings(filters, Side::Local);
        let (remote_filters, more) = FilterEngine::from_settings(filters, Side::Remote);
        warnings.extend(more);
        for w in warnings {
            tracing::warn!("filters: {w}");
        }
        let local = FileList::new(Side::Local, &config.settings, local_filters);
        let remote = FileList::new(Side::Remote, &config.settings, remote_filters);
        Self {
            config,
            theme,
            opts,
            focus: Region::LocalList,
            local,
            remote,
            log,
            quickconnect: Quickconnect::new(),
            modals: Vec::new(),
            tick: 0,
            last: Regions::default(),
            status,
            action_tx: None,
            outbox: Vec::new(),
            prompts: VecDeque::new(),
            last_key: None,
            vault: None,
            vault_shown: false,
            vault_requests: Vec::new(),
        }
    }

    /// Where dialogs send their results.
    pub(crate) fn set_action_tx(&mut self, tx: UnboundedSender<Action>) {
        self.action_tx = Some(tx);
    }

    /// The actions the panes asked for since the last call.
    pub(crate) fn take_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.outbox)
    }

    fn apply(&mut self, effect: Option<Effect>) {
        match effect {
            Some(Effect::Action(a)) => self.outbox.push(a),
            Some(Effect::Modal(m)) => self.modals.push(m),
            None => {}
        }
    }

    fn focused_list(&mut self) -> Option<&mut FileList> {
        match self.focus.side()? {
            Side::Local => Some(&mut self.local),
            Side::Remote => Some(&mut self.remote),
        }
    }

    /// Install the vault view (shown, covering the panes).
    pub(crate) fn set_vault_view(&mut self, view: VaultView) {
        self.vault = Some(view);
        self.vault_shown = true;
    }

    /// The vault view, if this app has a vault.
    pub(crate) fn vault_view_mut(&mut self) -> Option<&mut VaultView> {
        self.vault.as_mut()
    }

    #[cfg(test)]
    pub(crate) fn vault_view(&self) -> Option<&VaultView> {
        self.vault.as_ref()
    }

    /// Show or hide the vault view (hidden: "Continue without vault" or
    /// unlocked).
    pub(crate) fn show_vault(&mut self, shown: bool) {
        self.vault_shown = shown && self.vault.is_some();
    }

    /// Whether the vault view covers the panes.
    #[cfg(test)]
    pub(crate) fn vault_shown(&self) -> bool {
        self.vault_shown
    }

    /// The status bar's `🔐 locked`.
    pub(crate) fn set_vault_locked(&mut self, locked: bool) {
        self.status.vault_locked = locked;
    }

    /// What the vault view asked for since the last call.
    pub(crate) fn take_vault_requests(&mut self) -> Vec<VaultRequest> {
        std::mem::take(&mut self.vault_requests)
    }

    /// The current input mode, which selects the keymap.
    pub(crate) fn mode(&self) -> Mode {
        if !self.modals.is_empty() || self.vault_shown {
            return Mode::Dialog;
        }
        if self.log.is_searching() {
            return Mode::Filter;
        }
        if let Some(side) = self.focus.side() {
            let list = match side {
                Side::Local => &self.local,
                Side::Remote => &self.remote,
            };
            if list.is_editing_address() {
                return Mode::Input;
            }
            if list.is_typing() {
                return Mode::Filter;
            }
        }
        match self.focus {
            Region::Quickconnect => Mode::Input,
            Region::LocalList | Region::RemoteList | Region::LocalTree | Region::RemoteTree => {
                Mode::FileList
            }
            Region::Log => Mode::Log,
            Region::Queue => Mode::Queue,
        }
    }

    #[cfg(test)]
    pub(crate) fn focus(&self) -> Region {
        self.focus
    }

    #[cfg(test)]
    pub(crate) fn has_modal(&self) -> bool {
        !self.modals.is_empty()
    }

    /// Show the pending keys of an unfinished sequence in the status bar.
    pub(crate) fn set_pending_keys(&mut self, keys: String) {
        self.status.pending_keys = keys;
    }

    /// Route a key: the top modal first, then the focused region. Keys nobody
    /// takes go to the keymap.
    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> KeyOutcome {
        self.last_key = Some(Instant::now());
        if self.vault_shown {
            if let Some(view) = self.vault.as_mut()
                && let Some(request) = view.handle_key(key, Instant::now())
            {
                self.vault_requests.push(request);
            }
            return KeyOutcome::Consumed;
        }
        if let Some(top) = self.modals.last_mut() {
            if top.handle_key(key) == ModalOutcome::Close {
                self.modals.pop();
            }
            return KeyOutcome::Consumed;
        }
        // A region typing text of its own (a search query) takes every key.
        if self.focus == Region::Log && self.log.handle_search_key(key) {
            return KeyOutcome::Consumed;
        }
        if self.focus == Region::Quickconnect {
            match self.quickconnect.handle_key(key) {
                QuickKey::Consumed => return KeyOutcome::Consumed,
                QuickKey::Submit => {
                    self.submit_quickconnect();
                    return KeyOutcome::Consumed;
                }
                QuickKey::NotHandled => {}
            }
        }
        if let Some(list) = self.focused_list()
            && let Some(effect) = list.handle_key(key)
        {
            self.apply(effect);
            return KeyOutcome::Consumed;
        }
        KeyOutcome::NotHandled
    }

    /// Pasted text goes to the top modal (T52), the quickconnect bar or the
    /// focused list's address bar.
    pub(crate) fn handle_paste(&mut self, text: &str) {
        if self.vault_shown {
            if let Some(view) = self.vault.as_mut() {
                view.handle_paste(text);
            }
        } else if let Some(top) = self.modals.last_mut() {
            top.handle_paste(text);
        } else if self.focus == Region::Quickconnect {
            self.quickconnect.handle_paste(text);
        } else if let Some(list) = self.focused_list() {
            list.handle_paste(text);
        }
    }

    /// Put a dialog on top of the modal stack.
    pub(crate) fn push_modal(&mut self, modal: Box<dyn Modal>) {
        self.modals.push(modal);
    }

    /// Apply an action. May return a follow-up action.
    pub(crate) fn update(&mut self, action: &Action) -> Option<Action> {
        if let Action::CopyToClipboard(text) = action {
            let lines = text.lines().count();
            let what = if lines == 1 {
                "line".to_owned()
            } else {
                format!("{lines} lines")
            };
            self.status
                .flash(format!("Copied {what} to the clipboard"), Instant::now());
            return None;
        }
        if self.focus == Region::Log && is_pane_action(action) {
            return self.log.update(action);
        }
        if matches!(action, Action::ClearLog) {
            return self.log.update(action);
        }
        // Results for a particular side, whatever has focus.
        if let Action::ListingLoaded { side, result } = action {
            let error = self.pane_mut(*side).listing_loaded(result);
            self.outbox.extend(error);
            return None;
        }
        if let Action::ApplyPattern { side, .. } | Action::SetColumns { side, .. } = action {
            let tx = self.action_tx.clone();
            let effect = self.pane_mut(*side).update(action, tx.as_ref());
            self.apply(effect);
            return None;
        }
        if matches!(action, Action::Refresh) {
            let tx = self.action_tx.clone();
            for side in [Side::Local, Side::Remote] {
                let effect = self.pane_mut(side).update(action, tx.as_ref());
                self.apply(effect);
            }
            return None;
        }
        if is_list_action(action) {
            let tx = self.action_tx.clone();
            if let Some(list) = self.focused_list() {
                let effect = list.update(action, tx.as_ref());
                self.apply(effect);
                return None;
            }
        }
        match action {
            Action::Tick => {
                self.tick = self.tick.wrapping_add(1);
                if let Some(view) = self.vault.as_mut() {
                    view.tick();
                }
                self.pump_prompts(Instant::now(), false);
            }
            Action::OpenPrompt => {
                if self.prompts.is_empty() {
                    self.status.flash("No prompt waiting", Instant::now());
                }
                self.pump_prompts(Instant::now(), true);
            }
            Action::Help => self.open_help(),
            Action::CloseDialog => {
                self.modals.pop();
            }
            Action::FocusNext | Action::FocusPrev => {
                self.focus = self.focus.toggled();
                if let Some(side) = self.focus.side() {
                    self.opts.compact_side = side;
                }
            }
            Action::FocusLocal => self.set_focus(Region::LocalList),
            Action::FocusRemote => self.set_focus(Region::RemoteList),
            Action::FocusLog => self.set_focus(Region::Log),
            Action::FocusQueue => self.set_focus(Region::Queue),
            Action::FocusQuickconnect => {
                self.set_focus(Region::Quickconnect);
                self.quickconnect.focus_host();
            }
            Action::ToggleLog => self.opts.visible.log = !self.opts.visible.log,
            Action::ToggleQueue => self.opts.visible.queue = !self.opts.visible.queue,
            Action::ToggleTree => self.opts.visible.tree = !self.opts.visible.tree,
            Action::ToggleSpeedLimit => {
                self.status.speed_limit = !self.status.speed_limit;
                let state = if self.status.speed_limit { "on" } else { "off" };
                self.status
                    .flash(format!("Speed limit {state}"), Instant::now());
            }
            Action::CycleTransferType => self.status.cycle_transfer_type(),
            Action::ToggleSyncBrowsing => self.status.sync_browsing = !self.status.sync_browsing,
            Action::ToggleCompare => self.status.compare = !self.status.compare,
            Action::ServerInfo => {
                let (modal, _) = message(
                    "Server info",
                    &status::server_info_text(self.status.session.as_ref()),
                );
                self.modals.push(modal);
            }
            Action::ToggleQuickconnect => {
                self.opts.visible.quickconnect = !self.opts.visible.quickconnect;
            }
            _ => {}
        }
        None
    }

    fn set_focus(&mut self, region: Region) {
        self.focus = region;
        if let Some(side) = region.side() {
            self.opts.compact_side = side;
        }
        // Focusing a hidden log/queue/quickconnect shows it.
        match region {
            Region::Log => self.opts.visible.log = true,
            Region::Queue => self.opts.visible.queue = true,
            Region::Quickconnect => self.opts.visible.quickconnect = true,
            _ => {}
        }
    }

    /// Connect with what the quickconnect bar holds, or say what is wrong.
    /// Focus moves to the remote list so the prompts of the connection (host
    /// key, password) can open: they wait while a text field has focus.
    fn submit_quickconnect(&mut self) {
        match self.quickconnect.request() {
            Ok(request) => {
                self.outbox.push(Action::Connect {
                    request: Box::new(request),
                    replace: false,
                });
                self.set_focus(Region::RemoteList);
            }
            Err(e) => self.status.flash(e, Instant::now()),
        }
    }

    /// Show `text` in the status bar for a few seconds.
    pub(crate) fn flash(&mut self, text: impl Into<String>) {
        self.status.flash(text, Instant::now());
    }

    /// A connection to `server` is being opened in the remote pane.
    pub(crate) fn remote_connecting(&mut self, server: String) {
        self.status.session = None;
        self.remote.connecting(server);
    }

    /// The remote pane's connection is up: show its first listing and its
    /// security in the status bar.
    pub(crate) fn remote_connected(&mut self, connected: &Connected) {
        self.status.session = connected.info.clone();
        self.remote.busy = false;
        let result: Result<Listing, String> = Ok(connected.listing.clone());
        let error = self.remote.listing_loaded(&result);
        self.outbox.extend(error);
    }

    /// The remote pane is not connected (any more); `error` says why a
    /// connection failed.
    pub(crate) fn remote_disconnected(&mut self, error: Option<String>) {
        self.status.session = None;
        self.remote.disconnected(error);
    }

    pub(crate) fn pane_mut(&mut self, side: Side) -> &mut FileList {
        match side {
            Side::Local => &mut self.local,
            Side::Remote => &mut self.remote,
        }
    }

    /// Something from the core (T04).
    pub(crate) fn handle_core(&mut self, event: CoreEvent) {
        match event {
            CoreEvent::Log(msg) => self.log.push(msg),
            CoreEvent::Prompt(request) => {
                self.prompts.push_back(request);
                self.pump_prompts(Instant::now(), false);
            }
            // Connection, listing, transfer and queue events get their UI in
            // T53/T56/T57/T61.
            _ => {}
        }
    }

    /// Show the next queued prompt when nothing else is in the way (T69).
    ///
    /// A prompt opens by itself only when no dialog is open, the user isn't
    /// typing (input or filter mode) and no key was pressed for
    /// [`PROMPT_IDLE`]. Until then the status bar shows `⚠ N prompts` and
    /// `<Ctrl-x><p>` (`force`) opens the next one at once. Prompts the core
    /// stopped waiting for are dropped.
    pub(crate) fn pump_prompts(&mut self, now: Instant, force: bool) {
        self.prompts.retain(|p| !p.reply.is_closed());
        // Nothing opens over the vault view (input is blocked there).
        let busy = !self.modals.is_empty()
            || self.vault_shown
            || (!force
                && (matches!(self.mode(), Mode::Input | Mode::Filter)
                    || self
                        .last_key
                        .is_some_and(|t| now.saturating_duration_since(t) < PROMPT_IDLE)));
        if !busy && let Some(request) = self.prompts.pop_front() {
            self.modals.push(prompt_modal(request, self.status.unicode));
        }
        self.status.pending_prompts = self.prompts.len();
    }

    /// Prompts waiting for their turn.
    #[cfg(test)]
    pub(crate) fn queued_prompts(&self) -> usize {
        self.prompts.len()
    }

    #[cfg(test)]
    pub(crate) fn set_last_key(&mut self, at: Option<Instant>) {
        self.last_key = at;
    }

    fn open_help(&mut self) {
        let mode = self.mode();
        let bindings = self.config.keybindings.describe(mode);
        self.modals
            .push(Box::new(HelpOverlay::new(&format!("{mode:?}"), bindings)));
    }

    /// Draw everything.
    pub(crate) fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();
        self.modals.retain(|m| !m.is_done());
        self.status.pending_prompts = self.prompts.len();
        let r = layout::compute(area, &self.opts);
        if self.vault_shown
            && let Some(view) = &self.vault
        {
            // Panes hidden, input blocked; the status bar stays so running
            // transfers stay visible (T60 §4).
            let status = r.status.unwrap_or(ratatui::layout::Rect::new(
                area.x,
                area.bottom().saturating_sub(1),
                area.width,
                1.min(area.height),
            ));
            let above = ratatui::layout::Rect::new(
                area.x,
                area.y,
                area.width,
                status.y.saturating_sub(area.y),
            );
            view.draw(frame, above, &self.theme, Instant::now());
            status::draw(frame, status, &self.status, &self.theme);
            return;
        }
        if !self.focus.visible_in(&r) {
            self.focus = Region::list(self.opts.compact_side);
            if !self.focus.visible_in(&r) {
                self.focus = Region::LocalList;
            }
        }
        self.last = r;
        self.status.filters_active = self.local.is_filtered() || self.remote.is_filtered();
        let theme = &self.theme;
        let f = self.focus;
        if let Some(a) = r.quickconnect {
            self.quickconnect
                .draw(frame, a, f == Region::Quickconnect, theme);
        }
        if let Some(a) = r.tabs {
            panes::draw_tabs(frame, a, theme);
        }
        if let Some(a) = r.log {
            self.log.draw(frame, a, f == Region::Log, theme);
        }
        for (tree, region) in [
            (r.local_tree, Region::LocalTree),
            (r.remote_tree, Region::RemoteTree),
        ] {
            if let Some(a) = tree {
                let focused = f == region;
                frame.render_widget(
                    ratatui::widgets::Paragraph::new("(directory tree: T54)")
                        .style(theme.dim)
                        .block(panes::block(" Tree ", focused, theme)),
                    a,
                );
            }
        }
        if let Some(a) = r.local_list {
            self.local
                .draw(frame, a, f == Region::LocalList, self.tick, theme);
        }
        if let Some(a) = r.remote_list {
            self.remote
                .draw(frame, a, f == Region::RemoteList, self.tick, theme);
        }
        if let Some(a) = r.queue {
            panes::draw_queue(frame, a, f == Region::Queue, theme);
        }
        if let Some(a) = r.status {
            status::draw(frame, a, &self.status, theme);
        }
        if let Some(a) = r.hint {
            panes::draw_hint(frame, a, theme);
        }
        for modal in &mut self.modals {
            modal.draw(frame, area, theme);
        }
    }
}
