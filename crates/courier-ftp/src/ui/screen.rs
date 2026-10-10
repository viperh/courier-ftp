//! [`MainScreen`]: the courier-ftp main window (T50).

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use courier_ftp_core::{
    backend::Listing,
    compare::{CompareOpts, Highlight},
    events::{CoreEvent, PromptRequest},
    filters::FilterEngine,
    local::display_native,
    model::RemotePath,
    settings::InterfaceSettings,
};
use crossterm::event::KeyEvent;
use ratatui::Frame;
use tokio::sync::mpsc::UnboundedSender;

use super::{
    Side,
    compare::{self, CompareState, NavStage, SyncBase, SyncNav, other},
    dir_tree::{DirTree, TreeEffect, is_tree_action},
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
    action::{Action, Connected, SyncChoice},
    app::Mode,
    config::Config,
    keymap::key_to_string,
    ui::dialog::{ask, confirm, message},
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
    pub(crate) local_tree: DirTree,
    pub(crate) remote_tree: DirTree,
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
    /// Synchronized browsing (T66): the base directories, when on.
    sync: Option<SyncBase>,
    /// A synchronized directory change waiting for the other side.
    sync_nav: Option<SyncNav>,
    /// Directory comparison (T66), when on.
    compare: Option<CompareState>,
    compare_opts: CompareOpts,
    /// The "filters differ" warning was shown for this comparison.
    compare_warned: bool,
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
        let unicode = status.unicode;
        let local_tree = DirTree::new(Side::Local, unicode, local.show_hidden());
        let remote_tree = DirTree::new(Side::Remote, unicode, remote.show_hidden());
        let compare_opts = CompareOpts {
            dirs_first: ui.dirs_first,
            natural_sort: ui.natural_sort,
            ..CompareOpts::default()
        };
        Self {
            config,
            theme,
            opts,
            focus: Region::LocalList,
            local,
            remote,
            local_tree,
            remote_tree,
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
            sync: None,
            sync_nav: None,
            compare: None,
            compare_opts,
            compare_warned: false,
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
            // A pane changes directory: synchronized browsing follows.
            Some(Effect::Action(a @ Action::ListDir { force: false, .. }))
                if self.sync.is_some() =>
            {
                self.sync_navigate(a);
            }
            Some(Effect::Action(a)) => self.outbox.push(a),
            Some(Effect::Modal(m)) => self.modals.push(m),
            None => {}
        }
    }

    /// The focused file list (not when its tree has focus).
    fn focused_list(&mut self) -> Option<&mut FileList> {
        match self.focus {
            Region::LocalList => Some(&mut self.local),
            Region::RemoteList => Some(&mut self.remote),
            _ => None,
        }
    }

    /// The side whose directory tree has focus.
    fn focused_tree_side(&self) -> Option<Side> {
        match self.focus {
            Region::LocalTree => Some(Side::Local),
            Region::RemoteTree => Some(Side::Remote),
            _ => None,
        }
    }

    pub(crate) fn tree_mut(&mut self, side: Side) -> &mut DirTree {
        match side {
            Side::Local => &mut self.local_tree,
            Side::Remote => &mut self.remote_tree,
        }
    }

    /// What a tree asked for: show a directory in the side's file list.
    fn apply_tree(&mut self, side: Side, effect: Option<TreeEffect>) {
        if let Some(TreeEffect::Navigate(dir)) = effect {
            let effect = self.pane_mut(side).go_to(dir);
            self.apply(effect);
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
        let outcome = self.route_key(key);
        self.after_change();
        outcome
    }

    fn route_key(&mut self, key: KeyEvent) -> KeyOutcome {
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
        if let Some(side) = self.focused_tree_side()
            && let Some(effect) = self.tree_mut(side).handle_key(key)
        {
            self.apply_tree(side, effect);
            return KeyOutcome::Consumed;
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
        let next = self.apply_action(action);
        self.after_change();
        next
    }

    fn apply_action(&mut self, action: &Action) -> Option<Action> {
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
            if self
                .sync_nav
                .as_ref()
                .is_some_and(|n| n.stage == NavStage::Following && *side == other(n.lead))
            {
                self.followed(*side, result);
                return None;
            }
            let first = self.pane_mut(*side).dir.is_none();
            let error = self.pane_mut(*side).listing_loaded(result);
            self.outbox.extend(error);
            if let Ok(listing) = result {
                self.list_shown(*side, listing, first);
            }
            return None;
        }
        if let Action::TreeListingLoaded { side, dir, result } = action {
            self.tree_mut(*side).loaded(dir, result);
            return None;
        }
        if let Some(side) = self.focused_tree_side() {
            if is_tree_action(action) {
                let effect = self.tree_mut(side).update(action);
                self.apply_tree(side, effect);
                return None;
            }
            if matches!(action, Action::ToggleHidden) {
                let tx = self.action_tx.clone();
                let effect = self.pane_mut(side).update(action, tx.as_ref());
                self.apply(effect);
                return None;
            }
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
            Action::FocusTree => {
                let target = match self.focus {
                    Region::LocalTree => Region::LocalList,
                    Region::RemoteTree => Region::RemoteList,
                    Region::RemoteList => Region::RemoteTree,
                    _ => Region::LocalTree,
                };
                if matches!(target, Region::LocalTree | Region::RemoteTree) {
                    self.opts.visible.tree = true;
                }
                self.set_focus(target);
            }
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
            Action::ToggleSyncBrowsing => {
                if self.sync.is_some() {
                    self.end_sync();
                    self.status
                        .flash("Synchronized browsing off", Instant::now());
                } else if self.start_sync() {
                    self.status
                        .flash("Synchronized browsing on", Instant::now());
                }
            }
            Action::ToggleCompare => {
                if self.compare.is_some() {
                    self.end_compare();
                } else {
                    self.start_compare();
                }
            }
            Action::CompareOptions => {
                let modal = compare::options_dialog(&self.compare_opts, self.action_tx.as_ref());
                self.modals.push(modal);
            }
            Action::SetCompareOptions(opts) => {
                self.compare_opts = (**opts).clone();
                if let Some(state) = &mut self.compare {
                    state.built_from = None;
                }
            }
            Action::SelectCompareLonely => self.select_by_status(Highlight::Lonely),
            Action::SelectCompareNewer => self.select_by_status(Highlight::Newer),
            Action::SelectCompareDifferent => self.select_by_status(Highlight::Different),
            Action::SyncAnswer(choice) => self.sync_answer(*choice),
            Action::DirMade { side, dir, result } => self.dir_made(*side, dir, result),
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

    /// A listing arrived for a side's file list: fill in the tree and make
    /// it follow the list.
    fn list_shown(&mut self, side: Side, listing: &Listing, first: bool) {
        let shown = self.pane_mut(side).dir.as_ref() == Some(&listing.dir);
        let tree = self.tree_mut(side);
        if first && side == Side::Local {
            tree.set_home(&listing.dir);
        }
        tree.listing(listing);
        if shown {
            tree.sync_to(&listing.dir);
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
        self.end_sync();
        self.end_compare();
        self.status.session = None;
        self.remote.connecting(server);
        self.remote_tree.reset();
    }

    /// The remote pane's connection is up: show its first listing and its
    /// security in the status bar.
    pub(crate) fn remote_connected(&mut self, connected: &Connected) {
        self.status.session = connected.info.clone();
        self.remote.busy = false;
        let result: Result<Listing, String> = Ok(connected.listing.clone());
        let error = self.remote.listing_loaded(&result);
        self.outbox.extend(error);
        self.remote_tree.reset();
        self.remote_tree.set_active(true);
        self.list_shown(Side::Remote, &connected.listing, true);
    }

    /// The remote pane is not connected (any more); `error` says why a
    /// connection failed.
    pub(crate) fn remote_disconnected(&mut self, error: Option<String>) {
        self.end_sync();
        self.end_compare();
        self.status.session = None;
        self.remote.disconnected(error);
        self.remote_tree.reset();
    }

    pub(crate) fn pane_mut(&mut self, side: Side) -> &mut FileList {
        match side {
            Side::Local => &mut self.local,
            Side::Remote => &mut self.remote,
        }
    }

    fn pane(&self, side: Side) -> &FileList {
        match side {
            Side::Local => &self.local,
            Side::Remote => &self.remote,
        }
    }

    /// A directory as the user knows it (native on the local side).
    fn show_dir(side: Side, dir: &RemotePath) -> String {
        match side {
            Side::Local => display_native(dir),
            Side::Remote => dir.to_string(),
        }
    }

    // --- T66: synchronized browsing and directory comparison ---

    /// After every action and key: keep the comparison current and both
    /// cursors on the same row.
    fn after_change(&mut self) {
        self.refresh_compare();
        self.lockstep();
    }

    /// Settings of the site or bookmark just connected: turn synchronized
    /// browsing and/or directory comparison on; `case_sensitive` is how
    /// names match ([`courier_ftp_core::compare::names_case_sensitive`]).
    pub(crate) fn connected_view(&mut self, sync: bool, compare: bool, case_sensitive: bool) {
        self.compare_opts.case_sensitive_names = case_sensitive;
        if let Some(state) = &mut self.compare {
            state.built_from = None;
        }
        if compare {
            self.start_compare();
        } else if sync {
            self.start_sync();
        }
        self.after_change();
    }

    /// Turn synchronized browsing on from the directories shown now.
    fn start_sync(&mut self) -> bool {
        match (&self.local.dir, &self.remote.dir) {
            (Some(local), Some(remote)) => {
                self.sync = Some(SyncBase {
                    local: local.clone(),
                    remote: remote.clone(),
                });
                true
            }
            _ => {
                self.status.flash(
                    "Synchronized browsing needs a directory on both sides",
                    Instant::now(),
                );
                false
            }
        }
    }

    /// Turn synchronized browsing off. A directory change waiting for the
    /// other side goes ahead; one waiting for an answer is dropped.
    fn end_sync(&mut self) {
        self.sync = None;
        if let Some(nav) = self.sync_nav.take() {
            if nav.stage == NavStage::Following {
                self.outbox.push(nav.held);
            } else {
                self.pane_mut(nav.lead).cancel_pending();
            }
        }
    }

    /// Turn directory comparison on (and synchronized browsing with it, as
    /// FileZilla does).
    fn start_compare(&mut self) {
        if self.local.dir.is_none() || self.remote.dir.is_none() {
            self.status.flash(
                "Directory comparison needs a directory on both sides",
                Instant::now(),
            );
            return;
        }
        if self.sync.is_none() {
            self.start_sync();
        }
        self.compare = Some(CompareState::default());
        self.compare_warned = false;
    }

    fn end_compare(&mut self) {
        if self.compare.take().is_some() {
            self.local.set_comparison(None);
            self.remote.set_comparison(None);
        }
    }

    /// Rebuild the comparison when either pane's entries changed.
    fn refresh_compare(&mut self) {
        let Some(state) = self.compare.as_mut() else {
            return;
        };
        if self.local.dir.is_none() || self.remote.dir.is_none() {
            self.end_compare();
            return;
        }
        if !state.stale(&self.local, &self.remote) {
            return;
        }
        let differ = state.rebuild(&mut self.local, &mut self.remote, &self.compare_opts);
        if differ && !self.compare_warned {
            self.compare_warned = true;
            let (modal, _) = message(
                "Directory comparison",
                "The two sides are filtered differently (filters or hidden files). \
                 Entries hidden on one side show as missing there.",
            );
            self.modals.push(modal);
        }
    }

    /// While comparing, the other list's cursor follows the focused one.
    fn lockstep(&mut self) {
        if self.compare.is_none() {
            return;
        }
        let lead = match self.focus {
            Region::RemoteList | Region::RemoteTree => Side::Remote,
            _ => Side::Local,
        };
        let position = self.pane(lead).position();
        self.pane_mut(other(lead)).set_position(position);
    }

    /// "Select all yellow/green/red rows on this side".
    fn select_by_status(&mut self, highlight: Highlight) {
        let Some(side) = self.focused_list().map(|l| l.side) else {
            return;
        };
        let Some(state) = &self.compare else {
            self.status
                .flash("Directory comparison is off", Instant::now());
            return;
        };
        let visible = state.listing.indices(side, |h| h == highlight);
        let pane = self.pane_mut(side);
        let indices: Vec<usize> = visible
            .into_iter()
            .filter_map(|i| pane.entry_index(i))
            .collect();
        let added = pane.select_indices(&indices);
        let what = match highlight {
            Highlight::Lonely => "only on this side",
            Highlight::Newer => "newer",
            _ => "different",
        };
        self.status.flash(
            format!(
                "Selected {added} {} {what}",
                if added == 1 { "entry" } else { "entries" }
            ),
            Instant::now(),
        );
    }

    /// A pane wants to change directory while synchronized browsing is on:
    /// the other pane goes to the corresponding directory first, then this
    /// one follows ([`MainScreen::followed`]).
    fn sync_navigate(&mut self, action: Action) {
        let Action::ListDir {
            side: lead, dir, ..
        } = &action
        else {
            self.outbox.push(action);
            return;
        };
        let (lead, dir) = (*lead, dir.clone());
        if self.sync_nav.is_some() {
            self.pane_mut(lead).cancel_pending();
            self.status
                .flash("Waiting for the other side", Instant::now());
            return;
        }
        let Some(target) = self.sync.as_ref().and_then(|b| b.map(lead, &dir)) else {
            let (modal, rx) = confirm(
                "Synchronized browsing",
                &format!(
                    "{} is outside the synchronized directories.\n\n\
                     Turn synchronized browsing off and go there?",
                    Self::show_dir(lead, &dir)
                ),
                false,
            );
            self.modals.push(modal);
            self.answer_later(async move {
                if matches!(rx.await, Ok(true)) {
                    SyncChoice::Disable
                } else {
                    SyncChoice::Stay
                }
            });
            self.sync_nav = Some(SyncNav {
                lead,
                held: action,
                target: None,
                stage: NavStage::AskLeave,
            });
            return;
        };
        match self.pane_mut(other(lead)).go_to(target.clone()) {
            Some(Effect::Action(follow)) => {
                self.outbox.push(follow);
                self.sync_nav = Some(SyncNav {
                    lead,
                    held: action,
                    target: Some(target),
                    stage: NavStage::Following,
                });
            }
            Some(Effect::Modal(m)) => self.modals.push(m),
            // Already there.
            None => self.outbox.push(action),
        }
    }

    /// Send the answer of a sync browsing question as [`Action::SyncAnswer`].
    fn answer_later(&self, answer: impl std::future::Future<Output = SyncChoice> + Send + 'static) {
        if let Some(tx) = self.action_tx.clone() {
            tokio::spawn(async move {
                let _ = tx.send(Action::SyncAnswer(answer.await));
            });
        }
    }

    /// The other pane's listing of the sync browsing target arrived.
    fn followed(&mut self, side: Side, result: &Result<Listing, String>) {
        let Some(mut nav) = self.sync_nav.take() else {
            return;
        };
        let first = self.pane(side).dir.is_none();
        // A failure is reported by the question below, not the log.
        let _ = self.pane_mut(side).listing_loaded(result);
        match result {
            Ok(listing) => {
                self.list_shown(side, listing, first);
                self.outbox.push(nav.held);
            }
            Err(e) => {
                self.pane_mut(side).clear_error();
                let target = nav
                    .target
                    .as_ref()
                    .map(|t| Self::show_dir(side, t))
                    .unwrap_or_default();
                let (modal, rx) = ask(
                    "Synchronized browsing",
                    &format!("Target directory does not exist on the other side:\n{target}\n({e})"),
                    &["Create it", "Disable sync browsing", "Stay"],
                    2,
                );
                self.modals.push(modal);
                self.answer_later(async move {
                    match rx.await {
                        Ok(Some(0)) => SyncChoice::Create,
                        Ok(Some(1)) => SyncChoice::Disable,
                        _ => SyncChoice::Stay,
                    }
                });
                nav.stage = NavStage::AskMissing;
                self.sync_nav = Some(nav);
            }
        }
    }

    fn sync_answer(&mut self, choice: SyncChoice) {
        let Some(mut nav) = self.sync_nav.take() else {
            return;
        };
        match (choice, nav.target.clone()) {
            (SyncChoice::Create, Some(dir)) if nav.stage == NavStage::AskMissing => {
                self.outbox.push(Action::MakeDir {
                    side: other(nav.lead),
                    dir,
                });
                nav.stage = NavStage::Creating;
                self.sync_nav = Some(nav);
            }
            (SyncChoice::Disable, _) => {
                self.sync = None;
                self.outbox.push(nav.held);
                self.status
                    .flash("Synchronized browsing off", Instant::now());
            }
            _ => self.pane_mut(nav.lead).cancel_pending(),
        }
    }

    /// "Create it" finished: list the new directory, then follow.
    fn dir_made(&mut self, side: Side, dir: &RemotePath, result: &Result<(), String>) {
        let Some(mut nav) = self
            .sync_nav
            .take_if(|n| n.stage == NavStage::Creating && side == other(n.lead))
        else {
            return;
        };
        match result {
            Ok(()) => match self.pane_mut(side).go_to(dir.clone()) {
                Some(Effect::Action(follow)) => {
                    self.outbox.push(follow);
                    nav.stage = NavStage::Following;
                    self.sync_nav = Some(nav);
                }
                _ => self.outbox.push(nav.held),
            },
            Err(e) => {
                self.pane_mut(nav.lead).cancel_pending();
                self.outbox
                    .push(Action::Error(format!("{}: {e}", Self::show_dir(side, dir))));
            }
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
        self.refresh_compare();
        self.status.sync_browsing = self.sync.is_some();
        self.status.compare = self.compare.is_some();
        self.local.synced = self.sync.is_some();
        self.remote.synced = self.sync.is_some();
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
        for (area, side, region) in [
            (r.local_tree, Side::Local, Region::LocalTree),
            (r.remote_tree, Side::Remote, Region::RemoteTree),
        ] {
            let Some(a) = area else {
                continue;
            };
            let (list, tree) = match side {
                Side::Local => (&self.local, &mut self.local_tree),
                Side::Remote => (&self.remote, &mut self.remote_tree),
            };
            tree.set_show_hidden(list.show_hidden());
            // Only trees on screen list anything (lazy loading).
            for dir in tree.take_requests() {
                self.outbox.push(Action::TreeListDir { side, dir });
            }
            tree.draw(frame, a, f == region, self.tick, theme);
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
