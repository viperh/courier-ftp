//! [`MainScreen`]: the courier-ftp main window (T50).

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use courier_ftp_core::{
    backend::Listing,
    compare::{CompareOpts, Highlight},
    events::{CoreEvent, PromptRequest},
    filters::{FilterEngine, FilterSettings},
    local::display_native,
    model::RemotePath,
    settings::{InterfaceSettings, Settings},
};
use crossterm::event::KeyEvent;
use ratatui::Frame;
use tokio::sync::mpsc::UnboundedSender;

use super::{
    Side,
    bookmarks::BookmarksMenu,
    compare::{self, CompareState, NavStage, SyncBase, SyncNav, other},
    dir_tree::{DirTree, TreeEffect, is_tree_action},
    file_list::{Effect, FileList},
    filters::FiltersDialog,
    focus::Region,
    layout::{self, LayoutOptions, Regions, Visibility},
    log::LogPane,
    modal::{HelpOverlay, Modal, ModalOutcome, prompt_modal},
    panes,
    queue::QueuePane,
    quickconnect::{QuickKey, Quickconnect},
    search::{Fmt, SearchOpts, SearchUpdate, SearchView},
    settings::SettingsView,
    site_manager::SiteManagerView,
    splash::Splash,
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
            | Action::CopyLog
            | Action::SaveLog
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

/// The filter engines of both sides; problems (an invalid regex in the
/// config file) are logged.
fn engines(filters: &FilterSettings) -> (FilterEngine, FilterEngine) {
    let (local, mut warnings) = FilterEngine::from_settings(filters, Side::Local);
    let (remote, more) = FilterEngine::from_settings(filters, Side::Remote);
    warnings.extend(more);
    for w in warnings {
        tracing::warn!("filters: {w}");
    }
    (local, remote)
}

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
    /// The transfer queue (T56).
    queue: QueuePane,
    /// The transfer engine's state (processing, paused), once the app runs
    /// one.
    engine_status: Option<tokio::sync::watch::Receiver<courier_ftp_core::transfer::EngineStatus>>,
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
    /// The Site Manager (T59), when open. It covers the panes; dialogs open
    /// over it.
    sites: Option<SiteManagerView>,
    /// The settings screen (T68), when open. It covers the panes (and the
    /// Site Manager); dialogs open over it.
    settings: Option<SettingsView>,
    /// The search view (T65). It stays for the session once opened, hidden
    /// or shown, so the last query and results come back with `Ctrl-f`.
    search: Option<SearchView>,
    /// Synchronized browsing (T66): the base directories, when on.
    sync: Option<SyncBase>,
    /// A synchronized directory change waiting for the other side.
    sync_nav: Option<SyncNav>,
    /// Directory comparison (T66), when on.
    compare: Option<CompareState>,
    compare_opts: CompareOpts,
    /// The "filters differ" warning was shown for this comparison.
    compare_warned: bool,
    /// The bookmarks menu (T64), when open. Dialogs open over it.
    bookmarks: Option<BookmarksMenu>,
    /// A bookmark being applied waits for its listings before turning
    /// synchronized browsing / comparison on.
    bookmark_modes: Option<PendingModes>,
    /// The splash screen (T74), while shown. It covers everything.
    splash: Option<Splash>,
    /// "Update available: …" (T74), shown at the top of Help.
    update_notice: Option<String>,
    /// The sync screens (T90), when open. They cover the panes like the
    /// Site Manager.
    #[cfg(feature = "sync")]
    sync_view: Option<super::sync::SyncView>,
    /// What the sync screens asked for, taken by the app after each key.
    #[cfg(feature = "sync")]
    sync_requests: Vec<super::sync::SyncRequest>,
}

/// Synchronized browsing / comparison to turn on once the panes show a
/// bookmark's directories.
#[derive(Debug)]
struct PendingModes {
    local: bool,
    remote: bool,
    sync: bool,
    compare: bool,
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
        let (local_filters, remote_filters) = engines(&config.settings.filters);
        let local = FileList::new(Side::Local, &config.settings, local_filters);
        let remote = FileList::new(Side::Remote, &config.settings, remote_filters);
        let unicode = status.unicode;
        let queue = QueuePane::new(
            crate::transfers::new_queue(&config.settings),
            unicode,
            time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC),
        );
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
            queue,
            engine_status: None,
            quickconnect: Quickconnect::new().with_unicode(unicode),
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
            sites: None,
            settings: None,
            search: None,
            sync: None,
            sync_nav: None,
            compare: None,
            compare_opts,
            compare_warned: false,
            bookmarks: None,
            bookmark_modes: None,
            splash: None,
            update_notice: None,
            #[cfg(feature = "sync")]
            sync_view: None,
            #[cfg(feature = "sync")]
            sync_requests: Vec::new(),
        }
    }

    /// Cover the screen with the splash (T74) for `version`.
    pub(crate) fn show_splash(&mut self, version: &str, now: Instant) {
        self.splash = Some(Splash::new(version, now));
    }

    /// Whether the splash screen is up.
    pub(crate) fn splash_shown(&self) -> bool {
        self.splash.is_some()
    }

    /// Take the splash down once it has been up long enough (`starting`:
    /// the app is still opening the vault).
    pub(crate) fn expire_splash(&mut self, now: Instant, starting: bool) {
        if self
            .splash
            .as_ref()
            .is_some_and(|s| s.expired(now, starting))
        {
            self.splash = None;
        }
    }

    /// A newer release exists (T74): say so in the status bar and in Help.
    pub(crate) fn set_update_notice(&mut self, notice: String) {
        self.flash(notice.clone());
        self.update_notice = Some(notice);
    }

    /// Where dialogs send their results.
    pub(crate) fn set_action_tx(&mut self, tx: UnboundedSender<Action>) {
        self.action_tx = Some(tx);
    }

    /// The queue the pane shows (shared with the engine and persister).
    pub(crate) fn queue_shared(&self) -> &courier_ftp_core::queue::SharedQueue {
        self.queue.shared()
    }

    /// Follow the transfer engine's status (processing, paused).
    pub(crate) fn set_engine_status(
        &mut self,
        rx: tokio::sync::watch::Receiver<courier_ftp_core::transfer::EngineStatus>,
    ) {
        self.engine_status = Some(rx);
    }

    /// The side of the focused file list (not its tree).
    pub(crate) fn focused_list_side(&self) -> Option<Side> {
        match self.focus {
            Region::LocalList => Some(Side::Local),
            Region::RemoteList => Some(Side::Remote),
            _ => None,
        }
    }

    /// The transfer type chosen in the status bar.
    pub(crate) fn transfer_type(&self) -> courier_ftp_core::settings::TransferTypeChoice {
        self.status.transfer_type
    }

    /// List `dir` again when `side` shows it (a transfer into it finished).
    pub(crate) fn refresh_dir(&mut self, side: Side, dir: &RemotePath) {
        if self.pane(side).dir.as_ref() != Some(dir) || self.pane(side).busy {
            return;
        }
        let tx = self.action_tx.clone();
        let effect = self.pane_mut(side).update(&Action::Refresh, tx.as_ref());
        self.apply(effect);
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

    /// Open the Site Manager (replacing one already open).
    pub(crate) fn open_site_manager(&mut self, view: SiteManagerView) {
        self.sites = Some(view);
    }

    /// The Site Manager, when open.
    pub(crate) fn site_manager_mut(&mut self) -> Option<&mut SiteManagerView> {
        self.sites.as_mut()
    }

    /// The Site Manager, when open.
    #[cfg(test)]
    pub(crate) fn site_manager(&self) -> Option<&SiteManagerView> {
        self.sites.as_ref()
    }

    /// Close the Site Manager (vault locked, connecting).
    pub(crate) fn close_site_manager(&mut self) {
        self.sites = None;
    }

    /// Open the sync screens (replacing ones already open).
    #[cfg(feature = "sync")]
    pub(crate) fn open_sync_view(&mut self, view: super::sync::SyncView) {
        self.sync_view = Some(view);
        self.pump_sync();
    }

    /// The sync screens, when open.
    #[cfg(feature = "sync")]
    pub(crate) fn sync_view_mut(&mut self) -> Option<&mut super::sync::SyncView> {
        self.sync_view.as_mut()
    }

    /// The sync screens, when open.
    #[cfg(all(test, feature = "sync"))]
    pub(crate) fn sync_view(&self) -> Option<&super::sync::SyncView> {
        self.sync_view.as_ref()
    }

    /// Close the sync screens (vault locked).
    #[cfg(feature = "sync")]
    pub(crate) fn close_sync_view(&mut self) {
        self.sync_view = None;
    }

    /// What the sync screens asked for since the last call.
    #[cfg(feature = "sync")]
    pub(crate) fn take_sync_requests(&mut self) -> Vec<super::sync::SyncRequest> {
        self.pump_sync();
        std::mem::take(&mut self.sync_requests)
    }

    /// Collect the sync screens' requests and drop them once closed.
    #[cfg(feature = "sync")]
    fn pump_sync(&mut self) {
        let Some(view) = self.sync_view.as_mut() else {
            return;
        };
        self.sync_requests.extend(view.take_requests());
        if view.is_closed() {
            self.sync_view = None;
        }
    }

    /// The status bar's device sync segment (T90).
    #[cfg(feature = "sync")]
    pub(crate) fn set_sync_status(&mut self, sync: Option<(String, status::SyncLevel)>) {
        self.status.sync = sync;
    }

    /// Open the bookmarks menu (replacing one already open).
    pub(crate) fn open_bookmarks(&mut self, menu: BookmarksMenu) {
        self.bookmarks = Some(menu);
        self.pump_bookmarks();
    }

    /// The bookmarks menu, when open.
    pub(crate) fn bookmarks_mut(&mut self) -> Option<&mut BookmarksMenu> {
        self.bookmarks.as_mut()
    }

    /// The bookmarks menu, when open.
    #[cfg(test)]
    pub(crate) fn bookmarks(&self) -> Option<&BookmarksMenu> {
        self.bookmarks.as_ref()
    }

    /// Close the bookmarks menu (vault locked).
    pub(crate) fn close_bookmarks(&mut self) {
        self.bookmarks = None;
    }

    /// Pass the bookmarks menu's requests on and drop it once it closed.
    fn pump_bookmarks(&mut self) {
        let Some(menu) = self.bookmarks.as_mut() else {
            return;
        };
        for op in menu.take_requests() {
            self.outbox
                .push(Action::BookmarkOp(crate::action::Shared::new(op)));
        }
        if menu.take_unlock_request() {
            self.outbox.push(Action::UnlockVault);
        }
        let apply = menu.take_apply();
        if menu.is_closed() {
            self.bookmarks = None;
        }
        if let Some(target) = apply {
            self.apply_bookmark(target);
        }
    }

    /// Pass the Site Manager's requests on and drop it once it closed.
    fn pump_sites(&mut self) {
        let Some(view) = self.sites.as_mut() else {
            return;
        };
        for op in view.take_requests() {
            self.outbox
                .push(Action::SiteOp(crate::action::Shared::new(op)));
        }
        if view.take_unlock_request() {
            self.outbox.push(Action::UnlockVault);
        }
        if view.is_closed() {
            self.sites = None;
        }
    }

    /// Open the settings screen (replacing one already open).
    pub(crate) fn open_settings(&mut self, view: SettingsView) {
        self.settings = Some(view);
    }

    /// The settings screen, when open.
    #[cfg(test)]
    pub(crate) fn settings_view(&self) -> Option<&SettingsView> {
        self.settings.as_ref()
    }

    /// Pass the settings screen's requests on and drop it once it closed.
    fn pump_settings(&mut self) {
        let Some(view) = self.settings.as_mut() else {
            return;
        };
        for request in view.take_requests() {
            self.outbox
                .push(Action::SettingsRequest(crate::action::Shared::new(request)));
        }
        if view.is_closed() {
            self.settings = None;
        }
    }

    /// Whether the search view covers the panes.
    pub(crate) fn search_shown(&self) -> bool {
        self.search.as_ref().is_some_and(|v| !v.is_hidden())
    }

    /// The search view, when one was opened this session.
    #[cfg(test)]
    pub(crate) fn search_view_mut(&mut self) -> Option<&mut SearchView> {
        self.search.as_mut()
    }

    /// `Ctrl-f`: show the search view, searching the focused pane's side
    /// from its current directory (the remote side only when connected).
    fn open_search(&mut self) {
        let side = match self.opts.compact_side {
            Side::Remote if self.remote.dir.is_some() => Side::Remote,
            _ => Side::Local,
        };
        let opts = SearchOpts {
            side,
            dirs: [
                self.local
                    .dir
                    .as_ref()
                    .map(display_native)
                    .unwrap_or_default(),
                self.remote
                    .dir
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
            ],
            unicode: self.status.unicode,
            fmt: Fmt::new(
                &self.config.settings,
                time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC),
            ),
        };
        match self.search.as_mut() {
            Some(view) => view.reopen(opts),
            None => self.search = Some(SearchView::new(opts)),
        }
    }

    /// Something from the running search (or a result action) for the view.
    pub(crate) fn search_update(&mut self, update: &SearchUpdate) {
        if let Some(view) = self.search.as_mut() {
            view.apply_update(update);
        }
    }

    /// Pass the search view's requests on.
    fn pump_search(&mut self) {
        let Some(view) = self.search.as_mut() else {
            return;
        };
        for request in view.take_requests() {
            self.outbox
                .push(Action::SearchRequest(crate::action::Shared::new(request)));
        }
    }

    /// "Go to" a search result: hide the search view, show `dir` in the
    /// `side` pane with the cursor on `name`, and focus that pane.
    pub(crate) fn reveal(&mut self, side: Side, dir: RemotePath, name: String) {
        if let Some(view) = self.search.as_mut() {
            view.hide();
        }
        self.set_focus(Region::list(side));
        let effect = self.pane_mut(side).go_to_entry(dir, name);
        self.apply(effect);
    }

    /// Settings changed on the settings screen (T68): apply what the screen
    /// shows at once (layout, visibility, formats, sort order, colours, log
    /// pane, status bar).
    pub(crate) fn apply_settings(&mut self, new: &Settings) {
        let old = &self.config.settings;
        let (ui, was) = (&new.interface, &old.interface);
        self.opts.layout = ui.layout;
        self.opts.swap_panes = ui.swap_panes;
        // Visibility toggled with keys this run stays unless the setting
        // itself changed.
        let visible = &mut self.opts.visible;
        for (now, before, slot) in [
            (
                ui.show_quickconnect,
                was.show_quickconnect,
                &mut visible.quickconnect,
            ),
            (ui.show_log, was.show_log, &mut visible.log),
            (ui.show_queue, was.show_queue, &mut visible.queue),
            (ui.show_tree, was.show_tree, &mut visible.tree),
        ] {
            if now != before {
                *slot = now;
            }
        }
        let unicode = status::unicode_enabled(ui.unicode_symbols);
        self.status.unicode = unicode;
        self.quickconnect.set_unicode(unicode);
        self.local_tree.set_unicode(unicode);
        self.remote_tree.set_unicode(unicode);
        if ui != was {
            self.local.apply_settings(new);
            self.remote.apply_settings(new);
        }
        self.compare_opts.dirs_first = ui.dirs_first;
        self.compare_opts.natural_sort = ui.natural_sort;
        if let Some(state) = &mut self.compare {
            state.built_from = None;
        }
        self.log
            .configure(new.logging.log_lines, new.logging.show_timestamps);
        if ui.color_scheme != was.color_scheme {
            self.theme = Theme::with_scheme(
                ui.color_scheme,
                self.config.styles.0.get(&Mode::Normal),
                Theme::no_color_requested(),
            );
        }
        let t = &new.transfers;
        self.status.speed_limit = t.speed_limit_enabled;
        self.status.download_limit_kib = t.download_limit_kib;
        self.status.upload_limit_kib = t.upload_limit_kib;
        if new.file_types.default_type != old.file_types.default_type {
            self.status.transfer_type = new.file_types.default_type;
        }
        self.config.settings = new.clone();
    }

    /// The current input mode, which selects the keymap.
    pub(crate) fn mode(&self) -> Mode {
        if !self.modals.is_empty()
            || self.vault_shown
            || self.sites.is_some()
            || self.bookmarks.is_some()
            || self.settings.is_some()
            || self.sync_open()
            || self.search_shown()
        {
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

    /// Whether the sync screens are open.
    fn sync_open(&self) -> bool {
        #[cfg(feature = "sync")]
        return self.sync_view.is_some();
        #[cfg(not(feature = "sync"))]
        false
    }

    #[cfg(test)]
    pub(crate) fn focus(&self) -> Region {
        self.focus
    }

    #[cfg(test)]
    pub(crate) fn quickconnect(&self) -> &Quickconnect {
        &self.quickconnect
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
        // Any key skips the splash, and does nothing else.
        if self.splash.take().is_some() {
            return KeyOutcome::Consumed;
        }
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
        // Over the settings screen when opened from its Sync page.
        #[cfg(feature = "sync")]
        if let Some(view) = self.sync_view.as_mut() {
            view.handle_key(key);
            self.pump_sync();
            return KeyOutcome::Consumed;
        }
        if let Some(view) = self.settings.as_mut() {
            view.handle_key(key);
            self.pump_settings();
            return KeyOutcome::Consumed;
        }
        if let Some(view) = self.search.as_mut().filter(|v| !v.is_hidden()) {
            view.handle_key(key);
            self.pump_search();
            return KeyOutcome::Consumed;
        }
        if let Some(view) = self.sites.as_mut() {
            view.handle_key(key);
            self.pump_sites();
            return KeyOutcome::Consumed;
        }
        if let Some(menu) = self.bookmarks.as_mut() {
            menu.handle_key(key);
            self.pump_bookmarks();
            return KeyOutcome::Consumed;
        }
        if self.focus == Region::Queue && self.queue.handle_key(key) {
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
                QuickKey::History => {
                    self.outbox.push(Action::QuickconnectHistory);
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
        } else if self.paste_sync(text) {
        } else if let Some(view) = self.settings.as_mut() {
            view.handle_paste(text);
        } else if let Some(view) = self.search.as_mut().filter(|v| !v.is_hidden()) {
            view.handle_paste(text);
        } else if let Some(view) = self.sites.as_mut() {
            view.handle_paste(text);
        } else if let Some(menu) = self.bookmarks.as_mut() {
            menu.handle_paste(text);
        } else if self.focus == Region::Quickconnect {
            self.quickconnect.handle_paste(text);
        } else if let Some(list) = self.focused_list() {
            list.handle_paste(text);
        }
    }

    /// Paste into the sync screens; `false` when they aren't open.
    fn paste_sync(&mut self, text: &str) -> bool {
        #[cfg(feature = "sync")]
        if let Some(view) = self.sync_view.as_mut() {
            view.handle_paste(text);
            return true;
        }
        let _ = text;
        false
    }

    /// The side of the file list or tree that last had focus.
    pub(crate) fn active_side(&self) -> Side {
        self.opts.compact_side
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
        if QueuePane::handles_anywhere(action)
            || (self.focus == Region::Queue && QueuePane::handles(action))
        {
            let tx = self.action_tx.clone();
            let effect = self.queue.update(action, tx.as_ref());
            self.apply(effect);
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
            self.bookmark_listing(*side, result.is_ok());
            return None;
        }
        if let Action::BookmarksReply(reply) = action {
            if let Some(menu) = self.bookmarks.as_mut() {
                menu.apply_reply(&reply.0);
                self.pump_bookmarks();
            }
            return None;
        }
        if let Action::SitesReply(reply) = action {
            if let Some(view) = self.sites.as_mut() {
                view.apply_reply(&reply.0);
                self.pump_sites();
            }
            return None;
        }
        if let Action::SettingsReply(reply) = action {
            if let Some(view) = self.settings.as_mut() {
                view.apply_reply(&reply.0);
                self.pump_settings();
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
                #[cfg(feature = "sync")]
                if let Some(view) = self.sync_view.as_mut() {
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
            Action::Filters => {
                let dialog =
                    FiltersDialog::new(&self.config.settings.filters, self.action_tx.clone());
                self.modals.push(Box::new(dialog));
            }
            Action::SetFilters(filters) => self.set_filters(filters),
            Action::Search => self.open_search(),
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

    /// New filters from the filters dialog (T67): both panes re-filter now.
    /// The app saves them.
    fn set_filters(&mut self, filters: &FilterSettings) {
        let were_equal = self.local.filters().equivalent(self.remote.filters());
        self.config.settings.filters = filters.clone();
        let (local, remote) = engines(filters);
        // Filters now differing: the comparison warns again.
        if were_equal && !local.equivalent(&remote) {
            self.compare_warned = false;
        }
        self.local.set_filters(local);
        self.remote.set_filters(remote);
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

    /// The quickconnect bar (history, T33).
    pub(crate) fn quickconnect_mut(&mut self) -> &mut Quickconnect {
        &mut self.quickconnect
    }

    /// Show `text` in the status bar for a few seconds.
    pub(crate) fn flash(&mut self, text: impl Into<String>) {
        self.status.flash(text, Instant::now());
    }

    /// A connection to `server` is being opened in the remote pane.
    pub(crate) fn remote_connecting(&mut self, server: String) {
        self.end_sync();
        self.end_compare();
        self.bookmark_modes = None;
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
        self.bookmark_modes = None;
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

    // --- T64: applying a bookmark ---

    /// Apply a bookmark: show its directories (the remote one only when
    /// connected), then turn synchronized browsing / comparison on as it
    /// says once both listings arrived. Both are turned off first so the
    /// panes move independently.
    pub(crate) fn apply_bookmark(&mut self, target: courier_ftp_core::sites::BookmarkTarget) {
        self.end_sync();
        self.end_compare();
        self.bookmark_modes = None;
        let mut waiting = PendingModes {
            local: false,
            remote: false,
            sync: target.sync_browsing,
            compare: target.comparison,
        };
        let mut problems = Vec::new();
        if let Some(local) = &target.local_dir {
            match courier_ftp_core::local::local_to_remote(local.as_path()) {
                Ok(dir) => {
                    if let Some(Effect::Action(a)) = self.local.go_to(dir) {
                        self.outbox.push(a);
                        waiting.local = true;
                    }
                }
                Err(e) => problems.push(format!("{}: {e}", local.to_display())),
            }
        }
        if let Some(remote) = &target.remote_dir {
            if self.remote.dir.is_some() {
                if let Some(Effect::Action(a)) = self.remote.go_to(remote.clone()) {
                    self.outbox.push(a);
                    waiting.remote = true;
                }
            } else {
                problems.push("Not connected: the remote directory was not opened".to_owned());
            }
        }
        self.set_focus(Region::list(if target.local_dir.is_none() {
            Side::Remote
        } else {
            self.opts.compact_side
        }));
        if let Some(problem) = problems.first() {
            // Synchronizing needs both directories: leave it off.
            self.status.flash(problem.clone(), Instant::now());
            return;
        }
        if !(waiting.sync || waiting.compare) {
            return;
        }
        if waiting.local || waiting.remote {
            self.bookmark_modes = Some(waiting);
        } else {
            self.bookmark_modes_on(&waiting);
        }
    }

    /// A listing for `side` arrived while a bookmark waits for it.
    fn bookmark_listing(&mut self, side: Side, ok: bool) {
        let Some(mut modes) = self.bookmark_modes.take() else {
            return;
        };
        let waited = match side {
            Side::Local => std::mem::take(&mut modes.local),
            Side::Remote => std::mem::take(&mut modes.remote),
        };
        if !waited {
            self.bookmark_modes = Some(modes);
            return;
        }
        if !ok {
            // The error is in the log; don't synchronize the wrong place.
            self.status.flash(
                "The bookmark's directory could not be opened",
                Instant::now(),
            );
            return;
        }
        if modes.local || modes.remote {
            self.bookmark_modes = Some(modes);
        } else {
            self.bookmark_modes_on(&modes);
        }
    }

    fn bookmark_modes_on(&mut self, modes: &PendingModes) {
        if modes.compare {
            self.start_compare();
        } else if modes.sync && self.start_sync() {
            self.status
                .flash("Synchronized browsing on", Instant::now());
        }
    }

    /// Whether synchronized browsing is on.
    #[cfg(test)]
    pub(crate) fn sync_on(&self) -> bool {
        self.sync.is_some()
    }

    /// Whether directory comparison is on.
    #[cfg(test)]
    pub(crate) fn compare_on(&self) -> bool {
        self.compare.is_some()
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
        self.queue.handle_core(&event, Instant::now());
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
            || self.sites.is_some()
            || self.settings.is_some()
            || self.sync_open()
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
        self.modals.push(Box::new(
            HelpOverlay::new(&format!("{mode:?}"), bindings)
                .with_notice(self.update_notice.clone()),
        ));
    }

    /// Draw everything.
    pub(crate) fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();
        if let Some(splash) = &self.splash {
            splash.draw(frame, area, &self.theme);
            return;
        }
        self.modals.retain(|m| !m.is_done());
        self.status.pending_prompts = self.prompts.len();
        let r = layout::compute(area, &self.opts);
        let now = Instant::now();
        let (stats, speed) = self.queue.stats(now);
        self.status.queue_files = stats.items as u64;
        self.status.queue_bytes = stats.bytes;
        self.status.queue_speed_bps = speed;
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
            let status = self
                .engine_status
                .as_ref()
                .map(|rx| rx.borrow().clone())
                .unwrap_or_default();
            let processing =
                courier_ftp_core::queue::lock_queue(self.queue.shared()).is_processing();
            self.queue.draw(
                frame,
                a,
                f == Region::Queue,
                super::queue::RunState {
                    processing,
                    paused: status.paused,
                },
                theme,
                now,
            );
        }
        if let Some(a) = r.status {
            status::draw(frame, a, &self.status, theme);
        }
        if let Some(a) = r.hint {
            panes::draw_hint(frame, a, theme);
        }
        if let Some(view) = self.sites.as_mut() {
            let bottom = r.status.map_or(area.bottom(), |s| s.y);
            let above = ratatui::layout::Rect::new(
                area.x,
                area.y,
                area.width,
                bottom.saturating_sub(area.y),
            );
            view.draw(frame, above, theme);
        }
        if let Some(menu) = self.bookmarks.as_mut() {
            menu.draw(frame, area, theme);
        }
        if let Some(view) = self.settings.as_mut() {
            let bottom = r.status.map_or(area.bottom(), |s| s.y);
            let above = ratatui::layout::Rect::new(
                area.x,
                area.y,
                area.width,
                bottom.saturating_sub(area.y),
            );
            view.draw(frame, above, theme);
        }
        // Over the settings screen when opened from its Sync page.
        #[cfg(feature = "sync")]
        if let Some(view) = self.sync_view.as_ref() {
            let bottom = r.status.map_or(area.bottom(), |s| s.y);
            let above = ratatui::layout::Rect::new(
                area.x,
                area.y,
                area.width,
                bottom.saturating_sub(area.y),
            );
            view.draw(frame, above, theme);
        }
        if let Some(view) = self.search.as_mut().filter(|v| !v.is_hidden()) {
            let bottom = r.status.map_or(area.bottom(), |s| s.y);
            let above = ratatui::layout::Rect::new(
                area.x,
                area.y,
                area.width,
                bottom.saturating_sub(area.y),
            );
            view.draw(frame, above, self.tick, theme);
        }
        for modal in &mut self.modals {
            modal.draw(frame, area, theme);
        }
    }
}
