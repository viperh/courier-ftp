//! T61: connection tabs.
//!
//! Each tab has its own connection, both panes (lists, trees, history),
//! synchronized browsing and comparison. The queue, vault, sites, bookmarks
//! and the message log are shared (the log hides the other tabs'
//! connections unless "all sessions" is on).
//!
//! The current tab's state is where it always was: [`App::remote`],
//! [`App::last_connect`] and the [`MainScreen`](crate::ui::MainScreen)'s
//! panes, so the rest of the app works on "the" connection. The other tabs
//! are parked in [`Tabs`] and swapped in when shown. Late results (a
//! listing, a connection) for a background tab are applied to it by
//! swapping it in for the moment ([`App::with_tab`]); what they ask for
//! next waits until the tab is shown. Results for a closed tab are dropped.
//!
//! With `interface.restore_tabs` the tabs (their sites or servers and
//! directories) are saved in the vault as a device-local blob when the app
//! quits and reopened after the next unlock.

use std::{collections::HashSet, time::Duration};

use courier_ftp_core::{
    backend::ConnectInfo,
    events::{LogKind, SessionId},
    model::{
        LogonType, Protocol, RemotePath, ServerAddress,
        item::{ItemId, LogonKind, SiteColor, WireEnum},
    },
    settings::TabConnect,
    sites::HistoryEntry,
    vault::DeviceBlobVault,
};
use serde::{Deserialize, Serialize};

use super::{App, Remote, server_label};
use crate::{
    action::{Action, ConnectRequest, ConnectTarget, Shared},
    ui::{
        Side, TabView,
        dialog::{Checkbox, Form, FormDialog, RadioGroup, prompt_text},
        tabs::{TabBar, TabLabel, TabState},
    },
    vault::Vault,
};

/// The device blob holding the tabs to restore.
const TABS_BLOB: &str = "tabs";
/// How long quitting waits for the tabs to be saved.
const SAVE_TIMEOUT: Duration = Duration::from_secs(2);

/// One tab. The current tab's `view`, `remote` and `last_connect` are
/// `None`: they live in the screen and the app while it is shown.
pub(super) struct Tab {
    pub(super) id: u64,
    /// A title the user gave it (otherwise the site name or `user@host`).
    pub(super) title: Option<String>,
    view: Option<TabView>,
    remote: Option<Remote>,
    last_connect: Option<ConnectRequest>,
    /// The last connection attempt failed (`!` in the tab bar).
    failed: bool,
    /// Every connection this tab opened, for the message log.
    sessions: Vec<SessionId>,
    /// What background results asked for, done when the tab is shown.
    pending: Vec<Action>,
}

impl Tab {
    fn new(id: u64, view: Option<TabView>) -> Self {
        Self {
            id,
            title: None,
            view,
            remote: None,
            last_connect: None,
            failed: false,
            sessions: Vec::new(),
            pending: Vec::new(),
        }
    }
}

/// All tabs (never none) and which one is shown.
pub(super) struct Tabs {
    pub(super) list: Vec<Tab>,
    pub(super) active: usize,
    next_id: u64,
    /// The saved tabs were (or are being) restored this run.
    pub(super) restored: bool,
    /// Saved tabs waiting for the sites to load.
    waiting: Option<Vec<SavedTab>>,
}

impl Default for Tabs {
    fn default() -> Self {
        Self {
            list: vec![Tab::new(1, None)],
            active: 0,
            next_id: 2,
            restored: false,
            waiting: None,
        }
    }
}

impl Tabs {
    /// The current tab's id.
    pub(super) fn current_id(&self) -> u64 {
        self.list.get(self.active).map_or(0, |t| t.id)
    }

    fn current(&mut self) -> Option<&mut Tab> {
        self.list.get_mut(self.active)
    }

    /// The current tab starts connecting as `session`.
    pub(super) fn connecting(&mut self, session: SessionId) {
        if let Some(tab) = self.current() {
            tab.failed = false;
            tab.sessions.push(session);
        }
    }

    /// The current tab's connection attempt failed.
    pub(super) fn failed(&mut self) {
        if let Some(tab) = self.current() {
            tab.failed = true;
        }
    }

    pub(super) fn len(&self) -> usize {
        self.list.len()
    }
}

/// A tab as saved for `interface.restore_tabs`: no secrets, only where it
/// was (a saved site, or a quickconnect server without its password).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SavedTab {
    #[serde(default)]
    pub(crate) title: Option<String>,
    /// The saved site's id.
    #[serde(default)]
    pub(crate) site: Option<String>,
    /// A quickconnect server.
    #[serde(default)]
    pub(crate) server: Option<SavedServer>,
    #[serde(default)]
    pub(crate) local_dir: Option<RemotePath>,
    #[serde(default)]
    pub(crate) remote_dir: Option<RemotePath>,
    /// The tab shown when the app quit.
    #[serde(default)]
    pub(crate) active: bool,
}

/// A quickconnect server of a [`SavedTab`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SavedServer {
    pub(crate) protocol: Protocol,
    pub(crate) host: String,
    pub(crate) port: u16,
    #[serde(default)]
    pub(crate) user: String,
    /// The history entry's logon kind (`normal` asks for the password).
    pub(crate) logon: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SavedTabs {
    version: u32,
    tabs: Vec<SavedTab>,
}

impl SavedServer {
    fn request(&self, remote_dir: Option<RemotePath>) -> ConnectRequest {
        let address = ServerAddress {
            protocol: self.protocol,
            host: self.host.clone(),
            port: self.port,
            user: None,
        };
        // No password: a normal login asks for it again.
        let mut entry =
            HistoryEntry::from_connect_info(&ConnectInfo::new(address, LogonType::Anonymous));
        entry.logon = LogonKind::from_wire(&self.logon).unwrap_or(LogonKind::AskForPassword);
        entry.user = self.user.clone();
        ConnectRequest {
            info: entry.to_connect_info(),
            path: remote_dir,
            sync_browsing: false,
            compare: false,
            site: None,
            local_dir: None,
        }
    }
}

/// Encode tabs for the vault blob.
pub(super) fn encode(tabs: &[SavedTab]) -> Vec<u8> {
    serde_json::to_vec(&SavedTabs {
        version: 1,
        tabs: tabs.to_vec(),
    })
    .unwrap_or_default()
}

/// Decode the vault blob (an unknown version or bad data: nothing).
pub(super) fn decode(bytes: &[u8]) -> Vec<SavedTab> {
    match serde_json::from_slice::<SavedTabs>(bytes) {
        Ok(saved) if saved.version == 1 => saved.tabs,
        _ => Vec::new(),
    }
}

impl App {
    // --- finding tabs ---

    /// The index of the tab with this id.
    pub(super) fn tab_index(&self, id: u64) -> Option<usize> {
        self.tabs.list.iter().position(|t| t.id == id)
    }

    /// The tab whose connection is `session` (the current one or a parked
    /// one).
    pub(super) fn tab_of_session(&self, session: SessionId) -> Option<usize> {
        if self.remote.as_ref().is_some_and(|r| r.session == session) {
            return Some(self.tabs.active);
        }
        self.tabs
            .list
            .iter()
            .position(|t| t.remote.as_ref().is_some_and(|r| r.session == session))
    }

    /// Tab `i`'s connection and last connect request, wherever they are.
    pub(super) fn tab_conn(&self, i: usize) -> (Option<&Remote>, Option<&ConnectRequest>) {
        if i == self.tabs.active {
            (self.remote.as_ref(), self.last_connect.as_ref())
        } else {
            self.tabs.list.get(i).map_or((None, None), |t| {
                (t.remote.as_ref(), t.last_connect.as_ref())
            })
        }
    }

    /// Whether any tab has a connection (open or opening).
    pub(super) fn any_connection(&self) -> bool {
        (0..self.tabs.len()).any(|i| self.tab_conn(i).0.is_some())
    }

    // --- swapping ---

    /// Exchange the current state with parked tab `i`'s (a no-op for the
    /// current tab). Doing it twice restores everything.
    fn swap_parked(&mut self, i: usize) {
        if i == self.tabs.active {
            return;
        }
        let Some(tab) = self.tabs.list.get_mut(i) else {
            return;
        };
        if let Some(view) = tab.view.as_mut() {
            self.screen.swap_tab(view);
        }
        std::mem::swap(&mut self.remote, &mut tab.remote);
        std::mem::swap(&mut self.last_connect, &mut tab.last_connect);
    }

    /// Run `f` with tab `i` as the current tab, then put everything back.
    /// What the screen asks for meanwhile waits in the tab until it is
    /// shown.
    pub(super) fn with_tab<R>(&mut self, i: usize, f: impl FnOnce(&mut Self) -> R) -> R {
        if i == self.tabs.active || i >= self.tabs.len() {
            return f(self);
        }
        let outbox = self.screen.take_actions();
        let shown = self.tabs.active;
        self.swap_parked(i);
        self.tabs.active = i;
        let result = f(self);
        let asked = self.screen.take_actions();
        self.tabs.active = shown;
        self.swap_parked(i);
        if let Some(tab) = self.tabs.list.get_mut(i) {
            tab.pending.extend(asked);
        }
        self.screen.restore_actions(outbox);
        result
    }

    /// A background result for tab `i`'s screen: the current tab handles it
    /// as usual, a parked one at once (what follows waits).
    pub(super) fn deliver_to_tab(&mut self, i: usize, action: Action) {
        if i == self.tabs.active {
            let _ = self.action_tx.send(action);
            return;
        }
        self.with_tab(i, |app| {
            if let Some(next) = app.screen.update(&action) {
                app.screen.restore_actions(vec![next]);
            }
        });
    }

    /// Show tab `i`.
    pub(super) fn activate(&mut self, i: usize) {
        let shown = self.tabs.active;
        if i == shown || i >= self.tabs.len() {
            return;
        }
        self.swap_parked(i);
        let tab = &mut self.tabs.list[i];
        let parked = (tab.view.take(), tab.remote.take(), tab.last_connect.take());
        let pending = std::mem::take(&mut tab.pending);
        let old = &mut self.tabs.list[shown];
        (old.view, old.remote, old.last_connect) = parked;
        self.tabs.active = i;
        // Changes made meanwhile (transfers, file operations) are in the
        // listing cache.
        for side in [Side::Local, Side::Remote] {
            if let Some(dir) = self.screen.pane_mut(side).dir.clone() {
                self.listing_patched(side, &dir);
            }
        }
        for action in pending {
            let _ = self.action_tx.send(action);
        }
        self.refresh_tabs();
    }

    // --- the tab bar and log ---

    /// What the tab bar shows for tab `i`.
    fn tab_label(&self, i: usize) -> TabLabel {
        let Some(tab) = self.tabs.list.get(i) else {
            return TabLabel::local();
        };
        let (remote, last) = self.tab_conn(i);
        let failed = remote.is_none() && tab.failed;
        let site = remote
            .and_then(|r| r.site)
            .or_else(|| last.filter(|_| failed).and_then(|l| l.site))
            .and_then(|id| self.site_snapshot.as_ref()?.tree.site(id));
        let auto = match (site, remote) {
            (Some(site), _) => site.name.clone(),
            (None, Some(r)) => server_label(&r.info.address),
            (None, None) => match last.filter(|_| failed) {
                Some(l) => server_label(&l.info.address),
                None => "local".to_owned(),
            },
        };
        TabLabel {
            title: tab.title.clone().unwrap_or(auto),
            state: match remote {
                Some(r) if r.connected => TabState::Connected,
                Some(_) => TabState::Connecting,
                None if failed => TabState::Error,
                None => TabState::Disconnected,
            },
            color: site.map_or(SiteColor::None, |s| s.color),
        }
    }

    /// Bring the tab bar and the message log's filter up to date.
    pub(super) fn refresh_tabs(&mut self) {
        let labels = (0..self.tabs.len()).map(|i| self.tab_label(i)).collect();
        self.screen.set_tab_bar(TabBar {
            labels,
            active: self.tabs.active,
        });
        let hidden: HashSet<SessionId> = self
            .tabs
            .list
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != self.tabs.active)
            .flat_map(|(_, t)| t.sessions.iter().copied())
            .collect();
        self.screen.set_log_hidden(hidden);
    }

    // --- actions ---

    pub(super) fn tab_action(&mut self, action: &Action) {
        match action {
            Action::NewTab => {
                let local = self.screen.local.dir.clone();
                self.new_tab(local);
            }
            Action::CloseTab => self.close_tab(self.tabs.active, false),
            Action::CloseTabNow { tab } => {
                if let Some(i) = self.tab_index(*tab) {
                    self.close_tab(i, true);
                }
            }
            Action::NextTab | Action::PrevTab => {
                let n = self.tabs.len();
                let step = if matches!(action, Action::NextTab) {
                    1
                } else {
                    n - 1
                };
                self.activate((self.tabs.active + step) % n);
            }
            Action::Tab1
            | Action::Tab2
            | Action::Tab3
            | Action::Tab4
            | Action::Tab5
            | Action::Tab6
            | Action::Tab7
            | Action::Tab8
            | Action::Tab9 => {
                let n = tab_number(action);
                if n <= self.tabs.len() {
                    self.activate(n - 1);
                } else {
                    self.screen.flash(format!("There is no tab {n}"));
                }
            }
            Action::RenameTab => self.rename_tab(),
            Action::TabRenamed { tab, title } => {
                if let Some(i) = self.tab_index(*tab) {
                    let title = title.trim();
                    self.tabs.list[i].title = (!title.is_empty()).then(|| title.to_owned());
                }
            }
            Action::DuplicateTab => self.duplicate_tab(),
            Action::SetConnectChoice(choice) => {
                self.settings.interface.connect_in_tab = *choice;
                let settings = self.settings.clone();
                self.screen.apply_settings(&settings);
                self.save_settings();
            }
            Action::TabsLoaded(saved) => self.tabs_loaded(saved.0.as_ref().clone()),
            // The sites are loaded: saved site tabs can connect now.
            Action::SitesReply(reply) if reply.0.snapshot.is_some() => {
                if let Some(saved) = self.tabs.waiting.take() {
                    self.open_saved(saved);
                }
            }
            _ => {}
        }
    }

    /// Open a disconnected tab showing `local` (the home directory when
    /// `None`) and show it.
    pub(super) fn new_tab(&mut self, local: Option<RemotePath>) {
        self.add_tab();
        self.list(Side::Local, local, false, false);
    }

    /// Open an empty tab and show it.
    fn add_tab(&mut self) {
        let view = self.screen.new_tab_view();
        let id = self.tabs.next_id;
        self.tabs.next_id += 1;
        self.tabs.list.push(Tab::new(id, Some(view)));
        self.activate(self.tabs.len() - 1);
    }

    /// Close tab `i`: its connection closes (queued transfers keep their
    /// own). A connected tab asks first unless `confirmed`. The last tab is
    /// replaced by an empty one.
    fn close_tab(&mut self, i: usize, confirmed: bool) {
        let Some(id) = self.tabs.list.get(i).map(|t| t.id) else {
            return;
        };
        if !confirmed && let Some(remote) = self.tab_conn(i).0 {
            let (modal, rx) = crate::ui::dialog::confirm(
                "Close tab",
                &format!(
                    "Close this tab and disconnect from {}?\n\
                     Transfers already queued keep running.",
                    server_label(&remote.info.address)
                ),
                true,
            );
            self.screen.push_modal(modal);
            let tx = self.action_tx.clone();
            tokio::spawn(async move {
                if let Ok(true) = rx.await {
                    let _ = tx.send(Action::CloseTabNow { tab: id });
                }
            });
            return;
        }
        self.with_tab(i, Self::disconnect);
        if self.tabs.len() == 1 {
            let local = self.screen.local.dir.clone();
            self.new_tab(local);
        } else if i == self.tabs.active {
            self.activate(if i + 1 < self.tabs.len() {
                i + 1
            } else {
                i - 1
            });
        }
        let Some(i) = self.tab_index(id) else {
            return;
        };
        self.tabs.list.remove(i);
        if i < self.tabs.active {
            self.tabs.active -= 1;
        }
        self.refresh_tabs();
    }

    /// Ask for the current tab's title.
    fn rename_tab(&mut self) {
        let current = self.tab_label(self.tabs.active).title;
        let (modal, rx) = prompt_text("Rename tab", "Title (empty: automatic)", &current);
        self.screen.push_modal(modal);
        let tab = self.tabs.current_id();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            if let Ok(Some(title)) = rx.await {
                let _ = tx.send(Action::TabRenamed { tab, title });
            }
        });
    }

    /// A new tab connected to the current tab's server, in the same
    /// directories.
    fn duplicate_tab(&mut self) {
        let Some(remote) = self.remote.as_ref() else {
            let local = self.screen.local.dir.clone();
            self.new_tab(local);
            return;
        };
        let request = ConnectRequest {
            info: remote.info.clone(),
            path: self.screen.remote.dir.clone(),
            sync_browsing: false,
            compare: false,
            site: remote.site,
            local_dir: None,
        };
        let local = self.screen.local.dir.clone();
        self.new_tab(local);
        self.start_connect(request);
    }

    // --- connecting ---

    /// Connect a tab as `target` says (T58/T59/T61).
    pub(super) fn connect(&mut self, request: ConnectRequest, target: ConnectTarget) {
        match target {
            ConnectTarget::Current => self.start_connect(request),
            ConnectTarget::NewTab => self.connect_in_new_tab(request),
            ConnectTarget::Tab(id) => {
                if let Some(i) = self.tab_index(id) {
                    self.with_tab(i, |app| app.start_connect(request));
                }
            }
            ConnectTarget::Ask if self.remote.is_none() => self.start_connect(request),
            ConnectTarget::Ask => match self.settings.interface.connect_in_tab {
                TabConnect::NewTab => self.connect_in_new_tab(request),
                TabConnect::Replace => self.start_connect(request),
                TabConnect::Ask => self.ask_connect_target(request),
            },
        }
    }

    fn connect_in_new_tab(&mut self, request: ConnectRequest) {
        // The site's local directory (listed by `start_connect`), or the
        // current one.
        if request.local_dir.is_some() {
            self.add_tab();
        } else {
            let local = self.screen.local.dir.clone();
            self.new_tab(local);
        }
        self.start_connect(request);
    }

    /// The current tab is connected: open in a new tab or replace the
    /// connection? "Remember my choice" sets `interface.connect_in_tab`.
    fn ask_connect_target(&mut self, request: ConnectRequest) {
        let current = self
            .remote
            .as_ref()
            .map(|r| server_label(&r.info.address))
            .unwrap_or_default();
        let form = Form::new(&["Connect", "Cancel"])
            .field(
                "target",
                RadioGroup::new(
                    "Connect in",
                    vec![
                        "a new tab".to_owned(),
                        format!("this tab (closes {current})"),
                    ],
                    0,
                ),
            )
            .field("remember", Checkbox::new("Remember my choice", false));
        let (dialog, rx) = FormDialog::new(
            format!("Connect to {}", server_label(&request.info.address)),
            76,
            form,
            |v| Ok((v.index("target").unwrap_or(0), v.bool("remember"))),
        );
        self.screen.push_modal(Box::new(dialog));
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            if let Ok(Some((choice, remember))) = rx.await {
                let (target, setting) = if choice == 0 {
                    (ConnectTarget::NewTab, TabConnect::NewTab)
                } else {
                    (ConnectTarget::Current, TabConnect::Replace)
                };
                if remember {
                    let _ = tx.send(Action::SetConnectChoice(setting));
                }
                let _ = tx.send(Action::Connect {
                    request: Box::new(request),
                    target,
                });
            }
        });
    }

    /// Close every tab's connection, keeping the tabs (T45 "Disconnect",
    /// `vault.lock_disconnects`).
    pub(super) fn disconnect_all(&mut self) {
        for i in 0..self.tabs.len() {
            if self.tab_conn(i).0.is_some() {
                self.with_tab(i, Self::disconnect);
            }
        }
    }

    // --- saving and restoring ---

    /// The tabs as saved for `interface.restore_tabs`.
    pub(super) fn saved_tabs(&self) -> Vec<SavedTab> {
        (0..self.tabs.len())
            .map(|i| {
                let tab = &self.tabs.list[i];
                let (remote, last) = self.tab_conn(i);
                let (local_dir, remote_dir) = if i == self.tabs.active {
                    (
                        self.screen.local.dir.clone(),
                        self.screen.remote.dir.clone(),
                    )
                } else {
                    let view = tab.view.as_ref();
                    (
                        view.and_then(|v| v.local_dir().cloned()),
                        view.and_then(|v| v.remote_dir().cloned()),
                    )
                };
                let (site, info) = match (remote, last) {
                    (Some(r), _) => (r.site, Some(&r.info)),
                    (None, Some(l)) => (l.site, Some(&l.info)),
                    (None, None) => (None, None),
                };
                let server = info.filter(|_| site.is_none()).map(|info| {
                    let entry = HistoryEntry::from_connect_info(info);
                    SavedServer {
                        protocol: entry.protocol,
                        host: entry.host,
                        port: entry.port,
                        user: entry.user,
                        logon: entry.logon.as_wire().to_owned(),
                    }
                });
                SavedTab {
                    title: tab.title.clone(),
                    site: site.map(|id| id.to_string()),
                    server,
                    local_dir,
                    // Only a connected tab has a remote directory to go back to.
                    remote_dir: remote.and(remote_dir),
                    active: i == self.tabs.active,
                }
            })
            .collect()
    }

    /// Save the tabs in the vault (when quitting), or delete saved ones
    /// when `interface.restore_tabs` is off.
    pub(crate) async fn save_tabs(&self) {
        let Some(engine) = self.vault.as_ref().and_then(Vault::engine).cloned() else {
            return;
        };
        let result = if self.settings.interface.restore_tabs {
            let bytes = encode(&self.saved_tabs());
            tokio::time::timeout(SAVE_TIMEOUT, engine.save_blob(TABS_BLOB, &bytes))
                .await
                .map(|r| r.map(|()| true))
        } else {
            tokio::time::timeout(SAVE_TIMEOUT, engine.delete_blob(TABS_BLOB)).await
        };
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::debug!(error = %e, "tabs not saved"),
            Err(_) => tracing::debug!("saving the tabs timed out"),
        }
    }

    /// After the first unlock: read the saved tabs (`interface.restore_tabs`).
    pub(super) fn restore_tabs(&mut self) {
        if !self.settings.interface.restore_tabs || self.tabs.restored {
            return;
        }
        let Some(engine) = self.vault.as_ref().and_then(Vault::engine).cloned() else {
            return;
        };
        self.tabs.restored = true;
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            match engine.load_blob(TABS_BLOB).await {
                Ok(Some(bytes)) => {
                    let _ = tx.send(Action::TabsLoaded(Shared::new(decode(&bytes))));
                }
                Ok(None) => {}
                Err(e) => tracing::debug!(error = %e, "saved tabs not read"),
            }
        });
    }

    /// The saved tabs were read: open them once the sites are loaded.
    fn tabs_loaded(&mut self, saved: Vec<SavedTab>) {
        if saved.is_empty() {
            return;
        }
        if self.site_snapshot.is_some() {
            self.open_saved(saved);
        } else {
            self.tabs.waiting = Some(saved);
        }
    }

    /// Reopen saved tabs: the first goes into the current tab when it is
    /// the only one and not connected.
    fn open_saved(&mut self, saved: Vec<SavedTab>) {
        let reuse = self.tabs.len() == 1 && self.remote.is_none();
        let mut shown = None;
        for (n, tab) in saved.into_iter().enumerate() {
            if n == 0 && reuse {
                if tab.local_dir.is_some() {
                    self.list(Side::Local, tab.local_dir.clone(), false, false);
                }
            } else {
                let local = tab.local_dir.clone().or(self.screen.local.dir.clone());
                self.new_tab(local);
            }
            let id = self.tabs.current_id();
            if let Some(current) = self.tabs.current() {
                current.title = tab.title.clone();
            }
            if tab.active {
                shown = Some(self.tabs.active);
            }
            match (tab.site.as_deref().map(str::parse::<ItemId>), &tab.server) {
                (Some(Ok(site)), _) => self.connect_saved_site(site, id, tab.remote_dir),
                (_, Some(server)) => {
                    self.start_connect(server.request(tab.remote_dir));
                }
                _ => {}
            }
        }
        if let Some(i) = shown {
            self.activate(i);
        }
        self.events_tx
            .log(self.local_session, LogKind::Status, "Tabs restored");
    }

    /// Connect restored tab `tab` to a saved site, in `remote_dir` (else the
    /// site's directory).
    fn connect_saved_site(&mut self, site: ItemId, tab: u64, remote_dir: Option<RemotePath>) {
        let slot = std::sync::Arc::clone(&self.sites);
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            match crate::sites::connect(&slot, site).await {
                Ok(connect) => {
                    let request = ConnectRequest {
                        info: connect.info,
                        path: remote_dir.or(connect.remote_dir),
                        sync_browsing: connect.sync_browsing,
                        compare: connect.directory_comparison,
                        site: Some(site),
                        local_dir: None,
                    };
                    let _ = tx.send(Action::Connect {
                        request: Box::new(request),
                        target: ConnectTarget::Tab(tab),
                    });
                }
                Err(e) => {
                    let _ = tx.send(Action::Error(format!("Could not reopen a tab's site: {e}")));
                }
            }
        });
    }
}

/// 1 for `Tab1` … 9 for `Tab9`.
fn tab_number(action: &Action) -> usize {
    match action {
        Action::Tab1 => 1,
        Action::Tab2 => 2,
        Action::Tab3 => 3,
        Action::Tab4 => 4,
        Action::Tab5 => 5,
        Action::Tab6 => 6,
        Action::Tab7 => 7,
        Action::Tab8 => 8,
        _ => 9,
    }
}
