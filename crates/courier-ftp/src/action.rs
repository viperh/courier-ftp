use courier_ftp_core::{
    backend::{ConnectInfo, Listing, SessionInfo},
    events::SessionId,
    model::{LogonType, RemotePath},
};
use serde::{Deserialize, Serialize};
use strum::Display;

use crate::ui::Side;

/// Messages passed between the event loop, [`App`](crate::app::App) and the
/// [`MainScreen`](crate::ui::MainScreen).
///
/// Unit variants can be bound to keys in the config by name
/// (`"<F1>": "Help"`); the default keymap is in `config/default.json` and
/// documented in `docs/keybindings.md` (T51). Many actions are bindable before
/// the task that implements them lands; until then they do nothing. Variants
/// marked `#[serde(skip)]` carry results of background tasks.
#[derive(Debug, Clone, PartialEq, Eq, Display, Serialize, Deserialize)]
pub(crate) enum Action {
    // --- event loop ---
    Tick,
    Render,
    Resize(u16, u16),
    Suspend,
    Resume,
    Quit,
    ClearScreen,
    Error(String),

    // --- global ---
    /// Show the keybindings of the current mode.
    Help,
    /// Close the topmost dialog.
    CloseDialog,
    /// Rename the entry under the cursor (T62).
    Rename,
    /// View the file under the cursor (T63).
    View,
    /// Edit the file under the cursor in an external editor (T63).
    Edit,
    /// The files being edited: upload now, stop watching, discard (T63).
    EditedFiles,
    /// Transfer the selection to the other pane (T62).
    Copy,
    /// Add the selection to the queue without starting it (T62).
    QueueSelection,
    /// Transfer, then delete the source; rename on the same side (T62).
    Move,
    /// Make a directory (T62).
    Mkdir,
    /// Make a directory and enter it (T62).
    MkdirEnter,
    /// Create an empty file (T62).
    NewFile,
    /// Delete the selection, with confirmation (T62).
    Delete,
    /// Open the settings screen (T68).
    Settings,
    /// Open the Site Manager (T59).
    SiteManager,
    /// Pick a saved site by typing part of its name and connect (T59).
    SitePicker,
    /// Open the Site Manager with a new site prefilled from the current
    /// quickconnect connection, password included (T58 §7, T59).
    SaveAsSite,
    /// Re-list the directories shown in both panes.
    Refresh,
    /// Show the raw listing (LIST/MLSD text, SFTP long names) of the focused
    /// pane's directory (T71).
    ShowRawListing,
    NewTab,
    CloseTab,
    NextTab,
    PrevTab,
    Tab1,
    Tab2,
    Tab3,
    Tab4,
    Tab5,
    Tab6,
    Tab7,
    Tab8,
    Tab9,
    /// Synchronized browsing on/off (T66).
    ToggleSyncBrowsing,
    /// Directory comparison on/off (T66). Also turns synchronized browsing on.
    ToggleCompare,
    /// Directory comparison options: by size or time, threshold, hide
    /// identical files (T66).
    CompareOptions,
    /// While comparing, select the entries only on this side (yellow).
    SelectCompareLonely,
    /// While comparing, select the newer files on this side (green).
    SelectCompareNewer,
    /// While comparing, select the files whose size differs (red).
    SelectCompareDifferent,
    /// Search (T65).
    Search,
    /// The directory listing filters dialog: which filters are active on
    /// each side, filter sets, and the filter editor (T67).
    Filters,
    /// Bookmarks menu (T64).
    Bookmarks,
    /// Disconnect the current tab. Default `<Ctrl-x><d>`: `Ctrl-d` is the
    /// vim half-page-down key in file lists.
    Disconnect,
    /// Connect again to the last server of this run (T58). The password is
    /// asked for again: it isn't kept in the history.
    Reconnect,
    /// Start or stop processing the queue (T41).
    ProcessQueue,
    ToggleLog,
    ToggleQueue,
    ToggleTree,
    ToggleQuickconnect,
    /// Show or hide hidden files (T53).
    ToggleHidden,
    /// Speed limits on/off (status bar, T44).
    ToggleSpeedLimit,
    /// Auto → ASCII → Binary transfer type (status bar).
    CycleTransferType,
    /// Protocol, software and encryption details of the current tab.
    ServerInfo,
    /// Open the next waiting prompt (host key, certificate, password…) now
    /// instead of when the user is idle (T69).
    OpenPrompt,
    /// Lock the vault now (T60): keys are dropped and the unlock view covers
    /// the panes.
    LockVault,
    /// Show the unlock view after "Continue without vault" (T60).
    UnlockVault,
    /// The device sync panel (T90): status, "sync now", the account and
    /// devices screens, or the wizard that connects this device to a sync
    /// server. Builds without the `sync` feature say so.
    SyncPanel,

    // --- focus ---
    /// `Tab`: switch between the two file lists (Midnight Commander style).
    FocusNext,
    /// `Shift-Tab`: the same, backwards.
    FocusPrev,
    FocusLocal,
    FocusRemote,
    FocusLog,
    FocusQueue,
    FocusQuickconnect,
    /// Move focus between a file list and the directory tree of the same
    /// side, showing the trees when they are hidden (T54).
    FocusTree,

    // --- file list, log and queue navigation (T53/T55/T56) ---
    CursorDown,
    CursorUp,
    Top,
    Bottom,
    HalfPageDown,
    HalfPageUp,
    PageDown,
    PageUp,
    /// Go to the parent directory.
    ParentDir,
    /// Enter a directory, or transfer a file (FileZilla's double-click).
    Open,
    /// Toggle the selection of the entry under the cursor and move down.
    ToggleSelect,
    /// Range selection mode.
    VisualSelect,
    InvertSelection,
    SelectPattern,
    DeselectPattern,
    SelectAll,
    /// Start typing the pane's quick filter.
    QuickFilter,
    SortName,
    SortSize,
    SortModified,
    SortPermissions,
    SortOwner,
    /// Enter a raw server command (T62).
    CommandLine,
    /// Copy the URL of the entry under the cursor (T62).
    CopyUrl,
    /// Change permissions (T62).
    Chmod,
    /// Type a path into the pane's address bar (T53).
    EditAddress,
    /// Show the equivalent directory in the other pane.
    MirrorDir,
    /// Previous / next directory in the pane's history.
    HistoryBack,
    HistoryForward,
    /// Choose the pane's columns.
    ColumnMenu,

    // --- message log (T55) ---
    /// Next / previous search match.
    SearchNext,
    SearchPrev,
    /// Copy the selected lines to the clipboard (OSC 52).
    CopySelection,
    /// Copy the whole log (as the filters show it) to the clipboard (T71).
    CopyLog,
    /// Save the log (as the filters show it) to a file (T71).
    SaveLog,
    ClearLog,
    /// Wrap long lines on/off.
    ToggleWrap,
    /// All sessions' messages, or only the current tab's.
    ToggleLogAll,
    /// Only errors, or everything.
    ToggleErrorsOnly,
    ScrollLeft,
    ScrollRight,

    // --- queue (T56) ---
    /// Pause or resume the item under the cursor.
    QueueToggleItem,
    PriorityUp,
    PriorityDown,
    MoveItemUp,
    MoveItemDown,
    RemoveItem,
    /// Reset failed items and queue them again.
    Requeue,
    QueueTabQueued,
    QueueTabFailed,
    QueueTabSuccessful,
    /// Move the selected items to the top / bottom of the queue.
    MoveItemTop,
    MoveItemBottom,
    /// Empty the current tab (the queued tab asks first).
    QueueClear,
    /// Group the queued tab under server headers, or not.
    QueueGroupByServer,
    /// Every queue action for the selection, as a menu.
    QueueMenu,
    /// Set the "file exists" action of the selected items.
    QueueExistsMenu,
    /// Choose what happens when the queue finishes this time (T45).
    QueueAfterMenu,
    /// Hold every running transfer mid-stream, or let them continue.
    ToggleTransfersPaused,

    // --- background results ---
    /// The update check found a newer release (T74).
    #[serde(skip)]
    UpdateAvailable(crate::update::UpdateInfo),
    /// The queue pane changed the queue: cancel `cancel` (removed or paused
    /// while running), schedule the save and, with `wake`, look for work.
    #[serde(skip)]
    QueueEdited {
        cancel: Vec<courier_ftp_core::events::TransferId>,
        wake: bool,
    },
    /// The "file exists" action chosen for the selected items (`None`: the
    /// setting).
    #[serde(skip)]
    QueueSetExists(Option<courier_ftp_core::settings::ExistsAction>),
    /// "Remove all" was confirmed.
    #[serde(skip)]
    QueueRemoveAll,
    /// The saved queue was merged in after unlock (how many items).
    #[serde(skip)]
    QueueRestored(Result<usize, String>),
    /// A settings or vault backup was opened or restored (T73).
    #[serde(skip)]
    Archive(Shared<crate::archive::ArchiveMsg>),
    /// What quitting now would lose.
    #[serde(skip)]
    QuitChecked {
        check: courier_ftp_core::queue::QuitCheck,
        active: usize,
    },
    /// Quit without asking (confirmed).
    #[serde(skip)]
    QuitNow,
    /// List a directory for a pane (through the listing cache unless `force`).
    #[serde(skip)]
    ListDir {
        side: Side,
        dir: courier_ftp_core::model::RemotePath,
        force: bool,
    },
    /// List a directory for a side's directory tree (through the cache).
    #[serde(skip)]
    TreeListDir {
        side: Side,
        dir: courier_ftp_core::model::RemotePath,
    },
    /// A listing asked for by [`Action::TreeListDir`] finished.
    #[serde(skip)]
    TreeListingLoaded {
        side: Side,
        dir: courier_ftp_core::model::RemotePath,
        result: Result<Listing, String>,
    },
    /// Select (or deselect) the entries matching a glob.
    #[serde(skip)]
    ApplyPattern {
        side: Side,
        pattern: String,
        select: bool,
    },
    /// The columns chosen in the column menu.
    #[serde(skip)]
    SetColumns {
        side: Side,
        columns: Vec<courier_ftp_core::settings::Column>,
    },
    /// Filters applied in the filters dialog: re-filter both panes and save
    /// the settings (T67).
    #[serde(skip)]
    SetFilters(Box<courier_ftp_core::filters::FilterSettings>),
    /// New directory comparison options (from the options dialog).
    #[serde(skip)]
    SetCompareOptions(Box<courier_ftp_core::compare::CompareOpts>),
    /// The answer to a synchronized browsing question.
    #[serde(skip)]
    SyncAnswer(SyncChoice),
    /// Create a directory (synchronized browsing's "create it").
    #[serde(skip)]
    MakeDir {
        side: Side,
        dir: RemotePath,
    },
    /// A directory asked for by [`Action::MakeDir`] was created (or not).
    #[serde(skip)]
    DirMade {
        side: Side,
        dir: RemotePath,
        result: Result<(), String>,
    },
    /// The one-shot action after the queue finishes (`None`: the
    /// `queue.on_complete` setting, T45).
    #[serde(skip)]
    QueueSetAfter(Option<courier_ftp_core::settings::OnComplete>),
    /// Ask for the command to run when the queue finishes this time.
    #[serde(skip)]
    QueueAskCommand(String),
    /// The countdown before disconnecting or quitting after the queue
    /// finished ran out.
    #[serde(skip)]
    QueueAfterDue(courier_ftp_core::settings::OnComplete),
    /// The command run after the queue finished exited (its code; `None`:
    /// killed by a signal) or couldn't be started.
    #[serde(skip)]
    QueueAfterCommandExited(Result<Option<i32>, String>),
    /// A step or result of a file operation (T62).
    #[serde(skip)]
    FileOp(Shared<crate::app::FileOpMsg>),
    /// A step or result of viewing / editing a file (T63).
    #[serde(skip)]
    EditMsg(Shared<crate::app::EditMsg>),
    /// Run a program in the terminal: the event loop suspends the TUI,
    /// waits for it and restores the TUI (T63).
    #[serde(skip)]
    RunForeground(Shared<crate::edit::Foreground>),
    /// Put text on the clipboard (OSC 52) and say so in the status bar.
    #[serde(skip)]
    CopyToClipboard(String),
    /// Ask where to save this log text (T71).
    #[serde(skip)]
    SaveLogText(String),
    /// "Save log as…" finished.
    #[serde(skip)]
    LogSaved {
        path: std::path::PathBuf,
        result: Result<(), String>,
    },
    /// A directory listing finished in the background.
    #[serde(skip)]
    ListingLoaded {
        side: Side,
        result: Result<Listing, String>,
    },
    /// Connect the remote pane (quickconnect, T58). With `replace` an
    /// existing connection is closed without asking.
    #[serde(skip)]
    Connect {
        request: Box<ConnectRequest>,
        replace: bool,
    },
    /// Open the quickconnect history (the bar's `[▾]`, T33).
    #[serde(skip)]
    QuickconnectHistory,
    /// A quickconnect history entry was picked: fill the bar and connect.
    #[serde(skip)]
    HistoryPicked(Box<ConnectRequest>),
    /// "Clear history" was picked in the quickconnect history.
    #[serde(skip)]
    ClearHistory,
    /// The quickconnect history was (re)loaded from the vault.
    #[serde(skip)]
    HistoryLoaded(Vec<crate::ui::HistoryItem>),
    /// A sync background call finished or the sync engine reported
    /// something (T90).
    #[cfg(feature = "sync")]
    #[serde(skip)]
    Sync(Shared<crate::sync::Once<crate::sync::SyncMsg>>),
    /// The Site Manager screen asks for an operation (T59).
    #[serde(skip)]
    SiteOp(Shared<crate::sites::SiteOp>),
    /// A Site Manager operation finished.
    #[serde(skip)]
    SitesReply(Shared<crate::sites::SitesReply>),
    /// The bookmarks menu asks for an operation (T64).
    #[serde(skip)]
    BookmarkOp(Shared<crate::bookmarks::BookmarkOp>),
    /// A bookmarks operation finished.
    #[serde(skip)]
    BookmarksReply(Shared<crate::bookmarks::BookmarksReply>),
    /// The settings screen asks for something (T68).
    #[serde(skip)]
    SettingsRequest(Shared<crate::ui::settings::SettingsRequest>),
    /// The answer to a settings screen request.
    #[serde(skip)]
    SettingsReply(Shared<crate::ui::settings::SettingsReply>),
    /// The search view asks for something (T65).
    #[serde(skip)]
    SearchRequest(Shared<crate::ui::search::SearchRequest>),
    /// News from search `run` (results, progress, the end, deletions);
    /// dropped when another search started since.
    #[serde(skip)]
    SearchUpdate {
        run: u64,
        update: Shared<crate::ui::search::SearchUpdate>,
    },
    /// A connection attempt started by [`Action::Connect`] finished.
    #[serde(skip)]
    Connected {
        session: SessionId,
        result: Result<Box<Connected>, String>,
    },
    /// A remote listing of `dir` finished, for the file list or (with
    /// `tree`) the directory tree; dropped when `session` is no longer the
    /// current connection.
    #[serde(skip)]
    RemoteListingLoaded {
        session: SessionId,
        dir: RemotePath,
        tree: bool,
        result: Result<Listing, String>,
    },
}

/// What the user chose when synchronized browsing asked (T66).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncChoice {
    /// Create the missing directory on the other side and go on.
    Create,
    /// Turn synchronized browsing off and go on in this pane only.
    Disable,
    /// Don't change directory.
    Stay,
}

/// What to connect to, from the quickconnect bar.
#[derive(Debug, Clone)]
pub(crate) struct ConnectRequest {
    pub(crate) info: ConnectInfo,
    /// The directory to open instead of the home directory.
    pub(crate) path: Option<RemotePath>,
    /// Turn synchronized browsing on once connected (site setting, bookmark).
    pub(crate) sync_browsing: bool,
    /// Turn directory comparison on once connected (site setting, bookmark).
    pub(crate) compare: bool,
    /// The Site Manager entry connected to (`None` for quickconnect).
    pub(crate) site: Option<courier_ftp_core::model::item::ItemId>,
}

impl ConnectRequest {
    /// The request with its password removed, for the reconnect history: the
    /// password is asked for again (T58 §6; T33 stores it in the vault when
    /// `vault.store_passwords` allows).
    pub(crate) fn without_password(&self) -> Self {
        let mut request = self.clone();
        request.info.logon = match &self.info.logon {
            LogonType::Normal { user, .. } | LogonType::Account { user, .. } => {
                LogonType::AskForPassword { user: user.clone() }
            }
            other => other.clone(),
        };
        request
    }
}

impl PartialEq for ConnectRequest {
    /// Address, logon type (passwords are compared, never shown) and path.
    fn eq(&self, other: &Self) -> bool {
        self.info == other.info && self.path == other.path
    }
}

impl Eq for ConnectRequest {}

/// A value carried by an action that can't be compared or serialized (a
/// background task's request or result). Two `Shared` values are equal only
/// when they are the same allocation.
pub(crate) struct Shared<T>(pub(crate) std::sync::Arc<T>);

// By hand: cloning shares the allocation, so `T` needn't be `Clone`.
impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(std::sync::Arc::clone(&self.0))
    }
}

impl<T> Shared<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(std::sync::Arc::new(value))
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Shared<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T> PartialEq for Shared<T> {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<T> Eq for Shared<T> {}

/// A successful connection: what the status bar shows and the first listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Connected {
    pub(crate) info: Option<SessionInfo>,
    pub(crate) listing: Listing,
    /// What the backend supports (operations it can't do are explained
    /// instead of failing, T62).
    pub(crate) capabilities: courier_ftp_core::backend::Capabilities,
}
