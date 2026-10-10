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
    /// Delete the selection, with confirmation (T62).
    Delete,
    /// Open the settings screen (T68).
    Settings,
    /// Open the Site Manager (T59).
    SiteManager,
    /// Re-list the directories shown in both panes.
    Refresh,
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
    /// Directory comparison on/off (T66).
    ToggleCompare,
    /// Search (T65).
    Search,
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

    // --- background results ---
    /// List a directory for a pane (through the listing cache unless `force`).
    #[serde(skip)]
    ListDir {
        side: Side,
        dir: courier_ftp_core::model::RemotePath,
        force: bool,
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
    /// Put text on the clipboard (OSC 52) and say so in the status bar.
    #[serde(skip)]
    CopyToClipboard(String),
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
    /// A connection attempt started by [`Action::Connect`] finished.
    #[serde(skip)]
    Connected {
        session: SessionId,
        result: Result<Box<Connected>, String>,
    },
    /// A remote listing finished; dropped when `session` is no longer the
    /// current connection.
    #[serde(skip)]
    RemoteListingLoaded {
        session: SessionId,
        result: Result<Listing, String>,
    },
}

/// What to connect to, from the quickconnect bar.
#[derive(Debug, Clone)]
pub(crate) struct ConnectRequest {
    pub(crate) info: ConnectInfo,
    /// The directory to open instead of the home directory.
    pub(crate) path: Option<RemotePath>,
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

/// A successful connection: what the status bar shows and the first listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Connected {
    pub(crate) info: Option<SessionInfo>,
    pub(crate) listing: Listing,
}
