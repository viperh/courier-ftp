use courier_ftp_core::backend::Listing;
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
    /// Put text on the clipboard (OSC 52) and say so in the status bar.
    #[serde(skip)]
    CopyToClipboard(String),
    /// A directory listing finished in the background.
    #[serde(skip)]
    ListingLoaded {
        side: Side,
        result: Result<Listing, String>,
    },
}
