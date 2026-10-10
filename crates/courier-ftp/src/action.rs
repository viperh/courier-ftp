//! Actions: messages between the event loop, the app and components, and the registry
//! of bindable actions (names, descriptions, groups, owners; T51).

use serde::{Deserialize, Serialize};
use strum::{Display, VariantNames};

use crate::{
    components::{
        file_list::{PaneId, PaneInput, PaneRequest},
        main_screen::layout::Region,
    },
    runtime::TaskId,
};

/// Help-overlay and documentation group of a bindable action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, strum::EnumIter)]
pub(crate) enum Group {
    /// Help, quit, settings.
    General,
    /// Moving the focus between regions.
    Focus,
    /// Showing and hiding regions, layouts.
    View,
    /// Connection tabs.
    Tabs,
    /// Connecting, sites, the vault.
    Connection,
    /// Moving in lists.
    Navigation,
    /// Marking rows.
    Selection,
    /// Sorting file lists.
    Sorting,
    /// File operations.
    FileOps,
    /// The transfer queue.
    Queue,
    /// The message log.
    Log,
    /// Directory trees.
    Tree,
    /// The Site Manager.
    SiteManager,
    /// Directory comparison and synchronized browsing.
    Compare,
    /// Search, bookmarks, filters and other tools.
    Tools,
    /// Text fields.
    Text,
    /// Dialogs.
    Dialog,
}

impl Group {
    /// Heading in the help overlay and the docs.
    pub(crate) fn title(self) -> &'static str {
        match self {
            Self::General => "General",
            Self::Focus => "Focus",
            Self::View => "View",
            Self::Tabs => "Tabs",
            Self::Connection => "Connection",
            Self::Navigation => "Navigation",
            Self::Selection => "Selection",
            Self::Sorting => "Sorting",
            Self::FileOps => "File operations",
            Self::Queue => "Queue",
            Self::Log => "Message log",
            Self::Tree => "Directory tree",
            Self::SiteManager => "Site Manager",
            Self::Compare => "Comparison",
            Self::Tools => "Tools",
            Self::Text => "Text fields",
            Self::Dialog => "Dialogs",
        }
    }
}

/// Registry entry of a bindable action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActionMeta {
    /// The name used in `keybindings` (the variant name).
    pub name: &'static str,
    /// One-line description (help overlay, docs, "… is not available yet").
    pub description: &'static str,
    /// Help group.
    pub group: Group,
    /// The task that implements it ("T62").
    pub owner: &'static str,
}

/// Names of the internal (never bindable) variants.
#[cfg(test)]
pub(crate) const INTERNAL: &[&str] = &[
    "Tick",
    "Render",
    "Resize",
    "Resume",
    "ClearScreen",
    "Error",
    "StatusMessage",
    "StatusNotice",
    "FocusRegion",
    "TaskFinished",
    "SettingsSaved",
    "QuitConfirmed",
    "Wake",
    "Pane",
    "PaneInput",
    "PaneSettings",
    "SaveCredential",
    "CertificateChain",
    "Vault",
    "VaultTimer",
    "VaultRequest",
];

macro_rules! actions {
    (
        internal { $($internal:tt)* }
        bindable { $( $name:ident : $group:ident, $owner:literal, $desc:literal; )* }
    ) => {
        /// Messages between the event loop, [`App`](crate::app::App) and components.
        ///
        /// Unit variants that are not `#[serde(skip)]` are **bindable**: they can appear
        /// in `keybindings` and are listed in [`BINDABLE`]. No `PartialEq`: later
        /// variants carry `Arc<Error>` payloads (T53, T62); tests compare with
        /// `matches!`.
        #[derive(Debug, Clone, Display, Serialize, Deserialize, VariantNames)]
        #[expect(
            clippy::enum_variant_names,
            reason = "T56's names QueueSetExistsAction and QueueCompletionAction"
        )]
        pub(crate) enum Action {
            $($internal)*
            $(
                #[doc = $desc]
                $name,
            )*
        }

        /// Every bindable action, in documentation order.
        pub(crate) static BINDABLE: &[(Action, ActionMeta)] = &[
            $(
                (
                    Action::$name,
                    ActionMeta {
                        name: stringify!($name),
                        description: $desc,
                        group: Group::$group,
                        owner: $owner,
                    },
                ),
            )*
        ];
    };
}

actions! {
    internal {
        /// Timer tick (4 Hz by default) for component timers.
        #[serde(skip)]
        Tick,
        /// Frame tick: draws when something changed.
        #[serde(skip)]
        Render,
        /// The terminal was resized.
        #[serde(skip)]
        Resize(u16, u16),
        /// Back from suspend.
        #[serde(skip)]
        Resume,
        /// Clear the terminal before the next frame.
        #[serde(skip)]
        ClearScreen,
        /// An error to log and show.
        #[serde(skip)]
        Error(String),
        /// A transient status-line message (3 s).
        #[serde(skip)]
        StatusMessage(String),
        /// A transient status-bar message with a level (T57: 3/5/8 s).
        #[serde(skip)]
        #[cfg_attr(not(test), allow(dead_code, reason = "sent by components (T53–T71)"))]
        StatusNotice(crate::components::status_bar::MessageLevel, String),
        /// Focus a region.
        #[serde(skip)]
        #[cfg_attr(
            not(test),
            expect(dead_code, reason = "sent by later components (T54, T58) and tests")
        )]
        FocusRegion(Region),
        /// A runner task finished (after its output action).
        #[serde(skip)]
        TaskFinished(TaskId),
        /// The debounced settings save finished.
        #[serde(skip)]
        SettingsSaved(Result<(), String>),
        /// Quit despite blockers (from the confirm modal).
        #[serde(skip)]
        QuitConfirmed,
        /// An async widget result is ready (path completion, T52): poll the dialogs.
        #[serde(skip)]
        Wake,
        /// A file list pane asks the app to do something (T53).
        #[serde(skip)]
        Pane(PaneRequest),
        /// An input for one file list pane (results, events; T53).
        #[serde(skip)]
        PaneInput(PaneId, PaneInput),
        /// New settings for one file list pane (T53).
        #[serde(skip)]
        PaneSettings(PaneId, std::sync::Arc<courier_ftp_core::settings::Settings>),
        /// Save a typed secret in the vault once the server accepted it (T69 → T31).
        #[serde(skip)]
        SaveCredential(crate::components::prompts::SaveRequest),
        /// Show the certificate chain of the focused tab's session (T57 → T69).
        #[serde(skip)]
        CertificateChain,
        /// A result or request from the vault service (T60). No secrets; `Debug` of
        /// passwords is redacted.
        #[serde(skip)]
        Vault(crate::app::vault::VaultEvent),
        /// A vault timer fired (auto-lock, countdown; T60).
        #[serde(skip)]
        VaultTimer(crate::app::vault::VaultTimer),
        /// A vault effect from a dialog (keyring toggle, T60/T68); `Debug` is redacted.
        #[serde(skip)]
        #[cfg_attr(not(test), allow(dead_code, reason = "Settings → Security (T68)"))]
        VaultRequest(crate::app::vault::VaultEffect),
    }
    bindable {
        // ---- Normal: general ----
        Help: General, "T50", "Help: bindings for the current mode";
        Quit: General, "T50", "Quit (confirm when transfers run)";
        Suspend: General, "T50", "Suspend to the shell (Unix)";
        Redraw: General, "T50", "Clear and redraw the screen";
        Cancel: General, "T50", "Cancel the focused pane's running operation";
        Settings: General, "T68", "Settings";
        // ---- focus ----
        FocusOtherSide: Focus, "T50", "Switch between local and remote list";
        FocusNextRegion: Focus, "T50", "Focus next region (log, trees, lists, queue)";
        FocusLog: Focus, "T50", "Focus message log";
        FocusQueue: Focus, "T50", "Focus queue";
        FocusFiles: Focus, "T50", "Focus the last file list";
        FocusRegion1: Focus, "T50", "Focus the quickconnect bar (region 1)";
        FocusRegion2: Focus, "T50", "Focus the local tree (region 2)";
        FocusRegion3: Focus, "T50", "Focus the local list (region 3)";
        FocusRegion4: Focus, "T50", "Focus the remote tree (region 4)";
        FocusRegion5: Focus, "T50", "Focus the remote list (region 5)";
        FocusRegion6: Focus, "T50", "Focus the message log (region 6)";
        FocusRegion7: Focus, "T50", "Focus the queue (region 7)";
        FocusQuickconnect: Focus, "T58", "Focus the quickconnect bar (opens the dialog when the bar is hidden)";
        // ---- view ----
        ToggleLog: View, "T50", "Show/hide message log";
        ToggleQueuePane: View, "T50", "Show/hide queue";
        ToggleTree: View, "T50", "Show/hide directory trees";
        ToggleQuickconnect: View, "T58", "Show/hide quickconnect bar";
        SwapPanes: View, "T50", "Swap local and remote sides";
        LayoutClassic: View, "T50", "Layout: classic";
        LayoutExplorer: View, "T50", "Layout: explorer";
        LayoutWidescreen: View, "T50", "Layout: widescreen";
        // ---- tabs ----
        NewTab: Tabs, "T61", "New tab";
        CloseTab: Tabs, "T61", "Close tab (confirm when connected)";
        GoToTab1: Tabs, "T61", "Go to tab 1";
        GoToTab2: Tabs, "T61", "Go to tab 2";
        GoToTab3: Tabs, "T61", "Go to tab 3";
        GoToTab4: Tabs, "T61", "Go to tab 4";
        GoToTab5: Tabs, "T61", "Go to tab 5";
        GoToTab6: Tabs, "T61", "Go to tab 6";
        GoToTab7: Tabs, "T61", "Go to tab 7";
        GoToTab8: Tabs, "T61", "Go to tab 8";
        GoToTab9: Tabs, "T61", "Go to tab 9";
        NextTab: Tabs, "T61", "Next tab";
        PrevTab: Tabs, "T61", "Previous tab";
        RenameTab: Tabs, "T61", "Rename tab";
        DuplicateTab: Tabs, "T61", "Duplicate tab (same server and directories)";
        MoveTabLeft: Tabs, "T61", "Move tab left";
        MoveTabRight: Tabs, "T61", "Move tab right";
        // ---- connection ----
        SiteManager: Connection, "T59", "Site Manager";
        SitePicker: Connection, "T59", "Quick site picker (fuzzy)";
        ReconnectLast: Connection, "T58", "Reconnect (active tab's server, else the last server)";
        SaveAsSite: Connection, "T58", "Save the current connection as a site";
        Disconnect: Connection, "T61", "Disconnect the current tab";
        ServerInfo: Connection, "T57", "Connection and encryption details";
        LockVault: Connection, "T30, T60", "Lock the vault";
        NetworkWizard: Connection, "T72", "Network configuration wizard";
        // ---- file operations (global) ----
        Refresh: FileOps, "T62", "Refresh both panes (bypass cache)";
        ManualTransfer: FileOps, "T62", "Manual transfer";
        NewFile: FileOps, "T62", "New empty file in the focused (else last focused) list";
        EditedFilesList: FileOps, "T63", "Files being edited";
        ShowRawListing: FileOps, "T71", "Raw directory listing of the focused (else remote) list";
        // ---- queue (global) ----
        ProcessQueue: Queue, "T56", "Start/stop processing the queue";
        ToggleSpeedLimit: Queue, "T44, T57", "Speed limits on/off";
        CycleTransferType: Queue, "T57", "Transfer type Auto/ASCII/Binary";
        // ---- compare ----
        ToggleSyncBrowsing: Compare, "T66", "Synchronized browsing";
        ToggleComparison: Compare, "T66", "Directory comparison";
        CompareOptions: Compare, "T66", "Comparison options";
        SelectByStatus: Compare, "T66", "Select rows by comparison status";
        // ---- tools ----
        Search: Tools, "T65", "Search files";
        Bookmarks: Tools, "T64", "Bookmarks menu";
        AddBookmark: Tools, "T64", "Add bookmark for the current directories";
        FiltersDialog: Tools, "T67", "Directory listing filters";
        OpenNextPrompt: Tools, "T69", "Open the next pending prompt";
        SyncPanel: Tools, "T90", "Sync panel (feature sync)";
        DismissUpdate: Tools, "T74", "Dismiss the update notice";
        ShowAppLog: Tools, "T71", "Application log (only with --debug)";
        // ---- log (global) ----
        ClearLog: Log, "T55", "Clear the message log of the current scope";
        SaveLogAs: Log, "T71", "Save the message log to a file";

        // ---- lists: navigation ----
        CursorDown: Navigation, "T53", "Move the cursor down";
        CursorUp: Navigation, "T53", "Move the cursor up";
        HalfPageDown: Navigation, "T53", "Half a page down";
        HalfPageUp: Navigation, "T53", "Half a page up";
        PageDown: Navigation, "T53", "Page down";
        PageUp: Navigation, "T53", "Page up";
        Top: Navigation, "T53", "First row";
        Bottom: Navigation, "T53", "Last row";
        Open: Navigation, "T53", "Enter directory; on a file: interface.enter_on_file";
        Parent: Navigation, "T53", "Parent directory";
        Back: Navigation, "T53", "Back in the directory history";
        Forward: Navigation, "T53", "Forward in the directory history";
        EditAddress: Navigation, "T53", "Edit the address bar";
        MirrorOtherPane: Navigation, "T53", "Open the equivalent directory in the other pane";
        Escape: Navigation, "T53", "Leave visual mode / clear quick filter / close the menu";
        // ---- lists: selection ----
        ToggleMark: Selection, "T53", "Mark/unmark and move down";
        VisualMode: Selection, "T53", "Range selection";
        MarkAll: Selection, "T53", "Mark all";
        InvertMarks: Selection, "T53", "Invert marks";
        MarkPattern: Selection, "T53", "Mark by pattern";
        UnmarkPattern: Selection, "T53", "Unmark by pattern";
        QuickFilter: Selection, "T53", "Quick filter";
        // ---- lists: sorting ----
        SortByName: Sorting, "T53", "Sort by name (again = reverse)";
        SortBySize: Sorting, "T53", "Sort by size (again = reverse)";
        SortByType: Sorting, "T53", "Sort by type (again = reverse)";
        SortByModified: Sorting, "T53", "Sort by modification time (again = reverse)";
        SortByPermissions: Sorting, "T53", "Sort by permissions (again = reverse)";
        SortByOwner: Sorting, "T53", "Sort by owner (again = reverse)";
        // ---- lists: view ----
        ToggleHidden: View, "T53", "Show/hide hidden files";
        ColumnMenu: View, "T53", "Columns";
        // ---- lists: file operations ----
        Transfer: FileOps, "T62", "Copy: transfer selection to the other side";
        QueueOnly: FileOps, "T62", "Add selection to the queue only";
        Move: FileOps, "T62", "Move / rename to a path";
        Rename: FileOps, "T62", "Rename";
        Mkdir: FileOps, "T62", "Make directory";
        MkdirEnter: FileOps, "T62", "Make directory and enter it";
        Delete: FileOps, "T62", "Delete (confirm)";
        View: FileOps, "T63", "View";
        Edit: FileOps, "T63", "Edit";
        Chmod: FileOps, "T62", "Change permissions";
        CopyUrl: FileOps, "T62", "Copy URL";
        CopyUrlOptions: FileOps, "T62", "Copy URL with options";
        CustomCommand: FileOps, "T62", "Send a raw command";
        // ---- filter ----
        FilterAccept: Selection, "T53", "Keep the filter, back to the list";
        FilterClear: Selection, "T53", "Clear the filter, back to the list";

        // ---- tree ----
        TreeDown: Tree, "T54", "Move down";
        TreeUp: Tree, "T54", "Move up";
        TreeHalfPageDown: Tree, "T54", "Half a page down";
        TreeHalfPageUp: Tree, "T54", "Half a page up";
        TreeTop: Tree, "T54", "First row";
        TreeBottom: Tree, "T54", "Last row";
        TreeExpand: Tree, "T54", "Expand; if expanded, first child";
        TreeCollapse: Tree, "T54", "Collapse; if collapsed or a leaf, parent";
        TreeToggle: Tree, "T54", "Toggle expand";
        TreeOpen: Tree, "T54", "Show this directory in the file list";
        TreeRefresh: Tree, "T54", "Relist the cursor directory";
        TreeRevealCurrent: Tree, "T54", "Reveal the file list's current directory";

        // ---- log ----
        LogCursorDown: Log, "T55", "Move down";
        LogCursorUp: Log, "T55", "Move up";
        LogHalfPageDown: Log, "T55", "Half a page down";
        LogHalfPageUp: Log, "T55", "Half a page up";
        LogPageDown: Log, "T55", "Page down";
        LogPageUp: Log, "T55", "Page up";
        LogTop: Log, "T55", "First line";
        LogBottom: Log, "T55", "Last line (follow)";
        LogSearch: Log, "T55", "Search the log";
        LogSearchNext: Log, "T55", "Next match";
        LogSearchPrev: Log, "T55", "Previous match";
        LogVisual: Log, "T55", "Line selection";
        LogCopy: Log, "T55", "Copy the selected lines";
        LogToggleWrap: Log, "T55", "Wrap long lines on/off";
        LogToggleScope: Log, "T55", "Current tab / all tabs";
        LogCycleKindFilter: Log, "T55", "Cycle the message kind filter";
        LogScrollLeft: Log, "T55", "Scroll left";
        LogScrollRight: Log, "T55", "Scroll right";
        LogScrollHome: Log, "T55", "Scroll to the line start";
        CopyLog: Log, "T71", "Copy the whole current log view";

        // ---- queue ----
        QueueTabQueued: Queue, "T56", "Show queued files";
        QueueTabFailed: Queue, "T56", "Show failed transfers";
        QueueTabSuccessful: Queue, "T56", "Show successful transfers";
        QueueToggleGroup: Queue, "T56", "Collapse/expand server group";
        QueuePauseResume: Queue, "T56", "Pause/resume selected items";
        QueuePriorityUp: Queue, "T56", "Raise priority";
        QueuePriorityDown: Queue, "T56", "Lower priority";
        QueueMoveUp: Queue, "T56", "Move up";
        QueueMoveDown: Queue, "T56", "Move down";
        QueueMoveTop: Queue, "T56", "Move to top";
        QueueMoveBottom: Queue, "T56", "Move to bottom";
        QueueRemove: Queue, "T56", "Remove selected";
        QueueClearList: Queue, "T56", "Clear the Failed/Successful list (confirm)";
        QueueResetRequeue: Queue, "T56", "Reset and requeue (failed list)";
        QueueSetExistsAction: Queue, "T56", "File-exists action for selected items";
        QueueCompletionAction: Queue, "T45, T56", "Action after queue completion";
        QueueMenu: Queue, "T56", "All actions for the selection";

        // ---- site manager ----
        SmConnect: SiteManager, "T59", "Site: open/connect; folder: toggle";
        SmConnectNewTab: SiteManager, "T59", "Connect in a new tab";
        SmEdit: SiteManager, "T59", "Focus the editor";
        SmNewSite: SiteManager, "T59", "New site";
        SmNewFolder: SiteManager, "T59", "New folder";
        SmDuplicate: SiteManager, "T59", "Duplicate";
        SmRename: SiteManager, "T59", "Rename inline";
        SmDelete: SiteManager, "T59", "Delete (confirm)";
        SmMark: SiteManager, "T59", "Mark for move";
        SmPaste: SiteManager, "T59", "Move the marked item here";
        SmCopyToVault: SiteManager, "T59", "Copy to another vault";
        SmMoveToVault: SiteManager, "T59", "Move to another vault";
        SmFind: SiteManager, "T59", "Filter";
        SmCredentialOverride: SiteManager, "T90", "My login for this site (team vaults)";
        SmSave: SiteManager, "T59", "Save the draft";
        SmImport: SiteManager, "T59", "Import";
        SmExport: SiteManager, "T59", "Export";
        SmPrevTab: SiteManager, "T59", "Previous editor tab";
        SmNextTab: SiteManager, "T59", "Next editor tab";
        SmClose: SiteManager, "T59", "Close (unsaved-changes guard)";

        // ---- text fields ----
        InputSubmit: Text, "T50", "Submit the field";
        InputCancel: Text, "T50", "Cancel the field";
        NextField: Text, "T52, T58", "Next field";
        PrevField: Text, "T52, T58", "Previous field";
        InputHistoryPrev: Text, "T58, T62", "Previous history entry";
        InputHistoryNext: Text, "T58, T62", "Next history entry";

        // ---- dialogs ----
        DialogSubmit: Dialog, "T52", "Default button (newline in a multi-line field)";
        DialogCancel: Dialog, "T52", "Cancel the dialog";
        DialogSave: Dialog, "T52", "Save (forms)";
        NextFormTab: Dialog, "T52", "Next form tab";
        PrevFormTab: Dialog, "T52", "Previous form tab";
    }
}

impl Action {
    /// The bindable action named `name` (`"GoToTab3"`); None for internal and unknown
    /// names.
    pub(crate) fn bindable_from_name(name: &str) -> Option<Self> {
        BINDABLE
            .iter()
            .find(|(_, m)| m.name == name)
            .map(|(a, _)| a.clone())
    }

    /// Metadata for bindable actions; None for internal ones.
    pub(crate) fn meta(&self) -> Option<&'static ActionMeta> {
        let d = std::mem::discriminant(self);
        BINDABLE
            .iter()
            .find(|(a, _)| std::mem::discriminant(a) == d)
            .map(|(_, m)| m)
    }

    /// Whether this action can appear in `keybindings`.
    pub(crate) fn is_bindable(&self) -> bool {
        self.meta().is_some()
    }

    /// Same variant (payloads ignored).
    pub(crate) fn same_variant(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn only_unit_public_variants_are_bindable() {
        assert!(matches!(
            Action::bindable_from_name("Quit"),
            Some(Action::Quit)
        ));
        assert!(matches!(
            Action::bindable_from_name("ToggleLog"),
            Some(Action::ToggleLog)
        ));
        for internal in ["Tick", "Render", "Resize", "Error", "QuitConfirmed", "Nope"] {
            assert!(Action::bindable_from_name(internal).is_none(), "{internal}");
        }
        assert!(!Action::Tick.is_bindable());
        assert!(Action::Help.is_bindable());
    }

    // AC9: the registry, the enum and serde agree.
    #[test]
    fn registry_matches_enum() {
        let bindable: HashSet<&str> = BINDABLE.iter().map(|(_, m)| m.name).collect();
        assert_eq!(bindable.len(), BINDABLE.len(), "duplicate registry names");
        for name in Action::VARIANTS {
            assert!(
                bindable.contains(name) || INTERNAL.contains(name),
                "{name} is neither bindable nor internal"
            );
            assert!(
                !(bindable.contains(name) && INTERNAL.contains(name)),
                "{name} is both"
            );
        }
        for (a, m) in BINDABLE {
            assert_eq!(a.to_string(), m.name);
            let de: Action = match serde_json::from_value(serde_json::json!(m.name)) {
                Ok(a) => a,
                Err(e) => panic!("{}: {e}", m.name),
            };
            assert!(de.same_variant(a));
            assert_eq!(a.meta(), Some(m));
            assert!(!m.description.is_empty());
            assert!(m.owner.starts_with('T'));
        }
        for name in INTERNAL {
            assert!(Action::bindable_from_name(name).is_none(), "{name}");
        }
        assert!(Action::Tick.meta().is_none());
        assert!(Action::Error(String::new()).meta().is_none());
        // T68's internal `OpenSettingsAt(SectionId)` does not exist yet; its name is
        // not bindable either way.
        assert!(Action::bindable_from_name("OpenSettingsAt").is_none());
        assert!(Action::bindable_from_name("Settings").is_some());
    }
}
