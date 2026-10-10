//! Pure pane state and its reducer: no I/O, no async. Every change goes through
//! [`FileListState::reduce`], which returns the [`PaneRequest`]s the app carries out.

use std::{path::PathBuf, sync::Arc};

use courier_ftp_core::{
    Error,
    backend::Listing,
    filters::{FilterEngine, QuickFilter as GlobMatcher, Side as FilterSide},
    local::path_map::{from_native, to_native},
    model::{Entry, EntryKind, LocalPath, RemotePath, ServerIdentity},
    settings::{Column, ColumnSpec, EnterOnFile, Settings, SortSpec},
};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use super::{
    columns::normalize,
    view::{self, BuiltView, INLINE_LIMIT, ViewParams},
};
use crate::tabs::TabId;

/// Back/forward history depth (each way).
pub(crate) const HISTORY_MAX: usize = 50;
/// Directories whose cursor entry is remembered.
pub(crate) const CURSOR_MEMORY_MAX: usize = 256;
/// Quick filter and pattern input limit (characters).
pub(crate) const INPUT_MAX: usize = 256;
/// How long an error stays in the footer (or until the next key).
pub(crate) const ERROR_TTL: std::time::Duration = std::time::Duration::from_secs(10);

/// Which side of a tab a pane shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum Side {
    /// The local filesystem.
    Local,
    /// The server.
    Remote,
}

impl Side {
    /// The other side.
    pub(crate) fn other(self) -> Self {
        match self {
            Self::Local => Self::Remote,
            Self::Remote => Self::Local,
        }
    }

    /// The T47 filter side.
    pub(crate) fn filter_side(self) -> FilterSide {
        match self {
            Self::Local => FilterSide::Local,
            Self::Remote => FilterSide::Remote,
        }
    }
}

/// Identifies one pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PaneId {
    /// The tab.
    pub tab: TabId,
    /// The side.
    pub side: Side,
}

impl PaneId {
    /// The pane on the other side of the same tab.
    pub(crate) fn other(self) -> Self {
        Self {
            tab: self.tab,
            side: self.side.other(),
        }
    }
}

/// A listing request (monotonic per pane).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct RequestId(pub u64);

/// The directory a pane shows.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum PaneDir {
    /// A local directory.
    Local(LocalPath),
    /// A remote directory.
    Remote(RemotePath),
}

impl PaneDir {
    /// The parent directory; `None` at the root.
    pub(crate) fn parent(&self) -> Option<Self> {
        match self {
            Self::Local(p) => p.parent().map(Self::Local),
            Self::Remote(p) => p.parent().map(Self::Remote),
        }
    }

    /// True at the root (no `..` row).
    pub(crate) fn is_root(&self) -> bool {
        self.parent().is_none()
    }

    /// One component down.
    pub(crate) fn join(&self, name: &str) -> Result<Self, Error> {
        match self {
            Self::Local(p) => p.join(name).map(Self::Local),
            Self::Remote(p) => p.join(name).map(Self::Remote),
        }
    }

    /// The last component.
    pub(crate) fn file_name(&self) -> Option<String> {
        match self {
            Self::Local(p) => p.file_name().map(|n| n.to_string_lossy().into_owned()),
            Self::Remote(p) => p.file_name().map(str::to_owned),
        }
    }

    /// Address bar text: local with `~` for home, remote absolute.
    pub(crate) fn display(&self) -> String {
        match self {
            Self::Local(p) => p.to_display(),
            Self::Remote(p) => p.as_str().to_owned(),
        }
    }

    /// The `/`-path the backends and the filters use.
    pub(crate) fn backend_path(&self) -> Result<RemotePath, Error> {
        match self {
            Self::Local(p) => from_native(p.as_path()),
            Self::Remote(p) => Ok(p.clone()),
        }
    }

    /// The side this directory belongs to.
    pub(crate) fn side(&self) -> Side {
        match self {
            Self::Local(_) => Side::Local,
            Self::Remote(_) => Side::Remote,
        }
    }
}

/// What the pane is doing.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PaneStatus {
    /// Showing `listing`.
    Ready,
    /// A listing request is in flight; the previous listing (if any) stays visible.
    Loading {
        /// The request.
        request: RequestId,
        /// Since when.
        since: Instant,
    },
    /// Remote pane without a session.
    NotConnected,
    /// The last request failed. `listing` still holds the previous directory.
    Error {
        /// The mapped message (without `Error: `).
        message: String,
        /// When.
        at: Instant,
    },
}

/// The quick filter (`/`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuickFilter {
    /// Text typed so far.
    pub text: String,
    /// Mode `Filter` is active.
    pub editing: bool,
}

/// T66 hook: colour and alignment of rows during directory comparison.
pub(crate) trait RowDecoration: Send + Sync + std::fmt::Debug {
    /// The style key for a row (`None` entry index = placeholder row).
    fn style_for(&self, entry_index: Option<u32>) -> Option<RowStyleKey>;
}

/// A style key a [`RowDecoration`] returns (`compare_newer`, …).
pub(crate) type RowStyleKey = &'static str;

/// File operations the pane can request (names match T51 actions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileOp {
    /// `Transfer`.
    Transfer,
    /// `QueueOnly`.
    QueueOnly,
    /// `Move`.
    Move,
    /// `Rename`.
    Rename,
    /// `Mkdir`.
    Mkdir,
    /// `MkdirEnter`.
    MkdirEnter,
    /// `NewFile`.
    NewFile,
    /// `Delete`.
    Delete,
    /// `View`.
    View,
    /// `Edit`.
    Edit,
    /// `Chmod`.
    Chmod,
    /// `CopyUrl`.
    CopyUrl,
    /// `CopyUrlOptions`.
    CopyUrlOptions,
    /// `CustomCommand`.
    CustomCommand,
    /// `Refresh` (handled by the pane: relist bypassing the cache).
    Refresh,
}

impl FileOp {
    /// Needs entries (marked or under the cursor).
    fn needs_selection(self) -> bool {
        !matches!(
            self,
            Self::Mkdir | Self::MkdirEnter | Self::NewFile | Self::CustomCommand | Self::Refresh
        )
    }
}

/// The entries an operation applies to: marked entries, else the cursor entry.
/// `..` is never part of a selection.
#[derive(Debug, Clone)]
#[allow(dead_code, reason = "read by the file operations (T62, T63)")]
pub(crate) struct Selection {
    /// The directory.
    pub dir: PaneDir,
    /// The entries (view order).
    pub entries: Arc<[Entry]>,
}

/// A settings change the pane asks the app to make (and save).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InterfaceEdit {
    /// `interface.show_hidden_local`.
    ShowHiddenLocal(bool),
    /// `interface.force_show_hidden_remote`.
    ForceShowHiddenRemote(bool),
    /// `interface.sort.{local,remote}`.
    Sort(Side, SortSpec),
    /// `interface.columns.{local,remote}`.
    Columns(Side, Vec<ColumnSpec>),
}

/// The pane's view job for the blocking pool.
#[derive(Debug, Clone)]
pub(crate) struct ViewJob {
    /// The listing.
    pub listing: Arc<Listing>,
    /// Parameters.
    pub params: ViewParams,
    /// T47 filters.
    pub filters: Arc<FilterEngine>,
    /// The directory as the filters see it.
    pub parent: String,
}

impl ViewJob {
    /// Runs the job.
    pub(crate) fn run(&self) -> BuiltView {
        view::build(&self.listing, &self.params, &self.filters, &self.parent)
    }
}

/// What the pane asks the app to do.
#[derive(Debug, Clone)]
pub(crate) enum PaneRequest {
    /// List `dir` (through `ListingCache` unless `force`).
    List {
        /// The pane.
        pane: PaneId,
        /// The directory.
        dir: PaneDir,
        /// The request id.
        request: RequestId,
        /// Bypass the cache.
        force: bool,
    },
    /// Cancel an in-flight listing.
    CancelList {
        /// The pane.
        pane: PaneId,
        /// The request.
        request: RequestId,
    },
    /// A file operation on the selection (handled by T62/T63).
    #[allow(dead_code, reason = "read by the file operations (T62, T63)")]
    FileOp {
        /// The pane.
        pane: PaneId,
        /// The operation.
        op: FileOp,
        /// The selection.
        selection: Selection,
    },
    /// Navigate the other pane of the same tab to the equivalent path (`=`).
    MirrorToOtherPane {
        /// The pane.
        pane: PaneId,
        /// Its directory.
        dir: PaneDir,
    },
    /// Build the view off the UI thread; answered with `PaneInput::SortDone`.
    BuildView {
        /// The pane.
        pane: PaneId,
        /// The view generation.
        generation: u64,
        /// The job.
        job: Box<ViewJob>,
    },
    /// Ask for a glob (`+`/`-`); answered with `PaneInput::Pattern`.
    PromptPattern {
        /// The pane.
        pane: PaneId,
        /// Mark (`+`) or unmark (`-`).
        mark: bool,
    },
    /// Open the column menu; answered with `PaneInput::Columns`.
    ColumnMenu {
        /// The pane.
        pane: PaneId,
        /// The current configuration.
        columns: Vec<ColumnSpec>,
    },
    /// Change and save a setting.
    Settings(InterfaceEdit),
    /// Show a message in a pane's footer.
    Notice {
        /// The pane.
        pane: PaneId,
        /// The text.
        text: String,
    },
}

/// Keymap actions in mode `FileList` / `Filter` (and the address bar results).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PaneCommand {
    /// `CursorDown`.
    CursorDown,
    /// `CursorUp`.
    CursorUp,
    /// `HalfPageDown`.
    HalfPageDown,
    /// `HalfPageUp`.
    HalfPageUp,
    /// `PageDown`.
    PageDown,
    /// `PageUp`.
    PageUp,
    /// `Top`.
    Top,
    /// `Bottom`.
    Bottom,
    /// `Open`.
    Open,
    /// `Parent`.
    Parent,
    /// `Back`.
    Back,
    /// `Forward`.
    Forward,
    /// `ToggleMark`.
    ToggleMark,
    /// `VisualMode`.
    VisualMode,
    /// `MarkAll`.
    MarkAll,
    /// `InvertMarks`.
    InvertMarks,
    /// `MarkPattern`.
    MarkPattern,
    /// `UnmarkPattern`.
    UnmarkPattern,
    /// `QuickFilter`: enter mode `Filter`.
    QuickFilter,
    /// A printable character typed in mode `Filter`.
    FilterInsert(char),
    /// `Backspace` in mode `Filter`.
    FilterBackspace,
    /// `FilterAccept`.
    FilterAccept,
    /// `FilterClear`.
    FilterClear,
    /// `SortBy*`.
    SortBy(Column),
    /// `ToggleHidden`.
    ToggleHidden,
    /// `EditAddress` (the component opens the editor).
    EditAddress,
    /// The address bar was submitted with this text.
    AddressSubmit(String),
    /// The address bar was cancelled.
    AddressCancel,
    /// `MirrorOtherPane`.
    MirrorOtherPane,
    /// `ColumnMenu`.
    ColumnMenu,
    /// `Escape`.
    Escape,
    /// `Cancel` (the runner cancels the task; the pane leaves `Loading`).
    Cancel,
    /// A file operation.
    FileOp(FileOp),
}

/// Inputs to the reducer.
#[derive(Debug, Clone)]
pub(crate) enum PaneInput {
    /// A keymap action.
    Key(PaneCommand),
    /// A listing request finished.
    ListingLoaded {
        /// The request.
        request: RequestId,
        /// The directory listed (normalised).
        dir: PaneDir,
        /// The listing or the error.
        result: Result<Arc<Listing>, Arc<Error>>,
    },
    /// A new listing for a directory (T46 patch or refresh).
    #[allow(dead_code, reason = "sent by T58, T61, T62 and T67")]
    ListingUpdated {
        /// The directory.
        dir: PaneDir,
        /// The listing.
        listing: Arc<Listing>,
    },
    /// An off-thread view build finished.
    SortDone {
        /// Its generation.
        generation: u64,
        /// The view.
        view: Vec<u32>,
        /// Entries hidden by T47 filters.
        filtered: usize,
    },
    /// The remote pane got a session.
    #[allow(dead_code, reason = "sent by T58, T61, T62 and T67")]
    Connected {
        /// The server (matches `ListingUpdated` events).
        server: ServerIdentity,
        /// Title label (site name or `user@host`).
        label: String,
    },
    /// The remote pane lost its session.
    #[allow(dead_code, reason = "sent by T58, T61, T62 and T67")]
    Disconnected,
    /// The T47 filters changed.
    #[allow(dead_code, reason = "sent by T58, T61, T62 and T67")]
    FiltersChanged(Arc<FilterEngine>),
    /// The settings changed (the new ones are in the context).
    SettingsChanged,
    /// The body height changed.
    Resize {
        /// Entry rows visible.
        body_rows: u16,
    },
    /// Navigate to a directory (start-up, tree, bookmarks, the other pane's `=`).
    Navigate(PaneDir),
    /// The other pane asks for the equivalent of its directory (`=`).
    MirrorFrom(PaneDir),
    /// A glob from the `+`/`-` prompt.
    Pattern {
        /// The glob.
        glob: String,
        /// Mark or unmark.
        mark: bool,
    },
    /// New column configuration from the column menu.
    Columns(Vec<ColumnSpec>),
    /// A message for the footer (`No equivalent directory`).
    Notice(String),
    /// Relist the shown directory through the cache (`ListingUpdated` core event).
    Reload,
}

/// Settings and engines the reducer reads.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PaneCtx<'a> {
    /// The settings.
    pub settings: &'a Settings,
    /// The T47 filters of this side.
    pub filters: &'a Arc<FilterEngine>,
    /// Now.
    pub now: Instant,
}

/// The footer numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FooterSummary {
    /// Files (everything that is not a directory).
    pub files: usize,
    /// Directories.
    pub dirs: usize,
    /// Total size of the files.
    pub bytes: u64,
    /// Some file size is unknown.
    pub unknown_size: bool,
    /// The numbers are of the marked entries.
    pub selected: bool,
    /// Entries in the view.
    pub shown: usize,
    /// Entries in the listing.
    pub total: usize,
}

/// A small fixed-size bit set (one bit per listing entry).
#[derive(Debug, Clone, Default)]
pub(crate) struct Marks {
    words: Vec<u64>,
    count: usize,
}

impl Marks {
    fn with_len(n: usize) -> Self {
        Self {
            words: vec![0; n.div_ceil(64)],
            count: 0,
        }
    }

    /// Whether `i` is marked.
    pub(crate) fn contains(&self, i: u32) -> bool {
        let i = i as usize;
        self.words
            .get(i / 64)
            .is_some_and(|w| w & (1 << (i % 64)) != 0)
    }

    fn set(&mut self, i: u32, on: bool) {
        let i = i as usize;
        let Some(w) = self.words.get_mut(i / 64) else {
            return;
        };
        let bit = 1u64 << (i % 64);
        let was = *w & bit != 0;
        if on && !was {
            *w |= bit;
            self.count += 1;
        } else if !on && was {
            *w &= !bit;
            self.count -= 1;
        }
    }

    /// Number of marked entries.
    pub(crate) fn len(&self) -> usize {
        self.count
    }

    fn clear(&mut self) {
        self.words.iter_mut().for_each(|w| *w = 0);
        self.count = 0;
    }

    /// Marked indices.
    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.words.iter().enumerate().flat_map(|(wi, &w)| {
            (0..64u32)
                .filter(move |b| w & (1 << b) != 0)
                .map(move |b| u32::try_from(wi * 64).unwrap_or(0) + b)
        })
    }
}

/// Back/forward stacks.
#[derive(Debug, Clone, Default)]
struct NavHistory {
    back: Vec<PaneDir>,
    forward: Vec<PaneDir>,
}

fn push_capped(v: &mut Vec<PaneDir>, d: PaneDir) {
    v.push(d);
    if v.len() > HISTORY_MAX {
        v.remove(0);
    }
}

/// Last cursor entry per directory, least recently used dropped first.
#[derive(Debug, Clone, Default)]
struct CursorMemory {
    /// Most recent last.
    items: Vec<(PaneDir, String)>,
}

impl CursorMemory {
    fn get(&self, dir: &PaneDir) -> Option<&str> {
        self.items
            .iter()
            .find(|(d, _)| d == dir)
            .map(|(_, n)| n.as_str())
    }

    fn put(&mut self, dir: PaneDir, name: String) {
        self.items.retain(|(d, _)| *d != dir);
        self.items.push((dir, name));
        if self.items.len() > CURSOR_MEMORY_MAX {
            self.items.remove(0);
        }
    }
}

/// How a pending navigation was started.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NavKind {
    /// Open, address bar, external.
    Normal,
    /// `Parent`, from this child name.
    Parent(Option<String>),
    /// `Back`.
    Back,
    /// `Forward`.
    Forward,
    /// Relist of the shown directory.
    Reload,
}

#[derive(Debug, Clone)]
struct Pending {
    request: RequestId,
    kind: NavKind,
}

/// Where the cursor goes once the view is built.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CursorTarget {
    /// Row 0.
    Top,
    /// The entry with this name, else row `fallback`.
    Name(String, usize),
    /// Keep the row index.
    Row(usize),
}

/// Pure pane state.
#[derive(Debug)]
pub(crate) struct FileListState {
    /// The pane.
    pub id: PaneId,
    /// The directory shown.
    pub dir: Option<PaneDir>,
    /// Its listing.
    pub listing: Option<Arc<Listing>>,
    /// Status.
    pub status: PaneStatus,
    view: Vec<u32>,
    view_generation: u64,
    /// Cursor row (row 0 is `..` when `has_parent_row()`).
    pub cursor: usize,
    /// First visible row.
    pub offset: usize,
    marks: Marks,
    visual_anchor: Option<usize>,
    /// Sort order.
    pub sort: SortSpec,
    /// Column configuration.
    pub columns: Vec<ColumnSpec>,
    /// Quick filter.
    pub quick_filter: Option<QuickFilter>,
    /// Show hidden entries (local) / force `LIST -a` (remote).
    pub show_hidden: bool,
    history: NavHistory,
    cursor_memory: CursorMemory,
    /// Address bar text while `a` is active (the component owns the editor).
    pub address_editing: bool,
    /// Per-row decoration provided by T66.
    pub decoration: Option<Arc<dyn RowDecoration>>,
    /// The session's server (remote, connected).
    pub server: Option<ServerIdentity>,
    /// Title label (remote, connected).
    pub label: Option<String>,
    /// A footer message and when it was set (errors: `Error: …`).
    pub notice: Option<(String, bool, Instant)>,
    pending: Option<Pending>,
    next_request: u64,
    cursor_target: Option<CursorTarget>,
    body_rows: u16,
    filtered: usize,
    summary: FooterSummary,
}

impl FileListState {
    /// A pane with the settings' sort, columns and hidden flag; remote panes start
    /// `NotConnected`.
    pub(crate) fn new(id: PaneId, settings: &Settings) -> Self {
        let mut me = Self {
            id,
            dir: None,
            listing: None,
            status: match id.side {
                Side::Local => PaneStatus::Ready,
                Side::Remote => PaneStatus::NotConnected,
            },
            view: Vec::new(),
            view_generation: 0,
            cursor: 0,
            offset: 0,
            marks: Marks::default(),
            visual_anchor: None,
            sort: SortSpec::default(),
            columns: Vec::new(),
            quick_filter: None,
            show_hidden: false,
            history: NavHistory::default(),
            cursor_memory: CursorMemory::default(),
            address_editing: false,
            decoration: None,
            server: None,
            label: None,
            notice: None,
            pending: None,
            next_request: 0,
            cursor_target: None,
            body_rows: 10,
            filtered: 0,
            summary: FooterSummary::default(),
        };
        me.read_settings(settings);
        me
    }

    fn read_settings(&mut self, s: &Settings) {
        let i = &s.interface;
        match self.id.side {
            Side::Local => {
                self.sort = i.sort.local;
                self.columns = normalize(&i.columns.local);
                self.show_hidden = i.show_hidden_local;
            }
            Side::Remote => {
                self.sort = i.sort.remote;
                self.columns = normalize(&i.columns.remote);
                self.show_hidden = i.force_show_hidden_remote;
            }
        }
    }

    /// Rows in the view including the `..` row.
    pub(crate) fn row_count(&self) -> usize {
        self.view.len() + usize::from(self.has_parent_row())
    }

    /// A `..` row is shown.
    pub(crate) fn has_parent_row(&self) -> bool {
        self.status != PaneStatus::NotConnected
            && self.listing.is_some()
            && self.dir.as_ref().is_some_and(|d| !d.is_root())
    }

    /// The view (indices into `listing.entries`).
    pub(crate) fn view(&self) -> &[u32] {
        &self.view
    }

    /// Entry index of `row` (`None` for `..`).
    pub(crate) fn entry_index(&self, row: usize) -> Option<u32> {
        let p = usize::from(self.has_parent_row());
        if row < p {
            return None;
        }
        self.view.get(row - p).copied()
    }

    /// The entry at `row`.
    pub(crate) fn entry_at(&self, row: usize) -> Option<&Entry> {
        let i = self.entry_index(row)?;
        self.listing.as_ref()?.entries.get(i as usize)
    }

    /// Entry under the cursor (`None` on `..` or empty view).
    pub(crate) fn cursor_entry(&self) -> Option<&Entry> {
        self.entry_at(self.cursor)
    }

    /// Whether entry `i` is marked.
    pub(crate) fn is_marked(&self, i: u32) -> bool {
        self.marks.contains(i)
    }

    /// Number of marked entries.
    #[cfg(test)]
    pub(crate) fn marked_count(&self) -> usize {
        self.marks.len()
    }

    /// The visual-mode range of rows, if active.
    pub(crate) fn visual_range(&self) -> Option<(usize, usize)> {
        self.visual_anchor
            .map(|a| (a.min(self.cursor), a.max(self.cursor)))
    }

    /// Body rows (from the last `Resize`).
    pub(crate) fn body_rows(&self) -> u16 {
        self.body_rows
    }

    /// The entries an operation applies to.
    pub(crate) fn selection(&self) -> Option<Selection> {
        let dir = self.dir.clone()?;
        let listing = self.listing.as_ref()?;
        let entries: Vec<Entry> = if self.marks.len() > 0 {
            self.view
                .iter()
                .filter(|i| self.marks.contains(**i))
                .filter_map(|i| listing.entries.get(*i as usize).cloned())
                .collect()
        } else {
            self.cursor_entry().cloned().into_iter().collect()
        };
        if entries.is_empty() {
            return None;
        }
        Some(Selection {
            dir,
            entries: entries.into(),
        })
    }

    /// True when a T47 filter hid at least one entry or the quick filter is set.
    pub(crate) fn is_filtered(&self) -> bool {
        self.filtered > 0
            || self
                .quick_filter
                .as_ref()
                .is_some_and(|q| !q.text.is_empty())
    }

    /// The footer numbers (kept up to date by the reducer).
    pub(crate) fn footer(&self) -> FooterSummary {
        self.summary
    }

    fn refresh_summary(&mut self) {
        let mut s = FooterSummary {
            selected: self.marks.len() > 0,
            shown: self.view.len(),
            total: self.listing.as_ref().map_or(0, |l| l.entries.len()),
            ..FooterSummary::default()
        };
        if let Some(l) = &self.listing {
            for &i in &self.view {
                if s.selected && !self.marks.contains(i) {
                    continue;
                }
                let Some(e) = l.entries.get(i as usize) else {
                    continue;
                };
                if e.is_dir_like() {
                    s.dirs += 1;
                } else {
                    s.files += 1;
                    match e.size {
                        Some(b) => s.bytes = s.bytes.saturating_add(b),
                        // A link has no size of its own.
                        None if matches!(e.kind, EntryKind::Symlink { .. }) => {}
                        None => s.unknown_size = true,
                    }
                }
            }
        }
        self.summary = s;
    }

    fn view_params(&self, ctx: &PaneCtx<'_>) -> ViewParams {
        let i = &ctx.settings.interface;
        ViewParams {
            // Remote entries are shown as listed (the server decides with `LIST -a`).
            show_hidden: self.id.side == Side::Remote || self.show_hidden,
            quick: self
                .quick_filter
                .as_ref()
                .map(|q| q.text.clone())
                .unwrap_or_default(),
            sort: self.sort,
            natural: i.natural_sort,
            case_sensitive: i.sort_case_sensitive,
            dirs_first: i.dirs_first,
        }
    }

    /// Rebuilds the view (inline for small listings, else a `BuildView` request); the
    /// cursor goes to `target` once the view exists.
    fn rebuild(&mut self, ctx: &PaneCtx<'_>, target: CursorTarget) -> Vec<PaneRequest> {
        self.view_generation += 1;
        let Some(listing) = self.listing.clone() else {
            self.view.clear();
            self.filtered = 0;
            self.cursor = 0;
            self.offset = 0;
            self.refresh_summary();
            return Vec::new();
        };
        let job = ViewJob {
            listing,
            params: self.view_params(ctx),
            filters: Arc::clone(ctx.filters),
            parent: self
                .dir
                .as_ref()
                .and_then(|d| d.backend_path().ok())
                .map(|p| p.as_str().to_owned())
                .unwrap_or_default(),
        };
        if job.listing.entries.len() <= INLINE_LIMIT {
            let built = job.run();
            self.apply_view(built, target);
            Vec::new()
        } else {
            self.cursor_target = Some(target);
            vec![PaneRequest::BuildView {
                pane: self.id,
                generation: self.view_generation,
                job: Box::new(job),
            }]
        }
    }

    fn cursor_name(&self) -> CursorTarget {
        match self.cursor_entry() {
            Some(e) => CursorTarget::Name(e.name.clone(), self.cursor),
            None => CursorTarget::Row(self.cursor),
        }
    }

    fn apply_view(&mut self, built: BuiltView, target: CursorTarget) {
        self.view = built.view;
        self.filtered = built.filtered;
        // Marks never stay on entries the view does not contain.
        if self.marks.len() > 0 {
            let n = self.listing.as_ref().map_or(0, |l| l.entries.len());
            let mut keep = Marks::with_len(n);
            for &i in &self.view {
                if self.marks.contains(i) {
                    keep.set(i, true);
                }
            }
            self.marks = keep;
        }
        let rows = self.row_count();
        self.cursor = match target {
            CursorTarget::Top => 0,
            CursorTarget::Row(r) => r,
            CursorTarget::Name(name, fallback) => self.row_of_name(&name).unwrap_or(fallback),
        }
        .min(rows.saturating_sub(1));
        if let Some(a) = self.visual_anchor {
            self.visual_anchor = Some(a.min(rows.saturating_sub(1)));
        }
        self.fix_offset();
        self.refresh_summary();
    }

    fn row_of_name(&self, name: &str) -> Option<usize> {
        let l = self.listing.as_ref()?;
        let p = usize::from(self.has_parent_row());
        self.view
            .iter()
            .position(|&i| l.entries.get(i as usize).is_some_and(|e| e.name == name))
            .map(|r| r + p)
    }

    /// Keeps the cursor inside `offset..offset + body_rows`.
    fn fix_offset(&mut self) {
        let rows = usize::from(self.body_rows.max(1));
        let count = self.row_count();
        if self.cursor < self.offset {
            self.offset = self.cursor;
        } else if self.cursor >= self.offset + rows {
            self.offset = self.cursor + 1 - rows;
        }
        // No empty space below the last row when it can be avoided.
        let max_offset = count.saturating_sub(rows);
        self.offset = self.offset.min(max_offset);
    }

    fn move_cursor(&mut self, delta: isize) {
        let last = self.row_count().saturating_sub(1);
        let c = self.cursor.saturating_add_signed(delta).min(last);
        self.cursor = c;
        self.fix_offset();
    }

    fn new_request(&mut self) -> RequestId {
        self.next_request += 1;
        RequestId(self.next_request)
    }

    /// Starts listing `dir`: cancels the request in flight, emits `List`.
    fn navigate(
        &mut self,
        ctx: &PaneCtx<'_>,
        dir: PaneDir,
        kind: NavKind,
        force: bool,
    ) -> Vec<PaneRequest> {
        let mut out = Vec::new();
        if self.id.side == Side::Remote
            && self.server.is_none()
            && self.status == PaneStatus::NotConnected
        {
            return out;
        }
        if let Some(p) = self.pending.take() {
            out.push(PaneRequest::CancelList {
                pane: self.id,
                request: p.request,
            });
        }
        let request = self.new_request();
        self.pending = Some(Pending { request, kind });
        self.status = PaneStatus::Loading {
            request,
            since: ctx.now,
        };
        out.push(PaneRequest::List {
            pane: self.id,
            dir,
            request,
            force,
        });
        out
    }

    /// Relists the shown directory.
    fn reload(&mut self, ctx: &PaneCtx<'_>, force: bool) -> Vec<PaneRequest> {
        match self.dir.clone() {
            Some(d) => self.navigate(ctx, d, NavKind::Reload, force),
            None => Vec::new(),
        }
    }

    fn set_error(&mut self, message: String, now: Instant) {
        self.notice = Some((message, true, now));
    }

    /// Drops an expired footer notice; true if one was dropped.
    pub(crate) fn expire_notice(&mut self, now: Instant) -> bool {
        if self
            .notice
            .as_ref()
            .is_some_and(|(_, _, at)| now.duration_since(*at) >= ERROR_TTL)
        {
            self.notice = None;
            if let PaneStatus::Error { .. } = self.status
                && self.listing.is_some()
            {
                self.status = PaneStatus::Ready;
            }
            return true;
        }
        false
    }

    /// Applies one input; returns requests for the app.
    pub(crate) fn reduce(&mut self, input: PaneInput, ctx: &PaneCtx<'_>) -> Vec<PaneRequest> {
        match input {
            PaneInput::Key(cmd) => {
                // Any key dismisses a footer notice (errors stay in the body when
                // there is no listing).
                self.notice = None;
                if let PaneStatus::Error { .. } = self.status
                    && self.listing.is_some()
                {
                    self.status = PaneStatus::Ready;
                }
                self.command(cmd, ctx)
            }
            PaneInput::ListingLoaded {
                request,
                dir,
                result,
            } => self.loaded(request, dir, result, ctx),
            PaneInput::ListingUpdated { dir, listing } => {
                if self.dir.as_ref() != Some(&dir) {
                    return Vec::new();
                }
                self.replace_same_dir(listing, ctx)
            }
            PaneInput::SortDone {
                generation,
                view,
                filtered,
            } => {
                if generation != self.view_generation {
                    return Vec::new();
                }
                let target = self
                    .cursor_target
                    .take()
                    .unwrap_or(CursorTarget::Row(self.cursor));
                self.apply_view(BuiltView { view, filtered }, target);
                Vec::new()
            }
            PaneInput::Connected { server, label } => {
                self.server = Some(server);
                self.label = Some(label);
                if self.status == PaneStatus::NotConnected {
                    self.status = PaneStatus::Ready;
                }
                Vec::new()
            }
            PaneInput::Disconnected => {
                let mut out = Vec::new();
                if let Some(p) = self.pending.take() {
                    out.push(PaneRequest::CancelList {
                        pane: self.id,
                        request: p.request,
                    });
                }
                self.server = None;
                self.label = None;
                self.status = PaneStatus::NotConnected;
                self.listing = None;
                self.dir = None;
                self.marks.clear();
                self.visual_anchor = None;
                self.history = NavHistory::default();
                self.view.clear();
                self.cursor = 0;
                self.offset = 0;
                self.refresh_summary();
                out
            }
            PaneInput::FiltersChanged(_) | PaneInput::SettingsChanged => {
                if matches!(input, PaneInput::SettingsChanged) {
                    self.read_settings(ctx.settings);
                }
                let target = self.cursor_name();
                self.rebuild(ctx, target)
            }
            PaneInput::Resize { body_rows } => {
                self.body_rows = body_rows;
                self.fix_offset();
                Vec::new()
            }
            PaneInput::Navigate(dir) => {
                if dir.side() != self.id.side {
                    return Vec::new();
                }
                self.navigate(ctx, dir, NavKind::Normal, false)
            }
            PaneInput::MirrorFrom(source) => self.mirror_from(&source, ctx),
            PaneInput::Pattern { glob, mark } => {
                self.mark_pattern(&glob, mark);
                Vec::new()
            }
            PaneInput::Columns(cols) => {
                self.columns = normalize(&cols);
                vec![PaneRequest::Settings(InterfaceEdit::Columns(
                    self.id.side,
                    self.columns.clone(),
                ))]
            }
            PaneInput::Reload => self.reload(ctx, false),
            PaneInput::Notice(text) => {
                self.notice = Some((text, false, ctx.now));
                Vec::new()
            }
        }
    }

    fn mirror_from(&mut self, source: &PaneDir, ctx: &PaneCtx<'_>) -> Vec<PaneRequest> {
        let target = match (source.file_name(), self.listing.clone(), self.dir.clone()) {
            (Some(name), Some(listing), Some(dir))
                if listing
                    .entries
                    .iter()
                    .any(|e| e.name == name && e.is_dir_like()) =>
            {
                dir.join(&name).ok()
            }
            _ => None,
        };
        match target {
            Some(t) => self.navigate(ctx, t, NavKind::Normal, false),
            None => vec![PaneRequest::Notice {
                pane: self.id.other(),
                text: "No equivalent directory".to_owned(),
            }],
        }
    }

    fn mark_pattern(&mut self, glob: &str, mark: bool) {
        let glob: String = glob.chars().take(INPUT_MAX).collect();
        if glob.is_empty() {
            return;
        }
        // Whole-name glob, case-insensitive; a text without wildcards is a name.
        let matcher = if glob.contains(['*', '?', '[']) {
            GlobMatcher::parse(&glob)
        } else {
            None
        };
        let Some(listing) = self.listing.clone() else {
            return;
        };
        self.ensure_marks_len();
        let lower = glob.to_lowercase();
        for &i in &self.view {
            let Some(e) = listing.entries.get(i as usize) else {
                continue;
            };
            let hit = match &matcher {
                Some(m) => m.matches(&e.name),
                None => e.name.to_lowercase() == lower,
            };
            if hit {
                self.marks.set(i, mark);
            }
        }
        self.refresh_summary();
    }

    fn ensure_marks_len(&mut self) {
        let n = self.listing.as_ref().map_or(0, |l| l.entries.len());
        if self.marks.words.len() != n.div_ceil(64) {
            self.marks = Marks::with_len(n);
        }
    }

    fn mark_rows(&mut self, from: usize, to: usize, on: Option<bool>) {
        self.ensure_marks_len();
        for r in from..=to {
            if let Some(i) = self.entry_index(r) {
                let v = on.unwrap_or_else(|| !self.marks.contains(i));
                self.marks.set(i, v);
            }
        }
        self.refresh_summary();
    }

    fn command(&mut self, cmd: PaneCommand, ctx: &PaneCtx<'_>) -> Vec<PaneRequest> {
        let half = isize::try_from(usize::from((self.body_rows / 2).max(1))).unwrap_or(1);
        let page =
            isize::try_from(usize::from(self.body_rows.saturating_sub(1).max(1))).unwrap_or(1);
        match cmd {
            PaneCommand::CursorDown => self.move_cursor(1),
            PaneCommand::CursorUp => self.move_cursor(-1),
            PaneCommand::HalfPageDown => self.move_cursor(half),
            PaneCommand::HalfPageUp => self.move_cursor(-half),
            PaneCommand::PageDown => self.move_cursor(page),
            PaneCommand::PageUp => self.move_cursor(-page),
            PaneCommand::Top => {
                self.cursor = 0;
                self.fix_offset();
            }
            PaneCommand::Bottom => {
                self.cursor = self.row_count().saturating_sub(1);
                self.fix_offset();
            }
            PaneCommand::Open => return self.open(ctx),
            PaneCommand::Parent => return self.parent(ctx),
            PaneCommand::Back => {
                if let Some(d) = self.history.back.last().cloned() {
                    return self.navigate(ctx, d, NavKind::Back, false);
                }
            }
            PaneCommand::Forward => {
                if let Some(d) = self.history.forward.last().cloned() {
                    return self.navigate(ctx, d, NavKind::Forward, false);
                }
            }
            PaneCommand::ToggleMark => {
                if let Some((a, b)) = self.visual_range() {
                    self.mark_rows(a, b, Some(true));
                    self.visual_anchor = None;
                } else {
                    let c = self.cursor;
                    self.mark_rows(c, c, None);
                    self.move_cursor(1);
                }
            }
            PaneCommand::VisualMode => match self.visual_range() {
                Some((a, b)) => {
                    self.mark_rows(a, b, Some(true));
                    self.visual_anchor = None;
                }
                None => self.visual_anchor = Some(self.cursor),
            },
            PaneCommand::MarkAll => {
                let last = self.row_count().saturating_sub(1);
                if self.row_count() > 0 {
                    self.mark_rows(0, last, Some(true));
                }
            }
            PaneCommand::InvertMarks => {
                let last = self.row_count().saturating_sub(1);
                if self.row_count() > 0 {
                    self.mark_rows(0, last, None);
                }
            }
            PaneCommand::MarkPattern | PaneCommand::UnmarkPattern => {
                if self.listing.is_some() {
                    return vec![PaneRequest::PromptPattern {
                        pane: self.id,
                        mark: cmd == PaneCommand::MarkPattern,
                    }];
                }
            }
            PaneCommand::QuickFilter => {
                let text = self.quick_filter.take().map(|q| q.text).unwrap_or_default();
                self.quick_filter = Some(QuickFilter {
                    text,
                    editing: true,
                });
            }
            PaneCommand::FilterInsert(c) => {
                if let Some(q) = &mut self.quick_filter
                    && q.text.chars().count() < INPUT_MAX
                {
                    q.text.push(c);
                    let t = self.cursor_name();
                    return self.rebuild(ctx, t);
                }
            }
            PaneCommand::FilterBackspace => {
                if let Some(q) = &mut self.quick_filter {
                    if q.text.pop().is_none() {
                        self.quick_filter = None;
                    }
                    let t = self.cursor_name();
                    return self.rebuild(ctx, t);
                }
            }
            PaneCommand::FilterAccept => {
                if let Some(q) = &mut self.quick_filter {
                    q.editing = false;
                    if q.text.is_empty() {
                        self.quick_filter = None;
                    }
                }
            }
            PaneCommand::FilterClear => {
                if self.quick_filter.take().is_some() {
                    let t = self.cursor_name();
                    return self.rebuild(ctx, t);
                }
            }
            PaneCommand::SortBy(col) => {
                if self.sort.column == col {
                    self.sort.descending = !self.sort.descending;
                } else {
                    self.sort = SortSpec {
                        column: col,
                        descending: false,
                    };
                }
                let t = self.cursor_name();
                let mut out = self.rebuild(ctx, t);
                out.push(PaneRequest::Settings(InterfaceEdit::Sort(
                    self.id.side,
                    self.sort,
                )));
                return out;
            }
            PaneCommand::ToggleHidden => {
                self.show_hidden = !self.show_hidden;
                return match self.id.side {
                    Side::Local => {
                        let t = self.cursor_name();
                        let mut out = self.rebuild(ctx, t);
                        out.push(PaneRequest::Settings(InterfaceEdit::ShowHiddenLocal(
                            self.show_hidden,
                        )));
                        out
                    }
                    Side::Remote => {
                        let mut out = vec![PaneRequest::Settings(
                            InterfaceEdit::ForceShowHiddenRemote(self.show_hidden),
                        )];
                        out.extend(self.reload(ctx, true));
                        out
                    }
                };
            }
            PaneCommand::EditAddress => {
                if self.status != PaneStatus::NotConnected {
                    self.address_editing = true;
                }
            }
            PaneCommand::AddressCancel => self.address_editing = false,
            PaneCommand::AddressSubmit(text) => {
                self.address_editing = false;
                return match self.parse_address(&text) {
                    Ok(dir) => self.navigate(ctx, dir, NavKind::Normal, false),
                    Err(e) => {
                        self.set_error(error_message(&e, &text), ctx.now);
                        Vec::new()
                    }
                };
            }
            PaneCommand::MirrorOtherPane => {
                if let Some(dir) = self.dir.clone() {
                    return vec![PaneRequest::MirrorToOtherPane { pane: self.id, dir }];
                }
            }
            PaneCommand::ColumnMenu => {
                return vec![PaneRequest::ColumnMenu {
                    pane: self.id,
                    columns: self.columns.clone(),
                }];
            }
            PaneCommand::Escape => {
                if self.visual_anchor.take().is_none() && self.quick_filter.take().is_some() {
                    let t = self.cursor_name();
                    return self.rebuild(ctx, t);
                }
            }
            PaneCommand::Cancel => {
                if self.pending.take().is_some() {
                    self.status = if self.id.side == Side::Remote && self.server.is_none() {
                        PaneStatus::NotConnected
                    } else {
                        PaneStatus::Ready
                    };
                }
            }
            PaneCommand::FileOp(FileOp::Refresh) => return self.reload(ctx, true),
            PaneCommand::FileOp(op) => {
                let selection = if op.needs_selection() {
                    self.selection()
                } else {
                    self.dir.clone().map(|dir| Selection {
                        dir,
                        entries: Arc::from(Vec::new()),
                    })
                };
                if let Some(selection) = selection {
                    return vec![PaneRequest::FileOp {
                        pane: self.id,
                        op,
                        selection,
                    }];
                }
            }
        }
        Vec::new()
    }

    fn open(&mut self, ctx: &PaneCtx<'_>) -> Vec<PaneRequest> {
        if self.has_parent_row() && self.cursor == 0 {
            return self.parent(ctx);
        }
        let Some(entry) = self.cursor_entry().cloned() else {
            return Vec::new();
        };
        if entry.is_dir_like() {
            return match self.dir.as_ref().map(|d| d.join(&entry.name)) {
                Some(Ok(target)) => self.navigate(ctx, target, NavKind::Normal, false),
                Some(Err(e)) => {
                    self.set_error(error_message(&e, &entry.name), ctx.now);
                    Vec::new()
                }
                None => Vec::new(),
            };
        }
        let op = match ctx.settings.interface.enter_on_file {
            EnterOnFile::Transfer => FileOp::Transfer,
            EnterOnFile::View => FileOp::View,
            EnterOnFile::Edit => FileOp::Edit,
            EnterOnFile::None => return Vec::new(),
        };
        self.command(PaneCommand::FileOp(op), ctx)
    }

    fn parent(&mut self, ctx: &PaneCtx<'_>) -> Vec<PaneRequest> {
        let Some(dir) = self.dir.clone() else {
            return Vec::new();
        };
        match dir.parent() {
            Some(p) => self.navigate(ctx, p, NavKind::Parent(dir.file_name()), false),
            None => Vec::new(),
        }
    }

    /// Parses the address bar: local `~`, `~/x`, relative to the current dir, `C:` on
    /// Windows; remote relative to the current dir with `..` normalised.
    fn parse_address(&self, text: &str) -> Result<PaneDir, Error> {
        let text = text.trim_end_matches(['\r', '\n']);
        if text.is_empty() {
            return Err(Error::InvalidInput("empty path".into()));
        }
        match self.id.side {
            Side::Remote => {
                let base = match &self.dir {
                    Some(PaneDir::Remote(p)) => p.clone(),
                    _ => RemotePath::root(),
                };
                base.resolve(text).map(PaneDir::Remote)
            }
            Side::Local => {
                let home = directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf());
                let path = expand_local(text, home.as_deref(), self.dir.as_ref())?;
                // Normalise `..` and check the path maps to the backend form.
                let mapped = from_native(&path)?;
                to_native(&mapped).map(PaneDir::Local)
            }
        }
    }

    /// A successful or failed listing.
    fn loaded(
        &mut self,
        request: RequestId,
        dir: PaneDir,
        result: Result<Arc<Listing>, Arc<Error>>,
        ctx: &PaneCtx<'_>,
    ) -> Vec<PaneRequest> {
        let Some(pending) = self.pending.take_if(|p| p.request == request) else {
            // Stale (an older request): dropped.
            return Vec::new();
        };
        match result {
            Err(e) => {
                if matches!(*e, Error::Cancelled) {
                    self.status = PaneStatus::Ready;
                    return Vec::new();
                }
                let message = error_message(&e, &dir.display());
                self.status = PaneStatus::Error {
                    message: message.clone(),
                    at: ctx.now,
                };
                self.set_error(message, ctx.now);
                Vec::new()
            }
            Ok(listing) => {
                self.status = PaneStatus::Ready;
                if self.dir.as_ref() == Some(&dir) && pending.kind == NavKind::Reload {
                    return self.replace_same_dir(listing, ctx);
                }
                let leaving = self.cursor_entry().map(|e| e.name.clone());
                let old = self.dir.take();
                if let (Some(old), Some(name)) = (&old, leaving) {
                    self.cursor_memory.put(old.clone(), name);
                }
                match (&pending.kind, old) {
                    (NavKind::Back, Some(old)) => {
                        self.history.back.pop();
                        push_capped(&mut self.history.forward, old);
                    }
                    (NavKind::Forward, Some(old)) => {
                        self.history.forward.pop();
                        push_capped(&mut self.history.back, old);
                    }
                    (_, Some(old)) if old != dir => {
                        push_capped(&mut self.history.back, old);
                        self.history.forward.clear();
                    }
                    _ => {}
                }
                let target = match (&pending.kind, self.cursor_memory.get(&dir)) {
                    (NavKind::Parent(Some(child)), _) => CursorTarget::Name(child.clone(), 0),
                    (_, Some(name)) => CursorTarget::Name(name.to_owned(), 0),
                    _ => CursorTarget::Top,
                };
                self.dir = Some(dir);
                self.listing = Some(listing);
                self.marks = Marks::with_len(self.listing.as_ref().map_or(0, |l| l.entries.len()));
                self.visual_anchor = None;
                self.quick_filter = None;
                self.offset = 0;
                self.rebuild(ctx, target)
            }
        }
    }

    /// A new listing of the shown directory: cursor and marks stay on the same names.
    fn replace_same_dir(&mut self, listing: Arc<Listing>, ctx: &PaneCtx<'_>) -> Vec<PaneRequest> {
        let marked: Vec<String> = match &self.listing {
            Some(old) => self
                .marks
                .iter()
                .filter_map(|i| old.entries.get(i as usize).map(|e| e.name.clone()))
                .collect(),
            None => Vec::new(),
        };
        let target = self.cursor_name();
        let mut marks = Marks::with_len(listing.entries.len());
        if !marked.is_empty() {
            let set: std::collections::HashSet<&str> = marked.iter().map(String::as_str).collect();
            for (i, e) in listing.entries.iter().enumerate() {
                if set.contains(e.name.as_str()) {
                    marks.set(u32::try_from(i).unwrap_or(u32::MAX), true);
                }
            }
        }
        self.marks = marks;
        self.listing = Some(listing);
        self.rebuild(ctx, target)
    }
}

/// `~`, `~/x`, relative and (Windows) `C:` local paths.
pub(crate) fn expand_local(
    text: &str,
    home: Option<&std::path::Path>,
    current: Option<&PaneDir>,
) -> Result<PathBuf, Error> {
    let no_home = || Error::InvalidInput("no home directory".into());
    let sep = |c: char| std::path::is_separator(c);
    if text == "~" {
        return home.map(std::path::Path::to_path_buf).ok_or_else(no_home);
    }
    if let Some(rest) = text.strip_prefix('~').filter(|r| r.starts_with(sep)) {
        let home = home.ok_or_else(no_home)?;
        return Ok(home.join(rest.trim_start_matches(sep)));
    }
    #[cfg(windows)]
    {
        let b = text.as_bytes();
        if b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
            return Ok(PathBuf::from(format!("{text}\\")));
        }
    }
    let p = PathBuf::from(text);
    if p.is_absolute() {
        return Ok(p);
    }
    match current {
        Some(PaneDir::Local(c)) => Ok(c.as_path().join(p)),
        _ => Err(Error::InvalidInput(format!(
            "path is not absolute: \"{text}\""
        ))),
    }
}

/// The user message for a listing error (without the `Error: ` prefix).
pub(crate) fn error_message(e: &Error, dir: &str) -> String {
    match e {
        Error::PermissionDenied(_) => format!("Permission denied: {dir}"),
        Error::NotFound(_) => format!("Directory not found: {dir}"),
        Error::Timeout => format!("Timed out listing {dir}"),
        Error::Connection(_) => "Connection lost".to_owned(),
        Error::Protocol { code, message } => match code {
            Some(c) => format!("{c} {message}"),
            None => message.clone(),
        },
        Error::InvalidInput(msg) => msg.clone(),
        other => other.to_string(),
    }
}
