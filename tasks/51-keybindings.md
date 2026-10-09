# T51 — Keybindings (hybrid)

**Phase:** F TUI · **Milestone:** M1 · **Depends on:** T50 · **Crate(s):** `courier-ftp` (`keymap/`, `action.rs`, `config.rs`, `.config/config.json`, `docs/keybindings.md`) · **Decisions:** D6, D7 · **FEATURES.md:** §3 (keyboard shortcuts for most actions)
**Related (integrates with, not blocking):** T59, T62, T63, T64, T65, T68, T77
**Reference:** sverb `crates/sverb-tui/src/keymap/` (`chord.rs` grammar and normalisation, `keymap.rs` sequence lookup, `validate.rs`, `dump.rs`, `whichkey.rs`), `docs/keybindings.md` (generated, `SVERB_BLESS`), SPEC §8.2–8.3

## Goal

A complete default keymap that combines Midnight Commander's function keys (F5 copy,
F6 move, F7 mkdir, F8 delete, Tab switches panes) with vim motions (`j/k/h/l`, `gg`/`G`,
`/`), works in a plain xterm, tmux and Windows Terminal, and is fully rebindable in the
user config. Multi-key sequences (`g g`, `ctrl-x d`, `s n`) work at human typing speed
with a configurable timeout, pending keys are shown, bad key strings produce readable
errors instead of panics, conflicts are reported, and the help overlay and
`docs/keybindings.md` are generated from the same registry.

## Context

- Before (T50): `Mode` (`Normal`, `FileList`, `Tree`, `Log`, `Queue`, `SiteManager`,
  `Filter`, `Input`, `Dialog`) with `Mode::chain()`, `Action` (internal variants
  `#[serde(skip)]`, bindable unit variants), `KeyChord` with normalisation
  (`from_key_event`), the T50 `KeyResolver` (single-chord lookup), the routing pipeline,
  the help overlay and `AppHarness`. The template's `parse_key_sequence` lower-cases the
  whole string (so `G` cannot be bound), `unwrap()`s parse errors and clears pending
  keys on every tick.
- T05 defines `interface.key_sequence_timeout_ms` (u32, default 1000, range 200–5000)
  and `interface.enter_on_file` (`EnterOnFile`: `transfer` default, `view`, `edit`,
  `none`).
- Owners of the actions listed below implement them (T30, T44, T45, T53–T74, T90); this
  task defines the
  names, descriptions, groups and default keys. An action whose owner has not landed
  yet shows the status message "‹Name› is not available yet".
- Later: T77 publishes `docs/keybindings.md`; T68 shows the bindings read-only; T76
  `PtyApp` sends keys in this grammar.

## Technical specification

### Types and APIs

```rust
// keymap/chord.rs (extends T50's KeyChord)
impl FromStr for KeyChord { type Err = ChordParseError; }    // one chord
impl fmt::Display for KeyChord;                              // canonical form, round-trips
pub fn parse_sequence(s: &str) -> Result<Vec<KeyChord>, ChordParseError>;
pub fn display_sequence(seq: &[KeyChord]) -> String;         // "ctrl-x d"
pub const MAX_SEQUENCE_LEN: usize = 4;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChordParseError { pub input: String, pub reason: String }   // Display: invalid key `…`: reason

// action.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group { General, Focus, View, Tabs, Connection, Navigation, Selection, Sorting,
                 FileOps, Queue, Log, Tree, SiteManager, Compare, Tools, Text, Dialog }
pub struct ActionMeta { pub name: &'static str, pub description: &'static str,
                        pub group: Group, pub owner: &'static str /* "T62" */ }
impl Action {
    /// Metadata for bindable actions; None for internal ones.
    pub fn meta(&self) -> Option<&'static ActionMeta>;
}
/// Every bindable action, in documentation order.
pub static BINDABLE: &[(Action, ActionMeta)];

// keymap/keymap.rs
pub struct Keymap { tables: HashMap<Mode, Table> }       // effective (defaults ⊕ user)
struct Table { bindings: HashMap<Vec<KeyChord>, Action>, prefixes: HashSet<Vec<KeyChord>> }
impl Keymap {
    /// Never fails: problems are returned and the offending entries skipped.
    pub fn build(defaults: &RawKeymap, user: &RawKeymap) -> (Self, Vec<KeymapProblem>);
    pub fn lookup(&self, mode: Mode, seq: &[KeyChord]) -> Lookup;   // Exact(Action) | Prefix | None
    pub fn bindings_for(&self, chain: &[Mode]) -> Vec<BindingRow>;  // help overlay and docs
    pub fn continuations(&self, chain: &[Mode], prefix: &[KeyChord]) -> Vec<(KeyChord, Action)>;
}
/// `keybindings` exactly as written in a config file: mode name → key string → action name.
pub type RawKeymap = BTreeMap<String, BTreeMap<String, String>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeymapProblem { pub mode: String, pub key: String, pub action: String, pub kind: ProblemKind }
pub enum ProblemKind {
    UnknownMode,
    BadKey(String),                         // ChordParseError reason
    SequenceTooLong,                        // > MAX_SEQUENCE_LEN chords
    UnknownAction,                          // not a bindable action name (or an internal one)
    Duplicate { other_key: String },        // two strings normalise to the same sequence
    Unreachable { mode: Mode, blocked_by: String },  // prefix conflict in a chain
}
impl fmt::Display for KeymapProblem;        // one readable line, see Errors

// keymap/resolver.rs (replaces T50's internals; same public API)
pub struct KeyResolver { keymap: Keymap, pending: Vec<KeyChord>, mode: Mode,
                         deadline: Option<Instant>, timeout: Duration, which_key_at: Option<Instant> }
pub enum Resolution { Action(Action), Pending, Unbound, Cancelled }
impl KeyResolver {
    pub fn resolve(&mut self, key: KeyChord, mode: Mode, now: Instant) -> Resolution;
    pub fn deadline(&self) -> Option<Instant>;          // earliest of timeout and which-key
    pub fn on_timeout(&mut self, now: Instant);
    pub fn pending_display(&self) -> Option<String>;     // e.g. "ctrl-x", "g"
    pub fn which_key(&self, now: Instant) -> Option<Vec<(KeyChord, Action)>>;
}
pub const WHICH_KEY_DELAY: Duration = Duration::from_millis(500);

// components.rs (T50 trait, one addition)
/// Bindable actions this component implements; used for "not available yet".
fn handled_actions(&self) -> &'static [Action] { &[] }
```

### Behaviour

#### Key string grammar

```
binding   = sequence | angle-seq
sequence  = chord { WS chord }                 (1..=4 chords, WS = one or more spaces)
angle-seq = "<" chord ">" { "<" chord ">" }    (template form, kept for compatibility)
chord     = { modifier "-" } key
modifier  = "ctrl" | "alt" | "shift" | "super"         (case-insensitive, any order, each once)
key       = named | fkey | char
named     = "space" | "enter" | "esc" | "tab" | "backtab" | "backspace" | "delete"
          | "insert" | "home" | "end" | "pageup" | "pagedown" | "up" | "down" | "left"
          | "right" | "minus" | "lt" | "gt"
          | aliases: "escape" "return" "del" "ins" "pgup" "pgdn" "hyphen"   (case-insensitive)
fkey      = ("f" | "F") 1..24
char      = one printable Unicode scalar value that is not whitespace (case-sensitive)
```

Rules (adapted from sverb `chord.rs`):
- A lone `-` is the minus key; `ctrl--` is ctrl + minus. `<` and `>` are plain chars in
  the space-separated form; inside the angle form write `lt` / `gt`.
- Without `ctrl`, an uppercase letter means shift: `G` = `shift-g`; `alt-G` = alt+shift+g.
  With `ctrl` the letter case is ignored (`ctrl-A` = `ctrl-a`); write `ctrl-shift-a`
  for the shifted chord. SHIFT on other printable chars is dropped (`?`, `+`, `*`).
- `backtab` = `shift-tab`. Legacy control bytes: `ctrl-4`/0x1C = `ctrl-\`, `ctrl-5` =
  `ctrl-]`, `ctrl-6` = `ctrl-^`, `ctrl-7`/`ctrl-/` = `ctrl-_`.
- The canonical `Display` is lower-case modifiers in the order `ctrl-alt-shift-super-`,
  chords separated by one space; `parse(display(x)) == x` for every chord.
- The value `"none"` unbinds the key in that mode (removes a default).
- Errors name the input and the reason: `invalid key "ctrl-foo": unknown key name "foo"`,
  `invalid key "g g g g g": sequences are limited to 4 keys`,
  `invalid key "<ctrl-q": unbalanced "<"`.

#### Building the effective keymap

1. Parse `.config/config.json` (defaults, baked in) and the user config's `keybindings`
   as `RawKeymap` (plain strings, so serde never fails on a bad key — this replaces the
   template's `parse_key_sequence(..).unwrap()`).
2. For each (mode, key string, action name): unknown mode → `UnknownMode`; parse the key
   (`BadKey`, `SequenceTooLong`); `"none"` → remove; unknown or internal action name →
   `UnknownAction`. Valid entries are inserted keyed by the normalised sequence; user
   entries replace default entries with the same sequence.
3. Two strings of the **same source and mode** that normalise to the same sequence
   (`"G"` and `"shift-g"`) → `Duplicate`; the first in sorted key-string order is kept.
4. **Prefix conflicts** per chain (`Mode::chain()` for every mode): if sequence `P` is
   bound and a different bound sequence `S` starts with `P` (both in the same table, or
   in two tables of one chain), one of them can never fire: by the lookup order below, the
   exact match wins when it is in the same or a higher table, otherwise the longer
   sequence wins. The unreachable binding is reported as `Unreachable { mode, blocked_by }`
   and kept (it may be reachable in another chain). The default keymap must produce
   zero problems (test).
5. A user binding that **replaces** a binding of a lower table in the same chain with
   the same sequence (e.g. `tab` in `Input` vs `Normal`) is an intended override, not a
   problem.

#### Resolving keys (sequence state machine)

State: `pending` (chords typed so far), `mode` at the time the first chord was typed,
`deadline`.

```
on key k at time now (mode m):
  if pending non-empty and k == esc:    clear → Cancelled (consumed)
  if pending non-empty and m != mode:   clear pending (focus changed)
  seq = pending + [k]
  for table in m.chain():               // highest priority first
     match table.lookup(seq):
       Exact(a)  → clear → Action(a)
       Prefix    → pending = seq; deadline = now + timeout → Pending
  // no table knows seq
  if pending non-empty: clear; re-resolve [k] alone once (so a stray `g` then `j` moves down)
  else → Unbound
on timeout (now >= deadline): clear pending (no action)
```
- `timeout` = `interface.key_sequence_timeout_ms` (default 1000 ms, range 200–5000,
  T05 validation). The App's `select!` sleeps until `deadline()` (T50), so expiry does
  not depend on the tick rate.
- `pending_display()` shows the pending chords (`ctrl-x`, `g`, `s`); the status bar shows
  it in the key-hint area (T57; T50's minimal status line until then).
- **Which-key popup**: when a prefix stays pending for `WHICH_KEY_DELAY` (500 ms), the
  app draws a popup above the status bar listing `continuations()` (`d Disconnect`,
  `r ReconnectLast`, …), at most 16 rows sorted by key, more as `… N more (F1)`. It closes
  with the sequence.
- Keys consumed by a focused text widget (T50 routing step 2) never reach the resolver.
- Unhandled actions: when a bindable action reaches dispatch and no component lists it in
  `handled_actions()` and it is not App-level, the status line shows
  "‹Description› is not available yet" (keeps the keymap stable while features land).

#### Default keymap

Notation: `ctrl-x d` = press `ctrl-x`, release, press `d`. "Portable" = works in xterm,
tmux and Windows Terminal without configuration (see Terminal caveats). Owner = task
that implements the action. This is the complete default keymap; every other task
references these keys and action names exactly. Two control keys are deliberately
**not bound anywhere**: `ctrl-h` (arrives as `backspace`; hidden files are `.` in lists)
and `ctrl-j` (is line feed; the queue toggle is `ctrl-x j`).

**`Normal` (global; consulted in every non-modal mode after the focused table)**

| Keys | Action | Description | Group | Owner |
|---|---|---|---|---|
| `f1`, `?` | `Help` | Help: bindings for the current mode | General | T50 |
| `f10`, `ctrl-q` | `Quit` | Quit (confirm when transfers run) | General | T50 |
| `ctrl-z` | `Suspend` | Suspend to the shell (Unix) | General | T50 |
| `g r` | `Redraw` | Clear and redraw the screen | General | T50 |
| `ctrl-c` | `Cancel` | Cancel the focused pane's running operation | General | T50 |
| `f9` | `Settings` | Settings (unit action, opens at the first section; T68 additionally uses the internal message `OpenSettingsAt(SectionId)` to open at a given section — an internal `#[serde(skip)]` variant, not a key binding, not in `BINDABLE`) | General | T68 |
| `tab` | `FocusOtherSide` | Switch between local and remote list | Focus | T50 |
| `backtab` | `FocusNextRegion` | Focus next region (log, trees, lists, queue) | Focus | T50 |
| `g l` | `FocusLog` | Focus message log | Focus | T50 |
| `g q` | `FocusQueue` | Focus queue | Focus | T50 |
| `g f` | `FocusFiles` | Focus the last file list | Focus | T50 |
| `ctrl-x 1` … `ctrl-x 7` | `FocusRegion1` … `FocusRegion7` | Focus region: 1 quickconnect, 2 local tree, 3 local list, 4 remote tree, 5 remote list, 6 log, 7 queue | Focus | T50 |
| `ctrl-k` | `FocusQuickconnect` | Focus the quickconnect bar (opens the dialog when the bar is hidden) | Focus | T58 |
| `ctrl-l` | `ToggleLog` | Show/hide message log | View | T50 |
| `ctrl-x j` | `ToggleQueuePane` | Show/hide queue | View | T50 |
| `ctrl-e` | `ToggleTree` | Show/hide directory trees | View | T50 |
| `ctrl-x q` | `ToggleQuickconnect` | Show/hide quickconnect bar | View | T58 |
| `g x` | `SwapPanes` | Swap local and remote sides | View | T50 |
| `z 1` / `z 2` / `z 3` | `LayoutClassic` / `LayoutExplorer` / `LayoutWidescreen` | Layout | View | T50 |
| `ctrl-t` | `NewTab` | New tab | Tabs | T61 |
| `ctrl-w` | `CloseTab` | Close tab (confirm when connected) | Tabs | T61 |
| `alt-1` … `alt-9`, `g 1` … `g 9` | `GoToTab1` … `GoToTab9` | Go to tab N | Tabs | T61 |
| `g t`, `ctrl-pagedown` | `NextTab` | Next tab | Tabs | T61 |
| `g T`, `ctrl-pageup` | `PrevTab` | Previous tab | Tabs | T61 |
| `ctrl-x t` | `RenameTab` | Rename tab | Tabs | T61 |
| `ctrl-x T` | `DuplicateTab` | Duplicate tab (same server and directories) | Tabs | T61 |
| `ctrl-x <` / `ctrl-x >` | `MoveTabLeft` / `MoveTabRight` | Move tab left / right | Tabs | T61 |
| `ctrl-s` | `SiteManager` | Site Manager | Connection | T59 |
| `ctrl-x s` | `SitePicker` | Quick site picker (fuzzy) | Connection | T59 |
| `ctrl-x r` | `ReconnectLast` | Reconnect (active tab's server, else the last server) | Connection | T58 |
| `ctrl-x S` | `SaveAsSite` | Save the current connection as a site | Connection | T58 |
| `ctrl-x d` | `Disconnect` | Disconnect the current tab | Connection | T61 |
| `ctrl-x i` | `ServerInfo` | Connection and encryption details | Connection | T57 |
| `ctrl-x ctrl-l` | `LockVault` | Lock the vault | Connection | T30, T60 |
| `ctrl-x N` | `NetworkWizard` | Network configuration wizard | Connection | T72 |
| `ctrl-r` | `Refresh` | Refresh both panes (bypass cache) | FileOps | T62 |
| `ctrl-x m` | `ManualTransfer` | Manual transfer | FileOps | T62 |
| `ctrl-x n` | `NewFile` | New empty file in the focused (else last focused) list | FileOps | T62 |
| `ctrl-x e` | `EditedFilesList` | Files being edited | FileOps | T63 |
| `ctrl-x v` | `ShowRawListing` | Raw directory listing of the focused (else remote) list | FileOps | T71 |
| `ctrl-p` | `ProcessQueue` | Start/stop processing the queue | Queue | T56 |
| `ctrl-x k` | `ToggleSpeedLimit` | Speed limits on/off | Queue | T44, T57 |
| `ctrl-x a` | `CycleTransferType` | Transfer type Auto/ASCII/Binary | Queue | T57 |
| `ctrl-y` | `ToggleSyncBrowsing` | Synchronized browsing | Compare | T66 |
| `ctrl-o` | `ToggleComparison` | Directory comparison | Compare | T66 |
| `ctrl-x c` | `CompareOptions` | Comparison options | Compare | T66 |
| `ctrl-x =` | `SelectByStatus` | Select rows by comparison status | Compare | T66 |
| `ctrl-f` | `Search` | Search files | Tools | T65 |
| `ctrl-b` | `Bookmarks` | Bookmarks menu | Tools | T64 |
| `ctrl-x b` | `AddBookmark` | Add bookmark for the current directories | Tools | T64 |
| `ctrl-x f` | `FiltersDialog` | Directory listing filters | Tools | T67 |
| `ctrl-x p` | `OpenNextPrompt` | Open the next pending prompt | Tools | T69 |
| `ctrl-x y` | `SyncPanel` | Sync panel (feature `sync`) | Tools | T90 |
| `ctrl-x u` | `DismissUpdate` | Dismiss the update notice | Tools | T74 |
| `ctrl-x D` | `ShowAppLog` | Application log (only with `--debug`) | Tools | T71 |
| `ctrl-x l` | `ClearLog` | Clear the message log of the current scope | Log | T55 |
| `ctrl-x w` | `SaveLogAs` | Save the message log to a file | Log | T71 |

**The `ctrl-x` prefix table** (all in `Normal`; the which-key popup lists exactly these):

| Key | Action | Owner | | Key | Action | Owner |
|---|---|---|---|---|---|---|
| `a` | `CycleTransferType` | T57 | | `p` | `OpenNextPrompt` | T69 |
| `b` | `AddBookmark` | T64 | | `q` | `ToggleQuickconnect` | T58 |
| `c` | `CompareOptions` | T66 | | `r` | `ReconnectLast` | T58 |
| `d` | `Disconnect` | T61 | | `s` | `SitePicker` | T59 |
| `D` | `ShowAppLog` | T71 | | `S` | `SaveAsSite` | T58 |
| `e` | `EditedFilesList` | T63 | | `t` | `RenameTab` | T61 |
| `f` | `FiltersDialog` | T67 | | `T` | `DuplicateTab` | T61 |
| `i` | `ServerInfo` | T57 | | `u` | `DismissUpdate` | T74 |
| `j` | `ToggleQueuePane` | T50 | | `v` | `ShowRawListing` | T71 |
| `k` | `ToggleSpeedLimit` | T44/T57 | | `w` | `SaveLogAs` | T71 |
| `l` | `ClearLog` | T55 | | `y` | `SyncPanel` | T90 |
| `m` | `ManualTransfer` | T62 | | `=` | `SelectByStatus` | T66 |
| `n` | `NewFile` | T62 | | `<` / `>` | `MoveTabLeft` / `MoveTabRight` | T61 |
| `N` | `NetworkWizard` | T72 | | `1` … `7` | `FocusRegion1` … `FocusRegion7` | T50 |
| | | | | `ctrl-l` | `LockVault` | T30/T60 |

No other `ctrl-x` continuation is bound by default; a new one requires an update of this
table.

**`FileList`** (T53 pane; file operations T62/T63)

| Keys | Action | Description | Group | Owner |
|---|---|---|---|---|
| `j`, `down` / `k`, `up` | `CursorDown` / `CursorUp` | Move cursor | Navigation | T53 |
| `ctrl-d` / `ctrl-u` | `HalfPageDown` / `HalfPageUp` | Half page | Navigation | T53 |
| `pagedown` / `pageup` | `PageDown` / `PageUp` | Page | Navigation | T53 |
| `g g`, `home` / `G`, `end` | `Top` / `Bottom` | First / last row | Navigation | T53 |
| `l`, `right`, `enter` | `Open` | Enter directory; on a file: `interface.enter_on_file` | Navigation | T53 |
| `h`, `left`, `backspace` | `Parent` | Parent directory | Navigation | T53 |
| `alt-left`, `[` / `alt-right`, `]` | `Back` / `Forward` | Directory history | Navigation | T53 |
| `a` | `EditAddress` | Edit the address bar | Navigation | T53 |
| `=` | `MirrorOtherPane` | Open the equivalent directory in the other pane | Navigation | T53 |
| `esc` | `Escape` | Leave visual mode / clear quick filter | Navigation | T53 |
| `space`, `insert` | `ToggleMark` | Mark/unmark and move down | Selection | T53 |
| `v` | `VisualMode` | Range selection | Selection | T53 |
| `ctrl-a` | `MarkAll` | Mark all | Selection | T53 |
| `*` | `InvertMarks` | Invert marks | Selection | T53 |
| `+` / `-` | `MarkPattern` / `UnmarkPattern` | Mark / unmark by pattern | Selection | T53 |
| `/` | `QuickFilter` | Quick filter | Selection | T53 |
| `s n` `s s` `s t` `s m` `s p` `s o` | `SortByName` `SortBySize` `SortByType` `SortByModified` `SortByPermissions` `SortByOwner` | Sort (again = reverse) | Sorting | T53 |
| `.` | `ToggleHidden` | Show/hide hidden files | View | T53 |
| `C` | `ColumnMenu` | Columns | View | T53 |
| `f5` | `Transfer` | Copy: transfer selection to the other side | FileOps | T62 |
| `shift-f5`, `f15`, `Q` | `QueueOnly` | Add selection to the queue only | FileOps | T62 |
| `f6` | `Move` | Move / rename to a path | FileOps | T62 |
| `f2` | `Rename` | Rename | FileOps | T62 |
| `f7` | `Mkdir` | Make directory | FileOps | T62 |
| `shift-f7`, `f17`, `M` | `MkdirEnter` | Make directory and enter it | FileOps | T62 |
| `f8`, `delete` | `Delete` | Delete (confirm) | FileOps | T62 |
| `f3`, `o` | `View` | View | FileOps | T63 |
| `f4`, `e` | `Edit` | Edit | FileOps | T63 |
| `c` | `Chmod` | Change permissions | FileOps | T62 |
| `y u` / `y U` | `CopyUrl` / `CopyUrlOptions` | Copy URL / with options | FileOps | T62 |
| `:` | `CustomCommand` | Send a raw command | FileOps | T62 |

**`Filter`** (typing a quick filter; printable keys and `backspace` go to the field)

| Keys | Action | Description | Owner |
|---|---|---|---|
| `enter` | `FilterAccept` | Keep the filter, back to the list | T53 |
| `esc` | `FilterClear` | Clear the filter, back to the list | T53 |
| `down` / `up` | `CursorDown` / `CursorUp` | Move the cursor while typing | T53 |

**`Tree`** (T54; action names are T54's)

| Keys | Action | Description | Owner |
|---|---|---|---|
| `j`, `down` / `k`, `up` | `TreeDown` / `TreeUp` | Move | T54 |
| `ctrl-d` / `ctrl-u` | `TreeHalfPageDown` / `TreeHalfPageUp` | Half page | T54 |
| `g g`, `home` / `G`, `end` | `TreeTop` / `TreeBottom` | First / last row | T54 |
| `l`, `right` | `TreeExpand` | Expand; if expanded, first child | T54 |
| `h`, `left` | `TreeCollapse` | Collapse; if collapsed or a leaf, parent | T54 |
| `o` | `TreeToggle` | Toggle expand | T54 |
| `enter` | `TreeOpen` | Show this directory in the file list | T54 |
| `ctrl-r` | `TreeRefresh` | Relist the cursor directory (overrides `Normal` `Refresh`) | T54 |
| `.` | `TreeRevealCurrent` | Reveal the file list's current directory | T54 |

**`Log`** (T55, T71)

| Keys | Action | Owner |
|---|---|---|
| `j`, `down` / `k`, `up` | `LogCursorDown` / `LogCursorUp` | T55 |
| `ctrl-d` / `ctrl-u` | `LogHalfPageDown` / `LogHalfPageUp` | T55 |
| `pagedown` / `pageup` | `LogPageDown` / `LogPageUp` | T55 |
| `g g`, `home` / `G`, `end` | `LogTop` / `LogBottom` | T55 |
| `/`, `n`, `N` | `LogSearch`, `LogSearchNext`, `LogSearchPrev` | T55 |
| `v`, `y` | `LogVisual`, `LogCopy` | T55 |
| `w`, `t`, `e` | `LogToggleWrap`, `LogToggleScope`, `LogCycleKindFilter` | T55 |
| `h`, `left` / `l`, `right` / `0` | `LogScrollLeft` / `LogScrollRight` / `LogScrollHome` | T55 |
| `esc` | `Escape` | T55 |
| `Y` | `CopyLog` (whole current view) | T71 |

**`Queue`** (T56)

| Keys | Action | Description | Owner |
|---|---|---|---|
| `j`, `down` / `k`, `up`, `ctrl-d` / `ctrl-u`, `pagedown` / `pageup`, `g g`, `home` / `G`, `end` | `CursorDown` / `CursorUp`, `HalfPageDown` / `HalfPageUp`, `PageDown` / `PageUp`, `Top` / `Bottom` | Move | T56 |
| `1` / `2` / `3` | `QueueTabQueued` / `QueueTabFailed` / `QueueTabSuccessful` | Switch list | T56 |
| `insert` | `ToggleMark` | Mark/unmark and move down | T56 |
| `v` | `VisualMode` | Range selection | T56 |
| `ctrl-a` | `MarkAll` | Mark all in this list | T56 |
| `enter`, `o` | `QueueToggleGroup` | Collapse/expand server group | T56 |
| `space` | `QueuePauseResume` | Pause/resume selected items | T56 |
| `+` / `-` | `QueuePriorityUp` / `QueuePriorityDown` | Priority | T56 |
| `K` / `J` | `QueueMoveUp` / `QueueMoveDown` | Move up / down | T56 |
| `t` / `b` | `QueueMoveTop` / `QueueMoveBottom` | Move to top / bottom | T56 |
| `x`, `delete` | `QueueRemove` | Remove selected | T56 |
| `X` | `QueueClearList` | Clear the Failed/Successful list (confirm) | T56 |
| `r` | `QueueResetRequeue` | Reset and requeue (failed list) | T56 |
| `e` | `QueueSetExistsAction` | File-exists action for selected items | T56 |
| `a` | `QueueCompletionAction` | Action after queue completion | T45, T56 |
| `m` | `QueueMenu` | All actions for the selection | T56 |
| `esc` | `Escape` | Cancel visual mode / close the menu | T56 |

**`SiteManager`** (T59; the Site Manager's tree has focus; the editor on the right uses
`Dialog`). The Site Manager is a full-screen modal, so its chain is `[SiteManager]` only
(T50 `Mode::chain`); `Help` and `Quit` are therefore listed in the table itself.

| Keys | Action | Description | Owner |
|---|---|---|---|
| `j`, `down` / `k`, `up`, `g g`, `home` / `G`, `end` | `CursorDown` / `CursorUp`, `Top` / `Bottom` | Move | T59 |
| `l`, `right` / `h`, `left` | `TreeExpand` / `TreeCollapse` | Expand / collapse (or parent) | T59 |
| `enter`, `o` | `SmConnect` | Site: open/connect (T61 target rules); folder: toggle | T59 |
| `O` | `SmConnectNewTab` | Connect in a new tab | T59 |
| `e`, `tab` | `SmEdit` | Focus the editor | T59 |
| `n` / `f` | `SmNewSite` / `SmNewFolder` | New site / folder | T59 |
| `d` | `SmDuplicate` | Duplicate | T59 |
| `r`, `f2` | `SmRename` | Rename inline | T59 |
| `x`, `delete` | `SmDelete` | Delete (confirm) | T59 |
| `m` / `p` | `SmMark` / `SmPaste` | Mark for move / move the marked item here | T59 |
| `C` / `M` | `SmCopyToVault` / `SmMoveToVault` | Copy / move to another vault (team vaults, T89/T90 stage B; "not available yet" before) | T59 |
| `/` | `SmFind` | Filter | T59 |
| `L` | `SmCredentialOverride` | My login for this site (team vaults; "not available yet" before T90) | T90 |
| `ctrl-s` | `SmSave` | Save the draft | T59 |
| `i` / `E` | `SmImport` / `SmExport` | Import / export | T59 |
| `[`, `ctrl-pageup` / `]`, `ctrl-pagedown` | `SmPrevTab` / `SmNextTab` | Editor tab | T59 |
| `esc`, `q` | `SmClose` | Close (unsaved-changes guard) | T59 |
| `f1`, `?` | `Help` | Help | T50 |
| `f10`, `ctrl-q` | `Quit` | Quit (unsaved-changes guard first) | T50 |

**`Input`** (single-line fields outside dialogs: quickconnect T58, `:` line T62, log search T55)

| Keys | Action | Owner |
|---|---|---|
| `enter` | `InputSubmit` | T50 |
| `esc` | `InputCancel` | T50 |
| `tab` / `backtab` | `NextField` / `PrevField` | T58 |
| `up` / `down` | `InputHistoryPrev` / `InputHistoryNext` | T58, T62 |

**`Dialog`** (T52)

| Keys | Action | Owner |
|---|---|---|
| `enter` | `DialogSubmit` (default button; inserts a newline in a multi-line field) | T52 |
| `esc` | `DialogCancel` | T52 |
| `tab` / `backtab` | `NextField` / `PrevField` | T52 |
| `ctrl-s` | `DialogSave` (forms) | T52 |
| `ctrl-pagedown` / `ctrl-pageup` | `NextFormTab` / `PrevFormTab` | T52 |

**Component-local keys (not in the keymap):** some full-screen views and menus read
plain letters as raw keys in `handle_key` because they act like buttons of that view:
the unlock screen (T60: `ctrl-r`, `ctrl-n`, `ctrl-b`, `ctrl-g`, forgot-screen letters),
trust prompts (T69: `t`/`alt-t`, `a`/`alt-a`, `c`/`alt-c`, `o`/`alt-o`, `r`/`alt-r`,
`d`/`alt-d`), the bookmarks menu (T64), the search view (T65), the sync panel (T90: `s`,
`o`), dialog mnemonics (`alt-<letter>`, T52). They are listed in each task, shown in the
view's own hint line, and are not rebindable in v1.

**Text editing keys (fixed, not rebindable; inside every text field, T52 `TextInput`)**:
`left`/`right`, `home`/`ctrl-a`, `end`/`ctrl-e`, `ctrl-left`/`alt-b` and
`ctrl-right`/`alt-f` (word), `backspace`, `delete`, `ctrl-w`/`alt-backspace` (delete word
back), `alt-d` (delete word forward), `ctrl-u` (delete to start), `ctrl-k` (delete to
end), bracketed paste. These are consumed by the field before any table is consulted.

`ctrl-d` is a half page in lists (vim); disconnect is `ctrl-x d`. `ctrl-h` and `ctrl-j`
are not bound anywhere (see Terminal caveats); hidden files use `.`, the queue toggle
`ctrl-x j`.

#### Terminal caveats

| Key | Problem | Default policy |
|---|---|---|
| `ctrl-h`, `ctrl-i`, `ctrl-m`, `ctrl-j`, `ctrl-[` | arrive as `backspace`, `tab`, `enter`, `enter`/LF, `esc` in legacy encoding | never bound by default (hidden files are `.`, queue toggle `ctrl-x j`); binding them emits no warning but the help shows "(may be received as backspace)" |
| `shift-f1`…`shift-f12` | rxvt/linux console send F11+ codes; some terminals send nothing | always paired with a portable alternative (`Q`, `M`) and the F13–F24 alias |
| `f1`, `f10`, `f11` | GNOME Terminal help/menu, fullscreen in many terminals | `f1`/`f10` paired with `?`/`ctrl-q`; `f11`, `f12` unbound |
| `alt-*` | macOS Terminal/iTerm2 need "Option as Meta" | every `alt-` binding has a portable alternative (`g 1` … `g 9`, `[`, `]`) |
| `ctrl-pageup/pagedown` | intercepted by some terminals (tab switching) | paired with `g t` / `g T` |
| `ctrl-s`, `ctrl-q` | XON/XOFF flow control in cooked mode | raw mode disables IXON (crossterm), so both arrive; documented |
| `ctrl-z` | job control | Unix only; Windows shows a message |

**Portable chord set** (used by the coverage test): printable characters; `ctrl-`
letters except `h i j m`; `f2`–`f9`; `up down left right home end pageup pagedown insert
delete tab backtab enter esc backspace space`. Every bindable action must have at least
one default sequence made only of portable chords.

#### Generated documentation

`docs/keybindings.md` is generated from `BINDABLE` (descriptions, groups, owners) plus the
default `.config/config.json` tables (keys), with an intro (grammar, timeout, caveats,
the "none" unbinding rule). A test fails when the committed file differs;
`COURIER_FTP_BLESS=1 cargo test -p courier-ftp keybindings_doc` rewrites it (T00 rule for
generated docs). The help overlay (T50) uses `bindings_for(chain)` plus `ActionMeta`
descriptions, grouped by `Group`.

### Data formats and configuration

`.config/config.json` holds the default tables exactly as listed above, one JSON object
per mode, keys in the space-separated form:

```json
"keybindings": {
  "Normal":   { "f1": "Help", "?": "Help", "f10": "Quit", "ctrl-q": "Quit",
                "ctrl-x d": "Disconnect", "ctrl-x j": "ToggleQueuePane",
                "ctrl-x 1": "FocusRegion1", "g t": "NextTab", "alt-1": "GoToTab1", "...": "..." },
  "FileList": { "j": "CursorDown", "g g": "Top", "G": "Bottom", "s n": "SortByName",
                ".": "ToggleHidden", "shift-f5": "QueueOnly", "f15": "QueueOnly", "Q": "QueueOnly", "...": "..." },
  "Filter": { }, "Tree": { }, "Log": { }, "Queue": { }, "SiteManager": { }, "Input": { }, "Dialog": { }
}
```

User override example (`config.json` in the user config dir):
```json
{ "keybindings": { "FileList": { "ctrl-d": "Delete", "f8": "none", "<g><h>": "Parent" } } }
```

| Setting | Type | Default | Notes |
|---|---|---|---|
| `interface.key_sequence_timeout_ms` | u32 | 1000 | 200–5000 (T05 validation) |
| `interface.enter_on_file` | `transfer` \| `view` \| `edit` \| `none` | `transfer` | used by `Open` on a file (T53) |

Mode names in config are the `Mode` variant names (`Normal`, `FileList`, `Tree`, `Log`,
`Queue`, `SiteManager`, `Filter`, `Input`, `Dialog`), matched case-sensitively; action names are the
`Action` variant names (`GoToTab3`, not `GoToTab(3)`; `FocusRegion3`, not the internal
`FocusRegion(Region)`).

### Errors

All keymap problems are non-fatal (T05 rule): the entry is skipped (or kept but
unreachable), each problem is logged once with `warn!` and collected into
`Config::problems`, the status line shows "N configuration problems — see the log", and
T52 shows the list in a dialog after startup. Line format:

```
keybindings.FileList."ctrl-foo": invalid key: unknown key name "foo"
keybindings.Normal."g": "Help" makes "g t" (NextTab) unreachable in mode FileList
keybindings.Queue."x": unknown action "Remove" (see docs/keybindings.md)
keybindings.Dialog."G" and "shift-g" are the same key; "shift-g" is ignored
```

No `courier_ftp_core::Error` is involved (binary-crate config).

### Security and logging

- Key events are logged only at `trace!` as action names; typed characters are never
  logged (they may be passwords in fields).
- The resolver never sees keys consumed by text fields (T50 step 2), so a password typed
  into a field can't trigger actions or appear in the pending display.
- User config is untrusted input: parsing is total (no panics), sequences are capped at 4
  chords, key strings at 64 bytes, and at most 1 000 bindings per mode are read (more →
  one `warn!`, rest ignored).

## Implementation steps

1. `KeyChord` `FromStr`/`Display`, `parse_sequence`, angle-form compatibility; parser tests; remove the template's `parse_key_event`/`parse_key_sequence`/`key_event_to_string` and the `unwrap()`.
2. `RawKeymap` deserialisation; `Keymap::build` with problems (unknown mode/action, bad key, duplicates, `none`).
3. Prefix-conflict analysis per chain; `KeymapProblem` display; startup reporting.
4. Sequence resolver with timeout, `Esc` cancel, re-resolve rule, `deadline()`; wire into T50's loop; pending display.
5. `BINDABLE` registry with all actions above (including the `Tree` and `SiteManager` modes); `handled_actions()` and "not available yet".
6. Full default tables in `.config/config.json` (including the complete `ctrl-x` table); zero-problem test; portability test; `ctrl_x_table_matches_spec` test.
7. Which-key popup; help overlay descriptions and groups.
8. `docs/keybindings.md` generator and staleness test; terminal caveats in the doc intro.

## Acceptance criteria

- [ ] AC1 Every bindable action has at least one default sequence made only of portable chords (`every_bindable_action_has_portable_default`), and the manual checklist (xterm, tmux 3.x, Windows Terminal; macOS Terminal noted) is ticked in the PR.
- [ ] AC2 Sequences fire with up to 999 ms between keys at the default timeout and do not fire at 1000 ms (paused-time tests); `interface.key_sequence_timeout_ms = 3000` lets 2.5 s pass.
- [ ] AC3 Bad key strings, unknown modes and unknown actions in the user config produce the documented one-line messages and never panic (property test over arbitrary strings).
- [ ] AC4 Duplicate and prefix conflicts are reported with both keys named; the shipped defaults produce zero problems.
- [ ] AC5 `ctrl-d` is half-page-down in `FileList`, `Disconnect` is `ctrl-x d`, `ToggleQueuePane` is `ctrl-x j`, `ToggleHidden` is `.`, and neither `ctrl-h` nor `ctrl-j` is bound in any mode; documented in `docs/keybindings.md`.
- [ ] AC6 `G`, `shift-g`, `<G>` parse to the same chord and `g` does not; `parse(display(x)) == x` for every chord (property test).
- [ ] AC7 Pending keys are shown while a prefix is pending and cleared on completion, `Esc`, timeout and focus change; the which-key popup appears after 500 ms.
- [ ] AC8 A user binding overrides a default with the same sequence; `"none"` removes a default.
- [ ] AC9 `docs/keybindings.md` is generated and the staleness test passes; the help overlay shows descriptions from the registry.
- [ ] AC10 An unimplemented action shows "… is not available yet" instead of doing nothing.
- [ ] AC11 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os` pass.
- [ ] AC12 The default `ctrl-x` continuations are exactly the 36 entries of the `ctrl-x` prefix table (letters, `=`, `<`, `>`, `1`–`7`, `ctrl-l`) with the listed actions; `alt-1`…`alt-9` and `g t`/`g T` switch tabs; `ctrl-x 1`…`ctrl-x 7` focus the listed regions.

## Tests

### Unit tests
- `parse_named_keys_table` — every named key and alias, `f1`…`f24`, `space`, `minus`, `lt`, `gt`. AC6.
- `parse_modifiers_any_order_and_case` — `Alt-Ctrl-x` = `ctrl-alt-x`. AC6.
- `parse_uppercase_means_shift` — `G` = `shift-g` = `<G>`, `ctrl-G` = `ctrl-g`, `alt-G` = alt+shift+g. AC6.
- `parse_minus_and_ctrl_minus` — `-`, `ctrl--`. AC6.
- `parse_angle_form_compat` — `<ctrl-q>`, `<g><g>`, `<lt>`. AC6.
- `parse_errors_are_readable` — `ctrl-foo`, `ctrl-`, `<ctrl-q`, `g g g g g`, `""`, 65-byte string → exact messages. AC3.
- `legacy_control_bytes_normalise` — `Char('4')+CTRL` = `ctrl-\`, `ctrl-/` = `ctrl-_`.
- `build_reports_unknown_mode_action_and_internal_action` — `"Tick"` is rejected. AC3.
- `build_duplicate_same_source` — `"G"` and `"shift-g"`. AC4.
- `build_prefix_conflict_same_table` and `build_prefix_conflict_across_chain` — `Normal "g"` vs `FileList "g g"`. AC4.
- `default_keymap_has_no_problems` — AC4.
- `user_overrides_default_and_none_unbinds` — AC8.
- `input_tab_override_is_not_a_problem` — rule 5.
- `ctrl_d_and_disconnect_defaults` — `ctrl-d` → `HalfPageDown`, `ctrl-x d` → `Disconnect`, `ctrl-x j` → `ToggleQueuePane`, `.` → `ToggleHidden`. AC5.
- `ctrl_h_and_ctrl_j_unbound_in_every_mode` — no default sequence in any mode contains `ctrl-h` or `ctrl-j`. AC5.
- `ctrl_x_table_matches_spec` — `continuations(Normal, [ctrl-x])` equals the 36-entry table (key → action) exactly. AC12.
- `tab_and_focus_region_defaults` — `alt-3`/`g 3` → `GoToTab3`, `g t`/`g T` → `NextTab`/`PrevTab`, `ctrl-x 6` → `FocusRegion6`, and `FocusRegion6` focuses `Log` in `AppHarness`. AC12.
- `site_manager_mode_defaults` — `o`/`enter` → `SmConnect`, `m`/`p` → `SmMark`/`SmPaste`, `C`/`M` → `SmCopyToVault`/`SmMoveToVault`, `L` → `SmCredentialOverride` (and `l` stays `TreeExpand`); chain `SiteManager → [SiteManager]`. AC12.
- `every_bindable_action_has_portable_default` — AC1.
- `registry_matches_enum` — every `Action` variant name (strum `VariantNames`) is in `BINDABLE` or in the internal list, and every `BINDABLE` name deserialises; `f9` → `Settings` in `Normal`, and `OpenSettingsAt` is internal (`meta()` is `None`, `"OpenSettingsAt"` in a user keymap → `UnknownAction`). AC9.
- `display_problem_lines` — the four example lines in Errors. AC3.

### Property / fuzz tests
- `prop_chord_display_roundtrip` — random `KeyChord` (all codes and modifier sets) → `parse(display(c)) == c`. AC6.
- `prop_parse_never_panics` — arbitrary strings into `parse_sequence` and `Keymap::build`. AC3.
- `prop_resolver_never_stuck` — random key/time sequences: after any key followed by `timeout` of idle time, `pending` is empty. AC7.

### Snapshot tests
- `snap_which_key_ctrl_x_80x24`, `snap_which_key_ctrl_x_160x48` — popup after `ctrl-x`. AC7.
- `snap_help_filelist_80x24`, `snap_help_filelist_160x48` — help overlay with descriptions and groups. AC9.
- `snap_pending_keys_status_80x24` — `g` pending shown in the status line. AC7.
- `snap_keymap_problems_status_80x24` — "2 configuration problems" message. AC3.

### Integration tests
- `sequence_fires_within_timeout` / `sequence_expires_at_timeout` (`start_paused`, `AppHarness`): `g` at 0 ms, `g` at 999 ms → `Top`; at 1000 ms → nothing, second `g` starts a new sequence. AC2.
- `custom_timeout_3000ms`. AC2.
- `esc_cancels_pending`, `focus_change_clears_pending`, `unbound_continuation_reresolves_key` — `g` then `j` moves down once. AC7.
- `keys_in_text_field_never_reach_resolver` — quickconnect field focused, typing `g g` inserts text. 
- `unimplemented_action_shows_not_available` — bind a test action with no handler. AC10.
- `keybindings_doc_is_current` — regenerates into memory and compares with `docs/keybindings.md`; `COURIER_FTP_BLESS=1` rewrites. AC9.
- `bad_user_config_starts_app` — user config with five bad entries; app starts, problems listed, valid entries active. AC3.

### End-to-end tests
- `e2e_pty_sequences_and_fkeys` (`PtyApp`, no Docker) — real binary in a PTY: `g g`, `G`, `tab`, `f1` then `esc`, `ctrl-x l`, `ctrl-x j`, with 500 ms between chords; screen changes as expected. AC1, AC2, AC12.
- Manual checklist (recorded in the PR): every default key in xterm 390+, tmux 3.3 (`TERM=tmux-256color`), Windows Terminal 1.20, macOS Terminal with and without Option-as-Meta. AC1.

## Out of scope

- A rebinding UI (T68 shows bindings read-only).
- A leader key and a command palette (sverb has both; not planned for v1).
- Mouse bindings (D7).
- `courier-ftp keys --dump` CLI (could be added to T70 later).

## Open questions

None. (Resolved by the coordinator: the keymap above is final; `ctrl-h`/`ctrl-j` are
unbound, the `ctrl-x` table is as listed, tabs use `alt-1..9`/`g t`/`g T`, focus regions
`ctrl-x 1..7`, the setting is `interface.enter_on_file`. Actions displaced from `ctrl-x`
by the final table moved to: `Redraw` `g r`, `SwapPanes` `g x`, layouts `z 1/2/3`,
`QueueCompletionAction` `a` in `Queue`, `QueueOnly` alias `Q`, `MkdirEnter` alias `M`.)
