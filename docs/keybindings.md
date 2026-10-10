<!-- Generated from crates/courier-ftp/src/action.rs (registry) and crates/courier-ftp/config/config.json (tables). Do not edit:
     run `COURIER_FTP_BLESS=1 cargo test -p courier-ftp keybindings_doc` to regenerate. -->

# Key bindings

courier-ftp combines Midnight Commander's function keys (`f5` copy, `f6` move, `f7`
mkdir, `f8` delete, `tab` switches sides) with vim motions (`j` `k` `h` `l`, `g g` / `G`,
`/`). Every binding below can be changed in the user configuration; the help overlay
(`f1` or `?`) shows the bindings of the focused region, including your changes.

## How keys are looked up

Each region has a key table (a *mode*). A key is looked up in the focused region's
table first, then in `Normal`, the global table. Dialogs (`Dialog`) and the Site Manager
(`SiteManager`) are modal: only their own table is consulted. Text fields (quickconnect,
dialog fields, filters) take printable keys and the text editing keys first, so typing
never triggers a binding.

| Mode | Used while | Tables consulted |
|---|---|---|
| `Normal` | nothing more specific has the focus | `Normal` |
| `FileList` | a file list has the focus | `FileList`, `Normal` |
| `Tree` | a directory tree has the focus | `Tree`, `Normal` |
| `Log` | the message log has the focus | `Log`, `Normal` |
| `Queue` | the queue has the focus | `Queue`, `Normal` |
| `Filter` | typing a quick filter | `Filter`, `Normal` |
| `Input` | a single-line field outside dialogs | `Input`, `Normal` |
| `SiteManager` | the Site Manager tree | `SiteManager` |
| `Dialog` | a dialog or overlay is open | `Dialog` |

## Key sequences

Several bindings are sequences: `ctrl-x d` means press `ctrl-x`, release, then press
`d`. While a sequence is pending, the typed keys are shown in the status bar; after
500 ms a popup lists the possible next keys. `esc` cancels a pending sequence. A key
that does not continue the sequence drops it and is then used on its own (a stray `g`
followed by `j` still moves down). A sequence expires after
`interface.key_sequence_timeout_ms` (default 1000 ms, 200–5000) without a key.

## Changing bindings

Add a `keybindings` object to `config.json` in the configuration directory. Mode names
and action names are the ones in the tables below (case-sensitive); `"none"` removes a
binding. Your bindings replace the built-in binding of the same key in the same mode.

```json
{ "keybindings": { "FileList": { "ctrl-d": "Delete", "f8": "none", "g h": "Parent" } } }
```

Problems (an unknown key name, mode or action, two spellings of the same key, a
binding that can never fire because another binding is a prefix of it) never stop
courier-ftp: the entry is skipped, the problem is written to the log, and the status bar
says how many problems there are.

### Key syntax

```text
binding   = chord { " " chord }               (1 to 4 chords)
          | "<" chord ">" { "<" chord ">" }   (older form, e.g. "<g><g>")
chord     = { modifier "-" } key
modifier  = ctrl | alt | shift | super        (any case, any order, each once)
key       = a named key | f1 … f24 | one printable character (case-sensitive)
```

- Named keys: `space enter esc tab backtab backspace delete insert home end pageup
  pagedown up down left right minus lt gt`, and the aliases `escape return del ins pgup
  pgdn hyphen`.
- An uppercase letter means shift: `G` is `shift-g`, `alt-G` is alt + shift + g. After
  `ctrl-` the case of a letter is ignored (`ctrl-A` is `ctrl-a`); write `ctrl-shift-a`
  for the shifted chord. Shift is ignored on other printable characters (`?`, `+`, `*`).
- A lone `-` is the minus key and `ctrl--` is ctrl + minus. `<` and `>` are plain
  characters, except in the `<…>` form, where they are written `lt` and `gt`.
- `backtab` is `shift-tab`. `ctrl-4` is `ctrl-\`, `ctrl-5` is `ctrl-]`, `ctrl-6` is
  `ctrl-^`, and `ctrl-7` and `ctrl-/` are `ctrl-_` (what terminals send for them).

## Terminal caveats

| Key | Problem | Default policy |
|---|---|---|
| `ctrl-h`, `ctrl-i`, `ctrl-m`, `ctrl-j`, `ctrl-[` | arrive as `backspace`, `tab`, `enter`, `enter`, `esc` | never bound by default (hidden files are `.`, the queue toggle is `ctrl-x j`) |
| `shift-f1` … `shift-f12` | some terminals send `f13`…`f24`, some nothing | paired with a portable key and the `f13`–`f24` alias |
| `f1`, `f10`, `f11` | terminal help, menu or full screen | `f1` / `f10` paired with `?` / `ctrl-q`; `f11`, `f12` unbound |
| `alt-*` | macOS Terminal and iTerm2 need "Option as Meta" | every `alt-` binding has a portable alternative (`g 1` … `g 9`, `[`, `]`) |
| `ctrl-pageup`, `ctrl-pagedown` | used by some terminals for their own tabs | paired with `g T` / `g t` |
| `ctrl-s`, `ctrl-q` | XON/XOFF flow control | courier-ftp turns flow control off while it runs |
| `ctrl-z` | job control | Unix only; Windows shows a message |

Every action has at least one default key that works in xterm, tmux and Windows
Terminal without configuration.

## Keys that are not in the tables

- **Text fields** (fixed): `left` / `right`, `home` / `ctrl-a`, `end` / `ctrl-e`,
  `ctrl-left` / `alt-b` and `ctrl-right` / `alt-f` (word), `backspace`, `delete`,
  `ctrl-w` / `alt-backspace` (delete word back), `alt-d` (delete word forward), `ctrl-u`
  (delete to start), `ctrl-k` (delete to end), bracketed paste.
- **View buttons**: the unlock screen, trust prompts, the bookmarks menu, the search
  view, the sync panel and dialog mnemonics (`alt-<letter>`) read their own keys, shown
  in each view's hint line. They cannot be rebound.

## `Normal`

Global: consulted in every non-modal mode after the focused region's table.

### General

| Keys | Action | Description | Owner |
|---|---|---|---|
| `?`, `f1` | `Help` | Help: bindings for the current mode | T50 |
| `ctrl-q`, `f10` | `Quit` | Quit (confirm when transfers run) | T50 |
| `ctrl-z` | `Suspend` | Suspend to the shell (Unix) | T50 |
| `g r` | `Redraw` | Clear and redraw the screen | T50 |
| `ctrl-c` | `Cancel` | Cancel the focused pane's running operation | T50 |
| `f9` | `Settings` | Settings | T68 |

### Focus

| Keys | Action | Description | Owner |
|---|---|---|---|
| `tab` | `FocusOtherSide` | Switch between local and remote list | T50 |
| `backtab` | `FocusNextRegion` | Focus next region (log, trees, lists, queue) | T50 |
| `g l` | `FocusLog` | Focus message log | T50 |
| `g q` | `FocusQueue` | Focus queue | T50 |
| `g f` | `FocusFiles` | Focus the last file list | T50 |
| `ctrl-x 1` | `FocusRegion1` | Focus the quickconnect bar (region 1) | T50 |
| `ctrl-x 2` | `FocusRegion2` | Focus the local tree (region 2) | T50 |
| `ctrl-x 3` | `FocusRegion3` | Focus the local list (region 3) | T50 |
| `ctrl-x 4` | `FocusRegion4` | Focus the remote tree (region 4) | T50 |
| `ctrl-x 5` | `FocusRegion5` | Focus the remote list (region 5) | T50 |
| `ctrl-x 6` | `FocusRegion6` | Focus the message log (region 6) | T50 |
| `ctrl-x 7` | `FocusRegion7` | Focus the queue (region 7) | T50 |
| `ctrl-k` | `FocusQuickconnect` | Focus the quickconnect bar (opens the dialog when the bar is hidden) | T58 |

### View

| Keys | Action | Description | Owner |
|---|---|---|---|
| `ctrl-l` | `ToggleLog` | Show/hide message log | T50 |
| `ctrl-x j` | `ToggleQueuePane` | Show/hide queue | T50 |
| `ctrl-e` | `ToggleTree` | Show/hide directory trees | T50 |
| `ctrl-x q` | `ToggleQuickconnect` | Show/hide quickconnect bar | T58 |
| `g x` | `SwapPanes` | Swap local and remote sides | T50 |
| `z 1` | `LayoutClassic` | Layout: classic | T50 |
| `z 2` | `LayoutExplorer` | Layout: explorer | T50 |
| `z 3` | `LayoutWidescreen` | Layout: widescreen | T50 |

### Tabs

| Keys | Action | Description | Owner |
|---|---|---|---|
| `ctrl-t` | `NewTab` | New tab | T61 |
| `ctrl-w` | `CloseTab` | Close tab (confirm when connected) | T61 |
| `alt-1`, `g 1` | `GoToTab1` | Go to tab 1 | T61 |
| `alt-2`, `g 2` | `GoToTab2` | Go to tab 2 | T61 |
| `alt-3`, `g 3` | `GoToTab3` | Go to tab 3 | T61 |
| `alt-4`, `g 4` | `GoToTab4` | Go to tab 4 | T61 |
| `alt-5`, `g 5` | `GoToTab5` | Go to tab 5 | T61 |
| `alt-6`, `g 6` | `GoToTab6` | Go to tab 6 | T61 |
| `alt-7`, `g 7` | `GoToTab7` | Go to tab 7 | T61 |
| `alt-8`, `g 8` | `GoToTab8` | Go to tab 8 | T61 |
| `alt-9`, `g 9` | `GoToTab9` | Go to tab 9 | T61 |
| `ctrl-pagedown`, `g t` | `NextTab` | Next tab | T61 |
| `ctrl-pageup`, `g T` | `PrevTab` | Previous tab | T61 |
| `ctrl-x t` | `RenameTab` | Rename tab | T61 |
| `ctrl-x T` | `DuplicateTab` | Duplicate tab (same server and directories) | T61 |
| `ctrl-x <` | `MoveTabLeft` | Move tab left | T61 |
| `ctrl-x >` | `MoveTabRight` | Move tab right | T61 |

### Connection

| Keys | Action | Description | Owner |
|---|---|---|---|
| `ctrl-s` | `SiteManager` | Site Manager | T59 |
| `ctrl-x s` | `SitePicker` | Quick site picker (fuzzy) | T59 |
| `ctrl-x r` | `ReconnectLast` | Reconnect (active tab's server, else the last server) | T58 |
| `ctrl-x S` | `SaveAsSite` | Save the current connection as a site | T58 |
| `ctrl-x d` | `Disconnect` | Disconnect the current tab | T61 |
| `ctrl-x i` | `ServerInfo` | Connection and encryption details | T57 |
| `ctrl-x ctrl-l` | `LockVault` | Lock the vault | T30, T60 |
| `ctrl-x N` | `NetworkWizard` | Network configuration wizard | T72 |

### File operations

| Keys | Action | Description | Owner |
|---|---|---|---|
| `ctrl-r` | `Refresh` | Refresh both panes (bypass cache) | T62 |
| `ctrl-x m` | `ManualTransfer` | Manual transfer | T62 |
| `ctrl-x n` | `NewFile` | New empty file in the focused (else last focused) list | T62 |
| `ctrl-x e` | `EditedFilesList` | Files being edited | T63 |
| `ctrl-x v` | `ShowRawListing` | Raw directory listing of the focused (else remote) list | T71 |

### Queue

| Keys | Action | Description | Owner |
|---|---|---|---|
| `ctrl-p` | `ProcessQueue` | Start/stop processing the queue | T56 |
| `ctrl-x k` | `ToggleSpeedLimit` | Speed limits on/off | T44, T57 |
| `ctrl-x a` | `CycleTransferType` | Transfer type Auto/ASCII/Binary | T57 |

### Message log

| Keys | Action | Description | Owner |
|---|---|---|---|
| `ctrl-x l` | `ClearLog` | Clear the message log of the current scope | T55 |
| `ctrl-x w` | `SaveLogAs` | Save the message log to a file | T71 |

### Comparison

| Keys | Action | Description | Owner |
|---|---|---|---|
| `ctrl-y` | `ToggleSyncBrowsing` | Synchronized browsing | T66 |
| `ctrl-o` | `ToggleComparison` | Directory comparison | T66 |
| `ctrl-x c` | `CompareOptions` | Comparison options | T66 |
| `ctrl-x =` | `SelectByStatus` | Select rows by comparison status | T66 |

### Tools

| Keys | Action | Description | Owner |
|---|---|---|---|
| `ctrl-f` | `Search` | Search files | T65 |
| `ctrl-b` | `Bookmarks` | Bookmarks menu | T64 |
| `ctrl-x b` | `AddBookmark` | Add bookmark for the current directories | T64 |
| `ctrl-x f` | `FiltersDialog` | Directory listing filters | T67 |
| `ctrl-x p` | `OpenNextPrompt` | Open the next pending prompt | T69 |
| `ctrl-x y` | `SyncPanel` | Sync panel (feature sync) | T90 |
| `ctrl-x u` | `DismissUpdate` | Dismiss the update notice | T74 |
| `ctrl-x D` | `ShowAppLog` | Application log (only with --debug) | T71 |

### The `ctrl-x` prefix

Press `ctrl-x`, then one of these keys (36 in all; the popup lists them).

| Key | Action | Description |
|---|---|---|
| `a` | `CycleTransferType` | Transfer type Auto/ASCII/Binary |
| `b` | `AddBookmark` | Add bookmark for the current directories |
| `c` | `CompareOptions` | Comparison options |
| `d` | `Disconnect` | Disconnect the current tab |
| `D` | `ShowAppLog` | Application log (only with --debug) |
| `e` | `EditedFilesList` | Files being edited |
| `f` | `FiltersDialog` | Directory listing filters |
| `i` | `ServerInfo` | Connection and encryption details |
| `j` | `ToggleQueuePane` | Show/hide queue |
| `k` | `ToggleSpeedLimit` | Speed limits on/off |
| `l` | `ClearLog` | Clear the message log of the current scope |
| `m` | `ManualTransfer` | Manual transfer |
| `n` | `NewFile` | New empty file in the focused (else last focused) list |
| `N` | `NetworkWizard` | Network configuration wizard |
| `p` | `OpenNextPrompt` | Open the next pending prompt |
| `q` | `ToggleQuickconnect` | Show/hide quickconnect bar |
| `r` | `ReconnectLast` | Reconnect (active tab's server, else the last server) |
| `s` | `SitePicker` | Quick site picker (fuzzy) |
| `S` | `SaveAsSite` | Save the current connection as a site |
| `t` | `RenameTab` | Rename tab |
| `T` | `DuplicateTab` | Duplicate tab (same server and directories) |
| `u` | `DismissUpdate` | Dismiss the update notice |
| `v` | `ShowRawListing` | Raw directory listing of the focused (else remote) list |
| `w` | `SaveLogAs` | Save the message log to a file |
| `y` | `SyncPanel` | Sync panel (feature sync) |
| `1` | `FocusRegion1` | Focus the quickconnect bar (region 1) |
| `2` | `FocusRegion2` | Focus the local tree (region 2) |
| `3` | `FocusRegion3` | Focus the local list (region 3) |
| `4` | `FocusRegion4` | Focus the remote tree (region 4) |
| `5` | `FocusRegion5` | Focus the remote list (region 5) |
| `6` | `FocusRegion6` | Focus the message log (region 6) |
| `7` | `FocusRegion7` | Focus the queue (region 7) |
| `<` | `MoveTabLeft` | Move tab left |
| `=` | `SelectByStatus` | Select rows by comparison status |
| `>` | `MoveTabRight` | Move tab right |
| `ctrl-l` | `LockVault` | Lock the vault |

## `FileList`

A file list has the focus.

### View

| Keys | Action | Description | Owner |
|---|---|---|---|
| `.` | `ToggleHidden` | Show/hide hidden files | T53 |
| `C` | `ColumnMenu` | Columns | T53 |

### Navigation

| Keys | Action | Description | Owner |
|---|---|---|---|
| `j`, `down` | `CursorDown` | Move the cursor down | T53 |
| `k`, `up` | `CursorUp` | Move the cursor up | T53 |
| `ctrl-d` | `HalfPageDown` | Half a page down | T53 |
| `ctrl-u` | `HalfPageUp` | Half a page up | T53 |
| `pagedown` | `PageDown` | Page down | T53 |
| `pageup` | `PageUp` | Page up | T53 |
| `home`, `g g` | `Top` | First row | T53 |
| `G`, `end` | `Bottom` | Last row | T53 |
| `l`, `enter`, `right` | `Open` | Enter directory; on a file: interface.enter_on_file | T53 |
| `h`, `backspace`, `left` | `Parent` | Parent directory | T53 |
| `[`, `alt-left` | `Back` | Back in the directory history | T53 |
| `]`, `alt-right` | `Forward` | Forward in the directory history | T53 |
| `a` | `EditAddress` | Edit the address bar | T53 |
| `=` | `MirrorOtherPane` | Open the equivalent directory in the other pane | T53 |
| `esc` | `Escape` | Leave visual mode / clear quick filter / close the menu | T53 |

### Selection

| Keys | Action | Description | Owner |
|---|---|---|---|
| `insert`, `space` | `ToggleMark` | Mark/unmark and move down | T53 |
| `v` | `VisualMode` | Range selection | T53 |
| `ctrl-a` | `MarkAll` | Mark all | T53 |
| `*` | `InvertMarks` | Invert marks | T53 |
| `+` | `MarkPattern` | Mark by pattern | T53 |
| `-` | `UnmarkPattern` | Unmark by pattern | T53 |
| `/` | `QuickFilter` | Quick filter | T53 |

### Sorting

| Keys | Action | Description | Owner |
|---|---|---|---|
| `s n` | `SortByName` | Sort by name (again = reverse) | T53 |
| `s s` | `SortBySize` | Sort by size (again = reverse) | T53 |
| `s t` | `SortByType` | Sort by type (again = reverse) | T53 |
| `s m` | `SortByModified` | Sort by modification time (again = reverse) | T53 |
| `s p` | `SortByPermissions` | Sort by permissions (again = reverse) | T53 |
| `s o` | `SortByOwner` | Sort by owner (again = reverse) | T53 |

### File operations

| Keys | Action | Description | Owner |
|---|---|---|---|
| `f5` | `Transfer` | Copy: transfer selection to the other side | T62 |
| `Q`, `f15`, `shift-f5` | `QueueOnly` | Add selection to the queue only | T62 |
| `f6` | `Move` | Move / rename to a path | T62 |
| `f2` | `Rename` | Rename | T62 |
| `f7` | `Mkdir` | Make directory | T62 |
| `M`, `f17`, `shift-f7` | `MkdirEnter` | Make directory and enter it | T62 |
| `delete`, `f8` | `Delete` | Delete (confirm) | T62 |
| `o`, `f3` | `View` | View | T63 |
| `e`, `f4` | `Edit` | Edit | T63 |
| `c` | `Chmod` | Change permissions | T62 |
| `y u` | `CopyUrl` | Copy URL | T62 |
| `y U` | `CopyUrlOptions` | Copy URL with options | T62 |
| `:` | `CustomCommand` | Send a raw command | T62 |

## `Tree`

A directory tree has the focus.

### Directory tree

| Keys | Action | Description | Owner |
|---|---|---|---|
| `j`, `down` | `TreeDown` | Move down | T54 |
| `k`, `up` | `TreeUp` | Move up | T54 |
| `ctrl-d` | `TreeHalfPageDown` | Half a page down | T54 |
| `ctrl-u` | `TreeHalfPageUp` | Half a page up | T54 |
| `home`, `g g` | `TreeTop` | First row | T54 |
| `G`, `end` | `TreeBottom` | Last row | T54 |
| `l`, `right` | `TreeExpand` | Expand; if expanded, first child | T54 |
| `h`, `left` | `TreeCollapse` | Collapse; if collapsed or a leaf, parent | T54 |
| `o` | `TreeToggle` | Toggle expand | T54 |
| `enter` | `TreeOpen` | Show this directory in the file list | T54 |
| `ctrl-r` | `TreeRefresh` | Relist the cursor directory | T54 |
| `.` | `TreeRevealCurrent` | Reveal the file list's current directory | T54 |

## `Log`

The message log has the focus.

### Navigation

| Keys | Action | Description | Owner |
|---|---|---|---|
| `esc` | `Escape` | Leave visual mode / clear quick filter / close the menu | T53 |

### Message log

| Keys | Action | Description | Owner |
|---|---|---|---|
| `j`, `down` | `LogCursorDown` | Move down | T55 |
| `k`, `up` | `LogCursorUp` | Move up | T55 |
| `ctrl-d` | `LogHalfPageDown` | Half a page down | T55 |
| `ctrl-u` | `LogHalfPageUp` | Half a page up | T55 |
| `pagedown` | `LogPageDown` | Page down | T55 |
| `pageup` | `LogPageUp` | Page up | T55 |
| `home`, `g g` | `LogTop` | First line | T55 |
| `G`, `end` | `LogBottom` | Last line (follow) | T55 |
| `/` | `LogSearch` | Search the log | T55 |
| `n` | `LogSearchNext` | Next match | T55 |
| `N` | `LogSearchPrev` | Previous match | T55 |
| `v` | `LogVisual` | Line selection | T55 |
| `y` | `LogCopy` | Copy the selected lines | T55 |
| `w` | `LogToggleWrap` | Wrap long lines on/off | T55 |
| `t` | `LogToggleScope` | Current tab / all tabs | T55 |
| `e` | `LogCycleKindFilter` | Cycle the message kind filter | T55 |
| `h`, `left` | `LogScrollLeft` | Scroll left | T55 |
| `l`, `right` | `LogScrollRight` | Scroll right | T55 |
| `0` | `LogScrollHome` | Scroll to the line start | T55 |
| `Y` | `CopyLog` | Copy the whole current log view | T71 |

## `Queue`

The queue has the focus.

### Navigation

| Keys | Action | Description | Owner |
|---|---|---|---|
| `j`, `down` | `CursorDown` | Move the cursor down | T53 |
| `k`, `up` | `CursorUp` | Move the cursor up | T53 |
| `ctrl-d` | `HalfPageDown` | Half a page down | T53 |
| `ctrl-u` | `HalfPageUp` | Half a page up | T53 |
| `pagedown` | `PageDown` | Page down | T53 |
| `pageup` | `PageUp` | Page up | T53 |
| `home`, `g g` | `Top` | First row | T53 |
| `G`, `end` | `Bottom` | Last row | T53 |
| `esc` | `Escape` | Leave visual mode / clear quick filter / close the menu | T53 |

### Selection

| Keys | Action | Description | Owner |
|---|---|---|---|
| `insert` | `ToggleMark` | Mark/unmark and move down | T53 |
| `v` | `VisualMode` | Range selection | T53 |
| `ctrl-a` | `MarkAll` | Mark all | T53 |

### Queue

| Keys | Action | Description | Owner |
|---|---|---|---|
| `1` | `QueueTabQueued` | Show queued files | T56 |
| `2` | `QueueTabFailed` | Show failed transfers | T56 |
| `3` | `QueueTabSuccessful` | Show successful transfers | T56 |
| `o`, `enter` | `QueueToggleGroup` | Collapse/expand server group | T56 |
| `space` | `QueuePauseResume` | Pause/resume selected items | T56 |
| `+` | `QueuePriorityUp` | Raise priority | T56 |
| `-` | `QueuePriorityDown` | Lower priority | T56 |
| `K` | `QueueMoveUp` | Move up | T56 |
| `J` | `QueueMoveDown` | Move down | T56 |
| `t` | `QueueMoveTop` | Move to top | T56 |
| `b` | `QueueMoveBottom` | Move to bottom | T56 |
| `x`, `delete` | `QueueRemove` | Remove selected | T56 |
| `X` | `QueueClearList` | Clear the Failed/Successful list (confirm) | T56 |
| `r` | `QueueResetRequeue` | Reset and requeue (failed list) | T56 |
| `e` | `QueueSetExistsAction` | File-exists action for selected items | T56 |
| `a` | `QueueCompletionAction` | Action after queue completion | T45, T56 |
| `m` | `QueueMenu` | All actions for the selection | T56 |

## `SiteManager`

The Site Manager's tree has the focus (the editor on the right uses `Dialog`). The Site Manager is modal, so only this table is consulted.

### General

| Keys | Action | Description | Owner |
|---|---|---|---|
| `?`, `f1` | `Help` | Help: bindings for the current mode | T50 |
| `ctrl-q`, `f10` | `Quit` | Quit (confirm when transfers run) | T50 |

### Navigation

| Keys | Action | Description | Owner |
|---|---|---|---|
| `j`, `down` | `CursorDown` | Move the cursor down | T53 |
| `k`, `up` | `CursorUp` | Move the cursor up | T53 |
| `home`, `g g` | `Top` | First row | T53 |
| `G`, `end` | `Bottom` | Last row | T53 |

### Directory tree

| Keys | Action | Description | Owner |
|---|---|---|---|
| `l`, `right` | `TreeExpand` | Expand; if expanded, first child | T54 |
| `h`, `left` | `TreeCollapse` | Collapse; if collapsed or a leaf, parent | T54 |

### Site Manager

| Keys | Action | Description | Owner |
|---|---|---|---|
| `o`, `enter` | `SmConnect` | Site: open/connect; folder: toggle | T59 |
| `O` | `SmConnectNewTab` | Connect in a new tab | T59 |
| `e`, `tab` | `SmEdit` | Focus the editor | T59 |
| `n` | `SmNewSite` | New site | T59 |
| `f` | `SmNewFolder` | New folder | T59 |
| `d` | `SmDuplicate` | Duplicate | T59 |
| `r`, `f2` | `SmRename` | Rename inline | T59 |
| `x`, `delete` | `SmDelete` | Delete (confirm) | T59 |
| `m` | `SmMark` | Mark for move | T59 |
| `p` | `SmPaste` | Move the marked item here | T59 |
| `C` | `SmCopyToVault` | Copy to another vault | T59 |
| `M` | `SmMoveToVault` | Move to another vault | T59 |
| `/` | `SmFind` | Filter | T59 |
| `L` | `SmCredentialOverride` | My login for this site (team vaults) | T90 |
| `ctrl-s` | `SmSave` | Save the draft | T59 |
| `i` | `SmImport` | Import | T59 |
| `E` | `SmExport` | Export | T59 |
| `[`, `ctrl-pageup` | `SmPrevTab` | Previous editor tab | T59 |
| `]`, `ctrl-pagedown` | `SmNextTab` | Next editor tab | T59 |
| `q`, `esc` | `SmClose` | Close (unsaved-changes guard) | T59 |

## `Filter`

Typing a quick filter; printable keys and `backspace` go to the field.

### Navigation

| Keys | Action | Description | Owner |
|---|---|---|---|
| `down` | `CursorDown` | Move the cursor down | T53 |
| `up` | `CursorUp` | Move the cursor up | T53 |

### Selection

| Keys | Action | Description | Owner |
|---|---|---|---|
| `enter` | `FilterAccept` | Keep the filter, back to the list | T53 |
| `esc` | `FilterClear` | Clear the filter, back to the list | T53 |

## `Input`

A single-line field outside dialogs (quickconnect, the `:` line, log search).

### Text fields

| Keys | Action | Description | Owner |
|---|---|---|---|
| `enter` | `InputSubmit` | Submit the field | T50 |
| `esc` | `InputCancel` | Cancel the field | T50 |
| `tab` | `NextField` | Next field | T52, T58 |
| `backtab` | `PrevField` | Previous field | T52, T58 |
| `up` | `InputHistoryPrev` | Previous history entry | T58, T62 |
| `down` | `InputHistoryNext` | Next history entry | T58, T62 |

## `Dialog`

A dialog or overlay is open; only this table is consulted.

### General

| Keys | Action | Description | Owner |
|---|---|---|---|
| `ctrl-q`, `f10` | `Quit` | Quit (confirm when transfers run) | T50 |

### Text fields

| Keys | Action | Description | Owner |
|---|---|---|---|
| `tab` | `NextField` | Next field | T52, T58 |
| `backtab` | `PrevField` | Previous field | T52, T58 |

### Dialogs

| Keys | Action | Description | Owner |
|---|---|---|---|
| `enter` | `DialogSubmit` | Default button (newline in a multi-line field) | T52 |
| `esc` | `DialogCancel` | Cancel the dialog | T52 |
| `ctrl-s` | `DialogSave` | Save (forms) | T52 |
| `ctrl-n`, `ctrl-pagedown` | `NextFormTab` | Next form tab | T52 |
| `ctrl-p`, `ctrl-pageup` | `PrevFormTab` | Previous form tab | T52 |
