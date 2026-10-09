# T54 — Directory tree pane

**Phase:** F TUI · **Milestone:** M6 · **Depends on:** T53 · **Crate(s):** `courier-ftp` (`components/dir_tree/`) · **Decisions:** D6, D7 · **FEATURES.md:** §3 (local pane: folder tree plus file list; remote pane: folder tree plus file list; showing or hiding each pane)
**Related (integrates with, not blocking):** T06, T46

## Goal

Optional folder trees for the local and the remote side, like FileZilla's upper
panes: lazily loaded, kept in sync with the file list in both directions, and safe on
huge or slow directories. Off by default, toggled with `Ctrl-e`.

## Context

**Before this task:** T53 provides `PaneId`, `Side`, `PaneDir`, the listing request
path (`PaneRequest::List` served by T50's runner through `ListingCache`), and
`PaneInput::ListingLoaded`/`ListingUpdated`. T46 provides `ListingCache` and
`CoreEvent::ListingUpdated` after mkdir/rmdir/rename/delete patches. T06 provides
the Windows drive list at the virtual root. T50 places the tree (above the list in
Classic and Widescreen, beside it in Explorer) and owns `interface.show_tree`. T51
provides `ctrl-e` (`ToggleTree`), the `Tree` keymap mode with this task's actions, and
`ctrl-x 2` / `ctrl-x 4` (`FocusRegion2`/`FocusRegion4`: local / remote tree); T50
`ui::text::sanitize` and `ui::symbols::Symbols`.

**Later tasks need from it:** T66 (synchronized browsing moves the tree with the
list), T64 (bookmark navigation shows in the tree), nothing else depends on it.

## Technical specification

### Types and APIs

Module `crates/courier-ftp/src/components/dir_tree/` (`mod.rs`, `state.rs`, `render.rs`).

```rust
/// Index into `DirTreeState::nodes` (arena; ids are never reused while the tree lives).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(u32);

#[derive(Debug, Clone, PartialEq)]
pub enum Children {
    /// Never listed; drawn with `▸`.
    Unknown,
    /// Only the children on the way to a known path are present (no listing yet).
    Partial(Vec<NodeId>),
    Loading { request: RequestId, partial: Vec<NodeId> },
    Loaded(Vec<NodeId>),               // sorted, directories only
    Error { message: String, partial: Vec<NodeId> },
}

#[derive(Debug, Clone)]
pub struct TreeNode {
    pub name: String,                  // as listed (sanitised at render)
    pub dir: PaneDir,
    pub parent: Option<NodeId>,
    pub depth: u16,
    pub expanded: bool,
    pub children: Children,
    /// Pseudo roots on Windows (drives, Home, Desktop) are not real directories' children.
    pub pseudo: bool,
}

#[derive(Debug)]
pub struct DirTreeState {
    pub pane: PaneId,
    nodes: Vec<TreeNode>,
    roots: Vec<NodeId>,
    /// Flattened visible rows; rebuilt on expand/collapse/children change.
    visible: Vec<NodeId>,
    pub cursor: usize,
    pub offset: usize,
    pub hscroll: u16,
    /// Node of the file list's current directory (highlighted).
    pub current: Option<NodeId>,
    index: HashMap<PaneDir, NodeId>,
}

#[derive(Debug, Clone)]
pub enum TreeInput {
    Key(TreeCommand),
    /// The file list of the same pane changed directory (T53 navigation finished).
    ListDirChanged(PaneDir),
    /// A listing for any dir arrived (own request, file list's, or cache patch).
    Listing { request: Option<RequestId>, dir: PaneDir, result: Result<Arc<Listing>, Arc<Error>> },
    ChildrenBuilt { node: NodeId, generation: u64, children: Vec<(String, PaneDir)> },
    Connected { home: PaneDir }, Disconnected,
    Resize { rows: u16, cols: u16 },
}

#[derive(Debug, Clone)]
pub enum TreeRequest {
    /// List a directory for the tree (same runner as T53; cache first).
    List { pane: PaneId, dir: PaneDir, request: RequestId, force: bool },
    CancelList { pane: PaneId, request: RequestId },
    /// Make the file list of the same pane navigate there.
    NavigateList { pane: PaneId, dir: PaneDir },
}

impl DirTreeState {
    pub fn new_local(pane: PaneId, home: &LocalPath) -> Self;   // Unix: "/" ; Windows: pseudo roots
    pub fn new_remote(pane: PaneId) -> Self;                     // empty until Connected
    pub fn reduce(&mut self, input: TreeInput) -> Vec<TreeRequest>;
    pub fn reveal(&mut self, dir: &PaneDir) -> Vec<TreeRequest>; // expand ancestors, set current
    pub fn node_count(&self) -> usize;
}
```

Keymap actions (mode `Tree`, defined in T51's table with exactly these names): `TreeDown`, `TreeUp`, `TreeExpand`,
`TreeCollapse`, `TreeToggle`, `TreeOpen`, `TreeTop`, `TreeBottom`, `TreeHalfPageDown`,
`TreeHalfPageUp`, `TreeRefresh`, `TreeRevealCurrent`.

### Behaviour

#### Roots

| Side / OS | Roots |
|---|---|
| Local, Unix/macOS | `/`, then `reveal(home)` at start |
| Local, Windows | pseudo roots in this order: `Home` (`%USERPROFILE%`), `Desktop`, then every drive from T06's drive list (`C:`, `D:` …); `reveal(current dir)` |
| Remote | not connected: empty with `Not connected`; on `Connected { home }`: `/` (or the server's root per `PathStyle`, T02) and `reveal(home)` |

#### Lazy loading

1. Expanding a node with `Unknown` or `Partial` children issues `TreeRequest::List`
   (cache first; T46) with a fresh `RequestId`; state `Loading` keeps the partial
   children visible. Marker `…` (ASCII `.`).
2. The result keeps only entries with `EntryKind::Dir` or symlinks whose `target_kind`
   is `Dir` (hidden directories follow the pane's hidden setting, filters from T47 apply
   like in the list). Children sorted by T53's name comparison (natural, case per setting).
3. ≤ 10 000 directory children: children built inline. Above: built in
   `spawn_blocking`, delivered by `ChildrenBuilt { generation }`; stale generations dropped.
4. Error: `Children::Error { message }`, marker `!`; when the cursor is on it, the last
   inner row shows `Error: <message>   Ctrl-r retry`. Partial children stay.
5. At most 2 tree listing requests in flight per pane; more expansions queue (FIFO).
   Remote requests use the tab's browsing `SessionHandle`, so they run one at a time
   with the file list's requests (T03 "one operation at a time").
6. Collapsing keeps children in memory. If the tree exceeds 200 000 nodes, children of
   the least recently collapsed subtrees are dropped back to `Unknown` until under
   150 000.

#### Sync with the file list

- `ListDirChanged(dir)` (T53 finished navigating): `reveal(dir)` creates missing
  ancestors as `Partial` nodes **without** listing them, expands them, sets `current`,
  moves the cursor to it if the tree is not focused, and scrolls it into view (centred
  if it was off-screen).
- Any `Listing` for a directory present in the tree (including the file list's own
  listing and T46 patch events) refreshes that node's children (`Loaded`), so mkdir,
  rmdir and rename made in the list show up in the tree without extra requests; the
  cursor stays on the same `PaneDir` or, if it vanished, moves to its parent.
- `TreeOpen` (`Enter`) emits `NavigateList` for the cursor node; the list's
  navigation then triggers `ListDirChanged`. If the list's navigation fails, `current`
  stays where it was and the list shows the error (T53).

#### Row layout

Each row: horizontal offset applied, then for each ancestor level below the root
`│ ` (more siblings follow) or `  `; then `├─` or `└─` (none for roots); then the marker;
then a space and the name. Markers: `▸` collapsed/unknown, `▾` expanded, ` ` loaded with
no children, `…` loading, `!` error (ASCII: `+`, `-`, ` `, `.`, `!`; guides `| `,
`|-`, `` `- ``). Names longer than the remaining width are cut with `…`. The current
directory row uses `tree.current` (bold + underline); the cursor row `tree.cursor`
(reverse; when unfocused `tree.cursor_inactive`, underline). Pseudo roots use
`tree.pseudo` (italic; monochrome: plain with a trailing `:` for drives).

**Horizontal offset:** when the cursor row's indentation + 12 exceeds the width, the
tree shifts left by multiples of 8 columns until the cursor name has at least 12
columns; `«` (ASCII `<<`) at column 0 shows hidden indentation.

Title: ` Local tree ` / ` Remote tree · <site> ` + ` · <current dir>` when it fits
(cut from the left).

#### Mock-up: standalone at 80×24 (local, Unix, current dir `~/projects/site`)

```
┌ Local tree · ~/projects/site ────────────────────────────────────────────────┐
│▾ /                                                                           │
│├─▸ bin                                                                       │
│├─▸ etc                                                                       │
│├─▾ home                                                                      │
││ └─▾ alice                                                                   │
││   ├─▸ .config                                                               │
││   ├─▸ Downloads                                                             │
││   ├─▾ projects                                                              │
││   │ ├─▾ site                                                                │
││   │ │ ├─  assets                                                            │
││   │ │ ├─▸ css                                                               │
││   │ │ └─▸ js                                                                │
││   │ └─▸ tools                                                               │
││   └─▸ src                                                                   │
│├─▸ opt                                                                       │
│├─▸ srv                                                                       │
│├─▸ tmp                                                                       │
│├─▸ usr                                                                       │
│└─▸ var                                                                       │
│                                                                              │
│                                                                              │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

#### Mock-up: standalone at 160×48 (remote; `uploads` loading, `logs` failed, cursor on `logs`)

```
┌ Remote tree · web01 · /var/www/html ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│▾ /                                                                                                                                                           │
│└─▾ var                                                                                                                                                       │
│  └─▾ www                                                                                                                                                     │
│    ├─▾ html                                                                                                                                                  │
│    │ ├─▸ assets                                                                                                                                              │
│    │ ├─  css                                                                                                                                                 │
│    │ ├─  js                                                                                                                                                  │
│    │ └─… uploads                                                                                                                                             │
│    ├─! logs                                                                                                                                                  │
│    └─▸ staging                                                                                                                                               │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│Error: Permission denied: /var/www/logs   Ctrl-r retry                                                                                                        │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

#### Mock-up: Classic layout at 80×24, tree above the list in a 40-column pane (6 rows)

```
┌ Local tree ──────────────────────────┐
││ └─▾ alice                           │
││   ├─▸ .config                       │
││   ├─▸ Downloads                     │
││   ├─▾ projects                      │
││   │ ├─▾ site                        │
││   │ │ ├─  assets                    │
└──────────────────────────────────────┘
```

#### Placement and narrow terminals

T50 places the tree; this task adds the size rules it must apply:

| Layout | Placement | Tree size | Hidden when |
|---|---|---|---|
| Classic, Widescreen | above the file list, same width | 35 % of the column height, min 4 rows | column height < 14 rows |
| Explorer | left of the file list | 35 % of the column width, min 22 columns | column width < 60 |
| single-pane mode (< 80×24) | not shown | — | always |

When the tree is enabled but hidden by size, the status bar shows once
`Directory tree hidden: terminal too small` (Info).

#### Keybindings (mode `Tree`)

| Key | Action |
|---|---|
| `j` `↓` / `k` `↑` | `TreeDown` / `TreeUp` — cursor down / up |
| `ctrl-d` / `ctrl-u` | `TreeHalfPageDown` / `TreeHalfPageUp` — half page |
| `g g` `Home` / `G` `End` | `TreeTop` / `TreeBottom` — first / last row |
| `l` `→` | `TreeExpand` — expand; if already expanded, move to the first child |
| `h` `←` | `TreeCollapse` — collapse; if collapsed or a leaf, move to the parent |
| `o` | `TreeToggle` — toggle expand |
| `Enter` | `TreeOpen` — navigate the file list to the cursor dir |
| `ctrl-r` | `TreeRefresh` — relist the cursor dir (bypasses cache; overrides the global `Refresh` in this mode) |
| `.` | `TreeRevealCurrent` — reveal the file list's current dir |
| `Tab` / `Shift-Tab` | T50 focus cycling (tree → list → other side) |

#### Performance targets

| Measure | Target |
|---|---|
| Expanding a directory with 100 000 entries (60 000 subdirectories) | UI keeps handling keys; children ready ≤ 100 ms after the listing (bench `tree_children_60k`) |
| Draw at 160×48 with 200 000 nodes, 60 000 visible | ≤ 1 ms median (only visible rows; bench `tree_render_large`) |
| `reveal` of a 30-component path | no network request; ≤ 1 ms |
| Memory | ≤ 200 000 nodes per tree (see eviction) |

### Data formats and configuration

| Key | Type | Default | Notes |
|---|---|---|---|
| `interface.show_tree` | bool | `false` | T05; toggled by `ctrl-e` (T51 `ToggleTree`), saved |
| `interface.show_hidden_local` / `force_show_hidden_remote` | bool | `false` | T05; shared with T53 |
| `interface.natural_sort`, `interface.sort_case_sensitive` | bool | `true`, `false` | shared with T53 |

Style keys: `tree.guide` (dim), `tree.dir`, `tree.current`, `tree.cursor`,
`tree.cursor_inactive`, `tree.pseudo`, `tree.loading` (dim), `tree.error` (red;
monochrome bold), `tree.border`, `tree.border_focused`.

### Errors

| Error (`courier_ftp_core::Error`) | Node state / text |
|---|---|
| `PermissionDenied` | `!` + `Error: Permission denied: <dir>` |
| `NotFound(path)` | node removed; parent relisted once |
| `Timeout` | `!` + `Error: Timed out listing <dir>` |
| `Connection(_)` | remote tree reset to `Not connected` on `Disconnected` |
| `Cancelled` | node back to its previous state |

### Security and logging

- Directory names are untrusted: rendered through `sanitize` (T50); a name containing
  `/` or NUL from a hostile server is shown escaped and never used to build a path
  (paths come from `RemotePath::join`, which rejects `/`, T02).
- No paths in `tracing` at `info`+; `debug` may log `tree pane=<id> nodes=<n> request=<id>`.

## Implementation steps

1. Arena, `Children` states, flattening of visible rows, cursor/offset; unit tests.
2. Row rendering with guides, markers, horizontal offset, Unicode/ASCII; snapshots.
3. Lazy loading through T50's runner with request ids, in-flight limit, error state.
4. `reveal` and `ListDirChanged`; refresh from listings and T46 patches.
5. Windows pseudo roots; remote connect/disconnect.
6. Placement/size rules with T50; `Ctrl-e` toggle; eviction; benches.

## Acceptance criteria

- [ ] AC1 Snapshot tests at 80×24 and 160×48 for collapsed, expanded, loading, error, not connected, Windows pseudo roots, deep path with horizontal offset, and the 40×8 Classic placement; `NO_COLOR` + ASCII variants contain only ASCII.
- [ ] AC2 After mkdir, rmdir and rename in the file list (T46 patch events), the tree shows the change without a new listing request (mock call counter).
- [ ] AC3 Navigating in the file list reveals and highlights the directory in the tree without listing ancestors (zero extra backend calls).
- [ ] AC4 `Enter` in the tree navigates the file list; a failed navigation leaves `current` unchanged.
- [ ] AC5 Expanding a 100 000-entry directory does not block input (keys processed while children build) and meets the bench targets.
- [ ] AC6 Never more than 2 tree listing requests in flight per pane; stale results ignored.
- [ ] AC7 Eviction keeps the node count ≤ 200 000.
- [ ] AC8 CI gates `fmt`, `clippy`, `test-local-only`, `test-os` (Windows pseudo roots), `bench-build` pass.

## Tests

### Unit tests
- `flatten_visible_rows_respects_expansion`.
- `guides_and_markers_for_last_and_middle_children` (AC1).
- `expand_unknown_issues_list_request`, `collapse_moves_to_parent_when_leaf`.
- `listing_keeps_only_dirs_and_dir_symlinks`.
- `reveal_creates_partial_ancestors_without_requests` (AC3).
- `listing_patch_refreshes_children_and_keeps_cursor` (AC2).
- `error_node_shows_message_row_and_retries` (AC1).
- `in_flight_limit_queues_expansions` (AC6), `stale_result_ignored` (AC6).
- `eviction_drops_collapsed_subtrees_lru` (AC7).
- `horizontal_offset_keeps_cursor_name_visible`.
- `tree_default_keys` — `AppHarness` with the default keymap and the tree focused: each key in the table produces its `Tree*` action; `ctrl-r` yields `TreeRefresh`, not `Refresh`.
- `windows_pseudo_roots_order` (`#[cfg(windows)]` and a pure test with a fake drive list).

### Property / fuzz tests
- `prop_tree_render_never_panics` — random trees, names with control chars, sizes 0–200 × 0–60.
- `prop_visible_rows_match_reference_flatten` — random expand/collapse sequences vs. a naive recursive flatten.

### Snapshot tests
`tree_local_{80x24,160x48}`, `tree_remote_loading_error_{80x24,160x48}`, `tree_not_connected_80x24`,
`tree_windows_roots_80x24`, `tree_deep_hscroll_80x24`, `tree_classic_40x8`, each also `*_mono_ascii` (AC1).

### Integration tests
- `tree_follows_list_with_local_backend` — `LocalBackend` on a temp dir: navigate the list, create and delete directories, assert the tree (AC2, AC3, AC4).
- `tree_large_dir_with_mock_backend` — 100 000 entries, keys during build (AC5).
- Benches `tree_children_60k`, `tree_render_large` (AC5).

### End-to-end tests
- None beyond T76's PtyApp smoke test toggling `Ctrl-e` (asserts `Local tree` title appears).

## Out of scope

- Drag and drop between tree and list (D7, D8).
- File operations from the tree (only navigation); a context menu.
- Showing files in the tree.

## Open questions

None. (Resolved: T51 has the `Tree` mode with the actions listed above.)
