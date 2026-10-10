# T43 — Recursive operations

**Phase:** E Transfers · **Milestone:** M4 · **Depends on:** T40, T41, T47 · **Crate(s):** `courier-ftp-core` (`transfer::recursive`) · **Decisions:** none · **FEATURES.md:** §4 (recursive delete, recursive chmod), §5, §6 (empty folders, symlinks), §8 (filters applied to transfers)
**Related (integrates with, not blocking):** T62

## Goal

Directories become individual operations for upload, download, delete and chmod —
lazily, cancellably, with filters applied and with bounded memory. Transfers expand a
selected directory one level at a time inside the queue (FileZilla's lazy recursion), so
a 100 000-file tree starts transferring at once and listings run in parallel with
transfers. Delete and chmod walk the tree on the tab's browsing session and report
progress and partial failures.

## Context

- Before: T40 gives `QueueItem` with `kind: QueueItemKind::DirPlaceholder(DirExpansion)` /
  `RemoveSourceDir { pending }`, `cleanup_parent`, `Queue::replace_placeholder`; T41 gives
  the slot lifecycle (a placeholder is scheduled like a file and runs the `Listing` phase
  on a pooled connection), `TouchedDirs`, `CachePatch` use; T47 gives `FilterEngine`
  (`excluded(entry, parent)`), `Side`, setting `filters.apply_to_transfers`; T03 gives
  `SessionHandle` (`list`, `stat`, `remove_file`, `rmdir`, `chmod`, `mkdir`) and listing
  hygiene (invalid names dropped); T06 gives `LocalBackend::canonicalize` and `path_map`;
  T04 gives `OperationId`, `CoreEvent::OperationProgress` / `OperationFinished`; T02 gives
  `RemotePath::resolve`/`starts_with`, `LocalPath::join`, `EntryKind::Symlink`; T42 gives
  the local-name sanitiser used for downloaded names.
- After: T62 calls `build_transfer_items` → placeholders, and `delete_recursive` /
  `chmod_recursive` with a `ProgressDialog`; T41b documents that parallel listing comes
  from parallel placeholder expansion; T65/T66 reuse the placeholder path.

## Technical specification

### Types and APIs

Module `courier_ftp_core::transfer::recursive` (`expand.rs`, `links.rs`, `walk.rs`,
`delete.rs`, `chmod.rs`).

```rust
// ---- transfer expansion (called by the T41 slot in phase Listing) ----
/// Lists the placeholder's source directory and returns the child items, in queue
/// order. Creates the destination directory when `transfers.empty_dirs = create`.
pub async fn expand_placeholder(
    item: &QueueItem,
    source: &mut dyn Backend,           // remote guard (download) or local backend (upload)
    target: &mut dyn Backend,           // the other side
    filter: Option<&FilterEngine>,      // source side; None when apply_to_transfers = false
    settings: &Settings,
    log: &SessionLog,
) -> Result<Expansion>;
pub struct Expansion {
    pub children: Vec<QueueItem>,       // files (by name), then directories (by name), then
                                        // an optional RemoveSourceDir marker
    pub filtered: u32,                  // entries skipped by filters
    pub skipped: Vec<(String, SkipWhy)>,// symlinks to dirs, loops, too deep, other kinds
    pub created_target_dir: bool,
}
pub enum SkipWhy { SymlinkToDirNotFollowed, SymlinkLoop, BrokenSymlink, TooDeep, NotAFileOrDir, InvalidName }

pub const MAX_DEPTH: u16 = 64;

/// Pure loop check (unit-tested): following a symlink from a directory whose real path is
/// `parent_real` to `target_real` loops if `parent_real` or any path in `chain` lies at or
/// below `target_real`.
pub fn is_link_loop(parent_real: &RemotePath, chain: &[RemotePath], target_real: &RemotePath) -> bool;

// ---- walk.rs: the iterative walker, with a caller-supplied lister ----
/// Where the walker gets directory listings. The caller chooses: delete/chmod pass the
/// browsing `SessionHandle` (fresh listings); T49 search passes a lister that goes through
/// the T46 listing cache; tests pass a closure over a `MockServer`.
#[async_trait]
pub trait DirLister: Send + Sync {
    async fn list(&self, dir: &RemotePath, cancel: &CancellationToken) -> Result<Listing>;
}
impl DirLister for SessionHandle { /* SessionHandle::list */ }
/// Adapter for closures (T49, tests).
pub struct FnLister<F>(pub F);

pub struct WalkOpts { pub max_depth: u16 /* MAX_DEPTH */, pub follow_symlinks: bool }
pub enum WalkEvent<'a> {
    /// A directory's listing arrived (entries already filtered when a filter is given).
    Listed { dir: &'a RemotePath, depth: u16, entries: &'a [Entry], filtered: u32 },
    ListFailed { dir: &'a RemotePath, error: &'a Error },
    /// All children of `dir` were visited (post-order hook; delete's `rmdir`, chmod's
    /// post-order mode change).
    DirDone { dir: &'a RemotePath, depth: u16 },
}
pub enum WalkControl { Continue, SkipChildren, Stop }
/// Depth-first, iterative (explicit stack), symlinks to dirs followed only with
/// `follow_symlinks` (loop check as above). Checks `cancel` before every list call.
/// `visit` returns which subdirectories of a `Listed` dir to descend into.
pub async fn walk(roots: &[RemotePath], lister: &dyn DirLister, filter: Option<&FilterEngine>,
                  opts: WalkOpts, cancel: &CancellationToken,
                  visit: &mut (dyn FnMut(WalkEvent<'_>) -> WalkControl + Send)) -> Result<()>;

// ---- delete / chmod on the browsing session ----
pub struct RecursiveCtx<'a> {
    pub id: OperationId,                         // T04
    pub events: &'a EventSender,
    pub cache: Option<(&'a ListingCache, ServerIdentity)>,   // None for the local pane
    pub filter: Option<FilterEngine>,            // pane side; None when apply_to_transfers = false
    pub cancel: CancellationToken,
}

/// `session` performs the mutations; `lister` provides listings (normally the same
/// `SessionHandle`, never a cache — deletes must see the current server state).
pub async fn delete_recursive(session: &SessionHandle, lister: &dyn DirLister,
                              targets: Vec<(RemotePath, Entry)>, ctx: RecursiveCtx<'_>) -> DeleteReport;
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeleteReport {
    pub files_deleted: u64, pub dirs_deleted: u64,
    pub kept_dirs: u64,                          // left because they hold filtered entries
    pub filtered: u64,
    pub failed: Vec<(RemotePath, String)>,       // first 1000
    pub failed_total: u64,
    pub cancelled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChmodSpec { pub value: u32, pub mask: u32 }   // 12 bits each; mask bit 1 = take from value
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChmodScope { All, FilesOnly, DirsOnly }
/// `(old & !mask) | (value & mask)`; `old = None` → `Some(value)` only if `mask == 0o7777`.
pub fn compute_mode(old: Option<u32>, spec: ChmodSpec) -> Option<u32>;

pub async fn chmod_recursive(session: &SessionHandle, lister: &dyn DirLister,
                             targets: Vec<(RemotePath, Entry)>,
                             spec: ChmodSpec, scope: ChmodScope, recurse: bool,
                             ctx: RecursiveCtx<'_>) -> ChmodReport;
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChmodReport {
    pub changed: u64, pub unchanged: u64,
    pub skipped_unknown_mode: u64, pub skipped_symlinks: u64, pub filtered: u64,
    pub failed: Vec<(RemotePath, String)>, pub failed_total: u64,
    pub cancelled: bool,
}
```

### Behaviour

#### Lazy expansion for transfers

1. T62 adds one `DirPlaceholder` item per selected directory (`depth = 0`,
   `link_chain = []`, `real_path = None`). The scheduler treats it like a file; its slot
   runs phase `Listing` (counts against all limits, so listings of different
   placeholders run in parallel with file transfers).
2. **List** the source directory: download → remote `list(item.remote)`; upload → local
   `list(from_native(item.local))`. Log Status "Retrieving directory listing of
   \"<path>\"...". Listing errors use T41's classes (`NotFound`/`PermissionDenied` →
   placeholder `Failed(Permanent)` with the message; the run continues).
3. **Classify** each entry (names were validated by the backend, T03; re-checked with
   `Entry::is_valid_name`, invalid → `SkipWhy::InvalidName` + Error log line):

   | Entry | `follow_symlinks = false` | `follow_symlinks = true` |
   |---|---|---|
   | File | file item | file item |
   | Dir | placeholder `depth + 1` | placeholder `depth + 1` |
   | Symlink → file | file item (content transferred) | file item |
   | Symlink → dir | skipped (`SymlinkToDirNotFollowed`, Status line) | placeholder via the loop check |
   | Symlink, broken | skipped (`BrokenSymlink`) | skipped |
   | Symlink, `target_kind = None` | `stat` it first (T03 fills `target_kind`) | same |
   | Other (device, socket, MVS) | skipped (`NotAFileOrDir`, Debug log) | skipped |

   `depth + 1 > MAX_DEPTH` → skipped (`TooDeep`, Error log "Directory nesting deeper than
   64 levels; skipped <path>").
4. **Filters**: when `filters.apply_to_transfers` (T47, default true), entries for which
   the source side's `FilterEngine::excluded(entry, parent)` is true are dropped (files)
   or not descended (directories); the count is logged at `Debug(Info)` per directory
   ("12 entries filtered") and summed for the item's parent run.
5. **Names**: download children get `local = item.local.join(sanitized name)` (T42
   sanitiser, also for directory names; a name that stays invalid → `InvalidName`
   skip); `remote = item.remote.join(name)`. Upload children: `remote =
   item.remote.join(name)` (`RemotePath::join` rejects bad names → `InvalidName`),
   `local = item.local.join(name)`.
6. **Child fields**: `size`, `source_modified` from the entry; priority, `on_exists`,
   `transfer_type`, `delete_source_after` inherited (T40 `replace_placeholder`).
   Order: files sorted by name (byte order), then directories sorted by name — files of a
   directory finish before its subdirectories start (FileZilla order, and it keeps the
   queue small: depth-first).
7. **Destination directory**: `transfers.empty_dirs = create` (default) → create it now
   (remote: `mkdir` each missing component, `AlreadyExists` is fine; local: `mkdir` via
   the local backend, components as needed) and add a `CachePatch::Created` for remote
   dirs. `skip` → nothing is created here; T41 creates parents on demand before the first
   file, so directories without files never appear.
8. **Move** (`delete_source_after`): append one `RemoveSourceDir { pending = number of
   children }` marker after the children; each child's `cleanup_parent` = the marker; the
   marker takes over the placeholder's own `cleanup_parent`. When the marker runs it calls
   `rmdir` on the source dir; "not empty" (children failed or were filtered) → `Done
   (Skipped(NotEmpty))`, not a failure.
9. `Queue::replace_placeholder(id, children)`; the placeholder disappears (`Done
   (Expanded)`, not listed); `CoreEvent::QueueChanged`. An empty directory with
   `empty_dirs = create` yields zero children and still creates the target directory.

**Memory bound.** Because children replace the placeholder in place and files sort first,
the queue holds at most the unfinished files of the directories currently being
processed plus the pending sibling placeholders along the current paths: with `S` slots
and fan-out `F` (entries per directory) and depth `D`, live items ≤ `S·F + D·F`.

**Symlink loops** (`follow_symlinks = true`):
- Real paths: a placeholder's real path is `real_path.unwrap_or(remote or local path)`;
  a child directory's real path is `parent_real.join(name)`; a followed symlink's real
  path is, remote: `parent_real.resolve(target)` (T02; when the listing has no target
  string, `stat` gives none either → follow without a real path, only `MAX_DEPTH`
  protects), local: `LocalBackend::canonicalize(child)` (T06).
- `is_link_loop(parent_real, chain, target_real)` = `parent_real.starts_with(target_real)
  || chain.iter().any(|c| c.starts_with(target_real))`. A loop → `SymlinkLoop` skip with a
  Status line "Skipped symbolic link loop <path> → <target>".
- Following a symlink pushes `parent_real` onto the child's `link_chain` and sets its
  `real_path = Some(target_real)`; normal subdirectories copy the chain.
- Directories reachable twice through different links (no cycle) are transferred twice
  (FileZilla does the same); `MAX_DEPTH` bounds every case.

#### Recursive delete (browsing session, T62)

Built on `walk` (listings from the caller's `DirLister`). Iterative post-order with an
explicit stack; memory holds only the *subdirectories still to visit* per level (files are
deleted as soon as their listing arrives):

```
for each target:
  file / symlink (any, never followed) / other → remove_file
  dir → push Frame { dir, subdirs: [], kept: false, failed: false } after listing it:
        for e in listing (sorted by name):
          if filter excludes e → frame.kept = true; filtered += 1; continue
          if e is Dir (not a symlink) → frame.subdirs.push(e)
          else remove_file(dir/e)  (failure → record, frame.failed = true)
loop while stack not empty:
  top = stack.last
  if top.subdirs non-empty → list next subdir, push its frame (as above)
  else → pop; if !kept && !failed → rmdir (failure → record); else kept_dirs += 1
         propagate kept/failed to the parent frame
```

- Symlinks to directories are removed as links (`remove_file`, T03: "never its target").
- Cancellation: the token is checked before every backend call; the running call finishes
  (≤ one RTT), then `cancelled = true` and the report is returned. AC: ≤ 1 s with 100 ms
  latency.
- Progress: `OperationProgress { id, text: "Deleting <path>", done: files+dirs deleted,
  total: None }` at most every 100 ms; `OperationFinished { id, error }` at the end
  (`error = Some("3 entries could not be deleted")` on partial failure).
- Cache: `CachePatch::RemovedFile` per file and `RemovedDir` per removed directory
  (T46 drops the subtree).
- Max depth 64 (deeper directories recorded as failures "too deep", parents kept).

#### Recursive chmod

- Targets: the selected entries; with `recurse`, directories are walked (same iterative
  walker without deletion, symlinks never followed or changed — counted in
  `skipped_symlinks`; FileZilla behaviour, since chmod on a link changes its target).
- Scope: `All` → files and dirs; `FilesOnly` → only files (dirs are walked but not
  changed); `DirsOnly` → only dirs. Selected directories are included unless
  `FilesOnly` (T62).
- New mode per entry: `compute_mode(entry.permissions.mode, spec)`; `None` → skipped
  (`skipped_unknown_mode`, Error log "Permissions of X are unknown; set all bits or none
  to change them"); equal to old → no call (`unchanged`).
- Order for directories: when the new mode keeps owner read and execute (`new & 0o500 ==
  0o500`), apply it **before** descending; otherwise apply it **after** the children
  (so removing `r`/`x` never blocks the walk).
- Progress, cancellation, failure collection and cache (`CachePatch::ModeChanged`) as for
  delete.

### Data formats and configuration

Settings read: `transfers.empty_dirs` (`create` | `skip`, default `create`, T05),
`transfers.follow_symlinks` (false, T05), `filters.apply_to_transfers` (true, T47), and the
active filter set (T47). No new keys. `DirExpansion` persistence format is in T40.

### Errors

| Situation | Result |
|---|---|
| Listing a placeholder fails (`NotFound`, `PermissionDenied`) | placeholder `Failed(Permanent)`; other items continue; listed in the failed tab |
| Listing fails transiently | T41 retry policy for the placeholder |
| Target directory creation fails | placeholder `Failed` with the message ("Could not create directory …") |
| Delete/chmod entry fails | recorded in the report (`path`, `err.to_string()`), walk continues |
| Subdirectory can't be listed during delete/chmod | recorded; that subtree and its parents kept |
| Cancelled | report with `cancelled = true`; no error dialog (T62 shows "Cancelled after N entries") |

### Security and logging

- Names from listings are untrusted: only valid single components are joined
  (`RemotePath::join`, `LocalPath::join`, sanitiser); a hostile `..` or `a/b` entry is
  skipped with an Error line and can never redirect a download or a delete outside the
  selected tree (T91).
- Delete never follows symlinks (only the link is removed); chmod never touches links.
- Loops and depth are bounded (`MAX_DEPTH`, loop check), so a hostile server cannot make
  recursion run forever; each listing is capped by the backend (T22: 1 000 000 entries).
- Status/Error lines contain paths (user-facing message log); tracing at `info`+ logs
  only operation ids and counts.

## Implementation steps

1. `compute_mode`, `is_link_loop`, child ordering helpers + unit tests.
2. `expand_placeholder` with classification, filters, names, destination dir creation.
3. Hook into T41's slot (`Listing` phase) and `Queue::replace_placeholder`; Move markers.
4. Symlink following with real-path tracking (remote resolve, local canonicalize).
5. Iterative `walk` with the `DirLister` seam (`SessionHandle`, `FnLister`);
   `delete_recursive` with reports, progress, cache patches.
6. `chmod_recursive` with scope and pre/post order.
7. Memory-bound and property tests; local symlink-loop test; e2e scenarios.

## Acceptance criteria

- [ ] AC1 Downloading a mock tree of 10 × 10 × 10 directories with 100 files per leaf (100 000 files) with `max_concurrent = 4` transfers every file, and the queue never holds more than 1 000 live items (sampled every tick).
- [ ] AC2 With `follow_symlinks = true`, a remote mock tree with `a/loop → /a`, `b/x → ../b`, and a two-link cycle `c/l1 → /d`, `d/l2 → /c` finishes, each loop logged once; locally (Unix, temp dir) a `loop → .` link finishes too.
- [ ] AC3 `delete_recursive` removes everything bottom-up (every `rmdir` after its children, checked from the mock call log); with one injected `remove_file` failure the report lists exactly that file and its ancestors are kept; everything else is gone.
- [ ] AC4 `compute_mode` matches the table tests (tri-state masks, special bits, unknown old mode), and recursive chmod with `FilesOnly`/`DirsOnly` changes exactly the expected entries; removing `u+x` on a directory still visits its children.
- [ ] AC5 With filters active and `apply_to_transfers = true`, excluded files are never queued, excluded directories are never listed (mock `calls(List)`), and delete/chmod leave them (and their parents) untouched; with `apply_to_transfers = false` everything is processed.
- [ ] AC6 Recursive delete is cancelled within 1 s of virtual time (100 ms latency) and reports how many entries were deleted.
- [ ] AC7 `empty_dirs = create` creates empty directories on the target; `skip` creates none of them, but directories with files still appear.
- [ ] AC8 Move of a directory removes the source tree only for children that transferred; a failed child keeps its directory chain.
- [ ] AC9 Hostile names (`..`, `a/b`, ESC sequences) in a mock listing never produce a path outside the target directory.
- [ ] AC10 T00 `test-local-only`, `test-os` (Windows: no symlink test; canonicalize path) and `e2e` pass.
- [ ] AC11 `walk` lists only through the supplied `DirLister`: with an `FnLister` that
  counts calls and serves a fixed tree, every directory is listed exactly once, none of the
  session's `list` calls happen, `SkipChildren` prunes a subtree, `Stop` and cancellation
  end the walk before the next list call.

## Tests

### Unit tests
- `fn compute_mode_table` — known/unknown old × full/partial/zero mask × special bits (AC4).
- `fn is_link_loop_cases` — self link, parent link, sibling link, two-link cycle, unrelated link (AC2).
- `fn children_order_files_then_dirs_by_name` (AC1).
- `fn classify_symlink_matrix` — the table above × `follow_symlinks` (AC2, AC5).
- `fn depth_limit_skips_level_65`.
- `async fn walk_uses_supplied_lister_only` and `async fn walk_skip_children_and_stop` (AC11).

### Property / fuzz tests
- `proptest fn delete_postorder_and_complete` — random trees (≤ 500 entries, depth ≤ 8, random symlinks, random injected failures) on `MockServer`; afterwards exactly the failed paths and their ancestors remain, every `rmdir` comes after its children, links' targets untouched (AC3).
- `proptest fn expansion_preserves_tree` — random trees downloaded through the engine to a local mock; resulting tree equals the source minus filtered entries (AC1, AC5, AC7).

### Snapshot tests
Not applicable (T62 renders the dialogs).

### Integration tests
`#[tokio::test(start_paused = true)]`, remote and local `MockServer`s, T41 engine:
- `async fn hundred_thousand_files_bounded_queue` (AC1).
- `async fn symlink_loops_terminate_remote` (AC2).
- `#[cfg(unix)] async fn local_symlink_loop_terminates` — real `LocalBackend` in a `tempfile::TempDir` with `loop -> .` (AC2).
- `async fn delete_partial_failure_report` and `async fn delete_cancel_within_one_second` (AC3, AC6).
- `async fn chmod_scopes_and_order` (AC4).
- `async fn filters_skip_queue_list_delete_chmod` and `async fn apply_to_transfers_off` (AC5).
- `async fn empty_dirs_create_vs_skip` (AC7).
- `async fn move_directory_removes_only_transferred` (AC8).
- `async fn hostile_names_never_escape` (AC9).

### End-to-end tests
`crates/courier-ftp-e2e/tests/recursive.rs` (`#[ignore]`, `require_docker!`, `Headless`):
- `fn recursive_roundtrip_<profile>` (`vsftpd-plain`, sshd `password`): upload a 30-dir,
  200-file tree incl. empty dirs and a symlink, download it elsewhere, compare trees and
  hashes (AC1, AC7).
- `fn recursive_delete_on_server` and `fn recursive_chmod_files_only` (`proftpd-plain`
  with `SITE CHMOD`, sshd `password`) — a server-side listing confirms the result (AC3, AC4).

## Out of scope

- The confirmation and progress dialogs (T62).
- Recursive operations on the remote → remote path (no FXP).
- Detecting the same directory reached through different links (hard links, bind mounts)
  beyond the loop check.

## Open questions

1. With `follow_symlinks = false`, symlinks to directories are skipped with a Status
   line, and symlinks to files are transferred as regular files (their content). Should
   symlinks instead be recreated as symlinks where both sides support it (SFTP `symlink`,
   local)? FileZilla doesn't; this spec doesn't either.
2. Resolved: T62 uses `compute_mode` and T40's `QueueItemKind`; T49 walks through `walk`
   with a cache-backed `DirLister`.
