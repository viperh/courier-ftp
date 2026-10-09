# T49 — Search engine

**Phase:** E Transfers · **Milestone:** M6 · **Depends on:** T43, T46, T47 · **Crate(s):** `courier-ftp-core` (`search` module) · **FEATURES.md:** §4 (remote search, local search)
**Related (integrates with, not blocking):** T65

## Goal

Recursive search under a local or remote directory with FileZilla's condition
builder (name, size, path, date, attributes; match all/any/none/not all). Results
stream to the caller while the walk continues, the search is cancellable within one
second, and remote searches run on their own session so the tab stays usable. The
engine also turns selected results into download/upload plans (keeping the directory
structure or flattening) and delete plans that the UI (T65) hands to the queue and
recursive operations.

## Context

- Before: T43 provides the async depth-first `Walker` over a `Backend` with bounded
  memory, symlink-loop protection and per-directory error skipping; T46 provides
  `ListingCache::get_or_fetch` with `ListMode::FreshOnly` and `ServerKey`; T47 provides
  `Condition`, `MatchMode`, `AppliesTo`, `Filter`, `CompiledFilter::matches`; T03
  provides `BackendFactory`, `ConnectInfo`, `SessionHandle`; T06 `LocalBackend`.
- After: T65 builds the query form, shows streamed results, and uses the plan helpers
  to create queue items (T40) or start recursive deletes (T43).

## Technical specification

### Types and APIs

Module `courier_ftp_core::search`.

```rust
pub enum SearchRoot {
    Local(LocalPath),
    Remote { dir: RemotePath, server: ServerKey, connect: ConnectInfo },
}

#[derive(Debug, Clone)]
pub struct SearchQuery {
    pub root: SearchRoot,
    pub conditions: Vec<Condition>,   // T47 types; 1..=32
    pub match_mode: MatchMode,        // All | Any | None | NotAll
    pub case_sensitive: bool,
    pub search_type: AppliesTo,       // Files | Dirs | Both
    pub max_depth: Option<u32>,       // None = unlimited; 0 = root directory only
    pub max_results: usize,           // default 100_000
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub dir: String,                  // parent directory (remote path or native local path)
    pub entry: Entry,
}

#[derive(Debug)]
pub enum SearchEvent {
    /// Up to 256 hits; sent when 256 accumulate or 100 ms after the first unsent hit.
    Found(Vec<SearchHit>),
    /// At most 4 per second.
    Progress { dirs_scanned: u64, entries_scanned: u64, current_dir: String },
    /// A subdirectory could not be listed; the walk continues.
    DirError { dir: String, error: String },
    /// Final event, always sent exactly once (unless the receiver was dropped).
    Done(SearchSummary),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchSummary {
    pub hits: u64,
    pub dirs_scanned: u64,
    pub entries_scanned: u64,
    pub dir_errors: u64,
    pub outcome: SearchOutcome,       // Completed | Cancelled | Truncated | Failed(String)
    pub elapsed: Duration,
}

pub struct SearchHandle {
    pub events: tokio::sync::mpsc::Receiver<SearchEvent>,  // capacity 64
    pub cancel: CancellationToken,
    pub id: SearchId,                 // Uuid v4, used in logs instead of paths
}

pub struct SearchEngine { /* factory, cache, browsing-session lookup */ }

impl SearchEngine {
    pub fn new(factory: Arc<dyn BackendFactory>, cache: ListingCache, events: EventSender) -> Self;
    /// Validates the query, then spawns the search task.
    /// `browsing` is the tab's session, used only when the server allows one connection.
    pub fn start(&self, query: SearchQuery, browsing: Option<SessionHandle>)
        -> Result<SearchHandle>;
}

// ---- plans for result actions (pure functions) ----

pub enum ResultLayout { KeepStructure, Flatten }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedDownload { pub remote: RemotePath, pub local: LocalPath, pub is_dir: bool }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedUpload { pub local: LocalPath, pub remote: RemotePath, pub is_dir: bool }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanSkip { pub hit_dir: String, pub name: String, pub reason: SkipReason }
pub enum SkipReason { UnsafeName, NestedInSelectedDir, OutsideRoot }

pub fn plan_downloads(hits: &[SearchHit], root: &RemotePath, target: &LocalPath,
                      layout: ResultLayout) -> (Vec<PlannedDownload>, Vec<PlanSkip>);
pub fn plan_uploads(hits: &[SearchHit], root: &LocalPath, target: &RemotePath,
                    layout: ResultLayout) -> (Vec<PlannedUpload>, Vec<PlanSkip>);
/// Order for deletion: files first, then directories deepest first.
pub fn plan_delete(hits: &[SearchHit]) -> (Vec<SearchHit>, Vec<PlanSkip>);
/// `name (1).ext`, `name (2).ext`, …: the same format as T42's Rename action.
pub fn numbered_name(name: &str, n: u32) -> String;
```

### Behaviour

**Validation** (before spawning): 1..=32 conditions, every condition compiles (via
`CompiledFilter::compile` of a synthetic `Filter { applies_to: search_type, match_mode,
case_sensitive, conditions, scope: Both }`), `max_results` in 1..=1 000 000. Failure →
`Error::InvalidInput` with the `FilterError` message.

**Matching.** An entry is a hit when the compiled filter `matches(entry, dir)` (search
**includes** matches; filters exclude them). Directory listing filters (T47 sets) are
**not** applied: the query is the only criterion. The root directory itself is never
a hit.

**Session choice (remote).**
1. If the server's connection limit (`ConnectInfo` connection limit, T31) is `Some(1)`
   and `browsing` is given, use the browsing `SessionHandle` (its mutex interleaves
   search listings with browsing) and log a status line saying so.
2. Otherwise create a new backend with `BackendFactory::create(&connect, events)`,
   wrap it in a `SessionHandle`, connect with the search's cancel token, and disconnect
   it when the search ends (any outcome). Connect failure → `Done(Failed)`.
Local searches use a fresh `LocalBackend`.

**Walk.** Use the T43 `Walker` (depth-first, bounded memory, `follow_symlinks` from
`transfers.follow_symlinks` with loop detection) with its directory listing routed
through the cache for remote roots: `cache.get_or_fetch(server, dir, ListMode::FreshOnly,
|| session.list(dir, cancel))`, which reuses fresh cached listings and stores new ones
(the search fills the cache). `max_depth` stops descent below that depth (root = 0).
A directory listing error (permission denied, not found) → `DirError` and the walk
continues; an error on the **root** → `Done(Failed(message))`.

**Streaming and back-pressure.** Hits are batched (≤ 256 per `Found`, flushed at the
latest 100 ms after the first unsent hit, and before `Done`). The channel is bounded
(64 events); when the UI does not consume, the walker waits, so memory stays bounded
by 64 × 256 hits plus the walker's own bound. If the receiver is dropped, the search
cancels itself.

**Limits.** After `max_results` hits the walk stops with `Truncated`. Progress at most
every 250 ms.

**Cancellation.** The token is checked before every directory listing and after every
256 entries; listing calls receive the token (T03 `list(dir, cancel)`), so a pending
network read is abandoned. Required: `Done(Cancelled)` arrives within 1 s of
`cancel.cancel()`, including during a slow listing. The dedicated session is then
disconnected in the background (bounded by `connection.timeout_secs`).

**Plans.**
- Relative path of a hit = its full path relative to `root` (components). Hits not
  under `root` → `PlanSkip(OutsideRoot)`.
- Every component that becomes a local path component must be safe: not empty, not `.`
  or `..`, no `/`, `\`, NUL or other control characters. Unsafe → `PlanSkip(UnsafeName)`
  (protects against hostile servers; T42 still applies `sanitize_local_name` for
  OS-invalid characters at transfer time).
- A hit lying inside another selected directory hit → `PlanSkip(NestedInSelectedDir)`
  (the directory transfer/delete already covers it).
- `KeepStructure`: `target / relative path`; directories become `is_dir = true` items
  (T65 queues them as dir placeholders, T43).
- `Flatten`: `target / name`; on a name collision within the plan the later hit (in
  input order) gets `numbered_name(name, n)` with the smallest free `n >= 1`. Collisions
  with files already in `target` are not handled here (T42 file-exists policy decides).
- Name collision checks use case-insensitive comparison when the target side is
  case-insensitive (`NameCase` rules from T48 for local targets, server type for remote).

**Complexity.** Matching is O(conditions) per entry. Plans are O(h log h) for h hits.

### Data formats and configuration

No new settings. Uses `transfers.follow_symlinks` (T05) and `connection.timeout_secs`.
The previous query is kept in memory by T65 only (never persisted: it may contain
paths).

### Errors

- `start`: `Error::InvalidInput` for an invalid query.
- During the search, errors become events: per-directory → `DirError { error: e.to_string() }`;
  root listing or connect failure → `Done(Failed(message))`; `Error::Cancelled` →
  `Done(Cancelled)` (not reported as a failure).
- Plans never fail; problems are returned as `PlanSkip` entries that T65 lists in a
  summary ("3 results skipped: unsafe names").

### Security and logging

- Remote names are untrusted: the plan rejects path traversal (`..`, separators, NUL,
  control characters) so no planned local path escapes `target`. Covered by the T76
  hostile-server scenario.
- Logs: `info!` "search {id} started/finished: {hits} hits, {dirs} dirs, {outcome}" with
  the `SearchId` only; no hostnames, users, paths or patterns at `info`+ (T91). `debug!`
  may include the root path.
- The dedicated session uses the same `ConnectInfo` (secrets stay in `SecretString`,
  never logged).

## Implementation steps

1. Types, query validation (compile through T47), `numbered_name`.
2. Search task over a `Backend` with the T43 walker, matching, batching and the bounded channel (local first, using `LocalBackend` in temp dirs).
3. Remote: dedicated session creation/teardown and the single-connection fallback; cache routing with `FreshOnly`.
4. Cancellation, `max_depth`, `max_results`, progress throttling, `Done` guarantees.
5. `plan_downloads`, `plan_uploads`, `plan_delete` with safety checks.
6. Module docs; integration tests with `MockBackend` latency.

## Acceptance criteria

- [ ] AC1 With a mock backend adding 200 ms per listing, the first `Found` event arrives before `Done` and within 500 ms of start for a hit in the root directory.
- [ ] AC2 `cancel()` during a slow listing produces `Done(Cancelled)` within 1 s (paused-time test and a real-time test with 5 s listing latency).
- [ ] AC3 Conditions name/size/path/date combine correctly with All/Any/None/NotAll (table test over a fixed mock tree with expected hit sets).
- [ ] AC4 `search_type` Files/Dirs/Both and `max_depth` 0/1/unlimited restrict hits as expected.
- [ ] AC5 Remote search opens a second session (factory called once) and leaves the browsing session idle; with connection limit 1 it uses the browsing session instead and opens none.
- [ ] AC6 Fresh cached directories are not listed again during a search, and listed directories are in the cache afterwards.
- [ ] AC7 `plan_downloads` keeps relative structure, flattens with `name (1).ext` on collisions, skips nested hits and rejects `..`, `/`, `\`, NUL and control characters in names.
- [ ] AC8 A directory that fails to list yields one `DirError` and the search still completes with the other hits.
- [ ] AC9 Memory stays bounded when the consumer stops reading: on a 100 000-entry mock tree with nobody reading, at most 64 events are buffered (channel capacity) and the walker is suspended.
- [ ] AC10 `max_results = 10` stops with `Truncated` and exactly 10 hits.
- [ ] AC11 No hostname, path or pattern appears in `info`+ log lines of a search (log capture test).
- [ ] AC12 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os` pass; the e2e search scenario passes in the `e2e` job.

## Tests

### Unit tests
- `query_validation_rejects_bad_regex_and_empty_conditions` — `InvalidInput`.
- `numbered_name_formats` — `a.txt` → `a (1).txt`, `archive.tar.gz` → `archive.tar (1).gz` (same rule as T42: last extension only), `noext` → `noext (1)`, `.bashrc` → `.bashrc (1)`. AC7.
- `plan_downloads_keep_structure` — AC7.
- `plan_downloads_flatten_renames_collisions` — three `index.html` hits → `index.html`, `index (1).html`, `index (2).html`. AC7.
- `plan_skips_nested_hits` — dir hit `/a` and file hit `/a/b.txt` → only `/a`. AC7.
- `plan_rejects_unsafe_names` — names `..`, `a/b`, `a\b`, `x\0y`, `\x1b[2J` → `UnsafeName`. AC7.
- `plan_uploads_mirror` — symmetric cases for uploads.
- `plan_delete_orders_files_then_deepest_dirs`.
- `flatten_case_insensitive_collision_on_windows_target` — `A.txt` and `a.txt` collide when the target is case-insensitive.

### Property / fuzz tests
- `prop_plan_paths_stay_under_target` — random hit names (arbitrary Unicode including separators and dots) → every planned local path starts with `target` and has no `..` component. AC7.
- `prop_flatten_names_unique` — random duplicate-heavy hit lists → planned names unique (case-insensitive when requested).

### Snapshot tests
Not applicable (UI in T65).

### Integration tests
- `streams_hits_before_done_with_slow_backend` — `MockBackend` with 200 ms latency. AC1.
- `cancel_within_one_second_paused_time` and `cancel_within_one_second_real_time`. AC2.
- `condition_combinations_table` — fixed mock tree (≈ 40 entries over 3 levels). AC3.
- `search_type_and_depth_limits`. AC4.
- `remote_search_uses_dedicated_session` and `single_connection_server_uses_browsing_session` — counting `BackendFactory` stub. AC5.
- `uses_and_fills_listing_cache` — pre-populate fresh `/a`; mock list counter excludes `/a`; afterwards `/b` is cached. AC6.
- `dir_error_skipped_and_reported`. AC8.
- `backpressure_bounds_buffer` — 100 000 entries (1 000 dirs × 100), receiver not polled for 2 s; walker progress counter stops advancing. AC9.
- `max_results_truncates`. AC10.
- `info_logs_contain_no_paths` — `tracing` capture layer, asserts no root path / hostname / pattern substring in `info`+ lines. AC11.
- `local_search_in_tempdir` — `LocalBackend` on a `tempfile::TempDir` tree, including a symlink loop (Unix only) that terminates.

### End-to-end tests
- `e2e_remote_search_sftp_and_ftp` (`courier-ftp-e2e`, `#[ignore]`, `COURIER_E2E=1`) — `Headless` search on the `sshd` `password` profile and the vsftpd `plain` profile over a seeded tree; hits equal the expected set; the browsing session remains usable (a `list` on it completes while the search runs). AC12.
- `e2e_hostile_names_never_escape_target` — hostile FTP fixture (T76) serves `../evil` and `a/b` names; `plan_downloads` skips them. AC7, AC12.

## Out of scope

- The search UI, result actions dialogs and "go to result" (T65).
- Searching file contents.
- Server-side search commands (`SITE FIND`, `find` over SSH exec).
- Persisting queries or results.

## Open questions

- **Dependency seam with T43 (not owned):** this task needs T43's `Walker` to list
  directories through a caller-supplied lister (a `DirLister` trait or closure) so
  listings can go through the T46 cache. T43 currently describes the walker "over any
  `Backend`" only. T43's owner should expose that seam; otherwise T49 duplicates the
  walk logic.
