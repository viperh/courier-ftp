# T42 — File-exists policy, resume and transfer options

**Phase:** E Transfers · **Milestone:** M4 · **Depends on:** T04, T05, T06, T41 · **Crate(s):** `courier-ftp-core` (`transfer::exists`, `transfer::options`) · **Decisions:** none · **FEATURES.md:** §5 (file exists actions, resume, > 4 GB), §6 (preallocate, timestamps, invalid characters, ASCII/binary)
**Related (integrates with, not blocking):** T11

## Goal

Everything that decides *how* one file is transferred once the engine (T41) has picked
it: what happens when the target exists (FileZilla's eight actions, set per direction,
per item, or "apply to all" from the prompt), resuming partial files including files
over 4 GiB, the transfer type, invalid local characters, preallocation and preserved
timestamps. The decision itself is a pure function with an exhaustive table test.

## Context

- Before: T41 gives the `ExistsPolicy` trait, `ExistsRequest`, `ExistsOutcome`,
  `TargetPath`, `TargetProbe`, `LocalFs`/`LocalWriter`, the worker's `Preparing` and
  `Finishing` phases and `OverwritePolicy` (replaced by this task's policy); T04 gives
  `PromptKind::FileExists(Box<FileExistsPrompt>)`, `PromptResponse::FileExists { action,
  apply_to, new_name }`, `ApplyTo { Once, AllInQueue, AllForDirection }` and
  `EventSender::prompt_with_cancel`; T05 gives `ExistsAction`, `TransferTypeChoice`,
  `decide_transfer_type`, `transfers.{on_exists_download, on_exists_upload, preallocate,
  preserve_timestamps, replace_invalid_chars, invalid_char_replacement}`; T06 gives
  `sanitize_local_name` and `available_space`; T02 gives `Timestamp::cmp_coarse`,
  `Precision`, `LocalPath::join`; T40 gives `QueueItem::on_exists`, `RangeSet`.
- After: T69 renders the file-exists prompt; T56 sets per-item `on_exists`; T41b reuses
  `decide` for segmented resume; T48/T66 reuse `compare_times`.

## Technical specification

### Types and APIs

Module `courier_ftp_core::transfer::exists`:

```rust
/// What the decision needs to know about one side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileFacts { pub kind: FactKind, pub size: Option<u64>, pub modified: Option<Timestamp> }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactKind { File, DirOrOther }
impl FileFacts { pub fn from_entry(e: &Entry) -> Self; }   // symlink → its target kind (Dir → DirOrOther)

/// Pure decision (no I/O). `resume_ok` = binary type ∧ capability (`resume_download` for
/// downloads, `resume_upload` for uploads) ∧ local side supports seeking (always true).
pub fn decide(action: ExistsAction, src: &FileFacts, dst: Option<&FileFacts>, resume_ok: bool) -> Decision;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Transfer(WriteMode),            // Create | Truncate | ResumeAt(n) (T03)
    Skip(SkipReason),               // T40: ExistsPolicy | AlreadyComplete
    Rename,                         // pick a free name, then Transfer(Create)
    AskUser,
    TargetIsDirectory,              // item fails
}

/// Size relation of target to source, and time relation of source to target.
pub enum SizeRel { TargetSmaller, Equal, TargetLarger, SourceUnknown, TargetUnknown }
pub enum TimeRel { SourceNewer, Equal, SourceOlder, Unknown }
pub fn size_rel(src: &FileFacts, dst: &FileFacts) -> SizeRel;
/// Compares at the coarser precision of the two (`Timestamp::cmp_coarse`, T02).
pub fn time_rel(src: &FileFacts, dst: &FileFacts) -> TimeRel;

/// "name (1).ext", "name (2).ext", … up to "(999)".
pub fn rename_candidates(name: &str) -> impl Iterator<Item = String> + '_;
/// Validates a user-typed new name (prompt "Rename" field).
pub fn validate_new_name(name: &str, target: &TargetPath, s: &TransferSettings) -> Result<String>;

/// The real policy injected into the engine (replaces T41's `OverwritePolicy`).
pub struct FileExistsPolicy { /* settings, events, rules: Mutex<RunRules>, ask_gate: tokio::sync::Mutex<()> */ }
impl FileExistsPolicy {
    pub fn new(settings: SharedSettings, events: EventSender) -> Self;
    /// The action that applies to this item right now (for the queue pane's display).
    pub fn effective_action(&self, item: &QueueItem) -> ExistsAction;
}
impl ExistsPolicy for FileExistsPolicy { /* resolve, run_finished */ }

/// Answers remembered for the current queue run ("apply to all").
#[derive(Clone, Debug, Default)]
struct RunRules { download: Option<ExistsAction>, upload: Option<ExistsAction> }
```

Module `courier_ftp_core::transfer::options`:

```rust
/// Final per-file choices the worker uses after the exists decision.
pub struct FileOptions {
    pub transfer_type: TransferType,
    pub local_target: Option<LocalPath>,   // downloads: sanitised path
    pub preallocate: bool,
    pub preserve_timestamp: Option<Timestamp>,
}
/// Auto → `decide_transfer_type(name, choice, &settings.file_types)` (T05); backends
/// without ASCII mode (`caps.ascii_mode == false`, SFTP) → always Binary.
pub fn resolve_transfer_type(item: &QueueItem, caps: &Capabilities, s: &Settings) -> TransferType;
/// Download target name: sanitise the final component (T06) when `replace_invalid_chars`,
/// else reject invalid names. Returns the path and whether it changed.
pub fn local_target(item: &QueueItem, s: &TransferSettings) -> Result<(LocalPath, bool)>;
```

`LocalWriter::allocate(len)` (declared in T41, implemented here) reserves real space: `fs4` `allocate` = `posix_fallocate` / `SetFileInformationByHandle
(FileAllocationInfo)` / `F_PREALLOCATE`; `MemLocalFs` records the call.

### Behaviour

**Which action applies** (`effective_action`), first match wins:
1. `item.on_exists` (set per item in the queue pane, T56);
2. the run rule for the item's direction (set by a prompt answer with `ApplyTo::AllInQueue`
   — both directions — or `ApplyTo::AllForDirection` — this direction only); a later
   answer replaces an earlier rule;
3. `transfers.on_exists_download` / `transfers.on_exists_upload` (default `Ask`).

Run rules are cleared by `run_finished()` (queue run ends, `Stop`) — FileZilla's
"apply to current queue only".

**Decision table.** A missing target → `Transfer(Create)` for **every** action. A target
that is a directory or another non-file (`FactKind::DirOrOther`): `Ask` → `AskUser`
(the prompt shows it; overwrite answers then fail), `Rename` → `Rename`, `Skip` →
`Skip(ExistsPolicy)`, all others → `TargetIsDirectory` (item fails "A directory with this
name exists"). For a file target:

| Action | Result (for every size/time combination) |
|---|---|
| `Ask` | `AskUser` |
| `Overwrite` | `Transfer(Truncate)` |
| `Rename` | `Rename` |
| `Skip` | `Skip(ExistsPolicy)` |

The four conditional actions (`T` = `Transfer(Truncate)`, `S` = `Skip(ExistsPolicy)`,
`SC` = `Skip(AlreadyComplete)`, `R` = `Transfer(ResumeAt(target size))`, with
`ResumeAt(0)` written as `Truncate`); rows = size relation × time relation:

| Size rel. | Time rel. | IfNewer | IfSizeDiffers | IfNewerOrSizeDiffers | Resume (`resume_ok`) | Resume (¬`resume_ok`) |
|---|---|---|---|---|---|---|
| TargetSmaller | SourceNewer | T | T | T | R | T |
| TargetSmaller | Equal | S | T | T | R | T |
| TargetSmaller | SourceOlder | S | T | T | R | T |
| TargetSmaller | Unknown | T | T | T | R | T |
| Equal | SourceNewer | T | S | T | SC | T |
| Equal | Equal | S | S | S | SC | T |
| Equal | SourceOlder | S | S | S | SC | T |
| Equal | Unknown | T | S | T | SC | T |
| TargetLarger | SourceNewer | T | T | T | T | T |
| TargetLarger | Equal | S | T | T | T | T |
| TargetLarger | SourceOlder | S | T | T | T | T |
| TargetLarger | Unknown | T | T | T | T | T |
| SourceUnknown | SourceNewer | T | T | T | R | T |
| SourceUnknown | Equal | S | T | T | R | T |
| SourceUnknown | SourceOlder | S | T | T | R | T |
| SourceUnknown | Unknown | T | T | T | R | T |
| TargetUnknown | SourceNewer | T | T | T | T | T |
| TargetUnknown | Equal | S | T | T | T | T |
| TargetUnknown | SourceOlder | S | T | T | T | T |
| TargetUnknown | Unknown | T | T | T | T | T |

Rules behind the table (FileZilla behaviour): unknown time or size counts as "newer" /
"differs" so data is never silently left stale; `Resume` with a larger target overwrites
(it's a different file) and logs Status "Target is larger than the source; overwriting";
`Resume` without `resume_ok` overwrites and logs "Resume not possible (ASCII mode or not
supported by the server); overwriting"; `SourceUnknown` (e.g. FTP without `SIZE`) resumes
at the target size and lets the server end the stream. `size_rel` uses
`SourceUnknown` when the source size is unknown (whatever the target), `TargetUnknown`
when only the target size is unknown. `time_rel` is `Unknown` when either mtime is
missing; otherwise `cmp_coarse` (Day-precision listings compare by date only).

**Ask flow** (only `AskUser` reaches it):
1. Acquire `ask_gate` (a `tokio::sync::Mutex<()>`, awaited with the slot's cancel token):
   only one file-exists prompt per engine is open at a time. Other slots keep working;
   only slots that also need to ask wait.
2. After acquiring, recompute `effective_action` — an answer given meanwhile with
   "apply to all" now decides this item without a prompt.
3. Otherwise set the item to `Active { phase: AwaitingUser }` and call
   `events.prompt_with_cancel(session, PromptKind::FileExists(Box::new(FileExistsPrompt {
   direction, source_path, source, target_path, target, can_resume: resume_ok })), cancel)`.
4. Answer `PromptResponse::FileExists { action, apply_to, new_name }` (`action ≠ Ask`):
   `apply_to = AllInQueue` / `AllForDirection` stores the run rule **before** releasing the
   gate; then `decide(action, …)`. `new_name` is used only for this item's `Rename`.
   `PromptResponse::Cancel`, a withdrawn prompt or no UI → `Error::Cancelled`, which T41
   turns into `Paused` for this item (dismissed question). The gate is released on every
   path (RAII guard).

**Rename.** Candidates come from `rename_candidates(file_name)`: split at the last `.`
unless that dot is the first character (dotfile) or the last; `report.pdf` →
`report (1).pdf`; `.bashrc` → `.bashrc (1)`; `archive.tar.gz` → `archive.tar (1).gz`;
`README` → `README (1)`. Each candidate is checked with `TargetProbe::exists`; the first
free one is used with `WriteMode::Create`; 999 taken → item fails with
`AlreadyExists` "No free file name found". A user-typed `new_name` is validated by
`validate_new_name`: 1–255 bytes, not `.`/`..`, no `/`, NUL or control characters; for
local targets the T06 sanitiser applies (if `replace_invalid_chars`) or an invalid name is
rejected; if it exists, the prompt is shown again with the message "<name> already
exists" (each re-prompt also respects cancel). **Never overwrite**: `WriteMode::Create`
opens locally with `create_new` (O_EXCL) and on SFTP with `CREATE|EXCL`; if that fails
with `AlreadyExists` (race), the next candidate is tried. FTP has no exclusive create —
there `STOR` is used after the probe; the race window is documented.

**Transfer type.** `resolve_transfer_type`: item `Ascii`/`Binary` as chosen; `Auto` →
`decide_transfer_type`; SFTP always `Binary`. ASCII disables resume and segmentation.

**Invalid local characters** (downloads, before the exists check):
- The final component of `item.local` (built by T62/T43 from the remote name) goes
  through `sanitize_local_name(name, transfers.invalid_char_replacement)` when
  `transfers.replace_invalid_chars` (default true); a changed name logs Status
  "Renamed \"a:b.txt\" to \"a_b.txt\" (invalid characters for this system)".
- When the setting is off and the name is invalid → item `Failed(Permanent)`
  "File name is not valid on this system".
- Always rejected regardless of the setting (T91 path traversal): `.`, `..`, names
  containing `/`, NUL, or `\` and a drive prefix on Windows (`LocalPath::join` rules).

**Preallocate** (`transfers.preallocate`, default false): only for downloads with a known
size, mode `Create`/`Truncate`, and size ≥ 1 MiB. Before writing: `writer.allocate(size)`.
- `ENOSPC`/disk full → `LocalDiskFull` (T41 stops the queue before any byte is written).
- Unsupported filesystem (`EOPNOTSUPP`, `ERROR_INVALID_FUNCTION`) → continue without, Debug
  log once per run.
- Because a preallocated file already has its full length, a failed or cancelled download
  is truncated back to the checkpointed `completed.contiguous_prefix()` (`set_len`) before
  closing, so a later resume by size starts at the right offset.
- Before any download with known size ≥ 1 MiB, `available_space(parent)` (T06) <
  remaining bytes → `LocalDiskFull` without starting (`None` = unknown → proceed).

**Preserve timestamps** (`transfers.preserve_timestamps`, default false), in `Finishing`:
- Download: if the source `modified` has precision ≥ `Minute` → `LocalFs::set_mtime`;
  `Day` precision → not set (Debug log "server time too imprecise").
- Upload: if `caps.set_mtime` → `Backend::set_mtime(path, local mtime)`; otherwise a
  Status line once per server group per run: "Server does not support setting file
  times". A failing `set_mtime` logs an Error line; the item is still `Done`.

**Large files.** All sizes and offsets are `u64`; `ResumeAt(n)` with n > 4 GiB is passed
unchanged to `REST n` (T11) and SFTP offsets. Tests use sparse data (below).

### Data formats and configuration

Settings read (all defined in T05): `transfers.on_exists_download` (`ask`),
`transfers.on_exists_upload` (`ask`), `transfers.preallocate` (false),
`transfers.preserve_timestamps` (false), `transfers.replace_invalid_chars` (true),
`transfers.invalid_char_replacement` ('_'), `file_types.*`. No new keys. Run rules are in
memory only and never persisted.

Prompt payload: T04's `FileExistsPrompt { direction, source_path, source, target_path,
target, can_resume }`; paths are display strings (remote `RemotePath::as_str`, local
`LocalPath::to_display`).

### Errors

| Situation | Error / class | User sees |
|---|---|---|
| Target is a directory | `AlreadyExists(path)` → `ItemFatal` | failed list: "A directory with this name exists" |
| No free rename candidate | `AlreadyExists` → `ItemFatal` | "No free file name found" |
| Invalid local name, replacement off | `InvalidInput` → `ItemFatal` | "File name is not valid on this system" |
| Prompt dismissed | `Cancelled` (not engine-cancelled) | item paused, Status "Question dismissed; item paused" |
| Not enough space / preallocate ENOSPC | `Io(StorageFull)` → `LocalDiskFull` | T41 stop message |
| `set_mtime` failed | logged only | Error log line |

### Security and logging

- Remote names are untrusted: local target names pass the `LocalPath::join` rules and the
  sanitiser; nothing can escape the destination directory (T91 hostile-server tests).
- Prompt texts carry paths and are shown only in the UI; tracing logs at `info`+ record
  only the `TransferId`, the action and the decision (`"exists: id=42 action=resume
  decision=resume-at"`), never names.
- Rename never overwrites (exclusive create where the protocol allows it).

## Implementation steps

1. `FileFacts`, `size_rel`, `time_rel`, `decide` + exhaustive table test.
2. `rename_candidates`, `validate_new_name` + tests.
3. `FileExistsPolicy` with run rules, `effective_action`, ask gate and prompt handling.
4. `options.rs`: transfer type, local target sanitising, wiring into T41's `Preparing`.
5. Preallocation (`LocalWriter::allocate`, truncate-on-failure), free-space check.
6. Preserve timestamps in `Finishing`.
7. Large-file tests with sparse mock data; engine-level prompt tests.

## Acceptance criteria

- [ ] AC1 `decide` matches the tables above for every `ExistsAction` × {missing, directory, 20 file combinations} × `resume_ok` ∈ {true, false} (352 cases, generated table test).
- [ ] AC2 With 4 slots and 20 conflicting downloads, answering the first prompt with `Overwrite` + `AllInQueue` shows exactly one prompt; the other 19 overwrite; the next run asks again.
- [ ] AC3 `AllForDirection` given for a download does not apply to uploads in the same run.
- [ ] AC4 Rename never overwrites: property test with random existing names and a racing creator; no existing file's content changes.
- [ ] AC5 Resume of a 5 GiB sparse download at offset 4.5 GiB requests `open_read(offset = 4 831 838 208)` and the final content matches the source pattern (mock backend).
- [ ] AC6 A dismissed prompt pauses only that item; other items continue.
- [ ] AC7 With `replace_invalid_chars` on, `a:b?.txt` downloads to `a_b_.txt` on Windows and unchanged on Unix (`a:b?.txt` is valid there); `..` and `x/y` are always rejected.
- [ ] AC8 With `preallocate`, a cancelled download at 30 % leaves a file of exactly the checkpointed length.
- [ ] AC9 `preserve_timestamps` sets local mtime for Minute/Second precision sources and not for Day; on a server without `set_mtime` one Status line per run is logged.
- [ ] AC10 T00 `test-local-only` and `test-os` (Windows/macOS sanitiser cases) pass.

## Tests

### Unit tests
- `fn decide_table_exhaustive` — iterates the literal table (AC1).
- `fn missing_target_always_create` and `fn directory_target_rules` (AC1).
- `fn time_rel_uses_coarser_precision` — Day vs Second on the same date → `Equal` (AC1).
- `fn rename_candidates_examples` — `report.pdf`, `.bashrc`, `archive.tar.gz`, `README`, `name.` (AC4).
- `fn validate_new_name_rejects` — empty, `.`, `..`, `a/b`, NUL, ESC, 256 bytes (AC4, AC7).
- `fn effective_action_precedence` — item > run rule (direction) > settings (AC2, AC3).
- `fn resolve_transfer_type_sftp_always_binary`.
- `fn local_target_sanitises_or_rejects` — `#[cfg(windows)]` and `#[cfg(unix)]` tables (AC7).

### Property / fuzz tests
- `proptest fn decide_never_resumes_beyond_source` — `ResumeAt(n)` only with `n < src.size` when the source size is known (AC1).
- `proptest fn rename_never_overwrites` — random sets of existing names, concurrent `create_new` by another task in `MemLocalFs` (AC4).

### Snapshot tests
Not applicable (prompt rendering is T69).

### Integration tests
`#[tokio::test(start_paused = true)]`, `MockBackend` + `MemLocalFs`, a scripted prompt
responder reading `CoreEvent::Prompt`:
- `async fn one_prompt_apply_to_all_across_slots` (AC2).
- `async fn apply_for_direction_scoped` and `async fn run_rules_cleared_after_run` (AC2, AC3).
- `async fn dismissed_prompt_pauses_item_only` (AC6).
- `async fn resume_5gib_sparse_at_4_5gib` — `MockBackend` pattern file (`byte = f(offset)`, no storage) and sparse `MemLocalFs` (AC5).
- `async fn resume_upload_uses_remote_size`.
- `async fn preallocate_then_cancel_truncates_to_checkpoint` (AC8).
- `async fn preserve_timestamps_by_precision` and `async fn set_mtime_unsupported_logged_once` (AC9).
- `async fn insufficient_space_stops_before_writing` (`available_space` fake).

### End-to-end tests
`crates/courier-ftp-e2e/tests/exists.rs` (`#[ignore]`, `require_docker!`, `Headless`):
- `fn resume_download_ftp_and_sftp` — truncate a downloaded file to half, re-queue with
  `Resume`; hash equal; server log shows `REST` (FTP) (AC5 on real servers, small file).
- `fn preserve_timestamps_proftpd_mfmt` — upload, `MLST` shows the local mtime (AC9).

## Out of scope

- The prompt dialog (T69) and the queue pane's per-item action menu (T56).
- Segmented resume (T41b, uses `completed` ranges).
- Session-wide (beyond the current queue run) "apply to all" — see Open questions.
- Hash comparison to decide "differs" (FileZilla doesn't).

## Open questions

1. FileZilla's dialog has "Apply to current queue only"; unchecked, the answer applies
   for the rest of the session. T04's `ApplyTo` has only run-scoped values, so this spec
   offers run scope only and T69's "apply only to current queue" checkbox has no effect.
   Should a session scope be added (T04 `ApplyTo::Session`, T69 checkbox), or the
   checkbox removed from T69?
2. Inconsistency for T03's owner: `WriteMode::Create` must be documented as exclusive
   (fail with `AlreadyExists` when the file exists) where the protocol allows it (local,
   SFTP); this task relies on it for "Rename never overwrites".
