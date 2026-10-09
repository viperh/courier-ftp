# T06 — Local filesystem backend

**Phase:** A Foundation · **Milestone:** M1 · **Depends on:** T03 · **Crate(s):** `courier-ftp-core` (`local` module) · **Decisions:** D5 · **FEATURES.md:** §3 (local pane, hidden files), §4, §6 (invalid characters, preallocate)
**Related (integrates with, not blocking):** T42, T76

## Goal

The local pane uses the same `Backend` trait as remote panes, so file lists, search,
filters, comparison, recursive operations and the transfer engine share one code path for
both sides. This task also provides the local-only helpers other tasks need: mapping
between `RemotePath`-style paths and native paths (including Windows drives and UNC
shares), file name sanitising for downloads, and free-space queries.

## Context

- Before: T03 defines `Backend`, `Listing`, `Capabilities`, `WriteMode`, `TransferOpts`,
  `TransferEnd`, the mock, and the conformance suite (`backend_conformance_tests!`). T02
  defines `RemotePath`, `LocalPath`, `Entry`, `Permissions`, `Timestamp`.
- After: T53 (file list) and T54 (tree) browse local directories through
  `SessionHandle`/`LocalBackend`; T41/T41b read and write local files through it; T42 uses
  `sanitize_local_name` and `available_space`; T43 walks local trees (loop detection with
  `canonicalize`); T63 opens local files directly; T76 reuses the conformance setup.

## Technical specification

### Types and APIs

Module `courier_ftp_core::local` (`local/{mod,backend,path_map,sanitize,space,owners}.rs`).

```rust
/// Backend over the local filesystem. Always "connected"; disconnect is a no-op.
#[derive(Debug)]
pub struct LocalBackend { /* ctx: BackendContext, owner/group name cache, open-transfer flag */ }
impl LocalBackend {
    pub fn new(ctx: BackendContext) -> Self;
    /// Native canonical path of `path` mapped back (symlinks resolved). T43 loop detection.
    pub async fn canonicalize(&self, path: &RemotePath) -> Result<RemotePath>;
}
impl Backend for LocalBackend;

/// The single mapping between the trait's '/'-paths and native paths.
pub mod path_map {
    /// Unix: identity ("/home/u" ↔ /home/u).
    /// Windows: "/" = virtual root (drive list); "/C:/Users/u" ↔ C:\Users\u;
    /// "/UNC/server/share/dir" ↔ \\server\share\dir.
    /// Errors: InvalidInput for "/" itself on Windows (not a real path) and for
    /// "/X" where X is not a drive ("C:") or "UNC" on Windows.
    pub fn to_native(path: &RemotePath) -> Result<LocalPath>;
    /// Inverse. Errors: InvalidInput for relative paths, verbatim prefixes other than
    /// \\?\C:\ and \\?\UNC\, and non-UTF-8 paths.
    pub fn from_native(path: &Path) -> Result<RemotePath>;
}

/// Make `name` valid as one file name on this OS (T42 "replace invalid characters").
/// Never returns "", ".", "..", or a name containing a separator.
pub fn sanitize_local_name(name: &str, replacement: char) -> String;
/// True if `name` needs no change on this OS (sanitize_local_name(name, _) == name).
pub fn is_valid_local_name(name: &str) -> bool;
/// Fuzz body `remote_name_sanitize` (T91 §7), also a property test: for any input the
/// result is non-empty, not "."/"..", has no separator, NUL or control character and (on
/// Windows) is not a reserved device name.
pub fn fuzz_sanitize_local_name(data: &[u8]);

/// Free bytes available to this user on the volume holding `path` (T42 preallocate
/// warning, T41 disk-full handling). Uses `fs4::available_space`.
pub async fn available_space(path: &LocalPath) -> Result<u64>;
```

### Behaviour

**Path mapping decision.** The `Backend` trait stays path-type-agnostic: it always takes
`RemotePath`. `LocalBackend` maps to native paths with `path_map` at its boundary; the UI
displays local paths through `LocalPath::to_display()` (native separators, `~`), and the
address bar parses native input with `from_native`. Rationale: one trait, one cache key
type, one walker; Windows names cannot contain '/', so the mapping is lossless; on Unix a
name containing '\' is just a character. Non-UTF-8 names cannot be represented (see Listing).

**connect / disconnect / is_connected:** no-ops; `is_connected()` always true; no events.

**home_dir:** `directories::BaseDirs::home_dir()` mapped with `from_native`; if unavailable,
the root `/`.

**list(dir, cancel):** whole listing in one `spawn_blocking` using `std::fs` (tokio's per-call
blocking would cost two thread hops per entry). The blocking loop checks
`cancel.is_cancelled()` every 256 entries and returns `Cancelled`; the async side also
returns `Cancelled` as soon as the token fires (the blocking task finishes on its own):
1. Windows virtual root `/`: probe drives `A:`–`Z:` concurrently (`Path::try_exists` on
   `X:\`, each in the blocking pool) with an overall limit of 1 s; drives that answer
   `true` in time are listed as `Dir` entries named `"C:"`; drives that time out are
   omitted and logged at `Debug(Info)`. UNC shares are not enumerated (typed in the address bar).
2. Otherwise `read_dir`. Per entry: `symlink_metadata`. If that fails with `NotFound`
   (removed meanwhile) the entry is skipped; with any other error the entry is listed with
   `kind = Other` and no metadata (directory readable but not searchable).
3. Symlinks: `read_link` gives `target` (lossy display string); `metadata` (following)
   gives `target_kind` `File`/`Dir`/`Other`, or `Broken` when it fails.
4. `size`: files and symlinks-to-files: length; directories: None.
5. `modified`: `Timestamp { precision: Millis }` from `modified()` when available.
6. `permissions`: Unix: `mode & 0o7777`. Windows: read-only attribute → mode `0o555` (dirs)
   / `0o444` (files), otherwise `0o777` / `0o666`, and `raw = "R"` or `""`.
7. `owner`/`group`: Unix uid/gid → names via the `uzers` crate, cached per `LocalBackend`
   (HashMap, unbounded but keyed by id); unknown ids → the number as text. Windows: None.
8. `hidden`: Unix (incl. macOS): name starts with '.'. Windows: `FILE_ATTRIBUTE_HIDDEN`
   (`MetadataExt::file_attributes() & 0x2`), via std, no `unsafe`.
9. Names that are not valid UTF-8 (Unix) or contain unpaired surrogates (Windows) are
   skipped; one Status line reports the count:
   `3 entries with names that are not valid UTF-8 are not shown`.
10. `Listing.raw = None`. Hygiene rules from T03 apply (no "."/"..").
11. `dir` itself missing → `NotFound(dir)`; not readable → `PermissionDenied`.

**stat:** `symlink_metadata` with the same mapping as `list` (target resolved for symlinks).
On Windows `stat("/C:")` returns a `Dir` entry named `"C:"`; `stat("/")` returns a `Dir`
entry named `"/"`.

**mkdir:** `create_dir` (not recursive) → `AlreadyExists` if present.
**rmdir:** `remove_dir`. **remove_file:** `remove_file` (removes a symlink, not its target;
on Windows a directory symlink is removed with `remove_dir`).

**rename(from, to, replace):** `replace = false` → `symlink_metadata(to)` exists →
`AlreadyExists(to)`, else `std::fs::rename`. `replace = true` → `std::fs::rename` (replaces
a file on all platforms; replacing a directory fails with the OS error mapped to `Io`).

**chmod:** Unix `set_permissions(mode & 0o7777)`; Windows → `Unsupported`.
**set_mtime:** `filetime::set_file_mtime` (works for directories on Windows too); the
access time is left unchanged.

**open_read(path, offset, opts):** open, seek to `offset` (offset > length → returns EOF
immediately), wrap in `take(range_len)` when set. Returns a `tokio::fs::File`-based stream.

**open_write(path, mode, opts):**

| Mode | Implementation |
|---|---|
| `Create` | `OpenOptions::create_new(true).write(true)` → `AlreadyExists` if present |
| `Truncate` | `create(true).truncate(true).write(true)` |
| `Append` | `create(true).append(true)` |
| `ResumeAt(n)` | open existing for write; length < n → `InvalidInput("resume offset beyond end of file")`; `set_len(n)`; seek n |
| `WriteAt(n)` | `create(true).write(true)` (no truncate); seek n (writing past EOF leaves a sparse hole) |

`preallocate_hint = Some(len)`: reserve space **without changing the file length**, so a
partial download never looks complete to resume logic: Linux uses
`rustix::fs::fallocate(fd, FallocateFlags::KEEP_SIZE, 0, len)`; on other platforms, and when
the filesystem does not support it (`EOPNOTSUPP`), it is skipped with one `Debug(Info)` line.
The stream is flushed and `sync_all` is called when the caller shuts it down.

**finish_transfer:** `Complete` → Ok (data already synced at shutdown); `Abort` → Ok (the
partial file stays for resume, FileZilla behaviour). Transfer-in-progress rules from T03.

**raw_command:** `Unsupported("custom commands are not available for local files")`.
**keepalive:** Ok. **security_info:** `{ encrypted: false, summary: "local", .. }`.

**Capabilities:**

| Capability | Unix | macOS | Windows |
|---|---|---|---|
| chmod | true | true | false |
| set_mtime, resume_download, resume_upload, append, symlinks, server_side_rename_across_dirs, parallel_connections_allowed, positional_writes | true | true | true |
| raw_commands, ascii_mode | false | false | false |
| case_insensitive_names | false | true (default APFS; per-volume detection is out of scope) | true |
| path_style | Unix | Unix | Unix (mapped) |

**sanitize_local_name(name, replacement)** (the replacement char is validated by T05 to be
safe on every OS):
1. Replace every character invalid or unsafe on the current OS with `replacement`:
   - all OSes: C0 control characters U+0000–U+001F and DEL U+007F (a name with an escape
     sequence must not reach a later `ls` in a terminal, T91);
   - Windows additionally: `< > : " / \ | ? *`;
   - Unix and macOS additionally: `/`.
2. Windows only: replace trailing `.` and space characters (one replacement per char),
   because Windows strips them silently; reserved device names `CON`, `PRN`, `AUX`, `NUL`,
   `COM1`–`COM9`, `LPT1`–`LPT9` and `COM¹ COM² COM³ LPT¹ LPT² LPT³` — compared
   case-insensitively on the part before the first '.' — get the replacement appended to
   that part (`con.txt` → `con_.txt`, `LPT1` → `LPT1_`).
3. All OSes: `""` → one replacement char; `"."` → one, `".."` → two replacement chars.
4. Names longer than 255 UTF-8 bytes are not shortened (the OS error surfaces in T42).

### Data formats and configuration

- Settings read: `transfers.invalid_char_replacement` (by callers of the sanitiser),
  `transfers.preallocate` (T41/T42 set `preallocate_hint` only when true). Hidden-file
  display (`interface.show_hidden_local`) is applied by the UI, not by `list`.
- New dependencies: `filetime`, `fs4` (free space), `rustix` (Linux `fallocate`, target-specific),
  `uzers` (Unix owner names, target-specific), `directories`.
- No `unsafe` in this module (the crate keeps `unsafe_code = "deny"`, T91).

### Errors

| Situation | Error |
|---|---|
| `std::io::ErrorKind::NotFound` | `NotFound(path)` |
| `PermissionDenied` | `PermissionDenied("<display path>")` |
| `AlreadyExists` | `AlreadyExists(path)` |
| chmod on Windows, raw_command | `Unsupported(..)` |
| `/` or a non-drive top-level name on Windows passed to a file operation | `InvalidInput(..)` |
| anything else (incl. `StorageFull`, `DirectoryNotEmpty`) | `Io(err)` (T41 detects `StorageFull` and pauses the queue) |

The UI shows the Display text; for `Io` it is the OS message.

### Security and logging

- Names coming from servers reach the local filesystem only through `RemotePath::join` /
  `LocalPath::join` (reject `..`, separators, NUL, drive prefixes) and `sanitize_local_name`
  — a hostile listing cannot write outside the target directory (T91 mitigation row
  "path traversal on download").
- Symlinks are never followed for deletion (`remove_file` removes the link).
- No session log output except the skipped-names Status line and debug lines; no `tracing`
  at info+ with paths (T91 §4).

## Implementation steps

1. `path_map` (`to_native`/`from_native`) with Unix and Windows (`#[cfg(windows)]`) tests.
2. `sanitize_local_name` / `is_valid_local_name` with per-OS tables.
3. `LocalBackend` metadata mapping, `list`, `stat`, owner cache; Windows drive root.
4. Mutating operations, `open_read`/`open_write` per mode, preallocation, `finish_transfer`.
5. `available_space`, `canonicalize`.
6. Run `backend_conformance_tests!` for `LocalBackend` in a `tempfile::TempDir`; Windows/macOS
   in the `test-os` CI job.

## Acceptance criteria

- [ ] AC1 `LocalBackend` passes every conformance case from T03 (including
  `large_offset_resume_beyond_4gib` with sparse files) on Linux, macOS and Windows in CI.
- [ ] AC2 Symlinks: a link to a dir lists as `Symlink { target_kind: Dir }` and can be
  listed through; a dangling link lists with `Broken`; `remove_file` on a link keeps the
  target (Unix and Windows-with-developer-mode tests; skipped with a message when the OS
  refuses to create symlinks).
- [ ] AC3 Hidden files: dotfiles hidden on Unix/macOS; `FILE_ATTRIBUTE_HIDDEN` on Windows.
- [ ] AC4 A directory without read permission → `PermissionDenied`; an entry whose
  metadata cannot be read is listed as `Other` (Unix test, skipped when running as root).
- [ ] AC5 Windows: listing `/` returns existing drives within 1 s; `/C:/Windows` lists;
  `\\?\` and UNC paths map both ways.
- [ ] AC6 `sanitize_local_name` covers every Windows reserved name case-insensitively, with
  and without extension, trailing dots/spaces, all invalid characters and control
  characters; `.`/`..`/empty are never returned; the `remote_name_sanitize` fuzz target
  exists (T91 §7).
- [ ] AC7 Non-UTF-8 names (Unix) are skipped with one Status line giving the count.
- [ ] AC8 `ResumeAt(n)` produces byte-identical files; preallocation never changes the file
  length (Linux test checks `metadata.len()` after `open_write` with a hint).
- [ ] AC9 T00 CI gates pass, including `test-os` on Windows and macOS.

## Tests

### Unit tests
- `path_map_unix_identity` — `/a b/c` ↔ `/a b/c`. (AC1)
- `#[cfg(windows)] path_map_windows_drives_and_unc` — `/C:/Users/u` ↔ `C:\Users\u`; `/UNC/srv/share/d` ↔ `\\srv\share\d`; `\\?\C:\x` → `/C:/x`; `/foo` → InvalidInput. (AC5)
- `sanitize_unix_table` — `"a/b"`→`"a_b"`, `"a\0b"`→`"a_b"`, `"con.txt"` unchanged, `".."`→`"__"`, `""`→`"_"`. (AC6)
- `#[cfg(windows)] sanitize_windows_table` — every char of `<>:"/\|?*`, `"\x01"`, `"name. "`→`"name__"`, `"CON"`→`"CON_"`, `"con.tar.gz"`→`"con_.tar.gz"`, `"Com1"`→`"Com1_"`, `"LPT¹"`→`"LPT¹_"`, `"CONSOLE"` unchanged. (AC6)
- `capabilities_per_os`. (AC1)
- `sanitize_replaces_control_chars_everywhere` — `"a\x1b[31mb"` → `"a_[31mb"`, `"\x7f"` → `"_"`. (AC6)

### Property / fuzz tests
- `prop_sanitized_name_is_valid` — random strings → `is_valid_local_name(sanitize(..))`, never `""`/`"."`/`".."`, no control chars (10 000 cases; body = `fuzz_sanitize_local_name`). (AC6)
- `prop_sanitized_name_stays_inside_target` (T91 AC9) — arbitrary names; `target.join(sanitize_local_name(n))` normalised starts with `target` and has exactly one more component. (AC6)

### Snapshot tests
Not applicable.

### Integration tests
(tempdir-based, `#[tokio::test]`)
- `backend_conformance_tests!(local_env)` — all T03 cases with `large_files: true`. (AC1)
- `symlink_to_dir_and_dangling_link` / `remove_symlink_keeps_target`. (AC2)
- `dotfiles_are_hidden` (Unix) / `hidden_attribute_is_hidden` (Windows, sets the attribute with `attrib +h`). (AC3)
- `unreadable_dir_is_permission_denied` (Unix, skip as root). (AC4)
- `unsearchable_dir_lists_entries_as_other` (Unix, mode 0o444 on the dir, skip as root). (AC4)
- `#[cfg(windows)] virtual_root_lists_system_drive` — contains `C:` (or `%SystemDrive%`) within 1 s. (AC5)
- `#[cfg(unix)] non_utf8_names_are_skipped_and_reported` — creates `b"bad\xff"` via `OsStr::from_bytes`; listing has the others and one Status line "1 entries…". (AC7)
- `resume_at_offset_is_byte_identical`, `write_at_preserves_existing_bytes`, `resume_offset_beyond_eof_is_invalid_input`. (AC8)
- `#[cfg(target_os = "linux")] preallocate_keeps_length` — hint 10 MiB → `len() == 0` after open, allocated blocks ≥ 10 MiB when the fs supports it. (AC8)
- `available_space_is_positive`. (AC1)
- `canonicalize_resolves_symlink_loop_entry` — `a/loop -> ..` canonicalises to the parent. (AC2)
- Benchmark (ignored): `list_10k_entries` — 10 000 files listed in < 300 ms (release build), result recorded in this file.

### End-to-end tests
Not applicable (T76 PtyApp flows browse the local pane).

## Out of scope

- Watching directories for external changes (FileZilla does not refresh automatically either).
- Per-volume case-sensitivity detection, Windows alternate data streams, ACL editing.
- Enumerating network shares.

## Open questions

- Non-UTF-8 local file names are hidden (with a count in the log) because every layer uses
  `String` names. Supporting them would need a byte-string name type throughout. Is hiding
  acceptable for v1?
