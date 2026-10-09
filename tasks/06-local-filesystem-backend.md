# T06 — Local filesystem backend

**Phase:** A Foundation · **Depends on:** T03 · **Crate:** `courier-ftp-core` (`local` module) · **FEATURES.md:** §3 local pane, §4

## Goal

The local pane uses the same `Backend` trait as remote panes, so file lists,
search, filters, comparison and recursive operations share one code path.

## Scope

1. `LocalBackend` implementing `Backend` over `tokio::fs`.
   - `list`: `read_dir` + `symlink_metadata` per entry; for symlinks also `metadata` to resolve target kind; `hidden` = dotfile on Unix, `FILE_ATTRIBUTE_HIDDEN` on Windows.
   - `Permissions`: Unix mode on Unix; on Windows map read-only attribute to a synthetic mode and set `raw` to `"R"`/`""`.
   - Owner/group on Unix via `uid`/`gid` → names (cache lookups; use `libc::getpwuid_r`/`getgrgid_r` or the `uzers` crate).
   - `chmod`: Unix only (`Capabilities.chmod = false` on Windows).
   - `set_mtime`: `filetime` crate or `File::set_modified`.
   - `open_read(offset)`: `File::open` + `seek`. `open_write(ResumeAt)`: open + seek; `Append`; `Truncate`.
   - `raw_command`: unsupported.
2. **Path mapping**: the local backend still speaks `RemotePath`-style (`/`-separated) internally? **No** — use `LocalPath` and provide an adapter: decide in implementation whether the trait takes an associated `Path` type or the local backend maps `RemotePath` ↔ `LocalPath`. Requirement: Windows drive letters (`C:\`) and UNC paths must work, and the UI must show native separators. Document the chosen approach in the module docs.
3. **Windows drive list**: listing the virtual root on Windows returns available drives (`A:`–`Z:` that exist) as `Dir` entries, like FileZilla's local tree.
4. **Invalid filename handling** helper `sanitize_local_name(name, replacement) -> String`: replaces characters invalid on the current OS (`\ / : * ? " < > |` + control chars on Windows, `/` and NUL on Unix), and reserved Windows names (`CON`, `NUL`, `COM1` …). Used by T42.
5. Free-space query `available_space(path)` (for preallocate warnings, T42) via `fs2`/`sysinfo` or platform calls.

## Acceptance criteria

- [ ] `LocalBackend` passes the same generic backend test suite as `MockBackend` (write that suite here as a reusable `backend_conformance_tests!` macro or generic async fn — later reused by FTP/SFTP integration tests in T76).
- [ ] Symlinks, hidden files, unreadable dirs (permission denied → entry still listed or clear error) handled.
- [ ] Windows drive root works (CI windows job).
- [ ] `sanitize_local_name` covers all Windows reserved names case-insensitively.

## Tests

- Conformance suite in a `tempfile::TempDir`.
- Resume write at offset produces correct bytes.
- Sanitizer table tests per OS (`#[cfg(windows)]` / `#[cfg(unix)]`).
