# T14 — FTP operations and Backend impl

**Phase:** B FTP · **Depends on:** T03, T06, T10, T11, T12, T13, T76 · **Crate:** `courier-ftp-proto-ftp` · **FEATURES.md:** §4
**Related (integrates with, not blocking):** T31, T41

## Goal

Implement `Backend` for FTP/FTPS on top of the control and data connection code.

## Scope

| Backend method | FTP commands | Notes |
|---|---|---|
| `connect` | T10 sequence | Applies site's default remote dir with `CWD` after login if set. |
| `home_dir` | `PWD` | cached after connect |
| `list(dir)` | `CWD dir` + `MLSD`/`LIST` | Some servers fail `MLSD path`; always `CWD` first then list with no argument (FileZilla does this). Track `cwd` to skip redundant `CWD`. |
| `stat(path)` | `MLST path` → else `SIZE` + `MDTM` → else list parent and find | |
| `mkdir` | `MKD` | `257` or `250`; "already exists" `550` → `AlreadyExists` when a subsequent `CWD` succeeds. |
| `rmdir` | `RMD` | |
| `remove_file` | `DELE` | |
| `rename` | `RNFR` → `350` → `RNTO` | |
| `chmod` | `SITE CHMOD 755 path` | Capability only if server didn't reject it with `500/502` before (learn per session). |
| `set_mtime` | `MFMT YYYYMMDDHHMMSS path` → fallback `MDTM YYYYMMDDHHMMSS path` (some servers) → `SITE UTIME` | Used by `preserve_timestamps`. |
| `open_read(off)` | `TYPE`, `REST off` (if >0), `RETR` | T11 |
| `open_write(mode)` | `STOR` / `APPE` / `REST off`+`STOR` | |
| `finish_transfer` | read `226` | |
| `raw_command` | verbatim | T10 |
| `keepalive` | T10 | |

Additional:
0. **Wiring**: add the FTP/FTPS arm to the binary's `BackendFactory` (created in T58).
1. **Path translation**: for VMS/MVS servers (detected via SYST + listing format), translate `RemotePath` to server syntax when sending `CWD`. Minimum: Unix and Windows-style servers fully; VMS basic (`CWD [.DIR]`); MVS best-effort with a logged warning.
2. **Error mapping**: `550` with "No such file"/"not found" → `NotFound`; "Permission denied" → `PermissionDenied`; 4xx → transient protocol error; 5xx → permanent.
3. **Capabilities** computed from FEAT: `resume_*` = REST STREAM, `set_mtime` = MFMT or MDTM-set, `chmod` = assume true until rejected, `ascii_mode` = true.
4. **Parallel connections**: `parallel_connections_allowed` true; the engine opens extra sessions with the same credentials (T41). Respect site's connection limit (T31).
5. **Server type override** (site Advanced tab, T31): force `Unix`, `Dos`, `Vms`, `Mvs`, … to override auto-detection.

## Acceptance criteria

- [ ] `FtpBackend` passes the backend conformance suite (T06) against vsftpd, proftpd and pure-ftpd in Docker (T76), for plain FTP and explicit FTPS.
- [ ] Error mapping verified for missing file, permission denied, existing dir.
- [ ] `SITE CHMOD` rejection disables the capability for the session (UI greys it out).
- [ ] `MLSD` and `LIST` paths both exercised (toggle `use_mlsd`).

## Tests

- Fake server scripts for each method (fast, run in unit tests).
- Integration via T76.
