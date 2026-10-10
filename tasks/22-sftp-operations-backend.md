# T22 — SFTP operations and Backend impl

**Phase:** C SFTP · **Depends on:** T03, T06, T13, T20, T21, T76 · **Crate:** `courier-ftp-proto-sftp` · **FEATURES.md:** §4
**Related (integrates with, not blocking):** T41, T41b

## Goal

Implement `Backend` for SFTP using `russh-sftp` over the session from T20.

## Scope

| Backend method | SFTP | Notes |
|---|---|---|
| `connect` | T20 + open `session` channel + `request_subsystem("sftp")` + `SftpSession::new` | Log SFTP protocol version. |
| `home_dir` | `canonicalize(".")` | |
| `list` | `read_dir` | Use `longname` (ls -l line) to fill `owner`/`group` names when attrs only have uid/gid; parse with the Unix `ls -l` parser in `courier-ftp-core::listing::unix` (T13). Resolve symlink targets with `read_link` + `metadata` lazily (only for symlinks, batched, bounded concurrency). |
| `stat` | `metadata` (follows links) / `symlink_metadata` | |
| `mkdir` / `rmdir` / `remove_file` | `create_dir` / `remove_dir` / `remove_file` | |
| `rename` | `rename`; if it fails because target exists and user chose overwrite, `remove_file` then `rename` (or `posix-rename@openssh.com` extension if advertised) | |
| `chmod` | `set_metadata` with permissions only | |
| `set_mtime` | `set_metadata` with atime+mtime | |
| `open_read(off)` | `open` + seek | Pipelined reads, see T41b §3. |
| `open_write(mode)` | `open_with_flags` (`CREATE|TRUNCATE`, `APPEND`, or `WRITE` + seek for resume) | Same pipelining for writes. |
| `raw_command` | **Unsupported** for SFTP (FileZilla allows some; we expose `exec` over a separate channel only if user enables it — out of scope v1) | Capability false. |
| `keepalive` | SSH-level keepalive is automatic; method is a no-op or `canonicalize(".")` | |

Additional:
1. **Charset**: SFTP v3 filenames are bytes; decode as UTF-8, fall back to site charset if set to custom.
2. **Error mapping**: `NoSuchFile` → `NotFound`, `PermissionDenied`, `Failure` with context message, `ConnectionLost` → `Connection`.
3. **Throughput target**: ≥ 80 % of OpenSSH `sftp` CLI throughput on a localhost 1 GiB transfer. Measure and record in the task when done.
4. Multiple sessions: engine (T41) may open extra SSH connections, or multiple SFTP channels on one SSH connection — prefer **one SSH connection per transfer slot** (simpler, matches FileZilla), revisit later.

## Acceptance criteria

- [ ] Passes backend conformance suite against OpenSSH in Docker.
  (`crates/courier-ftp-e2e/tests/sftp_backend.rs`, `atmoz/sftp`; awaiting the
  CI e2e job. Already passes in-process and against a local OpenSSH 10.5p1
  `sshd` via `scripts/bench-sftp.sh`.)
- [x] Symlink to dir shows as symlink with `target_kind = Dir` and can be entered.
- [x] Resume download/upload byte-identical.
- [x] Throughput target met (numbers written here).

### Throughput (2026-10-10)

`scripts/bench-sftp.sh 1024`: 1 GiB over localhost to an unprivileged
OpenSSH 10.5p1 `sshd` (`sftp-server`, `limits@openssh.com` → 255 KiB
requests, 64 in flight), AMD Ryzen 5 8645HS, release build. The courier side
streams from/to memory; the CLI side reads/writes a local file.

| | courier-ftp | OpenSSH `sftp` CLI | ratio |
|---|---|---|---|
| upload | 671–690 MiB/s | 575 MiB/s | 117–120 % |
| download | 552–609 MiB/s | 610–632 MiB/s | 90–96 % |

## Tests

- Integration (T76) with `linuxserver/openssh-server` or `atmoz/sftp`.
- Benchmark script `scripts/bench-sftp.sh` (manual, not CI).
