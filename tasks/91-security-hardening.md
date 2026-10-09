# T91 — Security hardening and threat model (sverb parity)

**Phase:** H Sync & security (start early; checks apply to every crate) · **Depends on:** T01, T30 · **Crates:** all, CI · **Decisions:** D3, D13
**Reference:** sverb `docs/threat-model.md`, `SPEC.md` §17–§19, `crates/sverb-core/src/{secret.rs,hardening/,logging/}`, `scripts/check-unsafe.py`, `scripts/canary-scan.sh`, `fuzz/`, CI jobs `deny`, `vet`, `unsafe-check`, `canary`, `fuzz.yml`.

## Goal

Give courier-ftp the same security measures and proofs as sverb: process
hardening, secret handling, logging rules, supply-chain checks, fuzzing, and a
threat model that maps every threat to a mitigation and the tests that prove it.

## Scope

### 1. Process hardening
- `harden_process()` is the first thing `main` does after installing the panic hook,
  before any secret exists: Linux `prctl(PR_SET_DUMPABLE, 0)` + `RLIMIT_CORE = 0`
  (blocks same-user `ptrace` and `/proc/<pid>/mem`, no core dumps); macOS `RLIMIT_CORE = 0`;
  Windows `SetErrorMode` + `WerSetFlags(NOHEAP)`. Report logged at debug.
- `Locked<T>`: key material (LMK, VKs, item keys while in use) on `mlock`/`VirtualLock`ed
  pages with per-page reference counts; zeroize before unlock; when `RLIMIT_MEMLOCK` is
  too low, keep working and log one debug line.
- Test: the running binary is not dumpable and has core limit 0 (Linux).

### 2. `unsafe` policy
- Workspace lint `unsafe_code = "deny"` inherited by every crate.
- Only `courier-ftp-core/src/hardening/{unix,windows}.rs` may `#![allow(unsafe_code)]`,
  each block with a `SAFETY:` comment.
- `scripts/check-unsafe.py` (CI job `unsafe-check`) fails if the lint is lifted anywhere
  else, a crate overrides it, or the workspace level is weakened; plus a test proving
  every crate inherits it.

### 3. Secret handling
- `Secret<T>` / `SecretString` / `Key32` / `Zeroizing` for every secret (passwords, key
  passphrases, recovery words, tokens, TOTP codes, keys). `Debug`/`Display` print
  `[REDACTED]`; no `Clone`/`Serialize` on secret wrappers; `expose()` only at the point
  of use.
- Request DTOs carrying secrets (`courier-ftp-proto`: register/login/TOTP/password
  change) implement `Debug` by hand with redaction.
- clippy `unwrap_used` and `expect_used` denied in non-test code (documented exceptions only).
- One-time audit (checklist kept in `docs/threat-model.md`): every `expose()` call site is
  outside `tracing`/`format!`/`panic!`; no `Debug` derive on types with plain secret fields.

### 4. Logging policy (extends T71)
- Application log to file only (stdout belongs to the TUI); daily rotation, 7 days kept;
  level from `COURIER_FTP_LOG_LEVEL` (default `info`).
- **No hostnames, usernames, paths or commands at `info` and above** in client crates —
  only ids (UUIDs). `debug` may contain hostnames; `--debug` prints a warning saying so.
  (The session/message log of T55/T71 is a user-facing feature and is separate; when
  written to a file it is the user's explicit choice and the setting says what it contains.)
- Panic hook restores the terminal first, then writes a crash report to the state dir
  built from the recent `info`+ log ring buffer (no secrets by construction).
- Server: structured JSON logs; tokens never logged; emails only hashed at info.

### 5. Canary secrets
- Tests plant canary values (e.g. `CANARY-PW-7f3a…`) as site passwords, key passphrases,
  recovery words, TOTP secrets, sync tokens.
- `scripts/canary-scan.sh` (with `--self-test`) scans everything a full
  `COURIER_FTP_LOG_LEVEL=trace` test run leaves behind: logs, crash reports, `*.db`,
  `-wal`, `-shm`, backups, edit temp dirs, server DB dump. Any canary found → CI fails.
  Also checks that hostnames from fixtures don't appear in `info`+ lines.
- CI job `canary`.

### 6. Supply chain
- `cargo-deny` (licenses, advisories, bans, sources) — CI job `deny`, config `deny.toml`.
- `cargo-vet` with crypto crates tracked; unaudited crypto deps flagged as a CI warning.
- `Cargo.lock` committed, `--locked` everywhere (already the case).
- Reproducible release builds (`SOURCE_DATE_EPOCH`, `--remap-path-prefix`), SHA256SUMS
  in releases (T77).

### 7. Fuzzing
- `fuzz/` (cargo-fuzz, own workspace). Each target's body is also a property test in its
  crate so `cargo test` covers it without nightly.
- Targets: FTP reply parser (T10), PASV/EPSV parser (T11), LIST/MLSD listing parsers (T13),
  FileZilla `sitemanager.xml` import (T32), known_hosts parser (T21), PPK parser (T20),
  HTTP CONNECT response and SOCKS replies (T07), item envelope open, account bundle open,
  grant open (T80), backup decrypt (T30/T73), sync DTO JSON decode (T83).
- PR CI runs each target 30 s; nightly `fuzz.yml` 10 minutes with cached corpus and
  uploaded crashes.

### 8. Synced values that act locally (sverb §17.1)
Fields that would make this device do something locally, and that a teammate or a
compromised account could plant in a shared vault:
- `key_file` pointing at a **local path** (would use a local private key for a host
  defined by someone else),
- logon type `Agent` / `try_agent_first` (offers the local SSH agent's keys to that host),
- any future per-site command (e.g. "run after transfer") or local directory that
  courier-ftp writes to automatically.

Rule: the first time this device is about to act on such a field, and whenever its value
changes, show the exact value and ask; store `(item_id, field, sha256(value))` in the
device-local `local_approvals` table (T82). Values typed on this device are pre-approved.
Denials last for the running process. Headless/CLI starts (`--site`) fail with a message
pointing to the approval screen.

### 9. Threat model document
`docs/threat-model.md` in sverb's structure:
- **Assets**: master password/KEK, LMK and vault keys, items (sites with passwords, SSH
  keys, passphrases), decrypted index, account keys and sync tokens, trusted host keys and
  certs, transfer queue, edit temp files, transferred data in flight.
- **Actors**: malicious/compromised sync server operator; network attacker (to the sync
  server, FTP/SFTP servers, proxies); **malicious FTP/SFTP server** (hostile listings,
  replies, filenames with `../`, control characters, huge sizes); malicious teammate;
  local attacker without / with an unlocked session.
- **Mitigations table** mapping each threat → mitigation → task → tests, including
  FTP-specific rows: path traversal in remote names (`..`, `/`, NUL, drive letters) when
  downloading (sanitize + reject, T06/T42), terminal escape sequences in filenames and
  server messages (strip control chars before rendering, T53/T55), plain FTP warnings
  (T12/T57), PASV bounce (T11), certificate and host-key changes (T12/T21).
- `unsafe` policy, hardening details, fuzzing table, review checklist, **residual risks**
  (revoked members keep old data; server-asserted membership; TOFU first sight; debug logs
  contain hostnames; mlock best effort; same-user attacker with an unlocked session on
  macOS/Windows; plain FTP is inherently insecure).
- `SECURITY.md` with a reporting address.

### 10. Teams trust rules (verify in T89)
TOFU pins device-local and never synced; key-change warning blocks grants to and from
that user until accepted after comparing safety numbers; grants used only with a valid
signature by a **pinned** key of a granter who has `manage`; personal vault keys accepted
only as self-grants signed by this account's own key.

## Acceptance criteria

- [ ] Hardening applied at startup; Linux test proves non-dumpable + core limit 0.
- [ ] `unsafe-check`, `deny`, `vet`, `canary` and fuzz CI jobs exist and pass.
- [ ] Canary scan finds nothing after a full trace-level test run (and its self-test proves it can find planted canaries).
- [ ] No hostnames at `info`+ in client logs (test).
- [ ] Approval prompts appear for synced local-acting fields and are re-asked on change.
- [ ] Hostile filenames (`../x`, `a/b`, names with ESC sequences) can't escape the target dir or affect the terminal.
- [ ] `docs/threat-model.md` complete with a test reference for every mitigation.

## Tests

- As listed per section; port sverb's hardening, secret and canary tests.
