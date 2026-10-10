# T91 — Security hardening and threat model (sverb parity)

**Phase:** H Sync & security (start early; checks apply to every crate) · **Depends on:** T00, T01, T30 · **Crates:** all, CI · **Decisions:** D3, D13
**Related (integrates with, not blocking):** T06, T07, T10, T11, T12, T13, T20, T21, T32, T42, T53, T55, T71, T80, T82, T83, T89
**Reference:** sverb `docs/threat-model.md`, `SPEC.md` §17–§19, `crates/sverb-core/src/{secret.rs,hardening/,logging/}`, `scripts/check-unsafe.py`, `scripts/canary-scan.sh`, `fuzz/`, CI jobs `deny`, `vet`, `unsafe-check`, `canary`, `fuzz.yml`.

## Goal

Give courier-ftp the same security measures and proofs as sverb: process
hardening, secret handling, logging rules, supply-chain checks, fuzzing, and a
threat model that maps every threat to a mitigation and the tests that prove it.

## Scope

Delivered in stages: hardening, secret types, `unsafe` policy, canary scanner and `deny`/`vet` right after T30 (milestone M2); each parser task adds its own fuzz target when it lands (T07, T10, T11, T13, T20, T21, T32, T80, T83); the threat model document is completed at the end.


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

- [x] Hardening applied at startup; Linux test proves non-dumpable + core limit 0.
- [ ] `unsafe-check`, `deny`, `vet`, `canary` and fuzz CI jobs exist and pass.
- [x] Canary scan finds nothing after a full trace-level test run (and its self-test proves it can find planted canaries).
- [x] No hostnames at `info`+ in client logs (test).
- [ ] Approval prompts appear for synced local-acting fields and are re-asked on change.
- [ ] Hostile filenames (`../x`, `a/b`, names with ESC sequences) can't escape the target dir or affect the terminal.
- [ ] `docs/threat-model.md` complete with a test reference for every mitigation.

## Tests

- As listed per section; port sverb's hardening, secret and canary tests.

## Status after the M2 pass

Done (code that exists after T30):

- §1 `courier-ftp-core::hardening` (copied from sverb): `harden_process()` called in
  `main` right after the panic hook; `Locked<T>` holds the vault engine's LMK and vault
  keys. Tests: `courier-ftp-core/tests/hardening.rs` (prctl + `RLIMIT_CORE` in-process,
  mlock fallback), `courier-ftp/tests/hardening.rs` (the real binary logs
  `non_dumpable=true core_dumps_disabled=true`; Linux, started without a terminal).
- §2 `scripts/check-unsafe.py` now also requires a `// SAFETY:` comment on every `unsafe`
  block in the hardening module (tested in `courier-ftp-e2e/tests/forbid_unsafe.rs`).
- §4 partial: `known_hosts` file paths moved from `warn`/`info` to `debug`.
- §5 canary fixtures that always leave artifacts in `target/tmp`: vault DB/WAL/SHM, a
  `.cftp-backup` and a trace log (`courier-ftp-store/tests/canary_artifacts.rs`, which
  also runs the scanner on Linux) and a trace-level SSH login log with russh's own output
  (`courier-ftp-proto-sftp` `ssh::tests::canary_secrets_stay_out_of_trace_logs`). The
  scanner knows `*.cftp-backup`; CI `canary` uses `--require-files`.
- §6 `supply-chain/` generated with cargo-vet 0.10.2 (`cargo vet init`, imports from
  Mozilla, Google, Bytecode Alliance, ISRG, Zcash, Zcash Foundation, then `cargo vet
  prune`): `cargo vet --locked` passes locally (105 fully audited, 4 partially, 660
  exempted); the crypto crates are exempted, so `check-vet-crypto.py` warns. CI job `vet`.
- §7 nine new fuzz targets (`proxy_reply`, `known_hosts_parse`, `key_parse`,
  `envelope_open`, `bundle_open`, `grant_open`, `kdf_params`, `item_body`,
  `backup_decrypt`) next to `listing`, each body a property test in its crate; seed corpus
  extended; CI job `fuzz` (30 s per target) next to the nightly `fuzz.yml`.
- `local::sanitize_name` never returns `.` or `..` (property test: a sanitized name is
  always one component under the target directory).
- §9 `docs/threat-model.md` (M2 version) and `SECURITY.md`.

Deferred to later milestones:

- FTP reply / PASV-EPSV parsers and their fuzz targets (T10, T11), FTPS certificate rules
  and plain-FTP warnings (T12, T57), `sitemanager.xml` fuzzing (T32), sync DTO fuzzing and
  server logging/dumps (T83–T86), teams trust rules (§10, T89).
- §3 proto DTO redaction (T83/T84, `courier-ftp-proto` has no DTOs yet).
- §4 logging rework: daily rotation, `--debug` warning and the `info`+ audit are done
  (T71; test `courier-ftp` `app::log_tests::info_and_above_never_name_hosts_users_or_paths`).
  Still open: the crash report built from an `info`+ ring buffer.
- §8 approval prompts (the `local_approvals` table exists; the UI comes later).
- Hostile filenames: the download path join is T42 and a rendering test with escape
  sequences belongs to T53/T55 (ratatui already drops graphemes with control characters).
- §6 reproducible release flags and SHA256SUMS are T77; auditing the crypto crates so
  `VET_CRYPTO_STRICT=1` can be turned on.
- The CI jobs `vet`, `fuzz` and `canary --require-files` were not run on GitHub yet; their
  commands were run locally except `cargo +nightly fuzz` (no nightly here; the targets
  were checked on stable with `cargo check --bins` in `fuzz/`).
