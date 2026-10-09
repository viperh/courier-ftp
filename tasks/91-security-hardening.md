# T91 — Security hardening and threat model (sverb parity)

**Phase:** H Sync & security (start early; checks apply to every crate) · **Milestone:** M2 (grows through M3–M9) · **Depends on:** T00, T01, T30 · **Crate(s):** all; `courier-ftp-core` (`hardening`, `vault::approvals`), `courier-ftp` (startup, approval dialog, canary/hardening tests), `fuzz/`, `docs/threat-model.md`, `SECURITY.md` · **Decisions:** D3, D8, D9, D13, D14 · **FEATURES.md:** §2 (password storage, master password), §9 (logging)
**Related (integrates with, not blocking):** T06, T07, T10, T11, T12, T13, T20, T21, T32, T42, T53, T55, T71, T80, T82, T83, T89
**Reference:** sverb `docs/threat-model.md`, `SPEC.md` §17–§19 (§17.1 synced items that act locally), `crates/sverb-core/src/{secret.rs,hardening/{mod,unix,windows}.rs}`, `crates/sverb-core/tests/hardening.rs`, `crates/sverb/tests/{hardening,canary}.rs`, `crates/sverb-store/src/approvals.rs`, `scripts/{check-unsafe.py,canary-scan.sh,check-vet-crypto.py}`, `fuzz/`, `CONTRIBUTING.md` ("Canary secrets", "`unsafe`", "Fuzzing"), CI jobs `deny`, `vet`, `unsafe-check`, `canary`, `fuzz`, `fuzz.yml`.

## Goal

courier-ftp gets the same security measures and the same proofs as sverb: the process is
hardened before any secret exists, secrets cannot be printed or logged by accident, logs
follow a strict content policy, the supply chain is checked, every parser of untrusted
input is fuzzed, synced values that would make this device act locally need a local
approval, and `docs/threat-model.md` maps every threat to a mitigation, the task that
implemented it and the tests that prove it.

## Context

**Before this task:**
- T00: CI jobs `deny`, `vet` (+ `check-vet-crypto.py`), `unsafe-check`
  (`check-unsafe.py`, allowed path `crates/courier-ftp-core/src/hardening/`), `canary`
  (`canary-scan.sh`), `fuzz` / `fuzz.yml` (skipped while `fuzz/fuzz_targets/` is empty),
  `packaging` (no `test-hooks`/`test-util`/`insecure-test-ksf` in shipped graphs).
- T01: crates, `COURIER_FTP_HOME`, features `test-hooks`, `test-util`.
- T02: `courier_ftp_core::secret::{Secret, SecretString, SecretBytes, REDACTED}`.
- T30: `VaultEngine`, unlock with master password / optional keyring, `Argon2Cost::TEST`,
  backup files `.cftp-backup`. T80: `Key32`, envelopes, `insecure-test-ksf`.
- T76: `courier-ftp-e2e` (`TestHome::kept`, `HostileFtpd`, `PtyApp`, test hooks).

**Delivered in stages** (the task is done when every stage's ACs are ticked):

| Stage | Milestone | Content |
|---|---|---|
| S1 | M2 (with T30) | §1 hardening, §2 `unsafe` (already enforced by T00), §3 secret audit, §4 logging rules on the current logger, §5 canary fixture, §6 supply chain on, first fuzz targets (T80, T20, T21, T13) |
| S2 | M3 | FTP fuzz targets (T10, T11, T12, T07); hostile-server rules (§9 rows) with T76 `hostile.rs` |
| S3 | M5 | §8 approvals for synced local-acting fields (needs T31 sites); `filezilla_xml_import` target (T32) |
| S4 | M7–M8 | sync/team rows: DTO fuzzing (T83), server canaries (T84), §10 trust rules verified in T89 |
| S5 | M9 | `docs/threat-model.md` complete, `SECURITY.md`, review checklist signed off; T71 crash reports scanned |

**Later tasks need from it:** `harden_process`, `Locked<T>` (T30 keys), the logging rules
(T71 implements rotation and crash reports under these rules), the approval API (T20, T70,
T88, T68 revoke list), the fuzz-target convention (each parser task adds its target).

## Technical specification

### Types and APIs

**`courier_ftp_core::hardening`** (ported from sverb; `mod.rs` is safe code,
`unix.rs` / `windows.rs` carry `#![allow(unsafe_code)]` and a `SAFETY:` comment on every
block — the only `unsafe` in the workspace):

```rust
/// What `harden_process` managed to do. Contains nothing secret.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HardeningReport {
    /// RLIMIT_CORE is 0 (unix) / heap excluded from WER dumps (Windows).
    pub core_dumps_disabled: bool,
    /// Linux only: PR_SET_DUMPABLE is 0 (blocks same-user ptrace and /proc/<pid>/mem).
    pub non_dumpable: bool,
    /// Steps that failed or are unsupported, for the debug log.
    pub failures: Vec<String>,
}
/// Disable core dumps and (Linux) same-user ptrace. First thing in `main`. Never fails.
pub fn harden_process() -> HardeningReport;
/// Linux: PR_GET_DUMPABLE (`Some(false)` after hardening); `None` elsewhere.
pub fn is_dumpable() -> Option<bool>;
/// Unix: soft RLIMIT_CORE in bytes (`Some(0)` after hardening); `None` elsewhere.
pub fn core_dump_limit() -> Option<u64>;
/// Unix: set the soft RLIMIT_MEMLOCK (tests exercise the fallback). `Unsupported` elsewhere.
pub fn set_memlock_limit(soft_bytes: u64) -> std::io::Result<()>;
/// Pages currently locked by `Locked` values (tests).
pub fn locked_page_count() -> usize;

/// A value on mlock'ed / VirtualLock'ed pages (best effort), zeroized before the pages
/// are unlocked. Pages are reference-counted so freeing one value never unlocks a page
/// another value shares. Used for the LMK, vault keys and item keys while in use (T30).
pub struct Locked<T: Zeroize> { … }
impl<T: Zeroize> Locked<T> {
    pub fn new(value: T) -> Self;
    /// Whether the pages could be locked (false when RLIMIT_MEMLOCK is too low).
    pub fn is_locked(&self) -> bool;
}
impl<T: Zeroize> Deref for Locked<T> { type Target = T; }
impl<T: Zeroize> DerefMut for Locked<T> {}
impl<T: Zeroize> Drop for Locked<T> {}           // zeroize, then munlock/VirtualUnlock
impl<T: Zeroize> fmt::Debug for Locked<T> {}     // prints "Locked([REDACTED])"
```

Platform calls: Linux `prctl(PR_SET_DUMPABLE, 0)`, `setrlimit(RLIMIT_CORE, {0, 0})`,
`mlock`/`munlock`, `sysconf(_SC_PAGESIZE)`; macOS/BSD the same without `prctl`; Windows
(`windows-sys` features `Win32_System_Diagnostics_Debug`, `Win32_System_ErrorReporting`,
`Win32_System_Memory`, `Win32_System_SystemInformation`) `SetErrorMode(SEM_FAILCRITICALERRORS
| SEM_NOGPFAULTERRORBOX)`, `WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP)`,
`VirtualLock`/`VirtualUnlock`, `GetSystemInfo` (page size).

T30 may land a first `harden_process` (its §6); this task owns the final API above and its
tests.

**Keyring switch** (read once at startup in the binary, passed to the vault's keyring
factory, T30): env `COURIER_FTP_KEYRING`:
`off` | `0` | `none` | `disabled` → no keyring (keyring unlock hidden, as on headless Linux);
unset → OS keyring; `file:<dir>` → file-backed test keyring, **only** in builds with
feature `test-hooks` (otherwise treated as `off` with a warning on stderr).

**Approvals for synced values that act locally** — `courier_ftp_core::vault::approvals`
(pure logic; persistence through T82 `ApprovalRepo` / `local_approvals`):

```rust
/// A synced field whose value makes this device do something locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalActingField {
    /// `LogonType::KeyFile { key: KeySource::File(path) }`: use a private key file on this device.
    KeyFilePath,
    /// `LogonType::Agent`: offer this device's SSH agent keys to the host.
    AgentLogon,
    /// `try_agent_first = true` (T20): same effect as AgentLogon.
    TryAgentFirst,
}
impl LocalActingField {
    /// Stored in `local_approvals.field`: "key_file_path", "agent_logon", "try_agent_first".
    pub fn as_str(self) -> &'static str;
}
/// One value waiting for this device's approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApproval {
    pub item_id: ItemId,
    pub field: LocalActingField,
    /// Exactly what will be used, shown verbatim (after display sanitising) in the dialog:
    /// the path, or "SSH agent of this computer".
    pub value: String,
    /// The site's display name and host, for the dialog text.
    pub site_label: String,
}
/// SHA-256 of the canonical value bytes (UTF-8 of `value`).
pub fn value_hash(value: &str) -> [u8; 32];
/// Fields of `site` that need approval before connecting: a local-acting field is pending
/// when its value was last stamped by another device (`Stamped.device != this_device`, T81)
/// and `(item_id, field, value_hash)` is not in `approved`. Values stamped by this device
/// are pre-approved.
pub fn pending_approvals(
    item_id: ItemId,
    body: &ItemBody,
    site: &Site,
    this_device: DeviceId,
    approved: &dyn Fn(ItemId, LocalActingField, &[u8; 32]) -> bool,
) -> Vec<PendingApproval>;
```

`VaultEngine` gains (T30 integration): `approve(&PendingApproval)` (writes the
`local_approvals` row, `approved_at = now`), `revoke_approval(item_id, field)`,
`list_approvals() -> Vec<ApprovalRow>` (T68 shows and revokes them),
`pending_approvals_for(item_id) -> Result<Vec<PendingApproval>>`.

**Approval dialog** — `crates/courier-ftp/src/components/dialog/approval.rs` (T52 dialog
framework): shown by the connect path (Site Manager, `--site`, tabs restore, T20/T70)
before `ConnectInfo` is built, one dialog per pending field:

```
┌ Approve local action ───────────────────────────────────┐
│ "web01 (example.org)" was changed on another device.     │
│ It wants to use this private key file on this computer:  │
│   /home/me/.ssh/id_ed25519                               │
│                                                          │
│ [Allow]  [Deny]                                          │
└──────────────────────────────────────────────────────────┘
```

`Allow` → `VaultEngine::approve`, continue. `Deny` (default button, also `Esc`) → the field
is remembered as denied for this process only, the connect is cancelled.

**Fuzz convention**: each owning crate exposes a `#[doc(hidden)] pub fn fuzz_…(data: &[u8])`
body (never panics, ignores errors; names in §7); `fuzz/fuzz_targets/<target>.rs`
is `fuzz_target!(|data: &[u8]| <body>(data));` and the crate has a property test that
runs the same body (`proptest`, `vec(any::<u8>(), 0..4096)`, at least 256 cases; the parser
tasks use 10 000) so `cargo test` covers it on stable.

### Behaviour

#### 1. Process hardening

- Order in `main` (T70 owns the full sequence): install the panic hook → `harden_process()`
  → parse CLI → resolve `AppPaths` → logging init → log the `HardeningReport` at `debug`
  (one line, no secrets) → everything else. No secret exists before `harden_process`.
- `PR_SET_DUMPABLE 0` is reset by `execve`, so editors (T63), the queue-completion command
  (T45) and `ssh-agent` clients started by courier-ftp behave normally.
- `Locked<T>`: when `mlock` fails (e.g. `RLIMIT_MEMLOCK` 64 KiB exhausted) the value stays
  usable, `is_locked()` is false, and one `debug` line is written per process.

#### 2. `unsafe` policy

Workspace lint `unsafe_code = "deny"` (T00). Only `crates/courier-ftp-core/src/hardening/`
may lift it (`#![allow(unsafe_code)]` in `unix.rs` / `windows.rs`). `check-unsafe.py`
(CI `unsafe-check`) and `courier-ftp-e2e/tests/forbid_unsafe.rs` (T76) enforce it.
`courier-ftp-crypto` uses `#![forbid(unsafe_code)]` (T80).

#### 3. Secret handling

- Every secret is `SecretString` / `SecretBytes` (T02), `Key32` (T80) or
  `zeroize::Zeroizing<_>`: passwords, account strings, key passphrases, keyboard-interactive
  answers, proxy passwords, the master password, recovery words, OPAQUE export keys,
  session tokens, TOTP codes/seeds, LMK/VK/item keys.
- `Debug`/`Display` print `[REDACTED]`; no `Clone`, `Serialize`, `PartialEq` on wrappers;
  `expose()` only at the point of use.
- Types with secret fields implement `Debug` by hand with `[REDACTED]`: `ConnectInfo`,
  `LogonType`, `KeySource`, `ParsedUrl`, `PromptResponse`, `QueueServer`, and the
  `courier-ftp-proto` DTOs with secrets or tokens (`RegisterFinishRequest`,
  `LoginFinishRequest`, `RefreshRequest`, `TotpRequest`, the password-change and recovery
  requests; names and the full list in T83).
- clippy `unwrap_used` / `expect_used` are errors in non-test code (`-D warnings`);
  allowed exceptions carry `#[allow(...)]` with a comment stating the invariant and are
  listed in the review checklist.
- FTP `PASS`/`ACCT` and proxy credentials are masked in every log path (`mask_command`, T04);
  SFTP never logs secrets.

#### 4. Logging policy (rules; T71 implements rotation, crash reports and `--debug`)

| Level | May contain | Must never contain |
|---|---|---|
| `error`, `warn`, `info` | ids (`SessionId`, `ItemId`, `VaultId`, transfer ids), counts, sizes, durations, protocol names, error kinds, reply codes | hostnames, IP addresses, usernames, emails, remote or local paths, file names, commands, server reply text, item labels/site names, any secret |
| `debug`, `trace` | the above plus hostnames, IPs, paths, masked commands, server replies | any secret |

- Application log: file only (stdout belongs to the TUI); level from
  `COURIER_FTP_LOG_LEVEL` (default `info`) or `--debug`; `--debug` prints to stderr before
  the TUI starts: `Debug logging is on: the log file may contain host names, user names and
  paths.`
- The **session log** (T55 message log written to a file, T71) is a user feature: it may
  contain hostnames, usernames, paths and masked commands, never secrets; the setting's
  help text says so.
- Crash reports (T71) are built from the `info`+ ring buffer only; the panic message itself
  is included unredacted (residual risk).
- Server (T86): JSON logs; tokens, OPAQUE messages and TOTP codes never logged; emails at
  `info` only as `sha256(lowercased email)` truncated to 12 hex chars.

#### 5. Canary secrets

| Kind | Planted as | Rule |
|---|---|---|
| Secrets | `CANARY-PW-…` (site/proxy passwords), `CANARY-PASS-…` (master password, key passphrases, backup passwords), `CANARY-KEY-…` (inline key text), `CANARY-TOKEN-…` (sync tokens), `CANARY-TOTP-…`, `CANARY-WORDS-…` (recovery words in tests that bypass BIP39 encoding) | never in any log (any level), crash report, SQLite file, backup, edit temp file, session log or server DB dump |
| Hostnames | `canary-host-<hex>.example` | never at `info`+ in application logs; never in crash reports, DB files, backups, dumps; allowed at `debug`/`trace` and in the session log |

`scripts/canary-scan.sh` (T00) implements these rules over the artifact classes `log`,
`crash`, `edit`, `backup`, `db`, `dump`. The binary fixture
`crates/courier-ftp/tests/canary.rs` (`#[cfg(unix)]`) is the end-to-end proof:
1. Kept home `$CARGO_TARGET_TMPDIR/t91-canary/` (wiped at test start).
2. Through the library (`VaultEngine` with `Argon2Cost::TEST`): master password
   `CANARY-PASS-master-7f3a correct horse battery`; a site `canary-site` with host
   `canary-host-7f3a.example`, user `canary-user`, password `CANARY-PW-7f3a-site`, an
   encrypted key passphrase `CANARY-PASS-7f3a-key`; a `.cftp-backup` export with password
   `CANARY-PASS-7f3a-backup` written into the home (S3+: also a FileZilla-XML import).
3. Runs the real binary in a PTY with `COURIER_FTP_LOG_LEVEL=trace`,
   `COURIER_FTP_KEYRING=off`: unlock, open the Site Manager, connect to `canary-site`
   (the `.example` host fails to resolve → error path logged), quit.
4. Runs `scripts/canary-scan.sh --require-files <home>`; must exit 0.
The CI `canary` job scans this home again together with everything else (T00).

#### 6. Supply chain

- `cargo-deny` (`deny.toml`, T00): licenses, advisories, bans (OpenSSL/native-tls banned,
  D9; UI crates only in the binary), sources (crates.io only).
- `cargo-vet` with the crypto/TLS/SSH list of `check-vet-crypto.py`; exempted entries are a
  CI warning until audited; `VET_CRYPTO_STRICT=1` once audits exist (Open questions).
- `Cargo.lock` committed, `--locked` everywhere; reproducible release builds and
  `SHA256SUMS` + SBOM (T00 `cd.yml`, T77).

#### 7. Fuzzing

`fuzz/` (cargo-fuzz, own workspace, T00). PR CI 30 s per target, nightly 600 s with cached
corpus and uploaded crashes.

| Target (`fuzz/fuzz_targets/<name>.rs`) | Body | Input | Seeds (`fuzz/seed-corpus.sh`) | Task, stage |
|---|---|---|---|---|
| `envelope_open` | `courier_ftp_crypto::envelope::fuzz_open_item` | item envelope bytes under a fixed test key | `crates/courier-ftp-crypto/tests/fixtures/envelopes/*` | T80, S1 |
| `device_blob_open` | `courier_ftp_crypto::device_blob::fuzz_open_device_blob` | LMK-encrypted device blob (queue, tabs) | crypto fixtures | T80, S1 |
| `bundle_open` | `courier_ftp_crypto::account::fuzz_open_bundle` | account key bundle | crypto fixtures | T80, S1 |
| `grant_open` | `courier_ftp_crypto::grant::fuzz_open_grant` | team vault-key grant | crypto fixtures | T80, S1 |
| `ppk_parse` | `courier_ftp_proto_sftp::keys::ppk` (body of `props::parse_never_panics`) | PuTTY `.ppk` v2/v3 text | `tests/fixtures/sshd/keys/*.ppk`, `crates/courier-ftp-proto-sftp/tests/fixtures/keys/*.ppk` | T20, S1 |
| `known_hosts_parse` | `courier_ftp_proto_sftp::known_hosts` (body of `props::parse_never_panics`) | OpenSSH known_hosts text | `tests/fixtures/known_hosts/*` | T21, S1 |
| `ftp_listing` | `courier_ftp_proto_ftp::listing::fuzz_listing` | LIST/MLSD bytes with every parser hint | `crates/courier-ftp-proto-ftp/tests/fixtures/listings/**` | T13, S1 |
| `backup_decrypt` | `courier_ftp_core::vault::fuzz_backup_decrypt` | `.cftp-backup` header + payload | one test backup | T30/T73, S1 |
| `ftp_reply` | `courier_ftp_proto_ftp::reply::fuzz_reply_parser` | control-channel bytes in arbitrary chunks | hand-written single/multi-line replies | T10, S2 |
| `ftp_pasv` | `courier_ftp_proto_ftp::fuzz_pasv_epsv` | 227/229 reply text | `printf` seeds | T11, S2 |
| `tls_cert_details` | `courier_ftp_proto_ftp::tls::fuzz_cert_details` | DER certificate → prompt details (`x509-parser`) | `tests/fixtures/tls/*.der` | T12, S2 |
| `http_connect_response` | `courier_ftp_core::net::fuzz_http_connect_response` | proxy reply to CONNECT, split reads | `printf` seeds | T07, S2 |
| `socks_reply` | `courier_ftp_core::net::fuzz_socks_reply` | SOCKS4/5 server replies | `printf` seeds | T07, S2 |
| `remote_name_sanitize` | `courier_ftp_core::local::fuzz_sanitize_local_name` | arbitrary name → `sanitize_local_name`; asserts no separator, NUL, control char, not empty/`.`/`..`, not a reserved Windows name | `FIXTURE_TREE` names (T76) | T06/T42, S2 |
| `filezilla_xml_import` | `courier_ftp_core::sites::import::fuzz_filezilla_xml` | `sitemanager.xml` bytes | `crates/courier-ftp-core/tests/fixtures/filezilla/*.xml` | T32, S3 |
| `sync_dto_decode` | `courier_ftp_proto::fuzz_decode_all` | JSON decoded as every request and response DTO | serialized DTO fixtures | T83, S4 |

Body names already fixed by their owning task (T10, T11, T13, T20, T21, T80, T83) are
used as written there; the others are proposals for their owners.

All bodies cap input-driven allocations (listing lines ≤ 64 KiB, XML ≤ 16 MiB, backup
decompressed ≤ 1 GiB per T30, envelope ≤ 16 MiB per T80).

#### 8. Synced values that act locally (sverb SPEC §17.1)

- Local-acting fields today: `KeyFilePath`, `AgentLogon`, `TryAgentFirst` (see Types).
  Device-local fields (`default_local_dir`, `last_connected_at`, local queue, settings,
  editor associations, queue completion command) never sync and need no approval.
  Any future synced field that runs a command or writes to a local directory
  automatically must be added to `LocalActingField` in the same change (review checklist).
- A field is pending when its `Stamped.device` differs from this device's `DeviceId` and no
  matching `(item_id, field, sha256(value))` row exists. A changed value (new hash) asks
  again. Team vault items follow the same rule (a teammate's device is "another device").
- Denials last for the running process (in-memory set keyed like the table); they are not
  persisted.
- T88 marks items whose local-acting fields changed during a pull, so the Site Manager can
  show a "needs approval" badge (T59/T90).
- `--site` starts (T70) show the same dialog after unlock; there is no non-interactive
  path that skips it.

#### 9. Untrusted remote input (FTP/SFTP-specific rules, cross-task)

| Threat | Rule | Owner |
|---|---|---|
| Path traversal in remote names (`..`, `.`, `/`, `\`, NUL, drive letters `C:`) on download | Listing layer drops entries named `.`/`..` or containing `/` or NUL (debug log); local target = `sanitize_local_name(name)` joined to the target dir, then checked to stay inside it (`starts_with` on the normalised path); violation → that file fails with `Error::InvalidInput("unsafe file name from server")`, the queue continues | T13, T06, T42, T43 |
| Terminal escape sequences in names, server messages, banners, certificate fields | Everything from the network passes `crate::ui::text::sanitize` (C0/C1/DEL/bidi → visible escapes) before rendering; the session log file escapes controls too | T53, T55, T69, T71 |
| Huge or bogus sizes | Sizes are `u64`, never trusted for allocation; preallocation is capped by free space (T42) | T11, T42 |
| Malformed listings | Unparseable lines skipped, never abort a listing; parsers fuzzed | T13 |
| PASV/EPSV to another address | Unroutable PASV address replaced by the control peer (T11); see Open questions for routable mismatches | T11 |
| Active-mode bounce | Accepted data connection must come from the control peer's IP (T11) | T11 |
| Plain FTP | Status bar shows an open lock; `ExplicitIfAvailable` fallback logs a warning | T12, T57 |
| TLS certificate / SSH host-key change | Prompt with old and new fingerprints; changed host keys blocked by default | T12, T21, T69 |

#### 10. Teams trust rules (verified in T89)

TOFU pins are device-local and never synced; a key change blocks grants to and from that
user until accepted after comparing safety numbers; grants are used only with a valid
signature by a **pinned** key of a granter who has `manage`; personal vault keys are
accepted only as self-grants signed by this account's own key.

### Data formats and configuration

- `local_approvals(item_id BLOB, field TEXT, value_sha256 BLOB, approved_at INT,
  PRIMARY KEY (item_id, field))` (T82). `field` = `LocalActingField::as_str()`.
- Environment: `COURIER_FTP_KEYRING` (above), `COURIER_FTP_LOG_LEVEL` (existing),
  `COURIER_FTP_TEST_HOOK` (T76, test-hooks builds only).
- **`docs/threat-model.md`** (sverb's structure):
  1. *Assets* table: master password/KEK, LMK and vault keys, items (sites with passwords,
     `ssh-key` items, passphrases, proxy credentials), decrypted search labels (TEMP table),
     account keys and sync tokens, trusted host keys and certificates, transfer queue
     (`device_blobs`), edit temp files (T63), transferred data in flight, logs and session logs.
  2. *Actors*: malicious/compromised sync server operator; network attacker (sync server,
     FTP/SFTP servers, proxies); **malicious FTP/SFTP server**; malicious teammate; local
     attacker without / with an unlocked session.
  3. *Mitigations* table — columns Threat | Mitigation | Task | Tests — with at least the
     rows: server compromise, stolen laptop (not running / unlocked), memory scraping,
     secrets in logs, MITM on SFTP, MITM on FTPS, plain FTP, malicious server (each §9 row),
     synced local-acting fields, supply chain, hostile input files (fuzzing). Every row
     names at least one test by path and function.
  4. *`unsafe` policy*, 5. *Process hardening details*, 6. *Fuzzing* (the §7 table with the
     property test running each body), 7. *Review checklist* (below), 8. *Residual risks*:
     revoked members keep old data; server-asserted membership; TOFU first sight; debug logs
     contain hostnames; panic messages unredacted in crash reports; `mlock` best effort;
     same-user attacker with an unlocked session on macOS/Windows (and root/`CAP_SYS_PTRACE`
     on Linux); plain FTP is inherently insecure; FTP servers see transferred data in clear
     unless TLS is used; canary coverage limited to artifacts tests leave behind; Windows
     code only exercised by the Windows CI job.
- **Review checklist** (one-time audit before 1.0, kept in the threat model with counts):
  every `expose(` call site outside `tracing`/`format!`/`print`/`panic` macros (list
  exceptions); every `#[allow(clippy::unwrap_used|expect_used)]` in non-test code with its
  invariant; no `#[derive(Debug)]` on a type with a plain secret field; no hostname/
  username/path field at `info`+ (grep `info!`/`warn!`/`error!` in client crates); every
  parser of network or file input has a fuzz target; `LocalActingField` covers every synced
  field that acts locally.
- **`SECURITY.md`**: supported versions (latest minor), how to report (GitHub private
  vulnerability reporting: *Security → Report a vulnerability*), expected response time
  (acknowledge within 7 days), link to the threat model.

### Errors

- `harden_process` never fails; failures go into `HardeningReport.failures` (debug log).
- Approval denied → the connect returns `Error::Cancelled`; the status bar shows
  "Connection cancelled: <field description> not approved".
- Approval needed while the vault is locked → `Error::VaultLocked` (the unlock overlay
  appears first, T60).
- `COURIER_FTP_KEYRING=file:` in a release build → stderr warning
  `COURIER_FTP_KEYRING=file: is only available in test builds; keyring disabled`, keyring off.
- Unsafe file names from the server → `Error::InvalidInput` for that queue item (T42).

### Security and logging

This task *is* the security and logging specification; the rules above apply to every
task. In addition: the approval dialog shows the path verbatim after `sanitize`; approval
rows store only the value hash; `HardeningReport` and approval decisions are logged at
`debug` with ids only.

## Implementation steps

1. **S1** `courier_ftp_core::hardening` (`mod.rs`, `unix.rs`, `windows.rs`) with tests;
   call `harden_process()` first in `main`; log the report at debug.
2. **S1** `Locked<T>` + page refcounting; T30 stores LMK/VK in `Locked<Key32>`.
3. **S1** Secret audit: hand-written `Debug` for every type in §3; `trybuild` compile-fail
   tests; `COURIER_FTP_KEYRING` parsing.
4. **S1** Logging-policy test `crates/courier-ftp-core/tests/logging_policy.rs`; `--debug`
   warning (with T70 if it has landed, else in `cli.rs`).
5. **S1** `crates/courier-ftp/tests/canary.rs` + `tests/common/mod.rs` (PTY helper);
   `crates/courier-ftp/tests/hardening.rs`.
6. **S1** First fuzz targets `envelope_open`, `bundle_open`, `grant_open`, `ppk_parse`,
   `known_hosts_parse`, `ftp_listing_parse`, `backup_decrypt` (each as its owning task
   lands); `seed-corpus.sh` entries.
7. **S2** FTP/TLS/proxy fuzz targets and `remote_name_sanitize`; hostile-server rules
   checked by T76 `hostile.rs`.
8. **S3** `vault::approvals`, `VaultEngine` approval methods, approval dialog, connect-path
   integration (T20/T59/T70), revoke list hook for T68.
9. **S4** `sync_dto_decode`; server canary tests (T84) included in the `canary` job dump.
10. **S5** `docs/threat-model.md`, `SECURITY.md`, review checklist with counts; set
    `VET_CRYPTO_STRICT=1` if audits exist.

## Acceptance criteria

- [ ] AC1 (S1) On Linux the running binary is non-dumpable and has core limit 0: `crates/courier-ftp/tests/hardening.rs` passes (owner of `/proc/<pid>/status` is root or differs from the test user; `/proc/<pid>/limits` shows `Max core file size 0 0`).
- [ ] AC2 (S1) `harden_process()` is called before CLI parsing and before any secret exists (code review + `main.rs` order test via the `exit:0` hook finding the debug report line as the first `courier_ftp` line of the log).
- [ ] AC3 (S1) `Locked<T>`: values zeroized before unlock, shared pages stay locked until the last value drops, low `RLIMIT_MEMLOCK` falls back without failing (unit tests).
- [ ] AC4 (S1) `unsafe-check`, `deny`, `vet`, `canary` and `fuzz` CI jobs pass; `check-unsafe.py` passes with `hardening/unix.rs` and `windows.rs` as the only `allow(unsafe_code)` sites.
- [ ] AC5 (S1) `scripts/canary-scan.sh --self-test` passes, and after `COURIER_FTP_LOG_LEVEL=trace cargo test --workspace --all-features`, the scan over `target/tmp` and the CI roots finds nothing; `canary.rs` passes with `--require-files`.
- [ ] AC6 (S1) No hostname, username or path at `info`+ in client logs: `logging_policy.rs` passes and the canary scan finds no `canary-host-` on `INFO`/`WARN`/`ERROR` lines.
- [ ] AC7 (S1) Secret types: `format!("{:?}")` and `format!("{}")` of every type in §3 holding a canary contain `[REDACTED]` and not the canary; `trybuild` proves `SecretString` is not `Clone`, `Serialize` or `PartialEq`.
- [ ] AC8 (S1–S4) Every fuzz target in §7 whose owning task has landed exists, runs 30 s in PR CI without a crash, and its body is run by a property test in its crate.
- [ ] AC9 (S2) Hostile filenames (`../x`, `a/b`, `..`, names with ESC/NUL, `C:evil`) cannot create files outside the target directory and are never written raw to the terminal (T76 `hostile.rs` scenarios pass).
- [ ] AC10 (S3) Approval: a site whose key file path / agent logon / try-agent-first was stamped by another device shows the approval dialog before connecting; Allow persists (no dialog next time); a changed value asks again; Deny cancels and asks again after restart; values typed on this device never ask.
- [ ] AC11 (S5) `docs/threat-model.md` exists with all sections of §"Data formats", every mitigation row names at least one existing test (`scripts/` check: each referenced `path::fn` resolves by `grep`), and `SECURITY.md` exists.
- [ ] AC12 (S1) `COURIER_FTP_KEYRING=off` disables keyring use (no keyring calls; option hidden), `file:` is rejected in builds without `test-hooks`.

## Tests

### Unit tests
- `courier-ftp-core/src/hardening/mod.rs`: `locked_value_zeroized_on_drop` (inspect through a raw pointer captured before drop in a `#[cfg(test)]` hook), `shared_page_stays_locked_until_last_drop`, `locked_falls_back_when_memlock_exhausted` (`set_memlock_limit(0)` in a forked child via `std::process::Command` re-running the test binary with a filter) (AC3).
- `courier-ftp-core/tests/hardening.rs`: `t01_harden_sets_core_limit_zero` (unix), `t02_harden_clears_dumpable` (linux), `t03_report_has_no_failures_on_linux_ci` (AC1, AC2).
- `courier-ftp-core/src/vault/approvals.rs`: `own_device_values_are_preapproved`, `other_device_key_file_is_pending`, `agent_logon_and_try_agent_first_pending`, `approved_hash_matches_suppresses`, `changed_value_is_pending_again`, `team_vault_item_from_teammate_is_pending`, `value_hash_is_sha256_of_utf8` (AC10).
- Binary `cli`/startup: `keyring_env_off_variants`, `keyring_file_rejected_without_test_hooks` (AC12).
- Secret `Debug` tests per type in its owning crate, collected here as AC7: `connect_info_debug_redacts`, `logon_type_debug_redacts`, `prompt_response_debug_redacts`, `proto_dtos_debug_redact`.

### Property / fuzz tests
- The never-panics property test of each §7 body in its owning crate (names in the owning tasks, e.g. T10 `prop_reply_parser_never_panics`, T83 `props::fuzz_body_never_panics`) (AC8).
- `courier-ftp-core/src/local`: `prop_sanitized_name_stays_inside_target` — arbitrary names; `target.join(sanitize_local_name(n))` normalised starts with `target` and has exactly one more component (AC9).

### Snapshot tests
- `components/dialog/approval.rs`: `approval_key_file_dialog`, `approval_agent_dialog`, `approval_long_path_wraps` at 80×24 and 160×48 (T76 helper) (AC10).

### Integration tests
- `crates/courier-ftp-core/tests/logging_policy.rs::info_lines_have_no_host_user_or_path` — installs a `tracing` test subscriber at `trace`, drives `SessionHandle` with `MockBackend` (host `canary-host-1a2b.example`, user `canary-user`, path `/canary/path`) through connect, list, a failing connect and a transfer; asserts no captured `info`+ event contains those strings and no event at any level contains `CANARY-PW-` (AC6).
- `crates/courier-ftp-core/tests/compile_fail/*.rs` + `tests/secret_traits.rs` (`trybuild`): `secret_string_not_clone.rs`, `secret_string_not_serialize.rs`, `secret_string_not_partial_eq.rs` (AC7).
- `crates/courier-ftp/tests/hardening.rs::t01_running_binary_is_not_dumpable` (`#[cfg(target_os = "linux")]`, PTY, `COURIER_FTP_TEST_HOOK=exit:3000`) (AC1).
- `crates/courier-ftp/tests/canary.rs::t02_no_canary_leaks_after_trace_run` (`#[cfg(unix)]`, flow in §5) (AC5, AC6).
- `crates/courier-ftp/tests/approval.rs::approval_dialog_flow` — `TestHome`-style vault with a site whose `KeySource::File` is stamped by a foreign `DeviceId`; drive the app with scripted keys (reducer test, no PTY): dialog appears, Deny → `Error::Cancelled`, Allow → row stored, second connect has no dialog (AC10).
- CI jobs as tests: `unsafe-check`, `deny`, `vet`, `canary`, `fuzz` (AC4, AC8).

### End-to-end tests
- `courier-ftp-e2e/tests/hostile.rs` (T76, in-process, not ignored): the six hostile scenarios (AC9).
- `courier-ftp-e2e/tests/pty_flows.rs::add_site_with_password_restart_unlock_connect_without_prompt` keeps its home under `target/tmp` with the `canary` user's password, so the CI `e2e` job's canary scan covers a real SFTP/FTP session (AC5).
- Manual check (S5, recorded in the threat model): review checklist counts.

## Out of scope

- Implementing the logging pipeline, rotation, crash reports and `--debug` flag (T71, T70);
  this task sets the rules and tests them.
- The trust prompt UIs (T69) and certificate/host-key verification (T12, T21).
- Sync server rate limiting and account security (T84–T86).
- Kerberos/GSS and other dropped features (D8).
- Code signing and notarization (T00 `cd.yml`, T77).

## Open questions

- **PASV to a different routable address:** T11 replaces only *unroutable* PASV addresses. A malicious server can make the client connect to any routable host:port (FTP "PASV bounce"/port scanning through the client). FileZilla accepts it by default. Should courier-ftp always use the control peer's address unless the user enables "allow PASV to other hosts" per site? (Owner of T11 to implement whichever is chosen.)
- **Vulnerability contact:** `SECURITY.md` uses GitHub private vulnerability reporting. Should an email address be listed as well?
- **cargo-vet strictness:** crypto/TLS/SSH crates are exempted (CI warning). When should `VET_CRYPTO_STRICT=1` become mandatory (before 1.0, or later)?
- **Inconsistency (T71, not owned here):** T71 (M9) implements the logging pipeline and crash reports, but this task's rules apply from M2. Until T71 lands, S1 enforces §4 on the template logger (`<data>/courier-ftp.log`, single file); T71 must keep `logging_policy.rs` and `canary.rs` green.
