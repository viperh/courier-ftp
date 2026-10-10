# Threat model

courier-ftp follows sverb's security design (decision D3; the vault, crypto and store
code is adapted from sverb, D13). This document names, for each threat, the mitigation,
the task that implements it and the tests that prove it, then lists the risks we accept.

It is written in stages (T91). This is the **M2 version**: it covers the code that exists
after T30 (encrypted vault, keyring unlock, backups), the SSH/SFTP client (T20–T22), the
network layer and proxies (T07), the FTP listing parsers (T13) and the binary. Rows marked
**planned** describe mitigations owned by tasks that have not landed yet (FTP/FTPS control
and data connections, transfers, sync server, teams); their tests are added with them, and
the document is completed at the end of the project.

## Assets

| Asset | Where it lives |
|---|---|
| Master password, KEK | typed at unlock, never stored; KEK derived with Argon2id (or held by the OS keyring when keyring unlock is on) |
| LMK and vault keys | in memory only while unlocked, in `mlock`ed pages (`hardening::Locked`), zeroized on lock |
| Items: sites with passwords, SSH keys, key passphrases | SQLite `items.envelope`, XChaCha20-Poly1305 under the vault key |
| Decrypted index | memory only (the engine's in-memory map), zeroized on lock |
| Account keys and sync tokens (sync, planned) | `meta` / `sync_state`, AEAD under the LMK |
| Trusted host keys (SFTP) and certificates (FTPS, planned) | vault items; integrity matters, not secrecy. `~/.ssh/known_hosts` is read, never written |
| Transfer queue (hosts, paths, quickconnect passwords) | SQLite `device_blobs`, an envelope under a device data key wrapped by the LMK; never synced, never written while the vault is locked. Queue exports (JSON) carry no passwords |
| Edit temp files (planned: T63) | a private temp dir |
| Transferred data in flight | SSH channel (SFTP), TLS (FTPS, planned), plaintext for plain FTP |
| Backups (`.cftp-backup`) | Argon2id + XChaCha20-Poly1305 under a backup password; the header is authenticated |

## Actors

- **Malicious or compromised sync server operator** (sync is planned, T83–T89): sees all
  ciphertext, membership lists and the public-key directory; can drop, replay or reorder.
- **Network attacker**: on the path to an FTP/SFTP server, a proxy, or the sync server.
- **Malicious FTP/SFTP server**: controls every reply, listing and file name: `../`
  components, `/` and NUL in names, control characters and terminal escape sequences, huge
  sizes and dates, hostile PASV addresses, endless or malformed replies.
- **Malicious proxy**: answers the HTTP `CONNECT` / SOCKS handshake.
- **Malicious teammate** (teams, planned): can write items into shared vaults.
- **Local attacker without an unlocked session**: has the disk (stolen laptop) or runs code
  as another user.
- **Local attacker with an unlocked session**: runs code as the same user while courier-ftp
  is unlocked.

## Mitigations

| Threat | Mitigation | Task | Tests |
|---|---|---|---|
| Stolen laptop, courier-ftp not running | Vault encrypted at rest: KEK from Argon2id (or OS keyring, off by default); item bodies are AEAD envelopes; no plaintext item data in the DB, WAL or SHM | T30, T80, T81 | `courier-ftp-store` `tests/store.rs::no_plaintext_item_data_on_disk`, `tests/vault_canary.rs::canary_secrets_never_leak`, `tests/canary_artifacts.rs` + `scripts/canary-scan.sh` |
| Online guessing of the master password | Argon2id cost, persistent backoff shared between processes | T30 | `courier-ftp-store` `tests/vault.rs::{backoff_matches_the_table_and_is_shared_between_engines, backoff_survives_a_restart, wrong_password_changes_nothing_but_the_counter}` |
| Stolen laptop, courier-ftp unlocked | Auto-lock (idle, suspend); lock drops every key and the decrypted index | T30 | `courier-ftp-core` `vault::lock::tests`; `courier-ftp-store` `tests/vault.rs::live_key_counter_is_zero_after_lock` |
| Tampered vault or backup | Envelopes bind vault id, item id and key version in the AAD; tampered items are skipped and logged by id; backup header is part of the AAD and its KDF bounds are checked before Argon2 | T30, T80 | `courier-ftp-crypto` `tests/envelope.rs::{tamper_every_byte, tamper_aad_other_item_vault_or_key_version}`; `courier-ftp-store` `tests/vault.rs::tampered_item_envelopes_are_skipped`; `courier-ftp-core` `vault::backup::tests::{tampering_is_detected, out_of_bounds_kdf_is_refused_before_argon2, decompression_is_capped}` |
| Memory scraping | `zeroize`/`secrecy` on every secret type; LMK and vault keys in `mlock`ed pages (best effort); core dumps off and same-user `ptrace` blocked (Linux `PR_SET_DUMPABLE 0` + `RLIMIT_CORE 0`; macOS `RLIMIT_CORE 0`; Windows no WER heap, no fault dialogs) | **T91** | `courier-ftp-core` `tests/hardening.rs` (`t01_harden_process_disables_core_dumps`, `t02_mlock_fallback_with_zero_memlock_limit`), `hardening::tests`; `courier-ftp` `tests/hardening.rs::binary_hardens_itself_at_startup` |
| Secrets in logs, crash reports or `Debug` output | Secret types print `[REDACTED]` (or `****`); canary values planted in tests; `scripts/canary-scan.sh` scans every log, DB, WAL/SHM and backup left after a `COURIER_FTP_LOG_LEVEL=trace` run | T30, **T91** | `scripts/canary-scan.sh --self-test`; `courier-ftp-store` `tests/canary_artifacts.rs`, `tests/vault_canary.rs`; `courier-ftp-proto-sftp` `ssh::tests::canary_secrets_stay_out_of_trace_logs` (password + keyboard-interactive code, russh's own trace output included); CI job `canary` |
| Hostnames, user names and paths in logs | No hostnames, user names or paths at `info`+ in client crates (ids only); debug may contain hostnames | T71, **T91** | canary scan (hostname canary on `info`+ lines, any canary in DB/backup); fixed in T91: `known_hosts` file paths moved to `debug`. Open items: see the review checklist |
| MITM on SFTP | Strict host-key verification against the vault and `known_hosts` (hashed entries, `@revoked`); a changed key prompts with both fingerprints, cancel fails | T21 | `courier-ftp-proto-sftp` `ssh::trust::tests::{a_changed_key_prompts_with_both_fingerprints_and_cancel_fails, a_revoked_key_is_rejected_without_a_prompt, a_hashed_known_hosts_entry_matches_silently, first_connect_prompts_and_always_makes_the_next_one_silent}` |
| MITM on FTPS, certificate changes | rustls only (D9), certificate pinning on change | T12 (**planned**) | added with T12 |
| Plain FTP | Warnings when credentials or data go unencrypted | T12, T57 (**planned**) | added with T12/T57 |
| PASV bounce / hostile PASV address | Ignore the address in the PASV reply when it differs from the control connection's peer (FileZilla behaviour); active mode can be refused | T11 (**planned**), T07 | `courier-ftp-core` `net::tests` (`ensure_active_mode_allowed`); PASV parser tests with T11 |
| Path traversal in remote names | `sanitize_name` turns `/`, NUL (Windows: `\ : * ? " < > |`, control characters, reserved device names) into a replacement and never returns `.` or `..`, so a name is always one component under the target directory | T06, **T91**; the download path join is T42 (**planned**) | `courier-ftp-core` `local::sanitize::tests::{unix_rules, windows_rules, sanitized_names_never_escape_the_directory}` |
| Terminal escapes in file names and server messages | SSH banners and server text pass `sanitize_server_text` (escape sequences and control characters removed, length capped); ratatui drops graphemes containing control characters when it writes to its buffer | T21, T53, T55 | `courier-ftp-proto-sftp` `ssh::text::tests::strips_escapes_and_controls`; a rendering test with hostile names is open (T53/T55) |
| Hostile parser input (servers, proxies, files) | Every parser of untrusted bytes is fuzzed (below) and its fuzz body is a property test in its crate | T07, T13, T20, T21, T30, T80, T81, **T91** | 10 cargo-fuzz targets (table below); CI job `fuzz` (30 s per target), nightly `fuzz.yml` (10 min) |
| Synced values that act locally (key file paths, agent use) | Device-local approval by value hash (`local_approvals`), re-asked when the value changes; headless starts fail | T82 (store table exists), approval UI **planned** | `courier-ftp-store` approvals tests; prompt tests with the UI |
| Server compromise, key substitution (sync, teams) | E2EE, OPAQUE, TOFU pins, safety numbers, signed grants (see sverb's threat model) | T80, T83–T89 (**planned**) | crypto: `courier-ftp-crypto` `tests/{kat,envelope,opaque,account}.rs`; trust rules with T89 |
| Supply chain | `cargo-deny` (licenses, advisories, bans, sources); `cargo-vet` (imported audits from Mozilla, Google, Bytecode Alliance, ISRG, Zcash; the rest exempted, crypto crates flagged as a CI warning until audited); `Cargo.lock` committed, `--locked` in CI; reproducible archives | T00, T77, **T91** | CI jobs `deny`, `vet` (+ `scripts/check-vet-crypto.py`), `packaging` (archives are reproducible) |

## `unsafe` policy

The workspace lint is `unsafe_code = "deny"` (not `forbid`, which an inner `allow` can't
lift). Exactly one module carries `#![allow(unsafe_code)]`:
`crates/courier-ftp-core/src/hardening/{unix,windows}.rs` (`prctl(PR_SET_DUMPABLE)`,
`setrlimit`/`getrlimit`, `mlock`/`munlock`, `sysconf`; `SetErrorMode`, `WerSetFlags`,
`VirtualLock`/`VirtualUnlock`, `GetSystemInfo`). Plain libc/Win32 calls with integer arguments
or pointers to values we own; none keeps a pointer. `hardening/mod.rs` (page reference
counting and `Locked<T>`) is safe code.

`scripts/check-unsafe.py` (CI job `unsafe-check`) fails if the lint is lifted anywhere else,
if a crate overrides it or doesn't inherit the workspace lints, if the workspace level is
weakened, or if an `unsafe` block in the allowed module has no `// SAFETY:` comment on its
line or in the comment block above it. `courier-ftp-e2e/tests/forbid_unsafe.rs` proves that
every crate inherits the `deny`, that an `unsafe` block is rejected, and tests the script.

## Process hardening details

- `harden_process()` runs in `main` right after the panic hook is installed and before
  logging, config or the vault exist. Its report (no secrets) is logged at `debug` once
  logging is up. Non-interactive subcommands (`generate`) exit before it.
- `PR_SET_DUMPABLE 0` makes `/proc/<pid>/*` root-owned and blocks `ptrace` and
  `/proc/<pid>/mem` for same-user, non-root processes. `execve` resets it, so an external
  editor (T63) or a `ProxyCommand` behaves normally; children inherit `RLIMIT_CORE 0`.
- `Locked<T>` counts references per page, so freeing one key never unlocks a page another key
  shares. Values are zeroized before their pages are unlocked. When `RLIMIT_MEMLOCK` is too low
  the key stays usable and one `debug` line says so. The vault engine keeps the LMK and every
  vault key in `Locked<Key32>` (`courier-ftp-store` `vault::TrackedKey`).

## Fuzzing

`fuzz/` (cargo-fuzz, its own workspace, excluded from the root one). PR CI (`ci.yml` job
`fuzz`) runs each target for 30 s; `fuzz.yml` runs each one for 10 minutes nightly with the
corpus cached between runs, seeded from the test fixtures (`fuzz/seed-corpus.sh`), and uploads
crashes. Every target compiles on stable (`cargo check` in `fuzz/`); running needs nightly.

| Target | Input | Body also run by |
|---|---|---|
| `listing` | FTP `LIST`/`MLSD` output, server time zones (T13) | `courier-ftp-proto-ftp` `tests/no_panic.rs` |
| `proxy_reply` | proxy answers to HTTP `CONNECT`, SOCKS4/4a, SOCKS5 (+ login), split reads (T07) | `courier-ftp-core` `net::tests::fuzz_proxy_reply_*` |
| `known_hosts_parse` | `known_hosts` text, matched against fixed hosts (T21) | `courier-ftp-core` `trust::known_hosts::tests::fuzz_known_hosts_*` |
| `key_parse` | private key files: OpenSSH, PEM, PKCS#8, PPK v2/v3 incl. Argon2 bounds (T20) | `courier-ftp-proto-sftp` `ssh::keys::tests::fuzz_key_parse_*` |
| `envelope_open` | item envelopes (T80) | `courier-ftp-crypto` `tests/primitives.rs::fuzz_open_item_never_panics` |
| `bundle_open`, `grant_open` | account bundles, vault-key grants (T80) | `courier-ftp-crypto` `tests/account.rs::t09_decoders_never_panic` |
| `kdf_params` | KDF parameter CBOR (T80) | `courier-ftp-crypto` `tests/primitives.rs::fuzz_kdf_params_never_panics` |
| `item_body` | item body CBOR (T81) | `courier-ftp-core` `model::item::tests::fuzz_item_body_*` |
| `backup_decrypt` | `.cftp-backup` header, KDF bounds, AEAD, capped zstd, CBOR items, without Argon2 (T30) | `courier-ftp-core` `vault::backup::tests::fuzz_backup_decrypt_*` |

Planned with their tasks: FTP reply parser (T10), PASV/EPSV parser (T11), FileZilla
`sitemanager.xml` import (T32), sync DTO JSON decode (T83).

## Review checklist (one-time audit; M2 pass)

- `expose_secret()` (40 non-test call sites at the M2 pass): none inside a `tracing`,
  `format!`, `write!`, `print`/`panic` macro. The proxy `Proxy-Authorization` header builds
  the Basic token from the exposed password by design (`courier-ftp-core` `net/http.rs`).
- `unwrap()` / `expect()` in non-test code: `clippy::unwrap_used` / `expect_used` are `warn`
  at the workspace level and CI runs clippy with `-D warnings`, so they fail the build;
  tests are exempt (`clippy.toml`).
- `Debug` derives on types with plain secret fields: none found. Secrets use `SecretString`,
  `Key32`, `Zeroizing` or hand-written redacting `Debug` (`ProxyAuth`, `KeyFile`, `Locked`,
  `VaultEngine`).
- `info`+ logging: the vault engine logs ids and counts only. Fixed in T91: `known_hosts`
  file paths (which contain the user name) moved from `warn`/`info` to `debug`.
  **Open (T71)**: the binary logs every action at `info` (`app.rs`, `Got action: {action:?}`;
  actions may carry hosts and paths) and config/filter warnings may include paths; T71's
  logging rework moves these to `debug`.

## Residual risks

- **Debug logs contain hostnames** (`COURIER_FTP_LOG_LEVEL=debug`); the `--debug` warning
  comes with T71.
- **`mlock` is best effort**: not available with a low `RLIMIT_MEMLOCK`, and values copied
  before they reach `Locked` (stack temporaries, Argon2 buffers, the KEK during unlock) are
  only zeroized, not locked.
- **Same-user attacker with an unlocked session** on macOS/Windows can still read process
  memory (no `PR_SET_DUMPABLE` equivalent); on Linux, root or `CAP_SYS_PTRACE` can.
- **Windows hardening is not compiled or run locally**; only the Windows CI job (`test-os`)
  builds it.
- **TOFU on first sight** of an SFTP host key (and, with sync, of a teammate's key) until the
  fingerprint is compared out of band.
- **Plain FTP is inherently insecure**: credentials and data travel in clear text.
- **Revoked members keep old data; membership is server-asserted** (teams, planned; see
  sverb's threat model).
- **Canary coverage** is limited to what tests leave behind: the vault and SSH fixtures
  (`target/tmp/canary-vault`, `target/tmp/canary-ssh`) are always scanned; tests that delete
  their temp dirs are covered by their own in-test checks only.
- **Panic messages** reach the terminal and the log unredacted; the crash report built from
  the `info`+ ring buffer comes with T71.
