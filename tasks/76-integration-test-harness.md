# T76 — Test strategy and e2e harness (sverb parity)

**Phase:** G App-level (start early, alongside phases B/C) · **Depends on:** T03, T06 · **Crates:** all, new `crates/courier-ftp-e2e` (not published)
**Reference:** sverb `crates/sverb-e2e/` (`lib.rs`, `home.rs`, `keys.rs`, `pty.rs`, `session.rs`, `sshd.rs`, `diag.rs`, `tests/*`), `tests/fixtures/sshd/` (Dockerfile, profiles, `check-configs.sh`, `entrypoint.sh`), SPEC §19, `CONTRIBUTING.md`.

## Goal

Test every layer the way sverb does: fast unit/property/snapshot tests in each
crate, and a Docker-based end-to-end suite against real FTP, SFTP and sync
servers that is skipped by default and required in CI.

## Testing strategy per layer (SPEC §19 equivalent)

| Layer | Approach |
|---|---|
| Crypto (T80) | Known-answer tests, `proptest` round-trips, AAD tamper tests, cross-version envelope fixtures |
| Merge / sync (T81, T88) | Property tests: random concurrent edit sequences on N simulated devices converge to identical state (tombstones, resurrection); parallel pushers against Postgres while a puller asserts no revision is missed; killing a key rotation mid-way recovers |
| FTP protocol (T10–T15) | Scripted fake servers (`tokio::io::duplex`) for every command flow; reply/PASV parsers as property tests |
| Listing parsers (T13) | Fixture corpus with `insta` snapshots; parser-never-panics property tests (shared with fuzz bodies) |
| Importers (T32) | FileZilla XML fixtures with `insta` snapshots of the result |
| Backends | One conformance suite (T06) run against Local, Mock, FTP/FTPS (each server), SFTP (each auth profile) |
| Transfer engine (T41, T41b, T42–T44) | Deterministic tests with `tokio::time::pause` and a mock backend with per-connection latency/bandwidth; exhaustive table for the file-exists decision |
| Settings / config | Table tests; schema snapshot (generated docs fail when stale) |
| TUI | ratatui `TestBackend` + `insta` snapshots of every view at **80×24 and 160×48**; reducer-style tests that drive the app with scripted key events |
| Server (T84–T86) | Per-test Postgres database; HTTP-level tests through `axum::Router` + `tower::ServiceExt`; in-memory store variants for fast tests; multi-client sync scenarios against a real server |
| Security (T91) | Canary scan over all artifacts; hardening test on the real binary; compile-fail tests (`trybuild`) proving secret types can't be `Clone`/`Serialize`/printed |
| Fuzzing (T91 §7) | `cargo-fuzz` targets whose bodies are also property tests |
| Performance (T92 §4) | `criterion` benches with CI gates |

## The `courier-ftp-e2e` crate

Modelled on `sverb-e2e`. Pieces:

1. **Server fixtures in Docker** via `testcontainers` (no TLS provider; talks to the local
   Docker socket only). One image per server family, with **runtime-selected profiles**
   (env `FTPD_PROFILE` / `SSHD_PROFILE`), each validated with `--check` in CI:
   - `tests/fixtures/ftpd/` — vsftpd-based image. Profiles: `plain`, `explicit-tls`,
     `implicit-tls`, `tls-reuse-required` (`require_ssl_reuse=YES`), `active-only`,
     `passive-unroutable` (PASV returns a private IP), `no-mlsd`, `max-1-connection`,
     `anonymous`, `slow` (rate-limited, for cancel/resume tests).
   - `tests/fixtures/proftpd/` — MLSD, `SITE CHMOD`, `MFMT`, mod_tls.
   - `tests/fixtures/pureftpd/` — TLS and its LIST output format.
   - `tests/fixtures/sshd/` — copied from sverb and trimmed: profiles `password`, `key`,
     `kbd` (2-step keyboard-interactive), `maxauth2`, `legacy` (old algorithms, negative
     tests), `chroot-sftp` (internal-sftp only), `windows-like` (OpenSSH-for-Windows style
     paths); plus `MaxSessions 1` to test the connection-limit back-off.
   - Proxies: `squid` (HTTP CONNECT) and `dante` (SOCKS5) profiles.
   - Sync: `courier-ftp-server` + `postgres:16` (from `deploy/`).
   - Network faults: `toxiproxy` in front of a server to cut connections, add latency or
     throttle a single connection (resume, work stealing in T41b).
2. **`keys`**: committed, clearly **test-only** fixture keys (ed25519, RSA, ECDSA,
   encrypted/unencrypted, OpenSSH and PPK v2/v3), host keys and a test CA for TLS certs
   (self-signed, expired, wrong-host variants).
3. **`TestHome`**: a temporary `COURIER_FTP_HOME` with an initialised vault (cheap Argon2
   via test cost) and helpers that write sites, bookmarks, known hosts and trusted certs
   through the vault engine. Homes that should be canary-scanned live under
   `CARGO_TARGET_TMPDIR`.
4. **`Headless`**: drives sessions through the real backend factory, transfer engine and
   vault without a TUI (list, transfer, compare, search), and exposes the event stream.
5. **`PtyApp`**: runs the real `courier-ftp` binary in a PTY, sends keys in chord syntax
   (`"ctrl-s"`, `"F5"`, `"g g"`), reads the screen through a terminal emulator crate
   (sverb uses alacritty_terminal; we can use it or `vt100`), with `wait_for_text`.
   Used for full user flows: first-run vault creation, unlock, Site Manager → connect →
   upload → verify on the server, edit-in-`$EDITOR` round-trip with a fake editor script.
6. **`diag`**: on panic, live harness objects dump container logs, the last screen and the
   message log into the test output.
7. **Macros/rules** (copy sverb's):
   - Container tests are `#[ignore]`; `require_docker!` at the start of each returns early
     with a skip message unless `COURIER_E2E=1` is set and Docker answers. On CI
     (`CI=true`) a missing Docker daemon is a **failure**, not a skip.
   - **No fixed sleeps**: everything polls with `timeout()` — 10 s locally, 20 s on CI.
   - Each test starts its own containers → parallel-safe (`--test-threads=4` in CI).
   - Harness self-tests that need no Docker (Headless against an in-process SFTP server
     built on `russh` server API, PtyApp against the local binary) run in the normal suite.
8. **`tests/workspace_metadata.rs`**: crate layering rules (T92 §6) checked via
   `cargo_metadata` for both the all-features and the `--no-default-features` graphs;
   every crate inherits the workspace lints.
9. **`tests/forbid_unsafe.rs`**: proves every crate inherits `unsafe_code = "deny"`.

## E2E scenarios (minimum)

- Backend conformance suite × every FTP profile and SFTP auth profile.
- Queue of 50 mixed-size files up and down, SHA-256 verified; segmented download of a
  2 GiB sparse file (T41b) verified; resume after toxiproxy cuts the connection.
- Connection limit back-off (`max-1-connection`, `MaxSessions 1`).
- TLS: session reuse required, self-signed prompt, changed certificate warning.
- SSH: unknown host key prompt, changed key blocked, every auth method, PPK keys.
- Hostile server (custom tiny FTP server in the harness): filenames with `../`, `/`, ESC
  sequences and NUL, huge sizes, malformed listings — nothing escapes the target directory
  or reaches the terminal unescaped.
- Sync: register, second device login with duplicate preview, offline edits on both,
  conflict merge, team invite, member removal + rotation, `410` resync, password change
  logs out the other device, recovery with 24 words.
- PtyApp: first run → create vault → add site with password → quit → start → unlock →
  connect without a password prompt.

## Running locally

```sh
cargo test --workspace                        # fast suite, no Docker
COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored
scripts/canary-scan.sh --self-test
```

## Acceptance criteria

- [ ] `courier-ftp-e2e` crate with the pieces above, documented in its crate docs like sverb's `lib.rs`.
- [ ] Every fixture image builds and every profile passes `--check`.
- [ ] Without Docker, `cargo test` skips container tests cleanly; on CI a missing Docker fails.
- [ ] All scenarios above pass in the CI `e2e` job (T92).
- [ ] TUI snapshot tests exist for every view at 80×24 and 160×48.

## Tests

- This task *is* tests.
