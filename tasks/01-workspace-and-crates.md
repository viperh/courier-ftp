# T01 — Workspace and crate layout

**Phase:** A Foundation · **Depends on:** T00 · **Crates:** all · **Decisions:** D1, D2, D5, D9

## Goal

Turn the template workspace into the courier-ftp workspace: add the protocol crates,
add the shared dependencies, remove template placeholders and fix CI so later
tasks have somewhere to put their code.

## Context

Current layout (after `setup.sh`):

```
crates/courier-ftp/        binary: tui.rs, app.rs, components/home.rs (hello world), config.rs …
crates/courier-ftp-core/   placeholder Core { ticks } + Error::InvalidState
```

`.github/workflows/ci.yml` only triggers on pushes to `main`, but the default branch is `master`.

## Scope

1. **Create crates**
   - `crates/courier-ftp-proto-ftp` (lib) — own FTP/FTPS client (T10–T15).
   - `crates/courier-ftp-proto-sftp` (lib) — russh-based SFTP client (T20–T22).
   - `crates/courier-ftp-crypto` (lib, pure) — T80.
   - `crates/courier-ftp-store` (lib, SQLite) — T82.
   - `crates/courier-ftp-proto` (lib, sync wire types) — T83.
   - `crates/courier-ftp-sync` (lib, sync client) — T87/T88, optional via the binary's `sync` feature (default on).
   - `crates/courier-ftp-server` (bin) — T84–T86. Must not depend on ratatui/crossterm; its heavy deps must not leak into the client build.
   - All new crates use `version.workspace = true` etc., like the existing crates.
   - The two protocol crates depend on `courier-ftp-core` (for the `Backend` trait and domain types) and **must not** depend on `ratatui`, `crossterm` or `clap`. Put the same comment the core crate has in their `Cargo.toml`.
   - Add each to `[workspace.dependencies]` as path deps.
2. **Add workspace dependencies** (pin to current latest versions at the time of implementation, check with `cargo search`):
   - Async: `async-trait` (only if native `async fn` in traits is not enough for `dyn Backend` — see T03), `bytes`, `pin-project-lite`.
   - TLS: `rustls`, `tokio-rustls`, `rustls-platform-verifier`, `rustls-pki-types`, `x509-parser` (cert details for trust prompt).
   - SSH: `russh`, `russh-sftp`, `ssh-key` (with `ppk`/`encryption` features if available; verify).
   - Crypto / vault / sync: see T80–T82 and T87 (copied from sverb's versions): `argon2`, `chacha20poly1305`, `hkdf`, `hpke`, `ed25519-dalek`, `x25519-dalek`, `opaque-ke`, `bip39`, `zxcvbn`, `rand`, `zeroize`, `secrecy`, `uhlc`, `ciborium`, `zstd`, `rusqlite` (bundled), `rusqlite_migration`, `reqwest` (rustls), `tokio-tungstenite`, `keyring` (optional per-device unlock, D3; pick features that avoid C build deps on Linux, e.g. pure-Rust Secret Service + crypto-rust).
   - Server only (T84–T86): `axum`, `axum-server`, `tower-http`, `sqlx-core` + `sqlx-postgres`, `governor`, `lettre`, `totp-rs`, `metrics`.
   - Text: `encoding_rs` (non-UTF-8 server charsets), `chrono` or `time` (pick **one**, prefer `time` with `macros`, `parsing`, `formatting`, `local-offset`), `regex`, `globset`.
   - Misc: `uuid` (`v4`, `v7`, `serde`), `serde_json`, `quick-xml` (FileZilla import), `notify` (watch edited files, T63), `bytesize`.
   - Dev: `tempfile`, `tokio-test`, `insta` (snapshot tests for listing parsers and UI rendering).
3. **Remove template placeholders**
   - Replace `Core { ticks }` in `courier-ftp-core/src/lib.rs` with module declarations (empty modules are fine): `model`, `backend`, `events`, `settings`, `local`, `net`, `queue`, `transfer`, `filters`, `compare`, `search`, `cache`, `vault`, `sites`. Keep the crate-level doc comment but rewrite it for courier-ftp.
   - Keep `Home` component until T50 replaces it; remove `Action::Help` only if unused after T51.
   - Update the `description` of the binary crate in its `Cargo.toml` to "A terminal FTP, FTPS and SFTP client" (setup kept the template default).
4. **CI**: set up the full sverb-style CI from T00 (at least `fmt`, `clippy`, `docs`, `test-local-only`, `test-os`, `deny`, `unsafe-check`, `layering` in this task; the rest as their features land). Replace the template's `ci.yml`, which triggers on `main` while the default branch is `master`.
4b. **`COURIER_FTP_HOME`**: one env var that overrides both the config and data directories (like sverb's `SVERB_HOME`), used by tests (T76) and CI. The existing `COURIER_FTP_CONFIG`/`COURIER_FTP_DATA` keep working and win over it.
5. **README**: update the "Layout" tree with the new crates and a one-line purpose for each.
6. `cargo check --workspace`, then commit the refreshed `Cargo.lock`.

## Design notes

- Feature flags: none for now. Do **not** make protocols optional features yet; revisit if build times hurt.
- The binary crate depends on both protocol crates and wires them into a `BackendFactory` (T03).

## Acceptance criteria

- [x] `crates/courier-ftp-proto-ftp` and `crates/courier-ftp-proto-sftp` exist and build.
- [x] Neither new crate nor core pulls in `ratatui`/`crossterm`/`clap` (`cargo tree -p <crate> -i ratatui` returns nothing).
- [x] Placeholder `Core`/ticks code is gone; `app.rs` no longer calls `core.tick()`.
- [ ] The initial T00 CI jobs exist and pass on `master` and on PRs.
- [x] `COURIER_FTP_HOME` redirects config and data.
- [x] README layout section reflects the new crates.
- [x] All four CI gates pass locally.

## Tests

- Existing tests updated/removed with the placeholder. No new behaviour to test.

## Out of scope

- Any actual protocol code.

## Implementation notes

- **CI (scope 4) not done here.** T00 is implemented concurrently in its own lane, so this
  task wrote no workflows or scripts; the "T00 CI jobs exist" criterion stays open until
  T00 lands.
- **`[workspace.lints]`** was added to the root `Cargo.toml` (the T00 set, copied from sverb)
  so the new crates can use `[lints] workspace = true`. The existing `courier-ftp` and
  `courier-ftp-core` crates do not opt in yet (T00 does that and fixes the template's
  `unwrap()`s); the new core code is clean under those lints.
- **`AppPaths`** lives in a new `courier_ftp_core::paths` module (not in the scope's module
  list): `AppPaths::from_env()` / `AppPaths::resolve(env_fn, DefaultDirs)`, with
  `config_dir()` / `data_dir()`. Order: `COURIER_FTP_CONFIG`/`COURIER_FTP_DATA`, then
  `COURIER_FTP_HOME/{config,data}`, then the platform dirs, then `./.config`/`./.data`;
  empty variables count as unset. The binary's `config::get_config_dir`/`get_data_dir`
  delegate to it (`config::PATHS`), and the binary no longer depends on `directories`.
- The placeholder `Error`/`Result` in core stay until T02 replaces them.
- **New crates are skeletons** (crate doc only). Internal path deps follow the layering:
  proto-ftp/proto-sftp -> core; store, proto -> crypto; sync -> core, crypto, proto, store;
  server -> crypto, proto (no client crates). The binary depends on both protocol crates
  and optionally on `courier-ftp-sync` (`sync` feature, default on).
- **Dependency versions:** crypto, storage, sync-client and server deps use sverb's
  versions (a known-compatible set: rustls 0.23 with `ring`, reqwest 0.12, tokio-tungstenite
  0.29, sqlx 0.8.6, tower-http 0.6, totp-rs 5.7) rather than newest majors; the rest are
  the latest stable releases from `cargo search`. `time` was picked over `chrono`, so the
  sqlx features use `time` instead of sverb's `chrono`. `ssh-key` has `ppk` and
  `encryption`. The whole set was checked to resolve together (`cargo metadata` with a
  throwaway crate depending on all of them). `russh` keeps its default features
  (`aws-lc-rs`, like sverb); switch to `default-features = false, features = ["ring", ...]`
  in T20 if the C build of aws-lc becomes a problem.
- **MSRV:** several pinned deps need a newer Rust than the current `rust-version = "1.85"`
  (`encoding_rs` 0.8.42 and `keyring` 4.2 need 1.88, `uuid` 1.27 needs 1.89). Unused
  workspace deps are not resolved, so nothing breaks yet; the first task that uses them must
  raise `rust-version` (sverb uses 1.95).
- Fixed the template's `config::tests::test_config`, which looked up `<q>` while the
  default config binds `<Ctrl-q>` (it failed on the base commit too).
