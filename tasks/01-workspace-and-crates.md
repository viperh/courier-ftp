# T01 — Workspace and crate layout

**Phase:** A Foundation · **Depends on:** — · **Crates:** all · **Decisions:** D1, D2, D5, D9

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
   - Crypto / vault / sync: see T80–T82 and T87 (copied from sverb's versions): `argon2`, `chacha20poly1305`, `hkdf`, `hpke`, `ed25519-dalek`, `x25519-dalek`, `opaque-ke`, `bip39`, `zxcvbn`, `rand`, `zeroize`, `secrecy`, `uhlc`, `ciborium`, `zstd`, `rusqlite` (bundled), `rusqlite_migration`, `reqwest` (rustls), `tokio-tungstenite`. **No `keyring`** (D3).
   - Server only (T84–T86): `axum`, `axum-server`, `tower-http`, `sqlx-core` + `sqlx-postgres`, `governor`, `lettre`, `totp-rs`, `metrics`.
   - Text: `encoding_rs` (non-UTF-8 server charsets), `chrono` or `time` (pick **one**, prefer `time` with `macros`, `parsing`, `formatting`, `local-offset`), `regex`, `globset`.
   - Misc: `uuid` (`v4`, `v7`, `serde`), `serde_json`, `quick-xml` (FileZilla import), `notify` (watch edited files, T63), `bytesize`.
   - Dev: `tempfile`, `tokio-test`, `insta` (snapshot tests for listing parsers and UI rendering).
3. **Remove template placeholders**
   - Replace `Core { ticks }` in `courier-ftp-core/src/lib.rs` with module declarations (empty modules are fine): `model`, `backend`, `events`, `settings`, `local`, `net`, `queue`, `transfer`, `filters`, `compare`, `search`, `cache`, `vault`, `sites`. Keep the crate-level doc comment but rewrite it for courier-ftp.
   - Keep `Home` component until T50 replaces it; remove `Action::Help` only if unused after T51.
   - Update the `description` of the binary crate in its `Cargo.toml` to "A terminal FTP, FTPS and SFTP client" (setup kept the template default).
4. **CI**
   - Change the `push` trigger in `ci.yml` from `main` to `master`.
   - Add a job (or extend `test`) that runs on `windows-latest` and `macos-latest` too — at least `cargo check --workspace --locked`.
5. **README**: update the "Layout" tree with the new crates and a one-line purpose for each.
6. `cargo check --workspace`, then commit the refreshed `Cargo.lock`.

## Design notes

- Feature flags: none for now. Do **not** make protocols optional features yet; revisit if build times hurt.
- The binary crate depends on both protocol crates and wires them into a `BackendFactory` (T03).

## Acceptance criteria

- [ ] `crates/courier-ftp-proto-ftp` and `crates/courier-ftp-proto-sftp` exist and build.
- [ ] Neither new crate nor core pulls in `ratatui`/`crossterm`/`clap` (`cargo tree -p <crate> -i ratatui` returns nothing).
- [ ] Placeholder `Core`/ticks code is gone; `app.rs` no longer calls `core.tick()`.
- [ ] CI triggers on `master` and checks Linux, macOS and Windows.
- [ ] README layout section reflects the new crates.
- [ ] All four CI gates pass locally.

## Tests

- Existing tests updated/removed with the placeholder. No new behaviour to test.

## Out of scope

- Any actual protocol code.
