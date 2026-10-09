# T01 — Workspace and crate layout

**Phase:** A Foundation · **Milestone:** M1 · **Depends on:** T00 · **Crate(s):** all (new: `courier-ftp-proto-ftp`, `courier-ftp-proto-sftp`, `courier-ftp-crypto`, `courier-ftp-store`, `courier-ftp-proto`, `courier-ftp-sync`, `courier-ftp-server`) · **Decisions:** D1, D2, D5, D9, D10, D12, D13 · **FEATURES.md:** — (infrastructure for §1–§10)
**Reference:** sverb `Cargo.toml` (`[workspace.dependencies]`, versions), `crates/*/Cargo.toml` (crate headers, `[lints]`, feature `sync`), `crates/sverb-core/src/paths.rs` (`SVERB_HOME`).

## Goal

The template workspace becomes the courier-ftp workspace: every planned crate exists as a
compiling skeleton with the right dependency direction, shared dependency versions are
pinned in one place, the template placeholders are gone, and one environment variable
(`COURIER_FTP_HOME`) relocates all on-disk state so tests and CI never touch the real home
directory. Later tasks only add code to crates that already exist.

## Context

**Before** (template after `setup.sh`, plus T00):

```
crates/courier-ftp/        binary: main.rs, app.rs, action.rs, cli.rs, config.rs, errors.rs,
                           logging.rs, tui.rs, components/home.rs (hello world)
crates/courier-ftp-core/   placeholder `Core { ticks }` + `Error::InvalidState`
```

- `app.rs` owns a `Core` and calls `core.tick()`.
- `config.rs` resolves directories with `ProjectDirs::from("com", "viperh", "courier-ftp")`,
  overridable by `COURIER_FTP_CONFIG` / `COURIER_FTP_DATA`, and falls back to `./.data` /
  `./.config` (relative to the current directory) when no home directory exists.
- T00 added `[workspace.lints]`, `rust-version = "1.95"`, the CI jobs and the layering
  rules for all crates below.

**After**, later tasks need:

- `courier-ftp-core` modules to put code in (T02–T07, T30, T31, T33, T40–T49, T81).
- The protocol crates (T10–T15, T20–T22), crypto (T80), store (T82), proto (T83),
  sync (T87/T88), server (T84–T86).
- `AppPaths` (binary crate) and `COURIER_FTP_HOME` (T05, T63, T70, T71, T76, T91).
- The `sync` cargo feature on the binary (project rule: the client works without sync).

## Technical specification

### Types and APIs

**Crates** (all `version.workspace = true`, `edition`, `authors`, `license`, `repository`,
`rust-version` inherited; all have `[lints] workspace = true`):

| Crate | Kind | `description` | Internal deps (normal) | Owner tasks |
|---|---|---|---|---|
| `courier-ftp` | bin | "A terminal FTP, FTPS and SFTP client" | core, proto-ftp, proto-sftp, crypto, store, proto, sync (optional) | T50+ |
| `courier-ftp-core` | lib | "Domain logic for courier-ftp, independent of any user interface" | crypto, proto (added when T30/T81 need them) | T02–T07, T30–T49, T81 |
| `courier-ftp-proto-ftp` | lib | "FTP and FTPS client for courier-ftp" | core | T10–T15 |
| `courier-ftp-proto-sftp` | lib | "SFTP client for courier-ftp, built on russh" | core | T20–T22 |
| `courier-ftp-crypto` | lib | "Cryptography for the courier-ftp vault and sync (no I/O)" | — | T80 |
| `courier-ftp-store` | lib | "SQLite store for courier-ftp's encrypted items" | core, crypto | T82 |
| `courier-ftp-proto` | lib | "Wire types of the courier-ftp sync protocol" | crypto | T83 |
| `courier-ftp-sync` | lib | "Sync client for courier-ftp" | core, store, proto, crypto | T87, T88 |
| `courier-ftp-server` | bin | "Self-hosted sync server for courier-ftp" | proto, crypto | T84–T86 |

`courier-ftp-e2e` (not published) is created by T76.

Every library `Cargo.toml` that must stay UI-free carries the comment

```toml
# Keep this crate UI-agnostic: no ratatui, no crossterm, no clap
# (scripts/check-layering.py and deny.toml enforce it).
```

`courier-ftp-server` carries "no ratatui, no crossterm, no russh, no rusqlite; no client
crates" instead.

**Root `Cargo.toml`, internal entries** (the `version` is required for `cargo package` /
crates.io; bump together with `workspace.package.version`):

```toml
courier-ftp-core       = { path = "crates/courier-ftp-core",       version = "0.1.0" }
courier-ftp-proto-ftp  = { path = "crates/courier-ftp-proto-ftp",  version = "0.1.0" }
courier-ftp-proto-sftp = { path = "crates/courier-ftp-proto-sftp", version = "0.1.0" }
courier-ftp-crypto     = { path = "crates/courier-ftp-crypto",     version = "0.1.0" }
courier-ftp-store      = { path = "crates/courier-ftp-store",      version = "0.1.0" }
courier-ftp-proto      = { path = "crates/courier-ftp-proto",      version = "0.1.0" }
courier-ftp-sync       = { path = "crates/courier-ftp-sync",       version = "0.1.0" }
courier-ftp-server     = { path = "crates/courier-ftp-server",     version = "0.1.0" }
```

**Features**

| Crate | Features |
|---|---|
| `courier-ftp` | `default = ["sync"]`; `sync = ["dep:courier-ftp-sync"]`; `test-hooks = []` (crash-path and startup hooks for the binary's PTY tests, T76/T91; never in release builds — T00 `packaging` checks) |
| `courier-ftp-core` | `test-util = []` (`MockBackend`, the backend conformance suite; T03/T06) |
| `courier-ftp-proto-sftp` | `test-util = []` (in-process russh SFTP server for harness self-tests; T22/T76) |
| `courier-ftp-crypto` | `insecure-test-ksf = []` (cheap OPAQUE KSF, T80) |

Protocols are **not** optional features (D5): both protocol crates are always linked.

**`courier_ftp_core` module skeleton** (`src/lib.rs`; each module file holds only a `//!`
line naming the task that fills it):

```rust
//! Domain logic for courier-ftp: protocols-agnostic file management, transfers, the
//! vault and settings. No terminal, no ratatui/crossterm/clap (checked in CI).
pub mod backend;    // T03
pub mod bookmarks;  // T33
pub mod cache;      // T46
pub mod compare;    // T48
pub mod events;     // T04
pub mod filters;    // T47
pub mod hardening;  // T91 (the only module allowed to use `unsafe`)
pub mod listing;    // T13 (shared Unix `ls -l` parser, reused by SFTP longnames)
pub mod local;      // T06
pub mod model;      // T02, T81 (`model::item`)
pub mod net;        // T07
pub mod queue;      // T40
pub mod search;     // T49
pub mod secret;     // T30/T91
pub mod settings;   // T05
pub mod sites;      // T31, T32
pub mod transfer;   // T41–T44, T41b
pub mod trust;      // T12, T21 (`CertTrustStore`, `HostKeyStore`)
pub mod vault;      // T30

/// Errors produced by the core (placeholder until T02 replaces it).
#[derive(Debug, thiserror::Error)]
pub enum Error { /* InvalidState(String) kept as is */ }
pub type Result<T, E = Error> = std::result::Result<T, E>;
```

**`crates/courier-ftp/src/paths.rs`** (new in this task; T70 later adds the `--config-dir` /
`--data-dir` flags and the derived-path helpers `vault_db()`, `log_dir()`, `crash_dir()`,
T71 uses them). Paths live in the binary crate: core and the other libraries never read
the environment, they receive explicit paths.

```rust
/// Relocates every courier-ftp directory: `P/config`, `P/data`, `P/cache`.
pub(crate) const HOME_ENV: &str = "COURIER_FTP_HOME";
/// Override only the config directory (wins over `HOME_ENV`).
pub(crate) const CONFIG_ENV: &str = "COURIER_FTP_CONFIG";
/// Override only the data directory (wins over `HOME_ENV`).
pub(crate) const DATA_ENV: &str = "COURIER_FTP_DATA";

/// Source of environment variables, injectable for tests.
pub(crate) trait Env {
    /// The variable's value; `None` when unset **or empty**.
    fn var_os(&self, name: &str) -> Option<OsString>;
}
/// The process environment.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SystemEnv;
/// A fixed map, for tests.
#[derive(Debug, Default, Clone)]
pub(crate) struct MapEnv(pub HashMap<String, OsString>);

/// The resolved directories. Built once in `main` and passed explicitly (replaces the
/// template's `LazyLock` env statics and `get_config_dir`/`get_data_dir` in `config.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppPaths {
    /// Config files (`config.json` etc., D10).
    pub config_dir: PathBuf,
    /// Vault DB (T30/T82), logs and crash reports (T71/T91).
    pub data_dir: PathBuf,
    /// Disposable files: edit temp copies (T63). `$COURIER_FTP_HOME/cache` or
    /// `ProjectDirs::cache_dir()`.
    pub cache_dir: PathBuf,
}

impl AppPaths {
    /// Precedence per directory: CLI flag (T70; `None` until then) >
    /// `COURIER_FTP_CONFIG` / `COURIER_FTP_DATA` > `COURIER_FTP_HOME/{config,data,cache}` >
    /// `directories::ProjectDirs::from("com", "viperh", "courier-ftp")`
    /// (`config_local_dir`, `data_local_dir`, `cache_dir`). Creates nothing.
    pub(crate) fn resolve(
        cli_config: Option<&Path>,
        cli_data: Option<&Path>,
        env: &dyn Env,
    ) -> Result<Self, PathsError>;
    /// Create the three directories (Unix mode `0o700` on creation). Called only on
    /// paths that start the TUI (not for `--version` / `generate`, T70).
    pub(crate) fn ensure_dirs(&self) -> std::io::Result<()>;
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PathsError {
    #[error("could not determine your home directory; set COURIER_FTP_HOME to the directory courier-ftp should use")]
    NoHome,
    #[error("{var} ({}) could not be made absolute: {source}", path.display())]
    NotAbsolute { var: &'static str, path: PathBuf, #[source] source: std::io::Error },
}
```

`main` resolves `AppPaths::resolve(None, None, &SystemEnv)?`, calls `ensure_dirs()` and
passes `&AppPaths` to `Config::new(&paths)` and `logging::init(&paths)`. `--version` keeps
printing the config and data directories.

### Behaviour

- **Directory resolution order** (per directory, first match wins):
  1. the CLI flag (from T70 on);
  2. `COURIER_FTP_CONFIG` (config) / `COURIER_FTP_DATA` (data); the cache dir has no
     own variable;
  3. `COURIER_FTP_HOME` → `$COURIER_FTP_HOME/config`, `/data`, `/cache`;
  4. the platform directory from `ProjectDirs`;
  5. otherwise `PathsError::NoHome` (the template's `./.data` fallback is removed: it
     wrote into whatever directory the user started from).
- Empty values count as unset. Relative values are made absolute against the current
  directory at resolution time (`std::path::absolute`); failure → `NotAbsolute`.
- `ensure_dirs()` creates missing directories with `create_dir_all`; on Unix newly created
  directories get mode `0o700` (`DirBuilderExt::mode`); existing directories are left
  as they are (T82 tightens the data dir).
- `.envrc` keeps working unchanged (it sets `COURIER_FTP_CONFIG` / `COURIER_FTP_DATA`).
- **Template placeholders**: `Core`, `Core::new`, `Core::tick` and the `core` field of
  `App` are deleted; `App::new` no longer returns a core error. `components/home.rs`
  stays until T50 replaces it. `Action::Help` stays until T51 rewrites the action list.
- **`courier-ftp-server` skeleton**: `src/main.rs` prints `courier-ftp-server <version>`
  for `--version` and otherwise prints "courier-ftp-server: not implemented yet (T84)" to
  stderr and exits with code 2. No clap yet.
- **Library skeletons**: `src/lib.rs` with a crate doc comment (purpose, layering rule,
  owner task) and nothing else. `courier-ftp-crypto` additionally has
  `#![forbid(unsafe_code)]` (T80).
- **README "Layout"** lists every crate with the one-line purpose from the table above
  and the dependency direction
  `crypto ← proto ← core ← {store, proto-ftp, proto-sftp} ← sync ← courier-ftp`,
  `server ← {proto, crypto}`.

### Data formats and configuration

**`[workspace.dependencies]` added in this task** (versions are the pins sverb uses for
the same crates where sverb has them; others are the current releases at the time of
writing and are re-checked with `cargo search` during implementation — the version that
lands in `Cargo.lock` is recorded in the PR):

| Group | Entries |
|---|---|
| Async | `async-trait = "0.1.92"` (T03 uses it for `dyn Backend`, as sverb does for `dyn Transport`), `bytes = "1.12.1"`, `pin-project-lite = "0.2"` |
| TLS (D9) | `rustls = { version = "0.23.43", default-features = false, features = ["logging", "ring", "std", "tls12"] }`, `tokio-rustls = { version = "0.26", default-features = false, features = ["logging", "ring", "tls12"] }`, `rustls-platform-verifier = "0.6"`, `rustls-pki-types = "1"`, `x509-parser = "0.18"`, `webpki-roots = "1.0.9"` |
| SSH (D2) | `russh = "0.64.1"`, `russh-sftp = "2.1"` (the release built on russh 0.64; `cargo tree -d` must show one russh), `ssh-key = { version = "=0.7.0-rc.11", features = ["ed25519", "encryption"] }` (PPK support is decided in T20) |
| Crypto / vault (T80, T30) | `argon2 = "0.6.0"`, `chacha20poly1305 = "0.11.0"`, `hkdf = "0.13.0"`, `hpke = "0.14.1"`, `ed25519-dalek = { version = "3.0.0", features = ["zeroize"] }`, `x25519-dalek = { version = "3.0.0", features = ["static_secrets", "zeroize"] }`, `opaque-ke = { version = "4.0.1", features = ["argon2"] }`, `bip39 = { version = "3.0.0", default-features = false, features = ["zeroize"] }`, `zxcvbn = { version = "3.1.0", default-features = false }`, `sha2 = "0.11.0"`, `getrandom = { version = "0.4.3", features = ["sys_rng"] }`, `rand_core = "0.10.1"`, `subtle = "2.6.1"`, `zeroize = { version = "1.9.1", features = ["derive"] }`, `secrecy = "0.10.3"`, `keyring = "4.2.0"` |
| Storage (T81, T82) | `uhlc = "0.9.0"`, `ciborium = "0.2.2"`, `zstd = "0.14.0"`, `rusqlite = { version = "0.40.2", features = ["bundled"] }`, `rusqlite_migration = "2.6.0"` |
| Sync client (T87, T88) | `reqwest = { version = "0.12.28", default-features = false, features = ["json", "rustls-tls-webpki-roots-no-provider"] }`, `tokio-tungstenite = { version = "0.29.0", default-features = false, features = ["connect", "handshake", "rustls-tls-webpki-roots"] }`, `fastrand = "2.3.0"` |
| Server only (T84–T86) | `axum = { version = "0.8.9", features = ["macros"] }`, `axum-server = { version = "0.8.0", features = ["tls-rustls-no-provider"] }`, `tower = { version = "0.5.3", features = ["util"] }`, `tower-http = { version = "0.6.11", features = ["compression-gzip", "cors", "limit", "timeout", "trace"] }`, `sqlx-core` / `sqlx-postgres = "0.8.6"` (features as sverb: no `sqlx` facade, it conflicts with rusqlite's `links = "sqlite3"`), `governor = "0.10.4"`, `lettre` (as sverb, rustls/ring), `totp-rs = { version = "5.7.0", default-features = false }`, `metrics = "0.24.6"`, `metrics-exporter-prometheus = { version = "0.18.3", default-features = false }`, `chrono = { version = "0.4.45", default-features = false, features = ["clock", "std"] }` (server only, for sqlx), `base64 = "0.22.1"`, `ipnet = "2.12.2"` |
| Text / time | `time = { version = "0.3", features = ["formatting", "local-offset", "macros", "parsing", "serde"] }` (the client's only date/time crate), `encoding_rs = "0.8.35"`, `regex = "1.13.1"`, `globset = "0.4"` |
| Misc | `uuid = { version = "1.27.0", features = ["serde", "v4", "v7"] }`, `serde_json = "1.0.149"`, `quick-xml = "0.38"` (T32), `notify = "8.2.0"` (T63), `bytesize = "2"`, `tracing-appender = "0.2.5"` (T71), `hex = "0.4.3"`, `libc = "0.2.189"` (bump), `windows-sys = "0.61.2"` (T91 hardening), `clap_complete = "4.6"`, `clap_mangen = "0.2"` (T70/T77) |
| Dev | `tempfile = "3.27.0"`, `tokio-test = "0.4"`, `insta = "1.49.0"`, `proptest = "1.11.0"`, `trybuild = "1.0.121"`, `criterion = "0.8.2"`, `rcgen = "0.14"` (T12 test certificates), `cargo_metadata = "0.23.1"`, `toml = "1.1.6"`, `testcontainers = { version = "0.28.0", default-features = false }`, `portable-pty = "0.9.0"`, `vt100 = "0.16"` (T76) |

Each crate references only what it uses (`dep = { workspace = true }`); an entry nobody
uses yet costs nothing. Template entries `config`, `json5` (D10) stay; `better-panic` and
`human-panic` stay until T91 replaces the panic hook.

**No new settings keys.** Environment variables: `COURIER_FTP_HOME` (new),
`COURIER_FTP_CONFIG`, `COURIER_FTP_DATA` (existing, now documented as winning over
`COURIER_FTP_HOME`).

### Errors

- `PathsError::NoHome` / `NotAbsolute` (binary crate) → `main` returns a `color_eyre` report; the user
  sees the one-line message above on stderr before the TUI starts, exit code 1.
- `courier_ftp_core::Error` keeps the template's `InvalidState(String)` until T02.

### Security and logging

- `COURIER_FTP_HOME` exists so tests and CI never read or write the real user directories
  (T00 jobs set it; T76 `TestHome` uses it).
- New directories are created `0o700` on Unix (vault DB, logs and crash reports live in
  the data dir).
- Resolved paths are not logged at `info` or above (T91: no paths at `info`+); `--version`
  prints them to stdout because the user asked.
- The layering rules (T00 `check-layering.py`, `deny.toml` wrappers) keep secrets-handling
  crates (crypto, store, core) free of UI dependencies.

## Implementation steps

1. Add the seven crates as skeletons (manifests with inherited package fields,
   `[lints] workspace = true`, the UI comment, doc-only `lib.rs` / `main.rs`); add the
   internal `[workspace.dependencies]` entries with `version`; `cargo check --workspace`.
2. Wire internal dependencies per the table (binary: `courier-ftp-sync` optional, feature
   `sync` default on; `test-hooks`, `test-util`, `insecure-test-ksf` features declared);
   `python3 scripts/check-layering.py` passes for both feature sets.
3. Add the external `[workspace.dependencies]` entries; commit the refreshed `Cargo.lock`;
   `cargo deny … check` and `cargo vet --locked` pass (exemptions regenerated only for
   crates that are actually in the lock file).
4. Replace `Core` with the module skeleton in `courier-ftp-core`; remove `core` from
   `App`; update tests that used it.
5. Add `crates/courier-ftp/src/paths.rs` (`AppPaths`) with tests; switch `config.rs`,
   `logging.rs` and `main.rs` to an `AppPaths` value; remove the `LazyLock` env statics
   and the `./.data` fallback.
6. Update the binary's `description`, README "Layout" and "Configuration" (env var table),
   `.envrc` comment.

## Acceptance criteria

- [ ] AC1 All nine crates in the table exist and `cargo build --workspace --all-features --locked` and `cargo build -p courier-ftp --no-default-features --locked` succeed.
- [ ] AC2 `python3 scripts/check-layering.py` exits 0 (all-features and no-default-features graphs); `cargo tree -p courier-ftp-core -p courier-ftp-proto-ftp -p courier-ftp-proto-sftp -e normal --locked | grep -E ' (ratatui|crossterm|clap) v'` prints nothing.
- [ ] AC3 `cargo tree -p courier-ftp --no-default-features -e normal --locked` does not contain `courier-ftp-sync`; with default features it does.
- [ ] AC4 `grep -rn "Core\b\|tick()" crates/courier-ftp/src crates/courier-ftp-core/src` finds no template placeholder; `app.rs` has no `core` field.
- [ ] AC5 `COURIER_FTP_HOME=/tmp/x cargo run -p courier-ftp -- --version` prints `/tmp/x/config` and `/tmp/x/data` (and creates neither); with `COURIER_FTP_CONFIG=/tmp/c` also set, the config line shows `/tmp/c`.
- [ ] AC6 With no `HOME` and no override (`env -i cargo run …` on Linux) the binary exits 1 with the `COURIER_FTP_HOME` message and creates no `./.data`.
- [ ] AC7 `courier-ftp-server --version` prints `courier-ftp-server 0.1.0`.
- [ ] AC8 `cargo package --workspace --exclude courier-ftp-e2e --locked` succeeds (internal deps carry versions).
- [ ] AC9 README "Layout" lists every crate with its purpose; README "Configuration" documents `COURIER_FTP_HOME`, `COURIER_FTP_CONFIG`, `COURIER_FTP_DATA` and their precedence.
- [ ] AC10 All T00 CI jobs pass on the PR (`fmt`, `clippy`, `docs`, `test`, `test-os`, `test-local-only`, `msrv`, `deny`, `vet`, `layering`, `unsafe-check`, `canary` self-test, `packaging`).

## Tests

### Unit tests
In `crates/courier-ftp/src/paths.rs` (`#[cfg(test)]`, all with `MapEnv`, no real env changes; the names match T70's later precedence tests):
- `fn paths_home_sets_both` — `COURIER_FTP_HOME=/h` → `/h/config`, `/h/data`, `/h/cache` (AC5).
- `fn paths_env_wins_over_home` — `COURIER_FTP_CONFIG=/c` → `/c` for config, `/h/data` for data; mirror case for `COURIER_FTP_DATA` (AC5).
- `fn paths_empty_values_are_unset` — `COURIER_FTP_HOME=""` falls through to the platform dirs.
- `fn paths_relative_home_is_made_absolute` — `COURIER_FTP_HOME=rel` → `<cwd>/rel/config`.
- `fn paths_no_home_is_an_error` — resolution with a `ProjectDirs`-less platform hook returns `PathsError::NoHome` (AC6). The platform lookup is injected through a private `fn resolve_with(cli_config, cli_data, env, platform: impl Fn() -> Option<[PathBuf; 3]>)` so the test runs on any host.
- `fn paths_resolve_creates_nothing_and_ensure_creates_0700` (`#[cfg(unix)]`) — in a `tempfile::TempDir`: after `resolve` no directory exists; after `ensure_dirs` all three exist with mode `0o700`.

### Property / fuzz tests
Not applicable.

### Snapshot tests
Not applicable (no UI change; `Home` stays).

### Integration tests
- `crates/courier-ftp/tests/version.rs::fn version_prints_overridden_dirs` — runs `env!("CARGO_BIN_EXE_courier-ftp") --version` with `COURIER_FTP_HOME` set to a temp dir and checks both paths in stdout (AC5).
- `crates/courier-ftp/tests/version.rs::fn no_home_fails_without_writing_cwd` (`#[cfg(target_os = "linux")]`) — runs the binary with an empty environment in a temp cwd; exit code 1, stderr mentions `COURIER_FTP_HOME`, cwd still empty (AC6).
- `crates/courier-ftp-server/tests/version.rs::fn server_version` (AC7).
- AC1–AC3, AC8, AC10 are the CI jobs and commands themselves; AC4 and AC9 are checked in review.

### End-to-end tests
Not applicable (the e2e crate arrives with T76).

## Out of scope

- Any protocol, vault, store, sync or server code (only skeletons here).
- The `courier-ftp-e2e` crate (T76) and the `fuzz/` targets (T91).
- Replacing the `config` crate or the template's panic handling (T91 / T05).

## Open questions

- **Inconsistency (T30 vs T82, not owned here):** T30 puts `VaultEngine` in `courier-ftp-core` (`vault` module) and has it use the SQLite store, but T82's `courier-ftp-store` depends on `courier-ftp-core` (for `model::item`, T81). Cargo forbids the cycle, and the layering rules (T00) forbid core → store. One of them has to change: (a) `VaultEngine` in core works over a storage trait that `courier-ftp-store` implements, or (b) the engine moves to `courier-ftp-store` / the binary (sverb keeps it in `sverb-tui`). Owners of T30/T82 to decide.
- **Inconsistency (README rule, not owned here):** the project rule says the server crate never depends on `clap`, but T86's admin CLI needs one (sverb-server uses clap). T00's layering rules allow `clap` in `courier-ftp-server`.
- **Alignment with T70 (not owned here):** T70 declares `AppPaths { config_dir, data_dir }` with `resolve(...) -> Self`. This task adds `cache_dir` (T63 keeps edit copies under `$COURIER_FTP_HOME/cache`) and makes `resolve` return `Result<Self, PathsError>`, because without a home directory there is no safe fallback. T70 should adopt both.
