# courier-ftp task list

courier-ftp is a terminal (TUI) replacement for the FileZilla client. Every task in
this folder traces back to a section of [`../FEATURES.md`](../FEATURES.md).

## How to use these files

- One file per task. The number is the task ID (`T13` = `13-*.md`). Numbers group tasks by
  area; they are **not** the build order — use the milestones below.
- **T00 (CI/CD) is the first task.**
- **Depends on** lists *hard* dependencies: those tasks must be done before this one can be
  finished. **Related** lists tasks it integrates with later; they don't block it.
  The dependency graph has no cycles, and every milestone only depends on itself and earlier
  milestones (checked when this list was last updated).
- Each task has: **Goal**, **Depends on**, **Related**, **Crate(s)**, **FEATURES.md refs**,
  **Scope** (step by step), **Design notes**, **Acceptance criteria**, **Tests**
  and **Out of scope**.
- Tick acceptance-criteria boxes in the file as they are met. A task is done when
  every box is ticked and the required CI checks from T00 pass.
- Tasks can run in parallel once their hard dependencies are done.
- If a task uncovers a decision not recorded below, stop and ask, then record it here.

## Decisions (agreed)

| # | Topic | Decision |
|---|-------|----------|
| D1 | FTP / FTPS | **Own FTP client** written from scratch on tokio (no `suppaftp`). |
| D2 | SFTP | **`russh` + `russh-sftp`** (pure Rust, async). |
| D3 | Secrets | **Same security design as sverb.** Encrypted vault (Argon2id + XChaCha20-Poly1305). The **master password is asked at TUI start** and always works; per-device **OS keyring unlock is optional and off by default**. Recovery: 24-word recovery key for sync accounts; local-only users can recover only through keyring unlock. Hardening, canary scans, fuzzing and threat model as in sverb (T91). |
| D4 | Site storage | **Sites live in the vault, passwords included.** Storage is a SQLite DB of individually encrypted items (sverb design), so items can sync and merge. Bookmarks, history, trusted host keys/certificates and SSH keys are items too; the transfer queue is encrypted but device-local. |
| D5 | Crate layout | **Separate protocol crates**: `courier-ftp-proto-ftp`, `courier-ftp-proto-sftp`, both implementing a `Backend` trait from `courier-ftp-core`. |
| D6 | Keybindings | **Hybrid**: Midnight Commander F-keys (F5 copy, F6 move, F7 mkdir, F8 delete, Tab switch pane) plus vim motions (`j/k/h/l`, `gg/G`, `/`). All rebindable. |
| D7 | Mouse | **Keyboard only** for v1. Mouse capture stays off. |
| D8 | Dropped features | Kerberos/GSS auth, OS drag and drop, sound / sleep / shutdown on queue completion. No tasks exist for these. |
| D9 | TLS | `rustls` (with `rustls-platform-verifier` for OS trust roots). No OpenSSL. *(Default chosen by Claude — say so if you want it changed.)* |
| D10 | App settings | Non-secret settings stay in the existing layered config (`crates/courier-ftp/config/default.json` defaults, baked into the binary, + user `config.*`; moved out of `.config/` in T00 so `cargo package` works). |
| D11 | Speed | Transfers run in parallel (4 by default) and large files are split into ranges over several connections, with SFTP request pipelining (T41b). |
| D12 | Sync | Device sync through **courier-ftp's own self-hosted server** (`courier-ftp-server`: axum + PostgreSQL), end-to-end encrypted, OPAQUE login with the master password, based on sverb's design. Sync is optional; everything works offline without an account. |
| D13 | sverb code | sverb's vault, crypto, store, protocol and sync code is **copied and adapted** into courier-ftp crates (no dependency on sverb). |
| D14 | Teams | **Team/shared vaults are included** (orgs, invites, grants, safety numbers, key rotation). |
| D15 | CI and tests | **Same workflows and test approach as sverb** (T00, T76): full CI job set, nightly fuzz and benchmarks, reproducible releases, Docker e2e crate with server profiles, snapshot tests at 80×24 and 160×48. Plus a Windows/macOS test job (our addition). |

### Choices made during implementation

Smaller calls made while building, recorded so they can be revisited:

- **T00** MSRV is Rust **1.96** (vergen 10.0.3 needs it). Man page and completions use `clap_mangen`/`clap_complete` instead of sverb's hand-written generator. The built-in config moved to `crates/courier-ftp/config/default.json` so `cargo package` works (D10).
- **T03** `Backend` uses `async-trait`: native `async fn` in traits is not dyn-compatible. `BackendFactory::create` also takes the `SessionId` the backend logs under.
- **T05** Settings load leniently: a field with a wrong type or out-of-range value is replaced by its default and reported (`Settings::from_value`), so a bad config never stops startup.
- **T50** Explorer layout puts each directory tree beside its file list; Classic puts it above. The plan's `Home` component and the template `Component` trait are replaced by a `ui` module (`MainScreen`, layout, focus, modal stack).
- **T51** Keymaps have context modes (`FileList`, `Queue`, `Log`) that fall back to the global `Normal` map; text input and dialogs don't fall back. Disconnect is `<Ctrl-x><d>`. Bad or conflicting bindings are skipped with a warning instead of stopping startup. `Ctrl-j`/`Ctrl-h` get alternates (`Alt-j`, `.`) because many terminals send them as Enter/Backspace.
- **T57** Backends report connection details through `Backend::session_info()` (default `None`) as a `SessionInfo`; the status bar and server info dialog read it. New setting `interface.unicode_symbols` (auto/unicode/ascii). New keys: `<Ctrl-x><i>` server info, `<Ctrl-x><t>` transfer type, `<Ctrl-x><l>` speed limit.
- **T53** Pane effects (listing requests, dialogs) go through an outbox the app drains after each event. New settings `interface.natural_sort` and `interface.columns`. New keys in file lists: `[`/`]` and `Alt-←`/`Alt-→` history, `C` column menu. The 100k-entry render gate is a release-only test run by `bench.yml`.
- **T47** A filter has one `scope` field (both / local only / remote only) instead of two booleans. A filter without conditions never matches.
- **T07** SOCKS and HTTP CONNECT are hand-written (no `tokio-socks`) so replies are read exactly and `connect_tcp` returns a plain `TcpStream`. It takes a `CancellationToken` and `SessionId`. Host names go to the proxy unresolved (SOCKS4a/SOCKS5 domain). The proxy password comes from the vault via `NetOpts::set_proxy_password`, not settings. Neither proxy user nor password is logged.
- **T69** Prompts open one at a time, only when no dialog is open, the user isn't typing and no key was pressed for 1 s, so a stray Enter can't answer them; `<Ctrl-x><p>` opens the next at once. Unknown host key defaults to *OK* with "Always trust" ticked (trust on first use); changed keys and certificates default to *Cancel* and need an "I have verified" checkbox. "Always trust" is unavailable while the vault is locked (`can_remember`). Server identity types live in `model::server_identity`.
- **T13** Formats are auto-detected (Unix, DOS, MLSD-style, EPLF, VMS, NetWare, AS/400, MVS), then the last matching format is tried first. Year inference picks the most recent date at most one day after server "now". The site offset applies to LIST times only (MLSD/EPLF are UTC; an explicit `--full-time` zone wins). Symlinks split at the first ` -> `. VMS keeps only the newest version, size = blocks × 512. With `Charset::Auto` each line falls back to Windows-1252 on its own. The Unix `ls` parser lives in core (`listing::unix`) for SFTP to reuse.
- **T80** sverb's `share` and `recording` modules aren't ported; `WrapPurpose::RecordingKey` became `Device`. The wrap AAD label is `courier-ftp-wrap-v1`. `KdfParams` is a strict CBOR map replacing sverb's fixed 28-byte encoding. `Argon2Cost::TEST` exists only behind feature `insecure-test-ksf` (dev-only). Randomized functions keep sverb's explicit `rng` argument. The envelope takes already-encoded CBOR bytes (`ItemBody` is T81's). `check-vet-crypto.py` warns instead of failing until `supply-chain/` exists (T91; `VET_CRYPTO_STRICT=1` makes it fail).
- **T20** russh uses ring instead of aws-lc-rs (no aws-lc build on Windows). PPK is decoded by `ssh-key`'s built-in support, with Argon2 parameter limits. Inactivity timeout is the larger of `timeout_secs` and 4 × keepalive, so idle sessions aren't dropped. "Remember for this session" is a caller-supplied in-memory `CredentialCache` that keeps a secret only after it authenticates; the UI checkbox and saving to the vault are still open. RSA falls back to `ssh-rsa` only when the server sends no `server-sig-algs`. A rejected key file doesn't fall back to password. Server text is stripped of control characters and capped at 2048 chars.
- **T21** `HostKeyStore` is async so the vault (T30) can implement it over SQLite; `HostKeyStoreSlot` swaps the vault store in after unlock. Core has its own `HostKey` (algorithm + wire blob) and stays free of russh. One key per (host, port, key type); a host known only under other algorithms counts as unknown, not changed. `@revoked` beats everything. known_hosts is re-read on each connect and never copied into the store or written. No CheckHostIP. If saving an "Always" answer fails, the key is trusted for the session and the error logged.
- **T22** Uses russh-sftp's raw request API with its own pipelined streams (the high-level `SftpSession` drops `longname`, extensions and posix-rename). `rename` overwrites like `rename(2)` (posix-rename, else remove then rename), so the UI must confirm first. `ResumeAt(n)` truncates the remote file to n first. Names are always UTF-8 over SFTP; a site charset doesn't apply. Pipeline sizes are constants (64 in flight, server limit up to 255 KiB, 16 MiB window); no `sftp.*` settings yet. `SftpBackendFactory` covers SFTP only and takes an `Arc<dyn HostKeyVerifier>`.
- **T81** Enum values inside item fields are snake_case (matching `Protocol`/`LogonType` serde); kinds are kebab-case. Site logon is stored flat under `logon.*` so a site can point at a vault `ssh-key` item. `logon.key_path` syncs (T31 may make it device-local). Bookmarks gained a `position` sort key; folder expansion is UI state, not stored.
- **T82** Every local write marks the item dirty and queues it in the outbox. Local writes accept only v1 envelopes, so plaintext can never be stored; `apply_remote` stays lenient for newer clients. `pinned_keys` uses sverb's fuller layout. sverb's in-memory approvals layer and health check aren't ported. std locks instead of `parking_lot`. rusqlite uses `bundled` SQLite.
- **T58** The bar lives in `ui/quickconnect.rs`. A pasted URL is split into fields when focus leaves Host. Focus moves to the remote list after connecting so prompts can open. Reconnect history is in memory without the password (it's asked again); persisted history is T33's. SFTP with no user logs in as the local user; no agent-first. FTP/FTPS go through an `Unsupported` backend until T14. The first listing loads before "connected" is shown, falling back to home if the start path is missing. Listings are tagged with their session id so late results are dropped.
- **T30** `VaultEngine` lives in `courier-ftp-store::vault` because the store already depends on core; core keeps the I/O-free logic, an `ItemVault` trait for its callers, and `VaultHostKeyStore`. The OS keyring is the `keyring` crate behind the store's default `os-keyring` feature (`COURIER_FTP_KEYRING=off` disables it). `vault.store_passwords = false` erases stored passwords. Suspend is detected as a wall-clock jump over 60 s beyond monotonic time. Certificate trust store deferred to T12, device-local data key to T40, memory locking to T91.
- **T60** Vault screens are a full-screen view, not a modal; the panes are hidden, the status bar stays, and no prompts open over it. Every engine call runs in a background task so drawing never waits on Argon2. The keyring probe (which writes a test entry) runs only at first-run setup. "Start a new empty vault" renames the old database and WAL files to `courier-ftp.db.moved-<unix secs>`; nothing is deleted. Esc doesn't skip first-run setup. Masked inputs zeroize their buffer on clear and drop. New keys `<Ctrl-x><v>` lock and `<Ctrl-x><u>` unlock.
- **T91** `supply-chain/` was generated with cargo-vet 0.10.2 using sverb's audit imports; unaudited crates (including the crypto crates) are exemptions, so `check-vet-crypto.py` stays in warning mode. Each fuzz body is a hidden `pub fn fuzz_*` in its own crate so the fuzz target and its proptest run the same code. Key fuzzing never decrypts (bcrypt/Argon2 are slow by design). `sanitize_name` maps `.`/`..` to `_`/`__`. Canary fixtures are rewritten under `target/tmp` on every run so CI's `--require-files` always has files to scan.
- **T48** Comparison rows have their own order (name, dirs first); the pane's sort column doesn't apply while comparing. A directory and a file with the same name don't pair. A missing size or time gives `Unknown`. Time comparison truncates both to the coarser precision in a common offset, and times within the threshold (inclusive) are equal. Only the newer side turns green; a size difference turns both red. `natural_cmp` moved to core so panes and comparison sort alike.
- **T83** Proto depends only on crypto (the server must not link client crates), so ids on the wire are plain `Uuid`s. Proto may not pull in tokio/hyper/axum/reqwest (checked by layering). Timestamps are RFC 3339 via `time`. base64url uses `base64ct` with strict decoding. Version 0 is rejected; a missing version header means current. Tokens are plain strings with redacted `Debug`; clients move them into `SecretString` on receipt. Unknown fields are ignored, so new optional fields don't bump the version.
- **T10** The reply parser keeps its own buffer (no `BufReader`) so the stream can be swapped for TLS without losing bytes. A cancelled wait leaves the connection open and the late reply is dropped by the next command; a cancelled or timed-out write closes it. "Ask for password" and Interactive prompt before connecting (FTP has no challenge-response). CLNT goes before `OPTS UTF8 ON`. With Auto charset commands are UTF-8; a fixed charset is never switched. Keep-alive picks NOOP/PWD/TYPE at random like FileZilla. `raw_command` refuses data-channel and TLS commands, and CR/LF/NUL.
- **T54** Trees list directories only while on screen (requests gathered at draw time). The current directory and its ancestors are expanded; hidden directories on that path stay visible. New key `T` (`FocusTree`) switches between a list and its tree. Tree listing errors show `!` and are logged at debug; expanding again retries. On Windows the drive-list root is labelled "Computer", with Home and Desktop shortcuts above it.
- **T31** Names are unique within a folder so path lookup is unambiguous; copies are named "X (copy)", "X (copy) (2)". A local key file path is device-local (store migration 2); a vault `ssh-key` item syncs and wins over a local path. `SiteManager` runs each operation on a copy of the tree and re-reads written items, so the tree shows what is stored. `ConnectInfo` gained `key_passphrase` and `try_agent_first`, and `KeySource::Vault` carries the key text. Account logon with no stored password connects as "ask for password". Moving between vaults is refused.
- **T40** Device blobs are sealed under a random device key wrapped by the LMK (`meta.device_key_wrapped`), created on first save, and bound to the device id and blob name. The engine implements core's `DeviceBlobVault`. While the vault is locked nothing is saved (no plaintext fallback), and saves wait until `restore()` ran so an unloaded queue is never overwritten; a later restore merges. Turning `queue.persist` off deletes the saved queue. Active items are stored as queued; progress isn't saved. New setting `queue.max_successful`.

## Phases and tasks

### A. Foundation
- [00 CI/CD workflows](00-ci-cd-workflows.md) — **first task**
- [01 Workspace and crate layout](01-workspace-and-crates.md)
- [02 Core domain model](02-core-domain-model.md)
- [03 Backend trait](03-backend-trait.md)
- [04 Event and log bus](04-event-and-log-bus.md)
- [05 Settings model](05-settings-model.md)
- [06 Local filesystem backend](06-local-filesystem-backend.md)
- [07 Network layer: sockets, IPv6, generic proxies](07-network-and-proxy-layer.md)

### B. FTP / FTPS (own implementation)
- [10 FTP control connection](10-ftp-control-connection.md)
- [11 FTP data connections and transfer modes](11-ftp-data-connections.md)
- [12 FTPS (TLS)](12-ftps-tls.md)
- [13 FTP directory listing parsers](13-ftp-listing-parsers.md)
- [14 FTP operations and Backend impl](14-ftp-operations-backend.md)
- [15 FTP proxies](15-ftp-proxies.md)

### C. SFTP
- [20 SSH connection and authentication](20-ssh-connection-auth.md)
- [21 SSH host key verification](21-ssh-host-key-trust.md)
- [22 SFTP operations and Backend impl](22-sftp-operations-backend.md)

### D. Vault, sites, bookmarks
- [30 Vault](30-vault.md)
- [31 Site model and storage](31-site-model-and-storage.md)
- [32 Site import / export (incl. FileZilla XML)](32-site-import-export.md)
- [33 Bookmarks and connection history](33-bookmarks-and-history.md)

### E. Transfers and file logic (core)
- [40 Queue model and persistence](40-queue-model-persistence.md)
- [41 Transfer engine](41-transfer-engine.md)
- [41b Fast transfers: parallelism, segmented files, pipelining](41b-fast-transfers.md)
- [42 File-exists policy, resume, transfer options](42-file-exists-and-resume.md)
- [43 Recursive operations](43-recursive-operations.md)
- [44 Speed limits](44-speed-limits.md)
- [45 Queue completion actions](45-queue-completion-actions.md)
- [46 Directory listing cache](46-listing-cache.md)
- [47 Filename filter engine](47-filter-engine.md)
- [48 Directory comparison engine](48-directory-comparison-engine.md)
- [49 Search engine](49-search-engine.md)

### F. TUI
- [50 App shell and layout](50-app-shell-layout.md)
- [51 Keybindings (hybrid)](51-keybindings.md)
- [52 Dialog and form framework](52-dialog-framework.md)
- [53 File list pane](53-file-list-pane.md)
- [54 Directory tree pane](54-directory-tree-pane.md)
- [55 Message log pane](55-message-log-pane.md)
- [56 Queue pane](56-queue-pane.md)
- [57 Status bar](57-status-bar.md)
- [58 Quickconnect bar](58-quickconnect-bar.md)
- [59 Site Manager screen](59-site-manager-ui.md)
- [60 Vault unlock, keyring and recovery UI](60-vault-unlock-ui.md)
- [61 Connection tabs](61-connection-tabs.md)
- [62 File operations UI](62-file-operations-ui.md)
- [63 View / edit files externally](63-view-edit-files.md)
- [64 Bookmarks UI](64-bookmarks-ui.md)
- [65 Search UI](65-search-ui.md)
- [66 Directory comparison and synchronized browsing UI](66-compare-and-sync-browsing-ui.md)
- [67 Filters UI](67-filters-ui.md)
- [68 Settings screen](68-settings-ui.md)
- [69 Trust prompts (host keys and certificates)](69-trust-prompts-ui.md)

### G. App-level
- [70 Command-line arguments](70-cli-arguments.md)
- [71 Log to file, debug levels, raw listing](71-file-logging-and-diagnostics.md)
- [72 Network configuration wizard](72-network-wizard.md)
- [73 Settings import / export](73-settings-import-export.md)
- [74 Update check and splash screen](74-update-check-and-splash.md)
- [75 Internationalisation](75-i18n.md)
- [76 Test strategy and e2e harness](76-integration-test-harness.md)
- [77 Documentation and release](77-docs-and-release.md)

### H. Sync, accounts and teams (sverb-based)
T80–T82 are also needed by the local vault (T30), so they come early.
- [80 Crypto crate](80-crypto-crate.md)
- [81 Item model, HLC and merge](81-item-model-hlc-merge.md)
- [82 Local store (SQLite)](82-local-store.md)
- [83 Sync protocol types](83-sync-protocol-types.md)
- [84 Sync server: accounts, login and devices](84-sync-server-auth.md)
- [85 Sync server: vaults, pull/push and live updates](85-sync-server-vaults.md)
- [86 Sync server: configuration, admin CLI and deployment](86-sync-server-ops.md)
- [87 Sync client: account, devices and recovery](87-sync-client-account.md)
- [88 Sync engine: pull, push and live updates](88-sync-engine.md)
- [89 Teams and shared vaults](89-team-vaults.md)
- [90 Sync and teams UI](90-sync-ui.md)
- [91 Security hardening and threat model](91-security-hardening.md)

## Milestones (build order)

Within a milestone the tasks are listed in a valid order (each task after its hard dependencies). Tasks on separate lines without a dependency between them can be done in parallel.

### M1 — Foundation and local browsing
1. [T00 CI/CD workflows (sverb parity)](00-ci-cd-workflows.md)
1. [T01 Workspace and crate layout](01-workspace-and-crates.md)
1. [T02 Core domain model](02-core-domain-model.md)
1. [T05 Settings model](05-settings-model.md)
1. [T04 Event and log bus](04-event-and-log-bus.md)
1. [T47 Filename filter engine](47-filter-engine.md)
1. [T03 Backend trait](03-backend-trait.md)
1. [T50 App shell and layout](50-app-shell-layout.md)
1. [T06 Local filesystem backend](06-local-filesystem-backend.md)
1. [T46 Directory listing cache](46-listing-cache.md)
1. [T51 Keybindings (hybrid)](51-keybindings.md)
1. [T52 Dialog and form framework](52-dialog-framework.md)
1. [T57 Status bar](57-status-bar.md)
1. [T76 Test strategy and e2e harness (sverb parity)](76-integration-test-harness.md)
1. [T55 Message log pane](55-message-log-pane.md)
1. [T53 File list pane](53-file-list-pane.md)

### M2 — Vault and SFTP
1. [T80 Crypto crate](80-crypto-crate.md)
1. [T07 Network layer: sockets, IPv6, generic proxies](07-network-and-proxy-layer.md)
1. [T13 FTP directory listing parsers](13-ftp-listing-parsers.md)
1. [T69 Trust prompts (host keys and certificates)](69-trust-prompts-ui.md)
1. [T81 Item model, HLC and merge](81-item-model-hlc-merge.md)
1. [T20 SSH connection and authentication](20-ssh-connection-auth.md)
1. [T82 Local store (SQLite)](82-local-store.md)
1. [T21 SSH host key verification](21-ssh-host-key-trust.md)
1. [T30 Vault (local encrypted store and unlock)](30-vault.md)
1. [T22 SFTP operations and Backend impl](22-sftp-operations-backend.md)
1. [T60 Vault unlock, keyring and recovery UI](60-vault-unlock-ui.md)
1. [T91 Security hardening and threat model (sverb parity)](91-security-hardening.md)
1. [T58 Quickconnect bar](58-quickconnect-bar.md)

### M3 — FTP and FTPS
1. [T10 FTP control connection](10-ftp-control-connection.md)
1. [T11 FTP data connections and transfer modes](11-ftp-data-connections.md)
1. [T15 FTP proxies](15-ftp-proxies.md)
1. [T12 FTPS (TLS)](12-ftps-tls.md)
1. [T14 FTP operations and Backend impl](14-ftp-operations-backend.md)

### M4 — Transfers
1. [T40 Queue model and persistence](40-queue-model-persistence.md)
1. [T41 Transfer engine](41-transfer-engine.md)
1. [T42 File-exists policy, resume and transfer options](42-file-exists-and-resume.md)
1. [T43 Recursive operations](43-recursive-operations.md)
1. [T44 Speed limits](44-speed-limits.md)
1. [T56 Queue pane](56-queue-pane.md)
1. [T62 File operations UI](62-file-operations-ui.md)
1. [T41b Fast transfers: parallelism, segmented files, pipelining](41b-fast-transfers.md)
1. [T45 Queue completion actions](45-queue-completion-actions.md)

### M5 — Sites, bookmarks and tabs
1. [T31 Site model and storage](31-site-model-and-storage.md)
1. [T33 Bookmarks and connection history](33-bookmarks-and-history.md)
1. [T32 Site import / export (incl. FileZilla XML)](32-site-import-export.md)
1. [T64 Bookmarks UI](64-bookmarks-ui.md)
1. [T59 Site Manager screen](59-site-manager-ui.md)
1. [T61 Connection tabs](61-connection-tabs.md)

### M6 — Power features
1. [T48 Directory comparison engine](48-directory-comparison-engine.md)
1. [T49 Search engine](49-search-engine.md)
1. [T54 Directory tree pane](54-directory-tree-pane.md)
1. [T63 View / edit files externally](63-view-edit-files.md)
1. [T67 Filters UI](67-filters-ui.md)
1. [T68 Settings screen](68-settings-ui.md)
1. [T66 Directory comparison and synchronized browsing UI](66-compare-and-sync-browsing-ui.md)
1. [T65 Search UI](65-search-ui.md)

### M7 — Sync between your devices
1. [T83 Sync protocol types](83-sync-protocol-types.md)
1. [T84 Sync server: accounts, login and devices](84-sync-server-auth.md)
1. [T85 Sync server: vaults, pull/push and live updates](85-sync-server-vaults.md)
1. [T86 Sync server: configuration, admin CLI and deployment](86-sync-server-ops.md)
1. [T87 Sync client: account, devices and recovery](87-sync-client-account.md)
1. [T88 Sync engine: pull, push and live updates](88-sync-engine.md)
1. [T90 Sync and teams UI](90-sync-ui.md)

### M8 — Teams
1. [T89 Teams and shared vaults](89-team-vaults.md)

### M9 — Polish and release
1. [T70 Command-line arguments](70-cli-arguments.md)
1. [T71 Log to file, debug levels, raw listing](71-file-logging-and-diagnostics.md)
1. [T72 Network configuration wizard](72-network-wizard.md)
1. [T73 Settings import / export](73-settings-import-export.md)
1. [T74 Update check and splash screen](74-update-check-and-splash.md)
1. [T75 Internationalisation](75-i18n.md)
1. [T77 Documentation and release](77-docs-and-release.md)

Notes:
- T76 (tests) and T91 (security) start in M1/M2 and grow with later milestones; T00 jobs are switched on as their features land.
- T69 builds each prompt when its producer exists (SFTP in M2, certificates in M3, file-exists in M4).

## Project-wide rules

- `courier-ftp-core`, the protocol crates, crypto, store, proto, sync and server crates never depend on `ratatui`, `crossterm` or `clap`.
- The client must work fully without a sync server; sync is an optional cargo feature (`sync`, default on).
- No `unwrap()`/`expect()` on anything that can fail at runtime (network, files, user input). Tests are exempt.
- Secrets (`Password`, key passphrases, the vault key) are wrapped in `secrecy::SecretString`/`zeroize` types and never logged, even at debug level. Log lines that would contain `PASS` must be masked (`PASS ****`).
- Every network operation has a timeout and is cancellable via `tokio_util::sync::CancellationToken`.
- Paths: remote paths are always a dedicated `RemotePath` type, never `std::path::Path` (see T02).
- Windows, macOS and Linux are all supported targets (the CD workflow already builds all three).
