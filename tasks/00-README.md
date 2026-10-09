# courier-ftp task list

courier-ftp is a terminal (TUI) replacement for the FileZilla client. Every task in
this folder traces back to a section of [`../FEATURES.md`](../FEATURES.md).

## How to use these files

- One file per task. The number is the task ID (`T13` = `13-*.md`).
- Each task has: **Goal**, **Depends on**, **Crate(s)**, **FEATURES.md refs**,
  **Scope** (step by step), **Design notes**, **Acceptance criteria**, **Tests**
  and **Out of scope**.
- Tick acceptance-criteria boxes in the file as they are met. A task is done when
  every box is ticked and the four CI gates pass (`cargo test`, `fmt`, `clippy -D warnings`, `doc -D warnings`).
- Tasks within a phase can mostly run in parallel once their dependencies are done.
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
| D10 | App settings | Non-secret settings stay in the existing layered config (`.config/config.json` defaults + user `config.*`). |
| D11 | Speed | Transfers run in parallel (4 by default) and large files are split into ranges over several connections, with SFTP request pipelining (T41b). |
| D12 | Sync | Device sync through **courier-ftp's own self-hosted server** (`courier-ftp-server`: axum + PostgreSQL), end-to-end encrypted, OPAQUE login with the master password, based on sverb's design. Sync is optional; everything works offline without an account. |
| D13 | sverb code | sverb's vault, crypto, store, protocol and sync code is **copied and adapted** into courier-ftp crates (no dependency on sverb). |
| D14 | Teams | **Team/shared vaults are included** (orgs, invites, grants, safety numbers, key rotation). |
| D15 | CI and tests | **Same workflows and test approach as sverb** (T92, T76): full CI job set, nightly fuzz and benchmarks, reproducible releases, Docker e2e crate with server profiles, snapshot tests at 80×24 and 160×48. Plus a Windows/macOS test job (our addition). |

## Phases and tasks

### A. Foundation
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
- [60 Vault unlock and master password UI](60-vault-unlock-ui.md)
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
- [92 CI/CD workflows](92-ci-cd-workflows.md)

## Suggested order / milestones

1. **M1 – Browse locally:** 01, 92 (CI from day one), 76 (test crate skeleton), 02–06, 50–53, 55, 57.
2. **M2 – Vault and SFTP:** 80–82, 30, 60, 91 (hardening, unsafe/canary/deny CI from the start), 07, 20–22, 69, 58.
3. **M3 – FTP/FTPS:** 10–14, 76.
4. **M4 – Transfers:** 40–46, 41b, 56, 62.
5. **M5 – Sites:** 31–33, 59, 61, 64.
6. **M6 – Power features:** 47–49, 54, 63, 65–68, 15.
7. **M7 – Sync:** 83–88, 90 (personal sync between your devices).
8. **M8 – Teams:** 89 and the team parts of 90.
9. **M9 – Polish:** 70–75, 77.

## Project-wide rules

- `courier-ftp-core`, the protocol crates, crypto, store, proto, sync and server crates never depend on `ratatui`, `crossterm` or `clap`.
- The client must work fully without a sync server; sync is an optional cargo feature (`sync`, default on).
- No `unwrap()`/`expect()` on anything that can fail at runtime (network, files, user input). Tests are exempt.
- Secrets (`Password`, key passphrases, the vault key) are wrapped in `secrecy::SecretString`/`zeroize` types and never logged, even at debug level. Log lines that would contain `PASS` must be masked (`PASS ****`).
- Every network operation has a timeout and is cancellable via `tokio_util::sync::CancellationToken`.
- Paths: remote paths are always a dedicated `RemotePath` type, never `std::path::Path` (see T02).
- Windows, macOS and Linux are all supported targets (the CD workflow already builds all three).
