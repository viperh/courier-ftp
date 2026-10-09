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
| D3 | Secrets | **Vault** file encrypted with a key derived by **Argon2id**. The vault is unlocked automatically through the **OS keyring** when one is available; otherwise (or if the user prefers) with a **master password**. |
| D4 | Site storage | **Sites live in the vault** (encrypted), not in a plain config file. Bookmarks, quickconnect history, trusted host keys/certificates and the persisted queue are encrypted with the same vault key. |
| D5 | Crate layout | **Separate protocol crates**: `courier-ftp-proto-ftp`, `courier-ftp-proto-sftp`, both implementing a `Backend` trait from `courier-ftp-core`. |
| D6 | Keybindings | **Hybrid**: Midnight Commander F-keys (F5 copy, F6 move, F7 mkdir, F8 delete, Tab switch pane) plus vim motions (`j/k/h/l`, `gg/G`, `/`). All rebindable. |
| D7 | Mouse | **Keyboard only** for v1. Mouse capture stays off. |
| D8 | Dropped features | Kerberos/GSS auth, OS drag and drop, sound / sleep / shutdown on queue completion. No tasks exist for these. |
| D9 | TLS | `rustls` (with `rustls-platform-verifier` for OS trust roots). No OpenSSL. *(Default chosen by Claude — say so if you want it changed.)* |
| D10 | App settings | Non-secret settings stay in the existing layered config (`.config/config.json` defaults + user `config.*`). |

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
- [76 Integration test harness](76-integration-test-harness.md)
- [77 Documentation and release](77-docs-and-release.md)

## Suggested order / milestones

1. **M1 – Browse locally:** 01–06, 50–53, 55, 57.
2. **M2 – Browse remotely (SFTP first, it's simpler):** 07, 20–22, 69, 58, 30, 60.
3. **M3 – FTP/FTPS:** 10–14, 76.
4. **M4 – Transfers:** 40–46, 56, 62.
5. **M5 – Sites:** 31–33, 59, 61, 64.
6. **M6 – Power features:** 47–49, 54, 63, 65–68, 15.
7. **M7 – Polish:** 70–75, 77.

## Project-wide rules

- `courier-ftp-core` and the protocol crates never depend on `ratatui`, `crossterm` or `clap`.
- No `unwrap()`/`expect()` on anything that can fail at runtime (network, files, user input). Tests are exempt.
- Secrets (`Password`, key passphrases, the vault key) are wrapped in `secrecy::SecretString`/`zeroize` types and never logged, even at debug level. Log lines that would contain `PASS` must be masked (`PASS ****`).
- Every network operation has a timeout and is cancellable via `tokio_util::sync::CancellationToken`.
- Paths: remote paths are always a dedicated `RemotePath` type, never `std::path::Path` (see T02).
- Windows, macOS and Linux are all supported targets (the CD workflow already builds all three).
