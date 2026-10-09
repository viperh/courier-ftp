# Open questions
Product decisions collected from the task files. Implementation uses the default each task states ("current"/"assumed") until the owner decides; change a default by answering here and updating the task.

## [T00 — CI/CD workflows (sverb parity)](00-ci-cd-workflows.md)
- **i686 Linux builds**: the template builds `i686-unknown-linux-gnu`; sverb parity drops it. Keep dropped? (Assumed: dropped.)
- **Nix flake**: sverb ships `flake.nix` and a `nix` CI job; courier-ftp has no flake planned. Add one for parity?
- **Package channel names**: the Homebrew tap `<owner>/homebrew-courier-ftp` and Scoop bucket `<owner>/scoop-courier-ftp` repositories must be created by the owner before the first release.

## [T02 — Core domain model](02-core-domain-model.md)
- `FtpEncryption::PlainOnly` has no URL scheme (FileZilla has none either), so a copied URL

## [T04 — Event and log bus](04-event-and-log-bus.md)
- **File-exists answer scoped to the current queue run / session:** `ApplyTo` offers `Once`,

## [T05 — Settings model](05-settings-model.md)
- `ftp.send_keepalive_command` default is `noop`. FileZilla rotates NOOP/PWD/TYPE at random
- Default for `logging.level` is 2 (Info) as in the original plan; FileZilla's default is 0
- `queue.notify` default is `bell`. OSC 9/777 desktop notifications are opt-in because some

## [T06 — Local filesystem backend](06-local-filesystem-backend.md)
- Non-UTF-8 local file names are hidden (with a count in the log) because every layer uses

## [T07 — Network layer: sockets, IPv6, generic proxies](07-network-and-proxy-layer.md)
- Should courier-ftp also honour the `ALL_PROXY`/`HTTPS_PROXY` environment variables or the

## [T10 — FTP control connection](10-ftp-control-connection.md)
- T05 keeps `ftp.send_keepalive_command` default `noop`. FileZilla rotates `NOOP`/`PWD`/

## [T11 — FTP data connections and transfer modes](11-ftp-data-connections.md)
- PASV replies naming a **different public IP** than the control peer are always replaced

## [T12 — FTPS (TLS)](12-ftps-tls.md)
- `trusted-cert` items sync through the vault (D4). Should trusted certificates stored in a

## [T20 — SSH connection and authentication](20-ssh-connection-auth.md)
1. **MSRV:** russh 0.64.1 declares `rust-version = 1.89`; the workspace says `1.85`
2. **Legacy servers:** should a site be able to opt into CBC ciphers, `ssh-dss` and
3. **`ssh-rsa` (SHA-1) fallback** is used automatically for servers without

## [T21 — SSH host key verification](21-ssh-host-key-trust.md)
1. Should keys found in `~/.ssh/known_hosts` be offered for one-click import into the
2. Should "Always trust" be pre-checked in the prompt (T69 currently pre-checks it when

## [T22 — SFTP operations and Backend impl](22-sftp-operations-backend.md)
1. **Non-UTF-8 names:** `russh-sftp` 3.0.1 decodes names with `String::from_utf8_lossy`,

## [T30 — Vault (local encrypted store and unlock)](30-vault.md)
1. When the user turns `vault.store_passwords` off, should existing saved passwords be deleted

## [T32 — Site import / export (incl. FileZilla XML)](32-site-import-export.md)
1. Should v1 decrypt FileZilla passwords protected by FileZilla's master password
2. FEATURES §2 says "import from other clients". Which clients besides FileZilla should be
3. Should the FileZilla XML export offer to include passwords (FileZilla's own export writes them

## [T40 — Queue model and persistence](40-queue-model-persistence.md)
1. Should FileZilla's exported queue XML be importable (FEATURES §5 says "import and

## [T41 — Transfer engine](41-transfer-engine.md)
2. Product: should a learned connection limit be remembered across restarts (per site,
3. Product: when connecting to a server fails (after T03's connect retries), this spec

## [T41b — Fast transfers: parallelism, segmented files, pipelining](41b-fast-transfers.md)
1. Hash verification after segmented transfers: T10 parses FTP `HASH` support and T22

## [T42 — File-exists policy, resume and transfer options](42-file-exists-and-resume.md)
1. FileZilla's dialog has "Apply to current queue only"; unchecked, the answer applies

## [T43 — Recursive operations](43-recursive-operations.md)
1. With `follow_symlinks = false`, symlinks to directories are skipped with a Status

## [T44 — Speed limits](44-speed-limits.md)
1. With a low limit, the SFTP pipeline (T22: up to 8 MiB in flight per stream) lets the

## [T45 — Queue completion actions](45-queue-completion-actions.md)
1. `queue.notify` is used only together with `ShowMessage` in this spec (default

## [T46 — Directory listing cache](46-listing-cache.md)
- Should the cache also be cleared when the last session to a server disconnects? FileZilla keeps it so reconnecting is instant; this task keeps it (cleared only on lock and quit). Product decision for the owner.

## [T48 — Directory comparison engine](48-directory-comparison-engine.md)
- FileZilla's time mode, as far as documented, compares only dates; rule 8 (equal time

## [T50 — App shell and layout](50-app-shell-layout.md)
- Explorer layout stacks local over remote with trees on the left (closest to

## [T53 — File list pane](53-file-list-pane.md)
1. FileZilla offers three folder placements (first / inline / always on top); T05 has only `dirs_first: bool`. This task maps `true` to "always on top". Should the three-way option be added?

## [T58 — Quickconnect bar](58-quickconnect-bar.md)
1. **SFTP without a user name:** this task requires a user name (error). Should it

## [T59 — Site Manager screen](59-site-manager-ui.md)
1. Default local dir is device-local (T31 §4), so on a second device the field is empty. Should the editor show the value from the device that created the site as a hint?

## [T60 — Vault unlock, keyring and recovery UI](60-vault-unlock-ui.md)
1. sverb's `Ctrl-r` goes straight to keyring unlock; this task shows a "Forgot password" chooser first because courier-ftp has more recovery paths (sync key, backup, new vault). Confirm this deviation.
2. T30 lists "Continue without vault" but does not say whether a vault can later be created from that mode on first run (no vault exists yet). This task shows the first-run screen again at the next start only. Should "Create vault" also be offered inside the running session?

## [T61 — Connection tabs](61-connection-tabs.md)
1. Should tab state restore also reconnect automatically (current design), or open the tabs disconnected and let the user press `Ctrl-x r`? Automatic reconnects to many servers at startup may be unwanted.

## [T62 — File operations UI](62-file-operations-ui.md)
1. **Local delete to trash**: FileZilla on Windows uses the recycle bin. Should

## [T63 — View / edit files externally](63-view-edit-files.md)
1. Should FileZilla-style default associations ship (e.g. images → platform opener),

## [T64 — Bookmarks UI](64-bookmarks-ui.md)
1. Should a global bookmark's local dir also be device-local (like site bookmarks),

## [T65 — Search UI](65-search-ui.md)
1. Should search results also be exportable (e.g. copy all paths to the clipboard

## [T68 — Settings screen](68-settings-ui.md)
1. Should turning off `vault.store_passwords` delete already saved passwords from

## [T69 — Trust prompts (host keys and certificates)](69-trust-prompts-ui.md)
1. **File-exists "remember":** FileZilla can also turn the chosen action into the new
2. **"Always trust" pre-checked:** the unknown host key and certificate dialogs

## [T72 — Network configuration wizard](72-network-wizard.md)
- **Probe server**: FileZilla's wizard tests against its own probe server, which can check
- **IP lookup URL**: FileZilla ships a default lookup URL on its own domain. Should

## [T74 — Update check and splash screen](74-update-check-and-splash.md)
- **Default of `interface.check_updates`**: T05 sets it to `true` (FileZilla behaviour),

## [T75 — Internationalisation](75-i18n.md)
- **Second language**: which language should be implemented as the proof translation —
- This task changes T04's `LogMessage::text` from `String` to `LogText` (with

## [T77 — Documentation and release](77-docs-and-release.md)
- **winget / Debian / Fedora packages:** add more channels after 1.0, or before?
- **Demo GIF:** is a VHS GIF in the README wanted, or a static screenshot only (smaller repository)?
- **1.0 scope statement:** which FEATURES.md items may ship as "later" in 1.0 (the README status table needs the owner's list)?
- **Dependency change (reported):** T70 added to **Depends on** because the man page and completions in the release archives come from T70's `generate` subcommand (this task originally generated the man page itself).

## [T84 — Sync server: accounts, login and devices](84-sync-server-auth.md)
- **Registration reveals existing emails** (409 `email already registered`) in `open` mode.

## [T85 — Sync server: vaults, pull/push and live updates](85-sync-server-vaults.md)
- **Team vault quota.** Team vaults are capped at 1 GiB each and not counted against any

## [T87 — Sync client: account, devices and recovery](87-sync-client-account.md)
- **Self-signed sync servers.** Only OS-trusted certificates are accepted. Should a
- **Headless sync commands** (`courier-ftp sync --now|--status`, `logout`) like sverb's

## [T89 — Teams and shared vaults](89-team-vaults.md)
- **Unsynced edits in a vault whose access was revoked** are discarded (with a toast giving the

## [T90 — Sync and teams UI](90-sync-ui.md)
- **Copying invite links.** T55 provides `crate::ui::clipboard` (OSC 52 + platform tools).

## [T91 — Security hardening and threat model (sverb parity)](91-security-hardening.md)
- **PASV to a different routable address:** T11 replaces only *unroutable* PASV addresses. A malicious server can make the client connect to any routable host:port (FTP "PASV bounce"/port scanning through the client). FileZilla accepts it by default. Should courier-ftp always use the control peer's address unless the user enables "allow PASV to other hosts" per site? (Owner of T11 to implement whichever is chosen.)
- **Vulnerability contact:** `SECURITY.md` uses GitHub private vulnerability reporting. Should an email address be listed as well?
- **cargo-vet strictness:** crypto/TLS/SSH crates are exempted (CI warning). When should `VET_CRYPTO_STRICT=1` become mandatory (before 1.0, or later)?
- **Inconsistency (T71, not owned here):** T71 (M9) implements the logging pipeline and crash reports, but this task's rules apply from M2. Until T71 lands, S1 enforces §4 on the template logger (`<data>/courier-ftp.log`, single file); T71 must keep `logging_policy.rs` and `canary.rs` green.
