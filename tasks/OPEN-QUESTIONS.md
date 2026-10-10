# Open questions

Product decisions collected from the task files. Implementation uses the default each task states ("current", "assumed", "default") until the owner decides. To change one, answer it here and update the task.

## [T00 — CI/CD workflows (sverb parity)](00-ci-cd-workflows.md)

- **i686 Linux builds**: the template builds `i686-unknown-linux-gnu`; sverb parity drops it. Keep dropped? (Assumed: dropped.)
- **Nix flake**: sverb ships `flake.nix` and a `nix` CI job; courier-ftp has no flake planned. Add one for parity?
- **Package channel names**: the Homebrew tap `<owner>/homebrew-courier-ftp` and Scoop bucket `<owner>/scoop-courier-ftp` repositories must be created by the owner before the first release.

## [T02 — Core domain model](02-core-domain-model.md)

- `FtpEncryption::PlainOnly` has no URL scheme (FileZilla has none either), so a copied URL of a plain-only site reopens as "explicit TLS if available". Is that acceptable, or do you want a courier-ftp-specific scheme (e.g. `ftp+plain://`)?

## [T04 — Event and log bus](04-event-and-log-bus.md)

- **File-exists answer scoped to the current queue run / session:** `ApplyTo` offers `Once`, `AllInQueue` and `AllForDirection`. FileZilla's "apply only to current queue" checkbox is removed from T69 unless a session scope is added here (e.g. `ApplyTo::Session`, forgotten when the session ends). Add it, or keep the three scopes? (Assumed: keep three.)

## [T05 — Settings model](05-settings-model.md)

- `ftp.send_keepalive_command` default is `noop`. FileZilla rotates NOOP/PWD/TYPE at random (some servers ignore NOOP for idle timeouts). Should `random` be the default?
- Default for `logging.level` is 2 (Info) as in the original plan; FileZilla's default is 0 (no debug lines). Keep 2?
- `queue.notify` default is `bell`. OSC 9/777 desktop notifications are opt-in because some terminals print the sequence. Confirm.

## [T06 — Local filesystem backend](06-local-filesystem-backend.md)

- Non-UTF-8 local file names are hidden (with a count in the log) because every layer uses `String` names. Supporting them would need a byte-string name type throughout. Is hiding acceptable for v1?

## [T07 — Network layer: sockets, IPv6, generic proxies](07-network-and-proxy-layer.md)

- Should courier-ftp also honour the `ALL_PROXY`/`HTTPS_PROXY` environment variables or the OS proxy configuration when `proxy.generic.kind = none`? FileZilla does not; this task does not.

## [T10 — FTP control connection](10-ftp-control-connection.md)

- T05 keeps `ftp.send_keepalive_command` default `noop`. FileZilla rotates `NOOP`/`PWD`/ `TYPE` because some servers don't count `NOOP` as activity. Should the default be `random`? (Setting owner: T05.)

## [T11 — FTP data connections and transfer modes](11-ftp-data-connections.md)

- PASV replies naming a **different public IP** than the control peer are always replaced with the peer address (safe default, same as curl). FileZilla connects to such addresses unless they are unroutable. Do we need a setting (e.g. `ftp.trust_pasv_address`, off by default) for server farms that really hand out another host?

## [T12 — FTPS (TLS)](12-ftps-tls.md)

- `trusted-cert` items sync through the vault (D4). Should trusted certificates stored in a **team** vault (T89) be honoured on this device, or only those in the personal vault? A teammate (or compromised account) could otherwise plant a trust decision for a host; T91 §8 covers only locally-acting fields. Same question applies to T21 `known-host` items.

## [T20 — SSH connection and authentication](20-ssh-connection-auth.md)

1. **MSRV:** russh 0.64.1 declares `rust-version = 1.89`; the workspace says `1.85` (T01/T00 own `rust-version`). Raise the workspace MSRV to at least 1.89 (sverb uses 1.95)?
2. **Legacy servers:** should a site be able to opt into CBC ciphers, `ssh-dss` and `diffie-hellman-group1-sha1` (very old embedded SFTP servers)? FileZilla still supports some of them; this task does not.
3. **`ssh-rsa` (SHA-1) fallback** is used automatically for servers without `server-sig-algs` (OpenSSH < 7.2), with a warning line. Keep automatic, or require a per-site opt-in like sverb?

## [T21 — SSH host key verification](21-ssh-host-key-trust.md)

1. Should keys found in `~/.ssh/known_hosts` be offered for one-click import into the vault (so they sync to devices without OpenSSH)? Not done in v1.
2. Should "Always trust" be pre-checked in the prompt (T69 currently pre-checks it when the vault is unlocked, as in FileZilla's dialog sketch in the original task)?

## [T30 — Vault (local encrypted store and unlock)](30-vault.md)

1. When the user turns `vault.store_passwords` off, should existing saved passwords be deleted (FileZilla asks and deletes them)? Current spec: they are kept but ignored until the user runs "Delete saved passwords" (a T68 button calling `put` with secrets cleared). Owner to decide whether turning the setting off should offer deletion immediately.

## [T32 — Site import / export (incl. FileZilla XML)](32-site-import-export.md)

1. Should v1 decrypt FileZilla passwords protected by FileZilla's master password (`encoding="crypt"`, libfilezilla public-key scheme: X25519 key pair derived from the master password with PBKDF2, AES-256-GCM)? Current spec: such passwords are not imported, the site becomes "ask for password" and the report says so.
2. FEATURES §2 says "import from other clients". Which clients besides FileZilla should be supported (FileZilla itself imports from WinSCP, CuteFTP, …)? Current spec: FileZilla only.
3. Should the FileZilla XML export offer to include passwords (FileZilla's own export writes them as base64, i.e. readable)? Current spec: never.

## [T40 — Queue model and persistence](40-queue-model-persistence.md)

1. Should FileZilla's exported queue XML be importable (FEATURES §5 says "import and export"; our export is courier-ftp JSON only)?

## [T41 — Transfer engine](41-transfer-engine.md)

2. Product: should a learned connection limit be remembered across restarts (per site, device-local)? This spec keeps it for the process lifetime only, like FileZilla.
3. Product: when connecting to a server fails (after T03's connect retries), this spec blocks the whole server group until the user presses Start again, instead of failing each item. FileZilla instead retries per item. Confirm.

## [T41b — Fast transfers: parallelism, segmented files, pipelining](41b-fast-transfers.md)

1. Hash verification after segmented transfers: T10 parses FTP `HASH` support and T22 detects SFTP `check-file`, but `Backend` has no checksum method. Add `Backend::checksum(path, range) -> Option<Digest>` (T03) and verify when available, or rely on size + unchanged-source checks only (this spec, v1)?

## [T42 — File-exists policy, resume and transfer options](42-file-exists-and-resume.md)

1. FileZilla's dialog has "Apply to current queue only"; unchecked, the answer applies for the rest of the session. T04's `ApplyTo` has only run-scoped values, so this spec offers run scope only and T69 does not show that checkbox (coordinator decision). Should a session scope be added later (T04 `ApplyTo::Session` + T69 checkbox)?

## [T43 — Recursive operations](43-recursive-operations.md)

1. With `follow_symlinks = false`, symlinks to directories are skipped with a Status line, and symlinks to files are transferred as regular files (their content). Should symlinks instead be recreated as symlinks where both sides support it (SFTP `symlink`, local)? FileZilla doesn't; this spec doesn't either.

## [T44 — Speed limits](44-speed-limits.md)

1. With a low limit, the SFTP pipeline (T22: up to 8 MiB in flight per stream) lets the network run ahead of the limit at the start of each transfer. Should T22 reduce its in-flight window when a limit is active (e.g. to 0.5 s worth of the limit), as FileZilla's fzsftp effectively does? Current spec: documented overshoot only.

## [T45 — Queue completion actions](45-queue-completion-actions.md)

1. `queue.notify` is used only together with `ShowMessage` in this spec (default `on_complete = none`, so no bell by default). Should the notification fire after every finished run regardless of the action (e.g. for runs longer than 10 s)?

## [T46 — Directory listing cache](46-listing-cache.md)

- Should the cache also be cleared when the last session to a server disconnects? FileZilla keeps it so reconnecting is instant; this task keeps it (cleared only on lock and quit). Product decision for the owner.

## [T48 — Directory comparison engine](48-directory-comparison-engine.md)

- FileZilla's time mode, as far as documented, compares only dates; rule 8 (equal time but different size → `SizeDiffers`) is an addition that flags truncated uploads. Keep it, or report `Equal` as FileZilla does? Product decision for the owner.

## [T50 — App shell and layout](50-app-shell-layout.md)

- Explorer layout stacks local over remote with trees on the left (closest to FileZilla's Explorer arrangement in a terminal). If the owner prefers side-by-side sides in Explorer too, only `compute_layout` changes. Product decision.

## [T53 — File list pane](53-file-list-pane.md)

1. FileZilla offers three folder placements (first / inline / always on top); T05 has only `dirs_first: bool`. This task maps `true` to "always on top". Should the three-way option be added?

## [T58 — Quickconnect bar](58-quickconnect-bar.md)

1. **SFTP without a user name:** this task requires a user name (error). Should it default to the local OS user name like `ssh` does?

## [T59 — Site Manager screen](59-site-manager-ui.md)

1. Default local dir is device-local (T31 §4), so on a second device the field is empty. Should the editor show the value from the device that created the site as a hint?

## [T60 — Vault unlock, keyring and recovery UI](60-vault-unlock-ui.md)

1. sverb's `Ctrl-r` goes straight to keyring unlock; this task shows a "Forgot password" chooser first because courier-ftp has more recovery paths (sync key, backup, new vault). Confirm this deviation.
2. T30 lists "Continue without vault" but does not say whether a vault can later be created from that mode on first run (no vault exists yet). This task shows the first-run screen again at the next start only. Should "Create vault" also be offered inside the running session?

## [T61 — Connection tabs](61-connection-tabs.md)

1. Should tab state restore also reconnect automatically (current design), or open the tabs disconnected and let the user press `Ctrl-x r`? Automatic reconnects to many servers at startup may be unwanted.

## [T62 — File operations UI](62-file-operations-ui.md)

1. **Local delete to trash**: FileZilla on Windows uses the recycle bin. Should local deletes go to the OS trash (`trash` crate) instead of deleting permanently? Current spec: permanent delete with explicit wording.

## [T63 — View / edit files externally](63-view-edit-files.md)

1. Should FileZilla-style default associations ship (e.g. images → platform opener), or stay empty as specified?

## [T64 — Bookmarks UI](64-bookmarks-ui.md)

1. Should a global bookmark's local dir also be device-local (like site bookmarks), since home directories differ between machines? Current spec: synced.

## [T65 — Search UI](65-search-ui.md)

1. Should search results also be exportable (e.g. copy all paths to the clipboard as a list)? Not specified by FileZilla; left out.

## [T68 — Settings screen](68-settings-ui.md)

1. Should turning off `vault.store_passwords` delete already saved passwords from all sites (FileZilla asks), or only stop saving new ones? This spec asks the user.

## [T69 — Trust prompts (host keys and certificates)](69-trust-prompts-ui.md)

1. **File-exists "remember":** FileZilla can also turn the chosen action into the new default setting, and has an "apply to current queue only" scope. T04's `ApplyTo` has only `Once`, `AllInQueue` and `AllForDirection` (this queue run), so the dialog offers no session-wide or default-changing scope. Should T04 add a session scope, or the dialog offer "Make this the default for downloads/uploads" (writes the T05 exists setting)?
2. **"Always trust" pre-checked:** the unknown host key and certificate dialogs pre-check "Always trust" when the vault is unlocked. Keep, or default to trust-once?

## [T72 — Network configuration wizard](72-network-wizard.md)

- **Probe server**: FileZilla's wizard tests against its own probe server, which can check that the server side sees the correct external address. We test only against a server the user chooses. Should courier-ftp ever host its own probe server, or is the user-chosen server enough for v1? (Current spec: user-chosen only.)
- **IP lookup URL**: FileZilla ships a default lookup URL on its own domain. Should courier-ftp suggest a third-party default (e.g. a public "what is my IP" service) in the *Get it from this URL* field, or leave it empty as specified? A default would contact a third party whenever active mode with `FromUrl` is used.

## [T74 — Update check and splash screen](74-update-check-and-splash.md)

- **Default of `interface.check_updates`**: T05 sets it to `true` (FileZilla behaviour), while sverb's policy is that the client never phones home. Keep the default `true`, or make it `false` / ask on first run? (Current spec: `true`, with the opt-outs above.)

## [T75 — Internationalisation](75-i18n.md)

- **Second language**: which language should be implemented as the proof translation — for example **Romanian** or **German**? Implementation step 9 and AC9 wait for this answer.
- This task changes T04's `LogMessage::text` from `String` to `LogText` (with `Localizable`) so core status lines can be translated; the owner of T04 should confirm, or T04 could adopt `LogText` from the start to avoid converting every producer in M9.

## [T77 — Documentation and release](77-docs-and-release.md)

- **winget / Debian / Fedora packages:** add more channels after 1.0, or before?
- **Demo GIF:** is a VHS GIF in the README wanted, or a static screenshot only (smaller repository)?
- **1.0 scope statement:** which FEATURES.md items may ship as "later" in 1.0 (the README status table needs the owner's list)?
- **Dependency change (reported):** T70 added to **Depends on** because the man page and completions in the release archives come from T70's `generate` subcommand (this task originally generated the man page itself).

## [T84 — Sync server: accounts, login and devices](84-sync-server-auth.md)

- **Registration reveals existing emails** (409 `email already registered`) in `open` mode. Accept (as sverb does) or answer `register/start` identically and fail only at `finish`?

## [T85 — Sync server: vaults, pull/push and live updates](85-sync-server-vaults.md)

- **Team vault quota.** Team vaults are capped at 1 GiB each and not counted against any user (sverb v1 decision). Is a per-org quota wanted?

## [T87 — Sync client: account, devices and recovery](87-sync-client-account.md)

- **Self-signed sync servers.** Only OS-trusted certificates are accepted. Should a per-account custom CA / certificate pin (e.g. `sync.ca_file` or TOFU like T12) be supported for servers without a public certificate?

## [T89 — Teams and shared vaults](89-team-vaults.md)

- **Unsynced edits in a vault whose access was revoked** are discarded (with a toast giving the count), as in sverb. Alternative: move them into the personal vault as copies. Which one?

## [T90 — Sync and teams UI](90-sync-ui.md)

- **Copying invite links.** T55 provides `crate::ui::clipboard` (OSC 52 + platform tools). Invite links are bearer tokens and recovery codes are secrets, so this spec shows them for manual selection only. Should T90 offer clipboard copy (with a warning) for invite links and/or recovery codes, or a "write to file" option?

## [T91 — Security hardening and threat model (sverb parity)](91-security-hardening.md)

- **PASV to a different routable address:** T11 replaces only *unroutable* PASV addresses. A malicious server can make the client connect to any routable host:port (FTP "PASV bounce"/port scanning through the client). FileZilla accepts it by default. Should courier-ftp always use the control peer's address unless the user enables "allow PASV to other hosts" per site? (Owner of T11 to implement whichever is chosen.)
- **Vulnerability contact:** `SECURITY.md` uses GitHub private vulnerability reporting. Should an email address be listed as well?
- **cargo-vet strictness:** crypto/TLS/SSH crates are exempted (CI warning). When should `VET_CRYPTO_STRICT=1` become mandatory (before 1.0, or later)?
- **Inconsistency (T71, not owned here):** T71 (M9) implements the logging pipeline and crash reports, but this task's rules apply from M2. Until T71 lands, S1 enforces §4 on the template logger (`<data>/courier-ftp.log`, single file); T71 must keep `logging_policy.rs` and `canary.rs` green.
