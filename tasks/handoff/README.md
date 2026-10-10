# Handoff: implementation status (session ending 2026-10-10)

Read this first when continuing. Branch `claude/lucid-fermat-bhtbd0`, draft PR viperh/courier-ftp#3.

## Status

- **Done and merged (31 tasks):** T00–T07, T10, T11, T13, T20, T21, T22, T30, T46, T47,
  T50–T53, T55, T57, T60, T69, T76, T80–T84. Milestone M1 is complete; M2 is mostly done.
- **CI:** fully green (Windows, macOS, Docker e2e) on `847ff5d`, which includes every
  merged task above.
- **Stopped mid-way:**
  - **T12 (FTPS/TLS):** partial work saved as `tasks/handoff/t12-ftps-wip.patch`
    (applies cleanly to `ab379a4`; unverified, gates not run). It has `TlsSession`, the
    certificate trust gate, explicit/implicit TLS, PBSZ/PROT, data TLS with session
    resumption, `CertTrustStore` with memory/switchable/vault-backed stores, and a started
    `crates/courier-ftp-e2e/tests/ftps.rs`. Next step was `TestHome::trust_cert`. Apply with
    `git apply tasks/handoff/t12-ftps-wip.patch`, then finish the spec and run the gates.
  - **T58 (quickconnect bar):** not started (no code). Restart from the task file.

## Ready to start now

| Task | Milestone | File |
|---|---|---|
| T12 | M3 | `12-ftps-tls.md` |
| T15 | M3 | `15-ftp-proxies.md` |
| T31 | M5 | `31-site-model-and-storage.md` |
| T40 | M4 | `40-queue-model-persistence.md` |
| T48 | M6 | `48-directory-comparison-engine.md` |
| T54 | M6 | `54-directory-tree-pane.md` |
| T58 | M2 | `58-quickconnect-bar.md` |
| T67 | M6 | `67-filters-ui.md` |
| T68 | M6 | `68-settings-ui.md` |
| T71 | M9 | `71-file-logging-and-diagnostics.md` |
| T72 | M9 | `72-network-wizard.md` |
| T74 | M9 | `74-update-check-and-splash.md` |
| T75 | M9 | `75-i18n.md` |
| T85 | M7 | `85-sync-server-vaults.md` |
| T91 | M2 | `91-security-hardening.md` |

Recommended order: T12 (finish from the patch) and T58 first (the app can't connect to a
server without T58), then T91, T31, T40, T14/T15, then the M6 UI tasks.

## Blocked tasks

| Task | Milestone | File | Waits on |
|---|---|---|---|
| T14 | M3 | `14-ftp-operations-backend.md` | waits on T12, T15 |
| T32 | M5 | `32-site-import-export.md` | waits on T31, T33 |
| T33 | M5 | `33-bookmarks-and-history.md` | waits on T31 |
| T41 | M4 | `41-transfer-engine.md` | waits on T40 |
| T42 | M4 | `42-file-exists-and-resume.md` | waits on T41 |
| T43 | M4 | `43-recursive-operations.md` | waits on T40, T41 |
| T44 | M4 | `44-speed-limits.md` | waits on T41 |
| T45 | M4 | `45-queue-completion-actions.md` | waits on T41, T56 |
| T49 | M6 | `49-search-engine.md` | waits on T43 |
| T56 | M4 | `56-queue-pane.md` | waits on T40, T41 |
| T59 | M5 | `59-site-manager-ui.md` | waits on T31, T32, T33, T58 |
| T61 | M5 | `61-connection-tabs.md` | waits on T58, T59 |
| T62 | M4 | `62-file-operations-ui.md` | waits on T40, T41, T43 |
| T63 | M6 | `63-view-edit-files.md` | waits on T41, T62 |
| T64 | M5 | `64-bookmarks-ui.md` | waits on T33 |
| T65 | M6 | `65-search-ui.md` | waits on T41, T49 |
| T66 | M6 | `66-compare-and-sync-browsing-ui.md` | waits on T48 |
| T70 | M9 | `70-cli-arguments.md` | waits on T31, T61 |
| T73 | M9 | `73-settings-import-export.md` | waits on T32, T40, T68 |
| T77 | M9 | `77-docs-and-release.md` | waits on T70, T86, T91 |
| T86 | M7 | `86-sync-server-ops.md` | waits on T85 |
| T87 | M7 | `87-sync-client-account.md` | waits on T85 |
| T88 | M7 | `88-sync-engine.md` | waits on T85, T87 |
| T89 | M8 | `89-team-vaults.md` | waits on T85, T87, T88 |
| T90 | M7 | `90-sync-ui.md` | waits on T59, T87, T88 |

## How the work was run

- One helper agent per task in its own git worktree:
  `git worktree add -b impl/tNN .claude/worktrees/tNN claude/lucid-fermat-bhtbd0`.
  The helper follows `tasks/handoff/helper-brief.md`, commits on `impl/tNN` and does not push.
- The coordinator merges with `git merge --no-ff impl/tNN`, runs the gates, pushes, then
  removes the worktree (`git worktree remove -f -f`) and deletes the branch.
- Run at most 2 helpers at once: 4 CPUs, 15 GB RAM and limited disk. The container restarted
  twice from memory pressure, and the disk filled more than once.
- Always `export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`.
- Gates after every merge:
  - `cargo fmt --all --check`
  - `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  - `cargo clippy -p courier-ftp --all-targets --no-default-features --locked -- -D warnings`
  - `python3 scripts/check-layering.py` and `python3 scripts/check-unsafe.py`
  - `cargo vet --locked`
  - `cargo deny --all-features --locked check advisories bans licenses sources`
  - `cargo test --workspace --all-features --locked -- --test-threads=2`
  - `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --all-features --workspace --locked`, then `rm -rf target/doc`
- Local toolchain is rustc 1.99 stable (matches CI clippy). Docker is not available
  locally; the Docker e2e tests only run in CI's `e2e` job, which is green.
- CI logs: the full log download is blocked by the proxy. Use the GitHub MCP
  `get_job_logs` with `tail_lines`, or a read-only helper agent for long logs.

## Follow-ups recorded by merged tasks

These are acceptance criteria and integration points left for later tasks. Each task's
`## Implementation notes` section has the details.

- T50 deferred e2e tests: e2e_pty_starts_and_quits, e2e_pty_resize_to_compact_and_back (write in T76)
- T51 deferred e2e: e2e_pty_sequences_and_fkeys
- T76 partial ACs: AC1 sync_server.rs (M7), AC12 (T60), AC13 backend_conformance.rs (T14/T22), AC15 (T13/T14 MLSD/LIST e2e), AC4/8/10 need CI docker run
- T76: wire FTP/SFTP into E2eBackendFactory (src/session.rs) in T14/T22; TestHome vault helpers T30/T31; PtyApp::unlock waits "Unlock" (T60); panic hooks T91; T50 snapshots -> assert_view_snapshots!
- T52 deferred e2e: e2e_pty_paste_into_quickconnect_host (needs T58)
- T11: check ProxyConfig::allows_inbound() before active mode; Unsupported msg (T07 notes). T14/T22: proxies.rs conformance subset (T76 table)
- T61: call MessageLogPane::set_active_tab on tab switch, store_mut().remove_tab() on close; T53/T61 set_tab_route(TabId, TabRoute{browsing, server}) (T55 notes)
- T57: AC4 real indicator sources (feed App::status_sources from T61 session, T60 vault, T69 prompts, T47/T53/T67 filters, T66, T90 sync, T40/T41 queue); PTY e2e plain_ftp_warning_visible + tls_indicator_after_explicit_tls (need T58/T61); T41/T44 send EngineCommand::SettingsChanged on speed-limit toggle; server info Details button (T69); tab label (T61)
- Harness: tests that read the saved config must call AppHarness::wait_saved() after advance
- Binary crate: use crate::runtime::spawn_blocking (not tokio's) so AppHarness waits for it.
- T53: AC6 render bench not gated (ignored release timing test instead); T58/T61 insert RemoteSource into App.panes.remote + PaneInput::Connected; T62/T63 take PaneRequest::FileOp; T67 set status_sources.filters_active; T31 site colour accent
- Harness: AppHarness tests injecting fake listings must wait for the real listing then use PaneInput::ListingUpdated (not ListingLoaded)
- T69: PTY e2e pty_unknown_host_key_trust_then_silent, pty_changed_host_key_enter_rejects (need T58); AC8 against T20 server; T61 narrow PromptOrigin foreground to active tab browsing session; T31 replaces Action::SaveCredential arm (SiteRef); T60 call App::set_vault_locked
- T20: e2e ssh_auth.rs ACs 2,3,4,8,13 need CI e2e; AC7 Windows agent manual; T21 replaces UnverifiedHostKeys with known-hosts verifier; T22 adds SFTP server behind ssh::testing::TestServer
- T10: AC3 nightly fuzz run; AC15 e2e ftp_control.rs (pure-ftpd mfmt assert unverified) needs CI; T11 use write_command for ABOR; T14 calls pwd() itself, uses take_prompted_password/account, LineDecoder::text_decoder for listings
- Tests capturing tracing output: call tracing::callsite::rebuild_interest_cache() right after set_default
- T21: AC14 e2e ssh_host_keys.rs needs CI; T22/T58 pass TrustVerifier::new(store, session, OpenSshKnownHosts::from_settings) to SshConnection::connect; T30 uses SwitchableHostKeyStore::set; TestHome::trust_host_key needs T30 store
- T11: AC11 e2e ftp_data.rs + AC12 fuzz need CI; T14 maps Protocol{code,text} external-IP errors
- T30: AC13 nightly fuzz; AC16 CI; AC9 canary-scan CI; AC14 windows hardening clippy in CI; T40 re-exports vault::DeviceBlobStore (don't redefine); T60 builds VaultEngine + set_vault_locked; T87/T88/T89 add sync methods (sync_handles, lmk_rewrap_rows, reload, apply_remote, transfer); TestHome add_site/add_bookmark/trust_cert wait T31/T33/T12
- T22: AC1 e2e conformance vs sshd, AC9 255KiB limit e2e, AC16 bench-sftp.sh results table; proto-sftp test-util must not enable core test-util
- T60: AC11 CI; Docker PTY lock_and_unlock_keeps_sftp_session (needs T58/T61); T61 closes sessions in App::disconnect_requests; T58/T59/T64 drop decrypted lists in lock_vault and call request_unlock; T68 uses open_change_password/toggle_keyring_unlock; T70 replaces LaunchIntent stand-in + vault_defer_launch/on_launch; T90/T73 unhide Forgot s/b + first-run Ctrl-b/Ctrl-g; T87 sync_account/Relogin
- PTY tests: use PtyOptions::no_vault() unless testing the vault (else first-run screen); or TestHome::with_vault + unlock()

