# T90 — Sync and teams UI

**Phase:** H Sync · **Milestone:** M7 (stage A); stage B (team screens) lands in M8 after T89 · **Depends on:** T52, T59, T60, T87, T88 · **Crate(s):** `courier-ftp` (`components/sync/`, `components/toast.rs`, Site Manager and status bar integration) · **Decisions:** D3, D6, D7, D12, D14 · **FEATURES.md:** §2 (Site Manager, master password)
**Related (integrates with, not blocking):** T89
**Reference:** sverb `crates/sverb-tui/src/views/settings/{mod,account_wizard,team_verify,vaults}.rs`, `src/app/{sync,sync_ui}.rs`, `src/app/sync/vaults.rs`, `src/views/first_run.rs`, snapshots `src/app/snapshots/sverb_tui__app__sync_tests__*.snap`; SPEC §8.7, §11.2, §13.

## Goal

Every sync and team action is reachable by keyboard inside courier-ftp: connect to a
server (create an account or log in, with the recovery-key ceremony and the duplicate
preview), see sync status at a glance and in a panel, manage the account (password, TOTP,
recovery, logout, deletion) and devices, and — once T89 lands — manage orgs, members,
safety numbers, team vaults and shared sites in the Site Manager. Notifications explain
what sync did (merged, restored, access changed).

## Context

- **Before:** T52 dialog/form widgets and modal stack; T59 Site Manager (tree + editor);
  T60 unlock/first-run screens (its "Forgot password? → sync recovery" and "password changed
  on another device" entries call into this task); T87 account library (wizards
  `RegisterWizard`, `LoginWizard`, `RecoveryWizard`, `RecoveryConfirm`, `ImportPreview`,
  device/TOTP/logout functions, `SyncError` texts); T88 `SyncHandle`, `SyncStatus`,
  `SyncEvent`, `local_info`; T57 status bar segments; T68 Settings screen with the
  "Sync & teams" section placeholder; T51 keymap.
- **After:** T89 provides the team APIs used by stage B; T75 extracts the strings defined
  here; T76's `PtyApp` runs the end-to-end flows.

**Delivery stages.** T90 is in M7, T89 in M8. **Stage A (M7)**: status segment, sync
panel, toasts, Settings → Sync/Account/Devices, account wizard (register, login, recovery),
sign-in-again dialog. **Stage B (M8, after T89)**: Settings → Team/Vaults, safety numbers,
key-change modal, invites, audit log, rotation progress, Site Manager vault roots,
read-only lock, copy/move to vault, credential override editor. ACs are tagged [A]/[B].

## Technical specification

### Types and APIs

Module `crates/courier-ftp/src/components/sync/` (whole module `#[cfg(feature = "sync")]`):

```rust
// mod.rs
pub struct SyncService {               // owns the SyncHandle and runs library calls off the UI thread
    pub fn start(vault: &VaultEngine, settings: &Settings, tx: UnboundedSender<Action>) -> Option<Self>; // None if not configured
    pub fn status(&self) -> SyncStatus;
    pub fn sync_now(&self);
    pub async fn shutdown(self);
}
// Actions added to `Action` (T50/T51):
pub enum SyncAction {
    OpenPanel, SyncNow, OpenSettingsSync,
    Status(SyncStatus), Event(SyncEvent),
    Wizard(WizardMsg),                  // results of library calls fed back into wizards
    NeedsLogin(NeedsLoginReason),
}
// Components (each implements the T50 `Component` trait, renders at any size ≥ 40×12):
pub struct SyncStatusSegment;          // status bar segment (T57)
pub struct SyncPanel;                  // modal: status, per-vault pending, recent events
pub struct ToastStack;                 // bottom-right notifications
pub struct SyncSettingsPage;           // Settings → Sync & teams → Sync
pub struct AccountPage; pub struct DevicesPage;               // stage A
pub struct TeamPage; pub struct VaultsPage;                   // stage B
pub struct AccountWizard { flow: Flow /*Register|Login|Recovery*/, screen: WizardScreen }
pub struct RecoveryWordsView { words: Zeroizing<Vec<String>> } // dropped when the screen closes
pub struct DuplicatePreviewView;
pub struct SignInAgainDialog;
pub struct TotpSetupDialog;            // QR + secret + code
pub struct SafetyNumberDialog; pub struct KeyChangedModal;   // stage B
pub struct RotationProgressDialog; pub struct AuditLogView; pub struct InviteDialog; // stage B
pub struct VaultPickerDialog;          // "Copy/Move to vault…" (stage B)
pub struct CredentialOverrideDialog;   // stage B
```

Keybindings added to the default keymap (T51, rebindable):

| Context | Key | Action |
|---|---|---|
| global | `Ctrl-x y` | open sync panel |
| sync panel | `s` | sync now |
| sync panel | `o` | open Settings → Sync & teams |
| Settings → Sync & teams | `[` / `]` | previous / next page (Sync · Account · Devices · Team · Vaults) |
| Sync page | `Enter` / `n` / `s` / `d` / `h` | log in / create account / sync now / disconnect / toggle `sync.history` |
| Account page | `p` / `t` / `r` / `o` / `D` | change password / enable-disable two-factor / recovery code / log out / delete account |
| Devices page | `j`/`k`, `x`, `r` | move, revoke, reload |
| Team page [B] | `Tab` org, `i`, `p`/`d`, `x`, `v`, `l`, `n`, `a`, `L` | switch org, invite, promote/demote, remove, verify, audit log, new org, accept invite, leave |
| Vaults page [B] | `n`, `Enter`, `g`, `x`, `R` | new vault, members, grant/change, revoke, restart abandoned rotation |
| Site Manager [B] | `C` / `M` / `o` | copy to vault / move to vault / my login for this site |
| toasts | — | no keys (they never take focus) |

### Behaviour

#### Status segment (T57 slot "Sync", right of the vault segment)

| `SyncStatus` | Unicode | ASCII (`interface.unicode_symbols = false`) | Style |
|---|---|---|---|
| `Disabled` | (hidden) | (hidden) | — |
| `Synced` | `⟳ synced` | `sync ok` | normal |
| `Syncing` | `⟳ syncing` (spinner frame every 250 ms) | `sync ...` | normal |
| `Offline{n}` | `⟳ offline (n)` | `sync offline (n)` | warning |
| `Error{..}` | `⟳ error` | `sync error` | error |
| `NeedsLogin` | `⟳ login needed` | `sync login` | error |

Collapses to the bare symbol below 100 columns, hidden below 60.

#### Sync panel (`Ctrl-x y`, modal 70×18 or smaller)

```
┌ Sync ───────────────────────────────────────────────────────────┐
│ Status     ⟳ offline (3)            Last sync  2026-10-09 12:00  │
│ Server     https://sync.example.com                              │
│ Vault                 Cursor   Pending   Problems                │
│ Personal                 412         3   —                       │
│ Team: Ops                 88         0   1 too large             │
│                                                                  │
│ Recent                                                           │
│ 12:00:31  web01 was restored: it was edited on another device     │
│ 11:58:02  Clock skew detected on device 4f2a (ahead 7 min)       │
│                                                                  │
│ [s] Sync now   [o] Settings   [Esc] Close                        │
└──────────────────────────────────────────────────────────────────┘
```

"Recent" keeps the last 50 `SyncEvent` toasts of this process (memory only).

#### Toasts

`ToastStack` bottom-right above the status bar, width `min(50, cols-4)`, at most 3
visible (newest at the bottom), never focused. Lifetimes: Info 5 s, Warn 10 s, Error 30 s.
Texts (exact):

| Event | Level | Text |
|---|---|---|
| `Resurrected` | Info | `"<label>" was restored: it was edited on another device` |
| `ClockSkew` | Warn | `Clock skew detected on device <short id> (ahead <n> min)` |
| `AccessChanged{granted}` [B] | Info | `You now have access to <vault>` |
| `AccessChanged{revoked}` [B] | Warn | `You no longer have access to <vault>` (+ `; <n> unsynced changes were discarded`) |
| `KeyRotated` [B] | Info | `<vault>: key rotated` |
| rotation paused (`Syncing` with rotating vault) [B] | Info | `<vault>: key rotation in progress, uploads paused` |
| merge after conflict (push conflict resolved) | Info | `"<label>" was changed on two devices; changes were merged` |
| `Toast{Error}` too large | Error | engine text |
| `LocalActingChanged` | Warn | `"<label>" now uses a different <field> from another device; you'll be asked before it is used` |
| `AccountChanged` | Warn | `Your password was changed on another device` |

#### Settings → Sync & teams (T68 section, `TabbedForm`)

Sync page, not connected:

```
 [Sync]  Account  Devices  Team  Vaults
 Not connected.
 courier-ftp works fully offline. Nothing is sent anywhere until you connect a
 sync server you trust (your own courier-ftp-server).
 [Enter] Log in to a server   [n] Create an account
```

Connected:

```
 [Sync]  Account  Devices  Team  Vaults
 Status      ⟳ synced
 Server      https://sync.example.com
 Account     alice@example.com
 Device      laptop (this device)
 Last sync   2026-10-09 12:00:31
 Pending     Personal: 0 · Team: Ops: 2
 Problems    1 item too large to sync
 History     [ ] Also sync quickconnect history
 [s] Sync now   [d] Disconnect (keep local data)
```

Disconnect asks: "Disconnect from the server? Sites in team vaults are removed from this
device; your personal sites and master password stay." → T87 `logout`.

Account page:

```
 Email        alice@example.com            Instance admin  no
 Two-factor   off
 [p] Change master password   [t] Enable two-factor   [r] Request recovery code
 [o] Log out (keep local data)                        [D] Delete account…
```

- Change password: dialog with current password, new password + confirm (zxcvbn meter and
  feedback, score ≥ 3); offline → error "Changing the password needs the sync server; you
  are offline"; success toast "Master password changed. Other devices must sign in again."
- Two-factor: `TotpSetupDialog` shows the `otpauth` URI as a QR code (crate `qrcode`,
  rendered with Unicode half blocks `▀▄█`, quiet zone 2) when the dialog fits (≥ 41×27
  cells), otherwise only the base32 secret in groups of 4; then a 6-digit code field →
  `totp_confirm`. Disable asks for a current code.
- Delete account: type the email to confirm + master password → T87 `delete_account`.

Devices page:

```
 › laptop        linux     added 2026-10-01   seen 2 min ago    this device
   phone-sftp    macos     added 2026-09-12   seen 3 days ago
   old-desktop   windows   added 2025-12-01   revoked 2026-01-10
 [x] Revoke   [r] Reload
```

Revoking this device asks "This logs this device out of sync. Local data stays." Others:
"Revoke <name>? It will have to sign in again."

#### Account wizard (modal, one screen at a time, `Esc` cancels and discards everything)

Register: `Server` (URL, validated as T87, "Checking server…" spinner) → `Credentials`
(email, current master password masked, device name default hostname, optional "Invite or
setup token") → `ShowWords` → `ConfirmWords` → `Working` ("Creating account…", then
"Uploading N items" from engine progress) → `Done`.

```
┌ Recovery key ─────────────────────────────────────────────────────────┐
│ Write these 24 words down and keep them offline. They are shown only  │
│ once. Without them and without a signed-in device, a forgotten        │
│ password means your synced data is lost.                              │
│                                                                       │
│  1 abandon    7 cradle    13 hockey    19 olympic                     │
│  2 ability    8 crane     14 hold      20 omit                        │
│  …            …           …            …                              │
│  6 above     12 crash     18 hollow    24 once                        │
│                                                                       │
│ [ I wrote them down ]                                                 │
└───────────────────────────────────────────────────────────────────────┘
```

(4 columns × 6 rows, column-major numbering. At 80×24 the dialog is 72×16.) Confirm screen:
"Type word #3, #11 and #20" with three inputs; mismatch → inline "Word 11 does not match"
and the inputs stay; `Back` returns to the words.

Login: `Server` → `Credentials` (email, master password, device name) → `Totp` (only when
required) → `AdoptPassword` (only if `password_differs`: shows `PASSWORD_ADOPT_WARNING`, or
"Your password was changed on another device" when `password_changed_elsewhere`) →
`Preview` (only if `will_import`) → `Working` → `Done`.

```
┌ Import local data ─────────────────────────────────────────────────────┐
│ 12 local items will be added to your account. 3 look like duplicates: │
│                                                                        │
│ Kind   Item                              Choice                       │
│ › site sftp://deploy@web01:22            Keep both                    │
│   site ftp://anon@mirror.example:21      Keep account                 │
│   key  ssh-ed25519 AAAAC3Nza…            Keep local                   │
│                                                                        │
│ b keep both · l keep local · a keep account · B/L/A for all rows       │
│ [ Import ]   [ Cancel ]                                                │
└────────────────────────────────────────────────────────────────────────┘
```

Recovery (from Account page `r`, or T60 "Forgot password?" when sync is configured):
`Server`+`Email` → `[Request code]` (always "If the account exists, a code was sent. Without
mail on the server, ask its operator.") → `Code` + `Recovery words` (multi-line input,
masked by default, `Ctrl-r` toggles visibility) + new password + confirm → `Working` →
`Done` → continues with the Login flow using the new password (or, when the local vault
cannot be unlocked, offers "Start fresh from the account" per T87).

All long operations run in `SyncService` tasks; the wizard shows a spinner and stays
cancellable (`Esc` → cancellation token).

#### Sign-in-again dialog

Opened on `SyncStatus::NeedsLogin` (once per occurrence; later via the status segment /
panel): title "Sign in to sync again" or "Your password was changed on another device"
(`PasswordChangedElsewhere`), or "This device was signed out" (`DeviceRevoked`); fields
master password (+ TOTP when required); runs T87 login case A; success restarts the engine.
`Esc` leaves sync paused; local use continues.

#### Stage B: teams

Team page:

```
 [Org: Acme ▾]  you: owner
 ✔ alice@example.com   owner   (you)
 ✔ bob@example.com     admin
 ⚠ carol@example.com   member  key changed
   dave@example.com    member  not verified
 [i] Invite  [p/d] Promote/demote  [x] Remove  [v] Verify  [l] Audit log
 [n] New org  [a] Accept invite  [L] Leave org
```

- Invite: email (optional) + role select (≤ own role) → shows the link in the dialog for
  manual selection (no clipboard access, see Open questions) or "Invite mailed to …".
- Accept invite: paste the link or token.
- Remove member: confirm "Remove carol from Acme? Her access to N vaults is revoked and their
  keys are rotated." → `RotationProgressDialog` per vault (phases: begin, download n/N,
  upload n/N, commit); `UntrustedMembers` → error listing members whose keys must be
  accepted first; the rotation stays paused and `R` on Vaults page resumes it.
- Verify: `SafetyNumberDialog`

```
┌ Verify bob@example.com ──────────────────────┐
│ Compare this number with bob in person or    │
│ over a channel you trust:                    │
│   01234 56789 01234 56789 01234 56789        │
│   98765 43210 98765 43210 98765 43210        │
│ [y] Mark verified   [Esc] Close              │
└──────────────────────────────────────────────┘
```

- `KeyChangedModal` (red border, opened the first time a changed key is seen this session):
  "carol@example.com's key changed. This happens when the account was re-created, or when
  the server is attacking you. Until you accept it, you can't share vaults with carol and
  vaults she shares are not trusted." Shows the **new** safety number; `[a] Accept new key`
  (asks "Did you compare the number?" → yes marks verified) / `[Esc] Keep blocked`.
- Audit log: table `time  actor  event  target`, newest first, `PageDown` loads the next
  page; emails resolved from the member list, otherwise short ids.

Vaults page:

```
 Vault          Org    Access   Members   Key
 › Ops          Acme   manage   5         v3
   Customers    Acme   read     12        v1   🔒
   Staging      Acme   —        —         needs key
 [n] New vault  [Enter] Members  [g] Grant  [x] Revoke  [R] Restart rotation
```

Members of a vault: org members with permission column; `g` opens a permission select
(`read`/`write`/`manage`); granting to a member with a changed key shows the
`KeyChangedModal` instead.

Site Manager integration (T59):
- Tree roots = vaults: `Personal`, then `Team: <name>` per team vault (sorted); folders and
  sites under them. Read-only vault roots and their items show `🔒` (ASCII `[ro]`); the editor
  opens read-only with the banner "Read-only: you have read access to Team: Customers".
- `C` / `M`: `VaultPickerDialog` (writable vaults only for move) + target folder + "Also
  copy the SSH key / proxy credential it uses" checkbox when references exist; errors from
  T89 shown as dialogs.
- Saving a team-vault site that references a personal item → the T89 error text inline.
- `o` on a team-vault site: `CredentialOverrideDialog` (user, password, account, key from
  personal vault, passphrase) — "Only you use these; they stay in your personal vault."

### Data formats and configuration

- Settings used: `sync.history` (toggle on the Sync page; saved via T05 `save_user`),
  `interface.unicode_symbols`.
- All user-facing strings live in `components/sync/strings.rs` (T75 extraction).
- No new files on disk.

### Errors

`SyncError` variants are shown with the T87 texts in the dialog that caused them (inline for
field errors, `error(...)` dialog otherwise). Engine errors never open dialogs; they appear
in the status segment, the panel and toasts. `TrustError`/`RotationError` texts from T89.

### Security and logging

- Password, TOTP code, recovery code and recovery-word inputs use T52 masked inputs backed by
  `Zeroizing<String>` and are cleared when the dialog closes; recovery words are rendered only
  on the `ShowWords` screen and dropped (zeroized) when it is left.
- No secret, email, server hostname or item label is logged at info+ by this module; toasts
  and dialogs are UI-only. Debug logs may name screens and outcomes.
- The invite link is a secret: shown only in its dialog, never logged.
- Keyboard only (D7); every action reachable without a mouse.

## Implementation steps

1. [A] `SyncService` (start/stop with unlock/lock, `SyncEvent` → `Action`), status segment,
   `ToastStack`, sync panel.
2. [A] Settings → Sync page and Devices page.
3. [A] Account wizard: register (words + confirm), login (TOTP, adopt warning, preview),
   recovery; T60 entry points.
4. [A] Account page: password change, TOTP dialog with QR, logout, delete; sign-in-again
   dialog.
5. [A] Snapshot tests for every stage-A screen; UI-flow tests against the in-process server.
6. [B] Team page, invites, safety numbers, key-change modal, audit log.
7. [B] Vaults page, grants, rotation progress, restart.
8. [B] Site Manager vault roots, read-only, copy/move, credential override; snapshots and
   flow tests.
9. PtyApp end-to-end flows (T76).

## Acceptance criteria

- [ ] AC1 [A] Register → recovery words → confirm 3 words → second device (second data dir)
  login with duplicate preview → both show the same sites; driven only by key events
  (UI-flow test and PtyApp e2e).
- [ ] AC2 [A] The recovery-words screen cannot be skipped: `Done` is reachable only after the
  three requested words were typed correctly.
- [ ] AC3 [A] After closing the wizard, no component holds the recovery words (state
  inspection test) and a trace-level run leaves no recovery word, password, code or token in
  any log or DB file (canary scan, T91 §5).
- [ ] AC4 [A] Status segment shows each `SyncStatus` with the documented text in Unicode and
  ASCII mode, and collapses/hides at 99 / 59 columns.
- [ ] AC5 [A] `NeedsLogin(PasswordChangedElsewhere)` opens the sign-in dialog with the
  "changed on another device" title; signing in with the new password resumes sync.
- [ ] AC6 [A] Each toast in the table appears with the exact text for its event and expires
  after 5/10/30 s (paused time).
- [ ] AC7 [B] Owner invites a member, member accepts by pasting the link, owner grants
  `write`; the member's Site Manager shows `Team: Ops` with the shared site — keyboard only.
- [ ] AC8 [B] Read-only items show the lock and the editor refuses edits; copy to personal
  vault works.
- [ ] AC9 [B] A changed member key opens the red modal once, blocks granting, and accepting it
  after viewing the safety number unblocks.
- [ ] AC10 Snapshot tests exist for every screen and dialog in this task at 80×24 and 160×48
  (stage A in M7, stage B in M8), in Unicode and for the status segment also in ASCII mode.
- [ ] AC11 `cargo build -p courier-ftp --no-default-features` builds without this module and
  the Settings section shows no "Sync & teams" entry (snapshot).
- [ ] AC12 CI `fmt`, `clippy` (both feature sets), `docs`, `test-os`, `e2e` pass.

## Tests

### Unit tests
- `sync::status_segment::tests::text_per_status_and_width` (AC4).
- `sync::toast::tests::lifetimes_and_max_three` (AC6).
- `sync::wizard::tests::register_cannot_finish_without_confirm` (AC2).
- `sync::wizard::tests::preview_keys_set_choices` — `b/l/a/B/L/A`.
- `sync::totp::tests::qr_fits_or_falls_back_to_secret`.
- `sync::strings::tests::all_strings_present` (T75 extraction list).

### Property / fuzz tests
- `props::render_never_panics_any_size` — every sync component rendered at random sizes from
  1×1 to 300×100 (T52 rule: no panic, "terminal too small").

### Snapshot tests (ratatui `TestBackend` + `insta`, each at 80×24 and 160×48)
Stage A: `status_segment_{synced,syncing,offline,error,login,ascii}`, `sync_panel`,
`toasts_three`, `settings_sync_not_connected`, `settings_sync_connected`,
`settings_account`, `settings_account_totp_on`, `settings_devices`,
`wizard_register_{server,credentials,words,confirm,confirm_error,working,done}`,
`wizard_login_{credentials,totp,adopt_password,preview}`,
`wizard_recovery_{request,enter}`, `totp_setup_qr`, `totp_setup_secret_only`,
`change_password`, `sign_in_again_{expired,password_changed,revoked}`,
`settings_without_sync_feature` (AC10, AC11).
Stage B: `settings_team`, `settings_team_key_changed`, `safety_number`, `key_changed_modal`,
`invite_dialog_{link,mailed}`, `audit_log`, `settings_vaults`, `vault_members`,
`rotation_progress`, `rotation_blocked`, `site_manager_vault_roots`,
`site_manager_read_only`, `vault_picker`, `credential_override` (AC10).
Snapshots use a fixed fake mnemonic and fixed ids/timestamps.

### Integration tests (UI-flow, scripted key events, in-process server from T87's harness)
- `flows::register_then_login_second_device_with_preview` (AC1).
- `flows::recovery_words_not_retained` (AC3).
- `flows::password_changed_elsewhere_sign_in_again` (AC5).
- `flows::disconnect_keeps_personal_sites`.
- `flows::devices_revoke_other_and_self`.
- [B] `flows::team_invite_accept_grant_shows_site` (AC7), `flows::read_only_site_editor`
  (AC8), `flows::key_change_modal_blocks_grant` (AC9), `flows::remove_member_shows_rotation`.

### End-to-end tests
- `courier-ftp-e2e/tests/pty_sync.rs` (`#[ignore]`, `COURIER_E2E=1`, Docker sync fixture,
  `PtyApp`): `first_run_register_with_setup_token_and_words`,
  `second_home_login_preview_keep_both`, `sync_status_goes_offline_and_back` (toxiproxy),
  [B] `team_invite_flow_three_homes` (AC1, AC7 against the real binary).

## Out of scope

- Headless CLI commands for sync/teams (see T87 Open questions).
- Mouse support (D7).
- Translations (T75 does them; this task only centralises strings).

## Open questions

- **Copying invite links.** The terminal clipboard (OSC 52) is not used anywhere in the
  project; the link is shown for manual selection. Should T90 offer OSC 52 copy for invite
  links and recovery codes, or a "write to file" option?
- **Milestone order.** T90 (M7) contains team screens that need T89 (M8). This file splits
  them into stage A (M7) and stage B (M8). Alternatively move the team screens into T89 or
  move T90 to M8 in `tasks/README.md`.
