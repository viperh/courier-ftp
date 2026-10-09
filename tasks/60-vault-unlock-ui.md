# T60 — Vault unlock, keyring and recovery UI

**Phase:** F TUI · **Milestone:** M2 · **Depends on:** T30, T50, T52, T57 · **Crate(s):** `courier-ftp` (`app/vault.rs`, `services/vault.rs`, `views/{unlock,first_run,forgot,lock_overlay}.rs`) · **Decisions:** D3, D4, D13 · **FEATURES.md:** §2 (password storage options, master password)
**Related (integrates with, not blocking):** T73, T87, T90
**Reference:** sverb `crates/sverb-tui/src/app/vault.rs` (reducer, startup flow, lock, auto-lock), `crates/sverb-tui/src/views/{unlock,first_run,lock_overlay}.rs`, `crates/sverb-tui/src/app/vault/tests.rs`, `crates/sverb-core/src/vault/{lock,password}.rs`, SPEC §5.3 (unlock and auto-lock), §11.2 (account keys, recovery, one password two derivations).

## Goal

Every vault screen of courier-ftp, built the way sverb builds them (D3, D13): the
first-run screen that creates the vault, the master-password prompt at start, the
optional silent keyring unlock with fallback to the prompt, brute-force backoff with a
countdown, "Forgot password?" recovery paths, the lock overlay after auto-lock or
manual lock, the change-password form, and the "password changed on another device"
prompt. Typed secrets are zeroized, never rendered and never logged.

## Context

**Before this task:** T30 delivers `VaultEngine` (`status()`, `initialize`, `unlock`,
`unlock_with_keyring`, `lock`, `change_password`, `set_keyring_unlock`, backoff
persisted in `meta`, zxcvbn check with `MIN_SCORE = 3`, keyring under service
`courier-ftp`, account `lmk-kek:<db_id>`), `VaultStatus { Uninitialised, Locked,
Unlocked }`, the secret types (`SecretString`, `Key32`) and the auto-lock rules
(`vault.auto_lock_minutes`, lock on suspend, `vault.lock_disconnects`). T50 delivers
the main screen, modal stack, input routing and `Tick`. T52 delivers dialogs, the
masked `TextInput` and `confirm`. T57 (M1) delivers `Symbols`, the status bar's
`VaultIndicator` and `Action::StatusMessage`.

**Later tasks need from it:** T58/T59/T64 (offer unlock when the vault is locked),
T61/T62 (tabs and dialogs are hidden behind the lock overlay), T68 (Settings →
Security uses `ChangePasswordForm` and the keyring toggle flow), T70 (launch intent
deferred until unlock; `--no-vault`, `--no-keyring`), T73 (restore from backup on the
first-run and forgot screens), T87/T90 (sync recovery, password changed elsewhere,
sync login from first run), T76 (PtyApp first-run and unlock flows).

## Technical specification

### Types and APIs

Names, fields and semantics follow sverb `app/vault.rs` and `views/unlock.rs`
(same type names). courier-ftp additions are marked **(courier)**.

```rust
// crates/courier-ftp/src/app/vault.rs

/// What the UI knows about the vault (sverb `LockState`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LockState { #[default] Locked, Unlocking, Unlocked }
impl LockState { pub fn is_locked(self) -> bool; pub fn can_start_unlock(self) -> bool; }

/// The idle timeout for `vault.auto_lock_minutes`; `None` when 0.
pub fn auto_lock_timeout(minutes: u32) -> Option<Duration>;

/// A password on its way to the vault service. `Debug` prints
/// `VaultPassword([REDACTED])`; the buffer is zeroized when the last clone drops.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultPassword(Arc<Zeroizing<String>>);
impl VaultPassword { pub fn new(text: Zeroizing<String>) -> Self; pub fn expose(&self) -> &str; }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockRequest { Password(VaultPassword), Keyring }

/// Effects sent to the vault service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultEffect {
    Initialize { password: VaultPassword, keyring: bool },
    Unlock(UnlockRequest),
    Lock,
    /// `current: None` only right after a keyring unlock in the recovery flow.
    ChangePassword { current: Option<VaultPassword>, new: VaultPassword },
    /// (courier) Settings → Security; enabling requires the password.
    SetKeyringUnlock { enable: bool, password: Option<VaultPassword> },
    /// (courier) Move the database aside and start over (Forgot → new vault).
    StartNewVault,
    /// (courier) T87: log in again with the password set on another device.
    Relogin { password: VaultPassword },
}

/// The locked database's state, sent once at startup.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VaultStatusInfo {
    pub initialized: bool,
    pub keyring_enabled: bool,
    pub keyring_available: bool,     // probed (write + delete a test entry) only before first run
    pub failures: u32,
    pub retry_after: Option<Duration>,
    pub sync_account: bool,          // (courier) a sync account exists → recovery key path (T87)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnlockFailure {
    WrongPassword { failures: u32, retry_after: Option<Duration> },
    Backoff { retry_after: Duration },
    Keyring(String),
    /// (courier) SQLite busy after `busy_timeout` (another courier-ftp writing).
    Busy,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultEvent {
    Status(VaultStatusInfo),
    Unlocked { via_keyring: bool, note: Option<String> },
    UnlockFailed(UnlockFailure),
    PasswordChanged,
    PasswordChangeFailed(String),
    LockRequested,
    KeyringChanged { enabled: bool },          // (courier)
    NewVaultStarted { old_path_display: String }, // (courier)
    PasswordChangedElsewhere,                  // (courier) from T87
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum VaultScreen {
    #[default] None,
    Starting,
    FirstRun(FirstRunForm),
    Unlock(UnlockForm),
    ChangePassword(ChangePasswordForm),
    Forgot(ForgotScreen),                      // (courier)
    NewVaultConfirm(NewVaultConfirm),          // (courier) type "NEW VAULT"
    PasswordElsewhere(PasswordElsewhereForm),  // (courier)
}

/// How the app runs relative to the vault. (courier)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VaultMode {
    #[default] Normal,
    /// "Continue without vault": quickconnect only, nothing saved, vault stays locked.
    WithoutVault,
    /// `--no-vault`: the database is not opened at all.
    Disabled,
}

/// Vault state in `App`. No key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultUi {
    pub active: bool,                 // a vault service exists
    pub lock: LockState,
    pub screen: VaultScreen,
    pub mode: VaultMode,
    pub keyring_enabled: bool,
    deferred_launch: Option<LaunchIntent>,   // T70
    discarded_forms: bool,
    recovering: bool,
    auto_lock_armed: bool,
    quit_armed_until: Option<Instant>,       // (courier) second Ctrl-q while transfers run
}

/// sverb's constant, adapted.
pub const DISCARDED_FORMS: &str = "Unsaved changes were discarded when the vault locked";
/// Shown on first run and in Settings → Security (courier wording).
pub const NO_RECOVERY_WARNING: &str = "There is no way to recover this password. If you forget it, \
    your saved sites and passwords are lost unless you enable keyring unlock or set up a sync \
    account (which gives you a recovery key).";

impl App {
    pub fn with_vault(self, opts: VaultStartOptions) -> Self;   // starts Locked + Starting
    pub fn lock_state(&self) -> LockState;
    pub fn vault_available(&self) -> bool;                       // Unlocked
    pub fn open_change_password(&mut self);                      // T68
    pub fn request_unlock(&mut self);                            // T58/T59/T64 "unlock" offers
    pub(crate) fn vault_on_input(&mut self, input: &InputEvent) -> bool; // before routing
    pub(crate) fn lock_vault(&mut self);
    pub(crate) fn on_vault(&mut self, ev: VaultEvent);
    pub(crate) fn vault_on_timer(&mut self, kind: VaultTimer);
    pub(crate) fn vault_defer_launch(&mut self, intent: LaunchIntent) -> Option<LaunchIntent>;
    pub(crate) fn vault_hides_panes(&self) -> bool;
    pub(crate) fn render_vault(&self, frame: &mut Frame<'_>);
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultStartOptions { pub no_vault: bool, pub no_keyring: bool }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultTimer { AutoLockCheck, UnlockCountdown, QuitDisarm }

// crates/courier-ftp/src/views/unlock.rs (forms: plain data, pure key handling, infallible render)
pub struct MaskedField { text: Zeroizing<String> }      // Debug: "MaskedField(N chars)"
pub enum FormAction { None, Changed, Submit, Cancel, Forgot,
                      ContinueWithoutVault, Restore, SyncLogin, Choose(char) } // last four (courier)
pub struct UnlockForm { pub password: MaskedField, pub error: Option<String>, pub busy: Option<String>,
                        pub countdown: Option<u64>, pub keyring_enabled: bool,
                        pub sessions_open: bool, pub startup: bool /* (courier) shows Ctrl-n */ }
pub struct NewPassword { pub password: MaskedField, pub confirm: MaskedField, pub strength: PasswordStrength }
pub struct FirstRunForm { pub new: NewPassword, pub focus: FirstRunFocus, pub keyring_available: bool,
                          pub use_keyring: bool, pub error: Option<String>, pub busy: bool,
                          pub restore_available: bool, pub sync_available: bool /* (courier) */ }
pub struct ChangePasswordForm { pub current: Option<MaskedField>, pub new: NewPassword,
                                pub focus: usize, pub error: Option<String>, pub busy: bool }
pub struct ForgotScreen { pub keyring: bool, pub sync: bool, pub restore: bool }        // (courier)
pub struct NewVaultConfirm { pub typed: String, pub error: Option<String> }            // (courier)
pub struct PasswordElsewhereForm { pub password: MaskedField, pub error: Option<String>, pub busy: bool } // (courier)
```

**Vault service** (`services/vault.rs`): a tokio task that owns the `VaultEngine`
(T30), receives `VaultEffect`s on an `mpsc` channel (capacity 16) and answers with
`VaultEvent`s that T50 turns into `Action::Vault(VaultEvent)`. Argon2 and SQLite run
in `spawn_blocking` inside the engine; the UI never awaits them. The service sends
`Status` once at startup. Lock is processed before any other queued effect
(zeroize first).

### Behaviour

#### Startup (sverb `with_vault` + `on_vault_status`)

1. `--no-vault` (T70): `active = false`, `mode = Disabled`; status bar `no vault`; the
   database is not opened.
2. Otherwise the app starts `lock = Locked`, `screen = Starting`; nothing but the
   vault screen and the status bar is drawn (no panes, tabs, log, quickconnect).
3. `Status { initialized: false }` → `FirstRun`.
4. `initialized` and `keyring_enabled` and not `--no-keyring` and
   `COURIER_FTP_KEYRING` ≠ `off`: `Unlock` form with busy `Unlocking with the keyring…`,
   `lock = Unlocking`, effect `Unlock(Keyring)`.
5. Otherwise `Unlock` form; if `retry_after` is set the countdown starts.
6. `Unlocked` → `screen = None`, arm auto-lock, show the note (Warning message), show
   `DISCARDED_FORMS` (Info) if a lock discarded forms, then run the deferred launch
   intent. A `recovering` unlock opens `ChangePasswordForm::recovery()` instead.
7. `UnlockFailed(Keyring(msg))` → prompt ready, Info message
   `Keyring unlock failed (<msg>); enter your master password`.

#### While locked (sverb `vault_on_input`)

- Every key and paste goes to the vault screen; mouse is off (D7). Nothing reaches
  panes, dialogs or the keymap, except the **Quit** binding (T51 `Quit`: `Ctrl-q`/`F10`):
  no active transfers → quit at once (a confirmation could not be answered behind the
  lock); active transfers → the form shows `Transfers are running. Press Ctrl-q again
  within 3 s to quit.` and a second press within 3 s quits.
- Paste goes into the focused masked field; control characters and newlines are dropped.

#### Unlock form keys

| Key | Effect |
|---|---|
| printable | append to password (ignored while busy or counting down) |
| `Backspace` | delete last char |
| `Enter` | submit if non-empty → busy `Unlocking…`, `Unlock(Password)`, field taken (zeroized) |
| `Esc` | clear field and error |
| `Ctrl-r` | open `Forgot` screen (sverb goes straight to keyring unlock; courier shows the available options first) |
| `Ctrl-n` | startup only: continue without vault |

On `WrongPassword { failures, retry_after }`: field cleared, error
`Wrong password (N failed attempt[s])`, countdown if `retry_after`. On `Backoff`:
countdown only. Countdown: whole seconds rounded up, decremented by a 1 s
`UnlockCountdown` timer; input ignored while it runs; the line reads
`Too many failed attempts. Try again in Ns.`. T30's schedule applies (failures 1–4 no
delay; then 1, 2, 4, 8, 16 s, capped at 30 s; persisted, shared across processes).
On `Busy`: error `The database is busy (another courier-ftp may be writing). Enter the
password again to retry.`

#### Continue without vault (courier)

`mode = WithoutVault`, `screen = None`, `lock` stays `Locked`, auto-lock not armed.
Quickconnect works; history, bookmarks, Site Manager, trust stores (`HostKeyStore`/
`CertTrustStore` stay in-memory, "always trust" disabled with a note, T69) and queue
persistence are unavailable. Status bar `🔐 vault locked`. Components that need the
vault call `request_unlock()`, which shows the `Unlock` form as an overlay with
`startup = false`; `Esc` on an empty field returns to `WithoutVault`. A `--site` launch
intent fails with `Unlock the vault to open saved sites`; a URL intent runs.

#### Forgot password (courier extension of sverb's `Forgot`)

Options shown only when they exist on this device; keys pick them:

| Key | Option | Shown when | Flow |
|---|---|---|---|
| `k` | Unlock with the system keyring, then set a new master password | `keyring_enabled` | sverb: `recovering = true`, `Unlock(Keyring)`; on success `ChangePasswordForm::recovery()` (no current password); on failure back to `Unlock` with the keyring error |
| `s` | Use the 24-word recovery key of your sync account | `sync_account` and feature `sync` | opens T90's recovery screen (code + 24 words + new password, T87 §7) |
| `b` | Restore from a backup file (`.cftp-backup`) | T73 available | T73 import in "restore into a new vault" mode (current DB moved aside first) |
| `n` | Start a new, empty vault | always | `NewVaultConfirm`: user types `NEW VAULT`; effect `StartNewVault` → service closes the engine and renames `courier-ftp.db`, `-wal`, `-shm` to `courier-ftp.db.old-YYYYMMDD-HHMMSS` (never deletes), then `Status { initialized: false }` → `FirstRun`; Info message names the kept file |
| `Esc` | back to `Unlock` | | |

When neither keyring nor sync account exists the screen first explains that the
password cannot be recovered on this device.

#### First run (sverb `FirstRunForm`, courier text)

Fields: Master password, Confirm (masked), live zxcvbn meter (`Strength` + 5 cells +
label + feedback; meter style error for score 0–1, warning 2, ok 3–4), checkbox
`Also unlock with the system keyring on this device` (only when
`keyring_available`, default off), `NO_RECOVERY_WARNING`, busy line
`Creating your vault…`. Keys: `Tab`/`↓` next, `Shift-Tab`/`↑` previous, `Enter` on
Password → Confirm, `Enter` elsewhere → validate (non-empty, equal, score ≥ 3; else
inline error with zxcvbn feedback `Too weak (fair): Add another word or two.`) →
`Initialize { password, keyring }`. `Space` toggles the checkbox. (courier) `Ctrl-n`
continue without vault (no vault created; first run again next start),
`Ctrl-b` restore from backup (T73, hidden until it exists), `Ctrl-g` log in to a sync
server (T90 wizard, hidden until it exists / without feature `sync`). Keyring
enrolment failure after creation is a note on `Unlocked`, not an error.

#### Lock (sverb `lock_vault`)

Triggers: `LockVault` action (`Ctrl-x Ctrl-l`, T30/T51), the auto-lock timer, resume
from system sleep when `vault.lock_on_suspend` (detected on `Tick`: wall-clock advance
minus monotonic advance > 30 s), `Suspend` (`Ctrl-z`) when `vault.lock_on_suspend`
(lock before suspending), and `VaultEvent::LockRequested`. Steps, in order:
1. `lock = Locked`; cancel auto-lock timer; effect `Lock` (zeroize first).
2. Drop pending key sequences (T51).
3. If any open dialog holds a dirty form (Site Manager editor, bookmark editor,
   settings), set `discarded_forms`. Close every dialog and the modal stack.
4. Drop decrypted UI data (site tree, bookmarks, history lists).
5. `vault.lock_disconnects`: disconnect every tab's sessions; else keep them.
6. `screen = Unlock { sessions_open: connections or transfers exist, startup: false }`.

The lock overlay covers every region except the status bar: centred
`🔒 Vault locked` / `Ctrl-q quit` (ASCII `[locked]`), and the unlock box on top.
The status bar renders in locked mode: Security (no host), Vault, Transfer type,
Speed, Queue segments only. Transfers continue; transfers that need a secret wait
(T30 §5).

#### Auto-lock (sverb `arm_auto_lock`)

While unlocked, every key or paste re-arms a one-shot `AutoLockCheck` timer of
`auto_lock_timeout(vault.auto_lock_minutes)`; 0 disables it (and cancels an armed
timer). When it fires and the setting is still non-zero, `lock_vault`. Timers are
`tokio::time::sleep` tasks owned by `crate::timers::Timers` that send
`Action::VaultTimer(kind)`; scheduling a kind cancels its previous timer.

#### Change password (sverb `ChangePasswordForm`)

Rows: Current password (absent in the recovery variant), New password, Confirm, meter.
`Tab`/`↓`, `Shift-Tab`/`↑`, `Enter` advances then validates (current non-empty,
`NewPassword::validate`), `Esc` cancels (not in the recovery variant: the user must
set a password; `Esc` there shows `Set a new password to finish recovery`). With a sync
account the service runs T87's online flow; offline → `PasswordChangeFailed("The sync
server must be reachable to change the password")`. Success → Success message
`Master password changed`.

#### Keyring toggle (Settings → Security, T68 hosts the page)

Enable: asks the master password in a masked prompt, effect
`SetKeyringUnlock { enable: true, password }`, shows the keyring note (it is the only
local recovery path). Disable: `confirm("Turn off keyring unlock? …")`, effect with
`enable: false` (T30 deletes the keyring entry and the wrap). Hidden when no keyring.

#### Password changed on another device (courier, T87 §10)

`VaultEvent::PasswordChangedElsewhere` while unlocked opens `PasswordElsewhere`
(modal, not blocking the app). `Enter` → `Relogin { password }`; success → Success
message `Signed in again; sync resumed`; failure → inline error; `Esc` → closed, status
bar sync segment shows `⟳ login needed` (T90) and the same form opens from there.

#### Mock-ups

Unlock at startup, 80×24 (box 68×9 centred; last row is the status bar):
```
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
      ┌ 🔒 Unlock courier-ftp ───────────────────────────────────────────┐      
      │Enter your master password to unlock courier-ftp.                 │      
      │                                                                  │      
      │Password: ••••••••▏                                               │      
      │                                                                  │      
      │                                                                  │      
      │Enter unlock · Esc clear · Ctrl-r forgot password?                │      
      │Ctrl-n continue without vault (quickconnect only, nothing saved)  │      
      └──────────────────────────────────────────────────────────────────┘      
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
                                                                                
 – not connected │ 🔐 vault locked                                              
```
Unlock at startup, 160×48:
```
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                              ┌ 🔒 Unlock courier-ftp ───────────────────────────────────────────┐                                              
                                              │Enter your master password to unlock courier-ftp.                 │                                              
                                              │                                                                  │                                              
                                              │Password: ••••••••▏                                               │                                              
                                              │                                                                  │                                              
                                              │                                                                  │                                              
                                              │Enter unlock · Esc clear · Ctrl-r forgot password?                │                                              
                                              │Ctrl-n continue without vault (quickconnect only, nothing saved)  │                                              
                                              └──────────────────────────────────────────────────────────────────┘                                              
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
 – not connected │ 🔐 vault locked                                                                                                                              
```
Unlock form states (box only): wrong password, backoff countdown, keyring/Argon2 busy:
```
┌ 🔒 Unlock courier-ftp ───────────────────────────────────────────┐
│Enter your master password to unlock courier-ftp.                 │
│                                                                  │
│Password: ▏                                                       │
│                                                                  │
│Wrong password (2 failed attempts)                                │
│Enter unlock · Esc clear · Ctrl-r forgot password?                │
│Ctrl-n continue without vault (quickconnect only, nothing saved)  │
└──────────────────────────────────────────────────────────────────┘
```
```
┌ 🔒 Unlock courier-ftp ───────────────────────────────────────────┐
│Enter your master password to unlock courier-ftp.                 │
│                                                                  │
│Password:                                                         │
│                                                                  │
│Too many failed attempts. Try again in 4s.                        │
│Enter unlock · Esc clear · Ctrl-r forgot password?                │
│Ctrl-n continue without vault (quickconnect only, nothing saved)  │
└──────────────────────────────────────────────────────────────────┘
```
```
┌ 🔒 Unlock courier-ftp ───────────────────────────────────────────┐
│Enter your master password to unlock courier-ftp.                 │
│                                                                  │
│Password:                                                         │
│                                                                  │
│⠋ Unlocking…                                                      │
│Enter unlock · Esc clear · Ctrl-r forgot password?                │
│Ctrl-n continue without vault (quickconnect only, nothing saved)  │
└──────────────────────────────────────────────────────────────────┘
```
First run, 80×24 (keyring available, weak password typed):
```
                                                                                
                                                                                
┌ Welcome to courier-ftp ──────────────────────────────────────────────────────┐
│courier-ftp keeps your sites, passwords, bookmarks, history and trusted keys  │
│encrypted on this machine. The master password is the only key; with sync it  │
│is also your account password.                                                │
│                                                                              │
│Master password   ••••••••••••••••••▏                                         │
│Confirm                                                                       │
│                                                                              │
│Strength          ███░░ fair — Add another word or two.                       │
│                                                                              │
│[ ] Also unlock with the system keyring on this device                        │
│                                                                              │
│There is no way to recover this password. If you forget it, your saved sites  │
│and passwords are lost unless you enable keyring unlock or set up a sync      │
│account (which gives you a recovery key).                                     │
│                                                                              │
│                                                                              │
│Tab next field · Space toggle · Enter create · Ctrl-n continue without vault  │
└──────────────────────────────────────────────────────────────────────────────┘
                                                                                
                                                                                
 – not connected │ 🔐 vault locked                                              
```
First run, 160×48 (keyring checked, T73 and T90 available):
```
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                          ┌ Welcome to courier-ftp ─────────────────────────────────────────────────────────────────────────────────┐                           
                          │courier-ftp keeps your sites, passwords, bookmarks, history and trusted keys encrypted on this machine.  │                           
                          │The master password is the only key; with sync it is also your account password.                         │                           
                          │                                                                                                         │                           
                          │Master password   ••••••••••••••••••••••▏                                                                │                           
                          │Confirm           ••••••••••••••••••••••                                                                 │                           
                          │                                                                                                         │                           
                          │Strength          █████ very strong                                                                      │                           
                          │                                                                                                         │                           
                          │[x] Also unlock with the system keyring on this device (it is also the only local recovery path)         │                           
                          │                                                                                                         │                           
                          │There is no way to recover this password. If you forget it, your saved sites and passwords are lost      │                           
                          │unless you enable keyring unlock or set up a sync account (which gives you a recovery key).              │                           
                          │                                                                                                         │                           
                          │                                                                                                         │                           
                          │Tab next field · Space toggle · Enter create · Ctrl-n continue without vault                             │                           
                          │Ctrl-b restore from backup · Ctrl-g log in to a sync server                                              │                           
                          └─────────────────────────────────────────────────────────────────────────────────────────────────────────┘                           
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
                                                                                                                                                                
 – not connected │ 🔐 vault locked                                                                                                                              
```
Forgot password, all options available / no recovery available (boxes):
```
┌ Forgot master password ───────────────────────────────────────────┐
│Choose how to get back into your vault on this device:             │
│                                                                   │
│k  Unlock with the system keyring, then set a new master password  │
│s  Use the 24-word recovery key of your sync account               │
│b  Restore from a backup file (.cftp-backup)                       │
│n  Start a new, empty vault (the current one is kept as a file)    │
│                                                                   │
│Esc back                                                           │
└───────────────────────────────────────────────────────────────────┘
```
```
┌ Forgot master password ──────────────────────────────────────────────┐
│Keyring unlock is off and no sync account is set up on this device, so│
│a forgotten master password cannot be recovered here. Your saved      │
│sites, passwords and trusted keys can only be opened with the master  │
│password.                                                             │
│                                                                      │
│b  Restore from a backup file (.cftp-backup)                          │
│n  Start a new, empty vault (the current one is kept as a file)       │
│                                                                      │
│Esc back                                                              │
└──────────────────────────────────────────────────────────────────────┘
```
Lock overlay, 80×24 (a transfer is running):
```
┌──────────────────────────────────────────────────────────────────────────────┐
│                               🔒 Vault locked                                │
│                                 Ctrl-q quit                                  │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│       ┌ 🔒 Unlock courier-ftp ───────────────────────────────────────┐       │
│       │The vault is locked. Connections and transfers keep running.  │       │
│       │                                                              │       │
│       │Password: ▏                                                   │       │
│       │                                                              │       │
│       │                                                              │       │
│       │Enter unlock · Esc clear · Ctrl-r forgot password?            │       │
│       └──────────────────────────────────────────────────────────────┘       │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
 🔒 TLS 1.3 │ 🔐 vault locked │ Q: 3, 1.21 GiB                                  
```
Lock overlay, 160×48:
```
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                       🔒 Vault locked                                                                        │
│                                                                         Ctrl-q quit                                                                          │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                               ┌ 🔒 Unlock courier-ftp ───────────────────────────────────────┐                                               │
│                                               │The vault is locked. Connections and transfers keep running.  │                                               │
│                                               │                                                              │                                               │
│                                               │Password: •••▏                                                │                                               │
│                                               │                                                              │                                               │
│                                               │                                                              │                                               │
│                                               │Enter unlock · Esc clear · Ctrl-r forgot password?            │                                               │
│                                               └──────────────────────────────────────────────────────────────┘                                               │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
│                                                                                                                                                              │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
 🔒 TLS 1.3 │ 🔐 vault locked │ Type: Auto │ ⇅ off │ Queue: 3 files, 1.21 GiB, ↓8.40 MiB/s, ~00:02:27                                                           
```
Change password: recovery variant and normal variant with a validation error:
```
┌ Change master password ──────────────────────────────────┐
│Unlocked with the keyring. Choose a new master password.  │
│                                                          │
│New password      ••••••••••••••••▏                       │
│Confirm                                                   │
│                                                          │
│Strength          ████░ strong                            │
│                                                          │
│                                                          │
│Tab next field · Enter save · Esc cancel                  │
└──────────────────────────────────────────────────────────┘
```
```
┌ Change master password ──────────────────┐
│Current password  ••••••••                │
│New password      ••••••••••••••••        │
│Confirm           •••••••••••••••▏        │
│                                          │
│Strength          ████░ strong            │
│                                          │
│The passwords do not match                │
│Tab next field · Enter save · Esc cancel  │
└──────────────────────────────────────────┘
```
Password changed on another device:
```
┌ Password changed on another device ────────────────────────────────────┐
│Your master password was changed on another device. Sync is paused on   │
│this device until you enter the new password. Local unlock keeps using  │
│the old one until then.                                                 │
│                                                                        │
│New password: ▏                                                         │
│                                                                        │
│Enter continue · Esc later (sync stays paused)                          │
└────────────────────────────────────────────────────────────────────────┘
```

Box sizing (sverb `render_box`): width = longest line + 4, capped at the form's max
(unlock 72, first run 84 at ≤ 80 columns and 110 above, others 72–76) and the screen
width; height = wrapped lines + 2; centred above the status bar; drawn over `Clear`.
Below 40×12 the vault screen shows `Terminal too small` and still accepts the
password and `Enter` (no panic at any size). ASCII mode replaces `🔒` with `[locked]`,
`•` with `*`, `▏` with `_`, meter cells with `#`/`-`, the spinner with `|`.

#### Rendering rules

- Masked fields show one `•` per character, capped at 32; never the text, never its
  length beyond 32.
- The spinner is a static glyph (sverb), so a running Argon2 causes no redraws.
- Colours via style keys `vault.title`, `vault.text`, `vault.dim`, `vault.accent`
  (focused field), `vault.error`, `vault.warn`, `vault.ok`, `vault.info`,
  `vault.overlay`. `NO_COLOR`: errors bold, warnings bold, focus by `▏`/`_` cursor
  and bold label; meter label text carries the strength.

### Data formats and configuration

| Key | Type | Default | Range / notes |
|---|---|---|---|
| `vault.auto_lock_minutes` | u32 | 15 | 0 = off, max 1440 |
| `vault.lock_on_suspend` | bool | `true` | sleep/resume and `Ctrl-z` |
| `vault.lock_disconnects` | bool | `false` | close sessions on lock |
| `vault.store_passwords` | bool | `true` | T30/T31; shown in Settings → Security |
| `vault.argon2_cost` | preset | T30 default | T30 defines presets; T68 shows measured unlock time |
| env `COURIER_FTP_KEYRING` | `off` | unset | disables keyring use (CI canary job, T00) |
| CLI `--no-vault`, `--no-keyring` | flags | — | T70 |

Keyring entry: service `courier-ftp`, account `lmk-kek:<db_id>` (T30). Moved-aside
database name: `courier-ftp.db.old-YYYYMMDD-HHMMSS` (+ `-wal`, `-shm` with the same suffix).

### Errors

| Error | Shown as |
|---|---|
| `Error::Vault(WrongPassword)` from T30 | `UnlockFailed(WrongPassword)` inline |
| backoff active | `UnlockFailed(Backoff)` countdown |
| keyring errors (`keyring::Error`) | `UnlockFailed(Keyring(msg))` → prompt + Info message |
| SQLite busy | `UnlockFailed(Busy)` inline |
| weak password on create/change | inline `Too weak (<label>): <feedback>` |
| tampered `meta.kdf` / corrupt DB | `UnlockFailed(Other("The vault database is damaged: <reason>"))` + Forgot screen offers restore / new vault |
| `StartNewVault` rename failure | Error dialog `Could not move the database aside: <io error>`; nothing deleted |
| sync change-password offline | `PasswordChangeFailed` inline |

### Security and logging

- Typed secrets live only in `MaskedField` (`Zeroizing<String>`) and `VaultPassword`
  (`Arc<Zeroizing<String>>`); `Debug` is redacted for both; `take()` moves the buffer out
  at submit so the form holds nothing afterwards; `clear()` zeroizes.
- No secret is ever in an `Action` that derives `Serialize`; `Action::Vault*` variants
  are `#[serde(skip)]` and their `Debug` is redacted.
- While locked or while a vault screen is open no pane, tab title, log line, dialog or
  quickconnect text is drawn (they contain decrypted or server data).
- Nothing about passwords, keyring results or failure counts is logged at `info`+;
  `debug` may log `vault unlock via=keyring|password ok|failed failures=<n>` (no text).
- Canary test (T91 §5): a canary password typed through the UI never appears in the
  application log, snapshots, or any file under the test home.
- The no-recovery warning is shown on first run and in Settings → Security (D3).

## Implementation steps

1. Port sverb's forms (`MaskedField`, `UnlockForm`, `NewPassword`, `FirstRunForm`, `ChangePasswordForm`, `render_box`, meter) with courier text; unit tests.
2. `VaultUi`, `LockState`, `VaultEffect`/`VaultEvent`, reducer functions (`vault_on_input`, `on_vault`, `on_vault_status`, `on_unlock_failed`), timers.
3. Vault service task around `VaultEngine`; wire into T50's loop; startup gating of panes; launch-intent deferral.
4. Lock: action, auto-lock, suspend detection, overlay, status bar locked mode, form discard.
5. Continue without vault; `request_unlock()`; `--no-vault`/`--no-keyring` handling.
6. Forgot screen with keyring recovery and new-vault flow; hooks for T73/T90 options.
7. Keyring toggle and change-password entry points for T68; password-changed-elsewhere form for T87.
8. Snapshot and UI-flow tests (port sverb `app/vault/tests.rs`), canary test.

## Acceptance criteria

- [ ] AC1 Without keyring unlock, every start shows the unlock view and no pane is drawn before unlock.
- [ ] AC2 With keyring unlock enabled (mock keyring), start unlocks without a prompt; a keyring error falls back to the prompt with the reason.
- [ ] AC3 Wrong password clears the field and shows the attempt count; from the 5th failure the countdown shows and input is ignored until it ends (paused-time test).
- [ ] AC4 First run creates the vault only with matching passwords of zxcvbn score ≥ 3; weaker passwords show the zxcvbn feedback; the keyring checkbox appears only when a keyring is available.
- [ ] AC5 Forgot password: keyring path leads to the recovery change-password form and sets a new password; sync path opens T90's recovery (once T90 exists); with neither, the explanation and only `b`/`n` are shown; `n` keeps the old database file.
- [ ] AC6 Auto-lock locks after `vault.auto_lock_minutes` of no input; input resets it; 0 never locks; resume from sleep locks when `lock_on_suspend`.
- [ ] AC7 While locked no key reaches panes or sessions; only the unlock form and Quit work; `vault.lock_disconnects` closes sessions; dirty forms are discarded with the toast after unlock.
- [ ] AC8 A launch intent (T70) waits until unlock and then runs; with "continue without vault" a URL intent runs and a `--site` intent fails with the message.
- [ ] AC9 Snapshot tests at 80×24 and 160×48 for: unlock, wrong password, backoff, busy, first run, forgot (both variants), new-vault confirm, lock overlay, change password (both variants), password changed elsewhere; ASCII + `NO_COLOR` variants contain only ASCII.
- [ ] AC10 No password text appears in `Debug` output, snapshots, logs or files (canary test).
- [ ] AC11 CI gates `fmt`, `clippy`, `test-local-only`, `test-os`, `canary` pass.

## Tests

### Unit tests
- `masked_field_never_debugs_its_text` (sverb) (AC10).
- `unlock_form_keys` (sverb, plus `Ctrl-n`, `Ctrl-r` → `Forgot`) (AC3).
- `change_form_validates` (sverb), `recovery_change_form_cannot_be_cancelled`.
- `first_run_validation_and_feedback` (AC4), `first_run_keyring_row_only_when_available` (AC4).
- `forgot_screen_lists_only_available_options` (AC5).
- `new_vault_requires_typed_confirmation` (AC5).
- `auto_lock_timeout_zero_is_none`.
- `vault_password_debug_is_redacted` (AC10).

### Property / fuzz tests
- `prop_masked_field_drops_control_chars` — random pasted strings never put control chars in the buffer.
- `prop_vault_screens_render_at_any_size` — 0×0 … 200×60, every screen.

### Snapshot tests
`TestBackend` + `insta` at 80×24 and 160×48: `unlock_startup`, `unlock_wrong_password`,
`unlock_backoff`, `unlock_busy`, `first_run`, `first_run_keyring_checked`, `forgot_all_options`,
`forgot_no_recovery`, `new_vault_confirm`, `lock_overlay`, `change_password_recovery`,
`change_password_mismatch`, `password_elsewhere`; plus `*_mono_ascii` for unlock, first run
and lock overlay (AC9).

### Integration tests
UI-flow tests (sverb `app/vault/tests.rs` ported, with a fake vault service backed by a
real `VaultEngine` on a temp DB with `Argon2Cost::TEST` and a mock keyring):
- `startup_first_run_then_launch_after_unlock` (AC4, AC8).
- `keyring_first_then_fallback_to_prompt` (AC2).
- `backoff_countdown_disables_input` (AC3).
- `keyring_recovery_opens_the_new_password_form` (AC5).
- `auto_lock_after_idle_minutes`, `input_resets_the_idle_timer`, `zero_never_locks` (AC6).
- `resume_from_sleep_locks_when_configured` (AC6).
- `locked_app_gets_no_input_and_overlay_renders` (AC7), `quit_while_locked`, `quit_while_locked_with_transfers_needs_second_press` (AC7).
- `lock_disconnects_sessions_when_configured` (AC7).
- `lock_discards_forms_and_toasts_after_unlock` (AC7).
- `without_a_vault_service_nothing_changes` (`--no-vault`).
- `continue_without_vault_runs_url_intent_and_rejects_site_intent` (AC8).
- `start_new_vault_moves_database_aside` (AC5).
- `password_never_appears_in_debug_output` (AC10), `canary_password_not_in_logs_or_files` (AC10).

### End-to-end tests
- T76 PtyApp `first_run_create_vault_quit_unlock` — real binary, `COURIER_FTP_KEYRING=off`: create vault, quit, restart, wrong password, right password, panes appear.
- T76 PtyApp `lock_and_unlock_keeps_sftp_session` against the `sshd` `password` profile: connect, `Ctrl-x Ctrl-l`, unlock, the remote pane still lists.

## Out of scope

- Sync account registration, login wizard, recovery-key screens (T90) — only the entry points are here.
- Backup file format and restore logic (T30 §10, T73).
- Settings page layout (T68), CLI parsing (T70).

## Open questions

1. sverb's `Ctrl-r` goes straight to keyring unlock; this task shows a "Forgot password" chooser first because courier-ftp has more recovery paths (sync key, backup, new vault). Confirm this deviation.
2. T30 lists "Continue without vault" but does not say whether a vault can later be created from that mode on first run (no vault exists yet). This task shows the first-run screen again at the next start only. Should "Create vault" also be offered inside the running session?
