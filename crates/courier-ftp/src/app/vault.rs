//! The vault in the app (T60; sverb `app/vault.rs`, D3, D13): startup unlock,
//! keyring unlock, backoff, recovery, lock and auto-lock.
//!
//! The reducer only knows [`LockState`] and the vault forms; the keys live in the vault
//! service ([`crate::services::vault`]). Effects go out as [`VaultEffect`]s, results
//! come back as `Action::Vault(VaultEvent)`.
//!
//! - **Startup:** `App::with_vault` starts locked (`Starting`) and the service sends
//!   [`VaultEvent::Status`]: first-run screen, keyring unlock, or the password prompt.
//!   Nothing but the vault screen and the status bar is drawn until unlock; a launch
//!   intent waits until then.
//! - **While locked** every key and paste goes to the vault screen; only the Quit
//!   binding also works. Nothing reaches panes, dialogs or the keymap.
//! - **Lock** (`LockVault`, the idle timer, resume from sleep, `Ctrl-z`,
//!   `VaultEvent::LockRequested`): keys zeroized by the service first, dialogs (and
//!   unsaved forms) discarded, sessions kept behind the overlay or disconnected with
//!   `vault.lock_disconnects`.
//! - **Auto-lock** is a reset-on-input timer (`VaultTimer::AutoLockCheck`).

use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime},
};

use courier_ftp_core::{events::SessionId, vault::lock::MAX_AUTO_LOCK_MINUTES};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    widgets::{Clear, Paragraph, Wrap},
};
use tokio::time::Instant;
use tracing::debug;
use zeroize::Zeroizing;

use super::App;
use crate::{
    action::Action,
    components::{
        dialog::{ConfirmOpts, confirm, message, prompt_password},
        status_bar::{self, MessageLevel, SecurityIndicator, StatusInfo, VaultIndicator},
    },
    keymap::{
        chord::{KeyChord, display_sequence},
        map::Lookup,
    },
    services::vault::VaultService,
    views::{
        Look,
        first_run::FirstRunForm,
        forgot::{ForgotScreen, NewVaultConfirm},
        lock_overlay,
        unlock::{ChangePasswordForm, FormAction, PasswordElsewhereForm, UnlockForm},
    },
};

#[cfg(test)]
mod snapshot_tests;
#[cfg(test)]
mod tests;

/// The toast after unlocking when a lock discarded unsaved forms (sverb, adapted).
pub(crate) const DISCARDED_FORMS: &str = "Unsaved changes were discarded when the vault locked";
/// Shown on first run and in Settings → Security: T30's constant, not redefined here.
#[cfg_attr(not(test), allow(unused_imports, reason = "Settings → Security (T68)"))]
pub(crate) use courier_ftp_core::vault::NO_RECOVERY_WARNING;

/// How long a first `Ctrl-q` while transfers run stays armed.
const QUIT_ARM: Duration = Duration::from_secs(3);

/// The busy text of a keyring unlock.
const KEYRING_BUSY: &str = "Unlocking with the keyring…";

/// What the UI knows about the vault (sverb `LockState`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum LockState {
    /// No keys in memory.
    #[default]
    Locked,
    /// An unlock (or first run) is running.
    Unlocking,
    /// Keys are in memory (in the service).
    Unlocked,
}

impl LockState {
    /// Locked or unlocking.
    pub(crate) fn is_locked(self) -> bool {
        self != Self::Unlocked
    }

    /// A new unlock may start (not already running, not unlocked).
    #[cfg_attr(not(test), allow(dead_code, reason = "T58/T59/T64 unlock offers"))]
    pub(crate) fn can_start_unlock(self) -> bool {
        self == Self::Locked
    }
}

/// The idle timeout for `vault.auto_lock_minutes`; `None` when 0 (capped at one day).
pub(crate) fn auto_lock_timeout(minutes: u32) -> Option<Duration> {
    (minutes > 0).then(|| Duration::from_secs(u64::from(minutes.min(MAX_AUTO_LOCK_MINUTES)) * 60))
}

/// A password on its way to the vault service. `Debug` prints
/// `VaultPassword([REDACTED])`; the buffer is zeroized when the last clone drops.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VaultPassword(Arc<Zeroizing<String>>);

impl VaultPassword {
    /// Wraps a typed password.
    pub(crate) fn new(text: Zeroizing<String>) -> Self {
        Self(Arc::new(text))
    }

    /// The password (keep borrows short).
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for VaultPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultPassword([REDACTED])")
    }
}

/// How to unlock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnlockRequest {
    /// With the master password.
    Password(VaultPassword),
    /// With the OS keyring.
    Keyring,
}

/// Effects sent to the vault service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum VaultEffect {
    /// First run: create the vault (the form checked the strength).
    Initialize {
        /// The new master password.
        password: VaultPassword,
        /// Also enable keyring unlock.
        keyring: bool,
    },
    /// Unlock.
    Unlock(UnlockRequest),
    /// Zeroize the keys now (processed before any other queued effect).
    Lock,
    /// Re-wrap the LMK under a new password. `current: None` only right after a keyring
    /// unlock in the recovery flow.
    ChangePassword {
        /// The current password.
        current: Option<VaultPassword>,
        /// The new password.
        new: VaultPassword,
    },
    /// (courier) Settings → Security; enabling requires the password.
    SetKeyringUnlock {
        /// Turn it on.
        enable: bool,
        /// The master password (enabling only).
        password: Option<VaultPassword>,
    },
    /// (courier) Move the database aside and start over (Forgot → new vault).
    StartNewVault,
    /// (courier) T87: log in again with the password set on another device.
    Relogin {
        /// The new password.
        password: VaultPassword,
    },
}

/// The locked database's state, sent once at startup.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct VaultStatusInfo {
    /// A master password exists.
    pub initialized: bool,
    /// Keyring unlock is enabled.
    pub keyring_enabled: bool,
    /// A keyring works (probed by writing and deleting an entry) — only before first run.
    pub keyring_available: bool,
    /// Consecutive failed attempts.
    pub failures: u32,
    /// The next attempt must wait this long.
    pub retry_after: Option<Duration>,
    /// (courier) A sync account exists → recovery key path (T87).
    pub sync_account: bool,
}

/// Why an unlock (or first run) failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum UnlockFailure {
    /// Wrong password (counted).
    WrongPassword {
        /// Consecutive failures.
        failures: u32,
        /// Delay before the next attempt.
        retry_after: Option<Duration>,
    },
    /// Refused: the backoff delay has not elapsed.
    Backoff {
        /// Remaining delay.
        retry_after: Duration,
    },
    /// The keyring could not unlock (falls back to the password prompt).
    Keyring(String),
    /// (courier) SQLite busy after `busy_timeout` (another courier-ftp writing).
    Busy,
    /// T30 `VaultError::UnlockInProgress`: another unlock is still running; the form
    /// stays busy and the first attempt's result decides.
    InProgress,
    /// Anything else (weak password on first run, damaged database, storage error).
    Other(String),
}

/// Results and requests from the vault service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum VaultEvent {
    /// The locked database's state (startup, after a new vault).
    Status(VaultStatusInfo),
    /// Unlocked (or created on first run).
    Unlocked {
        /// Via the keyring.
        via_keyring: bool,
        /// A non-fatal note (keyring enrolment failed on first run, unreadable items).
        note: Option<String>,
    },
    /// An unlock or first run failed.
    UnlockFailed(UnlockFailure),
    /// The master password was changed.
    PasswordChanged,
    /// Changing the password failed.
    PasswordChangeFailed(String),
    /// Lock now (system suspend, T87/T90 requests).
    #[cfg_attr(not(test), allow(dead_code, reason = "sent by T87/T90"))]
    LockRequested,
    /// (courier) Keyring unlock was turned on or off.
    KeyringChanged {
        /// Now enabled.
        enabled: bool,
    },
    /// (courier) Turning keyring unlock on or off failed.
    KeyringChangeFailed(String),
    /// (courier) The database was moved aside (`StartNewVault`); a `Status` follows.
    NewVaultStarted {
        /// The kept file's name.
        old_path_display: String,
    },
    /// (courier) `StartNewVault` could not move the database aside; nothing was
    /// deleted.
    NewVaultFailed(String),
    /// (courier) From T87: the password was changed on another device.
    #[cfg_attr(not(test), allow(dead_code, reason = "sent by T87"))]
    PasswordChangedElsewhere,
    /// (courier) The answer to `Relogin`.
    Relogin(Result<(), String>),
}

/// What the vault screen shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum VaultScreen {
    /// Nothing.
    #[default]
    None,
    /// Locked, waiting for the service's status.
    Starting,
    /// First run.
    FirstRun(FirstRunForm),
    /// The password prompt.
    Unlock(UnlockForm),
    /// Change (or, after a keyring recovery, set) the master password.
    ChangePassword(ChangePasswordForm),
    /// (courier) Recovery options.
    Forgot(ForgotScreen),
    /// (courier) Type "NEW VAULT".
    NewVaultConfirm(NewVaultConfirm),
    /// (courier) The password was changed on another device.
    PasswordElsewhere(PasswordElsewhereForm),
}

/// How the app runs relative to the vault. (courier)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum VaultMode {
    /// The vault gates the app.
    #[default]
    Normal,
    /// "Continue without vault": quickconnect only, nothing saved, vault stays locked.
    WithoutVault,
    /// `--no-vault`: the database is not opened at all.
    Disabled,
}

/// What the command line asked to open, run after unlock (T70 parses it; until then
/// only tests create one).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code, reason = "T70 sends launch intents"))]
pub(crate) enum LaunchIntent {
    /// A URL (`sftp://…`): quickconnect.
    Url(String),
    /// `--site <name>`: a saved site (needs the vault).
    Site(String),
}

/// Vault state in [`App`]. No key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VaultUi {
    /// A vault service exists. Without one (`App::new`, `--no-vault`) the app behaves
    /// as unlocked and never locks.
    pub active: bool,
    /// Locked / unlocking / unlocked.
    pub lock: LockState,
    /// The vault screen.
    pub screen: VaultScreen,
    /// Normal, without vault, disabled.
    pub mode: VaultMode,
    /// Keyring unlock is enabled for this database.
    pub keyring_enabled: bool,
    /// The launch intent, run after unlock.
    deferred_launch: Option<LaunchIntent>,
    /// A lock discarded unsaved forms; toast after unlock.
    discarded_forms: bool,
    /// The keyring recovery flow is running.
    recovering: bool,
    /// The idle timer is scheduled.
    auto_lock_armed: bool,
    /// (courier) A first `Ctrl-q` while transfers run; a second one before this quits.
    quit_armed_until: Option<Instant>,
    /// `--no-keyring` / `COURIER_FTP_KEYRING=off`.
    no_keyring: bool,
    /// The vault was unlocked once in this run (the lock overlay is drawn from then on).
    unlocked_once: bool,
    /// A sync account exists (T87).
    sync_account: bool,
    /// The last input while unlocked (auto-lock).
    last_input: Option<Instant>,
}

impl Default for VaultUi {
    fn default() -> Self {
        Self {
            active: false,
            lock: LockState::Unlocked,
            screen: VaultScreen::None,
            mode: VaultMode::Normal,
            keyring_enabled: false,
            deferred_launch: None,
            discarded_forms: false,
            recovering: false,
            auto_lock_armed: false,
            quit_armed_until: None,
            no_keyring: false,
            unlocked_once: false,
            sync_account: false,
            last_input: None,
        }
    }
}

/// `--no-vault`, `--no-keyring` (T70).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct VaultStartOptions {
    /// Do not open the database at all.
    pub no_vault: bool,
    /// Never use the keyring (also `COURIER_FTP_KEYRING=off`).
    pub no_keyring: bool,
}

/// Vault timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum VaultTimer {
    /// The idle auto-lock.
    AutoLockCheck,
    /// One second of the backoff countdown.
    UnlockCountdown,
    /// The armed second `Ctrl-q` expires.
    QuitDisarm,
}

/// An input the vault may take before normal routing.
#[derive(Debug, Clone, Copy)]
pub(crate) enum InputEvent<'a> {
    /// A key.
    Key(KeyChord),
    /// Bracketed paste.
    Paste(&'a str),
}

/// The plural `s`.
fn plural(n: u32) -> &'static str {
    if n == 1 { "" } else { "s" }
}

impl App {
    /// Starts locked with a vault (`Starting`), or without one for `--no-vault`.
    pub(crate) fn with_vault(mut self, opts: VaultStartOptions) -> Self {
        self.start_vault(opts);
        self
    }

    /// [`Self::with_vault`] in place.
    pub(crate) fn start_vault(&mut self, opts: VaultStartOptions) {
        if opts.no_vault {
            self.vault = VaultUi {
                mode: VaultMode::Disabled,
                ..VaultUi::default()
            };
            self.status_sources.vault = Some(VaultIndicator::NoVault);
        } else {
            self.vault = VaultUi {
                active: true,
                lock: LockState::Locked,
                screen: VaultScreen::Starting,
                no_keyring: opts.no_keyring,
                ..VaultUi::default()
            };
            self.status_sources.vault = Some(VaultIndicator::Locked);
            self.set_vault_locked(true);
        }
        self.dirty = true;
    }

    /// Connects the vault service (its `Status` starts the startup flow).
    pub(crate) fn attach_vault_service(&mut self, service: VaultService) {
        self.vault_service = Some(service);
    }

    /// The vault service (T31 and later read items through its engine).
    #[cfg_attr(not(test), allow(dead_code, reason = "T31 reads items"))]
    pub(crate) fn vault_service(&self) -> Option<&VaultService> {
        self.vault_service.as_ref()
    }

    /// The lock state.
    #[cfg_attr(not(test), allow(dead_code, reason = "T58/T59/T64/T68 read it"))]
    pub(crate) fn lock_state(&self) -> LockState {
        self.vault.lock
    }

    /// The vault can be used (unlocked; also without any vault service).
    #[cfg_attr(not(test), allow(dead_code, reason = "T31, T33, T59, T64"))]
    pub(crate) fn vault_available(&self) -> bool {
        self.vault.active && self.vault.lock == LockState::Unlocked
    }

    /// The vault screen.
    #[cfg_attr(not(test), allow(dead_code, reason = "T58/T59/T64/T68 read it"))]
    pub(crate) fn vault_screen(&self) -> &VaultScreen {
        &self.vault.screen
    }

    /// Settings → Security → Change password (T68). Only while unlocked.
    #[cfg_attr(not(test), allow(dead_code, reason = "Settings → Security (T68)"))]
    pub(crate) fn open_change_password(&mut self) {
        if self.vault.active && self.vault.lock == LockState::Unlocked {
            self.vault.screen = VaultScreen::ChangePassword(ChangePasswordForm::new());
            self.dirty = true;
        }
    }

    /// A component needs the vault while running without it (T58/T59/T64): shows the
    /// unlock form over the app; `Esc` on an empty field returns.
    #[cfg_attr(not(test), allow(dead_code, reason = "T58/T59/T64 unlock offers"))]
    pub(crate) fn request_unlock(&mut self) {
        if self.vault.active
            && self.vault.mode == VaultMode::WithoutVault
            && self.vault.lock == LockState::Locked
            && self.vault.screen == VaultScreen::None
        {
            self.vault.screen = VaultScreen::Unlock(self.unlock_form(false));
            self.dirty = true;
        }
    }

    /// Settings → Security: turn keyring unlock on (asks the master password) or off
    /// (asks for confirmation) (T68 hosts the page).
    #[cfg_attr(not(test), allow(dead_code, reason = "Settings → Security (T68)"))]
    pub(crate) fn toggle_keyring_unlock(&mut self, enable: bool) {
        if !self.vault_available() {
            return;
        }
        if enable {
            let dialog = prompt_password(
                "Turn on keyring unlock",
                "Master password (keyring unlock is also the only local recovery path)",
            );
            self.modals.push_then(dialog, |pw| {
                pw.map(|pw| {
                    Action::VaultRequest(VaultEffect::SetKeyringUnlock {
                        enable: true,
                        password: Some(VaultPassword::new(Zeroizing::new(pw.expose().to_owned()))),
                    })
                })
            });
        } else {
            let dialog = confirm(
                "Keyring unlock",
                "Turn off keyring unlock? The keyring entry is deleted; without it a \
                 forgotten master password cannot be recovered on this device.",
                ConfirmOpts::danger("Turn off"),
            );
            self.modals.push_then(dialog, |yes| {
                (yes == Some(true)).then_some(Action::VaultRequest(VaultEffect::SetKeyringUnlock {
                    enable: false,
                    password: None,
                }))
            });
        }
        self.dirty = true;
    }

    /// Sends an effect to the vault service.
    pub(crate) fn send_vault(&mut self, effect: VaultEffect) {
        #[cfg(test)]
        self.vault_effects.push(effect.clone());
        if let Some(service) = &self.vault_service {
            service.send(effect);
        }
    }

    /// An unlock form for the current state.
    fn unlock_form(&mut self, startup: bool) -> UnlockForm {
        UnlockForm {
            keyring_enabled: self.vault.keyring_enabled,
            sessions_open: !startup && self.sessions_or_transfers(),
            startup,
            ..UnlockForm::default()
        }
    }

    /// Connections or transfers exist (they keep running behind the lock).
    fn sessions_or_transfers(&mut self) -> bool {
        !self.session_purposes.is_empty() || !self.main.quit_blockers().is_empty()
    }

    /// The Forgot screen's options on this device.
    fn forgot_screen(&self) -> ForgotScreen {
        ForgotScreen {
            keyring: self.vault.keyring_enabled && !self.vault.no_keyring,
            // T90's recovery screen and T73's restore do not exist yet.
            sync: false,
            restore: false,
        }
    }

    /// Whether the vault takes every input (locked, or a vault form is open).
    fn vault_takes_input(&self) -> bool {
        self.vault.active
            && (self.vault.screen != VaultScreen::None
                || (self.vault.mode == VaultMode::Normal && self.vault.lock.is_locked()))
    }

    /// Input hook, run before normal routing. Returns `true` when the vault consumed the
    /// input (locked, or a vault form is open).
    pub(crate) fn vault_on_input(&mut self, input: &InputEvent<'_>) -> bool {
        if !self.vault.active {
            return false;
        }
        if self.vault.lock == LockState::Unlocked {
            self.note_vault_input();
        }
        if !self.vault_takes_input() {
            return false;
        }
        self.dirty = true;
        match input {
            InputEvent::Key(key) => {
                if self.is_quit_key(*key) {
                    if self.vault.lock == LockState::Unlocked {
                        // A form over the unlocked app: the normal Quit path.
                        return false;
                    }
                    self.vault_quit(*key);
                    return true;
                }
                self.resolver.clear();
                self.vault_form_key(*key);
            }
            InputEvent::Paste(text) => self.vault_paste(text),
        }
        true
    }

    /// The key is bound to `Quit` (T51 `ctrl-q` / `f10`).
    fn is_quit_key(&self, key: KeyChord) -> bool {
        matches!(
            self.resolver.keymap().lookup(super::Mode::Normal, &[key]),
            Lookup::Exact(Action::Quit)
        )
    }

    /// Quit while locked: at once without transfers (a confirmation could not be
    /// answered behind the lock); with transfers a second press within 3 s.
    fn vault_quit(&mut self, key: KeyChord) {
        let now = Instant::now();
        if self.main.quit_blockers().is_empty()
            || self.vault.quit_armed_until.is_some_and(|until| now < until)
        {
            self.modals.close_all();
            self.should_quit = true;
            return;
        }
        self.vault.quit_armed_until = Some(now + QUIT_ARM);
        self.vault_timers.schedule(
            VaultTimer::QuitDisarm,
            QUIT_ARM,
            Action::VaultTimer(VaultTimer::QuitDisarm),
        );
        let keys = status_bar::pretty_keys(&display_sequence(&[key]));
        let text = format!("Transfers are running. Press {keys} again within 3 s to quit.");
        if let VaultScreen::Unlock(f) = &mut self.vault.screen
            && !f.input_disabled()
        {
            f.notice = Some(text);
        } else {
            self.notify(MessageLevel::Warning, &text);
        }
    }

    fn vault_paste(&mut self, text: &str) {
        match &mut self.vault.screen {
            VaultScreen::Unlock(f) if !f.input_disabled() => f.password.push_str(text),
            VaultScreen::FirstRun(f) => f.paste(text),
            VaultScreen::ChangePassword(f) => f.paste(text),
            VaultScreen::PasswordElsewhere(f) if !f.busy => f.password.push_str(text),
            _ => {}
        }
    }

    fn vault_form_key(&mut self, key: KeyChord) {
        let action = match &mut self.vault.screen {
            VaultScreen::FirstRun(f) => f.handle_key(key),
            VaultScreen::Unlock(f) => f.handle_key(key),
            VaultScreen::ChangePassword(f) => f.handle_key(key),
            VaultScreen::Forgot(f) => f.handle_key(key),
            VaultScreen::NewVaultConfirm(f) => f.handle_key(key),
            VaultScreen::PasswordElsewhere(f) => f.handle_key(key),
            VaultScreen::None | VaultScreen::Starting => FormAction::None,
        };
        match action {
            FormAction::None | FormAction::Changed => {}
            FormAction::Submit => self.vault_submit(),
            FormAction::Cancel => self.vault_cancel(),
            FormAction::Forgot => {
                self.vault.screen = VaultScreen::Forgot(self.forgot_screen());
            }
            FormAction::ContinueWithoutVault => self.continue_without_vault(),
            FormAction::Restore => {
                self.notify(
                    MessageLevel::Info,
                    "Restoring from a backup is not available yet",
                );
            }
            FormAction::SyncLogin => {
                self.notify(
                    MessageLevel::Info,
                    "Logging in to a sync server is not available yet",
                );
            }
            FormAction::Choose(c) => self.forgot_choose(c),
        }
    }

    fn forgot_choose(&mut self, c: char) {
        match c {
            'k' => {
                let mut form = self.unlock_form(!self.vault.unlocked_once);
                form.busy = Some(KEYRING_BUSY.into());
                self.vault.screen = VaultScreen::Unlock(form);
                self.vault.recovering = true;
                self.vault.lock = LockState::Unlocking;
                self.send_vault(VaultEffect::Unlock(UnlockRequest::Keyring));
            }
            'n' => self.vault.screen = VaultScreen::NewVaultConfirm(NewVaultConfirm::default()),
            's' => self.notify(
                MessageLevel::Info,
                "Recovery with the sync recovery key is not available yet",
            ),
            'b' => self.notify(
                MessageLevel::Info,
                "Restoring from a backup is not available yet",
            ),
            _ => {}
        }
    }

    fn vault_cancel(&mut self) {
        let unlocked = self.vault.lock == LockState::Unlocked;
        let without = self.vault.mode == VaultMode::WithoutVault;
        match &self.vault.screen {
            VaultScreen::Unlock(_) if without => {
                self.vault.screen = VaultScreen::None;
            }
            VaultScreen::ChangePassword(f) if !f.is_recovery() && unlocked => {
                self.vault.screen = VaultScreen::None;
            }
            VaultScreen::Forgot(_) => {
                let startup = !self.vault.unlocked_once;
                let form = self.unlock_form(startup);
                self.vault.screen = VaultScreen::Unlock(form);
            }
            VaultScreen::NewVaultConfirm(_) => {
                self.vault.screen = VaultScreen::Forgot(self.forgot_screen());
            }
            VaultScreen::PasswordElsewhere(_) => {
                self.vault.screen = VaultScreen::None;
                self.notify(
                    MessageLevel::Info,
                    "Sync stays paused until you enter the new password",
                );
            }
            _ => {}
        }
    }

    fn vault_submit(&mut self) {
        let effect = match &mut self.vault.screen {
            VaultScreen::FirstRun(f) => {
                f.busy = true;
                f.error = None;
                let password = VaultPassword::new(f.new.password.take());
                f.new.confirm.clear();
                self.vault.lock = LockState::Unlocking;
                VaultEffect::Initialize {
                    password,
                    keyring: f.keyring_available && f.use_keyring,
                }
            }
            VaultScreen::Unlock(f) => {
                f.busy = Some("Unlocking…".into());
                f.error = None;
                self.vault.lock = LockState::Unlocking;
                VaultEffect::Unlock(UnlockRequest::Password(VaultPassword::new(
                    f.password.take(),
                )))
            }
            VaultScreen::ChangePassword(f) => {
                f.busy = true;
                f.error = None;
                let current = f.current.as_mut().map(|c| VaultPassword::new(c.take()));
                let new = VaultPassword::new(f.new.password.take());
                f.new.confirm.clear();
                VaultEffect::ChangePassword { current, new }
            }
            VaultScreen::NewVaultConfirm(_) => {
                self.vault.screen = VaultScreen::Starting;
                VaultEffect::StartNewVault
            }
            VaultScreen::PasswordElsewhere(f) => {
                f.busy = true;
                f.error = None;
                VaultEffect::Relogin {
                    password: VaultPassword::new(f.password.take()),
                }
            }
            VaultScreen::Forgot(_) | VaultScreen::None | VaultScreen::Starting => return,
        };
        self.send_vault(effect);
    }

    /// "Continue without vault": quickconnect only, nothing saved; the vault stays
    /// locked and auto-lock is not armed.
    fn continue_without_vault(&mut self) {
        self.vault.mode = VaultMode::WithoutVault;
        self.vault.screen = VaultScreen::None;
        self.vault.lock = LockState::Locked;
        self.vault.recovering = false;
        // Prompts (host keys of quickconnect) work again; nothing is remembered.
        self.set_vault_locked(false);
        self.notify(
            MessageLevel::Info,
            "Running without the vault: quickconnect only, nothing is saved",
        );
        if let Some(intent) = self.vault.deferred_launch.take() {
            self.on_launch(intent);
        }
    }

    /// `LockVault`, the idle timer, resume from sleep, `Ctrl-z`, `LockRequested`.
    pub(crate) fn lock_vault(&mut self) {
        if !self.vault.active
            || self.vault.mode != VaultMode::Normal
            || self.vault.lock != LockState::Unlocked
        {
            return;
        }
        // 1. Zeroize first, then everything else.
        self.vault.lock = LockState::Locked;
        self.vault.recovering = false;
        self.vault.auto_lock_armed = false;
        self.vault.quit_armed_until = None;
        self.vault_timers.cancel_all();
        self.send_vault(VaultEffect::Lock);
        // 2. A pending key sequence is dropped.
        self.resolver.clear();
        // 3. Dialogs close; unsaved forms are discarded (toast after unlock).
        if self.modals.any_dirty() {
            self.vault.discarded_forms = true;
        }
        self.modals.close_all();
        self.set_vault_locked(true);
        // 4. Decrypted UI data goes with the keys: the site tree, bookmarks and
        //    history lists drop theirs here (T59, T64, T58).
        // 5. Sessions.
        let disconnect = self.settings.current().vault.lock_disconnects;
        if disconnect {
            self.disconnect_sessions_on_lock();
        }
        // 6. The unlock form over the overlay.
        let mut form = self.unlock_form(false);
        form.sessions_open &= !disconnect;
        self.vault.screen = VaultScreen::Unlock(form);
        self.status_sources.vault = Some(VaultIndicator::Locked);
        debug!("vault locked by the ui");
        self.dirty = true;
    }

    /// `vault.lock_disconnects`: every session is closed. The tabs own the sessions
    /// (T61 closes them through `disconnect_requests`); until then the request is
    /// recorded and logged.
    fn disconnect_sessions_on_lock(&mut self) {
        let mut ids: Vec<SessionId> = self.session_purposes.keys().copied().collect();
        ids.sort_by_key(|s| s.get());
        debug!(sessions = ids.len(), "lock disconnects sessions");
        self.disconnect_requests.extend(ids);
    }

    /// Input while unlocked: restart the idle countdown (arms the timer if needed).
    fn note_vault_input(&mut self) {
        if self.vault.mode != VaultMode::Normal {
            return;
        }
        self.vault.last_input = Some(Instant::now());
        if !self.vault.auto_lock_armed {
            self.arm_auto_lock();
        } else if self.auto_lock_after().is_none() {
            self.vault.auto_lock_armed = false;
            self.vault_timers.cancel(VaultTimer::AutoLockCheck);
        }
    }

    fn auto_lock_after(&self) -> Option<Duration> {
        auto_lock_timeout(self.settings.current().vault.auto_lock_minutes)
    }

    /// (Re-)arm the idle auto-lock timer from the last input, or cancel it when
    /// `auto_lock_minutes = 0`.
    fn arm_auto_lock(&mut self) {
        match self.auto_lock_after() {
            Some(after) => {
                let now = Instant::now();
                let last = *self.vault.last_input.get_or_insert(now);
                let left = (last + after).saturating_duration_since(now);
                self.vault.auto_lock_armed = true;
                self.vault_timers.schedule(
                    VaultTimer::AutoLockCheck,
                    left,
                    Action::VaultTimer(VaultTimer::AutoLockCheck),
                );
            }
            None => {
                if self.vault.auto_lock_armed {
                    self.vault_timers.cancel(VaultTimer::AutoLockCheck);
                }
                self.vault.auto_lock_armed = false;
            }
        }
    }

    /// A vault timer fired.
    pub(crate) fn vault_on_timer(&mut self, kind: VaultTimer) {
        let now = Instant::now();
        if !self.vault_timers.take_due(kind, now) {
            return;
        }
        self.dirty = true;
        match kind {
            VaultTimer::AutoLockCheck => {
                self.vault.auto_lock_armed = false;
                // `auto_lock_minutes` may have been set to 0 since the timer was armed.
                let Some(after) = self.auto_lock_after() else {
                    return;
                };
                let idle = self
                    .vault
                    .last_input
                    .is_none_or(|last| now.saturating_duration_since(last) >= after);
                if idle {
                    self.lock_vault();
                } else {
                    self.arm_auto_lock();
                }
            }
            VaultTimer::UnlockCountdown => {
                if let VaultScreen::Unlock(f) = &mut self.vault.screen
                    && let Some(secs) = f.countdown
                {
                    f.countdown = secs.checked_sub(1).filter(|s| *s > 0);
                    if f.countdown.is_some() {
                        self.vault_timers.schedule(
                            VaultTimer::UnlockCountdown,
                            Duration::from_secs(1),
                            Action::VaultTimer(VaultTimer::UnlockCountdown),
                        );
                    }
                }
            }
            VaultTimer::QuitDisarm => {
                self.vault.quit_armed_until = None;
                if let VaultScreen::Unlock(f) = &mut self.vault.screen {
                    f.notice = None;
                }
            }
        }
    }

    fn start_countdown(&mut self, retry_after: Duration) {
        let secs = retry_after.as_millis().div_ceil(1000);
        let secs = u64::try_from(secs).unwrap_or(u64::MAX).max(1);
        if let VaultScreen::Unlock(f) = &mut self.vault.screen {
            f.countdown = Some(secs);
            self.vault_timers.schedule(
                VaultTimer::UnlockCountdown,
                Duration::from_secs(1),
                Action::VaultTimer(VaultTimer::UnlockCountdown),
            );
        }
    }

    /// Every tick: resume from sleep (wall clock advanced much more than the monotonic
    /// clock, or the process was frozen) locks when `vault.lock_on_suspend`.
    pub(crate) fn vault_on_tick(&mut self) {
        if !self.vault.active || self.vault.lock != LockState::Unlocked {
            // Start sampling afresh after the next unlock.
            self.suspend = courier_ftp_core::vault::SuspendDetector::new();
            return;
        }
        let wall = self.wall_now();
        let mono = Instant::now().into_std();
        if self.suspend.tick(wall, mono) && self.settings.current().vault.lock_on_suspend {
            debug!("resume from suspend detected; locking the vault");
            self.lock_vault();
        }
    }

    /// The wall clock (tests derive it from the virtual clock plus a simulated jump).
    fn wall_now(&self) -> SystemTime {
        #[cfg(test)]
        {
            SystemTime::UNIX_EPOCH
                + Duration::from_secs(1_700_000_000)
                + Instant::now().duration_since(self.started)
                + self.wall_jump
        }
        #[cfg(not(test))]
        {
            SystemTime::now()
        }
    }

    /// `Suspend` (`Ctrl-z`): lock first when `vault.lock_on_suspend`.
    pub(crate) fn vault_on_suspend(&mut self) {
        if self.settings.current().vault.lock_on_suspend {
            self.lock_vault();
        }
    }

    /// Holds the launch intent back while locked; returns it when it may run now.
    #[cfg_attr(not(test), allow(dead_code, reason = "T70 sends launch intents"))]
    pub(crate) fn vault_defer_launch(&mut self, intent: LaunchIntent) -> Option<LaunchIntent> {
        if self.vault.active && self.vault.mode == VaultMode::Normal && self.vault.lock.is_locked()
        {
            self.vault.deferred_launch = Some(intent);
            None
        } else {
            Some(intent)
        }
    }

    /// Runs a launch intent (T70 wires it to quickconnect and the Site Manager).
    pub(crate) fn on_launch(&mut self, intent: LaunchIntent) {
        if matches!(intent, LaunchIntent::Site(_)) && self.vault.active && !self.vault_available() {
            self.notify(MessageLevel::Error, "Unlock the vault to open saved sites");
            return;
        }
        let what = match &intent {
            LaunchIntent::Site(_) => "Opening saved sites is not available yet",
            LaunchIntent::Url(_) => "Connecting to a URL is not available yet",
        };
        self.notify(MessageLevel::Info, what);
        #[cfg(test)]
        self.launched.push(intent);
    }

    /// `Action::Vault`.
    pub(crate) fn on_vault(&mut self, ev: VaultEvent) {
        self.dirty = true;
        match ev {
            VaultEvent::Status(status) => self.on_vault_status(status),
            VaultEvent::Unlocked { via_keyring, note } => {
                if !self.vault.active {
                    return;
                }
                debug!(
                    via = if via_keyring { "keyring" } else { "password" },
                    "vault unlock ok"
                );
                self.vault.lock = LockState::Unlocked;
                self.vault.mode = VaultMode::Normal;
                self.vault.unlocked_once = true;
                self.vault.quit_armed_until = None;
                self.vault.screen = if std::mem::take(&mut self.vault.recovering) {
                    VaultScreen::ChangePassword(ChangePasswordForm::recovery())
                } else {
                    VaultScreen::None
                };
                self.vault_timers.cancel(VaultTimer::UnlockCountdown);
                self.vault_timers.cancel(VaultTimer::QuitDisarm);
                self.vault.last_input = None;
                self.vault.auto_lock_armed = false;
                self.arm_auto_lock();
                self.status_sources.vault = None;
                self.set_vault_locked(false);
                if let Some(note) = note {
                    self.notify(MessageLevel::Warning, &note);
                }
                if std::mem::take(&mut self.vault.discarded_forms) {
                    self.notify(MessageLevel::Info, DISCARDED_FORMS);
                }
                if let Some(intent) = self.vault.deferred_launch.take() {
                    self.on_launch(intent);
                }
            }
            VaultEvent::UnlockFailed(failure) => self.on_unlock_failed(failure),
            VaultEvent::PasswordChanged => {
                if matches!(self.vault.screen, VaultScreen::ChangePassword(_)) {
                    self.vault.screen = VaultScreen::None;
                }
                self.notify(MessageLevel::Success, "Master password changed");
            }
            VaultEvent::PasswordChangeFailed(msg) => {
                if let VaultScreen::ChangePassword(f) = &mut self.vault.screen {
                    f.busy = false;
                    f.error = Some(msg);
                    f.focus = 0;
                } else {
                    self.notify(MessageLevel::Error, &msg);
                }
            }
            VaultEvent::LockRequested => self.lock_vault(),
            VaultEvent::KeyringChanged { enabled } => {
                self.vault.keyring_enabled = enabled;
                self.notify(
                    MessageLevel::Success,
                    if enabled {
                        "Keyring unlock is on (it is also the only local recovery path)"
                    } else {
                        "Keyring unlock is off"
                    },
                );
            }
            VaultEvent::KeyringChangeFailed(msg) => self.notify(MessageLevel::Error, &msg),
            VaultEvent::NewVaultStarted { old_path_display } => {
                self.notify(
                    MessageLevel::Info,
                    &format!("The old vault was kept as {old_path_display}"),
                );
            }
            VaultEvent::NewVaultFailed(msg) => {
                self.vault.screen = VaultScreen::Forgot(self.forgot_screen());
                let text = format!("Could not move the database aside: {msg}");
                self.modals.push_then(
                    message(
                        "Start a new vault",
                        &text,
                        crate::components::dialog::standard::MessageLevel::Error,
                    ),
                    |_| None,
                );
            }
            VaultEvent::PasswordChangedElsewhere => {
                if self.vault.lock == LockState::Unlocked && self.vault.screen == VaultScreen::None
                {
                    self.vault.screen =
                        VaultScreen::PasswordElsewhere(PasswordElsewhereForm::default());
                }
            }
            VaultEvent::Relogin(result) => match result {
                Ok(()) => {
                    if matches!(self.vault.screen, VaultScreen::PasswordElsewhere(_)) {
                        self.vault.screen = VaultScreen::None;
                    }
                    self.notify(MessageLevel::Success, "Signed in again; sync resumed");
                }
                Err(msg) => {
                    if let VaultScreen::PasswordElsewhere(f) = &mut self.vault.screen {
                        f.busy = false;
                        f.error = Some(msg);
                    } else {
                        self.notify(MessageLevel::Error, &msg);
                    }
                }
            },
        }
    }

    fn on_vault_status(&mut self, status: VaultStatusInfo) {
        if !self.vault.active {
            return;
        }
        self.vault.keyring_enabled = status.keyring_enabled;
        self.vault.sync_account = status.sync_account;
        self.vault.mode = VaultMode::Normal;
        self.vault.lock = LockState::Locked;
        self.status_sources.vault = Some(VaultIndicator::Locked);
        if !status.initialized {
            self.vault.screen = VaultScreen::FirstRun(FirstRunForm::new(
                status.keyring_available && !self.vault.no_keyring,
            ));
            return;
        }
        let mut form = self.unlock_form(!self.vault.unlocked_once);
        let keyring = status.keyring_enabled && !self.vault.no_keyring;
        if keyring {
            // Keyring first; the prompt appears if it fails.
            form.busy = Some(KEYRING_BUSY.into());
            self.vault.lock = LockState::Unlocking;
        }
        self.vault.screen = VaultScreen::Unlock(form);
        if keyring {
            self.send_vault(VaultEffect::Unlock(UnlockRequest::Keyring));
        } else if let Some(retry_after) = status.retry_after {
            self.start_countdown(retry_after);
        }
    }

    fn on_unlock_failed(&mut self, failure: UnlockFailure) {
        if self.vault.lock == LockState::Unlocked {
            return;
        }
        if failure == UnlockFailure::InProgress {
            // The first attempt's result decides; the form stays busy.
            debug!("vault unlock already in progress");
            return;
        }
        self.vault.lock = LockState::Locked;
        match &failure {
            UnlockFailure::WrongPassword { failures, .. } => {
                debug!(failures, "vault unlock failed");
            }
            _ => debug!("vault unlock failed"),
        }
        let mut countdown = None;
        let mut info = None;
        match &mut self.vault.screen {
            VaultScreen::FirstRun(f) => {
                f.busy = false;
                f.error = Some(match failure {
                    UnlockFailure::Other(msg) | UnlockFailure::Keyring(msg) => msg,
                    UnlockFailure::Busy => busy_text().to_owned(),
                    other => format!("Could not create the vault ({other:?})"),
                });
            }
            VaultScreen::Unlock(f) => {
                f.busy = None;
                f.password.clear();
                match failure {
                    UnlockFailure::WrongPassword {
                        failures,
                        retry_after,
                    } => {
                        f.error = Some(format!(
                            "Wrong password ({failures} failed attempt{})",
                            plural(failures)
                        ));
                        countdown = retry_after;
                    }
                    UnlockFailure::Backoff { retry_after } => countdown = Some(retry_after),
                    UnlockFailure::Keyring(msg) => {
                        info = Some(format!(
                            "Keyring unlock failed ({msg}); enter your master password"
                        ));
                    }
                    UnlockFailure::Busy => f.error = Some(busy_text().to_owned()),
                    UnlockFailure::Other(msg) => f.error = Some(msg),
                    UnlockFailure::InProgress => {}
                }
            }
            _ => {
                info = Some(match failure {
                    UnlockFailure::Other(msg) | UnlockFailure::Keyring(msg) => msg,
                    _ => "The vault could not be unlocked".to_owned(),
                });
            }
        }
        self.vault.recovering = false;
        if let Some(d) = countdown {
            self.start_countdown(d);
        }
        if let Some(text) = info {
            self.notify(MessageLevel::Info, &text);
        }
    }

    /// Whether the vault covers the app: locked (or before the first unlock) in normal
    /// mode. Nothing but the vault screen and the status bar is drawn then.
    pub(crate) fn vault_hides_panes(&self) -> bool {
        self.vault.active && self.vault.mode == VaultMode::Normal && self.vault.lock.is_locked()
    }

    /// The Quit key as a hint (`Ctrl-q`; any non-function key first).
    fn quit_key_hint(&self) -> String {
        let all = self.key_hint_all("Quit");
        all.iter()
            .find(|k| !k.starts_with('F'))
            .or_else(|| all.first())
            .cloned()
            .unwrap_or_else(|| "Ctrl-q".to_owned())
    }

    /// The status bar while locked: security (no host), vault, transfer type, speed
    /// and queue only; no hints.
    fn locked_status_info(&self) -> StatusInfo<'static> {
        let s = &self.status_sources;
        let security = if s.connecting {
            SecurityIndicator::Connecting
        } else {
            s.session
                .as_ref()
                .map_or(SecurityIndicator::NotConnected, |x| {
                    SecurityIndicator::from_security_info(&x.info, None)
                })
        };
        let settings = self.settings.current();
        let t = &settings.transfers;
        StatusInfo {
            security,
            vault: s.vault,
            prompts_badge: None,
            transfer_type: Some(settings.file_types.default_type),
            speed: Some(status_bar::SpeedLimitIndicator {
                enabled: t.speed_limit_enabled,
                down_kib: t.download_limit_kib,
                up_kib: t.upload_limit_kib,
            }),
            filters_active: false,
            sync_browsing: false,
            comparison: false,
            sync: None,
            queue: s.queue,
            pending_keys: "",
            message: None,
            hints: &[],
        }
    }

    /// Draws the lock screen (locked: status bar, overlay, vault screen) or a vault
    /// form over the app.
    pub(crate) fn render_vault(&self, frame: &mut Frame<'_>) {
        if !self.vault.active {
            return;
        }
        let area = frame.area();
        let look = Look::new(&self.theme, &self.symbols);
        let covering = self.vault_hides_panes();
        if covering {
            frame.render_widget(Clear, area);
            if area.width < 40 || area.height < 12 {
                let text = "Terminal too small";
                let y = area.y + area.height / 2;
                frame.render_widget(
                    Paragraph::new(text)
                        .alignment(Alignment::Center)
                        .wrap(Wrap { trim: true }),
                    Rect {
                        y,
                        height: area.height.saturating_sub(y - area.y),
                        ..area
                    },
                );
                return;
            }
        }
        let body = if covering {
            let status = Rect {
                y: area.bottom() - 1,
                height: 1,
                ..area
            };
            let info = StatusInfo {
                message: self.main.status(),
                ..self.locked_status_info()
            };
            status_bar::render(frame, status, &info, &self.symbols, &self.theme);
            Rect {
                height: area.height - 1,
                ..area
            }
        } else {
            Rect {
                height: area.height.saturating_sub(1),
                ..area
            }
        };
        if covering && self.vault.unlocked_once {
            lock_overlay::render(frame, body, look, &self.quit_key_hint());
        }
        match &self.vault.screen {
            VaultScreen::FirstRun(f) => f.render(frame, body, look),
            VaultScreen::Unlock(f) => f.render(frame, body, look),
            VaultScreen::ChangePassword(f) => f.render(frame, body, look),
            VaultScreen::Forgot(f) => f.render(frame, body, look),
            VaultScreen::NewVaultConfirm(f) => f.render(frame, body, look),
            VaultScreen::PasswordElsewhere(f) => f.render(frame, body, look),
            VaultScreen::None | VaultScreen::Starting => {}
        }
    }
}

/// `UnlockFailure::Busy`.
fn busy_text() -> &'static str {
    "The database is busy (another courier-ftp may be writing). Enter the password again \
     to retry."
}

/// Masked fields used by tests.
#[cfg(test)]
pub(crate) fn masked(text: &str) -> crate::views::unlock::MaskedField {
    let mut f = crate::views::unlock::MaskedField::default();
    f.push_str(text);
    f
}
