//! The vault screens (T60, D3): first-run setup, the unlock view (also the
//! lock overlay), "Forgot password?", the keyring reset and "start a new
//! empty vault".
//!
//! [`VaultView`] is a full-screen view, not a modal: while it is shown the
//! panes are hidden and it takes every key. It never talks to the vault
//! itself; what the user asks for comes out as a [`VaultRequest`] that the app
//! runs in the background (Argon2 must not block drawing) and reports back
//! through the `show_*` / `*_failed` methods.
//!
//! Passwords live only in masked [`TextInput`]s, which zeroize their buffer
//! when cleared or dropped; a request carries a [`SecretString`].

use std::time::{Duration, Instant};

use courier_ftp_core::vault::{NO_RECOVERY_WARNING, PasswordStrength, VaultError, estimate};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use secrecy::SecretString;

use super::{
    dialog::{ButtonRow, Checkbox, Field, TextInput},
    modal::centered,
    theme::Theme,
};

/// What the user asked the vault to do.
pub(crate) enum VaultRequest {
    /// First run: create the vault (and enrol the keyring).
    Create {
        password: SecretString,
        keyring: bool,
    },
    /// Unlock with the master password.
    Unlock(SecretString),
    /// "Unlock with the system keyring and set a new password".
    Reset(SecretString),
    /// Continue without the vault (quickconnect only, nothing saved).
    Skip,
    /// Open the database again (after "database busy").
    Retry,
    /// Move the database aside and start a new empty vault.
    NewVault,
    /// Quit courier-ftp.
    Quit,
}

impl std::fmt::Debug for VaultRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the secret.
        f.write_str(match self {
            Self::Create { .. } => "Create",
            Self::Unlock(_) => "Unlock",
            Self::Reset(_) => "Reset",
            Self::Skip => "Skip",
            Self::Retry => "Retry",
            Self::NewVault => "NewVault",
            Self::Quit => "Quit",
        })
    }
}

/// What the view knows about this device's vault (no secrets).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct VaultFacts {
    /// Keyring unlock is enabled on this device.
    pub(crate) keyring_enabled: bool,
    /// The OS keyring works (offer the first-run checkbox).
    pub(crate) keyring_available: bool,
    /// A sync account exists (recovery code + words, T90). Always `false`
    /// until sync accounts exist.
    pub(crate) sync_account: bool,
}

/// Which page is shown (for tests).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultPage {
    Opening,
    Unavailable,
    Create,
    Unlock,
    Forgot,
    Reset,
    NewVault,
}

/// The two-password form of first run and the keyring reset.
struct PasswordForm {
    password: TextInput,
    confirm: TextInput,
    keyring: Option<Checkbox>,
    buttons: ButtonRow,
    focus: usize,
    strength: PasswordStrength,
}

impl PasswordForm {
    fn new(keyring: bool, buttons: &[&str]) -> Self {
        Self {
            password: TextInput::password("Master password"),
            confirm: TextInput::password("Confirm"),
            keyring: keyring
                .then(|| Checkbox::new("Unlock with system keyring on this device", false)),
            buttons: ButtonRow::new(buttons, 0),
            focus: 0,
            strength: PasswordStrength::default(),
        }
    }

    fn slots(&self) -> usize {
        3 + usize::from(self.keyring.is_some())
    }

    fn on_buttons(&self) -> bool {
        self.focus + 1 == self.slots()
    }

    fn rescore(&mut self) {
        self.strength = self.password.with_text(|pw| estimate(pw, &[]));
    }

    /// Checks strength and confirmation; the error to show otherwise.
    fn check(&self) -> Result<(), String> {
        if self.password.is_empty() {
            return Err("Choose a master password.".to_owned());
        }
        if !self.strength.acceptable() {
            let feedback = self.strength.feedback();
            return Err(format!(
                "Too weak ({}): a strong password is required.{}{}",
                self.strength.label(),
                if feedback.is_empty() { "" } else { " " },
                feedback
            ));
        }
        let same = self
            .password
            .with_text(|a| self.confirm.with_text(|b| a == b));
        if !same {
            return Err("The passwords don't match.".to_owned());
        }
        Ok(())
    }

    fn handle_paste(&mut self, text: &str) {
        match self.focus {
            0 => {
                self.password.handle_paste(text);
                self.rescore();
            }
            1 => self.confirm.handle_paste(text),
            _ => {}
        }
    }
}

/// Up/down list of the recovery options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForgotOption {
    KeyringReset,
    RestoreBackup,
    NewVault,
    Back,
}

impl ForgotOption {
    fn label(self) -> &'static str {
        match self {
            Self::KeyringReset => "Unlock with the system keyring and set a new password",
            Self::RestoreBackup => "Restore from a .cftp-backup file",
            Self::NewVault => "Start a new empty vault (the old database is moved aside)",
            Self::Back => "Back",
        }
    }
}

enum Page {
    Opening,
    Unavailable {
        error: String,
        buttons: ButtonRow,
    },
    Create(PasswordForm),
    Unlock {
        password: TextInput,
        buttons: ButtonRow,
        on_buttons: bool,
    },
    Forgot {
        options: Vec<ForgotOption>,
        cursor: usize,
    },
    Reset(PasswordForm),
    NewVault(ButtonRow),
}

/// The vault screens (see the module docs).
pub(crate) struct VaultView {
    page: Page,
    facts: VaultFacts,
    /// A background operation runs: its message next to a spinner. Input is
    /// ignored meanwhile (except quitting).
    busy: Option<String>,
    /// One informational line (why the vault locked, keyring fallback).
    note: Option<String>,
    /// One error line.
    error: Option<String>,
    /// Consecutive failed unlocks (persisted by the engine).
    failures: u32,
    /// No password attempt before this.
    retry_at: Option<Instant>,
    unicode: bool,
    tick: u64,
}

const LABEL_W: u16 = 18;
const PANEL_W: u16 = 78;
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_ASCII: [&str; 4] = ["|", "/", "-", "\\"];

impl VaultView {
    /// The "opening the vault" placeholder shown at start.
    pub(crate) fn opening(unicode: bool) -> Self {
        Self {
            page: Page::Opening,
            facts: VaultFacts::default(),
            busy: Some("Opening the vault…".to_owned()),
            note: None,
            error: None,
            failures: 0,
            retry_at: None,
            unicode,
            tick: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn page(&self) -> VaultPage {
        match self.page {
            Page::Opening => VaultPage::Opening,
            Page::Unavailable { .. } => VaultPage::Unavailable,
            Page::Create(_) => VaultPage::Create,
            Page::Unlock { .. } => VaultPage::Unlock,
            Page::Forgot { .. } => VaultPage::Forgot,
            Page::Reset(_) => VaultPage::Reset,
            Page::NewVault(_) => VaultPage::NewVault,
        }
    }

    #[cfg(test)]
    pub(crate) fn is_busy(&self) -> bool {
        self.busy.is_some()
    }

    pub(crate) fn facts(&self) -> VaultFacts {
        self.facts
    }

    /// The database could not be opened (busy, damaged).
    pub(crate) fn show_unavailable(&mut self, error: String) {
        self.page = Page::Unavailable {
            error,
            buttons: ButtonRow::new(&["Retry", "Continue without vault", "Quit"], 0),
        };
        self.busy = None;
        self.error = None;
    }

    /// First run.
    pub(crate) fn show_create(&mut self, facts: VaultFacts) {
        self.facts = facts;
        self.page = Page::Create(PasswordForm::new(
            facts.keyring_available,
            &["Set password", "Continue without vault"],
        ));
        self.busy = None;
        self.error = None;
    }

    /// The unlock view (also the lock overlay). `retry_after` is the backoff
    /// the engine reported at `now`.
    pub(crate) fn show_unlock(
        &mut self,
        facts: VaultFacts,
        failures: u32,
        retry_after: Option<Duration>,
        now: Instant,
    ) {
        self.facts = facts;
        self.failures = failures;
        self.retry_at = retry_after.map(|d| now + d);
        self.unlock_page();
        self.busy = None;
        self.error = None;
    }

    fn unlock_page(&mut self) {
        self.page = Page::Unlock {
            password: TextInput::password("Master password"),
            buttons: ButtonRow::new(&["Unlock", "Continue without vault", "Forgot password?"], 0),
            on_buttons: false,
        };
    }

    fn forgot_page(&mut self) {
        let mut options = Vec::new();
        if self.facts.keyring_enabled {
            options.push(ForgotOption::KeyringReset);
        }
        if !self.facts.keyring_enabled && !self.facts.sync_account {
            options.push(ForgotOption::RestoreBackup);
            options.push(ForgotOption::NewVault);
        }
        options.push(ForgotOption::Back);
        self.page = Page::Forgot { options, cursor: 0 };
        self.error = None;
    }

    /// Show `message` with a spinner and ignore input until the next
    /// `show_*`/`*_failed`/`set_busy(None)`.
    pub(crate) fn set_busy(&mut self, message: Option<&str>) {
        self.busy = message.map(str::to_owned);
        if self.busy.is_some() {
            self.error = None;
        }
    }

    pub(crate) fn set_note(&mut self, note: Option<String>) {
        self.note = note;
    }

    pub(crate) fn set_error(&mut self, error: Option<String>) {
        self.busy = None;
        self.error = error;
    }

    /// An unlock (or keyring reset) failed: show why, clear the field and
    /// start the backoff countdown.
    pub(crate) fn unlock_failed(&mut self, err: &VaultError, now: Instant) {
        self.busy = None;
        if let Page::Unlock { password, .. } = &mut self.page {
            password.clear();
        }
        match err {
            VaultError::WrongPassword {
                failures,
                retry_after,
            } => {
                self.failures = *failures;
                self.retry_at = retry_after.map(|d| now + d);
                self.error = Some("Wrong master password.".to_owned());
            }
            VaultError::Backoff { retry_after } => {
                self.retry_at = Some(now + *retry_after);
                self.error = Some("Too many failed attempts; wait for the countdown.".to_owned());
            }
            other => self.error = Some(capitalised(&other.to_string())),
        }
    }

    /// Advance the spinner.
    pub(crate) fn tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
    }

    /// Seconds left before the next attempt, rounded up; `None` when free.
    fn wait_secs(&self, now: Instant) -> Option<u64> {
        let left = self.retry_at?.checked_duration_since(now)?;
        if left.is_zero() {
            return None;
        }
        Some(left.as_secs() + u64::from(left.subsec_nanos() > 0))
    }

    pub(crate) fn handle_paste(&mut self, text: &str) {
        if self.busy.is_some() {
            return;
        }
        match &mut self.page {
            Page::Unlock {
                password,
                on_buttons: false,
                ..
            } => password.handle_paste(text),
            Page::Create(form) | Page::Reset(form) => form.handle_paste(text),
            _ => {}
        }
    }

    /// Handle a key at `now`; what the user asked for, if anything.
    pub(crate) fn handle_key(&mut self, key: KeyEvent, now: Instant) -> Option<VaultRequest> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(key.code, KeyCode::Char('q') | KeyCode::Char('c')) {
            return Some(VaultRequest::Quit);
        }
        if self.busy.is_some() {
            return None;
        }
        match &mut self.page {
            Page::Opening => None,
            Page::Unavailable { buttons, .. } => match buttons.handle_key(key) {
                Some(0) => Some(VaultRequest::Retry),
                Some(1) => Some(VaultRequest::Skip),
                Some(_) => Some(VaultRequest::Quit),
                None => None,
            },
            Page::Unlock { .. } => self.unlock_key(key, now),
            Page::Create(_) => self.password_form_key(key, true),
            Page::Reset(_) => self.password_form_key(key, false),
            Page::Forgot { options, cursor } => {
                match key.code {
                    KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                        *cursor = (*cursor + 1).min(options.len().saturating_sub(1));
                    }
                    KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                        *cursor = cursor.saturating_sub(1);
                    }
                    KeyCode::Esc => self.unlock_page(),
                    KeyCode::Enter => match options.get(*cursor).copied() {
                        Some(ForgotOption::KeyringReset) => {
                            self.page = Page::Reset(PasswordForm::new(
                                false,
                                &["Set new password", "Back"],
                            ));
                            self.error = None;
                        }
                        Some(ForgotOption::RestoreBackup) => {
                            self.error = Some(
                                "Restoring a .cftp-backup is not available in this build yet (T73)."
                                    .to_owned(),
                            );
                        }
                        Some(ForgotOption::NewVault) => {
                            self.page = Page::NewVault(ButtonRow::new(
                                &["Move it aside and start over", "Back"],
                                1,
                            ));
                            self.error = None;
                        }
                        Some(ForgotOption::Back) | None => self.unlock_page(),
                    },
                    _ => {}
                }
                None
            }
            Page::NewVault(buttons) => {
                if key.code == KeyCode::Esc {
                    self.forgot_page();
                    return None;
                }
                match buttons.handle_key(key) {
                    Some(0) => {
                        self.busy = Some("Moving the old database aside…".to_owned());
                        Some(VaultRequest::NewVault)
                    }
                    Some(_) => {
                        self.forgot_page();
                        None
                    }
                    None => None,
                }
            }
        }
    }

    fn unlock_key(&mut self, key: KeyEvent, now: Instant) -> Option<VaultRequest> {
        let wait = self.wait_secs(now);
        let Page::Unlock {
            password,
            buttons,
            on_buttons,
        } = &mut self.page
        else {
            return None;
        };
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        let pressed = if alt {
            buttons.handle_key(key)
        } else if *on_buttons {
            match key.code {
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Up => {
                    *on_buttons = false;
                    None
                }
                _ => buttons.handle_key(key),
            }
        } else {
            match key.code {
                KeyCode::Enter => Some(0),
                KeyCode::Tab | KeyCode::Down => {
                    *on_buttons = true;
                    None
                }
                _ => {
                    password.handle_key(key);
                    None
                }
            }
        };
        match pressed? {
            0 => {
                if let Some(secs) = wait {
                    self.error = Some(format!("Too many failed attempts; try again in {secs} s."));
                    return None;
                }
                if password.is_empty() {
                    self.error = Some("Enter the master password.".to_owned());
                    return None;
                }
                let secret = password.secret();
                password.clear();
                self.busy = Some("Unlocking…".to_owned());
                self.error = None;
                Some(VaultRequest::Unlock(secret))
            }
            1 => Some(VaultRequest::Skip),
            _ => {
                self.forgot_page();
                None
            }
        }
    }

    fn password_form_key(&mut self, key: KeyEvent, create: bool) -> Option<VaultRequest> {
        let (Page::Create(form) | Page::Reset(form)) = &mut self.page else {
            return None;
        };
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        let slots = form.slots();
        let pressed = if alt {
            form.buttons.handle_key(key)
        } else {
            match key.code {
                KeyCode::Tab | KeyCode::Down => {
                    form.focus = (form.focus + 1) % slots;
                    None
                }
                KeyCode::BackTab | KeyCode::Up => {
                    form.focus = (form.focus + slots - 1) % slots;
                    None
                }
                KeyCode::Esc if !create => Some(1),
                KeyCode::Esc => None,
                _ if form.on_buttons() => form.buttons.handle_key(key),
                KeyCode::Enter => Some(0),
                _ => {
                    match form.focus {
                        0 => {
                            form.password.handle_key(key);
                            form.rescore();
                        }
                        1 => {
                            form.confirm.handle_key(key);
                        }
                        _ => {
                            if let Some(cb) = &mut form.keyring {
                                cb.handle_key(key);
                            }
                        }
                    }
                    None
                }
            }
        };
        match pressed? {
            0 => {
                if let Err(e) = form.check() {
                    self.error = Some(e);
                    return None;
                }
                let password = form.password.secret();
                let keyring = form
                    .keyring
                    .as_ref()
                    .is_some_and(|cb| matches!(cb.value(), super::dialog::FieldValue::Bool(true)));
                form.password.clear();
                form.confirm.clear();
                form.rescore();
                form.focus = 0;
                self.error = None;
                if create {
                    self.busy = Some("Creating the vault…".to_owned());
                    Some(VaultRequest::Create { password, keyring })
                } else {
                    self.busy = Some("Setting the new password…".to_owned());
                    Some(VaultRequest::Reset(password))
                }
            }
            _ if create => Some(VaultRequest::Skip),
            _ => {
                self.forgot_page();
                None
            }
        }
    }

    fn spinner(&self) -> &'static str {
        if self.unicode {
            SPINNER[(self.tick as usize) % SPINNER.len()]
        } else {
            SPINNER_ASCII[(self.tick as usize) % SPINNER_ASCII.len()]
        }
    }

    /// Draw over `area` (everything but the status bar) at `now`.
    pub(crate) fn draw(&self, frame: &mut Frame, area: Rect, theme: &Theme, now: Instant) {
        frame.render_widget(Clear, area);
        let width = PANEL_W.min(area.width);
        let text_w = usize::from(width.saturating_sub(4)).max(10);
        let mut body = Body::new(text_w);
        let title = self.build(&mut body, theme, now);
        let height = u16::try_from(body.lines.len())
            .unwrap_or(u16::MAX)
            .saturating_add(2);
        let rect = centered(area, width, height);
        let block = Block::bordered()
            .title(title)
            .border_style(theme.focused_border);
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        let inner = Rect::new(
            inner.x + 1,
            inner.y,
            inner.width.saturating_sub(2),
            inner.height,
        );
        frame.render_widget(Paragraph::new(body.lines.clone()), inner);
        for (mark, row) in &body.marks {
            let Ok(row) = u16::try_from(*row) else {
                continue;
            };
            if row >= inner.height {
                continue;
            }
            let y = inner.y + row;
            let field = Rect::new(inner.x + LABEL_W, y, inner.width.saturating_sub(LABEL_W), 1);
            let full = Rect::new(inner.x, y, inner.width, 1);
            self.draw_mark(frame, *mark, field, full, theme);
        }
    }

    fn draw_mark(&self, frame: &mut Frame, mark: Mark, field: Rect, full: Rect, theme: &Theme) {
        let idle = self.busy.is_none();
        match (&self.page, mark) {
            (
                Page::Unlock {
                    password,
                    on_buttons,
                    ..
                },
                Mark::Password,
            ) => password.draw(frame, field, idle && !*on_buttons, theme),
            (
                Page::Unlock {
                    buttons,
                    on_buttons,
                    ..
                },
                Mark::Buttons,
            ) => buttons.draw(frame, full, idle && *on_buttons, theme),
            (Page::Unavailable { buttons, .. }, Mark::Buttons)
            | (Page::NewVault(buttons), Mark::Buttons) => buttons.draw(frame, full, idle, theme),
            (Page::Create(form) | Page::Reset(form), mark) => {
                let focused = |i: usize| idle && form.focus == i;
                match mark {
                    Mark::Password => form.password.draw(frame, field, focused(0), theme),
                    Mark::Confirm => form.confirm.draw(frame, field, focused(1), theme),
                    Mark::Keyring => {
                        if let Some(cb) = &form.keyring {
                            let r = Rect::new(full.x, full.y, 4, 1);
                            cb.draw(frame, r, focused(2), theme);
                        }
                    }
                    Mark::Buttons => {
                        form.buttons
                            .draw(frame, full, idle && form.on_buttons(), theme);
                    }
                }
            }
            _ => {}
        }
    }

    /// Fill `body` for the current page; returns the panel title.
    fn build(&self, body: &mut Body, theme: &Theme, now: Instant) -> &'static str {
        let title = match &self.page {
            Page::Opening => {
                body.blank();
                " courier-ftp "
            }
            Page::Unavailable { error, .. } => {
                body.blank();
                body.text("The vault database could not be opened:", Style::new());
                body.text(&capitalised(error), theme.error);
                body.blank();
                body.text(
                    "If another courier-ftp is running, wait for it or close it, then retry. \
                     Without the vault you can still connect with quickconnect; nothing is saved.",
                    theme.dim,
                );
                body.blank();
                body.mark(Mark::Buttons, Line::default());
                " courier-ftp: vault unavailable "
            }
            Page::Unlock { .. } => {
                body.blank();
                body.centered("courier-ftp", theme.title);
                body.blank();
                body.mark(Mark::Password, label_line("Master password:", theme));
                body.blank();
                body.mark(Mark::Buttons, Line::default());
                body.blank();
                match (self.failures, self.wait_secs(now)) {
                    (0, None) => body.blank(),
                    (n, None) => body.centered(&attempts(n), theme.dim),
                    (n, Some(s)) => body.centered(
                        &format!("{} · next try in {s} s", attempts(n.max(1))),
                        theme.error,
                    ),
                }
                " Unlock vault "
            }
            Page::Create(form) => {
                body.text(
                    "courier-ftp keeps your sites, passwords, history and trusted keys \
                     encrypted on this device. The master password is the only key; with \
                     sync it is also the account password.",
                    Style::new(),
                );
                body.blank();
                self.password_rows(body, form, theme);
                if form.keyring.is_some() {
                    body.mark(
                        Mark::Keyring,
                        Line::from(vec![
                            Span::raw("    "),
                            Span::raw("Unlock with system keyring on this device"),
                        ]),
                    );
                    body.indented(
                        4,
                        "The keyring is also the only local recovery path.",
                        theme.dim,
                    );
                }
                let warn = if self.unicode { "⚠" } else { "!" };
                body.text(&format!("{warn} {NO_RECOVERY_WARNING}"), theme.key_hint);
                body.blank();
                body.mark(Mark::Buttons, Line::default());
                body.text(
                    "Restore from a .cftp-backup (T73) or sign in to a sync server (T90): not available yet.",
                    theme.dim,
                );
                " Create your vault "
            }
            Page::Reset(form) => {
                body.text(
                    "The system keyring unlocks the vault; choose a new master password for it.",
                    Style::new(),
                );
                body.blank();
                self.password_rows(body, form, theme);
                body.blank();
                body.mark(Mark::Buttons, Line::default());
                " Set a new master password "
            }
            Page::Forgot { options, cursor } => {
                body.blank();
                if self.facts.keyring_enabled {
                    body.text(
                        "Keyring unlock is on for this device: the system keyring can open the \
                         vault, then you choose a new master password.",
                        Style::new(),
                    );
                } else if !self.facts.sync_account {
                    body.text(
                        "There is no way to recover a forgotten master password on this device: \
                         keyring unlock is off and there is no sync account with a recovery key.",
                        Style::new(),
                    );
                    body.text(
                        "You can restore a .cftp-backup, or start over with a new empty vault. \
                         The old database is moved aside, never deleted.",
                        theme.dim,
                    );
                }
                body.blank();
                for (i, option) in options.iter().enumerate() {
                    let (marker, style) = if i == *cursor {
                        (if self.unicode { "› " } else { "> " }, theme.selection)
                    } else {
                        ("  ", Style::new())
                    };
                    body.lines
                        .push(Line::styled(format!("{marker}{}", option.label()), style));
                }
                body.blank();
                body.text("↑/↓ choose · Enter select · Esc back", theme.dim);
                " Forgot password? "
            }
            Page::NewVault(_) => {
                body.blank();
                body.text(
                    "Start a new empty vault? The current database is renamed (moved aside) in \
                     the data directory, not deleted: you can move it back later if you remember \
                     the password.",
                    Style::new(),
                );
                body.blank();
                body.mark(Mark::Buttons, Line::default());
                " Start a new vault "
            }
        };
        if let Some(note) = &self.note
            && !matches!(self.page, Page::Opening)
        {
            body.text(note, theme.key_hint);
        }
        if let Some(msg) = &self.busy {
            body.lines.push(Line::from(vec![
                Span::styled(format!("{} ", self.spinner()), theme.key_hint),
                Span::raw(msg.clone()),
            ]));
        } else if let Some(err) = &self.error {
            body.text(err, theme.error);
        }
        title
    }

    fn password_rows(&self, body: &mut Body, form: &PasswordForm, theme: &Theme) {
        body.mark(Mark::Password, label_line("Master password:", theme));
        body.mark(Mark::Confirm, label_line("Confirm:", theme));
        let s = &form.strength;
        let filled = usize::from(s.score.min(4));
        let (on, off) = if self.unicode {
            ("█", "░")
        } else {
            ("#", "-")
        };
        let meter = format!("{}{}", on.repeat(filled), off.repeat(4 - filled));
        let style = if form.password.is_empty() {
            theme.dim
        } else if s.acceptable() {
            theme.log_response
        } else {
            theme.error
        };
        let label = if form.password.is_empty() {
            "—"
        } else {
            s.label()
        };
        body.lines.push(Line::from(vec![
            Span::styled(
                format!("{:<w$}", "Strength:", w = usize::from(LABEL_W)),
                theme.dim,
            ),
            Span::styled(meter, style),
            Span::raw(" "),
            Span::styled(label.to_owned(), style),
        ]));
        let feedback = if !form.confirm.is_empty()
            && !form
                .password
                .with_text(|a| form.confirm.with_text(|b| a == b))
        {
            "The passwords don't match.".to_owned()
        } else if form.password.is_empty() {
            "At least “strong” is required.".to_owned()
        } else {
            s.feedback()
        };
        if feedback.is_empty() {
            body.blank();
        } else {
            for line in wrap(&feedback, body.width.saturating_sub(usize::from(LABEL_W))) {
                body.lines.push(Line::from(vec![
                    Span::raw(" ".repeat(usize::from(LABEL_W))),
                    Span::styled(line, theme.dim),
                ]));
            }
        }
    }
}

fn attempts(n: u32) -> String {
    if n == 1 {
        "1 failed attempt".to_owned()
    } else {
        format!("{n} failed attempts")
    }
}

fn capitalised(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn label_line(label: &str, theme: &Theme) -> Line<'static> {
    Line::styled(
        format!("{label:<w$}", w = usize::from(LABEL_W)),
        theme.title,
    )
}

/// Where a widget goes in the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mark {
    Password,
    Confirm,
    Keyring,
    Buttons,
}

/// The lines of a page plus the rows widgets are drawn on.
struct Body {
    width: usize,
    lines: Vec<Line<'static>>,
    marks: Vec<(Mark, usize)>,
}

impl Body {
    fn new(width: usize) -> Self {
        Self {
            width,
            lines: Vec::new(),
            marks: Vec::new(),
        }
    }

    fn blank(&mut self) {
        self.lines.push(Line::default());
    }

    fn text(&mut self, text: &str, style: Style) {
        for line in wrap(text, self.width) {
            self.lines.push(Line::styled(line, style));
        }
    }

    fn indented(&mut self, indent: usize, text: &str, style: Style) {
        for line in wrap(text, self.width.saturating_sub(indent)) {
            self.lines
                .push(Line::styled(format!("{}{line}", " ".repeat(indent)), style));
        }
    }

    fn centered(&mut self, text: &str, style: Style) {
        self.lines
            .push(Line::styled(text.to_owned(), style).centered());
    }

    fn mark(&mut self, mark: Mark, line: Line<'static>) {
        self.marks.push((mark, self.lines.len()));
        self.lines.push(line);
    }
}

/// Greedy word wrap to `width` columns (characters).
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    let mut line = String::new();
    let mut len = 0;
    for word in text.split_whitespace() {
        let w = word.chars().count();
        if len > 0 && len + 1 + w > width {
            out.push(std::mem::take(&mut line));
            len = 0;
        }
        if len > 0 {
            line.push(' ');
            len += 1;
        }
        line.push_str(word);
        len += w;
    }
    if !line.is_empty() || out.is_empty() {
        out.push(line);
    }
    out
}

#[cfg(test)]
mod tests;
