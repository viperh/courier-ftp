//! The settings screen (T68): FileZilla's Settings dialog as a full-screen
//! view. The section list is on the left, the section's fields on the
//! right ([`pages`]), the focused field's help and the buttons below.
//!
//! The screen edits a draft copy of the settings. Every key re-reads the
//! page into the draft and checks it with [`Settings::validate`] (the same
//! checks as loading, T05), so problems show under their field at once.
//! *OK* and *Apply* hand the draft to the app ([`SettingsRequest::Save`]),
//! which applies it live and writes the non-default values to the user
//! config; *Cancel* drops unsaved edits. Vault and trust store work (master
//! password, keyring, stored host keys and certificates) also goes to the
//! app as requests, answered with a [`SettingsReply`].
//!
//! Keys are fixed, like the dialogs': see [`HINTS`].

mod pages;
#[cfg(test)]
mod tests;

use std::collections::HashMap;

use courier_ftp_core::{
    settings::Settings,
    trust::{KnownHost, TrustedCertificate},
    vault::estimate,
};
use courier_ftp_crypto::kdf::Argon2Cost;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::oneshot;

pub(crate) use pages::Section;
use pages::{Command, Ctx, Page, RowKind, SECTIONS};

use super::{
    dialog::{ButtonRow, FieldOutcome, Form, FormDialog, TextInput, confirm, message},
    modal::{Modal, ModalOutcome},
    theme::Theme,
};

/// The keys, shown at the bottom.
pub(crate) const HINTS: &str =
    "↑↓ sections · Tab next field · Esc back · ^s apply · Alt-o OK · Alt-c cancel";

const BUTTONS: [&str; 4] = ["OK", "Apply", "Reset section", "Cancel"];

/// What the screen needs from the app besides the settings.
#[derive(Debug, Clone, Default)]
pub(crate) struct SettingsOpts {
    /// The user config file settings are saved to (for hints).
    pub(crate) config_file: String,
    /// The default session log path (placeholder of the log file field).
    pub(crate) default_log_file: String,
    /// Every binding: mode, keys, action.
    pub(crate) keybindings: Vec<(String, String, String)>,
}

/// The vault as the Security page shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultState {
    /// This run has no vault (tests, `--no-vault`).
    None,
    /// The database could not be opened.
    Unavailable,
    Locked,
    Unlocked,
}

/// What the Security page shows about the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SecurityInfo {
    pub(crate) state: VaultState,
    /// Keyring unlock is on for this device.
    pub(crate) keyring_enabled: bool,
    /// The Argon2 cost of new password wraps.
    pub(crate) cost: Option<Argon2Cost>,
}

/// A trust store's entries, as far as the screen knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Trust<T> {
    Loading,
    /// No vault in this run.
    NoVault,
    /// The vault is locked: the stored entries can't be read.
    Locked,
    Loaded(Vec<T>),
}

/// Which proxy a password is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ProxyTarget {
    Generic,
    Ftp,
}

/// What the screen asks the app to do.
#[derive(Debug, Clone)]
pub(crate) enum SettingsRequest {
    /// Apply `settings` live and save them to the user config. Typed proxy
    /// passwords go to the vault.
    Save {
        settings: Box<Settings>,
        proxy_passwords: Vec<(ProxyTarget, SecretString)>,
    },
    /// Read the stored host keys and certificates.
    LoadTrust,
    ForgetHostKey {
        host: String,
        port: u16,
        key_type: String,
    },
    ForgetCert {
        host: String,
        port: u16,
        sha256: [u8; 32],
    },
    /// Read the vault state for the Security page.
    LoadSecurity,
    ChangePassword {
        old: SecretString,
        new: SecretString,
    },
    SetKeyring(bool),
    LockNow,
    /// Open the sync panel over the settings screen (T90).
    OpenSync,
}

/// The app's answer to a [`SettingsRequest`].
#[derive(Debug, Clone)]
pub(crate) enum SettingsReply {
    /// The settings were applied and saved.
    Saved,
    /// Something failed; the message says what.
    Failed(String),
    /// Something worked; the message says what.
    Done(String),
    Trust {
        host_keys: Trust<KnownHost>,
        certs: Trust<TrustedCertificate>,
    },
    Security(SecurityInfo),
}

/// Which part of the screen has the keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pane {
    Sections,
    Page,
    Buttons,
}

type Then = Box<dyn FnOnce(&mut SettingsView) + Send>;

/// A dialog of the settings screen and what to do with its answer.
struct Overlay {
    modal: Box<dyn Modal>,
    then: Then,
}

/// The settings screen. See the module docs.
pub(crate) struct SettingsView {
    opts: SettingsOpts,
    /// The settings in effect (last saved).
    saved: Settings,
    /// The edited copy.
    draft: Settings,
    section: Section,
    page: Page,
    /// The focused row of the page.
    row: usize,
    focus: Pane,
    buttons: ButtonRow,
    /// Problems on this page, by key.
    errors: Vec<(&'static str, String)>,
    /// Problems with settings on other pages.
    other_errors: Vec<String>,
    host_keys: Trust<KnownHost>,
    certs: Trust<TrustedCertificate>,
    security: Option<SecurityInfo>,
    /// Proxy passwords typed and not saved yet.
    proxy_passwords: HashMap<ProxyTarget, SecretString>,
    overlay: Option<Overlay>,
    requests: Vec<SettingsRequest>,
    /// The last result, shown instead of the help line.
    message: Option<(String, bool)>,
    /// A save is running: the draft it saves, and whether to close after.
    saving: Option<(Box<Settings>, bool)>,
    closed: bool,
}

impl SettingsView {
    pub(crate) fn new(settings: Settings, opts: SettingsOpts) -> Self {
        let mut view = Self {
            opts,
            saved: settings.clone(),
            draft: settings,
            section: Section::Connection,
            page: Page { rows: Vec::new() },
            row: 0,
            focus: Pane::Sections,
            buttons: ButtonRow::new(&BUTTONS, 0),
            errors: Vec::new(),
            other_errors: Vec::new(),
            host_keys: Trust::Loading,
            certs: Trust::Loading,
            security: None,
            proxy_passwords: HashMap::new(),
            overlay: None,
            requests: Vec::new(),
            message: None,
            saving: None,
            closed: false,
        };
        view.rebuild();
        view.requests.push(SettingsRequest::LoadSecurity);
        view.requests.push(SettingsRequest::LoadTrust);
        view
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    /// A save is running.
    #[cfg(test)]
    pub(crate) fn is_busy(&self) -> bool {
        self.saving.is_some()
    }

    /// Unsaved edits exist.
    pub(crate) fn is_dirty(&self) -> bool {
        self.draft != self.saved || !self.proxy_passwords.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn section(&self) -> Section {
        self.section
    }

    #[cfg(test)]
    pub(crate) fn draft(&self) -> &Settings {
        &self.draft
    }

    #[cfg(test)]
    pub(crate) fn focus(&self) -> Pane {
        self.focus
    }

    #[cfg(test)]
    pub(crate) fn has_overlay(&self) -> bool {
        self.overlay.is_some()
    }

    #[cfg(test)]
    pub(crate) fn message(&self) -> Option<&(String, bool)> {
        self.message.as_ref()
    }

    /// Whether the SFTP page lists a key of `host`.
    #[cfg(test)]
    pub(crate) fn lists_host_key(&self, host: &str) -> bool {
        matches!(&self.host_keys, Trust::Loaded(list) if list.iter().any(|k| k.host == host))
    }

    /// Whether the Security page knows the vault is unlocked.
    #[cfg(test)]
    pub(crate) fn security_unlocked(&self) -> bool {
        self.security
            .is_some_and(|s| s.state == VaultState::Unlocked)
    }

    /// Whether the Security page shows keyring unlock as on.
    #[cfg(test)]
    pub(crate) fn keyring_shown(&self) -> bool {
        self.security.is_some_and(|s| s.keyring_enabled)
    }

    /// The problems shown on this page, by key.
    #[cfg(test)]
    pub(crate) fn errors(&self) -> &[(&'static str, String)] {
        &self.errors
    }

    /// The requests made since the last call.
    pub(crate) fn take_requests(&mut self) -> Vec<SettingsRequest> {
        std::mem::take(&mut self.requests)
    }

    /// The app answered.
    pub(crate) fn apply_reply(&mut self, reply: &SettingsReply) {
        match reply {
            SettingsReply::Saved => {
                if let Some((settings, close)) = self.saving.take() {
                    self.saved = *settings;
                    self.closed = close;
                }
                self.proxy_passwords.clear();
                self.message = Some(("Settings saved".to_owned(), false));
                self.rebuild_keep_focus();
            }
            SettingsReply::Failed(e) => {
                self.saving = None;
                self.message = Some((e.clone(), true));
            }
            SettingsReply::Done(text) => self.message = Some((text.clone(), false)),
            SettingsReply::Trust { host_keys, certs } => {
                self.host_keys = host_keys.clone();
                self.certs = certs.clone();
                if matches!(self.section, Section::Sftp | Section::Tls) {
                    self.rebuild_keep_focus();
                }
            }
            SettingsReply::Security(info) => {
                self.security = Some(*info);
                if self.section == Section::Security {
                    self.rebuild_keep_focus();
                }
            }
        }
    }

    // ---- page state

    fn ctx(&self) -> Ctx<'_> {
        Ctx {
            opts: &self.opts,
            host_keys: &self.host_keys,
            certs: &self.certs,
            security: self.security.as_ref(),
            proxy_typed: (
                self.proxy_passwords.contains_key(&ProxyTarget::Generic),
                self.proxy_passwords.contains_key(&ProxyTarget::Ftp),
            ),
        }
    }

    /// Build the page of the current section from the draft.
    fn rebuild(&mut self) {
        self.page = pages::build(self.section, &self.draft, &self.ctx());
        self.row = self.page.focusable().first().copied().unwrap_or(0);
        self.refresh();
    }

    /// Rebuild after new data, keeping the focused row where it was.
    fn rebuild_keep_focus(&mut self) {
        let row = self.row;
        self.rebuild();
        let focusable = self.page.focusable();
        self.row = focusable
            .iter()
            .copied()
            .find(|&r| r >= row)
            .or(focusable.last().copied())
            .unwrap_or(0);
    }

    /// Read the page into the draft and check it.
    fn refresh(&mut self) {
        let values = self.page.values();
        let mut draft = self.draft.clone();
        let mut errors = pages::apply(self.section, &values, &mut draft);
        for row in &self.page.rows {
            if let RowKind::Field(f) = &row.kind
                && let Some(e) = f.error()
                && !errors.iter().any(|(k, _)| *k == row.key)
            {
                errors.push((row.key, e));
            }
        }
        for (target, key) in [
            (ProxyTarget::Generic, pages::GENERIC_PASSWORD),
            (ProxyTarget::Ftp, pages::FTP_PASSWORD),
        ] {
            if let Some(secret) = pages::typed_secret(&values, key) {
                self.proxy_passwords.insert(target, secret);
            }
        }
        let mut other = Vec::new();
        for warning in draft.clone().validate() {
            let (key, problem) = warning.split_once(": ").unwrap_or(("", &warning));
            let problem = problem.trim_end_matches("; using the default").to_owned();
            match self.page.rows.iter().find(|r| r.key == key) {
                Some(row) if !errors.iter().any(|(k, _)| *k == row.key) => {
                    errors.push((row.key, problem));
                }
                Some(_) => {}
                None => other.push(format!("{key}: {problem}")),
            }
        }
        self.draft = draft;
        self.errors = errors;
        self.other_errors = other;
        if let Some(i) = self.page.position("preview") {
            self.page.rows[i].label = pages::preview(&self.draft);
        }
    }

    fn error_of(&self, key: &str) -> Option<&str> {
        self.errors
            .iter()
            .find(|(k, _)| *k == key && !key.is_empty())
            .map(|(_, e)| e.as_str())
    }

    /// Go to another section (not while the page has problems).
    fn select_section(&mut self, section: Section) {
        if section == self.section {
            return;
        }
        if !self.errors.is_empty() {
            self.message = Some(("Fix the marked field first".to_owned(), true));
            return;
        }
        self.section = section;
        self.rebuild();
        match section {
            Section::Security => self.requests.push(SettingsRequest::LoadSecurity),
            Section::Sftp | Section::Tls => self.requests.push(SettingsRequest::LoadTrust),
            _ => {}
        }
    }

    fn move_section(&mut self, delta: isize) {
        let i = self.section.index();
        let next = i
            .saturating_add_signed(delta)
            .min(SECTIONS.len().saturating_sub(1));
        self.select_section(SECTIONS[next].0);
    }

    fn focus_first_error(&mut self) {
        if let Some((key, _)) = self.errors.first()
            && let Some(i) = self.page.position(key)
        {
            self.row = i;
            self.focus = Pane::Page;
        }
    }

    // ---- actions

    /// *OK* (`close`) or *Apply*.
    fn save(&mut self, close: bool) {
        if self.saving.is_some() {
            return;
        }
        self.refresh();
        if !self.errors.is_empty() {
            self.focus_first_error();
            self.message = Some(("Please fix the marked field".to_owned(), true));
            return;
        }
        if let Some(problem) = self.other_errors.first() {
            self.message = Some((problem.clone(), true));
            return;
        }
        if !self.is_dirty() {
            self.closed = close;
            if !close {
                self.message = Some(("Nothing to save".to_owned(), false));
            }
            return;
        }
        let settings = Box::new(self.draft.clone());
        // Kept until the app says it saved them, so a failure loses nothing.
        let mut proxy_passwords: Vec<(ProxyTarget, SecretString)> = self
            .proxy_passwords
            .iter()
            .map(|(t, p)| (*t, p.clone()))
            .collect();
        proxy_passwords.sort_by_key(|(t, _)| *t == ProxyTarget::Ftp);
        self.saving = Some((settings.clone(), close));
        self.requests.push(SettingsRequest::Save {
            settings,
            proxy_passwords,
        });
    }

    fn cancel(&mut self) {
        if !self.is_dirty() {
            self.closed = true;
            return;
        }
        let (modal, rx) = confirm("Settings", "Discard the unsaved changes?", false);
        self.overlay(modal, rx, |view, yes| {
            if yes {
                view.closed = true;
            }
        });
    }

    /// The fields of this section back to their defaults (not saved yet).
    fn reset_section(&mut self) {
        let defaults = Settings::default();
        let page = pages::build(self.section, &defaults, &self.ctx());
        let _ = pages::apply(self.section, &page.values(), &mut self.draft);
        if self.section == Section::GenericProxy {
            self.proxy_passwords.remove(&ProxyTarget::Generic);
        }
        if self.section == Section::FtpProxy {
            self.proxy_passwords.remove(&ProxyTarget::Ftp);
        }
        self.rebuild();
        self.message = Some((
            format!(
                "{} reset to the defaults (not saved yet)",
                self.section.title()
            ),
            false,
        ));
    }

    fn press_button(&mut self, i: usize) {
        match i {
            0 => self.save(true),
            1 => self.save(false),
            2 => self.reset_section(),
            _ => self.cancel(),
        }
    }

    fn overlay<T: Send + 'static>(
        &mut self,
        modal: Box<dyn Modal>,
        rx: oneshot::Receiver<T>,
        then: impl FnOnce(&mut Self, T) + Send + 'static,
    ) {
        self.overlay = Some(Overlay {
            modal,
            then: Box::new(move |view| {
                let mut rx = rx;
                if let Ok(answer) = rx.try_recv() {
                    then(view, answer);
                }
            }),
        });
    }

    /// The index of the selected entry of the list row `key`.
    fn list_selection(&self, key: &str) -> Option<usize> {
        let row = self.page.rows.get(self.page.position(key)?)?;
        match &row.kind {
            RowKind::Field(f) => match f.value() {
                super::dialog::FieldValue::Index(i) => Some(i),
                _ => None,
            },
            _ => None,
        }
    }

    fn run(&mut self, command: Command) {
        match command {
            Command::ForgetHostKey => self.forget_host_key(),
            Command::ForgetCert => self.forget_cert(),
            Command::CertDetails => self.cert_details(),
            Command::ChangePassword => self.change_password(),
            Command::ToggleKeyring => {
                if let Some(info) = self.security {
                    self.requests
                        .push(SettingsRequest::SetKeyring(!info.keyring_enabled));
                }
            }
            Command::LockNow => self.requests.push(SettingsRequest::LockNow),
            Command::OpenSync => self.requests.push(SettingsRequest::OpenSync),
        }
    }

    fn forget_host_key(&mut self) {
        let Trust::Loaded(list) = &self.host_keys else {
            return;
        };
        let Some(entry) = self
            .list_selection("sftp.host_keys")
            .and_then(|i| list.get(i))
            .cloned()
        else {
            return;
        };
        let (modal, rx) = confirm(
            "Forget host key",
            &format!(
                "Forget the {} key of {}:{}?\n\nThe next connection to it asks about its key again.",
                entry.key_type(),
                entry.host,
                entry.port
            ),
            false,
        );
        self.overlay(modal, rx, move |view, yes| {
            if yes {
                view.requests.push(SettingsRequest::ForgetHostKey {
                    host: entry.host.clone(),
                    port: entry.port,
                    key_type: entry.key_type().to_owned(),
                });
            }
        });
    }

    fn selected_cert(&self) -> Option<TrustedCertificate> {
        let Trust::Loaded(list) = &self.certs else {
            return None;
        };
        self.list_selection("tls.certificates")
            .and_then(|i| list.get(i))
            .cloned()
    }

    fn forget_cert(&mut self) {
        let Some(cert) = self.selected_cert() else {
            return;
        };
        let (modal, rx) = confirm(
            "Forget certificate",
            &format!(
                "Forget the certificate of {}:{} ({})?\n\nThe next connection to it asks about its certificate again.",
                cert.host, cert.port, cert.subject
            ),
            false,
        );
        self.overlay(modal, rx, move |view, yes| {
            if yes {
                view.requests.push(SettingsRequest::ForgetCert {
                    host: cert.host.clone(),
                    port: cert.port,
                    sha256: cert.sha256,
                });
            }
        });
    }

    fn cert_details(&mut self) {
        let Some(cert) = self.selected_cert() else {
            return;
        };
        let (modal, rx) = message("Certificate", &cert_text(&cert));
        self.overlay(modal, rx, |_, ()| {});
    }

    fn change_password(&mut self) {
        let form = Form::new(&["Change", "Cancel"])
            .field("old", TextInput::password("Current password"))
            .field("new", TextInput::password("New password"))
            .field("confirm", TextInput::password("Confirm"))
            .validate_with(|v| {
                let (Some(old), Some(new), Some(confirm)) =
                    (v.secret("old"), v.secret("new"), v.secret("confirm"))
                else {
                    return Err("Fill in every field.".to_owned());
                };
                if old.expose_secret().is_empty() {
                    return Err("Enter the current password.".to_owned());
                }
                let strength = estimate(new.expose_secret(), &[]);
                if !strength.acceptable() {
                    return Err(format!(
                        "Too weak ({}): a strong password is required. {}",
                        strength.label(),
                        strength.feedback()
                    ));
                }
                if new.expose_secret() != confirm.expose_secret() {
                    return Err("The new passwords don't match.".to_owned());
                }
                Ok(())
            });
        let (dialog, rx) = FormDialog::new("Change master password", 64, form, |v| {
            match (v.secret("old"), v.secret("new")) {
                (Some(old), Some(new)) => Ok((old, new)),
                _ => Err("Fill in every field.".to_owned()),
            }
        });
        self.overlay(Box::new(dialog), rx, |view, answer| {
            if let Some((old, new)) = answer {
                view.requests
                    .push(SettingsRequest::ChangePassword { old, new });
                view.message = Some(("Changing the master password…".to_owned(), false));
            }
        });
    }

    // ---- keys

    pub(crate) fn handle_paste(&mut self, text: &str) {
        if let Some(o) = self.overlay.as_mut() {
            o.modal.handle_paste(text);
            return;
        }
        if self.focus == Pane::Page
            && let Some(RowKind::Field(f)) = self.page.rows.get_mut(self.row).map(|r| &mut r.kind)
        {
            f.handle_paste(text);
            self.refresh();
        }
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        if let Some(o) = self.overlay.as_mut() {
            if o.modal.handle_key(key) == ModalOutcome::Close
                && let Some(o) = self.overlay.take()
            {
                (o.then)(self);
            }
            return;
        }
        if self.saving.is_some() {
            return;
        }
        self.message = None;
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        if ctrl && key.code == KeyCode::Char('s') {
            self.save(false);
            return;
        }
        if alt && let Some(i) = self.buttons.clone().handle_key(key) {
            self.press_button(i);
            return;
        }
        match self.focus {
            Pane::Sections => self.sections_key(key),
            Pane::Page => self.page_key(key),
            Pane::Buttons => match key.code {
                KeyCode::Tab => self.focus = Pane::Sections,
                KeyCode::BackTab => self.enter_page(true),
                KeyCode::Esc => self.cancel(),
                KeyCode::Up => self.enter_page(true),
                _ => {
                    if let Some(i) = self.buttons.handle_key(key) {
                        self.press_button(i);
                    }
                }
            },
        }
    }

    fn sections_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_section(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_section(1),
            KeyCode::Home | KeyCode::Char('g') => self.select_section(SECTIONS[0].0),
            KeyCode::End | KeyCode::Char('G') => {
                self.select_section(SECTIONS[SECTIONS.len() - 1].0);
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') | KeyCode::Tab => {
                self.enter_page(false);
            }
            KeyCode::BackTab => self.focus = Pane::Buttons,
            KeyCode::Esc | KeyCode::Char('q') => self.cancel(),
            _ => {}
        }
    }

    /// Focus the first (`last`: the last) row of the page, or the buttons
    /// when nothing on it takes focus.
    fn enter_page(&mut self, last: bool) {
        let focusable = self.page.focusable();
        let target = if last {
            focusable.last()
        } else {
            focusable.first()
        };
        match target {
            Some(&row) => {
                self.row = row;
                self.focus = Pane::Page;
            }
            None => self.focus = Pane::Buttons,
        }
    }

    fn step(&mut self, forward: bool) {
        let focusable = self.page.focusable();
        let at = focusable.iter().position(|&r| r == self.row);
        let next = match (at, forward) {
            (Some(i), true) => focusable.get(i + 1).copied(),
            (Some(i), false) => i.checked_sub(1).and_then(|j| focusable.get(j).copied()),
            (None, _) => None,
        };
        match next {
            Some(row) => self.row = row,
            None if forward => self.focus = Pane::Buttons,
            None => self.focus = Pane::Sections,
        }
    }

    fn page_key(&mut self, key: KeyEvent) {
        let Some(row) = self.page.rows.get_mut(self.row) else {
            self.focus = Pane::Sections;
            return;
        };
        let row_key = row.key;
        match &mut row.kind {
            RowKind::Field(field) => {
                let capturing = field.is_capturing();
                if field.handle_key(key) == FieldOutcome::Consumed || capturing {
                    self.refresh();
                    return;
                }
            }
            RowKind::Button(command) => {
                let command = *command;
                if matches!(key.code, KeyCode::Enter | KeyCode::Char(' ')) {
                    self.run(command);
                    return;
                }
            }
            RowKind::Note => {}
        }
        match (key.code, row_key) {
            (KeyCode::Char('x') | KeyCode::Delete, "sftp.host_keys") => self.forget_host_key(),
            (KeyCode::Char('x') | KeyCode::Delete, "tls.certificates") => self.forget_cert(),
            (KeyCode::Enter, "tls.certificates") => self.cert_details(),
            (KeyCode::Tab | KeyCode::Down, _) => self.step(true),
            (KeyCode::BackTab | KeyCode::Up, _) => self.step(false),
            (KeyCode::Esc, _) => self.focus = Pane::Sections,
            _ => {}
        }
    }

    // ---- drawing

    pub(crate) fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        frame.render_widget(Clear, area);
        if area.width < 40 || area.height < 10 {
            frame.render_widget(
                Paragraph::new("terminal too small").style(theme.error),
                area,
            );
            return;
        }
        let bottom = 3;
        let body = Rect::new(area.x, area.y, area.width, area.height - bottom);
        let list_w = 24.min(body.width / 3);
        self.draw_sections(frame, Rect::new(body.x, body.y, list_w, body.height), theme);
        self.draw_page(
            frame,
            Rect::new(body.x + list_w, body.y, body.width - list_w, body.height),
            theme,
        );
        let y = body.bottom();
        let help = match &self.message {
            Some((text, true)) => Span::styled(text.clone(), theme.error),
            Some((text, false)) => Span::styled(text.clone(), theme.key_hint),
            None if self.saving.is_some() => Span::styled("Saving…", theme.key_hint),
            None => match self.focus {
                Pane::Page => Span::styled(
                    self.page
                        .rows
                        .get(self.row)
                        .map(|r| r.help)
                        .unwrap_or_default()
                        .to_owned(),
                    theme.dim,
                ),
                _ => Span::styled(
                    format!("Settings are saved to {}", self.opts.config_file),
                    theme.dim,
                ),
            },
        };
        frame.render_widget(
            Paragraph::new(Line::from(vec![Span::raw(" "), help])),
            Rect::new(area.x, y, area.width, 1),
        );
        self.buttons.draw(
            frame,
            Rect::new(area.x, y + 1, area.width, 1),
            self.focus == Pane::Buttons,
            theme,
        );
        frame.render_widget(
            Paragraph::new(Span::styled(format!(" {HINTS}"), theme.dim)),
            Rect::new(area.x, y + 2, area.width, 1),
        );
        if let Some(o) = self.overlay.as_mut() {
            o.modal.draw(frame, area, theme);
        }
    }

    fn draw_sections(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let focused = self.focus == Pane::Sections;
        let title = if self.is_dirty() {
            " Settings * "
        } else {
            " Settings "
        };
        let block = Block::bordered().title(title).border_style(if focused {
            theme.focused_border
        } else {
            theme.border
        });
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let lines: Vec<Line> = SECTIONS
            .iter()
            .take(usize::from(inner.height))
            .map(|(section, title, indent)| {
                let text = format!("{}{title}", "  ".repeat(usize::from(*indent)));
                if *section == self.section {
                    Line::styled(
                        format!("> {text}"),
                        if focused {
                            theme.selection
                        } else {
                            theme.title
                        },
                    )
                } else {
                    Line::raw(format!("  {text}"))
                }
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), inner);
    }

    fn draw_page(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let focused = self.focus == Pane::Page;
        let block = Block::bordered()
            .title(format!(" {} ", self.section.title()))
            .border_style(if focused {
                theme.focused_border
            } else {
                theme.border
            });
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let body = Rect::new(
            inner.x + 1,
            inner.y,
            inner.width.saturating_sub(2),
            inner.height,
        );
        let rows = &self.page.rows;
        let label_w = rows
            .iter()
            .filter(|r| matches!(r.kind, RowKind::Field(_)))
            .map(|r| r.label.chars().count())
            .max()
            .unwrap_or(0)
            .saturating_add(2);
        let label_w = u16::try_from(label_w).unwrap_or(20).min(body.width / 2);
        let heights: Vec<u16> = rows
            .iter()
            .map(|r| r.height() + u16::from(self.error_of(r.key).is_some()))
            .collect();
        let footer = u16::from(!self.other_errors.is_empty());
        let avail = body.height.saturating_sub(footer);
        let focus_top: u16 = heights.iter().take(self.row).sum();
        let focus_h = heights.get(self.row).copied().unwrap_or(1);
        let scroll = (focus_top + focus_h).saturating_sub(avail);
        let mut y = body.y;
        let mut top = 0u16;
        let mut overlay = None;
        for (i, (row, h)) in rows.iter().zip(&heights).enumerate() {
            let row_top = top;
            top += h;
            if row_top < scroll {
                continue;
            }
            if y + row.height() > body.y + avail {
                break;
            }
            let is_focused = focused && i == self.row;
            match &row.kind {
                RowKind::Note => {
                    frame.render_widget(
                        Paragraph::new(Span::styled(row.label.clone(), theme.dim)),
                        Rect::new(body.x, y, body.width, 1),
                    );
                }
                RowKind::Button(_) => {
                    let style = if is_focused {
                        theme.selection
                    } else {
                        theme.title
                    };
                    frame.render_widget(
                        Paragraph::new(Span::styled(format!("[ {} ]", row.label), style)),
                        Rect::new(body.x, y, body.width, 1),
                    );
                }
                RowKind::Field(widget) => {
                    frame.render_widget(
                        Paragraph::new(Span::styled(
                            row.label.clone(),
                            if is_focused { theme.title } else { theme.dim },
                        )),
                        Rect::new(body.x, y, label_w, 1),
                    );
                    let field_area = Rect::new(
                        body.x + label_w,
                        y,
                        body.width.saturating_sub(label_w),
                        widget.height(),
                    );
                    widget.draw(frame, field_area, is_focused, theme);
                    if is_focused {
                        overlay = Some((i, field_area));
                    }
                    if let Some(e) = self.error_of(row.key)
                        && y + widget.height() < body.y + avail
                    {
                        frame.render_widget(
                            Paragraph::new(Span::styled(e.to_owned(), theme.error)),
                            Rect::new(field_area.x, y + widget.height(), field_area.width, 1),
                        );
                    }
                }
            }
            y += h;
        }
        if let Some(problem) = self.other_errors.first() {
            frame.render_widget(
                Paragraph::new(Span::styled(problem.clone(), theme.error)),
                Rect::new(body.x, body.bottom().saturating_sub(1), body.width, 1),
            );
        }
        if let Some((i, rect)) = overlay
            && let RowKind::Field(widget) = &rows[i].kind
        {
            widget.draw_overlay(frame, rect, theme);
        }
    }
}

/// The details of a trusted certificate, for the details dialog.
fn cert_text(cert: &TrustedCertificate) -> String {
    let info = courier_ftp_proto_ftp::tls::certificate_info(&cert.der);
    let date = super::trust::format_date;
    let mut lines = vec![
        format!("Server:     {}:{}", cert.host, cert.port),
        format!("Subject:    {}", info.subject),
        format!("Issuer:     {}", info.issuer),
        format!("Serial:     {}", info.serial),
        format!("Valid from: {}", date(info.not_before)),
        format!("Valid to:   {}", date(info.not_after)),
    ];
    if !info.subject_alt_names.is_empty() {
        lines.push(format!("Names:      {}", info.subject_alt_names.join(", ")));
    }
    lines.extend([
        format!("Public key: {}", info.public_key),
        format!("Signature:  {}", info.signature_algorithm),
        format!("SHA-256:    {}", cert.fingerprint()),
        format!("SHA-1:      {}", info.fingerprint_sha1),
        format!("Trusted:    {}", date(cert.added_at)),
    ]);
    lines.join("\n")
}
