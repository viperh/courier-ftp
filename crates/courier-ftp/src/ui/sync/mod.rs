//! The sync screens (T90, feature `sync`): the sync panel (status, last
//! sync, pending changes, per-vault cursors, held-back items, "sync now"),
//! the account wizard (register with the 24-word recovery key, or log in
//! with the duplicate preview), devices, the account screen (password, TOTP,
//! recovery code, log out, delete) and the teams placeholder.
//!
//! [`SyncView`] is a large view owned by the main screen, like the Site
//! Manager (T59): it takes every key while open, never talks to the network
//! and asks for work with [`SyncRequest`]s that the app runs in the
//! background (`crate::sync`), reporting back through the `show_*` and
//! `failed` methods.
//!
//! Passwords, codes and recovery words live only in zeroizing fields; the
//! recovery phrase is held (zeroizing) only while its two pages are open.

mod qr;

use courier_ftp_core::model::item::ItemId;
use courier_ftp_proto::auth::DeviceSummary;
use courier_ftp_store::VaultKind;
use courier_ftp_sync::{
    SyncStatus, TotpSetup,
    account::{
        DuplicateChoice, DuplicateRow, PASSWORD_ADOPT_WARNING, RECOVERY_WARNING, RegistrationToken,
    },
    info::LocalSyncInfo,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;
use zeroize::Zeroizing;

use self::qr::Qr;
use super::{
    dialog::{ButtonRow, Form, FormOutcome, FormValues, RadioGroup, TextInput},
    theme::Theme,
    vault::{capitalised, wrap},
};

/// What the sync screens ask the app to do.
pub(crate) enum SyncRequest {
    /// Register: probe the server, check the password, make the keys and
    /// the recovery words.
    Register {
        server: String,
        email: String,
        device: String,
        password: SecretString,
        token: Option<RegistrationToken>,
    },
    /// The three re-typed recovery words.
    ConfirmWords(Box<[Zeroizing<String>; 3]>),
    /// Registration step 2, with a token when the server asked for one.
    FinishRegistration(Option<RegistrationToken>),
    CancelRegistration,
    Login {
        server: String,
        email: String,
        device: String,
        password: SecretString,
        totp: Option<SecretString>,
    },
    /// Commit the login with these duplicate choices.
    CommitLogin(Vec<(ItemId, DuplicateChoice)>),
    CancelLogin,
    /// Re-read the local sync state.
    Refresh,
    SyncNow,
    Devices,
    Revoke {
        id: Uuid,
        this_device: bool,
    },
    ChangePassword {
        old: SecretString,
        new: SecretString,
        totp: Option<SecretString>,
    },
    TotpStart,
    TotpConfirm(SecretString),
    TotpDisable(SecretString),
    /// Mail a recovery code to the account.
    RecoveryCode,
    Logout,
    DeleteAccount {
        password: SecretString,
        totp: Option<SecretString>,
    },
}

impl std::fmt::Debug for SyncRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the secrets.
        f.write_str(match self {
            Self::Register { .. } => "Register",
            Self::ConfirmWords(_) => "ConfirmWords",
            Self::FinishRegistration(_) => "FinishRegistration",
            Self::CancelRegistration => "CancelRegistration",
            Self::Login { .. } => "Login",
            Self::CommitLogin(_) => "CommitLogin",
            Self::CancelLogin => "CancelLogin",
            Self::Refresh => "Refresh",
            Self::SyncNow => "SyncNow",
            Self::Devices => "Devices",
            Self::Revoke { .. } => "Revoke",
            Self::ChangePassword { .. } => "ChangePassword",
            Self::TotpStart => "TotpStart",
            Self::TotpConfirm(_) => "TotpConfirm",
            Self::TotpDisable(_) => "TotpDisable",
            Self::RecoveryCode => "RecoveryCode",
            Self::Logout => "Logout",
            Self::DeleteAccount { .. } => "DeleteAccount",
        })
    }
}

/// What a login will do, shown before it is committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoginSummary {
    pub(crate) email: String,
    /// The account password differs from the local master password.
    pub(crate) password_differs: bool,
    /// Local items will be imported into the account.
    pub(crate) will_import: bool,
    pub(crate) new_items: usize,
    pub(crate) skipped_deleted: usize,
}

/// Which page is shown (for tests).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncPage {
    Overview,
    Register,
    Login,
    Words,
    Confirm,
    Token,
    LoginConfirm,
    Devices,
    Account,
    ChangePassword,
    TotpSetup,
    TotpDisable,
    DeleteAccount,
    Teams,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuItem {
    Register,
    Login,
    Relogin,
    SyncNow,
    Devices,
    Account,
    Teams,
    Close,
}

impl MenuItem {
    fn label(self) -> &'static str {
        match self {
            Self::Register => "Create an account on a sync server",
            Self::Login => "Log in to an existing account",
            Self::Relogin => "Log in again",
            Self::SyncNow => "Sync now",
            Self::Devices => "Devices",
            Self::Account => "Account: password, two-factor, recovery, log out",
            Self::Teams => "Teams and shared vaults",
            Self::Close => "Close",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccountItem {
    ChangePassword,
    TotpEnable,
    TotpDisable,
    RecoveryCode,
    Logout,
    Delete,
    Back,
}

const ACCOUNT_ITEMS: [AccountItem; 7] = [
    AccountItem::ChangePassword,
    AccountItem::TotpEnable,
    AccountItem::TotpDisable,
    AccountItem::RecoveryCode,
    AccountItem::Logout,
    AccountItem::Delete,
    AccountItem::Back,
];

impl AccountItem {
    fn label(self) -> &'static str {
        match self {
            Self::ChangePassword => "Change the password (needs the server)",
            Self::TotpEnable => "Enable two-factor authentication (TOTP)",
            Self::TotpDisable => "Disable two-factor authentication",
            Self::RecoveryCode => "Email me a recovery code",
            Self::Logout => "Log out of sync on this device",
            Self::Delete => "Delete the account",
            Self::Back => "Back",
        }
    }
}

enum ConfirmAction {
    Revoke {
        id: Uuid,
        this_device: bool,
    },
    Logout,
    Delete {
        password: SecretString,
        totp: Option<SecretString>,
    },
    CancelRegistration,
}

/// A yes/no question drawn over the page.
struct Confirm {
    title: &'static str,
    text: String,
    action: ConfirmAction,
    buttons: ButtonRow,
}

enum Page {
    Overview {
        cursor: usize,
    },
    Register(Form),
    Login(Form),
    /// The 24 words, shown once.
    Words {
        phrase: Zeroizing<String>,
        numbers: [usize; 3],
        ack: bool,
        on_buttons: bool,
        buttons: ButtonRow,
    },
    /// Re-type three of them.
    Confirm {
        phrase: Zeroizing<String>,
        numbers: [usize; 3],
        form: Form,
    },
    /// The server needs an invite or setup token.
    Token(Form),
    LoginConfirm {
        summary: LoginSummary,
        rows: Vec<DuplicateRow>,
        cursor: usize,
        on_buttons: bool,
        buttons: ButtonRow,
    },
    Devices {
        rows: Vec<DeviceSummary>,
        cursor: usize,
        loaded: bool,
    },
    Account {
        cursor: usize,
    },
    ChangePassword(Form),
    TotpSetup {
        qr: Option<Qr>,
        secret: SecretString,
        form: Form,
    },
    TotpDisable(Form),
    DeleteAccount(Form),
    Teams,
}

/// See the module docs.
pub(crate) struct SyncView {
    page: Page,
    info: Option<LocalSyncInfo>,
    status: Option<SyncStatus>,
    signed_in: bool,
    item_errors: Vec<(String, String)>,
    device_name: String,
    busy: Option<String>,
    note: Option<String>,
    error: Option<String>,
    confirm: Option<Confirm>,
    requests: Vec<SyncRequest>,
    closed: bool,
    unicode: bool,
    tick: u64,
}

const PANEL_W: u16 = 84;
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_ASCII: [&str; 4] = ["|", "/", "-", "\\"];

fn url_check(s: &str) -> Result<(), String> {
    courier_ftp_sync::http::normalize_server_url(s)
        .map(drop)
        .map_err(|e| capitalised(&e.to_string().replace("not configured: ", "")))
}

fn email_check(s: &str) -> Result<(), String> {
    let s = s.trim();
    if s.is_empty() || !s.contains('@') || s.chars().any(char::is_whitespace) {
        return Err("Enter a valid email address".to_owned());
    }
    Ok(())
}

fn required(what: &'static str) -> impl Fn(&str) -> Result<(), String> + Send {
    move |s: &str| {
        if s.trim().is_empty() {
            Err(format!("Enter {what}"))
        } else {
            Ok(())
        }
    }
}

/// A secret that is empty counts as absent.
fn optional(v: &FormValues, key: &str) -> Option<SecretString> {
    v.secret(key)
        .filter(|s| !s.expose_secret().trim().is_empty())
}

fn secret(v: &FormValues, key: &str) -> SecretString {
    v.secret(key)
        .unwrap_or_else(|| SecretString::from(String::new()))
}

fn token_from(v: &FormValues) -> Option<RegistrationToken> {
    let token = optional(v, "token")?;
    Some(match v.index("token_kind") {
        Some(1) => RegistrationToken::Setup(token),
        _ => RegistrationToken::Invite(token),
    })
}

impl SyncView {
    /// The panel for this device's state.
    pub(crate) fn new(unicode: bool, device_name: String) -> Self {
        Self {
            page: Page::Overview { cursor: 0 },
            info: None,
            status: None,
            signed_in: false,
            item_errors: Vec::new(),
            device_name,
            busy: None,
            note: None,
            error: None,
            confirm: None,
            requests: vec![SyncRequest::Refresh],
            closed: false,
            unicode,
            tick: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn page(&self) -> SyncPage {
        match self.page {
            Page::Overview { .. } => SyncPage::Overview,
            Page::Register(_) => SyncPage::Register,
            Page::Login(_) => SyncPage::Login,
            Page::Words { .. } => SyncPage::Words,
            Page::Confirm { .. } => SyncPage::Confirm,
            Page::Token(_) => SyncPage::Token,
            Page::LoginConfirm { .. } => SyncPage::LoginConfirm,
            Page::Devices { .. } => SyncPage::Devices,
            Page::Account { .. } => SyncPage::Account,
            Page::ChangePassword(_) => SyncPage::ChangePassword,
            Page::TotpSetup { .. } => SyncPage::TotpSetup,
            Page::TotpDisable(_) => SyncPage::TotpDisable,
            Page::DeleteAccount(_) => SyncPage::DeleteAccount,
            Page::Teams => SyncPage::Teams,
        }
    }

    /// The recovery phrase while its pages are open (tests read it to
    /// answer the check).
    #[cfg(test)]
    pub(crate) fn shown_phrase(&self) -> Option<(String, [usize; 3])> {
        match &self.page {
            Page::Words {
                phrase, numbers, ..
            }
            | Page::Confirm {
                phrase, numbers, ..
            } => Some((phrase.to_string(), *numbers)),
            _ => None,
        }
    }

    /// The TOTP secret while its page is open (tests compute codes).
    #[cfg(test)]
    pub(crate) fn totp_secret(&self) -> Option<String> {
        match &self.page {
            Page::TotpSetup { secret, .. } => Some(secret.expose_secret().to_owned()),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn is_busy(&self) -> bool {
        self.busy.is_some()
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    pub(crate) fn take_requests(&mut self) -> Vec<SyncRequest> {
        std::mem::take(&mut self.requests)
    }

    /// The local state, the engine status and the held-back items.
    pub(crate) fn set_state(
        &mut self,
        info: Option<LocalSyncInfo>,
        status: Option<SyncStatus>,
        signed_in: bool,
        item_errors: Vec<(String, String)>,
    ) {
        if info.is_some() {
            self.info = info;
        }
        self.status = status;
        self.signed_in = signed_in;
        self.item_errors = item_errors;
        let last = self.menu().len().saturating_sub(1);
        if let Page::Overview { cursor } = &mut self.page {
            *cursor = (*cursor).min(last);
        }
    }

    pub(crate) fn info(&self) -> Option<&LocalSyncInfo> {
        self.info.as_ref()
    }

    /// Advance the spinner.
    pub(crate) fn tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
    }

    fn request(&mut self, request: SyncRequest, busy: Option<&str>) {
        self.requests.push(request);
        self.busy = busy.map(str::to_owned);
        self.error = None;
        self.note = None;
    }

    /// A call failed: show why and stay on the page.
    pub(crate) fn failed(&mut self, message: &str) {
        self.busy = None;
        self.error = Some(capitalised(message));
    }

    /// Back to the overview with `note`.
    pub(crate) fn done(&mut self, note: Option<String>) {
        self.page = Page::Overview { cursor: 0 };
        self.busy = None;
        self.error = None;
        self.note = note;
        self.confirm = None;
        self.requests.push(SyncRequest::Refresh);
    }

    /// Back to the account page with `note`.
    pub(crate) fn account_done(&mut self, note: Option<String>) {
        self.page = Page::Account { cursor: 0 };
        self.busy = None;
        self.error = None;
        self.note = note;
    }

    /// Registration step 1 done: show the words.
    pub(crate) fn show_words(&mut self, phrase: Zeroizing<String>, numbers: [usize; 3]) {
        self.page = Page::Words {
            phrase,
            numbers,
            ack: false,
            on_buttons: false,
            buttons: ButtonRow::new(&["Continue", "Cancel"], 0),
        };
        self.busy = None;
        self.error = None;
    }

    fn confirm_page(phrase: Zeroizing<String>, numbers: [usize; 3]) -> Page {
        let mut form = Form::new(&["Continue", "Back to the words"]);
        for (i, n) in numbers.iter().enumerate() {
            form = form.field(
                &format!("w{i}"),
                TextInput::sensitive(format!("Word #{n}")).with_max_len(32),
            );
        }
        Page::Confirm {
            phrase,
            numbers,
            form,
        }
    }

    /// The re-typed words were wrong.
    pub(crate) fn words_wrong(&mut self) {
        if let Page::Confirm {
            phrase, numbers, ..
        } = &mut self.page
        {
            let (phrase, numbers) = (std::mem::take(phrase), *numbers);
            self.page = Self::confirm_page(phrase, numbers);
        }
        self.busy = None;
        self.error = Some(
            "Those words don't match. Check what you wrote down (or go back to the words)."
                .to_owned(),
        );
    }

    /// The words were confirmed; the account is being created. The phrase
    /// is dropped here.
    pub(crate) fn words_confirmed(&mut self) {
        self.page = Page::Overview { cursor: 0 };
        self.busy = Some("Creating the account…".to_owned());
        self.error = None;
    }

    /// Creating the account failed (often: the server wants an invite or
    /// setup token); retry with a token, or cancel.
    pub(crate) fn show_token(&mut self, error: &str) {
        let form = Form::new(&["Create account", "Cancel"])
            .field(
                "token_kind",
                RadioGroup::new(
                    "Token type",
                    vec!["Invite".to_owned(), "Setup token".to_owned()],
                    0,
                ),
            )
            .field(
                "token",
                TextInput::sensitive("Token").with_placeholder("only if the server needs one"),
            );
        self.page = Page::Token(form);
        self.busy = None;
        self.error = Some(capitalised(error));
    }

    /// A login is ready: what it will do, and the duplicates.
    pub(crate) fn show_login(&mut self, summary: LoginSummary, rows: Vec<DuplicateRow>) {
        self.page = Page::LoginConfirm {
            on_buttons: rows.is_empty(),
            summary,
            rows,
            cursor: 0,
            buttons: ButtonRow::new(&["Log in", "Cancel"], 0),
        };
        self.busy = None;
        self.error = None;
    }

    pub(crate) fn show_devices(&mut self, rows: Vec<DeviceSummary>) {
        let cursor = match &self.page {
            Page::Devices { cursor, .. } => (*cursor).min(rows.len().saturating_sub(1)),
            _ => 0,
        };
        self.page = Page::Devices {
            rows,
            cursor,
            loaded: true,
        };
        self.busy = None;
    }

    pub(crate) fn show_totp(&mut self, setup: &TotpSetup) {
        self.page = Page::TotpSetup {
            qr: Qr::new(setup.otpauth_uri.expose_secret()),
            secret: setup.secret_base32.clone(),
            form: Form::new(&["Enable", "Cancel"]).field(
                "code",
                TextInput::sensitive("Code from the app")
                    .with_max_len(10)
                    .with_validator(required("the 6-digit code")),
            ),
        };
        self.busy = None;
        self.error = None;
    }

    fn menu(&self) -> Vec<MenuItem> {
        if self.signed_in {
            let relogin = matches!(self.status, Some(SyncStatus::NeedsLogin));
            relogin
                .then_some(MenuItem::Relogin)
                .into_iter()
                .chain([
                    MenuItem::SyncNow,
                    MenuItem::Devices,
                    MenuItem::Account,
                    MenuItem::Teams,
                    MenuItem::Close,
                ])
                .collect()
        } else if self.info.as_ref().is_some_and(|i| i.server_url.is_some()) {
            vec![MenuItem::Relogin, MenuItem::Close]
        } else {
            vec![MenuItem::Register, MenuItem::Login, MenuItem::Close]
        }
    }

    fn server_field(&self) -> TextInput {
        let server = self
            .info
            .as_ref()
            .and_then(|i| i.server_url.clone())
            .unwrap_or_default();
        TextInput::new("Server URL")
            .with_value(&server)
            .with_placeholder("https://sync.example.com")
            .with_validator(url_check)
    }

    fn email_field(&self) -> TextInput {
        let email = self
            .info
            .as_ref()
            .and_then(|i| i.email.clone())
            .unwrap_or_default();
        TextInput::new("Email")
            .with_value(&email)
            .with_validator(email_check)
    }

    fn register_page(&self) -> Page {
        Page::Register(
            Form::new(&["Continue", "Cancel"])
                .field("server", self.server_field())
                .field("email", self.email_field())
                .field(
                    "device",
                    TextInput::new("Device name")
                        .with_value(&self.device_name)
                        .with_validator(required("a device name")),
                )
                .field(
                    "password",
                    TextInput::password("Master password")
                        .with_validator(required("the master password")),
                )
                .field(
                    "token_kind",
                    RadioGroup::new(
                        "Token type",
                        vec!["Invite".to_owned(), "Setup token".to_owned()],
                        0,
                    ),
                )
                .field(
                    "token",
                    TextInput::sensitive("Token").with_placeholder("only if the server needs one"),
                ),
        )
    }

    fn login_page(&self) -> Page {
        Page::Login(
            Form::new(&["Log in", "Cancel"])
                .field("server", self.server_field())
                .field("email", self.email_field())
                .field(
                    "password",
                    TextInput::password("Account password")
                        .with_validator(required("the account password")),
                )
                .field(
                    "totp",
                    TextInput::sensitive("TOTP code")
                        .with_max_len(10)
                        .with_placeholder("if two-factor is on"),
                )
                .field(
                    "device",
                    TextInput::new("Device name")
                        .with_value(&self.device_name)
                        .with_validator(required("a device name")),
                ),
        )
    }

    fn change_password_page() -> Page {
        Page::ChangePassword(
            Form::new(&["Change password", "Cancel"])
                .field(
                    "old",
                    TextInput::password("Current password")
                        .with_validator(required("the current password")),
                )
                .field(
                    "new",
                    TextInput::password("New password").with_validator(required("a new password")),
                )
                .field("confirm", TextInput::password("Confirm"))
                .field(
                    "totp",
                    TextInput::sensitive("TOTP code")
                        .with_max_len(10)
                        .with_placeholder("if two-factor is on"),
                )
                .validate_with(|v| {
                    let (Some(new), Some(confirm)) = (v.secret("new"), v.secret("confirm")) else {
                        return Err("Enter the new password twice.".to_owned());
                    };
                    if new.expose_secret() != confirm.expose_secret() {
                        return Err("The new passwords don't match.".to_owned());
                    }
                    let strength = courier_ftp_core::vault::estimate(new.expose_secret(), &[]);
                    if !strength.acceptable() {
                        return Err(format!(
                            "Too weak ({}): a strong password is required.",
                            strength.label()
                        ));
                    }
                    Ok(())
                }),
        )
    }

    fn code_form(button: &str, label: &str) -> Form {
        Form::new(&[button, "Cancel"]).field(
            "code",
            TextInput::sensitive(label)
                .with_max_len(10)
                .with_validator(required("the 6-digit code")),
        )
    }

    fn delete_page() -> Page {
        Page::DeleteAccount(
            Form::new(&["Delete account", "Cancel"])
                .field(
                    "password",
                    TextInput::password("Account password")
                        .with_validator(required("the account password")),
                )
                .field(
                    "totp",
                    TextInput::sensitive("TOTP code")
                        .with_max_len(10)
                        .with_placeholder("if two-factor is on"),
                ),
        )
    }

    // ---- keys ---------------------------------------------------------

    pub(crate) fn handle_paste(&mut self, text: &str) {
        if self.busy.is_some() || self.confirm.is_some() {
            return;
        }
        match &mut self.page {
            Page::Register(f)
            | Page::Login(f)
            | Page::Token(f)
            | Page::ChangePassword(f)
            | Page::TotpDisable(f)
            | Page::DeleteAccount(f)
            | Page::Confirm { form: f, .. }
            | Page::TotpSetup { form: f, .. } => f.handle_paste(text),
            _ => {}
        }
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        if self.busy.is_some() {
            return;
        }
        if self.confirm.is_some() {
            self.confirm_key(key);
            return;
        }
        match &mut self.page {
            Page::Overview { .. } => self.overview_key(key),
            Page::Register(_) | Page::Login(_) => self.account_form_key(key),
            Page::Words { .. } => self.words_key(key),
            Page::Confirm { .. } => self.confirm_words_key(key),
            Page::Token(form) => match form.handle_key(key) {
                FormOutcome::Submit => {
                    let token = token_from(&form.values());
                    self.request(
                        SyncRequest::FinishRegistration(token),
                        Some("Creating the account…"),
                    );
                }
                FormOutcome::Cancel => {
                    self.requests.push(SyncRequest::CancelRegistration);
                    self.done(Some("Registration cancelled.".to_owned()));
                }
                _ => {}
            },
            Page::LoginConfirm { .. } => self.login_confirm_key(key),
            Page::Devices { .. } => self.devices_key(key),
            Page::Account { .. } => self.account_key(key),
            Page::ChangePassword(form) => match form.handle_key(key) {
                FormOutcome::Submit => {
                    let v = form.values();
                    self.request(
                        SyncRequest::ChangePassword {
                            old: secret(&v, "old"),
                            new: secret(&v, "new"),
                            totp: optional(&v, "totp"),
                        },
                        Some("Changing the password…"),
                    );
                }
                FormOutcome::Cancel => self.account_done(None),
                _ => {}
            },
            Page::TotpSetup { form, .. } => match form.handle_key(key) {
                FormOutcome::Submit => {
                    let code = secret(&form.values(), "code");
                    self.request(
                        SyncRequest::TotpConfirm(code),
                        Some("Enabling two-factor authentication…"),
                    );
                }
                FormOutcome::Cancel => self.account_done(None),
                _ => {}
            },
            Page::TotpDisable(form) => match form.handle_key(key) {
                FormOutcome::Submit => {
                    let code = secret(&form.values(), "code");
                    self.request(
                        SyncRequest::TotpDisable(code),
                        Some("Disabling two-factor authentication…"),
                    );
                }
                FormOutcome::Cancel => self.account_done(None),
                _ => {}
            },
            Page::DeleteAccount(form) => match form.handle_key(key) {
                FormOutcome::Submit => {
                    let v = form.values();
                    self.confirm = Some(Confirm {
                        title: "Delete the account",
                        text: "Delete the account on the server? Every device is signed out and \
                               the synced copy of your data is deleted. The data on this device \
                               stays, no longer synced."
                            .to_owned(),
                        action: ConfirmAction::Delete {
                            password: secret(&v, "password"),
                            totp: optional(&v, "totp"),
                        },
                        buttons: ButtonRow::new(&["Delete", "Cancel"], 1),
                    });
                }
                FormOutcome::Cancel => self.account_done(None),
                _ => {}
            },
            Page::Teams => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                    self.done(None);
                }
            }
        }
    }

    fn confirm_key(&mut self, key: KeyEvent) {
        let Some(confirm) = self.confirm.as_mut() else {
            return;
        };
        let pressed = if key.code == KeyCode::Esc {
            Some(1)
        } else {
            confirm.buttons.handle_key(key)
        };
        let Some(pressed) = pressed else {
            return;
        };
        let Some(confirm) = self.confirm.take() else {
            return;
        };
        if pressed != 0 {
            return;
        }
        match confirm.action {
            ConfirmAction::Revoke { id, this_device } => self.request(
                SyncRequest::Revoke { id, this_device },
                Some("Revoking the device…"),
            ),
            ConfirmAction::Logout => self.request(SyncRequest::Logout, Some("Logging out…")),
            ConfirmAction::Delete { password, totp } => self.request(
                SyncRequest::DeleteAccount { password, totp },
                Some("Deleting the account…"),
            ),
            ConfirmAction::CancelRegistration => {
                self.requests.push(SyncRequest::CancelRegistration);
                self.done(Some(
                    "Registration cancelled; the recovery words were discarded.".to_owned(),
                ));
            }
        }
    }

    fn overview_key(&mut self, key: KeyEvent) {
        let menu = self.menu();
        let Page::Overview { cursor } = &mut self.page else {
            return;
        };
        match key.code {
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                *cursor = (*cursor + 1).min(menu.len().saturating_sub(1));
            }
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                *cursor = cursor.saturating_sub(1);
            }
            KeyCode::Esc | KeyCode::Char('q') => self.closed = true,
            KeyCode::Enter => {
                let item = menu.get(*cursor).copied();
                self.error = None;
                self.note = None;
                match item {
                    Some(MenuItem::Register) => self.page = self.register_page(),
                    Some(MenuItem::Login | MenuItem::Relogin) => self.page = self.login_page(),
                    Some(MenuItem::SyncNow) => {
                        self.requests.push(SyncRequest::SyncNow);
                        self.note = Some("Sync requested.".to_owned());
                    }
                    Some(MenuItem::Devices) => {
                        self.page = Page::Devices {
                            rows: Vec::new(),
                            cursor: 0,
                            loaded: false,
                        };
                        self.request(SyncRequest::Devices, Some("Loading the devices…"));
                    }
                    Some(MenuItem::Account) => self.page = Page::Account { cursor: 0 },
                    Some(MenuItem::Teams) => self.page = Page::Teams,
                    Some(MenuItem::Close) | None => self.closed = true,
                }
            }
            _ => {}
        }
    }

    fn account_form_key(&mut self, key: KeyEvent) {
        let register = matches!(self.page, Page::Register(_));
        let (Page::Register(form) | Page::Login(form)) = &mut self.page else {
            return;
        };
        match form.handle_key(key) {
            FormOutcome::Submit => {
                let v = form.values();
                let server = v.text("server").trim().to_owned();
                let email = v.text("email").trim().to_owned();
                let device = v.text("device").trim().to_owned();
                let password = secret(&v, "password");
                if register {
                    let token = token_from(&v);
                    self.request(
                        SyncRequest::Register {
                            server,
                            email,
                            device,
                            password,
                            token,
                        },
                        Some("Checking the server and making the account keys…"),
                    );
                } else {
                    self.request(
                        SyncRequest::Login {
                            server,
                            email,
                            device,
                            password,
                            totp: optional(&v, "totp"),
                        },
                        Some("Logging in…"),
                    );
                }
            }
            FormOutcome::Cancel => self.done(None),
            _ => {}
        }
    }

    fn words_key(&mut self, key: KeyEvent) {
        let Page::Words {
            phrase,
            numbers,
            ack,
            on_buttons,
            buttons,
        } = &mut self.page
        else {
            return;
        };
        let pressed = if key.modifiers.contains(KeyModifiers::ALT) {
            buttons.handle_key(key)
        } else {
            match key.code {
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => {
                    *on_buttons = !*on_buttons;
                    None
                }
                KeyCode::Char(' ') if !*on_buttons => {
                    *ack = !*ack;
                    None
                }
                KeyCode::Enter if !*on_buttons => {
                    *ack = !*ack;
                    None
                }
                KeyCode::Esc => Some(1),
                _ if *on_buttons => buttons.handle_key(key),
                _ => None,
            }
        };
        match pressed {
            Some(0) if !*ack => {
                self.error = Some("Tick “I wrote them down” first.".to_owned());
            }
            Some(0) => {
                let (phrase, numbers) = (std::mem::take(phrase), *numbers);
                self.page = Self::confirm_page(phrase, numbers);
                self.error = None;
            }
            Some(_) => self.ask_cancel_registration(),
            None => {}
        }
    }

    fn ask_cancel_registration(&mut self) {
        self.confirm = Some(Confirm {
            title: "Cancel the registration",
            text: "Cancel the registration? The recovery words are discarded and nothing is \
                   created on the server."
                .to_owned(),
            action: ConfirmAction::CancelRegistration,
            buttons: ButtonRow::new(&["Cancel registration", "Keep going"], 1),
        });
    }

    fn confirm_words_key(&mut self, key: KeyEvent) {
        let Page::Confirm {
            phrase,
            numbers,
            form,
        } = &mut self.page
        else {
            return;
        };
        match form.handle_key(key) {
            FormOutcome::Submit => {
                let v = form.values();
                let word = |k: &str| {
                    Zeroizing::new(
                        v.secret(k)
                            .map(|s| s.expose_secret().trim().to_lowercase())
                            .unwrap_or_default(),
                    )
                };
                let answers = Box::new([word("w0"), word("w1"), word("w2")]);
                self.request(SyncRequest::ConfirmWords(answers), Some("Checking…"));
            }
            FormOutcome::Cancel => {
                let (phrase, numbers) = (std::mem::take(phrase), *numbers);
                self.show_words(phrase, numbers);
            }
            _ => {}
        }
    }

    fn login_confirm_key(&mut self, key: KeyEvent) {
        let Page::LoginConfirm {
            rows,
            cursor,
            on_buttons,
            buttons,
            ..
        } = &mut self.page
        else {
            return;
        };
        let cycle = |c: DuplicateChoice, forward: bool| match (c, forward) {
            (DuplicateChoice::KeepBoth, true) | (DuplicateChoice::KeepAccount, false) => {
                DuplicateChoice::KeepLocal
            }
            (DuplicateChoice::KeepLocal, true) | (DuplicateChoice::KeepBoth, false) => {
                DuplicateChoice::KeepAccount
            }
            (DuplicateChoice::KeepAccount, true) | (DuplicateChoice::KeepLocal, false) => {
                DuplicateChoice::KeepBoth
            }
        };
        let pressed = if key.modifiers.contains(KeyModifiers::ALT) {
            buttons.handle_key(key)
        } else if *on_buttons {
            match key.code {
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Up if !rows.is_empty() => {
                    *on_buttons = false;
                    None
                }
                KeyCode::Esc => Some(1),
                _ => buttons.handle_key(key),
            }
        } else {
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    *cursor = (*cursor + 1).min(rows.len().saturating_sub(1));
                    None
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    *cursor = cursor.saturating_sub(1);
                    None
                }
                KeyCode::Right | KeyCode::Char(' ') | KeyCode::Char('l') => {
                    if let Some(r) = rows.get_mut(*cursor) {
                        r.choice = cycle(r.choice, true);
                    }
                    None
                }
                KeyCode::Left | KeyCode::Char('h') => {
                    if let Some(r) = rows.get_mut(*cursor) {
                        r.choice = cycle(r.choice, false);
                    }
                    None
                }
                KeyCode::Char('a') => {
                    if let Some(c) = rows.get(*cursor).map(|r| r.choice) {
                        for r in rows.iter_mut() {
                            r.choice = c;
                        }
                    }
                    None
                }
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Enter => {
                    *on_buttons = true;
                    None
                }
                KeyCode::Esc => Some(1),
                _ => None,
            }
        };
        match pressed {
            Some(0) => {
                let choices = rows.iter().map(|r| (r.local, r.choice)).collect();
                self.request(SyncRequest::CommitLogin(choices), Some("Logging in…"));
            }
            Some(_) => {
                self.requests.push(SyncRequest::CancelLogin);
                self.done(Some("Login cancelled; nothing was changed.".to_owned()));
            }
            None => {}
        }
    }

    fn devices_key(&mut self, key: KeyEvent) {
        let Page::Devices { rows, cursor, .. } = &mut self.page else {
            return;
        };
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                *cursor = (*cursor + 1).min(rows.len().saturating_sub(1));
            }
            KeyCode::Up | KeyCode::Char('k') => *cursor = cursor.saturating_sub(1),
            KeyCode::Char('r') => self.request(SyncRequest::Devices, Some("Loading the devices…")),
            KeyCode::Char('d') | KeyCode::Delete => {
                if let Some(d) = rows.get(*cursor) {
                    let this_device = d.current;
                    let text = if this_device {
                        format!(
                            "Revoke this device (“{}”)? It is logged out of sync; its local \
                             data stays.",
                            d.name
                        )
                    } else {
                        format!(
                            "Revoke “{}” ({})? It can no longer sync and must log in again.",
                            d.name, d.platform
                        )
                    };
                    self.confirm = Some(Confirm {
                        title: "Revoke device",
                        text,
                        action: ConfirmAction::Revoke {
                            id: d.id,
                            this_device,
                        },
                        buttons: ButtonRow::new(&["Revoke", "Cancel"], 1),
                    });
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => self.done(None),
            _ => {}
        }
    }

    fn account_key(&mut self, key: KeyEvent) {
        let Page::Account { cursor } = &mut self.page else {
            return;
        };
        match key.code {
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                *cursor = (*cursor + 1).min(ACCOUNT_ITEMS.len() - 1);
            }
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                *cursor = cursor.saturating_sub(1);
            }
            KeyCode::Esc | KeyCode::Char('q') => self.done(None),
            KeyCode::Enter => {
                self.error = None;
                self.note = None;
                match ACCOUNT_ITEMS.get(*cursor).copied() {
                    Some(AccountItem::ChangePassword) => {
                        self.page = Self::change_password_page();
                    }
                    Some(AccountItem::TotpEnable) => {
                        self.request(SyncRequest::TotpStart, Some("Starting two-factor setup…"))
                    }
                    Some(AccountItem::TotpDisable) => {
                        self.page =
                            Page::TotpDisable(Self::code_form("Disable", "Code from the app"));
                    }
                    Some(AccountItem::RecoveryCode) => self.request(
                        SyncRequest::RecoveryCode,
                        Some("Requesting a recovery code…"),
                    ),
                    Some(AccountItem::Logout) => {
                        self.confirm = Some(Confirm {
                            title: "Log out",
                            text: "Log out of sync on this device? Your sites stay on this device \
                                   but are no longer synced."
                                .to_owned(),
                            action: ConfirmAction::Logout,
                            buttons: ButtonRow::new(&["Log out", "Cancel"], 1),
                        });
                    }
                    Some(AccountItem::Delete) => self.page = Self::delete_page(),
                    Some(AccountItem::Back) | None => self.done(None),
                }
            }
            _ => {}
        }
    }

    // ---- drawing ------------------------------------------------------

    fn spinner(&self) -> &'static str {
        if self.unicode {
            SPINNER[(self.tick as usize) % SPINNER.len()]
        } else {
            SPINNER_ASCII[(self.tick as usize) % SPINNER_ASCII.len()]
        }
    }

    fn title(&self) -> &'static str {
        match self.page {
            Page::Overview { .. } => " Sync ",
            Page::Register(_) => " Sync: create an account ",
            Page::Login(_) => " Sync: log in ",
            Page::Words { .. } => " Sync: your recovery key ",
            Page::Confirm { .. } => " Sync: check the recovery key ",
            Page::Token(_) => " Sync: invite or setup token ",
            Page::LoginConfirm { .. } => " Sync: before logging in ",
            Page::Devices { .. } => " Sync: devices ",
            Page::Account { .. } => " Sync: account ",
            Page::ChangePassword(_) => " Sync: change the password ",
            Page::TotpSetup { .. } => " Sync: two-factor authentication ",
            Page::TotpDisable(_) => " Sync: disable two-factor ",
            Page::DeleteAccount(_) => " Sync: delete the account ",
            Page::Teams => " Sync: teams ",
        }
    }

    /// Draw over `area` (everything but the status bar).
    pub(crate) fn draw(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        frame.render_widget(Clear, area);
        let outer = Block::bordered()
            .title(self.title())
            .border_style(theme.focused_border);
        let inner = outer.inner(area);
        frame.render_widget(outer, area);
        if inner.height < 6 || inner.width < 30 {
            frame.render_widget(
                Paragraph::new("terminal too small").style(theme.error),
                inner,
            );
            return;
        }
        let width = PANEL_W.min(inner.width.saturating_sub(2));
        let x = inner.x + (inner.width - width) / 2;
        let body = Rect::new(x, inner.y + 1, width, inner.height.saturating_sub(3));
        let hint = Rect::new(inner.x + 1, inner.bottom() - 1, inner.width - 2, 1);
        let mut c = Canvas {
            frame,
            area: body,
            y: body.y,
        };
        let hints = self.draw_page(&mut c, theme);
        if let Some(msg) = &self.busy {
            c.blank();
            c.line(Line::from(vec![
                Span::styled(format!("{} ", self.spinner()), theme.key_hint),
                Span::raw(msg.clone()),
            ]));
        } else if let Some(err) = &self.error {
            c.blank();
            c.text(err, theme.error);
        }
        if let Some(note) = &self.note
            && self.busy.is_none()
        {
            c.blank();
            c.text(note, theme.key_hint);
        }
        c.frame
            .render_widget(Paragraph::new(Line::styled(hints, theme.dim)), hint);
        if let Some(confirm) = &self.confirm {
            draw_confirm(c.frame, inner, confirm, theme);
        }
    }

    /// Draws the page; returns the key hints.
    fn draw_page(&self, c: &mut Canvas<'_, '_>, theme: &Theme) -> String {
        let u = self.unicode;
        let marker = if u { "› " } else { "> " };
        let menu_line = |c: &mut Canvas<'_, '_>, label: &str, selected: bool| {
            let (m, style) = if selected {
                (marker, theme.selection)
            } else {
                ("  ", Style::new())
            };
            c.line(Line::styled(format!("{m}{label}"), style));
        };
        match &self.page {
            Page::Overview { cursor } => {
                self.draw_overview(c, theme);
                c.blank();
                for (i, item) in self.menu().iter().enumerate() {
                    menu_line(c, item.label(), i == *cursor);
                }
                "↑/↓ choose · Enter select · Esc close".to_owned()
            }
            Page::Register(form) => {
                c.text(
                    "Your vault is uploaded end-to-end encrypted: the server never sees your \
                     sites or passwords. The account password is your current master password \
                     (type it again to confirm). A token is needed only on servers that are not \
                     open for registration.",
                    Style::new(),
                );
                c.blank();
                c.form(form, theme);
                "Tab next field · Enter continue · Esc cancel".to_owned()
            }
            Page::Login(form) => {
                c.text(
                    "Log in with the account's email and password. Sites already on this \
                     device are added to the account; you choose what happens to duplicates \
                     before anything changes.",
                    Style::new(),
                );
                c.blank();
                c.form(form, theme);
                "Tab next field · Enter log in · Esc cancel".to_owned()
            }
            Page::Words {
                phrase,
                ack,
                on_buttons,
                buttons,
                ..
            } => {
                let warn = if u { "⚠" } else { "!" };
                c.text(&format!("{warn} {RECOVERY_WARNING}"), theme.key_hint);
                c.blank();
                let words: Vec<&str> = phrase.split_whitespace().collect();
                let rows = words.len().div_ceil(4);
                for r in 0..rows {
                    let mut line = String::new();
                    for col in 0..4 {
                        let i = col * rows + r;
                        if let Some(w) = words.get(i) {
                            line.push_str(&format!("{:>3}. {:<14}", i + 1, w));
                        }
                    }
                    c.line(Line::styled(line, theme.title));
                }
                c.blank();
                let mark = if *ack { "[x]" } else { "[ ]" };
                let style = if *on_buttons {
                    Style::new()
                } else {
                    theme.selection
                };
                c.line(Line::from(vec![
                    Span::styled(mark, style),
                    Span::raw(" I wrote them down (on paper, kept somewhere safe)"),
                ]));
                c.blank();
                c.buttons(buttons, *on_buttons, theme);
                "Space tick · Tab buttons · Enter press · Esc cancel the registration".to_owned()
            }
            Page::Confirm { form, .. } => {
                c.text(
                    "Type these words from your recovery key to show you have them.",
                    Style::new(),
                );
                c.blank();
                c.form(form, theme);
                "Tab next field · Enter check · Esc back to the words".to_owned()
            }
            Page::Token(form) => {
                c.text(
                    "The account was not created (the reason is below). Your recovery words \
                     stay valid: try again, adding a token if the server is not open for \
                     registration — the invite token you were sent, or the one-time setup \
                     token the server printed on its first start.",
                    Style::new(),
                );
                c.blank();
                c.form(form, theme);
                "←/→ token type · Tab next field · Enter create · Esc cancel".to_owned()
            }
            Page::LoginConfirm {
                summary,
                rows,
                cursor,
                on_buttons,
                buttons,
            } => {
                c.text(&format!("Logging in as {}.", summary.email), Style::new());
                if summary.password_differs {
                    let warn = if u { "⚠" } else { "!" };
                    c.text(
                        &format!(
                            "{warn} {PASSWORD_ADOPT_WARNING}. Unlock with the account password \
                             from now on."
                        ),
                        theme.key_hint,
                    );
                }
                c.blank();
                if summary.will_import {
                    let n = summary.new_items;
                    c.text(
                        &format!(
                            "{n} item{} from this device will be added to the account.{}",
                            if n == 1 { "" } else { "s" },
                            if summary.skipped_deleted > 0 {
                                format!(
                                    " {} deleted item(s) are left out.",
                                    summary.skipped_deleted
                                )
                            } else {
                                String::new()
                            }
                        ),
                        Style::new(),
                    );
                } else {
                    c.text(
                        "The account's data will be downloaded to this device.",
                        Style::new(),
                    );
                }
                if !rows.is_empty() {
                    c.blank();
                    c.text(
                        "These sites exist on this device and in the account. Choose for each:",
                        Style::new(),
                    );
                    // Marker, label, what matched, `‹ keep account ›`.
                    let free = usize::from(c.area.width).saturating_sub(2 + 1 + 1 + 16);
                    let label_w = (free * 2 / 5).max(8);
                    let matched_w = free.saturating_sub(label_w).max(8);
                    for (i, r) in rows.iter().enumerate() {
                        let selected = i == *cursor && !*on_buttons;
                        let style = if selected {
                            theme.selection
                        } else {
                            Style::new()
                        };
                        let m = if selected { marker } else { "  " };
                        c.line(Line::from(vec![
                            Span::styled(
                                format!("{m}{:<label_w$} ", clip(&r.label, label_w)),
                                style,
                            ),
                            Span::styled(
                                format!("{:<matched_w$} ", clip(&r.matched, matched_w)),
                                theme.dim,
                            ),
                            Span::styled(format!("‹ {} ›", r.choice.label()), theme.title),
                        ]));
                    }
                }
                c.blank();
                c.buttons(buttons, *on_buttons, theme);
                if rows.is_empty() {
                    "Enter press · Esc cancel".to_owned()
                } else {
                    "↑/↓ site · ←/→ keep both / keep local / keep account · a same for all · \
                     Tab buttons · Esc cancel"
                        .to_owned()
                }
            }
            Page::Devices {
                rows,
                cursor,
                loaded,
            } => {
                if rows.is_empty() {
                    if *loaded {
                        c.text("No devices.", theme.dim);
                    }
                } else {
                    c.line(Line::styled(
                        format!(
                            "  {:<22} {:<10} {:<11} {:<11}",
                            "Name", "Platform", "Added", "Last seen"
                        ),
                        theme.dim,
                    ));
                }
                for (i, d) in rows.iter().enumerate() {
                    let selected = i == *cursor;
                    let style = if selected {
                        theme.selection
                    } else {
                        Style::new()
                    };
                    let m = if selected { marker } else { "  " };
                    let this = if d.current {
                        if u {
                            "  ★ this device"
                        } else {
                            "  * this device"
                        }
                    } else {
                        ""
                    };
                    c.line(Line::from(vec![
                        Span::styled(
                            format!(
                                "{m}{:<22} {:<10} {:<11} {:<11}",
                                clip(&d.name, 22),
                                clip(&d.platform, 10),
                                date(d.created_at),
                                d.last_seen_at.map_or_else(|| "—".to_owned(), date),
                            ),
                            style,
                        ),
                        Span::styled(this, theme.title),
                    ]));
                }
                "↑/↓ choose · d revoke · r refresh · Esc back".to_owned()
            }
            Page::Account { cursor } => {
                if let Some(email) = self.info.as_ref().and_then(|i| i.email.as_deref()) {
                    c.text(&format!("Account: {email}"), theme.title);
                    c.blank();
                }
                for (i, item) in ACCOUNT_ITEMS.iter().enumerate() {
                    menu_line(c, item.label(), i == *cursor);
                }
                "↑/↓ choose · Enter select · Esc back".to_owned()
            }
            Page::ChangePassword(form) => {
                c.text(
                    "The new password is also the master password of this device. Your other \
                     devices are signed out and must log in again with it.",
                    Style::new(),
                );
                c.blank();
                c.form(form, theme);
                "Tab next field · Enter change · Esc cancel".to_owned()
            }
            Page::TotpSetup { qr, secret, form } => {
                c.text(
                    "Scan the code with an authenticator app, or type the secret, then enter \
                     the 6-digit code it shows.",
                    Style::new(),
                );
                c.blank();
                // The code and the form below it must fit, or only the
                // secret is shown.
                let fits = qr.as_ref().is_some_and(|qr| {
                    usize::from(c.room()) >= qr.height(u) + form.height() as usize + 6
                        && usize::from(c.area.width) >= qr.width(u)
                });
                if let Some(qr) = qr.as_ref().filter(|_| fits) {
                    let pad = usize::from(c.area.width).saturating_sub(qr.width(u)) / 2;
                    for mut line in qr.lines(u) {
                        line.spans.insert(0, Span::raw(" ".repeat(pad)));
                        c.line(line);
                    }
                    c.blank();
                } else {
                    c.text(
                        "(The window is too small for the QR code: enlarge it, or type the \
                         secret into the app.)",
                        theme.dim,
                    );
                    c.blank();
                }
                c.line(Line::from(vec![
                    Span::styled("Secret: ", theme.dim),
                    Span::styled(group(secret.expose_secret()), theme.title),
                ]));
                c.blank();
                c.form(form, theme);
                "Enter enable · Esc cancel".to_owned()
            }
            Page::TotpDisable(form) => {
                c.text(
                    "Enter a current code from your authenticator app to turn two-factor \
                     authentication off.",
                    Style::new(),
                );
                c.blank();
                c.form(form, theme);
                "Enter disable · Esc cancel".to_owned()
            }
            Page::DeleteAccount(form) => {
                c.text(
                    "Deleting the account removes it and its synced data from the server and \
                     signs every device out. The data on this device stays.",
                    theme.key_hint,
                );
                c.blank();
                c.form(form, theme);
                "Tab next field · Enter delete · Esc cancel".to_owned()
            }
            Page::Teams => {
                c.text(
                    "Teams and shared vaults (organisations, members with roles and \
                     safety-number verification, invites, vault permissions and the audit \
                     log) are not available in this version of courier-ftp yet.",
                    Style::new(),
                );
                c.blank();
                c.text(
                    "Your personal vault syncs between your devices as usual.",
                    theme.dim,
                );
                "Esc back".to_owned()
            }
        }
    }

    fn draw_overview(&self, c: &mut Canvas<'_, '_>, theme: &Theme) {
        let row = |c: &mut Canvas<'_, '_>, label: &str, value: String, style: Style| {
            c.line(Line::from(vec![
                Span::styled(format!("{label:<14}"), theme.dim),
                Span::styled(value, style),
            ]));
        };
        let Some(info) = &self.info else {
            c.text("Reading the sync state…", theme.dim);
            return;
        };
        let Some(server) = &info.server_url else {
            c.text(
                "This device is not connected to a sync server. Your sites, passwords and \
                 trusted keys stay on this device only.",
                Style::new(),
            );
            c.blank();
            c.text(
                "With a sync account they are kept end-to-end encrypted on a courier-ftp \
                 server and shared between your devices. The server never sees them.",
                theme.dim,
            );
            return;
        };
        row(c, "Server:", server.clone(), Style::new());
        row(
            c,
            "Account:",
            info.email.clone().unwrap_or_else(|| "—".to_owned()),
            Style::new(),
        );
        let (status, style) = match &self.status {
            Some(SyncStatus::Error(e)) => (format!("error: {e}"), theme.error),
            Some(SyncStatus::NeedsLogin) => (
                "sign-in required (the password may have changed on another device)".to_owned(),
                theme.key_hint,
            ),
            Some(s @ SyncStatus::Offline { .. }) => (s.to_string(), theme.key_hint),
            Some(s) => (
                s.short().trim_start_matches('⟳').trim().to_owned(),
                Style::new(),
            ),
            None if !info.signed_in => ("signed out".to_owned(), theme.key_hint),
            None => ("—".to_owned(), theme.dim),
        };
        row(c, "Status:", status, style);
        row(
            c,
            "Last sync:",
            info.last_sync_ms
                .map_or_else(|| "never".to_owned(), datetime_ms),
            Style::new(),
        );
        let pending = info.pending_total();
        row(
            c,
            "Pending:",
            format!(
                "{pending} local change{} to upload",
                if pending == 1 { "" } else { "s" }
            ),
            Style::new(),
        );
        c.blank();
        c.line(Line::styled(
            format!("{:<24} {:>10} {:>10}", "Vault", "Revision", "Pending"),
            theme.dim,
        ));
        for v in &info.vaults {
            let name = match v.kind {
                VaultKind::Personal => "Personal".to_owned(),
                VaultKind::Shared => format!("Team vault {}", short_id(&v.vault.to_string())),
            };
            c.line(Line::raw(format!(
                "{name:<24} {:>10} {:>10}",
                v.cursor, v.pending
            )));
        }
        if !self.item_errors.is_empty() {
            c.blank();
            c.text(
                &format!(
                    "{} change(s) held back on this device:",
                    self.item_errors.len()
                ),
                theme.error,
            );
            for (id, message) in self.item_errors.iter().take(5) {
                c.text(&format!("  {} {message}", short_id(id)), theme.dim);
            }
        }
    }
}

/// `2026-10-11`.
fn date(t: time::OffsetDateTime) -> String {
    let d = t.date();
    format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
}

/// `2026-10-11 14:03 UTC`.
fn datetime_ms(ms: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000) {
        Ok(t) => format!("{} {:02}:{:02} UTC", date(t), t.hour(), t.minute()),
        Err(_) => "—".to_owned(),
    }
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// `ABCD EFGH IJKL …` for typing the secret by hand.
fn group(s: &str) -> String {
    s.chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

fn draw_confirm(frame: &mut Frame, area: Rect, confirm: &Confirm, theme: &Theme) {
    let width = 60.min(area.width.saturating_sub(4));
    let lines = wrap(&confirm.text, usize::from(width.saturating_sub(4)));
    let height = u16::try_from(lines.len()).unwrap_or(10) + 5;
    let rect = super::modal::centered(area, width, height);
    frame.render_widget(Clear, rect);
    let block = Block::bordered()
        .title(format!(" {} ", confirm.title))
        .border_style(theme.error);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let text: Vec<Line> = lines.into_iter().map(Line::raw).collect();
    frame.render_widget(
        Paragraph::new(text),
        Rect::new(
            inner.x + 1,
            inner.y + 1,
            inner.width.saturating_sub(2),
            inner.height,
        ),
    );
    confirm.buttons.draw(
        frame,
        Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
        true,
        theme,
    );
}

/// Draws top to bottom in a column.
struct Canvas<'a, 'b> {
    frame: &'a mut Frame<'b>,
    area: Rect,
    y: u16,
}

impl Canvas<'_, '_> {
    fn room(&self) -> u16 {
        self.area.bottom().saturating_sub(self.y)
    }

    fn line(&mut self, line: Line<'_>) {
        if self.room() == 0 {
            return;
        }
        self.frame.render_widget(
            Paragraph::new(line),
            Rect::new(self.area.x, self.y, self.area.width, 1),
        );
        self.y += 1;
    }

    fn blank(&mut self) {
        self.y = (self.y + 1).min(self.area.bottom());
    }

    fn text(&mut self, text: &str, style: Style) {
        for l in wrap(text, usize::from(self.area.width)) {
            self.line(Line::styled(l, style));
        }
    }

    fn form(&mut self, form: &Form, theme: &Theme) {
        let h = form.height().min(self.room());
        form.draw(
            self.frame,
            Rect::new(self.area.x, self.y, self.area.width, h),
            theme,
        );
        self.y += h;
    }

    fn buttons(&mut self, buttons: &ButtonRow, focused: bool, theme: &Theme) {
        if self.room() == 0 {
            return;
        }
        buttons.draw(
            self.frame,
            Rect::new(self.area.x, self.y, self.area.width, 1),
            focused,
            theme,
        );
        self.y += 1;
    }
}

#[cfg(test)]
mod tests;
