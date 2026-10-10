//! Trust prompts and other questions from the core (T69): the prompt queue with its
//! focus rules, the session secret cache, and one dialog per [`PromptKind`]
//! (host keys, certificates, passwords and passphrases, keyboard-interactive, file
//! exists, messages).
//!
//! The queue owns the visible prompt dialog; it is drawn above every other modal and
//! gets every key while visible (`App::mode` is `Dialog` then). Prompts never open
//! while another dialog is open.

use std::fmt;

use courier_ftp_core::{
    events::{PromptKind, PromptRequest, PromptResponse},
    secret::SecretString,
    settings::{InterfaceSettings, enums::SizeFormat},
};
use ratatui::{
    Frame,
    layout::{Position, Rect},
};
use time::OffsetDateTime;

use crate::{
    components::{file_list::format::DateFormats, widgets::WidgetCx},
    keymap::chord::KeyChord,
};

pub(crate) mod certificate;
pub(crate) mod file_exists;
pub(crate) mod host_key;
pub(crate) mod kbd;
pub(crate) mod layout;
pub(crate) mod message;
pub(crate) mod queue;
pub(crate) mod secret;
pub(crate) mod secrets;

#[cfg(test)]
mod app_tests;
#[cfg(test)]
mod props;
#[cfg(test)]
mod snapshot_tests;
#[cfg(test)]
pub(crate) mod tests;

pub(crate) use certificate::{CertificateChainDialog, CertificateDialog};
pub(crate) use file_exists::FileExistsDialog;
pub(crate) use host_key::HostKeyDialog;
pub(crate) use kbd::KbdDialog;
pub(crate) use layout::{Body, BodyCx};
pub(crate) use message::MessagePromptDialog;
pub(crate) use queue::{PromptAnswered, PromptOrigin, PromptQueue, PromptTick, UiFocusState};
pub(crate) use secret::SecretDialog;
pub(crate) use secrets::{CredentialField, Pending, PendingCredentials, SaveRequest, SecretCache};

/// What a prompt dialog did with a key.
pub(crate) enum Step {
    /// Used (or ignored); the dialog stays open.
    Continue,
    /// The user answered.
    Answer(PromptResponse),
}

impl fmt::Debug for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue => f.write_str("Continue"),
            Self::Answer(r) => f.debug_tuple("Answer").field(r).finish(),
        }
    }
}

/// One prompt dialog. Built from the request's payload; draws through
/// [`layout::render_body`].
pub(crate) trait PromptDialog: fmt::Debug + Send {
    /// Kind name for logs (no payload).
    fn kind(&self) -> &'static str;

    /// The title (cleaned when drawn).
    fn title(&self, unicode: bool) -> String;

    /// Border and title in the error style (changed keys and certificates).
    fn danger(&self) -> bool {
        false
    }

    /// A key (the input guard has passed).
    fn handle_key(&mut self, key: KeyChord) -> Step;

    /// Bracketed paste into the focused text field.
    fn handle_paste(&mut self, text: &str) {
        let _ = text;
    }

    /// The content at `width` columns.
    fn body(&self, width: u16, cx: &BodyCx) -> Body;

    /// Draws text field `field` into `area`; returns the cursor position.
    fn draw_input(
        &self,
        frame: &mut Frame,
        field: usize,
        area: Rect,
        cx: &WidgetCx,
    ) -> Option<Position> {
        let _ = (frame, field, area, cx);
        None
    }

    /// A status-line message (paste cut), taken once.
    fn take_notice(&mut self) -> Option<String> {
        None
    }
}

/// What the dialogs need from the settings (formats of the file-exists dialog) and
/// the wall clock (certificate validity).
#[derive(Debug, Clone)]
pub(crate) struct PromptEnv {
    /// `interface.size_format`.
    pub size_format: SizeFormat,
    /// `interface.thousands_separator`.
    pub thousands: bool,
    /// `interface.date_format` / `time_format`.
    pub dates: DateFormats,
    /// Fixed "now" (tests); `None` = the current time.
    pub now: Option<OffsetDateTime>,
}

impl PromptEnv {
    /// The environment for `interface`.
    pub(crate) fn from_settings(interface: &InterfaceSettings) -> Self {
        Self {
            size_format: interface.size_format,
            thousands: interface.thousands_separator,
            dates: DateFormats::from_settings(interface, OffsetDateTime::now_utc()),
            now: None,
        }
    }

    /// "Now" for validity checks.
    pub(crate) fn now(&self) -> OffsetDateTime {
        self.now.unwrap_or_else(OffsetDateTime::now_utc)
    }
}

impl Default for PromptEnv {
    fn default() -> Self {
        Self::from_settings(&InterfaceSettings::default())
    }
}

/// The dialog for `kind`.
pub(crate) fn build_dialog(kind: &PromptKind, env: &PromptEnv) -> Box<dyn PromptDialog> {
    match kind {
        PromptKind::TrustHostKey(p) => Box::new(HostKeyDialog::new(p.clone())),
        PromptKind::TrustCertificate(p) => {
            Box::new(CertificateDialog::new((**p).clone(), env.now()))
        }
        PromptKind::Password(p) => Box::new(SecretDialog::password(p)),
        PromptKind::KeyPassphrase(p) => Box::new(SecretDialog::passphrase(p)),
        PromptKind::KeyboardInteractive(p) => Box::new(KbdDialog::new(p)),
        PromptKind::FileExists(p) => Box::new(FileExistsDialog::new((**p).clone(), env)),
        PromptKind::Message(p) => Box::new(MessagePromptDialog::new(p.clone())),
        // `PromptKind` is non-exhaustive: a kind added later is shown as a message.
        _ => Box::new(MessagePromptDialog::unsupported()),
    }
}

/// Short name of a prompt kind (logs; no payload).
pub(crate) fn kind_name(kind: &PromptKind) -> &'static str {
    match kind {
        PromptKind::TrustHostKey(_) => "TrustHostKey",
        PromptKind::TrustCertificate(_) => "TrustCertificate",
        PromptKind::Password(_) => "Password",
        PromptKind::KeyPassphrase(_) => "KeyPassphrase",
        PromptKind::KeyboardInteractive(_) => "KeyboardInteractive",
        PromptKind::FileExists(_) => "FileExists",
        PromptKind::Message(_) => "Message",
        _ => "unknown",
    }
}

/// Rule 2: a non-retry password/passphrase prompt whose cache key is remembered is
/// answered at once (`None`); any other request is returned.
pub(crate) fn answer_from_cache(req: PromptRequest, cache: &SecretCache) -> Option<PromptRequest> {
    let key = match &req.kind {
        PromptKind::Password(p) if !p.retry => &p.cache_key,
        PromptKind::KeyPassphrase(p) if !p.retry => &p.cache_key,
        _ => return Some(req),
    };
    let Some(value) = cache.get(key) else {
        return Some(req);
    };
    let value = SecretString::from(value.expose());
    tracing::debug!(
        prompt_id = req.id.get(),
        "secret prompt answered from the session cache"
    );
    // A closed reply only means the requester gave up.
    let _ = req.respond(PromptResponse::Secret {
        value,
        remember_session: false,
        save_in_vault: false,
    });
    None
}
