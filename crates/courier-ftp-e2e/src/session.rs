//! [`Headless`]: one session through a real backend, [`SessionHandle`] and the event
//! bus, without a TUI.
//!
//! A drain task owns the bus: it records every message-log line, answers prompts from
//! [`HeadlessOptions`] and forwards every other event to [`Headless::wait_for_event`].
//! A prompt without an answer (policy [`PromptPolicy::Fail`], or a kind the options do
//! not cover) is cancelled and fails the running operation with
//! `unexpected prompt: <kind and content>`.
//!
//! The transfer helpers of the spec (`download`, `upload`, `run_queue`) arrive with the
//! transfer engine (M4, T41–T44).

use std::{fmt, sync::Arc, time::Duration};

use courier_ftp_core::{
    Error as CoreError,
    backend::{
        Backend, BackendContext, BackendFactory, ConnectInfo, Listing, SessionHandle,
        SessionOptions,
    },
    events::{
        CoreEvent, EventReceiver, LogMessage, PromptKind, PromptRequest, PromptResponse, SessionId,
        TrustAnswer, channel as event_channel,
    },
    model::{Protocol, RemotePath},
    settings::{DebugLevel, Settings, SharedSettings},
};
use parking_lot::Mutex;
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{E2eError, TestHome, WaitError, diag};

/// How [`Headless`] answers a trust prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PromptPolicy {
    /// Fail the test with the prompt's content.
    #[default]
    Fail,
    /// Trust for this connection.
    TrustOnce,
    /// Store as trusted.
    TrustAlways,
    /// Refuse.
    Reject,
}

impl PromptPolicy {
    fn answer(self) -> Option<TrustAnswer> {
        match self {
            Self::Fail => None,
            Self::TrustOnce => Some(TrustAnswer::TrustOnce),
            Self::TrustAlways => Some(TrustAnswer::AlwaysTrust),
            Self::Reject => Some(TrustAnswer::Reject),
        }
    }
}

/// Answers for the prompts of a [`Headless`] session.
#[derive(Debug, Default)]
pub struct HeadlessOptions {
    /// Host-key prompts (T21).
    pub host_key: PromptPolicy,
    /// Certificate prompts (T12).
    pub certificate: PromptPolicy,
    /// Answer to password prompts.
    pub password: Option<String>,
    /// Answer to key passphrase prompts.
    pub passphrase: Option<String>,
    /// Keyboard-interactive answers, in prompt order (consumed field by field).
    pub kbd_answers: Vec<String>,
    /// Settings (defaults otherwise).
    pub settings: Option<Settings>,
}

/// Maps the protocol to the FTP / SFTP backend exactly like the binary's factory.
///
/// The FTP (T14) and SFTP (T22) backends do not exist yet; until they do, both
/// protocols answer `Unsupported` (the container scenarios that need them are written
/// in those tasks).
#[derive(Debug, Default)]
pub struct E2eBackendFactory;

impl BackendFactory for E2eBackendFactory {
    fn create(
        &self,
        info: Arc<ConnectInfo>,
        _ctx: BackendContext,
    ) -> courier_ftp_core::Result<Box<dyn Backend>> {
        info.validate()?;
        match info.address.protocol {
            Protocol::Ftp => Err(CoreError::Unsupported(
                "the FTP backend is not wired into the e2e harness yet (T14)".into(),
            )),
            Protocol::Sftp => Err(CoreError::Unsupported(
                "the SFTP backend is not wired into the e2e harness yet (T22)".into(),
            )),
        }
    }
}

/// A [`Headless`] failure: the backend's own error (unchanged, so scenarios can match
/// on `Error::Auth`, `Error::Tls`, …) or a harness failure (an unexpected prompt).
#[derive(Debug)]
pub enum HeadlessError {
    /// The backend or session failed.
    Core(CoreError),
    /// The harness failed (e.g. `unexpected prompt: …`).
    Harness(E2eError),
}

impl HeadlessError {
    /// The core error, if that is what failed.
    pub fn core(&self) -> Option<&CoreError> {
        match self {
            Self::Core(e) => Some(e),
            Self::Harness(_) => None,
        }
    }
}

impl fmt::Display for HeadlessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(e) => write!(f, "{e}"),
            Self::Harness(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for HeadlessError {}

/// Result of [`Headless`] operations.
pub type HeadlessResult<T> = std::result::Result<T, HeadlessError>;

#[derive(Default)]
struct Shared {
    log: Vec<String>,
    prompts: Vec<String>,
    unexpected: Option<String>,
}

/// One session without a TUI. Dumps its last 200 message-log lines when dropped during
/// a failing test.
pub struct Headless {
    session: SessionHandle,
    shared: Arc<Mutex<Shared>>,
    events: mpsc::UnboundedReceiver<CoreEvent>,
    drain: JoinHandle<()>,
    cancel: CancellationToken,
    // Keeps the settings channel open for the backend.
    _settings: tokio::sync::watch::Sender<Arc<Settings>>,
}

impl fmt::Debug for Headless {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Headless")
            .field("session", &self.session.id())
            .finish_non_exhaustive()
    }
}

/// `HH:MM:SS Kind: text`, like the message log.
fn format_log(m: &LogMessage) -> String {
    format!(
        "{:02}:{:02}:{:02} {:?}: {}",
        m.time.hour(),
        m.time.minute(),
        m.time.second(),
        m.kind,
        m.text
    )
}

/// The answer for `prompt`, or why there is none.
fn answer(
    prompt: &PromptKind,
    opts: &HeadlessOptions,
    kbd_next: &mut usize,
) -> std::result::Result<PromptResponse, String> {
    let secret = |v: &String| PromptResponse::Secret {
        value: v.as_str().into(),
        remember_session: false,
        save_in_vault: false,
    };
    match prompt {
        PromptKind::TrustHostKey(_) => opts
            .host_key
            .answer()
            .map(PromptResponse::HostKey)
            .ok_or_else(|| "host_key policy is Fail".into()),
        PromptKind::TrustCertificate(_) => opts
            .certificate
            .answer()
            .map(PromptResponse::Certificate)
            .ok_or_else(|| "certificate policy is Fail".into()),
        PromptKind::Password(_) => opts
            .password
            .as_ref()
            .map(secret)
            .ok_or_else(|| "no password in HeadlessOptions".into()),
        PromptKind::KeyPassphrase(_) => opts
            .passphrase
            .as_ref()
            .map(secret)
            .ok_or_else(|| "no passphrase in HeadlessOptions".into()),
        PromptKind::KeyboardInteractive(k) => {
            let end = *kbd_next + k.prompts.len();
            let Some(answers) = opts.kbd_answers.get(*kbd_next..end) else {
                return Err(format!(
                    "{} keyboard-interactive answers needed, {} left",
                    k.prompts.len(),
                    opts.kbd_answers.len().saturating_sub(*kbd_next)
                ));
            };
            *kbd_next = end;
            Ok(PromptResponse::Answers(
                answers.iter().map(|a| a.as_str().into()).collect(),
            ))
        }
        PromptKind::Message(_) => Ok(PromptResponse::Ack),
        _ => Err("no answer for this prompt kind".into()),
    }
}

async fn drain_task(
    mut rx: EventReceiver,
    opts: HeadlessOptions,
    shared: Arc<Mutex<Shared>>,
    forward: mpsc::UnboundedSender<CoreEvent>,
    cancel: CancellationToken,
) {
    let mut kbd_next = 0;
    while let Some(event) = rx.recv().await {
        match event {
            CoreEvent::Log(m) => {
                shared.lock().log.push(format_log(&m));
                let _ = forward.send(CoreEvent::Log(m));
            }
            CoreEvent::Prompt(req) => handle_prompt(req, &opts, &shared, &mut kbd_next, &cancel),
            other => {
                let _ = forward.send(other);
            }
        }
    }
}

fn handle_prompt(
    req: PromptRequest,
    opts: &HeadlessOptions,
    shared: &Mutex<Shared>,
    kbd_next: &mut usize,
    cancel: &CancellationToken,
) {
    let content = format!("{:?}", req.kind);
    shared.lock().prompts.push(content.clone());
    match answer(&req.kind, opts, kbd_next) {
        Ok(response) => {
            req.respond(response);
        }
        Err(why) => {
            shared.lock().unexpected = Some(format!("unexpected prompt ({why}): {content}"));
            req.respond(PromptResponse::Cancel);
            cancel.cancel();
        }
    }
}

impl Headless {
    /// Connect through [`E2eBackendFactory`]. `home` provides the trust stores and
    /// credentials once the vault exists (T30); it is unused until then.
    ///
    /// # Errors
    /// The backend's error, or an unexpected prompt.
    pub async fn connect(
        home: Option<&TestHome>,
        info: ConnectInfo,
        opts: HeadlessOptions,
    ) -> HeadlessResult<Self> {
        let _ = home;
        Self::connect_with(Arc::new(E2eBackendFactory), info, opts).await
    }

    /// Connect through `factory` (harness self-tests use a `MockServer`).
    ///
    /// # Errors
    /// The backend's error, or an unexpected prompt.
    pub async fn connect_with(
        factory: Arc<dyn BackendFactory>,
        info: ConnectInfo,
        mut opts: HeadlessOptions,
    ) -> HeadlessResult<Self> {
        let settings = opts.settings.take().unwrap_or_default();
        let (events, rx) = event_channel(DebugLevel::Debug);
        let (settings_tx, settings_rx): (_, SharedSettings) =
            tokio::sync::watch::channel(Arc::new(settings));
        let ctx = BackendContext {
            session: SessionId::next(),
            events,
            settings: settings_rx,
        };
        let label = info.label.clone();
        let backend = factory
            .create(Arc::new(info), ctx.clone())
            .map_err(HeadlessError::Core)?;
        let shared = Arc::new(Mutex::new(Shared::default()));
        let (tx, events_rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let drain = tokio::spawn(drain_task(
            rx,
            opts,
            Arc::clone(&shared),
            tx,
            cancel.clone(),
        ));
        let session = SessionHandle::new(backend, ctx, SessionOptions::default(), label);
        let headless = Self {
            session,
            shared,
            events: events_rx,
            drain,
            cancel,
            _settings: settings_tx,
        };
        let res = headless.session.connect(&headless.cancel).await;
        headless.check(res)?;
        Ok(headless)
    }

    fn check<T>(&self, res: courier_ftp_core::Result<T>) -> HeadlessResult<T> {
        if let Some(msg) = self.shared.lock().unexpected.clone() {
            return Err(HeadlessError::Harness(E2eError::new(msg)));
        }
        res.map_err(HeadlessError::Core)
    }

    /// The session.
    pub fn session(&self) -> &SessionHandle {
        &self.session
    }

    /// List `dir`.
    ///
    /// # Errors
    /// The backend's error, or an unexpected prompt.
    pub async fn list(&self, dir: &RemotePath) -> HeadlessResult<Listing> {
        let res = self.session.list(dir, &self.cancel).await;
        self.check(res)
    }

    /// Wait (up to [`crate::timeout`]) for an event matching `pred`; earlier events
    /// are discarded.
    ///
    /// # Errors
    /// No such event in time; `last` is the message-log tail.
    pub async fn wait_for_event(
        &mut self,
        what: &str,
        pred: impl Fn(&CoreEvent) -> bool,
    ) -> std::result::Result<CoreEvent, WaitError> {
        let limit = crate::timeout();
        let started = tokio::time::Instant::now();
        loop {
            let left = limit.saturating_sub(started.elapsed());
            match tokio::time::timeout(left, self.events.recv()).await {
                Ok(Some(ev)) if pred(&ev) => return Ok(ev),
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {
                    return Err(WaitError {
                        what: what.to_owned(),
                        waited: started.elapsed(),
                        last: diag::tail(&self.log_text(), 40),
                    });
                }
            }
        }
    }

    /// Every message-log line seen so far (`HH:MM:SS Kind: text`).
    pub fn log_text(&self) -> String {
        self.shared.lock().log.join("\n")
    }

    /// The `Debug` form of every prompt seen so far.
    pub fn prompts_seen(&self) -> Vec<String> {
        self.shared.lock().prompts.clone()
    }

    /// Disconnect (best effort) and stop the drain task.
    pub async fn close(self) {
        let _ = tokio::time::timeout(Duration::from_secs(5), self.session.disconnect()).await;
    }
}

impl Drop for Headless {
    fn drop(&mut self) {
        if diag::failing() {
            diag::dump(
                &format!("message log of session {:?}", self.session.id()),
                &diag::tail(&self.log_text(), 200),
            );
        }
        self.drain.abort();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use courier_ftp_core::events::{KbdField, KbdInteractivePrompt};

    use super::*;

    #[test]
    fn prompt_answers_follow_the_options() {
        let opts = HeadlessOptions {
            kbd_answers: vec!["test".into(), "424242".into()],
            ..HeadlessOptions::default()
        };
        let kbd = |n| {
            PromptKind::KeyboardInteractive(KbdInteractivePrompt {
                host: "h:22".into(),
                name: String::new(),
                instructions: String::new(),
                prompts: (0..n)
                    .map(|i| KbdField {
                        text: format!("p{i}"),
                        echo: false,
                    })
                    .collect(),
            })
        };
        let mut next = 0;
        assert!(matches!(
            answer(&kbd(1), &opts, &mut next),
            Ok(PromptResponse::Answers(a)) if a.len() == 1
        ));
        assert!(matches!(
            answer(&kbd(1), &opts, &mut next),
            Ok(PromptResponse::Answers(a)) if a.len() == 1
        ));
        assert!(
            answer(&kbd(1), &opts, &mut next)
                .unwrap_err()
                .contains("left")
        );
        assert_eq!(PromptPolicy::default().answer(), None);
        assert_eq!(
            PromptPolicy::TrustAlways.answer(),
            Some(TrustAnswer::AlwaysTrust)
        );
    }
}
