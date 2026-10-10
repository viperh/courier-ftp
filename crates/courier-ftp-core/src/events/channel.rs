//! The event channel: [`EventSender`] / [`EventReceiver`] (T04).
//!
//! An unbounded FIFO of normal events plus a per-transfer progress slot map, behind one
//! mutex, with a [`Notify`] to wake the single receiver. Log events are capped at
//! [`MAX_QUEUED_LOGS`]; other events are low-rate by design and never dropped.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use time::OffsetDateTime;
use tokio::sync::{Notify, oneshot};
use tokio_util::sync::CancellationToken;

use super::log::{sanitise_line, split_lines};
use super::mask::mask_command;
use super::prompt::validate;
use super::{
    CoreEvent, LogKind, LogMessage, PromptId, PromptKind, PromptRequest, PromptResponse, SessionId,
    TransferId, TransferProgress,
};
use crate::settings::DebugLevel;
use crate::{Error, Result};

/// At most this many `Log` events are queued; further lines are counted and dropped.
pub(crate) const MAX_QUEUED_LOGS: usize = 10_000;

/// Creates the event bus with the initial debug level (`logging.level`).
pub fn channel(level: DebugLevel) -> (EventSender, EventReceiver) {
    let shared = Arc::new(Shared {
        level: LogLevelHandle::new(level as u8),
        state: Mutex::new(State::default()),
        notify: Notify::new(),
        senders: AtomicUsize::new(1),
        closed: AtomicBool::new(false),
    });
    (
        EventSender {
            shared: Arc::clone(&shared),
        },
        EventReceiver { shared },
    )
}

/// The message-log debug level shared by every [`EventSender`] clone (T71, T68).
///
/// Values are clamped to 0..=4 (`DebugLevel::None..=Debug`).
#[derive(Debug, Clone)]
pub struct LogLevelHandle(Arc<AtomicU8>);

impl LogLevelHandle {
    fn new(level: u8) -> Self {
        Self(Arc::new(AtomicU8::new(level.min(4))))
    }

    /// The current level, 0..=4.
    pub fn get(&self) -> u8 {
        self.0.load(Ordering::Relaxed)
    }

    /// Changes the level for every clone; takes effect for the next log call.
    /// Values above 4 are clamped to 4.
    pub fn set(&self, level: u8) {
        self.0.store(level.min(4), Ordering::Relaxed);
    }
}

#[derive(Default)]
struct State {
    queue: VecDeque<CoreEvent>,
    /// Number of `CoreEvent::Log` in `queue`.
    queued_logs: usize,
    /// Log lines dropped since the queue was last below the cap.
    dropped_logs: u64,
    progress: BTreeMap<TransferId, TransferProgress>,
}

struct Shared {
    level: LogLevelHandle,
    state: Mutex<State>,
    notify: Notify,
    /// Live `EventSender`s; 0 → `recv` returns None once drained.
    senders: AtomicUsize,
    /// The receiver was dropped; events are discarded.
    closed: AtomicBool,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Sending half of the bus. Cheap to clone; `Send + Sync`.
pub struct EventSender {
    shared: Arc<Shared>,
}

impl Clone for EventSender {
    fn clone(&self) -> Self {
        self.shared.senders.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl Drop for EventSender {
    fn drop(&mut self) {
        if self.shared.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.notify.notify_one();
        }
    }
}

impl fmt::Debug for EventSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventSender")
            .field("level", &self.shared.level.get())
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl EventSender {
    /// Sends an event. Never blocks and never fails; events are discarded when the
    /// receiver is gone. `Log` events go through the flood limit (prefer [`log`](Self::log),
    /// which also filters and sanitises); `TransferProgress` goes through the
    /// coalescing slot like [`progress`](Self::progress).
    pub fn send(&self, event: CoreEvent) {
        match event {
            CoreEvent::Log(msg) => self.push_log(msg),
            CoreEvent::TransferProgress(p) => self.progress(p),
            event => {
                if self.is_closed() {
                    return;
                }
                self.shared.lock().queue.push_back(event);
                self.shared.notify.notify_one();
            }
        }
    }

    /// Logs `text` for `session`: applies the level filter, splits on `'\n'`, sanitises,
    /// truncates and timestamps (one [`LogMessage`] per line). `Debug(0)` and levels
    /// above 4 are clamped to 1 and 4.
    pub fn log(&self, session: SessionId, kind: LogKind, text: impl AsRef<str>) {
        let kind = match kind {
            LogKind::Debug(level) => {
                let level = level.clamp(1, 4);
                if !self.enabled(level) {
                    return;
                }
                LogKind::Debug(level)
            }
            kind => kind,
        };
        if self.is_closed() {
            return;
        }
        let time = OffsetDateTime::now_utc();
        for line in split_lines(text.as_ref()) {
            self.push_log(LogMessage {
                time,
                session,
                kind,
                text: sanitise_line(line),
            });
        }
    }

    /// `log(Command, mask_command(cmd))`.
    pub fn log_command(&self, session: SessionId, cmd: &str) {
        self.log(session, LogKind::Command, mask_command(cmd));
    }

    /// Whether `Debug(level)` lines are currently delivered. Cheap; check it before
    /// formatting expensive debug text.
    pub fn enabled(&self, level: u8) -> bool {
        level.clamp(1, 4) <= self.shared.level.get()
    }

    /// Changes the debug level at runtime (T68, T71); applies to every clone.
    pub fn set_level(&self, level: DebugLevel) {
        self.shared.level.set(level as u8);
    }

    /// The current debug level.
    pub fn level(&self) -> DebugLevel {
        DebugLevel::try_from(self.shared.level.get()).unwrap_or(DebugLevel::Debug)
    }

    /// The shared level handle (T71).
    pub fn log_level(&self) -> &LogLevelHandle {
        &self.shared.level
    }

    /// Stores `p` in its transfer's coalescing slot, replacing any pending value.
    pub fn progress(&self, p: TransferProgress) {
        if self.is_closed() {
            return;
        }
        self.shared.lock().progress.insert(p.id, p);
        self.shared.notify.notify_one();
    }

    /// Sends `TransferStateChanged` and discards pending progress for `id`.
    pub fn transfer_state(&self, id: TransferId) {
        if self.is_closed() {
            return;
        }
        {
            let mut state = self.shared.lock();
            state.progress.remove(&id);
            state
                .queue
                .push_back(CoreEvent::TransferStateChanged { id });
        }
        self.shared.notify.notify_one();
    }

    /// Asks the UI and waits for the answer (no timeout).
    ///
    /// # Errors
    ///
    /// [`Error::Cancelled`] when there is no receiver, the UI drops the request or
    /// answers `Cancel`; [`Error::Internal`] when the answer does not match the kind.
    /// `AlwaysTrust` for a prompt whose `can_save` is false is returned as `TrustOnce`.
    pub async fn prompt(&self, session: SessionId, kind: PromptKind) -> Result<PromptResponse> {
        self.prompt_tracked(session, kind, None)
            .await
            .map(|(_, r)| r)
    }

    /// As [`prompt`](Self::prompt), but also returns `Cancelled` as soon as `cancel`
    /// fires (the request is then withdrawn).
    ///
    /// # Errors
    ///
    /// As [`prompt`](Self::prompt).
    pub async fn prompt_with_cancel(
        &self,
        session: SessionId,
        kind: PromptKind,
        cancel: &CancellationToken,
    ) -> Result<PromptResponse> {
        self.prompt_tracked(session, kind, Some(cancel))
            .await
            .map(|(_, r)| r)
    }

    /// As [`prompt_with_cancel`](Self::prompt_with_cancel), also returning the
    /// [`PromptId`] (secret prompts, so the producer can later call
    /// [`credential_accepted`](Self::credential_accepted)).
    ///
    /// # Errors
    ///
    /// As [`prompt`](Self::prompt).
    pub async fn prompt_tracked(
        &self,
        session: SessionId,
        kind: PromptKind,
        cancel: Option<&CancellationToken>,
    ) -> Result<(PromptId, PromptResponse)> {
        if self.is_closed() || cancel.is_some_and(CancellationToken::is_cancelled) {
            return Err(Error::Cancelled);
        }
        let id = PromptId::next();
        let (tx, rx) = oneshot::channel();
        self.send(CoreEvent::Prompt(PromptRequest::new(
            id,
            session,
            kind.clone(),
            tx,
        )));
        let answer = match cancel {
            Some(token) => tokio::select! {
                biased;
                () = token.cancelled() => return Err(Error::Cancelled),
                answer = rx => answer,
            },
            None => rx.await,
        };
        let response = answer.map_err(|_| Error::Cancelled)?;
        validate(&kind, response).map(|r| (id, r))
    }

    /// Sends [`CoreEvent::CredentialAccepted`]: the server accepted the secret given for
    /// `prompt_id`.
    pub fn credential_accepted(&self, session: SessionId, prompt_id: PromptId) {
        self.send(CoreEvent::CredentialAccepted { session, prompt_id });
    }

    /// The receiver was dropped.
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }

    fn push_log(&self, msg: LogMessage) {
        if self.is_closed() {
            return;
        }
        {
            let mut state = self.shared.lock();
            let needed = if state.dropped_logs > 0 { 2 } else { 1 };
            if state.queued_logs + needed > MAX_QUEUED_LOGS {
                state.dropped_logs += 1;
                return;
            }
            if state.dropped_logs > 0 {
                let n = std::mem::take(&mut state.dropped_logs);
                state.queue.push_back(CoreEvent::Log(LogMessage {
                    time: msg.time,
                    session: SessionId::APP,
                    kind: LogKind::Status,
                    text: format!("{n} log messages dropped (message log could not keep up)"),
                }));
                state.queued_logs += 1;
            }
            state.queue.push_back(CoreEvent::Log(msg));
            state.queued_logs += 1;
        }
        self.shared.notify.notify_one();
    }
}

/// Receiving half of the bus, owned by the binary's main loop (T50) or a headless
/// drain task (T76).
pub struct EventReceiver {
    shared: Arc<Shared>,
}

impl fmt::Debug for EventReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventReceiver").finish_non_exhaustive()
    }
}

impl EventReceiver {
    /// The next event; None when every [`EventSender`] is dropped and nothing is
    /// pending. Queued normal events come first (FIFO), then one pending progress value
    /// (lowest transfer id first).
    pub async fn recv(&mut self) -> Option<CoreEvent> {
        loop {
            if let Some(event) = self.try_recv() {
                return Some(event);
            }
            if self.shared.senders.load(Ordering::Acquire) == 0 {
                return self.try_recv();
            }
            // `notify_one` stores a permit when nobody waits, so a send between
            // `try_recv` and here is not lost.
            self.shared.notify.notified().await;
        }
    }

    /// The next event, if one is pending.
    pub fn try_recv(&mut self) -> Option<CoreEvent> {
        let mut state = self.shared.lock();
        if let Some(event) = state.queue.pop_front() {
            if matches!(event, CoreEvent::Log(_)) {
                state.queued_logs -= 1;
            }
            return Some(event);
        }
        state
            .progress
            .pop_first()
            .map(|(_, p)| CoreEvent::TransferProgress(p))
    }
}

impl Drop for EventReceiver {
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::Release);
        // Drop pending events (and with them pending prompt requests, which cancels
        // their requesters) outside the lock.
        let (queue, progress) = {
            let mut state = self.shared.lock();
            state.queued_logs = 0;
            (
                std::mem::take(&mut state.queue),
                std::mem::take(&mut state.progress),
            )
        };
        drop(queue);
        drop(progress);
    }
}

/// Convenience for code that logs for one session (backends, net layer).
#[derive(Clone, Debug)]
pub struct SessionLog {
    /// The bus.
    pub events: EventSender,
    /// The session the lines belong to.
    pub session: SessionId,
}

impl SessionLog {
    /// A `Status` line.
    pub fn status(&self, t: impl AsRef<str>) {
        self.events.log(self.session, LogKind::Status, t);
    }

    /// An `Error` line.
    pub fn error(&self, t: impl AsRef<str>) {
        self.events.log(self.session, LogKind::Error, t);
    }

    /// A `Command` line, masked with [`mask_command`].
    pub fn command(&self, cmd: &str) {
        self.events.log_command(self.session, cmd);
    }

    /// A `Response` line.
    pub fn response(&self, t: impl AsRef<str>) {
        self.events.log(self.session, LogKind::Response, t);
    }

    /// A `ListingRaw` line.
    pub fn listing(&self, t: impl AsRef<str>) {
        self.events.log(self.session, LogKind::ListingRaw, t);
    }

    /// A `Debug(level)` line, level 1..=4.
    pub fn debug(&self, level: u8, t: impl AsRef<str>) {
        self.events.log(self.session, LogKind::Debug(level), t);
    }

    /// Whether `Debug(level)` lines are currently delivered.
    pub fn enabled(&self, level: u8) -> bool {
        self.events.enabled(level)
    }
}

#[cfg(test)]
impl EventSender {
    /// Number of pending progress slots (AC4).
    pub(crate) fn shared_progress_len(&self) -> usize {
        self.shared.lock().progress.len()
    }
}
