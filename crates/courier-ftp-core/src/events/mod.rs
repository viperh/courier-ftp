//! The event and log bus between backends, the transfer engine, the vault and
//! the UI (T04).
//!
//! Everything the core wants to tell the UI goes through one [`EventSender`]:
//! message-log lines, connection state, transfer progress and prompts. The UI
//! owns the matching [`EventReceiver`] and turns events into actions (T50); the
//! core never knows what is on the screen.
//!
//! - **Log lines** below the configured FileZilla debug level are dropped at the
//!   source ([`EventSender::log`]), so a chatty backend can't flood the channel.
//!   Outgoing commands are masked with [`mask_command`] before they are logged.
//! - **Transfer progress** is coalesced: only the latest value per transfer is
//!   kept until the UI picks it up, so a fast transfer and a slow UI can't fill
//!   memory.
//! - **Prompts** ([`EventSender::ask`]) send a question and wait for the answer.
//!   There is no timeout (the user may be away); the operation's
//!   [`CancellationToken`] or a dropped reply cancels the wait.

mod mask;
mod prompt;

use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};

pub use mask::{mask_command, mask_secrets};
pub use prompt::{
    ApplyTo, FileExistsAnswer, PromptId, PromptKind, PromptRequest, PromptResponse, TrustDecision,
};
use time::OffsetDateTime;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::{
    Error, Result,
    model::{RemotePath, ServerAddress},
};

/// Identifies one connection (one tab, or one extra transfer connection).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

impl SessionId {
    /// A new id, unique within this process.
    pub fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// Identifies one transfer queue item (T40).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct TransferId(pub u64);

/// The kind of a message-log line, as FileZilla colours them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogKind {
    /// Progress in plain words ("Connecting to …", "Directory listing successful").
    Status,
    /// A command sent to the server (already masked).
    Command,
    /// A reply from the server.
    Response,
    /// A failure.
    Error,
    /// A raw directory listing line (shown with `logging.show_raw_listing`, or
    /// at debug level 3 and up).
    ListingRaw,
    /// Debug output of level 1 (warning) to 4 (debug); shown when the configured
    /// level is at least this.
    Debug(u8),
}

/// One line of the message log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogMessage {
    /// When it happened.
    pub time: OffsetDateTime,
    /// The connection it belongs to.
    pub session: SessionId,
    /// Its kind.
    pub kind: LogKind,
    /// The text, with secrets already masked.
    pub text: String,
}

/// Progress of one running transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferProgress {
    /// The transfer.
    pub id: TransferId,
    /// Bytes transferred so far (including a resumed offset).
    pub bytes_done: u64,
    /// The total size, when known.
    pub total: Option<u64>,
    /// Current speed in bytes per second.
    pub speed_bps: u64,
    /// Estimated time left, when it can be estimated.
    pub eta: Option<Duration>,
}

/// The coarse state of a transfer, as the queue pane shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransferState {
    /// Waiting in the queue.
    Queued,
    /// Running.
    Active,
    /// Paused by the user.
    Paused,
    /// Finished successfully.
    Done,
    /// Skipped (file exists, filter).
    Skipped,
    /// Failed with this message.
    Failed(String),
}

/// Totals when the queue finishes (T45).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueueStats {
    /// Files transferred successfully.
    pub files_ok: u64,
    /// Files that failed.
    pub files_failed: u64,
    /// Files skipped.
    pub files_skipped: u64,
    /// Bytes transferred.
    pub bytes: u64,
    /// Wall-clock time from the first start to the end.
    pub elapsed: Duration,
}

/// Everything the core tells the UI.
#[derive(Debug)]
#[non_exhaustive]
pub enum CoreEvent {
    /// A message-log line.
    Log(LogMessage),
    /// A session connected.
    Connected {
        /// The session.
        session: SessionId,
        /// Where it is connected to.
        address: ServerAddress,
    },
    /// A session disconnected.
    Disconnected {
        /// The session.
        session: SessionId,
        /// Why, when it wasn't asked for.
        reason: Option<String>,
    },
    /// A directory listing changed (fresh listing or local change).
    ListingUpdated {
        /// The session (local browsing has its own session).
        session: SessionId,
        /// The directory.
        dir: RemotePath,
    },
    /// Latest progress of a transfer (coalesced).
    TransferProgress(TransferProgress),
    /// A transfer changed state.
    TransferStateChanged {
        /// The transfer.
        id: TransferId,
        /// Its new state.
        state: TransferState,
    },
    /// The queue ran empty.
    QueueFinished {
        /// Totals.
        stats: QueueStats,
    },
    /// The core is waiting for an answer.
    Prompt(PromptRequest),
    /// Progress of a recursive listing, delete or chmod (T43), for the
    /// status bar. Coalesced by the sender (about 10 per second), plus a
    /// final one with `finished` set.
    RecursiveProgress(RecursiveProgress),
}

/// Which recursive operation a [`RecursiveProgress`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecursiveOperation {
    /// Walking a tree (counting, comparing, searching).
    Listing,
    /// Recursive delete.
    Delete,
    /// Recursive chmod.
    Chmod,
}

/// Progress of a recursive operation (T43).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveProgress {
    /// The session doing the work.
    pub session: SessionId,
    /// What is being done.
    pub operation: RecursiveOperation,
    /// The directory being listed or processed.
    pub current: RemotePath,
    /// Directories found so far.
    pub dirs: u64,
    /// Files (and symlinks) found so far.
    pub files: u64,
    /// Entries deleted or changed so far (0 for a plain listing).
    pub done: u64,
    /// The operation ended (completed, cancelled or failed).
    pub finished: bool,
}

/// Which log lines are kept. Shared by every clone of an [`EventSender`] and
/// changeable at runtime (the settings screen).
#[derive(Debug)]
struct LogFilter {
    level: AtomicU8,
    raw_listing: AtomicBool,
}

impl LogFilter {
    fn allows(&self, kind: LogKind) -> bool {
        match kind {
            LogKind::Debug(n) => n >= 1 && n <= self.level.load(Ordering::Relaxed),
            // Debug level 3 (verbose) and up includes raw listings too (T71).
            LogKind::ListingRaw => {
                self.raw_listing.load(Ordering::Relaxed) || self.level.load(Ordering::Relaxed) >= 3
            }
            _ => true,
        }
    }
}

#[derive(Debug, Default)]
struct ProgressSlot {
    latest: Mutex<HashMap<TransferId, TransferProgress>>,
    notify: Notify,
}

/// The sending half of the bus. Cheap to clone; give one to every backend,
/// worker and service.
#[derive(Debug, Clone)]
pub struct EventSender {
    tx: mpsc::UnboundedSender<CoreEvent>,
    filter: Arc<LogFilter>,
    progress: Arc<ProgressSlot>,
}

/// The receiving half of the bus, owned by the UI.
#[derive(Debug)]
pub struct EventReceiver {
    rx: mpsc::UnboundedReceiver<CoreEvent>,
    progress: Arc<ProgressSlot>,
    pending: Vec<TransferProgress>,
}

/// A connected sender and receiver. `level` is the FileZilla debug level 0–4
/// (setting `logging.level`).
pub fn channel(level: u8) -> (EventSender, EventReceiver) {
    let (tx, rx) = mpsc::unbounded_channel();
    let progress = Arc::new(ProgressSlot::default());
    let sender = EventSender {
        tx,
        filter: Arc::new(LogFilter {
            level: AtomicU8::new(level),
            raw_listing: AtomicBool::new(false),
        }),
        progress: Arc::clone(&progress),
    };
    let receiver = EventReceiver {
        rx,
        progress,
        pending: Vec::new(),
    };
    (sender, receiver)
}

impl EventSender {
    /// Send an event. Returns `false` when the UI has gone away.
    pub fn send(&self, event: CoreEvent) -> bool {
        self.tx.send(event).is_ok()
    }

    /// Log a line, unless the configured level filters it out.
    pub fn log(&self, session: SessionId, kind: LogKind, text: impl Into<String>) {
        if self.filter.allows(kind) {
            self.send(CoreEvent::Log(LogMessage {
                time: OffsetDateTime::now_utc(),
                session,
                kind,
                text: text.into(),
            }));
        }
    }

    /// Log an outgoing command, masking secrets ([`mask_command`]).
    pub fn log_command(&self, session: SessionId, cmd: &str) {
        if self.filter.allows(LogKind::Command) {
            self.log(session, LogKind::Command, mask_command(cmd).into_owned());
        }
    }

    /// Whether a line of this kind would be kept; check before building
    /// expensive debug text.
    pub fn enabled(&self, kind: LogKind) -> bool {
        self.filter.allows(kind)
    }

    /// Change the debug level (0–4) for every clone of this sender.
    pub fn set_log_level(&self, level: u8) {
        self.filter.level.store(level.min(4), Ordering::Relaxed);
    }

    /// Show or hide raw listing lines.
    pub fn set_raw_listing(&self, on: bool) {
        self.filter.raw_listing.store(on, Ordering::Relaxed);
    }

    /// Report progress. Only the latest value per transfer is kept until the UI
    /// takes it, so this never grows memory with the number of calls.
    pub fn progress(&self, progress: TransferProgress) {
        if let Ok(mut latest) = self.progress.latest.lock() {
            latest.insert(progress.id, progress);
        }
        self.progress.notify.notify_one();
    }

    /// Ask the user and wait for the answer.
    ///
    /// Fails with [`Error::Cancelled`] when `cancel` fires, when the UI drops
    /// the request without answering, or when the UI has gone away.
    pub async fn ask(
        &self,
        session: Option<SessionId>,
        kind: PromptKind,
        cancel: &CancellationToken,
    ) -> Result<PromptResponse> {
        let (reply, answer) = oneshot::channel();
        let request = PromptRequest {
            id: PromptId::next(),
            session,
            kind,
            reply,
        };
        if !self.send(CoreEvent::Prompt(request)) {
            return Err(Error::Cancelled);
        }
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(Error::Cancelled),
            answer = answer => answer.map_err(|_| Error::Cancelled),
        }
    }
}

impl EventReceiver {
    /// The next event, waiting if there is none. `None` once every sender is gone
    /// and everything has been delivered.
    pub async fn recv(&mut self) -> Option<CoreEvent> {
        loop {
            if let Some(event) = self.try_recv() {
                return Some(event);
            }
            tokio::select! {
                event = self.rx.recv() => match event {
                    Some(event) => return Some(event),
                    None => return self.take_progress(),
                },
                () = self.progress.notify.notified() => {}
            }
        }
    }

    /// The next event if one is ready, without waiting. Queued events come
    /// before coalesced progress.
    pub fn try_recv(&mut self) -> Option<CoreEvent> {
        if let Some(p) = self.pending.pop() {
            return Some(CoreEvent::TransferProgress(p));
        }
        if let Ok(event) = self.rx.try_recv() {
            return Some(event);
        }
        self.take_progress()
    }

    fn take_progress(&mut self) -> Option<CoreEvent> {
        if self.pending.is_empty()
            && let Ok(mut latest) = self.progress.latest.lock()
        {
            self.pending = latest.drain().map(|(_, p)| p).collect();
            self.pending.sort_by_key(|p| std::cmp::Reverse(p.id));
        }
        self.pending.pop().map(CoreEvent::TransferProgress)
    }

    /// How many transfers have undelivered progress (for tests and metrics).
    pub fn pending_progress(&self) -> usize {
        self.pending.len() + self.progress.latest.lock().map_or(0, |l| l.len())
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use secrecy::ExposeSecret;

    use super::*;

    fn log_texts(rx: &mut EventReceiver) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(event) = rx.try_recv() {
            if let CoreEvent::Log(m) = event {
                out.push(m.text);
            }
        }
        out
    }

    #[test]
    fn level_filter_drops_debug_above_level() {
        let (tx, mut rx) = channel(2);
        let s = SessionId::next();
        tx.log(s, LogKind::Status, "status");
        tx.log(s, LogKind::Debug(1), "warning");
        tx.log(s, LogKind::Debug(2), "info");
        tx.log(s, LogKind::Debug(3), "verbose");
        tx.log(s, LogKind::Debug(4), "debug");
        tx.log(s, LogKind::ListingRaw, "raw");
        assert_eq!(log_texts(&mut rx), ["status", "warning", "info"]);

        tx.set_log_level(0);
        tx.set_raw_listing(true);
        tx.log(s, LogKind::Debug(1), "warning");
        tx.log(s, LogKind::ListingRaw, "raw");
        assert_eq!(log_texts(&mut rx), ["raw"]);
        assert!(!tx.enabled(LogKind::Debug(1)));

        // Level 3+ shows raw listings without the setting.
        tx.set_raw_listing(false);
        assert!(!tx.enabled(LogKind::ListingRaw));
        tx.set_log_level(3);
        assert!(tx.enabled(LogKind::ListingRaw));
    }

    #[test]
    fn commands_are_masked() {
        let (tx, mut rx) = channel(2);
        tx.log_command(SessionId::next(), "PASS CANARY-PW-x");
        assert_eq!(log_texts(&mut rx), ["PASS ****"]);
    }

    #[test]
    fn progress_is_coalesced_and_bounded() {
        let (tx, mut rx) = channel(2);
        for i in 0..10_000u64 {
            tx.progress(TransferProgress {
                id: TransferId(i % 3),
                bytes_done: i,
                total: Some(10_000),
                speed_bps: 0,
                eta: None,
            });
        }
        assert_eq!(rx.pending_progress(), 3);
        let mut latest = Vec::new();
        while let Some(CoreEvent::TransferProgress(p)) = rx.try_recv() {
            latest.push((p.id.0, p.bytes_done));
        }
        assert_eq!(latest, [(0, 9_999), (1, 9_997), (2, 9_998)]);
        assert_eq!(rx.pending_progress(), 0);
    }

    #[tokio::test]
    async fn recv_wakes_up_for_progress() {
        let (tx, mut rx) = channel(2);
        let task = tokio::spawn(async move { rx.recv().await });
        tokio::task::yield_now().await;
        tx.progress(TransferProgress {
            id: TransferId(7),
            bytes_done: 1,
            total: None,
            speed_bps: 0,
            eta: None,
        });
        let event = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(event, Some(CoreEvent::TransferProgress(p)) if p.id == TransferId(7)));
    }

    #[tokio::test]
    async fn recv_ends_after_senders_are_gone() {
        let (tx, mut rx) = channel(2);
        tx.log(SessionId::next(), LogKind::Status, "last words");
        drop(tx);
        assert!(matches!(rx.recv().await, Some(CoreEvent::Log(_))));
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn prompt_round_trip() {
        let (tx, mut rx) = channel(2);
        let ui = tokio::spawn(async move {
            match rx.recv().await {
                Some(CoreEvent::Prompt(req)) => {
                    assert!(matches!(req.kind, PromptKind::Password { .. }));
                    req.reply
                        .send(PromptResponse::Secret("CANARY-PW-answer".into()))
                        .unwrap();
                }
                other => panic!("unexpected {other:?}"),
            }
        });
        let answer = tx
            .ask(
                None,
                PromptKind::Password {
                    for_: "bob@h".into(),
                },
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        ui.await.unwrap();
        match answer {
            PromptResponse::Secret(s) => assert_eq!(s.expose_secret(), "CANARY-PW-answer"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn dropped_prompt_is_cancelled() {
        let (tx, mut rx) = channel(2);
        let ui = tokio::spawn(async move {
            let event = rx.recv().await;
            drop(event);
            rx
        });
        let result = tx
            .ask(
                None,
                PromptKind::Message("hi".into()),
                &CancellationToken::new(),
            )
            .await;
        assert!(matches!(result, Err(Error::Cancelled)));
        drop(ui.await.unwrap());
    }

    #[tokio::test]
    async fn token_cancels_a_waiting_prompt() {
        let (tx, mut rx) = channel(2);
        let cancel = CancellationToken::new();
        let waiter = {
            let tx = tx.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                tx.ask(None, PromptKind::Message("hi".into()), &cancel)
                    .await
            })
        };
        // The UI receives the prompt but never answers.
        let held = rx.recv().await;
        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(Error::Cancelled)));
        drop(held);
    }

    #[tokio::test]
    async fn prompt_without_ui_is_cancelled() {
        let (tx, rx) = channel(2);
        drop(rx);
        let result = tx
            .ask(
                None,
                PromptKind::Message("hi".into()),
                &CancellationToken::new(),
            )
            .await;
        assert!(matches!(result, Err(Error::Cancelled)));
    }

    #[test]
    fn secrets_are_redacted_in_debug() {
        let r = PromptResponse::Secret("CANARY-PW-dbg".into());
        assert!(!format!("{r:?}").contains("CANARY"));
        let r = PromptResponse::Answers(vec!["CANARY-PW-a".into()]);
        assert!(!format!("{r:?}").contains("CANARY"));
    }

    fn assert_send_static<T: Send + 'static>() {}

    #[test]
    fn types_are_send_and_static() {
        assert_send_static::<CoreEvent>();
        assert_send_static::<EventSender>();
        assert_send_static::<EventReceiver>();
        assert_send_static::<PromptRequest>();
    }
}
