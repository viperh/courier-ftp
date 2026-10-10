//! [`TransferEngine`]: the scheduler task, its [`Command`]s and the
//! per-server connection pool.

use std::{collections::HashMap, sync::Arc, time::Duration};

use time::OffsetDateTime;
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use super::{
    CLEANUP_TIMEOUT, IDLE_TIMEOUT, MAX_RETRY_DELAY,
    hooks::{
        DirExpander, ExistsPolicy, LocalBackendFactory, OverwriteAll, RateLimiter, RealLocal,
        ServerResolver, Unlimited,
    },
    worker::{self, Failure, Job, Outcome, Shared, Side, WorkerResult},
};
use crate::{
    Error,
    backend::{BackendFactory, SessionHandle},
    events::{CoreEvent, EventSender, LogKind, QueueStats, SessionId, TransferId, TransferState},
    model::Direction,
    queue::{FailOutcome, ItemState, QueueItem, QueueList, ServerKey, SharedQueue, lock_queue},
    settings::Settings,
};

/// What the engine can be told (through an [`EngineHandle`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Command {
    /// Start processing the queue ([`Queue::set_processing`](crate::queue::Queue::set_processing)`(true)`).
    Start,
    /// Stop processing: start nothing new and cancel the active transfers;
    /// they go back to queued (a later start resumes them where possible).
    Stop,
    /// Hold every active transfer where it is (connections stay open) and
    /// start nothing new.
    PauseAll,
    /// Undo [`Command::PauseAll`].
    ResumeAll,
    /// Cancel one active transfer. If it is still active in the queue it is
    /// paused there; if the UI already removed or paused it, only the
    /// worker stops. Send it for the ids `Queue::remove`/`Queue::pause`
    /// return.
    Cancel(TransferId),
    /// New settings (limits, retries, timeouts…); also passed to the
    /// [`RateLimiter`].
    SettingsChanged(Box<Settings>),
    /// The queue changed (items added, resumed, requeued, reordered): look
    /// for work now instead of at the next poll (≤ 1 s).
    Wake,
    /// Cancel everything, wait for every task, close the connections and
    /// end [`TransferEngine::run`].
    Shutdown,
}

/// A snapshot of the engine, published after every change
/// ([`EngineHandle::status`], [`EngineHandle::watch_status`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineStatus {
    /// The queue is being processed.
    pub processing: bool,
    /// [`Command::PauseAll`] is in effect.
    pub paused: bool,
    /// Transfers holding a slot (including cancelled ones still winding
    /// down).
    pub active: usize,
    /// Tasks the engine owns (workers and connection closers). Zero after
    /// [`Command::Stop`] once the workers are gone.
    pub tasks: usize,
    /// Transfer connections open (busy and idle).
    pub connections: usize,
}

/// Controls a running [`TransferEngine`]. Cheap to clone.
#[derive(Debug, Clone)]
pub struct EngineHandle {
    tx: mpsc::UnboundedSender<Command>,
    status: watch::Receiver<EngineStatus>,
}

impl EngineHandle {
    /// Send a command. `false` when the engine has ended.
    pub fn send(&self, cmd: Command) -> bool {
        self.tx.send(cmd).is_ok()
    }

    /// [`Command::Start`].
    pub fn start(&self) -> bool {
        self.send(Command::Start)
    }

    /// [`Command::Stop`].
    pub fn stop(&self) -> bool {
        self.send(Command::Stop)
    }

    /// [`Command::PauseAll`].
    pub fn pause_all(&self) -> bool {
        self.send(Command::PauseAll)
    }

    /// [`Command::ResumeAll`].
    pub fn resume_all(&self) -> bool {
        self.send(Command::ResumeAll)
    }

    /// [`Command::Cancel`].
    pub fn cancel(&self, id: TransferId) -> bool {
        self.send(Command::Cancel(id))
    }

    /// [`Command::SettingsChanged`].
    pub fn settings_changed(&self, settings: Settings) -> bool {
        self.send(Command::SettingsChanged(Box::new(settings)))
    }

    /// [`Command::Wake`].
    pub fn wake(&self) -> bool {
        self.send(Command::Wake)
    }

    /// [`Command::Shutdown`].
    pub fn shutdown(&self) -> bool {
        self.send(Command::Shutdown)
    }

    /// The latest status.
    pub fn status(&self) -> EngineStatus {
        self.status.borrow().clone()
    }

    /// A receiver for status changes (status bar, tests).
    pub fn watch_status(&self) -> watch::Receiver<EngineStatus> {
        self.status.clone()
    }
}

type QueueChanged = Arc<dyn Fn() + Send + Sync>;

/// Builds a [`TransferEngine`]; see [`TransferEngine::builder`].
pub struct EngineBuilder {
    queue: SharedQueue,
    factory: Arc<dyn BackendFactory>,
    resolver: Arc<dyn ServerResolver>,
    events: EventSender,
    settings: Settings,
    exists: Arc<dyn ExistsPolicy>,
    limiter: Arc<dyn RateLimiter>,
    expander: Option<Arc<dyn DirExpander>>,
    local: Arc<dyn LocalBackendFactory>,
    on_changed: Option<QueueChanged>,
}

impl std::fmt::Debug for EngineBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineBuilder").finish_non_exhaustive()
    }
}

impl EngineBuilder {
    /// The settings to start with (default: [`Settings::default`]).
    #[must_use]
    pub fn settings(mut self, settings: Settings) -> Self {
        self.settings = settings;
        self
    }

    /// The file-exists policy (default: [`OverwriteAll`]; T42 provides the
    /// real one).
    #[must_use]
    pub fn exists_policy(mut self, policy: Arc<dyn ExistsPolicy>) -> Self {
        self.exists = policy;
        self
    }

    /// The speed limiter (default: [`Unlimited`]; T44 provides the token
    /// bucket).
    #[must_use]
    pub fn rate_limiter(mut self, limiter: Arc<dyn RateLimiter>) -> Self {
        self.limiter = limiter;
        self
    }

    /// The directory-placeholder expander (T43). Without one, placeholders
    /// are never scheduled.
    #[must_use]
    pub fn dir_expander(mut self, expander: Arc<dyn DirExpander>) -> Self {
        self.expander = Some(expander);
        self
    }

    /// The local side (default: [`RealLocal`], the real filesystem).
    #[must_use]
    pub fn local_backends(mut self, local: Arc<dyn LocalBackendFactory>) -> Self {
        self.local = local;
        self
    }

    /// Called after every change that alters the persisted queue (finish,
    /// fail, requeue, skip, expand): pass `move || persister.changed()`
    /// ([`QueuePersister::changed`](crate::queue::QueuePersister::changed)).
    #[must_use]
    pub fn on_queue_changed(mut self, f: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_changed = Some(Arc::new(f));
        self
    }

    /// The engine (run it with [`TransferEngine::run`] or
    /// [`TransferEngine::spawn`]) and its handle.
    pub fn build(self) -> (TransferEngine, EngineHandle) {
        let (tx, rx) = mpsc::unbounded_channel();
        let processing = lock_queue(&self.queue).is_processing();
        let (status_tx, status) = watch::channel(EngineStatus {
            processing,
            ..EngineStatus::default()
        });
        let (paused_tx, _) = watch::channel(false);
        self.limiter.settings_changed(&self.settings.transfers);
        let shared = Arc::new(Shared {
            queue: self.queue,
            factory: self.factory,
            resolver: self.resolver,
            events: self.events,
            exists: self.exists,
            limiter: self.limiter,
            expander: self.expander,
            local: self.local,
        });
        let engine = TransferEngine {
            shared,
            settings: Arc::new(self.settings),
            on_changed: self.on_changed,
            rx,
            status_tx,
            paused_tx,
            paused: false,
            active: HashMap::new(),
            tasks: JoinSet::new(),
            task_ids: HashMap::new(),
            pools: HashMap::new(),
            retry: HashMap::new(),
            run: None,
            log_session: SessionId::next(),
        };
        (engine, EngineHandle { tx, status })
    }
}

/// An active transfer as the scheduler sees it.
#[derive(Debug)]
struct Active {
    server: ServerKey,
    direction: Direction,
    file_name: String,
    cancel: CancellationToken,
    /// Cancelled by the engine; the result only returns the session.
    cancelled: bool,
}

/// Transfer connections to one server.
#[derive(Default)]
struct ServerPool {
    /// Sessions in use by workers (or being opened).
    busy: u32,
    /// Connected sessions waiting for the next transfer, with when they
    /// became idle.
    idle: Vec<(SessionHandle, Instant)>,
    /// Lowered after "too many connections" (for the engine's lifetime).
    reduced_limit: Option<u32>,
}

/// When and from where a failed item may run again.
#[derive(Debug, Clone, Copy)]
struct Retry {
    not_before: Instant,
    /// Bytes of the target written by an earlier attempt.
    offset: Option<u64>,
}

/// Totals of the current run, for [`CoreEvent::QueueFinished`].
#[derive(Debug, Clone)]
struct RunStats {
    started: Instant,
    stats: QueueStats,
}

enum Task {
    Worker(Box<WorkerResult>),
    Closed,
}

/// The transfer engine (see the [module docs](super)).
pub struct TransferEngine {
    shared: Arc<Shared>,
    settings: Arc<Settings>,
    on_changed: Option<QueueChanged>,
    rx: mpsc::UnboundedReceiver<Command>,
    status_tx: watch::Sender<EngineStatus>,
    paused_tx: watch::Sender<bool>,
    paused: bool,
    active: HashMap<TransferId, Active>,
    tasks: JoinSet<Task>,
    task_ids: HashMap<tokio::task::Id, TransferId>,
    pools: HashMap<ServerKey, ServerPool>,
    retry: HashMap<TransferId, Retry>,
    run: Option<RunStats>,
    log_session: SessionId,
}

impl std::fmt::Debug for TransferEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferEngine")
            .field("paused", &self.paused)
            .field("active", &self.active.len())
            .finish_non_exhaustive()
    }
}

/// Fallback poll interval while processing (in case a [`Command::Wake`]
/// was not sent).
const POLL: Duration = Duration::from_secs(1);

impl TransferEngine {
    /// A builder with the required parts: the shared queue, the backend
    /// factory for transfer connections, the resolver turning queue servers
    /// into connect info, and the event bus.
    pub fn builder(
        queue: SharedQueue,
        factory: Arc<dyn BackendFactory>,
        resolver: Arc<dyn ServerResolver>,
        events: EventSender,
    ) -> EngineBuilder {
        EngineBuilder {
            queue,
            factory,
            resolver,
            events,
            settings: Settings::default(),
            exists: Arc::new(OverwriteAll),
            limiter: Arc::new(Unlimited),
            expander: None,
            local: Arc::new(RealLocal),
            on_changed: None,
        }
    }

    /// Run on a new tokio task.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(self.run())
    }

    /// Run until [`Command::Shutdown`] or until every [`EngineHandle`] is
    /// dropped. Returns after all tasks ended and connections closed.
    pub async fn run(mut self) {
        loop {
            self.schedule();
            self.check_finished();
            self.publish_status();
            let wake_at = self.next_wakeup();
            tokio::select! {
                cmd = self.rx.recv() => match cmd {
                    None | Some(Command::Shutdown) => break,
                    Some(cmd) => self.handle(cmd),
                },
                Some(joined) = self.tasks.join_next_with_id(), if !self.tasks.is_empty() => {
                    self.on_joined(joined);
                }
                () = tokio::time::sleep_until(wake_at) => {}
            }
            self.prune_idle(Instant::now());
        }
        self.shutdown().await;
    }

    // ------------------------------------------------------------ commands

    fn handle(&mut self, cmd: Command) {
        match cmd {
            Command::Start => {
                lock_queue(&self.shared.queue).set_processing(true);
            }
            Command::Stop => {
                lock_queue(&self.shared.queue).set_processing(false);
                self.cancel_all();
                self.run = None;
            }
            Command::PauseAll => self.set_paused(true),
            Command::ResumeAll => self.set_paused(false),
            Command::Cancel(id) => self.cancel_one(id),
            Command::SettingsChanged(settings) => {
                self.shared.limiter.settings_changed(&settings.transfers);
                self.settings = Arc::new(*settings);
            }
            Command::Wake | Command::Shutdown => {}
        }
    }

    fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
        self.paused_tx.send_replace(paused);
    }

    /// Cancels every active transfer and puts it back to queued.
    fn cancel_all(&mut self) {
        let mut q = lock_queue(&self.shared.queue);
        for (id, a) in &mut self.active {
            if a.cancelled {
                continue;
            }
            a.cancelled = true;
            a.cancel.cancel();
            if q.stop(*id).is_ok() {
                self.shared.events.send(CoreEvent::TransferStateChanged {
                    id: *id,
                    state: TransferState::Queued,
                });
            }
        }
    }

    fn cancel_one(&mut self, id: TransferId) {
        let Some(a) = self.active.get_mut(&id) else {
            return;
        };
        if a.cancelled {
            return;
        }
        a.cancelled = true;
        a.cancel.cancel();
        let paused = {
            let mut q = lock_queue(&self.shared.queue);
            q.get(id).is_some_and(|i| i.state.is_active()) && !q.pause(&[id]).is_empty()
        };
        if paused {
            self.shared.events.send(CoreEvent::TransferStateChanged {
                id,
                state: TransferState::Paused,
            });
            self.changed();
        }
    }

    // ------------------------------------------------------------ scheduling

    fn max_concurrent(&self) -> usize {
        self.settings.transfers.max_concurrent.max(1) as usize
    }

    /// The connection limit for `item`'s server.
    fn server_limit(&self, item: &QueueItem, key: &ServerKey) -> u32 {
        let mut limit = self.settings.transfers.max_concurrent.max(1);
        if let Some(site) = self.shared.resolver.connection_limit(&item.server) {
            limit = limit.min(site.max(1));
        }
        if let Some(reduced) = self.pools.get(key).and_then(|p| p.reduced_limit) {
            limit = limit.min(reduced.max(1));
        }
        limit
    }

    fn eligible(&self, item: &QueueItem, now: Instant) -> bool {
        if item.is_dir_placeholder && self.shared.expander.is_none() {
            return false;
        }
        if self.retry.get(&item.id).is_some_and(|r| r.not_before > now) {
            return false;
        }
        let t = &self.settings.transfers;
        let dir_limit = match item.direction {
            Direction::Download => t.max_downloads,
            Direction::Upload => t.max_uploads,
        };
        if dir_limit > 0 {
            let running = self
                .active
                .values()
                .filter(|a| a.direction == item.direction)
                .count();
            if running >= dir_limit as usize {
                return false;
            }
        }
        let key = item.server.key();
        let busy = self.pools.get(&key).map_or(0, |p| p.busy);
        busy < self.server_limit(item, &key)
    }

    /// Starts as many eligible items as the limits allow.
    fn schedule(&mut self) {
        if self.paused {
            return;
        }
        loop {
            if self.active.len() >= self.max_concurrent() {
                return;
            }
            let now = Instant::now();
            let item = {
                let mut q = lock_queue(&self.shared.queue);
                if !q.is_processing() {
                    return;
                }
                let Some(id) = q.next_runnable(|item| self.eligible(item, now)) else {
                    return;
                };
                if q.start(id).is_err() {
                    return;
                }
                match q.get(id) {
                    Some(item) => item.clone(),
                    None => return,
                }
            };
            self.spawn_worker(item, now);
        }
    }

    fn spawn_worker(&mut self, item: QueueItem, now: Instant) {
        let id = item.id;
        let key = item.server.key();
        let pool = self.pools.entry(key.clone()).or_default();
        pool.busy += 1;
        // Reuse the most recently idle session.
        let session = pool.idle.pop().map(|(s, _)| s);
        let cancel = CancellationToken::new();
        let resume_from = self.retry.get(&id).and_then(|r| r.offset);
        self.active.insert(
            id,
            Active {
                server: key,
                direction: item.direction,
                file_name: item.remote.file_name().unwrap_or_default().to_owned(),
                cancel: cancel.clone(),
                cancelled: false,
            },
        );
        self.run.get_or_insert_with(|| RunStats {
            started: now,
            stats: QueueStats::default(),
        });
        self.shared.events.send(CoreEvent::TransferStateChanged {
            id,
            state: TransferState::Active,
        });
        let job = Job {
            item,
            session,
            resume_from,
            cancel,
            paused: self.paused_tx.subscribe(),
            settings: Arc::clone(&self.settings),
            shared: Arc::clone(&self.shared),
        };
        let handle = self
            .tasks
            .spawn(async move { Task::Worker(Box::new(worker::run(job).await)) });
        self.task_ids.insert(handle.id(), id);
    }

    // ------------------------------------------------------------ results

    fn on_joined(&mut self, joined: Result<(tokio::task::Id, Task), tokio::task::JoinError>) {
        match joined {
            Ok((task, Task::Worker(result))) => {
                self.task_ids.remove(&task);
                self.on_result(*result);
            }
            Ok((task, Task::Closed)) => {
                self.task_ids.remove(&task);
            }
            Err(err) => {
                let Some(id) = self.task_ids.remove(&err.id()) else {
                    return;
                };
                tracing::warn!("transfer task ended abnormally: {err}");
                self.on_result(WorkerResult {
                    id,
                    session: None,
                    outcome: Outcome::Failed(Failure {
                        error: Error::Io(std::io::Error::other("transfer task failed")),
                        side: Side::Local,
                        written: None,
                    }),
                });
            }
        }
    }

    fn on_result(&mut self, result: WorkerResult) {
        let id = result.id;
        let Some(active) = self.active.remove(&id) else {
            return;
        };
        let now = Instant::now();
        let limit = self.settings.transfers.max_concurrent.max(1);
        let pool = self.pools.entry(active.server.clone()).or_default();
        pool.busy = pool.busy.saturating_sub(1);
        if let Some(session) = result.session {
            pool.idle.push((session, now));
        }
        // Don't keep more connections than the (possibly lowered) limit.
        let keep = pool.reduced_limit.unwrap_or(limit).min(limit);
        let mut surplus = Vec::new();
        while pool.busy as usize + pool.idle.len() > keep as usize && !pool.idle.is_empty() {
            surplus.push(pool.idle.remove(0).0);
        }
        for s in surplus {
            self.close_later(s);
        }
        if active.cancelled {
            if let Outcome::Failed(f) = &result.outcome
                && let Some(w) = f.written.filter(|w| *w > 0)
            {
                self.retry.insert(
                    id,
                    Retry {
                        not_before: now,
                        offset: Some(w),
                    },
                );
            }
            return;
        }
        match result.outcome {
            Outcome::Done {
                bytes,
                transferred,
                duration,
            } => {
                self.retry.remove(&id);
                let done = lock_queue(&self.shared.queue)
                    .finish(id, bytes, duration, OffsetDateTime::now_utc())
                    .is_ok();
                if done {
                    if let Some(run) = &mut self.run {
                        run.stats.files_ok += 1;
                        run.stats.bytes += transferred;
                    }
                    self.state(id, TransferState::Done);
                    self.changed();
                }
            }
            Outcome::Skipped => {
                self.retry.remove(&id);
                lock_queue(&self.shared.queue).remove(&[id]);
                if let Some(run) = &mut self.run {
                    run.stats.files_skipped += 1;
                }
                self.state(id, TransferState::Skipped);
                self.changed();
            }
            Outcome::Expanded(children) => {
                self.retry.remove(&id);
                let _ = lock_queue(&self.shared.queue).expand_placeholder(
                    id,
                    children,
                    OffsetDateTime::now_utc(),
                );
                self.changed();
            }
            Outcome::TooManyConnections(error) => {
                let others = self
                    .pools
                    .get(&active.server)
                    .map_or(0, |p| p.busy as usize + p.idle.len());
                if others == 0 {
                    // Not even one connection: a real failure.
                    self.on_failure(
                        id,
                        &active,
                        Failure {
                            error,
                            side: Side::Remote,
                            written: None,
                        },
                    );
                    return;
                }
                let new_limit = u32::try_from(others).unwrap_or(u32::MAX).max(1);
                if let Some(pool) = self.pools.get_mut(&active.server) {
                    pool.reduced_limit = Some(new_limit);
                }
                self.shared.events.log(
                    self.log_session,
                    LogKind::Status,
                    format!(
                        "The server refused another connection ({error}); \
                         using at most {new_limit} for this session"
                    ),
                );
                if lock_queue(&self.shared.queue).stop(id).is_ok() {
                    self.state(id, TransferState::Queued);
                }
            }
            Outcome::Failed(failure) => self.on_failure(id, &active, failure),
        }
    }

    fn retry_delay(&self, attempts: u8) -> Duration {
        let base = Duration::from_secs(self.settings.connection.retry_delay_secs);
        let factor = 1u32 << u32::from(attempts.saturating_sub(1)).min(16);
        base.saturating_mul(factor).min(base.max(MAX_RETRY_DELAY))
    }

    fn on_failure(&mut self, id: TransferId, active: &Active, failure: Failure) {
        let message = failure.message();
        let max_attempts = if failure.is_transient() {
            u8::try_from(self.settings.connection.retries.saturating_add(1)).unwrap_or(u8::MAX)
        } else {
            0
        };
        let (outcome, attempts) = {
            let mut q = lock_queue(&self.shared.queue);
            let outcome = q.fail(id, message.clone(), max_attempts);
            (outcome, q.get(id).map_or(0, |i| i.attempts))
        };
        match outcome {
            Ok(FailOutcome::Requeued) => {
                let delay = self.retry_delay(attempts);
                let offset = failure
                    .written
                    .filter(|w| *w > 0)
                    .or_else(|| self.retry.get(&id).and_then(|r| r.offset));
                self.retry.insert(
                    id,
                    Retry {
                        not_before: Instant::now() + delay,
                        offset,
                    },
                );
                self.shared.events.log(
                    self.log_session,
                    LogKind::Status,
                    format!(
                        "{}: {message}; retrying in {} s",
                        active.file_name,
                        delay.as_secs()
                    ),
                );
                self.state(id, TransferState::Queued);
            }
            Ok(FailOutcome::Failed) => {
                self.retry.remove(&id);
                if let Some(run) = &mut self.run {
                    run.stats.files_failed += 1;
                }
                self.shared.events.log(
                    self.log_session,
                    LogKind::Error,
                    format!("{}: {message}", active.file_name),
                );
                self.state(id, TransferState::Failed(message));
            }
            Err(_) => {}
        }
        if failure.is_disk_full() && !self.paused {
            self.set_paused(true);
            self.shared.events.log(
                self.log_session,
                LogKind::Error,
                "The local disk is full; the queue is paused",
            );
        }
        self.changed();
    }

    fn state(&self, id: TransferId, state: TransferState) {
        self.shared
            .events
            .send(CoreEvent::TransferStateChanged { id, state });
    }

    fn changed(&self) {
        if let Some(f) = &self.on_changed {
            f();
        }
    }

    /// Emits `QueueFinished` when a run has nothing left to do.
    fn check_finished(&mut self) {
        if self.run.is_none() || !self.active.is_empty() {
            return;
        }
        let has_expander = self.shared.expander.is_some();
        {
            let mut q = lock_queue(&self.shared.queue);
            if !q.is_processing() {
                return;
            }
            let pending = q
                .items(QueueList::Queued)
                .any(|i| i.state == ItemState::Queued && (!i.is_dir_placeholder || has_expander));
            if pending {
                return;
            }
            q.set_processing(false);
            // Keep resume offsets of items still waiting (paused ones).
            self.retry
                .retain(|id, _| q.get(*id).is_some_and(|i| i.state == ItemState::Paused));
        }
        if let Some(run) = self.run.take() {
            let mut stats = run.stats;
            stats.elapsed = run.started.elapsed();
            self.shared.events.send(CoreEvent::QueueFinished { stats });
        }
    }

    // ------------------------------------------------------------ housekeeping

    fn close_later(&mut self, session: SessionHandle) {
        self.tasks.spawn(async move {
            let _ = tokio::time::timeout(CLEANUP_TIMEOUT, session.disconnect()).await;
            Task::Closed
        });
    }

    /// Closes sessions idle for longer than [`IDLE_TIMEOUT`].
    fn prune_idle(&mut self, now: Instant) {
        let mut expired = Vec::new();
        for pool in self.pools.values_mut() {
            let mut i = 0;
            while i < pool.idle.len() {
                if now.saturating_duration_since(pool.idle[i].1) >= IDLE_TIMEOUT {
                    expired.push(pool.idle.remove(i).0);
                } else {
                    i += 1;
                }
            }
        }
        for s in expired {
            self.close_later(s);
        }
        self.pools
            .retain(|_, p| p.busy > 0 || !p.idle.is_empty() || p.reduced_limit.is_some());
    }

    fn next_wakeup(&self) -> Instant {
        let now = Instant::now();
        let mut at = now + Duration::from_secs(3600);
        let processing = lock_queue(&self.shared.queue).is_processing();
        if processing && !self.paused {
            at = at.min(now + POLL);
            for r in self.retry.values() {
                if r.not_before > now {
                    at = at.min(r.not_before);
                }
            }
        }
        for pool in self.pools.values() {
            for (_, since) in &pool.idle {
                at = at.min(*since + IDLE_TIMEOUT);
            }
        }
        at
    }

    fn publish_status(&self) {
        let status = EngineStatus {
            processing: lock_queue(&self.shared.queue).is_processing(),
            paused: self.paused,
            active: self.active.len(),
            tasks: self.tasks.len(),
            connections: self
                .pools
                .values()
                .map(|p| p.busy as usize + p.idle.len())
                .sum(),
        };
        self.status_tx.send_if_modified(|s| {
            if *s == status {
                false
            } else {
                *s = status;
                true
            }
        });
    }

    async fn shutdown(&mut self) {
        self.cancel_all();
        while let Some(joined) = self.tasks.join_next_with_id().await {
            self.on_joined(joined);
        }
        let idle: Vec<SessionHandle> = self
            .pools
            .drain()
            .flat_map(|(_, p)| p.idle.into_iter().map(|(s, _)| s))
            .collect();
        for s in idle {
            let _ = tokio::time::timeout(CLEANUP_TIMEOUT, s.disconnect()).await;
        }
        self.publish_status();
    }
}
