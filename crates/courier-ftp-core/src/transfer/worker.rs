//! One active transfer: connect (or reuse a pooled session), stat, ask the
//! [`ExistsPolicy`], open the streams, copy, finish.
//!
//! The worker never changes the item's queue state except its progress; it
//! returns a [`WorkerResult`] and the engine applies it, so a cancelled
//! worker can't race the engine.

use std::{future::Future, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use super::{
    BUFFER_SIZE, CLEANUP_TIMEOUT,
    hooks::{
        DirExpander, ExistsContext, ExistsDecision, ExistsPolicy, LocalBackendFactory, RateLimiter,
        ServerResolver,
    },
    is_too_many_connections,
    progress::ProgressTracker,
};
use crate::{
    Error, Result,
    backend::{
        Backend, BackendFactory, ReadStream, SessionHandle, TransferOpts, TransferType, WriteMode,
        WriteStream,
    },
    events::{EventSender, SessionId, TransferId},
    local::local_to_remote,
    model::{Direction, Entry, EntryKind, RemotePath},
    queue::{NewItem, QueueItem, SharedQueue, lock_queue},
    settings::{Settings, TransferTypeChoice},
};

/// Everything the workers share with the engine.
pub(super) struct Shared {
    pub queue: SharedQueue,
    pub factory: Arc<dyn BackendFactory>,
    pub resolver: Arc<dyn ServerResolver>,
    pub events: EventSender,
    pub exists: Arc<dyn ExistsPolicy>,
    pub limiter: Arc<dyn RateLimiter>,
    pub expander: Option<Arc<dyn DirExpander>>,
    pub local: Arc<dyn LocalBackendFactory>,
}

/// What a worker is given.
pub(super) struct Job {
    pub item: QueueItem,
    /// A pooled session to reuse, or `None` to open a new one.
    pub session: Option<SessionHandle>,
    /// Resume at this offset (a retried transfer), when the target allows.
    pub resume_from: Option<u64>,
    pub cancel: CancellationToken,
    pub paused: watch::Receiver<bool>,
    pub settings: Arc<Settings>,
    pub shared: Arc<Shared>,
}

/// Which side of the transfer an error came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Side {
    Local,
    Remote,
}

/// A failed attempt.
#[derive(Debug)]
pub(super) struct Failure {
    pub error: Error,
    pub side: Side,
    /// Bytes of the target known to be written (resume offset for a retry).
    pub written: Option<u64>,
}

impl Failure {
    fn new(side: Side, error: Error) -> Self {
        Self {
            error,
            side,
            written: None,
        }
    }

    /// The local disk (or quota) is full.
    pub(super) fn is_disk_full(&self) -> bool {
        use std::io::ErrorKind;
        self.side == Side::Local
            && matches!(&self.error, Error::Io(e)
                if matches!(e.kind(), ErrorKind::StorageFull | ErrorKind::QuotaExceeded))
    }

    /// Worth retrying.
    pub(super) fn is_transient(&self) -> bool {
        !self.is_disk_full() && self.error.is_transient()
    }

    /// The message for the failed list.
    pub(super) fn message(&self) -> String {
        match self.side {
            Side::Remote => self.error.to_string(),
            Side::Local if self.is_disk_full() => {
                format!("local disk is full: {}", self.error)
            }
            Side::Local => format!("local file: {}", self.error),
        }
    }
}

/// How the attempt ended.
#[derive(Debug)]
pub(super) enum Outcome {
    /// Transferred: `bytes` is the file size reached, `transferred` what this
    /// attempt moved.
    Done {
        bytes: u64,
        transferred: u64,
        duration: Duration,
    },
    /// The exists policy said skip.
    Skipped,
    /// A directory placeholder was listed (T43).
    Expanded(Vec<NewItem>),
    /// The server refused the connection as one too many.
    TooManyConnections(Error),
    /// The attempt failed (including cancellation).
    Failed(Failure),
}

/// What the worker hands back.
pub(super) struct WorkerResult {
    pub id: TransferId,
    /// The session, when it can be reused.
    pub session: Option<SessionHandle>,
    pub outcome: Outcome,
}

/// Runs `fut` with the operation timeout, failing fast on cancellation.
async fn timed<T>(
    timeout: Duration,
    cancel: &CancellationToken,
    fut: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(Error::Cancelled),
        r = tokio::time::timeout(timeout, fut) => r.unwrap_or(Err(Error::Timeout)),
    }
}

/// Runs the job to its end.
pub(super) async fn run(mut job: Job) -> WorkerResult {
    let id = job.item.id;
    let session = match job.session.take() {
        Some(s) => s,
        None => match connect(&job).await {
            Ok(s) => s,
            Err(e) => {
                let outcome = if is_too_many_connections(&e) {
                    Outcome::TooManyConnections(e)
                } else {
                    Outcome::Failed(Failure::new(Side::Remote, e))
                };
                return WorkerResult {
                    id,
                    session: None,
                    outcome,
                };
            }
        },
    };
    let (outcome, reusable) = execute(&job, &session).await;
    let reusable = reusable && session.lock().await.is_connected();
    WorkerResult {
        id,
        session: if reusable { Some(session) } else { None },
        outcome,
    }
}

/// Opens a new transfer connection.
async fn connect(job: &Job) -> Result<SessionHandle> {
    let shared = &job.shared;
    let cancel = &job.cancel;
    let info = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(Error::Cancelled),
        r = shared.resolver.resolve(&job.item.server, cancel) => r?,
    };
    let session_id = SessionId::next();
    let backend = shared
        .factory
        .create(&info, session_id, shared.events.clone());
    let conn = &job.settings.connection;
    let keepalive = conn
        .keepalive
        .then(|| Duration::from_secs(conn.keepalive_interval_secs));
    let handle = SessionHandle::new(backend, keepalive);
    tracing::debug!(session = %session_id, "opening transfer connection");
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(Error::Cancelled),
        r = handle.connect(cancel.clone()) => r.map(|()| handle),
    }
}

/// The attempt on a connected session. Returns the outcome and whether the
/// session is still usable.
async fn execute(job: &Job, session: &SessionHandle) -> (Outcome, bool) {
    let mut local = job.shared.local.create();
    if let Err(e) = local.connect(job.cancel.clone()).await {
        return (Outcome::Failed(Failure::new(Side::Local, e)), true);
    }
    let local_path = match local_to_remote(job.item.local.as_path()) {
        Ok(p) => p,
        Err(e) => return (Outcome::Failed(Failure::new(Side::Local, e)), true),
    };
    let mut remote = session.lock().await;
    if !remote.is_connected()
        && let Err(e) = remote.connect(job.cancel.clone()).await
    {
        return (Outcome::Failed(Failure::new(Side::Remote, e)), false);
    }
    if job.item.is_dir_placeholder {
        return expand(job, &mut **remote, &mut *local).await;
    }
    let started = Instant::now();
    let (outcome, reusable) =
        transfer_file(job, &mut **remote, &mut *local, local_path, started).await;
    drop(remote);
    let _ = local.disconnect().await;
    (outcome, reusable)
}

async fn expand(job: &Job, remote: &mut dyn Backend, local: &mut dyn Backend) -> (Outcome, bool) {
    let Some(expander) = job.shared.expander.clone() else {
        let e = Error::InvalidInput("directory placeholders need a DirExpander".into());
        return (Outcome::Failed(Failure::new(Side::Remote, e)), true);
    };
    let cancel = &job.cancel;
    let result = tokio::select! {
        biased;
        () = cancel.cancelled() => Err(Error::Cancelled),
        r = expander.expand(&job.item, remote, local, cancel) => r,
    };
    match result {
        Ok(children) => (Outcome::Expanded(children), true),
        Err(e) => {
            let reusable = !e.is_transient();
            (Outcome::Failed(Failure::new(Side::Remote, e)), reusable)
        }
    }
}

/// `stat` that reconnects once when the (pooled) connection turns out to be
/// dead, like [`SessionHandle::run`].
async fn stat_reconnecting(
    backend: &mut dyn Backend,
    path: &RemotePath,
    side: Side,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Entry> {
    match timed(timeout, cancel, backend.stat(path)).await {
        Err(Error::Connection(reason)) if side == Side::Remote => {
            tracing::debug!("transfer connection lost ({reason}); reconnecting once");
            backend.connect(cancel.clone()).await?;
            timed(timeout, cancel, backend.stat(path)).await
        }
        other => other,
    }
}

fn transfer_type(job: &Job, path: &RemotePath) -> TransferType {
    let ascii = match job.item.transfer_type {
        TransferTypeChoice::Ascii => true,
        TransferTypeChoice::Binary => false,
        TransferTypeChoice::Auto => job
            .settings
            .file_types
            .is_ascii(path.file_name().unwrap_or_default()),
    };
    if ascii {
        TransferType::Ascii
    } else {
        TransferType::Binary
    }
}

#[allow(clippy::too_many_lines)]
async fn transfer_file(
    job: &Job,
    remote: &mut dyn Backend,
    local: &mut dyn Backend,
    local_path: RemotePath,
    started: Instant,
) -> (Outcome, bool) {
    let item = &job.item;
    let cancel = &job.cancel;
    let settings = &job.settings;
    let shared = &job.shared;
    let timeout = Duration::from_secs(settings.connection.timeout_secs.max(1));
    let direction = item.direction;
    let (src, dst, src_side, dst_side, src_path, mut dst_path): (
        &mut dyn Backend,
        &mut dyn Backend,
        _,
        _,
        _,
        _,
    ) = match direction {
        Direction::Download => (
            remote,
            local,
            Side::Remote,
            Side::Local,
            item.remote.clone(),
            local_path,
        ),
        Direction::Upload => (
            local,
            remote,
            Side::Local,
            Side::Remote,
            local_path,
            item.remote.clone(),
        ),
    };
    let fail = |side: Side, error: Error| {
        let reusable = !(side == Side::Remote && error.is_transient());
        (Outcome::Failed(Failure::new(side, error)), reusable)
    };

    // 1. Source and target.
    let source = match stat_reconnecting(src, &src_path, src_side, timeout, cancel).await {
        Ok(e) => e,
        Err(e) => return fail(src_side, e),
    };
    if matches!(source.kind, EntryKind::Dir) {
        return fail(
            src_side,
            Error::InvalidInput(format!("{src_path} is a directory")),
        );
    }
    let size = source.size;
    if size.is_some() && size != item.size {
        let _ = lock_queue(&shared.queue).set_size(item.id, size);
    }
    let target = match stat_reconnecting(dst, &dst_path, dst_side, timeout, cancel).await {
        Ok(e) => Some(e),
        Err(Error::NotFound(_)) => None,
        Err(e) => return fail(dst_side, e),
    };

    // 2. The exists check (T42 hook). A retried transfer resumes at the
    //    offset it reached without asking again.
    let transfer_type = transfer_type(job, &src_path);
    let (src_caps, dst_caps) = (src.capabilities(), dst.capabilities());
    let can_resume =
        transfer_type == TransferType::Binary && src_caps.resume_download && dst_caps.resume_upload;
    let decision = match (job.resume_from, &target) {
        (Some(offset), Some(t)) if can_resume && offset > 0 => ExistsDecision::Resume {
            offset: offset.min(t.size.unwrap_or(0)),
        },
        _ => {
            let ctx = ExistsContext {
                item,
                source: &source,
                target: target.as_ref(),
                target_caps: dst_caps,
                can_resume,
            };
            let decided = tokio::select! {
                biased;
                () = cancel.cancelled() => Err(Error::Cancelled),
                r = shared.exists.decide(ctx, cancel) => r,
            };
            match decided {
                Ok(d) => d,
                Err(e) => return fail(dst_side, e),
            }
        }
    };
    let (offset, mode) = match decision {
        ExistsDecision::Resume { offset } if can_resume && offset > 0 => {
            (offset, WriteMode::ResumeAt(offset))
        }
        ExistsDecision::Overwrite | ExistsDecision::Resume { .. } => (0, WriteMode::Truncate),
        ExistsDecision::Skip => return (Outcome::Skipped, true),
        ExistsDecision::Rename { name } => {
            let renamed = dst_path
                .parent()
                .ok_or_else(|| Error::InvalidInput(format!("{dst_path} has no parent")))
                .and_then(|p| p.join(&name));
            match renamed {
                Ok(p) => dst_path = p,
                Err(e) => return fail(dst_side, e),
            }
            (0, WriteMode::Create)
        }
    };

    // 3. Streams.
    let opts = TransferOpts {
        transfer_type,
        preallocate_hint: if settings.transfers.preallocate {
            size
        } else {
            None
        },
    };
    let mut reader = match timed(timeout, cancel, src.open_read(&src_path, offset, &opts)).await {
        Ok(r) => r,
        Err(e) => return fail(src_side, e),
    };
    let mut writer = match timed(timeout, cancel, dst.open_write(&dst_path, mode, &opts)).await {
        Ok(w) => w,
        Err(e) => {
            drop(reader);
            let _ = tokio::time::timeout(CLEANUP_TIMEOUT, src.finish_transfer()).await;
            return fail(dst_side, e);
        }
    };

    // 4. Copy.
    let mut tracker = ProgressTracker::new(item.id, offset, size, Instant::now());
    if let Some(p) = tracker.advance(0, Instant::now()) {
        shared.events.progress(p);
    }
    let copied = copy_loop(job, &mut reader, &mut writer, &mut tracker, timeout).await;
    let written = tracker.done();

    if let Err((error, side)) = copied {
        // Best effort, bounded: flush what was written (the resume offset),
        // then let both backends end the transfer (FTP sends ABOR for a
        // stream dropped early, SFTP closes the handle).
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let _ = tokio::time::timeout_at(deadline, writer.flush()).await;
        drop(reader);
        drop(writer);
        let src_ok = matches!(
            tokio::time::timeout_at(deadline, src.finish_transfer()).await,
            Ok(Ok(()))
        );
        let dst_ok = matches!(
            tokio::time::timeout_at(deadline, dst.finish_transfer()).await,
            Ok(Ok(()))
        );
        let remote_ok = match direction {
            Direction::Download => src_ok,
            Direction::Upload => dst_ok,
        };
        let reusable = remote_ok && !(side == Side::Remote && error.is_transient());
        let failure = Failure {
            error,
            side,
            written: Some(written),
        };
        return (Outcome::Failed(failure), reusable);
    }
    drop(reader);
    drop(writer);

    // 5. Finish.
    for (backend, side) in [(&mut *src, src_side), (&mut *dst, dst_side)] {
        if let Err(error) = timed(timeout, cancel, backend.finish_transfer()).await {
            let reusable = !(side == Side::Remote && error.is_transient());
            let failure = Failure {
                error,
                side,
                written: Some(written),
            };
            return (Outcome::Failed(failure), reusable);
        }
    }
    if settings.transfers.preserve_timestamps
        && dst_caps.set_mtime
        && let Some(modified) = source.modified
        && let Err(e) = timed(timeout, cancel, dst.set_mtime(&dst_path, modified.time)).await
    {
        tracing::debug!("could not preserve the modification time: {e}");
    }
    shared.events.progress(tracker.report());
    (
        Outcome::Done {
            bytes: written,
            transferred: written.saturating_sub(offset),
            duration: started.elapsed(),
        },
        true,
    )
}

/// Moves the bytes: read a chunk, pass the rate limiter, write it, report
/// progress; waits while the engine is paused.
async fn copy_loop(
    job: &Job,
    reader: &mut ReadStream,
    writer: &mut WriteStream,
    tracker: &mut ProgressTracker,
    timeout: Duration,
) -> Result<(), (Error, Side)> {
    let cancel = &job.cancel;
    let shared = &job.shared;
    let direction = job.item.direction;
    let (src_side, dst_side) = match direction {
        Direction::Download => (Side::Remote, Side::Local),
        Direction::Upload => (Side::Local, Side::Remote),
    };
    let mut paused = job.paused.clone();
    let mut buf = vec![0u8; BUFFER_SIZE];
    loop {
        if *paused.borrow_and_update() {
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Err((Error::Cancelled, src_side)),
                r = paused.wait_for(|p| !*p) => {
                    if r.is_err() {
                        return Err((Error::Cancelled, src_side));
                    }
                }
            }
            tracker.restart_speed(Instant::now());
        }
        let chunk = shared
            .limiter
            .chunk_size(direction, BUFFER_SIZE)
            .clamp(1, BUFFER_SIZE);
        let n = timed(timeout, cancel, async {
            reader.read(&mut buf[..chunk]).await.map_err(Error::Io)
        })
        .await
        .map_err(|e| (e, src_side))?;
        if n == 0 {
            break;
        }
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Err((Error::Cancelled, src_side)),
            () = shared.limiter.acquire(direction, n) => {}
        }
        timed(timeout, cancel, async {
            writer.write_all(&buf[..n]).await.map_err(Error::Io)
        })
        .await
        .map_err(|e| (e, dst_side))?;
        if let Some(p) = tracker.advance(n as u64, Instant::now()) {
            let _ = lock_queue(&shared.queue).set_progress(job.item.id, p.bytes_done);
            shared.events.progress(p);
        }
    }
    timed(timeout, cancel, async {
        writer.shutdown().await.map_err(Error::Io)
    })
    .await
    .map_err(|e| (e, dst_side))
}
