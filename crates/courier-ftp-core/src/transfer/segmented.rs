//! Segmented (multi-connection) transfer of one file (T41b §2).
//!
//! The worker that runs the file is the first connection. It tells the
//! engine how many connections in total it could use
//! ([`SegmentLink::desired`]); the engine grants more when slots are free
//! and no other file is waiting ([`Grant`]s: an idle pooled session, or
//! permission to open one), all at once so they connect in parallel. Each
//! connection loops: claim a range ([`Ranges::claim`], which steals half of
//! the slowest range when nothing is pending), `open_read` at its start,
//! `open_write` with [`WriteMode::At`] there, copy until the range's
//! (possibly lowered) end, drop the reader (FTP aborts the rest with
//! `ABOR`), repeat.
//!
//! - Every chunk passes the shared [`RateLimiter`](super::RateLimiter), so
//!   speed limits hold for the sum of all segments.
//! - A connection with nothing left to claim waits until the file is done
//!   (a failed range may come back) and keeps its slot until then.
//! - A segment that fails with a transient remote error puts its unflushed
//!   rest back and reconnects (up to `connection.retries` times); other
//!   errors fail the whole file. When every connection gave up, the file
//!   fails and the engine retries it later.
//! - The missing ranges are saved in the queue item
//!   ([`Queue::set_segments`](crate::queue::Queue::set_segments)) every
//!   [`SAVE_INTERVAL`] and on failure, so a retry or a restart after a crash
//!   transfers only those. A segment flushes its writer every 4 MiB and only
//!   flushed bytes count as done there.
//! - At the end the target's size is compared with the source's.

use std::{
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Notify, mpsc, watch},
    task::JoinSet,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use super::{
    BUFFER_SIZE, CLEANUP_TIMEOUT,
    progress::ProgressTracker,
    segments::Ranges,
    worker::{Failure, Job, Outcome, Shared, Side, connect_session, stat_reconnecting, timed},
};
use crate::{
    Error,
    backend::{Backend, ReadStream, SessionHandle, TransferOpts, WriteMode, WriteStream},
    events::TransferId,
    model::{Direction, RemotePath},
    queue::{ByteRange, QueueServer, lock_queue},
    settings::Settings,
};

/// How often the missing ranges are saved to the queue item.
pub const SAVE_INTERVAL: Duration = Duration::from_secs(1);
/// A segment flushes its writer (making its progress a safe resume point)
/// after this many bytes.
const FLUSH_EVERY: u64 = 4 * 1024 * 1024;

/// One more connection for a segmented transfer, sent by the engine.
pub(super) struct Grant(pub Option<SessionHandle>);

/// What a worker and the engine share about extra connections.
pub(super) struct SegmentLink {
    /// Grants from the engine (taken by the segmented transfer).
    grants: Mutex<Option<mpsc::UnboundedReceiver<Grant>>>,
    /// How many connections in total (the worker's included) the transfer
    /// could use right now; 0 when it wants no more. The engine grants
    /// while `1 + granted < desired`.
    pub desired: Arc<AtomicU32>,
    /// Extra sessions to give back to the pool.
    returned: Mutex<Vec<SessionHandle>>,
    /// An extra connection was refused as one too many.
    refused: Mutex<Option<Error>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl SegmentLink {
    pub(super) fn new(grants: mpsc::UnboundedReceiver<Grant>, desired: Arc<AtomicU32>) -> Self {
        Self {
            grants: Mutex::new(Some(grants)),
            desired,
            returned: Mutex::default(),
            refused: Mutex::default(),
        }
    }

    fn give_back(&self, session: SessionHandle) {
        lock(&self.returned).push(session);
    }

    /// Stops accepting grants and returns the extra sessions (including
    /// pooled ones granted but never used) and a refusal, if any.
    pub(super) fn close(&self) -> (Vec<SessionHandle>, Option<Error>) {
        self.desired.store(0, Ordering::Release);
        let mut sessions = std::mem::take(&mut *lock(&self.returned));
        if let Some(mut rx) = lock(&self.grants).take() {
            close_and_drain(&mut rx, &mut sessions);
        }
        (sessions, lock(&self.refused).take())
    }
}

fn close_and_drain(rx: &mut mpsc::UnboundedReceiver<Grant>, sessions: &mut Vec<SessionHandle>) {
    rx.close();
    while let Ok(Grant(session)) = rx.try_recv() {
        sessions.extend(session);
    }
}

/// How the transfer starts.
pub(super) enum Start {
    /// A new transfer: create (`Create`) or truncate (`Truncate`) the target
    /// first.
    Fresh(WriteMode),
    /// Continue the saved missing ranges.
    Resume(Vec<ByteRange>),
}

/// The paths and sizes of one segmented transfer.
pub(super) struct Plan {
    pub src_path: RemotePath,
    pub dst_path: RemotePath,
    pub total: u64,
    pub opts: TransferOpts,
    pub start: Start,
}

struct State {
    ranges: Ranges,
    tracker: ProgressTracker,
    last_saved: Instant,
    /// Bytes moved by this attempt.
    moved: u64,
    /// The error that ends the whole transfer (permanent or local).
    fatal: Option<(Error, Side)>,
    /// The most recent error of a connection that gave up.
    last_error: Option<(Error, Side)>,
}

struct Ctx {
    id: TransferId,
    server: QueueServer,
    direction: Direction,
    src_path: RemotePath,
    dst_path: RemotePath,
    total: u64,
    read_opts: TransferOpts,
    write_opts: TransferOpts,
    timeout: Duration,
    /// Child of the job's token: cancelled on a fatal error too.
    cancel: CancellationToken,
    paused: watch::Receiver<bool>,
    settings: Arc<Settings>,
    shared: Arc<Shared>,
    desired: Arc<AtomicU32>,
    max_segments: u32,
    /// Connections working on (or waiting for) ranges.
    alive: AtomicU32,
    /// Woken when ranges are finished or released.
    work: Notify,
    /// An extra connection was refused as one too many.
    refused: Mutex<Option<Error>>,
    state: Mutex<State>,
}

impl Ctx {
    fn state(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    fn sides(&self) -> (Side, Side) {
        match self.direction {
            Direction::Download => (Side::Remote, Side::Local),
            Direction::Upload => (Side::Local, Side::Remote),
        }
    }

    /// Recomputes how many connections are worth having and wakes the
    /// engine when that grew.
    fn update_desired(&self, st: &State) {
        let desired = if st.fatal.is_some() || self.cancel.is_cancelled() {
            0
        } else {
            let more = u32::try_from(st.ranges.could_use()).unwrap_or(u32::MAX);
            self.alive
                .load(Ordering::Acquire)
                .saturating_add(more)
                .min(self.max_segments)
        };
        let before = self.desired.swap(desired, Ordering::AcqRel);
        if desired > before {
            self.shared.wake.notify_one();
        }
    }

    fn save(&self, st: &mut State, now: Instant) {
        st.last_saved = now;
        let missing = st.ranges.missing();
        let _ = lock_queue(&self.shared.queue).set_segments(self.id, Some(missing));
        self.shared.changed();
    }

    /// `slot` moved `n` bytes.
    fn advance(&self, slot: usize, n: u64) {
        let now = Instant::now();
        let mut st = self.state();
        let counted = st.ranges.advance(slot, n);
        st.moved += counted;
        if let Some(p) = st.tracker.advance(counted, now) {
            let _ = lock_queue(&self.shared.queue).set_progress(self.id, p.bytes_done);
            self.shared.events.progress(p);
        }
        if now.saturating_duration_since(st.last_saved) >= SAVE_INTERVAL {
            self.save(&mut st, now);
        }
    }

    /// Ends the whole transfer with `error`.
    fn fail(&self, error: Error, side: Side) {
        let mut st = self.state();
        if st.fatal.is_none() {
            st.fatal = Some((error, side));
        }
        self.desired.store(0, Ordering::Release);
        self.cancel.cancel();
    }

    /// Puts what `slot` didn't flush back and wakes waiting connections.
    fn release(&self, slot: usize) {
        self.state().ranges.release(slot);
        self.work.notify_waiters();
    }

    /// A connection stops after transient errors; the others carry on.
    fn gave_up(&self, error: Error, side: Side) -> bool {
        self.state().last_error = Some((error, side));
        false
    }
}

/// Runs a segmented transfer on `src`/`dst` (the worker's connection) plus
/// the connections the engine grants. Returns the outcome and whether the
/// worker's remote session is reusable.
#[allow(clippy::too_many_lines)]
pub(super) async fn run(
    job: &Job,
    src: &mut dyn Backend,
    dst: &mut dyn Backend,
    plan: Plan,
    started: Instant,
) -> (Outcome, bool) {
    let item = &job.item;
    let settings = &job.settings;
    let seg = &settings.transfers.segmented;
    let timeout = Duration::from_secs(settings.connection.timeout_secs.max(1));
    let min_split = seg.min_segment_size_mib.max(1).saturating_mul(1024 * 1024);
    let (src_side, dst_side) = match item.direction {
        Direction::Download => (Side::Remote, Side::Local),
        Direction::Upload => (Side::Local, Side::Remote),
    };
    let remote_ok = |error: &Error, side: Side| !(side == Side::Remote && error.is_transient());

    // 1. A new target is created (or truncated) once; segments then write
    //    into it at their offsets.
    let missing = match plan.start {
        Start::Fresh(mode) => {
            let create_opts = TransferOpts {
                preallocate_hint: None,
                ..plan.opts
            };
            let created = async {
                let mut w = timed(
                    timeout,
                    &job.cancel,
                    dst.open_write(&plan.dst_path, mode, &create_opts),
                )
                .await?;
                timed(timeout, &job.cancel, async {
                    w.shutdown().await.map_err(Error::Io)
                })
                .await?;
                drop(w);
                timed(timeout, &job.cancel, dst.finish_transfer()).await
            }
            .await;
            if let Err(e) = created {
                let reusable = remote_ok(&e, dst_side);
                return (Outcome::Failed(Failure::new(dst_side, e)), reusable);
            }
            vec![ByteRange::new(0, plan.total)]
        }
        Start::Resume(missing) => missing,
    };
    let ranges = Ranges::new(missing, min_split);
    let left = ranges.left();
    let now = Instant::now();
    let mut tracker = ProgressTracker::new(
        item.id,
        plan.total.saturating_sub(left),
        Some(plan.total),
        now,
    );
    if let Some(p) = tracker.advance(0, now) {
        job.shared.events.progress(p);
    }
    let write_opts = TransferOpts {
        // Downloads reserve the full size (sparse is fine): positional
        // writes need it, and a restart recognises the file by its size.
        preallocate_hint: match item.direction {
            Direction::Download => Some(plan.total),
            Direction::Upload => None,
        },
        ..plan.opts
    };
    let ctx = Arc::new(Ctx {
        id: item.id,
        server: item.server.clone(),
        direction: item.direction,
        src_path: plan.src_path,
        dst_path: plan.dst_path.clone(),
        total: plan.total,
        read_opts: plan.opts,
        write_opts,
        timeout,
        cancel: job.cancel.child_token(),
        paused: job.paused.clone(),
        settings: Arc::clone(settings),
        shared: Arc::clone(&job.shared),
        desired: Arc::clone(&job.link.desired),
        max_segments: seg.max_segments.max(1),
        alive: AtomicU32::new(1),
        work: Notify::new(),
        refused: Mutex::default(),
        state: Mutex::new(State {
            ranges,
            tracker,
            last_saved: now,
            moved: 0,
            fatal: None,
            last_error: None,
        }),
    });
    {
        let mut st = ctx.state();
        ctx.save(&mut st, now);
        ctx.update_desired(&st);
    }
    tracing::debug!(
        id = ?item.id,
        bytes = left,
        "segmented transfer, up to {} connections",
        ctx.max_segments
    );

    // 2. The worker's connection plus granted ones.
    let mut grants = lock(&job.link.grants).take();
    let mut tasks: JoinSet<Option<SessionHandle>> = JoinSet::new();
    let mut next_slot = 1usize;
    let mut main = Box::pin(run_ranges(&ctx, 0, &mut *src, &mut *dst));
    let mut main_reusable = None;
    while main_reusable.is_none() || !tasks.is_empty() {
        tokio::select! {
            reusable = &mut main, if main_reusable.is_none() => {
                main_reusable = Some(reusable);
                ctx.alive.fetch_sub(1, Ordering::AcqRel);
                ctx.work.notify_waiters();
            }
            grant = recv(&mut grants) => {
                let Some(Grant(session)) = grant else {
                    grants = None;
                    continue;
                };
                let useful = {
                    let st = ctx.state();
                    st.fatal.is_none() && !st.ranges.is_complete() && !ctx.cancel.is_cancelled()
                };
                if !useful {
                    if let Some(s) = session {
                        job.link.give_back(s);
                    }
                    continue;
                }
                ctx.alive.fetch_add(1, Ordering::AcqRel);
                let slot = next_slot;
                next_slot += 1;
                tasks.spawn(extra_connection(Arc::clone(&ctx), slot, session));
            }
            Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                ctx.alive.fetch_sub(1, Ordering::AcqRel);
                ctx.work.notify_waiters();
                if let Ok(Some(session)) = joined {
                    job.link.give_back(session);
                }
            }
        }
    }
    drop(main);
    job.link.desired.store(0, Ordering::Release);
    if let Some(mut rx) = grants {
        let mut sessions = Vec::new();
        close_and_drain(&mut rx, &mut sessions);
        for s in sessions {
            job.link.give_back(s);
        }
    }
    if let Some(e) = lock(&ctx.refused).take() {
        lock(&job.link.refused).get_or_insert(e);
    }
    let main_reusable = main_reusable.unwrap_or(false);

    // 3. The result.
    let (complete, moved, fatal, last_error) = {
        let mut st = ctx.state();
        let complete = st.ranges.is_complete();
        if !complete {
            ctx.save(&mut st, Instant::now());
        }
        (complete, st.moved, st.fatal.take(), st.last_error.take())
    };
    if !complete {
        let (error, side) = if job.cancel.is_cancelled() {
            (Error::Cancelled, src_side)
        } else {
            fatal.or(last_error).unwrap_or((
                Error::Connection("every segment connection failed".into()),
                Side::Remote,
            ))
        };
        let failure = Failure {
            error,
            side,
            written: None,
        };
        return (Outcome::Failed(failure), main_reusable);
    }

    // Integrity: the target has the source's size.
    match stat_reconnecting(dst, &plan.dst_path, dst_side, timeout, &job.cancel).await {
        Ok(entry) if entry.size == Some(plan.total) => {}
        Ok(entry) => {
            let _ = lock_queue(&job.shared.queue).set_segments(item.id, None);
            let error = Error::Protocol {
                code: None,
                message: format!(
                    "size check after a segmented transfer failed: {} bytes instead of {}",
                    entry.size.unwrap_or(0),
                    plan.total
                ),
            };
            return (
                Outcome::Failed(Failure::new(dst_side, error)),
                main_reusable,
            );
        }
        Err(e) => {
            let reusable = main_reusable && remote_ok(&e, dst_side);
            return (Outcome::Failed(Failure::new(dst_side, e)), reusable);
        }
    }
    let progress = ctx.state().tracker.report();
    job.shared.events.progress(progress);
    (
        Outcome::Done {
            bytes: plan.total,
            transferred: moved,
            duration: started.elapsed(),
        },
        main_reusable,
    )
}

async fn recv(rx: &mut Option<mpsc::UnboundedReceiver<Grant>>) -> Option<Grant> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// A granted connection: open it if needed, run ranges, hand the session
/// back when it is still usable.
async fn extra_connection(
    ctx: Arc<Ctx>,
    slot: usize,
    session: Option<SessionHandle>,
) -> Option<SessionHandle> {
    let session = match session {
        Some(s) => s,
        None => match connect_session(&ctx.shared, &ctx.settings, &ctx.server, &ctx.cancel).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("extra segment connection failed: {e}");
                if super::is_too_many_connections(&e) {
                    // The engine lowers the server's limit.
                    lock(&ctx.refused).get_or_insert(e);
                }
                return None;
            }
        },
    };
    let mut local = ctx.shared.local.create();
    if let Err(e) = local.connect(ctx.cancel.clone()).await {
        ctx.fail(e, Side::Local);
        return Some(session);
    }
    let reusable = {
        let mut remote = session.lock().await;
        let (src, dst): (&mut dyn Backend, &mut dyn Backend) = match ctx.direction {
            Direction::Download => (&mut **remote, &mut *local),
            Direction::Upload => (&mut *local, &mut **remote),
        };
        run_ranges(&ctx, slot, src, dst).await
    };
    let _ = local.disconnect().await;
    let connected = session.lock().await.is_connected();
    (reusable && connected).then_some(session)
}

/// The remote one of `src` and `dst`.
fn remote_of<'a>(
    direction: Direction,
    src: &'a mut dyn Backend,
    dst: &'a mut dyn Backend,
) -> &'a mut dyn Backend {
    match direction {
        Direction::Download => src,
        Direction::Upload => dst,
    }
}

/// One connection's loop over claimed ranges; with nothing to claim it
/// waits until the file is complete (or a range comes back). Returns
/// whether its remote session is still usable.
async fn run_ranges(ctx: &Ctx, slot: usize, src: &mut dyn Backend, dst: &mut dyn Backend) -> bool {
    let mut reconnects = 0u32;
    loop {
        let work = ctx.work.notified();
        tokio::pin!(work);
        work.as_mut().enable();
        let range = {
            let mut st = ctx.state();
            if st.fatal.is_some() || ctx.cancel.is_cancelled() || st.ranges.is_complete() {
                return true;
            }
            let range = st.ranges.claim(slot);
            ctx.update_desired(&st);
            range
        };
        let Some(range) = range else {
            tokio::select! {
                () = ctx.cancel.cancelled() => return true,
                () = &mut work => continue,
            }
        };
        let remote = remote_of(ctx.direction, &mut *src, &mut *dst);
        if !remote.is_connected()
            && let Err(e) =
                timed(ctx.timeout, &ctx.cancel, remote.connect(ctx.cancel.clone())).await
        {
            ctx.release(slot);
            return ctx.gave_up(e, Side::Remote);
        }
        match copy_range(ctx, slot, range, src, dst).await {
            Ok(()) => {
                reconnects = 0;
                ctx.state().ranges.finish(slot);
                ctx.work.notify_waiters();
            }
            Err((error, side)) => {
                ctx.release(slot);
                if ctx.cancel.is_cancelled() || matches!(error, Error::Cancelled) {
                    return true;
                }
                if !(side == Side::Remote && error.is_transient()) {
                    ctx.fail(error, side);
                    return side != Side::Remote;
                }
                if reconnects >= ctx.settings.connection.retries {
                    return ctx.gave_up(error, side);
                }
                reconnects += 1;
                tracing::debug!(slot, "segment failed ({error}); reconnecting");
                let remote = remote_of(ctx.direction, &mut *src, &mut *dst);
                let _ = tokio::time::timeout(CLEANUP_TIMEOUT, remote.disconnect()).await;
            }
        }
    }
}

/// Moves one range: open both streams at `range.start`, copy until the
/// slot's end (which may be lowered meanwhile), close both.
async fn copy_range(
    ctx: &Ctx,
    slot: usize,
    range: ByteRange,
    src: &mut dyn Backend,
    dst: &mut dyn Backend,
) -> Result<(), (Error, Side)> {
    let (src_side, dst_side) = ctx.sides();
    let cancel = &ctx.cancel;
    let timeout = ctx.timeout;
    let began = Instant::now();
    tracing::debug!(
        slot,
        start = range.start,
        end = range.end,
        "segment range claimed"
    );
    // The reader needn't fetch past the range (an SFTP reader would keep
    // up to its whole pipeline in flight beyond it). A range shortened by
    // work stealing meanwhile still wastes what is already requested.
    let read_opts = TransferOpts {
        read_limit: Some(range.end.saturating_sub(range.start)),
        ..ctx.read_opts
    };
    let mut reader = timed(
        timeout,
        cancel,
        src.open_read(&ctx.src_path, range.start, &read_opts),
    )
    .await
    .map_err(|e| (e, src_side))?;
    let mut writer = match timed(
        timeout,
        cancel,
        dst.open_write(&ctx.dst_path, WriteMode::At(range.start), &ctx.write_opts),
    )
    .await
    {
        Ok(w) => w,
        Err(e) => {
            drop(reader);
            let _ = tokio::time::timeout(CLEANUP_TIMEOUT, src.finish_transfer()).await;
            return Err((e, dst_side));
        }
    };
    let copied = copy_loop(ctx, slot, &mut reader, &mut writer).await;
    let closed = match copied {
        Ok(()) => timed(timeout, cancel, async {
            writer.shutdown().await.map_err(Error::Io)
        })
        .await
        .map_err(|e| (e, dst_side)),
        Err(e) => {
            // What was written before the error is kept for the resume.
            if let Ok(Ok(())) = tokio::time::timeout(CLEANUP_TIMEOUT, writer.flush()).await {
                ctx.state().ranges.flushed(slot);
            }
            Err(e)
        }
    };
    drop(reader);
    drop(writer);
    let deadline = Instant::now() + timeout;
    // A reader stopped before the end of the file is aborted here (FTP
    // `ABOR`, reported as cancelled): that is how a range normally ends.
    let src_done = tokio::time::timeout_at(deadline, src.finish_transfer()).await;
    let dst_done = tokio::time::timeout_at(deadline, dst.finish_transfer()).await;
    closed?;
    match dst_done {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err((e, dst_side)),
        Err(_) => return Err((Error::Timeout, dst_side)),
    }
    ctx.state().ranges.flushed(slot);
    tracing::debug!(slot, elapsed = ?began.elapsed(), "segment range done");
    if !matches!(src_done, Ok(Ok(()) | Err(Error::Cancelled))) {
        // The range is complete; only the connection is suspect: reconnect
        // before the next range.
        tracing::debug!("finishing a segment read failed: {src_done:?}");
        if src_side == Side::Remote {
            let _ = tokio::time::timeout(CLEANUP_TIMEOUT, src.disconnect()).await;
        }
    }
    Ok(())
}

async fn copy_loop(
    ctx: &Ctx,
    slot: usize,
    reader: &mut ReadStream,
    writer: &mut WriteStream,
) -> Result<(), (Error, Side)> {
    let (src_side, dst_side) = ctx.sides();
    let cancel = &ctx.cancel;
    let limiter = &ctx.shared.limiter;
    let direction = ctx.direction;
    let mut paused = ctx.paused.clone();
    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut unflushed = 0u64;
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
            ctx.state().tracker.restart_speed(Instant::now());
        }
        let Some((pos, end)) = ctx.state().ranges.position(slot) else {
            return Ok(());
        };
        if pos >= end {
            return Ok(());
        }
        let want = usize::try_from(end - pos).unwrap_or(usize::MAX);
        let chunk = limiter
            .chunk_size(direction, BUFFER_SIZE)
            .clamp(1, BUFFER_SIZE)
            .min(want);
        let n = timed(ctx.timeout, cancel, async {
            reader.read(&mut buf[..chunk]).await.map_err(Error::Io)
        })
        .await
        .map_err(|e| (e, src_side))?;
        if n == 0 {
            let error = Error::Protocol {
                code: None,
                message: format!(
                    "the file ended at {pos} bytes, expected {} (it changed during the transfer)",
                    ctx.total
                ),
            };
            return Err((error, src_side));
        }
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Err((Error::Cancelled, src_side)),
            () = limiter.acquire(direction, n) => {}
        }
        timed(ctx.timeout, cancel, async {
            writer.write_all(&buf[..n]).await.map_err(Error::Io)
        })
        .await
        .map_err(|e| (e, dst_side))?;
        ctx.advance(slot, n as u64);
        unflushed += n as u64;
        if unflushed >= FLUSH_EVERY {
            timed(ctx.timeout, cancel, async {
                writer.flush().await.map_err(Error::Io)
            })
            .await
            .map_err(|e| (e, dst_side))?;
            ctx.state().ranges.flushed(slot);
            unflushed = 0;
        }
    }
}

/// Whether saved `missing` ranges can be continued: they fit the source's
/// `total` size, and the target looks like the file they belong to (a
/// download's target was preallocated to the full size; an upload's is no
/// longer than the source).
pub(super) fn can_continue(
    missing: &[ByteRange],
    total: u64,
    target_size: Option<u64>,
    direction: Direction,
) -> bool {
    let Some(size) = target_size else {
        return false;
    };
    let size_ok = match direction {
        Direction::Download => size == total,
        Direction::Upload => size <= total,
    };
    size_ok && super::segments::fits(missing, total)
}
