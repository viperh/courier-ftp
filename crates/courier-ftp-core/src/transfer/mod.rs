//! Transfer engine (T41; extended by T41b–T45): takes items from the
//! [`queue`](crate::queue) and moves the bytes, within the connection
//! limits, with progress, retries and cancellation (FEATURES.md §5, §6).
//!
//! # Running it
//!
//! ```ignore
//! let (engine, handle) = TransferEngine::builder(queue.clone(), factory, resolver, events)
//!     .settings(settings.clone())
//!     .exists_policy(policy)            // T42; default: overwrite
//!     .rate_limiter(limiter)            // T44; default: unlimited
//!     .on_queue_changed(move || persister.changed())
//!     .build();
//! engine.spawn();
//! handle.start();                       // "process queue"
//! handle.wake();                        // after adding items
//! ```
//!
//! The engine is one tokio task controlled through [`Command`]s sent with an
//! [`EngineHandle`]: `Start`, `Stop` (start nothing new, cancel the active
//! transfers back to queued), `PauseAll`/`ResumeAll` (hold the active
//! transfers mid-stream, connections stay open), `Cancel(id)`,
//! `SettingsChanged`, `Wake` (queue edited: schedule now rather than at the
//! next 1 s poll) and `Shutdown`. [`EngineHandle::status`] /
//! [`EngineHandle::watch_status`] publish an [`EngineStatus`] (processing,
//! paused, active slots, owned tasks, open connections).
//!
//! The [`SharedQueue`](crate::queue::SharedQueue) stays the source of truth:
//! the UI edits it directly (T56) and the engine reads
//! [`Queue::is_processing`](crate::queue::Queue::is_processing) and
//! [`Queue::next_runnable`](crate::queue::Queue::next_runnable). When the UI
//! removes or pauses active items, it sends `Cancel` for the ids those calls
//! return.
//!
//! # Scheduling
//!
//! - Global `transfers.max_concurrent`, plus `max_downloads` /
//!   `max_uploads` (0 = no extra limit), plus a per-server limit:
//!   [`ServerResolver::connection_limit`] (the site's `limit_connections`).
//! - The next item is the queue's highest priority, earliest queued item
//!   whose server and direction have a free slot and whose retry delay has
//!   passed.
//! - **Connection pool** per server ([`ServerKey`](crate::queue::ServerKey)):
//!   transfer connections are separate from the tabs' browsing sessions.
//!   A finished transfer leaves its [`SessionHandle`](crate::backend::SessionHandle)
//!   idle for the next item of that server; new ones open up to the limit;
//!   idle ones close after [`IDLE_TIMEOUT`] (30 s). A pooled connection that
//!   died meanwhile is reconnected once.
//! - **Too many connections** (`421`/`530` replies mentioning "too many" or
//!   "maximum", see [`is_too_many_connections`]) while connecting: the
//!   server's limit drops to the connections already open (for the engine's
//!   lifetime), the item is requeued without counting an attempt, and the
//!   message log says so. With no other connection open it is an ordinary
//!   failure.
//!
//! # A transfer
//!
//! 1. Connect (resolver + [`BackendFactory`](crate::backend::BackendFactory))
//!    or take a pooled session; create the local side
//!    ([`LocalBackendFactory`], default the real filesystem).
//! 2. Stat source and target. **Exists hook**: [`ExistsPolicy::decide`]
//!    gets both entries and returns overwrite / resume at / skip / rename
//!    (default [`OverwriteAll`]; T42 implements the real policy and prompt).
//!    A retried transfer resumes at its own offset without asking.
//! 3. `open_read` + `open_write`, then copy in [`BUFFER_SIZE`] chunks. Each
//!    chunk passes the **rate-limiter hook** [`RateLimiter::acquire`]
//!    (default [`Unlimited`]; T44's token bucket), with the chunk size from
//!    [`RateLimiter::chunk_size`]. Every read and write has the
//!    `connection.timeout_secs` timeout and races the item's cancellation.
//! 4. Shut the writer down, drop the streams, `finish_transfer` on both
//!    sides, apply `transfers.preserve_timestamps` (`set_mtime` when the
//!    target supports it), mark Done. Downloads write to the final name.
//!
//! After an error or cancellation, the writer is flushed (so the written
//! length is a valid resume offset), the streams are dropped and both
//! sides get `finish_transfer` within [`CLEANUP_TIMEOUT`] (FTP aborts the
//! data transfer there with `ABOR`, SFTP closes the handle). The session is
//! pooled again when that worked and the error wasn't a lost connection.
//!
//! # Progress, retries, failures
//!
//! - Progress: bytes (including a resumed offset), total, speed as an
//!   exponential moving average over [`SPEED_WINDOW`] (5 s), ETA; sent as
//!   coalesced [`CoreEvent::TransferProgress`](crate::events::CoreEvent) at
//!   most every [`REPORT_INTERVAL`] (10 Hz) per item, plus a final one, and
//!   mirrored into the queue with `Queue::set_progress`.
//! - Transient errors ([`Error::is_transient`](crate::Error::is_transient))
//!   are retried up to `connection.retries` times; the item goes back to
//!   queued and waits `retry_delay_secs × 2^(attempt−1)` (capped at
//!   [`MAX_RETRY_DELAY`] or the setting, whichever is larger), then resumes
//!   at the offset it reached when both sides support it (binary mode
//!   only). Permanent errors fail at once. The failed list shows the last
//!   error (local errors prefixed "local file:").
//! - Local disk full (`StorageFull`/`QuotaExceeded`): permanent failure
//!   and the whole engine pauses (as [`Command::PauseAll`]), so the rest of
//!   the queue doesn't fail in a row.
//! - Events: [`TransferStateChanged`](crate::events::CoreEvent::TransferStateChanged)
//!   (Active, Queued on requeue/stop, Paused on cancel, Done, Skipped,
//!   Failed), and [`QueueFinished`](crate::events::CoreEvent::QueueFinished)
//!   with totals when a run has nothing queued or active left; processing
//!   then stops.
//!
//! # Hooks for later tasks
//!
//! - **T42**: [`ExistsPolicy`] (with [`ExistsContext`] / [`ExistsDecision`]).
//! - **T43**: [`DirExpander`]: directory placeholders take a slot, get
//!   listed, and are replaced by their children.
//! - **T44**: [`RateLimiter`] (`acquire`, `chunk_size`, `settings_changed`).
//! - **T45**: `QueueFinished { stats }`.
//! - **T41b**: the pool and the worker are the places to add warm-up and
//!   segments; slots are counted per server in the engine.
//! - **T56/T62**: [`EngineHandle`] commands and [`EngineStatus`].

mod engine;
mod hooks;
mod progress;
mod worker;

#[cfg(test)]
mod tests;

use std::time::Duration;

pub use engine::{Command, EngineBuilder, EngineHandle, EngineStatus, TransferEngine};
pub use hooks::{
    DirExpander, ExistsContext, ExistsDecision, ExistsPolicy, LocalBackendFactory, OverwriteAll,
    QuickResolver, RateLimiter, RealLocal, ServerResolver, Unlimited, quick_connect_info,
};
pub use progress::{ProgressTracker, REPORT_INTERVAL, SPEED_WINDOW};

use crate::Error;

/// Copy buffer size (128 KiB).
pub const BUFFER_SIZE: usize = 128 * 1024;
/// Idle transfer connections close after this long.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound on the clean-up after a failed or cancelled transfer.
pub const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
/// Upper bound of the retry back-off (unless `retry_delay_secs` is larger).
pub const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);

/// Whether `err` is a server refusing one connection too many
/// (`421 Too many connections`, `530 … maximum number of clients …`).
pub fn is_too_many_connections(err: &Error) -> bool {
    match err {
        Error::Protocol {
            code: Some(421 | 530),
            message,
        } => {
            let m = message.to_ascii_lowercase();
            ["too many", "maximum", "max connections", "connection limit"]
                .iter()
                .any(|needle| m.contains(needle))
        }
        _ => false,
    }
}
