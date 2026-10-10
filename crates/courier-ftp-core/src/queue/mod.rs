//! Transfer queue model and persistence (T40, FEATURES.md §5).
//!
//! I/O-free except for [`persist`], which goes through the
//! [`DeviceBlobVault`](crate::vault::DeviceBlobVault) seam: the implementation
//! (sealing under the LMK-wrapped device key, the `device_blobs` table) is
//! `courier_ftp_store::vault::VaultEngine`, because the store depends on core
//! and not the other way round — the same split as [`ItemVault`](crate::vault::ItemVault).
//!
//! # Model
//!
//! - [`QueueItem`]: server ([`QueueServer`]: a site id, or an inline
//!   quickconnect address with its password as a `SecretString`), direction,
//!   paths, size, type, [`Priority`], exists override, [`ItemState`],
//!   attempts, added time, directory-placeholder flag (T43).
//! - [`Queue`] owns the items and three lists ([`QueueList`]): **queued**
//!   (queued, active and paused items in queue order), **failed** and
//!   **successful** (capped by `queue.max_successful`, default 1000; the
//!   oldest drop off).
//!
//! # API for later tasks
//!
//! - **UI (T56/T57/T62)**: [`Queue::add`]/[`Queue::add_batch`],
//!   [`Queue::remove`]/[`Queue::remove_all`], [`Queue::clear_failed`],
//!   [`Queue::clear_successful`], [`Queue::move_up`]/[`Queue::move_down`]/
//!   [`Queue::move_to_top`]/[`Queue::move_to_bottom`], [`Queue::set_priority`],
//!   [`Queue::requeue_failed`]/[`Queue::requeue_all_failed`],
//!   [`Queue::pause`]/[`Queue::resume`], [`Queue::rows`] (optionally grouped
//!   by server, [`Queue::groups`]), [`Queue::stats`] with a [`SpeedMeter`],
//!   [`Queue::export_json`]/[`import_json`]. Selection-taking operations ignore
//!   ids that don't apply. Removing or pausing returns the ids that were
//!   active so the engine can cancel them.
//! - **Engine (T41)**: [`Queue::is_processing`]/[`Queue::set_processing`],
//!   [`Queue::next_runnable`] (highest priority first, then queue order,
//!   skipping paused/active items and what the eligibility closure rejects),
//!   [`Queue::start`], [`Queue::set_progress`], [`Queue::stop`],
//!   [`Queue::finish`], [`Queue::fail`] (retry until `max_attempts`, then the
//!   failed list), [`Queue::set_on_exists`], [`Queue::set_size`];
//!   [`Queue::expand_placeholder`] for T43.
//! - **Persistence**: share the queue as a [`SharedQueue`] and drive a
//!   [`QueuePersister`] (restore after unlock, `changed()` after mutations,
//!   debounced writes ≤ 2 s, final write on quit, [`QueuePersister::quit_check`]
//!   for the "items would be lost" warning).

mod export;
mod item;
mod model;
pub mod persist;
mod view;

#[cfg(test)]
mod tests;

pub use export::{
    EXPORT_FORMAT, EXPORT_VERSION, ExportError, ExportedItem, ExportedServer, ImportReport,
    QueueExport, import_json,
};
pub use item::{ItemState, NewItem, Priority, Progress, QueueItem, QueueServer, ServerKey, SiteId};
pub use model::{DEFAULT_MAX_SUCCESSFUL, FailOutcome, Queue, QueueError, QueueList, Removed};
pub use persist::{
    LossReason, PersistError, QUEUE_BLOB, QueuePersister, QuitCheck, SaveOutcome, SharedQueue,
    lock_queue,
};
pub use view::{QueueRow, QueueStats, ServerGroup, ServerHeader, SpeedMeter};
