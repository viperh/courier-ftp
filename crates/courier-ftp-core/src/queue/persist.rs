//! Queue persistence (setting `queue.persist`): the encrypted blob format and
//! the debounced [`QueuePersister`].
//!
//! The queue holds hosts, paths and quickconnect passwords, so it is only ever
//! written through [`DeviceBlobVault`] — sealed under the device data key that
//! the LMK wraps (see [`crate::vault::device_blobs`]) into the store's
//! `device_blobs` table as [`QUEUE_BLOB`]. It is device-local and never syncs.
//!
//! **Vault locked or skipped:** nothing is written (no plaintext fallback), and
//! the persisted queue can't be read. [`QueuePersister::quit_check`] tells the
//! UI how many items would be lost so it can warn on quit. Saves are also
//! refused until the persisted queue has been restored
//! ([`QueuePersister::restore`]), so a session that started locked can't
//! overwrite a queue it never loaded; after a later unlock, `restore` merges
//! the saved items into the current queue.
//!
//! Blob format: CBOR `{ "v": 1, "items": [...] }`, items in list order
//! (queued, failed, successful), each with its state. Progress is not kept:
//! active items are stored, and come back, as queued (resume uses REST/offset).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::item::{ItemState, Priority, QueueItem, QueueServer, SiteId};
use super::model::Queue;
use crate::events::TransferId;
use crate::model::{Direction, LocalPath, RemotePath, ServerAddress};
use crate::settings::{ExistsAction, TransferTypeChoice};
use crate::vault::{DeviceBlobVault, VaultError};

/// The `device_blobs` name of the persisted queue.
pub const QUEUE_BLOB: &str = "transfer_queue";

/// Blob format version written by this build.
pub const FORMAT_VERSION: u32 = 1;

/// Longest a change waits before it is written.
pub const DEBOUNCE: Duration = Duration::from_secs(2);

/// A queue shared between the UI, the engine and the persister.
pub type SharedQueue = Arc<Mutex<Queue>>;

/// Locks a [`SharedQueue`], ignoring poisoning (the queue has no invariants a
/// panic mid-operation could leave worse than a lost update).
pub fn lock_queue(queue: &SharedQueue) -> MutexGuard<'_, Queue> {
    queue.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Persistence errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PersistError {
    /// The vault refused (locked, storage, corrupt envelope).
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// The decrypted blob isn't a queue.
    #[error("the saved queue is damaged: {0}")]
    Decode(String),
    /// The blob was written by a newer courier-ftp.
    #[error("the saved queue was written by a newer courier-ftp (format {0})")]
    NewerFormat(u32),
    /// Encoding failed.
    #[error("could not encode the queue: {0}")]
    Encode(String),
}

// ------------------------------------------------------------------ codec

#[derive(Serialize, Deserialize)]
struct Blob {
    v: u32,
    items: Vec<StoredItem>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredServer {
    Site(SiteId),
    Quick {
        address: ServerAddress,
        #[serde(with = "opt_secret")]
        password: Option<SecretString>,
    },
}

#[derive(Serialize, Deserialize)]
struct StoredItem {
    id: TransferId,
    server: StoredServer,
    direction: Direction,
    local: LocalPath,
    remote: RemotePath,
    size: Option<u64>,
    transfer_type: TransferTypeChoice,
    priority: Priority,
    on_exists: Option<ExistsAction>,
    state: ItemState,
    attempts: u8,
    #[serde(with = "time::serde::rfc3339")]
    added_at: OffsetDateTime,
    is_dir_placeholder: bool,
}

mod opt_secret {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        secret: &Option<SecretString>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match secret {
            Some(s) => serializer.serialize_some(s.expose_secret()),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<SecretString>, D::Error> {
        Option::<String>::deserialize(deserializer).map(|o| o.map(SecretString::from))
    }
}

impl From<&QueueItem> for StoredItem {
    fn from(i: &QueueItem) -> Self {
        let state = match &i.state {
            ItemState::Active { .. } => ItemState::Queued,
            other => other.clone(),
        };
        Self {
            id: i.id,
            server: match &i.server {
                QueueServer::Site(id) => StoredServer::Site(*id),
                QueueServer::Quick { address, password } => StoredServer::Quick {
                    address: address.clone(),
                    password: password
                        .as_ref()
                        .map(|p| SecretString::from(p.expose_secret().to_owned())),
                },
            },
            direction: i.direction,
            local: i.local.clone(),
            remote: i.remote.clone(),
            size: i.size,
            transfer_type: i.transfer_type,
            priority: i.priority,
            on_exists: i.on_exists,
            state,
            attempts: i.attempts,
            added_at: i.added_at,
            is_dir_placeholder: i.is_dir_placeholder,
        }
    }
}

impl From<StoredItem> for QueueItem {
    fn from(s: StoredItem) -> Self {
        Self {
            id: s.id,
            server: match s.server {
                StoredServer::Site(id) => QueueServer::Site(id),
                StoredServer::Quick { address, password } => {
                    QueueServer::Quick { address, password }
                }
            },
            direction: s.direction,
            local: s.local,
            remote: s.remote,
            size: s.size,
            transfer_type: s.transfer_type,
            priority: s.priority,
            on_exists: s.on_exists,
            state: s.state,
            attempts: s.attempts,
            added_at: s.added_at,
            is_dir_placeholder: s.is_dir_placeholder,
        }
    }
}

/// Encodes the queue for the encrypted blob (secrets included: never write
/// this anywhere but [`DeviceBlobVault::save_blob`]). Active items are stored
/// as queued.
///
/// # Errors
/// [`PersistError::Encode`].
pub fn encode(queue: &Queue) -> Result<Zeroizing<Vec<u8>>, PersistError> {
    let blob = Blob {
        v: FORMAT_VERSION,
        items: queue.all_in_order().map(StoredItem::from).collect(),
    };
    // Room up front so the buffer (which holds secrets) rarely reallocates and
    // leaves unzeroized copies behind.
    let mut out = Zeroizing::new(Vec::with_capacity(256 * blob.items.len() + 64));
    ciborium::into_writer(&blob, &mut *out).map_err(|e| PersistError::Encode(e.to_string()))?;
    Ok(out)
}

/// Decodes a blob from [`encode`] into a queue keeping at most
/// `max_successful` successful items. Active items come back queued; the
/// queue is not processing.
///
/// # Errors
/// [`PersistError::Decode`], [`PersistError::NewerFormat`].
pub fn decode(bytes: &[u8], max_successful: usize) -> Result<Queue, PersistError> {
    #[derive(Deserialize)]
    struct Version {
        v: u32,
    }
    let Version { v } =
        ciborium::from_reader(bytes).map_err(|e| PersistError::Decode(e.to_string()))?;
    if v > FORMAT_VERSION {
        return Err(PersistError::NewerFormat(v));
    }
    let blob: Blob =
        ciborium::from_reader(bytes).map_err(|e| PersistError::Decode(e.to_string()))?;
    Ok(Queue::from_items(
        blob.items.into_iter().map(QueueItem::from).collect(),
        max_successful,
    ))
}

/// Loads the persisted queue (`None` when none was saved).
///
/// # Errors
/// [`PersistError::Vault`] (e.g. [`VaultError::Locked`]),
/// [`PersistError::Decode`], [`PersistError::NewerFormat`].
pub async fn load(
    vault: &dyn DeviceBlobVault,
    max_successful: usize,
) -> Result<Option<Queue>, PersistError> {
    match vault.load_blob(QUEUE_BLOB).await? {
        Some(bytes) => decode(&bytes, max_successful).map(Some),
        None => Ok(None),
    }
}

// ------------------------------------------------------------------ persister

/// What a save did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveOutcome {
    /// Written.
    Saved,
    /// Nothing changed since the last write.
    Unchanged,
    /// `queue.persist` is off.
    Disabled,
    /// The vault is locked: not written.
    Locked,
    /// The persisted queue hasn't been restored yet (the vault was locked at
    /// startup): not written, so it isn't overwritten.
    NotRestored,
}

/// Why quitting now would lose items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossReason {
    /// The vault is locked (or was skipped), or the saved queue was never
    /// restored.
    VaultLocked,
    /// `queue.persist` is off.
    Disabled,
}

/// The result of [`QueuePersister::quit_check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuitCheck {
    /// Everything will be saved (or there is nothing to save).
    Safe,
    /// `items` queued and failed items won't survive the restart.
    WouldLose {
        /// How many.
        items: usize,
        /// Why.
        reason: LossReason,
    },
}

#[derive(Debug)]
struct PersistState {
    enabled: bool,
    restored: bool,
    saved_revision: Option<u64>,
}

/// Writes the shared queue to the vault, debounced, and restores it.
///
/// Typical use (app, T41/T56):
/// 1. after the vault unlocks: [`QueuePersister::restore`] (the queue is not
///    started);
/// 2. [`QueuePersister::spawn`] the background task;
/// 3. call [`QueuePersister::changed`] after every queue mutation (cheap);
/// 4. on quit: [`QueuePersister::quit_check`] to warn, then cancel the task's
///    token and await its handle — it makes the final write.
#[derive(Debug)]
pub struct QueuePersister {
    queue: SharedQueue,
    vault: Arc<dyn DeviceBlobVault>,
    debounce: Duration,
    state: tokio::sync::Mutex<PersistState>,
    notify: tokio::sync::Notify,
}

impl QueuePersister {
    /// A persister for `queue` over `vault`; `enabled` is `queue.persist`.
    pub fn new(queue: SharedQueue, vault: Arc<dyn DeviceBlobVault>, enabled: bool) -> Arc<Self> {
        Self::with_debounce(queue, vault, enabled, DEBOUNCE)
    }

    /// [`QueuePersister::new`] with another debounce window (tests).
    pub fn with_debounce(
        queue: SharedQueue,
        vault: Arc<dyn DeviceBlobVault>,
        enabled: bool,
        debounce: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            queue,
            vault,
            debounce,
            state: tokio::sync::Mutex::new(PersistState {
                enabled,
                restored: false,
                saved_revision: None,
            }),
            notify: tokio::sync::Notify::new(),
        })
    }

    /// The queue.
    pub fn queue(&self) -> &SharedQueue {
        &self.queue
    }

    /// Signals a change: the background task writes within the debounce
    /// window. Also call it after the vault unlocks.
    pub fn changed(&self) {
        self.notify.notify_one();
    }

    /// Loads the persisted queue and merges its items into the shared queue
    /// (appended to each list, with new ids; active items come back queued;
    /// processing is not started). Returns how many items were restored. A
    /// second call after a successful one does nothing.
    ///
    /// A blob that doesn't decode still counts as restored (it is
    /// overwritten by the next save), and the error is returned so the UI can
    /// say the saved queue was lost.
    ///
    /// # Errors
    /// [`PersistError::Vault`] (locked: try again after unlock),
    /// [`PersistError::Decode`], [`PersistError::NewerFormat`] (not counted
    /// as restored, so a newer client's queue isn't overwritten).
    pub async fn restore(&self) -> Result<usize, PersistError> {
        let mut st = self.state.lock().await;
        if st.restored {
            return Ok(0);
        }
        let max = lock_queue(&self.queue).max_successful();
        match load(self.vault.as_ref(), max).await {
            Ok(saved) => {
                st.restored = true;
                let n = saved.map_or(0, |saved| {
                    let mut q = lock_queue(&self.queue);
                    let was_empty = q.is_empty();
                    let n = q.absorb(saved);
                    if was_empty {
                        // Identical to the blob: nothing to write yet.
                        st.saved_revision = Some(q.revision());
                    }
                    n
                });
                tracing::debug!(items = n, "transfer queue restored");
                Ok(n)
            }
            Err(e @ PersistError::Decode(_)) => {
                st.restored = true;
                tracing::warn!(error = %e, "the saved transfer queue could not be read");
                Err(e)
            }
            Err(e @ PersistError::Vault(VaultError::Corrupt(_))) => {
                st.restored = true;
                tracing::warn!(error = %e, "the saved transfer queue could not be decrypted");
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Turns persistence on or off (`queue.persist`). Turning it off deletes
    /// the saved queue; turning it on schedules a write.
    ///
    /// # Errors
    /// [`PersistError::Vault`] when deleting fails.
    pub async fn set_enabled(&self, enabled: bool) -> Result<(), PersistError> {
        let mut st = self.state.lock().await;
        if st.enabled == enabled {
            return Ok(());
        }
        st.enabled = enabled;
        st.saved_revision = None;
        if enabled {
            drop(st);
            self.changed();
        } else {
            self.vault.delete_blob(QUEUE_BLOB).await?;
        }
        Ok(())
    }

    /// Writes now if anything changed since the last write.
    ///
    /// # Errors
    /// [`PersistError::Vault`], [`PersistError::Encode`].
    pub async fn save_now(&self) -> Result<SaveOutcome, PersistError> {
        let mut st = self.state.lock().await;
        if !st.enabled {
            return Ok(SaveOutcome::Disabled);
        }
        if !self.vault.is_unlocked().await {
            return Ok(SaveOutcome::Locked);
        }
        if !st.restored {
            return Ok(SaveOutcome::NotRestored);
        }
        let (revision, bytes) = {
            let q = lock_queue(&self.queue);
            if st.saved_revision == Some(q.revision()) {
                return Ok(SaveOutcome::Unchanged);
            }
            (q.revision(), encode(&q)?)
        };
        match self.vault.save_blob(QUEUE_BLOB, &bytes).await {
            Ok(()) => {
                st.saved_revision = Some(revision);
                tracing::debug!(bytes = bytes.len(), "transfer queue saved");
                Ok(SaveOutcome::Saved)
            }
            Err(VaultError::Locked) => Ok(SaveOutcome::Locked),
            Err(e) => Err(e.into()),
        }
    }

    /// Whether quitting now would lose queued or failed items, and why.
    pub async fn quit_check(&self) -> QuitCheck {
        let items = lock_queue(&self.queue).unsaved_count();
        if items == 0 {
            return QuitCheck::Safe;
        }
        let st = self.state.lock().await;
        if !st.enabled {
            QuitCheck::WouldLose {
                items,
                reason: LossReason::Disabled,
            }
        } else if !st.restored || !self.vault.is_unlocked().await {
            QuitCheck::WouldLose {
                items,
                reason: LossReason::VaultLocked,
            }
        } else {
            QuitCheck::Safe
        }
    }

    async fn save_logged(&self) {
        match self.save_now().await {
            Ok(outcome) => tracing::trace!(?outcome, "queue save"),
            Err(e) => tracing::warn!(error = %e, "could not save the transfer queue"),
        }
    }

    /// Runs the debounced writer until `cancel` fires, then makes the final
    /// write. The first change after a write starts the window; changes
    /// within it are written together at its end.
    pub fn spawn(self: &Arc<Self>, cancel: CancellationToken) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    () = this.notify.notified() => {}
                }
                tokio::select! {
                    () = cancel.cancelled() => break,
                    () = tokio::time::sleep(this.debounce) => {}
                }
                this.save_logged().await;
            }
            this.save_logged().await;
        })
    }
}
