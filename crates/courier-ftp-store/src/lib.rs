//! Encrypted SQLite store for courier-ftp items (T82, D4): sites, bookmarks,
//! history, trusted host keys and certificates, SSH keys, each item encrypted on
//! its own so items can sync and merge, plus sync bookkeeping and device-local
//! data (the transfer queue, frecency, local directory overrides). Adapted from
//! sverb's `sverb-store` (D13).
//!
//! - [`Store`] owns one writer connection (behind a `tokio::sync::Mutex`, IMMEDIATE
//!   transactions) and a pool of [`READER_POOL_SIZE`] read-only connections; every
//!   connection runs with WAL, `synchronous = NORMAL`, `foreign_keys = ON`,
//!   `busy_timeout = 5000` and `temp_store = MEMORY`; all SQLite work runs in
//!   `spawn_blocking`. The data directory is mode `0700` and the database file and
//!   its `-wal`/`-shm` siblings `0600` on Unix.
//! - Schema migrations live in `crates/courier-ftp-store/migrations/` and run
//!   transactionally on open. A database from a newer courier-ftp is refused with
//!   [`StoreError::NewerSchema`] and left untouched.
//! - Typed repositories ([`MetaRepo`], [`VaultRepo`], [`ItemRepo`], [`OutboxRepo`],
//!   [`SyncStateRepo`], [`DeviceLocalRepo`], [`DeviceBlobRepo`], [`PinRepo`],
//!   [`ApprovalRepo`]) give async one-shot access (`store.items().put(…)`). The
//!   same operations exist as methods on [`WriteTx`] / [`ReadTx`] for combining
//!   several in one transaction via [`Store::write`] / [`Store::read`].
//! - **Every local item write** marks the item dirty and upserts its outbox row in
//!   the same transaction, whether or not sync is on, so enabling sync later
//!   pushes everything that exists.
//! - **The store only handles ciphertext.** Item bodies arrive as envelopes sealed
//!   by `courier-ftp-crypto` (checked on every write); wrapped keys and tokens
//!   arrive already wrapped. Decrypted search labels may only go to the TEMP
//!   `item_index` ([`search`]), which lives in memory.

pub mod approvals;
pub mod clock;
pub mod db;
pub mod device_blobs;
pub mod device_local;
pub mod error;
pub mod items;
pub mod meta;
pub mod outbox;
pub mod pins;
pub mod schema;
pub mod search;
pub mod sync_state;
pub mod vaults;

pub use approvals::{ApprovalRepo, LocalApproval};
pub use clock::{Clock, ManualClock, SystemClock};
pub use db::{DB_FILE_NAME, READER_POOL_SIZE, ReadTx, Store, WriteTx};
pub use device_blobs::DeviceBlobRepo;
pub use device_local::{DeviceLocal, DeviceLocalRepo};
pub use error::{Result, StoreError};
pub use items::{ItemRepo, ItemRow, RemoteItem, check_envelope, check_local_envelope};
pub use meta::MetaRepo;
pub use outbox::{OutboxRepo, OutboxRow};
pub use pins::{KeyChange, PinObservation, PinRepo, PinState, PinnedKey, SetVerified};
pub use schema::SCHEMA_VERSION;
pub use search::IndexRow;
pub use sync_state::{SyncState, SyncStateRepo};
pub use vaults::{VaultKind, VaultRepo, VaultRow};
