//! The local SQLite store of individually encrypted items (T82, adapted
//! from sverb `crates/sverb-store`).
//!
//! One database file holds the vaults' encrypted items, the vault keys wrapped
//! under the LMK, the sync bookkeeping (outbox, cursors, sync state) and
//! device-local data (frecency, device blobs such as the transfer queue, TOFU
//! key pins, local approvals).
//!
//! - [`Store`] owns one writer connection (behind a `tokio::sync::Mutex`) and a
//!   pool of [`READER_POOL_SIZE`] read-only connections; every connection runs
//!   with WAL, `synchronous = NORMAL`, `foreign_keys = ON`,
//!   `busy_timeout = 5000` and `temp_store = MEMORY`. On Unix the database file
//!   and its `-wal`/`-shm` siblings are mode `0600`, the directory `0700`. On
//!   Windows the file inherits the ACL of the user profile directory
//!   (`%LOCALAPPDATA%`).
//! - Schema migrations live in `crates/courier-ftp-store/migrations/` and run
//!   transactionally on open. A database from a newer courier-ftp is refused with
//!   [`StoreError::NewerSchema`] and left untouched.
//! - The repository API exists twice: as async one-shot methods on [`Store`],
//!   and as methods on [`WriteTx`] / [`ReadTx`] for combining several
//!   operations in one transaction via [`Store::write`] / [`Store::read`].
//! - **The store only handles ciphertext.** Item bodies arrive as envelopes
//!   sealed by `courier-ftp-crypto` (checked on every write by
//!   [`check_envelope`]); wrapped keys, tokens and device blobs arrive already
//!   sealed. The store never decrypts anything.
//!
//! Layering: core -> store -> crypto. Depends only on `courier-ftp-crypto`,
//! never on `courier-ftp-core`; ids cross the API as [`Id16`].

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
pub mod sync_state;
pub mod vaults;

/// A 16-byte id (UUID bytes) as it crosses the store API.
pub type Id16 = courier_ftp_crypto::canon::Id16;

pub use approvals::LocalApproval;
pub use clock::{Clock, ManualClock, SystemClock};
pub use db::{BUSY_TIMEOUT_MS, READER_POOL_SIZE, ReadTx, Store, WriteTx};
pub use device_blobs::MAX_DEVICE_BLOB_LEN;
pub use device_local::DeviceLocal;
pub use error::{Result, StoreError};
pub use items::{ItemMarker, ItemRow, MAX_ENVELOPE_LEN, PutItem, RemoteItem, check_envelope};
pub use outbox::OutboxRow;
pub use pins::{
    KeyChange, PinObservation, PinState, PinTrust, PinnedKey, SetVerified, VerifyOutcome,
};
pub use schema::{SCHEMA_VERSION, TABLES};
pub use sync_state::SyncState;
pub use vaults::{VaultKind, VaultRow};
