//! Store errors.

use rusqlite::ErrorCode;
use thiserror::Error;

/// Errors returned by the store.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The database was written by a newer courier-ftp. It was not modified.
    #[error(
        "This database was created by a newer courier-ftp (schema {found}). Please update \
         courier-ftp. (this build supports schema {supported})"
    )]
    NewerSchema {
        /// `PRAGMA user_version` found in the file.
        found: i64,
        /// The latest schema version this build knows.
        supported: i64,
    },

    /// Another connection or process held a lock for longer than `busy_timeout`.
    #[error("the database is busy (another courier-ftp may be writing); try again")]
    Busy,

    /// The addressed row does not exist.
    #[error("not found")]
    NotFound,

    /// The file is not a SQLite database, is damaged, or holds a value this
    /// build cannot have written.
    #[error(
        "the database is corrupt: {0}. Restore it from a backup (or move it away to start fresh)"
    )]
    Corrupt(String),

    /// A value handed to the store does not look encrypted. The store refuses it
    /// so plaintext cannot reach disk by mistake.
    #[error("refusing to store an invalid envelope: {0}")]
    InvalidEnvelope(&'static str),

    /// A value exceeds its size limit (device blobs, [`crate::MAX_DEVICE_BLOB_LEN`]).
    #[error("value too large to store")]
    TooLarge,

    /// A migration failed for a reason other than a SQLite error. The database
    /// stays at its previous version (migrations are transactional).
    #[error("database migration failed: {0}")]
    Migration(String),

    /// Filesystem error while preparing the database file.
    #[error("database file: {0}")]
    Io(#[from] std::io::Error),

    /// Any other SQLite error.
    #[error(transparent)]
    Sqlite(rusqlite::Error),

    /// A blocking task was cancelled (or the reader pool is gone).
    #[error("store task failed: {0}")]
    Task(String),
}

/// Convenience alias.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> Self {
        match err.sqlite_error_code() {
            Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => Self::Busy,
            Some(ErrorCode::DatabaseCorrupt) => {
                Self::Corrupt("database disk image is malformed".into())
            }
            Some(ErrorCode::NotADatabase) => Self::Corrupt("file is not a SQLite database".into()),
            _ => Self::Sqlite(err),
        }
    }
}

impl From<rusqlite_migration::Error> for StoreError {
    fn from(err: rusqlite_migration::Error) -> Self {
        match err {
            rusqlite_migration::Error::RusqliteError { err, .. } => err.into(),
            other => Self::Migration(other.to_string()),
        }
    }
}

/// `bytes` as a 16-byte id, or [`StoreError::Corrupt`] naming the column.
pub(crate) fn id16(bytes: Vec<u8>, what: &str) -> Result<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt(format!("{what} is not a 16-byte id")))
}

/// `value` as a `u32`, or [`StoreError::Corrupt`] naming the column.
pub(crate) fn u32_col(value: i64, what: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| StoreError::Corrupt(format!("{what} is out of range")))
}

/// A non-negative count from SQLite.
pub(crate) fn count(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| StoreError::Corrupt("negative row count".into()))
}
