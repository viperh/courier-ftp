//! The local SQLite store of individually encrypted items (T82, adapted
//! from sverb).
//!
//! Holds the vault's items (sites, bookmarks, history, trusted keys), the
//! device-local transfer queue and the sync bookkeeping.
//!
//! Layering: core -> store -> crypto. Depends only on `courier-ftp-crypto`,
//! never on `courier-ftp-core`.
