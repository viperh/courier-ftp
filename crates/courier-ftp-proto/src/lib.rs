//! The sync protocol: request, response and live-update types shared by
//! `courier-ftp-sync` and `courier-ftp-server` (T83, adapted from sverb).
//!
//! Layering: depends only on `courier-ftp-crypto`; used by `core`, `sync` and
//! the server.
