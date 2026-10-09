//! Domain logic for courier-ftp, a terminal FTP, FTPS and SFTP client.
//!
//! This crate knows nothing about the terminal. The `courier-ftp` binary owns
//! rendering, key handling and the event loop; this crate owns the domain
//! model, the `Backend` trait the protocol crates (`courier-ftp-proto-ftp`,
//! `courier-ftp-proto-sftp`) implement, settings, the vault, sites, the
//! transfer queue and engine, and the file logic (filters, comparison,
//! search, listing cache). Everything here is testable without a TTY.

use thiserror::Error;

pub mod backend;
pub mod cache;
pub mod compare;
pub mod events;
pub mod filters;
pub mod local;
pub mod model;
pub mod net;
pub mod paths;
pub mod queue;
pub mod search;
pub mod settings;
pub mod sites;
pub mod transfer;
pub mod vault;

/// Errors produced by the core.
///
/// The `courier-ftp` crate converts these into `color_eyre` reports at the boundary,
/// which is why this enum carries no formatting or reporting concerns of its own.
/// T02 replaces this placeholder with the real error type.
#[derive(Debug, Error)]
pub enum Error {
    /// The core was asked to do something its current state does not allow.
    #[error("invalid state transition: {0}")]
    InvalidState(String),
}

/// Convenience alias used throughout this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;
