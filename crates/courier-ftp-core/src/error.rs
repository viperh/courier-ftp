//! Errors produced by the core (placeholder until T02 replaces it).

/// Errors produced by the core.
///
/// The `courier-ftp` crate converts these into `color_eyre` reports at the boundary,
/// which is why this enum carries no formatting or reporting concerns of its own.
/// T02 replaces this placeholder with the real error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The core was asked to do something its current state does not allow.
    #[error("invalid state transition: {0}")]
    InvalidState(String),
}

/// Convenience alias used throughout this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;
