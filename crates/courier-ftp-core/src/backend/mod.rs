//! The [`Backend`] trait every protocol implements, and what surrounds it (T03).
//!
//! FTP/FTPS (`courier-ftp-proto-ftp`), SFTP (`courier-ftp-proto-sftp`) and the local
//! filesystem ([`crate::local`]) implement [`Backend`], so the UI, the transfer engine,
//! search, comparison and recursive operations never care which protocol is in use.
//! Around the trait:
//!
//! - [`ConnectInfo`]: everything needed to open sessions to one server;
//! - [`BackendFactory`]: creates a backend for a [`ConnectInfo`] (implemented by the
//!   binary, D5; core never names the protocol crates);
//! - [`SessionHandle`]: a backend behind a mutex with connect retries, reconnect-once,
//!   keep-alive and cancellation;
//! - `mock` and `conformance` (feature `test-util`): an in-memory server and the
//!   reusable backend conformance suite ([`backend_conformance_tests!`](crate::backend_conformance_tests)).
//!
//! # Async style
//!
//! The trait uses `#[async_trait::async_trait]`. Native `async fn` in traits is not
//! dyn-compatible, and the protocol is chosen at runtime, so callers hold a
//! `Box<dyn Backend>`. The one boxed future per call is negligible next to network I/O.
//!
//! # Cancellation convention (all of core)
//!
//! The two long-running methods, [`Backend::connect`] (may wait for user prompts) and
//! [`Backend::list`] (large directories), take a [`CancellationToken`] and return
//! [`Error::Cancelled`](crate::Error::Cancelled) within 100 ms of it firing. Every other
//! method is cancelled by dropping its future. Top-level entry points
//! ([`SessionHandle`] methods, engine tasks) take `&CancellationToken`, pass child tokens
//! to `connect`/`list`, and `select!` on the token for the rest. A backend stays
//! consistent when a future is dropped at any `.await`: afterwards it is either usable
//! or reports `is_connected() == false` (the [`SessionHandle`] then reconnects). Every
//! network wait inside a backend is bounded by `connection.timeout_secs` of inactivity.
//!
//! # Transfer protocol (all backends)
//!
//! 1. At most one open stream per backend. While a stream is open, every method except
//!    `finish_transfer`, `capabilities`, `address`, `is_connected` and `security_info`
//!    returns `Error::Internal("transfer in progress")`.
//! 2. Read: read until `Ok(0)` (EOF, also after `range_len` bytes), drop the stream, call
//!    `finish_transfer(Complete)`. Stopping early: drop the stream,
//!    `finish_transfer(Abort)`.
//! 3. Write: write everything, `shutdown().await`, drop, `finish_transfer(Complete)`. The
//!    upload counts as successful only when `finish_transfer` returns Ok.
//! 4. If a stream is dropped and `finish_transfer` is never called, the next method call
//!    performs the `Abort` cleanup first.
//! 5. `TransferType::Ascii` on a backend without `ascii_mode` is treated as Binary.
//!
//! # Listing hygiene
//!
//! Backends drop entries whose names fail
//! [`Entry::is_valid_name`](crate::model::Entry::is_valid_name) (including "." and ".."),
//! keep the first of duplicate names, and log one Status line per listing with the
//! number dropped. [`Listing::build`] does all of that.
//!
//! [`CancellationToken`]: tokio_util::sync::CancellationToken

mod connect_info;
mod factory;
mod session;
mod types;

#[cfg(any(test, feature = "test-util"))]
pub mod conformance;
#[cfg(any(test, feature = "test-util"))]
pub mod mock;

#[cfg(test)]
mod session_tests;
#[cfg(test)]
mod tests;

pub use connect_info::{ConnectInfo, ProxyChoice, TransferModeOverride};
pub use factory::{BackendContext, BackendFactory};
pub use session::{BackendGuard, SessionHandle, SessionOptions, SessionState};
pub use types::{
    Backend, Capabilities, Listing, ReadStream, SessionSecurityInfo, TransferEnd, TransferOpts,
    WriteMode, WriteStream,
};
