//! Sync client for courier-ftp (T87, T88): account registration and login,
//! devices and recovery, and the pull/push engine with live updates.
//!
//! Optional: the `courier-ftp` binary links this crate only with its `sync`
//! feature (on by default). Everything works without it, and a build with
//! `--no-default-features` contains no network sync code at all.
//!
//! Adapted from sverb's `sverb-sync` (D13), without terminal sharing and team
//! administration (T89).
//!
//! # Entry points
//! * [`account`]: register ([`account::prepare_registration`],
//!   [`account::finish_registration`]), log in ([`account::start_login`],
//!   [`account::LoginSession::commit`]), recover
//!   ([`account::recover_locked_device`]); each gives a [`SyncSession`].
//! * [`SyncSession`]: the signed-in device after unlock
//!   ([`SyncSession::open`]): devices, password change, TOTP, logout,
//!   account deletion.
//!
//! The LMK never leaves the vault engine
//! (`courier_ftp_store::vault::VaultEngine`): tokens and account keys are
//! sealed through its sync API.

pub mod account;
pub mod error;
pub mod http;
mod session;
pub mod tokens;

pub use account::{AccountConfig, AccountError};
pub use error::SyncError;
pub use http::ApiClient;
pub use session::{Revoked, SyncSession, TotpSetup};
pub use tokens::TokenManager;
