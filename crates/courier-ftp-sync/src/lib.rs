//! Sync client for courier-ftp (T87, T88): account registration and login,
//! devices and recovery, and the pull/push engine with live updates.
//!
//! Optional: the `courier-ftp` binary links this crate only with its `sync`
//! feature (on by default). Everything works without it, and a build with
//! `--no-default-features` contains no network sync code at all.
//!
//! Adapted from sverb's `sverb-sync` (D13), without terminal sharing.
//!
//! # Entry points
//! * [`account`]: register ([`account::prepare_registration`],
//!   [`account::finish_registration`]), log in ([`account::start_login`],
//!   [`account::LoginSession::commit`]), recover
//!   ([`account::recover_locked_device`]); each gives a [`SyncSession`].
//! * [`SyncSession`]: the signed-in device after unlock
//!   ([`SyncSession::open`]): devices, password change, TOTP, logout,
//!   account deletion, and the sync engine
//!   ([`SyncSession::start_engine`] → [`SyncHandle`]: status, events, sync
//!   now, item errors; stop it on lock or logout).
//! * [`info::local_info`]: the local sync state without network or keys.
//! * [`teams`]: orgs, members, invites, audit, team vaults, trust (pins,
//!   safety numbers) and key rotation ([`SyncSession::teams`] → [`Teams`];
//!   the API of the Settings → Teams screens). [`trust`] holds the grant
//!   verification rules, [`rotation`] the rotation protocol.
//!
//! The LMK never leaves the vault engine
//! (`courier_ftp_store::vault::VaultEngine`): tokens and account keys are
//! sealed through its sync API.

pub mod account;
pub mod engine;
pub mod error;
pub mod http;
pub mod info;
mod pull;
mod push;
pub mod rotation;
mod session;
mod shared;
pub mod status;
pub mod teams;
pub mod tokens;
pub mod trust;
pub mod ws;

pub use account::{AccountConfig, AccountError};
pub use engine::{EngineConfig, MAX_CONFLICT_ROUNDS, SyncEngine, SyncHandle, SyncPolicy};
pub use error::SyncError;
pub use http::ApiClient;
pub use rotation::{RotationError, RotationOptions, RotationProgress, RotationReport};
pub use session::{Revoked, SyncSession, TotpSetup};
pub use status::{SyncEvent, SyncStatus, ToastLevel};
pub use teams::{MemberEntry, OrgVaultEntry, TeamError, Teams};
pub use tokens::TokenManager;
pub use trust::{Trust, TrustError};
