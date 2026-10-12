//! Wire types of the courier-ftp sync protocol (T83), shared by the sync client
//! (`courier-ftp-sync`, T87/T88) and the server (`courier-ftp-server`, T84–T86).
//!
//! Serde only: no I/O, no async runtime, no HTTP stack. Adapted from sverb's
//! `sverb-proto` (D13) without its terminal-sharing messages.
//!
//! # Conventions
//!
//! * HTTPS + JSON under [`version::API_PREFIX`] (`/v1`). Every module lists its
//!   endpoints with the request and response types.
//! * Binary fields (OPAQUE messages, keys, envelopes, grants, signatures,
//!   encrypted names) are base64url **without padding**, see [`b64`].
//! * Ids are [`uuid::Uuid`]s; they are the same values as
//!   `courier_ftp_core::model::item::{ItemId, VaultId, DeviceId, OrgId, UserId}`
//!   (convert with `from_uuid` / `uuid()`). This crate may not depend on core
//!   (the server must not link client crates), hence plain UUIDs here.
//! * Timestamps are RFC 3339 strings (`time::OffsetDateTime`).
//! * Requests carry [`version::PROTO_HEADER`] (`Courier-Proto: 1`); the server
//!   accepts the current version and the previous one ([`version::negotiate`])
//!   and echoes [`version::REQUEST_ID_HEADER`].
//! * Every non-2xx response has an [`ErrorEnvelope`] body; `429` also sets
//!   `Retry-After`.
//! * Size limits are in [`limits`]; [`sync::PushRequest::check_limits`] and
//!   [`sync::PullQuery::effective_limit`] apply them.
//!
//! # Secrets
//!
//! Types holding tokens, TOTP codes or recovery codes are plain `String`s on
//! the wire but print `[REDACTED]` in `Debug`. Receivers should move them into
//! `secrecy` types right away.

// Conventions: error envelope, versioning, limits, base64url.
pub mod b64;
pub mod error;
pub mod limits;
pub mod version;

// Accounts, login, devices.
pub mod auth;

// Vault list, pull and push.
pub mod sync;

// Team vaults (T89): user keys, orgs and invites, shared vaults, key rotation.
pub mod orgs;
pub mod rotation;
pub mod users;
pub mod vaults;

// `/v1/ws` notifications.
pub mod ws;

pub use error::{ErrorBody, ErrorCode, ErrorEnvelope};
pub use limits::LimitError;
pub use version::VersionError;
