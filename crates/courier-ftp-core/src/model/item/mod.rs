//! The vault's item model (T81, D4): field-stamped [`ItemBody`]s, the HLC that
//! stamps them, a field-level merge, schema migrations and typed views per
//! [`ItemKind`]. Adapted from sverb's `sverb-core::model` (D13).
//!
//! - Every write goes through [`ItemBody::set`] and is HLC-stamped; writing an
//!   unchanged value creates no stamp.
//! - Nested values are flattened to dotted keys (`logon.user`); lists are single
//!   values.
//! - Typed views ([`Site`], [`Bookmark`], …) are read with [`ItemView::from_body`]
//!   and written back with [`ItemView::apply_to`], which only touches fields that
//!   changed and never drops keys the view doesn't know.
//! - [`ItemBody::to_cbor`] gives the deterministic bytes that
//!   `courier_ftp_crypto::envelope::seal_item` encrypts.
//! - [`merge()`] is commutative, associative and idempotent, so two devices editing
//!   offline converge (`tests/merge_props.rs`).
//! - The store persists [`HlcClock::last`] in `meta.hlc_last` and resumes with
//!   [`HlcClock::with_last`], so stamps stay monotonic across restarts.

mod body;
mod fields;
mod hlc;
mod ids;
mod kinds;
pub mod merge;
pub mod migrate;
mod views;

#[cfg(test)]
mod tests;

pub use body::{BodyCodecError, ItemBody, SECRET_FIELDS, Stamped, is_secret_field};
pub use fields::{ViewError, WireEnum};
pub use hlc::{ClockSkew, Hlc, HlcClock, MAX_SKEW, ManualClock, PhysicalClock, SystemClock};
pub use ids::{DeviceId, IdGen, IdParseError, ItemId, OrgId, SeqGen, UserId, V7Gen, VaultId};
pub use kinds::ItemKind;
pub use merge::{MergeOutcome, SchemaOutcome, merge, merge_all};
pub use migrate::{CURRENT_SCHEMA, MigrateOutcome, current_schema, is_read_only, migrate};
pub use views::{
    Bookmark, CredentialOverride, HistoryEntry, ItemView, KnownHost, LogonKind, ProxyCredential,
    ServerType, Site, SiteColor, SiteFolder, SiteTransferMode, SshKey, TrustedCert, UnixMillis,
};
