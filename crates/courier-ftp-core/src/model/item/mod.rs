//! The vault item model (T81; copied and adapted from sverb `model/`, D13).
//!
//! Everything stored in the vault (sites, folders, bookmarks, trusted host keys and
//! certificates, SSH keys, proxy credentials, credential overrides, history) is an
//! [`ItemBody`]: a [`ItemKind`], a schema version, a map of field-level
//! last-writer-wins registers ([`Stamped`] with an [`Hlc`] and a [`DeviceId`]) and a
//! tombstone. Two devices that edit offline converge with [`merge()`] regardless of
//! delivery order.
//!
//! - Every write goes through [`ItemBody::set`] and is HLC-stamped; writing an
//!   unchanged value creates no stamp.
//! - Nested settings are flattened to dotted keys (`proxy.host`); lists are whole-value
//!   registers.
//! - Typed views ([`KnownHostItem`], …) implement [`ItemView`]; writing one back only
//!   touches changed fields and never drops keys the view does not know.
//! - [`ItemBody::to_cbor`] gives the deterministic bytes that
//!   `courier_ftp_crypto::envelope::seal_item` encrypts.
//!
//! Field names, CBOR shapes and enum strings of every kind are in `docs/data-model.md`.
//! Logs from this module carry kinds and field names only, never values.

mod body;
mod hlc;
mod kinds;
mod merge;
mod migrate;
mod refs;
pub(crate) mod view;
mod views;

pub use crate::model::ids::{
    DeviceId, IdGen, IdParseError, ItemId, OrgId, SeqGen, UnixMillis, UserId, V7Gen, VaultId,
};
pub use body::{BodyCodecError, ItemBody, SECRET_FIELDS, Stamped, is_secret_field};
pub use hlc::{ClockSkew, Hlc, HlcClock, MAX_SKEW, ManualClock, PhysicalClock, SystemClock};
pub use kinds::ItemKind;
pub use merge::{MergeOutcome, SchemaOutcome, merge, merge_all};
pub use migrate::{
    CURRENT_SCHEMA, MigrateOutcome, Migration, current_schema, is_read_only, migrate,
};
pub use refs::{OVERRIDE_SITE_FIELD, RefError, check_vault_refs, references};
pub use view::{FieldReader, FieldWriter, ItemView, SecretField, ViewError, WireEnum};
pub use views::known_host::{DEFAULT_SSH_PORT, KnownHostItem};
pub use views::proxy_credential::{ProxyCredentialItem, ProxyScope};
pub use views::ssh_key::{MAX_PRIVATE_KEY, SshKeyAlgorithm, SshKeyFormat, SshKeyItem};
pub use views::trusted_cert::{MAX_CERT_DER, TrustedCertItem};
