//! Site model and storage (T31): the data behind the Site Manager.
//!
//! A folder tree ([`SiteTree`] of [`SiteNode`]s) of [`Site`]s with every
//! setting FileZilla has per site, stored in the vault (D4): each site is a
//! `site` item and each folder a `site-folder` item (T81), pointing to their
//! parent folder by id. The tree is rebuilt from the items on unlock
//! ([`SiteManager::load`]) and after a sync ([`SiteManager::reload`]).
//!
//! # Where each field is stored
//!
//! - In the encrypted, synced item: everything in [`Site::to_item`],
//!   **including passwords, the FTP account and key passphrases** (fields
//!   `logon.*`, see [`crate::model::item`] for the wire names).
//! - Device-local ([`SiteLocal`], the store's `device_local` table, never
//!   synced): the default local directory, a key file path on disk and the
//!   last connect time. Local paths differ per machine; a key that should
//!   work on every device is imported into the vault as an `ssh-key` item
//!   and referenced with [`SiteKey::Vault`] (`logon.key_id`).
//! - Not stored: whether a folder is expanded (kept across reloads).
//!
//! # Passwords
//!
//! - [`SiteLogon`] holds only the secrets its logon type has. Changing the
//!   type ([`SiteLogon::with_kind`]) drops the others, and saving writes them
//!   as null, which erases them on every device once the change syncs.
//! - With `vault.store_passwords = false` the vault engine erases site
//!   password fields on every write ([`crate::vault::strip_passwords`]).
//!   The manager re-reads each site after writing it, so the tree shows a
//!   `None` password and [`Site::to_connect_info`] turns Normal into "ask
//!   for password".
//!
//! # API for later tasks
//!
//! **Site Manager UI (T59)**
//! - [`SiteManager::load`]`(vault, local)` after unlock; `tree()` and
//!   [`SiteTree::visible_rows`] for the left pane, `set_expanded`/`reveal`.
//! - Editing: clone a [`Site`] from `site(id)`, change fields, compare with
//!   the original (`PartialEq`, secrets included) for the dirty marker,
//!   show [`Site::validate`] issues inline (by [`SiteField`]), save with
//!   [`SiteManager::save_site`] (refuses errors, returns warnings).
//!   [`logon_kinds`] lists the logon types per protocol; changing the type
//!   goes through [`SiteLogon::with_kind`].
//! - New site: [`Site::new`] with `parent` set, then `save_site`. New
//!   folder: [`SiteManager::add_folder`]. Rename, cut/paste
//!   ([`SiteManager::move_node`]; a folder into itself or a subfolder is
//!   refused), duplicate, delete (confirm with [`SiteNode::count`]).
//! - Key picker: [`SiteManager::ssh_keys`].
//! - Connect: [`SiteManager::connect`]`(id)` gives a [`SiteConnect`] — the
//!   `ConnectInfo` for the `BackendFactory` (with a vault SSH key and saved
//!   passphrase already filled in) plus the default directories and modes
//!   to apply. After the session is up, [`SiteManager::record_connected`].
//!
//! **Bookmarks and history (T33)**: site bookmarks reference
//! [`Site::id`]; "convert quickconnect entry to site" builds a [`Site`]
//! (`Site::new` + logon) and calls `save_site` with `parent = None`;
//! "recent servers" reads `last_connected_at` ([`SiteLocalStore`]); when a
//! site is deleted its device-local row is removed.
//!
//! **Import/export (T32)**: build [`Folder`]/[`Site`] values, pick free names
//! with [`SiteTree::unique_name`], create folders with `add_folder` and sites
//! with `save_site`. Export walks [`SiteTree::walk`] / [`SiteTree::path_of`];
//! the full site, passwords and local paths included, is in [`Site`].
//!
//! **CLI `--site` (T70)**: [`SiteManager::find_site`]`("Work/Production/web01")`.
//!
//! **Team vaults (T89)**: nodes carry their [`VaultId`](crate::model::item::VaultId);
//! new items go into their folder's vault, moving between vaults is refused
//! ([`SiteError::CrossVault`]). Credential overrides are not applied yet.
//!
//! # Schema changes
//!
//! A new site field is added to the item view ([`crate::model::item::Site`],
//! a new dotted key) and to [`Site`] with its default when absent; older
//! builds keep unknown keys when they write. A change older builds must not
//! write bumps the `site` schema version in
//! [`item::migrate`](mod@crate::model::item::migrate) with a migration step; items from a newer
//! schema load read-only ([`Site::read_only`]). Device-local columns are
//! added with a new store migration (`courier-ftp-store/migrations/`).

mod error;
mod site;
mod store;
mod tree;
mod validate;

#[cfg(test)]
mod tests;

pub use error::SiteError;
pub use site::{Site, SiteConnect, SiteKey, SiteLocal, SiteLogon, path_style};
#[cfg(any(test, feature = "test-util"))]
pub use store::MemSiteLocalStore;
pub use store::{SiteLocalStore, SiteManager};
pub use tree::{COPY_SUFFIX, Folder, SiteNode, SiteTree, TreeRow};
pub use validate::{
    CONNECTION_LIMITS, MAX_TIMEZONE_OFFSET_MINUTES, NameError, Severity, SiteField, SiteIssue,
    logon_kinds, validate_name,
};
