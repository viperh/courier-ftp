# T31 — Site model and storage

**Phase:** D Vault & sites · **Milestone:** M5 · **Depends on:** T02, T03, T30, T81, T82 · **Crate(s):** `courier-ftp-core` (`sites` module) · **Decisions:** D4, D14 · **FEATURES.md:** §2 (Site Manager: folder tree, copy/rename/duplicate/move, General / Advanced / Transfer settings / Charset tabs, background colour, password storage options)
**Related (integrates with, not blocking):** T70, T88, T89

## Goal

The data model and operations behind the Site Manager: a folder tree of sites with every
setting FileZilla's Site Manager exposes per site, stored as encrypted, mergeable vault items
(passwords included), plus the conversion of a saved site into the `ConnectInfo` a backend
receives. Sites survive restarts, sync between devices (T88) and can be shared in team vaults
(T89) without changes to this model.

## Context

- Before: T02 (`Protocol`, `FtpEncryption`, `ServerAddress`, `LogonType`, `LogonKind`,
  `KeySource`, `Charset`, `ServerTypeOverride`, `RemotePath`, `LocalPath`, `Error`),
  T03 (`ConnectInfo`, `BackendFactory`), T30 (`VaultEngine`: `list`/`get`/`put`/`delete_many`/
  `get_body`/approvals, device-local helpers, `VaultChange`), T81 (`ItemView`, `FieldWriter`,
  `SecretField`, the `site` / `site-folder` / `credential-override` field tables, `SshKeyItem`,
  `ProxyCredentialItem`), T82 (`device_local.local_dir_override`, `tree_expanded`).
- After: T59 (Site Manager screen) edits through `SiteManager`; T32 imports/exports trees;
  T33 attaches bookmarks to `SiteId`s and converts history entries into sites; T40 stores
  `QueueServer::Site { site_id }`; T58/T61 connect through `SiteManager::connect_info`; T64
  uses `SiteId`; T70 resolves `--site` paths through `SiteTree::lookup_path`; T88 and T89 sync
  and share the items unchanged.

## Technical specification

### Types and APIs

Module `courier_ftp_core::sites` (files `model.rs`, `tree.rs`, `manager.rs`, `connect.rs`,
`validate.rs`).

```rust
pub type SiteId = ItemId;
pub type FolderId = ItemId;

/// FileZilla's background colours (§2), used as tab and pane accent (T57, T61).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SiteColor { #[default] None, Red, Green, Blue, Yellow, Cyan, Magenta, Orange }

/// Transfer settings tab: Default = global `ftp.transfer_mode` (T05).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SiteTransferMode { #[default] Default, Active, Passive }

/// One Site Manager entry (`site` item, T81 field table). No Clone (secrets): use `duplicate()`.
pub struct Site {
    pub name: String,
    pub parent: Option<FolderId>,
    // General tab
    pub protocol: Protocol,
    pub encryption: FtpEncryption,
    pub host: String,
    pub port: Option<u16>,
    pub logon: LogonKind,
    pub user: String,
    pub password: SecretField,
    pub account: SecretField,
    pub key_file: Option<String>,          // local path as typed, "~" allowed
    pub ssh_key_id: Option<ItemId>,        // ssh-key item; wins over key_file
    pub key_passphrase: SecretField,
    pub try_agent_first: bool,
    pub color: SiteColor,
    pub comments: String,
    // Advanced tab
    pub server_type: ServerTypeOverride,
    pub bypass_proxy: bool,
    pub remote_dir: Option<RemotePath>,
    pub sync_browsing: bool,
    pub directory_comparison: bool,
    pub timezone_offset_minutes: i32,
    // Transfer settings tab
    pub transfer_mode: SiteTransferMode,
    pub connection_limit: Option<u8>,
    // Charset tab
    pub charset: Charset,
    pub created_at: UnixMillis,
}
impl Site {
    pub fn new(name: impl Into<String>, protocol: Protocol, host: impl Into<String>) -> Self;
    pub fn duplicate(&self) -> Self;                       // deep copy, secrets re-wrapped
    /// Clears credential fields the logon type does not use (rules below).
    pub fn normalize_for_logon(&mut self);
    pub fn effective_port(&self) -> u16;                   // via ServerAddress rules (21/990/22)
}
impl ItemView for Site { const KIND: ItemKind = ItemKind::Site; .. }
impl fmt::Debug for Site;                                  // secrets [REDACTED]

pub struct SiteFolder { pub name: String, pub parent: Option<FolderId>, pub created_at: UnixMillis }
impl ItemView for SiteFolder { const KIND: ItemKind = ItemKind::SiteFolder; .. }

/// A team member's own credentials for a shared site (personal vault, T89, T81 table).
pub struct CredentialOverride {
    pub shared_site_id: SiteId,
    pub user: Option<String>, pub password: SecretField, pub account: SecretField,
    pub logon: Option<LogonKind>, pub key_file: Option<String>, pub ssh_key_id: Option<ItemId>,
    pub key_passphrase: SecretField,
}
impl ItemView for CredentialOverride { const KIND: ItemKind = ItemKind::CredentialOverride; .. }

/// Device-local site data (T82 device_local), never synced.
pub struct SiteLocal { pub default_local_dir: Option<LocalPath>, pub last_connected_at: Option<i64>, pub expanded: Option<bool> }

// ---- tree.rs (pure) ----
pub enum SiteNode { Folder(FolderNode), Site(SiteEntry) }
pub struct FolderNode { pub id: FolderId, pub vault: VaultId, pub name: String, pub expanded: bool,
                        pub read_only: bool, pub children: Vec<SiteNode> }
pub struct SiteEntry { pub id: SiteId, pub vault: VaultId, pub site: Site /* secrets Kept/Absent */,
                       pub local: SiteLocal, pub read_only: bool }
pub struct VaultRoot { pub vault: VaultId, pub label: String, pub permission: VaultPermission,
                       pub children: Vec<SiteNode> }
pub struct SiteTree { pub roots: Vec<VaultRoot>, pub warnings: Vec<TreeWarning> }
pub enum TreeWarning { DuplicateName { parent: Option<FolderId>, name: String, ids: Vec<ItemId> },
                       CycleBroken { folder: FolderId }, MissingParent { item: ItemId } }
impl SiteTree {
    pub fn build(vaults: &[VaultInfo], folders: Vec<Loaded<SiteFolder>>, sites: Vec<Loaded<Site>>,
                 local: impl Fn(ItemId) -> Option<DeviceLocalInfo>) -> SiteTree;
    pub fn node(&self, id: ItemId) -> Option<&SiteNode>;
    pub fn path_of(&self, id: ItemId) -> Option<String>;           // "Work/Production/web01" or "@Team/…"
    pub fn lookup_path(&self, path: &str) -> Result<&SiteEntry, PathLookupError>;
    pub fn all_site_paths(&self) -> Vec<(String, SiteId)>;          // T70 suggestions, T59 picker
    pub fn descendants(&self, id: ItemId) -> Vec<ItemId>;           // post-order (children first)
    pub fn is_descendant(&self, ancestor: FolderId, id: ItemId) -> bool;
}
pub enum PathLookupError { NotFound, Ambiguous(Vec<SiteId>), IsFolder, UnknownVault(String) }

// ---- manager.rs ----
pub struct Location { pub vault: VaultId, pub folder: Option<FolderId> }
pub struct SiteManager { vault: VaultEngine }
impl SiteManager {
    pub fn new(vault: VaultEngine) -> Self;
    pub fn tree(&self) -> Result<SiteTree, Error>;                           // from the T30 cache
    pub async fn load_site(&self, id: SiteId) -> Result<Loaded<Site>, Error>;  // secrets loaded
    pub async fn add_site(&self, at: Location, site: Site) -> Result<SiteId, Error>;
    pub async fn update_site(&self, id: SiteId, site: Site) -> Result<(), Error>;
    pub async fn add_folder(&self, at: Location, name: &str) -> Result<FolderId, Error>;
    pub async fn rename(&self, id: ItemId, name: &str) -> Result<(), Error>;
    pub async fn delete(&self, id: ItemId) -> Result<DeleteReport, Error>;   // folders recursive
    pub async fn move_node(&self, id: ItemId, to: Location) -> Result<ItemId, Error>; // new id if vault changes
    pub async fn duplicate(&self, id: ItemId) -> Result<ItemId, Error>;
    pub async fn copy_to(&self, id: ItemId, to: Location) -> Result<CopyReport, Error>;
    pub async fn set_expanded(&self, folder: FolderId, expanded: bool) -> Result<(), Error>;
    pub async fn set_default_local_dir(&self, id: SiteId, dir: Option<LocalPath>) -> Result<(), Error>;
    pub async fn clear_saved_passwords(&self, scope: Location) -> Result<usize, Error>;
    pub async fn connect_info(&self, id: SiteId, ctx: &ConnectContext<'_>) -> Result<ConnectOutcome, Error>;
    pub async fn mark_connected(&self, id: SiteId) -> Result<(), Error>;      // touch_connected
}
pub struct DeleteReport { pub folders: usize, pub sites: usize, pub bookmarks: usize }
pub struct CopyReport { pub new_root: ItemId, pub items: usize, pub dropped_refs: Vec<(SiteId, &'static str)> }

// ---- connect.rs ----
pub struct ConnectContext<'a> { pub settings: &'a Settings }
pub enum ConnectOutcome {
    Ready(ResolvedSite),
    /// Synced values that would act on this machine and are not approved here (T91 §8).
    NeedsApproval(Vec<ApprovalRequest>),
}
pub struct ResolvedSite {
    pub info: ConnectInfo,                       // T03
    pub label: String,                           // tree path, UI only
    pub color: SiteColor,
    pub initial_local_dir: Option<LocalPath>,
    pub initial_remote_dir: Option<RemotePath>,
    pub sync_browsing: bool,
    pub directory_comparison: bool,
}
pub struct ApprovalRequest { pub site: SiteId, pub field: &'static str, pub value: String, pub value_sha256: [u8; 32] }
impl SiteManager { pub async fn approve(&self, req: &ApprovalRequest) -> Result<(), Error>; }

// ---- validate.rs ----
pub enum SiteField { Name, Host, Port, Logon, User, KeyFile, RemoteDir, TimezoneOffset,
                     ConnectionLimit, Charset, Comments }
pub struct FieldIssue { pub field: SiteField, pub message: String }
pub struct Validation { pub errors: Vec<FieldIssue>, pub warnings: Vec<FieldIssue> }
pub fn validate_site(site: &Site, siblings: &[&str]) -> Validation;
pub fn validate_name(name: &str, siblings: &[&str]) -> Result<String, String>;   // trimmed name
```

### Behaviour

**Tree model**: one root per vault the user can read: the personal vault (label "My Sites",
FileZilla's root) and one per team vault (label `@<vault name>` once T89 provides names,
`@Shared <short id>` before). Folders and sites point to their parent folder by
`parent_id`; `None` = vault root. `SiteTree::build` is pure and deterministic:
- children sorted folders first, then by name compared with Unicode simple case folding,
  ties by id (no manual ordering, as in FileZilla's sorted tree);
- a `parent_id` that is missing, deleted or in another vault → item shown at its vault root,
  `TreeWarning::MissingParent` (logged at `debug` with ids);
- parent cycles (possible after two devices move folders into each other offline and sync):
  the cycle is broken at the folder with the smallest id, which is placed at the vault root,
  `TreeWarning::CycleBroken`;
- two siblings with the same folded name (possible after sync) are both shown with a warning
  marker; path lookup returns `Ambiguous` and the UI asks the user to rename one;
- `expanded` comes from `device_local.tree_expanded` (default: roots expanded, folders
  collapsed).
The tree is rebuilt from the T30 cache on unlock and on every `VaultChange::ItemsChanged`
touching `site` or `site-folder` (cost for 5 000 sites < 20 ms, see AC).

**Names**: trimmed; 1–255 characters; no `/`, no control characters (U+0000–U+001F,
U+007F–U+009F); unique among siblings after case folding. Violations return
`Error::InvalidInput` with the message shown inline by T59.

**Path lookup** (`lookup_path`, used by T70 `--site` and the T59 picker): split on `/`, ignore
one leading `/` and empty segments; a first segment starting with `@` selects a team vault by
label, otherwise the personal vault. Each segment matches exactly (case-sensitive) first; if
none, a case-insensitive match is accepted when unique among the siblings. The last segment
must be a site (`IsFolder` otherwise). Unicode names work as typed (NFC-normalised before
comparing).

**Operations** (all through `VaultEngine`, each one vault write transaction unless stated):
- `add_site` / `add_folder`: validate, new UUIDv7 id, `put`. The `site` keys written follow
  T81's "never write a default into a missing key" rule.
- `update_site`: validate; `normalize_for_logon`; `put` (only changed fields get new stamps,
  so two devices editing different fields of one site merge cleanly).
- `rename`: name rules; `put` of the `name` field only.
- `delete`: a site → `delete_many([site] + its site bookmarks (T33))`; a folder → confirmation
  is the UI's job (T59 shows the counts from `DeleteReport`); all descendants in post-order plus
  their bookmarks in **one** `delete_many`. Undo is not provided (FileZilla has none).
- `move_node(id, to)`: same vault → write `parent_id`; moving a folder into itself or a
  descendant → `InvalidInput("cannot move a folder into itself")`; name clash in the target →
  `InvalidInput`. Different vault (team ↔ personal, T89) → `copy_to` + `delete_many` of the
  source in one `put_many` transaction; returns the new id.
- `duplicate(id)`: deep copy into the same parent with new ids (loads each site with secrets,
  so passwords are copied), name + `" (copy)"`, then `" (copy 2)"`, `" (copy 3)"`… until unique;
  site bookmarks and the device-local default local dir are copied too.
- `copy_to(id, to)`: deep copy with new ids into another location or vault. References are
  rewritten for copied items; `ssh_key_id` pointing into another vault is dropped (T81 cross-vault
  rule) and listed in `CopyReport::dropped_refs` so the UI can tell the user.
- `set_expanded`, `set_default_local_dir`: device-local only (`device_local`), never synced.
- `clear_saved_passwords(scope)`: sets `password`, `account`, `key_passphrase` to `Absent` on
  every site in the scope (one transaction); used by T68 "Delete saved passwords".

**Logon normalisation** (`normalize_for_logon`, also applied on import, T32):

| `logon` | keeps | clears (`Absent` / `None`) |
|---|---|---|
| `anonymous` | — | user (set to `anonymous` on connect), password, account, key fields |
| `normal` | user, password | account, key_passphrase |
| `ask-for-password` | user | password, account, key_passphrase |
| `interactive` | user | password, account, key_passphrase |
| `key-file` | user, key_file, ssh_key_id, key_passphrase | password, account |
| `account` | user, password, account | key_passphrase |
| `agent` | user | password, account, key_passphrase |

`key_file`/`ssh_key_id` are kept for every logon (harmless, restores the choice when the user
switches back); cleared secrets are gone from the item once the change syncs. `logon` must be
valid for the protocol (`LogonType::is_valid_for`: `anonymous`/`account` FTP only,
`key-file`/`agent` SFTP only); switching protocol in the editor resets an invalid logon to
`normal` (T59).

**Saving passwords**: with `vault.store_passwords = false` T30 never writes secret fields, and
`connect_info` treats any stored password, account and key passphrase as absent (`Normal`
behaves like `AskForPassword`; the backend prompts, T04 `Prompt::Password`).

**SSH keys in the vault**: `key_file` is a path on the device (synced as typed, `~` expanded at
connect time on each device); `ssh_key_id` references an `ssh-key` item (T81) so a key-file site
works on every synced device. `import_key_file(path) -> ItemId` (T59 "Store key in vault"
button): reads at most 64 KiB, detects the format (`openssh`, `pem`, `pkcs8`, `ppk2`, `ppk3`)
by header line, takes the public key from an unencrypted key or a sibling `.pub` file, writes an
`ssh-key` item in the site's vault and sets `ssh_key_id`.

**`connect_info(id, ctx)`** (what `BackendFactory` receives):
1. `get` the site with secrets. If it lives in a team vault, apply the
   `credential-override` from the personal vault whose `shared_site_id == id` (smallest item id
   if several): each field it sets replaces the site's.
2. **Approval check** (T91 §8, sverb SPEC §17.1): the local-acting values are `key_file` (a
   local private key used for a host someone else defined), `logon = agent` and
   `try_agent_first = true` (offers the local agent's keys). For each that is set, read the
   field's stamp from `get_body`: if the writing device is not this device and
   `is_approved(site, field, sha256(value))` is false, return `NeedsApproval` with the exact
   values. Values written on this device are approved by T30 at write time. `approve(req)`
   stores the approval; a changed value hashes differently and is asked again.
3. Build `ServerAddress::new(protocol, encryption, host, port, user)` (empty user → `None`).
4. Build `LogonType` from `logon`: `Anonymous`; `Normal { password }` (password only if
   `store_passwords`); `AskForPassword`; `Interactive`; `KeyFile { key, passphrase }` with
   `key = KeySource::Inline(ssh-key.private_key)` when `ssh_key_id` resolves, else
   `KeySource::Path(expand_tilde(key_file))`, passphrase from the `ssh-key` item or
   `key_passphrase`; `Account { password, account }`; `Agent`. A missing `ssh-key` item falls
   back to `key_file`; neither → `Error::InvalidInput("the site has no key file")`.
5. Fill the remaining `ConnectInfo` fields (T03): charset, `server_type`, timezone offset,
   transfer mode (`Default` → `settings.ftp.transfer_mode`), connection limit (`None` → global
   limits, T41), proxy choice (`bypass_proxy` → no proxy; else T05 `proxy.*` with the password
   from the `proxy-credential` item referenced by `credential_id`, absent when missing or
   locked), `try_agent_first`.
6. `initial_local_dir` = device-local default local dir; `initial_remote_dir` = `remote_dir`;
   flags and colour copied.
After a successful login the caller (T58/T61) calls `mark_connected(id)`
(`device_local.last_connected_at`, frecency).

**Validation** (`validate_site`), errors block saving, warnings do not:

| Field | Error | Warning |
|---|---|---|
| name | name rules above | — |
| host | empty after trim; > 253 bytes; whitespace, control chars, `/`, `@`; `[`/`]` are stripped from IPv6 literals before checking | — |
| port | `Some(0)` (u16 makes > 65535 impossible; the form rejects non-numbers) | — |
| logon | not valid for the protocol | — |
| key file | `key-file` logon without `key_file` and `ssh_key_id` | `key_file` does not exist on this device |
| remote dir | not an absolute path (`RemotePath::parse` fails) | — |
| timezone | outside −1440..=1440 minutes | — |
| connection limit | outside 1..=10 | — |
| charset | unknown label (`Charset::from_label`) | — |
| comments | > 65 536 bytes | — |
| user | — | empty for `normal`/`account`/`key-file`/`ask-for-password` |

**Schema evolution**: `CURRENT_SCHEMA[site] = 1`. Adding a field never bumps it (older builds
keep the unknown key, T81). A breaking change (renamed key, changed encoding) adds a migration
step `fn(ItemBody) -> ItemBody` in T81's table and bumps the version; older builds then open
such sites read-only. The procedure is documented in `docs/data-model.md`.

### Data formats and configuration

Item layouts: T81 tables `site`, `site-folder`, `credential-override` (this task implements
the views). Device-local: `device_local.local_dir_override` (site default local dir, absolute
path text), `device_local.tree_expanded` (folders), `last_connected_at`, `frecency` (T82).

Settings read: `vault.store_passwords` (T30), `ftp.transfer_mode`, `proxy.generic.*`,
`proxy.ftp_proxy.*` (T05). No new settings keys.

### Errors

| Error | When | UI (T59) |
|---|---|---|
| `Error::InvalidInput(msg)` | validation, name clash, move into descendant, missing key | inline field message |
| `Error::VaultLocked` | any operation while locked | "Unlock the vault to view sites" |
| `Error::Vault(msg)` from `ReadOnlyVault` / `ReadOnlyItem` | editing team `read` sites or newer-schema sites | fields disabled, lock icon |
| `Error::Vault(msg)` from `CrossVaultReference` | `ssh_key_id` into another vault | inline on the key field |
| `Error::NotFound`-style `InvalidInput("site not found")` | stale id (deleted on another device) | toast, tree refresh |

### Security and logging

- Passwords, account values and key passphrases are `SecretField`/`SecretString`; `Site`'s
  `Debug` redacts them; they exist in plaintext only inside the item envelope (T30).
- Log lines carry site ids (`short()`) and operation names only; never host, user, site name,
  path or comments at any level `info`+; `debug` may include the host (T91 §4).
- Synced values that act locally need per-device approval (step 2 above). Team-vault sites
  cannot reference personal `ssh-key` items (T81).
- Names and comments from synced or imported items are untrusted text: T59 strips control
  characters before rendering; this module rejects control characters in names on write.

## Implementation steps

1. `model.rs`: `Site`, `SiteFolder`, `CredentialOverride`, `SiteColor`, `SiteTransferMode`,
   `ItemView` impls (+ round-trip tests), `normalize_for_logon`.
2. `validate.rs` with the table above.
3. `tree.rs`: `SiteTree::build`, sorting, missing parents, cycle breaking, path lookup.
4. `manager.rs`: add/update/rename/folder ops, delete, move, duplicate, copy, device-local
   helpers, `clear_saved_passwords`. Site bookmarks are found through a private view
   `BookmarkSiteRef` that reads only the `bookmark.site_id` key (T81 table), so this task does
   not need T33's code.
5. `connect.rs`: override, approvals, `ConnectInfo` build, `mark_connected`.
6. `import_key_file` for `ssh-key` items.
7. `docs/data-model.md` site section and schema-evolution procedure.

## Acceptance criteria

- [ ] AC1 Every field of the T81 `site` table round-trips through `Site::apply_to` →
  `Site::from_body` (proptest over all fields), and an unchanged `put` writes nothing.
- [ ] AC2 Tree operations behave as specified: add, rename, delete (recursive, with counts),
  move, duplicate (passwords and bookmarks copied, `" (copy)"` suffixes), copy across vaults
  (dropped refs reported); moving a folder into itself or a descendant returns `InvalidInput`
  and changes nothing.
- [ ] AC3 `lookup_path` finds `Work/Production/web01`, `/Work/Production/web01`,
  `work/production/WEB01` (unique case-insensitive), `Ünïcødé/サイト`, and returns `Ambiguous`
  for two siblings named `a` and `A`, `IsFolder` for `Work`, `NotFound` otherwise.
- [ ] AC4 A site saved with a password, after `lock` + `unlock` of the vault, yields a
  `ConnectInfo` whose `LogonType::Normal { password: Some(_) }` equals the saved password (no
  prompt); with `vault.store_passwords = false` it yields `password: None`.
- [ ] AC5 A site whose `key_file` was written by another device (stamp device ≠ local) returns
  `NeedsApproval` with the exact path; after `approve` it returns `Ready`; changing the path on
  the other device asks again; a path typed on this device never asks.
- [ ] AC6 Changing `logon` from `normal` to `key-file` removes the `password` value from the
  decrypted item body.
- [ ] AC7 Two vault engines on separate databases edit different fields of the same site
  offline; exchanging their encrypted rows through the test helper `sync_sim` (T81 `merge`)
  gives both the same site with both edits; editing the same field keeps the newer stamp.
- [ ] AC8 A folder cycle created by merging two offline moves builds a tree without panics,
  with `CycleBroken` and every site still reachable.
- [ ] AC9 Building the tree of 5 000 sites in 200 folders takes < 20 ms in release mode
  (criterion bench `site_tree_build_5k`).
- [ ] AC10 `format!("{site:?}")` of a site with canary password/account/passphrase contains
  none of them; no `info`+ log line during the integration suite contains a fixture hostname.
- [ ] AC11 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os`, `canary` pass.

## Tests

### Unit tests
- `model::tests::{site_roundtrip_all_fields, unchanged_put_no_stamp, unknown_site_key_survives,
  secrets_kept_on_list_view}` (AC1).
- `model::tests::normalize_for_logon_table` — one row per logon kind (AC6).
- `validate::tests::{host_rules, port_zero, logon_protocol_matrix, timezone_bounds,
  connection_limit_bounds, charset_label, comments_size, name_rules, key_file_missing_warns}`.
- `tree::tests::{sorted_folders_first, missing_parent_to_root, cycle_broken_at_smallest_id,
  duplicate_names_warned, expanded_from_device_local}` (AC8).
- `tree::tests::lookup_path_cases` — the AC3 table (AC3).
- `model::tests::debug_redacts` (AC10).

### Property / fuzz tests
- `tests/site_props.rs::random_tree_ops_keep_invariants` (proptest, 500 cases): random add /
  move / rename / delete / duplicate sequences on a test vault; invariants: every live site
  reachable from a root, no folder its own ancestor, sibling names unique (AC2).
- `tests/site_props.rs::site_view_roundtrip` (AC1).

### Snapshot tests
Not applicable (screens are T59).

### Integration tests
(`crates/courier-ftp-core/tests/sites.rs`, `Argon2Cost::TEST`, temp store)
- `t01_add_rename_delete_folder_recursive` (AC2).
- `t02_move_into_descendant_rejected` (AC2).
- `t03_duplicate_copies_passwords_and_bookmarks` (AC2).
- `t04_copy_to_team_vault_drops_personal_key_ref` (AC2).
- `t05_password_survives_relock_into_connect_info` — `MockBackend` factory captures the
  `ConnectInfo` (AC4).
- `t06_store_passwords_off` (AC4).
- `t07_local_acting_field_needs_approval` (AC5).
- `t08_credential_override_applies_to_team_site`.
- `t09_concurrent_edits_merge_via_sync_sim` (AC7).
- `t10_tree_refreshes_on_items_changed` — a second engine writes a site; the tree contains it
  after the change poller fires.
- `benches/site_tree.rs::site_tree_build_5k` (AC9).
- `tests/canary.rs::sites_leak_nothing` (AC10).

### End-to-end tests
- `courier-ftp-e2e/tests/sites_sftp.rs::saved_site_connects_without_prompt` (`#[ignore]`,
  `COURIER_E2E=1`, `sshd` profile `password`): `TestHome` with a saved site and password,
  `Headless` connects through `connect_info` and lists `/` without any `Prompt` event (AC4).

## Out of scope

- The Site Manager screen, field visibility and dirty tracking (T59).
- Import/export (T32), bookmarks and history (T33).
- Sync transport (T88) and team management (T89).
- FileZilla's "post-login commands" and per-site proxy settings other than "bypass proxy"
  (not in FEATURES.md).

## Open questions

1. `ConnectInfo`'s exact field names are owned by T03 (currently a concept list). This task
   fills: address, logon, charset, server type, timezone offset, transfer mode, connection
   limit, proxy choice, `try_agent_first`. T03's owner should confirm the names and that
   `try_agent_first` is part of `ConnectInfo` (T20 reads it).
