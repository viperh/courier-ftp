# T81 — Item model, HLC and merge

**Phase:** H Sync (also used by the local vault) · **Milestone:** M2 · **Depends on:** T80 · **Crate(s):** `courier-ftp-core` (`model::item`) · **Decisions:** D4, D12, D13 · **FEATURES.md:** §2 (Site Manager data, bookmarks, history, password storage)
**Related (integrates with, not blocking):** T12, T21, T31, T33, T82, T89
**Reference:** sverb `crates/sverb-core/src/model/{body,hlc,merge,migrate,kinds,ids,fields}.rs`, `crates/sverb-core/tests/merge_props.rs`, `docs/data-model.md`, SPEC §4.1, §12.4.

## Goal

A generic, mergeable record format for everything stored in the vault (sites, folders,
bookmarks, trusted host keys and certificates, SSH keys, proxy credentials, credential
overrides, quickconnect history). Each field carries a hybrid-logical-clock stamp, so two
devices that edit offline converge to the same item regardless of delivery order. This task
also fixes the canonical field list of every item kind (the courier-ftp equivalent of sverb's
`docs/data-model.md`), so T30, T31, T33, T12, T21, T88 and T89 agree on keys and encodings.

## Context

- Before: T80 provides `envelope::seal_item` (which encrypts the CBOR produced here) and
  `canon::Id16`. T02 provides `RemotePath`, `LocalPath`, `Protocol`, `FtpEncryption`,
  `LogonType`, `Charset` used by typed views.
- After: T82 stores the sealed bytes; T30 (`VaultEngine`) stamps writes, decrypts, migrates
  and serves typed views; T31 (`Site`, `SiteFolder`, `CredentialOverride` views), T33
  (`Bookmark`, `HistoryEntry` views), T21/T12 (`KnownHostItem`, `TrustedCertItem`, implemented here)
  build on the `ItemView` trait; T88 calls `merge` and `HlcClock::observe`; T89 relies on the
  cross-vault reference rules.

## Technical specification

### Types and APIs

Ids live in `courier_ftp_core::model::ids` (file `model/ids.rs`, as T02 announces); everything
else in `courier_ftp_core::model::item` (files `kinds.rs`, `body.rs`, `hlc.rs`, `merge.rs`,
`migrate.rs`, `view.rs`, `views/{known_host,trusted_cert,ssh_key,proxy_credential}.rs`,
`refs.rs`). `model::item` re-exports the ids. T02's `KeySource::VaultItem(uuid::Uuid)` holds
`ItemId::uuid()`.

```rust
// ids.rs — UUIDv7 newtypes. CBOR: 16-byte byte string. JSON/Display: hyphenated.
pub struct ItemId(Uuid);  pub struct VaultId(Uuid);  pub struct DeviceId(Uuid);
pub struct UserId(Uuid);  pub struct OrgId(Uuid);
// each: new() (Uuid::now_v7), generate(&mut impl IdGen), from_bytes([u8;16]), as_bytes(),
// short() (first 8 hex chars), FromStr, Display, Copy, Ord, Hash, Serialize, Deserialize.
pub trait IdGen { fn next_uuid(&mut self) -> Uuid; }
pub struct V7Gen;                 // production
pub struct SeqGen { .. }          // tests: UUIDv7-shaped, fixed millis + counter

/// Unix milliseconds, UTC (CBOR integer).
pub struct UnixMillis(pub i64);

// kinds.rs
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ItemKind { Site, SiteFolder, Bookmark, KnownHost, TrustedCert, SshKey,
                    ProxyCredential, CredentialOverride, HistoryEntry }
impl ItemKind { pub const ALL: [ItemKind; 9]; pub const fn as_str(&self) -> &'static str; }

// body.rs
pub struct Stamped<T> { pub value: T, pub hlc: Hlc, pub device: DeviceId }  // CBOR [value, hlc, device]
pub struct ItemBody {
    pub kind: ItemKind,
    pub schema_version: u16,
    pub fields: BTreeMap<String, Stamped<ciborium::Value>>,
    pub deleted: Option<Stamped<bool>>,
}
impl ItemBody {
    pub fn new(kind: ItemKind, schema_version: u16) -> Self;
    /// Stamps and writes `value`; no-op (returns false) when the value is unchanged.
    pub fn set(&mut self, field: &str, value: impl Into<Value>, clock: &mut HlcClock, device: DeviceId) -> bool;
    pub fn unset(&mut self, field: &str, clock: &mut HlcClock, device: DeviceId) -> bool; // explicit Null
    pub fn get(&self, field: &str) -> Option<&Value>;                // Null and missing → None
    pub fn get_stamped(&self, field: &str) -> Option<&Stamped<Value>>;
    pub fn delete(&mut self, clock: &mut HlcClock, device: DeviceId); // tombstone after every field
    pub fn restore(&mut self, clock: &mut HlcClock, device: DeviceId);
    pub fn is_deleted(&self) -> bool;
    pub fn max_field_hlc(&self) -> Option<Hlc>;
    pub fn max_hlc(&self) -> Option<Hlc>;
    pub fn to_cbor(&self) -> Result<Vec<u8>, BodyCodecError>;
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, BodyCodecError>;
}
pub const SECRET_FIELDS: [&str; 5] = ["password", "private_key", "passphrase", "key_passphrase", "account"];
pub fn is_secret_field(field: &str) -> bool;   // last dotted segment in SECRET_FIELDS
pub enum BodyCodecError { Decode(String), Encode(String), UnknownKind(String) }

// hlc.rs
pub struct Hlc(uhlc::NTP64);      // Copy, Ord; CBOR uint
pub const MAX_SKEW: Duration = Duration::from_secs(300);
pub trait PhysicalClock: Send + Sync + Debug { fn now(&self) -> Duration; }
pub struct SystemClock;  pub struct ManualClock(Arc<AtomicU64>);   // tests: set/advance
pub struct HlcClock { .. }
impl HlcClock {
    pub fn new(physical: impl PhysicalClock + 'static) -> Self;
    pub fn with_last(self, last: Hlc) -> Self;       // resume from meta.hlc_last
    pub fn last(&self) -> Hlc;
    pub fn now(&mut self) -> Hlc;                    // strictly increasing
    pub fn observe(&mut self, remote: Hlc, from: DeviceId) -> Result<(), ClockSkew>;
}
pub struct ClockSkew { pub device: DeviceId, pub ahead_by: Duration }

// merge.rs
pub struct MergeOutcome { pub body: ItemBody, pub resurrected: bool, pub changed_fields: Vec<String>,
                          pub deletion_changed: bool, pub kind_changed: bool, pub schema: SchemaOutcome }
pub struct SchemaOutcome { pub version: u16, pub local_version: u16, pub read_only: bool }
pub fn merge(local: &ItemBody, remote: &ItemBody) -> MergeOutcome;
pub fn merge_all<'a>(bodies: impl IntoIterator<Item = &'a ItemBody>) -> Option<ItemBody>;

// migrate.rs
pub const CURRENT_SCHEMA: [(ItemKind, u16); 9];      // all 1 in this task
pub fn current_schema(kind: ItemKind) -> u16;
pub fn is_read_only(body: &ItemBody) -> bool;
pub type Migration = fn(ItemBody) -> ItemBody;
pub struct MigrateOutcome { pub body: ItemBody, pub migrated_from: Option<u16>, pub read_only: bool }
pub fn migrate(body: ItemBody) -> MigrateOutcome;

// view.rs — typed views over a body
pub trait ItemView: Sized {
    const KIND: ItemKind;
    fn from_body(body: &ItemBody) -> Result<Self, ViewError>;
    /// Writes only changed fields; never writes a default into a missing key; never
    /// touches keys it does not know.
    fn apply_to(&self, body: &mut ItemBody, w: &mut FieldWriter<'_>);
}
pub struct FieldWriter<'a> { clock: &'a mut HlcClock, device: DeviceId }
impl FieldWriter<'_> {
    pub fn text(&mut self, b: &mut ItemBody, key: &str, v: &str, default: &str) -> bool;
    pub fn opt_text(&mut self, b: &mut ItemBody, key: &str, v: Option<&str>) -> bool;
    pub fn secret(&mut self, b: &mut ItemBody, key: &str, v: Option<&SecretString>) -> bool;
    pub fn uint / opt_uint / int / bool / id / opt_id / ids / enum_ / bytes (same pattern)
}
pub enum ViewError { WrongKind { expected: ItemKind, found: ItemKind },
                     Missing(&'static str), FieldType { field: String, expected: &'static str } }
pub trait WireEnum: Sized { fn as_wire(&self) -> &'static str; fn from_wire(s: &str) -> Option<Self>; }

// views implemented in this task
pub struct KnownHostItem { .. }  pub struct TrustedCertItem { .. }
pub struct SshKeyItem { .. }  pub struct ProxyCredentialItem { .. }

// refs.rs — cross-vault reference rule (§13.4)
pub fn references(body: &ItemBody) -> Vec<(String, ItemId)>;   // every id-typed field
pub fn check_vault_refs(vault: VaultId, body: &ItemBody,
                        vault_of: impl Fn(ItemId) -> Option<VaultId>) -> Result<(), RefError>;
```

`SecretString` is `courier_ftp_core::secret::SecretString` (T30). `ItemBody`'s `Debug`
prints `[REDACTED] @ <hlc>/<device>` for every non-null secret field.

### Behaviour

**Body and encoding** (sverb SPEC §4.1, data-model §1):
- CBOR map with keys in this order: `kind` (text), `schema_version` (uint), `fields`
  (map text → `Stamped`, sorted because it is a `BTreeMap`), `deleted` (`Stamped<bool>` or
  null). `Stamped<T>` is the CBOR array `[value, hlc, device]`; `hlc` is a uint, `device` a
  16-byte byte string. Encoding is deterministic: the same body always gives the same bytes.
- `value = null` is an explicit "None" that wins merges like any write; a missing key also
  reads as `None`. `set` writes nothing when the new value equals the stored one (no new stamp,
  so the outbox sees no spurious change).
- A local write over a value carrying a future (skewed) stamp is stamped `stored + 1` so the
  local edit still wins (`next_stamp_after`).
- Nested settings use dotted keys (`proxy.host`). Lists are single whole-value registers.
- Unknown keys are kept untouched by views and merge, so an older build never erases data a
  newer one wrote.
- An unknown `kind` string decodes to `BodyCodecError::UnknownKind(s)`. T30 leaves such rows
  untouched (never rewritten, never shown, counted as `unknown_kind` in the vault status); T88
  stores remote versions of them as received without merging.

**HLC** (sverb `hlc.rs`): an `Hlc` is a `uhlc` NTP64 — 32 bits of seconds since the Unix
epoch, 32 bits of fraction whose low 4 bits (`uhlc::CSIZE`) are the logical counter. Order is
plain `u64` order. `now()` returns `max(physical, last + 1)` (logical overflow carries into the
time bits, keeping order strict). `observe(remote)`: if `remote > physical + MAX_SKEW`, the local
clock advances only to `physical + MAX_SKEW` and `ClockSkew { device, ahead_by }` is returned
for the UI toast ("Clock skew detected on device X", T90); otherwise the clock advances past
`remote`. The stored stamp of the received value is **never rewritten**, so every replica
converges; clamping only protects the local clock. The last stamp is persisted as
`meta.hlc_last` (u64 BE) by T30 in the same transaction as each item write.

**Merge** (sverb `merge.rs`, SPEC §12.4), `merge(local, remote)` is pure:
1. Every key present in either body is an LWW register: the higher `(hlc, device)` wins; equal
   stamps (only possible with corrupted input) are ordered by the CBOR bytes of the value, so
   the function stays total and commutative.
2. `deleted` merges the same way. The result is deleted iff `deleted.value == true` and
   `deleted.hlc` is greater than every field's hlc. An edit newer than the delete resurrects
   the item; `resurrected = local.is_deleted() && !result.is_deleted()` drives the toast
   "'<name>' was restored because it was edited on another device after being deleted" (T90).
3. `schema_version = max(local, remote)`; `read_only = schema_version > current_schema(kind)`.
4. `kind` should never differ; if it does, the kind of the body with the newest stamp wins
   (ties by kind order), `kind_changed = true`, and an `error!` is logged with item id only.
5. `changed_fields` lists keys whose register differs from `local` (sorted);
   `MergeOutcome::changed()` lets T88 skip unchanged writes.
6. Merge never touches a clock; T88 calls `HlcClock::observe` for every received stamp.
Properties: commutative, associative, idempotent on `body`.

**Tombstones**: `delete` stamps `deleted = true` after the body's max stamp. Tombstones keep
all fields (the server only ever sees ciphertext); T30 strips secret fields from a body when it
deletes it (writes `null` stamped before the tombstone) so a deleted site's password does not
survive in the tombstone.

**Migrations** (sverb `migrate.rs`): `schema_version` bumps only for breaking changes. Pure
`fn(ItemBody) -> ItemBody` steps run on read, one version at a time (`steps[i]` migrates
`i + 1 → i + 2`); missing steps relabel to the target (layout compatible). A body newer than
`current_schema(kind)` is opened **read-only**: views get `read_only = true`, T30 rejects writes
with `VaultError::ReadOnlyItem` and the UI shows "Update courier-ftp to edit this item".
Migrated bodies are not written back until the next real edit (the next `put` re-seals the
migrated body). Adding a new optional field never bumps the version.

**References** (sverb SPEC §12.4, §13.4): every 16-byte id inside a field value is a reference.
A reference to a missing or deleted item resolves to `None` at read time (logged at `debug`
with ids only) and is cleaned up lazily on the next edit of the referring item. An item in a
team vault may reference only items in the same vault (`check_vault_refs`), except
`credential-override.shared_site_id`, which lives in the personal vault and points into a team
vault. Violations are rejected on write (`RefError::CrossVault { field, target }`).

**Device-local data** never goes into item fields: last connected time, frecency, a site's
default local directory, a bookmark's per-device local directory override, tree expansion
state, the transfer queue and tab state. They live in T82 `device_local` / `device_blobs`.

### Data formats and configuration

Conventions for the tables: "id" = 16-byte byte string; "[id]" = array of ids; "text (secret)"
= plain CBOR text inside the encrypted body, exposed only as `SecretString`; missing key and
`null` both read as the stated default. Enum fields are text with the listed wire strings; an
unknown string is a `ViewError::FieldType` on read.

**`site`** (view `Site`, implemented in T31; FileZilla Site Manager tab in the last column):

| Key | CBOR | View type | Default | Tab |
|---|---|---|---|---|
| `name` | text | `String` | `""` | tree |
| `parent_id` | id | `Option<ItemId>` (a `site-folder` in the same vault) | `None` = vault root | tree |
| `protocol` | text `ftp`/`sftp` | `SiteProtocol` | `ftp` | General |
| `encryption` | text `plain-only`/`explicit-if-available`/`require-explicit`/`require-implicit` | `FtpEncryption` (T02) | `explicit-if-available` | General (FTP only) |
| `host` | text | `String` | `""` | General |
| `port` | uint | `Option<u16>` | `None` = protocol default (21, 990 implicit, 22) | General |
| `logon_type` | text `anonymous`/`normal`/`ask-for-password`/`interactive`/`key-file`/`account`/`agent` (T02 `LogonKind` serde strings) | `LogonKind` (T02) | `normal` | General |
| `user` | text | `String` | `""` | General |
| `password` | text (secret) | `Option<SecretString>` | `None` | General |
| `account` | text | `Option<SecretString>` (T02 keeps it secret) | `None` | General (Account logon) |
| `key_file` | text (local path, `~` allowed) | `Option<String>` | `None` | General (SFTP key file) |
| `ssh_key_id` | id | `Option<ItemId>` (an `ssh-key` item; wins over `key_file`) | `None` | General |
| `key_passphrase` | text (secret) | `Option<SecretString>` (for `key_file`) | `None` | General |
| `try_agent_first` | bool | `bool` | `false` | General (SFTP) |
| `color` | text `none`/`red`/`green`/`blue`/`yellow`/`cyan`/`magenta`/`orange` | `SiteColor` | `none` | General |
| `comments` | text (≤ 64 KiB) | `String` | `""` | General |
| `server_type` | text `default`/`unix`/`vms`/`dos`/`mvs`/`vxworks`/`zvm`/`hpnonstop`/`dos-virtual`/`cygwin`/`dos-fwd-slashes` | `ServerType` | `default` | Advanced |
| `bypass_proxy` | bool | `bool` | `false` | Advanced |
| `remote_dir` | text (absolute `/` path) | `Option<RemotePath>` | `None` | Advanced |
| `sync_browsing` | bool | `bool` | `false` | Advanced |
| `directory_comparison` | bool | `bool` | `false` | Advanced |
| `timezone_offset_minutes` | int (−1440..=1440) | `i32` | `0` | Advanced |
| `transfer_mode` | text `default`/`active`/`passive` | `SiteTransferMode` | `default` | Transfer settings |
| `connection_limit` | uint (1..=10) | `Option<u8>` | `None` = global limit | Transfer settings |
| `charset` | text `auto`/`utf-8`/encoding label (`encoding_rs`) | `Charset` (T02) | `auto` | Charset |
| `created_at` | UnixMillis | `UnixMillis` | write time | — |

Not item fields: default local directory (device-local `local_dir_override`), last connected
time and frecency (`device_local`), tree expansion (`device_local.tree_expanded`).

**`site-folder`** (view `SiteFolder`, T31): `name` text (required), `parent_id` id (optional,
`None` = vault root), `created_at` UnixMillis.

**`bookmark`** (view `Bookmark`, T33): `name` text; `site_id` id (optional; `None` = global
bookmark); `local_dir` text (optional, local path, may be overridden per device in
`device_local.local_dir_override`); `remote_dir` text (optional; required when `site_id` is
set); `sync_browsing` bool (`false`); `directory_comparison` bool (`false`); `position` int
(`0`; sort key within its list, gaps of 1024).

**`known-host`** (view `KnownHostItem`, this task; T30 converts it to and from `trust::KnownHost` of T21): `host` text (lowercase, no
brackets), `port` uint (default 22), `key_type` text (`ssh-ed25519`, `ecdsa-sha2-nistp256`,
`ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `ssh-rsa`, …), `public_key` text (OpenSSH base64
blob without type or comment), `added_at` UnixMillis, `comment` text (optional). One item per
`(host, port, key_type)`; lookups compare host case-insensitively.

**`trusted-cert`** (view `TrustedCertItem`, this task; used by T12): `host` text (lowercase),
`port` uint, `sha256` bytes(32) (fingerprint of the leaf DER), `cert_der` bytes (leaf
certificate, ≤ 16 KiB), `subject` text, `issuer` text, `not_after` UnixMillis, `added_at`
UnixMillis. One item per `(host, port)`: "Always trust" of a changed certificate replaces the
fingerprint in the existing item.

**`ssh-key`** (view `SshKeyItem`, this task; used by T20/T31): `label` text; `algorithm` text
(`ed25519`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `rsa`, `dsa`); `private_key` text (secret;
the key file content as imported, ≤ 64 KiB); `format` text (`openssh`, `pem`, `pkcs8`,
`ppk2`, `ppk3`); `public_key` text (OpenSSH one-line form, optional when it could not be
derived from an encrypted key without a `.pub` file); `passphrase` text (secret, optional);
`comment` text (optional); `added_at` UnixMillis.

**`proxy-credential`** (view `ProxyCredentialItem`, this task; referenced from settings by id,
T05/T07/T15): `label` text; `scope` text `generic`/`ftp-proxy`; `user` text; `password` text
(secret, optional).

**`credential-override`** (view `CredentialOverride`, T31; personal vault only, T89):
`shared_site_id` id (required, points into a team vault); `user` text (optional);
`password` text (secret, optional); `account` text (secret, optional); `logon_type` text (optional,
same strings as `site`); `key_file` text (optional); `ssh_key_id` id (optional, personal
vault); `key_passphrase` text (secret, optional). If several exist for one site, the smallest
item id wins (deterministic on every device).

**`history-entry`** (view `HistoryEntry`, T33): `protocol` text (`ftp`/`sftp`);
`encryption` text (FTP only, as `site`); `host` text; `port` uint (optional); `user` text;
`logon_type` text (T02 `LogonKind` strings except `account`);
`password` text (secret, optional; only when `vault.store_passwords`); `remote_dir` text
(optional); `last_used_at` UnixMillis.

`CURRENT_SCHEMA`: every kind at 1.

`docs/data-model.md` in the repository holds these tables (written in this task, extended by
T31/T33 if they add fields).

No settings keys in this task.

### Errors

- `BodyCodecError` (decode/encode/unknown kind) — mapped by T30 to an unreadable item
  (counted, logged at `warn` with the item's short id), never a panic.
- `ViewError` — wrong kind, missing required field, wrong CBOR type or unknown enum string;
  T30 reports the item as unreadable for that view and keeps the raw body untouched.
- `RefError::CrossVault { field, target }` — surfaced by T30 as
  `courier_ftp_core::Error::InvalidInput("<field> may only reference items in the same vault")`.
- `ClockSkew` — not an error for the write; returned to T88, which emits a toast.

### Security and logging

- Secrets are only `SecretString` in views; `ItemBody` `Debug` redacts every field whose last
  dotted segment is in `SECRET_FIELDS`; a test with canary values proves it.
- Logs from this module carry item ids (`short()`), kinds and field **names** only, never
  values, hostnames or usernames, at any level.
- Bodies come from the network (sync) and are untrusted: decoding is bounded by the 16 MiB
  plaintext cap (T80) and the 1 MiB item limit (T30); views validate types and ranges and
  reject, never panic.

## Implementation steps

1. `ids.rs`, `UnixMillis`, `IdGen` (`V7Gen`, `SeqGen`) with tests.
2. `kinds.rs` with wire strings and the unknown-kind decode error.
3. `hlc.rs` (`Hlc`, `HlcClock`, `PhysicalClock`, `ManualClock`, skew clamp).
4. `body.rs` (`Stamped`, `ItemBody`, deterministic CBOR, redacted `Debug`, tombstone rules).
5. `merge.rs` and `tests/merge_props.rs` (algebraic properties + N-device simulation).
6. `migrate.rs` with the step-runner and read-only rule.
7. `view.rs` (`ItemView`, `FieldWriter`, `ViewError`, `WireEnum`) and the four views of this
   task (`KnownHostItem`, `TrustedCertItem`, `SshKeyItem`, `ProxyCredentialItem`).
8. `refs.rs` and `docs/data-model.md`.

## Acceptance criteria

- [ ] AC1 `merge` is commutative, associative and idempotent: proptest with 1 000 cases each
  over random bodies with colliding stamps passes.
- [ ] AC2 N = 2..5 simulated devices with random offline edits, deletes and restores, exchanged
  through a network that reorders, duplicates and delays, end with identical bodies equal to
  the per-field maximum of every write (proptest, 1 000 seeds).
- [ ] AC3 With a `ManualClock`, a remote stamp 10 min ahead returns `ClockSkew` with
  `ahead_by ≈ 10 min`, the local clock ends at `physical + 5 min`, and the stored remote stamp
  is unchanged; a stamp 4 min ahead returns `Ok` and advances the clock past it.
- [ ] AC4 For each view implemented here, `from_body(apply_to(view)) == view`, and
  `apply_to` of an unchanged view creates no new stamp.
- [ ] AC5 A body with an unknown key `x.future` survives `from_body` → edit another field →
  `apply_to` → CBOR round trip byte-for-byte in that key.
- [ ] AC6 `ItemBody::to_cbor` is deterministic (same body → same bytes across 100 encodes and
  a decode/encode round trip).
- [ ] AC7 A body with `schema_version = CURRENT + 1` migrates to `read_only = true` and is not
  modified; a v1 body with a registered test step migrates to v2.
- [ ] AC8 `format!("{body:?}")` of a body with canary values in `password`, `key_passphrase`,
  `passphrase`, `private_key` and `proxy.password` contains none of them.
- [ ] AC9 An unknown kind string decodes to `BodyCodecError::UnknownKind`.
- [ ] AC10 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os` pass.

## Tests

### Unit tests
- `ids::tests::{cbor_is_16_bytes, json_is_hyphenated, seqgen_sorts}`.
- `kinds::tests::wire_strings_match_serde` — every `ItemKind::ALL` encodes to its `as_str`.
- `kinds::tests::unknown_kind_is_error` (AC9).
- `hlc::tests::{now_strictly_increases_on_frozen_clock, logical_overflow_carries,
  observe_within_skew_advances, observe_beyond_skew_clamps}` (AC3).
- `body::tests::{set_same_value_is_noop, unset_writes_null, tombstone_only_body_is_deleted,
  local_write_beats_skewed_stamp, debug_redacts_secret_fields}` (AC8).
- `body::tests::cbor_is_deterministic` (AC6).
- `merge::tests::{concurrent_edits_to_different_fields_both_survive,
  same_field_higher_hlc_then_higher_device_wins, delete_vs_older_edit_stays_deleted,
  edit_newer_than_delete_resurrects, schema_version_is_max, kind_mismatch_newest_wins}`.
- `migrate::tests::{newer_schema_is_read_only, steps_run_in_order, missing_step_relabels}` (AC7).
- `views::known_host::tests::roundtrip`, `trusted_cert::tests::roundtrip`,
  `ssh_key::tests::roundtrip_redacts`, `proxy_credential::tests::roundtrip` (AC4).
- `view::tests::unknown_keys_survive` (AC5).
- `refs::tests::{team_item_cannot_reference_personal_item, override_may_reference_team_site,
  missing_reference_passes}`.

### Property / fuzz tests
- `tests/merge_props.rs::{merge_is_commutative, merge_is_associative, merge_is_idempotent,
  resurrection_flag_matches_deletion_rule}` — sverb's strategies (values from a 4-element
  alphabet, stamps `0..4` × devices `0..3`) (AC1).
- `tests/merge_props.rs::n_devices_converge` + `simulation_covers_interesting_cases` (AC2).
- `tests/body_props.rs::from_cbor_never_panics` — random bytes and mutated valid bodies.

### Snapshot tests
Not applicable.

### Integration tests
Not applicable (T30 covers storage round trips; T88 covers sync).

### End-to-end tests
Not applicable.

## Out of scope

- Typed views for `site`, `site-folder`, `credential-override` (T31) and `bookmark`,
  `history-entry` (T33) — their field tables are fixed here.
- OR-set list merging (lists are whole-value LWW in v1, as in sverb).
- Storage, encryption and the outbox (T82, T30).

## Open questions

None.
