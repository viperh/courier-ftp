# Data model

The canonical field list of every vault item kind (T81). Code: `courier_ftp_core::model::item`
(`crates/courier-ftp-core/src/model/item/`) and `courier_ftp_core::model::ids`. Tasks that add
fields (T31, T33) extend the tables here.

## Item body

Every item is an `ItemBody`, CBOR-encoded and then sealed by `courier_ftp_crypto::envelope::seal_item`
(T80). The plaintext is a CBOR map with the keys in this order:

| Key | CBOR | Meaning |
|---|---|---|
| `kind` | text | the item kind (`site`, `site-folder`, `bookmark`, `known-host`, `trusted-cert`, `ssh-key`, `proxy-credential`, `credential-override`, `history-entry`) |
| `schema_version` | uint | bumped only for breaking changes |
| `fields` | map text → `[value, hlc, device]` | field-level last-writer-wins registers, sorted by key |
| `deleted` | `[bool, hlc, device]` or null | the tombstone |

- `hlc` is a uint: a `uhlc` NTP64 (32 bits of seconds since the Unix epoch, 32 bits of
  fraction whose low 4 bits are a logical counter). `device` is the 16-byte device id.
- Encoding is deterministic: the same body always gives the same bytes.
- `value = null` is an explicit "None" that wins merges like any write; a missing key also
  reads as unset. Writing the value a field already holds creates no new stamp.
- Nested settings use dotted keys (`proxy.host`). Lists are single whole-value registers.
- Unknown keys are kept untouched by views and merge, so an older build never erases what a
  newer one wrote. An unknown `kind` decodes to `BodyCodecError::UnknownKind`; such items
  are left untouched.
- Field names whose last dotted segment is `password`, `private_key`, `passphrase`,
  `key_passphrase` or `account` are secrets: plain CBOR text inside the encrypted body,
  exposed only as `SecretString` by views and redacted by `ItemBody`'s `Debug`.

## Merge

`merge(local, remote)` is pure, commutative, associative and idempotent:

1. Every key in either body is an LWW register: the higher `(hlc, device)` wins; equal stamps
   (corrupted input only) are ordered by the CBOR bytes of the value.
2. `deleted` merges the same way. The item is deleted iff the tombstone is `true` and its
   stamp is greater than every field's; an edit newer than the delete resurrects the item.
3. `schema_version = max(local, remote)`; a version newer than this build is read-only.
4. `kind` should never differ; if it does, the kind of the body with the newest stamp wins.

A received stamp more than 5 minutes ahead of local physical time only advances the local
clock to `physical + 5 min` (and raises a clock-skew warning); the stored stamp is never
rewritten, so all replicas converge.

## Schema versions

`schema_version` bumps only for breaking changes; adding an optional field never does.
Migrations are pure steps run on read, one version at a time; a body newer than this build
is read-only ("Update courier-ftp to edit this item"). Every kind is at version 1.

## References

Every 16-byte id inside a field value is a reference. A reference to a missing or deleted
item resolves to `None`. An item may reference only items in its own vault, except
`credential-override.shared_site_id` (personal vault, points into a team vault).

## Device-local data

Never item fields: last connected time, frecency, a site's default local directory, a
bookmark's per-device local directory override, tree expansion state, the transfer queue
and tab state (T82 `device_local` / `device_blobs`).

## Fields per kind

Conventions for the tables: "id" = 16-byte byte string; "[id]" = array of ids; "text (secret)"
= plain CBOR text inside the encrypted body, exposed only as `SecretString`; missing key and
`null` both read as the stated default. Enum fields are text with the listed wire strings; an
unknown string is a `ViewError::FieldType` on read.

**`site`** (view `Site`, implemented in T31; FileZilla Site Manager tab in the last column):

| Key | CBOR | View type | Default | Tab |
|---|---|---|---|---|
| `name` | text | `String` | `""` | tree |
| `parent_id` | id | `Option<ItemId>` (a `site-folder` in the same vault) | `None` = vault root | tree |
| `protocol` | text `ftp`/`sftp` | `Protocol` (T02) | `ftp` | General |
| `encryption` | text `plain-only`/`explicit-if-available`/`require-explicit`/`require-implicit` | `FtpEncryption` (T02) | `explicit-if-available` | General (FTP only; always `explicit-if-available` for SFTP sites, T31) |
| `host` | text | `String` | `""` | General |
| `port` | uint | `Option<u16>` | `None` = protocol default (21, 990 implicit, 22) | General |
| `logon_type` | text `anonymous`/`normal`/`ask-for-password`/`interactive`/`key-file`/`account`/`agent` (T02 `LogonKind` serde strings) | `LogonKind` (T02) | `normal` | General |
| `user` | text | `String` | `""` | General |
| `password` | text (secret) | `SecretField` | `Absent` | General |
| `account` | text (secret) | `SecretField` (T02 keeps it secret) | `Absent` | General (Account logon) |
| `key_file` | text (local path, `~` allowed) | `Option<String>` | `None` | General (SFTP key file) |
| `ssh_key_id` | id | `Option<ItemId>` (an `ssh-key` item; wins over `key_file`) | `None` | General |
| `key_passphrase` | text (secret) | `SecretField` (for `key_file`) | `Absent` | General |
| `try_agent_first` | bool | `bool` | `false` | General (SFTP) |
| `color` | text `none`/`red`/`green`/`blue`/`yellow`/`cyan`/`magenta`/`orange` | `SiteColor` | `none` | General |
| `comments` | text (≤ 64 KiB) | `String` | `""` | General |
| `server_type` | text `auto`/`unix`/`dos`/`vms`/`mvs` (exactly these five) | `ServerTypeOverride` (T02) | `auto` | Advanced |
| `bypass_proxy` | bool | `bool` | `false` | Advanced |
| `remote_dir` | text (absolute `/` path) | `Option<RemotePath>` | `None` | Advanced |
| `sync_browsing` | bool | `bool` | `false` | Advanced |
| `directory_comparison` | bool | `bool` | `false` | Advanced |
| `timezone_offset_minutes` | int (−1440..=1440): the server's UTC offset, utc = server time − offset (T13) | `i32` | `0` | Advanced |
| `transfer_mode` | text `default`/`active`/`passive` | `TransferModeOverride` (T03) | `default` | Transfer settings |
| `connection_limit` | uint (1..=10) | `Option<u8>` | `None` = global limit | Transfer settings |
| `charset` | text `auto`/`utf-8`/encoding label (`encoding_rs`) | `Charset` (T02) | `auto` | Charset |
| `created_at` | UnixMillis | `UnixMillis` | write time | — |

Not item fields: default local directory (device-local `local_dir_override`), last connected
time and frecency (`device_local`), tree expansion (`device_local.tree_expanded`).
Values of `server_type`, `color`, `transfer_mode` and `encryption` are the serde kebab-case
strings of the Rust enums named in the table.

**`site-folder`** (view `SiteFolder`, T31): `name` text (required), `parent_id` id (optional,
`None` = vault root), `created_at` UnixMillis.

**`bookmark`** (view `Bookmark`, T33): `name` text; `site_id` id (optional; `None` = global
bookmark, which lives in the personal vault; a site bookmark lives in its site's vault);
`local_dir` text (local path; written **only for global bookmarks** — a site bookmark's local
dir is device-local in `device_local.local_dir_override` keyed by the bookmark id, like a site's
default local dir); `remote_dir` text (absolute; required when `site_id` is set);
`sync_browsing` bool (`false`); `directory_comparison` bool (`false`); `position` float (f64,
fractional index within its list: global list or one site's list; default `0.0`).

**`known-host`** (view `KnownHostItem`, T81; T30 converts it to and from `trust::KnownHost` of T21): `host` text (lowercase, no
brackets), `port` uint (default 22), `key_type` text (`ssh-ed25519`, `ecdsa-sha2-nistp256`,
`ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `ssh-rsa`, …), `public_key` text (OpenSSH base64
blob without type or comment), `added_at` UnixMillis, `comment` text (optional). One item per
`(host, port, key_type)`; lookups compare host case-insensitively.

**`trusted-cert`** (view `TrustedCertItem`, T81; used by T12): `host` text (lowercase),
`port` uint, `sha256` bytes(32) (fingerprint of the leaf DER), `cert_der` bytes (leaf
certificate, ≤ 16 KiB), `subject` text, `issuer` text, `not_after` UnixMillis, `added_at`
UnixMillis. One item per `(host, port)`: "Always trust" of a changed certificate replaces the
fingerprint in the existing item.

**`ssh-key`** (view `SshKeyItem`, T81; used by T20/T31): `label` text; `algorithm` text
(`ed25519`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `rsa`, `dsa`); `private_key` text (secret;
the key file content as imported, ≤ 64 KiB); `format` text (`openssh`, `pem`, `pkcs8`,
`ppk2`, `ppk3`); `public_key` text (OpenSSH one-line form, optional when it could not be
derived from an encrypted key without a `.pub` file); `passphrase` text (secret, optional);
`comment` text (optional); `added_at` UnixMillis.

**`proxy-credential`** (view `ProxyCredentialItem`, T81; referenced by T05
`proxy.generic.credential_id` / `proxy.ftp_proxy.credential_id`, used by T07/T15): `label`
text; `scope` text `generic`/`ftp-proxy`; `password` text (secret). The proxy user name stays
in settings (T05).

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

Required fields of the views implemented in T81 (a missing or `null` value is a
`ViewError::Missing`): `known-host` `host`, `key_type`, `public_key`; `trusted-cert` `host`,
`port`, `sha256`, `cert_der`; `ssh-key` `algorithm`, `format`; `proxy-credential` `scope`.
Missing timestamps read as `0`; missing text fields without a stated default read as `""`.
