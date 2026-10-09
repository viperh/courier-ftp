# T32 — Site import / export (incl. FileZilla XML)

**Phase:** D Vault & sites · **Milestone:** M5 · **Depends on:** T31, T33, T80 · **Crate(s):** `courier-ftp-core` (`sites::import`, `sites::export`) · **Decisions:** D4, D13 · **FEATURES.md:** §2 (import and export of sites as XML; import from other clients)
**Related (integrates with, not blocking):** T30

## Goal

Users moving from FileZilla bring their whole Site Manager — folders, every site setting,
passwords stored as base64, site bookmarks — into courier-ftp in one step, with a report of
what could not be imported and why. Sites can be exported as an encrypted courier-ftp file
(passwords included, protected by a passphrase), as a plain courier-ftp file without secrets,
or as FileZilla-compatible XML (no passwords) for people going back.

## Context

- Before: T31 (`Site`, `SiteFolder`, `SiteManager`, `SiteTree`, `Location`, `validate_site`,
  `normalize_for_logon`), T33 (`Bookmark`, `Bookmarks`), T30 (`VaultEngine::put_many`,
  `set_local_dir_override`, the passphrase container `vault::backup::{encrypt_with,
  decrypt_with, ContainerSpec}`), T80 (crypto behind the container), T02 (`Protocol`,
  `FtpEncryption`, `LogonKind`, `ServerTypeOverride`, `Charset`, `RemotePath`).
- After: T59 offers *Import…* / *Export…* (file picker, preview, report, passphrase prompt);
  T73 includes sites in `.cftp-backup` with its own payload (it does not use these formats);
  T91 §7 adds the fuzz target defined here to CI.

## Technical specification

### Types and APIs

```rust
// sites::import::filezilla
pub const MAX_XML_BYTES: u64 = 16 * 1024 * 1024;
pub fn default_sitemanager_paths() -> Vec<PathBuf>;    // existing files first, see Data formats
pub struct FzFolder { pub name: String, pub expanded: bool, pub folders: Vec<FzFolder>, pub servers: Vec<FzServer> }
pub struct FzServer { /* raw values per element, see mapping table */ }
pub struct FzDocument { pub root: FzFolder, pub warnings: Vec<ParseWarning> }
pub struct ParseWarning { pub path: String, pub message: String }
/// Pure, bounded, never panics.
pub fn parse_sitemanager(xml: &[u8]) -> Result<FzDocument, ImportError>;
#[doc(hidden)] pub fn fuzz_parse_sitemanager(data: &[u8]);

/// What an import would create (pure; shown by T59 before anything is written).
pub struct ImportPreview {
    pub folder_name: String,                 // "Imported from FileZilla 2026-10-09"
    pub tree: Vec<PreviewNode>,              // folders and sites as they will be created
    pub report: ImportReport,
}
pub struct ImportReport {
    pub folders: usize, pub sites: usize, pub passwords: usize, pub bookmarks: usize,
    pub skipped: Vec<Skipped>,               // sites/bookmarks not imported
    pub notes: Vec<Note>,                    // imported with an approximation
}
pub struct Skipped { pub path: String, pub reason: SkipReason }
pub enum SkipReason { UnsupportedProtocol(i64), Invalid(String), BookmarkWithoutRemoteDir, TooMany }
pub struct Note { pub path: String, pub kind: NoteKind }
pub enum NoteKind { PasswordProtectedByMasterPassword, PasswordNotUtf8, ServerTypeApproximated(i64),
                    ConnectionLimitClamped(i64), UnknownCharset(String), TimezoneOutOfRange(i64),
                    UnknownColour(i64), KeyFileMissing, UnknownElement(String), RenamedDuplicate(String),
                    /// FileZilla's offset converted with this device's UTC offset (see mapping).
                    TimezoneConverted { filezilla: i64, stored: i32 } }
pub struct FzImportOptions {
    pub import_passwords: bool,            // default true
    pub today: Date,
    /// This device's current UTC offset in minutes (`time::UtcOffset::current_local_offset`,
    /// 0 if unknown); injectable for tests. Used for TimezoneOffset conversion.
    pub local_utc_offset_minutes: i32,
}
pub fn plan_filezilla(doc: &FzDocument, opts: &FzImportOptions, taken_root_names: &[&str]) -> ImportPreview;
/// Writes the preview into `at` in ONE vault transaction (all or nothing).
pub async fn apply_import(mgr: &SiteManager, preview: ImportPreview, at: Location) -> Result<ImportReport, Error>;

// sites::export (courier-ftp format)
pub const SITES: ContainerSpec = ContainerSpec { format: "courier-ftp-sites",
    aad: b"courier-ftp-sites-v1", extension: "cftp-sites" };
pub struct SitesPayload { pub folders: Vec<ExportFolder>, pub sites: Vec<ExportSite> }   // v1, below
pub enum ExportScope { Site(SiteId), Folder(FolderId), Vault(VaultId) }
pub struct ExportOptions { pub include_passwords: bool }
pub async fn collect(mgr: &SiteManager, bookmarks: &Bookmarks, scope: ExportScope, opts: &ExportOptions)
    -> Result<SitesPayload, Error>;
pub fn write_plain(payload: &SitesPayload, created_at: OffsetDateTime) -> Result<String, Error>;   // JSON
pub fn write_encrypted(payload: &SitesPayload, passphrase: &SecretString, cost: Argon2Cost,
                       created_at: OffsetDateTime) -> Result<String, BackupError>;              // T30 container
pub enum SitesFile { Plain(SitesPayload), Encrypted(BackupFile) }
pub fn read_sites_file(text: &str) -> Result<SitesFile, Error>;
pub fn decrypt_sites(file: &BackupFile, passphrase: &SecretString) -> Result<SitesPayload, BackupError>;
pub fn plan_courier(payload: &SitesPayload, today: Date, taken_root_names: &[&str]) -> ImportPreview;

// sites::export::filezilla (FileZilla XML, no passwords)
pub async fn export_filezilla_xml(mgr: &SiteManager, bookmarks: &Bookmarks, scope: ExportScope)
    -> Result<(String, ImportReport /* notes for lossy fields */), Error>;

pub enum ImportError { TooLarge(u64), NotFileZilla, Xml { line: usize, message: String },
                       Doctype, TooDeep, TooManyEntries, Io(std::io::Error) }
```

Argon2 and file I/O run in `spawn_blocking` (callers in T59).

### Behaviour

**FileZilla import flow**: locate the file (`default_sitemanager_paths`, or a path chosen in
T59) → size ≤ 16 MiB → `parse_sitemanager` → `plan_filezilla` → T59 shows the preview and
report → `apply_import` writes everything into a new folder "Imported from FileZilla
YYYY-MM-DD" at the chosen location (personal root by default; `" (2)"`, `" (3)"`… if the name
exists) in **one** `put_many` transaction. Nothing is written if the user cancels or the
transaction fails.

**Parsing** (`quick-xml` 0.37 reader, streaming):
- Root element must be `FileZilla3` (`NotFileZilla` otherwise); its `version`/`platform`
  attributes are ignored. Servers are under `Servers`.
- `Folder`: its name is the element's direct text content (trimmed), FileZilla's mixed-content
  form; attribute `expanded="1"` sets the device-local expansion. Nested folders recurse
  (max depth 64 → `TooDeep`).
- `Server`: child elements per the mapping table; the site name is `<Name>`, or, for files
  written by old FileZilla 3.x versions, the server's trailing direct text; or the host.
- `Bookmark` children of `Server`: `Name`, `LocalDir`, `RemoteDir`, `SyncBrowsing`,
  `DirectoryComparison`.
- Unknown elements (`PostLoginCommands`, `Parameters`, `Extra`, future ones) are ignored with a
  `UnknownElement` note per element name (once per file).
- Limits: 100 000 servers + folders (`TooManyEntries`), 64 KiB per text node (longer → the
  site is skipped as `Invalid("value too long")`). A `<!DOCTYPE` declaration is rejected
  (`Doctype`); no entity other than the five predefined XML entities and numeric character
  references is expanded. Invalid UTF-8 → `Xml` error with the line.

**Element mapping** (FileZilla 3.x `sitemanager.xml` → T81 `site` fields). Numeric codes are
from FileZilla's `src/include/server.h` (`ServerProtocol`, `ServerType`) and
`logon_type.h` (`LogonType`) as recalled for 3.x; rows marked ⚠ must be verified against the
FileZilla source of the version used for the fixture before this task is closed (step 1).

| Element | FileZilla meaning | courier-ftp |
|---|---|---|
| `Host` | host | `host` (trimmed; `[…]` stripped for IPv6) |
| `Port` | port, `0`/absent = default | `port` (`None` for 0 or the protocol default) |
| `Protocol` ⚠ | `0` FTP (explicit TLS if available), `1` SFTP, `2` HTTP, `3` FTPS implicit, `4` FTPES explicit required, `5` HTTPS, `6` insecure FTP, `7+` S3, Storj, WebDAV, cloud protocols | `0` → `ftp` + `explicit-if-available`; `1` → `sftp`; `3` → `ftp` + `require-implicit`; `4` → `ftp` + `require-explicit`; `6` → `ftp` + `plain-only`; `2`, `5`, `≥ 7` → skipped `UnsupportedProtocol(n)`; absent → `0` |
| `Type` ⚠ | server type: `0` default, `1` Unix, `2` VMS, `3` DOS, `4` MVS, `5` VxWorks, `6` z/VM, `7` HP NonStop, `8` DOS virtual, `9` Cygwin, `10` DOS forward slashes | T02 `ServerTypeOverride` has only `Auto, Unix, Dos, Vms, Mvs`: `0` auto, `1` unix, `2` vms, `3` dos, `4` mvs, `8` dos, `9` unix; `10` → dos, `5`/`6`/`7` → unix, each with `ServerTypeApproximated(n)`; other → unix + note |
| `Logontype` ⚠ | `0` anonymous, `1` normal, `2` ask for password, `3` interactive, `4` account, `5` key file, `6` profile (S3 only) | `anonymous`, `normal`, `ask-for-password`, `interactive`, `account`, `key-file`; `6` or other → site skipped `Invalid("unsupported logon type")`; logon invalid for the protocol (e.g. `account` on SFTP) → `normal` + note |
| `User` | user name | `user` |
| `Pass` | password; attribute `encoding="base64"` (FileZilla ≥ 3.26), no attribute (older, plain text), `encoding="crypt"` with `pubkey` (protected by FileZilla's master password) | base64 → decode → UTF-8 → `password`; plain → `password`; `crypt` → not imported, note `PasswordProtectedByMasterPassword`, logon `normal` → `ask-for-password`; invalid base64 or UTF-8 → note `PasswordNotUtf8`, same fallback. With `import_passwords = false` no password is imported |
| `Account` | account (FTP `ACCT`) | `account` |
| `Keyfile` | private key path | `key_file` as written (not read); missing on this device → note `KeyFileMissing` |
| `TimezoneOffset` ⚠ | minutes FileZilla **adds** to listing times parsed as the client's local time | converted to T31/T13's convention (server's UTC offset; utc = server time − offset): `stored = local_utc_offset_minutes − TimezoneOffset`; absent or `0` → `0` (Auto-like: no conversion, no note); non-zero → converted + note `TimezoneConverted` (the device's DST state at import time is used); result outside ±1440 → 0 + note `TimezoneOutOfRange` |
| `PasvMode` | `MODE_DEFAULT`, `MODE_ACTIVE`, `MODE_PASSIVE` | `transfer_mode` `default` / `active` / `passive`; other → default |
| `MaximumMultipleConnections` | `0` = no limit, else 1–10 | `0` → `None`; 1–10 → `Some(n)`; > 10 → 10 + note |
| `EncodingType` + `CustomEncoding` | `Auto`, `UTF-8`, `Custom` + label | `auto`, `utf-8`, `Charset::from_label(label)`; unknown label → auto + note `UnknownCharset` |
| `BypassProxy` | `0`/`1` | `bypass_proxy` |
| `Name` | site name | `name` (made unique among siblings: `" (2)"` + note `RenamedDuplicate`) |
| `Comments` | free text | `comments` |
| `Colour` ⚠ | `0` none, `1` red, `2` green, `3` blue, `4` yellow, `5` cyan, `6` magenta, `7` orange | `color`; other → none + note |
| `LocalDir` | default local directory | device-local default local dir (`set_local_dir_override`) if absolute, else ignored + note |
| `RemoteDir` | default remote dir in FileZilla's "safe path" encoding | `remote_dir` (decoding below) |
| `SyncBrowsing` | `0`/`1` | `sync_browsing` |
| `DirectoryComparison` | `0`/`1` | `directory_comparison` |
| `Bookmark` | site bookmark | T33 site bookmark: `Name`, `RemoteDir` (required; else skipped `BookmarkWithoutRemoteDir`), `LocalDir` → device-local, `SyncBrowsing`, `DirectoryComparison` (comparison forces sync browsing) |

Every planned site then runs through `normalize_for_logon` and `validate_site` (T31); errors
skip the site with `Invalid(message)`, warnings are kept as notes.

**FileZilla safe-path decoding** (`RemoteDir`, bookmark `RemoteDir`): FileZilla's
`CServerPath::GetSafePath` writes `<type> SP <prefix-len> [SP <prefix>] (SP <len> SP <segment>)*`,
with `<prefix-len> = 0` and no prefix when there is none, e.g. `1 0 4 home 4 user` =
`/home/user`, `1 0 8 my files 3 web` = `/my files/web`. Lengths count `wchar_t` units:
Unicode scalar values on Linux/macOS, UTF-16 code units on Windows. The decoder first counts
scalar values; if that does not consume the string exactly, it retries counting UTF-16 code
units; if both fail the site keeps `remote_dir = None` with a note. Conversion to `RemotePath`
(T14's representation): Unix-like types → `/` + segments; DOS types (`3`, `8`, `10`) →
`/` + segments (first segment is the drive, e.g. `/C:/Users/alice`); VMS (`2`) and MVS (`4`)
→ `/` + prefix without its trailing `:` + `/` + segments, with a `ServerTypeApproximated` note.
An empty string means no default remote dir.

**Default file locations** (`default_sitemanager_paths`, in order): Linux
`$XDG_CONFIG_HOME/filezilla/sitemanager.xml` (default `~/.config/filezilla/`), then the legacy
`~/.filezilla/sitemanager.xml`; macOS `~/.config/filezilla/sitemanager.xml`; Windows
`%APPDATA%\FileZilla\sitemanager.xml`. FileZilla's `-c`/custom config dirs are found through the
file picker. FileZilla's own "Export…" of the Site Manager writes the same format and is
accepted.

**courier-ftp export** (`collect` + `write_plain` / `write_encrypted`):
- Scope: one site, a folder (recursive) or a whole vault the user can read.
- `include_passwords = true` → the file must be encrypted: passphrase entered twice in T59,
  zxcvbn score ≥ 3 (T30 rule, user inputs `["courier-ftp", "export"]`), Argon2id
  `Argon2Cost::STANDARD`, T30 container with the `SITES` spec. The payload then includes
  `password`, `account`, `key_passphrase` and, for sites using `ssh_key_id`, the full `ssh-key`
  item (private key and passphrase).
- `include_passwords = false` → plain JSON; every secret is omitted; `normal` and `account`
  logons are written as `ask-for-password`; `ssh_key_id` references are dropped (`key_file`
  paths are kept). The plain file therefore contains no secret by construction (AC4).
- Default local dirs (device-local) and site bookmarks (with their local dirs) are included;
  ids are not (import always creates new ids, so importing twice never collides or merges).
- Files are written atomically (temp file + rename) with mode `0600` on Unix.

**courier-ftp import**: `read_sites_file` detects plain (`"payload"` present) or encrypted
(`"ciphertext_b64"` present) by the `format` `courier-ftp-sites`; `version` > 1 →
`Error::InvalidInput("this file was written by a newer courier-ftp")`. Encrypted files ask for
the passphrase (wrong → `BackupError::Decrypt`, "Wrong passphrase or the file was modified").
`plan_courier` builds the same `ImportPreview` (folder "Imported from courier-ftp YYYY-MM-DD")
and `apply_import` writes it in one transaction with new ids.

**FileZilla XML export** (`export_filezilla_xml`): writes `<?xml version="1.0"
encoding="UTF-8"?><FileZilla3><Servers>…</Servers></FileZilla3>` (no `version` attribute)
with the inverse of the mapping table: `Protocol` 0/1/3/4/6 from protocol + encryption, `Type`
0–4, `TimezoneOffset = local_utc_offset_minutes − timezone_offset_minutes` (omitted when the
site's offset is 0), `Logontype` from logon (`normal` and `account` → `2` because no password is written;
`agent` → `2` with a note; `key-file` → `5` + `Keyfile`), no `Pass` element, `RemoteDir` as
`1 0 …` (Unix-like types) or `3 0 …` (dos), bookmarks as `<Bookmark>`; text escaped with the five
XML entities; control characters other than tab/newline dropped with a note. Never includes
passwords (see Open questions).

### Data formats and configuration

Plain courier-ftp export (`.json`):

```json
{ "format": "courier-ftp-sites", "version": 1, "created_at": "2026-10-09T12:00:00Z",
  "app_version": "0.1.0", "payload": {
    "folders": [ { "ref": 1, "parent": null, "name": "Work" } ],
    "sites": [ { "ref": 2, "parent": 1, "name": "web01", "protocol": "sftp",
      "encryption": "explicit-if-available", "host": "web01.example.test", "port": 2222,
      "logon": "ask-for-password", "user": "deploy", "key_file": null,
      "try_agent_first": false, "color": "red", "comments": "", "server_type": "auto",
      "bypass_proxy": false, "remote_dir": "/var/www", "default_local_dir": "~/www",
      "sync_browsing": false, "directory_comparison": false, "timezone_offset_minutes": 0,
      "transfer_mode": "default", "connection_limit": null, "charset": "auto",
      "bookmarks": [ { "name": "logs", "remote_dir": "/var/log", "local_dir": null,
                       "sync_browsing": false, "directory_comparison": false } ] } ] } }
```

Encrypted export (`.cftp-sites`): the T30 backup container format (no separate magic header
or binary prefix) with `"format": "courier-ftp-sites"`,
`version` 1, KDF header, `nonce_b64`, `ciphertext_b64`; AAD `courier-ftp-sites-v1`;
plaintext `zstd_level3(cbor(SitesPayload))` where secret-bearing sites additionally carry
`"password"`, `"account"`, `"key_passphrase"` and `"ssh_key": { label, algorithm, format,
private_key, public_key, passphrase }`; decompressed size capped at 1 GiB.

`ref` values are file-local integers (1-based); `parent` refers to a folder `ref` or `null`.
Unknown JSON keys are ignored (forward compatibility); missing keys take T81 defaults.

Cargo: `quick-xml = "0.37"`, `base64`, `serde_json` (already in core via T30).

No settings keys.

### Errors

| Error | When | User sees (T59) |
|---|---|---|
| `ImportError::TooLarge` | file > 16 MiB | "The file is too large (max 16 MiB)" |
| `ImportError::NotFileZilla` / `Xml { line, .. }` / `Doctype` | not a FileZilla 3 site file, malformed XML | "Not a FileZilla site manager file" / "XML error at line N" |
| `ImportError::TooDeep` / `TooManyEntries` | limits | message with the limit |
| `Error::InvalidInput` | newer courier-ftp file version, weak passphrase, empty scope | inline message |
| `BackupError::Decrypt` | wrong passphrase / tampered file | "Wrong passphrase or the file was modified" |
| `Error::VaultLocked`, `Error::Vault(..)` | apply while locked, busy DB | unlock / Retry; nothing written |
| `SkipReason`, `NoteKind` | per entry | listed in the import report (escaped path + reason) |

### Security and logging

- Imported files are untrusted: size, depth, count and text-length limits; no DTD or external
  entities; every string is validated by `validate_site` before it reaches the vault; names and
  paths are escaped (control characters shown as `\u{..}`) in the report.
- Decoded FileZilla passwords become `SecretString` immediately; the base64 buffer is
  `Zeroizing`. The plain export and the XML export cannot contain secrets (they are never read
  into the export structs).
- Logs: counts and reasons at `info` (`imported 42 sites, 3 skipped`), never hosts, users,
  names or paths at `info`+ (T91 §4).
- Fuzz target `filezilla_sitemanager_parse` (T91 §7), body `fuzz_parse_sitemanager`, plus a
  courier-file decode target `sites_file_decode` (plain JSON + encrypted header).

## Implementation steps

1. Verify the ⚠ codes against FileZilla's source (`src/include/server.h`, `logon_type.h`,
   `src/interface/xmlfunctions.cpp`, `CServerPath::GetSafePath`) of the current 3.x release;
   fix the table if needed; record the FileZilla version in the fixture's header comment.
2. `parse_sitemanager` (limits, mixed-content names, bookmarks) + fuzz body.
3. Safe-path decoder/encoder with both length conventions.
4. `plan_filezilla` (mapping, notes, skips, `normalize_for_logon`, `validate_site`, unique names)
   and `apply_import` (one `put_many`, device-local dirs).
5. courier-ftp payload, `collect`, `write_plain`, `write_encrypted`, `read_sites_file`,
   `decrypt_sites`, `plan_courier`.
6. `export_filezilla_xml`.
7. Fixtures, snapshots and round-trip tests.

## Acceptance criteria

- [ ] AC1 The fixture `tests/fixtures/filezilla/sitemanager-full.xml` (fake `*.example.test`
  hosts; nested folders; every `Protocol` code 0–7; every `Logontype` 0–6; base64, plain and
  `crypt` passwords; all colours; bookmarks; unicode names; legacy text-node names) imports
  into the tree recorded in the insta snapshot `filezilla_full_import`, with the report
  counting exactly the expected sites, passwords, bookmarks, skips and notes.
- [ ] AC2 `RemoteDir` decoding: `1 0 4 home 4 user` → `/home/user`; `1 0 8 my files 3 web` →
  `/my files/web`; a path with an emoji segment encoded with Windows (UTF-16) lengths and with
  Linux lengths both decode to the same `RemotePath`; `3 0 2 C: 5 Users` → `/C:/Users`;
  encoder ∘ decoder is identity on Unix and DOS paths.
- [ ] AC3 Encrypted courier export → import into a fresh vault reproduces names, every site
  field, passwords, account values, key passphrases, embedded `ssh-key` items, bookmarks and
  default local dirs (with new ids); a wrong passphrase returns `Decrypt` and writes nothing.
- [ ] AC4 A plain export of sites carrying canary password, account, key passphrase and SSH
  private key contains none of the canaries (byte search), and its `normal`/`account` sites
  re-import as `ask-for-password`.
- [ ] AC5 FileZilla XML export of the imported fixture, re-imported through
  `parse_sitemanager`, yields the same tree except passwords (snapshot
  `filezilla_export_roundtrip`) and contains no `<Pass` element.
- [ ] AC6 Malformed inputs (truncated XML, `<!DOCTYPE` with entities, 65 nested folders,
  100 001 servers, a 17 MiB file, invalid UTF-8) return the documented `ImportError` without
  panicking and write nothing; the fuzz target runs 30 s in CI without findings.
- [ ] AC7 `apply_import` is all-or-nothing: an injected store error during the transaction
  leaves the vault without the import folder.
- [ ] AC8 Import of 10 000 sites completes (parse + plan + apply with `Argon2Cost::TEST`) in
  < 5 s in release mode (`benches/import.rs::filezilla_import_10k`).
- [ ] AC9 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os`, `fuzz`, `canary` pass.
- [ ] AC10 `TimezoneOffset` is converted with `stored = local_utc_offset_minutes −
  TimezoneOffset` on import and inverted on XML export (round trip with the same device
  offset is identity); every FileZilla server type maps to one of the five
  `ServerTypeOverride` values.

## Tests

### Unit tests
- `filezilla::tests::protocol_mapping_table`, `logontype_mapping_table`,
  `server_type_mapping_table`, `colour_mapping_table`, `pasv_mode_mapping` — one row per code (AC1).
- `filezilla::tests::timezone_offset_conversion` — device offset +120, FileZilla −120 →
  stored 240; FileZilla 0 → 0; export of 240 with device +120 writes −120 (AC10).
- `filezilla::tests::{pass_base64, pass_plain_legacy, pass_crypt_becomes_ask, pass_invalid_base64}` (AC1).
- `filezilla::tests::{folder_mixed_content_name, legacy_server_text_name, unknown_elements_noted,
  duplicate_names_renamed}`.
- `safepath::tests::{unix, spaces, dos_drive, vms_prefix, emoji_utf16_and_scalar_lengths,
  empty, garbage_returns_none, encode_decode_roundtrip}` (AC2).
- `export::tests::{plain_strips_secrets_and_downgrades_logon, refs_are_consistent,
  newer_version_rejected}` (AC4).
- `export::filezilla::tests::{escapes_xml, no_pass_element, logon_inverse_mapping}` (AC5).

### Property / fuzz tests
- `tests/import_props.rs::parse_never_panics` (proptest: mutated fixture bytes, 2 000 cases) and
  the fuzz targets `filezilla_sitemanager_parse`, `sites_file_decode` (AC6).
- `tests/import_props.rs::safepath_roundtrip` (random Unix paths incl. spaces and non-BMP) (AC2).

### Snapshot tests
- `insta` snapshots of the `ImportPreview` (tree rendered as indented text + report) for
  `sitemanager-full.xml` (`filezilla_full_import`), `sitemanager-minimal.xml`
  (`filezilla_minimal_import`, a FileZilla 3.0-era file with plain passwords and text-node
  names), and the XML export round trip (`filezilla_export_roundtrip`) (AC1, AC5).

### Integration tests
(`crates/courier-ftp-core/tests/site_import_export.rs`, `Argon2Cost::TEST`)
- `t01_filezilla_fixture_into_vault` — apply, then lock/unlock and compare with the preview (AC1).
- `t02_encrypted_export_import_roundtrip` (AC3).
- `t03_wrong_passphrase_writes_nothing` (AC3).
- `t04_plain_export_has_no_canaries` (AC4).
- `t05_xml_export_roundtrip` (AC5).
- `t06_malformed_inputs` (AC6).
- `t07_apply_is_atomic` — store error injected through the test hook of `put_many` (AC7).
- `benches/import.rs::filezilla_import_10k` (AC8).

### End-to-end tests
Not applicable (no network); T59's PTY flow covers the UI.

## Out of scope

- Importing from other clients (WinSCP, PuTTY, Cyberduck, CuteFTP) — see Open questions.
- FileZilla queue, filters, global `bookmarks.xml` and settings import.
- Decrypting FileZilla master-password-protected passwords — see Open questions.
- Sync of exports; backups of the whole vault (T73).

## Open questions

1. Should v1 decrypt FileZilla passwords protected by FileZilla's master password
   (`encoding="crypt"`, libfilezilla public-key scheme: X25519 key pair derived from the master
   password with PBKDF2, AES-256-GCM)? Current spec: such passwords are not imported, the site
   becomes "ask for password" and the report says so.
2. FEATURES §2 says "import from other clients". Which clients besides FileZilla should be
   supported (FileZilla itself imports from WinSCP, CuteFTP, …)? Current spec: FileZilla only.
3. Should the FileZilla XML export offer to include passwords (FileZilla's own export writes them
   as base64, i.e. readable)? Current spec: never.
