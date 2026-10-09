# T73 — Settings import / export

**Phase:** G App-level · **Milestone:** M9 · **Depends on:** T05, T30, T32, T40, T68 · **Crate(s):** `courier-ftp-core` (`backup` module), `courier-ftp` (export/import dialogs) · **Decisions:** D3, D4, D10, D13 · **FEATURES.md:** §10 (settings import and export)
**Related (integrates with, not blocking):** T60
**Reference:** sverb `crates/sverb-core/src/exporters/backup.rs`, `crates/sverb-core/src/importers/{backup.rs,mod.rs}`, `fuzz/fuzz_targets/backup_decrypt.rs`, SPEC §9.13

## Goal

Move a whole courier-ftp setup to another machine, or keep a backup of it, in one
encrypted `.cftp-backup` file: settings, sites with passwords, bookmarks, trusted host
keys and certificates, and optionally the queue and history. Import shows what the file
contains and lets the user pick sections and a merge mode. Settings alone can also be
exported as plain JSON (no secrets). A backup can be restored on the first-run screen to
create a new vault from it.

## Context

- T30 §10 defines the `.cftp-backup` container (JSON header, Argon2id,
  XChaCha20-Poly1305 over `zstd(cbor(…))`, AAD `"courier-ftp-backup-v1"`, 1 GiB
  decompressed cap) in `courier_ftp_core::vault::backup`, ported from sverb's
  `.sverb-backup`: `BackupFile`, `KdfHeader`, `BackupError`, `encrypt`, `decrypt`,
  `read_header`, `kdf_params`, `FORMAT`, `VERSION`, `AAD`, `EXTENSION`, `MAX_PAYLOAD`,
  `BackupPayload { vaults, items }`. This task defines the payload sections on top.
- T05: `Settings`, the user config file, `Settings::save_user`; keybindings, styles and
  filters (T47 `filters`) live in the same config.
- T30/T81/T82: `VaultEngine` (`list`, `put`, item merge), item kinds `site`,
  `site-folder`, `bookmark`, `known-host`, `trusted-cert`, `ssh-key`, `proxy-credential`,
  `history-entry`, `credential-override`; HLC-stamped `ItemBody`.
- T32: site export/import helpers and the "Imported … <date>" folder convention.
- T40: queue export JSON (no secrets).
- T68: the Settings screen hosts the Import/Export buttons; T60's first-run and
  "forgot password" screens offer "Restore from backup".

## Technical specification

### Types and APIs

`courier_ftp_core::backup` (core; no UI deps):

```rust
/// Sections a backup can contain. Serialised kebab-case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackupSection {
    Settings,       // user config: settings, keybindings, styles, filters
    Sites,          // site, site-folder, bookmark, ssh-key, proxy-credential items
    Trust,          // known-host, trusted-cert items
    History,        // history-entry items
    Queue,          // T40 export (no secrets)
}

/// The decrypted payload, version 1. Extends T30's `BackupPayload`; every field
/// added after v1 must be `#[serde(default)]` so older readers ignore it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BackupPayload {
    /// Sections the writer put in, as strings (unknown names are kept and reported).
    pub sections: Vec<String>,
    /// The personal vault only (team vaults are not exported).
    pub vaults: Vec<BackupVault>,
    /// Items with ids and full HLC stamps (secrets included), tombstones included.
    pub items: Vec<BackupItem>,
    #[serde(default)] pub settings: Option<SettingsSection>,
    #[serde(default)] pub queue: Option<QueueExport>,        // T40 type
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettingsSection {
    /// The user config file content after removing device-specific keys, as JSON text.
    pub config_json: String,
    /// `CARGO_PKG_VERSION` of the writer (for migration messages).
    pub app_version: String,
}

/// What the user picked in the export dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOptions { pub sections: BTreeSet<BackupSection> }

/// Builds the payload from the unlocked vault and the config dir.
pub async fn collect(vault: &VaultEngine, config_dir: &Path, queue: Option<&Queue>, opts: &ExportOptions)
    -> Result<BackupPayload, BackupError>;

/// Encrypts and writes atomically (temp file + rename, 0600). Runs Argon2 in `spawn_blocking`.
pub async fn write_backup(path: &Path, payload: BackupPayload, password: SecretString, cost: Argon2Cost)
    -> Result<(), BackupError>;

/// Reads and decrypts (file size checked first). Runs Argon2 in `spawn_blocking`.
pub async fn read_backup(path: &Path, password: SecretString) -> Result<BackupPayload, BackupError>;

/// Read-only summary for the preview screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSummary {
    pub created_at: String, pub app_version: String,
    pub sections: Vec<SectionSummary>,     // known sections with counts
    pub unknown_sections: Vec<String>,     // skipped with a warning
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionSummary { pub section: BackupSection, pub items: usize, pub secrets: usize }
pub fn summarize(file: &BackupFile, payload: &BackupPayload) -> BackupSummary;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsImportMode { Replace, Merge }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemImportMode {
    /// Keep ids; same id → field-level merge by HLC stamps (T81); new ids added.
    Merge,
    /// New ids; sites and folders go under a new folder "Imported from backup <date>".
    Copy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportOptions {
    pub sections: BTreeSet<BackupSection>,
    pub settings_mode: SettingsImportMode,
    pub items_mode: ItemImportMode,
    /// Import settings that run programs (editor, associations, queue command). Default false.
    pub allow_commands: bool,
}

/// Dry run: what an import would do. No writes.
pub async fn plan_import(vault: &VaultEngine, config_dir: &Path, payload: &BackupPayload, opts: &ImportOptions)
    -> Result<ImportReport, BackupError>;
/// Applies the import (items in one vault write transaction; config via atomic file replace).
pub async fn apply_import(vault: &VaultEngine, config_dir: &Path, queue: Option<&mut Queue>,
    payload: BackupPayload, opts: &ImportOptions) -> Result<ImportReport, BackupError>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub added: usize, pub updated: usize, pub unchanged: usize,
    /// Same id changed on both sides; merged field by field (newer stamp wins).
    pub merged_conflicts: usize,
    pub skipped: Vec<(String, SkipReason)>,   // label (escaped) + reason
    pub settings_changed_keys: Vec<String>,
    pub warnings: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason { UnknownKind, NewerSchema, CommandNotAllowed, TeamVaultItem, Invalid(String) }

/// Plain settings export (no secrets by construction).
pub fn export_settings_json(config_dir: &Path, now: OffsetDateTime) -> Result<String, BackupError>;
pub fn import_settings_json(text: &str) -> Result<SettingsSection, BackupError>;

/// Fuzz entry (T91 §7 `backup_decrypt`): header parse + decrypt with a fixed key + decode.
pub fn fuzz_backup_decrypt(data: &[u8]);
```

UI (`crates/courier-ftp/src/components/backup/{export,import}.rs`): `ExportDialog`,
`ImportWizard`, and `RestoreFromBackup` (first-run flow for T60).

### Behaviour

**Export** (Settings → Import/Export → *Export…*, T68):
1. Checkboxes (defaults): [x] Settings, [x] Sites, bookmarks and SSH keys, [x] Trusted
   host keys and certificates, [ ] Connection history, [ ] Transfer queue. At least one
   must be checked.
2. Format: (•) Encrypted backup `.cftp-backup` ( ) Plain settings JSON (only when *only*
   Settings is checked; the other boxes are disabled when plain is selected).
3. Encrypted: export password + confirm (masked, T52), zxcvbn score ≥ 3 with feedback
   (same rule and user-input list as T30: `["courier-ftp", "backup"]`), note: "This
   password is needed to import the file. It is not your master password."
4. Path: `PathInput` default `~/courier-ftp-<YYYY-MM-DD>.cftp-backup` (or `.json`); ask
   before overwrite.
5. `ProgressDialog` while collecting, Argon2 (`m = 256 MiB, t = 3, p = 1`, T30 defaults)
   and writing; Cancel stops before the file is renamed into place.
6. Result: `Backup written: 42 sites, 3 bookmarks, 12 trusted keys (2.1 KiB)`.

The vault must be unlocked for every section except Settings; locked → the vault
sections are disabled with "Unlock the vault to export sites".

**Collect rules:**
- Items: only the personal vault (`VaultId` of kind personal). Team vault items
  (T89) are not exported; their count is shown as a note ("12 team items are not included;
  they are restored by logging in to your team").
- Item → section: `site`, `site-folder`, `bookmark`, `ssh-key`, `proxy-credential` →
  Sites; `known-host`, `trusted-cert` → Trust; `history-entry` → History.
  `credential-override` items go with Sites. Tombstones of exported kinds are included so
  deletes survive a restore (sverb rule).
- `vault.store_passwords = false` has no effect on export: items contain only what was
  stored.
- Device-local data (T82 `device_local`, recent servers, tab state, `local_approvals`)
  is never exported. The queue is exported only via its T40 export form (no secrets).
- Settings: the user config file(s) in the config dir merged into one JSON object
  (T05 layering minus the built-in defaults, so only user overrides), with these
  device-specific keys removed: `logging.log_file`, `config_dir`, `data_dir`. Keybindings,
  styles and `filters` are included.

**Plain settings JSON** (`.json`):

```json
{
  "format": "courier-ftp-settings",
  "version": 1,
  "created_at": "2026-10-09T12:00:00Z",
  "app_version": "1.0.0",
  "settings": { "transfers": { "max_concurrent": 6 }, "keybindings": { … } }
}
```

**Import** (Settings → *Import…*, or a `.cftp-backup`/`.json` path):
1. Choose file. Size > 1 GiB → `TooLarge` error before reading. `.json` with
   `format = "courier-ftp-settings"` → settings-only flow (no password). Otherwise read
   the header (`read_header`): wrong `format` → `NotABackup`; `version > 1` →
   `UnsupportedVersion`.
2. Password prompt; Argon2 in the background with a progress dialog; wrong password →
   `Decrypt` error, prompt again (no lockout; the file is offline data).
3. Preview (`summarize` + `plan_import` dry run): created date, writer version, sections
   with counts, unknown sections listed as "skipped (written by a newer courier-ftp)".
   Per section checkbox (default all known ones checked). Options:
   - Settings: (•) Merge ( ) Replace.
   - Items: (•) Merge with existing items ( ) Import as copies.
   - [ ] Also import settings that run programs: shows each such value in full
     (`editing.editor`, every `editing.associations[].command`, `queue.on_complete` when it
     is `RunCommand`). Unchecked → those keys keep their current local values and are
     listed under *skipped*.
   The dry-run counts update when options change: `+12 new, 3 updated, 1 merged, 40 unchanged`.
4. Apply → report dialog with counts, skipped entries and warnings.

**Settings import modes:**
- **Merge**: deep-merge the backup's JSON into the current user config: objects merge
  recursively, scalars and arrays from the backup replace local ones, keys absent from the
  backup stay. Then validate (T05 rules: invalid values warn and fall back) and write via
  the same code path as `Settings::save_user` (unknown keys preserved).
- **Replace**: the user config becomes exactly the backup's settings plus the local
  device-specific keys listed above. The previous file is kept as
  `config.json.bak-<YYYYmmddTHHMMSSZ>` in the config dir.
- Both apply live where T68 supports live apply; others show "restart or reconnect to apply".

**Item import modes:**
- **Merge** (default): for each backup item of a selected section:
  - id absent locally → insert with its stamps (`added`);
  - id present → T81 `merge(local, backup)`; result identical to local → `unchanged`;
    identical to backup → `updated`; otherwise `merged_conflicts`;
  - kind unknown to this build → skipped `UnknownKind`; `schema_version` newer than this
    build → kept as-is per T81 (read-only) and counted, with a warning;
  - all writes go through `VaultEngine` in **one** write transaction, mark items dirty
    and add outbox rows (T82), so a synced account pushes them (T88).
  Re-importing the same backup is idempotent (second run: all `unchanged`).
- **Copy**: every imported item gets a new `ItemId`; references are rewritten through an
  old→new id map (folder `parent`, bookmark `site_id`, site `ssh-key` reference,
  `proxy-credential` ids in settings); top-level sites/folders go under a new folder
  `Imported from backup <YYYY-MM-DD>` (T32 convention). Fields are re-stamped with the
  local HLC. `known-host`/`trusted-cert` items are never copied: an identical
  host+fingerprint already present → `unchanged`, otherwise added once.
- Items that reference ids not in the backup and not in the vault (dangling `site_id`,
  `parent`) are imported with the reference cleared and a warning.
- Queue: imported through T40's import (resolves `SiteId`s, quickconnect items without
  secrets become ask-for-password); appended to the queued list, not started.

**Restore on first run** (T60 "Restore from backup"): file → backup password → preview
(all sections, Merge mode, `allow_commands` unchecked by default) → set a **new master
password** (T30 strength rule) and keyring checkbox → `VaultEngine::initialize` →
`apply_import` with Merge (ids and stamps kept) → unlocked app. If import fails after
initialize, the new empty vault stays and the error is shown with "Try again".
Also offered from T60's "Forgot password → no recovery" screen (the old DB is moved aside
by T60 first).

### Data formats and configuration

**Container**: T30 §10 / sverb format, JSON, pretty-printed, trailing newline:

```json
{ "format": "courier-ftp-backup", "version": 1,
  "kdf": { "alg": "argon2id", "m_kib": 262144, "t": 3, "p": 1, "salt_b64": "…" },
  "nonce_b64": "…", "ciphertext_b64": "…",
  "created_at": "2026-10-09T12:00:00Z", "app_version": "1.0.0" }
```

- `ciphertext = XChaCha20-Poly1305(key = Argon2id(password, salt), nonce, AAD = "courier-ftp-backup-v1", zstd_level_9(cbor(BackupPayload)))`.
- KDF bounds checked before Argon2 runs (T30: `m ≥ 19 MiB`, `m ≤ 4 GiB`, `t ≤ 64`, `p ≤ 16`).
- Decompression stops at `MAX_PAYLOAD = 1 GiB` (+1 byte read → `Corrupt`).
- File extension `.cftp-backup`; plain settings `.json`.
- CBOR payload map keys (v1): `sections`, `vaults`, `items`, `settings`, `queue`.
  `BackupVault = { id, name, kind, defaults }`, `BackupItem = { id, vault, body }` (sverb).
- **Versioning**: `version` in the header changes only for an incompatible container or
  crypto change. New payload content is added as new optional CBOR keys and new
  `sections` names; readers ignore unknown keys and report unknown section names
  (forward compatible within version 1).

No new settings keys.

### Errors

`BackupError` (T30, extended here; messages are what the user sees):

| Variant | When | Message |
|---|---|---|
| `NotABackup(String)` | bad JSON, other `format` | `not a courier-ftp backup: <reason>` |
| `UnsupportedVersion(u32)` | `version > 1` | `this backup has format version N; this courier-ftp reads version 1. Update courier-ftp to import it` |
| `Decrypt` | wrong password or modified file | `cannot decrypt the backup: wrong export password, or the file was modified` |
| `Corrupt(String)` | bad CBOR/zstd, payload > 1 GiB | `the backup is corrupted: <reason>` |
| `Kdf(String)` | params out of bounds | `invalid key-derivation parameters: <reason>` |
| `WeakPassword(String)` | zxcvbn < 3 | zxcvbn feedback |
| `TooLarge(u64)` | file > 1 GiB | `the file is too large to be a backup (N bytes)` |
| `Io(std::io::Error)` | read/write | `cannot read/write <path>: <error>` |
| `VaultLocked` | vault sections without unlock | `unlock the vault first` |
| `Vault(core::Error)` | vault write failed | underlying message; transaction rolled back, nothing imported |

### Security and logging

- The backup contains every secret of the exported items. The export password is a
  `SecretString`, dropped after use; derived keys are `Key32` (zeroized); CBOR and
  compressed buffers are `Zeroizing<Vec<u8>>` (sverb).
- Files are written `0600` via temp file + rename in the target directory; the temp file
  is removed on error or cancel.
- The plain settings export contains no secrets **by construction** (settings never hold
  passwords, T05) and a test plants a canary in every secret-bearing place to prove it.
- Importing is an explicit user action, but settings that run programs are shown in full
  and need the extra checkbox (same spirit as T91 §8 local approvals). Imported `site`
  items with local-acting fields (`key_file` local path, `Agent` logon) still go through
  T91 §8 approval on first use, because they did not originate on this device: imported
  items are **not** pre-approved.
- Untrusted input: header parsed with size limit (1 GiB file, 64 KiB header fields),
  base64 decoded with length checks, KDF bounds checked before Argon2, zstd bomb guard,
  CBOR decode errors are `Corrupt` (never panics). Labels from the backup shown in the
  preview pass through the control-character escaper (T71).
- Fuzz target `backup_decrypt` (T91 §7) calls `fuzz_backup_decrypt`; its body is also a
  proptest in the crate.
- Logging: `info!` only counts and section names (`backup written: sites=42 trust=12`),
  never labels, hosts, paths or the file path; `debug!` may include the file path.

## Implementation steps

1. `backup` module: `BackupSection`, payload v1 types (extending T30's), `summarize`,
   CBOR round-trip tests, `fuzz_backup_decrypt` + proptest.
2. `collect` for each section (personal-vault filter, kinds → sections, tombstones,
   settings with device keys removed) and `write_backup`/`read_backup` with size checks.
3. Plain settings JSON export/import.
4. `plan_import`/`apply_import`: Merge mode via T81 merge in one transaction; settings
   Merge/Replace with backup file; command-setting filter.
5. Copy mode with id remapping and the "Imported from backup" folder; queue import.
6. UI: `ExportDialog`, `ImportWizard` (file → password → preview → report) in T68's
   Import/Export section.
7. `RestoreFromBackup` flow for T60's first-run and no-recovery screens.
8. Fuzz target registration in `fuzz/` and T00's fuzz matrix.

## Acceptance criteria

- [ ] AC1 Export of all sections then import into a fresh `COURIER_FTP_HOME` (restore on
  first run) reproduces the user config (JSON-equal after removing device keys) and every
  exported item with identical ids, bodies and stamps.
- [ ] AC2 Re-importing the same backup into the same vault reports 0 added, 0 updated,
  everything unchanged, and changes nothing in the DB.
- [ ] AC3 Merge with concurrent edits: a site renamed locally after export and its
  password changed in the backup ends with both changes (field-level merge).
- [ ] AC4 Copy mode creates new ids, keeps folder/bookmark/key references consistent, and
  puts everything under one `Imported from backup <date>` folder.
- [ ] AC5 Partial import: only the selected sections change; unselected sections and the
  config file are untouched (hash compare).
- [ ] AC6 The plain settings JSON and every exported file's header contain none of the
  planted canary secrets; the encrypted file contains no plaintext canary either.
- [ ] AC7 Wrong password → `Decrypt`; modified ciphertext byte → `Decrypt`; `version: 2`
  → `UnsupportedVersion`; out-of-bounds KDF params → `Kdf` without running Argon2;
  1 GiB+1 decompressed → `Corrupt`; > 1 GiB file → `TooLarge`.
- [ ] AC8 A payload with an unknown section name and an unknown CBOR key imports the known
  parts and reports the unknown section as skipped.
- [ ] AC9 Command-running settings are not imported unless `allow_commands` is checked.
- [ ] AC10 Snapshot tests for export, password, preview and report dialogs at 80×24 and 160×48.
- [ ] AC11 T00 gates pass, including `fuzz` (target `backup_decrypt` runs 30 s in PR CI) and `canary`.

## Tests

### Unit tests
- `payload_cbor_roundtrip_all_sections` (AC1).
- `collect_excludes_team_vault_and_device_local` (AC1).
- `collect_includes_tombstones` (AC1).
- `settings_export_removes_device_keys` (AC1).
- `merge_import_idempotent` (AC2).
- `merge_import_field_level_conflict` — HLC-stamped edits on both sides (AC3).
- `copy_import_remaps_references_and_folder` (AC4).
- `copy_import_dedups_known_hosts_by_fingerprint` (AC4).
- `partial_import_touches_only_selected_sections` (AC5).
- `settings_merge_deep_and_arrays_replaced`, `settings_replace_keeps_bak_file` (AC5).
- `plain_settings_json_has_no_canary`, `encrypted_file_has_no_plaintext_canary` (AC6).
- `decrypt_wrong_password`, `decrypt_tampered_byte`, `header_version_2_rejected`, `kdf_bounds_checked_before_argon2`, `zstd_bomb_rejected`, `file_over_1gib_rejected_before_read` (AC7; Argon2 test cost, sparse file for size).
- `unknown_section_and_key_skipped_with_warning` (AC8).
- `command_settings_filtered_without_allow_commands` (AC9).
- `weak_export_password_rejected` (zxcvbn).

### Property / fuzz tests
- `prop_fuzz_backup_decrypt_never_panics` — proptest calling `fuzz_backup_decrypt` with arbitrary bytes and mutated valid files (AC7).
- Fuzz target `fuzz/fuzz_targets/backup_decrypt.rs` (T91 §7) (AC11).
- `prop_merge_import_commutes_with_local_edits` — random edit sequences; importing then editing equals T81 merge result (AC3).

### Snapshot tests
- `export_dialog_80x24`, `export_dialog_160x48`, `export_password_weak_80x24`, `import_preview_80x24`, `import_preview_160x48`, `import_preview_commands_listed_80x24`, `import_report_80x24`, `import_report_160x48`, `restore_first_run_80x24` (AC10).

### Integration tests
- `export_import_fresh_home_roundtrip` — `TestHome` with sites (passwords), bookmarks, known hosts, certs, filters and custom keybindings; export; restore into a second home via the `RestoreFromBackup` flow driven by synthetic keys; compare (AC1).
- `restore_then_unlock_connects_without_password_prompt` — mock backend factory receives the site password (AC1).
- `import_into_synced_vault_marks_outbox` — items dirty and outbox rows present (AC1).

### End-to-end tests
- `e2e_backup_restore_pty` (`#[ignore]`, `COURIER_E2E=1`): `PtyApp` creates a vault, adds a site for the `sshd` `password` profile, exports a backup, starts a second home, restores on first run, connects without a password prompt (AC1).

## Out of scope

- Headless CLI export/import commands (T70 has no headless subcommands).
- Exporting team vaults; importing FileZilla settings (`filezilla.xml`) or FileZilla
  queues (T32 covers FileZilla sites only).
- Scheduled/automatic backups.
- Encrypting the plain settings JSON.

## Open questions

- T32 describes its encrypted site export as "same container format as T30, separate
  magic `CFTPEXP\0`", but T30's container is JSON with a `format` field, not a binary
  magic. Proposed for T32: a JSON header with `"format": "courier-ftp-sites"` and AAD
  `"courier-ftp-sites-v1"`, reusing this module's container code. (T32 is not owned by
  this task; flagged for its owner.)
