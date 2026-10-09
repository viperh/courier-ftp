# T68 — Settings screen

**Phase:** F TUI · **Milestone:** M6 · **Depends on:** T05, T52, T60 · **Crate(s):** `courier-ftp` (`components/settings/`), field metadata in `courier-ftp-core::settings` · **Decisions:** D3, D6, D10 · **FEATURES.md:** §1, §3, §5, §6, §9, §10
**Related (integrates with, not blocking):** T12, T21, T73, T74, T75, T90

## Goal

Edit every setting from T05 inside the app (F9), organised like FileZilla's
Settings dialog: a section tree on the left, a form on the right with one-line help
for the focused field, inline validation identical to T05, and Save / Reset section
/ Cancel. Saved changes take effect without a restart wherever possible; network
settings apply to new connections. The screen also hosts the vault security flows
(T60), the trusted host key and certificate lists (T21, T12), and entry points for
sync (T90) and settings import/export (T73).

## Context

Before this task:
- T05 provides `Settings` with all sections, validation (invalid values → warning +
  default), and `Settings::save_user(config_dir)` (writes only non-default values,
  preserves unknown keys, keybindings and styles).
- T52 provides `TabbedForm`, `TextInput`, `NumberInput`, `Checkbox`, `Select`,
  `RadioGroup`, `ListView`, `PathInput`, `confirm`, `prompt_password`.
- T60 provides the vault flows used by the Security section (change master password,
  keyring unlock on/off, lock now, Argon2 cost presets with measured unlock time).
- Keys and sections added by later tasks (`vault`, `sync`, `transfers.segmented`,
  `sftp`, `interface.*`, `logging.show_timestamps`, `queue.notify`,
  `editing.max_size_mib`, `interface.check_prereleases`, `filters`) are edited here
  when they exist; the field registry below lists them all.

Related, not blocking: T21/T12 store management APIs (list/delete), T90 sync
screens, T73 import/export, T74 update settings, T75 language list. Until a related
task lands, its page or fields are hidden (the registry entry is behind a cfg or a
runtime "available" check).

## Technical specification

### Types and APIs

Core (`courier-ftp-core/src/settings/fields.rs`) — UI-independent metadata:

```rust
/// Where a setting can be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyWhen {
    Live,              // takes effect right after Save
    NewConnections,    // existing sessions keep the old value
    NextStart,         // read only at startup
}

/// Metadata for one leaf setting (one per T05 key).
#[derive(Debug, Clone, Copy)]
pub struct FieldSpec {
    pub key: &'static str,          // dotted path, e.g. "connection.timeout_secs"
    pub label: &'static str,
    pub help: &'static str,         // one line, from the T05 rustdoc
    pub apply: ApplyWhen,
}

/// All leaf settings, in display order. A test checks this covers every leaf of
/// `serde_json::to_value(Settings::default())`.
pub static FIELDS: &[FieldSpec] = &[ /* … */ ];

/// Validation used by both config loading (T05) and this screen.
pub fn validate_field(key: &str, value: &serde_json::Value, whole: &Settings)
    -> Result<(), String>;
```

Binary (`crates/courier-ftp/src/components/settings/`: `screen.rs`, `tree.rs`,
`form.rs`, `widgets.rs`, `sections/*.rs`, `stores.rs`, `security.rs`):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionId {
    Connection, Ftp, FtpProxy, GenericProxy, Sftp, TlsCertificates,
    Transfers, FastTransfers, FileTypes, FileExists,
    Interface, FileLists, Comparison, Theme, Keybindings,
    Editing, Queue, Logging, Security, Sync, ImportExport,
}

/// The settings screen (full-screen modal).
pub struct SettingsScreen {
    saved: Arc<Settings>,      // what is in effect
    draft: Settings,           // edited copy
    errors: BTreeMap<&'static str, String>,
    section: SectionId,
    focus: Focus,              // Tree | Form(field index) | Buttons
    pending_secrets: Vec<PendingSecret>, // proxy passwords to write to the vault on Save
}

impl SettingsScreen {
    pub fn open(settings: Arc<Settings>, start: Option<SectionId>) -> Self;
    pub fn is_dirty(&self) -> bool;
    pub fn reset_section(&mut self, s: SectionId);
    /// Validates, writes the vault items, calls `Settings::save_user`, and
    /// returns the actions to broadcast (`SettingsChanged(Arc<Settings>)`).
    pub fn save(&mut self, ctx: &mut SaveContext) -> Result<Vec<Action>, SaveError>;
}

/// Proxy password typed in the form; written as a `proxy-credential` item on Save.
pub struct PendingSecret { pub key: &'static str, pub value: SecretString }
```

New `Action` variants: `OpenSettings(Option<SectionId>)`,
`SettingsChanged(Arc<Settings>)` (broadcast; components and the engine re-read).

### Behaviour

#### Layout

```
┌ Settings ──────────────────────────────────────────────────────────────────────┐
│ ▾ Connection            │ Connection                                           │
│     FTP                 │ Timeout (seconds):            [20____]               │
│     FTP proxy           │ Number of retries:            [2_____]               │
│     Generic proxy       │ Delay between retries (s):    [5_____]               │
│     SFTP                │ [x] Send keep-alive commands                         │
│     TLS certificates    │ Keep-alive interval (s):      [30____]               │
│ ▸ Transfers             │ [ ] Prefer IPv6                                      │
│ ▸ Interface             │                                                      │
│   Editing               │                                                      │
│   Queue                 │                                                      │
│   Logging               │                                                      │
│   Security              │                                                      │
│   Sync & teams          │                                                      │
│   Import / export       │                                                      │
├─────────────────────────┴──────────────────────────────────────────────────────┤
│ Seconds without any data before the connection is dropped. (new connections)  │
│ [ Save ]   [ Reset section ]   [ Cancel ]                         ● unsaved    │
└────────────────────────────────────────────────────────────────────────────────┘
```
- At 80×24 the tree is 22 columns wide, the form scrolls vertically; the help line
  wraps to at most 2 lines.
- Opened with `F9` (T51), or from other screens with a section
  (`OpenSettings(Some(Security))` from the status bar vault indicator, `Comparison`
  from T66, `Editing` from T63's "no editor" error).

#### Keys

| Key | In tree | In form |
|---|---|---|
| `j`/`k`/`↓`/`↑` | move | — (`↓`/`↑` inside lists/selects) |
| `l`/`→`/`Enter` | expand / focus form | `Enter` activates button or opens select |
| `h`/`←` | collapse / parent | — |
| `Tab` / `Shift-Tab` | to form | next / previous field (T52) |
| `Esc` | close (guard if dirty) | back to tree |
| `Ctrl-s` | Save | Save |
| `Ctrl-r` | Reset section (confirm) | Reset section (confirm) |
| `/` | jump to a field by label (fuzzy, all sections) | — |

The global keymap is inactive while the screen is open, except `F1` (help) and
`Ctrl-q`/`F10` (quit, with the dirty guard first).

#### Draft, validation, save

1. Opening copies the live `Settings` into `draft`. Every edit updates `draft` and
   runs `validate_field` for that key (plus cross-field rules below); errors are
   shown under the field and in the tree (section name gets `!`).
2. Cross-field rules (T05/T15): `active_port_range` from ≤ to; `max_downloads` and
   `max_uploads` ≤ `max_concurrent`; generic proxy and FTP proxy not both active;
   `invalid_char_replacement` itself valid on the local OS; `min_segment_size_mib`
   ≤ `min_file_size_mib`; log file path's parent directory exists.
3. **Save** (`Ctrl-s` or button): blocked while any error exists (focus jumps to the
   first error). Order: (a) write `PendingSecret`s as `proxy-credential` items via
   `VaultEngine::put` (T30) and put their ids into the draft; (b)
   `draft.save_user(config_dir)`; (c) swap the live settings and broadcast
   `SettingsChanged(Arc<Settings>)`; (d) send `SettingsChanged` to the transfer
   engine (T41) and the log filter (T04). A failure in (a) or (b) shows an error
   dialog and leaves the live settings unchanged; the draft is kept.
4. **Reset section**: confirm "Reset all settings on this page to their defaults?",
   then set this page's keys in the draft to `Settings::default()` values (not
   saved until Save).
5. **Cancel** / `Esc` with a dirty draft: dialog *Save* / *Discard* / *Cancel*.
6. Apply timing per field (`ApplyWhen`): `Live` fields take effect after Save;
   `NewConnections` fields show "(new connections)" in their help line and a status
   message after Save: "Network settings apply to new connections"; `NextStart`
   fields show "(next start)".

#### Sections and fields

Widget abbreviations: **Num** `NumberInput` (range), **Chk** `Checkbox`, **Sel**
`Select`, **Rad** `RadioGroup`, **Txt** `TextInput`, **Path** `PathInput`, **Pw**
masked input. Apply: L = Live, N = New connections, S = Next start.

**Connection**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Timeout (seconds) | `connection.timeout_secs` | Num | 5–600 (default 20) | N |
| Number of retries | `connection.retries` | Num | 0–99 (2) | L |
| Delay between retries (s) | `connection.retry_delay_secs` | Num | 0–999 (5) | L |
| Send keep-alive commands | `connection.keepalive` | Chk | (true) | N |
| Keep-alive interval (s) | `connection.keepalive_interval_secs` | Num | 10–3600 (30) | N |
| Prefer IPv6 | `connection.prefer_ipv6` | Chk | (false) | N |

**Connection → FTP**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Transfer mode | `ftp.transfer_mode` | Rad | Passive / Active | N |
| Fall back to active mode | `ftp.fallback_to_active` | Chk | (true) | N |
| External IP for active mode | `ftp.active_external_ip` | Rad + Txt | Ask the OS (`Auto`) / Fixed IP (`Fixed`, valid IPv4/IPv6) / Get from URL (`FromUrl`, `https://` or `http://` URL) | N |
| Limit local ports for active mode | `ftp.active_port_range` | Chk + 2× Num | 1024–65535, from ≤ to; unchecked = `None` | N |
| Ignore unroutable passive IP | `ftp.passive_ignore_unroutable_ip` | Chk | (true) | N |
| Use MLSD when available | `ftp.use_mlsd` | Chk | (true) | N |
| Keep-alive command | `ftp.send_keepalive_command` | Sel | values of T05's type (default `NOOP`) | N |
| Network wizard… | — | button | opens T72 when available | — |

**Connection → FTP proxy**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Type | `proxy.ftp_proxy` (variant) | Rad | None / USER@HOST / SITE / OPEN / Custom | N |
| Proxy host | `proxy.ftp_proxy.host` | Txt | non-empty host when type ≠ None | N |
| Proxy port | `proxy.ftp_proxy.port` | Num | 1–65535 (21) | N |
| Proxy user | `proxy.ftp_proxy.user` | Txt | optional | N |
| Proxy password | vault `proxy-credential` item referenced from `proxy.ftp_proxy` | Pw | optional; needs the vault unlocked | N |
| Custom login script | `proxy.ftp_proxy` `Custom(script)` | multi-line Txt (≤ 20 lines) | placeholders `%h %u %p %a %s %w` (T15) | N |

**Connection → Generic proxy**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Type | `proxy.generic` (variant) | Rad | None / HTTP/1.1 CONNECT / SOCKS4 / SOCKS5 | N |
| Proxy host | `proxy.generic.host` | Txt | non-empty when type ≠ None | N |
| Proxy port | `proxy.generic.port` | Num | 1–65535 (8080 HTTP, 1080 SOCKS on type switch) | N |
| Proxy user | `proxy.generic.user` | Txt | optional (not for SOCKS4 password) | N |
| Proxy password | vault `proxy-credential` item referenced from `proxy.generic` | Pw | optional; SOCKS4 has none; needs the vault unlocked | N |

**Connection → SFTP**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Outstanding requests per file | `sftp.max_outstanding_requests` | Num | 1–256 (64) | N |
| Request size (KiB) | `sftp.request_size` | Num | 4–255 KiB (32) | N |
| Trusted host keys | `known-host` items (T21 `HostKeyStore`) | list, see "Trust stores" | — | L |

**Connection → TLS certificates**

| Label | Key | Widget | Apply |
|---|---|---|---|
| Trusted certificates | `trusted-cert` items (T12 `CertTrustStore`) | list, see "Trust stores" | L |

**Transfers**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Maximum simultaneous transfers | `transfers.max_concurrent` | Num | 1–16 (4) | L |
| Limit for downloads | `transfers.max_downloads` | Num | 0–16, 0 = no extra limit | L |
| Limit for uploads | `transfers.max_uploads` | Num | 0–16, 0 = no extra limit | L |
| Enable speed limits | `transfers.speed_limit_enabled` | Chk | (false) | L |
| Download limit (KiB/s) | `transfers.download_limit_kib` | Num | 0–10 000 000, 0 = unlimited | L |
| Upload limit (KiB/s) | `transfers.upload_limit_kib` | Num | 0–10 000 000, 0 = unlimited | L |
| Burst tolerance | `transfers.burst_tolerance` | Sel | Normal / High / Very high | L |
| Preallocate disk space | `transfers.preallocate` | Chk | (false) | L |
| Preserve timestamps | `transfers.preserve_timestamps` | Chk | (false) | L |
| Replace invalid characters | `transfers.replace_invalid_chars` | Chk | (true) | L |
| Replacement character | `transfers.invalid_char_replacement` | Txt (1 char) | must be valid on this OS | L |
| Empty directories | `transfers.empty_dirs` | Rad | Create / Skip | L |
| Follow symbolic links | `transfers.follow_symlinks` | Chk | (false) | L |

**Transfers → Fast transfers**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Split large files | `transfers.segmented.enabled` | Chk | (true) | L |
| Minimum file size (MiB) | `transfers.segmented.min_file_size_mib` | Num | 1–100 000 (32) | L |
| Maximum segments | `transfers.segmented.max_segments` | Num | 1–16 (4) | L |
| Minimum segment size (MiB) | `transfers.segmented.min_segment_size_mib` | Num | 1–100 000 (8), ≤ min file size | L |

**Transfers → File types**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Default transfer type | `file_types.default_type` | Rad | Auto / ASCII / Binary | L |
| ASCII extensions | `file_types.ascii_extensions` | Txt (space-separated) | tokens `[A-Za-z0-9_+-]{1,16}`, lower-cased, de-duplicated; "Restore default list" button | L |
| Dotfiles are ASCII | `file_types.dotfiles_ascii` | Chk | (true) | L |
| Files without extension are ASCII | `file_types.no_extension_ascii` | Chk | (true) | L |

**Transfers → File exists action**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Downloads | `transfers.on_exists_download` | Sel | Ask, Overwrite, Overwrite if newer, Overwrite if size differs, Overwrite if newer or size differs, Resume, Rename, Skip (`ExistsAction`) | L |
| Uploads | `transfers.on_exists_upload` | Sel | same | L |

**Interface**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Layout | `interface.layout` | Rad | Classic / Explorer / Widescreen | L |
| Swap local and remote panes | `interface.swap_panes` | Chk | (false) | L |
| Show directory trees | `interface.show_tree` | Chk | (false) | L |
| Show message log | `interface.show_log` | Chk | (true) | L |
| Show queue | `interface.show_queue` | Chk | (true) | L |
| Show quickconnect bar | `interface.show_quickconnect` | Chk | (true) | L |
| Unicode symbols | `interface.unicode_symbols` | Rad | Auto / On / Off | L |
| Confirm deletions | `interface.confirm_delete` | Chk | (true) | L |
| Confirm transfers | `interface.confirm_transfer` | Chk | (false) | L |
| Restore tabs on start | `interface.restore_tabs` | Chk | (T61 default) | S |
| Language | `interface.language` | Sel | "Automatic" + languages shipped by T75 | L |
| Show splash screen | `interface.show_splash` | Chk | (false) | S |
| Check for updates | `interface.check_updates` | Chk | (true) | S |
| Include pre-releases | `interface.check_prereleases` | Chk | (false) | S |

**Interface → File lists**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Size format | `interface.size_format` | Rad | Bytes / IEC (KiB) / SI (kB) | L |
| Thousands separator | `interface.thousands_separator` | Chk | (true) | L |
| Date format | `interface.date_format` | Txt | strftime-like (T05); live preview line with the current date | L |
| Time format | `interface.time_format` | Txt | same; live preview | L |
| Directories first | `interface.dirs_first` | Chk | (true) | L |
| Case-sensitive sorting | `interface.sort_case_sensitive` | Chk | (false) | L |
| Natural sorting (file2 < file10) | `interface.natural_sort` | Chk | (T53 default) | L |
| Show hidden local files | `interface.show_hidden_local` | Chk | (false) | L |
| Force showing hidden remote files | `interface.force_show_hidden_remote` | Chk | (false) — refreshes remote panes | L |
| Columns | `interface.columns.local`, `interface.columns.remote` | column list: visibility `Space`, order `J`/`K` per side (widths stay config-only) | L |
| Cache directory listings | `cache.listing_cache` | Chk | (true) | L |
| Cache lifetime (s) | `cache.listing_cache_ttl_secs` | Num | 0–86 400, 0 = until refresh | L |
| Filters… | `filters.*` | button → T67 dialog (`filters.apply_to_transfers` is edited there) | L |

**Interface → Directory comparison** (keys from T66)

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Compare by | `compare.mode` | Rad | Modification time / File size | L |
| Threshold (minutes) | `compare.threshold_minutes` | Num | 0–1440 (1) | L |
| Hide identical files | `compare.hide_identical` | Chk | (false) | L |

**Interface → Theme**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Colour scheme | `interface.theme` | Rad | Default / High contrast / Monochrome (fine-grained styles stay in the `styles` config) | L |

**Interface → Keybindings** — read-only table generated from the active keymap
(T51) grouped by mode (`Key`, `Action`, `Mode`), with the path of the user config
file and the note "Edit the keybindings in this file; changes are read at start."
`/` filters the table. No key is editable here.

**Editing** (types from T63)

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Default editor | `editing.editor` | Rad + Txt + Chk | Automatic ($VISUAL / $EDITOR / platform) or Command (`command`, `terminal`) | L |
| File associations | `editing.associations` | table (pattern, command, terminal) with `a` add, `e` edit, `x` delete, `J`/`K` order; edit dialog validates glob and command split | L |
| Watch files and offer to upload | `editing.watch_and_prompt_upload` | Chk | (true) | L |
| Ask before opening files larger than (MiB) | `editing.max_size_mib` | Num | 0–100 000 (50), 0 = never ask | L |

**Queue**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Action after the queue finished | `queue.on_complete` | Sel + Txt | None / Show a message / Run a command (command text, required) / Disconnect / Close courier-ftp | L |
| Notification | `queue.notify` | Rad | None / Terminal bell / Desktop notification (OSC) | L |
| Save the queue on exit | `queue.persist` | Chk | (true) | L |
| Refresh remote listing after the queue finished | `queue.refresh_remote_after` | Chk | (true) | L |
| Successful transfers kept in the list | `queue.successful_max` (see Open questions) | Num | 0–100 000 (1000) | L |

**Logging**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Debug level | `logging.level` | Sel | 0 None, 1 Warning, 2 Info, 3 Verbose, 4 Debug | L |
| Show timestamps | `logging.show_timestamps` | Chk | (T55 default) | L |
| Show raw directory listings | `logging.show_raw_listing` | Chk | (false) | L |
| Log to file | `logging.log_to_file` | Chk | (false); help says the file contains hosts, paths and commands (masked) | L |
| Log file | `logging.log_file` | Path | parent dir must exist | L |
| Maximum size (MiB) | `logging.log_file_max_mib` | Num | 1–1024 (10) | L |
| Rotated files kept | `logging.log_file_keep` | Num | 0–100 (3) | L |

**Security** (vault; flows from T60)

| Label | Key / flow | Widget | Range / values | Apply |
|---|---|---|---|---|
| Save passwords in the vault | `vault.store_passwords` | Chk | (true); turning off asks "Remove saved passwords from all sites?" Yes/No (T31 §6) | L |
| Lock after inactivity (min) | `vault.auto_lock_minutes` | Num | 0–1440 (15), 0 = never | L |
| Lock when the system suspends | `vault.lock_on_suspend` | Chk | (true) | L |
| Disconnect sessions when locking | `vault.lock_disconnects` | Chk | (false) | L |
| Unlock cost | `vault.argon2_cost` | Rad | presets from T60 with the measured unlock time on this device | L (next unlock re-wraps) |
| Unlock with system keyring on this device | T30 `set_keyring_unlock` | button (asks the master password to enable) | hidden when no keyring | L |
| Change master password… | T60 flow (T87 online flow when sync is on) | button | — | — |
| Lock now | T30 `lock()` | button | — | — |
| Approved local actions | T82 `local_approvals` (T91 §8) | list: site, field, approved at; `x` revoke (confirm) | — | L |

When the vault is locked, the page shows "Unlock the vault to change security
settings" and an *Unlock* button (T60 overlay); the vault keys above are still
read-only visible.

**Sync & teams** (`sync` cargo feature; T90)

| Label | Key / flow | Widget | Range / values | Apply |
|---|---|---|---|---|
| Sync quickconnect history | `sync.history` | Chk | (false) | L |
| Push delay (ms) | `sync.push_debounce_ms` | Num | 200–60 000 (2000) | L |
| Fallback poll interval (s) | `sync.poll_fallback_secs` | Num | 30–3600 (300) | L |
| Account, devices, teams, status | T90 screens | buttons | — | — |

Built without the `sync` feature: the page says "This build has no sync support."
Before T90 lands, only the three keys are shown.

**Import / export** — buttons *Export settings…* and *Import settings…* opening the
T73 flows (hidden until T73 lands).

#### Trust stores (SFTP host keys, TLS certificates)

```
│ Trusted host keys                                                    │
│ Host                     Port  Type          Fingerprint (SHA-256)    Added       │
│ > web01.example.com      22    ssh-ed25519   SHA256:abc…xyz           2026-09-30  │
│   backup.example.org     2222  ecdsa-p256    SHA256:k1Z…Qe4           2026-10-01  │
│ Enter details   x remove   / filter                                   │
```
- Host keys: from `HostKeyStore::list` (T21); `x` → `confirm("Remove the trusted
  key for web01.example.com:22? You will be asked to confirm it on the next
  connection.", default Cancel)` → `HostKeyStore::remove`; `Enter` → details dialog
  (full SHA-256 and MD5 fingerprints, key type and size, added date) using T69's
  renderer.
- Certificates: from `CertTrustStore::list` (T12): host:port, subject CN, issuer,
  expiry (expired in red), SHA-256; `x` remove (confirm); `Enter` → T69 certificate
  details view.
- Changes apply immediately (they are vault items, not draft settings; Cancel
  doesn't undo them — the confirm says so).
- Vault locked → "Unlock the vault to manage trusted keys" with *Unlock*.
- Read-only items (team vault, T90) show `🔒` and refuse removal.

### Data formats and configuration

- All keys are T05 keys (`section.key`), saved by `Settings::save_user` into the
  user `config.json` (D10). Only non-default values are written; keybindings,
  styles and unknown keys are preserved (T05).
- Proxy passwords are `proxy-credential` items (T81) in the personal vault; the
  settings hold only the item id (T05/T15).
- `FIELDS` metadata lives in core next to `Settings`; the `help` text is the first
  sentence of each field's rustdoc (kept in sync by the coverage test below).
- Default binding: `F9` → `OpenSettings(None)` (existing in T51).

### Errors

| Situation | Error | User sees |
|---|---|---|
| Field invalid | `validate_field` message | inline under the field; `!` on the section; Save blocked |
| Cross-field rule broken | same | message on both fields |
| `save_user` fails (permissions, disk full) | config I/O error | error dialog "Could not save settings to <path>: …"; nothing applied |
| Vault write for a proxy password fails / vault locked | `Error::Vault(..)` | error dialog; password field shows "not saved"; nothing applied |
| Host key / cert removal fails | `Error::Vault(..)` | error dialog; list unchanged |
| Related feature missing (T72, T73, T90) | — | page/button hidden |

### Security and logging

- Password fields are masked and never rendered (including snapshots); the typed
  value is a `SecretString`, zeroized after it is written to the vault or the draft
  is dropped.
- Revoking a local approval (T91 §8) takes effect immediately: the next use of that
  synced field asks again.
- The Logging page states plainly what "Log to file" writes (T91 §4: the session
  log is user-facing and contains hosts and paths).
- `tracing` at `debug`: which keys changed (key names only, never values); no
  hostnames, users or paths at `info`+.

## Implementation steps

1. Core `FIELDS` registry, `ApplyWhen`, `validate_field` (moving T05's validation
   into per-key functions used by both loading and the UI); coverage test.
2. Screen shell: section tree, form area, help line, buttons, keys, dirty guard,
   draft/save/reset/cancel, `SettingsChanged` broadcast.
3. Sections Connection, FTP, Transfers, Fast transfers, File types, File exists.
4. Interface, File lists (with date preview and column editor), Comparison, Theme,
   Keybindings (read-only).
5. Editing (associations table), Queue, Logging.
6. Proxy pages with vault-backed passwords.
7. Trust stores (host keys, certificates) and Security page with T60 flows and the
   approvals list.
8. Sync page and Import/export buttons behind availability checks.
9. Snapshot tests per section and UI-flow tests.

## Acceptance criteria

- [ ] AC1 Coverage: every leaf key of `serde_json::to_value(Settings::default())` has a `FIELDS` entry with non-empty help and is editable on some page (test walks the JSON and the page registry; entries edited by sub-dialogs — `filters.*` via T67 — are listed in an explicit allowlist).
- [ ] AC2 Each field's validation matches T05: for every numeric field, the minimum − 1 and maximum + 1 are rejected inline, and loading the same values from a config file produces the T05 warning + default.
- [ ] AC3 Save writes only non-default values; reloading the config dir yields a `Settings` equal to the draft; keybindings, styles and unknown keys survive.
- [ ] AC4 Live apply: after Save, a changed speed limit is used by the engine (T41 `SettingsChanged` observed), `interface.size_format` changes the pane rendering, `logging.level` changes the log filter, and `interface.layout` re-lays out the screen — all without restart.
- [ ] AC5 Fields marked "new connections" don't change existing sessions and a status message says so.
- [ ] AC6 Reset section restores defaults for that page only; Cancel with a dirty draft asks Save/Discard/Cancel and Discard leaves the live settings unchanged.
- [ ] AC7 Host keys and certificates can be listed, inspected and removed (mock stores; removal asks first, default Cancel).
- [ ] AC8 Proxy passwords are stored as `proxy-credential` items and never written to `config.json` (file grep test with a canary password).
- [ ] AC9 Security page: keyring toggle asks for the master password, lock now locks, approvals can be revoked; the page is read-only when the vault is locked.
- [ ] AC10 Snapshot tests for every section page at 80×24 and 160×48, including an error state and a locked-vault Security page.
- [ ] AC11 CI gates pass: `fmt`, `clippy -D warnings`, `docs`, `test-local-only` (without the `sync` feature: Sync page shows the no-sync text), `test-os`, `canary`.

## Tests

### Unit tests

- `fn fields_cover_every_settings_leaf` — walks `Settings::default()` JSON (AC1).
- `fn fields_have_help_and_unique_keys` (AC1).
- `fn validate_numeric_bounds_table` — min−1/min/max/max+1 for every Num field (AC2).
- `fn validate_cross_field_rules` — port range, max_downloads > max_concurrent, both proxies, segment sizes, replacement char (AC2).
- `fn ascii_extensions_parse_normalise_dedup` (AC2).
- `fn reset_section_touches_only_its_keys` (AC6).
- `fn draft_dirty_tracking` (AC6).
- `fn apply_when_new_connections_flagged` (AC5).

### Property / fuzz tests

Not applicable (no parsers or algorithms with a large input space; validation is covered by table tests).

### Snapshot tests

At 80×24 and 160×48 (AC10): `snapshot_settings_<section>` for every `SectionId`
(21 pages), plus `snapshot_settings_validation_error`,
`snapshot_settings_dirty_guard`, `snapshot_settings_security_locked`,
`snapshot_settings_host_key_details`, `snapshot_settings_cert_details`,
`snapshot_settings_associations_table`, `snapshot_settings_date_preview`,
`snapshot_settings_sync_unavailable`.

### Integration tests

UI-flow tests with scripted keys, a temp config dir, a test vault
(`Argon2Cost::TEST`), mock trust stores and a mock keyring:
- `fn save_round_trip_preserves_keybindings_and_unknown_keys` (AC3).
- `fn speed_limit_live_apply_reaches_engine` / `fn size_format_live_apply` / `fn log_level_live_apply` / `fn layout_live_apply` (AC4).
- `fn timeout_change_does_not_touch_open_session` (AC5).
- `fn cancel_dirty_discard_keeps_live_settings` (AC6).
- `fn remove_host_key_and_cert_with_confirm` (AC7).
- `fn proxy_password_goes_to_vault_not_config` — canary scan of `config.json` (AC8).
- `fn security_keyring_toggle_lock_now_revoke_approval` / `fn security_page_read_only_when_locked` (AC9).
- `fn invalid_value_blocks_save_and_marks_section` (AC2).

### End-to-end tests

`courier-ftp-e2e` (`#[ignore]`, `COURIER_E2E=1`): `fn e2e_settings_change_persists`
— `PtyApp`: F9, change `transfers.max_concurrent` to 2 and the size format, Save,
quit, restart, verify both on screen and in `config.json` (AC3, AC4).

## Out of scope

- Editing keybindings in the UI (config file only in v1).
- Editing individual style colours (config file only).
- Per-site overrides (Site Manager, T59).
- Hot reload of the config file when edited externally.

## Open questions

1. **Keys missing from T05** that this screen edits: `compare.mode`,
   `compare.threshold_minutes`, `compare.hide_identical` (T66), `interface.theme`
   (built-in colour schemes), `queue.successful_max` (T40 mentions a cap of 1000
   "setting" without a key), `filters.*` sub-keys (T67). T05 should add them, or the
   owner decides to drop the Theme page / fixed successful-list cap.
2. **Types not fixed in T05**: `ftp.send_keepalive_command` (which commands are
   allowed), `editing.editor` (T63 defines `EditorChoice`), `interface.unicode_symbols`
   (T57 says "default auto": an `Auto`/`On`/`Off` enum is assumed here),
   `vault.argon2_cost` presets (T60).
3. Should turning off `vault.store_passwords` delete already saved passwords from
   all sites (FileZilla asks), or only stop saving new ones? This spec asks the user.
