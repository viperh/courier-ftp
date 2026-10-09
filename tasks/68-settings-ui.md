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
- T05 provides `Settings` with all sections (the registry of every key; enum values
  are snake_case in JSON), validation (invalid values → warning + default),
  `Settings::save_user(config_dir)` (writes only non-default values, preserves unknown
  keys, keybindings and styles) and `SettingsStore::update` (validate, save, then
  publish to every `SharedSettings` receiver). The `filters` section is T47's
  `FilterSettings` and the `compare` section T48's `CompareSettings`, both registered
  in T05; `editing.editor` / `editing.associations` use `courier_ftp_core::edit::{
  EditorChoice, Association}`.
- T52 provides `TabbedForm`, `TextInput`, `NumberInput`, `Checkbox`, `Select`,
  `RadioGroup`, `ListView`, `PathInput`, `confirm` (destructive confirmations use
  `ConfirmOpts::danger(..)`), `prompt_password`.
- T60 provides the vault flows used by the Security section (change master password,
  keyring unlock on/off, lock now, Argon2 cost presets with measured unlock time).
- Every T05 key is edited here; the field registry below maps each one by its exact
  T05 name (including `ftp.active_no_external_ip_on_local`, `proxy.ftp_proxy.*` with
  `password_ref`, `ftp.send_keepalive_command`, `sftp.*`, `compare.*`,
  `cache.listing_cache_max_dirs`, `interface.{key_sequence_timeout_ms, theme,
  sort.local, sort.remote, enter_on_file, connect_target, unicode_symbols}`,
  `logging.pane_max_lines`, `queue.max_successful`, `filters.*`, `editing.*`,
  `vault.argon2_cost`, `vault.auto_lock_minutes`).

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
    /// Validates, writes the vault items, calls `SettingsStore::update` (T05: validate,
    /// `save_user`, publish), and returns the actions to broadcast
    /// (`SettingsChanged(Arc<Settings>)`).
    pub fn save(&mut self, ctx: &mut SaveContext) -> Result<Vec<Action>, SaveError>;
}

/// Proxy password typed in the form; written as a `proxy-credential` item on Save and
/// its id stored in `key` (`"proxy.generic.password_ref"` or `"proxy.ftp_proxy.password_ref"`).
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
2. Cross-field rules (exactly T05's validation, plus T15's `validate_ftp_proxy`):
   `ftp.active_port_range` min ≤ max; `transfers.max_downloads` and `max_uploads` ≤
   `max_concurrent`; `proxy.generic.kind` and `proxy.ftp_proxy.kind` not both ≠ `none`;
   a proxy kind ≠ `none` needs a valid host; `queue.on_complete_command` non-empty when
   `queue.on_complete = run_command`; `logging.log_file` absolute. A log file whose
   parent directory does not exist is shown as a warning under the field (not an
   error; T71 creates it).
3. **Save** (`Ctrl-s` or button): blocked while any error exists (focus jumps to the
   first error). Order: (a) write `PendingSecret`s as `proxy-credential` items through
   the vault (T30) and put their ids into `proxy.generic.password_ref` /
   `proxy.ftp_proxy.password_ref` in the draft; (b) `SettingsStore::update(|s| *s =
   draft.clone())` (T05: validates, `save_user`, then publishes to every
   `SharedSettings` receiver — the transfer engine T41, rate limiter T44, log filter
   T04 react through `changed()`); (c) broadcast `SettingsChanged(Arc<Settings>)` to
   UI components. A failure in (a) or (b) shows an error dialog and leaves the live
   settings unchanged (T05 publishes only after a successful save); the draft is kept.
4. **Reset section**: `confirm("Reset section", "Reset all settings on this page to
   their defaults?", ConfirmOpts::danger("Reset"))`, then set this page's keys in the
   draft to `Settings::default()` values (not saved until Save).
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
| Timeout (seconds) | `connection.timeout_secs` | Num | 5–600 (20) | N |
| Number of retries | `connection.retries` | Num | 0–10 (2) | L |
| Delay between retries (s) | `connection.retry_delay_secs` | Num | 0–600 (5) | L |
| Send keep-alive commands | `connection.keepalive` | Chk | (true) | N |
| Keep-alive interval (s) | `connection.keepalive_interval_secs` | Num | 10–3600 (30) | N |
| Prefer IPv6 | `connection.prefer_ipv6` | Chk | (false) | N |
| Use IPv6 | `connection.ipv6` | Chk | (true); off = never use IPv6 addresses ("Disable IPv6") | N |

**Connection → FTP**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Transfer mode | `ftp.transfer_mode` | Rad | Passive (`passive`) / Active (`active`) | N |
| Fall back to the other mode on failure | `ftp.fallback_to_active` | Chk | (true) | N |
| External IP for active mode | `ftp.active_external_ip` | Rad + Txt | Ask the OS (`auto`) / Fixed IP (`{"fixed": …}`, valid IPv4/IPv6) / Get from URL (`{"from_url": …}`, `http://` or `https://`, ≤ 512 chars) | N |
| Don't use the external IP on local connections | `ftp.active_no_external_ip_on_local` | Chk | (true) | N |
| Limit local ports for active mode | `ftp.active_port_range` | Chk + 2× Num | 1024 ≤ min ≤ max ≤ 65535; unchecked = `null` | N |
| Ignore unroutable passive IP | `ftp.passive_ignore_unroutable_ip` | Chk | (true) | N |
| Use MLSD when available | `ftp.use_mlsd` | Chk | (true) | N |
| Keep-alive command | `ftp.send_keepalive_command` | Rad | NOOP (`noop`, default) / Random NOOP, PWD or TYPE (`random`) | N |
| Network wizard… | — | button | opens T72 (`Ctrl-x N` elsewhere) when available | — |

**Connection → FTP proxy**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Type | `proxy.ftp_proxy.kind` | Rad | None (`none`) / USER@HOST (`user_at_host`) / SITE (`site`) / OPEN (`open`) / Custom (`custom`); not together with a generic proxy | N |
| Proxy host | `proxy.ftp_proxy.host` | Txt | required when type ≠ None (`ServerAddress` host rules) | N |
| Proxy port | `proxy.ftp_proxy.port` | Num | 1–65535 (21) | N |
| Proxy user | `proxy.ftp_proxy.user` | Txt | optional (`%s`) | N |
| Proxy password | `proxy.ftp_proxy.password_ref` (id of a `proxy-credential` vault item) | Pw | optional (`%w`); needs the vault unlocked | N |
| Custom login script | `proxy.ftp_proxy.custom_script` | multi-line Txt | String with `'\n'`-separated lines, ≤ 32 lines, each ≤ 512 chars; used when type = Custom; placeholders per T15 | N |

**Connection → Generic proxy**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Type | `proxy.generic.kind` | Rad | None (`none`) / HTTP/1.1 CONNECT (`http`) / SOCKS4 (`socks4`) / SOCKS5 (`socks5`) | N |
| Proxy host | `proxy.generic.host` | Txt | required when type ≠ None | N |
| Proxy port | `proxy.generic.port` | Num | 0–65535 (0 = kind default: 8080 HTTP, 1080 SOCKS) | N |
| Proxy user | `proxy.generic.user` | Txt | "" = no authentication (SOCKS4: sent as user id) | N |
| Proxy password | `proxy.generic.password_ref` (id of a `proxy-credential` vault item) | Pw | optional; hidden for SOCKS4; needs the vault unlocked | N |

**Connection → SFTP**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Outstanding requests per file | `sftp.max_outstanding_requests` | Num | 1–256 (64) | N |
| Request size (bytes) | `sftp.request_size` | Num | 4096–261120 (32768); the help line shows the value in KiB | N |
| Also trust OpenSSH known_hosts | `sftp.use_openssh_known_hosts` | Chk | (true) | N |
| Trusted host keys | `known-host` items (T21 `HostKeyStore`) | list, see "Trust stores" | — | L |

**Connection → TLS certificates**

| Label | Key | Widget | Apply |
|---|---|---|---|
| Trusted certificates | `trusted-cert` items (T12 vault-backed `CertTrustStore`) | list, see "Trust stores" | L |

**Transfers**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Maximum simultaneous transfers | `transfers.max_concurrent` | Num | 1–16 (4) | L |
| Limit for downloads | `transfers.max_downloads` | Num | 0–`max_concurrent` (0 = no separate limit) | L |
| Limit for uploads | `transfers.max_uploads` | Num | 0–`max_concurrent` (0 = no separate limit) | L |
| Enable speed limits | `transfers.speed_limit_enabled` | Chk | (false); also toggled by `Ctrl-x k` | L |
| Download limit (KiB/s) | `transfers.download_limit_kib` | Num | 0–1 048 576, 0 = unlimited | L |
| Upload limit (KiB/s) | `transfers.upload_limit_kib` | Num | 0–1 048 576, 0 = unlimited | L |
| Burst tolerance | `transfers.burst_tolerance` | Sel | Normal (`normal`) / High (`high`) / Very high (`very_high`) | L |
| Preallocate disk space | `transfers.preallocate` | Chk | (false) | L |
| Preserve timestamps | `transfers.preserve_timestamps` | Chk | (false) | L |
| Replace invalid characters | `transfers.replace_invalid_chars` | Chk | (true) | L |
| Replacement character | `transfers.invalid_char_replacement` | Txt (1 char) | not `\ / : * ? " < > \|`, `.`, space or a control character ('_') | L |
| Empty directories | `transfers.empty_dirs` | Rad | Create (`create`) / Skip (`skip`) | L |
| Follow symbolic links | `transfers.follow_symlinks` | Chk | (false) | L |

**Transfers → Fast transfers**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Split large files | `transfers.segmented.enabled` | Chk | (true) | L |
| Minimum file size (MiB) | `transfers.segmented.min_file_size_mib` | Num | 1–1 048 576 (32) | L |
| Maximum segments | `transfers.segmented.max_segments` | Num | 1–16 (4) | L |
| Minimum segment size (MiB) | `transfers.segmented.min_segment_size_mib` | Num | 1–1024 (8) | L |

**Transfers → File types**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Default transfer type | `file_types.default_type` | Rad | Auto (`auto`) / ASCII (`ascii`) / Binary (`binary`) | L |
| ASCII extensions | `file_types.ascii_extensions` | Txt (space-separated) | lower-cased, leading dots stripped, de-duplicated; entries with `/`, whitespace or > 16 chars rejected (T05); "Restore default list" button | L |
| Dotfiles are ASCII | `file_types.dotfiles_ascii` | Chk | (true) | L |
| Files without extension are ASCII | `file_types.no_extension_ascii` | Chk | (true) | L |

**Transfers → File exists action**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Downloads | `transfers.on_exists_download` | Sel | `ExistsAction`: Ask (`ask`), Overwrite (`overwrite`), Overwrite if newer (`overwrite_if_newer`), Overwrite if size differs (`overwrite_if_size_differs`), Overwrite if newer or size differs (`overwrite_if_newer_or_size_differs`), Resume (`resume`), Rename (`rename`), Skip (`skip`) | L |
| Uploads | `transfers.on_exists_upload` | Sel | same | L |

**Interface**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Layout | `interface.layout` | Rad | Classic (`classic`) / Explorer (`explorer`) / Widescreen (`widescreen`) | L |
| Swap local and remote panes | `interface.swap_panes` | Chk | (false) | L |
| Show directory trees | `interface.show_tree` | Chk | (false) | L |
| Show message log | `interface.show_log` | Chk | (true) | L |
| Show queue | `interface.show_queue` | Chk | (true) | L |
| Show quickconnect bar | `interface.show_quickconnect` | Chk | (true) | L |
| Unicode symbols | `interface.unicode_symbols` | Rad | Auto (`auto`) / Always (`always`) / Never (`never`) | L |
| Key sequence timeout (ms) | `interface.key_sequence_timeout_ms` | Num | 200–5000 (1000) | L |
| Enter on a file | `interface.enter_on_file` | Rad | Transfer (`transfer`) / View (`view`) / Edit (`edit`) / Nothing (`none`) | L |
| Where connections open | `interface.connect_target` | Rad | Ask (`ask`) / New tab (`new_tab`) / Replace current tab (`replace`) | L |
| Confirm deletions | `interface.confirm_delete` | Chk | (true) | L |
| Confirm transfers | `interface.confirm_transfer` | Chk | (false) | L |
| Restore tabs on start | `interface.restore_tabs` | Chk | (false) | S |
| Language | `interface.language` | Sel | "Automatic" (`auto`) + BCP-47 tags of the languages shipped by T75 | L |
| Show splash screen | `interface.show_splash` | Chk | (false) | S |
| Check for updates | `interface.check_updates` | Chk | (true) | S |
| Include pre-releases | `interface.check_prereleases` | Chk | (false) | S |

**Interface → File lists**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Size format | `interface.size_format` | Rad | Bytes (`bytes`) / IEC, KiB (`iec`) / SI, kB (`si`) | L |
| Thousands separator | `interface.thousands_separator` | Chk | (true) | L |
| Date format | `interface.date_format` | Txt | tokens `%Y %y %m %d %e %b %H %I %M %S %p %%` + literal text, ≤ 32 chars ("%Y-%m-%d"); live preview line with the current date | L |
| Time format | `interface.time_format` | Txt | same ("%H:%M"); live preview | L |
| Directories first | `interface.dirs_first` | Chk | (true) | L |
| Case-sensitive sorting | `interface.sort_case_sensitive` | Chk | (false) | L |
| Natural sorting (file2 < file10) | `interface.natural_sort` | Chk | (true) | L |
| Default sort, local / remote | `interface.sort.local`, `interface.sort.remote` | per side: Sel column (`Column`) + Chk descending | (`name`, ascending); also saved on quit by T53 | L |
| Show hidden local files | `interface.show_hidden_local` | Chk | (false) | L |
| Force showing hidden remote files | `interface.force_show_hidden_remote` | Chk | (false) — refreshes remote panes | L |
| Columns | `interface.columns.local`, `interface.columns.remote` | column list: visibility `Space`, order `J`/`K` per side; Name always present and visible | L |
| Cache directory listings | `cache.listing_cache` | Chk | (true) | L |
| Cache lifetime (s) | `cache.listing_cache_ttl_secs` | Num | 0–86 400 (0 = until refresh) | L |
| Cached directories per server | `cache.listing_cache_max_dirs` | Num | 10–10 000 (200) | L |
| Filters… | `filters.{filters, sets, active_set, apply_to_transfers}` | button → T67 dialog (all four keys are edited there) | L |

**Interface → Directory comparison** (T48 `CompareSettings`, registered in T05; UI in T66)

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Compare by | `compare.mode` | Rad | Modification time (`modification_time`) / File size (`size`) | L |
| Threshold (minutes) | `compare.threshold_minutes` | Num | 0–1440 (1) | L |
| Hide identical files | `compare.hide_identical` | Chk | (false) | L |

**Interface → Theme**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Colour scheme | `interface.theme` | Rad | Default (`default`) / High contrast (`high_contrast`) / Monochrome (`monochrome`); `NO_COLOR` forces monochrome (fine-grained styles stay in the `styles` config) | L |

**Interface → Keybindings** — read-only table generated from the active keymap
(T51) grouped by mode (`Key`, `Action`, `Mode`), with the path of the user config
file and the note "Edit the keybindings in this file; changes are read at start."
`/` filters the table. No key is editable here.

**Editing** (types `EditorChoice`, `Association` in `courier_ftp_core::edit`, T05/T63)

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Default editor | `editing.editor` | Rad + Txt + Chk | Automatic (`"auto"`: $VISUAL / $EDITOR / platform) or Command (`{"command": {"command", "terminal"}}`); an empty command reverts to Automatic (T05) | L |
| File associations | `editing.associations` | table (pattern, command, terminal) with `a` add, `e` edit, `x` delete, `J`/`K` order; ≤ 256 entries; edit dialog validates glob and command split | L |
| Watch files and offer to upload | `editing.watch_and_prompt_upload` | Chk | (true) | L |
| Ask before opening files larger than (MiB) | `editing.max_size_mib` | Num | 0–10 240 (50), 0 = never ask | L |

**Queue**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Action after the queue finished | `queue.on_complete` | Sel | None (`none`) / Show a message (`show_message`) / Run a command (`run_command`) / Disconnect (`disconnect`) / Close courier-ftp (`close_app`) | L |
| Command to run | `queue.on_complete_command` | Txt | ≤ 1024 chars; required (non-empty) when the action is Run a command | L |
| Notification | `queue.notify` | Rad | None (`none`) / Terminal bell (`bell`) / Desktop notification (`osc`) | L |
| Save the queue on exit | `queue.persist` | Chk | (true) | L |
| Refresh remote listing after the queue finished | `queue.refresh_remote_after` | Chk | (true) | L |
| Successful transfers kept in the list | `queue.max_successful` | Num | 0–100 000 (1000) | L |

**Logging**

| Label | Key | Widget | Range / values | Apply |
|---|---|---|---|---|
| Debug level | `logging.level` | Sel | 0 None, 1 Warning, 2 Info, 3 Verbose, 4 Debug (2) | L |
| Show timestamps | `logging.show_timestamps` | Chk | (true) | L |
| Show raw directory listings | `logging.show_raw_listing` | Chk | (false) | L |
| Lines kept in the message log | `logging.pane_max_lines` | Num | 500–100 000 (5000) | L |
| Log to file | `logging.log_to_file` | Chk | (false); help says the file contains hosts, paths and commands (masked) | L |
| Log file | `logging.log_file` | Path | absolute path; empty = `null` = `<data dir>/session.log` | L |
| Maximum size (MiB) | `logging.log_file_max_mib` | Num | 1–1024 (10) | L |
| Rotated files kept | `logging.log_file_keep` | Num | 1–50 (3) | L |

**Security** (vault; flows from T60)

| Label | Key / flow | Widget | Range / values | Apply |
|---|---|---|---|---|
| Save passwords in the vault | `vault.store_passwords` | Chk | (true); turning off asks "Remove saved passwords from all sites?" Yes/No (T31 §6) | L |
| Lock after inactivity (min) | `vault.auto_lock_minutes` | Num | 0–1440 (15), 0 = never | L |
| Lock when the system suspends | `vault.lock_on_suspend` | Chk | (true) | L |
| Disconnect sessions when locking | `vault.lock_disconnects` | Chk | (false) | L |
| Unlock cost | `vault.argon2_cost` | Rad | Light (`light`) / Standard (`standard`, default) / Strong (`strong`) with the measured unlock time on this device (T60) | L (applied at the next password change or unlock re-wrap) |
| Unlock with system keyring on this device | T30 `set_keyring_unlock` | button (asks the master password to enable) | hidden when no keyring | L |
| Change master password… | T60 flow (T87 online flow when sync is on) | button | — | — |
| Lock now | T30 `lock()` | button | — | — |
| Approved local actions | T82 `local_approvals` (T91 §8) | list: site, field, approved at; `x` revoke (`ConfirmOpts::danger("Revoke")`) | — | L |

When the vault is locked, the page shows "Unlock the vault to change security
settings" and an *Unlock* button (`App::request_unlock()`, T60); the vault keys above
are still read-only visible.

**Sync & teams** (`sync` cargo feature; T90)

| Label | Key / flow | Widget | Range / values | Apply |
|---|---|---|---|---|
| Sync quickconnect history | `sync.history` | Chk | (false) | L |
| Push delay (ms) | `sync.push_debounce_ms` | Num | 100–60 000 (2000) | L |
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
  connection.", ConfirmOpts::danger("Remove"))` → `HostKeyStore::remove`; `Enter` → details dialog
  (full SHA-256 and MD5 fingerprints, key type and size, added date) using T69's
  renderer.
- Certificates: from the vault-backed `CertTrustStore` (T12; `TrustedCertItem`, T30):
  host:port, subject CN, issuer, expiry (expired in red), SHA-256; `x` remove
  (`ConfirmOpts::danger("Remove")`); `Enter` → T69 certificate
  details view.
- Changes apply immediately (they are vault items, not draft settings; Cancel
  doesn't undo them — the confirm says so).
- Vault locked → "Unlock the vault to manage trusted keys" with *Unlock*
  (`App::request_unlock()`).
- Read-only items (team vault, T90) show `🔒` and refuse removal.

### Data formats and configuration

- All keys are T05 keys (`section.key`, exactly as named in T05's registry), saved by
  `SettingsStore::update` → `Settings::save_user` into the user `config.json` (D10).
  Only non-default values are written; keybindings, styles and unknown keys are
  preserved (T05). Enum values are written in snake_case (T05 convention).
- Proxy passwords are `proxy-credential` items (T81) in the personal vault; the
  settings hold only the item id (`proxy.generic.password_ref`,
  `proxy.ftp_proxy.password_ref`, T05/T15).
- `FIELDS` metadata lives in core next to `Settings`; the `help` text is the first
  sentence of each field's rustdoc (kept in sync by the coverage test below).
- Default binding: `F9` → `OpenSettings(None)` (existing in T51).

### Errors

| Situation | Error | User sees |
|---|---|---|
| Field invalid | `validate_field` message | inline under the field; `!` on the section; Save blocked |
| Cross-field rule broken | same | message on both fields |
| Save fails (permissions, disk full) | `Error::Io` from `SettingsStore::update` | error dialog "Could not save settings to <path>: …"; nothing applied |
| `config.json` is not valid JSON, or `config.yaml/toml/ini` shadows `settings` | `Error::InvalidInput` (T05) | error dialog with T05's message; nothing applied |
| Vault locked while a proxy password is pending | `Error::VaultLocked` | error dialog with *Unlock*; password field shows "not saved"; nothing applied |
| Vault write for a proxy password fails | `Error::Vault(..)` | error dialog; password field shows "not saved"; nothing applied |
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

1. Core `FIELDS` registry (one entry per T05 key, exact names), `ApplyWhen`,
   `validate_field` (moving T05's validation into per-key functions used by both
   loading and the UI); coverage test.
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

- [ ] AC1 Coverage: every leaf key of `serde_json::to_value(Settings::default())` has a `FIELDS` entry with the exact T05 key name and non-empty help and is editable on some page (test walks the JSON and the page registry; entries edited by sub-dialogs — `filters.{filters, sets, active_set, apply_to_transfers}` via T67 — are listed in an explicit allowlist); no `FIELDS` key is missing from `Settings::json_schema()`.
- [ ] AC2 Each field's validation matches T05: for every numeric field, the minimum − 1 and maximum + 1 are rejected inline, and loading the same values from a config file produces the T05 warning + default.
- [ ] AC3 Save writes only non-default values (enum values in snake_case); reloading the config dir yields a `Settings` equal to the draft; keybindings, styles and unknown keys survive.
- [ ] AC4 Live apply: after Save, a changed speed limit is used by the engine (T41/T44 observe the new value on their `SharedSettings`), `interface.size_format` changes the pane rendering, `logging.level` changes the log filter, and `interface.layout` re-lays out the screen — all without restart.
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
- `fn fields_use_t05_key_names` — every `FIELDS.key` resolves to a path in `Settings::json_schema()`; spot checks `queue.max_successful`, `proxy.ftp_proxy.password_ref`, `ftp.active_no_external_ip_on_local`, `interface.connect_target`, `cache.listing_cache_max_dirs`, `logging.pane_max_lines` (AC1).
- `fn enum_widgets_write_snake_case` — e.g. `interface.connect_target = new_tab`, `compare.mode = modification_time`, `editing.editor = "auto"` (AC3).
- `fn validate_numeric_bounds_table` — min−1/min/max/max+1 for every Num field (AC2).
- `fn validate_cross_field_rules` — port range, max_downloads > max_concurrent, both proxies, proxy without host, run_command without command, relative log file, replacement char (AC2).
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

1. Should turning off `vault.store_passwords` delete already saved passwords from
   all sites (FileZilla asks), or only stop saving new ones? This spec asks the user.

Resolved (reconciliation): every key this screen edits is in T05's registry
(`compare.*`, `interface.theme`, `queue.max_successful`, `filters.*`,
`ftp.send_keepalive_command` = `noop` | `random` with default `noop`,
`editing.editor: EditorChoice`, `interface.unicode_symbols` = `auto` | `always` |
`never`, `vault.argon2_cost` = `light` | `standard` | `strong`).
