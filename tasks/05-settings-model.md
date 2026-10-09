# T05 — Settings model

**Phase:** A Foundation · **Milestone:** M1 · **Depends on:** T02 · **Crate(s):** `courier-ftp-core` (`settings` module), `courier-ftp` (`config.rs`) · **Decisions:** D3, D10, D11 · **FEATURES.md:** §1, §3, §5, §6, §9, §10
**Related (integrates with, not blocking):** T30, T41b, T42, T45, T88
**Reference:** sverb `crates/sverb-core/src/config/{model,mod,validate,schema}.rs` (typed model, `#[serde(default)]` sections, schemars schema, warnings with dotted key paths)

## Goal

One typed, documented and defaulted `Settings` struct for everything FileZilla puts in its
Settings dialog plus courier-ftp's own knobs, loaded from the existing layered config
files (D10). A broken value never stops the app: it is reported with its key path and
replaced by its default. The Settings screen (T68) can save changes back without losing
the user's keybindings, styles or unknown keys.

## Context

- Before: the binary's `config.rs` (template) loads `.config/config.json` (baked in) plus
  user `config.{json5,json,yaml,toml,ini}` from the config dir into `Config { config,
  keybindings, styles }` with the `config` crate. T01 added `COURIER_FTP_HOME`.
- T02 provides `TransferType`, `Charset`, `RemotePath` etc.
- After: every runtime component reads settings from a `SharedSettings` receiver (T03
  keep-alive, T07 network options, T10–T15 FTP, T20/T22 SFTP, T41/T41b/T42/T44 transfers,
  T46 cache, T50–T58 UI, T55/T71 logging, T63 editing, T45 queue actions, T30/T60 vault,
  T88 sync). T68 edits and saves them. T47 adds the `filters` section.
- This file is the **registry of all settings keys**. A later task that needs a new key adds
  it to the tables here (with its default) in the same change.

## Technical specification

### Types and APIs

Module `courier_ftp_core::settings` (files `settings/{mod,model,enums,load,save,validate,file_types}.rs`).

```rust
/// All settings. Every struct is #[serde(default)] (a partial user file works) and derives
/// Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema.
/// Doc comments on each field are the help text shown in T68 and docs (T77).
pub struct Settings {
    pub connection: ConnectionSettings,
    pub ftp: FtpSettings,
    pub sftp: SftpSettings,
    pub proxy: ProxySettings,
    pub transfers: TransferSettings,
    pub file_types: FileTypeSettings,
    pub interface: InterfaceSettings,
    pub logging: LoggingSettings,
    pub editing: EditingSettings,
    pub queue: QueueSettings,
    pub cache: CacheSettings,
    pub vault: VaultSettings,
    pub sync: SyncSettings,
    // pub filters: FilterSettings,   — added by T47 (types live in `filters`)
}

/// A problem found while loading or validating. `path` is the dotted key ("ftp.active_port_range.min").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsWarning { pub path: String, pub message: String }

impl Settings {
    /// Build settings from the user's `settings` JSON object (may be Null/absent).
    /// Leaf-by-leaf merge onto the defaults: a leaf that fails to deserialize is dropped
    /// with a warning; unknown keys produce a warning and are ignored. Then `validate`.
    pub fn from_json_lenient(user: &serde_json::Value) -> (Settings, Vec<SettingsWarning>);
    /// Range/consistency checks (table below). Invalid fields are reset to their default.
    pub fn validate(&mut self) -> Vec<SettingsWarning>;
    /// Only leaves that differ from Settings::default() (arrays compared as a whole).
    pub fn to_user_json(&self) -> serde_json::Value;
    /// Merge `to_user_json()` into `<config_dir>/config.json` under the key "settings"
    /// (see Behaviour). Errors: Io, InvalidInput (existing file is not valid JSON).
    pub fn save_user(&self, config_dir: &Path) -> Result<()>;
    /// JSON Schema (draft 2020-12) of Settings with doc comments and defaults.
    pub fn json_schema() -> serde_json::Value;
}

/// Live settings shared by all components. Cheap to clone.
pub type SharedSettings = tokio::sync::watch::Receiver<Arc<Settings>>;

/// Owner of the live settings (created by the binary at startup).
pub struct SettingsStore { /* watch::Sender<Arc<Settings>>, config_dir: PathBuf */ }
impl SettingsStore {
    pub fn new(initial: Settings, config_dir: PathBuf) -> Self;
    pub fn current(&self) -> Arc<Settings>;
    pub fn subscribe(&self) -> SharedSettings;
    /// Apply `edit` to a copy, validate, save_user, then publish. On a save error nothing
    /// is published. Returns the validation warnings (fields that were reset).
    pub fn update(&self, edit: impl FnOnce(&mut Settings)) -> Result<Vec<SettingsWarning>>;
    /// Publish without saving (runtime toggles such as the speed-limit key, T44/T57,
    /// which T68 later persists).
    pub fn set_transient(&self, edit: impl FnOnce(&mut Settings));
}

/// Resolve Auto per file (T11, T41). See Behaviour.
pub fn decide_transfer_type(file_name: &str, choice: TransferTypeChoice, ft: &FileTypeSettings) -> TransferType;
```

Enums used by settings live in `settings::enums` (so this task depends on no later task);
all are `Copy`, `#[serde(rename_all = "kebab-case")]`, and have the default marked:

| Enum | Variants (default first-marked *) | Used by |
|---|---|---|
| `DebugLevel` | `None`=0, `Warning`=1, `Info`=2 *, `Verbose`=3, `Debug`=4 — serialised as the integer 0–4 | T04, T55, T71 |
| `ExistsAction` | `Ask` *, `Overwrite`, `OverwriteIfNewer`, `OverwriteIfSizeDiffers`, `OverwriteIfNewerOrSizeDiffers`, `Resume`, `Rename`, `Skip` | T04, T40, T42 |
| `TransferTypeChoice` | `Auto` *, `Ascii`, `Binary` | T11, T40, T57 |
| `FtpTransferMode` | `Passive` *, `Active` | T11 |
| `ActiveExternalIp` | `Auto` *, `Fixed(IpAddr)`, `FromUrl(String)` — JSON `"auto"`, `{"fixed":"203.0.113.5"}`, `{"from-url":"http://…"}` | T11, T72 |
| `KeepaliveCommand` | `Noop` *, `Pwd`, `Type`, `Random` (rotates NOOP/PWD/TYPE, T10) | T10 |
| `ProxyKind` | `None` *, `Http`, `Socks4`, `Socks5` | T07 |
| `FtpProxyKind` | `None` *, `UserAtHost`, `Site`, `Open`, `Custom` | T15 |
| `BurstTolerance` | `Normal` * (1 s), `High` (2 s), `VeryHigh` (5 s) | T44 |
| `EmptyDirs` | `Create` *, `Skip` | T43 |
| `Layout` | `Classic` *, `Explorer`, `Widescreen` | T50 |
| `SizeFormat` | `Bytes`, `Iec` *, `Si` | T53, T56, T57 |
| `Column` | `Name`, `Size`, `Type`, `Modified`, `Permissions`, `OwnerGroup` (FileZilla order) | T53 |
| `EnterOnFile` | `Transfer` *, `View`, `Edit`, `None` | T51, T53 |
| `UnicodeSymbols` | `Auto` *, `Always`, `Never` | T57 |
| `Theme` | `Default` *, `HighContrast`, `Monochrome` | T50, T68 |
| `OnComplete` | `None` *, `ShowMessage`, `RunCommand`, `Disconnect`, `CloseApp` (sound/sleep/shutdown dropped, D8) | T45 |
| `NotifyMethod` | `None`, `Bell` *, `Osc` | T45 |
| `Argon2Preset` | `Light` (m=64 MiB,t=3,p=1), `Standard` * (256 MiB,3,1), `Strong` (1 GiB,4,1) — parameters owned by T30 (`Argon2Cost::from_preset`) | T30, T60 |

Helper structs: `PortRange { min: u16, max: u16 }`, `ColumnSpec { column: Column,
visible: bool }`, `PaneColumns { local: Vec<ColumnSpec>, remote: Vec<ColumnSpec> }`,
`SortSpec { column: Column, descending: bool }`, `PaneSort { local: SortSpec, remote: SortSpec }`
(T53 uses these core types; it does not define its own),
`FileAssociation { pattern: String /* glob */, command: String, terminal: bool }`,
`SegmentedSettings` (below), `GenericProxySettings`, `FtpProxySettings` (below).

### Behaviour

**Loading (binary `config.rs`):**
1. The `config` crate builds the layered config as today. `Config` gains
   `pub settings: Settings`, filled from the raw `settings` value: the crate deserialises
   into a private `RawConfig { …, #[serde(default)] settings: serde_json::Value }` and then
   calls `Settings::from_json_lenient`. A bad setting never fails `Config::new`.
2. The baked-in `.config/config.json` does **not** contain settings: defaults have one
   source, `Settings::default()`. (Users see defaults in `docs/settings.schema.json` and in
   T68; T77 renders `docs/configuration.md` from the schema.)
3. Warnings are logged with `tracing::warn!(path = %w.path, "{message}")` (no values) and
   handed to the UI, which shows them once as `Error:` lines in the message log (T55) at
   startup: `Setting ftp.active_port_range ignored: min (6000) > max (5000); using default`.
4. `#![allow(dead_code)]` is removed from `config.rs` in this task.

**Lenient merge algorithm** (`from_json_lenient`): `acc = to_value(Settings::default())`.
Walk the user object depth-first. For each leaf (non-object value, arrays count as leaves)
at path P: if P does not exist in `acc` → warning "unknown setting" (keys under
`settings.filters` are left to T47's own loader once it exists); otherwise set it in a copy
of `acc` and try `from_value::<Settings>(copy)`; success → keep, failure → warning
"invalid value: <serde message>" and keep the default. An object given where a scalar is
expected (or vice versa) is one invalid leaf. Cost is O(leaves × deserialize), < 5 ms for
the full table. Then `validate()`.

**Validation rules** (`validate`): each failing field is reset to its default and a warning
is added. Ranges are in the tables below; additionally:
- `ftp.active_port_range`: `1024 ≤ min ≤ max ≤ 65535`.
- `ftp.active_external_ip`: `from-url` needs a URL starting with `http://` or `https://`
  (≤ 512 chars); `fixed` must be a valid IP (enforced by deserialisation); otherwise `auto`.
- `proxy.generic` and `proxy.ftp_proxy` both not `none` → warning, `proxy.ftp_proxy.kind`
  reset to `none` (T15). A proxy with `kind ≠ none` needs a non-empty valid host
  (`ServerAddress` host rules) else its kind is reset to `none`.
- `transfers.max_downloads`/`max_uploads` ≤ `max_concurrent` (0 = no separate limit).
- `transfers.invalid_char_replacement` must not be one of `\ / : * ? " < > |`, `.`, space,
  or a control character (portable across OSes).
- `interface.date_format`/`time_format`: only the tokens `%Y %y %m %d %e %b %H %I %M %S %p %%`
  plus literal text; ≤ 32 chars.
- `file_types.ascii_extensions`: lowercased, leading dots stripped, duplicates removed
  (normalisation, no warning); entries with `/`, whitespace or > 16 chars dropped with a warning.
- `editing.associations`: empty `pattern` or `command` entries dropped; invalid glob dropped.
- `logging.log_file`: if set, must be an absolute path.

**Saving** (`save_user`): read `<config_dir>/config.json` if it exists (invalid JSON →
`InvalidInput`, nothing written); take its `settings` object, remove every key path that
the schema knows (unknown keys stay, so a newer version's keys survive), overlay
`to_user_json()`, drop `settings` entirely if it ends up empty; keep all other top-level
keys (keybindings, styles, …) untouched; write pretty JSON (2 spaces, trailing newline) to
`config.json.tmp` in the same directory, `fsync`, rename over `config.json`. The config dir
is created with `0700` on Unix if missing. The binary wrapper refuses to save (InvalidInput,
shown in T68) when `config.yaml`, `config.toml` or `config.ini` in the config dir contains a
top-level `settings` key, because those files are loaded after `config.json` and would
shadow the saved values.

**Transfer type** (`decide_transfer_type`): `choice = Ascii|Binary` → that. `Auto` with
`file_types.default_type ≠ auto` → that type. Otherwise: name starts with '.' →
`dotfiles_ascii`; no '.' in the name → `no_extension_ascii`; else the extension after the
last '.' (case-insensitive) in `ascii_extensions` → Ascii; otherwise Binary.

**Live changes:** components hold a `SharedSettings` and read `borrow().clone()` (an `Arc`)
per operation; long-running tasks (T41 engine, T44 limiter, T03 keep-alive) `changed().await`
to react. Network settings apply to new connections only (T68 says so).

### Data formats and configuration

User config JSON shape (all keys optional):

```json
{ "keybindings": { … }, "styles": { … },
  "settings": { "connection": { "timeout_secs": 30 }, "transfers": { "max_concurrent": 8 } } }
```

Legend for the tables: **Owner** = the task that implements the behaviour (T05 implements
every field, its default and validation now; `filters` is the only section added later).

#### `connection`
| Key | Type | Default | Range / rule | FileZilla / notes | Owner |
|---|---|---|---|---|---|
| `timeout_secs` | u32 | 20 | 5–600 | "Timeout in seconds" (inactivity; FileZilla allows 0 = off, we require a timeout) | T07, T10, T20 |
| `retries` | u8 | 2 | 0–10 | "Maximum number of retries" | T03, T41 |
| `retry_delay_secs` | u32 | 5 | 0–600 | "Delay between failed login attempts" | T03, T41 |
| `keepalive` | bool | true | — | "Send FTP keep-alive commands" (we also apply it to SFTP) | T03 |
| `keepalive_interval_secs` | u32 | 30 | 10–3600 | idle time before a keep-alive | T03, T10, T20 |
| `prefer_ipv6` | bool | false | — | try IPv6 addresses first in Happy Eyeballs | T07 |
| `ipv6` | bool | true | — | false = never use IPv6 addresses ("Disable IPv6") | T07 |

#### `ftp`
| Key | Type | Default | Range / rule | Notes | Owner |
|---|---|---|---|---|---|
| `transfer_mode` | FtpTransferMode | passive | — | "Default transfer mode" | T11 |
| `fallback_to_active` | bool | true | — | "Allow fall back to other transfer mode on failure" | T11 |
| `active_external_ip` | ActiveExternalIp | auto | see validation | "Active mode IP": ask the OS / fixed / get from URL; no default URL (FileZilla's own service must not be used) | T11, T72 |
| `active_no_external_ip_on_local` | bool | true | — | "Don't use external IP address on local connections" | T11, T72 |
| `active_port_range` | Option\<PortRange\> | null | 1024 ≤ min ≤ max ≤ 65535 | null = OS ephemeral port | T11 |
| `passive_ignore_unroutable_ip` | bool | true | — | use the control peer IP when PASV returns a private address | T11 |
| `use_mlsd` | bool | true | — | use MLSD when FEAT lists it | T13 |
| `send_keepalive_command` | KeepaliveCommand | noop | — | command used by keep-alive (T10 asks whether `random` should be the default) | T10 |

#### `sftp`
| Key | Type | Default | Range | Notes | Owner |
|---|---|---|---|---|---|
| `max_outstanding_requests` | u16 | 64 | 1–1024 | pipelined requests per file | T41b |
| `request_size` | u32 | 32768 | 1024–262144 | bytes per read/write request (raised to the server's `limits@openssh.com` value, capped at 262144) | T41b |
| `use_openssh_known_hosts` | bool | true | — | also trust keys from the OpenSSH known_hosts files (read-only) | T21 |

#### `proxy`
`proxy.generic` (`GenericProxySettings`) and `proxy.ftp_proxy` (`FtpProxySettings`).
Proxy passwords are **never** in settings: they are `proxy-credential` vault items (T81)
referenced by `password_ref`; the binary resolves them when building `ConnectInfo` (T03).

| Key | Type | Default | Rule | Owner |
|---|---|---|---|---|
| `generic.kind` | ProxyKind | none | — | T07 |
| `generic.host` | String | "" | required when kind ≠ none | T07 |
| `generic.port` | u16 | 0 | 0 = kind default (HTTP 8080, SOCKS 1080) | T07 |
| `generic.user` | String | "" | "" = no authentication (SOCKS4: sent as user id) | T07 |
| `generic.password_ref` | Option\<Uuid\> | null | `proxy-credential` item id | T07, T30 |
| `ftp_proxy.kind` | FtpProxyKind | none | not together with generic | T15 |
| `ftp_proxy.host` | String | "" | required when kind ≠ none | T15 |
| `ftp_proxy.port` | u16 | 21 | 1–65535 | T15 |
| `ftp_proxy.user` | String | "" | `%s` | T15 |
| `ftp_proxy.password_ref` | Option\<Uuid\> | null | `%w` from the vault | T15 |
| `ftp_proxy.custom_script` | Vec\<String\> | [] | ≤ 32 lines, each ≤ 512 chars | T15 |

#### `transfers`
| Key | Type | Default | Range / rule | Notes | Owner |
|---|---|---|---|---|---|
| `max_concurrent` | u8 | 4 | 1–16 | FileZilla default 2, max 10; D11 | T41, T41b |
| `max_downloads` | u8 | 0 | 0–max_concurrent | 0 = no separate limit | T41 |
| `max_uploads` | u8 | 0 | 0–max_concurrent | | T41 |
| `speed_limit_enabled` | bool | false | — | status-bar toggle | T44, T57 |
| `download_limit_kib` | u32 | 0 | 0–1048576 | KiB/s, 0 = unlimited | T44 |
| `upload_limit_kib` | u32 | 0 | 0–1048576 | | T44 |
| `burst_tolerance` | BurstTolerance | normal | — | | T44 |
| `preallocate` | bool | false | — | reserve disk space for downloads (T06) | T06, T42 |
| `preserve_timestamps` | bool | false | — | | T42 |
| `replace_invalid_chars` | bool | true | — | | T42 |
| `invalid_char_replacement` | char | '_' | see validation | | T06, T42 |
| `on_exists_download` | ExistsAction | ask | — | | T42 |
| `on_exists_upload` | ExistsAction | ask | — | | T42 |
| `empty_dirs` | EmptyDirs | create | — | | T43 |
| `follow_symlinks` | bool | false | — | | T43 |
| `segmented.enabled` | bool | true | — | | T41b |
| `segmented.min_file_size_mib` | u32 | 32 | 1–1048576 | | T41b |
| `segmented.max_segments` | u8 | 4 | 1–16 | 1 = off for practical purposes | T41b |
| `segmented.min_segment_size_mib` | u32 | 8 | 1–1024 | | T41b |

#### `file_types`
| Key | Type | Default | Owner |
|---|---|---|---|
| `default_type` | TransferTypeChoice | auto | T11 |
| `ascii_extensions` | Vec\<String\> | `am asp bat c cfm cgi conf cpp css dhtml diz h hpp htm html in inc java js jsp lua m4 mak md5 nfo nsh nsi pas patch php phtml pl po povray py qmail rb rss sfv sh shtml sql svg tcl tpl txt vbs xhtml xml` (FileZilla's list) | T11 |
| `dotfiles_ascii` | bool | true | T11 |
| `no_extension_ascii` | bool | true | T11 |

#### `interface`
| Key | Type | Default | Range / rule | Owner |
|---|---|---|---|---|
| `layout` | Layout | classic | — | T50 |
| `swap_panes` | bool | false | — | T50 |
| `show_tree` | bool | false | — | T50, T54 |
| `show_log` | bool | true | — | T50 |
| `show_queue` | bool | true | — | T50 |
| `show_quickconnect` | bool | true | — | T58 |
| `theme` | Theme | default | `NO_COLOR` forces monochrome | T50 |
| `unicode_symbols` | UnicodeSymbols | auto | — | T57 |
| `key_sequence_timeout_ms` | u32 | 1000 | 200–5000 | T51 |
| `enter_on_file` | EnterOnFile | transfer | — | T51, T53 |
| `size_format` | SizeFormat | iec | — | T53 |
| `thousands_separator` | bool | true | — | T53 |
| `date_format` | String | "%Y-%m-%d" | token subset | T53 |
| `time_format` | String | "%H:%M" | token subset | T53 |
| `dirs_first` | bool | true | — | T53 |
| `sort_case_sensitive` | bool | false | — | T53 |
| `natural_sort` | bool | true | — | T53 |
| `columns` | PaneColumns | local: Name, Size, Type, Modified visible; Permissions, OwnerGroup hidden. remote: all six visible | each column at most once (duplicates dropped); unknown names skipped; Name always present and visible | T53 |
| `sort` | PaneSort | local and remote `{column: Name, descending: false}` | — | saved on quit (T53) |
| `show_hidden_local` | bool | false | — | T53 |
| `force_show_hidden_remote` | bool | false | sends `LIST -a` (T13) | T13, T53 |
| `confirm_delete` | bool | true | — | T62 |
| `confirm_transfer` | bool | false | — | T62 |
| `restore_tabs` | bool | false | — | T61 |
| `language` | String | "auto" | "auto" or a BCP-47 tag | T75 |
| `show_splash` | bool | false | — | T74 |
| `check_updates` | bool | true | — | T74 |
| `check_prereleases` | bool | false | — | T74 |

#### `logging`
| Key | Type | Default | Range | Owner |
|---|---|---|---|---|
| `level` | DebugLevel | 2 | 0–4 | T04, T71 |
| `show_timestamps` | bool | true | — | T55 |
| `show_raw_listing` | bool | false | — | T71 |
| `pane_max_lines` | u32 | 5000 | 500–100000 | T55 |
| `log_to_file` | bool | false | — | T71 |
| `log_file` | Option\<PathBuf\> | null = `<data dir>/session.log` | absolute | T71 |
| `log_file_max_mib` | u32 | 10 | 1–1024 | T71 |
| `log_file_keep` | u8 | 3 | 1–50 | T71 |

#### `editing`
| Key | Type | Default | Rule | Owner |
|---|---|---|---|---|
| `editor` | String | "" | "" = `$VISUAL`, `$EDITOR`, then the platform opener | T63 |
| `editor_terminal` | bool | true | whether a non-empty `editor` runs in the terminal | T63 |
| `viewer` | String | "" | "" = `$PAGER`, then `less` (text) / platform opener | T63 |
| `associations` | Vec\<FileAssociation\> | [] | first match wins | T63 |
| `watch_and_prompt_upload` | bool | true | — | T63 |
| `max_size_mib` | u32 | 50 | 1–10240; larger files need confirmation | T63 |

#### `queue`
| Key | Type | Default | Range | Owner |
|---|---|---|---|---|
| `on_complete` | OnComplete | none | — | T45 |
| `on_complete_command` | String | "" | used when on_complete = run-command; ≤ 1024 chars | T45 |
| `notify` | NotifyMethod | bell | — | T45 |
| `persist` | bool | true | — | T40 |
| `refresh_remote_after` | bool | true | — | T45 |
| `max_successful` | u32 | 1000 | 0–100000 | T40 |

#### `cache`
| Key | Type | Default | Range | Owner |
|---|---|---|---|---|
| `listing_cache` | bool | true | — | T46 |
| `listing_cache_ttl_secs` | u32 | 0 | 0–86400 (0 = until refresh) | T46 |
| `listing_cache_max_dirs` | u32 | 200 | 10–10000 | T46 |

#### `vault`
| Key | Type | Default | Range | Owner |
|---|---|---|---|---|
| `store_passwords` | bool | true | — | T30, T31 |
| `auto_lock_minutes` | u32 | 15 | 0–1440 (0 = off) | T30 |
| `lock_on_suspend` | bool | true | — | T30 |
| `lock_disconnects` | bool | false | — | T30 |
| `argon2_cost` | Argon2Preset | standard | applied at the next password change or unlock re-wrap | T30, T60 |

Keyring unlock is per device and lives in the vault DB (`meta.lmk_wrapped_keyring`, T30),
not in settings.

#### `sync`
| Key | Type | Default | Range | Owner |
|---|---|---|---|---|
| `history` | bool | false | sync quickconnect history items | T88 |
| `push_debounce_ms` | u32 | 2000 | 100–60000 | T88 |
| `poll_fallback_secs` | u32 | 300 | 30–3600 | T88 |

The server URL and tokens are not settings (T87 stores them in `sync_state`).

#### `filters` (added by T47)
`filters.filters` (list of `Filter`), `filters.sets` (list of `FilterSet`),
`filters.active_set` (String, default "default"), `filters.apply_to_transfers`
(bool, default true, T67). Types and defaults (built-in filters) are specified in T47.

#### Generated files
- `docs/settings.schema.json` — `Settings::json_schema()` pretty-printed; a test fails when it
  is stale; `COURIER_FTP_BLESS=1 cargo test -p courier-ftp-core settings_schema` rewrites it
  (T00/T76 convention).

### Errors

- Loading never returns an error for settings content; it returns warnings.
- `save_user`: `Error::Io` (cannot write; message names the file), `Error::InvalidInput`
  ("config.json is not valid JSON; fix or remove it before saving settings").
- `SettingsStore::update` propagates the save error; T68 shows it in an error dialog and
  keeps the unsaved edits.

### Security and logging

- No secrets in settings: proxy passwords are vault items (`password_ref`). A key named
  `password`/`pass` anywhere under `settings` is reported as unknown with the extra hint
  "passwords are stored in the vault, not in the config file" and its value is never logged.
- Warnings logged at `warn` contain only the key path, never the value (values can be hosts
  or paths, T91 §4).
- `on_complete_command`, `editor`, `viewer` and `associations` run local programs, but they
  are local config written by this user (not synced), so no approval is needed (T91 §8 covers
  synced values only).

## Implementation steps

1. `settings::enums` and `settings::model` with all structs, defaults (`impl Default`) and
   doc comments; serde + schemars derives; `decide_transfer_type`.
2. `Settings::validate` with the rules and ranges above.
3. `Settings::from_json_lenient` (leaf merge) with unknown-key warnings.
4. `to_user_json` and `save_user` (atomic write, unknown-key preservation).
5. `SettingsStore` / `SharedSettings`.
6. Binary: `RawConfig` → `Config.settings`, warnings to the log, refusal check for
   yaml/toml/ini shadowing, remove `#![allow(dead_code)]`.
7. `json_schema()`, `docs/settings.schema.json` and the staleness test.

## Acceptance criteria

- [ ] AC1 Every key in the tables exists with the listed type, default and rustdoc (the
  rustdoc names the FileZilla equivalent where there is one); `Settings::default()` equals the
  tables (test).
- [ ] AC2 `{}` / absent `settings` ⇒ `Settings::default()` with no warnings; a partial object
  overrides only the given leaves.
- [ ] AC3 Each invalid value in the validation list produces exactly one warning with the right
  dotted path and the field falls back to its default; startup continues (`Config::new` is Ok).
- [ ] AC4 Unknown keys produce a warning and are preserved by `save_user`.
- [ ] AC5 `save_user` writes only non-default leaves, keeps `keybindings`, `styles` and other
  top-level keys byte-for-byte equal as JSON values, and reload ⇒ equal `Settings`.
- [ ] AC6 `save_user` refuses to overwrite an invalid `config.json` and leaves it unchanged.
- [ ] AC7 `decide_transfer_type` follows the rules for all branches.
- [ ] AC8 `SettingsStore::update` publishes to subscribers only after a successful save.
- [ ] AC9 `docs/settings.schema.json` is current (staleness test).
- [ ] AC10 T00 CI gates pass (fmt, clippy, docs, test-local-only, test-os, layering).

## Tests

### Unit tests
- `default_settings_match_registry_tables` — spot-checks every key's default (one assert per key). (AC1)
- `empty_and_null_settings_give_defaults` — `{}`, `null`, missing key. (AC2)
- `partial_override_changes_only_that_leaf` — `{"connection":{"timeout_secs":30}}`. (AC2)
- `wrong_type_leaf_is_dropped_with_warning` — `{"transfers":{"max_concurrent":"many"}}` → default 4, warning path `transfers.max_concurrent`. (AC3)
- `validation_table` — one row per rule: port range (6000,5000), max_concurrent 0 and 17, timeout 2, replacement `/`, active_external_ip `{"from-url":"ftp://x"}`, both proxies set, proxy kind without host, date format `%Q`, relative log_file. Each: one warning, field = default. (AC3)
- `unknown_key_warns` and `password_key_gets_vault_hint`. (AC4)
- `ascii_extensions_are_normalised` — `[".PHP","php","a b"]` → `["php"]` + one warning. (AC3)
- `decide_transfer_type_table` — `index.HTML`→Ascii, `photo.jpg`→Binary, `.bashrc`→Ascii, `Makefile`→Ascii, both flags off → Binary, choice Binary overrides, default_type Binary overrides Auto. (AC7)
- `debug_level_serialises_as_integer`. (AC1)

### Property / fuzz tests
- `prop_lenient_load_never_panics` — random JSON trees (depth ≤ 4) under `settings`; always returns a `Settings` that passes `validate()` with no further warnings. (AC3)
- `prop_user_json_roundtrip` — random valid `Settings` (proptest strategies per field) → `to_user_json` → `from_json_lenient` gives the same value, no warnings. (AC5)

### Snapshot tests
- `settings_schema_is_current` — compares `Settings::json_schema()` with `docs/settings.schema.json`. (AC9)

### Integration tests
- `save_user_preserves_other_keys` (tempdir) — existing `config.json` with keybindings, styles, `settings.future_key` → save → those values unchanged, only diffs written. (AC4, AC5)
- `save_user_refuses_invalid_json` — file contents unchanged after the error. (AC6)
- `save_user_creates_file_and_dir` — no config dir → created (0700 on Unix), file written. (AC5)
- `settings_store_publishes_after_save` — subscriber sees the change; with a read-only dir the update errors and the subscriber sees no change. (AC8)
- Binary: `config_new_survives_bad_settings` — user config with an invalid setting in a temp `COURIER_FTP_HOME` → `Config::new()` is Ok and returns the warning. (AC3)
- Binary: `save_refused_when_toml_shadows_settings`. (AC6)

### End-to-end tests
Not applicable (covered by T68's UI tests).

## Out of scope

- The Settings screen (T68), settings import/export files (T73).
- Filter types and defaults (T47).
- Hot reload of hand-edited config files while the app runs (not in FileZilla; changes made
  outside the app apply at next start).

## Open questions

- Default for `logging.level` is 2 (Info) as in the original plan; FileZilla's default is 0
  (no debug lines). Keep 2?
- `queue.notify` default is `bell`. OSC 9/777 desktop notifications are opt-in because some
  terminals print the sequence. Confirm.
