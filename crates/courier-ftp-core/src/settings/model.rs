//! The typed settings model (T05): one struct per section, every field defaulted.
//!
//! This module is the code side of the settings registry in `tasks/05-settings-model.md`.
//! A later task that needs a key adds the field here (with its default, a doc comment that
//! names the FileZilla equivalent where there is one, and its validation rule) and to the
//! registry tables, then regenerates `docs/settings.schema.json`
//! (`COURIER_FTP_BLESS=1 cargo test -p courier-ftp-core settings_schema`).

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use super::enums::{
    ActiveExternalIp, Argon2Preset, BurstTolerance, Column, ConnectTarget, DebugLevel, EmptyDirs,
    EnterOnFile, ExistsAction, FtpProxyKind, FtpTransferMode, KeepaliveCommand, Layout,
    NotifyMethod, OnComplete, ProxyKind, SizeFormat, Theme, TransferTypeChoice, UnicodeSymbols,
};
use crate::edit::{Association, EditorChoice};

/// All settings. A partial user object works: every section and field has a default.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(title = "courier-ftp settings")]
pub struct Settings {
    /// Connection timeouts, retries, keep-alive and IPv6 (FileZilla: Connection).
    pub connection: ConnectionSettings,
    /// FTP transfer mode, active mode and listing options (FileZilla: Connection → FTP).
    pub ftp: FtpSettings,
    /// SFTP pipelining and host key sources (FileZilla: Connection → SFTP).
    pub sftp: SftpSettings,
    /// Generic and FTP proxies (FileZilla: Connection → Generic proxy / FTP → FTP Proxy).
    pub proxy: ProxySettings,
    /// Parallel transfers, speed limits, file-exists actions (FileZilla: Transfers).
    pub transfers: TransferSettings,
    /// ASCII / binary detection (FileZilla: Transfers → FTP: File Types).
    pub file_types: FileTypeSettings,
    /// Layout, file lists, date formats and confirmations (FileZilla: Interface).
    pub interface: InterfaceSettings,
    /// Message log and log file (FileZilla: Logging, Debug).
    pub logging: LoggingSettings,
    /// External editors and file associations (FileZilla: File editing).
    pub editing: EditingSettings,
    /// Queue completion actions and persistence (FileZilla: Transfers → queue).
    pub queue: QueueSettings,
    /// Directory listing cache.
    pub cache: CacheSettings,
    /// Vault locking and key derivation cost (FileZilla: Interface → Passwords).
    pub vault: VaultSettings,
    /// Device sync tuning. The server URL and tokens are not settings.
    pub sync: SyncSettings,
}

/// `connection`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ConnectionSettings {
    /// Inactivity timeout in seconds, 5–600. FileZilla: "Timeout in seconds" (FileZilla
    /// allows 0 = off; courier-ftp always uses a timeout).
    pub timeout_secs: u32,
    /// Retries after a failed connection, 0–10. FileZilla: "Maximum number of retries".
    pub retries: u8,
    /// Seconds between retries, 0–600. FileZilla: "Delay between failed login attempts".
    pub retry_delay_secs: u32,
    /// Keep idle connections alive (FTP and SFTP). FileZilla: "Send FTP keep-alive commands".
    pub keepalive: bool,
    /// Idle seconds before a keep-alive is sent, 10–3600.
    pub keepalive_interval_secs: u32,
    /// Try IPv6 addresses first when connecting (Happy Eyeballs).
    pub prefer_ipv6: bool,
    /// Use IPv6 addresses at all. FileZilla: "Disable IPv6" (inverted).
    pub ipv6: bool,
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            timeout_secs: 20,
            retries: 2,
            retry_delay_secs: 5,
            keepalive: true,
            keepalive_interval_secs: 30,
            prefer_ipv6: false,
            ipv6: true,
        }
    }
}

/// A port range, `1024 ≤ min ≤ max ≤ 65535`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PortRange {
    /// Lowest port.
    pub min: u16,
    /// Highest port.
    pub max: u16,
}

/// `ftp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct FtpSettings {
    /// FileZilla: "Default transfer mode" (`passive` or `active`).
    pub transfer_mode: FtpTransferMode,
    /// FileZilla: "Allow fall back to other transfer mode on failure".
    pub fallback_to_active: bool,
    /// FileZilla: "Active mode IP": `"auto"` (ask the OS), `{"fixed":"203.0.113.5"}` or
    /// `{"from_url":"http://…"}` (an `http://` URL, at most 512 characters).
    pub active_external_ip: ActiveExternalIp,
    /// FileZilla: "Don't use external IP address on local connections".
    pub active_no_external_ip_on_local: bool,
    /// FileZilla: "Limit local ports used by FileZilla". null = OS ephemeral port.
    pub active_port_range: Option<PortRange>,
    /// Use the control connection's peer address when PASV returns a private address.
    /// FileZilla: "Use the server's external IP address instead".
    pub passive_ignore_unroutable_ip: bool,
    /// Use MLSD for listings when the server lists it in FEAT.
    pub use_mlsd: bool,
    /// Keep-alive command: `noop` or `random` (NOOP, PWD or TYPE, as FileZilla does).
    pub send_keepalive_command: KeepaliveCommand,
}

impl Default for FtpSettings {
    fn default() -> Self {
        Self {
            transfer_mode: FtpTransferMode::Passive,
            fallback_to_active: true,
            active_external_ip: ActiveExternalIp::Auto,
            active_no_external_ip_on_local: true,
            active_port_range: None,
            passive_ignore_unroutable_ip: true,
            use_mlsd: true,
            send_keepalive_command: KeepaliveCommand::Noop,
        }
    }
}

/// `sftp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SftpSettings {
    /// Pipelined requests per open file, 1–256 (the effective value is also capped at
    /// 8 MiB / request size).
    pub max_outstanding_requests: u32,
    /// Bytes per read/write request, 4096–261120, when the server sends no
    /// `limits@openssh.com` (else the server's value, capped at 261120).
    pub request_size: u32,
    /// Also trust host keys from the OpenSSH known_hosts files (read-only).
    pub use_openssh_known_hosts: bool,
}

impl Default for SftpSettings {
    fn default() -> Self {
        Self {
            max_outstanding_requests: 64,
            request_size: 32768,
            use_openssh_known_hosts: true,
        }
    }
}

/// `proxy`. Proxy passwords are never settings: they are `proxy-credential` vault items
/// referenced by `password_ref`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ProxySettings {
    /// FileZilla: Connection → Generic proxy.
    pub generic: GenericProxySettings,
    /// FileZilla: Connection → FTP → FTP Proxy. Cannot be used with the generic proxy.
    pub ftp_proxy: FtpProxySettings,
}

/// `proxy.generic` (T07).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct GenericProxySettings {
    /// FileZilla: "Type of generic proxy": `none`, `http`, `socks4` or `socks5`.
    pub kind: ProxyKind,
    /// FileZilla: "Proxy host". Required when kind is not `none`.
    pub host: String,
    /// FileZilla: "Proxy port". 0 = the kind's default (HTTP 8080, SOCKS 1080).
    pub port: u16,
    /// FileZilla: "Proxy user". Empty = no authentication (SOCKS4: sent as user id).
    pub user: String,
    /// FileZilla: "Proxy password", stored as a `proxy-credential` vault item; this is its id.
    pub password_ref: Option<Uuid>,
}

/// `proxy.ftp_proxy` (T15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct FtpProxySettings {
    /// FileZilla: "Type of FTP Proxy": `none`, `user_at_host`, `site`, `open`, `custom`.
    pub kind: FtpProxyKind,
    /// FileZilla: "Proxy host". Required when kind is not `none`.
    pub host: String,
    /// FileZilla: "Proxy port", 1–65535.
    pub port: u16,
    /// FileZilla: "Proxy user" (`%s` in scripts).
    pub user: String,
    /// FileZilla: "Pass" (`%w` in scripts), a `proxy-credential` vault item id.
    pub password_ref: Option<Uuid>,
    /// FileZilla: custom login sequence. `'\n'`-separated lines, used when kind is
    /// `custom`; at most 32 lines of at most 512 characters.
    pub custom_script: String,
}

impl Default for FtpProxySettings {
    fn default() -> Self {
        Self {
            kind: FtpProxyKind::None,
            host: String::new(),
            port: 21,
            user: String::new(),
            password_ref: None,
            custom_script: String::new(),
        }
    }
}

/// `transfers.segmented` (T41b): large files split over several connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SegmentedSettings {
    /// Split large files into ranges.
    pub enabled: bool,
    /// Only files of at least this many MiB are split, 1–1048576.
    pub min_file_size_mib: u32,
    /// Segments per file, 1–16 (1 = off for practical purposes).
    pub max_segments: u8,
    /// Smallest segment in MiB, 1–1024.
    pub min_segment_size_mib: u32,
}

impl Default for SegmentedSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            min_file_size_mib: 32,
            max_segments: 4,
            min_segment_size_mib: 8,
        }
    }
}

/// `transfers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct TransferSettings {
    /// FileZilla: "Maximum simultaneous transfers", 1–16 (FileZilla: default 2, max 10).
    pub max_concurrent: u8,
    /// FileZilla: "Limit for concurrent downloads", 0 (no separate limit) to max_concurrent.
    pub max_downloads: u8,
    /// FileZilla: "Limit for concurrent uploads", 0 (no separate limit) to max_concurrent.
    pub max_uploads: u8,
    /// FileZilla: "Enable speed limits" (also toggled from the status bar).
    pub speed_limit_enabled: bool,
    /// FileZilla: "Download limit" in KiB/s, 0–1048576, 0 = unlimited.
    pub download_limit_kib: u32,
    /// FileZilla: "Upload limit" in KiB/s, 0–1048576, 0 = unlimited.
    pub upload_limit_kib: u32,
    /// FileZilla: "Burst tolerance": `normal`, `high` or `very_high`.
    pub burst_tolerance: BurstTolerance,
    /// FileZilla: "Preallocate space before downloading".
    pub preallocate: bool,
    /// FileZilla: "Preserve timestamps of transferred files".
    pub preserve_timestamps: bool,
    /// FileZilla: "Enable invalid character filtering".
    pub replace_invalid_chars: bool,
    /// FileZilla: "Replace invalid characters with". Not one of `\ / : * ? " < > |`, `.`,
    /// space or a control character.
    pub invalid_char_replacement: char,
    /// FileZilla: "Default file exists action" for downloads.
    pub on_exists_download: ExistsAction,
    /// FileZilla: "Default file exists action" for uploads.
    pub on_exists_upload: ExistsAction,
    /// Empty directories in recursive transfers: `create` or `skip`.
    pub empty_dirs: EmptyDirs,
    /// Follow symbolic links in recursive operations.
    pub follow_symlinks: bool,
    /// Segmented (multi-connection) transfers of large files.
    pub segmented: SegmentedSettings,
}

impl Default for TransferSettings {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
            max_downloads: 0,
            max_uploads: 0,
            speed_limit_enabled: false,
            download_limit_kib: 0,
            upload_limit_kib: 0,
            burst_tolerance: BurstTolerance::Normal,
            preallocate: false,
            preserve_timestamps: false,
            replace_invalid_chars: true,
            invalid_char_replacement: '_',
            on_exists_download: ExistsAction::Ask,
            on_exists_upload: ExistsAction::Ask,
            empty_dirs: EmptyDirs::Create,
            follow_symlinks: false,
            segmented: SegmentedSettings::default(),
        }
    }
}

/// FileZilla's default ASCII extension list.
pub const DEFAULT_ASCII_EXTENSIONS: &[&str] = &[
    "am", "asp", "bat", "c", "cfm", "cgi", "conf", "cpp", "css", "dhtml", "diz", "h", "hpp", "htm",
    "html", "in", "inc", "java", "js", "jsp", "lua", "m4", "mak", "md5", "nfo", "nsh", "nsi",
    "pas", "patch", "php", "phtml", "pl", "po", "povray", "py", "qmail", "rb", "rss", "sfv", "sh",
    "shtml", "sql", "svg", "tcl", "tpl", "txt", "vbs", "xhtml", "xml",
];

/// `file_types`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct FileTypeSettings {
    /// FileZilla: "Default transfer type": `auto`, `ascii` or `binary`.
    pub default_type: TransferTypeChoice,
    /// FileZilla: "Treat the following filetypes as ASCII files" (lowercase, no dot).
    pub ascii_extensions: Vec<String>,
    /// FileZilla: "Treat dotfiles as ASCII files".
    pub dotfiles_ascii: bool,
    /// FileZilla: "Treat files without extension as ASCII file".
    pub no_extension_ascii: bool,
}

impl Default for FileTypeSettings {
    fn default() -> Self {
        Self {
            default_type: TransferTypeChoice::Auto,
            ascii_extensions: DEFAULT_ASCII_EXTENSIONS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            dotfiles_ascii: true,
            no_extension_ascii: true,
        }
    }
}

/// One column of a file list and whether it is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ColumnSpec {
    /// The column.
    pub column: Column,
    /// Shown.
    pub visible: bool,
}

/// The columns of both file lists, in display order (T53).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct PaneColumns {
    /// Local file list. Unknown column names are skipped.
    #[serde(deserialize_with = "de_columns")]
    #[schemars(with = "Vec<ColumnSpec>")]
    pub local: Vec<ColumnSpec>,
    /// Remote file list. Unknown column names are skipped.
    #[serde(deserialize_with = "de_columns")]
    #[schemars(with = "Vec<ColumnSpec>")]
    pub remote: Vec<ColumnSpec>,
}

impl Default for PaneColumns {
    fn default() -> Self {
        let col = |column, visible| ColumnSpec { column, visible };
        Self {
            local: vec![
                col(Column::Name, true),
                col(Column::Size, true),
                col(Column::Type, true),
                col(Column::Modified, true),
                col(Column::Permissions, false),
                col(Column::OwnerGroup, false),
            ],
            remote: Column::ALL.iter().map(|c| col(*c, true)).collect(),
        }
    }
}

/// A column list where entries with unknown column names are skipped.
fn de_columns<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<ColumnSpec>, D::Error> {
    let raw = Vec::<serde_json::Value>::deserialize(d)?;
    Ok(raw
        .into_iter()
        .filter_map(|v| serde_json::from_value::<ColumnSpec>(v).ok())
        .collect())
}

/// Sort order of one file list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SortSpec {
    /// Sort column.
    pub column: Column,
    /// Descending order.
    pub descending: bool,
}

impl Default for SortSpec {
    fn default() -> Self {
        Self {
            column: Column::Name,
            descending: false,
        }
    }
}

/// Sort order of both file lists (saved on quit, T53).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct PaneSort {
    /// Local file list.
    pub local: SortSpec,
    /// Remote file list.
    pub remote: SortSpec,
}

/// `interface`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct InterfaceSettings {
    /// FileZilla: "Layout of file and directory panes": `classic`, `explorer`, `widescreen`.
    pub layout: Layout,
    /// FileZilla: "Swap local and remote panes".
    pub swap_panes: bool,
    /// Show the directory tree pane (FileZilla: View → Directory tree).
    pub show_tree: bool,
    /// Show the message log (FileZilla: View → Message log).
    pub show_log: bool,
    /// Show the transfer queue (FileZilla: View → Transfer queue).
    pub show_queue: bool,
    /// Show the quickconnect bar (FileZilla: View → Quickconnect bar).
    pub show_quickconnect: bool,
    /// Colour theme: `default`, `high_contrast` or `monochrome` (`NO_COLOR` forces
    /// monochrome). FileZilla: "Theme".
    pub theme: Theme,
    /// Unicode symbols: `auto`, `always` or `never`.
    pub unicode_symbols: UnicodeSymbols,
    /// Milliseconds to wait for the next key of a key sequence (`gg`), 200–5000.
    pub key_sequence_timeout_ms: u32,
    /// What Enter does on a file: `transfer`, `view`, `edit` or `none`. FileZilla: "Double-click
    /// action on files".
    pub enter_on_file: EnterOnFile,
    /// Where a connect request opens: `ask`, `new_tab` or `replace` (set by "remember my
    /// choice").
    pub connect_target: ConnectTarget,
    /// FileZilla: "Filesize format": `bytes`, `iec` or `si`.
    pub size_format: SizeFormat,
    /// FileZilla: "Use thousands separator".
    pub thousands_separator: bool,
    /// FileZilla: "Date/time format" (date part). Tokens `%Y %y %m %d %e %b %H %I %M %S %p
    /// %%` plus literal text, at most 32 characters.
    pub date_format: String,
    /// FileZilla: "Date/time format" (time part). Same tokens as `date_format`.
    pub time_format: String,
    /// FileZilla: "Sorting mode" → directories first.
    pub dirs_first: bool,
    /// FileZilla: "Sorting mode" → case sensitive.
    pub sort_case_sensitive: bool,
    /// Natural sort (`file2` before `file10`). FileZilla: "Natural sort".
    pub natural_sort: bool,
    /// File list columns. Each column at most once; Name is always present and visible.
    pub columns: PaneColumns,
    /// Sort order of the file lists.
    pub sort: PaneSort,
    /// Show hidden local files.
    pub show_hidden_local: bool,
    /// FileZilla: "Force showing hidden files" (sends `LIST -a`).
    pub force_show_hidden_remote: bool,
    /// Ask before deleting.
    pub confirm_delete: bool,
    /// Ask before transferring.
    pub confirm_transfer: bool,
    /// FileZilla: "Restore tabs and reconnect".
    pub restore_tabs: bool,
    /// FileZilla: "Language": `"auto"` or a BCP-47 tag.
    pub language: String,
    /// FileZilla: "Show welcome dialog / splash screen".
    pub show_splash: bool,
    /// FileZilla: "Check for FileZilla updates automatically".
    pub check_updates: bool,
    /// FileZilla: "Check for beta versions and release candidates".
    pub check_prereleases: bool,
}

impl Default for InterfaceSettings {
    fn default() -> Self {
        Self {
            layout: Layout::Classic,
            swap_panes: false,
            show_tree: false,
            show_log: true,
            show_queue: true,
            show_quickconnect: true,
            theme: Theme::Default,
            unicode_symbols: UnicodeSymbols::Auto,
            key_sequence_timeout_ms: 1000,
            enter_on_file: EnterOnFile::Transfer,
            connect_target: ConnectTarget::Ask,
            size_format: SizeFormat::Iec,
            thousands_separator: true,
            date_format: "%Y-%m-%d".to_owned(),
            time_format: "%H:%M".to_owned(),
            dirs_first: true,
            sort_case_sensitive: false,
            natural_sort: true,
            columns: PaneColumns::default(),
            sort: PaneSort::default(),
            show_hidden_local: false,
            force_show_hidden_remote: false,
            confirm_delete: true,
            confirm_transfer: false,
            restore_tabs: false,
            language: "auto".to_owned(),
            show_splash: false,
            check_updates: true,
            check_prereleases: false,
        }
    }
}

/// `logging`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LoggingSettings {
    /// FileZilla: "Debug information in message log", 0–4.
    pub level: DebugLevel,
    /// FileZilla: "Show timestamps in message log".
    pub show_timestamps: bool,
    /// FileZilla: "Show raw directory listing".
    pub show_raw_listing: bool,
    /// Lines kept in the message log pane, 500–100000.
    pub pane_max_lines: u32,
    /// FileZilla: "Log to file".
    pub log_to_file: bool,
    /// FileZilla: "Filename". Absolute path; null = `<data dir>/session.log`.
    pub log_file: Option<PathBuf>,
    /// FileZilla: "Limit size of logfile" in MiB, 1–1024.
    pub log_file_max_mib: u32,
    /// Rotated log files kept, 1–50.
    pub log_file_keep: u8,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self {
            level: DebugLevel::Info,
            show_timestamps: true,
            show_raw_listing: false,
            pane_max_lines: 5000,
            log_to_file: false,
            log_file: None,
            log_file_max_mib: 10,
            log_file_keep: 3,
        }
    }
}

/// `editing` (T63).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct EditingSettings {
    /// FileZilla: "Default editor": `"auto"` ($VISUAL, $EDITOR, then the platform
    /// default) or `{"command":{"command":"vim","terminal":true}}`.
    pub editor: EditorChoice,
    /// FileZilla: "Filetype associations". First match wins; at most 256 entries.
    pub associations: Vec<Association>,
    /// FileZilla: "Watch locally edited files and prompt to upload modifications".
    pub watch_and_prompt_upload: bool,
    /// Ask before downloading files larger than this many MiB for editing, 0–10240;
    /// 0 = never ask.
    pub max_size_mib: u32,
}

impl Default for EditingSettings {
    fn default() -> Self {
        Self {
            editor: EditorChoice::Auto,
            associations: Vec::new(),
            watch_and_prompt_upload: true,
            max_size_mib: 50,
        }
    }
}

/// `queue`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct QueueSettings {
    /// FileZilla: "Action after queue completion": `none`, `show_message`, `run_command`,
    /// `disconnect` or `close_app`.
    pub on_complete: OnComplete,
    /// FileZilla: "Run command"; used when `on_complete` is `run_command`, ≤ 1024 chars.
    pub on_complete_command: String,
    /// Notification when the queue is done: `none`, `bell` or `osc`.
    pub notify: NotifyMethod,
    /// Keep the queue across restarts (encrypted, device-local).
    pub persist: bool,
    /// Refresh the remote listing after the queue finished uploads.
    pub refresh_remote_after: bool,
    /// Successful transfers kept in the "Successful transfers" tab, 0–100000.
    pub max_successful: u32,
}

impl Default for QueueSettings {
    fn default() -> Self {
        Self {
            on_complete: OnComplete::None,
            on_complete_command: String::new(),
            notify: NotifyMethod::Bell,
            persist: true,
            refresh_remote_after: true,
            max_successful: 1000,
        }
    }
}

/// `cache` (T46).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct CacheSettings {
    /// Cache directory listings.
    pub listing_cache: bool,
    /// Seconds a cached listing stays valid, 0–86400 (0 = until refreshed).
    pub listing_cache_ttl_secs: u32,
    /// Directories kept in one global LRU across servers, 10–10000.
    pub listing_cache_max_dirs: u32,
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            listing_cache: true,
            listing_cache_ttl_secs: 0,
            listing_cache_max_dirs: 200,
        }
    }
}

/// `vault` (T30).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct VaultSettings {
    /// FileZilla: "Save passwords" (in the encrypted vault).
    pub store_passwords: bool,
    /// Lock the vault after this many idle minutes, 0–1440 (0 = off).
    pub auto_lock_minutes: u32,
    /// Lock the vault when the system suspends.
    pub lock_on_suspend: bool,
    /// Locking the vault also disconnects all sessions.
    pub lock_disconnects: bool,
    /// Argon2id cost: `light`, `standard` or `strong`; applied at the next password
    /// change or unlock re-wrap.
    pub argon2_cost: Argon2Preset,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            store_passwords: true,
            auto_lock_minutes: 15,
            lock_on_suspend: true,
            lock_disconnects: false,
            argon2_cost: Argon2Preset::Standard,
        }
    }
}

/// `sync` (T88).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SyncSettings {
    /// Sync quickconnect history items.
    pub history: bool,
    /// Milliseconds to wait after a change before pushing, 100–60000.
    pub push_debounce_ms: u32,
    /// Seconds between polls when live updates are unavailable, 30–3600.
    pub poll_fallback_secs: u32,
}

impl Default for SyncSettings {
    fn default() -> Self {
        Self {
            history: false,
            push_debounce_ms: 2000,
            poll_fallback_secs: 300,
        }
    }
}
