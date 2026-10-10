//! Typed application settings (T05): everything FileZilla puts in its Settings
//! dialog, with FileZilla's defaults.
//!
//! Settings live under the `settings` key of the layered config (D10): the
//! defaults baked into the binary plus the user's `config.*` files. Every
//! section and field is `#[serde(default)]`, so a partial user config only
//! overrides what it names. Load untrusted input with [`Settings::from_value`],
//! which never fails: a field with a wrong type or an out-of-range value is
//! reported and replaced by its default. [`Settings::save_user`] writes back only
//! the values that differ from the defaults.
//!
//! Later tasks add their own sections and fields here (vault T30, sync T88,
//! segmented transfers T41b, more interface options T50–T62).

mod persist;
mod validate;

use std::{net::IpAddr, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::filters::FilterSettings;

pub use persist::LoadReport;

/// All settings, grouped like FileZilla's Settings dialog.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Timeouts, retries, keep-alive (FileZilla: Connection).
    pub connection: ConnectionSettings,
    /// FTP specifics (FileZilla: Connection → FTP, Active/Passive mode).
    pub ftp: FtpSettings,
    /// Generic and FTP proxies (FileZilla: Connection → Generic proxy, FTP proxy).
    pub proxy: ProxySettings,
    /// Concurrency, speed limits, file-exists actions (FileZilla: Transfers).
    pub transfers: TransferSettings,
    /// ASCII/binary decision (FileZilla: Transfers → FTP: File Types).
    pub file_types: FileTypeSettings,
    /// Layout, formats, sorting, confirmations (FileZilla: Interface).
    pub interface: InterfaceSettings,
    /// Message log and log file (FileZilla: Logging, Debug).
    pub logging: LoggingSettings,
    /// External editor and associations (FileZilla: File editing).
    pub editing: EditingSettings,
    /// Queue persistence and the action when it finishes.
    pub queue: QueueSettings,
    /// Directory listing cache.
    pub cache: CacheSettings,
    /// Filename filters and filter sets (T47).
    pub filters: FilterSettings,
}

/// Timeouts, retries and keep-alive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionSettings {
    /// Seconds without any reply before a connection is considered dead. Must be
    /// at least 1: every network operation has a timeout. FileZilla default 20.
    pub timeout_secs: u64,
    /// How often a failed connection attempt is retried. FileZilla default 2.
    pub retries: u32,
    /// Seconds to wait between retries. FileZilla default 5.
    pub retry_delay_secs: u64,
    /// Send keep-alive commands on idle connections so they don't drop.
    pub keepalive: bool,
    /// Seconds of idleness before a keep-alive is sent.
    pub keepalive_interval_secs: u64,
    /// Try IPv6 addresses before IPv4 when a host has both.
    pub prefer_ipv6: bool,
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
        }
    }
}

/// FTP-only settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FtpSettings {
    /// Passive (`PASV`/`EPSV`) or active (`PORT`/`EPRT`) data connections.
    pub transfer_mode: FtpTransferMode,
    /// Fall back to active mode when passive mode fails.
    pub fallback_to_active: bool,
    /// The address to announce in active mode.
    pub active_external_ip: ExternalIp,
    /// Limit the local ports used in active mode, inclusive. `None` lets the OS
    /// choose.
    pub active_port_range: Option<(u16, u16)>,
    /// When `PASV` returns a private address but the server was reached over a
    /// public one, connect to the control connection's host instead.
    pub passive_ignore_unroutable_ip: bool,
    /// Use `MLSD` for listings when the server supports it (else `LIST`).
    pub use_mlsd: bool,
    /// The command sent as a keep-alive: `NOOP`, `PWD` or `TYPE`.
    pub send_keepalive_command: String,
}

impl Default for FtpSettings {
    fn default() -> Self {
        Self {
            transfer_mode: FtpTransferMode::Passive,
            fallback_to_active: true,
            active_external_ip: ExternalIp::Auto,
            active_port_range: None,
            passive_ignore_unroutable_ip: true,
            use_mlsd: true,
            send_keepalive_command: "NOOP".to_owned(),
        }
    }
}

/// FTP data connection mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FtpTransferMode {
    /// The client connects to the server (works through most NATs).
    #[default]
    Passive,
    /// The server connects back to the client.
    Active,
}

/// The external address announced in active mode.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalIp {
    /// Use the local address of the control connection.
    #[default]
    Auto,
    /// Always announce this address.
    Fixed(IpAddr),
    /// Ask this IP lookup service (a URL returning the address as text).
    FromUrl(String),
}

/// Proxy settings. Proxy passwords live in the vault (T30) and are referenced
/// by [`ProxyServer::password_ref`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxySettings {
    /// HTTP CONNECT or SOCKS proxy for every protocol.
    pub generic: GenericProxy,
    /// FTP-level proxy (FTP only).
    pub ftp_proxy: FtpProxy,
}

/// A proxy server's address and login. No password: see `password_ref`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProxyServer {
    /// Host name or address.
    pub host: String,
    /// Port.
    pub port: u16,
    /// User name, if the proxy needs one.
    #[serde(default)]
    pub user: Option<String>,
    /// Id of the vault item holding the proxy password.
    #[serde(default)]
    pub password_ref: Option<String>,
}

/// Generic proxy type (FileZilla: Connection → Generic proxy).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GenericProxy {
    /// Connect directly.
    #[default]
    None,
    /// HTTP/1.1 `CONNECT`.
    Http(ProxyServer),
    /// SOCKS 4.
    Socks4(ProxyServer),
    /// SOCKS 5.
    Socks5(ProxyServer),
}

/// FTP proxy type (FileZilla: Connection → FTP → FTP Proxy).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FtpProxy {
    /// No FTP proxy.
    #[default]
    None,
    /// `USER user@host`.
    UserAtHost(ProxyServer),
    /// `SITE host`.
    Site(ProxyServer),
    /// `OPEN host`.
    Open(ProxyServer),
    /// A custom login script (`%h`, `%u`, `%p`, `%s`, `%w` placeholders, T15).
    Custom {
        /// The proxy.
        server: ProxyServer,
        /// The login sequence, one command per line.
        script: String,
    },
}

/// Transfer settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TransferSettings {
    /// Maximum simultaneous transfers (1–32). Default 4 (D11).
    pub max_concurrent: u32,
    /// Maximum simultaneous downloads within `max_concurrent`; 0 = no extra limit.
    pub max_downloads: u32,
    /// Maximum simultaneous uploads within `max_concurrent`; 0 = no extra limit.
    pub max_uploads: u32,
    /// Whether the speed limits below apply (status bar toggle).
    pub speed_limit_enabled: bool,
    /// Download limit in KiB/s; 0 = unlimited.
    pub download_limit_kib: u64,
    /// Upload limit in KiB/s; 0 = unlimited.
    pub upload_limit_kib: u64,
    /// How far above the limit short bursts may go.
    pub burst_tolerance: BurstTolerance,
    /// Reserve the full file size on disk before downloading.
    pub preallocate: bool,
    /// Copy the source's modification time to the target.
    pub preserve_timestamps: bool,
    /// Replace characters the local filesystem can't store in file names.
    pub replace_invalid_chars: bool,
    /// The replacement character (must itself be valid locally).
    pub invalid_char_replacement: char,
    /// What to do when a downloaded file already exists locally.
    pub on_exists_download: ExistsAction,
    /// What to do when an uploaded file already exists on the server.
    pub on_exists_upload: ExistsAction,
    /// Whether recursive transfers create empty directories.
    pub empty_dirs: EmptyDirs,
    /// Follow symlinks during recursive operations.
    pub follow_symlinks: bool,
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
        }
    }
}

/// Speed limit burst tolerance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BurstTolerance {
    /// Little bursting.
    #[default]
    Normal,
    /// More bursting.
    High,
    /// The most bursting.
    VeryHigh,
}

/// What to do when the target of a transfer already exists (T42).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExistsAction {
    /// Ask the user.
    #[default]
    Ask,
    /// Always overwrite.
    Overwrite,
    /// Overwrite when the source is newer.
    OverwriteIfNewer,
    /// Overwrite when the sizes differ.
    OverwriteIfSizeDiffers,
    /// Overwrite when the source is newer or the sizes differ.
    OverwriteIfNewerOrSizeDiffers,
    /// Resume (append the missing part).
    Resume,
    /// Pick a new name for the target.
    Rename,
    /// Skip the file.
    Skip,
}

/// Empty directories in recursive transfers (T43).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmptyDirs {
    /// Create them on the target.
    #[default]
    Create,
    /// Leave them out.
    Skip,
}

/// ASCII or binary transfer type (T11/T40).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferTypeChoice {
    /// Decide per file from [`FileTypeSettings`].
    #[default]
    Auto,
    /// Always ASCII.
    Ascii,
    /// Always binary.
    Binary,
}

/// How the ASCII/binary decision is made for FTP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FileTypeSettings {
    /// The transfer type to use.
    pub default_type: TransferTypeChoice,
    /// Extensions (without the dot, case-insensitive) transferred as ASCII in
    /// `Auto` mode. FileZilla's default list.
    pub ascii_extensions: Vec<String>,
    /// Treat dotfiles (`.htaccess`) as ASCII in `Auto` mode.
    pub dotfiles_ascii: bool,
    /// Treat files without an extension as ASCII in `Auto` mode.
    pub no_extension_ascii: bool,
}

/// FileZilla's default ASCII extension list.
pub const DEFAULT_ASCII_EXTENSIONS: &[&str] = &[
    "am", "asp", "bat", "c", "cfm", "cgi", "conf", "cpp", "css", "dhtml", "diz", "h", "hpp", "htm",
    "html", "in", "inc", "java", "js", "jsp", "lua", "m4", "mak", "md5", "nfo", "nsh", "nsi",
    "pas", "patch", "php", "phtml", "pl", "po", "povray", "py", "qmail", "rb", "rss", "sfv", "sh",
    "shtml", "sql", "svg", "tcl", "tpl", "txt", "vbs", "xhtml", "xml",
];

impl Default for FileTypeSettings {
    fn default() -> Self {
        Self {
            default_type: TransferTypeChoice::Auto,
            ascii_extensions: DEFAULT_ASCII_EXTENSIONS
                .iter()
                .map(|e| (*e).to_owned())
                .collect(),
            dotfiles_ascii: true,
            no_extension_ascii: true,
        }
    }
}

impl FileTypeSettings {
    /// Whether `file_name` is transferred as ASCII.
    pub fn is_ascii(&self, file_name: &str) -> bool {
        match self.default_type {
            TransferTypeChoice::Ascii => true,
            TransferTypeChoice::Binary => false,
            TransferTypeChoice::Auto => {
                if let Some(rest) = file_name.strip_prefix('.')
                    && !rest.contains('.')
                {
                    return self.dotfiles_ascii;
                }
                match file_name.rsplit_once('.') {
                    Some((_, ext)) if !ext.is_empty() => self
                        .ascii_extensions
                        .iter()
                        .any(|e| e.eq_ignore_ascii_case(ext)),
                    _ => self.no_extension_ascii,
                }
            }
        }
    }
}

/// Interface settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InterfaceSettings {
    /// Pane arrangement.
    pub layout: Layout,
    /// Show the remote pane on the left.
    pub swap_panes: bool,
    /// Show the directory trees.
    pub show_tree: bool,
    /// Show the message log.
    pub show_log: bool,
    /// Show the transfer queue.
    pub show_queue: bool,
    /// Show the quickconnect bar.
    pub show_quickconnect: bool,
    /// How file sizes are shown.
    pub size_format: SizeFormat,
    /// Group digits in byte counts (`1,234,567`).
    pub thousands_separator: bool,
    /// Date format (strftime-like: `%Y-%m-%d`).
    pub date_format: String,
    /// Time format (strftime-like: `%H:%M`).
    pub time_format: String,
    /// List directories before files.
    pub dirs_first: bool,
    /// Case-sensitive name sorting.
    pub sort_case_sensitive: bool,
    /// Show hidden local files.
    pub show_hidden_local: bool,
    /// Ask servers to include hidden files (`LIST -a`).
    pub force_show_hidden_remote: bool,
    /// Ask before deleting.
    pub confirm_delete: bool,
    /// Show the splash screen at startup (T74).
    pub show_splash: bool,
    /// Check for new releases (T74).
    pub check_updates: bool,
    /// UI language, or `auto` for the system locale (T75).
    pub language: String,
    /// Milliseconds allowed between the keys of a sequence like `gg` (T51).
    pub key_sequence_timeout_ms: u64,
    /// Unicode symbols (🔒 ⇅ ⚑) or plain ASCII in the status bar (T57).
    pub unicode_symbols: SymbolMode,
    /// Sort names naturally: `file2` before `file10` (T53).
    pub natural_sort: bool,
    /// Which file list columns are shown, in order (T53).
    pub columns: ColumnSettings,
}

/// A file list column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Column {
    /// File name (always shown).
    Name,
    /// Size.
    Size,
    /// File type, from the extension.
    Type,
    /// Last modified.
    Modified,
    /// Permissions.
    Permissions,
    /// Owner and group.
    Owner,
}

/// The columns of each side's file list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ColumnSettings {
    /// Local pane.
    pub local: Vec<Column>,
    /// Remote pane.
    pub remote: Vec<Column>,
}

impl Default for ColumnSettings {
    fn default() -> Self {
        Self {
            local: vec![Column::Name, Column::Size, Column::Type, Column::Modified],
            remote: vec![
                Column::Name,
                Column::Size,
                Column::Type,
                Column::Modified,
                Column::Permissions,
                Column::Owner,
            ],
        }
    }
}

/// Whether the UI draws Unicode symbols.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolMode {
    /// Unicode when the locale is UTF-8.
    #[default]
    Auto,
    /// Always Unicode.
    Unicode,
    /// Always ASCII.
    Ascii,
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
            size_format: SizeFormat::Iec,
            thousands_separator: true,
            date_format: "%Y-%m-%d".to_owned(),
            time_format: "%H:%M".to_owned(),
            dirs_first: true,
            sort_case_sensitive: false,
            show_hidden_local: false,
            force_show_hidden_remote: false,
            confirm_delete: true,
            show_splash: false,
            check_updates: true,
            language: "auto".to_owned(),
            key_sequence_timeout_ms: 1000,
            unicode_symbols: SymbolMode::Auto,
            natural_sort: true,
            columns: ColumnSettings::default(),
        }
    }
}

/// Pane arrangement (FileZilla: Interface → Layout).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// Log on top, local and remote side by side, queue at the bottom.
    #[default]
    Classic,
    /// Trees on the left, lists on the right.
    Explorer,
    /// The log beside the panes, for wide terminals.
    Widescreen,
}

/// How byte counts are shown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SizeFormat {
    /// Exact bytes.
    Bytes,
    /// Binary units: KiB, MiB (1024).
    #[default]
    Iec,
    /// Decimal units: kB, MB (1000).
    Si,
}

/// Logging settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingSettings {
    /// FileZilla debug level 0–4: 0 none, 1 warning, 2 info, 3 verbose, 4 debug.
    pub level: u8,
    /// Also write the message log to a file.
    pub log_to_file: bool,
    /// The log file; `None` means `<data dir>/session.log`.
    pub log_file: Option<PathBuf>,
    /// Rotate the log file at this size (MiB).
    pub log_file_max_mib: u64,
    /// Rotated log files to keep.
    pub log_file_keep: u32,
    /// Show raw directory listings in the message log (T71).
    pub show_raw_listing: bool,
    /// Prefix message-log lines with the time (T55).
    pub show_timestamps: bool,
    /// Lines the message log keeps per tab (T55).
    pub log_lines: usize,
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self {
            level: 2,
            log_to_file: false,
            log_file: None,
            log_file_max_mib: 10,
            log_file_keep: 3,
            show_raw_listing: false,
            show_timestamps: true,
            log_lines: 5000,
        }
    }
}

/// External editor settings (T63).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EditingSettings {
    /// The default editor.
    pub editor: EditorChoice,
    /// Per-pattern editor overrides, first match wins.
    pub associations: Vec<FileAssociation>,
    /// Watch edited files and offer to upload them when they change.
    pub watch_and_prompt_upload: bool,
}

impl Default for EditingSettings {
    fn default() -> Self {
        Self {
            editor: EditorChoice::Auto,
            associations: Vec::new(),
            watch_and_prompt_upload: true,
        }
    }
}

/// Which editor opens files.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EditorChoice {
    /// `$VISUAL`, then `$EDITOR`, then the platform default.
    #[default]
    Auto,
    /// This command; the file path is appended.
    Command(String),
}

/// An editor for files matching a glob.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileAssociation {
    /// Glob on the file name, e.g. `*.php`.
    pub pattern: String,
    /// The command; the file path is appended.
    pub command: String,
    /// Run in the terminal (suspend the TUI) instead of detached.
    #[serde(default)]
    pub terminal: bool,
}

/// Queue settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct QueueSettings {
    /// What to do when the queue finishes (T45).
    pub on_complete: OnComplete,
    /// How to notify when the queue finishes (T45).
    pub notify: NotifyMethod,
    /// Save the queue on exit and restore it at startup.
    pub persist: bool,
    /// Refresh the remote listing after the queue finishes.
    pub refresh_remote_after: bool,
}

impl Default for QueueSettings {
    fn default() -> Self {
        Self {
            on_complete: OnComplete::None,
            notify: NotifyMethod::Bell,
            persist: true,
            refresh_remote_after: true,
        }
    }
}

/// Action when the queue finishes (D8 drops sound, sleep and shutdown).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnComplete {
    /// Nothing.
    #[default]
    None,
    /// Show a summary message.
    ShowMessage,
    /// Run a shell command.
    RunCommand(String),
    /// Disconnect from the server.
    Disconnect,
    /// Close courier-ftp.
    CloseApp,
}

/// How a finished queue is announced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifyMethod {
    /// No notification.
    None,
    /// The terminal bell.
    #[default]
    Bell,
    /// An OSC 9 / OSC 777 desktop notification.
    Osc,
}

/// Directory listing cache settings (T46).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheSettings {
    /// Cache directory listings.
    pub listing_cache: bool,
    /// Seconds a cached listing stays valid; 0 = until refreshed.
    pub listing_cache_ttl_secs: u64,
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            listing_cache: true,
            listing_cache_ttl_secs: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn empty_object_is_default() {
        let s: Settings = serde_json::from_str("{}").unwrap();
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn partial_override_touches_one_field() {
        let s: Settings = serde_json::from_str(r#"{"connection": {"timeout_secs": 60}}"#).unwrap();
        let mut expected = Settings::default();
        expected.connection.timeout_secs = 60;
        assert_eq!(s, expected);
    }

    #[test]
    fn enums_serialise_readably() {
        let mut s = Settings::default();
        s.proxy.generic = GenericProxy::Socks5(ProxyServer {
            host: "proxy".into(),
            port: 1080,
            user: None,
            password_ref: None,
        });
        s.queue.on_complete = OnComplete::RunCommand("notify-send done".into());
        s.ftp.active_external_ip = ExternalIp::Fixed("203.0.113.7".parse().unwrap());
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["proxy"]["generic"]["type"], "socks5");
        assert_eq!(v["queue"]["on_complete"]["run_command"], "notify-send done");
        assert_eq!(v["ftp"]["active_external_ip"]["fixed"], "203.0.113.7");
        assert_eq!(v["transfers"]["on_exists_upload"], "ask");
        assert_eq!(serde_json::from_value::<Settings>(v).unwrap(), s);
    }

    #[test]
    fn ascii_decision() {
        let ft = FileTypeSettings::default();
        assert!(ft.is_ascii("index.HTML"));
        assert!(ft.is_ascii("script.py"));
        assert!(ft.is_ascii(".htaccess"));
        assert!(ft.is_ascii("Makefile"));
        assert!(!ft.is_ascii("photo.jpg"));
        assert!(!ft.is_ascii(".config.bin"));
        assert!(ft.is_ascii("trailing."));

        let binary = FileTypeSettings {
            default_type: TransferTypeChoice::Binary,
            ..FileTypeSettings::default()
        };
        assert!(!binary.is_ascii("a.txt"));
    }
}
