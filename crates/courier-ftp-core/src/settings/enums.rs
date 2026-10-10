//! Enums used by the settings model (T05).
//!
//! Every enum is `#[serde(rename_all = "snake_case")]` (one convention for all settings
//! enums) and has its default variant marked with `#[default]`. They live here so the
//! settings model depends on no later task; the tasks named in each doc comment use them.

use std::borrow::Cow;
use std::net::IpAddr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};

/// How much the message log shows (T04, T55, T71). Serialised as the integer 0–4.
///
/// FileZilla: Settings → Debug → "Debug information in message log".
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(into = "u8", try_from = "u8")]
pub enum DebugLevel {
    /// 0: no debug information.
    None = 0,
    /// 1: warnings.
    Warning = 1,
    /// 2: informational messages (default).
    #[default]
    Info = 2,
    /// 3: verbose.
    Verbose = 3,
    /// 4: everything, including raw protocol details.
    Debug = 4,
}

impl From<DebugLevel> for u8 {
    fn from(level: DebugLevel) -> Self {
        level as u8
    }
}

impl TryFrom<u8> for DebugLevel {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::None,
            1 => Self::Warning,
            2 => Self::Info,
            3 => Self::Verbose,
            4 => Self::Debug,
            other => return Err(format!("debug level {other} is not 0-4")),
        })
    }
}

impl JsonSchema for DebugLevel {
    fn schema_name() -> Cow<'static, str> {
        "DebugLevel".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "0 = none, 1 = warning, 2 = info, 3 = verbose, 4 = debug.",
            "type": "integer",
            "minimum": 0,
            "maximum": 4
        })
    }
}

/// What to do when a transfer target already exists (T04, T40, T42).
///
/// FileZilla: Settings → Transfers → File exists action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExistsAction {
    /// Ask every time.
    #[default]
    Ask,
    /// Overwrite.
    Overwrite,
    /// Overwrite if the source is newer.
    OverwriteIfNewer,
    /// Overwrite if the size differs.
    OverwriteIfSizeDiffers,
    /// Overwrite if the source is newer or the size differs.
    OverwriteIfNewerOrSizeDiffers,
    /// Resume the transfer.
    Resume,
    /// Rename the target.
    Rename,
    /// Skip the file.
    Skip,
}

/// The transfer type the user chose; `Auto` is resolved per file by
/// [`decide_transfer_type`](super::decide_transfer_type) (T11, T40, T57).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransferTypeChoice {
    /// Decide from the file name (`file_types`).
    #[default]
    Auto,
    /// Always ASCII.
    Ascii,
    /// Always binary.
    Binary,
}

/// FTP data connection mode (T11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FtpTransferMode {
    /// PASV / EPSV.
    #[default]
    Passive,
    /// PORT / EPRT.
    Active,
}

/// The external IP address sent in active mode (T11, T72). Not `Copy` (holds a URL).
///
/// JSON: `"auto"`, `{"fixed":"203.0.113.5"}` or `{"from_url":"http://…"}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActiveExternalIp {
    /// Ask the operating system for the local address.
    #[default]
    Auto,
    /// Use this address.
    Fixed(IpAddr),
    /// Fetch the address from this `http://` URL (no default service).
    FromUrl(String),
}

/// The command sent as an FTP keep-alive (T10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeepaliveCommand {
    /// Always `NOOP`.
    #[default]
    Noop,
    /// `NOOP`, `PWD` or `TYPE` picked at random per keep-alive (FileZilla behaviour).
    Random,
}

/// Generic proxy type (T07).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProxyKind {
    /// No proxy.
    #[default]
    None,
    /// HTTP `CONNECT`.
    Http,
    /// SOCKS 4.
    Socks4,
    /// SOCKS 5.
    Socks5,
}

/// FTP proxy type (T15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FtpProxyKind {
    /// No FTP proxy.
    #[default]
    None,
    /// `USER user@host`.
    UserAtHost,
    /// `SITE host`.
    Site,
    /// `OPEN host`.
    Open,
    /// The user's login script (`proxy.ftp_proxy.custom_script`).
    Custom,
}

/// How far the speed limiter may burst above the limit (T44).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BurstTolerance {
    /// 1 second of data.
    #[default]
    Normal,
    /// 2 seconds of data.
    High,
    /// 5 seconds of data.
    VeryHigh,
}

/// Empty directories in recursive transfers (T43).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EmptyDirs {
    /// Create them on the target.
    #[default]
    Create,
    /// Skip them.
    Skip,
}

/// Main window layout (T50).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// FileZilla's classic layout.
    #[default]
    Classic,
    /// Explorer-like layout.
    Explorer,
    /// Wide screen layout.
    Widescreen,
}

/// How file sizes are shown (T53, T56, T57).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SizeFormat {
    /// Exact bytes.
    Bytes,
    /// Binary units (KiB, MiB).
    #[default]
    Iec,
    /// Decimal units (kB, MB).
    Si,
}

/// A file list column (T53), in FileZilla's order.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Column {
    /// File name.
    Name,
    /// File size.
    Size,
    /// File type.
    Type,
    /// Last modified.
    Modified,
    /// Permissions.
    Permissions,
    /// Owner and group.
    OwnerGroup,
}

impl Column {
    /// Every column, in FileZilla's order.
    pub const ALL: [Column; 6] = [
        Column::Name,
        Column::Size,
        Column::Type,
        Column::Modified,
        Column::Permissions,
        Column::OwnerGroup,
    ];
}

/// What Enter does on a file (T51, T53).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnterOnFile {
    /// Queue a transfer.
    #[default]
    Transfer,
    /// View the file.
    View,
    /// Edit the file.
    Edit,
    /// Nothing.
    None,
}

/// Where a connect request opens (T58, T59, T61).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectTarget {
    /// Ask each time.
    #[default]
    Ask,
    /// Open a new tab.
    NewTab,
    /// Replace the current connection.
    Replace,
}

/// Whether Unicode symbols are drawn (T50, T57).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnicodeSymbols {
    /// Detect from the terminal and locale.
    #[default]
    Auto,
    /// Always.
    Always,
    /// Never (ASCII only).
    Never,
}

/// Colour theme (T50, T68).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    /// The default colours.
    #[default]
    Default,
    /// High contrast.
    HighContrast,
    /// No colours (forced by `NO_COLOR`).
    Monochrome,
}

/// Action when the queue has finished (T45). Sound, sleep and shutdown are dropped (D8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OnComplete {
    /// Do nothing.
    #[default]
    None,
    /// Show a message.
    ShowMessage,
    /// Run `queue.on_complete_command`.
    RunCommand,
    /// Disconnect.
    Disconnect,
    /// Close courier-ftp.
    CloseApp,
}

/// How the user is notified when the queue has finished (T45).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotifyMethod {
    /// No notification.
    None,
    /// Terminal bell.
    #[default]
    Bell,
    /// OSC 9 / 777 desktop notification (some terminals print the sequence).
    Osc,
}

/// Argon2id cost preset for the vault (T30, T60). Parameters are owned by T30
/// (`Argon2Cost::from_preset`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Argon2Preset {
    /// m = 64 MiB, t = 3, p = 1.
    Light,
    /// m = 256 MiB, t = 3, p = 1.
    #[default]
    Standard,
    /// m = 1 GiB, t = 4, p = 1.
    Strong,
}
