//! The sections of the settings screen: which rows each one shows
//! ([`build`]) and how their values go back into [`Settings`] ([`apply`]).
//!
//! Every row is keyed by the setting's path (`connection.timeout_secs`), the
//! same name [`Settings::validate`] uses in its warnings, so its problems
//! show under the right field.

use courier_ftp_core::{
    settings::{
        BurstTolerance, ColorScheme, Column, EditorChoice, EmptyDirs, ExistsAction, ExternalIp,
        FileAssociation, FtpProxy, FtpTransferMode, GenericProxy, Layout, NotifyMethod, OnComplete,
        ProxyServer, Settings, SizeFormat, SymbolMode, TransferTypeChoice,
    },
    trust::{KnownHost, TrustedCertificate},
};
use time::OffsetDateTime;

use super::{SecurityInfo, SettingsOpts, Trust, VaultState};
use crate::ui::{
    dialog::{Checkbox, Field, FormValues, ListView, NumberInput, RadioGroup, Select, TextInput},
    file_list::{format_date, format_size},
    site_manager::TextArea,
    trust::format_date as trust_date,
};

/// A section of the settings screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Section {
    Connection,
    Ftp,
    FtpProxy,
    GenericProxy,
    Sftp,
    Tls,
    Transfers,
    FileTypes,
    FileExists,
    Interface,
    FileLists,
    Theme,
    Keybindings,
    Editing,
    Queue,
    Logging,
    Security,
    Sync,
}

/// The sections in the order of the list, with their title and indent.
pub(crate) const SECTIONS: [(Section, &str, u16); 18] = [
    (Section::Connection, "Connection", 0),
    (Section::Ftp, "FTP", 1),
    (Section::FtpProxy, "FTP proxy", 1),
    (Section::GenericProxy, "Generic proxy", 1),
    (Section::Sftp, "SFTP", 1),
    (Section::Tls, "TLS", 1),
    (Section::Transfers, "Transfers", 0),
    (Section::FileTypes, "File types", 1),
    (Section::FileExists, "File exists action", 1),
    (Section::Interface, "Interface", 0),
    (Section::FileLists, "File lists", 1),
    (Section::Theme, "Theme", 1),
    (Section::Keybindings, "Keybindings", 1),
    (Section::Editing, "Editing", 0),
    (Section::Queue, "Queue", 0),
    (Section::Logging, "Logging", 0),
    (Section::Sync, "Sync", 0),
    (Section::Security, "Security", 0),
];

impl Section {
    pub(crate) fn title(self) -> &'static str {
        SECTIONS
            .iter()
            .find(|(s, _, _)| *s == self)
            .map_or("", |(_, t, _)| t)
    }

    pub(crate) fn index(self) -> usize {
        SECTIONS
            .iter()
            .position(|(s, _, _)| *s == self)
            .unwrap_or(0)
    }

    /// Settings that only reach new connections.
    pub(crate) fn network(self) -> bool {
        matches!(
            self,
            Section::Connection | Section::Ftp | Section::FtpProxy | Section::GenericProxy
        )
    }
}

/// Buttons inside a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    ForgetHostKey,
    ForgetCert,
    CertDetails,
    ChangePassword,
    ToggleKeyring,
    LockNow,
    /// The sync panel (T90): account, devices, recovery.
    OpenSync,
}

pub(crate) enum RowKind {
    Field(Box<dyn Field>),
    Button(Command),
    /// Text only; not focusable.
    Note,
}

/// One line (or a few) of a page.
pub(crate) struct Row {
    /// The setting's path; empty for notes and buttons.
    pub(crate) key: &'static str,
    /// The field's label; a note's or a button's text.
    pub(crate) label: String,
    /// One line shown at the bottom while the row has focus.
    pub(crate) help: &'static str,
    pub(crate) kind: RowKind,
}

impl Row {
    pub(crate) fn focusable(&self) -> bool {
        !matches!(self.kind, RowKind::Note)
    }

    pub(crate) fn height(&self) -> u16 {
        match &self.kind {
            RowKind::Field(f) => f.height(),
            _ => 1,
        }
    }
}

/// The rows of one section.
pub(crate) struct Page {
    pub(crate) rows: Vec<Row>,
}

impl Page {
    /// The values of every field, by key.
    pub(crate) fn values(&self) -> FormValues {
        FormValues(
            self.rows
                .iter()
                .filter_map(|r| match &r.kind {
                    RowKind::Field(f) => Some((r.key.to_owned(), f.value())),
                    _ => None,
                })
                .collect(),
        )
    }

    pub(crate) fn position(&self, key: &str) -> Option<usize> {
        self.rows.iter().position(|r| r.key == key)
    }

    pub(crate) fn focusable(&self) -> Vec<usize> {
        (0..self.rows.len())
            .filter(|&i| self.rows[i].focusable())
            .collect()
    }
}

/// What a page shows besides the settings.
pub(crate) struct Ctx<'a> {
    pub(crate) opts: &'a SettingsOpts,
    pub(crate) host_keys: &'a Trust<KnownHost>,
    pub(crate) certs: &'a Trust<TrustedCertificate>,
    pub(crate) security: Option<&'a SecurityInfo>,
    /// A proxy password was typed and not saved yet: (generic, FTP).
    pub(crate) proxy_typed: (bool, bool),
}

// ---- row builders

fn field(key: &'static str, help: &'static str, widget: impl Field + 'static) -> Row {
    Row {
        key,
        label: widget.label().to_owned(),
        help,
        kind: RowKind::Field(Box::new(widget)),
    }
}

fn num(key: &'static str, label: &str, help: &'static str, value: u64, min: i64, max: i64) -> Row {
    let value = i64::try_from(value).unwrap_or(max);
    field(key, help, NumberInput::new(label, value, min, max))
}

fn check(key: &'static str, label: &str, help: &'static str, value: bool) -> Row {
    field(key, help, Checkbox::new(label, value))
}

fn select(key: &'static str, label: &str, help: &'static str, options: &[&str], i: usize) -> Row {
    let options = options.iter().map(|o| (*o).to_owned()).collect();
    field(key, help, Select::new(label, options, i))
}

fn radio(key: &'static str, label: &str, help: &'static str, options: &[&str], i: usize) -> Row {
    let options = options.iter().map(|o| (*o).to_owned()).collect();
    field(key, help, RadioGroup::new(label, options, i))
}

fn text(key: &'static str, label: &str, help: &'static str, value: &str) -> Row {
    field(key, help, TextInput::new(label).with_value(value))
}

fn note(text: impl Into<String>) -> Row {
    Row {
        key: "",
        label: text.into(),
        help: "",
        kind: RowKind::Note,
    }
}

/// A note that is updated as the settings change (the format preview).
fn live_note(key: &'static str, text: String) -> Row {
    Row {
        key,
        label: text,
        help: "",
        kind: RowKind::Note,
    }
}

fn button(command: Command, label: impl Into<String>, help: &'static str) -> Row {
    Row {
        key: "",
        label: label.into(),
        help,
        kind: RowKind::Button(command),
    }
}

/// Index of `value` in `list` (0 when missing).
fn pos<T: PartialEq>(list: &[(T, &str)], value: &T) -> usize {
    list.iter().position(|(v, _)| v == value).unwrap_or(0)
}

fn labels<T>(list: &[(T, &'static str)]) -> Vec<&'static str> {
    list.iter().map(|(_, l)| *l).collect()
}

/// The entry of `list` picked by field `key`, or `current`.
fn pick<T: Clone>(v: &FormValues, key: &str, list: &[(T, &str)], current: T) -> T {
    v.index(key)
        .and_then(|i| list.get(i))
        .map_or(current, |(t, _)| t.clone())
}

/// The number in field `key`, converted, or `current`.
fn number<T: TryFrom<i64>>(v: &FormValues, key: &str, current: T) -> T {
    v.number(key)
        .and_then(|n| T::try_from(n).ok())
        .unwrap_or(current)
}

// ---- choices

const TRANSFER_MODES: [(FtpTransferMode, &str); 2] = [
    (FtpTransferMode::Passive, "Passive"),
    (FtpTransferMode::Active, "Active"),
];
const EXTERNAL_IP: [&str; 3] = [
    "The connection's local address",
    "This address",
    "Ask an IP lookup service (URL)",
];
const KEEPALIVE_COMMANDS: [(&str, &str); 3] = [("NOOP", "NOOP"), ("PWD", "PWD"), ("TYPE", "TYPE")];
const FTP_PROXY_TYPES: [&str; 5] = [
    "None",
    "USER user@host",
    "SITE host",
    "OPEN host",
    "Custom login script",
];
const GENERIC_PROXY_TYPES: [&str; 4] = ["None", "HTTP CONNECT", "SOCKS 4", "SOCKS 5"];
const BURST: [(BurstTolerance, &str); 3] = [
    (BurstTolerance::Normal, "Normal"),
    (BurstTolerance::High, "High"),
    (BurstTolerance::VeryHigh, "Very high"),
];
const EMPTY_DIRS: [(EmptyDirs, &str); 2] = [
    (EmptyDirs::Create, "Create them"),
    (EmptyDirs::Skip, "Leave them out"),
];
const TRANSFER_TYPES: [(TransferTypeChoice, &str); 3] = [
    (TransferTypeChoice::Auto, "Auto"),
    (TransferTypeChoice::Ascii, "ASCII"),
    (TransferTypeChoice::Binary, "Binary"),
];
pub(crate) const EXISTS_ACTIONS: [(ExistsAction, &str); 8] = [
    (ExistsAction::Ask, "Ask"),
    (ExistsAction::Overwrite, "Overwrite"),
    (ExistsAction::OverwriteIfNewer, "Overwrite if newer"),
    (
        ExistsAction::OverwriteIfSizeDiffers,
        "Overwrite if the size differs",
    ),
    (
        ExistsAction::OverwriteIfNewerOrSizeDiffers,
        "Overwrite if newer or the size differs",
    ),
    (ExistsAction::Resume, "Resume"),
    (ExistsAction::Rename, "Rename"),
    (ExistsAction::Skip, "Skip"),
];
const LAYOUTS: [(Layout, &str); 3] = [
    (Layout::Classic, "Classic"),
    (Layout::Explorer, "Explorer"),
    (Layout::Widescreen, "Widescreen"),
];
const SYMBOLS: [(SymbolMode, &str); 3] = [
    (SymbolMode::Auto, "Auto"),
    (SymbolMode::Unicode, "Unicode"),
    (SymbolMode::Ascii, "ASCII"),
];
const SIZE_FORMATS: [(SizeFormat, &str); 3] = [
    (SizeFormat::Bytes, "Bytes"),
    (SizeFormat::Iec, "Binary units (KiB, MiB)"),
    (SizeFormat::Si, "Decimal units (kB, MB)"),
];
const SCHEMES: [(ColorScheme, &str); 3] = [
    (ColorScheme::Default, "Default"),
    (ColorScheme::HighContrast, "High contrast"),
    (ColorScheme::Monochrome, "Monochrome"),
];
const EDITORS: [&str; 2] = ["Automatic ($VISUAL, $EDITOR, system)", "This command"];
const ON_COMPLETE: [&str; 5] = [
    "Nothing",
    "Show a message",
    "Run a command",
    "Disconnect",
    "Close courier-ftp",
];
const NOTIFY: [(NotifyMethod, &str); 3] = [
    (NotifyMethod::None, "None"),
    (NotifyMethod::Bell, "Terminal bell"),
    (NotifyMethod::Osc, "Desktop notification (OSC 9/777)"),
];
const LEVELS: [(u8, &str); 5] = [
    (0, "0 none"),
    (1, "1 warnings"),
    (2, "2 info"),
    (3, "3 verbose (raw listings)"),
    (4, "4 debug"),
];
const COLUMNS: [(Column, &str); 6] = [
    (Column::Name, "name"),
    (Column::Size, "size"),
    (Column::Type, "type"),
    (Column::Modified, "modified"),
    (Column::Permissions, "permissions"),
    (Column::Owner, "owner"),
];

/// The marker after an association's command for "run in the terminal".
const TERMINAL_MARK: &str = "[terminal]";

// ---- building

/// The rows of `section` for `s`.
pub(crate) fn build(section: Section, s: &Settings, ctx: &Ctx<'_>) -> Page {
    let mut rows = match section {
        Section::Connection => connection(s),
        Section::Ftp => ftp(s),
        Section::FtpProxy => ftp_proxy(s, ctx.proxy_typed.1),
        Section::GenericProxy => generic_proxy(s, ctx.proxy_typed.0),
        Section::Sftp => sftp(ctx.host_keys),
        Section::Tls => tls(ctx.certs),
        Section::Transfers => transfers(s),
        Section::FileTypes => file_types(s),
        Section::FileExists => file_exists(s),
        Section::Interface => interface(s),
        Section::FileLists => file_lists(s),
        Section::Theme => theme(s, ctx.opts),
        Section::Keybindings => keybindings(ctx.opts),
        Section::Editing => editing(s),
        Section::Queue => queue(s),
        Section::Logging => logging(s, ctx.opts),
        Section::Security => security(s, ctx),
        Section::Sync => sync(s),
    };
    if section.network() {
        rows.push(note(""));
        rows.push(note("Changes here apply to new connections."));
    }
    Page { rows }
}

fn connection(s: &Settings) -> Vec<Row> {
    let c = &s.connection;
    vec![
        num(
            "connection.timeout_secs",
            "Timeout (seconds)",
            "Seconds without any reply before a connection is considered dead (at least 1).",
            c.timeout_secs,
            1,
            9999,
        ),
        num(
            "connection.retries",
            "Retries",
            "How often a failed connection attempt is retried.",
            u64::from(c.retries),
            0,
            99,
        ),
        num(
            "connection.retry_delay_secs",
            "Retry delay (seconds)",
            "Seconds to wait between retries.",
            c.retry_delay_secs,
            0,
            999,
        ),
        check(
            "connection.keepalive",
            "Send keep-alives",
            "Send keep-alive commands on idle connections so they don't drop.",
            c.keepalive,
        ),
        num(
            "connection.keepalive_interval_secs",
            "Keep-alive interval (seconds)",
            "Seconds of idleness before a keep-alive is sent.",
            c.keepalive_interval_secs,
            1,
            3600,
        ),
        check(
            "connection.prefer_ipv6",
            "Prefer IPv6",
            "Try IPv6 addresses before IPv4 when a host has both.",
            c.prefer_ipv6,
        ),
    ]
}

fn ftp(s: &Settings) -> Vec<Row> {
    let f = &s.ftp;
    let (ip_mode, ip_text) = match &f.active_external_ip {
        ExternalIp::Auto => (0, String::new()),
        ExternalIp::Fixed(ip) => (1, ip.to_string()),
        ExternalIp::FromUrl(url) => (2, url.clone()),
    };
    let range = f
        .active_port_range
        .map(|(lo, hi)| format!("{lo}-{hi}"))
        .unwrap_or_default();
    vec![
        radio(
            "ftp.transfer_mode",
            "Transfer mode",
            "Passive: the client opens data connections (works through most NATs).",
            &labels(&TRANSFER_MODES),
            pos(&TRANSFER_MODES, &f.transfer_mode),
        ),
        check(
            "ftp.fallback_to_active",
            "Fall back to active",
            "Switch to active mode when a passive data connection fails.",
            f.fallback_to_active,
        ),
        select(
            "ftp.active_external_ip.mode",
            "Active mode address",
            "The address announced to the server in active mode.",
            &EXTERNAL_IP,
            ip_mode,
        ),
        text(
            "ftp.active_external_ip",
            "Address or URL",
            "The fixed IP address, or the URL of a service that returns your address as text.",
            &ip_text,
        ),
        text(
            "ftp.active_port_range",
            "Active port range",
            "Local ports for active mode, like 50000-50100; empty lets the system choose.",
            &range,
        ),
        check(
            "ftp.passive_ignore_unroutable_ip",
            "Ignore private PASV address",
            "When PASV returns a private address for a public server, use the server's address.",
            f.passive_ignore_unroutable_ip,
        ),
        check(
            "ftp.use_mlsd",
            "Use MLSD",
            "Use MLSD for listings when the server supports it (else LIST).",
            f.use_mlsd,
        ),
        select(
            "ftp.send_keepalive_command",
            "Keep-alive command",
            "The command sent to keep an idle FTP connection open.",
            &labels(&KEEPALIVE_COMMANDS),
            pos(&KEEPALIVE_COMMANDS, &f.send_keepalive_command.as_str()),
        ),
    ]
}

fn proxy_server_rows(
    prefix: &'static [&'static str; 4],
    server: Option<&ProxyServer>,
    default_port: u16,
    typed: bool,
) -> Vec<Row> {
    let host = server.map(|p| p.host.clone()).unwrap_or_default();
    let port = server.map_or(default_port, |p| p.port);
    let user = server.and_then(|p| p.user.clone()).unwrap_or_default();
    let stored = server.is_some_and(|p| p.password_ref.is_some());
    let placeholder = if typed {
        "(typed, saved with the settings)"
    } else if stored {
        "(stored in the vault; type to replace)"
    } else {
        "(none)"
    };
    vec![
        text(
            prefix[0],
            "Host",
            "The proxy's host name or address.",
            &host,
        ),
        num(
            prefix[1],
            "Port",
            "The proxy's port.",
            u64::from(port),
            1,
            65535,
        ),
        text(
            prefix[2],
            "User",
            "The proxy login, if it needs one.",
            &user,
        ),
        field(
            prefix[3],
            "Saved in the encrypted vault, never in the config file.",
            TextInput::password("Password").with_placeholder(placeholder),
        ),
    ]
}

const FTP_PROXY_KEYS: [&str; 4] = [
    "proxy.ftp_proxy.host",
    "proxy.ftp_proxy.port",
    "proxy.ftp_proxy.user",
    "proxy.ftp_proxy.password",
];
const GENERIC_PROXY_KEYS: [&str; 4] = [
    "proxy.generic.host",
    "proxy.generic.port",
    "proxy.generic.user",
    "proxy.generic.password",
];

fn ftp_proxy_parts(p: &FtpProxy) -> (usize, Option<&ProxyServer>, &str) {
    match p {
        FtpProxy::None => (0, None, ""),
        FtpProxy::UserAtHost(s) => (1, Some(s), ""),
        FtpProxy::Site(s) => (2, Some(s), ""),
        FtpProxy::Open(s) => (3, Some(s), ""),
        FtpProxy::Custom { server, script } => (4, Some(server), script.as_str()),
    }
}

fn generic_proxy_parts(p: &GenericProxy) -> (usize, Option<&ProxyServer>) {
    match p {
        GenericProxy::None => (0, None),
        GenericProxy::Http(s) => (1, Some(s)),
        GenericProxy::Socks4(s) => (2, Some(s)),
        GenericProxy::Socks5(s) => (3, Some(s)),
    }
}

fn ftp_proxy(s: &Settings, typed: bool) -> Vec<Row> {
    let (kind, server, script) = ftp_proxy_parts(&s.proxy.ftp_proxy);
    let mut rows = vec![select(
        "proxy.ftp_proxy",
        "Type",
        "An FTP-level proxy (FTP and FTPS only); can't be combined with a generic proxy.",
        &FTP_PROXY_TYPES,
        kind,
    )];
    rows.extend(proxy_server_rows(&FTP_PROXY_KEYS, server, 21, typed));
    let default_script = "USER %u@%h\nPASS %p";
    rows.push(field(
        "proxy.ftp_proxy.script",
        "Custom script: one command per line; %h host, %u user, %p password, %a account, %s proxy user, %w proxy password.",
        TextArea::new(
            "Custom script",
            if script.is_empty() { default_script } else { script },
            4,
        ),
    ));
    rows
}

fn generic_proxy(s: &Settings, typed: bool) -> Vec<Row> {
    let (kind, server) = generic_proxy_parts(&s.proxy.generic);
    let mut rows = vec![select(
        "proxy.generic",
        "Type",
        "Connect through an HTTP CONNECT or SOCKS proxy (every protocol).",
        &GENERIC_PROXY_TYPES,
        kind,
    )];
    rows.extend(proxy_server_rows(&GENERIC_PROXY_KEYS, server, 1080, typed));
    rows
}

fn trust_state<T>(trust: &Trust<T>, what: &str, rows: &mut Vec<Row>) -> bool {
    match trust {
        Trust::Loading => rows.push(note("Loading…")),
        Trust::NoVault => rows.push(note(format!(
            "Trusted {what} are kept in the vault; this run has none."
        ))),
        Trust::Locked => rows.push(note(format!(
            "Unlock the vault (<Ctrl-x><u>) to see and remove trusted {what}."
        ))),
        Trust::Loaded(list) if list.is_empty() => {
            rows.push(note(format!("No trusted {what} yet.")));
        }
        Trust::Loaded(_) => return true,
    }
    false
}

fn list_rows(items: &[String]) -> u16 {
    u16::try_from(items.len()).unwrap_or(10).clamp(1, 10)
}

fn sftp(host_keys: &Trust<KnownHost>) -> Vec<Row> {
    let mut rows = vec![
        note("Host keys you trusted with “Always trust”. Keys in ~/.ssh/known_hosts"),
        note("are checked too but not listed or changed here."),
        note(""),
    ];
    if trust_state(host_keys, "host keys", &mut rows)
        && let Trust::Loaded(list) = host_keys
    {
        let items: Vec<String> = list
            .iter()
            .map(|k| {
                format!(
                    "{}:{}  {}  {}  {}",
                    k.host,
                    k.port,
                    k.key_type(),
                    trust_date(k.added_at),
                    k.key.sha256()
                )
            })
            .collect();
        let n = list_rows(&items);
        rows.push(field(
            "sftp.host_keys",
            "x or Delete forgets the selected key: the next connection asks again.",
            ListView::new("", items, n),
        ));
        rows.push(button(
            Command::ForgetHostKey,
            "Forget the selected host key",
            "The next connection to that server asks about its key again.",
        ));
    }
    rows
}

fn tls(certs: &Trust<TrustedCertificate>) -> Vec<Row> {
    let mut rows = vec![
        note("Certificates you trusted with “Always trust” (one per server and port)."),
        note("Certificates signed by a known authority are accepted without asking."),
        note(""),
    ];
    if trust_state(certs, "certificates", &mut rows)
        && let Trust::Loaded(list) = certs
    {
        let items: Vec<String> = list
            .iter()
            .map(|c| {
                let fp = c.fingerprint();
                let short: String = fp.chars().take(23).collect();
                format!(
                    "{}:{}  {}  {}  {short}…",
                    c.host,
                    c.port,
                    c.subject,
                    trust_date(c.added_at)
                )
            })
            .collect();
        let n = list_rows(&items);
        rows.push(field(
            "tls.certificates",
            "Enter shows the details; x or Delete forgets the selected certificate.",
            ListView::new("", items, n),
        ));
        rows.push(button(
            Command::CertDetails,
            "Show certificate details",
            "Subject, issuer, validity and fingerprints of the selected certificate.",
        ));
        rows.push(button(
            Command::ForgetCert,
            "Forget the selected certificate",
            "The next connection to that server asks about its certificate again.",
        ));
    }
    rows
}

fn transfers(s: &Settings) -> Vec<Row> {
    let t = &s.transfers;
    vec![
        num(
            "transfers.max_concurrent",
            "Simultaneous transfers",
            "Maximum transfers at the same time (1-32).",
            u64::from(t.max_concurrent),
            1,
            32,
        ),
        num(
            "transfers.max_downloads",
            "Of which downloads",
            "Maximum simultaneous downloads within the above; 0 = no extra limit.",
            u64::from(t.max_downloads),
            0,
            32,
        ),
        num(
            "transfers.max_uploads",
            "Of which uploads",
            "Maximum simultaneous uploads within the above; 0 = no extra limit.",
            u64::from(t.max_uploads),
            0,
            32,
        ),
        check(
            "transfers.speed_limit_enabled",
            "Limit speed",
            "Whether the speed limits below apply (also <Ctrl-x><l>). Applies at once.",
            t.speed_limit_enabled,
        ),
        num(
            "transfers.download_limit_kib",
            "Download limit (KiB/s)",
            "0 = unlimited.",
            t.download_limit_kib,
            0,
            10_000_000,
        ),
        num(
            "transfers.upload_limit_kib",
            "Upload limit (KiB/s)",
            "0 = unlimited.",
            t.upload_limit_kib,
            0,
            10_000_000,
        ),
        select(
            "transfers.burst_tolerance",
            "Burst tolerance",
            "How far above the limit short bursts may go (1, 2 or 5 seconds' worth).",
            &labels(&BURST),
            pos(&BURST, &t.burst_tolerance),
        ),
        check(
            "transfers.preallocate",
            "Preallocate",
            "Reserve the full file size on disk before downloading.",
            t.preallocate,
        ),
        check(
            "transfers.preserve_timestamps",
            "Preserve timestamps",
            "Copy the source's modification time to the target.",
            t.preserve_timestamps,
        ),
        check(
            "transfers.replace_invalid_chars",
            "Replace invalid characters",
            "Replace characters the local filesystem can't store in file names.",
            t.replace_invalid_chars,
        ),
        field(
            "transfers.invalid_char_replacement",
            "The replacement character; it must itself be allowed in local file names.",
            TextInput::new("Replace with")
                .with_value(&t.invalid_char_replacement.to_string())
                .with_max_len(1),
        ),
        select(
            "transfers.empty_dirs",
            "Empty directories",
            "Whether recursive transfers create empty directories on the target.",
            &labels(&EMPTY_DIRS),
            pos(&EMPTY_DIRS, &t.empty_dirs),
        ),
        check(
            "transfers.follow_symlinks",
            "Follow symlinks",
            "Follow symbolic links during recursive operations.",
            t.follow_symlinks,
        ),
    ]
}

fn file_types(s: &Settings) -> Vec<Row> {
    let f = &s.file_types;
    vec![
        radio(
            "file_types.default_type",
            "Transfer type",
            "FTP only. Auto decides per file from the list below.",
            &labels(&TRANSFER_TYPES),
            pos(&TRANSFER_TYPES, &f.default_type),
        ),
        text(
            "file_types.ascii_extensions",
            "ASCII extensions",
            "Extensions transferred as ASCII in Auto mode, separated by spaces (no dots).",
            &f.ascii_extensions.join(" "),
        ),
        check(
            "file_types.dotfiles_ascii",
            "Dotfiles are ASCII",
            "Treat dotfiles like .htaccess as ASCII in Auto mode.",
            f.dotfiles_ascii,
        ),
        check(
            "file_types.no_extension_ascii",
            "No extension is ASCII",
            "Treat files without an extension as ASCII in Auto mode.",
            f.no_extension_ascii,
        ),
    ]
}

fn file_exists(s: &Settings) -> Vec<Row> {
    let t = &s.transfers;
    vec![
        select(
            "transfers.on_exists_download",
            "Downloads",
            "What to do when a downloaded file already exists locally.",
            &labels(&EXISTS_ACTIONS),
            pos(&EXISTS_ACTIONS, &t.on_exists_download),
        ),
        select(
            "transfers.on_exists_upload",
            "Uploads",
            "What to do when an uploaded file already exists on the server.",
            &labels(&EXISTS_ACTIONS),
            pos(&EXISTS_ACTIONS, &t.on_exists_upload),
        ),
    ]
}

fn interface(s: &Settings) -> Vec<Row> {
    let i = &s.interface;
    vec![
        select(
            "interface.layout",
            "Layout",
            "Classic: log on top; Explorer: trees beside the lists; Widescreen: log beside.",
            &labels(&LAYOUTS),
            pos(&LAYOUTS, &i.layout),
        ),
        check(
            "interface.swap_panes",
            "Swap panes",
            "Show the remote pane on the left.",
            i.swap_panes,
        ),
        check(
            "interface.show_tree",
            "Show directory trees",
            "Show the directory trees.",
            i.show_tree,
        ),
        check(
            "interface.show_log",
            "Show message log",
            "Show the message log.",
            i.show_log,
        ),
        check(
            "interface.show_queue",
            "Show queue",
            "Show the transfer queue.",
            i.show_queue,
        ),
        check(
            "interface.show_quickconnect",
            "Show quickconnect bar",
            "Show the quickconnect bar.",
            i.show_quickconnect,
        ),
        select(
            "interface.unicode_symbols",
            "Symbols",
            "Unicode symbols (🔒 ⇅ ⚑) or plain ASCII; Auto uses Unicode in UTF-8 locales.",
            &labels(&SYMBOLS),
            pos(&SYMBOLS, &i.unicode_symbols),
        ),
        check(
            "interface.confirm_delete",
            "Confirm deletion",
            "Ask before deleting.",
            i.confirm_delete,
        ),
        check(
            "interface.show_hidden_local",
            "Show hidden local files",
            "Show hidden files in the local pane at start.",
            i.show_hidden_local,
        ),
        check(
            "interface.force_show_hidden_remote",
            "Ask servers for hidden files",
            "Ask FTP servers to include hidden files (LIST -a).",
            i.force_show_hidden_remote,
        ),
        num(
            "interface.key_sequence_timeout_ms",
            "Key sequence timeout (ms)",
            "Milliseconds allowed between the keys of a sequence like gg.",
            i.key_sequence_timeout_ms,
            100,
            10_000,
        ),
        check(
            "interface.show_splash",
            "Splash screen",
            "Show the splash screen at startup.",
            i.show_splash,
        ),
        check(
            "interface.check_updates",
            "Check for updates",
            "Check for new releases at startup.",
            i.check_updates,
        ),
    ]
}

/// "Preview: 2026-10-10 14:05  1,234,567 bytes = 1.2 MiB" for the File lists
/// page.
pub(crate) fn preview(s: &Settings) -> String {
    let i = &s.interface;
    let now = courier_ftp_core::model::Timestamp::new(
        OffsetDateTime::now_utc(),
        courier_ftp_core::model::Precision::Minute,
    );
    let offset = time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC);
    let date = format_date(&now, &i.date_format, &i.time_format, offset);
    let bytes = 1_234_567;
    format!(
        "Preview: {date}  ·  {}",
        format_size(bytes, i.size_format, i.thousands_separator)
    )
}

fn columns_text(columns: &[Column]) -> String {
    columns
        .iter()
        .map(|c| COLUMNS[pos(&COLUMNS, c)].1)
        .collect::<Vec<_>>()
        .join(" ")
}

fn file_lists(s: &Settings) -> Vec<Row> {
    let i = &s.interface;
    vec![
        select(
            "interface.size_format",
            "Size format",
            "How file sizes are shown.",
            &labels(&SIZE_FORMATS),
            pos(&SIZE_FORMATS, &i.size_format),
        ),
        check(
            "interface.thousands_separator",
            "Thousands separator",
            "Group digits in byte counts (1,234,567).",
            i.thousands_separator,
        ),
        text(
            "interface.date_format",
            "Date format",
            "%Y year, %y short year, %m month, %b month name, %d day.",
            &i.date_format,
        ),
        text(
            "interface.time_format",
            "Time format",
            "%H hour, %M minute, %S second.",
            &i.time_format,
        ),
        live_note("preview", preview(s)),
        check(
            "interface.dirs_first",
            "Directories first",
            "List directories before files.",
            i.dirs_first,
        ),
        check(
            "interface.sort_case_sensitive",
            "Case-sensitive sorting",
            "Sort names case-sensitively.",
            i.sort_case_sensitive,
        ),
        check(
            "interface.natural_sort",
            "Natural sorting",
            "Sort names naturally: file2 before file10.",
            i.natural_sort,
        ),
        text(
            "interface.columns.local",
            "Local columns",
            "Columns in order: name size type modified permissions owner.",
            &columns_text(&i.columns.local),
        ),
        text(
            "interface.columns.remote",
            "Remote columns",
            "Columns in order: name size type modified permissions owner.",
            &columns_text(&i.columns.remote),
        ),
        check(
            "cache.listing_cache",
            "Cache listings",
            "Keep directory listings in memory and show them again without asking the server.",
            s.cache.listing_cache,
        ),
        num(
            "cache.listing_cache_ttl_secs",
            "Cache lifetime (seconds)",
            "Seconds a cached listing stays valid; 0 = until refreshed.",
            s.cache.listing_cache_ttl_secs,
            0,
            1_000_000,
        ),
    ]
}

fn theme(s: &Settings, opts: &SettingsOpts) -> Vec<Row> {
    vec![
        radio(
            "interface.color_scheme",
            "Colour scheme",
            "A built-in colour scheme. Applies at once.",
            &labels(&SCHEMES),
            pos(&SCHEMES, &s.interface.color_scheme),
        ),
        note(""),
        note("Fine-grained styles live in the styles section of"),
        note(format!("{}.", opts.config_file)),
        note("NO_COLOR in the environment always turns colours off."),
    ]
}

fn keybindings(opts: &SettingsOpts) -> Vec<Row> {
    let items: Vec<String> = opts
        .keybindings
        .iter()
        .map(|(mode, key, action)| format!("{mode:<9} {key:<18} {action}"))
        .collect();
    let rows = u16::try_from(items.len()).unwrap_or(16).clamp(1, 16);
    vec![
        field(
            "keybindings",
            "Read-only. Rebind keys in the keybindings section of the config file.",
            ListView::new("", items, rows),
        ),
        note(""),
        note("To change a binding, edit the keybindings section of"),
        note(format!("{} (restart needed).", opts.config_file)),
    ]
}

fn editing(s: &Settings) -> Vec<Row> {
    let e = &s.editing;
    let (mode, command) = match &e.editor {
        EditorChoice::Auto => (0, ""),
        EditorChoice::Command(c) => (1, c.as_str()),
    };
    let associations = e
        .associations
        .iter()
        .map(|a| {
            let mut line = format!("{} = {}", a.pattern, a.command);
            if a.terminal {
                line.push(' ');
                line.push_str(TERMINAL_MARK);
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n");
    vec![
        select(
            "editing.editor",
            "Editor",
            "Which editor opens files.",
            &EDITORS,
            mode,
        ),
        text(
            "editing.editor.command",
            "Editor command",
            "The command; the file path is appended.",
            command,
        ),
        field(
            "editing.associations",
            "One per line: pattern = command; add [terminal] to run it in the terminal.",
            TextArea::new("Associations", &associations, 4),
        ),
        check(
            "editing.watch_and_prompt_upload",
            "Offer upload on change",
            "Watch edited files and offer to upload them when they change.",
            e.watch_and_prompt_upload,
        ),
    ]
}

fn queue(s: &Settings) -> Vec<Row> {
    let q = &s.queue;
    let (mode, command) = match &q.on_complete {
        OnComplete::None => (0, ""),
        OnComplete::ShowMessage => (1, ""),
        OnComplete::RunCommand(c) => (2, c.as_str()),
        OnComplete::Disconnect => (3, ""),
        OnComplete::CloseApp => (4, ""),
    };
    vec![
        select(
            "queue.on_complete",
            "When finished",
            "What to do when the queue finishes.",
            &ON_COMPLETE,
            mode,
        ),
        text(
            "queue.on_complete.command",
            "Command",
            "The shell command for “Run a command”.",
            command,
        ),
        select(
            "queue.notify",
            "Notify",
            "How a finished queue is announced.",
            &labels(&NOTIFY),
            pos(&NOTIFY, &q.notify),
        ),
        check(
            "queue.persist",
            "Keep the queue",
            "Save the queue in the vault and restore it at startup.",
            q.persist,
        ),
        check(
            "queue.refresh_remote_after",
            "Refresh after the queue",
            "Refresh the remote listing after the queue finishes.",
            q.refresh_remote_after,
        ),
        num(
            "queue.max_successful",
            "Successful transfers kept",
            "Most entries kept in the successful-transfers list (0-1000000).",
            u64::try_from(q.max_successful).unwrap_or(u64::MAX),
            0,
            1_000_000,
        ),
    ]
}

fn logging(s: &Settings, opts: &SettingsOpts) -> Vec<Row> {
    let l = &s.logging;
    let file = l
        .log_file
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    vec![
        select(
            "logging.level",
            "Debug level",
            "How much the message log shows. Applies at once.",
            &labels(&LEVELS),
            pos(&LEVELS, &l.level),
        ),
        check(
            "logging.show_timestamps",
            "Timestamps",
            "Prefix message-log lines with the time.",
            l.show_timestamps,
        ),
        check(
            "logging.show_raw_listing",
            "Raw listings",
            "Show raw directory listings in the message log.",
            l.show_raw_listing,
        ),
        num(
            "logging.log_lines",
            "Lines kept",
            "Lines the message log keeps.",
            u64::try_from(l.log_lines).unwrap_or(u64::MAX),
            100,
            1_000_000,
        ),
        check(
            "logging.log_to_file",
            "Log to file",
            "Also write the message log to a file.",
            l.log_to_file,
        ),
        field(
            "logging.log_file",
            "The log file; empty for session.log in the data directory.",
            TextInput::new("Log file")
                .with_value(&file)
                .with_placeholder(opts.default_log_file.clone()),
        ),
        num(
            "logging.log_file_max_mib",
            "Rotate at (MiB)",
            "Start a new log file at this size.",
            l.log_file_max_mib,
            1,
            10_000,
        ),
        num(
            "logging.log_file_keep",
            "Files kept",
            "Rotated log files to keep.",
            u64::from(l.log_file_keep),
            0,
            1000,
        ),
    ]
}

fn security(s: &Settings, ctx: &Ctx<'_>) -> Vec<Row> {
    let v = &s.vault;
    let mut rows = Vec::new();
    match ctx.security {
        None => rows.push(note("Vault: …")),
        Some(info) => match info.state {
            VaultState::None => rows.push(note("Vault: none in this run.")),
            VaultState::Unavailable => {
                rows.push(note("Vault: unavailable (see the vault screen)."));
            }
            VaultState::Locked => {
                rows.push(note("Vault: locked. Unlock it (<Ctrl-x><u>) to change"));
                rows.push(note("the master password or keyring unlock."));
            }
            VaultState::Unlocked => {
                rows.push(note("Vault: unlocked."));
                rows.push(button(
                    Command::ChangePassword,
                    "Change master password…",
                    "Re-encrypts the vault key under a new master password.",
                ));
                let mark = if info.keyring_enabled { "[x]" } else { "[ ]" };
                rows.push(button(
                    Command::ToggleKeyring,
                    format!("{mark} Unlock with the system keyring on this device"),
                    "Enter switches it. The keyring keeps a key that unlocks the vault without the password.",
                ));
                rows.push(button(
                    Command::LockNow,
                    "Lock now",
                    "Lock the vault: keys leave memory until you unlock it again.",
                ));
            }
        },
    }
    rows.push(note(""));
    rows.extend([
        num(
            "vault.auto_lock_minutes",
            "Auto-lock (minutes)",
            "Lock the vault after this many minutes without input; 0 = never (0-1440).",
            u64::from(v.auto_lock_minutes),
            0,
            1440,
        ),
        check(
            "vault.lock_on_suspend",
            "Lock on suspend",
            "Lock when a system suspend/resume is detected.",
            v.lock_on_suspend,
        ),
        check(
            "vault.lock_disconnects",
            "Locking disconnects",
            "Close connections when the vault locks.",
            v.lock_disconnects,
        ),
        check(
            "vault.store_passwords",
            "Store passwords",
            "Save site passwords and passphrases in the vault. Off erases the stored ones.",
            v.store_passwords,
        ),
    ]);
    if let Some(cost) = ctx.security.and_then(|i| i.cost) {
        rows.push(note(""));
        rows.push(note(format!(
            "Key derivation: Argon2id, {} MiB, {} passes, {} lane(s).",
            cost.m_kib / 1024,
            cost.t,
            cost.p
        )));
    }
    rows
}

// ---- applying

/// The problems found, by key.
pub(crate) type Problems = Vec<(&'static str, String)>;

/// Write the values of `section`'s page into `s`. Values that don't parse
/// leave the setting unchanged and are reported.
fn sync(s: &Settings) -> Vec<Row> {
    let y = &s.sync;
    let mut rows = Vec::new();
    if cfg!(feature = "sync") {
        rows.push(note(
            "Your vault syncs end-to-end encrypted through a courier-ftp server.",
        ));
        rows.push(button(
            Command::OpenSync,
            "Account, devices and recovery…",
            "Create or log in to a sync account, manage devices, two-factor, password, log out.",
        ));
    } else {
        rows.push(note("This build of courier-ftp has no sync support."));
    }
    rows.push(note(""));
    rows.extend([
        num(
            "sync.push_debounce_ms",
            "Upload delay (ms)",
            "Upload this long after the last local change (0-60000). Applies from the next unlock.",
            u64::from(y.push_debounce_ms),
            0,
            60_000,
        ),
        num(
            "sync.poll_fallback_secs",
            "Check every (s)",
            "Pull changes this often even without live notifications (30-86400). Applies from the next unlock.",
            u64::from(y.poll_fallback_secs),
            30,
            86_400,
        ),
        check(
            "sync.history",
            "Sync the connection history",
            "Also sync the quickconnect history between your devices.",
            y.history,
        ),
    ]);
    rows
}

pub(crate) fn apply(section: Section, v: &FormValues, s: &mut Settings) -> Problems {
    let mut problems = Problems::new();
    match section {
        Section::Connection => {
            let c = &mut s.connection;
            c.timeout_secs = number(v, "connection.timeout_secs", c.timeout_secs);
            c.retries = number(v, "connection.retries", c.retries);
            c.retry_delay_secs = number(v, "connection.retry_delay_secs", c.retry_delay_secs);
            c.keepalive = v.bool("connection.keepalive");
            c.keepalive_interval_secs = number(
                v,
                "connection.keepalive_interval_secs",
                c.keepalive_interval_secs,
            );
            c.prefer_ipv6 = v.bool("connection.prefer_ipv6");
        }
        Section::Ftp => apply_ftp(v, s, &mut problems),
        Section::FtpProxy => {
            let kind = v.index("proxy.ftp_proxy").unwrap_or(0);
            let (_, old, _) = ftp_proxy_parts(&s.proxy.ftp_proxy);
            let server = proxy_server(v, &FTP_PROXY_KEYS, old, kind, &mut problems);
            let script = v.text("proxy.ftp_proxy.script");
            s.proxy.ftp_proxy = match (kind, server) {
                (1, Some(p)) => FtpProxy::UserAtHost(p),
                (2, Some(p)) => FtpProxy::Site(p),
                (3, Some(p)) => FtpProxy::Open(p),
                (4, Some(p)) => {
                    if script.trim().is_empty() {
                        problems
                            .push(("proxy.ftp_proxy.script", "enter the login commands".into()));
                    }
                    FtpProxy::Custom { server: p, script }
                }
                (0, _) => FtpProxy::None,
                _ => s.proxy.ftp_proxy.clone(),
            };
        }
        Section::GenericProxy => {
            let kind = v.index("proxy.generic").unwrap_or(0);
            let (_, old) = generic_proxy_parts(&s.proxy.generic);
            let server = proxy_server(v, &GENERIC_PROXY_KEYS, old, kind, &mut problems);
            s.proxy.generic = match (kind, server) {
                (1, Some(p)) => GenericProxy::Http(p),
                (2, Some(p)) => GenericProxy::Socks4(p),
                (3, Some(p)) => GenericProxy::Socks5(p),
                (0, _) => GenericProxy::None,
                _ => s.proxy.generic.clone(),
            };
        }
        Section::Sftp | Section::Tls | Section::Keybindings => {}
        Section::Transfers => apply_transfers(v, s, &mut problems),
        Section::FileTypes => {
            let f = &mut s.file_types;
            f.default_type = pick(
                v,
                "file_types.default_type",
                &TRANSFER_TYPES,
                f.default_type,
            );
            f.ascii_extensions = v
                .text("file_types.ascii_extensions")
                .split([' ', ',', ';'])
                .map(|e| e.trim().trim_start_matches('.'))
                .filter(|e| !e.is_empty())
                .map(str::to_owned)
                .collect();
            f.dotfiles_ascii = v.bool("file_types.dotfiles_ascii");
            f.no_extension_ascii = v.bool("file_types.no_extension_ascii");
        }
        Section::FileExists => {
            let t = &mut s.transfers;
            t.on_exists_download = pick(
                v,
                "transfers.on_exists_download",
                &EXISTS_ACTIONS,
                t.on_exists_download,
            );
            t.on_exists_upload = pick(
                v,
                "transfers.on_exists_upload",
                &EXISTS_ACTIONS,
                t.on_exists_upload,
            );
        }
        Section::Interface => {
            let i = &mut s.interface;
            i.layout = pick(v, "interface.layout", &LAYOUTS, i.layout);
            i.swap_panes = v.bool("interface.swap_panes");
            i.show_tree = v.bool("interface.show_tree");
            i.show_log = v.bool("interface.show_log");
            i.show_queue = v.bool("interface.show_queue");
            i.show_quickconnect = v.bool("interface.show_quickconnect");
            i.unicode_symbols = pick(v, "interface.unicode_symbols", &SYMBOLS, i.unicode_symbols);
            i.confirm_delete = v.bool("interface.confirm_delete");
            i.show_hidden_local = v.bool("interface.show_hidden_local");
            i.force_show_hidden_remote = v.bool("interface.force_show_hidden_remote");
            i.key_sequence_timeout_ms = number(
                v,
                "interface.key_sequence_timeout_ms",
                i.key_sequence_timeout_ms,
            );
            i.show_splash = v.bool("interface.show_splash");
            i.check_updates = v.bool("interface.check_updates");
        }
        Section::FileLists => {
            let i = &mut s.interface;
            i.size_format = pick(v, "interface.size_format", &SIZE_FORMATS, i.size_format);
            i.thousands_separator = v.bool("interface.thousands_separator");
            for (key, slot) in [
                ("interface.date_format", &mut i.date_format),
                ("interface.time_format", &mut i.time_format),
            ] {
                let text = v.text(key);
                if text.trim().is_empty() {
                    problems.push((key, "enter a format".into()));
                } else {
                    *slot = text;
                }
            }
            i.dirs_first = v.bool("interface.dirs_first");
            i.sort_case_sensitive = v.bool("interface.sort_case_sensitive");
            i.natural_sort = v.bool("interface.natural_sort");
            for (key, slot) in [
                ("interface.columns.local", &mut i.columns.local),
                ("interface.columns.remote", &mut i.columns.remote),
            ] {
                match parse_columns(&v.text(key)) {
                    Ok(columns) => *slot = columns,
                    Err(e) => problems.push((key, e)),
                }
            }
            s.cache.listing_cache = v.bool("cache.listing_cache");
            s.cache.listing_cache_ttl_secs = number(
                v,
                "cache.listing_cache_ttl_secs",
                s.cache.listing_cache_ttl_secs,
            );
        }
        Section::Theme => {
            let i = &mut s.interface;
            i.color_scheme = pick(v, "interface.color_scheme", &SCHEMES, i.color_scheme);
        }
        Section::Editing => {
            let e = &mut s.editing;
            let command = v.text("editing.editor.command").trim().to_owned();
            match v.index("editing.editor") {
                Some(1) if command.is_empty() => {
                    problems.push(("editing.editor.command", "enter the editor command".into()));
                }
                Some(1) => e.editor = EditorChoice::Command(command),
                _ => e.editor = EditorChoice::Auto,
            }
            match parse_associations(&v.text("editing.associations")) {
                Ok(list) => e.associations = list,
                Err(err) => problems.push(("editing.associations", err)),
            }
            e.watch_and_prompt_upload = v.bool("editing.watch_and_prompt_upload");
        }
        Section::Queue => {
            let q = &mut s.queue;
            let command = v.text("queue.on_complete.command").trim().to_owned();
            q.on_complete = match v.index("queue.on_complete") {
                Some(1) => OnComplete::ShowMessage,
                Some(2) if command.is_empty() => {
                    problems.push(("queue.on_complete.command", "enter the command".into()));
                    q.on_complete.clone()
                }
                Some(2) => OnComplete::RunCommand(command),
                Some(3) => OnComplete::Disconnect,
                Some(4) => OnComplete::CloseApp,
                _ => OnComplete::None,
            };
            q.notify = pick(v, "queue.notify", &NOTIFY, q.notify);
            q.persist = v.bool("queue.persist");
            q.refresh_remote_after = v.bool("queue.refresh_remote_after");
            q.max_successful = number(v, "queue.max_successful", q.max_successful);
        }
        Section::Logging => {
            let l = &mut s.logging;
            l.level = pick(v, "logging.level", &LEVELS, l.level);
            l.show_timestamps = v.bool("logging.show_timestamps");
            l.show_raw_listing = v.bool("logging.show_raw_listing");
            l.log_lines = number(v, "logging.log_lines", l.log_lines);
            l.log_to_file = v.bool("logging.log_to_file");
            let file = v.text("logging.log_file").trim().to_owned();
            l.log_file = (!file.is_empty()).then(|| std::path::PathBuf::from(file));
            l.log_file_max_mib = number(v, "logging.log_file_max_mib", l.log_file_max_mib);
            l.log_file_keep = number(v, "logging.log_file_keep", l.log_file_keep);
        }
        Section::Security => {
            let s = &mut s.vault;
            s.auto_lock_minutes = number(v, "vault.auto_lock_minutes", s.auto_lock_minutes);
            s.lock_on_suspend = v.bool("vault.lock_on_suspend");
            s.lock_disconnects = v.bool("vault.lock_disconnects");
            s.store_passwords = v.bool("vault.store_passwords");
        }
        Section::Sync => {
            let y = &mut s.sync;
            y.push_debounce_ms = number(v, "sync.push_debounce_ms", y.push_debounce_ms);
            y.poll_fallback_secs = number(v, "sync.poll_fallback_secs", y.poll_fallback_secs);
            y.history = v.bool("sync.history");
        }
    }
    problems
}

fn apply_ftp(v: &FormValues, s: &mut Settings, problems: &mut Problems) {
    let f = &mut s.ftp;
    f.transfer_mode = pick(v, "ftp.transfer_mode", &TRANSFER_MODES, f.transfer_mode);
    f.fallback_to_active = v.bool("ftp.fallback_to_active");
    let ip_text = v.text("ftp.active_external_ip").trim().to_owned();
    match v.index("ftp.active_external_ip.mode") {
        Some(1) => match ip_text.parse() {
            Ok(ip) => f.active_external_ip = ExternalIp::Fixed(ip),
            Err(_) => problems.push(("ftp.active_external_ip", "enter an IP address".into())),
        },
        Some(2) if ip_text.starts_with("http://") || ip_text.starts_with("https://") => {
            f.active_external_ip = ExternalIp::FromUrl(ip_text);
        }
        Some(2) => problems.push((
            "ftp.active_external_ip",
            "enter an http:// or https:// URL".into(),
        )),
        _ => f.active_external_ip = ExternalIp::Auto,
    }
    let range = v.text("ftp.active_port_range");
    let range = range.trim();
    if range.is_empty() {
        f.active_port_range = None;
    } else {
        let parsed = range
            .split_once('-')
            .and_then(|(lo, hi)| Some((lo.trim().parse().ok()?, hi.trim().parse().ok()?)));
        match parsed {
            Some(r) => f.active_port_range = Some(r),
            None => problems.push((
                "ftp.active_port_range",
                "use start-end, like 50000-50100, or leave it empty".into(),
            )),
        }
    }
    f.passive_ignore_unroutable_ip = v.bool("ftp.passive_ignore_unroutable_ip");
    f.use_mlsd = v.bool("ftp.use_mlsd");
    f.send_keepalive_command =
        pick(v, "ftp.send_keepalive_command", &KEEPALIVE_COMMANDS, "NOOP").to_owned();
}

fn apply_transfers(v: &FormValues, s: &mut Settings, problems: &mut Problems) {
    let t = &mut s.transfers;
    t.max_concurrent = number(v, "transfers.max_concurrent", t.max_concurrent);
    t.max_downloads = number(v, "transfers.max_downloads", t.max_downloads);
    t.max_uploads = number(v, "transfers.max_uploads", t.max_uploads);
    t.speed_limit_enabled = v.bool("transfers.speed_limit_enabled");
    t.download_limit_kib = number(v, "transfers.download_limit_kib", t.download_limit_kib);
    t.upload_limit_kib = number(v, "transfers.upload_limit_kib", t.upload_limit_kib);
    t.burst_tolerance = pick(v, "transfers.burst_tolerance", &BURST, t.burst_tolerance);
    t.preallocate = v.bool("transfers.preallocate");
    t.preserve_timestamps = v.bool("transfers.preserve_timestamps");
    t.replace_invalid_chars = v.bool("transfers.replace_invalid_chars");
    match v.text("transfers.invalid_char_replacement").chars().next() {
        Some(c) => t.invalid_char_replacement = c,
        None => problems.push((
            "transfers.invalid_char_replacement",
            "enter one character".into(),
        )),
    }
    t.empty_dirs = pick(v, "transfers.empty_dirs", &EMPTY_DIRS, t.empty_dirs);
    t.follow_symlinks = v.bool("transfers.follow_symlinks");
}

/// The proxy server from the host/port/user fields (`None` for type 0 or
/// a missing host). The vault reference is kept from `old`.
fn proxy_server(
    v: &FormValues,
    keys: &[&'static str; 4],
    old: Option<&ProxyServer>,
    kind: usize,
    problems: &mut Problems,
) -> Option<ProxyServer> {
    if kind == 0 {
        return None;
    }
    let host = v.text(keys[0]).trim().to_owned();
    if host.is_empty() {
        problems.push((keys[0], "enter the proxy host".into()));
        return None;
    }
    let user = v.text(keys[2]).trim().to_owned();
    Some(ProxyServer {
        host,
        port: number(v, keys[1], old.map_or(1080, |p| p.port)),
        user: (!user.is_empty()).then_some(user),
        password_ref: old.and_then(|p| p.password_ref.clone()),
    })
}

fn parse_columns(text: &str) -> Result<Vec<Column>, String> {
    let mut out = Vec::new();
    for word in text.split([' ', ',']).filter(|w| !w.is_empty()) {
        let Some((c, _)) = COLUMNS.iter().find(|(_, n)| n.eq_ignore_ascii_case(word)) else {
            return Err(format!("unknown column {word}"));
        };
        if !out.contains(c) {
            out.push(*c);
        }
    }
    if !out.contains(&Column::Name) {
        return Err("name must be one of the columns".into());
    }
    Ok(out)
}

fn parse_associations(text: &str) -> Result<Vec<FileAssociation>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((pattern, command)) = line.split_once('=') else {
            return Err(format!("line {}: use pattern = command", n + 1));
        };
        let mut command = command.trim();
        let terminal = command.ends_with(TERMINAL_MARK);
        if terminal {
            command = command.trim_end_matches(TERMINAL_MARK).trim_end();
        }
        let pattern = pattern.trim();
        if pattern.is_empty() || command.is_empty() {
            return Err(format!("line {}: use pattern = command", n + 1));
        }
        out.push(FileAssociation {
            pattern: pattern.to_owned(),
            command: command.to_owned(),
            terminal,
        });
    }
    Ok(out)
}

/// The value of a password field, if one was typed.
pub(crate) fn typed_secret(v: &FormValues, key: &str) -> Option<secrecy::SecretString> {
    use secrecy::ExposeSecret;
    v.secret(key).filter(|s| !s.expose_secret().is_empty())
}

pub(crate) const GENERIC_PASSWORD: &str = "proxy.generic.password";
pub(crate) const FTP_PASSWORD: &str = "proxy.ftp_proxy.password";
