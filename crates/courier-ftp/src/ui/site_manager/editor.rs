//! The site editor on the right of the Site Manager: one site's settings
//! in FileZilla's tabs, with fields shown or hidden by protocol and logon
//! type, inline validation and dirty tracking.
//!
//! Every widget is built once from the site; after each key the focused
//! widget's value is written back into the edited [`Site`], so the dirty
//! marker is a plain comparison with the stored one.

use courier_ftp_core::{
    model::{
        Charset, FtpEncryption, LocalPath, Protocol, RemotePath,
        item::{LogonKind, ServerType, SiteColor, SiteTransferMode},
    },
    sites::{
        MAX_TIMEZONE_OFFSET_MINUTES, Severity, Site, SiteField, SiteIssue, SiteKey, SiteLogon,
        logon_kinds,
    },
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use encoding_rs::Encoding;
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use secrecy::{ExposeSecret, SecretString};

use crate::ui::{
    dialog::{
        Checkbox, Field, FieldOutcome, FieldValue, LocalPathCompleter, NumberInput, PathInput,
        RadioGroup, Select, TextInput,
    },
    theme::Theme,
};

/// The editor's tabs.
pub(crate) const TABS: [&str; 5] = ["General", "Advanced", "Transfer", "Charset", "Bookmarks"];

const ENCRYPTIONS: [FtpEncryption; 4] = [
    FtpEncryption::ExplicitIfAvailable,
    FtpEncryption::RequireExplicit,
    FtpEncryption::RequireImplicit,
    FtpEncryption::PlainOnly,
];

const COLORS: [SiteColor; 7] = [
    SiteColor::None,
    SiteColor::Red,
    SiteColor::Green,
    SiteColor::Blue,
    SiteColor::Yellow,
    SiteColor::Cyan,
    SiteColor::Magenta,
];

const SERVER_TYPES: [ServerType; 7] = [
    ServerType::Auto,
    ServerType::Unix,
    ServerType::Dos,
    ServerType::Vms,
    ServerType::Mvs,
    ServerType::NetWare,
    ServerType::As400,
];

const TRANSFER_MODES: [SiteTransferMode; 3] = [
    SiteTransferMode::Default,
    SiteTransferMode::Active,
    SiteTransferMode::Passive,
];

/// The fixed encodings the Charset tab offers (`encoding_rs`, WHATWG names).
fn encodings() -> Vec<&'static Encoding> {
    vec![
        encoding_rs::WINDOWS_1252,
        encoding_rs::WINDOWS_1250,
        encoding_rs::WINDOWS_1251,
        encoding_rs::WINDOWS_1253,
        encoding_rs::WINDOWS_1254,
        encoding_rs::WINDOWS_1255,
        encoding_rs::WINDOWS_1256,
        encoding_rs::WINDOWS_1257,
        encoding_rs::WINDOWS_1258,
        encoding_rs::WINDOWS_874,
        encoding_rs::ISO_8859_2,
        encoding_rs::ISO_8859_3,
        encoding_rs::ISO_8859_4,
        encoding_rs::ISO_8859_5,
        encoding_rs::ISO_8859_6,
        encoding_rs::ISO_8859_7,
        encoding_rs::ISO_8859_8,
        encoding_rs::ISO_8859_10,
        encoding_rs::ISO_8859_13,
        encoding_rs::ISO_8859_14,
        encoding_rs::ISO_8859_15,
        encoding_rs::ISO_8859_16,
        encoding_rs::KOI8_R,
        encoding_rs::KOI8_U,
        encoding_rs::IBM866,
        encoding_rs::MACINTOSH,
        encoding_rs::X_MAC_CYRILLIC,
        encoding_rs::SHIFT_JIS,
        encoding_rs::EUC_JP,
        encoding_rs::ISO_2022_JP,
        encoding_rs::EUC_KR,
        encoding_rs::GBK,
        encoding_rs::GB18030,
        encoding_rs::BIG5,
    ]
}

fn color_name(c: SiteColor) -> &'static str {
    match c {
        SiteColor::None => "None",
        SiteColor::Red => "Red",
        SiteColor::Green => "Green",
        SiteColor::Blue => "Blue",
        SiteColor::Yellow => "Yellow",
        SiteColor::Cyan => "Cyan",
        SiteColor::Magenta => "Magenta",
    }
}

/// The terminal colour of a site colour (tree dot).
pub(crate) fn color_style(c: SiteColor) -> Style {
    use ratatui::style::Color;
    let fg = match c {
        SiteColor::None => return Style::new(),
        SiteColor::Red => Color::Red,
        SiteColor::Green => Color::Green,
        SiteColor::Blue => Color::Blue,
        SiteColor::Yellow => Color::Yellow,
        SiteColor::Cyan => Color::Cyan,
        SiteColor::Magenta => Color::Magenta,
    };
    Style::new().fg(fg)
}

fn encryption_name(e: FtpEncryption) -> &'static str {
    match e {
        FtpEncryption::ExplicitIfAvailable => "Use explicit FTP over TLS if available",
        FtpEncryption::RequireExplicit => "Require explicit FTP over TLS",
        FtpEncryption::RequireImplicit => "Require implicit FTP over TLS",
        FtpEncryption::PlainOnly => "Only use plain FTP (insecure)",
    }
}

fn logon_name(k: LogonKind) -> &'static str {
    match k {
        LogonKind::Anonymous => "Anonymous",
        LogonKind::Normal => "Normal",
        LogonKind::AskForPassword => "Ask for password",
        LogonKind::Interactive => "Interactive",
        LogonKind::KeyFile => "Key file",
        LogonKind::Account => "Account",
        LogonKind::Agent => "SSH agent",
    }
}

fn server_type_name(t: ServerType) -> &'static str {
    match t {
        ServerType::Auto => "Default (autodetect)",
        ServerType::Unix => "Unix",
        ServerType::Dos => "DOS",
        ServerType::Vms => "VMS",
        ServerType::Mvs => "MVS, OS/390, z/OS",
        ServerType::NetWare => "NetWare",
        ServerType::As400 => "AS/400",
    }
}

fn transfer_mode_name(m: SiteTransferMode) -> &'static str {
    match m {
        SiteTransferMode::Default => "Default",
        SiteTransferMode::Active => "Active",
        SiteTransferMode::Passive => "Passive",
    }
}

fn position<T: PartialEq>(list: &[T], value: &T) -> usize {
    list.iter().position(|v| v == value).unwrap_or(0)
}

/// Every field of the editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FieldId {
    Protocol,
    Encryption,
    Host,
    Port,
    Logon,
    User,
    Password,
    Account,
    KeyFile,
    TryAgent,
    Color,
    Comments,
    ServerType,
    BypassProxy,
    LocalDir,
    RemoteDir,
    SyncBrowsing,
    Compare,
    TzHours,
    TzMinutes,
    TransferMode,
    LimitConnections,
    MaxConnections,
    CharsetMode,
    CustomCharset,
}

/// The fields on `tab` for `site`, in order: the visibility rules (T59 §2).
/// `Password` is listed even when passwords aren't stored (it shows why).
pub(crate) fn visible_fields(site: &Site, tab: usize) -> Vec<FieldId> {
    use FieldId as F;
    let ftp = site.protocol.is_ftp();
    let kind = site.logon.kind();
    let mut out = Vec::new();
    match tab {
        0 => {
            out.push(F::Protocol);
            if ftp {
                out.push(F::Encryption);
            }
            out.extend([F::Host, F::Port, F::Logon]);
            if kind != LogonKind::Anonymous {
                out.push(F::User);
            }
            if matches!(kind, LogonKind::Normal | LogonKind::Account) {
                out.push(F::Password);
            }
            if kind == LogonKind::Account {
                out.push(F::Account);
            }
            if kind == LogonKind::KeyFile {
                out.push(F::KeyFile);
            }
            if !ftp && !matches!(kind, LogonKind::KeyFile | LogonKind::Agent) {
                out.push(F::TryAgent);
            }
            out.extend([F::Color, F::Comments]);
        }
        1 => out.extend([
            F::ServerType,
            F::BypassProxy,
            F::LocalDir,
            F::RemoteDir,
            F::SyncBrowsing,
            F::Compare,
            F::TzHours,
            F::TzMinutes,
        ]),
        2 => {
            if ftp {
                out.push(F::TransferMode);
            }
            out.push(F::LimitConnections);
            if site.limit_connections.is_some() {
                out.push(F::MaxConnections);
            }
        }
        3 if ftp => {
            out.push(F::CharsetMode);
            if matches!(site.charset, Charset::Custom(_)) {
                out.push(F::CustomCharset);
            }
        }
        _ => {}
    }
    out
}

/// The field a validation issue is shown under.
fn issue_field(field: SiteField) -> Option<FieldId> {
    Some(match field {
        SiteField::Name => return None,
        SiteField::Host => FieldId::Host,
        SiteField::Port => FieldId::Port,
        SiteField::Logon => FieldId::Logon,
        SiteField::User => FieldId::User,
        SiteField::KeyFile => FieldId::KeyFile,
        SiteField::TimezoneOffset => FieldId::TzHours,
        SiteField::ConnectionLimit => FieldId::MaxConnections,
    })
}

/// The tab a field is on.
fn tab_of(field: FieldId) -> usize {
    use FieldId as F;
    match field {
        F::ServerType
        | F::BypassProxy
        | F::LocalDir
        | F::RemoteDir
        | F::SyncBrowsing
        | F::Compare
        | F::TzHours
        | F::TzMinutes => 1,
        F::TransferMode | F::LimitConnections | F::MaxConnections => 2,
        F::CharsetMode | F::CustomCharset => 3,
        _ => 0,
    }
}

/// A few lines of free text (Comments): `Enter` starts a new line.
pub(crate) struct TextArea {
    label: String,
    lines: Vec<Vec<char>>,
    row: usize,
    col: usize,
    rows: u16,
}

impl TextArea {
    pub(crate) fn new(label: &str, text: &str, rows: u16) -> Self {
        let mut lines: Vec<Vec<char>> = text.split('\n').map(|l| l.chars().collect()).collect();
        if lines.is_empty() {
            lines.push(Vec::new());
        }
        let row = lines.len() - 1;
        let col = lines[row].len();
        Self {
            label: label.to_owned(),
            lines,
            row,
            col,
            rows,
        }
    }

    pub(crate) fn text(&self) -> String {
        self.lines
            .iter()
            .map(|l| l.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Field for TextArea {
    fn label(&self) -> &str {
        &self.label
    }

    fn height(&self) -> u16 {
        self.rows
    }

    fn handle_key(&mut self, key: KeyEvent) -> FieldOutcome {
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return FieldOutcome::Ignored;
        }
        match key.code {
            KeyCode::Char(c) => {
                self.lines[self.row].insert(self.col, c);
                self.col += 1;
            }
            KeyCode::Enter => {
                let rest = self.lines[self.row].split_off(self.col);
                self.row += 1;
                self.lines.insert(self.row, rest);
                self.col = 0;
            }
            KeyCode::Backspace => {
                if self.col > 0 {
                    self.col -= 1;
                    self.lines[self.row].remove(self.col);
                } else if self.row > 0 {
                    let line = self.lines.remove(self.row);
                    self.row -= 1;
                    self.col = self.lines[self.row].len();
                    self.lines[self.row].extend(line);
                }
            }
            KeyCode::Delete => {
                if self.col < self.lines[self.row].len() {
                    self.lines[self.row].remove(self.col);
                } else if self.row + 1 < self.lines.len() {
                    let next = self.lines.remove(self.row + 1);
                    self.lines[self.row].extend(next);
                }
            }
            KeyCode::Left if self.col > 0 => self.col -= 1,
            KeyCode::Right if self.col < self.lines[self.row].len() => self.col += 1,
            KeyCode::Home => self.col = 0,
            KeyCode::End => self.col = self.lines[self.row].len(),
            KeyCode::Up if self.row > 0 => {
                self.row -= 1;
                self.col = self.col.min(self.lines[self.row].len());
            }
            KeyCode::Down if self.row + 1 < self.lines.len() => {
                self.row += 1;
                self.col = self.col.min(self.lines[self.row].len());
            }
            _ => return FieldOutcome::Ignored,
        }
        FieldOutcome::Consumed
    }

    fn handle_paste(&mut self, text: &str) {
        for c in text.chars().filter(|c| *c == '\n' || !c.is_control()) {
            if c == '\n' {
                let rest = self.lines[self.row].split_off(self.col);
                self.row += 1;
                self.lines.insert(self.row, rest);
                self.col = 0;
            } else {
                self.lines[self.row].insert(self.col, c);
                self.col += 1;
            }
        }
    }

    fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        let visible = usize::from(area.height.max(1));
        let start = self.row.saturating_sub(visible - 1);
        let lines: Vec<Line> = self
            .lines
            .iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(i, l)| {
                let text: String = l.iter().collect();
                if focused && i == self.row {
                    let (a, b) = l.split_at(self.col.min(l.len()));
                    let mut b = b.iter();
                    let cursor = b.next().map_or(" ".to_owned(), char::to_string);
                    Line::from(vec![
                        Span::raw(a.iter().collect::<String>()),
                        Span::styled(cursor, theme.selection),
                        Span::raw(b.collect::<String>()),
                    ])
                } else {
                    Line::raw(text)
                }
            })
            .collect();
        let lines = if lines.iter().all(|l| l.width() == 0) && !focused {
            vec![Line::styled("…", theme.dim)]
        } else {
            lines
        };
        frame.render_widget(Paragraph::new(lines), area);
    }

    fn value(&self) -> FieldValue {
        FieldValue::Text(self.text())
    }
}

/// The widgets, one per [`FieldId`].
struct Widgets {
    protocol: Select,
    encryption: Select,
    host: TextInput,
    port: TextInput,
    logon: Select,
    logon_kinds: Vec<LogonKind>,
    user: TextInput,
    password: TextInput,
    account: TextInput,
    key_file: PathInput,
    try_agent: Checkbox,
    color: Select,
    comments: TextArea,
    server_type: Select,
    bypass_proxy: Checkbox,
    local_dir: PathInput,
    remote_dir: TextInput,
    sync_browsing: Checkbox,
    compare: Checkbox,
    tz_hours: NumberInput,
    tz_minutes: NumberInput,
    transfer_mode: Select,
    limit_connections: Checkbox,
    max_connections: NumberInput,
    charset_mode: RadioGroup,
    custom_charset: Select,
    encodings: Vec<&'static Encoding>,
}

fn logon_select(protocol: Protocol, kind: LogonKind) -> (Select, Vec<LogonKind>) {
    let kinds = logon_kinds(protocol).to_vec();
    let options = kinds.iter().map(|k| logon_name(*k).to_owned()).collect();
    let selected = kinds.iter().position(|k| *k == kind).unwrap_or(0);
    (Select::new("Logon type:", options, selected), kinds)
}

fn key_text(logon: &SiteLogon) -> String {
    match logon {
        SiteLogon::KeyFile {
            key: Some(SiteKey::File(path)),
            ..
        } => path.as_path().display().to_string(),
        _ => String::new(),
    }
}

fn password_input(logon: &SiteLogon) -> TextInput {
    let input = TextInput::password("Password:");
    match logon.password() {
        Some(pw) => input.with_value(pw.expose_secret()),
        None => input,
    }
}

impl Widgets {
    fn new(site: &Site) -> Self {
        let encryption = site
            .encryption
            .or_else(|| site.protocol.default_encryption())
            .unwrap_or_default();
        let (logon, logon_kinds) = logon_select(site.protocol, site.logon.kind());
        let mut encodings = encodings();
        if let Charset::Custom(enc) = site.charset
            && !encodings.contains(&enc)
        {
            encodings.push(enc);
        }
        let custom = match site.charset {
            Charset::Custom(enc) => encodings.iter().position(|e| *e == enc).unwrap_or(0),
            _ => 0,
        };
        let offset = site.timezone_offset_minutes;
        let account = match &site.logon {
            SiteLogon::Account { account, .. } => account.clone(),
            _ => String::new(),
        };
        Self {
            protocol: Select::new(
                "Protocol:",
                vec!["FTP".into(), "SFTP".into()],
                usize::from(site.protocol == Protocol::Sftp),
            ),
            encryption: Select::new(
                "Encryption:",
                ENCRYPTIONS
                    .iter()
                    .map(|e| encryption_name(*e).to_owned())
                    .collect(),
                position(&ENCRYPTIONS, &encryption),
            ),
            host: TextInput::new("Host:").with_value(&site.host),
            port: TextInput::new("Port:")
                .with_max_len(5)
                .with_value(&site.port.map(|p| p.to_string()).unwrap_or_default())
                .with_placeholder(site.protocol.default_port().to_string()),
            logon,
            logon_kinds,
            user: TextInput::new("User:").with_value(site.logon.user()),
            password: password_input(&site.logon),
            account: TextInput::new("Account:").with_value(&account),
            key_file: PathInput::new("Key file:", Box::new(LocalPathCompleter))
                .with_value(&key_text(&site.logon)),
            try_agent: Checkbox::new("Try agent first:", site.try_agent_first),
            color: Select::new(
                "Colour:",
                COLORS.iter().map(|c| color_name(*c).to_owned()).collect(),
                position(&COLORS, &site.color),
            ),
            comments: TextArea::new("Comments:", &site.comments, 3),
            server_type: Select::new(
                "Server type:",
                SERVER_TYPES
                    .iter()
                    .map(|t| server_type_name(*t).to_owned())
                    .collect(),
                position(&SERVER_TYPES, &site.server_type),
            ),
            bypass_proxy: Checkbox::new("Bypass proxy:", site.bypass_proxy),
            local_dir: PathInput::new("Local dir:", Box::new(LocalPathCompleter)).with_value(
                &site
                    .default_local_dir
                    .as_ref()
                    .map(|p| p.as_path().display().to_string())
                    .unwrap_or_default(),
            ),
            remote_dir: TextInput::new("Remote dir:").with_value(
                site.default_remote_dir
                    .as_ref()
                    .map(RemotePath::as_str)
                    .unwrap_or_default(),
            ),
            sync_browsing: Checkbox::new("Sync browsing:", site.sync_browsing),
            compare: Checkbox::new("Comparison:", site.directory_comparison),
            tz_hours: NumberInput::new(
                "Time zone h:",
                i64::from(offset / 60),
                -i64::from(MAX_TIMEZONE_OFFSET_MINUTES / 60),
                i64::from(MAX_TIMEZONE_OFFSET_MINUTES / 60),
            ),
            tz_minutes: NumberInput::new("Time zone min:", i64::from(offset % 60), -59, 59),
            transfer_mode: Select::new(
                "Transfer mode:",
                TRANSFER_MODES
                    .iter()
                    .map(|m| transfer_mode_name(*m).to_owned())
                    .collect(),
                position(&TRANSFER_MODES, &site.transfer_mode),
            ),
            limit_connections: Checkbox::new(
                "Limit connections:",
                site.limit_connections.is_some(),
            ),
            max_connections: NumberInput::new(
                "Maximum:",
                i64::from(site.limit_connections.unwrap_or(2)),
                1,
                10,
            ),
            charset_mode: RadioGroup::new(
                "Charset:",
                vec!["Autodetect".into(), "Force UTF-8".into(), "Custom".into()],
                match site.charset {
                    Charset::Auto => 0,
                    Charset::Utf8 => 1,
                    Charset::Custom(_) => 2,
                },
            ),
            custom_charset: Select::new(
                "Encoding:",
                encodings.iter().map(|e| e.name().to_owned()).collect(),
                custom,
            ),
            encodings,
        }
    }

    fn get(&self, id: FieldId) -> &dyn Field {
        use FieldId as F;
        match id {
            F::Protocol => &self.protocol,
            F::Encryption => &self.encryption,
            F::Host => &self.host,
            F::Port => &self.port,
            F::Logon => &self.logon,
            F::User => &self.user,
            F::Password => &self.password,
            F::Account => &self.account,
            F::KeyFile => &self.key_file,
            F::TryAgent => &self.try_agent,
            F::Color => &self.color,
            F::Comments => &self.comments,
            F::ServerType => &self.server_type,
            F::BypassProxy => &self.bypass_proxy,
            F::LocalDir => &self.local_dir,
            F::RemoteDir => &self.remote_dir,
            F::SyncBrowsing => &self.sync_browsing,
            F::Compare => &self.compare,
            F::TzHours => &self.tz_hours,
            F::TzMinutes => &self.tz_minutes,
            F::TransferMode => &self.transfer_mode,
            F::LimitConnections => &self.limit_connections,
            F::MaxConnections => &self.max_connections,
            F::CharsetMode => &self.charset_mode,
            F::CustomCharset => &self.custom_charset,
        }
    }

    fn get_mut(&mut self, id: FieldId) -> &mut dyn Field {
        use FieldId as F;
        match id {
            F::Protocol => &mut self.protocol,
            F::Encryption => &mut self.encryption,
            F::Host => &mut self.host,
            F::Port => &mut self.port,
            F::Logon => &mut self.logon,
            F::User => &mut self.user,
            F::Password => &mut self.password,
            F::Account => &mut self.account,
            F::KeyFile => &mut self.key_file,
            F::TryAgent => &mut self.try_agent,
            F::Color => &mut self.color,
            F::Comments => &mut self.comments,
            F::ServerType => &mut self.server_type,
            F::BypassProxy => &mut self.bypass_proxy,
            F::LocalDir => &mut self.local_dir,
            F::RemoteDir => &mut self.remote_dir,
            F::SyncBrowsing => &mut self.sync_browsing,
            F::Compare => &mut self.compare,
            F::TzHours => &mut self.tz_hours,
            F::TzMinutes => &mut self.tz_minutes,
            F::TransferMode => &mut self.transfer_mode,
            F::LimitConnections => &mut self.limit_connections,
            F::MaxConnections => &mut self.max_connections,
            F::CharsetMode => &mut self.charset_mode,
            F::CustomCharset => &mut self.custom_charset,
        }
    }
}

fn index(field: &dyn Field) -> usize {
    match field.value() {
        FieldValue::Index(i) => i,
        _ => 0,
    }
}

fn flag(field: &dyn Field) -> bool {
    matches!(field.value(), FieldValue::Bool(true))
}

fn set_user(logon: &mut SiteLogon, value: String) {
    match logon {
        SiteLogon::Anonymous => {}
        SiteLogon::Normal { user, .. }
        | SiteLogon::AskForPassword { user }
        | SiteLogon::Interactive { user }
        | SiteLogon::KeyFile { user, .. }
        | SiteLogon::Account { user, .. }
        | SiteLogon::Agent { user } => *user = value,
    }
}

/// Messages under a field.
type Notes = Vec<(String, Severity)>;

/// What the editor did with a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EditorKey {
    Consumed,
    /// `Tab` past the last field.
    LeaveForward,
    /// `Shift-Tab` before the first field.
    LeaveBackward,
    /// Not for the editor.
    Unhandled,
}

/// One site being edited.
pub(crate) struct Editor {
    /// The site as stored (for a new site: as created).
    original: Site,
    /// The site with the edits so far.
    pub(crate) site: Site,
    /// Not saved yet.
    new: bool,
    tab: usize,
    focus: Option<FieldId>,
    w: Widgets,
    /// Show validation issues (from the first save attempt on a new site).
    show_issues: bool,
    /// `vault.store_passwords`: the password field explains why it is off.
    store_passwords: bool,
    bookmarks: Vec<String>,
    /// The last password typed or stored, so stepping through logon types
    /// (Normal → Ask for password → Account) doesn't lose it.
    kept_password: Option<SecretString>,
}

impl Editor {
    pub(crate) fn new(
        site: Site,
        new: bool,
        store_passwords: bool,
        bookmarks: Vec<String>,
    ) -> Self {
        let kept = site.logon.password().cloned();
        Self {
            w: Widgets::new(&site),
            original: site.clone(),
            site,
            new,
            tab: 0,
            focus: None,
            show_issues: !new,
            store_passwords,
            bookmarks,
            kept_password: kept,
        }
    }

    /// The site's id.
    pub(crate) fn id(&self) -> courier_ftp_core::model::item::ItemId {
        self.site.id
    }

    pub(crate) fn is_new(&self) -> bool {
        self.new
    }

    /// Unsaved changes (a new site always has them).
    pub(crate) fn is_dirty(&self) -> bool {
        self.new || self.site != self.original
    }

    #[cfg(test)]
    pub(crate) fn set_tab(&mut self, tab: usize) {
        self.tab = tab.min(TABS.len() - 1);
        self.focus = None;
    }

    pub(crate) fn focused(&self) -> Option<FieldId> {
        self.focus
    }

    /// Keep the tab and focused field of `other` (after a reload).
    pub(crate) fn keep_place(&mut self, other: &Editor) {
        self.tab = other.tab;
        self.focus = other.focus;
    }

    /// The name and folder changed in the tree (rename, move): take them
    /// over without touching the other edits.
    pub(crate) fn tree_changed(
        &mut self,
        name: &str,
        parent: Option<courier_ftp_core::model::item::ItemId>,
    ) {
        for s in [&mut self.original, &mut self.site] {
            s.name = name.to_owned();
            s.parent = parent;
        }
    }

    pub(crate) fn set_bookmarks(&mut self, bookmarks: Vec<String>) {
        self.bookmarks = bookmarks;
    }

    /// Validation issues of the edited site.
    pub(crate) fn issues(&self) -> Vec<SiteIssue> {
        self.site.validate()
    }

    /// Show validation issues from now on (a save attempt).
    pub(crate) fn touch(&mut self) {
        self.show_issues = true;
        for id in [
            FieldId::TzHours,
            FieldId::TzMinutes,
            FieldId::MaxConnections,
        ] {
            self.w.get_mut(id).touch();
        }
    }

    /// Whether a field widget itself has an error (a number out of range).
    pub(crate) fn widget_error(&self) -> Option<String> {
        [
            FieldId::TzHours,
            FieldId::TzMinutes,
            FieldId::MaxConnections,
        ]
        .into_iter()
        .filter(|id| visible_fields(&self.site, tab_of(*id)).contains(id))
        .find_map(|id| self.w.get(id).error())
    }

    /// Focus the first field with an error (switching tab).
    pub(crate) fn focus_first_error(&mut self) {
        let first = self
            .issues()
            .into_iter()
            .filter(SiteIssue::is_error)
            .find_map(|i| issue_field(i.field));
        if let Some(field) = first {
            self.tab = tab_of(field);
            self.focus = Some(field);
        }
    }

    fn focusable(&self) -> Vec<FieldId> {
        visible_fields(&self.site, self.tab)
            .into_iter()
            .filter(|f| *f != FieldId::Password || self.store_passwords)
            .collect()
    }

    /// Focus the first field (`backward`: the last) of the current tab.
    pub(crate) fn enter(&mut self, backward: bool) {
        let fields = self.focusable();
        self.focus = if backward {
            fields.last().copied()
        } else {
            fields.first().copied()
        };
    }

    /// Focus `field`, switching to its tab.
    pub(crate) fn focus_field(&mut self, field: FieldId) {
        self.tab = tab_of(field);
        self.focus = Some(field);
    }

    fn switch_tab(&mut self, forward: bool) {
        let n = TABS.len();
        self.tab = if forward {
            (self.tab + 1) % n
        } else {
            (self.tab + n - 1) % n
        };
        self.enter(false);
    }

    fn step(&mut self, forward: bool) -> EditorKey {
        let fields = self.focusable();
        let pos = self.focus.and_then(|f| fields.iter().position(|x| *x == f));
        match (pos, forward) {
            (None, true) => self.focus = fields.first().copied(),
            (None, false) => self.focus = fields.last().copied(),
            (Some(i), true) if i + 1 < fields.len() => self.focus = Some(fields[i + 1]),
            (Some(i), false) if i > 0 => self.focus = Some(fields[i - 1]),
            _ => {
                return if forward {
                    EditorKey::LeaveForward
                } else {
                    EditorKey::LeaveBackward
                };
            }
        }
        if self.focus.is_none() {
            return if forward {
                EditorKey::LeaveForward
            } else {
                EditorKey::LeaveBackward
            };
        }
        EditorKey::Consumed
    }

    /// Whether the focused field is busy with a key sequence of its own (an
    /// open dropdown).
    pub(crate) fn is_capturing(&self) -> bool {
        self.focus.is_some_and(|f| self.w.get(f).is_capturing())
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> EditorKey {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::PageDown if ctrl => {
                self.switch_tab(true);
                return EditorKey::Consumed;
            }
            KeyCode::PageUp if ctrl => {
                self.switch_tab(false);
                return EditorKey::Consumed;
            }
            _ => {}
        }
        if self.site.read_only {
            // Shown, not editable (an item from a newer courier-ftp).
            return match key.code {
                KeyCode::Tab | KeyCode::Down => self.step(true),
                KeyCode::BackTab | KeyCode::Up => self.step(false),
                KeyCode::Char('[') => {
                    self.switch_tab(false);
                    EditorKey::Consumed
                }
                KeyCode::Char(']') => {
                    self.switch_tab(true);
                    EditorKey::Consumed
                }
                _ => EditorKey::Unhandled,
            };
        }
        if let Some(field) = self.focus {
            let capturing = self.w.get(field).is_capturing();
            // The port takes digits only.
            let swallowed = field == FieldId::Port
                && matches!(key.code, KeyCode::Char(c) if !c.is_ascii_digit() && !ctrl);
            if swallowed {
                return EditorKey::Consumed;
            }
            if self.w.get_mut(field).handle_key(key) == FieldOutcome::Consumed || capturing {
                self.sync(field);
                return EditorKey::Consumed;
            }
        }
        match key.code {
            KeyCode::Tab | KeyCode::Down => self.step(true),
            KeyCode::BackTab | KeyCode::Up => self.step(false),
            KeyCode::Char('[') => {
                self.switch_tab(false);
                EditorKey::Consumed
            }
            KeyCode::Char(']') => {
                self.switch_tab(true);
                EditorKey::Consumed
            }
            _ => EditorKey::Unhandled,
        }
    }

    pub(crate) fn handle_paste(&mut self, text: &str) {
        if self.site.read_only {
            return;
        }
        if let Some(field) = self.focus {
            if field == FieldId::Port {
                let digits: String = text.chars().filter(char::is_ascii_digit).collect();
                self.w.port.handle_paste(&digits);
            } else {
                self.w.get_mut(field).handle_paste(text);
            }
            self.sync(field);
        }
    }

    /// The logon widgets after the logon type changed.
    fn refill_logon(&mut self) {
        let (select, kinds) = logon_select(self.site.protocol, self.site.logon.kind());
        self.w.logon = select;
        self.w.logon_kinds = kinds;
        self.w.password = password_input(&self.site.logon);
        let account = match &self.site.logon {
            SiteLogon::Account { account, .. } => account.clone(),
            _ => String::new(),
        };
        self.w.account = TextInput::new("Account:").with_value(&account);
        self.w.key_file = PathInput::new("Key file:", Box::new(LocalPathCompleter))
            .with_value(&key_text(&self.site.logon));
    }

    /// A logon type not available for the protocol becomes Normal.
    fn fix_logon(&mut self) {
        if !logon_kinds(self.site.protocol).contains(&self.site.logon.kind()) {
            self.site.logon = self.site.logon.clone().with_kind(LogonKind::Normal);
        }
        self.refill_logon();
    }

    /// Write the value of widget `field` into the edited site.
    fn sync(&mut self, field: FieldId) {
        use FieldId as F;
        let s = &mut self.site;
        match field {
            F::Protocol => {
                if index(&self.w.protocol) == 1 {
                    s.protocol = Protocol::Sftp;
                } else {
                    let e = ENCRYPTIONS[index(&self.w.encryption).min(ENCRYPTIONS.len() - 1)];
                    s.protocol = e.protocol();
                }
                self.w.port = TextInput::new("Port:")
                    .with_max_len(5)
                    .with_value(&self.w.port.text())
                    .with_placeholder(self.site.protocol.default_port().to_string());
                self.fix_logon();
            }
            F::Encryption => {
                let e = ENCRYPTIONS[index(&self.w.encryption).min(ENCRYPTIONS.len() - 1)];
                s.protocol = e.protocol();
                s.encryption = if self.original.encryption.is_none()
                    && Some(e) == self.original.protocol.default_encryption()
                {
                    None
                } else {
                    Some(e)
                };
                self.w.port = TextInput::new("Port:")
                    .with_max_len(5)
                    .with_value(&self.w.port.text())
                    .with_placeholder(self.site.protocol.default_port().to_string());
            }
            F::Host => s.host = self.w.host.text(),
            F::Port => {
                let text = self.w.port.text();
                s.port = if text.is_empty() {
                    None
                } else {
                    // Out of range shows the port error.
                    Some(text.parse().unwrap_or(0))
                };
            }
            F::Logon => {
                let kind = self
                    .w
                    .logon_kinds
                    .get(index(&self.w.logon))
                    .copied()
                    .unwrap_or(LogonKind::Normal);
                s.logon = s.logon.clone().with_kind(kind);
                if let SiteLogon::Normal { password, .. } | SiteLogon::Account { password, .. } =
                    &mut s.logon
                    && password.is_none()
                {
                    password.clone_from(&self.kept_password);
                }
                self.refill_logon();
            }
            F::User => set_user(&mut s.logon, self.w.user.text()),
            F::Password => {
                let secret = (!self.w.password.is_empty()).then(|| self.w.password.secret());
                self.kept_password.clone_from(&secret);
                if let SiteLogon::Normal { password, .. } | SiteLogon::Account { password, .. } =
                    &mut s.logon
                {
                    *password = secret;
                }
            }
            F::Account => {
                if let SiteLogon::Account { account, .. } = &mut s.logon {
                    *account = self.w.account.text();
                }
            }
            F::KeyFile => {
                let text = self.w.key_file.text();
                let vault_key = match &self.original.logon {
                    SiteLogon::KeyFile {
                        key: Some(SiteKey::Vault(id)),
                        ..
                    } => Some(SiteKey::Vault(*id)),
                    _ => None,
                };
                if let SiteLogon::KeyFile { key, .. } = &mut s.logon {
                    *key = if text.trim().is_empty() {
                        vault_key
                    } else {
                        Some(SiteKey::File(LocalPath::new(text)))
                    };
                }
            }
            F::TryAgent => s.try_agent_first = flag(&self.w.try_agent),
            F::Color => s.color = COLORS[index(&self.w.color).min(COLORS.len() - 1)],
            F::Comments => s.comments = self.w.comments.text(),
            F::ServerType => {
                s.server_type =
                    SERVER_TYPES[index(&self.w.server_type).min(SERVER_TYPES.len() - 1)];
            }
            F::BypassProxy => s.bypass_proxy = flag(&self.w.bypass_proxy),
            F::LocalDir => {
                let text = self.w.local_dir.text();
                s.default_local_dir = (!text.trim().is_empty()).then(|| LocalPath::new(text));
            }
            F::RemoteDir => {
                let text = self.w.remote_dir.text();
                s.default_remote_dir = (!text.trim().is_empty()).then(|| RemotePath::new(text));
            }
            F::SyncBrowsing => s.sync_browsing = flag(&self.w.sync_browsing),
            F::Compare => s.directory_comparison = flag(&self.w.compare),
            F::TzHours | F::TzMinutes => {
                if let (Some(h), Some(m)) = (self.w.tz_hours.number(), self.w.tz_minutes.number()) {
                    s.timezone_offset_minutes =
                        i32::try_from(h.saturating_mul(60).saturating_add(m)).unwrap_or(i32::MAX);
                }
            }
            F::TransferMode => {
                s.transfer_mode =
                    TRANSFER_MODES[index(&self.w.transfer_mode).min(TRANSFER_MODES.len() - 1)];
            }
            F::LimitConnections | F::MaxConnections => {
                s.limit_connections = flag(&self.w.limit_connections).then(|| {
                    let n = self.w.max_connections.number().unwrap_or(2).clamp(0, 255);
                    u8::try_from(n).unwrap_or(2)
                });
            }
            F::CharsetMode | F::CustomCharset => {
                s.charset = match index(&self.w.charset_mode) {
                    0 => Charset::Auto,
                    1 => Charset::Utf8,
                    _ => self
                        .w
                        .encodings
                        .get(index(&self.w.custom_charset))
                        .map_or(Charset::Auto, |e| Charset::Custom(e)),
                };
            }
        }
    }

    /// The issues shown under `field`.
    fn field_issues(&self, field: FieldId, issues: &[SiteIssue]) -> Notes {
        let mut out: Notes = Vec::new();
        if self.show_issues {
            out.extend(
                issues
                    .iter()
                    .filter(|i| issue_field(i.field) == Some(field))
                    .map(|i| (i.message.clone(), i.severity)),
            );
        }
        if let Some(e) = self.w.get(field).error() {
            out.push((e, Severity::Error));
        }
        out
    }

    /// Whether a tab holds an error (marked `!` in the tab header).
    fn tab_has_error(&self, tab: usize, issues: &[SiteIssue]) -> bool {
        self.show_issues
            && issues
                .iter()
                .filter(|i| i.is_error())
                .filter_map(|i| issue_field(i.field))
                .any(|f| tab_of(f) == tab && visible_fields(&self.site, tab).contains(&f))
    }

    /// Draw the editor into `area` (inside its pane border).
    pub(crate) fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        if area.height < 3 || area.width < 10 {
            return;
        }
        let issues = self.issues();
        // Header: name, dirty marker, problems with the name.
        let mut header = vec![Span::styled(self.site.name.clone(), theme.title)];
        if self.is_dirty() {
            header.push(Span::styled(" *", theme.key_hint));
        }
        if self.new {
            header.push(Span::styled(" (new, not saved)", theme.dim));
        }
        if self.site.read_only {
            header.push(Span::styled(
                " (from a newer courier-ftp: read-only)",
                theme.dim,
            ));
        }
        if let Some(i) = issues
            .iter()
            .find(|i| i.field == SiteField::Name && self.show_issues)
        {
            header.push(Span::styled(format!("  {}", i.message), theme.error));
        }
        frame.render_widget(
            Paragraph::new(Line::from(header)),
            Rect::new(area.x, area.y, area.width, 1),
        );
        // Tabs.
        let mut spans = Vec::new();
        for (i, title) in TABS.iter().enumerate() {
            let mark = if self.tab_has_error(i, &issues) {
                "!"
            } else {
                ""
            };
            let style = if i == self.tab {
                if focused {
                    theme.selection
                } else {
                    theme.title
                }
            } else {
                theme.dim
            };
            let text = if i == self.tab {
                format!("[{title}{mark}]")
            } else {
                format!(" {title}{mark} ")
            };
            spans.push(Span::styled(text, style));
            spans.push(Span::raw(" "));
        }
        frame.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect::new(area.x, area.y + 1, area.width, 1),
        );
        let body = Rect::new(
            area.x,
            area.y + 3,
            area.width,
            area.height.saturating_sub(3),
        );
        if self.tab == 4 {
            self.draw_bookmarks(frame, body, theme);
            return;
        }
        let fields = visible_fields(&self.site, self.tab);
        if fields.is_empty() || self.tab == 3 && !self.site.protocol.is_ftp() {
            frame.render_widget(
                Paragraph::new(Line::styled(
                    "SFTP file names are always UTF-8: there is nothing to set here.",
                    theme.dim,
                )),
                body,
            );
            return;
        }
        let label_w = fields
            .iter()
            .map(|f| self.w.get(*f).label().chars().count())
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let label_w = u16::try_from(label_w).unwrap_or(16).min(body.width / 2);
        let rows: Vec<(FieldId, u16, Notes)> = fields
            .iter()
            .map(|f| {
                let notes = self.field_issues(*f, &issues);
                let h = self.w.get(*f).height() + u16::try_from(notes.len()).unwrap_or(0);
                (*f, h, notes)
            })
            .collect();
        let focus_index = self
            .focus
            .and_then(|f| fields.iter().position(|x| *x == f))
            .unwrap_or(0);
        let focus_top: u16 = rows.iter().take(focus_index).map(|r| r.1).sum();
        let focus_h = rows.get(focus_index).map_or(1, |r| r.1);
        let scroll = (focus_top + focus_h).saturating_sub(body.height);
        let mut y = body.y;
        let mut top = 0u16;
        let mut overlay = None;
        for (field, h, notes) in &rows {
            let row_top = top;
            top += h;
            if row_top < scroll {
                continue;
            }
            let widget = self.w.get(*field);
            if y + widget.height() > body.bottom() {
                break;
            }
            let is_focused = focused && self.focus == Some(*field);
            frame.render_widget(
                Paragraph::new(Span::styled(
                    widget.label().to_owned(),
                    if is_focused { theme.title } else { theme.dim },
                )),
                Rect::new(body.x, y, label_w, 1),
            );
            let field_area = Rect::new(
                body.x + label_w,
                y,
                body.width.saturating_sub(label_w),
                widget.height(),
            );
            if *field == FieldId::Password {
                self.draw_password(frame, field_area, is_focused, theme);
            } else if *field == FieldId::KeyFile
                && self.w.key_file.text().is_empty()
                && matches!(
                    self.site.logon,
                    SiteLogon::KeyFile {
                        key: Some(SiteKey::Vault(_)),
                        ..
                    }
                )
            {
                frame.render_widget(
                    Paragraph::new(Span::styled(
                        "SSH key from the vault (type a path to use a file)",
                        if is_focused {
                            theme.selection
                        } else {
                            theme.dim
                        },
                    )),
                    field_area,
                );
            } else {
                widget.draw(frame, field_area, is_focused, theme);
            }
            if is_focused {
                overlay = Some((*field, field_area));
            }
            for (ny, (text, severity)) in (y + widget.height()..).zip(notes) {
                if ny >= body.bottom() {
                    break;
                }
                let style = match severity {
                    Severity::Error => theme.error,
                    Severity::Warning => theme.key_hint,
                };
                frame.render_widget(
                    Paragraph::new(Span::styled(text.clone(), style)),
                    Rect::new(field_area.x, ny, field_area.width, 1),
                );
            }
            y += h;
        }
        if let Some((field, rect)) = overlay {
            self.w.get(field).draw_overlay(frame, rect, theme);
        }
    }

    fn draw_password(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        if !self.store_passwords {
            frame.render_widget(
                Paragraph::new(Span::styled(
                    "not stored (vault.store_passwords is off): asked on connect",
                    theme.dim,
                )),
                area,
            );
            return;
        }
        let input_w = area.width.min(24);
        self.w.password.draw(
            frame,
            Rect::new(area.x, area.y, input_w, area.height),
            focused,
            theme,
        );
        if area.width > input_w + 1 {
            frame.render_widget(
                Paragraph::new(Span::styled(" stored in the vault", theme.dim)),
                Rect::new(area.x + input_w, area.y, area.width - input_w, 1),
            );
        }
    }

    fn draw_bookmarks(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let mut lines: Vec<Line> = if self.bookmarks.is_empty() {
            vec![Line::styled("No bookmarks for this site.", theme.dim)]
        } else {
            self.bookmarks
                .iter()
                .map(|b| Line::raw(format!("• {b}")))
                .collect()
        };
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "Bookmarks are added and edited from the Bookmarks menu.",
            theme.dim,
        ));
        frame.render_widget(Paragraph::new(lines), area);
    }

    /// The password the editor holds (tests).
    #[cfg(test)]
    pub(crate) fn password(&self) -> Option<SecretString> {
        self.site.logon.password().cloned()
    }
}
