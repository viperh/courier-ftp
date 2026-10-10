//! Typed views of every [`ItemKind`] (T81).
//!
//! A view is read from a body with [`ItemView::from_body`] (or `TryFrom<&ItemBody>`)
//! and written back with [`ItemView::apply_to`], which stamps only the fields whose
//! value changed and never drops keys the view doesn't know. Nested values are
//! flattened to dotted keys (`logon.user`, `logon.password`); lists are single values.
//!
//! Device-local data never goes into an item: last-connected time, frecency, a
//! site's default local directory and window/tab state live in the store's
//! `device_local` table (T82).
//!
//! Field names (wire format, stable):
//!
//! | Kind | Fields |
//! |---|---|
//! | `site` | `name`, `parent`, `protocol`, `encryption`, `host`, `port`, `logon.type`, `logon.user`, `logon.password`, `logon.account`, `logon.key_id`, `logon.key_path`, `logon.passphrase`, `try_agent_first`, `color`, `comments`, `server_type`, `bypass_proxy`, `default_remote_dir`, `sync_browsing`, `directory_comparison`, `timezone_offset_minutes`, `transfer_mode`, `limit_connections`, `charset`, `created_at` |
//! | `site-folder` | `name`, `parent` |
//! | `bookmark` | `name`, `site_id`, `local_dir`, `remote_dir`, `sync_browsing`, `comparison`, `position` |
//! | `known-host` | `host`, `port`, `key_type`, `public_key`, `added_at` |
//! | `trusted-cert` | `host`, `port`, `sha256`, `der`, `subject`, `added_at` |
//! | `ssh-key` | `label`, `algorithm`, `public_key`, `private_key`, `passphrase` |
//! | `proxy-credential` | `label`, `user`, `password` |
//! | `credential-override` | `shared_site_id`, `user`, `password`, `key_id`, `passphrase` |
//! | `history-entry` | `protocol`, `host`, `port`, `logon.type`, `logon.user`, `logon.password`, `used_at` |
//!
//! Ids are 16-byte CBOR byte strings, times are [`UnixMillis`] integers, enums are
//! the wire strings below, secrets (`password`, `private_key`, `passphrase`) are
//! text inside the encrypted body and [`SecretString`] in memory.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ciborium::Value;
use secrecy::SecretString;

use super::body::ItemBody;
use super::fields::{Reader, ViewError, WireEnum, Writer, check_kind, wire_enum};
use super::hlc::HlcClock;
use super::ids::{DeviceId, ItemId};
use super::kinds::ItemKind;
use super::migrate::current_schema;
use crate::model::{Charset, FtpEncryption, Protocol};

/// A UTC timestamp in milliseconds since the Unix epoch (stored as a CBOR integer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct UnixMillis(pub i64);

impl UnixMillis {
    /// The current system time.
    pub fn now() -> Self {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        Self(i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    }
}

impl From<UnixMillis> for Value {
    fn from(t: UnixMillis) -> Self {
        Value::from(t.0)
    }
}

fn read_time(r: &Reader<'_>, key: &str) -> Result<Option<UnixMillis>, ViewError> {
    Ok(r.int::<i64>(key)?.map(UnixMillis))
}

/// A typed view of one [`ItemKind`].
pub trait ItemView: Sized {
    /// The kind this view reads and writes.
    const KIND: ItemKind;

    /// Reads the view from `body`.
    ///
    /// # Errors
    /// [`ViewError`] for a body of another kind, a missing required field or a field
    /// of the wrong type.
    fn from_body(body: &ItemBody) -> Result<Self, ViewError>;

    /// Writes the fields that differ from `body`, stamped by `clock` and `device`.
    /// Keys the view doesn't know are left as they are.
    fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId);

    /// A new body of [`ItemView::KIND`] at this build's schema version holding `self`.
    fn to_body(&self, clock: &mut HlcClock, device: DeviceId) -> ItemBody {
        let mut body = ItemBody::new(Self::KIND, current_schema(Self::KIND));
        self.apply_to(&mut body, clock, device);
        body
    }
}

macro_rules! try_from_body {
    ($($view:ty),+ $(,)?) => {$(
        impl TryFrom<&ItemBody> for $view {
            type Error = ViewError;

            fn try_from(body: &ItemBody) -> Result<Self, ViewError> {
                <$view as ItemView>::from_body(body)
            }
        }
    )+};
}

try_from_body!(
    Site,
    SiteFolder,
    Bookmark,
    KnownHost,
    TrustedCert,
    SshKey,
    ProxyCredential,
    CredentialOverride,
    HistoryEntry,
);

// ------------------------------------------------------------------- wire enums

impl WireEnum for Protocol {
    fn as_wire(&self) -> &'static str {
        match self {
            Protocol::Ftp => "ftp",
            Protocol::FtpsExplicit => "ftps_explicit",
            Protocol::FtpsImplicit => "ftps_implicit",
            Protocol::Sftp => "sftp",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "ftp" => Some(Protocol::Ftp),
            "ftps_explicit" => Some(Protocol::FtpsExplicit),
            "ftps_implicit" => Some(Protocol::FtpsImplicit),
            "sftp" => Some(Protocol::Sftp),
            _ => None,
        }
    }
}

impl WireEnum for FtpEncryption {
    fn as_wire(&self) -> &'static str {
        match self {
            FtpEncryption::PlainOnly => "plain_only",
            FtpEncryption::ExplicitIfAvailable => "explicit_if_available",
            FtpEncryption::RequireExplicit => "require_explicit",
            FtpEncryption::RequireImplicit => "require_implicit",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "plain_only" => Some(FtpEncryption::PlainOnly),
            "explicit_if_available" => Some(FtpEncryption::ExplicitIfAvailable),
            "require_explicit" => Some(FtpEncryption::RequireExplicit),
            "require_implicit" => Some(FtpEncryption::RequireImplicit),
            _ => None,
        }
    }
}

wire_enum!(
    /// How a site logs in (FileZilla's "Logon Type"). Default: `normal`.
    LogonKind {
        /// `normal`: user and saved password.
        Normal => "normal",
        /// `anonymous`
        Anonymous => "anonymous",
        /// `ask_for_password`: the password is asked on every connect.
        AskForPassword => "ask_for_password",
        /// `interactive`: every prompt is asked.
        Interactive => "interactive",
        /// `key_file`: SFTP public key (vault `ssh-key` item or a local path).
        KeyFile => "key_file",
        /// `account`: FTP `USER`/`PASS`/`ACCT`.
        Account => "account",
        /// `agent`: SSH agent / Pageant.
        Agent => "agent",
    }
);

wire_enum!(
    /// Listing format override (Site Manager, Advanced). Default: `auto`.
    ServerType {
        /// `auto`: detect.
        Auto => "auto",
        /// `unix`
        Unix => "unix",
        /// `dos`
        Dos => "dos",
        /// `vms`
        Vms => "vms",
        /// `mvs`
        Mvs => "mvs",
        /// `netware`
        NetWare => "netware",
        /// `as400`
        As400 => "as400",
    }
);

wire_enum!(
    /// FTP data connection mode for a site. Default: `default` (the global setting).
    SiteTransferMode {
        /// `default`: the global setting.
        Default => "default",
        /// `active`
        Active => "active",
        /// `passive`
        Passive => "passive",
    }
);

wire_enum!(
    /// A site's accent colour (tab and pane). Default: `none`.
    SiteColor {
        /// `none`
        None => "none",
        /// `red`
        Red => "red",
        /// `green`
        Green => "green",
        /// `blue`
        Blue => "blue",
        /// `yellow`
        Yellow => "yellow",
        /// `cyan`
        Cyan => "cyan",
        /// `magenta`
        Magenta => "magenta",
    }
);

// ------------------------------------------------------------------- site

/// One Site Manager entry (T31). Device-local fields (default local directory,
/// last connected time) are not part of it.
#[derive(Debug, Clone)]
pub struct Site {
    /// `name`
    pub name: String,
    /// `parent`: the `site-folder` it lives in (`None` = root).
    pub parent: Option<ItemId>,
    /// `protocol`
    pub protocol: Protocol,
    /// `encryption` (FTP only).
    pub encryption: Option<FtpEncryption>,
    /// `host`
    pub host: String,
    /// `port` (`None` = the protocol's default).
    pub port: Option<u16>,
    /// `logon.type`
    pub logon: LogonKind,
    /// `logon.user`
    pub user: String,
    /// `logon.password`
    pub password: Option<SecretString>,
    /// `logon.account` (FTP `ACCT`).
    pub account: Option<String>,
    /// `logon.key_id`: an `ssh-key` item in the vault.
    pub key_id: Option<ItemId>,
    /// `logon.key_path`: a key file on disk.
    pub key_path: Option<String>,
    /// `logon.passphrase`: the key's passphrase.
    pub passphrase: Option<SecretString>,
    /// `try_agent_first`
    pub try_agent_first: bool,
    /// `color`
    pub color: SiteColor,
    /// `comments`
    pub comments: String,
    /// `server_type`
    pub server_type: ServerType,
    /// `bypass_proxy`
    pub bypass_proxy: bool,
    /// `default_remote_dir`
    pub default_remote_dir: Option<String>,
    /// `sync_browsing`
    pub sync_browsing: bool,
    /// `directory_comparison`
    pub directory_comparison: bool,
    /// `timezone_offset_minutes`
    pub timezone_offset_minutes: i32,
    /// `transfer_mode`
    pub transfer_mode: SiteTransferMode,
    /// `limit_connections` (1–10; `None` = the global limit).
    pub limit_connections: Option<u8>,
    /// `charset` (label; absent = `auto`).
    pub charset: Charset,
    /// `created_at`
    pub created_at: Option<UnixMillis>,
    /// The body's schema is newer than this build: show it, don't edit it.
    pub read_only: bool,
}

impl Site {
    /// A site with every other field at its default.
    pub fn new(name: impl Into<String>, protocol: Protocol, host: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parent: None,
            protocol,
            encryption: None,
            host: host.into(),
            port: None,
            logon: LogonKind::default(),
            user: String::new(),
            password: None,
            account: None,
            key_id: None,
            key_path: None,
            passphrase: None,
            try_agent_first: false,
            color: SiteColor::default(),
            comments: String::new(),
            server_type: ServerType::default(),
            bypass_proxy: false,
            default_remote_dir: None,
            sync_browsing: false,
            directory_comparison: false,
            timezone_offset_minutes: 0,
            transfer_mode: SiteTransferMode::default(),
            limit_connections: None,
            charset: Charset::Auto,
            created_at: None,
            read_only: false,
        }
    }
}

impl ItemView for Site {
    const KIND: ItemKind = ItemKind::Site;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, Self::KIND)?;
        let r = Reader::new(body);
        let charset = match r.opt_str("charset")? {
            None => Charset::Auto,
            Some(label) => Charset::from_label(&label).map_err(|_| ViewError::FieldTypeError {
                field: "charset".to_owned(),
            })?,
        };
        Ok(Self {
            name: r.str("name")?,
            parent: r.opt_id("parent")?,
            protocol: r.req_enum("protocol")?,
            encryption: r.opt_enum("encryption")?,
            host: r.str("host")?,
            port: r.int("port")?,
            logon: r.enum_or_default("logon.type")?,
            user: r.str("logon.user")?,
            password: r.opt_secret("logon.password")?,
            account: r.opt_str("logon.account")?,
            key_id: r.opt_id("logon.key_id")?,
            key_path: r.opt_str("logon.key_path")?,
            passphrase: r.opt_secret("logon.passphrase")?,
            try_agent_first: r.bool("try_agent_first")?,
            color: r.enum_or_default("color")?,
            comments: r.str("comments")?,
            server_type: r.enum_or_default("server_type")?,
            bypass_proxy: r.bool("bypass_proxy")?,
            default_remote_dir: r.opt_str("default_remote_dir")?,
            sync_browsing: r.bool("sync_browsing")?,
            directory_comparison: r.bool("directory_comparison")?,
            timezone_offset_minutes: r.int("timezone_offset_minutes")?.unwrap_or(0),
            transfer_mode: r.enum_or_default("transfer_mode")?,
            limit_connections: r.int("limit_connections")?,
            charset,
            created_at: read_time(&r, "created_at")?,
            read_only,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("name", &self.name);
        w.opt("parent", self.parent);
        w.always("protocol", self.protocol.as_wire());
        w.opt_enum("encryption", self.encryption);
        w.text("host", &self.host);
        w.opt("port", self.port);
        w.always("logon.type", self.logon.as_wire());
        w.text("logon.user", &self.user);
        w.opt_secret("logon.password", self.password.as_ref());
        w.opt("logon.account", self.account.clone());
        w.opt("logon.key_id", self.key_id);
        w.opt("logon.key_path", self.key_path.clone());
        w.opt_secret("logon.passphrase", self.passphrase.as_ref());
        w.flag("try_agent_first", self.try_agent_first);
        w.enum_or_default("color", self.color);
        w.text("comments", &self.comments);
        w.enum_or_default("server_type", self.server_type);
        w.flag("bypass_proxy", self.bypass_proxy);
        w.opt("default_remote_dir", self.default_remote_dir.clone());
        w.flag("sync_browsing", self.sync_browsing);
        w.flag("directory_comparison", self.directory_comparison);
        w.value(
            "timezone_offset_minutes",
            self.timezone_offset_minutes,
            self.timezone_offset_minutes == 0,
        );
        w.enum_or_default("transfer_mode", self.transfer_mode);
        w.opt("limit_connections", self.limit_connections);
        w.value(
            "charset",
            self.charset.label(),
            self.charset == Charset::Auto,
        );
        w.opt("created_at", self.created_at);
    }
}

// ------------------------------------------------------------------- site folder

/// A Site Manager folder. The tree is rebuilt from the `parent` ids.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiteFolder {
    /// `name`
    pub name: String,
    /// `parent` (`None` = root).
    pub parent: Option<ItemId>,
    /// The body's schema is newer than this build.
    pub read_only: bool,
}

impl ItemView for SiteFolder {
    const KIND: ItemKind = ItemKind::SiteFolder;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, Self::KIND)?;
        let r = Reader::new(body);
        Ok(Self {
            name: r.str("name")?,
            parent: r.opt_id("parent")?,
            read_only,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("name", &self.name);
        w.opt("parent", self.parent);
    }
}

// ------------------------------------------------------------------- bookmark

/// A global (`site_id` = `None`) or site bookmark (T33).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bookmark {
    /// `name`
    pub name: String,
    /// `site_id`: the site this bookmark belongs to.
    pub site_id: Option<ItemId>,
    /// `local_dir`
    pub local_dir: Option<String>,
    /// `remote_dir`
    pub remote_dir: Option<String>,
    /// `sync_browsing`
    pub sync_browsing: bool,
    /// `comparison`
    pub comparison: bool,
    /// `position`: sort key for user ordering.
    pub position: Option<i64>,
    /// The body's schema is newer than this build.
    pub read_only: bool,
}

impl ItemView for Bookmark {
    const KIND: ItemKind = ItemKind::Bookmark;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, Self::KIND)?;
        let r = Reader::new(body);
        Ok(Self {
            name: r.str("name")?,
            site_id: r.opt_id("site_id")?,
            local_dir: r.opt_str("local_dir")?,
            remote_dir: r.opt_str("remote_dir")?,
            sync_browsing: r.bool("sync_browsing")?,
            comparison: r.bool("comparison")?,
            position: r.int("position")?,
            read_only,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("name", &self.name);
        w.opt("site_id", self.site_id);
        w.opt("local_dir", self.local_dir.clone());
        w.opt("remote_dir", self.remote_dir.clone());
        w.flag("sync_browsing", self.sync_browsing);
        w.flag("comparison", self.comparison);
        w.opt("position", self.position);
    }
}

// ------------------------------------------------------------------- known host

/// A trusted SSH host key (T21).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownHost {
    /// `host`
    pub host: String,
    /// `port`
    pub port: u16,
    /// `key_type`, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// `public_key`: OpenSSH base64.
    pub public_key: String,
    /// `added_at`
    pub added_at: Option<UnixMillis>,
    /// The body's schema is newer than this build.
    pub read_only: bool,
}

impl ItemView for KnownHost {
    const KIND: ItemKind = ItemKind::KnownHost;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, Self::KIND)?;
        let r = Reader::new(body);
        Ok(Self {
            host: r.str("host")?,
            port: r.req_int("port")?,
            key_type: r.str("key_type")?,
            public_key: r.str("public_key")?,
            added_at: read_time(&r, "added_at")?,
            read_only,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("host", &self.host);
        w.always("port", self.port);
        w.text("key_type", &self.key_type);
        w.text("public_key", &self.public_key);
        w.opt("added_at", self.added_at);
    }
}

// ------------------------------------------------------------------- trusted cert

/// A trusted TLS certificate (T12), matched by host, port and SHA-256.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedCert {
    /// `host`
    pub host: String,
    /// `port`
    pub port: u16,
    /// `sha256`: fingerprint of the DER certificate (32 bytes).
    pub sha256: Vec<u8>,
    /// `der`: the certificate itself, for the details dialog.
    pub der: Vec<u8>,
    /// `subject`, for listing.
    pub subject: String,
    /// `added_at`
    pub added_at: Option<UnixMillis>,
    /// The body's schema is newer than this build.
    pub read_only: bool,
}

impl ItemView for TrustedCert {
    const KIND: ItemKind = ItemKind::TrustedCert;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, Self::KIND)?;
        let r = Reader::new(body);
        Ok(Self {
            host: r.str("host")?,
            port: r.req_int("port")?,
            sha256: r.bytes("sha256")?,
            der: r.bytes("der")?,
            subject: r.str("subject")?,
            added_at: read_time(&r, "added_at")?,
            read_only,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("host", &self.host);
        w.always("port", self.port);
        w.bytes("sha256", &self.sha256);
        w.bytes("der", &self.der);
        w.text("subject", &self.subject);
        w.opt("added_at", self.added_at);
    }
}

// ------------------------------------------------------------------- ssh key

/// A private SSH key stored in the vault; sites reference it by id.
#[derive(Debug, Clone)]
pub struct SshKey {
    /// `label`
    pub label: String,
    /// `algorithm`, e.g. `ssh-ed25519`.
    pub algorithm: String,
    /// `public_key`: OpenSSH public key line.
    pub public_key: String,
    /// `private_key`: OpenSSH (or PuTTY) private key text.
    pub private_key: SecretString,
    /// `passphrase`, stored so the user isn't asked.
    pub passphrase: Option<SecretString>,
    /// The body's schema is newer than this build.
    pub read_only: bool,
}

impl ItemView for SshKey {
    const KIND: ItemKind = ItemKind::SshKey;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, Self::KIND)?;
        let r = Reader::new(body);
        Ok(Self {
            label: r.str("label")?,
            algorithm: r.str("algorithm")?,
            public_key: r.str("public_key")?,
            private_key: r
                .opt_secret("private_key")?
                .unwrap_or_else(|| SecretString::from(String::new())),
            passphrase: r.opt_secret("passphrase")?,
            read_only,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        use secrecy::ExposeSecret;
        let mut w = Writer::new(body, clock, device);
        w.text("label", &self.label);
        w.text("algorithm", &self.algorithm);
        w.text("public_key", &self.public_key);
        w.text("private_key", self.private_key.expose_secret());
        w.opt_secret("passphrase", self.passphrase.as_ref());
    }
}

// ------------------------------------------------------------------- proxy credential

/// Proxy user and password, referenced from settings by item id.
#[derive(Debug, Clone, Default)]
pub struct ProxyCredential {
    /// `label`
    pub label: String,
    /// `user`
    pub user: String,
    /// `password`
    pub password: Option<SecretString>,
    /// The body's schema is newer than this build.
    pub read_only: bool,
}

impl ItemView for ProxyCredential {
    const KIND: ItemKind = ItemKind::ProxyCredential;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, Self::KIND)?;
        let r = Reader::new(body);
        Ok(Self {
            label: r.str("label")?,
            user: r.str("user")?,
            password: r.opt_secret("password")?,
            read_only,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("label", &self.label);
        w.text("user", &self.user);
        w.opt_secret("password", self.password.as_ref());
    }
}

// ------------------------------------------------------------------- credential override

/// A member's own credentials for a site in a team vault (T89). Stored in the
/// member's personal vault, keyed by the shared site's id: the one allowed
/// cross-vault reference. `None` fields fall back to the shared site's values.
#[derive(Debug, Clone)]
pub struct CredentialOverride {
    /// `shared_site_id` (required).
    pub shared_site_id: ItemId,
    /// `user`
    pub user: Option<String>,
    /// `password`
    pub password: Option<SecretString>,
    /// `key_id`: an `ssh-key` item in the personal vault.
    pub key_id: Option<ItemId>,
    /// `passphrase` of that key.
    pub passphrase: Option<SecretString>,
    /// The body's schema is newer than this build.
    pub read_only: bool,
}

impl CredentialOverride {
    /// An empty override for `shared_site_id`.
    pub fn new(shared_site_id: ItemId) -> Self {
        Self {
            shared_site_id,
            user: None,
            password: None,
            key_id: None,
            passphrase: None,
            read_only: false,
        }
    }

    /// Whether it overrides nothing (the UI deletes it instead).
    pub fn is_empty(&self) -> bool {
        self.user.as_deref().is_none_or(str::is_empty)
            && self.password.is_none()
            && self.key_id.is_none()
            && self.passphrase.is_none()
    }
}

impl ItemView for CredentialOverride {
    const KIND: ItemKind = ItemKind::CredentialOverride;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, Self::KIND)?;
        let r = Reader::new(body);
        Ok(Self {
            shared_site_id: r.req_id("shared_site_id")?,
            user: r.opt_str("user")?.filter(|u| !u.is_empty()),
            password: r.opt_secret("password")?,
            key_id: r.opt_id("key_id")?,
            passphrase: r.opt_secret("passphrase")?,
            read_only,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.always("shared_site_id", self.shared_site_id);
        w.opt("user", self.user.clone().filter(|u| !u.is_empty()));
        w.opt_secret("password", self.password.as_ref());
        w.opt("key_id", self.key_id);
        w.opt_secret("passphrase", self.passphrase.as_ref());
    }
}

// ------------------------------------------------------------------- history entry

/// A quickconnect history entry (T33).
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    /// `protocol`
    pub protocol: Protocol,
    /// `host`
    pub host: String,
    /// `port`
    pub port: Option<u16>,
    /// `logon.type`
    pub logon: LogonKind,
    /// `logon.user`
    pub user: String,
    /// `logon.password` (only when `vault.store_passwords` is on).
    pub password: Option<SecretString>,
    /// `used_at`
    pub used_at: Option<UnixMillis>,
    /// The body's schema is newer than this build.
    pub read_only: bool,
}

impl HistoryEntry {
    /// An entry with every other field at its default.
    pub fn new(protocol: Protocol, host: impl Into<String>) -> Self {
        Self {
            protocol,
            host: host.into(),
            port: None,
            logon: LogonKind::default(),
            user: String::new(),
            password: None,
            used_at: None,
            read_only: false,
        }
    }
}

impl ItemView for HistoryEntry {
    const KIND: ItemKind = ItemKind::HistoryEntry;

    fn from_body(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, Self::KIND)?;
        let r = Reader::new(body);
        Ok(Self {
            protocol: r.req_enum("protocol")?,
            host: r.str("host")?,
            port: r.int("port")?,
            logon: r.enum_or_default("logon.type")?,
            user: r.str("logon.user")?,
            password: r.opt_secret("logon.password")?,
            used_at: read_time(&r, "used_at")?,
            read_only,
        })
    }

    fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.always("protocol", self.protocol.as_wire());
        w.text("host", &self.host);
        w.opt("port", self.port);
        w.always("logon.type", self.logon.as_wire());
        w.text("logon.user", &self.user);
        w.opt_secret("logon.password", self.password.as_ref());
        w.opt("used_at", self.used_at);
    }
}
