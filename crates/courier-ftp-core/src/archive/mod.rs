//! Moving a whole setup to another machine (T73): settings, sites and
//! bookmarks, history, trusted host keys and certificates, and the queue in
//! one passphrase-protected `.cftp-backup` file, plus a plain JSON export of
//! the settings alone.
//!
//! # The archive
//!
//! The file is T30's backup container ([`crate::vault::backup`]: JSON header,
//! Argon2id, XChaCha20-Poly1305 over zstd, format `courier-ftp-backup`), and
//! its payload is a CBOR map of sections:
//!
//! ```text
//! {"version": 1, "sections": {
//!    "settings": {"config": "<JSON: settings, keybindings, styles>",
//!                 "items": [<proxy credential items>]},
//!    "sites":    {"passwords": bool, "items": [<sites, folders, bookmarks, SSH keys>]},
//!    "history":  {"items": [<history entries>]},
//!    "trust":    {"items": [<known hosts, trusted certificates>]},
//!    "queue":    {"json": "<T40 queue export>"}}}
//! ```
//!
//! Items are encoded as in T30 (`{id, vault_id, body}`), so they keep their
//! ids and field stamps and restore by merging. A payload that is a plain
//! item list (what `VaultEngine::export_backup` writes) reads as an archive
//! whose items are sorted into sections by kind. Unknown sections (from a
//! newer courier-ftp) are skipped with a warning.
//!
//! # The plain settings export
//!
//! ```json
//! {"format":"courier-ftp-settings","version":1,"exported_at":1760054400000,
//!  "settings":{…},"keybindings":{…},"styles":{…}}
//! ```
//!
//! Only settings that differ from the defaults are written, and nothing
//! secret: proxy passwords live in the vault, and their item references are
//! left out.
//!
//! [`restore`] brings an archive into a vault and a config directory.

pub mod restore;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::path::Path;

use ciborium::Value;
use courier_ftp_crypto::kdf::Argon2Cost;
use rand_core::CryptoRng;
use secrecy::SecretString;
use serde_json::{Map, Value as Json};
use zeroize::Zeroizing;

use crate::model::item::{ItemKind, UnixMillis, is_secret_field};
use crate::settings::{Settings, read_user_config};
use crate::vault::backup::{self, BackupError, BackupItem};
use crate::vault::{ItemVault, VaultError};

pub use restore::{
    ImportChoice, RestoreReport, SettingsMode, SitesMode, apply_settings, queue_items,
    restore_items,
};

/// The payload version this build writes.
pub const PAYLOAD_VERSION: u32 = 1;
/// The `format` of the plain settings export.
pub const SETTINGS_FORMAT: &str = "courier-ftp-settings";
/// The plain settings export version this build writes.
pub const SETTINGS_VERSION: u32 = 1;
/// The largest plain settings export accepted (4 MiB).
pub const MAX_SETTINGS_JSON: usize = 4 << 20;

/// A part of the setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Section {
    /// The config: settings (filters included), keybindings and styles,
    /// with the proxy credentials the settings point at.
    Settings,
    /// Site Manager sites and folders, bookmarks and vault SSH keys.
    Sites,
    /// The quickconnect history.
    History,
    /// Trusted SSH host keys and TLS certificates.
    Trust,
    /// The transfer queue (T40's export, without passwords).
    Queue,
}

impl Section {
    /// Every section, in display order.
    pub const ALL: [Section; 5] = [
        Section::Settings,
        Section::Sites,
        Section::History,
        Section::Trust,
        Section::Queue,
    ];

    /// The key in the payload.
    pub fn key(self) -> &'static str {
        match self {
            Section::Settings => "settings",
            Section::Sites => "sites",
            Section::History => "history",
            Section::Trust => "trust",
            Section::Queue => "queue",
        }
    }

    fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.key() == key)
    }

    /// The name shown to the user.
    pub fn title(self) -> &'static str {
        match self {
            Section::Settings => "Settings",
            Section::Sites => "Sites and bookmarks",
            Section::History => "Connection history",
            Section::Trust => "Trusted host keys and certificates",
            Section::Queue => "Transfer queue",
        }
    }

    /// The vault item kinds the section carries.
    pub fn kinds(self) -> &'static [ItemKind] {
        match self {
            Section::Settings => &[ItemKind::ProxyCredential],
            Section::Sites => &[
                ItemKind::SiteFolder,
                ItemKind::Site,
                ItemKind::Bookmark,
                ItemKind::SshKey,
                ItemKind::CredentialOverride,
            ],
            Section::History => &[ItemKind::HistoryEntry],
            Section::Trust => &[ItemKind::KnownHost, ItemKind::TrustedCert],
            Section::Queue => &[],
        }
    }

    /// The section an item kind belongs to.
    pub fn of_kind(kind: ItemKind) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.kinds().contains(&kind))
    }
}

/// The user config without secrets: the settings that differ from the
/// defaults, and the `keybindings` and `styles` keys of `config.json`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SettingsDoc {
    /// The `settings` key (non-default values only).
    pub settings: Option<Json>,
    /// The `keybindings` key.
    pub keybindings: Option<Json>,
    /// The `styles` key.
    pub styles: Option<Json>,
}

impl SettingsDoc {
    /// `settings` (what is in effect) with the keybindings and styles of
    /// `config.json` in `config_dir`.
    ///
    /// # Errors
    /// When `config.json` can't be read or isn't a JSON object.
    pub fn from_config(settings: &Settings, config_dir: Option<&Path>) -> crate::Result<Self> {
        let file = match config_dir {
            Some(dir) if !dir.as_os_str().is_empty() => read_user_config(dir)?,
            _ => Map::new(),
        };
        Ok(Self {
            settings: settings.user_value()?,
            keybindings: file.get("keybindings").cloned(),
            styles: file.get("styles").cloned(),
        })
    }

    /// As a JSON object (keys that are `None` left out).
    pub fn to_json(&self) -> Map<String, Json> {
        let mut out = Map::new();
        for (key, value) in [
            ("settings", &self.settings),
            ("keybindings", &self.keybindings),
            ("styles", &self.styles),
        ] {
            if let Some(v) = value {
                out.insert(key.to_owned(), v.clone());
            }
        }
        out
    }

    fn from_json(obj: &Map<String, Json>) -> Self {
        let get = |key: &str| obj.get(key).filter(|v| v.is_object()).cloned();
        Self {
            settings: get("settings"),
            keybindings: get("keybindings"),
            styles: get("styles"),
        }
    }

    /// Without references to vault items (proxy passwords), for the plain
    /// export.
    pub fn without_secrets(&self) -> Self {
        fn strip(v: &mut Json) {
            match v {
                Json::Object(map) => {
                    map.retain(|k, _| k != "password_ref" && !is_secret_field(k));
                    map.values_mut().for_each(strip);
                }
                Json::Array(list) => list.iter_mut().for_each(strip),
                _ => {}
            }
        }
        let mut out = self.clone();
        if let Some(s) = out.settings.as_mut() {
            strip(s);
        }
        out
    }

    /// Whether a value is set.
    pub fn is_empty(&self) -> bool {
        self.settings.is_none() && self.keybindings.is_none() && self.styles.is_none()
    }
}

/// What to put into an archive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportChoice {
    /// The config, with the proxy credentials it uses.
    pub settings: bool,
    /// Sites, folders, bookmarks, vault SSH keys.
    pub sites: bool,
    /// Include passwords, passphrases and vault SSH keys with the sites.
    pub passwords: bool,
    /// Quickconnect history.
    pub history: bool,
    /// Trusted host keys and certificates.
    pub trust: bool,
    /// The transfer queue.
    pub queue: bool,
}

impl ExportChoice {
    /// Everything, passwords included.
    pub const ALL: ExportChoice = ExportChoice {
        settings: true,
        sites: true,
        passwords: true,
        history: true,
        trust: true,
        queue: true,
    };

    /// Whether `section` is chosen.
    pub fn has(&self, section: Section) -> bool {
        match section {
            Section::Settings => self.settings,
            Section::Sites => self.sites,
            Section::History => self.history,
            Section::Trust => self.trust,
            Section::Queue => self.queue,
        }
    }

    /// Whether a chosen section is read from the vault.
    pub fn needs_vault(&self) -> bool {
        self.sites || self.history || self.trust
    }
}

/// An archive's contents (decrypted: the items hold secrets, which their
/// `Debug` redacts).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Archive {
    /// When it was written (UNIX ms).
    pub created_at: i64,
    /// The payload version it was written with.
    pub version: u32,
    /// The config.
    pub settings: Option<SettingsDoc>,
    /// Vault items by section ([`Section::Queue`] has none).
    pub items: BTreeMap<Section, Vec<BackupItem>>,
    /// The sites section includes passwords and vault SSH keys.
    pub passwords: bool,
    /// The queue export (JSON).
    pub queue: Option<String>,
    /// What was skipped while reading (unknown sections, misplaced items).
    pub warnings: Vec<String>,
}

impl Archive {
    /// An empty archive dated `created_at`.
    pub fn new(created_at: i64) -> Self {
        Self {
            created_at,
            version: PAYLOAD_VERSION,
            ..Self::default()
        }
    }

    /// The sections it holds, in display order.
    pub fn sections(&self) -> Vec<Section> {
        Section::ALL.into_iter().filter(|s| self.has(*s)).collect()
    }

    /// Whether it holds `section`.
    pub fn has(&self, section: Section) -> bool {
        match section {
            Section::Settings => self.settings.is_some(),
            Section::Queue => self.queue.is_some(),
            other => self.items.contains_key(&other),
        }
    }

    /// The items of `section`.
    pub fn items_of(&self, section: Section) -> &[BackupItem] {
        self.items.get(&section).map_or(&[], Vec::as_slice)
    }

    /// The number of items of `kind`.
    pub fn count(&self, kind: ItemKind) -> usize {
        self.items
            .values()
            .flatten()
            .filter(|i| i.body.kind == kind)
            .count()
    }

    /// What `section` holds, e.g. "3 sites, 1 folder, 2 bookmarks".
    pub fn describe(&self, section: Section) -> String {
        let n = |kind| self.count(kind);
        let parts: Vec<String> = match section {
            Section::Settings => {
                let mut parts = Vec::new();
                if let Some(doc) = &self.settings {
                    let changed = doc
                        .settings
                        .as_ref()
                        .and_then(Json::as_object)
                        .map_or(0, |m| m.len());
                    parts.push(plural(changed, "changed group", "changed groups"));
                    if doc.keybindings.is_some() {
                        parts.push("keybindings".to_owned());
                    }
                    if doc.styles.is_some() {
                        parts.push("styles".to_owned());
                    }
                }
                let proxies = n(ItemKind::ProxyCredential);
                if proxies > 0 {
                    parts.push(plural(proxies, "proxy password", "proxy passwords"));
                }
                parts
            }
            Section::Sites => {
                let mut parts = vec![
                    plural(n(ItemKind::Site), "site", "sites"),
                    plural(n(ItemKind::SiteFolder), "folder", "folders"),
                    plural(n(ItemKind::Bookmark), "bookmark", "bookmarks"),
                ];
                let keys = n(ItemKind::SshKey);
                if keys > 0 {
                    parts.push(plural(keys, "SSH key", "SSH keys"));
                }
                parts.push(if self.passwords {
                    "with passwords".to_owned()
                } else {
                    "without passwords".to_owned()
                });
                parts
            }
            Section::History => vec![plural(n(ItemKind::HistoryEntry), "entry", "entries")],
            Section::Trust => vec![
                plural(n(ItemKind::KnownHost), "host key", "host keys"),
                plural(n(ItemKind::TrustedCert), "certificate", "certificates"),
            ],
            Section::Queue => {
                let items = self
                    .queue
                    .as_deref()
                    .and_then(|q| serde_json::from_str::<Json>(q).ok())
                    .and_then(|v| v.get("items").and_then(Json::as_array).map(Vec::len))
                    .unwrap_or(0);
                vec![plural(items, "item", "items")]
            }
        };
        parts.join(", ")
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Reads the vault items `choice` asks for. Without `passwords`, secret
/// fields are removed from every site-section item and vault SSH keys are
/// left out (a site using one then asks for its credentials).
///
/// # Errors
/// [`VaultError::Locked`] and other vault errors.
pub async fn collect_items(
    vault: &dyn ItemVault,
    choice: &ExportChoice,
) -> Result<BTreeMap<Section, Vec<BackupItem>>, VaultError> {
    let mut out = BTreeMap::new();
    for section in [
        Section::Settings,
        Section::Sites,
        Section::History,
        Section::Trust,
    ] {
        if !choice.has(section) {
            continue;
        }
        let mut items = Vec::new();
        for kind in section.kinds() {
            if section == Section::Sites && !choice.passwords && *kind == ItemKind::SshKey {
                continue;
            }
            for item in vault.list(*kind).await? {
                let mut body = item.body;
                if section == Section::Sites && !choice.passwords {
                    body.fields.retain(|k, _| !is_secret_field(k));
                }
                items.push(BackupItem {
                    id: item.id,
                    vault_id: item.vault_id,
                    body,
                });
            }
        }
        out.insert(section, items);
    }
    Ok(out)
}

// ------------------------------------------------------------------ encoding

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

/// Seals `archive` with `password` (Argon2id `cost`).
///
/// **CPU- and memory-heavy** (Argon2): async callers use `spawn_blocking`.
///
/// # Errors
/// [`BackupError::Corrupt`] if something can't be encoded,
/// [`BackupError::Format`] for invalid KDF parameters.
pub fn seal<R: CryptoRng + ?Sized>(
    archive: &Archive,
    password: &SecretString,
    cost: Argon2Cost,
    rng: &mut R,
) -> Result<Vec<u8>, BackupError> {
    let corrupt = |e: &dyn std::fmt::Display| BackupError::Corrupt(e.to_string());
    let mut sections = Vec::new();
    let mut count = 0u64;
    for section in Section::ALL {
        let mut fields = Vec::new();
        match section {
            Section::Settings => {
                let Some(doc) = &archive.settings else {
                    continue;
                };
                let json = serde_json::to_string(&doc.to_json()).map_err(|e| corrupt(&e))?;
                fields.push((text("config"), Value::Text(json)));
            }
            Section::Queue => {
                let Some(json) = &archive.queue else {
                    continue;
                };
                fields.push((text("json"), Value::Text(json.clone())));
            }
            Section::Sites => {
                if !archive.items.contains_key(&section) {
                    continue;
                }
                fields.push((text("passwords"), Value::Bool(archive.passwords)));
            }
            _ => {
                if !archive.items.contains_key(&section) {
                    continue;
                }
            }
        }
        if let Some(items) = archive.items.get(&section) {
            count += items.len() as u64;
            fields.push((text("items"), backup::encode_items(items)?));
        }
        sections.push((text(section.key()), Value::Map(fields)));
    }
    let payload = Value::Map(vec![
        (text("version"), Value::from(PAYLOAD_VERSION)),
        (text("sections"), Value::Map(sections)),
    ]);
    let mut cbor = Zeroizing::new(Vec::new());
    ciborium::into_writer(&payload, &mut *cbor).map_err(|e| corrupt(&e))?;
    backup::seal_payload(
        backup::FORMAT,
        backup::AAD_LABEL,
        &cbor,
        count,
        password,
        cost,
        archive.created_at,
        rng,
    )
}

/// Whether `file` starts like a `.cftp-backup` (header only, nothing
/// decrypted).
pub fn is_backup(file: &[u8]) -> bool {
    backup::peek(file).is_ok()
}

/// Opens a `.cftp-backup` with `password`.
///
/// **CPU- and memory-heavy** (Argon2): async callers use `spawn_blocking`.
///
/// # Errors
/// [`BackupError::Format`] (not a backup, KDF parameters out of bounds),
/// [`BackupError::Decrypt`] (wrong password or a modified file),
/// [`BackupError::TooLarge`], [`BackupError::Corrupt`].
pub fn open(file: &[u8], password: &SecretString) -> Result<Archive, BackupError> {
    let (created_at, _) = backup::peek(file)?;
    let payload = backup::open_payload(
        file,
        backup::FORMAT,
        backup::AAD_LABEL,
        password,
        backup::MAX_DECOMPRESSED,
    )?;
    decode(&payload, created_at)
}

fn decode(payload: &[u8], created_at: i64) -> Result<Archive, BackupError> {
    let bad = |what: &str| BackupError::Corrupt(what.to_owned());
    let value: Value = ciborium::from_reader(payload).map_err(|_| bad("payload is not CBOR"))?;
    let mut archive = Archive::new(created_at);
    let map = match value {
        // T30's item list (`VaultEngine::export_backup`).
        Value::Array(list) => {
            archive.passwords = true;
            for item in backup::decode_item_list(list)? {
                match Section::of_kind(item.body.kind) {
                    Some(section) => archive.items.entry(section).or_default().push(item),
                    None => archive
                        .warnings
                        .push(format!("Skipped an item of kind {}", item.body.kind)),
                }
            }
            return Ok(archive);
        }
        Value::Map(map) => map,
        _ => return Err(bad("payload is not a map")),
    };
    archive.version = get(&map, "version")
        .and_then(Value::as_integer)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| bad("no version"))?;
    if archive.version > PAYLOAD_VERSION {
        archive.warnings.push(format!(
            "The backup was made by a newer courier-ftp (format {}); parts it added are skipped",
            archive.version
        ));
    }
    let Some(Value::Map(sections)) = get(&map, "sections") else {
        return Err(bad("no sections"));
    };
    for (key, body) in sections {
        let key = key.as_text().unwrap_or("?");
        let Some(section) = Section::from_key(key) else {
            archive.warnings.push(format!(
                "Skipped section “{key}” (from a newer courier-ftp)"
            ));
            continue;
        };
        let Value::Map(fields) = body else {
            return Err(bad("section is not a map"));
        };
        match section {
            Section::Settings => {
                let json = get(fields, "config")
                    .and_then(Value::as_text)
                    .ok_or_else(|| bad("settings without config"))?;
                let obj: Map<String, Json> =
                    serde_json::from_str(json).map_err(|_| bad("settings are not JSON"))?;
                archive.settings = Some(SettingsDoc::from_json(&obj));
            }
            Section::Queue => {
                let json = get(fields, "json")
                    .and_then(Value::as_text)
                    .ok_or_else(|| bad("queue without json"))?;
                archive.queue = Some(json.to_owned());
                continue;
            }
            Section::Sites => {
                archive.passwords = get(fields, "passwords")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            }
            Section::History | Section::Trust => {}
        }
        let items = match get(fields, "items") {
            Some(Value::Array(list)) => backup::decode_item_list(list.clone())?,
            Some(_) => return Err(bad("items are not a list")),
            None => Vec::new(),
        };
        let (fit, misplaced): (Vec<_>, Vec<_>) = items
            .into_iter()
            .partition(|i| section.kinds().contains(&i.body.kind));
        if !misplaced.is_empty() {
            archive.warnings.push(format!(
                "Skipped {} in “{key}”",
                plural(misplaced.len(), "unexpected item", "unexpected items")
            ));
        }
        if section != Section::Settings || !fit.is_empty() {
            archive.items.insert(section, fit);
        }
    }
    Ok(archive)
}

// ------------------------------------------------------------ plain settings

/// The plain settings export (no secrets, see the module docs).
pub fn settings_to_json(doc: &SettingsDoc, now: UnixMillis) -> String {
    let mut obj = Map::new();
    obj.insert("format".to_owned(), Json::from(SETTINGS_FORMAT));
    obj.insert("version".to_owned(), Json::from(SETTINGS_VERSION));
    obj.insert("exported_at".to_owned(), Json::from(now.0));
    obj.extend(doc.without_secrets().to_json());
    let mut text = serde_json::to_string_pretty(&Json::Object(obj)).unwrap_or_default();
    text.push('\n');
    text
}

/// Whether `bytes` look like a plain settings export.
pub fn is_settings_json(bytes: &[u8]) -> bool {
    bytes.len() <= MAX_SETTINGS_JSON
        && serde_json::from_slice::<Json>(bytes)
            .ok()
            .and_then(|v| v.get("format").and_then(Json::as_str).map(str::to_owned))
            .is_some_and(|f| f == SETTINGS_FORMAT)
}

/// Reads a plain settings export as an archive with only settings.
///
/// # Errors
/// [`BackupError::Format`] when it isn't one, [`BackupError::TooLarge`].
pub fn parse_settings_json(bytes: &[u8]) -> Result<Archive, BackupError> {
    if bytes.len() > MAX_SETTINGS_JSON {
        return Err(BackupError::TooLarge);
    }
    let bad = |what: &str| BackupError::Format(what.to_owned());
    let value: Json = serde_json::from_slice(bytes).map_err(|_| bad("not JSON"))?;
    let obj = value.as_object().ok_or_else(|| bad("not a JSON object"))?;
    if obj.get("format").and_then(Json::as_str) != Some(SETTINGS_FORMAT) {
        return Err(bad("not a courier-ftp settings export"));
    }
    let version = obj.get("version").and_then(Json::as_u64).unwrap_or(0);
    let mut archive = Archive::new(
        obj.get("exported_at")
            .and_then(Json::as_i64)
            .unwrap_or_default(),
    );
    if version > u64::from(SETTINGS_VERSION) {
        archive.warnings.push(format!(
            "The file was made by a newer courier-ftp (version {version}); unknown settings are skipped"
        ));
    }
    for key in obj.keys() {
        if ![
            "format",
            "version",
            "exported_at",
            "settings",
            "keybindings",
            "styles",
        ]
        .contains(&key.as_str())
        {
            archive
                .warnings
                .push(format!("Skipped “{key}” (from a newer courier-ftp)"));
        }
    }
    archive.settings = Some(SettingsDoc::from_json(obj).without_secrets());
    Ok(archive)
}
