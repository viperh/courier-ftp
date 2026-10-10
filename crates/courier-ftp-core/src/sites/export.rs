//! Exporting sites (T32): courier-ftp's own JSON format, plain or
//! passphrase-encrypted, and FileZilla `sitemanager.xml` (without
//! passwords) for users moving back.
//!
//! # The courier-ftp export format
//!
//! A JSON document (`.json`):
//!
//! ```json
//! {"format":"courier-ftp-sites","version":1,"exported_at":1760054400000,"passwords":false,
//!  "nodes":[{"type":"folder","id":"…","name":"Work","children":[
//!            {"type":"site","id":"…","name":"web01","protocol":"sftp","host":"web01.example.com",
//!             "logon":{"type":"ask_for_password","user":"deploy"}, "bookmarks":[…], …}]}]}
//! ```
//!
//! Enum values are the item wire strings ([`crate::model::item`]).
//!
//! - **Without passwords** the file is plain JSON and holds no secret:
//!   passwords, the FTP account, key passphrases and vault SSH keys are
//!   left out, and logins that need them become "ask for password" (a key
//!   file on disk is kept: its path is not a secret).
//! - **With passwords** the JSON (secrets and vault SSH keys included) is
//!   sealed with a passphrase: `CFTPEXP\0` then T30's backup container
//!   ([`crate::vault::backup`]: JSON header, Argon2id, XChaCha20-Poly1305
//!   over zstd) with format `courier-ftp-export`.
//!
//! [`ExportScope`] picks a site, a folder or everything; [`collect`] gathers
//! it with its site bookmarks and vault keys.

use std::collections::HashMap;

use courier_ftp_crypto::kdf::Argon2Cost;
use rand_core::CryptoRng;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::model::item::{
    self, ItemId, LogonKind, ServerType, SiteColor, SiteTransferMode, SshKey, UnixMillis, WireEnum,
};
use crate::model::{Charset, FtpEncryption, LocalPath, Protocol, RemotePath};
use crate::vault::ItemVaultExt;
use crate::vault::backup::{self, BackupError};

use super::filezilla::{self, XmlNode};
use super::import::{ImportBookmark, ImportError, ImportNode, ImportSite, ImportTree};
use super::{Site, SiteError, SiteKey, SiteLogon, SiteManager, SiteNode};

/// The first bytes of an encrypted export.
pub const ENCRYPTED_MAGIC: &[u8] = b"CFTPEXP\0";
/// The `format` of the JSON document.
pub const FORMAT: &str = "courier-ftp-sites";
/// The JSON format version this build writes and reads.
pub const VERSION: u32 = 1;
/// The container format name of encrypted exports.
pub const CONTAINER_FORMAT: &str = "courier-ftp-export";
/// The AAD label of encrypted exports.
pub const AAD_LABEL: &[u8] = b"courier-ftp-export-v1";
/// The largest export accepted on import (64 MiB, decompressed).
pub const MAX_EXPORT_LEN: usize = 64 << 20;

/// What to export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportScope {
    /// One site.
    Site(ItemId),
    /// A folder with everything in it (the folder itself included).
    Folder(ItemId),
    /// The whole tree.
    All,
}

/// The sites to export, gathered from the vault by [`collect`].
#[derive(Debug, Clone, Default)]
pub struct ExportSet {
    nodes: Vec<SiteNode>,
    bookmarks: HashMap<ItemId, Vec<ImportBookmark>>,
    keys: HashMap<ItemId, SshKey>,
}

impl ExportSet {
    /// `(folders, sites)` to export.
    pub fn count(&self) -> (usize, usize) {
        self.nodes.iter().fold((0, 0), |(f, s), n| {
            let (a, b) = n.count();
            (f + a, s + b)
        })
    }
}

/// Gathers `scope` from `sites`, with the site bookmarks and the vault SSH
/// keys the sites use.
///
/// # Errors
/// [`SiteError::NotFound`] for an unknown id, [`SiteError::NotAFolder`],
/// [`SiteError::Vault`].
pub async fn collect(sites: &SiteManager, scope: ExportScope) -> Result<ExportSet, SiteError> {
    let tree = sites.tree();
    let nodes: Vec<SiteNode> = match scope {
        ExportScope::All => tree.roots().to_vec(),
        ExportScope::Site(id) => {
            let site = tree.site(id).ok_or(SiteError::NotFound(id))?;
            vec![SiteNode::Site(Box::new(site.clone()))]
        }
        ExportScope::Folder(id) => {
            let folder = tree.get(id).ok_or(SiteError::NotFound(id))?;
            if !folder.is_folder() {
                return Err(SiteError::NotAFolder(id));
            }
            vec![folder.clone()]
        }
    };
    let site_ids: Vec<ItemId> = nodes
        .iter()
        .flat_map(SiteNode::walk)
        .filter_map(SiteNode::as_site)
        .map(|s| s.id)
        .collect();
    let mut bookmarks: HashMap<ItemId, Vec<(i64, ImportBookmark)>> = HashMap::new();
    for (_, b) in sites.vault().list_views::<item::Bookmark>().await? {
        let Some(site) = b.site_id.filter(|s| site_ids.contains(s)) else {
            continue;
        };
        bookmarks.entry(site).or_default().push((
            b.position.unwrap_or(0),
            ImportBookmark {
                name: b.name,
                local_dir: b.local_dir.filter(|d| !d.is_empty()).map(LocalPath::new),
                remote_dir: b.remote_dir.filter(|d| !d.is_empty()).map(RemotePath::new),
                sync_browsing: b.sync_browsing,
                comparison: b.comparison,
            },
        ));
    }
    let bookmarks = bookmarks
        .into_iter()
        .map(|(site, mut list)| {
            list.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.name.cmp(&b.1.name)));
            (site, list.into_iter().map(|(_, b)| b).collect())
        })
        .collect();
    let mut keys = HashMap::new();
    let wanted: Vec<ItemId> = nodes
        .iter()
        .flat_map(SiteNode::walk)
        .filter_map(SiteNode::as_site)
        .filter_map(Site::vault_key_id)
        .collect();
    if !wanted.is_empty() {
        for (id, key) in sites.ssh_keys().await? {
            if wanted.contains(&id) {
                keys.insert(id, key);
            }
        }
    }
    Ok(ExportSet {
        nodes,
        bookmarks,
        keys,
    })
}

/// The plain export: JSON without any secret.
///
/// # Errors
/// [`SiteError::Local`] if encoding fails (it doesn't in practice).
pub fn to_json(set: &ExportSet, now: UnixMillis) -> Result<String, SiteError> {
    let file = SitesFile::build(set, false, now);
    serde_json::to_string_pretty(&file).map_err(|e| SiteError::Local(e.to_string()))
}

/// The export with passwords, sealed with `passphrase` (Argon2id `cost`).
///
/// **CPU- and memory-heavy** (Argon2): async callers use `spawn_blocking`.
///
/// # Errors
/// [`SiteError::Local`] if sealing fails.
pub fn to_encrypted<R: CryptoRng + ?Sized>(
    set: &ExportSet,
    passphrase: &SecretString,
    cost: Argon2Cost,
    now: UnixMillis,
    rng: &mut R,
) -> Result<Vec<u8>, SiteError> {
    let file = SitesFile::build(set, true, now);
    let json =
        Zeroizing::new(serde_json::to_vec(&file).map_err(|e| SiteError::Local(e.to_string()))?);
    let (_, sites) = set.count();
    let sealed = backup::seal_payload(
        CONTAINER_FORMAT,
        AAD_LABEL,
        &json,
        sites as u64,
        passphrase,
        cost,
        now.0,
        rng,
    )
    .map_err(|e| SiteError::Local(e.to_string()))?;
    let mut out = ENCRYPTED_MAGIC.to_vec();
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// The export as a FileZilla `sitemanager.xml`, without passwords.
pub fn to_filezilla_xml(set: &ExportSet) -> String {
    fn node<'a>(n: &'a SiteNode, set: &ExportSet) -> XmlNode<'a> {
        match n {
            SiteNode::Folder(f) => {
                XmlNode::Folder(&f.name, f.children.iter().map(|c| node(c, set)).collect())
            }
            SiteNode::Site(s) => {
                XmlNode::Site(s, set.bookmarks.get(&s.id).cloned().unwrap_or_default())
            }
        }
    }
    let nodes: Vec<XmlNode<'_>> = set.nodes.iter().map(|n| node(n, set)).collect();
    filezilla::write_sitemanager(&nodes)
}

/// Opens an encrypted export and returns its JSON.
pub(super) fn open_encrypted(
    file: &[u8],
    passphrase: &SecretString,
) -> Result<Zeroizing<Vec<u8>>, ImportError> {
    let body = file
        .strip_prefix(ENCRYPTED_MAGIC)
        .ok_or_else(|| ImportError::Malformed("not an encrypted export".into()))?;
    backup::open_payload(
        body,
        CONTAINER_FORMAT,
        AAD_LABEL,
        passphrase,
        MAX_EXPORT_LEN as u64,
    )
    .map_err(|e| match e {
        BackupError::Decrypt => ImportError::WrongPassphrase,
        BackupError::TooLarge => ImportError::TooLarge,
        other => ImportError::Malformed(other.to_string()),
    })
}

// ------------------------------------------------------------------ JSON types

/// A secret in the JSON (encrypted exports only).
#[derive(Debug, Clone)]
struct Secret(SecretString);

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.0.expose_secret())
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = Zeroizing::new(String::deserialize(d)?);
        Ok(Self(SecretString::from(s.as_str().to_owned())))
    }
}

fn secret(s: Option<&SecretString>) -> Option<Secret> {
    s.map(|s| Secret(s.clone()))
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct SitesFile {
    format: String,
    version: u32,
    #[serde(default)]
    exported_at: i64,
    #[serde(default)]
    passwords: bool,
    #[serde(default)]
    nodes: Vec<FileNode>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum FileNode {
    Folder {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        name: String,
        #[serde(default)]
        children: Vec<FileNode>,
    },
    Site(Box<FileSite>),
}

#[derive(Debug, Serialize, Deserialize)]
struct FileSite {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    name: String,
    protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encryption: Option<String>,
    host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    logon: FileLogon,
    #[serde(default = "none")]
    color: String,
    #[serde(default)]
    comments: String,
    #[serde(default = "auto")]
    server_type: String,
    #[serde(default)]
    bypass_proxy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote_dir: Option<String>,
    #[serde(default)]
    sync_browsing: bool,
    #[serde(default)]
    directory_comparison: bool,
    #[serde(default)]
    timezone_offset_minutes: i32,
    #[serde(default = "default_mode")]
    transfer_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limit_connections: Option<u8>,
    #[serde(default = "auto")]
    charset: String,
    #[serde(default)]
    try_agent_first: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    bookmarks: Vec<FileBookmark>,
}

fn none() -> String {
    "none".into()
}
fn auto() -> String {
    "auto".into()
}
fn default_mode() -> String {
    "default".into()
}

#[derive(Debug, Serialize, Deserialize)]
struct FileLogon {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passphrase: Option<Secret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vault_key: Option<FileKey>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileKey {
    label: String,
    #[serde(default)]
    algorithm: String,
    #[serde(default)]
    public_key: String,
    private_key: Secret,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passphrase: Option<Secret>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileBookmark {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote_dir: Option<String>,
    #[serde(default)]
    sync_browsing: bool,
    #[serde(default)]
    comparison: bool,
}

fn local_text(p: &LocalPath) -> String {
    p.as_path().to_string_lossy().into_owned()
}

impl SitesFile {
    fn build(set: &ExportSet, passwords: bool, now: UnixMillis) -> Self {
        Self {
            format: FORMAT.to_owned(),
            version: VERSION,
            exported_at: now.0,
            passwords,
            nodes: set
                .nodes
                .iter()
                .map(|n| FileNode::build(n, set, passwords))
                .collect(),
        }
    }

    pub(super) fn into_tree(self) -> Result<ImportTree, ImportError> {
        if self.format != FORMAT {
            return Err(ImportError::Malformed("not a courier-ftp export".into()));
        }
        if self.version != VERSION {
            return Err(ImportError::Malformed(format!(
                "unsupported export version {}",
                self.version
            )));
        }
        let mut tree = ImportTree::default();
        tree.nodes = into_nodes(self.nodes, "", 0, &mut tree.skipped)?;
        Ok(tree)
    }
}

/// The deepest folder nesting accepted on import.
const MAX_DEPTH: usize = 64;

fn into_nodes(
    nodes: Vec<FileNode>,
    path: &str,
    depth: usize,
    skipped: &mut Vec<super::import::Skipped>,
) -> Result<Vec<ImportNode>, ImportError> {
    if depth > MAX_DEPTH {
        return Err(ImportError::Malformed("folders nested too deeply".into()));
    }
    let mut out = Vec::new();
    for n in nodes {
        match n {
            FileNode::Folder { id, name, children } => {
                let here = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}/{name}")
                };
                out.push(ImportNode::Folder {
                    id: id.as_deref().and_then(|i| i.parse().ok()),
                    children: into_nodes(children, &here, depth + 1, skipped)?,
                    name,
                });
            }
            FileNode::Site(s) => {
                let name = s.name.clone();
                match s.into_site() {
                    Ok(site) => out.push(ImportNode::Site(Box::new(site))),
                    Err(reason) => skipped.push(super::import::Skipped {
                        path: if path.is_empty() {
                            name
                        } else {
                            format!("{path}/{name}")
                        },
                        reason,
                    }),
                }
            }
        }
    }
    Ok(out)
}

impl FileNode {
    fn build(node: &SiteNode, set: &ExportSet, passwords: bool) -> Self {
        match node {
            SiteNode::Folder(f) => FileNode::Folder {
                id: Some(f.id.to_string()),
                name: f.name.clone(),
                children: f
                    .children
                    .iter()
                    .map(|c| FileNode::build(c, set, passwords))
                    .collect(),
            },
            SiteNode::Site(s) => FileNode::Site(Box::new(FileSite::build(s, set, passwords))),
        }
    }
}

impl FileSite {
    fn build(s: &Site, set: &ExportSet, passwords: bool) -> Self {
        let logon = if passwords {
            s.logon.clone()
        } else {
            strip_logon(&s.logon)
        };
        let mut l = FileLogon {
            kind: logon.kind().as_wire().to_owned(),
            user: logon.user().to_owned(),
            password: None,
            account: None,
            key_path: None,
            passphrase: None,
            vault_key: None,
        };
        match &logon {
            SiteLogon::Normal { password, .. } => l.password = secret(password.as_ref()),
            SiteLogon::Account {
                password, account, ..
            } => {
                l.password = secret(password.as_ref());
                l.account = Some(account.clone()).filter(|a| !a.is_empty());
            }
            SiteLogon::KeyFile {
                key, passphrase, ..
            } => {
                l.passphrase = secret(passphrase.as_ref());
                match key {
                    Some(SiteKey::File(p)) => l.key_path = Some(local_text(p)),
                    Some(SiteKey::Vault(id)) => {
                        l.vault_key = set.keys.get(id).map(|k| FileKey {
                            label: k.label.clone(),
                            algorithm: k.algorithm.clone(),
                            public_key: k.public_key.clone(),
                            private_key: Secret(k.private_key.clone()),
                            passphrase: secret(k.passphrase.as_ref()),
                        });
                    }
                    None => {}
                }
            }
            SiteLogon::Anonymous
            | SiteLogon::AskForPassword { .. }
            | SiteLogon::Interactive { .. }
            | SiteLogon::Agent { .. } => {}
        }
        Self {
            id: Some(s.id.to_string()),
            name: s.name.clone(),
            protocol: s.protocol.as_wire().to_owned(),
            encryption: s
                .encryption
                .filter(|_| s.protocol != Protocol::Sftp)
                .map(|e| e.as_wire().to_owned()),
            host: s.host.clone(),
            port: s.port,
            logon: l,
            color: s.color.as_wire().to_owned(),
            comments: s.comments.clone(),
            server_type: s.server_type.as_wire().to_owned(),
            bypass_proxy: s.bypass_proxy,
            local_dir: s.default_local_dir.as_ref().map(local_text),
            remote_dir: s.default_remote_dir.as_ref().map(|p| p.as_str().to_owned()),
            sync_browsing: s.sync_browsing,
            directory_comparison: s.directory_comparison,
            timezone_offset_minutes: s.timezone_offset_minutes,
            transfer_mode: s.transfer_mode.as_wire().to_owned(),
            limit_connections: s.limit_connections,
            charset: s.charset.label().to_owned(),
            try_agent_first: s.try_agent_first,
            created_at: s.created_at.map(|t| t.0),
            bookmarks: set
                .bookmarks
                .get(&s.id)
                .map(|list| {
                    list.iter()
                        .map(|b| FileBookmark {
                            name: b.name.clone(),
                            local_dir: b.local_dir.as_ref().map(local_text),
                            remote_dir: b.remote_dir.as_ref().map(|p| p.as_str().to_owned()),
                            sync_browsing: b.sync_browsing,
                            comparison: b.comparison,
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    fn into_site(self) -> Result<ImportSite, String> {
        fn wire<T: WireEnum>(value: &str, what: &str) -> Result<T, String> {
            T::from_wire(value).ok_or_else(|| format!("unknown {what} \"{value}\""))
        }
        let protocol: Protocol = wire(&self.protocol, "protocol")?;
        let mut site = Site::new(self.name, protocol, self.host);
        if let Some(id) = self.id.as_deref().and_then(|i| i.parse::<ItemId>().ok()) {
            site.id = id;
        }
        site.encryption = match self.encryption.as_deref() {
            Some(e) => Some(wire::<FtpEncryption>(e, "encryption")?),
            None => None,
        };
        site.port = self.port;
        let l = self.logon;
        let kind: LogonKind = wire(&l.kind, "logon type")?;
        let user = l.user;
        let password = l.password.map(|s| s.0);
        let mut vault_key = None;
        site.logon = match kind {
            LogonKind::Anonymous => SiteLogon::Anonymous,
            LogonKind::Normal => SiteLogon::Normal { user, password },
            LogonKind::AskForPassword => SiteLogon::AskForPassword { user },
            LogonKind::Interactive => SiteLogon::Interactive { user },
            LogonKind::Agent => SiteLogon::Agent { user },
            LogonKind::Account => SiteLogon::Account {
                user,
                password,
                account: l.account.unwrap_or_default(),
            },
            LogonKind::KeyFile => {
                vault_key = l.vault_key.map(|k| SshKey {
                    label: k.label,
                    algorithm: k.algorithm,
                    public_key: k.public_key,
                    private_key: k.private_key.0,
                    passphrase: k.passphrase.map(|p| p.0),
                    read_only: false,
                });
                SiteLogon::KeyFile {
                    user,
                    // A vault key is linked once it is imported.
                    key: l.key_path.map(|p| SiteKey::File(LocalPath::new(p))),
                    passphrase: l.passphrase.map(|p| p.0),
                }
            }
        };
        site.color = wire::<SiteColor>(&self.color, "colour")?;
        site.comments = self.comments;
        site.server_type = wire::<ServerType>(&self.server_type, "server type")?;
        site.bypass_proxy = self.bypass_proxy;
        site.default_local_dir = self.local_dir.filter(|d| !d.is_empty()).map(LocalPath::new);
        site.default_remote_dir = self
            .remote_dir
            .filter(|d| !d.is_empty())
            .map(RemotePath::new);
        site.sync_browsing = self.sync_browsing;
        site.directory_comparison = self.directory_comparison;
        site.timezone_offset_minutes = self.timezone_offset_minutes;
        site.transfer_mode = wire::<SiteTransferMode>(&self.transfer_mode, "transfer mode")?;
        site.limit_connections = self.limit_connections;
        site.charset = Charset::from_label(&self.charset)
            .map_err(|_| format!("unknown charset \"{}\"", self.charset))?;
        site.try_agent_first = self.try_agent_first;
        site.created_at = self.created_at.map(UnixMillis);
        let bookmarks = self
            .bookmarks
            .into_iter()
            .map(|b| ImportBookmark {
                name: b.name,
                local_dir: b.local_dir.filter(|d| !d.is_empty()).map(LocalPath::new),
                remote_dir: b.remote_dir.filter(|d| !d.is_empty()).map(RemotePath::new),
                sync_browsing: b.sync_browsing,
                comparison: b.comparison,
            })
            .collect();
        Ok(ImportSite {
            site,
            bookmarks,
            vault_key,
            password_skipped: None,
        })
    }
}

/// A logon without secrets: what needs a password, account or vault key
/// becomes "ask for password"; a key file on disk stays (without its
/// passphrase).
fn strip_logon(logon: &SiteLogon) -> SiteLogon {
    match logon {
        SiteLogon::Normal { user, .. } | SiteLogon::Account { user, .. } => {
            SiteLogon::AskForPassword { user: user.clone() }
        }
        SiteLogon::KeyFile {
            user,
            key: Some(SiteKey::File(path)),
            ..
        } => SiteLogon::KeyFile {
            user: user.clone(),
            key: Some(SiteKey::File(path.clone())),
            passphrase: None,
        },
        SiteLogon::KeyFile { user, .. } => SiteLogon::AskForPassword { user: user.clone() },
        other => other.clone(),
    }
}
