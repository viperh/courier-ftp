//! Importing sites (T32): from FileZilla's `sitemanager.xml` and from
//! courier-ftp export files (plain JSON or passphrase-encrypted).
//!
//! Importing is two steps, so the UI can show what will happen first:
//!
//! 1. **Parse** into an [`ImportTree`]: [`parse_filezilla`] or
//!    [`parse_export`] (which also takes the passphrase of an encrypted
//!    export, see [`is_encrypted_export`]). Nothing is written.
//! 2. **Apply** it with [`apply`]: folders and sites are created under a
//!    parent folder, names made unique, site bookmarks and vault SSH keys
//!    written, and an [`ImportReport`] returned. A FileZilla import goes
//!    into a new folder "Imported from FileZilla \<date\>"
//!    ([`filezilla_folder_name`]) so nothing clashes.
//!
//! Ids from an export are kept when the vault doesn't have them yet, so
//! importing on another install keeps the same items; an id that exists
//! gets a new one. Sites that fail [`Site::validate`] (and servers FileZilla
//! has that we can't use, like S3) are skipped and listed with the reason.

use std::path::PathBuf;

use secrecy::SecretString;

use crate::model::LocalPath;
use crate::model::item::{self, ItemId, SshKey, UnixMillis};
use crate::vault::ItemVaultExt;

use super::export::{self, SitesFile};
use super::{Site, SiteError, SiteKey, SiteLogon, SiteManager};

/// What can go wrong reading an import file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ImportError {
    /// The file is larger than the import accepts.
    #[error("the file is too large to import")]
    TooLarge,
    /// The file doesn't parse or is not the expected kind of file.
    #[error("the file can't be read: {0}")]
    Malformed(String),
    /// The export is encrypted and no passphrase was given.
    #[error("the export is encrypted: enter its passphrase")]
    PassphraseNeeded,
    /// Wrong passphrase, or the encrypted export was modified.
    #[error("wrong passphrase, or the export file is damaged")]
    WrongPassphrase,
    /// Writing to the vault failed.
    #[error(transparent)]
    Site(#[from] SiteError),
}

impl From<crate::vault::VaultError> for ImportError {
    fn from(e: crate::vault::VaultError) -> Self {
        Self::Site(SiteError::Vault(e))
    }
}

/// A parsed import, not yet written.
#[derive(Debug, Clone, Default)]
pub struct ImportTree {
    /// Top-level folders and sites.
    pub nodes: Vec<ImportNode>,
    /// Entries left out while parsing, with the reason.
    pub skipped: Vec<Skipped>,
}

impl ImportTree {
    /// `(folders, sites)` in the tree.
    pub fn count(&self) -> (usize, usize) {
        fn walk(nodes: &[ImportNode], acc: &mut (usize, usize)) {
            for n in nodes {
                match n {
                    ImportNode::Folder { children, .. } => {
                        acc.0 += 1;
                        walk(children, acc);
                    }
                    ImportNode::Site(_) => acc.1 += 1,
                }
            }
        }
        let mut acc = (0, 0);
        walk(&self.nodes, &mut acc);
        acc
    }
}

/// A folder or site to import.
#[derive(Debug, Clone)]
pub enum ImportNode {
    /// A folder and what is in it.
    Folder {
        /// The id to keep (exports), unless the vault already has it.
        id: Option<ItemId>,
        /// Name (made unique on import).
        name: String,
        /// Contents.
        children: Vec<ImportNode>,
    },
    /// A site.
    Site(Box<ImportSite>),
}

/// A site to import, with its bookmarks.
#[derive(Debug, Clone)]
pub struct ImportSite {
    /// The site (`id` is kept unless the vault has it; `parent` and `vault`
    /// are set on import).
    pub site: Site,
    /// Its bookmarks.
    pub bookmarks: Vec<ImportBookmark>,
    /// A vault SSH key the site logs in with (encrypted exports): imported
    /// as a new `ssh-key` item and referenced by the site.
    pub vault_key: Option<SshKey>,
    /// Why the password was left out, if it was (e.g. FileZilla master
    /// password).
    pub password_skipped: Option<String>,
}

/// A site bookmark to import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportBookmark {
    /// Name.
    pub name: String,
    /// Local directory.
    pub local_dir: Option<LocalPath>,
    /// Remote directory.
    pub remote_dir: Option<crate::model::RemotePath>,
    /// Synchronized browsing.
    pub sync_browsing: bool,
    /// Directory comparison.
    pub comparison: bool,
}

/// An entry that was not imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// Its path in the imported file (`Folder/Site`).
    pub path: String,
    /// Why.
    pub reason: String,
}

/// What [`apply`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// The folder created for the import (FileZilla), if any.
    pub root: Option<ItemId>,
    /// Folders created (the import folder included).
    pub folders: usize,
    /// Sites created.
    pub sites: usize,
    /// Sites imported with a password (or key passphrase).
    pub passwords: usize,
    /// Site bookmarks created.
    pub bookmarks: usize,
    /// Vault SSH keys created.
    pub keys: usize,
    /// Entries left out (while parsing or importing), with the reason.
    pub skipped: Vec<Skipped>,
}

impl ImportReport {
    /// "12 sites imported, 9 passwords imported, 2 skipped".
    pub fn summary(&self) -> String {
        format!(
            "{} sites imported, {} passwords imported, {} skipped",
            self.sites,
            self.passwords,
            self.skipped.len()
        )
    }
}

/// Parses a FileZilla `sitemanager.xml`.
///
/// # Errors
/// [`ImportError::TooLarge`], [`ImportError::Malformed`].
pub fn parse_filezilla(xml: &[u8]) -> Result<ImportTree, ImportError> {
    super::filezilla::parse_sitemanager(xml)
}

/// Whether `file` is a passphrase-encrypted courier-ftp export.
pub fn is_encrypted_export(file: &[u8]) -> bool {
    file.starts_with(export::ENCRYPTED_MAGIC)
}

/// Parses a courier-ftp export, plain or encrypted (`passphrase` is needed
/// for an encrypted one and ignored otherwise).
///
/// **CPU- and memory-heavy for encrypted files** (Argon2): async callers use
/// `spawn_blocking`.
///
/// # Errors
/// [`ImportError::PassphraseNeeded`], [`ImportError::WrongPassphrase`],
/// [`ImportError::TooLarge`], [`ImportError::Malformed`].
pub fn parse_export(
    file: &[u8],
    passphrase: Option<&SecretString>,
) -> Result<ImportTree, ImportError> {
    let json = if is_encrypted_export(file) {
        let passphrase = passphrase.ok_or(ImportError::PassphraseNeeded)?;
        export::open_encrypted(file, passphrase)?
    } else {
        if file.len() > export::MAX_EXPORT_LEN {
            return Err(ImportError::TooLarge);
        }
        zeroize::Zeroizing::new(file.to_vec())
    };
    let parsed: SitesFile = serde_json::from_slice(&json)
        .map_err(|e| ImportError::Malformed(format!("not a courier-ftp export: {e}")))?;
    parsed.into_tree()
}

/// The name of the folder a FileZilla import goes into:
/// "Imported from FileZilla 2026-10-10".
pub fn filezilla_folder_name(today: time::Date) -> String {
    format!(
        "Imported from FileZilla {:04}-{:02}-{:02}",
        today.year(),
        u8::from(today.month()),
        today.day()
    )
}

/// Where FileZilla keeps `sitemanager.xml` on this system (to suggest in the
/// file picker), most likely first. `home` is the user's home directory and
/// `appdata` `%APPDATA%` (Windows). The paths may not exist.
pub fn filezilla_locations(home: Option<PathBuf>, appdata: Option<PathBuf>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if cfg!(windows) {
        if let Some(a) = appdata {
            out.push(a.join("FileZilla").join("sitemanager.xml"));
        }
    } else if let Some(h) = home {
        // Linux and macOS (FileZilla uses ~/.config there too); the
        // XDG_CONFIG_HOME default.
        out.push(h.join(".config").join("filezilla").join("sitemanager.xml"));
        // Very old versions.
        out.push(h.join(".filezilla").join("sitemanager.xml"));
    }
    out
}

/// Writes `tree` into `parent` (`None` = top level), or into a new folder
/// `folder` there when given (FileZilla imports). Names are made unique in
/// their folder. Sites that don't validate are skipped and reported; vault
/// errors stop the import (what was written stays).
///
/// The caller reloads its [`Bookmarks`](super::Bookmarks) afterwards.
///
/// # Errors
/// [`ImportError::Site`] when writing fails.
pub async fn apply(
    sites: &mut SiteManager,
    tree: ImportTree,
    parent: Option<ItemId>,
    folder: Option<&str>,
) -> Result<ImportReport, ImportError> {
    let mut report = ImportReport {
        skipped: tree.skipped,
        ..ImportReport::default()
    };
    let mut parent = parent;
    if let Some(name) = folder {
        let name = sites.tree().unique_name(parent, name);
        let id = sites.add_folder(parent, &name).await?;
        report.root = Some(id);
        report.folders += 1;
        parent = Some(id);
    }
    import_nodes(sites, tree.nodes, parent, "", &mut report).await?;
    Ok(report)
}

async fn import_nodes(
    sites: &mut SiteManager,
    nodes: Vec<ImportNode>,
    parent: Option<ItemId>,
    path: &str,
    report: &mut ImportReport,
) -> Result<(), ImportError> {
    for node in nodes {
        match node {
            ImportNode::Folder { id, name, children } => {
                let name = sites.tree().unique_name(parent, &name);
                let here = join(path, &name);
                let id = match id {
                    Some(id) if !exists(sites, id).await? => id,
                    _ => ItemId::new(),
                };
                let id = sites.add_folder_as(parent, &name, id).await?;
                report.folders += 1;
                Box::pin(import_nodes(sites, children, Some(id), &here, report)).await?;
            }
            ImportNode::Site(s) => import_site(sites, *s, parent, path, report).await?,
        }
    }
    Ok(())
}

/// Whether `id` is taken (in the tree or by any other live item).
async fn exists(sites: &SiteManager, id: ItemId) -> Result<bool, ImportError> {
    Ok(sites.tree().get(id).is_some() || sites.vault().get(id).await?.is_some())
}

fn join(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.to_owned()
    } else {
        format!("{path}/{name}")
    }
}

async fn import_site(
    sites: &mut SiteManager,
    import: ImportSite,
    parent: Option<ItemId>,
    path: &str,
    report: &mut ImportReport,
) -> Result<(), ImportError> {
    let ImportSite {
        mut site,
        bookmarks,
        vault_key,
        password_skipped,
    } = import;
    site.name = sites.tree().unique_name(parent, &site.name);
    site.parent = parent;
    site.vault = None;
    site.read_only = false;
    site.last_connected_at = None;
    let here = join(path, &site.name);
    if exists(sites, site.id).await? {
        site.id = ItemId::new();
    }
    if let Some(reason) = password_skipped {
        report.skipped.push(Skipped {
            path: format!("{here} (password)"),
            reason,
        });
    }
    // A vault key gets a new id; it is written once the site validates.
    let vault_key = match (vault_key, &mut site.logon) {
        (Some(key), SiteLogon::KeyFile { key: k, .. }) => {
            let key_id = ItemId::new();
            *k = Some(SiteKey::Vault(key_id));
            Some((key_id, key))
        }
        _ => None,
    };
    let issues: Vec<String> = site
        .validate()
        .into_iter()
        .filter(super::SiteIssue::is_error)
        .map(|i| i.message)
        .collect();
    if !issues.is_empty() {
        report.skipped.push(Skipped {
            path: here,
            reason: issues.join("; "),
        });
        return Ok(());
    }
    if let Some((key_id, key)) = vault_key {
        sites.vault().put_view(key_id, None, key).await?;
        report.keys += 1;
    }
    let has_secret = site.logon.password().is_some()
        || matches!(
            &site.logon,
            SiteLogon::KeyFile {
                passphrase: Some(_),
                ..
            }
        );
    site.created_at.get_or_insert_with(UnixMillis::now);
    let id = site.id;
    match sites.save_site(site).await {
        Ok(_) => {}
        Err(SiteError::Invalid(issues)) => {
            report.skipped.push(Skipped {
                path: here,
                reason: SiteError::Invalid(issues).to_string(),
            });
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }
    report.sites += 1;
    // With `vault.store_passwords = false` the vault dropped it.
    if has_secret
        && sites.site(id).is_some_and(|s| {
            s.logon.password().is_some()
                || matches!(
                    &s.logon,
                    SiteLogon::KeyFile {
                        passphrase: Some(_),
                        ..
                    }
                )
        })
    {
        report.passwords += 1;
    }
    for (pos, b) in bookmarks.into_iter().enumerate() {
        let bid = ItemId::new();
        let view = item::Bookmark {
            name: b.name,
            site_id: Some(id),
            local_dir: b
                .local_dir
                .as_ref()
                .map(|p| p.as_path().to_string_lossy().into_owned()),
            remote_dir: b.remote_dir.as_ref().map(|p| p.as_str().to_owned()),
            sync_browsing: b.sync_browsing && b.local_dir.is_some() && b.remote_dir.is_some(),
            comparison: b.comparison,
            position: Some(i64::try_from(pos).unwrap_or(i64::MAX)),
            read_only: false,
        };
        let vault = sites.site(id).and_then(|s| s.vault);
        sites.vault().put_view(bid, vault, view).await?;
        report.bookmarks += 1;
    }
    Ok(())
}
