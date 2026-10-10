//! The app's side of the Site Manager (T59): the [`SiteManager`] loaded
//! after unlock, and the operations the Site Manager screen asks for, run in
//! background tasks that answer with a [`SitesReply`].
//!
//! The manager sits in a [`SitesSlot`] shared with [`SiteResolver`] (the
//! transfer engine's view of saved sites): `Some` while the vault is
//! unlocked, `None` after locking. Each operation locks the slot, runs, and
//! sends back a [`Snapshot`] of the tree for the screen to draw, so drawing
//! never waits on the vault.

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use courier_ftp_core::{
    backend::ConnectInfo,
    model::item::{ItemId, UnixMillis},
    queue::QueueServer,
    sites::{
        Bookmarks, Site, SiteConnect, SiteError, SiteIssue, SiteManager, SiteTree,
        export::{self, ExportScope},
        import::{self, ImportError, ImportReport},
    },
    transfer::{ServerResolver, quick_connect_info},
};
use courier_ftp_crypto::kdf::Argon2Cost;
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

/// The loaded Site Manager while the vault is unlocked.
pub(crate) type SitesSlot = Arc<tokio::sync::Mutex<Option<SiteManager>>>;

/// What the Site Manager screen draws: the tree and each site's bookmark
/// names (read-only list; editing is T64's).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Snapshot {
    pub(crate) tree: SiteTree,
    pub(crate) bookmarks: HashMap<ItemId, Vec<String>>,
}

/// Export file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportFormat {
    /// courier-ftp JSON without secrets.
    Json,
    /// courier-ftp export with passwords and vault SSH keys, sealed with a
    /// passphrase.
    Encrypted,
    /// FileZilla `sitemanager.xml` (no passwords).
    FileZilla,
}

/// An operation the Site Manager screen asks for.
#[derive(Debug, Clone)]
pub(crate) enum SiteOp {
    Save(Box<Site>),
    AddFolder {
        parent: Option<ItemId>,
        name: String,
    },
    Rename {
        id: ItemId,
        name: String,
    },
    Move {
        id: ItemId,
        parent: Option<ItemId>,
    },
    Duplicate(ItemId),
    Delete(ItemId),
    /// Connect the remote pane to a site (the app handles it).
    Connect(ItemId),
    /// Import a FileZilla `sitemanager.xml` or a courier-ftp export.
    Import {
        path: PathBuf,
        passphrase: Option<SecretString>,
    },
    Export {
        scope: ExportScope,
        format: ExportFormat,
        path: PathBuf,
        passphrase: Option<SecretString>,
    },
}

/// How an operation went.
#[derive(Debug, Clone)]
pub(crate) enum SiteOutcome {
    Loaded,
    Saved {
        id: ItemId,
        warnings: Vec<SiteIssue>,
    },
    /// A folder or copy was created: select it.
    Created(ItemId),
    Renamed,
    Moved,
    Deleted(usize),
    Imported(Box<ImportReport>),
    /// The export is encrypted: ask for its passphrase and try again.
    NeedPassphrase(PathBuf),
    Exported {
        path: PathBuf,
        sites: usize,
    },
    Failed(String),
}

/// The answer to a [`SiteOp`], with the tree as it is now (`None` when the
/// vault is locked).
#[derive(Debug, Clone)]
pub(crate) struct SitesReply {
    pub(crate) snapshot: Option<Snapshot>,
    pub(crate) outcome: SiteOutcome,
}

/// Loads the Site Manager over the unlocked vault `engine`.
pub(crate) async fn load(
    engine: &courier_ftp_store::vault::VaultEngine,
) -> Result<SiteManager, SiteError> {
    SiteManager::load(Arc::new(engine.clone()), Arc::new(engine.store().clone())).await
}

/// The tree and the site bookmarks.
pub(crate) async fn snapshot(sites: &SiteManager) -> Snapshot {
    let mut bookmarks: HashMap<ItemId, Vec<String>> = HashMap::new();
    match Bookmarks::load(Arc::clone(sites.vault()), Arc::clone(sites.local_store())).await {
        Ok(all) => {
            for b in all.all() {
                if let Some(site) = b.site_id {
                    bookmarks.entry(site).or_default().push(b.name.clone());
                }
            }
        }
        Err(e) => tracing::debug!(error = %e, "site bookmarks not loaded"),
    }
    Snapshot {
        tree: sites.tree().clone(),
        bookmarks,
    }
}

/// Runs `op` (anything but [`SiteOp::Connect`]) on the manager in `slot`.
/// `cost` seals encrypted exports; `today` names the FileZilla import
/// folder.
pub(crate) async fn run(
    slot: &SitesSlot,
    op: SiteOp,
    cost: Argon2Cost,
    today: time::Date,
) -> SitesReply {
    let mut guard = slot.lock().await;
    let Some(sites) = guard.as_mut() else {
        return SitesReply {
            snapshot: None,
            outcome: SiteOutcome::Failed("The vault is locked".to_owned()),
        };
    };
    let outcome = match apply(sites, op, cost, today).await {
        Ok(outcome) => outcome,
        Err(message) => SiteOutcome::Failed(message),
    };
    SitesReply {
        snapshot: Some(snapshot(sites).await),
        outcome,
    }
}

async fn apply(
    sites: &mut SiteManager,
    op: SiteOp,
    cost: Argon2Cost,
    today: time::Date,
) -> Result<SiteOutcome, String> {
    let text = |e: SiteError| e.to_string();
    Ok(match op {
        SiteOp::Save(site) => {
            let id = site.id;
            let warnings = sites.save_site(*site).await.map_err(text)?;
            SiteOutcome::Saved { id, warnings }
        }
        SiteOp::AddFolder { parent, name } => {
            SiteOutcome::Created(sites.add_folder(parent, &name).await.map_err(text)?)
        }
        SiteOp::Rename { id, name } => {
            sites.rename(id, &name).await.map_err(text)?;
            SiteOutcome::Renamed
        }
        SiteOp::Move { id, parent } => {
            sites.move_node(id, parent).await.map_err(text)?;
            SiteOutcome::Moved
        }
        SiteOp::Duplicate(id) => SiteOutcome::Created(sites.duplicate(id).await.map_err(text)?),
        SiteOp::Delete(id) => SiteOutcome::Deleted(sites.delete(id).await.map_err(text)?),
        SiteOp::Connect(_) => return Err("connect is handled by the app".to_owned()),
        SiteOp::Import { path, passphrase } => import_file(sites, path, passphrase, today).await?,
        SiteOp::Export {
            scope,
            format,
            path,
            passphrase,
        } => export_file(sites, scope, format, path, passphrase, cost).await?,
    })
}

/// Whether `bytes` look like XML (FileZilla) rather than a courier-ftp
/// export.
fn looks_like_xml(bytes: &[u8]) -> bool {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    bytes
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'<')
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| format!("background task failed: {e}"))?
}

fn import_error(e: ImportError) -> String {
    e.to_string()
}

async fn import_file(
    sites: &mut SiteManager,
    path: PathBuf,
    passphrase: Option<SecretString>,
    today: time::Date,
) -> Result<SiteOutcome, String> {
    let read_path = path.clone();
    let bytes = blocking(move || {
        let len = std::fs::metadata(&read_path)
            .map_err(|e| e.to_string())?
            .len();
        if len > export::MAX_EXPORT_LEN as u64 {
            return Err("the file is too large to import".to_owned());
        }
        std::fs::read(&read_path).map_err(|e| e.to_string())
    })
    .await?;
    let report = if looks_like_xml(&bytes) {
        let tree = blocking(move || import::parse_filezilla(&bytes).map_err(import_error)).await?;
        import::apply(
            sites,
            tree,
            None,
            Some(&import::filezilla_folder_name(today)),
        )
        .await
        .map_err(import_error)?
    } else {
        if import::is_encrypted_export(&bytes) && passphrase.is_none() {
            return Ok(SiteOutcome::NeedPassphrase(path));
        }
        let tree = blocking(move || {
            import::parse_export(&bytes, passphrase.as_ref()).map_err(import_error)
        })
        .await?;
        import::apply(sites, tree, None, None)
            .await
            .map_err(import_error)?
    };
    Ok(SiteOutcome::Imported(Box::new(report)))
}

async fn export_file(
    sites: &SiteManager,
    scope: ExportScope,
    format: ExportFormat,
    path: PathBuf,
    passphrase: Option<SecretString>,
    cost: Argon2Cost,
) -> Result<SiteOutcome, String> {
    let set = export::collect(sites, scope)
        .await
        .map_err(|e| e.to_string())?;
    let (_, count) = set.count();
    let now = UnixMillis::now();
    let target = path.clone();
    blocking(move || {
        let bytes = match format {
            ExportFormat::Json => export::to_json(&set, now)
                .map_err(|e| e.to_string())?
                .into_bytes(),
            ExportFormat::FileZilla => export::to_filezilla_xml(&set).into_bytes(),
            ExportFormat::Encrypted => {
                let passphrase = passphrase.ok_or("a passphrase is needed")?;
                export::to_encrypted(
                    &set,
                    &passphrase,
                    cost,
                    now,
                    &mut courier_ftp_crypto::keys::os_rng(),
                )
                .map_err(|e| e.to_string())?
            }
        };
        write_private(&target, &bytes).map_err(|e| e.to_string())
    })
    .await?;
    Ok(SiteOutcome::Exported { path, sites: count })
}

/// Writes `bytes` to a file only the user can read (exports name hosts and
/// users).
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    courier_ftp_core::logfile::write_private_bytes(path, bytes)
}

/// What connecting to site `id` needs.
pub(crate) async fn connect(slot: &SitesSlot, id: ItemId) -> Result<SiteConnect, String> {
    let guard = slot.lock().await;
    let sites = guard.as_ref().ok_or("The vault is locked")?;
    sites.connect(id).await.map_err(|e| e.to_string())
}

/// Records a successful connect to site `id` (device-local, for the recent
/// servers list).
pub(crate) async fn record_connected(slot: &SitesSlot, id: ItemId) {
    let mut guard = slot.lock().await;
    if let Some(sites) = guard.as_mut()
        && let Err(e) = sites.record_connected(id).await
    {
        tracing::debug!(error = %e, "last connect time not saved");
    }
}

/// The transfer engine's [`ServerResolver`] (T41): saved sites through the
/// Site Manager, with the vault's credentials; quickconnect servers inline.
/// The queue pane (T56) hands it to the engine.
#[derive(Debug, Clone)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the transfer engine is wired up by T56")
)]
pub(crate) struct SiteResolver {
    slot: SitesSlot,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the transfer engine is wired up by T56")
)]
impl SiteResolver {
    pub(crate) fn new(slot: SitesSlot) -> Self {
        Self { slot }
    }
}

#[async_trait::async_trait]
impl ServerResolver for SiteResolver {
    async fn resolve(
        &self,
        server: &QueueServer,
        cancel: &CancellationToken,
    ) -> courier_ftp_core::Result<ConnectInfo> {
        match server {
            QueueServer::Site(id) => {
                let id = *id;
                tokio::select! {
                    () = cancel.cancelled() => Err(courier_ftp_core::Error::Cancelled),
                    result = async {
                        let guard = self.slot.lock().await;
                        let sites = guard.as_ref().ok_or_else(|| {
                            courier_ftp_core::Error::Vault("the vault is locked".to_owned())
                        })?;
                        Ok(sites.connect(id).await?.info)
                    } => result,
                }
            }
            QueueServer::Quick { address, password } => {
                Ok(quick_connect_info(address, password.as_ref()))
            }
        }
    }

    fn connection_limit(&self, server: &QueueServer) -> Option<u32> {
        let QueueServer::Site(id) = server else {
            return None;
        };
        let guard = self.slot.try_lock().ok()?;
        guard.as_ref()?.site(*id)?.limit_connections.map(u32::from)
    }
}

#[cfg(test)]
mod tests {
    use courier_ftp_core::{
        model::{LogonType, Protocol},
        sites::{MemSiteLocalStore, SiteLogon},
        vault::MemItemVault,
    };
    use pretty_assertions::assert_eq;
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn xml_is_told_apart_from_json() {
        assert!(looks_like_xml(b"\xEF\xBB\xBF  <?xml version=\"1.0\"?>"));
        assert!(looks_like_xml(b"\n<FileZilla3>"));
        assert!(!looks_like_xml(b"{\"format\": 1}"));
        assert!(!looks_like_xml(b""));
    }

    #[tokio::test]
    async fn resolver_uses_saved_credentials_and_limits() {
        let mut sites = SiteManager::load(
            Arc::new(MemItemVault::unlocked()),
            Arc::new(MemSiteLocalStore::new()),
        )
        .await
        .unwrap();
        let mut site = Site::new("web", Protocol::Sftp, "web.example.com");
        site.logon = SiteLogon::Normal {
            user: "deploy".into(),
            password: Some(SecretString::from("pw")),
        };
        site.limit_connections = Some(2);
        let id = site.id;
        sites.save_site(site).await.unwrap();
        let slot: SitesSlot = Arc::new(tokio::sync::Mutex::new(Some(sites)));
        let resolver = SiteResolver::new(Arc::clone(&slot));
        let info = resolver
            .resolve(&QueueServer::Site(id), &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(info.address.host, "web.example.com");
        let LogonType::Normal { user, password } = &info.logon else {
            panic!("normal logon expected");
        };
        assert_eq!(user, "deploy");
        assert_eq!(password.expose_secret(), "pw");
        assert_eq!(resolver.connection_limit(&QueueServer::Site(id)), Some(2));

        // Locked: refused.
        *slot.lock().await = None;
        assert!(
            resolver
                .resolve(&QueueServer::Site(id), &CancellationToken::new())
                .await
                .is_err()
        );
    }
}
