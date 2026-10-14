//! Export and import of the queue as a plain JSON file without secrets
//! (FileZilla's "Export queue"; also used by settings export, T73).
//!
//! ```json
//! { "format": "courier-ftp-queue", "version": 1, "items": [
//!   { "server": { "type": "site", "site": "0190…" }, "direction": "download",
//!     "local": "/home/me/a.txt", "remote": "/pub/a.txt", "size": 12,
//!     "transfer_type": "auto", "priority": "normal", "on_exists": null,
//!     "is_dir_placeholder": false } ] }
//! ```
//!
//! Only the queued and failed lists are exported, without states, attempts or
//! passwords. Importing drops items whose site no longer exists and turns
//! quickconnect items into ask-for-password ones.

use serde::{Deserialize, Serialize};

use super::item::{NewItem, Priority, QueueItem, QueueServer, SiteId};
use super::model::{Queue, QueueList};
use crate::model::{Direction, LocalPath, RemotePath, ServerAddress};
use crate::settings::{ExistsAction, TransferTypeChoice};

/// The `format` value of an export file.
pub const EXPORT_FORMAT: &str = "courier-ftp-queue";
/// Export format version written by this build.
pub const EXPORT_VERSION: u32 = 1;

/// An export file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueueExport {
    /// Always [`EXPORT_FORMAT`].
    pub format: String,
    /// [`EXPORT_VERSION`] when written by this build.
    pub version: u32,
    /// The items.
    pub items: Vec<ExportedItem>,
}

/// A server in an export file: never a password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExportedServer {
    /// A saved site.
    Site {
        /// Its id.
        site: SiteId,
    },
    /// A quickconnect address.
    Quick {
        /// The address (with the user, if any).
        address: ServerAddress,
    },
}

/// One exported item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportedItem {
    /// The server.
    pub server: ExportedServer,
    /// Download or upload.
    pub direction: Direction,
    /// The local path.
    pub local: LocalPath,
    /// The remote path.
    pub remote: RemotePath,
    /// Size when known.
    #[serde(default)]
    pub size: Option<u64>,
    /// ASCII/binary choice.
    #[serde(default)]
    pub transfer_type: TransferTypeChoice,
    /// Priority.
    #[serde(default)]
    pub priority: Priority,
    /// Per-item file-exists action.
    #[serde(default)]
    pub on_exists: Option<ExistsAction>,
    /// A directory placeholder (T43).
    #[serde(default)]
    pub is_dir_placeholder: bool,
}

impl From<&QueueItem> for ExportedItem {
    fn from(i: &QueueItem) -> Self {
        Self {
            server: match &i.server {
                QueueServer::Site(site) => ExportedServer::Site { site: *site },
                QueueServer::Quick { address, .. } => ExportedServer::Quick {
                    address: address.clone(),
                },
            },
            direction: i.direction,
            local: i.local.clone(),
            remote: i.remote.clone(),
            size: i.size,
            transfer_type: i.transfer_type,
            priority: i.priority,
            on_exists: i.on_exists,
            is_dir_placeholder: i.is_dir_placeholder,
        }
    }
}

/// Export/import errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExportError {
    /// Not JSON, or not shaped like an export.
    #[error("not a courier-ftp queue export: {0}")]
    Invalid(String),
    /// Written by a newer courier-ftp.
    #[error("the queue export is from a newer courier-ftp (version {0})")]
    NewerVersion(u32),
}

/// The result of [`import_json`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ImportReport {
    /// Items to add (with [`Queue::add_batch`]).
    pub items: Vec<NewItem>,
    /// Items dropped because their site doesn't exist here.
    pub missing_sites: usize,
    /// Quickconnect items, which will ask for their password.
    pub ask_password: usize,
}

impl Queue {
    /// The queued and failed lists as an export, without secrets.
    pub fn export(&self) -> QueueExport {
        QueueExport {
            format: EXPORT_FORMAT.to_owned(),
            version: EXPORT_VERSION,
            items: self
                .items(QueueList::Queued)
                .chain(self.items(QueueList::Failed))
                .map(ExportedItem::from)
                .collect(),
        }
    }

    /// [`Queue::export`] as pretty-printed JSON.
    pub fn export_json(&self) -> String {
        // Serializing these plain types to a String can't fail.
        serde_json::to_string_pretty(&self.export()).unwrap_or_default()
    }
}

/// Parses an export file. `site_exists` resolves site ids against the Site
/// Manager; items of missing sites are dropped and counted.
///
/// # Errors
/// [`ExportError::Invalid`], [`ExportError::NewerVersion`].
pub fn import_json(
    json: &str,
    site_exists: impl Fn(SiteId) -> bool,
) -> Result<ImportReport, ExportError> {
    let export: QueueExport =
        serde_json::from_str(json).map_err(|e| ExportError::Invalid(e.to_string()))?;
    if export.format != EXPORT_FORMAT {
        return Err(ExportError::Invalid(format!(
            "format is {:?}, expected {EXPORT_FORMAT:?}",
            export.format
        )));
    }
    if export.version > EXPORT_VERSION {
        return Err(ExportError::NewerVersion(export.version));
    }
    let mut report = ImportReport::default();
    for e in export.items {
        let server = match e.server {
            ExportedServer::Site { site } if site_exists(site) => QueueServer::Site(site),
            ExportedServer::Site { .. } => {
                report.missing_sites += 1;
                continue;
            }
            ExportedServer::Quick { address } => {
                report.ask_password += 1;
                QueueServer::Quick {
                    address,
                    password: None,
                }
            }
        };
        report.items.push(NewItem {
            server,
            direction: e.direction,
            local: e.local,
            remote: e.remote,
            size: e.size,
            transfer_type: e.transfer_type,
            priority: e.priority,
            on_exists: e.on_exists,
            is_dir_placeholder: e.is_dir_placeholder,
        });
    }
    Ok(report)
}
