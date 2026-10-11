//! The app's side of settings and vault backups (T73): writing a
//! `.cftp-backup` or a plain settings file, opening one, and restoring its
//! vault items and queue in the background. The file format and the merge
//! rules are `courier_ftp_core::archive`; the dialogs are the settings
//! screen's (`ui::settings`) and the first-run screen's (`ui::vault`).

use std::{path::PathBuf, sync::Arc};

use courier_ftp_core::{
    archive::{self, Archive, ExportChoice, ImportChoice, RestoreReport, Section, SettingsDoc},
    model::item::{ItemKind, UnixMillis},
    queue::NewItem,
    vault::{ItemVault, backup::BackupError},
};
use courier_ftp_crypto::kdf::Argon2Cost;
use courier_ftp_store::vault::VaultEngine;
use secrecy::SecretString;

/// The largest file read for an import (the backup's decompression cap).
const MAX_FILE: u64 = courier_ftp_core::vault::backup::MAX_DECOMPRESSED;
/// How many conflict lines a summary lists.
const MAX_LINES: usize = 8;

/// An export the user asked for.
#[derive(Debug, Clone)]
pub(crate) struct ExportJob {
    pub(crate) choice: ExportChoice,
    /// Plain JSON of the settings only (no secrets, no passphrase).
    pub(crate) plain: bool,
    pub(crate) path: PathBuf,
    pub(crate) passphrase: Option<SecretString>,
}

/// Where a restore was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// The settings screen's Import.
    Settings,
    /// First run: "Restore from a .cftp-backup".
    FirstRun,
}

/// A file was opened.
#[derive(Debug, Clone)]
pub(crate) enum Opened {
    Ready(Box<Archive>),
    /// It is a `.cftp-backup`: ask for its passphrase.
    NeedPassphrase,
}

/// The vault part of a restore finished.
#[derive(Debug, Clone, Default)]
pub(crate) struct Restored {
    /// What happened, one line each (the first is the summary).
    pub(crate) lines: Vec<String>,
    /// Queue items to add.
    pub(crate) queue: Vec<NewItem>,
    /// Sites, bookmarks or history changed: reload them.
    pub(crate) items_changed: bool,
    /// Something failed.
    pub(crate) failed: bool,
}

/// Background results for the app.
#[derive(Debug, Clone)]
pub(crate) enum ArchiveMsg {
    /// An import file was opened (or not) for `origin`.
    Opened {
        origin: Origin,
        path: PathBuf,
        result: Result<Opened, String>,
    },
    /// A restore finished; `settings` describes the settings part, done
    /// before (and whether it failed).
    Restored {
        origin: Origin,
        settings: Option<(String, bool)>,
        restored: Box<Restored>,
    },
}

/// `~/courier-ftp-<date>.cftp-backup`.
pub(crate) fn default_backup_path() -> PathBuf {
    let offset = time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC);
    let today = time::OffsetDateTime::now_utc().to_offset(offset).date();
    let name = format!(
        "courier-ftp-{today}.{}",
        courier_ftp_core::vault::backup::EXTENSION
    );
    directories::BaseDirs::new()
        .map(|b| b.home_dir().join(&name))
        .unwrap_or_else(|| PathBuf::from(name))
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| format!("background task failed: {e}"))?
}

fn backup_error(e: &BackupError) -> String {
    match e {
        BackupError::Decrypt => "Wrong passphrase, or the file was modified".to_owned(),
        BackupError::TooLarge => "The file is too large".to_owned(),
        other => {
            let text = other.to_string();
            let mut chars = text.chars();
            chars
                .next()
                .map(|c| c.to_uppercase().chain(chars).collect())
                .unwrap_or_default()
        }
    }
}

/// Writes the export: Argon2 and the file write run off the async threads.
/// Returns the message to show.
pub(crate) async fn export(
    job: ExportJob,
    settings: Option<SettingsDoc>,
    queue: Option<String>,
    engine: Option<VaultEngine>,
    cost: Argon2Cost,
) -> Result<String, String> {
    let path = job.path.clone();
    if job.plain {
        let doc = settings.unwrap_or_default();
        let text = archive::settings_to_json(&doc, UnixMillis::now());
        blocking(move || {
            courier_ftp_core::logfile::write_private_bytes(&path, text.as_bytes())
                .map_err(|e| format!("Could not write {}: {e}", path.display()))
        })
        .await?;
        return Ok(format!("Settings exported to {}", job.path.display()));
    }
    let passphrase = job.passphrase.ok_or("A passphrase is needed")?;
    let mut archive = Archive::new(UnixMillis::now().0);
    let mut choice = job.choice;
    if let Some(engine) = &engine {
        archive.items = archive::collect_items(engine, &choice)
            .await
            .map_err(|e| format!("Could not read the vault: {e}"))?;
    } else {
        // Locked: the config only, without the proxy passwords.
        choice.sites = false;
        choice.history = false;
        choice.trust = false;
    }
    archive.passwords = choice.sites && choice.passwords;
    if choice.settings {
        archive.settings = settings;
    }
    archive.queue = if choice.queue { queue } else { None };
    let what: Vec<&str> = archive.sections().iter().map(|s| s.title()).collect();
    let what = what.join(", ").to_lowercase();
    blocking(move || {
        let bytes = archive::seal(
            &archive,
            &passphrase,
            cost,
            &mut courier_ftp_crypto::keys::os_rng(),
        )
        .map_err(|e| backup_error(&e))?;
        courier_ftp_core::logfile::write_private_bytes(&path, &bytes)
            .map_err(|e| format!("Could not write {}: {e}", path.display()))
    })
    .await?;
    Ok(format!("Exported {what} to {}", job.path.display()))
}

/// Reads and opens an import file: a plain settings export, or a
/// `.cftp-backup` (which needs `passphrase`).
pub(crate) async fn open_file(
    path: PathBuf,
    passphrase: Option<SecretString>,
) -> Result<Opened, String> {
    blocking(move || {
        let len = std::fs::metadata(&path)
            .map_err(|e| format!("Could not read {}: {e}", path.display()))?
            .len();
        if len > MAX_FILE {
            return Err("The file is too large".to_owned());
        }
        let bytes =
            std::fs::read(&path).map_err(|e| format!("Could not read {}: {e}", path.display()))?;
        if archive::is_backup(&bytes) {
            let Some(passphrase) = passphrase else {
                return Ok(Opened::NeedPassphrase);
            };
            // Argon2: this runs on a blocking thread.
            let archive = archive::open(&bytes, &passphrase).map_err(|e| backup_error(&e))?;
            return Ok(Opened::Ready(Box::new(archive)));
        }
        if archive::is_settings_json(&bytes) {
            let archive = archive::parse_settings_json(&bytes).map_err(|e| backup_error(&e))?;
            return Ok(Opened::Ready(Box::new(archive)));
        }
        Err("Not a courier-ftp backup or settings export".to_owned())
    })
    .await
}

/// What an archive holds, one `(section, description)` per section.
pub(crate) fn contents(archive: &Archive) -> Vec<(Section, String)> {
    archive
        .sections()
        .into_iter()
        .map(|s| (s, archive.describe(s)))
        .collect()
}

/// Restores the vault items and the queue `choice` asks for (the settings
/// are the caller's). Without `engine` (locked vault) only quickconnect
/// queue items come in.
pub(crate) async fn restore(
    archive: Arc<Archive>,
    choice: ImportChoice,
    engine: Option<VaultEngine>,
) -> Restored {
    let mut out = Restored::default();
    let mut report = RestoreReport::default();
    if choice.needs_vault(&archive) {
        match &engine {
            Some(engine) => match archive::restore_items(engine, &archive, &choice).await {
                Ok(r) => {
                    out.items_changed = r.added + r.updated > 0;
                    out.lines.push(format!("Vault items: {}", r.summary()));
                    out.lines
                        .extend(r.conflicts.iter().take(MAX_LINES).cloned());
                    if r.conflicts.len() > MAX_LINES {
                        out.lines
                            .push(format!("… and {} more", r.conflicts.len() - MAX_LINES));
                    }
                    report = r;
                }
                Err(e) => {
                    out.failed = true;
                    out.lines
                        .push(format!("Vault items were not imported: {e}"));
                }
            },
            None => {
                out.failed = true;
                out.lines.push(
                    "The vault is locked: sites, history and trusted keys were not imported"
                        .to_owned(),
                );
            }
        }
    }
    if choice.queue {
        let sites: Vec<_> = match &engine {
            Some(engine) => engine
                .list(ItemKind::Site)
                .await
                .map(|l| l.into_iter().map(|i| i.id).collect())
                .unwrap_or_default(),
            None => Vec::new(),
        };
        match archive::queue_items(&archive, &report, |id| sites.contains(&id)) {
            Ok(Some(q)) => {
                let mut line = format!("Queue: {} added", q.items.len());
                if q.missing_sites > 0 {
                    line.push_str(&format!(
                        ", {} skipped (their site isn't here)",
                        q.missing_sites
                    ));
                }
                out.lines.push(line);
                out.queue = q.items;
            }
            Ok(None) => {}
            Err(e) => {
                out.failed = true;
                out.lines.push(format!("The queue was not imported: {e}"));
            }
        }
    }
    out
}
