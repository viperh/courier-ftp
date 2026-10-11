//! Settings and vault backups through the app (T73): the settings screen's
//! Import/Export and the first-run screen's "Restore from a .cftp-backup"
//! (T60). The work itself is in `crate::archive`.

use std::sync::Arc;

use courier_ftp_core::{
    archive::{self, Archive, ImportChoice, SettingsDoc, SettingsMode},
    events::LogKind,
    sites::History,
};
use courier_ftp_crypto::kdf::Argon2Cost;
use courier_ftp_store::vault::VaultEngine;
use secrecy::SecretString;

use super::{App, load_history};
use crate::{
    action::{Action, Shared},
    archive::{ArchiveMsg, ExportJob, Opened, Origin, Restored},
    ui::settings::{ImportPreview, SettingsReply},
};

impl App {
    /// The settings screen's Export: the config and queue are read here,
    /// the vault items, Argon2 and the file write in the background.
    pub(super) fn settings_export(&mut self, job: &ExportJob) {
        let settings = if job.choice.settings {
            let dir = Some(self.config_dir.as_path());
            match SettingsDoc::from_config(&self.settings, dir) {
                Ok(doc) => Some(doc),
                Err(e) => {
                    self.settings_reply(SettingsReply::Failed(format!(
                        "Could not read the config: {e}"
                    )));
                    return;
                }
            }
        } else {
            None
        };
        let queue = (job.choice.queue && !job.plain)
            .then(|| courier_ftp_core::queue::lock_queue(&self.transfers.queue).export_json());
        let engine = self.unlocked_engine();
        if !job.plain && job.choice.needs_vault() && engine.is_none() {
            self.settings_reply(SettingsReply::Failed(
                "Unlock the vault (<Ctrl-x><u>) to export sites, history or trusted keys"
                    .to_owned(),
            ));
            return;
        }
        let cost = engine
            .as_ref()
            .map_or(Argon2Cost::DEFAULT, VaultEngine::cost);
        let job = job.clone();
        let tx = self.action_tx.clone();
        let events = self.events_tx.clone();
        let session = self.local_session;
        tokio::spawn(async move {
            let reply = match crate::archive::export(job, settings, queue, engine, cost).await {
                Ok(text) => {
                    events.log(session, LogKind::Status, text.clone());
                    SettingsReply::Done(text)
                }
                Err(e) => SettingsReply::Failed(e),
            };
            let _ = tx.send(Action::SettingsReply(Shared::new(reply)));
        });
    }

    /// Open an import file in the background (Argon2 for a backup).
    pub(super) fn open_import(
        &mut self,
        origin: Origin,
        path: std::path::PathBuf,
        passphrase: Option<SecretString>,
    ) {
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let result = crate::archive::open_file(path.clone(), passphrase).await;
            let msg = ArchiveMsg::Opened {
                origin,
                path,
                result,
            };
            let _ = tx.send(Action::Archive(Shared::new(msg)));
        });
    }

    /// The settings screen chose what to import from the opened file.
    pub(super) fn settings_import(&mut self, choice: ImportChoice) {
        let Some(archive) = self.import_archive.take() else {
            self.settings_reply(SettingsReply::Failed(
                "Open the file again: nothing is loaded".to_owned(),
            ));
            return;
        };
        self.start_restore(*archive, choice, Origin::Settings);
    }

    /// The first-run vault was created: restore the backup opened there.
    pub(super) fn restore_after_create(&mut self) {
        if let Some(archive) = self.restore_archive.take() {
            let choice = ImportChoice::everything(&archive);
            self.start_restore(*archive, choice, Origin::FirstRun);
        }
    }

    /// Settings now (they are small and the app owns them), vault items and
    /// the queue in the background.
    fn start_restore(&mut self, archive: Archive, choice: ImportChoice, origin: Origin) {
        let settings = match (choice.settings, &archive.settings) {
            (Some(mode), Some(doc)) => {
                let dir = Some(self.config_dir.as_path());
                Some(
                    match archive::apply_settings(doc, mode, &self.settings, dir) {
                        Ok((settings, report)) => {
                            for w in &report.warnings {
                                self.events_tx.log(
                                    self.local_session,
                                    LogKind::Error,
                                    format!("import: {w}"),
                                );
                            }
                            self.apply_settings(settings);
                            let how = match mode {
                                SettingsMode::Merge => "merged",
                                SettingsMode::Replace => "replaced",
                            };
                            let mut line = format!("Settings {how}");
                            if !report.warnings.is_empty() {
                                line.push_str(&format!(
                                    " ({} values reset to their defaults; see the log)",
                                    report.warnings.len()
                                ));
                            }
                            if doc.keybindings.is_some() || doc.styles.is_some() {
                                line.push_str("; keybindings and styles apply at the next start");
                            }
                            (line, false)
                        }
                        Err(e) => (format!("Settings were not imported: {e}"), true),
                    },
                )
            }
            _ => None,
        };
        let engine = self.unlocked_engine();
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let restored = crate::archive::restore(Arc::new(archive), choice, engine).await;
            let msg = ArchiveMsg::Restored {
                origin,
                settings,
                restored: Box::new(restored),
            };
            let _ = tx.send(Action::Archive(Shared::new(msg)));
        });
    }

    /// A background archive step finished.
    pub(super) fn archive_message(&mut self, msg: &ArchiveMsg) {
        match msg {
            ArchiveMsg::Opened {
                origin: Origin::Settings,
                path,
                result,
            } => match result {
                Ok(Opened::Ready(archive)) => {
                    let offset =
                        time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC);
                    let today = time::OffsetDateTime::now_utc().to_offset(offset).date();
                    let preview = ImportPreview {
                        sections: crate::archive::contents(archive),
                        warnings: archive.warnings.clone(),
                        folder: format!("Imported {today}"),
                    };
                    if preview.sections.is_empty() {
                        self.settings_reply(SettingsReply::Failed(
                            "The file holds nothing this version can import".to_owned(),
                        ));
                        return;
                    }
                    self.import_archive = Some(archive.clone());
                    self.settings_reply(SettingsReply::ImportReady(Box::new(preview)));
                }
                Ok(Opened::NeedPassphrase) => {
                    self.settings_reply(SettingsReply::NeedPassphrase(path.clone()));
                }
                Err(e) => self.settings_reply(SettingsReply::Failed(e.clone())),
            },
            ArchiveMsg::Opened {
                origin: Origin::FirstRun,
                result,
                ..
            } => {
                let Some(view) = self.screen.vault_view_mut() else {
                    return;
                };
                match result {
                    Ok(Opened::Ready(archive)) => {
                        let lines: Vec<String> = crate::archive::contents(archive)
                            .into_iter()
                            .map(|(s, text)| format!("{}: {text}", s.title()))
                            .collect();
                        view.backup_ready(&lines);
                        self.restore_archive = Some(archive.clone());
                    }
                    Ok(Opened::NeedPassphrase) => {
                        view.set_error(Some("Enter the backup's passphrase.".to_owned()));
                    }
                    Err(e) => view.set_error(Some(format!("{e}."))),
                }
            }
            ArchiveMsg::Restored {
                origin,
                settings,
                restored,
            } => self.restored(*origin, settings.clone(), restored),
        }
    }

    fn restored(&mut self, origin: Origin, settings: Option<(String, bool)>, done: &Restored) {
        if !done.queue.is_empty() {
            courier_ftp_core::queue::lock_queue(&self.transfers.queue)
                .add_batch(done.queue.clone(), time::OffsetDateTime::now_utc());
            self.transfers.edited(&[], false);
        }
        if done.items_changed
            && let Some(engine) = self.unlocked_engine()
        {
            let history = History::new(Arc::new(engine.clone()), Arc::new(engine.store().clone()));
            let tx = self.action_tx.clone();
            let loader = history.clone();
            tokio::spawn(async move { load_history(&loader, &tx).await });
            self.history = Some(history);
            self.load_sites(engine);
        }
        let mut failed = done.failed;
        let mut lines = Vec::new();
        let imported_settings = settings.is_some();
        if let Some((line, bad)) = settings {
            failed |= bad;
            lines.push(line);
        }
        lines.extend(done.lines.iter().cloned());
        if lines.is_empty() {
            lines.push("Nothing was imported".to_owned());
        }
        for line in &lines {
            self.events_tx.log(
                self.local_session,
                if failed {
                    LogKind::Error
                } else {
                    LogKind::Status
                },
                format!("Import: {line}"),
            );
        }
        let text = lines.join("\n");
        match origin {
            Origin::Settings => self.settings_reply(SettingsReply::Imported {
                settings: imported_settings.then(|| Box::new(self.settings.clone())),
                text,
                failed,
            }),
            Origin::FirstRun => {
                self.screen.flash(if failed {
                    "The backup was restored with problems; see the log"
                } else {
                    "Backup restored"
                });
                let (modal, _rx) = crate::ui::dialog::message("Restored from backup", &text);
                self.screen.push_modal(modal);
            }
        }
    }
}
