//! T56: the app's side of transfers — queueing files from the panes, the
//! engine commands, the persisted queue after unlock, refreshing listings
//! after transfers, and the quit warning.

use courier_ftp_core::{
    events::{CoreEvent, LogKind, TransferState},
    local::{local_to_remote, remote_to_local},
    model::{Direction, LocalPath, LogonType},
    queue::{LossReason, NewItem, QueueServer, QuitCheck, ServerKey, lock_queue},
    transfer::{download_target, recursive::dir_placeholder},
};

use super::App;
use crate::{action::Action, ui::Side};

impl App {
    /// The transfer-related part of [`App::dispatch`].
    pub(super) fn transfer_action(&mut self, action: &Action) {
        match action {
            Action::Copy => self.enqueue(true),
            Action::QueueSelection => self.enqueue(false),
            Action::ProcessQueue => {
                if self.transfers.processing() {
                    self.transfers.engine.stop();
                    self.screen.flash("Queue processing stopped");
                } else {
                    self.transfers.engine.start();
                    self.screen.flash("Processing the queue");
                }
            }
            Action::ToggleTransfersPaused => {
                if self.transfers.engine.status().paused {
                    self.transfers.engine.resume_all();
                    self.screen.flash("Transfers resumed");
                } else {
                    self.transfers.engine.pause_all();
                    self.screen.flash("All transfers paused");
                }
            }
            Action::QueueEdited { cancel, wake } => self.transfers.edited(cancel, *wake),
            Action::ToggleSpeedLimit => {
                // The status bar flips its own indicator; the engine's
                // limiter (T44) follows the setting.
                let t = &mut self.settings.transfers;
                t.speed_limit_enabled = !t.speed_limit_enabled;
                self.transfers
                    .engine
                    .settings_changed(self.settings.clone());
            }
            Action::QuitChecked { check, active } => self.quit_checked(*check, *active),
            Action::QueueRestored(result) => match result {
                Ok(0) => {}
                Ok(n) => {
                    let text = format!(
                        "Restored the saved transfer queue ({n} entr{}; Ctrl-p starts it)",
                        if *n == 1 { "y" } else { "ies" }
                    );
                    self.events_tx
                        .log(self.local_session, LogKind::Status, text);
                }
                Err(e) => self.events_tx.log(
                    self.local_session,
                    LogKind::Error,
                    format!("The saved transfer queue could not be restored: {e}"),
                ),
            },
            Action::Tick => {
                for (side, dir) in std::mem::take(&mut self.transfers.refresh) {
                    self.screen.refresh_dir(side, &dir);
                }
            }
            _ => {}
        }
    }

    /// Transfer events the app reacts to (the pane gets them too).
    pub(super) fn transfer_event(&mut self, event: &CoreEvent) {
        match event {
            CoreEvent::TransferStateChanged {
                id,
                state: TransferState::Done,
            } => {
                let Some(item) = lock_queue(&self.transfers.queue).get(*id).cloned() else {
                    return;
                };
                match item.direction {
                    Direction::Upload => {
                        let Some(dir) = item.remote.parent() else {
                            return;
                        };
                        let server = match item.server.key() {
                            ServerKey::Quick(address) => address,
                            ServerKey::Site(_) => return,
                        };
                        self.cache.invalidate(Some(&server), &dir);
                        let shown = self
                            .remote
                            .as_ref()
                            .is_some_and(|r| r.connected && r.info.address == server);
                        if shown && self.settings.queue.refresh_remote_after {
                            self.transfers.refresh.insert((Side::Remote, dir));
                        }
                    }
                    Direction::Download => {
                        let Some(dir) = item
                            .local
                            .parent()
                            .and_then(|p| local_to_remote(p.as_path()).ok())
                        else {
                            return;
                        };
                        self.cache.invalidate(None, &dir);
                        self.transfers.refresh.insert((Side::Local, dir));
                    }
                }
            }
            CoreEvent::QueueFinished { stats } => self.queue_finished(stats),
            _ => {}
        }
    }

    /// F5 (`start`) / Shift-F5: queue the selected files of the focused list
    /// for the other side. Directories wait for recursive transfers (T43).
    fn enqueue(&mut self, start: bool) {
        let Some(side) = self.screen.focused_list_side() else {
            self.screen
                .flash("Select files in a file list to transfer them");
            return;
        };
        let Some(remote) = self.remote.as_ref().filter(|r| r.connected) else {
            self.screen.flash("Not connected");
            return;
        };
        let (Some(local_dir), Some(remote_dir)) = (
            self.screen.local.dir.clone(),
            self.screen.remote.dir.clone(),
        ) else {
            self.screen.flash("Open a directory in both panes first");
            return;
        };
        let Some(local_base) = remote_to_local(&local_dir) else {
            self.screen.flash("Choose a local directory first");
            return;
        };
        let password = match &remote.info.logon {
            LogonType::Normal { password, .. } | LogonType::Account { password, .. } => {
                Some(password.clone())
            }
            _ => None,
        };
        let server = QueueServer::Quick {
            address: remote.info.address.clone(),
            password,
        };
        let t = &self.settings.transfers;
        let transfer_type = self.screen.transfer_type();
        let base = LocalPath::new(local_base);
        let mut items = Vec::new();
        let mut dirs = 0;
        for entry in self.screen.pane_mut(side).target_entries() {
            let Ok(remote_path) = remote_dir.join(&entry.name) else {
                continue;
            };
            let (direction, local) = match side {
                Side::Local => (Direction::Upload, base.join(&entry.name)),
                Side::Remote => (Direction::Download, download_target(&base, &entry.name, t)),
            };
            let mut item = if entry.is_dir_like() {
                // T43: expanded level by level when the engine reaches it.
                dirs += 1;
                dir_placeholder(server.clone(), direction, local, remote_path)
            } else {
                NewItem::file(server.clone(), direction, local, remote_path, entry.size)
            };
            item.transfer_type = transfer_type;
            items.push(item);
        }
        let n = items.len();
        if n > 0 {
            lock_queue(&self.transfers.queue).add_batch(items, time::OffsetDateTime::now_utc());
            self.transfers.edited(&[], true);
            if start && !self.transfers.processing() {
                self.transfers.engine.start();
            }
        }
        let files = n - dirs;
        let plural =
            |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
        let text = match (files, dirs) {
            (0, 0) => "Nothing to transfer".to_owned(),
            (f, 0) => format!("Queued {}", plural(f, "file", "files")),
            (0, d) => format!("Queued {}", plural(d, "directory", "directories")),
            (f, d) => format!(
                "Queued {} and {}",
                plural(f, "file", "files"),
                plural(d, "directory", "directories")
            ),
        };
        self.screen.flash(text);
    }

    /// The vault is unlocked: merge the saved queue in (not started).
    pub(super) fn restore_queue(&mut self) {
        if let Some(engine) = self.vault.as_ref().and_then(crate::vault::Vault::engine) {
            self.transfers.vault.set(Some(engine.clone()));
        }
        let persister = std::sync::Arc::clone(&self.transfers.persister);
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let result = persister.restore().await.map_err(|e| e.to_string());
            persister.changed();
            let _ = tx.send(Action::QueueRestored(result));
        });
    }

    /// Quit, after asking when transfers are running or the queue can't be
    /// saved.
    pub(super) fn request_quit(&mut self) {
        let active = self.transfers.engine.status().active;
        let persister = std::sync::Arc::clone(&self.transfers.persister);
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let check = persister.quit_check().await;
            let _ = tx.send(Action::QuitChecked { check, active });
        });
    }

    fn quit_checked(&mut self, check: QuitCheck, active: usize) {
        let mut reasons = Vec::new();
        if active > 0 {
            reasons.push(format!(
                "{active} transfer{} running and will be stopped.",
                if active == 1 { " is" } else { "s are" }
            ));
        }
        if let QuitCheck::WouldLose { items, reason } = check {
            let s = if items == 1 { "" } else { "s" };
            reasons.push(match reason {
                LossReason::VaultLocked => format!(
                    "{items} queued or failed transfer{s} will be lost: the queue is only \
                     saved in the vault, which is locked. Unlock it (<Ctrl-x><u>) to keep them."
                ),
                LossReason::Disabled => format!(
                    "{items} queued or failed transfer{s} will be lost (queue.persist is off)."
                ),
            });
        }
        if reasons.is_empty() {
            self.should_quit = true;
            return;
        }
        let (modal, rx) = crate::ui::dialog::confirm(
            "Quit",
            &format!("{}\n\nQuit anyway?", reasons.join("\n\n")),
            false,
        );
        self.screen.push_modal(modal);
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            if let Ok(true) = rx.await {
                let _ = tx.send(Action::QuitNow);
            }
        });
    }
}
