//! The app side of the update check and the splash screen (T74).

use std::time::{Instant, SystemTime};

use courier_ftp_core::events::LogKind;
use tracing::debug;

use super::App;
use crate::{
    action::Action,
    update::{Checker, Hook, UpdateInfo},
    vault::Phase,
};

impl App {
    /// `--no-update-check` / `COURIER_FTP_NO_UPDATE_CHECK`: no check this run.
    pub(crate) fn disable_update_check(&mut self) {
        self.update_opt_out = true;
    }

    /// Use `hook` for the update check (tests: a local server or a fake).
    #[cfg(test)]
    pub(crate) fn set_update_hook(&mut self, hook: Hook) {
        self.update = Some(hook);
    }

    /// Start the update check in the background, unless it is off. Nothing
    /// waits for it; a newer release comes back as
    /// [`Action::UpdateAvailable`].
    pub(crate) fn start_update_check(&mut self) {
        let Some(Hook { data_dir, source }) = self.update.clone() else {
            return;
        };
        let interface = &self.settings.interface;
        let checker = Checker {
            enabled: interface.check_updates && !self.update_opt_out,
            prereleases: interface.check_prereleases,
            ..Checker::new(&data_dir)
        };
        if !checker.enabled {
            debug!("update check off");
            return;
        }
        let tx = self.action_tx.clone();
        let cancel = self.update_cancel.clone();
        tokio::spawn(async move {
            let source = match source() {
                Ok(s) => s,
                Err(err) => {
                    debug!(%err, "update check not started");
                    return;
                }
            };
            if let Some(info) = checker.run(&*source, SystemTime::now(), &cancel).await {
                let _ = tx.send(Action::UpdateAvailable(info));
            }
        });
    }

    pub(super) fn update_available(&mut self, info: &UpdateInfo) {
        let notice = info.notice();
        self.events_tx
            .log(self.local_session, LogKind::Status, notice.clone());
        self.screen.set_update_notice(notice);
    }

    /// Take the splash screen down once it has been up long enough and the
    /// vault has opened.
    pub(super) fn expire_splash(&mut self, now: Instant) {
        if self.screen.splash_shown() {
            let starting = self
                .vault
                .as_ref()
                .is_some_and(|v| v.phase == Phase::Opening);
            self.screen.expire_splash(now, starting);
        }
    }
}
