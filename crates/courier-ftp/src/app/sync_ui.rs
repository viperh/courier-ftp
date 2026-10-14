//! T90: the app's glue between the sync screens (`ui::sync`), the vault's
//! "Forgot password?" recovery, and the sync controller (`crate::sync`).

use courier_ftp_core::{events::LogKind, model::item::VaultId};
use courier_ftp_sync::{
    AccountError, Revoked, RotationProgress, SyncEvent, SyncStatus, ToastLevel,
    account::{LoginRequest, LoginSession},
    rotation::RotationPhase,
};

use super::App;
use crate::{
    sync::{SyncCtl, SyncMsg},
    ui::{
        VaultRequest,
        sync::{LoginSummary, SyncRequest, SyncView, TeamReply},
    },
    vault::Phase,
};

/// An account error for the screens.
fn describe(e: &AccountError) -> String {
    match e {
        AccountError::WrongLocalPassword => {
            "Wrong master password: type the current master password of this device".to_owned()
        }
        AccountError::Sync(inner) => inner.to_string(),
        other => other.to_string(),
    }
}

fn summary(login: &LoginSession, email: &str) -> LoginSummary {
    let preview = login.preview();
    LoginSummary {
        email: email.to_owned(),
        password_differs: login.password_differs(),
        will_import: login.will_import(),
        new_items: preview.new_items,
        skipped_deleted: preview.skipped_deleted,
    }
}

impl App {
    fn sync_ctl(&mut self) -> Option<&mut SyncCtl> {
        self.vault.as_mut()?.sync.as_mut()
    }

    /// This device has a sync account in this session (signed in, or
    /// waiting for a new login).
    pub(super) fn sync_account_active(&self) -> bool {
        self.vault
            .as_ref()
            .and_then(|v| v.sync.as_ref())
            .is_some_and(|s| s.status().is_some())
    }

    /// `<Ctrl-x><y>`: the sync panel (the vault must be unlocked).
    pub(super) fn open_sync_panel(&mut self) {
        let device = self
            .vault
            .as_ref()
            .and_then(|v| v.sync.as_ref())
            .map(|s| s.device_name().to_owned());
        match self.vault.as_ref().map(|v| (v.phase, device)) {
            Some((Phase::Unlocked, Some(device))) => {
                let unicode = crate::ui::unicode_symbols(&self.settings);
                let view = SyncView::new(unicode, device);
                self.screen.open_sync_view(view);
                self.sync_changed();
            }
            Some((Phase::Unlocked, None)) | None => self.screen.flash("Sync needs the vault"),
            Some(_) => self.offer_unlock("sync"),
        }
    }

    /// The status bar and the open sync panel follow the controller.
    fn sync_changed(&mut self) {
        let Some(ctl) = self.vault.as_ref().and_then(|v| v.sync.as_ref()) else {
            return;
        };
        self.screen.set_sync_status(ctl.segment());
        let (status, signed_in, errors) =
            (ctl.status().cloned(), ctl.signed_in(), ctl.item_errors());
        if let Some(view) = self.screen.sync_view_mut() {
            view.set_state(None, status, signed_in, errors);
        }
        self.drain_sync_requests();
    }

    /// Run what the sync screens asked for.
    pub(super) fn drain_sync_requests(&mut self) {
        for request in self.screen.take_sync_requests() {
            self.sync_request(request);
        }
    }

    fn sync_request(&mut self, request: SyncRequest) {
        let email_server = self
            .screen
            .sync_view_mut()
            .and_then(|v| v.info())
            .and_then(|i| Some((i.server_url.clone()?, i.email.clone()?)));
        let Some(ctl) = self.vault.as_mut().and_then(|v| v.sync.as_mut()) else {
            return;
        };
        let ok = match request {
            SyncRequest::Refresh => {
                ctl.refresh_info();
                true
            }
            SyncRequest::SyncNow => ctl.sync_now(),
            SyncRequest::Register {
                server,
                email,
                device,
                password,
                token,
            } => {
                ctl.prepare_registration(server, email, password, &device, token);
                true
            }
            SyncRequest::ConfirmWords(answers) => match ctl.confirm_words(&answers) {
                Some(true) => {
                    if let Some(view) = self.screen.sync_view_mut() {
                        view.words_confirmed();
                    }
                    ctl.finish_registration(None)
                }
                Some(false) => {
                    if let Some(view) = self.screen.sync_view_mut() {
                        view.words_wrong();
                    }
                    true
                }
                None => false,
            },
            SyncRequest::FinishRegistration(token) => ctl.finish_registration(token),
            SyncRequest::CancelRegistration => {
                ctl.cancel_registration();
                true
            }
            SyncRequest::Login {
                server,
                email,
                device,
                password,
                totp,
            } => {
                ctl.start_login(
                    LoginRequest {
                        server_url: server,
                        email,
                        password,
                        totp,
                    },
                    &device,
                );
                true
            }
            SyncRequest::CommitLogin(choices) => ctl.commit_login(&choices),
            SyncRequest::CancelLogin => {
                ctl.cancel_login();
                true
            }
            SyncRequest::Devices => ctl.list_devices(),
            SyncRequest::Revoke { id, this_device } => ctl.revoke_device(id, this_device),
            SyncRequest::ChangePassword { old, new, totp } => ctl.change_password(old, new, totp),
            SyncRequest::TotpStart => ctl.totp_start(),
            SyncRequest::TotpConfirm(code) => ctl.totp_confirm(code),
            SyncRequest::TotpDisable(code) => ctl.totp_disable(code),
            SyncRequest::RecoveryCode => match email_server {
                Some((server, email)) => {
                    ctl.request_recovery_code(server, email, false);
                    true
                }
                None => false,
            },
            SyncRequest::Logout => ctl.logout(),
            SyncRequest::DeleteAccount { password, totp } => ctl.delete_account(password, totp),
            SyncRequest::Team(request) => ctl.team(request),
        };
        if !ok && let Some(view) = self.screen.sync_view_mut() {
            view.failed("not signed in to a sync server, or the flow expired: start again");
        }
    }

    /// "Forgot password?" requests of the locked vault view.
    pub(super) fn vault_sync_request(&mut self, request: VaultRequest) {
        let Some(vault) = self.vault.as_ref() else {
            return;
        };
        let (Some(ctl), Some(engine)) = (vault.sync.as_ref(), vault.engine()) else {
            if let Some(view) = self.screen.vault_view_mut() {
                view.set_error(Some("Sync is not available.".to_owned()));
            }
            return;
        };
        match request {
            VaultRequest::SendRecoveryCode { server, email } => {
                ctl.request_recovery_code(server, email, true);
            }
            VaultRequest::Recover {
                server,
                email,
                code,
                words,
                password,
            } => ctl.recover(engine.clone(), server, email, code, words, password),
            _ => {}
        }
    }

    /// The vault opened locked on a device with a sync account: prefill
    /// the recovery form.
    pub(super) fn sync_recovery_defaults(&mut self) {
        if let Some(vault) = self.vault.as_ref()
            && let (Some(ctl), Some(engine)) = (vault.sync.as_ref(), vault.engine())
        {
            ctl.load_recovery_defaults(engine.store().clone());
        }
    }

    /// The vault was locked: the panel closes, the status bar segment goes,
    /// and "Forgot password?" learns whether this device (still) has a sync
    /// account, which may have changed since the vault was opened.
    pub(super) fn sync_locked(&mut self) {
        self.screen.close_sync_view();
        self.screen.set_sync_status(None);
        self.sync_recovery_defaults();
    }

    fn sync_log(&self, kind: LogKind, text: &str) {
        self.events_tx.log(self.local_session, kind, text);
    }

    /// Sites (and history) changed under the Site Manager: load them again.
    fn sync_reload_sites(&mut self) {
        if let Some(engine) = self.vault.as_ref().and_then(|v| v.engine()).cloned() {
            self.load_sites(engine);
        }
        if let Some(history) = self.history.clone() {
            let tx = self.action_tx.clone();
            tokio::spawn(async move { super::load_history(&history, &tx).await });
        }
    }

    /// An engine event.
    fn sync_event(&mut self, event: SyncEvent) {
        match event {
            SyncEvent::Status(status) => {
                let needs_login = matches!(status, SyncStatus::NeedsLogin);
                let was = self
                    .sync_ctl()
                    .is_some_and(|c| matches!(c.status(), Some(SyncStatus::NeedsLogin)));
                if let Some(ctl) = self.sync_ctl() {
                    ctl.set_status(status);
                    ctl.refresh_info();
                }
                if needs_login && !was {
                    // Usually the password was changed on another device.
                    let text = "Sync: log in again from the sync panel (the account password \
                                may have changed on another device)";
                    self.sync_log(LogKind::Error, text);
                    self.screen.flash(text);
                }
            }
            SyncEvent::Applied { .. } => self.sync_reload_sites(),
            SyncEvent::Toast { level, message } => {
                let kind = match level {
                    ToastLevel::Info => LogKind::Status,
                    ToastLevel::Warn | ToastLevel::Error => LogKind::Error,
                };
                let text = format!("Sync: {message}");
                self.sync_log(kind, &text);
                self.screen.flash(text);
            }
            SyncEvent::ClockSkew { device, ahead_secs } => {
                let text = format!(
                    "Sync: clock skew detected on device {device} ({ahead_secs} s ahead of this one)"
                );
                self.sync_log(LogKind::Error, &text);
                self.screen.flash(text);
            }
            SyncEvent::ItemError { message, .. } => {
                self.sync_log(
                    LogKind::Error,
                    &format!("Sync: a change is kept on this device and not uploaded: {message}"),
                );
            }
            SyncEvent::ApprovalNeeded { field, .. } => {
                let text = format!(
                    "Sync: a site's {field} was changed on another device; it is asked about \
                     before it is used here"
                );
                self.sync_log(LogKind::Status, &text);
                self.screen.flash(text);
            }
            SyncEvent::VaultAccess { vault } => {
                let text = format!(
                    "Sync: your access to {} changed (granted, revoked or a new key)",
                    self.vault_label(vault)
                );
                self.sync_log(LogKind::Status, &text);
                self.screen.flash(text);
                self.sync_reload_sites();
            }
            SyncEvent::VaultAdded { name, .. } => {
                let text = match name {
                    Some(name) => format!(
                        "Sync: you were given access to the team vault “{name}”; its sites are \
                         in the Site Manager under “Team: {name}”"
                    ),
                    None => "Sync: you were given access to a team vault; its sites are in the \
                             Site Manager"
                        .to_owned(),
                };
                self.sync_log(LogKind::Status, &text);
                self.screen.flash(text);
                self.sync_reload_sites();
            }
            SyncEvent::VaultRemoved { vault } => {
                let text = format!(
                    "Sync: your access to {} was revoked; its sites were removed from this device",
                    self.vault_label(vault)
                );
                self.sync_log(LogKind::Status, &text);
                self.screen.flash(text);
                self.sync_reload_sites();
            }
            SyncEvent::RotationAbandoned { vault } => {
                let text = format!(
                    "Sync: a key rotation of {} was abandoned; changes to it wait until a \
                     manager restarts it (sync panel → Teams → shared vaults → R)",
                    self.vault_label(vault)
                );
                self.sync_log(LogKind::Error, &text);
                self.screen.flash(text);
            }
        }
    }

    /// `the team vault “Ops”` (or by id while its name is unknown).
    fn vault_label(&self, vault: VaultId) -> String {
        self.vault_roots.iter().find(|r| r.id == vault).map_or_else(
            || "a team vault".to_owned(),
            |r| format!("the team vault “{}”", r.name),
        )
    }

    /// A key rotation is in progress (removing a member, revoking access).
    fn rotation_progress(&mut self, p: &RotationProgress) {
        let name = self.vault_label(p.vault);
        let text = if p.phase == RotationPhase::Done {
            format!("Sync: the key of {name} was rotated")
        } else if p.total > 0 {
            format!(
                "Sync: rotating the key of {name}: {} {}/{} (changes to it wait)",
                p.phase.label(),
                p.done,
                p.total
            )
        } else {
            format!(
                "Sync: rotating the key of {name}: {} (changes to it wait)",
                p.phase.label()
            )
        };
        if matches!(p.phase, RotationPhase::Starting | RotationPhase::Done) {
            self.sync_log(LogKind::Status, &text);
        }
        self.screen.flash(text);
    }

    fn sync_view_failed(&mut self, e: &AccountError) {
        if let Some(view) = self.screen.sync_view_mut() {
            view.failed(&describe(e));
        }
    }

    /// A sync background call finished, or the engine said something.
    pub(super) fn sync_message(&mut self, msg: SyncMsg) {
        match msg {
            SyncMsg::Opened { generation, result } => {
                if let Some(ctl) = self.sync_ctl()
                    && ctl.current(generation)
                {
                    ctl.opened(result);
                }
            }
            SyncMsg::Event { generation, event } => {
                if self.sync_ctl().is_some_and(|c| c.current(generation)) {
                    self.sync_event(event);
                }
            }
            SyncMsg::Info { generation, result } => {
                if self.sync_ctl().is_some_and(|c| c.current(generation))
                    && let Some(view) = self.screen.sync_view_mut()
                {
                    match result {
                        Ok(info) => {
                            let (s, signed_in, e) = view_state(self.vault.as_ref());
                            if let Some(view) = self.screen.sync_view_mut() {
                                view.set_state(Some(info), s, signed_in, e);
                            }
                        }
                        Err(e) => view.failed(&e),
                    }
                }
            }
            SyncMsg::Prepared(result) => match result {
                Ok(prepared) => {
                    let shown = self.sync_ctl().map(|c| c.prepared(prepared));
                    if let (Some((phrase, numbers)), Some(view)) =
                        (shown, self.screen.sync_view_mut())
                    {
                        view.show_words(phrase, numbers);
                    }
                }
                Err(e) => self.sync_view_failed(&e),
            },
            SyncMsg::Registered { result, prepared } => match result {
                Ok((registered, session)) => {
                    if let Some(ctl) = self.sync_ctl() {
                        ctl.start(session);
                    }
                    self.sync_log(LogKind::Status, "Sync account created; uploading the vault");
                    if let Some(view) = self.screen.sync_view_mut() {
                        view.done(Some(format!(
                            "Account created. {} item(s) are being uploaded. Log in on your other \
                             devices with the same email and password.",
                            registered.queued
                        )));
                    }
                }
                Err(e) => {
                    let kept = prepared.is_some();
                    if let (Some(prepared), Some(ctl)) = (prepared, self.sync_ctl()) {
                        ctl.keep_prepared(prepared);
                    }
                    if let Some(view) = self.screen.sync_view_mut() {
                        if kept {
                            view.show_token(&describe(&e));
                        } else {
                            view.done(None);
                            view.failed(&describe(&e));
                        }
                    }
                }
            },
            SyncMsg::LoginStarted(result) => match result {
                Ok(login) => {
                    let email = self
                        .sync_ctl()
                        .map(|c| c.login_email().to_owned())
                        .unwrap_or_default();
                    let summary = summary(&login, &email);
                    let rows = login.preview().duplicates.clone();
                    if let Some(ctl) = self.sync_ctl() {
                        ctl.login_started(login);
                    }
                    if let Some(view) = self.screen.sync_view_mut() {
                        view.show_login(summary, rows);
                    }
                }
                Err(e) => self.sync_view_failed(&e),
            },
            SyncMsg::LoggedIn(result) => match result {
                Ok((logged_in, session)) => {
                    if let Some(ctl) = self.sync_ctl() {
                        ctl.start(session);
                    }
                    self.sync_reload_sites();
                    self.sync_log(LogKind::Status, "Logged in to the sync account");
                    let mut note = format!(
                        "Logged in. {} item(s) imported from this device, {} downloaded.",
                        logged_in.imported, logged_in.downloaded
                    );
                    if logged_in.password_changed {
                        note.push_str(
                            " The master password of this device is now the account password.",
                        );
                    }
                    if let Some(view) = self.screen.sync_view_mut() {
                        view.done(Some(note));
                    }
                }
                Err(e) => {
                    if let Some(ctl) = self.sync_ctl() {
                        ctl.restart();
                    }
                    if let Some(view) = self.screen.sync_view_mut() {
                        view.done(None);
                        view.failed(&describe(&e));
                    }
                }
            },
            SyncMsg::Devices(result) => match result {
                Ok(rows) => {
                    if let Some(view) = self.screen.sync_view_mut() {
                        view.show_devices(rows);
                    }
                }
                Err(e) => self.sync_view_failed(&e),
            },
            SyncMsg::Revoked(result) => match result {
                Ok(Revoked::Other) => {
                    self.sync_log(LogKind::Status, "Sync: device revoked");
                    if let Some(ctl) = self.sync_ctl() {
                        ctl.list_devices();
                    }
                }
                Ok(Revoked::ThisDevice(_)) => {
                    if let Some(ctl) = self.sync_ctl() {
                        ctl.signed_out();
                    }
                    self.sync_log(
                        LogKind::Status,
                        "Sync: this device was revoked and logged out",
                    );
                    if let Some(view) = self.screen.sync_view_mut() {
                        view.done(Some(
                            "This device was revoked and logged out of sync; its sites stay here."
                                .to_owned(),
                        ));
                    }
                }
                Err(e) => {
                    if let Some(ctl) = self.sync_ctl() {
                        ctl.restart();
                    }
                    self.sync_view_failed(&e);
                }
            },
            SyncMsg::PasswordChanged(result) => match result {
                Ok(_) => {
                    self.sync_log(LogKind::Status, "Sync: account password changed");
                    if let Some(view) = self.screen.sync_view_mut() {
                        view.account_done(Some(
                            "Password changed. It is now the master password of this device; \
                             your other devices must log in again with it."
                                .to_owned(),
                        ));
                    }
                }
                Err(e) => self.sync_view_failed(&e),
            },
            SyncMsg::TotpStarted(result) => match result {
                Ok(setup) => {
                    if let Some(view) = self.screen.sync_view_mut() {
                        view.show_totp(&setup);
                    }
                }
                Err(e) => self.sync_view_failed(&e),
            },
            SyncMsg::TotpConfirmed(result) => self.account_result(
                result,
                "Two-factor authentication is on: logins now ask for a code.",
            ),
            SyncMsg::TotpDisabled(result) => {
                self.account_result(result, "Two-factor authentication is off.");
            }
            SyncMsg::RecoveryCodeSent {
                vault: false,
                result,
            } => self.account_result(
                result,
                "A recovery code was sent to the account's email (if the server can send mail).",
            ),
            SyncMsg::RecoveryCodeSent {
                vault: true,
                result,
            } => {
                if let Some(view) = self.screen.vault_view_mut() {
                    view.set_busy(None);
                    match result {
                        Ok(()) => view.set_note(Some(
                            "A recovery code was sent to the account's email (if the server can \
                             send mail)."
                                .to_owned(),
                        )),
                        Err(e) => view.set_error(Some(describe(&e))),
                    }
                }
            }
            SyncMsg::LoggedOut(result) => match result {
                Ok(report) => {
                    if let Some(ctl) = self.sync_ctl() {
                        ctl.signed_out();
                    }
                    self.sync_log(LogKind::Status, "Logged out of sync");
                    let mut note = "Logged out. Your sites stay on this device.".to_owned();
                    if report.revoke_error.is_some() {
                        note.push_str(
                            " The server could not be told; revoke this device from another one.",
                        );
                    }
                    if let Some(view) = self.screen.sync_view_mut() {
                        view.done(Some(note));
                    }
                }
                Err(e) => {
                    if let Some(ctl) = self.sync_ctl() {
                        ctl.restart();
                    }
                    self.sync_view_failed(&e);
                }
            },
            SyncMsg::AccountDeleted(result) => match result {
                Ok(_) => {
                    if let Some(ctl) = self.sync_ctl() {
                        ctl.signed_out();
                    }
                    self.sync_log(LogKind::Status, "Sync account deleted");
                    if let Some(view) = self.screen.sync_view_mut() {
                        view.done(Some(
                            "The account was deleted. Your sites stay on this device.".to_owned(),
                        ));
                    }
                }
                Err(e) => {
                    if let Some(ctl) = self.sync_ctl() {
                        ctl.restart();
                    }
                    self.sync_view_failed(&e);
                }
            },
            SyncMsg::RecoveryDefaults {
                account,
                server,
                email,
            } => {
                if let Some(view) = self.screen.vault_view_mut() {
                    view.set_sync_account(account);
                    view.set_recovery_defaults(server, email);
                }
            }
            SyncMsg::Team(result) => {
                let changed = matches!(result, Ok(TeamReply::Done(_) | TeamReply::Left(_)));
                if let Some(view) = self.screen.sync_view_mut() {
                    view.team_reply(result);
                }
                if changed {
                    // New or removed vaults, keys and permissions: the
                    // Site Manager roots and the engine's vault list.
                    self.sync_reload_sites();
                    if let Some(ctl) = self.sync_ctl() {
                        ctl.sync_now();
                    }
                }
            }
            SyncMsg::Rotation(progress) => self.rotation_progress(&progress),
            SyncMsg::VaultRoots(roots) => {
                if let Some(view) = self.screen.site_manager_mut() {
                    view.set_vaults(roots.clone());
                }
                self.vault_roots = roots;
            }
            SyncMsg::Recovered(result) => match result {
                Ok(()) => {
                    if let Some(vault) = self.vault.as_mut() {
                        vault.on_unlocked();
                    }
                    self.vault_unlocked(Some(
                        "New master password set with the recovery key; vault unlocked",
                    ));
                }
                Err(e) => {
                    if let Some(view) = self.screen.vault_view_mut() {
                        view.set_error(Some(describe(&e)));
                    }
                }
            },
        }
        self.sync_changed();
    }

    fn account_result(&mut self, result: Result<(), AccountError>, ok: &str) {
        if let Some(view) = self.screen.sync_view_mut() {
            match result {
                Ok(()) => view.account_done(Some(ok.to_owned())),
                Err(e) => view.failed(&describe(&e)),
            }
        }
    }
}

type ViewState = (
    Option<courier_ftp_sync::SyncStatus>,
    bool,
    Vec<(String, String)>,
);

fn view_state(vault: Option<&crate::vault::Vault>) -> ViewState {
    match vault.and_then(|v| v.sync.as_ref()) {
        Some(ctl) => (ctl.status().cloned(), ctl.signed_in(), ctl.item_errors()),
        None => (None, false, Vec::new()),
    }
}
