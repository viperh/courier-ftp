//! The app's side of the network configuration wizard (T72): the saved
//! FTP sites to test with, and running the test
//! (`courier_ftp_proto_ftp::probe`) in a background task whose progress
//! comes back as [`WizardReply`]s.

use std::{str::FromStr, time::Duration};

use courier_ftp_core::{
    backend::ConnectInfo,
    events::SessionId,
    model::{LogonType, ServerUrl},
    settings::Settings,
    transfer::quick_connect_info,
};
use courier_ftp_proto_ftp::{
    control::{FtpContext, FtpOptions},
    probe::{self, ProbeOptions},
};
use secrecy::ExposeSecret;

use super::App;
use crate::{
    action::{Action, Shared},
    sites::SitesSlot,
    ui::settings::{
        SettingsReply,
        wizard::{ProbeTarget, WizardReply, WizardRequest},
    },
};

/// How long a data connection may take during the test (from the
/// connection timeout, kept short enough that a blocked active port is
/// reported soon).
fn data_timeout(settings: &Settings) -> Duration {
    Duration::from_secs(settings.connection.timeout_secs.clamp(5, 30))
}

impl App {
    /// The wizard asked for something.
    pub(super) fn wizard_request(&mut self, request: &WizardRequest) {
        let tx = self.action_tx.clone();
        let send = move |reply: WizardReply| {
            let _ = tx.send(Action::SettingsReply(Shared::new(SettingsReply::Wizard(
                reply,
            ))));
        };
        match request {
            WizardRequest::LoadSites => {
                let slot = self.sites.clone();
                tokio::spawn(async move { send(WizardReply::Sites(ftp_sites(&slot).await)) });
            }
            WizardRequest::Probe {
                run,
                target,
                settings,
                cancel,
            } => {
                let run = *run;
                let slot = self.sites.clone();
                let target = target.clone();
                let settings = (**settings).clone();
                let cancel = cancel.clone();
                let session = SessionId::next();
                let events = self.events_tx.clone();
                // The factory's options carry the certificate trust and the
                // FTP proxy password; without one (tests) plain options.
                let net = self.net.clone();
                tokio::spawn(async move {
                    let info = match resolve(&slot, target).await {
                        Ok(info) => info,
                        Err(message) => {
                            send(WizardReply::ProbeFailed { run, message });
                            return;
                        }
                    };
                    let opts = match &net {
                        Some(net) => net
                            .ftp
                            .create_ftp(&info, session, events.clone())
                            .options_mut()
                            .clone(),
                        None => {
                            let mut opts = FtpOptions::from_connect_info(&info, &settings);
                            opts.encryption = info.ftp_encryption().unwrap_or_default();
                            opts
                        }
                    };
                    let ctx = FtpContext {
                        session,
                        events,
                        cancel,
                    };
                    let progress = send.clone();
                    probe::run(
                        &opts,
                        ctx,
                        &settings,
                        &ProbeOptions::with_timeout(data_timeout(&settings)),
                        move |event| progress(WizardReply::Probe { run, event }),
                    )
                    .await;
                    send(WizardReply::ProbeDone { run });
                });
            }
        }
    }
}

/// The saved FTP sites by path, sorted.
async fn ftp_sites(
    slot: &SitesSlot,
) -> Result<Vec<(courier_ftp_core::model::item::ItemId, String)>, String> {
    let guard = slot.lock().await;
    let sites = guard
        .as_ref()
        .ok_or("Unlock the vault to test with a saved site")?;
    let tree = sites.tree();
    let mut list: Vec<_> = tree
        .sites()
        .filter(|s| s.protocol.is_ftp())
        .map(|s| (s.id, tree.path_of(s.id).unwrap_or_else(|| s.name.clone())))
        .collect();
    list.sort_by_key(|(_, name)| name.to_lowercase());
    Ok(list)
}

/// What to connect to for `target`.
async fn resolve(slot: &SitesSlot, target: ProbeTarget) -> Result<ConnectInfo, String> {
    let (mut info, typed) = match target {
        ProbeTarget::Site { id, password } => {
            let connect = crate::sites::connect(slot, id).await?;
            (connect.info, password)
        }
        ProbeTarget::Address { url, password } => {
            let text = if url.contains("://") {
                url
            } else {
                format!("ftp://{url}")
            };
            let parsed = ServerUrl::from_str(&text).map_err(|e| e.to_string())?;
            let typed = parsed.password.clone().or(password);
            (quick_connect_info(&parsed.address, typed.as_ref()), typed)
        }
    };
    if !info.address.protocol.is_ftp() {
        return Err(
            "The wizard tests FTP servers: use an ftp://, ftpes:// or ftps:// address".to_owned(),
        );
    }
    // The settings screen covers the panes, so nothing is asked during the
    // test: the password comes from the wizard's field.
    if let LogonType::AskForPassword { user } | LogonType::Interactive { user } = &info.logon {
        match typed.filter(|p| !p.expose_secret().is_empty()) {
            Some(password) => {
                info.logon = LogonType::Normal {
                    user: user.clone(),
                    password,
                };
            }
            None => {
                return Err(format!(
                    "Enter the password for {user} in the Password field"
                ));
            }
        }
    }
    Ok(info)
}
