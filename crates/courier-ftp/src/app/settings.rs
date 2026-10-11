//! The app's side of the settings screen (T68): applying settings live,
//! saving them to the user config, and the vault and trust store work the
//! Security, SFTP and TLS pages ask for.

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{
    model::item::{ItemId, ProxyCredential},
    settings::{FtpProxy, GenericProxy, ProxyServer, Settings},
    trust::{CertTrustStore, HostKeyStore},
    vault::{ItemVaultExt, VaultCertTrustStore, VaultHostKeyStore},
};
use courier_ftp_store::vault::VaultEngine;
use secrecy::SecretString;

use super::{App, Mode};
use crate::{
    action::{Action, Shared},
    ui::settings::{
        ProxyTarget, SecurityInfo, SettingsOpts, SettingsReply, SettingsRequest, SettingsView,
        Trust, VaultState,
    },
    vault::{Phase, Vault},
};

/// The modes listed on the Keybindings page, in order.
const MODES: [Mode; 7] = [
    Mode::Normal,
    Mode::FileList,
    Mode::Queue,
    Mode::Log,
    Mode::Filter,
    Mode::Input,
    Mode::Dialog,
];

/// The proxy server a typed password belongs to.
fn proxy_server(settings: &mut Settings, target: ProxyTarget) -> Option<&mut ProxyServer> {
    match target {
        ProxyTarget::Generic => match &mut settings.proxy.generic {
            GenericProxy::None => None,
            GenericProxy::Http(p) | GenericProxy::Socks4(p) | GenericProxy::Socks5(p) => Some(p),
        },
        ProxyTarget::Ftp => match &mut settings.proxy.ftp_proxy {
            FtpProxy::None => None,
            FtpProxy::UserAtHost(p)
            | FtpProxy::Site(p)
            | FtpProxy::Open(p)
            | FtpProxy::Custom { server: p, .. } => Some(p),
        },
    }
}

/// The FTP proxy's vault item id.
fn ftp_proxy_ref(settings: &Settings) -> Option<String> {
    match &settings.proxy.ftp_proxy {
        FtpProxy::None => None,
        FtpProxy::UserAtHost(p)
        | FtpProxy::Site(p)
        | FtpProxy::Open(p)
        | FtpProxy::Custom { server: p, .. } => p.password_ref.clone(),
    }
}

impl App {
    /// `<F9>`: open the settings screen.
    pub(super) fn open_settings(&mut self) {
        let view = SettingsView::new(self.settings.clone(), self.settings_opts());
        self.screen.open_settings(view);
    }

    fn settings_opts(&self) -> SettingsOpts {
        let keybindings = MODES
            .iter()
            .flat_map(|mode| {
                self.keybindings
                    .own(*mode)
                    .into_iter()
                    .map(move |(keys, action)| (format!("{mode:?}"), keys, action))
            })
            .collect();
        SettingsOpts {
            config_file: self.config_dir.join("config.json").display().to_string(),
            default_log_file: crate::config::get_data_dir()
                .join("session.log")
                .display()
                .to_string(),
            keybindings,
        }
    }

    /// Send the settings screen an answer (through the action channel, so
    /// it arrives like the background tasks' answers).
    fn settings_reply(&self, reply: SettingsReply) {
        let _ = self
            .action_tx
            .send(Action::SettingsReply(Shared::new(reply)));
    }

    /// The vault engine while unlocked.
    fn unlocked_engine(&self) -> Option<VaultEngine> {
        self.vault
            .as_ref()
            .filter(|v| v.phase == Phase::Unlocked)
            .and_then(Vault::engine)
            .cloned()
    }

    /// The settings screen asked for something.
    pub(super) fn settings_request(&mut self, request: &SettingsRequest) {
        match request {
            SettingsRequest::Save {
                settings,
                proxy_passwords,
            } => self.save_from_screen((**settings).clone(), proxy_passwords),
            SettingsRequest::LoadTrust => self.load_trust(None),
            SettingsRequest::ForgetHostKey {
                host,
                port,
                key_type,
            } => {
                let (host, port, key_type) = (host.clone(), *port, key_type.clone());
                self.load_trust(Some(Box::new(move |engine: VaultEngine| {
                    Box::pin(async move {
                        let store = VaultHostKeyStore::new(Arc::new(engine));
                        match store.forget(&host, port, &key_type).await {
                            Ok(true) => Ok(format!("Forgot the {key_type} key of {host}:{port}")),
                            Ok(false) => Ok("That host key was already gone".to_owned()),
                            Err(e) => Err(format!("Could not forget the host key: {e}")),
                        }
                    })
                })));
            }
            SettingsRequest::ForgetCert { host, port, sha256 } => {
                if let Some(net) = &self.net {
                    net.ftp.tls().clear_session_trust();
                }
                let (host, port, sha256) = (host.clone(), *port, *sha256);
                self.load_trust(Some(Box::new(move |engine: VaultEngine| {
                    Box::pin(async move {
                        let store = VaultCertTrustStore::new(Arc::new(engine));
                        match store.forget(&host, port, &sha256).await {
                            Ok(true) => Ok(format!("Forgot the certificate of {host}:{port}")),
                            Ok(false) => Ok("That certificate was already gone".to_owned()),
                            Err(e) => Err(format!("Could not forget the certificate: {e}")),
                        }
                    })
                })));
            }
            SettingsRequest::LoadSecurity => self.load_security(),
            SettingsRequest::ChangePassword { old, new } => {
                let Some(engine) = self.unlocked_engine() else {
                    self.settings_reply(SettingsReply::Failed("The vault is locked".to_owned()));
                    return;
                };
                let (old, new) = (old.clone(), new.clone());
                let tx = self.action_tx.clone();
                tokio::spawn(async move {
                    let reply = match engine.change_password(&old, &new).await {
                        Ok(()) => SettingsReply::Done("Master password changed".to_owned()),
                        Err(e) => SettingsReply::Failed(format!(
                            "Could not change the master password: {e}"
                        )),
                    };
                    let _ = tx.send(Action::SettingsReply(Shared::new(reply)));
                });
            }
            SettingsRequest::SetKeyring(enable) => {
                let Some(engine) = self.unlocked_engine() else {
                    self.settings_reply(SettingsReply::Failed("The vault is locked".to_owned()));
                    return;
                };
                let enable = *enable;
                let tx = self.action_tx.clone();
                tokio::spawn(async move {
                    let reply = match engine.set_keyring_unlock(enable).await {
                        Ok(()) if enable => {
                            SettingsReply::Done("Keyring unlock is on for this device".to_owned())
                        }
                        Ok(()) => SettingsReply::Done("Keyring unlock is off".to_owned()),
                        Err(e) => {
                            SettingsReply::Failed(format!("Could not change keyring unlock: {e}"))
                        }
                    };
                    let _ = tx.send(Action::SettingsReply(Shared::new(reply)));
                    let info = security_info(&engine).await;
                    let _ = tx.send(Action::SettingsReply(Shared::new(SettingsReply::Security(
                        info,
                    ))));
                });
            }
            SettingsRequest::LockNow => {
                if self.unlocked_engine().is_some() {
                    self.lock_vault(None);
                }
                self.load_security();
            }
        }
    }

    /// OK/Apply: typed proxy passwords go to the vault first (their item
    /// ids into the settings), then the settings are saved and applied.
    fn save_from_screen(
        &mut self,
        mut settings: Settings,
        passwords: &[(ProxyTarget, SecretString)],
    ) {
        if passwords.is_empty() {
            // No config directory (some tests): apply without saving.
            let saved = if self.config_dir.as_os_str().is_empty() {
                Ok(())
            } else {
                settings.save_user(&self.config_dir)
            };
            match saved {
                Ok(()) => {
                    self.apply_settings(settings);
                    self.settings_reply(SettingsReply::Saved);
                }
                Err(e) => self.settings_reply(SettingsReply::Failed(format!(
                    "Could not save the settings: {e}"
                ))),
            }
            return;
        }
        let Some(engine) = self.unlocked_engine() else {
            self.settings_reply(SettingsReply::Failed(
                "Unlock the vault (<Ctrl-x><u>) to store proxy passwords".to_owned(),
            ));
            return;
        };
        let mut writes = Vec::new();
        for (target, password) in passwords {
            let Some(server) = proxy_server(&mut settings, *target) else {
                continue;
            };
            let id = server
                .password_ref
                .as_deref()
                .and_then(|r| r.parse().ok())
                .unwrap_or_else(ItemId::new);
            server.password_ref = Some(id.to_string());
            let label = match target {
                ProxyTarget::Generic => "Generic proxy",
                ProxyTarget::Ftp => "FTP proxy",
            };
            writes.push((
                id,
                ProxyCredential {
                    label: label.to_owned(),
                    user: server.user.clone().unwrap_or_default(),
                    password: Some(password.clone()),
                    read_only: false,
                },
            ));
        }
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            for (id, view) in writes {
                if let Err(e) = engine.put_view(id, None, view).await {
                    let reply =
                        SettingsReply::Failed(format!("Could not store the proxy password: {e}"));
                    let _ = tx.send(Action::SettingsReply(Shared::new(reply)));
                    return;
                }
            }
            // Stored: save the settings that point at the items.
            let _ = tx.send(Action::SettingsRequest(Shared::new(
                SettingsRequest::Save {
                    settings: Box::new(settings),
                    proxy_passwords: Vec::new(),
                },
            )));
        });
    }

    /// New settings from the settings screen: apply everything that can
    /// change while running. Connection settings reach new connections.
    pub(crate) fn apply_settings(&mut self, new: Settings) {
        if new.logging != self.settings.logging {
            self.apply_logging(&new.logging);
        }
        self.screen.apply_settings(&new);
        self.sequencer
            .set_timeout(Duration::from_millis(new.interface.key_sequence_timeout_ms));
        if new.cache != self.settings.cache {
            self.cache.configure(&new.cache);
        }
        if let Some(vault) = &mut self.vault {
            vault.configure(&new.vault);
            vault.set_ftp_proxy_ref(ftp_proxy_ref(&new));
        }
        if let Some(net) = &self.net {
            net.set_settings(&new);
        }
        if new != self.settings {
            self.transfer_settings_changed(&new);
        }
        self.settings = new;
    }

    /// Tell the transfer engine (T56): speed limits, burst tolerance,
    /// concurrency and the other transfer settings apply to running
    /// transfers (its `SpeedLimiter` is updated in place, T44); the
    /// directory expander (T43) uses the new empty-dirs, symlink,
    /// invalid-character and filter settings for what is queued next. The
    /// successful-transfers cap applies to the queue at once; turning
    /// `queue.persist` on or off takes effect at the next start.
    fn transfer_settings_changed(&mut self, settings: &Settings) {
        self.transfers.settings_changed(settings);
        if settings.queue.max_successful != self.settings.queue.max_successful {
            courier_ftp_core::queue::lock_queue(&self.transfers.queue)
                .set_max_successful(settings.queue.max_successful);
        }
    }

    /// Read the trust stores for the SFTP and TLS pages, after running
    /// `change` (a forget) first.
    fn load_trust(&mut self, change: Option<TrustChange>) {
        let Some(vault) = &self.vault else {
            self.settings_reply(SettingsReply::Trust {
                host_keys: Trust::NoVault,
                certs: Trust::NoVault,
            });
            return;
        };
        let Some(engine) = vault
            .engine()
            .filter(|_| vault.phase == Phase::Unlocked)
            .cloned()
        else {
            if change.is_some() {
                self.settings_reply(SettingsReply::Failed("The vault is locked".to_owned()));
            }
            self.settings_reply(SettingsReply::Trust {
                host_keys: Trust::Locked,
                certs: Trust::Locked,
            });
            return;
        };
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let send = |reply| {
                let _ = tx.send(Action::SettingsReply(Shared::new(reply)));
            };
            if let Some(change) = change {
                send(match change(engine.clone()).await {
                    Ok(text) => SettingsReply::Done(text),
                    Err(text) => SettingsReply::Failed(text),
                });
            }
            let item_vault = Arc::new(engine);
            let host_keys = match VaultHostKeyStore::new(item_vault.clone()).list().await {
                Ok(mut list) => {
                    list.sort_by(|a, b| (&a.host, a.port).cmp(&(&b.host, b.port)));
                    Trust::Loaded(list)
                }
                Err(e) => {
                    tracing::debug!(error = %e, "host keys not listed");
                    Trust::Locked
                }
            };
            let certs = match VaultCertTrustStore::new(item_vault).list().await {
                Ok(mut list) => {
                    list.sort_by(|a, b| (&a.host, a.port).cmp(&(&b.host, b.port)));
                    Trust::Loaded(list)
                }
                Err(e) => {
                    tracing::debug!(error = %e, "certificates not listed");
                    Trust::Locked
                }
            };
            send(SettingsReply::Trust { host_keys, certs });
        });
    }

    /// The vault state for the Security page.
    fn load_security(&mut self) {
        let state = match self.vault.as_ref().map(|v| v.phase) {
            None => VaultState::None,
            Some(Phase::Unlocked) => VaultState::Unlocked,
            Some(Phase::Locked) => VaultState::Locked,
            Some(_) => VaultState::Unavailable,
        };
        match self.unlocked_engine() {
            Some(engine) => {
                let tx = self.action_tx.clone();
                tokio::spawn(async move {
                    let info = security_info(&engine).await;
                    let _ = tx.send(Action::SettingsReply(Shared::new(SettingsReply::Security(
                        info,
                    ))));
                });
            }
            None => self.settings_reply(SettingsReply::Security(SecurityInfo {
                state,
                keyring_enabled: false,
                cost: None,
            })),
        }
    }
}

/// A trust store change run before the stores are listed again.
type TrustChange = Box<
    dyn FnOnce(
            VaultEngine,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<String, String>> + Send>,
        > + Send,
>;

/// The Security page's view of an unlocked engine.
async fn security_info(engine: &VaultEngine) -> SecurityInfo {
    let status = engine.status().await.ok();
    SecurityInfo {
        state: match status.as_ref().map(|s| s.state) {
            Some(courier_ftp_core::vault::VaultState::Unlocked) => VaultState::Unlocked,
            Some(courier_ftp_core::vault::VaultState::Locked) => VaultState::Locked,
            _ => VaultState::Unavailable,
        },
        keyring_enabled: status.is_some_and(|s| s.keyring_enabled),
        cost: Some(engine.cost()),
    }
}
