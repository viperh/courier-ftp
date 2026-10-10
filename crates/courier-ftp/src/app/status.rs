//! The app side of the status bar (T57): the indicator sources later tasks feed,
//! assembling [`StatusInfo`] before each draw, the transfer-type and speed-limit
//! toggles and the server information dialog.

use courier_ftp_core::{
    backend::SessionSecurityInfo, model::ServerAddress, settings::enums::TransferTypeChoice,
};
use tokio::time::Instant;

use super::App;
use crate::{
    action::Action,
    components::{
        prompts::CertificateChainDialog,
        server_info::{ServerInfoChoice, ServerInfoDialog, ServerInfoView},
        status_bar::{
            KeyHint, MessageLevel, QueueSummary, SecurityIndicator, SpeedLimitIndicator,
            StatusInfo, SyncIndicator, VaultIndicator,
        },
    },
};

#[cfg(test)]
mod tests;

/// The browsing session of the focused tab, as the status bar and the server info
/// dialog see it (T61 fills it from `SessionHandle::security_info()`).
#[derive(Debug, Clone)]
pub(crate) struct SessionSnapshot {
    /// The negotiated security.
    pub info: SessionSecurityInfo,
    /// Where it is connected.
    pub addr: ServerAddress,
}

/// Indicator sources that do not exist yet in M1; later tasks set them (`None` /
/// `false` hides the segment).
#[derive(Debug, Clone, Default)]
pub(crate) struct StatusSources {
    /// Focused tab's browsing session (T61).
    pub session: Option<SessionSnapshot>,
    /// The focused tab is connecting (T58/T61).
    pub connecting: bool,
    /// Vault state (T60).
    pub vault: Option<VaultIndicator>,
    /// `PromptQueue::badge` (T69).
    pub prompts_badge: Option<String>,
    /// Any side filtered (T47/T53/T67).
    pub filters_active: bool,
    /// Synchronized browsing (T66).
    pub sync_browsing: bool,
    /// Directory comparison (T66).
    pub comparison: bool,
    /// Sync status (T90).
    pub sync: Option<SyncIndicator>,
    /// Queue summary (T40/T41).
    pub queue: Option<QueueSummary>,
}

impl App {
    /// The bar's content (the message is added by the main screen).
    pub(crate) fn status_info<'a>(&self, pending: &'a str, hints: &'a [KeyHint]) -> StatusInfo<'a> {
        let s = &self.status_sources;
        let security = if s.connecting {
            SecurityIndicator::Connecting
        } else {
            s.session
                .as_ref()
                .map_or(SecurityIndicator::NotConnected, |x| {
                    SecurityIndicator::from_security_info(&x.info, Some(&x.addr))
                })
        };
        let settings = self.settings.current();
        let t = &settings.transfers;
        StatusInfo {
            security,
            vault: s.vault,
            prompts_badge: s.prompts_badge.clone(),
            transfer_type: Some(settings.file_types.default_type),
            speed: Some(SpeedLimitIndicator {
                enabled: t.speed_limit_enabled,
                down_kib: t.download_limit_kib,
                up_kib: t.upload_limit_kib,
            }),
            filters_active: s.filters_active,
            sync_browsing: s.sync_browsing,
            comparison: s.comparison,
            sync: s.sync,
            queue: s.queue,
            pending_keys: pending,
            message: None,
            hints,
        }
    }

    /// A transient message of `level`.
    pub(crate) fn notify(&mut self, level: MessageLevel, text: &str) {
        self.main.status_bar_mut().show(text, level, Instant::now());
        self.dirty = true;
    }

    /// `CycleTransferType`: `Auto → Binary → ASCII → Auto`, saved.
    pub(crate) fn cycle_transfer_type(&mut self) {
        let next = match self.settings.current().file_types.default_type {
            TransferTypeChoice::Auto => TransferTypeChoice::Binary,
            TransferTypeChoice::Binary => TransferTypeChoice::Ascii,
            TransferTypeChoice::Ascii => TransferTypeChoice::Auto,
        };
        self.settings
            .set_transient(|s| s.file_types.default_type = next);
        self.schedule_save();
        let name = match next {
            TransferTypeChoice::Auto => "Auto",
            TransferTypeChoice::Binary => "Binary",
            TransferTypeChoice::Ascii => "ASCII",
        };
        self.notify(MessageLevel::Info, &format!("Transfer type: {name}"));
    }

    /// `ToggleSpeedLimit`: flips `transfers.speed_limit_enabled` and saves; refused
    /// when both limits are 0. The engine picks the change up from the settings
    /// (T41/T44 send `EngineCommand::SettingsChanged`).
    pub(crate) fn toggle_speed_limit(&mut self) {
        let t = self.settings.current().transfers.clone();
        if !t.speed_limit_enabled && t.download_limit_kib == 0 && t.upload_limit_kib == 0 {
            let arrow = if self.symbols.unicode { "→" } else { "->" };
            self.notify(
                MessageLevel::Warning,
                &format!("No speed limits set (Settings {arrow} Transfers)"),
            );
            return;
        }
        let on = !t.speed_limit_enabled;
        self.settings
            .set_transient(|s| s.transfers.speed_limit_enabled = on);
        self.schedule_save();
        self.notify(
            MessageLevel::Info,
            if on {
                "Speed limits on"
            } else {
                "Speed limits off"
            },
        );
    }

    /// `ServerInfo`: the server information dialog for the focused tab.
    pub(crate) fn open_server_info(&mut self) {
        let tab = "Tab 1";
        let view = self.status_sources.session.as_ref().map_or_else(
            || ServerInfoView::not_connected_in(tab),
            |s| ServerInfoView::from_session(&s.info, &s.addr, tab),
        );
        let dialog = ServerInfoDialog::new(view, self.symbols.unicode);
        self.modals.push_then(dialog, |choice| {
            (choice == Some(ServerInfoChoice::Details)).then_some(Action::CertificateChain)
        });
        self.dirty = true;
    }

    /// `[ Details ]` of the server information dialog: the session's certificate
    /// chain (T69's details view).
    pub(crate) fn open_certificate_chain(&mut self) {
        let chain = self
            .status_sources
            .session
            .as_ref()
            .and_then(|s| s.info.tls.as_ref())
            .map(|t| t.chain.clone());
        match chain {
            Some(chain) => {
                let dialog = CertificateChainDialog::new(chain, time::OffsetDateTime::now_utc());
                self.modals.push_then(dialog, |_| None);
                self.dirty = true;
            }
            None => self.notify(MessageLevel::Info, "No certificate to show"),
        }
    }
}
