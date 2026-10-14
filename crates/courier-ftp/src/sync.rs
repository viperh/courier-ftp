//! The app's side of device sync (T90, feature `sync`): the signed-in
//! [`SyncSession`] and its running engine while the vault is unlocked, the
//! account flows in progress (a registration waiting for its recovery words,
//! a login waiting for the duplicate choices), and the background calls the
//! sync screens ask for.
//!
//! Everything slow (HTTP, OPAQUE, Argon2) runs in spawned tasks that answer
//! with [`Action::Sync`]; the engine's [`SyncEvent`]s are forwarded the same
//! way, so the event loop needs no extra channel. Results of a session that
//! ended (the vault locked, the user logged out) carry an old generation and
//! are dropped.
//!
//! The screens are in `ui::sync` and never call the network themselves.

use std::sync::Mutex;

use courier_ftp_core::settings::Settings;
use courier_ftp_proto::auth::DeviceSummary;
use courier_ftp_store::vault::VaultEngine;
use courier_ftp_sync::{
    AccountConfig, AccountError, EngineConfig, Revoked, RotationError, RotationProgress, SyncEvent,
    SyncHandle, SyncSession, SyncStatus, TeamError, Teams, TotpSetup, TrustError,
    account::{
        self, DuplicateChoice, LoggedIn, LoginRequest, LoginSession, LogoutReport,
        PreparedRegistration, Registered, RegistrationToken,
    },
    info::LocalSyncInfo,
};
use secrecy::SecretString;
use tokio::sync::mpsc::{self, UnboundedSender};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    action::{Action, Shared},
    ui::{
        SyncLevel,
        sync::{Safety, TeamReply, TeamRequest},
    },
};

/// A value handed over exactly once through a cloneable [`Action`].
pub(crate) struct Once<T>(Mutex<Option<T>>);

impl<T> Once<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(Mutex::new(Some(value)))
    }

    /// The value, the first time.
    pub(crate) fn take(&self) -> Option<T> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Once<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.try_lock().ok().as_deref() {
            Some(Some(v)) => v.fmt(f),
            _ => f.write_str("(taken)"),
        }
    }
}

/// A finished background call or an engine event.
pub(crate) enum SyncMsg {
    /// [`SyncSession::open`] after unlock.
    Opened {
        generation: u64,
        result: Result<Option<SyncSession>, AccountError>,
    },
    /// From the running engine.
    Event {
        generation: u64,
        event: SyncEvent,
    },
    /// [`courier_ftp_sync::info::local_info`] for the sync panel.
    Info {
        generation: u64,
        result: Result<LocalSyncInfo, String>,
    },
    /// Registration step 1.
    Prepared(Result<PreparedRegistration, AccountError>),
    /// Registration step 2; `prepared` comes back on failure so a token can
    /// be added without new recovery words.
    Registered {
        result: Result<(Registered, SyncSession), AccountError>,
        prepared: Option<PreparedRegistration>,
    },
    LoginStarted(Result<LoginSession, AccountError>),
    LoggedIn(Result<(LoggedIn, SyncSession), AccountError>),
    Devices(Result<Vec<DeviceSummary>, AccountError>),
    Revoked(Result<Revoked, AccountError>),
    PasswordChanged(Result<u32, AccountError>),
    TotpStarted(Result<TotpSetup, AccountError>),
    TotpConfirmed(Result<(), AccountError>),
    TotpDisabled(Result<(), AccountError>),
    /// A recovery code was requested from the sync panel (`vault: false`)
    /// or the locked vault's "Forgot password?" (`vault: true`).
    RecoveryCodeSent {
        vault: bool,
        result: Result<(), AccountError>,
    },
    LoggedOut(Result<LogoutReport, AccountError>),
    AccountDeleted(Result<LogoutReport, AccountError>),
    /// The locked device's account, to prefill the recovery form.
    RecoveryDefaults {
        /// This device has a sync account (a recovery is possible).
        account: bool,
        server: Option<String>,
        email: Option<String>,
    },
    /// `recover_locked_device`: the vault is unlocked under the new password.
    Recovered(Result<(), AccountError>),
    /// A teams screen call (T90 §5).
    Team(Result<TeamReply, String>),
    /// A vault key rotation is in progress (removing a member, revoking).
    Rotation(RotationProgress),
    /// The Site Manager's vault roots (T90 §6).
    VaultRoots(Vec<crate::sites::VaultRoot>),
}

impl std::fmt::Debug for SyncMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Names only: results hold sessions, keys and recovery material.
        f.write_str(match self {
            Self::Opened { .. } => "Opened",
            Self::Event { .. } => "Event",
            Self::Info { .. } => "Info",
            Self::Prepared(_) => "Prepared",
            Self::Registered { .. } => "Registered",
            Self::LoginStarted(_) => "LoginStarted",
            Self::LoggedIn(_) => "LoggedIn",
            Self::Devices(_) => "Devices",
            Self::Revoked(_) => "Revoked",
            Self::PasswordChanged(_) => "PasswordChanged",
            Self::TotpStarted(_) => "TotpStarted",
            Self::TotpConfirmed(_) => "TotpConfirmed",
            Self::TotpDisabled(_) => "TotpDisabled",
            Self::RecoveryCodeSent { .. } => "RecoveryCodeSent",
            Self::LoggedOut(_) => "LoggedOut",
            Self::AccountDeleted(_) => "AccountDeleted",
            Self::RecoveryDefaults { .. } => "RecoveryDefaults",
            Self::Recovered(_) => "Recovered",
            Self::Team(_) => "Team",
            Self::Rotation(_) => "Rotation",
            Self::VaultRoots(_) => "VaultRoots",
        })
    }
}

/// The action that carries `msg` to the event loop.
pub(crate) fn action(msg: SyncMsg) -> Action {
    Action::Sync(Shared::new(Once::new(msg)))
}

/// This machine's name, the default device name.
pub(crate) fn default_device_name() -> String {
    hostname::get()
        .ok()
        .map(|h| h.to_string_lossy().trim().to_owned())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "courier-ftp device".to_owned())
}

/// See the module docs.
pub(crate) struct SyncCtl {
    tx: UnboundedSender<Action>,
    cfg: AccountConfig,
    engine_cfg: EngineConfig,
    /// Bumped whenever the session ends, so late results are dropped.
    generation: u64,
    /// The unlocked vault.
    vault: Option<VaultEngine>,
    session: Option<SyncSession>,
    handle: Option<SyncHandle>,
    /// What the status bar shows; `None`: no sync account, or locked.
    status: Option<SyncStatus>,
    /// A registration waiting for its recovery words to be confirmed.
    prepared: Option<PreparedRegistration>,
    /// The token typed on the registration form, for step 2.
    token: Option<RegistrationToken>,
    /// A login waiting for the duplicate choices.
    login: Option<LoginSession>,
    /// The email of the login in progress.
    login_email: String,
}

impl std::fmt::Debug for SyncCtl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncCtl")
            .field("generation", &self.generation)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl SyncCtl {
    pub(crate) fn new(tx: UnboundedSender<Action>, settings: &Settings) -> Self {
        Self {
            tx,
            cfg: AccountConfig::new(default_device_name()),
            engine_cfg: EngineConfig::from_settings(&settings.sync),
            generation: 0,
            vault: None,
            session: None,
            handle: None,
            status: None,
            prepared: None,
            token: None,
            login: None,
            login_email: String::new(),
        }
    }

    /// Replace the account settings (tests: the cheap OPAQUE KSF).
    #[cfg(test)]
    pub(crate) fn set_config(&mut self, cfg: AccountConfig, engine: EngineConfig) {
        self.cfg = cfg;
        self.engine_cfg = engine;
    }

    /// New `sync.*` settings: used from the next engine start (unlock,
    /// login).
    pub(crate) fn settings_changed(&mut self, settings: &courier_ftp_core::settings::SyncSettings) {
        self.engine_cfg = EngineConfig::from_settings(settings);
    }

    /// The name this device registers or logs in with by default.
    pub(crate) fn device_name(&self) -> &str {
        &self.cfg.device.name
    }

    fn spawn<F>(&self, f: F)
    where
        F: std::future::Future<Output = SyncMsg> + Send + 'static,
    {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(action(f.await));
        });
    }

    fn cfg_named(&self, device: &str) -> AccountConfig {
        let mut cfg = self.cfg.clone();
        let device = device.trim();
        if !device.is_empty() {
            device.clone_into(&mut cfg.device.name);
        }
        cfg
    }

    /// The vault was unlocked: open the session (if this device is signed
    /// in) and start the engine.
    pub(crate) fn unlocked(&mut self, vault: VaultEngine) {
        self.vault = Some(vault.clone());
        let generation = self.generation;
        let cfg = self.cfg.clone();
        self.spawn(async move {
            SyncMsg::Opened {
                generation,
                result: SyncSession::open(&vault, cfg).await,
            }
        });
    }

    /// The vault is being locked: forget the session and any flow in
    /// progress. Returns the running engine for the caller to stop before
    /// the vault drops its keys.
    #[must_use]
    pub(crate) fn locked(&mut self) -> Option<SyncHandle> {
        let handle = self.end_session();
        self.vault = None;
        self.prepared = None;
        self.token = None;
        self.login = None;
        handle
    }

    fn end_session(&mut self) -> Option<SyncHandle> {
        self.generation += 1;
        self.session = None;
        self.status = None;
        self.handle.take()
    }

    /// Whether `generation` is the current one.
    pub(crate) fn current(&self, generation: u64) -> bool {
        generation == self.generation
    }

    /// [`SyncMsg::Opened`].
    pub(crate) fn opened(&mut self, result: Result<Option<SyncSession>, AccountError>) {
        match result {
            Ok(Some(session)) => self.start(session),
            Ok(None) => self.status = None,
            Err(AccountError::NeedsLogin) => self.status = Some(SyncStatus::NeedsLogin),
            Err(e) => {
                tracing::debug!(error = %e, "sync session not opened");
                self.status = Some(SyncStatus::Error(e.to_string()));
            }
        }
    }

    /// Run the engine of a new session (after unlock, registration, login).
    pub(crate) fn start(&mut self, session: SyncSession) {
        if let Some(handle) = self.handle.take() {
            tokio::spawn(handle.shutdown());
        }
        self.generation += 1;
        let generation = self.generation;
        let (etx, mut erx) = mpsc::unbounded_channel();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            while let Some(event) = erx.recv().await {
                if tx
                    .send(action(SyncMsg::Event { generation, event }))
                    .is_err()
                {
                    break;
                }
            }
        });
        let handle = session.start_engine(self.engine_cfg.clone(), Some(etx));
        self.status = Some(handle.status());
        self.handle = Some(handle);
        self.session = Some(session);
    }

    /// An engine status change.
    pub(crate) fn set_status(&mut self, status: SyncStatus) {
        self.status = Some(status);
    }

    pub(crate) fn status(&self) -> Option<&SyncStatus> {
        self.status.as_ref()
    }

    /// The status bar segment.
    pub(crate) fn segment(&self) -> Option<(String, SyncLevel)> {
        let s = self.status.as_ref()?;
        let level = match s {
            SyncStatus::Synced => SyncLevel::Ok,
            SyncStatus::Syncing => SyncLevel::Busy,
            SyncStatus::Offline { .. } | SyncStatus::NeedsLogin => SyncLevel::Warn,
            SyncStatus::Error(_) => SyncLevel::Error,
        };
        Some((s.short(), level))
    }

    pub(crate) fn signed_in(&self) -> bool {
        self.session.is_some()
    }

    /// Items held back from pushing, with the reason.
    pub(crate) fn item_errors(&self) -> Vec<(String, String)> {
        self.handle
            .as_ref()
            .map(|h| {
                h.item_errors()
                    .into_iter()
                    .map(|(id, m)| (id.to_string(), m))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The account email, server and per-vault state for the panel.
    pub(crate) fn refresh_info(&self) {
        let Some(vault) = self.vault.clone() else {
            return;
        };
        let generation = self.generation;
        self.spawn(async move {
            SyncMsg::Info {
                generation,
                result: courier_ftp_sync::info::local_info(vault.store())
                    .await
                    .map_err(|e| e.to_string()),
            }
        });
    }

    /// "Sync now".
    pub(crate) fn sync_now(&self) -> bool {
        match &self.handle {
            Some(handle) => {
                handle.request_sync();
                true
            }
            None => false,
        }
    }

    // ---- registration -------------------------------------------------

    pub(crate) fn prepare_registration(
        &mut self,
        server: String,
        email: String,
        password: SecretString,
        device: &str,
        token: Option<RegistrationToken>,
    ) {
        let Some(vault) = self.vault.clone() else {
            return;
        };
        self.cfg = self.cfg_named(device);
        self.token = token;
        self.prepared = None;
        let cfg = self.cfg.clone();
        self.spawn(async move {
            SyncMsg::Prepared(
                account::prepare_registration(&vault, &server, &email, &password, &cfg).await,
            )
        });
    }

    /// Step 1 done: keep it, and return the words to show once.
    pub(crate) fn prepared(
        &mut self,
        prepared: PreparedRegistration,
    ) -> (Zeroizing<String>, [usize; 3]) {
        let words = (prepared.recovery_phrase(), prepared.confirm_word_numbers());
        self.prepared = Some(prepared);
        words
    }

    /// Checks the re-typed words; `None` when no registration is waiting.
    pub(crate) fn confirm_words(&mut self, answers: &[Zeroizing<String>; 3]) -> Option<bool> {
        let prepared = self.prepared.as_mut()?;
        let answers: [&str; 3] = [&answers[0], &answers[1], &answers[2]];
        Some(prepared.confirm_words(&answers))
    }

    /// Registration step 2 (with a token typed after the server asked).
    pub(crate) fn finish_registration(&mut self, token: Option<RegistrationToken>) -> bool {
        let (Some(vault), Some(prepared)) = (self.vault.clone(), self.prepared.take()) else {
            return false;
        };
        if token.is_some() {
            self.token = token;
        }
        let token = self.token.clone();
        let cfg = self.cfg.clone();
        self.spawn(async move {
            let result =
                account::finish_registration(&vault, &prepared, token.as_ref(), &cfg).await;
            let prepared = result.is_err().then_some(prepared);
            SyncMsg::Registered { result, prepared }
        });
        true
    }

    /// Step 2 failed: keep the confirmed registration for a retry.
    pub(crate) fn keep_prepared(&mut self, prepared: PreparedRegistration) {
        self.prepared = Some(prepared);
    }

    /// The registration was abandoned: the keys and words are dropped.
    pub(crate) fn cancel_registration(&mut self) {
        self.prepared = None;
        self.token = None;
    }

    // ---- login --------------------------------------------------------

    pub(crate) fn start_login(&mut self, request: LoginRequest, device: &str) {
        let Some(vault) = self.vault.clone() else {
            return;
        };
        self.cfg = self.cfg_named(device);
        self.login = None;
        request.email.trim().clone_into(&mut self.login_email);
        let cfg = self.cfg.clone();
        self.spawn(async move {
            SyncMsg::LoginStarted(account::start_login(&vault, &request, &cfg).await)
        });
    }

    pub(crate) fn login_started(&mut self, login: LoginSession) {
        self.login = Some(login);
    }

    /// The email of the login in progress.
    pub(crate) fn login_email(&self) -> &str {
        &self.login_email
    }

    /// Commit the login with the chosen duplicate handling.
    pub(crate) fn commit_login(
        &mut self,
        choices: &[(courier_ftp_core::model::item::ItemId, DuplicateChoice)],
    ) -> bool {
        let Some(mut login) = self.login.take() else {
            return false;
        };
        for (id, choice) in choices {
            login.preview_mut().set(*id, *choice);
        }
        // The engine of a previous session (a re-login after "login needed")
        // stops first.
        let old = self.handle.take();
        self.spawn(async move {
            if let Some(handle) = old {
                handle.shutdown().await;
            }
            SyncMsg::LoggedIn(login.commit().await)
        });
        true
    }

    pub(crate) fn cancel_login(&mut self) {
        self.login = None;
    }

    // ---- signed-in calls ----------------------------------------------

    fn with_session<F, Fut>(&self, f: F) -> bool
    where
        F: FnOnce(SyncSession) -> Fut,
        Fut: std::future::Future<Output = SyncMsg> + Send + 'static,
    {
        match self.session.clone() {
            Some(s) => {
                self.spawn(f(s));
                true
            }
            None => false,
        }
    }

    pub(crate) fn list_devices(&self) -> bool {
        self.with_session(|s| async move { SyncMsg::Devices(s.list_devices().await) })
    }

    /// Revoke a device; revoking this one stops the engine first.
    pub(crate) fn revoke_device(&mut self, id: Uuid, this_device: bool) -> bool {
        let Some(session) = self.session.clone() else {
            return false;
        };
        let handle = if this_device {
            self.handle.take()
        } else {
            None
        };
        self.spawn(async move {
            if let Some(h) = handle {
                h.shutdown().await;
            }
            SyncMsg::Revoked(session.revoke_device(id).await)
        });
        true
    }

    pub(crate) fn change_password(
        &self,
        old: SecretString,
        new: SecretString,
        totp: Option<SecretString>,
    ) -> bool {
        self.with_session(|s| async move {
            SyncMsg::PasswordChanged(s.change_password(&old, &new, totp.as_ref()).await)
        })
    }

    pub(crate) fn totp_start(&self) -> bool {
        self.with_session(|s| async move { SyncMsg::TotpStarted(s.totp_start().await) })
    }

    pub(crate) fn totp_confirm(&self, code: SecretString) -> bool {
        self.with_session(|s| async move { SyncMsg::TotpConfirmed(s.totp_confirm(&code).await) })
    }

    pub(crate) fn totp_disable(&self, code: SecretString) -> bool {
        self.with_session(|s| async move { SyncMsg::TotpDisabled(s.totp_disable(&code).await) })
    }

    /// Mail a recovery code for `email` at `server` (no session needed).
    pub(crate) fn request_recovery_code(&self, server: String, email: String, vault: bool) {
        let cfg = self.cfg.clone();
        self.spawn(async move {
            SyncMsg::RecoveryCodeSent {
                vault,
                result: account::request_recovery_code(&server, &email, &cfg).await,
            }
        });
    }

    /// Log out: the engine stops, then the tokens are revoked and the local
    /// sync state wiped (local data stays).
    pub(crate) fn logout(&mut self) -> bool {
        let Some(session) = self.session.clone() else {
            return false;
        };
        let handle = self.handle.take();
        self.spawn(async move {
            if let Some(h) = handle {
                h.shutdown().await;
            }
            SyncMsg::LoggedOut(session.logout().await)
        });
        true
    }

    pub(crate) fn delete_account(
        &mut self,
        password: SecretString,
        totp: Option<SecretString>,
    ) -> bool {
        let Some(session) = self.session.clone() else {
            return false;
        };
        // Stop pushing while the account goes away; restarted if the
        // password turns out wrong.
        let handle = self.handle.take();
        self.spawn(async move {
            if let Some(h) = handle {
                h.shutdown().await;
            }
            SyncMsg::AccountDeleted(session.delete_account(&password, totp.as_ref()).await)
        });
        true
    }

    /// The session ended on the server side or by the user (logout,
    /// account deleted, this device revoked).
    pub(crate) fn signed_out(&mut self) {
        if let Some(handle) = self.end_session() {
            tokio::spawn(handle.shutdown());
        }
    }

    /// The engine was stopped for a call that failed: run it again.
    pub(crate) fn restart(&mut self) {
        if self.handle.is_none()
            && let Some(session) = self.session.clone()
        {
            self.start(session);
        }
    }

    // ---- teams (T90 §5) -------------------------------------------------

    /// Run a teams screen call.
    pub(crate) fn team(&self, request: TeamRequest) -> bool {
        let tx = self.tx.clone();
        self.with_session(|s| async move {
            let result = match s.teams().await {
                Ok(teams) => team_call(&teams, request, &tx).await,
                Err(e) => Err(e.to_string()),
            };
            SyncMsg::Team(result)
        })
    }

    /// Recovery prefill for the locked vault: the account's server and
    /// email (no keys needed).
    pub(crate) fn load_recovery_defaults(&self, store: courier_ftp_store::Store) {
        self.spawn(async move {
            match courier_ftp_sync::info::local_info(&store).await {
                Ok(info) => SyncMsg::RecoveryDefaults {
                    account: info.server_url.is_some() && info.email.is_some(),
                    server: info.server_url,
                    email: info.email,
                },
                Err(e) => {
                    tracing::debug!(error = %e, "sync info not read");
                    SyncMsg::RecoveryDefaults {
                        account: false,
                        server: None,
                        email: None,
                    }
                }
            }
        });
    }

    /// "Forgot password?" with the recovery code and the 24 words: resets
    /// the account password and re-keys (and unlocks) this locked vault.
    pub(crate) fn recover(
        &self,
        vault: VaultEngine,
        server: String,
        email: String,
        code: SecretString,
        words: SecretString,
        password: SecretString,
    ) {
        let cfg = self.cfg.clone();
        self.spawn(async move {
            let result = account::recover_locked_device(
                &vault, &server, &email, &code, &words, &password, &cfg,
            )
            .await
            // The session is opened again by the unlock that follows.
            .map(drop);
            SyncMsg::Recovered(result)
        });
    }
}

/// A team error for the screens.
fn team_error(e: &TeamError) -> String {
    match e {
        TeamError::Account(AccountError::Sync(inner)) => inner.to_string(),
        other => other.to_string(),
    }
}

/// The safety number with `user` and their trust state (keys fetched and
/// pinned on first sight).
async fn safety(teams: &Teams, user: Uuid, email: String) -> Result<Safety, String> {
    let pin = teams.member_keys(user).await.map_err(|e| team_error(&e))?;
    let number = teams
        .safety_number(user)
        .await
        .map_err(|e| team_error(&e))?;
    Ok(Safety {
        user,
        email,
        number,
        state: pin.state(),
    })
}

/// A rotation that failed after the change it follows was made.
fn rotation_failed(what: &str, name: &str, e: &RotationError) -> String {
    format!(
        "{what}, but rotating the key of “{name}” failed: {e}. Changes to the vault wait; \
         resume with R in its team's vault list."
    )
}

/// Runs one teams screen call.
#[expect(clippy::too_many_lines, reason = "one arm per call")]
async fn team_call(
    teams: &Teams,
    request: TeamRequest,
    tx: &UnboundedSender<Action>,
) -> Result<TeamReply, String> {
    let err = |e: TeamError| team_error(&e);
    let progress_tx = tx.clone();
    let progress = move |p: RotationProgress| {
        let _ = progress_tx.send(action(SyncMsg::Rotation(p)));
    };
    Ok(match request {
        TeamRequest::Orgs => TeamReply::Orgs(teams.list_orgs().await.map_err(err)?),
        TeamRequest::CreateOrg(name) => {
            let org = teams.create_org(&name).await.map_err(err)?;
            TeamReply::Done(format!(
                "Team “{}” created. Invite people from its member list, and create a shared \
                 vault for the sites you want to share.",
                org.name
            ))
        }
        TeamRequest::AcceptInvite(link) => {
            let accepted = teams.accept_invite(&link).await.map_err(err)?;
            let name = teams
                .list_orgs()
                .await
                .ok()
                .and_then(|orgs| orgs.into_iter().find(|o| o.id == accepted.org_id))
                .map_or_else(|| "the team".to_owned(), |o| format!("“{}”", o.name));
            TeamReply::Done(format!(
                "You joined {name}. Its shared vaults arrive on this device once a manager \
                 gives you access."
            ))
        }
        TeamRequest::Members(org) => {
            // Fetch (and pin on first sight) every member's keys, so a
            // changed key shows up here.
            let members = teams.org_members(org).await.map_err(err)?;
            for m in members.iter().filter(|m| !m.is_me) {
                if let Err(e) = teams.member_keys(m.member.user_id).await {
                    tracing::debug!(error = %e, "member keys not fetched");
                }
            }
            TeamReply::Members(teams.org_members(org).await.map_err(err)?)
        }
        TeamRequest::Invite { org, email, role } => TeamReply::Invited(
            teams
                .invite(org, email.as_deref(), role)
                .await
                .map_err(err)?,
        ),
        TeamRequest::SetRole {
            org,
            user,
            email,
            role,
        } => {
            teams.set_role(org, user, role).await.map_err(err)?;
            TeamReply::Done(format!("{email} is now {}.", role.as_str()))
        }
        TeamRequest::Remove { org, user, email } => {
            let report = teams
                .remove_member(org, user, &progress)
                .await
                .map_err(err)?;
            let names = teams.vault_names().await.unwrap_or_default();
            let name_of = |v: &courier_ftp_core::model::item::VaultId| {
                names.get(v).cloned().unwrap_or_else(|| v.short())
            };
            if let Some((v, Err(e))) = report.rotations.iter().find(|(_, r)| r.is_err()) {
                return Err(rotation_failed(
                    &format!("{email} was removed"),
                    &name_of(v),
                    e,
                ));
            }
            let n = report.rotations.len();
            TeamReply::Done(if n == 0 {
                format!("{email} was removed from the team.")
            } else {
                format!(
                    "{email} was removed from the team; the key of {n} vault{} was rotated, \
                     so they can't read new changes.",
                    if n == 1 { "" } else { "s" }
                )
            })
        }
        TeamRequest::Leave(org) => {
            let removed = teams.leave_org(org).await.map_err(err)?;
            TeamReply::Left(format!(
                "You left the team; {} shared vault{} were removed from this device.",
                removed.len(),
                if removed.len() == 1 { "" } else { "s" }
            ))
        }
        TeamRequest::Safety { user, email } => TeamReply::Safety(safety(teams, user, email).await?),
        TeamRequest::Verify { user, email } => {
            teams.mark_verified(user).await.map_err(err)?;
            TeamReply::Done(format!("{email} is marked verified."))
        }
        TeamRequest::AcceptKey {
            user,
            email,
            verified,
        } => {
            teams.accept_new_key(user, verified).await.map_err(err)?;
            TeamReply::Done(if verified {
                format!("The new key of {email} is accepted and marked verified.")
            } else {
                format!("The new key of {email} is accepted.")
            })
        }
        TeamRequest::Vaults(org) => TeamReply::Vaults(teams.org_vaults(org).await.map_err(err)?),
        TeamRequest::CreateVault { org, name } => {
            teams.create_vault(org, &name).await.map_err(err)?;
            TeamReply::Done(format!(
                "Shared vault “{name}” created: it is in the Site Manager as “Team: {name}”. \
                 Give members access from its member list."
            ))
        }
        TeamRequest::VaultMembers(vault) => {
            TeamReply::VaultMembers(teams.vault_members(vault).await.map_err(err)?)
        }
        TeamRequest::Grant {
            vault,
            name,
            user,
            email,
            permission,
        } => match teams.grant(vault, user, permission).await {
            Ok(()) => TeamReply::Done(format!(
                "{email} can now {} “{name}”.",
                match permission {
                    courier_ftp_proto::sync::Permission::Read => "use (read only)",
                    courier_ftp_proto::sync::Permission::Write => "use and edit",
                    courier_ftp_proto::sync::Permission::Manage => "use, edit and manage",
                }
            )),
            Err(TeamError::Trust(TrustError::KeyChanged(_))) => {
                TeamReply::KeyChanged(safety(teams, user, email).await?)
            }
            Err(e) => return Err(err(e)),
        },
        TeamRequest::Revoke {
            vault,
            name,
            user,
            email,
        } => match teams.revoke_and_rotate(vault, user, &progress).await {
            Ok(_) => TeamReply::Done(format!(
                "{email} can no longer use “{name}”; its key was rotated."
            )),
            Err(RotationError::Team(e)) => return Err(err(e)),
            Err(e) => {
                return Err(rotation_failed(
                    &format!("{email}'s access was revoked"),
                    &name,
                    &e,
                ));
            }
        },
        TeamRequest::Rotate { vault, name } => {
            let report = teams
                .rotate(vault, &progress)
                .await
                .map_err(|e| e.to_string())?;
            TeamReply::Done(format!(
                "The key of “{name}” was rotated ({} item(s) re-encrypted for {} member(s)).",
                report.items, report.members
            ))
        }
        TeamRequest::Audit(org) => {
            let page = teams.audit(org, None, 100).await.map_err(err)?;
            let names = teams
                .org_members(org)
                .await
                .map(|m| {
                    m.into_iter()
                        .map(|m| (m.member.user_id, m.member.email))
                        .collect()
                })
                .unwrap_or_default();
            TeamReply::Audit {
                events: page.events,
                names,
            }
        }
    })
}
