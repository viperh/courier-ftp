//! The sync engine (T88): keeps every unlocked vault in sync in the
//! background, offline-first — local edits never wait for the network.
//!
//! One [`SyncEngine`] runs per unlocked session, started after unlock
//! ([`crate::SyncSession::start_engine`]) and stopped on lock or logout
//! ([`SyncHandle::shutdown`], or dropping the handle). It owns the WebSocket
//! client and the timers; HTTP goes through the session's shared
//! [`TokenManager`]; items go through the vault engine, which applies pulled
//! pages under its state lock (`VaultEngine::apply_incoming`).
//!
//! Triggers:
//! * startup: a full cycle (vault list, pull, push);
//! * a local change (any committed write that queues an outbox row,
//!   `Store::outbox_changes`, or [`SyncHandle::local_change`]): push after
//!   the debounce (`sync.push_debounce_ms`, 2 s), then pull;
//! * a WS `vault_changed` beyond the cursor: pull that vault; WS
//!   (re)connected: pull everything; `vault_access`: refresh the vault list;
//!   `account_changed`: sign-in required;
//! * the fallback poll (`sync.poll_fallback_secs`, 300 s);
//! * [`SyncHandle::sync_now`];
//! * after a transport failure: retry with exponential backoff (1 s → 300 s).
//!   Offline edits stay queued indefinitely; the status shows
//!   `offline (N pending)`.
//!
//! Team vaults (T89): every vault list refresh also adopts vaults shared
//! with the account, installs rotated keys, applies read-only permissions
//! and removes vaults the account lost access to (`crate::shared`).
//!
//! Adapted from sverb's `sverb-sync/src/engine.rs` (D13).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use courier_ftp_core::model::item::{ClockSkew, DeviceId, ItemId, ItemKind, VaultId};
use courier_ftp_core::settings::SyncSettings;
use courier_ftp_proto::ws::{AccessChange, ServerMsg};
use courier_ftp_store::meta::keys as meta_keys;
use courier_ftp_store::vault::{ApplyReport, VaultEngine};
use secrecy::SecretString;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::error::SyncError;
use crate::http::ApiClient;
use crate::status::{SyncEvent, SyncStatus, ToastLevel};
use crate::tokens::TokenManager;
use crate::ws::{self, Backoff, BackoffPolicy, WsConfig, WsEvent};

/// At most this many push rounds per item before a conflict is surfaced.
pub const MAX_CONFLICT_ROUNDS: u32 = 5;

/// What syncs: every item kind except `history-entry` unless
/// `sync.history` is on. Device-local data (the transfer queue, tabs, local
/// directory overrides, last-connected times) is never an item and never
/// syncs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncPolicy {
    /// `sync.history`.
    pub history: bool,
}

impl SyncPolicy {
    /// Whether items of `kind` are pushed.
    #[must_use]
    pub const fn allows(&self, kind: ItemKind) -> bool {
        match kind {
            ItemKind::HistoryEntry => self.history,
            _ => true,
        }
    }
}

/// Engine settings.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Push this long after the last local change (`sync.push_debounce_ms`).
    pub push_debounce: Duration,
    /// Fallback poll (`sync.poll_fallback_secs`).
    pub poll_interval: Duration,
    /// What syncs.
    pub policy: SyncPolicy,
    /// Run the `/v1/ws` notification client.
    pub websocket: bool,
    /// Retry backoff after transport errors (1 s → 300 s).
    pub retry: BackoffPolicy,
    /// WebSocket reconnect backoff (1 s → 60 s).
    pub ws_backoff: BackoffPolicy,
    /// Pull page size (≤ 500).
    pub page_limit: u32,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self::from_settings(&SyncSettings::default())
    }
}

impl EngineConfig {
    /// The engine settings from the `sync.*` settings.
    #[must_use]
    pub fn from_settings(s: &SyncSettings) -> Self {
        Self {
            push_debounce: Duration::from_millis(u64::from(s.push_debounce_ms)),
            poll_interval: Duration::from_secs(u64::from(s.poll_fallback_secs.max(1))),
            policy: SyncPolicy { history: s.history },
            websocket: true,
            retry: BackoffPolicy {
                initial: Duration::from_secs(1),
                max: Duration::from_secs(300),
            },
            ws_backoff: BackoffPolicy::default(),
            page_limit: courier_ftp_proto::limits::MAX_PULL_LIMIT,
        }
    }
}

/// Why an item is held back from pushing (for this engine's lifetime; the
/// item stays dirty and its local change is kept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BlockReason {
    /// `forbidden`: read-only access.
    ReadOnly,
    /// `too_large` (envelope over 1 MiB, or quota).
    TooLarge(String),
    /// Still conflicting after [`MAX_CONFLICT_ROUNDS`].
    Conflict,
    /// The local copy does not decrypt.
    Undecryptable,
}

impl BlockReason {
    fn message(&self) -> String {
        match self {
            Self::ReadOnly => "read-only access: the change was not uploaded".into(),
            Self::TooLarge(why) => format!("not uploaded: {why}"),
            Self::Conflict => "kept conflicting with the server; not uploaded".into(),
            Self::Undecryptable => "does not decrypt; not uploaded".into(),
        }
    }
}

/// The engine's state, owned by its task.
pub(crate) struct Ctx {
    pub(crate) vault: VaultEngine,
    pub(crate) tokens: Arc<TokenManager>,
    pub(crate) config: EngineConfig,
    pub(crate) events: Option<mpsc::UnboundedSender<SyncEvent>>,
    pub(crate) blocked: HashMap<ItemId, BlockReason>,
    pub(crate) conflicts: HashMap<ItemId, u32>,
    pub(crate) unknown_vaults: HashSet<VaultId>,
    pub(crate) undecryptable: HashSet<ItemId>,
    pub(crate) skew_warned: HashSet<DeviceId>,
    pub(crate) needs_login: bool,
    pub(crate) errors: Arc<Mutex<BTreeMap<ItemId, String>>>,
    /// This account and its keys (team grants), loaded on first use.
    pub(crate) account: Option<(uuid::Uuid, Arc<courier_ftp_crypto::account::AccountKeys>)>,
    /// Team vaults whose grant was refused (reported once).
    pub(crate) rejected_grants: HashMap<VaultId, String>,
    /// Vaults whose abandoned rotation was reported.
    pub(crate) abandoned_reported: HashSet<VaultId>,
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx")
            .field("blocked", &self.blocked.len())
            .field("needs_login", &self.needs_login)
            .finish_non_exhaustive()
    }
}

impl Ctx {
    pub(crate) fn emit(&self, ev: SyncEvent) {
        if let Some(tx) = &self.events {
            let _ = tx.send(ev);
        }
    }

    pub(crate) fn toast(&self, level: ToastLevel, message: impl Into<String>) {
        self.emit(SyncEvent::Toast {
            level,
            message: message.into(),
        });
    }

    fn errors(&self) -> std::sync::MutexGuard<'_, BTreeMap<ItemId, String>> {
        self.errors.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn warn_skew(&mut self, skew: Option<ClockSkew>) {
        if let Some(s) = skew
            && self.skew_warned.insert(s.device)
        {
            tracing::warn!(device = %s.device.short(), ahead_s = s.ahead_by.as_secs(), "clock skew");
            self.emit(SyncEvent::ClockSkew {
                device: s.device.short(),
                ahead_secs: s.ahead_by.as_secs(),
            });
        }
    }

    /// Holds `id` back and shows why next to it.
    pub(crate) fn block(&mut self, id: ItemId, reason: BlockReason) {
        let message = reason.message();
        self.errors().insert(id, message.clone());
        self.blocked.insert(id, reason);
        self.emit(SyncEvent::ItemError { item: id, message });
    }

    /// `id` was pushed: forget its error.
    pub(crate) fn clear_item(&mut self, id: ItemId) {
        self.conflicts.remove(&id);
        self.errors().remove(&id);
    }

    /// Calls the API with an access token; on 401 refreshes once and retries.
    /// `NeedsLogin` pauses the engine.
    pub(crate) async fn call<T, F, Fut>(&mut self, f: F) -> Result<T, SyncError>
    where
        F: Fn(ApiClient, SecretString) -> Fut,
        Fut: Future<Output = Result<T, SyncError>>,
    {
        let res = self.tokens.call(f).await;
        if matches!(res, Err(SyncError::NeedsLogin)) {
            self.needs_login = true;
        }
        res
    }

    /// The vaults to sync: loaded locally and known to the server.
    pub(crate) async fn vaults(&self) -> Vec<VaultId> {
        self.vault
            .loaded_vaults()
            .await
            .into_iter()
            .filter(|v| !self.unknown_vaults.contains(v))
            .collect()
    }

    /// `GET /v1/vaults`: which local vaults the server knows.
    pub(crate) async fn refresh_vaults(&mut self) -> Result<(), SyncError> {
        let views = self
            .call(|api, t| async move { api.list_vaults(&t).await })
            .await?;
        self.reconcile_vaults(&views).await?;
        for vault in self.vault.loaded_vaults().await {
            match views.iter().find(|v| v.id == vault.uuid()) {
                None => {
                    if self.unknown_vaults.insert(vault) {
                        tracing::warn!(vault = %vault.short(), "vault is not on the server; not syncing it");
                    }
                }
                Some(view) => {
                    self.unknown_vaults.remove(&vault);
                    if view.rotation.is_some() {
                        tracing::debug!(vault = %vault.short(), "vault key rotation in progress");
                    }
                }
            }
        }
        Ok(())
    }

    /// Bookkeeping and events after items were applied.
    pub(crate) fn after_apply(&mut self, vault: VaultId, report: ApplyReport) {
        for id in &report.applied {
            self.undecryptable.remove(id);
        }
        self.undecryptable
            .extend(report.undecryptable.iter().copied());
        self.warn_skew(report.skew);
        for label in &report.resurrected {
            self.toast(
                ToastLevel::Info,
                format!(
                    "‘{label}’ was restored because it was edited on another device after being deleted"
                ),
            );
        }
        for (item, field) in report.approvals {
            self.emit(SyncEvent::ApprovalNeeded { item, field });
        }
        if report.requeued > 0 || report.purged > 0 {
            tracing::info!(
                vault = %vault.short(),
                requeued = report.requeued,
                purged = report.purged,
                "full resync applied"
            );
        }
        if !report.applied.is_empty() {
            self.emit(SyncEvent::Applied {
                vault,
                items: report.applied,
            });
        }
    }

    /// One cycle: optionally the vault list, then pull, push, and pull again
    /// when something was pushed.
    pub(crate) async fn cycle(&mut self, refresh: bool) -> Result<(), SyncError> {
        if refresh {
            self.refresh_vaults().await?;
        }
        for vault in self.vaults().await {
            self.pull_vault(vault).await?;
        }
        let mut pushed = false;
        for vault in self.vaults().await {
            pushed |= self.push_vault(vault).await?;
        }
        if pushed {
            for vault in self.vaults().await {
                self.pull_vault(vault).await?;
            }
        }
        let now = self.vault.store().now().to_string().into_bytes();
        if let Err(e) = self
            .vault
            .store()
            .meta()
            .set(meta_keys::SYNC_LAST_OK, now)
            .await
        {
            tracing::warn!(error = %e, "cannot record the last sync time");
        }
        Ok(())
    }

    /// The status after a cycle that ended with `last`.
    pub(crate) async fn status(&self, last: Option<&SyncError>) -> SyncStatus {
        if self.needs_login || matches!(last, Some(SyncError::NeedsLogin)) {
            return SyncStatus::NeedsLogin;
        }
        let pending = self
            .vault
            .store()
            .outbox()
            .pending_count()
            .await
            .unwrap_or(0);
        if let Some(e) = last {
            return if e.is_offline() {
                SyncStatus::Offline { pending }
            } else {
                SyncStatus::Error(e.to_string())
            };
        }
        let count = |r: fn(&BlockReason) -> bool| self.blocked.values().filter(|b| r(b)).count();
        let read_only = count(|r| matches!(r, BlockReason::ReadOnly));
        let too_large = count(|r| matches!(r, BlockReason::TooLarge(_)));
        let conflict = count(|r| matches!(r, BlockReason::Conflict));
        let bad_local = count(|r| matches!(r, BlockReason::Undecryptable));
        let plural = |n: usize| if n == 1 { "item" } else { "items" };
        let mut issues = Vec::new();
        if !self.undecryptable.is_empty() || bad_local > 0 {
            let n = self.undecryptable.len() + bad_local;
            issues.push(format!("{n} {} could not be decrypted", plural(n)));
        }
        if conflict > 0 {
            issues.push(format!("{conflict} {} kept conflicting", plural(conflict)));
        }
        if too_large > 0 {
            issues.push(format!(
                "{too_large} {} too large to upload",
                plural(too_large)
            ));
        }
        if read_only > 0 {
            issues.push(format!(
                "{read_only} {} not uploaded (read-only access)",
                plural(read_only)
            ));
        }
        if issues.is_empty() {
            SyncStatus::Synced
        } else {
            SyncStatus::Error(issues.join("; "))
        }
    }
}

/// A configured, not yet running engine.
#[derive(Debug)]
pub struct SyncEngine {
    ctx: Ctx,
}

/// What the UI keeps of a running engine. Dropping it stops the engine.
#[derive(Debug)]
pub struct SyncHandle {
    cmds: mpsc::UnboundedSender<Command>,
    status: watch::Receiver<SyncStatus>,
    cancel: CancellationToken,
    errors: Arc<Mutex<BTreeMap<ItemId, String>>>,
    task: Option<JoinHandle<()>>,
}

#[derive(Debug)]
enum Command {
    LocalChange,
    SyncNow(Option<oneshot::Sender<SyncStatus>>),
}

impl SyncEngine {
    /// An engine for the unlocked `vault`, sharing `tokens` with the rest of
    /// the session; `events` receives [`SyncEvent`]s.
    #[must_use]
    pub fn new(
        vault: VaultEngine,
        tokens: Arc<TokenManager>,
        config: EngineConfig,
        events: Option<mpsc::UnboundedSender<SyncEvent>>,
    ) -> Self {
        Self {
            ctx: Ctx {
                vault,
                tokens,
                config,
                events,
                blocked: HashMap::new(),
                conflicts: HashMap::new(),
                unknown_vaults: HashSet::new(),
                undecryptable: HashSet::new(),
                skew_warned: HashSet::new(),
                needs_login: false,
                errors: Arc::new(Mutex::new(BTreeMap::new())),
                account: None,
                rejected_grants: HashMap::new(),
                abandoned_reported: HashSet::new(),
            },
        }
    }

    /// One full cycle (vault list, pull, push, pull) without timers or WS.
    /// Returns the resulting status.
    pub async fn sync_once(&mut self) -> SyncStatus {
        let res = self.ctx.cycle(true).await;
        if let Err(e) = &res {
            tracing::warn!(error = %e, "sync failed");
        }
        self.ctx.status(res.as_ref().err()).await
    }

    /// Runs the engine on the current runtime.
    #[must_use]
    pub fn spawn(self) -> SyncHandle {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (status_tx, status_rx) = watch::channel(SyncStatus::Syncing);
        let cancel = CancellationToken::new();
        let errors = Arc::clone(&self.ctx.errors);
        let task = tokio::spawn(run(self.ctx, cmd_rx, status_tx, cancel.clone()));
        SyncHandle {
            cmds: cmd_tx,
            status: status_rx,
            cancel,
            errors,
            task: Some(task),
        }
    }
}

impl SyncHandle {
    /// A local item was written (sets the push debounce). Writes through the
    /// vault engine are noticed on their own (`Store::outbox_changes`).
    pub fn local_change(&self) {
        let _ = self.cmds.send(Command::LocalChange);
    }

    /// Runs a full cycle now and returns the status after it (`None` when
    /// the engine has stopped). Also clears the items held back this session
    /// (a manual retry).
    pub async fn sync_now(&self) -> Option<SyncStatus> {
        let (tx, rx) = oneshot::channel();
        self.cmds.send(Command::SyncNow(Some(tx))).ok()?;
        rx.await.ok()
    }

    /// Requests a full cycle without waiting.
    pub fn request_sync(&self) {
        let _ = self.cmds.send(Command::SyncNow(None));
    }

    /// The current status.
    #[must_use]
    pub fn status(&self) -> SyncStatus {
        self.status.borrow().clone()
    }

    /// A status receiver (for the status bar).
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<SyncStatus> {
        self.status.clone()
    }

    /// Items held back with the reason shown next to them in the UI.
    #[must_use]
    pub fn item_errors(&self) -> BTreeMap<ItemId, String> {
        self.errors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Stops the engine (lock, logout, quit): closes the WS once the current
    /// step finishes.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    /// Whether the engine task has ended.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }
}

impl Drop for SyncHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn set_status(ctx: &Ctx, tx: &watch::Sender<SyncStatus>, status: SyncStatus) {
    let changed = *tx.borrow() != status;
    tx.send_replace(status.clone());
    if changed {
        ctx.emit(SyncEvent::Status(status));
    }
}

async fn sleep_until_opt(t: Option<Instant>) {
    match t {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Work {
    /// Vault list + pull + push.
    Full,
    /// Pull + push (WS notification, debounce).
    Quick,
}

impl Work {
    fn max(a: Option<Self>, b: Self) -> Self {
        if a == Some(Self::Full) { Self::Full } else { b }
    }
}

async fn run(
    mut ctx: Ctx,
    mut cmds: mpsc::UnboundedReceiver<Command>,
    status: watch::Sender<SyncStatus>,
    cancel: CancellationToken,
) {
    let mut backoff = Backoff::new(ctx.config.retry);
    let mut retry_at: Option<Instant> = None;
    let mut push_at: Option<Instant> = None;
    let mut poll = tokio::time::interval_at(
        Instant::now() + ctx.config.poll_interval,
        ctx.config.poll_interval,
    );
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut outbox = ctx.vault.store().outbox_changes();
    outbox.mark_unchanged();

    let ws_cancel = cancel.child_token();
    let (ws_tx, mut ws_rx) = mpsc::channel::<WsEvent>(64);
    let ws_task = if ctx.config.websocket {
        let api = ctx.tokens.api();
        let mut cfg = WsConfig::for_server(api.base_url(), api.tls());
        cfg.backoff = ctx.config.ws_backoff;
        let tokens = Arc::clone(&ctx.tokens);
        let c = ws_cancel.clone();
        Some(tokio::spawn(async move {
            ws::run(cfg, &*tokens, ws_tx, c).await;
        }))
    } else {
        drop(ws_tx);
        None
    };
    let mut ws_open = ctx.config.websocket;

    let mut pending_work = Some(Work::Full);
    let mut replies: Vec<oneshot::Sender<SyncStatus>> = Vec::new();

    loop {
        if let Some(work) = pending_work.take() {
            if ctx.needs_login {
                set_status(&ctx, &status, SyncStatus::NeedsLogin);
            } else {
                set_status(&ctx, &status, SyncStatus::Syncing);
                let res = tokio::select! {
                    () = cancel.cancelled() => break,
                    r = ctx.cycle(work == Work::Full) => r,
                };
                match &res {
                    Ok(()) => {
                        backoff.reset();
                        retry_at = None;
                    }
                    Err(e) if e.is_offline() => {
                        let d = backoff.next_delay();
                        tracing::info!(error = %e, retry_in_ms = d.as_millis(), "sync offline");
                        retry_at = Some(Instant::now() + d);
                    }
                    Err(e) => tracing::warn!(error = %e, "sync cycle failed"),
                }
                if ctx.needs_login {
                    ws_cancel.cancel();
                }
                let st = ctx.status(res.as_ref().err()).await;
                set_status(&ctx, &status, st);
            }
            let st = status.borrow().clone();
            for r in replies.drain(..) {
                let _ = r.send(st.clone());
            }
        }

        tokio::select! {
            () = cancel.cancelled() => break,
            cmd = cmds.recv() => match cmd {
                None => break,
                Some(Command::LocalChange) => {
                    push_at = Some(Instant::now() + ctx.config.push_debounce);
                }
                Some(Command::SyncNow(reply)) => {
                    // A manual sync also retries the items held back.
                    ctx.blocked.clear();
                    ctx.conflicts.clear();
                    ctx.errors().clear();
                    pending_work = Some(Work::Full);
                    replies.extend(reply);
                }
            },
            changed = outbox.changed() => {
                if changed.is_ok() {
                    push_at = Some(Instant::now() + ctx.config.push_debounce);
                }
            }
            () = sleep_until_opt(push_at) => {
                push_at = None;
                pending_work = Some(Work::max(pending_work, Work::Quick));
            }
            () = sleep_until_opt(retry_at) => {
                retry_at = None;
                pending_work = Some(Work::Full);
            }
            _ = poll.tick() => {
                pending_work = Some(Work::Full);
            }
            ev = ws_rx.recv(), if ws_open => match ev {
                None => ws_open = false,
                Some(ev) => {
                    if let Some(w) = on_ws_event(&mut ctx, ev).await {
                        pending_work = Some(Work::max(pending_work, w));
                    }
                }
            },
        }
    }

    ws_cancel.cancel();
    if let Some(t) = ws_task {
        let _ = t.await;
    }
}

/// What a WS event asks for.
async fn on_ws_event(ctx: &mut Ctx, ev: WsEvent) -> Option<Work> {
    match ev {
        // Catch up on anything missed while disconnected.
        WsEvent::Connected => Some(Work::Quick),
        WsEvent::Notification(ServerMsg::VaultChanged {
            vault_id,
            head_revision,
        }) => {
            let vault = VaultId::from_uuid(vault_id);
            let cursor = ctx
                .vault
                .store()
                .vaults()
                .get(vault)
                .await
                .ok()
                .flatten()
                .map(|v| v.sync_cursor);
            match cursor {
                Some(c) if u64::try_from(c).unwrap_or(0) < head_revision => Some(Work::Quick),
                _ => None,
            }
        }
        WsEvent::Notification(ServerMsg::VaultAccess { vault_id, change }) => {
            let vault = VaultId::from_uuid(vault_id);
            if change == AccessChange::Revoked {
                ctx.toast(
                    ToastLevel::Warn,
                    format!("Your access to vault {} was revoked", vault.short()),
                );
            }
            ctx.emit(SyncEvent::VaultAccess { vault });
            Some(Work::Full)
        }
        WsEvent::NeedsLogin => {
            ctx.needs_login = true;
            Some(Work::Quick)
        }
        // The password was changed (or the account recovered) on another
        // device: this device's tokens are revoked. It keeps unlocking
        // locally with the old password until the user signs in with the new
        // one (`account::start_login`).
        WsEvent::Notification(ServerMsg::AccountChanged { key_version }) => {
            tracing::info!(
                key_version,
                "account changed on another device; sign-in required"
            );
            ctx.tokens.invalidate().await;
            ctx.needs_login = true;
            ctx.toast(
                ToastLevel::Warn,
                "Your password was changed on another device; sign in with the new password",
            );
            Some(Work::Quick)
        }
        WsEvent::Notification(_) | WsEvent::Disconnected { .. } => None,
    }
}
