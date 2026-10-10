//! The vault service (T60): a tokio task that owns the [`VaultEngine`] (T30), receives
//! [`VaultEffect`]s on a channel (capacity 16) and answers with [`VaultEvent`]s as
//! `Action::Vault`. Argon2 and SQLite run in `spawn_blocking` inside the engine; the
//! UI never awaits them.
//!
//! - It sends `Status` once at startup (and after a new vault).
//! - `Lock` is processed by the service loop itself, before any other queued effect
//!   (zeroize first); every other effect runs in its own task. A generation counter
//!   makes an unlock that finishes after a lock lock the engine again and report
//!   nothing.
//! - Logs carry no passwords, keyring results or failure counts at `info`+.

use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use courier_ftp_core::{
    secret::SecretString,
    trust::SwitchableHostKeyStore,
    vault::{
        KeyringStore, LockReason, UnlockReport, VaultEngine, VaultError, VaultOptions, VaultState,
        move_database_aside,
    },
};
use tokio::sync::mpsc::{self, UnboundedSender};
use tracing::{debug, warn};

use crate::{
    action::Action,
    app::vault::{
        UnlockFailure, UnlockRequest, VaultEffect, VaultEvent, VaultPassword, VaultStatusInfo,
    },
    runtime::InFlight,
};

/// The database file inside the data directory.
pub(crate) const VAULT_DB: &str = "courier-ftp.db";

/// Effects waiting for the service.
const CHANNEL_CAPACITY: usize = 16;

/// What the service opens.
#[derive(Clone)]
pub(crate) struct VaultConfig {
    /// `<data>/courier-ftp.db`.
    pub db_path: PathBuf,
    /// The keyring (`NoKeyring` with `--no-keyring` / `COURIER_FTP_KEYRING=off`).
    pub keyring: Arc<dyn KeyringStore>,
    /// Engine options (Argon2 cost, …).
    pub opts: VaultOptions,
    /// The host-key store the SSH verifier holds (T21); the engine switches it.
    pub host_keys: Arc<SwitchableHostKeyStore>,
}

impl std::fmt::Debug for VaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultConfig")
            .field("db_path", &self.db_path)
            .field("opts", &self.opts)
            .finish_non_exhaustive()
    }
}

/// An effect with its in-flight marker (tests wait for it).
struct Envelope {
    effect: VaultEffect,
    _in_flight: InFlight,
}

/// The engine slot: `Err` holds why the database could not be opened.
type Slot = Arc<Mutex<Result<VaultEngine, String>>>;

/// The handle the app holds.
#[derive(Debug, Clone)]
pub(crate) struct VaultService {
    tx: mpsc::Sender<Envelope>,
    #[cfg_attr(not(test), allow(dead_code, reason = "T31 reads items"))]
    engine: Slot,
}

impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.effect.fmt(f)
    }
}

fn lock_slot(slot: &Slot) -> std::sync::MutexGuard<'_, Result<VaultEngine, String>> {
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

impl VaultService {
    /// Opens the database (in `spawn_blocking`) and starts the service; its `Status`
    /// arrives on `events`. Needs a tokio runtime.
    pub(crate) fn spawn(config: VaultConfig, events: UnboundedSender<Action>) -> Self {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let engine: Slot = Arc::new(Mutex::new(Err("the vault is opening".into())));
        let started = InFlight::new();
        tokio::spawn(run(config, rx, Arc::clone(&engine), events, started));
        Self { tx, engine }
    }

    /// Sends an effect (never blocks the UI: a full channel hands it to a task).
    pub(crate) fn send(&self, effect: VaultEffect) {
        let env = Envelope {
            effect,
            _in_flight: InFlight::new(),
        };
        match self.tx.try_send(env) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(env)) => {
                let tx = self.tx.clone();
                tokio::spawn(async move {
                    let _ = tx.send(env).await;
                });
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("the vault service stopped; effect dropped");
            }
        }
    }

    /// The engine, when the database is open (T31 and later read items through it).
    #[cfg_attr(not(test), allow(dead_code, reason = "T31 reads items"))]
    pub(crate) fn engine(&self) -> Option<VaultEngine> {
        lock_slot(&self.engine).as_ref().ok().cloned()
    }
}

async fn open_engine(config: &VaultConfig) -> Result<VaultEngine, String> {
    let path = config.db_path.clone();
    let store = crate::runtime::spawn_blocking(move || courier_ftp_store::Store::open(path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    Ok(VaultEngine::new(
        store,
        Arc::clone(&config.keyring),
        config.opts.clone(),
        Arc::clone(&config.host_keys),
    ))
}

async fn status(engine: &Result<VaultEngine, String>) -> VaultEvent {
    let engine = match engine {
        Ok(e) => e,
        // A database that cannot be opened: the prompt shows, unlocking reports why.
        Err(_) => {
            return VaultEvent::Status(VaultStatusInfo {
                initialized: true,
                ..VaultStatusInfo::default()
            });
        }
    };
    match engine.status().await {
        Ok(s) => {
            let initialized = s.state != VaultState::Uninitialised;
            let keyring_available = if initialized {
                false
            } else {
                engine.keyring_available().await
            };
            VaultEvent::Status(VaultStatusInfo {
                initialized,
                keyring_enabled: s.keyring_enabled,
                keyring_available,
                failures: s.backoff.failures,
                retry_after: s.retry_after,
                // T87 sets this from the sync account.
                sync_account: false,
            })
        }
        Err(e) => {
            debug!(error = %e, "vault status failed");
            VaultEvent::Status(VaultStatusInfo {
                initialized: true,
                ..VaultStatusInfo::default()
            })
        }
    }
}

async fn run(
    config: VaultConfig,
    mut rx: mpsc::Receiver<Envelope>,
    slot: Slot,
    events: UnboundedSender<Action>,
    started: InFlight,
) {
    let generation = Arc::new(AtomicU64::new(0));
    let opened = open_engine(&config).await;
    if let Err(e) = &opened {
        debug!(error = %e, "vault database could not be opened");
        warn!("the vault database could not be opened");
    }
    let first = status(&opened).await;
    *lock_slot(&slot) = opened;
    let _ = events.send(Action::Vault(first));
    drop(started);
    while let Some(env) = rx.recv().await {
        let current = lock_slot(&slot).clone();
        match env.effect {
            VaultEffect::Lock => {
                generation.fetch_add(1, Ordering::SeqCst);
                if let Ok(engine) = &current {
                    engine.lock(LockReason::Manual).await;
                }
            }
            VaultEffect::StartNewVault => {
                generation.fetch_add(1, Ordering::SeqCst);
                start_new_vault(&config, &slot, current, &events).await;
            }
            effect => {
                let generation = Arc::clone(&generation);
                let events = events.clone();
                let in_flight = env._in_flight;
                tokio::spawn(async move {
                    let at = generation.load(Ordering::SeqCst);
                    let ev = match &current {
                        Ok(engine) => handle(engine, effect, &generation, at).await,
                        Err(reason) => damaged(effect, reason),
                    };
                    if let Some(ev) = ev {
                        let _ = events.send(Action::Vault(ev));
                    }
                    drop(in_flight);
                });
            }
        }
    }
}

/// `StartNewVault`: drop the engine, move the database aside (never deleting it),
/// open a fresh one and send `Status`.
async fn start_new_vault(
    config: &VaultConfig,
    slot: &Slot,
    current: Result<VaultEngine, String>,
    events: &UnboundedSender<Action>,
) {
    if let Ok(engine) = &current {
        engine.lock(LockReason::Manual).await;
    }
    *lock_slot(slot) = Err("a new vault is being created".into());
    drop(current);
    let path = config.db_path.clone();
    let moved = crate::runtime::spawn_blocking(move || move_database_aside(&path)).await;
    let moved = match moved {
        Ok(r) => r.map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    match moved {
        Ok(kept) => {
            let name = kept.file_name().map_or_else(
                || kept.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            debug!("vault database moved aside");
            let _ = events.send(Action::Vault(VaultEvent::NewVaultStarted {
                old_path_display: name,
            }));
        }
        Err(e) => {
            let _ = events.send(Action::Vault(VaultEvent::NewVaultFailed(e)));
        }
    }
    let opened = open_engine(config).await;
    let ev = status(&opened).await;
    *lock_slot(slot) = opened;
    let _ = events.send(Action::Vault(ev));
}

fn secret(p: &VaultPassword) -> SecretString {
    SecretString::from(p.expose())
}

/// The answer when the database could not be opened.
fn damaged(effect: VaultEffect, reason: &str) -> Option<VaultEvent> {
    let msg = format!("The vault database is damaged: {reason}");
    Some(match effect {
        VaultEffect::Initialize { .. } | VaultEffect::Unlock(_) => {
            VaultEvent::UnlockFailed(UnlockFailure::Other(msg))
        }
        VaultEffect::ChangePassword { .. } => VaultEvent::PasswordChangeFailed(msg),
        VaultEffect::SetKeyringUnlock { .. } => VaultEvent::KeyringChangeFailed(msg),
        VaultEffect::Relogin { .. } => VaultEvent::Relogin(Err(msg)),
        VaultEffect::Lock | VaultEffect::StartNewVault => return None,
    })
}

/// Maps an unlock / first-run error.
pub(crate) fn unlock_failure(e: VaultError) -> UnlockFailure {
    match e {
        VaultError::WrongPassword {
            failures,
            retry_after,
        } => UnlockFailure::WrongPassword {
            failures,
            retry_after,
        },
        VaultError::Backoff { retry_after } => UnlockFailure::Backoff { retry_after },
        VaultError::Keyring(msg) => UnlockFailure::Keyring(msg),
        e @ (VaultError::KeyringNotEnabled | VaultError::KeyringUnavailable) => {
            UnlockFailure::Keyring(e.to_string())
        }
        VaultError::Busy => UnlockFailure::Busy,
        VaultError::UnlockInProgress => UnlockFailure::InProgress,
        VaultError::Corrupt(reason) => {
            UnlockFailure::Other(format!("The vault database is damaged: {reason}"))
        }
        VaultError::WeakPassword(w) => {
            let feedback = w.strength.feedback();
            UnlockFailure::Other(if feedback.is_empty() {
                format!("Too weak ({})", w.strength.label())
            } else {
                format!("Too weak ({}): {feedback}", w.strength.label())
            })
        }
        other => UnlockFailure::Other(capitalize(&other.to_string())),
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// A note for the unlock toast (unreadable items).
fn unlock_note(report: &UnlockReport) -> Option<String> {
    let n = report.unreadable_items + report.unknown_kind_items;
    (n > 0).then(|| {
        format!(
            "{n} saved item{} could not be read (written by a newer courier-ftp or damaged)",
            if n == 1 { "" } else { "s" }
        )
    })
}

async fn unlocked(
    engine: &VaultEngine,
    generation: &AtomicU64,
    at: u64,
    via_keyring: bool,
    note: Option<String>,
) -> Option<VaultEvent> {
    if generation.load(Ordering::SeqCst) != at {
        // Locked while unlocking: the keys go again, the UI hears nothing.
        engine.lock(LockReason::Manual).await;
        return None;
    }
    Some(VaultEvent::Unlocked { via_keyring, note })
}

async fn handle(
    engine: &VaultEngine,
    effect: VaultEffect,
    generation: &AtomicU64,
    at: u64,
) -> Option<VaultEvent> {
    match effect {
        VaultEffect::Initialize { password, keyring } => {
            match engine.initialize(secret(&password), keyring).await {
                Ok(report) => {
                    let note = report.keyring_error.map(|e| {
                        format!(
                            "Keyring unlock could not be turned on ({e}); the vault was created \
                             without it"
                        )
                    });
                    unlocked(engine, generation, at, false, note).await
                }
                Err(e) => Some(VaultEvent::UnlockFailed(unlock_failure(e))),
            }
        }
        VaultEffect::Unlock(UnlockRequest::Password(password)) => {
            match engine.unlock(secret(&password)).await {
                Ok(report) => unlocked(engine, generation, at, false, unlock_note(&report)).await,
                Err(e) => Some(VaultEvent::UnlockFailed(unlock_failure(e))),
            }
        }
        VaultEffect::Unlock(UnlockRequest::Keyring) => match engine.unlock_with_keyring().await {
            Ok(report) => unlocked(engine, generation, at, true, unlock_note(&report)).await,
            Err(e) => Some(VaultEvent::UnlockFailed(unlock_failure(e))),
        },
        VaultEffect::ChangePassword { current, new } => {
            let current = current.as_ref().map(secret);
            Some(match engine.change_password(current, secret(&new)).await {
                Ok(()) => VaultEvent::PasswordChanged,
                Err(VaultError::WrongPassword { .. }) => {
                    VaultEvent::PasswordChangeFailed("The current password is wrong".into())
                }
                Err(e) => VaultEvent::PasswordChangeFailed(match unlock_failure(e) {
                    UnlockFailure::Other(m) | UnlockFailure::Keyring(m) => m,
                    UnlockFailure::Backoff { retry_after } => format!(
                        "Too many failed attempts. Try again in {}s.",
                        retry_after.as_secs().max(1)
                    ),
                    other => format!("{other:?}"),
                }),
            })
        }
        VaultEffect::SetKeyringUnlock { enable, password } => {
            if enable {
                let Some(password) = password else {
                    return Some(VaultEvent::KeyringChangeFailed(
                        "Enter the master password to turn on keyring unlock".into(),
                    ));
                };
                if let Err(e) = engine.verify_password(secret(&password)).await {
                    return Some(VaultEvent::KeyringChangeFailed(match e {
                        VaultError::WrongPassword { .. } => "Wrong password".into(),
                        other => capitalize(&other.to_string()),
                    }));
                }
            }
            Some(match engine.set_keyring_unlock(enable).await {
                Ok(()) => VaultEvent::KeyringChanged { enabled: enable },
                Err(e) => VaultEvent::KeyringChangeFailed(capitalize(&e.to_string())),
            })
        }
        // T87 implements the online flow.
        VaultEffect::Relogin { .. } => Some(VaultEvent::Relogin(Err(
            "Signing in to the sync server is not available yet".into(),
        ))),
        VaultEffect::Lock | VaultEffect::StartNewVault => None,
    }
}
