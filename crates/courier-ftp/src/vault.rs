//! The app's side of the vault (T60): opens the database, runs the engine's
//! slow calls (Argon2, keyring, SQLite) in background tasks that report back
//! as [`VaultMsg`], and applies what locking and unlocking mean for the rest
//! of the program (the host key store behind "Always trust", the session
//! credential cache, auto-lock).
//!
//! The screens are in `ui::vault`; the engine is T30's
//! [`courier_ftp_store::vault::VaultEngine`].

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use courier_ftp_core::{
    model::item::{ItemId, ProxyCredential},
    settings::VaultSettings,
    trust::{CertTrustStoreSlot, HostKeyStoreSlot, MemoryCertTrustStore, MemoryHostKeyStore},
    vault::{
        AutoLock, ItemVaultExt, LockReason, VaultCertTrustStore, VaultError, VaultHostKeyStore,
        VaultStatus,
    },
};
use courier_ftp_crypto::kdf::Argon2Cost;
use courier_ftp_proto_ftp::backend::FtpBackendFactory;
use courier_ftp_proto_sftp::ssh::CredentialCache;
use courier_ftp_store::{
    Store, StoreError,
    vault::{InitReport, UnlockReport, VaultEngine, keyring_from_env},
};
use secrecy::SecretString;
use tokio::{sync::mpsc::UnboundedSender, task::JoinHandle, time::Instant};

/// Opens the store and builds the engine (blocking; runs in
/// `spawn_blocking`). Tests pass one over a temporary directory with an
/// in-memory keyring and cheap Argon2.
pub(crate) type VaultOpener = Arc<dyn Fn() -> Result<VaultEngine, VaultError> + Send + Sync>;

/// The production opener: `data_dir/courier-ftp.db`, the OS keyring unless
/// `COURIER_FTP_KEYRING=off`, and the default Argon2 cost.
pub(crate) fn opener(data_dir: PathBuf) -> VaultOpener {
    Arc::new(move || {
        let store = Store::open_in_dir(&data_dir).map_err(store_error)?;
        Ok(VaultEngine::new(
            store,
            keyring_from_env(),
            Argon2Cost::DEFAULT,
        ))
    })
}

fn store_error(e: StoreError) -> VaultError {
    match e {
        StoreError::Busy => VaultError::Busy,
        other => VaultError::Storage(other.to_string()),
    }
}

/// The database was opened.
pub(crate) struct Opened {
    pub(crate) engine: VaultEngine,
    pub(crate) status: VaultStatus,
    /// Whether the OS keyring works (only probed before first run, where the
    /// checkbox needs it).
    pub(crate) keyring_available: bool,
    /// Where the old database went ("start a new empty vault").
    pub(crate) moved_aside: Option<PathBuf>,
}

/// A background vault call finished.
pub(crate) enum VaultMsg {
    Opened(Result<Box<Opened>, VaultError>),
    Created(Result<InitReport, VaultError>),
    /// `keyring`: the silent keyring unlock at start.
    Unlocked {
        keyring: bool,
        result: Result<UnlockReport, VaultError>,
    },
    Reset(Result<UnlockReport, VaultError>),
}

/// Where the vault is, as far as the app is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// The database is being opened.
    Opening,
    /// It could not be opened (busy, damaged).
    Unavailable,
    /// No vault yet (first run).
    Uninitialised,
    Locked,
    Unlocked,
}

/// What the vault switches for FTP on unlock and lock.
struct FtpHooks {
    certs: Arc<CertTrustStoreSlot>,
    factory: FtpBackendFactory,
    proxy_password: Option<String>,
}

/// The FTP proxy password stored in the `proxy-credential` item `id`.
async fn read_proxy_password(engine: &VaultEngine, id: &str) -> Option<SecretString> {
    let id: ItemId = id.parse().ok()?;
    let views = match engine.list_views::<ProxyCredential>().await {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(%err, "reading the FTP proxy password failed");
            return None;
        }
    };
    views
        .into_iter()
        .find(|(item, _)| item.id == id)
        .and_then(|(_, view)| view.password)
}

/// See the module docs.
pub(crate) struct Vault {
    open: VaultOpener,
    engine: Option<VaultEngine>,
    /// "Always trust" goes here: the vault's store while unlocked, a locked
    /// in-memory one otherwise.
    host_keys: Arc<HostKeyStoreSlot>,
    /// Passwords typed at prompts this run; cleared on lock.
    credentials: CredentialCache,
    /// FTPS certificate trust and the FTP proxy password (T12/T14).
    ftp: Option<FtpHooks>,
    tx: UnboundedSender<VaultMsg>,
    /// The engine's `lock()` started by [`Vault::lock`]; unlocks wait for it
    /// so a quick unlock can't be undone by a late lock.
    pending_lock: Option<JoinHandle<()>>,
    pub(crate) phase: Phase,
    pub(crate) auto_lock: AutoLock,
    store_passwords: bool,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl Vault {
    pub(crate) fn new(
        open: VaultOpener,
        host_keys: Arc<HostKeyStoreSlot>,
        credentials: CredentialCache,
        settings: &VaultSettings,
        tx: UnboundedSender<VaultMsg>,
    ) -> Self {
        Self {
            open,
            engine: None,
            host_keys,
            credentials,
            ftp: None,
            tx,
            pending_lock: None,
            phase: Phase::Opening,
            auto_lock: AutoLock::from_settings(settings, Instant::now()),
            store_passwords: settings.store_passwords,
        }
    }

    /// Swap the certificate store with the host key store, and give the FTP
    /// factory the FTP proxy password from the vault item `proxy_password`
    /// (the settings' `password_ref`) while unlocked.
    pub(crate) fn set_ftp(
        &mut self,
        certs: Arc<CertTrustStoreSlot>,
        factory: FtpBackendFactory,
        proxy_password: Option<String>,
    ) {
        self.ftp = Some(FtpHooks {
            certs,
            factory,
            proxy_password,
        });
    }

    #[cfg(test)]
    pub(crate) fn engine(&self) -> Option<&VaultEngine> {
        self.engine.as_ref()
    }

    /// Open the database in the background. With `move_aside` the current
    /// database is first renamed next to itself (never deleted) so a new
    /// empty vault can start.
    pub(crate) fn open(&mut self, move_aside: bool) {
        self.phase = Phase::Opening;
        let old = self.engine.take();
        let open = Arc::clone(&self.open);
        let tx = self.tx.clone();
        let store_passwords = self.store_passwords;
        tokio::spawn(async move {
            let result = async {
                let (engine, moved_aside) = tokio::task::spawn_blocking(move || {
                    let moved = match old {
                        Some(old) if move_aside => {
                            let path = old.store().path().to_path_buf();
                            // The last handle: closes the database first.
                            drop(old);
                            Some(move_db_aside(&path).map_err(|e| {
                                VaultError::Storage(format!(
                                    "could not move {} aside: {e}",
                                    path.display()
                                ))
                            })?)
                        }
                        _ => None,
                    };
                    Ok::<_, VaultError>((open()?, moved))
                })
                .await
                .map_err(|e| VaultError::Storage(format!("background task failed: {e}")))??;
                engine.set_store_passwords(store_passwords);
                let status = engine.status().await?;
                let keyring_available = status.state
                    == courier_ftp_core::vault::VaultState::Uninitialised
                    && engine.keyring_available().await;
                Ok(Box::new(Opened {
                    engine,
                    status,
                    keyring_available,
                    moved_aside,
                }))
            }
            .await;
            let _ = tx.send(VaultMsg::Opened(result));
        });
    }

    /// The database is open.
    pub(crate) fn opened(&mut self, engine: VaultEngine) {
        self.engine = Some(engine);
    }

    fn spawn<F, Fut>(&mut self, f: F)
    where
        F: FnOnce(VaultEngine) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = VaultMsg> + Send,
    {
        let Some(engine) = self.engine.clone() else {
            return;
        };
        let pending = self.pending_lock.take();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            if let Some(pending) = pending {
                let _ = pending.await;
            }
            let _ = tx.send(f(engine).await);
        });
    }

    /// First run.
    pub(crate) fn create(&mut self, password: SecretString, keyring: bool) {
        self.spawn(
            move |e| async move { VaultMsg::Created(e.initialize(&password, keyring).await) },
        );
    }

    pub(crate) fn unlock(&mut self, password: SecretString) {
        self.spawn(move |e| async move {
            VaultMsg::Unlocked {
                keyring: false,
                result: e.unlock(&password).await,
            }
        });
    }

    pub(crate) fn unlock_with_keyring(&mut self) {
        self.spawn(|e| async move {
            VaultMsg::Unlocked {
                keyring: true,
                result: e.unlock_with_keyring().await,
            }
        });
    }

    /// "Forgot password?" through the keyring.
    pub(crate) fn reset_with_keyring(&mut self, password: SecretString) {
        self.spawn(move |e| async move {
            VaultMsg::Reset(e.reset_password_with_keyring(&password).await)
        });
    }

    /// The engine unlocked: "Always trust" now persists in the vault and the
    /// idle timer starts.
    pub(crate) fn on_unlocked(&mut self) {
        if let Some(engine) = &self.engine {
            self.host_keys
                .replace(Arc::new(VaultHostKeyStore::new(Arc::new(engine.clone()))));
            if let Some(ftp) = &self.ftp {
                ftp.certs
                    .replace(Arc::new(VaultCertTrustStore::new(Arc::new(engine.clone()))));
                if let Some(id) = ftp.proxy_password.as_deref() {
                    let (engine, factory, id) =
                        (engine.clone(), ftp.factory.clone(), id.to_owned());
                    tokio::spawn(async move {
                        factory.set_ftp_proxy_password(read_proxy_password(&engine, &id).await);
                    });
                }
            }
        }
        self.phase = Phase::Unlocked;
        self.auto_lock.reset(Instant::now());
    }

    /// Lock: keys are dropped (in the background), "Always trust" becomes
    /// unavailable and typed passwords are forgotten.
    pub(crate) fn lock(&mut self) {
        self.host_keys
            .replace(Arc::new(MemoryHostKeyStore::locked()));
        if let Some(ftp) = &self.ftp {
            ftp.certs.replace(Arc::new(MemoryCertTrustStore::locked()));
            ftp.factory.set_ftp_proxy_password(None);
        }
        self.credentials.clear();
        self.phase = Phase::Locked;
        if let Some(engine) = self.engine.clone() {
            self.pending_lock = Some(tokio::spawn(async move { engine.lock().await }));
        }
    }

    /// A key press re-arms the idle timer.
    pub(crate) fn on_input(&mut self) {
        self.auto_lock.on_input(Instant::now());
    }

    /// Whether auto-lock says to lock now.
    pub(crate) fn tick(&mut self) -> Option<LockReason> {
        if self.phase != Phase::Unlocked {
            return None;
        }
        self.auto_lock.tick(Instant::now(), SystemTime::now())
    }
}

/// Renames `path` (and its `-wal`/`-shm` files) to
/// `<name>.moved-<unix seconds>` next to it; returns the new path.
fn move_db_aside(path: &Path) -> std::io::Result<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| courier_ftp_store::DB_FILE_NAME.to_owned());
    let target = path.with_file_name(format!("{name}.moved-{stamp}"));
    if target.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} already exists", target.display()),
        ));
    }
    std::fs::rename(path, &target)?;
    for suffix in ["-wal", "-shm"] {
        let side = path.with_file_name(format!("{name}{suffix}"));
        if side.exists() {
            let to = target.with_file_name(format!(
                "{}{suffix}",
                target
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ));
            std::fs::rename(&side, to)?;
        }
    }
    Ok(target)
}
