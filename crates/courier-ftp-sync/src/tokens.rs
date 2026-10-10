//! The token manager.
//!
//! * The access and refresh tokens are stored in `sync_state.tokens_enc`,
//!   wrapped under the LMK (purpose `SyncTokens`) by the vault engine; the
//!   LMK never leaves the engine.
//! * Tokens arrive as plain strings and are moved into `SecretString`s right
//!   away; they are never logged.
//! * The access token is refreshed 60 s before it expires, and after a 401.
//! * A refresh **persists the new pair before it is used**: refresh tokens are
//!   single-use with strict reuse detection, so losing a rotated pair (crash
//!   between the response and the write) would log the device out.
//! * Only one refresh is in flight (single-flight: the state mutex is held
//!   across it); a caller whose rejected token was already replaced just uses
//!   the new one. Every user of a signed-in session shares one
//!   [`TokenManager`] (`Arc`), see [`crate::SyncSession`].
//! * A rejected refresh (`401`: expired, revoked, reuse detected, password
//!   changed elsewhere) means the user must sign in again:
//!   [`SyncError::NeedsLogin`].
//!
//! Adapted from sverb's `sverb-sync/src/tokens.rs` (D13).

use std::sync::atomic::{AtomicU64, Ordering};

use courier_ftp_core::model::item::DeviceId;
use courier_ftp_crypto::wrap::WrapPurpose;
use courier_ftp_proto::auth::TokenPair;
use courier_ftp_store::SyncState;
use courier_ftp_store::vault::VaultEngine;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::SyncError;
use crate::http::ApiClient;

/// Refresh this long before the access token expires.
pub const REFRESH_MARGIN_MS: i64 = 60_000;

/// A token pair as received, moved into secrets.
pub(crate) struct Tokens {
    access: SecretString,
    refresh: SecretString,
    /// UNIX ms (device clock) when the access token expires.
    access_expires_at: i64,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tokens")
            .field("access_expires_at", &self.access_expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct StoredRef<'a> {
    a: &'a str,
    r: &'a str,
    e: i64,
}

#[derive(Deserialize)]
struct StoredOwned {
    a: String,
    r: String,
    e: i64,
}

impl Tokens {
    /// Moves the strings of `pair` into secrets.
    pub(crate) fn from_pair(pair: TokenPair, now_ms: i64) -> Self {
        let ttl = i64::try_from(pair.access_expires_in_s.saturating_mul(1000)).unwrap_or(i64::MAX);
        let TokenPair {
            access_token,
            refresh_token,
            ..
        } = pair;
        Self {
            access: SecretString::from(access_token),
            refresh: SecretString::from(refresh_token),
            access_expires_at: now_ms.saturating_add(ttl),
        }
    }

    pub(crate) fn access(&self) -> &SecretString {
        &self.access
    }

    async fn seal(&self, vault: &VaultEngine) -> Result<Vec<u8>, SyncError> {
        let json = Zeroizing::new(
            serde_json::to_vec(&StoredRef {
                a: self.access.expose_secret(),
                r: self.refresh.expose_secret(),
                e: self.access_expires_at,
            })
            .map_err(|e| SyncError::Crypto(e.to_string()))?,
        );
        Ok(vault.lmk_seal(WrapPurpose::SyncTokens, &json).await?)
    }

    async fn open(vault: &VaultEngine, enc: &[u8]) -> Result<Self, SyncError> {
        let json = vault
            .lmk_open(WrapPurpose::SyncTokens, enc)
            .await
            .map_err(|e| SyncError::Crypto(format!("sync tokens: {e}")))?;
        let s: StoredOwned = serde_json::from_slice(&json)
            .map_err(|e| SyncError::Crypto(format!("sync tokens: {e}")))?;
        Ok(Self {
            access: SecretString::from(s.a),
            refresh: SecretString::from(s.r),
            access_expires_at: s.e,
        })
    }
}

enum State {
    Valid(Tokens),
    /// The refresh token was rejected; nothing works until a new login.
    Dead,
}

/// Holds the tokens while the vault is unlocked. Share it (`Arc`).
pub struct TokenManager {
    vault: VaultEngine,
    api: ApiClient,
    state: tokio::sync::Mutex<State>,
    refreshes: AtomicU64,
}

impl std::fmt::Debug for TokenManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenManager")
            .field("refreshes", &self.refreshes.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Persists `tokens_enc` (keeps the rest of the row).
async fn persist(vault: &VaultEngine, enc: Vec<u8>) -> Result<(), SyncError> {
    vault
        .store()
        .write(move |w| {
            let mut st = w.as_read().get_sync_state()?.unwrap_or_default();
            st.tokens_enc = Some(enc);
            w.set_sync_state(&st)
        })
        .await?;
    Ok(())
}

impl TokenManager {
    /// Saves a fresh token pair (after login, registration or recovery)
    /// together with the server URL and the server-assigned device id, and
    /// returns a manager holding it.
    ///
    /// # Errors
    /// [`SyncError::Crypto`] (vault locked) / [`SyncError::Store`].
    pub(crate) async fn save_login(
        vault: &VaultEngine,
        api: &ApiClient,
        device_id: DeviceId,
        tokens: Tokens,
    ) -> Result<Self, SyncError> {
        let enc = tokens.seal(vault).await?;
        let state = SyncState {
            server_url: Some(api.base_url().to_owned()),
            device_id: Some(device_id),
            tokens_enc: Some(enc),
        };
        vault.store().sync_state().set(state).await?;
        Ok(Self {
            vault: vault.clone(),
            api: api.clone(),
            state: tokio::sync::Mutex::new(State::Valid(tokens)),
            refreshes: AtomicU64::new(0),
        })
    }

    /// Loads the stored tokens.
    ///
    /// # Errors
    /// [`SyncError::NeedsLogin`] when no tokens are stored,
    /// [`SyncError::Crypto`] when they don't open (vault locked).
    pub async fn load(vault: VaultEngine, api: ApiClient) -> Result<Self, SyncError> {
        let enc = vault
            .store()
            .sync_state()
            .get()
            .await?
            .and_then(|s| s.tokens_enc)
            .ok_or(SyncError::NeedsLogin)?;
        let tokens = Tokens::open(&vault, &enc).await?;
        Ok(Self {
            vault,
            api,
            state: tokio::sync::Mutex::new(State::Valid(tokens)),
            refreshes: AtomicU64::new(0),
        })
    }

    /// Successful refreshes so far (test hook).
    pub fn refresh_count(&self) -> u64 {
        self.refreshes.load(Ordering::SeqCst)
    }

    /// The API client.
    pub fn api(&self) -> &ApiClient {
        &self.api
    }

    /// The vault engine the tokens are sealed with.
    pub fn vault(&self) -> &VaultEngine {
        &self.vault
    }

    /// Whether the refresh token was rejected (sign-in required).
    pub async fn is_dead(&self) -> bool {
        matches!(*self.state.lock().await, State::Dead)
    }

    /// Marks the session as needing a new login (the server said so through
    /// `account_changed`, or this device was revoked).
    pub async fn invalidate(&self) {
        *self.state.lock().await = State::Dead;
    }

    /// A usable access token, refreshing first when it expires within
    /// [`REFRESH_MARGIN_MS`].
    ///
    /// # Errors
    /// [`SyncError::NeedsLogin`], or the refresh's transport error.
    pub async fn access(&self) -> Result<SecretString, SyncError> {
        let mut st = self.state.lock().await;
        let expiring = match &*st {
            State::Dead => return Err(SyncError::NeedsLogin),
            State::Valid(t) => {
                t.access_expires_at.saturating_sub(REFRESH_MARGIN_MS) <= self.vault.store().now()
            }
        };
        if expiring {
            self.refresh_locked(&mut st).await?;
        }
        match &*st {
            State::Valid(t) => Ok(t.access.clone()),
            State::Dead => Err(SyncError::NeedsLogin),
        }
    }

    /// The server rejected `rejected` with 401: refresh, unless another
    /// caller already replaced it.
    ///
    /// # Errors
    /// [`SyncError::NeedsLogin`], or the refresh's transport error.
    pub async fn refresh_after_401(&self, rejected: &SecretString) -> Result<(), SyncError> {
        let mut st = self.state.lock().await;
        match &*st {
            State::Dead => Err(SyncError::NeedsLogin),
            State::Valid(t) if t.access.expose_secret() != rejected.expose_secret() => Ok(()),
            State::Valid(_) => self.refresh_locked(&mut st).await,
        }
    }

    /// Refreshes the current access token (the WebSocket was closed with
    /// 4401).
    ///
    /// # Errors
    /// As [`TokenManager::refresh_after_401`].
    pub async fn refresh_now(&self) -> Result<(), SyncError> {
        let current = {
            let st = self.state.lock().await;
            match &*st {
                State::Valid(t) => t.access.clone(),
                State::Dead => return Err(SyncError::NeedsLogin),
            }
        };
        self.refresh_after_401(&current).await
    }

    async fn refresh_locked(&self, st: &mut State) -> Result<(), SyncError> {
        let State::Valid(current) = &*st else {
            return Err(SyncError::NeedsLogin);
        };
        match self.api.refresh(&current.refresh).await {
            Ok(pair) => {
                let next = Tokens::from_pair(pair, self.vault.store().now());
                // Persist before anything uses the new pair (strict reuse
                // detection: the old refresh token is now spent).
                persist(&self.vault, next.seal(&self.vault).await?).await?;
                *st = State::Valid(next);
                self.refreshes.fetch_add(1, Ordering::SeqCst);
                tracing::debug!("sync tokens refreshed");
                Ok(())
            }
            Err(e) if e.is_status(401) || e.is_status(403) => {
                tracing::warn!("refresh token rejected; sign-in required");
                *st = State::Dead;
                Err(SyncError::NeedsLogin)
            }
            Err(e) => Err(e),
        }
    }

    /// Runs `f` with an access token; refreshes once after a 401 and retries.
    ///
    /// # Errors
    /// [`SyncError::NeedsLogin`], or `f`'s error.
    pub(crate) async fn call<T, F, Fut>(&self, f: F) -> Result<T, SyncError>
    where
        F: Fn(ApiClient, SecretString) -> Fut,
        Fut: Future<Output = Result<T, SyncError>>,
    {
        let token = self.access().await?;
        match f(self.api.clone(), token.clone()).await {
            Err(e) if e.is_status(401) => {
                self.refresh_after_401(&token).await?;
                let token = self.access().await?;
                match f(self.api.clone(), token).await {
                    // Still rejected right after a refresh: the device was
                    // revoked or the account changed.
                    Err(e) if e.is_status(401) => {
                        self.invalidate().await;
                        Err(SyncError::NeedsLogin)
                    }
                    other => other,
                }
            }
            other => other,
        }
    }
}
