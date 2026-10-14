//! The real host-key verifier (T21): trusted keys from the
//! [`HostKeyStore`], OpenSSH `known_hosts` (read-only) and the trust prompt.
//!
//! On every connection [`TrustStoreVerifier`]:
//!
//! 1. converts russh's key into a core [`HostKey`];
//! 2. reads the store's keys for the host, the `known_hosts` files (fresh, so
//!    edits apply at once) and the keys trusted once during this run;
//! 3. applies [`decide`]: a match connects silently, an `@revoked` key fails
//!    with [`Error::HostKey`] without asking, anything else asks
//!    `Prompt(TrustHostKey)` (with the old key when it changed);
//! 4. "Always trust" stores the key (replacing the old one of the same type),
//!    "Trust once" remembers it until the program exits (in this verifier and
//!    its clones), "Cancel" fails the connection with [`Error::HostKey`].

use std::{
    collections::HashMap,
    fmt,
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
};

use async_trait::async_trait;
use courier_ftp_core::{
    Error, Result,
    events::{LogKind, PromptKind, PromptResponse, TrustDecision},
    trust::{
        Decision, HostKey, HostKeyStore, KnownHost, KnownHosts, TrustInputs, TrustSource, decide,
        normalize_host,
    },
};
use russh::keys::PublicKey;
use time::OffsetDateTime;

use super::hostkey::{HostKeyContext, HostKeyVerifier};

/// Keys trusted once, per `(host, port)`; shared by clones.
type SessionTrust = Arc<Mutex<HashMap<(String, u16), Vec<HostKey>>>>;

/// The application's [`HostKeyVerifier`]: the trust store, `known_hosts` and
/// the trust prompt (see the [module docs](self)).
#[derive(Clone)]
pub struct TrustStoreVerifier {
    store: Arc<dyn HostKeyStore>,
    known_hosts: Arc<Vec<PathBuf>>,
    session: SessionTrust,
}

impl fmt::Debug for TrustStoreVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustStoreVerifier")
            .field("store", &self.store)
            .field("known_hosts", &self.known_hosts)
            .finish_non_exhaustive()
    }
}

impl TrustStoreVerifier {
    /// A verifier over `store` that also trusts the `known_hosts` files at
    /// `known_hosts` (usually
    /// [`known_hosts::default_paths`](courier_ftp_core::trust::known_hosts::default_paths)
    /// of the user's home directory; missing files are fine).
    pub fn new(store: Arc<dyn HostKeyStore>, known_hosts: Vec<PathBuf>) -> Self {
        Self {
            store,
            known_hosts: Arc::new(known_hosts),
            session: SessionTrust::default(),
        }
    }

    /// Forget every "Trust once" answer.
    pub fn clear_session_trust(&self) {
        self.session_map().clear();
    }

    fn session_map(&self) -> std::sync::MutexGuard<'_, HashMap<(String, u16), Vec<HostKey>>> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn trust_for_session(&self, host: &str, port: u16, key: &HostKey) {
        let mut map = self.session_map();
        let keys = map.entry((host.to_owned(), port)).or_default();
        keys.retain(|k| k.algorithm() != key.algorithm());
        keys.push(key.clone());
    }

    async fn load_known_hosts(&self) -> KnownHosts {
        let paths = Arc::clone(&self.known_hosts);
        tokio::task::spawn_blocking(move || KnownHosts::load(&paths))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(%err, "reading known_hosts failed");
                KnownHosts::default()
            })
    }
}

/// russh's key as a core [`HostKey`].
///
/// # Errors
/// [`Error::HostKey`] when the key can't be encoded.
pub fn host_key_of(key: &PublicKey) -> Result<HostKey> {
    let blob = key
        .to_bytes()
        .map_err(|e| Error::HostKey(format!("can't encode the server's host key: {e}")))?;
    HostKey::from_blob(blob).map_err(|e| Error::HostKey(e.to_string()))
}

#[async_trait]
impl HostKeyVerifier for TrustStoreVerifier {
    async fn verify(&self, ctx: HostKeyContext<'_>, key: &PublicKey) -> Result<bool> {
        let key = host_key_of(key)?;
        let host = normalize_host(&ctx.host.host);
        let port = ctx.host.port;
        let stored: Vec<HostKey> = self
            .store
            .keys_for(&host, port)
            .await?
            .into_iter()
            .map(|e| e.key)
            .collect();
        let known_hosts = self.load_known_hosts().await.lookup(&host, port);
        let session = self
            .session_map()
            .get(&(host.clone(), port))
            .cloned()
            .unwrap_or_default();
        let can_remember = self.store.can_remember().await;
        let decision = decide(
            &key,
            &TrustInputs {
                stored: &stored,
                known_hosts: &known_hosts,
                session: &session,
                can_remember,
            },
        );
        let log = |kind, text: String| ctx.events.log(ctx.session, kind, text);
        let (known, can_remember) = match decision {
            Decision::Accept(source) => {
                let source = match source {
                    TrustSource::Store => "trusted host keys",
                    TrustSource::KnownHosts => "known_hosts",
                    TrustSource::Session => "trusted for this session",
                };
                log(
                    LogKind::Status,
                    format!("Host key of {} is trusted ({source}): {key}", ctx.host),
                );
                return Ok(true);
            }
            Decision::Revoked => {
                return Err(Error::HostKey(format!(
                    "the host key of {} is revoked in known_hosts ({key})",
                    ctx.host
                )));
            }
            Decision::Ask {
                known,
                can_remember,
            } => (known, can_remember),
        };
        match &known {
            Some(old) => log(
                LogKind::Error,
                format!(
                    "WARNING: the host key of {} has changed! Trusted: {old}, offered: {key}",
                    ctx.host
                ),
            ),
            None => log(
                LogKind::Status,
                format!("The host key of {} is not known yet: {key}", ctx.host),
            ),
        }
        let response = ctx
            .events
            .ask(
                Some(ctx.session),
                PromptKind::TrustHostKey {
                    host: ctx.host.to_string(),
                    key: key.fingerprint(),
                    known: known.as_ref().map(HostKey::fingerprint),
                    can_remember,
                },
                ctx.cancel,
            )
            .await?;
        match response {
            PromptResponse::Trust(TrustDecision::Always) if can_remember => {
                let entry = KnownHost::new(&host, port, key.clone(), OffsetDateTime::now_utc());
                match self.store.remember(entry).await {
                    Ok(()) => log(
                        LogKind::Status,
                        format!("Host key of {} saved as trusted.", ctx.host),
                    ),
                    Err(err) => {
                        log(
                            LogKind::Error,
                            format!(
                                "Could not save the host key of {} ({err}); trusted for this session only.",
                                ctx.host
                            ),
                        );
                        self.trust_for_session(&host, port, &key);
                    }
                }
                Ok(true)
            }
            PromptResponse::Trust(TrustDecision::Once | TrustDecision::Always) => {
                self.trust_for_session(&host, port, &key);
                log(
                    LogKind::Status,
                    format!("Host key of {} trusted for this session.", ctx.host),
                );
                Ok(true)
            }
            PromptResponse::Trust(TrustDecision::Reject) => Ok(false),
            _ => {
                tracing::warn!("unexpected answer to the host key prompt");
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests;
