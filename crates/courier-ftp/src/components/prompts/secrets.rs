//! "Remember for this session" secrets and typed secrets waiting for the server to
//! accept them (T69 rules 2, 7 and 9). Values are `SecretString`s: zeroized when
//! dropped, `[REDACTED]` in `Debug`.

use std::{collections::HashMap, fmt, sync::Arc, time::Duration};

use courier_ftp_core::{
    events::{PromptId, SecretCacheKey, SessionId},
    secret::SecretString,
};
use tokio::time::Instant;

/// A pending credential is dropped after this long without `CredentialAccepted`.
pub(crate) const PENDING_EXPIRY: Duration = Duration::from_secs(5 * 60);

/// Secrets remembered for this process (cleared on vault lock and exit).
#[derive(Default)]
pub(crate) struct SecretCache {
    values: HashMap<SecretCacheKey, SecretString>,
}

impl fmt::Debug for SecretCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretCache")
            .field("len", &self.values.len())
            .finish_non_exhaustive()
    }
}

impl SecretCache {
    /// The remembered secret for `key`.
    pub(crate) fn get(&self, key: &SecretCacheKey) -> Option<&SecretString> {
        self.values.get(key)
    }

    /// Remembers `value` for `key` (the old value is zeroized).
    pub(crate) fn insert(&mut self, key: SecretCacheKey, value: SecretString) {
        self.values.insert(key, value);
    }

    /// Forgets everything (every value is zeroized on drop).
    pub(crate) fn clear(&mut self) {
        self.values.clear();
    }

    /// Number of remembered secrets.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }
}

/// Which credential of a site a [`SaveRequest`] is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialField {
    /// The login (or account / proxy) password.
    Password,
    /// The private key passphrase.
    KeyPassphrase,
}

/// "Save in the vault" for a typed secret, emitted as `Action::SaveCredential` after
/// the server accepted it; T31 writes it into the site item of `session`.
///
/// There is no `SiteRef` yet (T31): the request names the session and the prompt's
/// cache key, from which T31 finds the site. The value is shared (`Arc`) because
/// actions are `Clone`.
#[derive(Clone)]
pub(crate) struct SaveRequest {
    /// The session whose site gets the secret.
    pub session: SessionId,
    /// What the secret is for (host, port, user or key).
    #[cfg_attr(not(test), expect(dead_code, reason = "read by T31"))]
    pub key: SecretCacheKey,
    /// Which field.
    pub field: CredentialField,
    /// The secret.
    pub value: Arc<SecretString>,
}

impl fmt::Debug for SaveRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SaveRequest")
            .field("session", &self.session)
            .field("field", &self.field)
            .field("value", &self.value)
            .finish_non_exhaustive()
    }
}

/// A typed secret waiting for `CredentialAccepted`.
pub(crate) struct Pending {
    /// The session that asked.
    pub session: SessionId,
    /// Cache key of the prompt.
    pub key: SecretCacheKey,
    /// Which credential.
    pub field: CredentialField,
    /// The typed value.
    pub value: SecretString,
    /// "Remember for this session" was checked.
    pub remember: bool,
    /// "Save in the vault" was checked.
    pub save: bool,
    /// When it was answered.
    pub since: Instant,
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("session", &self.session)
            .field("field", &self.field)
            .field("value", &self.value)
            .field("remember", &self.remember)
            .field("save", &self.save)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
thread_local! {
    /// Pending secrets dropped on this thread (tests prove every typed secret goes).
    pub(crate) static PENDING_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
impl Drop for Pending {
    fn drop(&mut self) {
        PENDING_DROPS.with(|c| c.set(c.get() + 1));
    }
}

/// Typed secrets waiting for the server's verdict, by prompt.
#[derive(Debug, Default)]
pub(crate) struct PendingCredentials {
    items: HashMap<PromptId, Pending>,
}

impl PendingCredentials {
    /// Keeps `pending` until [`Self::on_accepted`] for `id`.
    pub(crate) fn insert(&mut self, id: PromptId, pending: Pending) {
        self.items.insert(id, pending);
    }

    /// The server accepted the secret of prompt `id`: remember it in `cache` and/or
    /// return the save request.
    pub(crate) fn on_accepted(
        &mut self,
        id: PromptId,
        cache: &mut SecretCache,
    ) -> Option<SaveRequest> {
        let p = self.items.remove(&id)?;
        if p.remember {
            cache.insert(p.key.clone(), SecretString::from(p.value.expose()));
        }
        p.save.then(|| SaveRequest {
            session: p.session,
            key: p.key.clone(),
            field: p.field,
            value: Arc::new(SecretString::from(p.value.expose())),
        })
    }

    /// The session's connection failed or ended: drop its secrets.
    pub(crate) fn on_session_ended(&mut self, session: SessionId) {
        self.items.retain(|_, p| p.session != session);
    }

    /// Drops secrets older than [`PENDING_EXPIRY`].
    pub(crate) fn expire(&mut self, now: Instant) {
        self.items
            .retain(|_, p| now.saturating_duration_since(p.since) < PENDING_EXPIRY);
    }

    /// Number of waiting secrets.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

    use courier_ftp_core::events::{PromptKind, PromptResponse};

    use super::*;
    use crate::components::prompts::tests::{Prompter, password_prompt};

    fn key(host: &str) -> SecretCacheKey {
        SecretCacheKey::Password {
            protocol: courier_ftp_core::model::Protocol::Sftp,
            host: host.into(),
            port: 22,
            user: "alice".into(),
        }
    }

    fn pending(session: SessionId, remember: bool, save: bool) -> Pending {
        Pending {
            session,
            key: key("web01"),
            field: CredentialField::Password,
            value: SecretString::from("CANARY-pw-1"),
            remember,
            save,
            since: Instant::now(),
        }
    }

    #[test]
    fn cache_answers_non_retry_only() {
        let mut p = Prompter::new();
        let mut cache = SecretCache::default();
        cache.insert(key("web01"), SecretString::from("s3cret"));
        // Non-retry: answered from the cache.
        let first = p.request(PromptKind::Password(password_prompt(key("web01"), false)));
        let answered = crate::components::prompts::answer_from_cache(first, &cache);
        assert!(answered.is_none(), "the cached prompt is answered");
        match p.answer() {
            Some(PromptResponse::Secret {
                value,
                remember_session,
                save_in_vault,
            }) => {
                assert_eq!(value.expose(), "s3cret");
                assert!(!remember_session && !save_in_vault);
            }
            other => panic!("unexpected {other:?}"),
        }
        // Retry: shown.
        let retry = p.request(PromptKind::Password(password_prompt(key("web01"), true)));
        let back = crate::components::prompts::answer_from_cache(retry, &cache);
        assert!(back.is_some(), "a retry prompt always shows");
        // Another key: shown.
        let other = p.request(PromptKind::Password(password_prompt(key("other"), false)));
        assert!(crate::components::prompts::answer_from_cache(other, &cache).is_some());
    }

    #[test]
    fn cache_cleared_on_lock() {
        let mut cache = SecretCache::default();
        cache.insert(key("a"), SecretString::from("1"));
        cache.insert(key("b"), SecretString::from("2"));
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.get(&key("a")).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn save_only_after_credential_accepted() {
        let s = SessionId::next();
        let mut pend = PendingCredentials::default();
        let mut cache = SecretCache::default();
        let id = Prompter::new().any_id();
        pend.insert(id, pending(s, true, true));
        assert_eq!(cache.len(), 0, "nothing cached before acceptance");
        let save = pend.on_accepted(id, &mut cache).expect("save request");
        assert_eq!(save.value.expose(), "CANARY-pw-1");
        assert_eq!(save.field, CredentialField::Password);
        assert_eq!(save.key, key("web01"));
        assert_eq!(save.session, s);
        assert_eq!(cache.len(), 1);
        assert!(pend.on_accepted(id, &mut cache).is_none(), "once only");
        // Remember only: cached, no save.
        let id2 = Prompter::new().any_id();
        pend.insert(id2, pending(s, true, false));
        assert!(pend.on_accepted(id2, &mut cache).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn pending_dropped_on_failure_drop_counter() {
        let before = PENDING_DROPS.with(std::cell::Cell::get);
        let s = SessionId::next();
        let other = SessionId::next();
        let mut pend = PendingCredentials::default();
        let mut p = Prompter::new();
        pend.insert(p.any_id(), pending(s, false, true));
        pend.insert(p.any_id(), pending(s, true, false));
        pend.insert(p.any_id(), pending(other, true, true));
        pend.on_session_ended(s);
        assert_eq!(pend.len(), 1);
        assert_eq!(PENDING_DROPS.with(std::cell::Cell::get) - before, 2);
        // Expiry after 5 minutes.
        tokio::time::advance(PENDING_EXPIRY).await;
        pend.expire(Instant::now());
        assert_eq!(pend.len(), 0);
        assert_eq!(PENDING_DROPS.with(std::cell::Cell::get) - before, 3);
    }
}
