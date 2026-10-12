//! [`SessionPasswords`]: passwords typed at a prompt, remembered in memory
//! for the rest of the run so further connections to the same server (the
//! transfer engine's) don't ask again.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, PoisonError},
};

use secrecy::SecretString;

/// Passwords typed this run, keyed by `user@host:port`. Clones share the
/// same store. In memory only; [`clear`](Self::clear) it when the vault
/// locks. `Debug` shows only how many there are.
#[derive(Clone, Default)]
pub struct SessionPasswords {
    inner: Arc<Mutex<HashMap<String, SecretString>>>,
}

impl fmt::Debug for SessionPasswords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionPasswords")
            .field("entries", &self.map().len())
            .finish()
    }
}

impl SessionPasswords {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, SecretString>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The password typed for `key` (`user@host:port`) this run.
    pub fn get(&self, key: &str) -> Option<SecretString> {
        self.map().get(key).cloned()
    }

    /// Remember `password` for `key` (only after it logged in).
    pub fn put(&self, key: &str, password: SecretString) {
        self.map().insert(key.to_owned(), password);
    }

    /// Forget the password for `key` (the server rejected it).
    pub fn remove(&self, key: &str) {
        self.map().remove(key);
    }

    /// Forget everything (the vault locked).
    pub fn clear(&self) {
        self.map().clear();
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn clones_share_and_debug_hides() {
        let a = SessionPasswords::new();
        let b = a.clone();
        a.put("u@h:21", SecretString::from("pw".to_owned()));
        assert_eq!(
            b.get("u@h:21").map(|p| p.expose_secret().to_owned()),
            Some("pw".to_owned())
        );
        assert!(!format!("{a:?}").contains("pw"));
        b.remove("u@h:21");
        assert!(a.get("u@h:21").is_none());
        a.put("x", SecretString::from("y".to_owned()));
        a.clear();
        assert!(b.get("x").is_none());
    }
}
