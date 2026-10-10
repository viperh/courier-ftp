//! The encrypted vault: pure logic and the item-access seam (T30, D3, D4).
//!
//! Adapted from sverb's `sverb-core::vault` (D13). Everything here is UI-free
//! and I/O-free. The **engine** — Argon2, SQLite, the OS keyring, the keys —
//! is `courier_ftp_store::vault::VaultEngine`: the store crate depends on core,
//! so the engine sits above both (like sverb's vault service above
//! `sverb-store`). Core code reaches the engine through the [`ItemVault`] trait.
//!
//! - [`unlock`]: the persisted brute-force backoff;
//! - [`lock`]: the lock state and the auto-lock timer (idle + suspend);
//! - [`password`]: master-password strength (zxcvbn ≥ 3);
//! - [`keyring`]: the OS keyring seam ([`KeyringStore`], [`MemKeyring`]);
//! - [`items`]: [`ItemVault`] for the site model, bookmarks, history, trust;
//! - [`host_keys`]: the vault-backed [`HostKeyStore`](crate::trust::HostKeyStore);
//! - [`backup`]: the `.cftp-backup` file format (T73).
//!
//! # Key hierarchy
//!
//! ```text
//! master password ──Argon2id(meta.kdf)──▶ KEK ──wrap(Lmk)──▶ LMK   (meta.lmk_wrapped_pw)
//! OS keyring KEK (optional, per device) ──wrap(Lmk)──▶ LMK         (meta.lmk_wrapped_keyring)
//! LMK ──wrap(VaultKey(id))──▶ VK (vaults.wrapped_key)
//! VK  ──HKDF(item id)──▶ item key ──▶ item envelope (items.envelope)
//! ```
//!
//! A wrong password is detected by the AEAD failing to unwrap the LMK; no
//! verifier is stored. The engine never contacts a sync server to unlock.

pub mod backup;
pub mod host_keys;
pub mod items;
pub mod keyring;
pub mod lock;
pub mod password;
pub mod unlock;

mod error;
#[cfg(any(test, feature = "test-util"))]
mod mem;

use std::time::Duration;

use zeroize::Zeroize;

pub use self::error::VaultError;
pub use self::host_keys::VaultHostKeyStore;
pub use self::items::{ItemEdit, ItemVault, ItemVaultExt, ItemWrite, VaultItem};
pub use self::keyring::{
    KEYRING_SERVICE, KeyringError, KeyringStore, MemKeyring, NoKeyring, keyring_account,
};
pub use self::lock::{AutoLock, LockReason, LockState, auto_lock_timeout};
#[cfg(any(test, feature = "test-util"))]
pub use self::mem::MemItemVault;
pub use self::password::{
    MIN_SCORE, NO_RECOVERY_WARNING, PasswordStrength, WeakPassword, check_strength, estimate,
};
pub use self::unlock::{BackoffState, backoff_delay};
use crate::model::item::{DeviceId, HlcClock, ItemBody, ItemKind, is_secret_field};

/// Whether a vault exists and whether its keys are loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    /// No vault yet: first-run setup (T60).
    Uninitialised,
    /// A vault exists; no keys in memory.
    Locked,
    /// Keys are in memory.
    Unlocked,
}

/// How the vault was unlocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockMethod {
    /// Master password (Argon2id KEK).
    Password,
    /// OS keyring KEK.
    Keyring,
    /// First-run setup created the vault.
    Created,
}

/// What the unlock screen needs to know (no secrets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultStatus {
    /// Uninitialised, locked or unlocked.
    pub state: VaultState,
    /// Keyring unlock is enabled on this device (`meta.lmk_wrapped_keyring`).
    pub keyring_enabled: bool,
    /// The persisted backoff.
    pub backoff: BackoffState,
    /// How long until the next password attempt is allowed, if it must wait.
    pub retry_after: Option<Duration>,
    /// How the current session was unlocked (`None` while locked).
    pub unlock_method: Option<UnlockMethod>,
}

/// Kinds whose password fields `vault.store_passwords = false` keeps out of
/// the vault (a site's and a history entry's login).
pub const PASSWORD_KINDS: [ItemKind; 2] = [ItemKind::Site, ItemKind::HistoryEntry];

/// Applies `vault.store_passwords = false` to a body about to be written:
/// for [`PASSWORD_KINDS`], every secret field (`logon.password`,
/// `logon.passphrase`, proxy passwords) and `logon.account` is set to an
/// explicit null, so the value is never written and a previously stored one
/// is erased (also on other devices once the change syncs). Other kinds (an
/// SSH key's `private_key`, a proxy credential) are left alone.
pub fn strip_passwords(body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
    if !PASSWORD_KINDS.contains(&body.kind) {
        return;
    }
    let keys: Vec<String> = body
        .fields
        .iter()
        .filter(|(k, v)| {
            (is_secret_field(k) || k.as_str() == "logon.account") && !v.value.is_null()
        })
        .map(|(k, _)| k.clone())
        .collect();
    for key in keys {
        body.unset(&key, clock, device);
    }
}

/// Zeroizes every text and byte value of `body` in place (best effort memory
/// hygiene for decrypted items that are about to be dropped; field names
/// stay).
pub fn scrub(body: &mut ItemBody) {
    fn scrub_value(v: &mut ciborium::Value) {
        use ciborium::Value;
        match v {
            Value::Text(s) => s.zeroize(),
            Value::Bytes(b) => b.zeroize(),
            Value::Array(a) => a.iter_mut().for_each(scrub_value),
            Value::Map(m) => m.iter_mut().for_each(|(k, v)| {
                scrub_value(k);
                scrub_value(v);
            }),
            Value::Tag(_, inner) => scrub_value(inner),
            _ => {}
        }
    }
    for stamped in body.fields.values_mut() {
        scrub_value(&mut stamped.value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_clears_values() {
        let mut clock = HlcClock::default();
        let dev = DeviceId::new();
        let mut b = ItemBody::new(ItemKind::Site, 1);
        b.set("logon.password", "secret", &mut clock, dev);
        scrub(&mut b);
        assert_eq!(
            b.get("logon.password"),
            Some(&ciborium::Value::Text(String::new()))
        );
    }

    #[test]
    fn strip_passwords_only_touches_logins() {
        let mut clock = HlcClock::default();
        let dev = DeviceId::new();
        let mut site = ItemBody::new(ItemKind::Site, 1);
        site.set("host", "example.com", &mut clock, dev);
        site.set("logon.password", "pw", &mut clock, dev);
        site.set("logon.account", "acct", &mut clock, dev);
        site.set("logon.passphrase", "pp", &mut clock, dev);
        strip_passwords(&mut site, &mut clock, dev);
        assert!(site.get("logon.password").is_none());
        assert!(site.get("logon.account").is_none());
        assert!(site.get("logon.passphrase").is_none());
        assert!(
            site.contains("logon.password"),
            "explicit null erases on sync"
        );
        assert!(site.get("host").is_some());

        let mut key = ItemBody::new(ItemKind::SshKey, 1);
        key.set("private_key", "k", &mut clock, dev);
        strip_passwords(&mut key, &mut clock, dev);
        assert!(key.get("private_key").is_some());
    }
}
