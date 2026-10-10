//! Write policy: what syncs and which secrets are stored.

use super::VaultOptions;
use crate::model::item::{ItemBody, ItemKind, is_secret_field};

/// Whether a local write of `kind` is queued for sync (`dirty`): false only for
/// `history-entry` items while `sync.history` is off.
pub fn mark_dirty(kind: ItemKind, opts: &VaultOptions) -> bool {
    !(kind == ItemKind::HistoryEntry && !opts.sync_history)
}

/// Kinds whose secrets follow `vault.store_passwords` (FileZilla's "save passwords").
pub const PASSWORD_KINDS: [ItemKind; 3] = [
    ItemKind::Site,
    ItemKind::CredentialOverride,
    ItemKind::HistoryEntry,
];

/// Whether new secret values of `kind` are dropped before writing.
pub fn drops_new_secrets(kind: ItemKind, opts: &VaultOptions) -> bool {
    !opts.store_passwords && PASSWORD_KINDS.contains(&kind)
}

/// Undoes every secret field of `after` that gained a new non-null value compared with
/// `before` (clearing a secret to `null` stays). Returns whether anything was undone.
pub(crate) fn revert_new_secrets(before: &ItemBody, after: &mut ItemBody) -> bool {
    let keys: Vec<String> = after
        .fields
        .iter()
        .filter(|(k, v)| {
            is_secret_field(k)
                && !v.value.is_null()
                && before.fields.get(*k).is_none_or(|b| b.value != v.value)
        })
        .map(|(k, _)| k.clone())
        .collect();
    for k in &keys {
        match before.fields.get(k) {
            Some(prev) => {
                after.fields.insert(k.clone(), prev.clone());
            }
            None => {
                after.fields.remove(k);
            }
        }
    }
    !keys.is_empty()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::model::item::{DeviceId, HlcClock, ManualClock};

    #[test]
    fn history_dirty_only_with_sync_history() {
        let mut o = VaultOptions::default();
        assert!(!mark_dirty(ItemKind::HistoryEntry, &o));
        assert!(mark_dirty(ItemKind::Site, &o));
        o.sync_history = true;
        assert!(mark_dirty(ItemKind::HistoryEntry, &o));
    }

    #[test]
    fn new_secrets_reverted_clear_kept() {
        let mut clock = HlcClock::new(ManualClock::new(Duration::from_secs(1_800_000_000)));
        let dev = DeviceId::from_bytes([1; 16]);
        let mut before = ItemBody::new(ItemKind::Site, 1);
        before.set("host", "h", &mut clock, dev);
        before.set("account", "a", &mut clock, dev);
        let mut after = before.clone();
        after.set("password", "p", &mut clock, dev);
        after.unset("account", &mut clock, dev);
        after.set("host", "h2", &mut clock, dev);
        assert!(revert_new_secrets(&before, &mut after));
        assert!(!after.contains("password"));
        assert!(after.get("account").is_none() && after.contains("account"));
        assert_eq!(
            after.get("host").and_then(ciborium::Value::as_text),
            Some("h2")
        );
        let mut o = VaultOptions::default();
        assert!(!drops_new_secrets(ItemKind::Site, &o));
        o.store_passwords = false;
        assert!(drops_new_secrets(ItemKind::Site, &o));
        assert!(!drops_new_secrets(ItemKind::SshKey, &o));
    }
}
