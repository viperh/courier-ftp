//! The vault-backed [`HostKeyStore`] (T21 trait, T30 implementation): trusted
//! host keys are `known-host` items, so they sync between devices (D4).
//!
//! The app starts with a locked `MemoryHostKeyStore` in its
//! [`HostKeyStoreSlot`](crate::trust::HostKeyStoreSlot), puts a
//! [`VaultHostKeyStore`] in after unlock and a locked memory store back after
//! lock.

use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;

use super::items::{ItemVault, ItemVaultExt, VaultItem};
use crate::model::item::{self, ItemId, UnixMillis};
use crate::trust::{HostKeyStore, KnownHost, normalize_host};
use crate::{Error, Result};

/// Trusted host keys stored as `known-host` items in the vault.
#[derive(Debug, Clone)]
pub struct VaultHostKeyStore {
    vault: Arc<dyn ItemVault>,
}

impl VaultHostKeyStore {
    /// A store over `vault`.
    pub fn new(vault: Arc<dyn ItemVault>) -> Self {
        Self { vault }
    }

    /// Every stored entry with its item id. Items that don't parse (a key type
    /// this build doesn't know, damaged data) are skipped and logged.
    async fn entries(&self) -> Result<Vec<(ItemId, KnownHost)>> {
        let views = self.vault.list_views::<item::KnownHost>().await?;
        Ok(views
            .into_iter()
            .filter_map(|(item, view)| to_entry(&item, &view).map(|e| (item.id, e)))
            .collect())
    }
}

fn to_time(t: Option<UnixMillis>) -> OffsetDateTime {
    t.and_then(|t| OffsetDateTime::from_unix_timestamp_nanos(i128::from(t.0) * 1_000_000).ok())
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn to_millis(t: OffsetDateTime) -> UnixMillis {
    UnixMillis(i64::try_from(t.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX))
}

fn to_entry(item: &VaultItem, view: &item::KnownHost) -> Option<KnownHost> {
    match KnownHost::from_parts(
        &view.host,
        view.port,
        &view.key_type,
        &view.public_key,
        to_time(view.added_at),
    ) {
        Ok(entry) => Some(entry),
        Err(e) => {
            tracing::warn!(item = %item.id.short(), error = %e, "known-host item does not parse");
            None
        }
    }
}

#[async_trait]
impl HostKeyStore for VaultHostKeyStore {
    async fn can_remember(&self) -> bool {
        self.vault.is_unlocked().await
    }

    async fn keys_for(&self, host: &str, port: u16) -> Result<Vec<KnownHost>> {
        let host = normalize_host(host);
        Ok(self
            .entries()
            .await?
            .into_iter()
            .map(|(_, e)| e)
            .filter(|e| e.port == port && e.host == host)
            .collect())
    }

    async fn remember(&self, entry: KnownHost) -> Result<()> {
        let entry = KnownHost::new(&entry.host, entry.port, entry.key, entry.added_at);
        let existing = self
            .entries()
            .await?
            .into_iter()
            .filter(|(_, e)| e.is_for(&entry.host, entry.port, entry.key_type()))
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
        // Reuse the item of the key it replaces, so the replacement syncs as
        // an edit; drop any duplicates (two devices trusting offline).
        let id = existing.first().copied().unwrap_or_else(ItemId::new);
        for dup in existing.iter().skip(1) {
            self.vault.delete(*dup).await?;
        }
        let view = item::KnownHost {
            host: entry.host.clone(),
            port: entry.port,
            key_type: entry.key_type().to_owned(),
            public_key: entry.public_key(),
            added_at: Some(to_millis(entry.added_at)),
            read_only: false,
        };
        self.vault.put_view(id, None, view).await?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<KnownHost>> {
        let mut all: Vec<KnownHost> = self.entries().await?.into_iter().map(|(_, e)| e).collect();
        all.sort_by(|a, b| (&a.host, a.port, a.key_type()).cmp(&(&b.host, b.port, b.key_type())));
        Ok(all)
    }

    async fn forget(&self, host: &str, port: u16, key_type: &str) -> Result<bool> {
        let ids: Vec<ItemId> = self
            .entries()
            .await?
            .into_iter()
            .filter(|(_, e)| e.is_for(host, port, key_type))
            .map(|(id, _)| id)
            .collect();
        let mut removed = false;
        for id in ids {
            removed |= self.vault.delete(id).await.map_err(Error::from)?;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;
    use time::macros::datetime;

    use super::*;
    use crate::model::item::ItemKind;
    use crate::trust::HostKey;
    use crate::vault::MemItemVault;

    const T: OffsetDateTime = datetime!(2026-10-10 12:00 UTC);

    fn blob(fields: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for f in fields {
            out.extend_from_slice(&u32::try_from(f.len()).unwrap().to_be_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    fn ed25519(seed: u8) -> HostKey {
        HostKey::from_blob(blob(&[b"ssh-ed25519", &[seed; 32]])).unwrap()
    }

    fn ecdsa() -> HostKey {
        HostKey::from_blob(blob(&[b"ecdsa-sha2-nistp256", b"nistp256", b"q"])).unwrap()
    }

    #[tokio::test]
    async fn remember_lookup_list_forget_through_items() {
        let vault = Arc::new(MemItemVault::unlocked());
        let store = VaultHostKeyStore::new(vault.clone());
        assert!(store.can_remember().await);
        store
            .remember(KnownHost::new("Example.com", 22, ed25519(1), T))
            .await
            .unwrap();
        store
            .remember(KnownHost::new("[example.com]", 22, ecdsa(), T))
            .await
            .unwrap();
        // Replacing the Ed25519 key reuses its item.
        store
            .remember(KnownHost::new("example.com", 22, ed25519(2), T))
            .await
            .unwrap();
        assert_eq!(vault.list(ItemKind::KnownHost).await.unwrap().len(), 2);

        let keys = store.keys_for("EXAMPLE.com", 22).await.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&KnownHost::new("example.com", 22, ed25519(2), T)));
        assert!(
            store
                .keys_for("example.com", 2222)
                .await
                .unwrap()
                .is_empty()
        );

        let list = store.list().await.unwrap();
        assert_eq!(
            list.iter().map(KnownHost::key_type).collect::<Vec<_>>(),
            ["ecdsa-sha2-nistp256", "ssh-ed25519"]
        );
        assert_eq!(list[1].added_at, T);

        assert!(
            store
                .forget("example.com", 22, "ssh-ed25519")
                .await
                .unwrap()
        );
        assert!(
            !store
                .forget("example.com", 22, "ssh-ed25519")
                .await
                .unwrap()
        );
        assert_eq!(store.list().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn locked_vault_cannot_remember() {
        let vault = Arc::new(MemItemVault::unlocked());
        let store = VaultHostKeyStore::new(vault.clone());
        vault.set_unlocked(false);
        assert!(!store.can_remember().await);
        let err = store
            .remember(KnownHost::new("h", 22, ed25519(1), T))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Vault(_)), "{err}");
        assert!(store.keys_for("h", 22).await.is_err());
    }
}
