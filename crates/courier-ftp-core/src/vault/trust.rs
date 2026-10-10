//! T21's [`HostKeyStore`] on `known-host` vault items.

use std::fmt;
use std::sync::Weak;

use async_trait::async_trait;
use time::OffsetDateTime;

use super::VaultError;
use super::engine::{Inner, VaultEngine};
use crate::Error;
use crate::model::item::{ItemId, ItemView, KnownHostItem, UnixMillis};
use crate::trust::{HostKeyStore, KnownHost, KnownHostId, normalize_host};

/// The vault-backed host-key store the engine installs in the
/// [`SwitchableHostKeyStore`](crate::trust::SwitchableHostKeyStore) on unlock. Holds the
/// engine weakly (the engine owns the switchable store).
pub struct VaultHostKeyStore {
    engine: Weak<Inner>,
}

impl fmt::Debug for VaultHostKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultHostKeyStore")
    }
}

fn to_millis(t: OffsetDateTime) -> UnixMillis {
    UnixMillis(i64::try_from(t.unix_timestamp_nanos() / 1_000_000).unwrap_or(0))
}

fn from_millis(ms: UnixMillis) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms.0) * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// `KnownHostItem` → `KnownHost`.
pub(crate) fn known_host(id: ItemId, item: KnownHostItem) -> KnownHost {
    KnownHost {
        id: KnownHostId(id.uuid()),
        host: normalize_host(&item.host),
        port: item.port,
        key_type: item.key_type,
        public_key: item.public_key,
        added_at: from_millis(item.added_at),
        comment: item.comment,
    }
}

/// `KnownHost` → `KnownHostItem`.
pub(crate) fn known_host_item(entry: &KnownHost) -> KnownHostItem {
    KnownHostItem {
        host: normalize_host(&entry.host),
        port: entry.port,
        key_type: entry.key_type.clone(),
        public_key: entry.public_key.clone(),
        added_at: to_millis(entry.added_at),
        comment: entry.comment.clone(),
    }
}

impl VaultHostKeyStore {
    pub(crate) fn new(engine: Weak<Inner>) -> Self {
        Self { engine }
    }

    fn engine(&self) -> Result<VaultEngine, VaultError> {
        self.engine
            .upgrade()
            .map(VaultEngine::from_inner)
            .ok_or(VaultError::Locked)
    }

    fn all(&self) -> Vec<KnownHost> {
        self.engine()
            .and_then(|e| e.list::<KnownHostItem>())
            .map(|items| {
                items
                    .into_iter()
                    .map(|l| known_host(l.id, l.view))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[async_trait]
impl HostKeyStore for VaultHostKeyStore {
    fn lookup(&self, host: &str, port: u16) -> Vec<KnownHost> {
        let host = normalize_host(host);
        self.all()
            .into_iter()
            .filter(|e| e.port == port && e.host.eq_ignore_ascii_case(&host))
            .collect()
    }

    fn list(&self) -> Vec<KnownHost> {
        let mut all = self.all();
        all.sort_by(|a, b| (&a.host, a.port, &a.key_type).cmp(&(&b.host, b.port, &b.key_type)));
        all
    }

    fn can_persist(&self) -> bool {
        true
    }

    async fn add(&self, entry: KnownHost, replaces: Vec<KnownHostId>) -> Result<(), Error> {
        let engine = self.engine()?;
        let vault = engine.personal_vault()?;
        let item = known_host_item(&entry);
        let replaces = replaces
            .into_iter()
            .map(|r| ItemId::from_uuid(r.0))
            .collect();
        engine
            .put_replacing(vault, ItemId::from_uuid(entry.id.0), item, replaces)
            .await?;
        tracing::debug!(
            kind = KnownHostItem::KIND.as_str(),
            "trusted host key stored"
        );
        Ok(())
    }

    async fn remove(&self, id: KnownHostId) -> Result<(), Error> {
        self.engine()?
            .delete_if_present(ItemId::from_uuid(id.0))
            .await?;
        Ok(())
    }
}
