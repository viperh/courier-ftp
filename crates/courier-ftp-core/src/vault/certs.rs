//! The vault-backed [`CertTrustStore`] (T12): trusted TLS certificates are
//! `trusted-cert` items, so they sync between devices (D4). Built like
//! [`VaultHostKeyStore`](super::VaultHostKeyStore): the app swaps it into its
//! [`CertTrustStoreSlot`](crate::trust::CertTrustStoreSlot) after unlock.

use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;

use super::items::{ItemVault, ItemVaultExt, VaultItem};
use crate::model::item::{self, ItemId, UnixMillis};
use crate::trust::{CertTrustStore, TrustedCertificate, normalize_host};
use crate::{Error, Result};

/// Trusted certificates stored as `trusted-cert` items in the vault.
#[derive(Debug, Clone)]
pub struct VaultCertTrustStore {
    vault: Arc<dyn ItemVault>,
}

impl VaultCertTrustStore {
    /// A store over `vault`.
    pub fn new(vault: Arc<dyn ItemVault>) -> Self {
        Self { vault }
    }

    /// Every stored entry with its item id; damaged items are skipped.
    async fn entries(&self) -> Result<Vec<(ItemId, TrustedCertificate)>> {
        let views = self.vault.list_views::<item::TrustedCert>().await?;
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

fn to_entry(item: &VaultItem, view: &item::TrustedCert) -> Option<TrustedCertificate> {
    let entry = TrustedCertificate::new(
        &view.host,
        view.port,
        view.der.clone(),
        view.subject.clone(),
        to_time(view.added_at),
    );
    // The stored fingerprint must match the certificate.
    if view.sha256.as_slice() != entry.sha256.as_slice() {
        tracing::warn!(item = %item.id.short(), "trusted-cert item: fingerprint does not match");
        return None;
    }
    Some(entry)
}

#[async_trait]
impl CertTrustStore for VaultCertTrustStore {
    async fn can_remember(&self) -> bool {
        self.vault.is_unlocked().await
    }

    async fn certs_for(&self, host: &str, port: u16) -> Result<Vec<TrustedCertificate>> {
        Ok(self
            .entries()
            .await?
            .into_iter()
            .map(|(_, e)| e)
            .filter(|e| e.is_for(host, port))
            .collect())
    }

    async fn remember(&self, cert: TrustedCertificate) -> Result<()> {
        let host = normalize_host(&cert.host);
        let existing: Vec<ItemId> = self
            .entries()
            .await?
            .into_iter()
            .filter(|(_, e)| e.is_for(&host, cert.port))
            .map(|(id, _)| id)
            .collect();
        // Reuse the replaced certificate's item so it syncs as an edit.
        let id = existing.first().copied().unwrap_or_else(ItemId::new);
        for dup in existing.iter().skip(1) {
            self.vault.delete(*dup).await?;
        }
        let view = item::TrustedCert {
            host,
            port: cert.port,
            sha256: cert.sha256.to_vec(),
            der: cert.der,
            subject: cert.subject,
            added_at: Some(to_millis(cert.added_at)),
            read_only: false,
        };
        self.vault.put_view(id, None, view).await?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<TrustedCertificate>> {
        let mut all: Vec<TrustedCertificate> =
            self.entries().await?.into_iter().map(|(_, e)| e).collect();
        all.sort_by(|a, b| (&a.host, a.port).cmp(&(&b.host, b.port)));
        Ok(all)
    }

    async fn forget(&self, host: &str, port: u16, sha256: &[u8; 32]) -> Result<bool> {
        let ids: Vec<ItemId> = self
            .entries()
            .await?
            .into_iter()
            .filter(|(_, e)| e.is_for(host, port) && &e.sha256 == sha256)
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
    use crate::trust::cert_sha256;
    use crate::vault::MemItemVault;

    const T: OffsetDateTime = datetime!(2026-10-10 12:00 UTC);

    fn cert(host: &str, der: &[u8]) -> TrustedCertificate {
        TrustedCertificate::new(host, 21, der.to_vec(), "CN=ftp", T)
    }

    #[tokio::test]
    async fn remember_lookup_list_forget_through_items() {
        let vault = Arc::new(MemItemVault::unlocked());
        let store = VaultCertTrustStore::new(vault.clone());
        assert!(store.can_remember().await);
        store
            .remember(cert("Ftp.Example.com", b"one"))
            .await
            .unwrap();
        store.remember(cert("other", b"two")).await.unwrap();
        // Replacing reuses the item.
        store
            .remember(cert("ftp.example.com", b"three"))
            .await
            .unwrap();
        assert_eq!(vault.list(ItemKind::TrustedCert).await.unwrap().len(), 2);
        let certs = store.certs_for("FTP.example.com", 21).await.unwrap();
        assert_eq!(certs, vec![cert("ftp.example.com", b"three")]);
        assert_eq!(certs[0].added_at, T);
        assert_eq!(store.list().await.unwrap().len(), 2);
        let sha = cert_sha256(b"three");
        assert!(store.forget("ftp.example.com", 21, &sha).await.unwrap());
        assert!(!store.forget("ftp.example.com", 21, &sha).await.unwrap());
        assert!(
            store
                .certs_for("ftp.example.com", 21)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn locked_vault_cannot_remember() {
        let vault = Arc::new(MemItemVault::unlocked());
        let store = VaultCertTrustStore::new(vault.clone());
        vault.set_unlocked(false);
        assert!(!store.can_remember().await);
        assert!(matches!(
            store.remember(cert("h", b"x")).await,
            Err(Error::Vault(_))
        ));
    }
}
