//! Trusted TLS certificates (T12): the [`CertTrustStore`] trait, the
//! in-memory store, a slot to swap stores at run time, fingerprints and the
//! pure trust decision ([`decide_certificate`]).
//!
//! A certificate the OS trust store accepts for the host name is trusted
//! without asking. Anything else (self-signed, expired, wrong host name,
//! unknown CA) is trusted only when the user said so: "Always trust" stores
//! it here (one certificate per `host:port`; trusting a new one replaces the
//! old), "Trust once" keeps it in memory until the program exits.

use std::{
    fmt,
    sync::{
        Arc, Mutex, PoisonError, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use super::normalize_host;
use crate::{Error, Result};

/// The SHA-256 digest of a DER certificate.
pub fn cert_sha256(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// Bytes as colon-separated upper-case hex pairs (`AB:CD:…`), the way
/// certificate fingerprints are shown.
pub fn colon_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// The SHA-256 fingerprint of a DER certificate, as colon-separated hex.
pub fn sha256_fingerprint(der: &[u8]) -> String {
    colon_hex(&cert_sha256(der))
}

/// The SHA-1 fingerprint of a DER certificate, as colon-separated hex.
pub fn sha1_fingerprint(der: &[u8]) -> String {
    colon_hex(&Sha1::digest(der))
}

/// One trusted certificate ("Always trust"). The vault stores it as a
/// `trusted-cert` item (T81) with the fields `host`, `port`, `sha256`,
/// `der`, `subject` and `added_at`.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustedCertificate {
    /// Host name or IP address, lower case, without brackets.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// SHA-256 of `der`.
    pub sha256: [u8; 32],
    /// The certificate (DER), for the details dialog.
    pub der: Vec<u8>,
    /// The subject, for listing.
    pub subject: String,
    /// When the user trusted it.
    pub added_at: OffsetDateTime,
}

impl fmt::Debug for TrustedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedCertificate")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("sha256", &self.fingerprint())
            .field("subject", &self.subject)
            .field("added_at", &self.added_at)
            .finish_non_exhaustive()
    }
}

impl TrustedCertificate {
    /// An entry for `host:port` (host normalized) with the fingerprint
    /// computed from `der`.
    pub fn new(
        host: &str,
        port: u16,
        der: Vec<u8>,
        subject: impl Into<String>,
        added_at: OffsetDateTime,
    ) -> Self {
        Self {
            host: normalize_host(host),
            port,
            sha256: cert_sha256(&der),
            der,
            subject: subject.into(),
            added_at,
        }
    }

    /// The SHA-256 fingerprint as colon-separated hex.
    pub fn fingerprint(&self) -> String {
        colon_hex(&self.sha256)
    }

    /// Whether this entry is for `host:port`.
    pub fn is_for(&self, host: &str, port: u16) -> bool {
        self.port == port && self.host == normalize_host(host)
    }
}

/// Where trusted certificates live.
///
/// [`MemoryCertTrustStore`] is used until the vault is unlocked;
/// `vault::VaultCertTrustStore` keeps them as synced `trusted-cert` items.
/// Hosts are normalized by the implementation ([`normalize_host`]).
#[async_trait]
pub trait CertTrustStore: Send + Sync + fmt::Debug {
    /// Whether [`CertTrustStore::remember`] can store certificates (`false`
    /// while the vault is locked: the prompt offers only "Trust once").
    async fn can_remember(&self) -> bool;

    /// The trusted certificates for `host:port`.
    ///
    /// # Errors
    /// Storage errors.
    async fn certs_for(&self, host: &str, port: u16) -> Result<Vec<TrustedCertificate>>;

    /// Trust `cert`, replacing any other certificate for its `host:port`.
    ///
    /// # Errors
    /// [`Error::Vault`] when the store can't remember, or storage errors.
    async fn remember(&self, cert: TrustedCertificate) -> Result<()>;

    /// Every trusted certificate, sorted by host and port.
    ///
    /// # Errors
    /// Storage errors.
    async fn list(&self) -> Result<Vec<TrustedCertificate>>;

    /// Stop trusting the certificate with `sha256` for `host:port`.
    /// `Ok(false)` when there was none.
    ///
    /// # Errors
    /// [`Error::Vault`] when the vault is locked, or storage errors.
    async fn forget(&self, host: &str, port: u16, sha256: &[u8; 32]) -> Result<bool>;
}

/// Certificates in memory, lost at exit: the store before the vault is
/// unlocked and in tests.
#[derive(Debug)]
pub struct MemoryCertTrustStore {
    entries: Mutex<Vec<TrustedCertificate>>,
    can_remember: AtomicBool,
}

impl Default for MemoryCertTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryCertTrustStore {
    /// An empty store that remembers (for this run only).
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            can_remember: AtomicBool::new(true),
        }
    }

    /// An empty store that refuses to remember (vault locked or skipped).
    pub fn locked() -> Self {
        let store = Self::new();
        store.set_can_remember(false);
        store
    }

    /// Allow or refuse [`CertTrustStore::remember`].
    pub fn set_can_remember(&self, can: bool) {
        self.can_remember.store(can, Ordering::Relaxed);
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, Vec<TrustedCertificate>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn check_writable(&self) -> Result<()> {
        if self.can_remember.load(Ordering::Relaxed) {
            Ok(())
        } else {
            Err(Error::Vault(
                "the vault is locked: certificates can't be saved".to_owned(),
            ))
        }
    }
}

#[async_trait]
impl CertTrustStore for MemoryCertTrustStore {
    async fn can_remember(&self) -> bool {
        self.can_remember.load(Ordering::Relaxed)
    }

    async fn certs_for(&self, host: &str, port: u16) -> Result<Vec<TrustedCertificate>> {
        Ok(self
            .entries()
            .iter()
            .filter(|e| e.is_for(host, port))
            .cloned()
            .collect())
    }

    async fn remember(&self, cert: TrustedCertificate) -> Result<()> {
        self.check_writable()?;
        let mut cert = cert;
        cert.host = normalize_host(&cert.host);
        let mut entries = self.entries();
        entries.retain(|e| !e.is_for(&cert.host, cert.port));
        entries.push(cert);
        Ok(())
    }

    async fn list(&self) -> Result<Vec<TrustedCertificate>> {
        let mut all = self.entries().clone();
        all.sort_by(|a, b| (&a.host, a.port).cmp(&(&b.host, b.port)));
        Ok(all)
    }

    async fn forget(&self, host: &str, port: u16, sha256: &[u8; 32]) -> Result<bool> {
        self.check_writable()?;
        let mut entries = self.entries();
        let before = entries.len();
        entries.retain(|e| !(e.is_for(host, port) && &e.sha256 == sha256));
        Ok(entries.len() != before)
    }
}

/// A [`CertTrustStore`] forwarding to a store that can be replaced while
/// connections hold the slot (like `HostKeyStoreSlot`): a locked memory
/// store until the vault is unlocked, the vault store after.
pub struct CertTrustStoreSlot {
    current: RwLock<Arc<dyn CertTrustStore>>,
}

impl CertTrustStoreSlot {
    /// A slot holding `store`.
    pub fn new(store: Arc<dyn CertTrustStore>) -> Self {
        Self {
            current: RwLock::new(store),
        }
    }

    /// Put `store` in; later calls go to it.
    pub fn replace(&self, store: Arc<dyn CertTrustStore>) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = store;
    }

    /// The store calls currently go to.
    pub fn current(&self) -> Arc<dyn CertTrustStore> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }
}

impl fmt::Debug for CertTrustStoreSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CertTrustStoreSlot")
            .field(&self.current())
            .finish()
    }
}

#[async_trait]
impl CertTrustStore for CertTrustStoreSlot {
    async fn can_remember(&self) -> bool {
        self.current().can_remember().await
    }

    async fn certs_for(&self, host: &str, port: u16) -> Result<Vec<TrustedCertificate>> {
        self.current().certs_for(host, port).await
    }

    async fn remember(&self, cert: TrustedCertificate) -> Result<()> {
        self.current().remember(cert).await
    }

    async fn list(&self) -> Result<Vec<TrustedCertificate>> {
        self.current().list().await
    }

    async fn forget(&self, host: &str, port: u16, sha256: &[u8; 32]) -> Result<bool> {
        self.current().forget(host, port, sha256).await
    }
}

/// Why a certificate was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertTrustSource {
    /// The OS trust store accepted the chain for the host name.
    System,
    /// The user chose "Always trust" before.
    Store,
    /// The user chose "Trust once" earlier in this run.
    Session,
}

/// What [`decide_certificate`] knows.
#[derive(Debug, Clone, Copy)]
pub struct CertTrustInputs<'a> {
    /// Whether the OS trust store accepted the chain for the host name.
    pub system_ok: bool,
    /// SHA-256 of the server's certificate.
    pub sha256: &'a [u8; 32],
    /// The stored certificates for the host.
    pub stored: &'a [TrustedCertificate],
    /// Fingerprints trusted once for the host during this run.
    pub session: &'a [[u8; 32]],
    /// Whether "Always trust" can be stored.
    pub can_remember: bool,
}

/// What to do with a server certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertDecision {
    /// Trusted: continue without asking.
    Accept(CertTrustSource),
    /// Ask the user (`PromptKind::TrustCertificate`).
    Ask {
        /// The certificate trusted before for this host, when the server
        /// now presents another one (the prompt warns).
        known: Option<TrustedCertificate>,
        /// Whether "Always trust" may be offered.
        can_remember: bool,
    },
}

/// Decide about a server certificate (pure):
///
/// 1. valid for the host by the OS trust store → accept (a renewed
///    CA-signed certificate doesn't prompt even if another one was stored);
/// 2. stored or trusted once with the same fingerprint → accept;
/// 3. otherwise ask, with the stored certificate as `known` when there is
///    one (the certificate changed).
pub fn decide_certificate(inputs: &CertTrustInputs<'_>) -> CertDecision {
    if inputs.system_ok {
        return CertDecision::Accept(CertTrustSource::System);
    }
    if inputs.stored.iter().any(|c| &c.sha256 == inputs.sha256) {
        return CertDecision::Accept(CertTrustSource::Store);
    }
    if inputs.session.contains(inputs.sha256) {
        return CertDecision::Accept(CertTrustSource::Session);
    }
    CertDecision::Ask {
        known: inputs.stored.first().cloned(),
        can_remember: inputs.can_remember,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::type_complexity)]

    use pretty_assertions::assert_eq;
    use time::macros::datetime;

    use super::*;

    const T: OffsetDateTime = datetime!(2026-10-10 12:00 UTC);

    fn cert(host: &str, port: u16, der: &[u8]) -> TrustedCertificate {
        TrustedCertificate::new(host, port, der.to_vec(), "CN=x", T)
    }

    #[test]
    fn fingerprints() {
        assert_eq!(colon_hex(&[0xab, 0x01, 0xff]), "AB:01:FF");
        // SHA-256 and SHA-1 of the empty input.
        assert!(sha256_fingerprint(b"").starts_with("E3:B0:C4:42"));
        assert!(sha1_fingerprint(b"").starts_with("DA:39:A3:EE"));
        assert_eq!(cert("h", 1, b"").fingerprint(), sha256_fingerprint(b""));
    }

    #[tokio::test]
    async fn memory_store_replaces_per_host_and_port() {
        let store = MemoryCertTrustStore::new();
        store.remember(cert("Example.com", 21, b"a")).await.unwrap();
        store
            .remember(cert("example.com", 990, b"b"))
            .await
            .unwrap();
        store.remember(cert("[::1]", 21, b"c")).await.unwrap();
        // Same host:port: replaced.
        store.remember(cert("EXAMPLE.COM", 21, b"d")).await.unwrap();
        let certs = store.certs_for("example.com", 21).await.unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].der, b"d");
        assert_eq!(store.list().await.unwrap().len(), 3);
        assert_eq!(store.certs_for("::1", 21).await.unwrap().len(), 1);
        let sha = cert_sha256(b"d");
        assert!(store.forget("example.com", 21, &sha).await.unwrap());
        assert!(!store.forget("example.com", 21, &sha).await.unwrap());
        assert_eq!(store.list().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn locked_store_and_slot() {
        let slot = CertTrustStoreSlot::new(Arc::new(MemoryCertTrustStore::locked()));
        assert!(!slot.can_remember().await);
        assert!(matches!(
            slot.remember(cert("h", 21, b"a")).await,
            Err(Error::Vault(_))
        ));
        let mem = Arc::new(MemoryCertTrustStore::new());
        slot.replace(mem.clone());
        assert!(slot.can_remember().await);
        slot.remember(cert("h", 21, b"a")).await.unwrap();
        assert_eq!(mem.list().await.unwrap().len(), 1);
    }

    #[test]
    fn decision_table() {
        let sha = cert_sha256(b"new");
        let old = cert("h", 21, b"old");
        let same = cert("h", 21, b"new");
        let ask = |known: Option<TrustedCertificate>, can_remember| CertDecision::Ask {
            known,
            can_remember,
        };
        let cases: Vec<(
            &str,
            bool,
            Vec<TrustedCertificate>,
            Vec<[u8; 32]>,
            bool,
            CertDecision,
        )> = vec![
            (
                "valid chain",
                true,
                vec![],
                vec![],
                true,
                CertDecision::Accept(CertTrustSource::System),
            ),
            (
                "valid chain, another stored",
                true,
                vec![old.clone()],
                vec![],
                true,
                CertDecision::Accept(CertTrustSource::System),
            ),
            (
                "stored",
                false,
                vec![same.clone()],
                vec![],
                true,
                CertDecision::Accept(CertTrustSource::Store),
            ),
            (
                "trusted once",
                false,
                vec![],
                vec![sha],
                false,
                CertDecision::Accept(CertTrustSource::Session),
            ),
            ("unknown", false, vec![], vec![], true, ask(None, true)),
            (
                "unknown, locked",
                false,
                vec![],
                vec![],
                false,
                ask(None, false),
            ),
            (
                "changed",
                false,
                vec![old.clone()],
                vec![],
                true,
                ask(Some(old.clone()), true),
            ),
        ];
        for (name, system_ok, stored, session, can_remember, want) in cases {
            let got = decide_certificate(&CertTrustInputs {
                system_ok,
                sha256: &sha,
                stored: &stored,
                session: &session,
                can_remember,
            });
            assert_eq!(got, want, "{name}");
        }
    }
}
