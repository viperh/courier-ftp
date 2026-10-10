//! The program's [`BackendFactory`] (T03): picks the protocol crate for a
//! connection: SFTP (T22), FTP and FTPS (T14).

use std::sync::Arc;

use courier_ftp_core::{
    backend::{Backend, BackendFactory, ConnectInfo},
    events::{EventSender, SessionId},
    model::Protocol,
    settings::Settings,
    trust::{
        CertTrustStoreSlot, HostKeyStoreSlot, MemoryCertTrustStore, MemoryHostKeyStore, known_hosts,
    },
};
use courier_ftp_proto_ftp::{backend::FtpBackendFactory, tls::TlsTrust};
use courier_ftp_proto_sftp::{
    SftpBackendFactory,
    ssh::{CredentialCache, HostKeyVerifier, trust::TrustStoreVerifier},
};

/// Creates the backend for each protocol.
#[derive(Debug)]
pub(crate) struct Backends {
    sftp: SftpBackendFactory,
    /// FTP and FTPS (T14).
    pub(crate) ftp: FtpBackendFactory,
    /// Where "Always trust" certificates go (T12); swapped like `host_keys`.
    pub(crate) certs: Arc<CertTrustStoreSlot>,
    /// Where "Always trust" host keys go. It starts as a locked in-memory
    /// store (nothing can be remembered); the app's vault (T60) puts its
    /// persistent store in after unlock and a locked one back after lock.
    pub(crate) host_keys: Arc<HostKeyStoreSlot>,
    /// Passwords and passphrases typed at a prompt, remembered for this run.
    /// Cleared when the vault is locked (T60).
    pub(crate) credentials: CredentialCache,
}

impl Backends {
    /// The production factory: host keys checked against the trust store
    /// and the user's OpenSSH `known_hosts`, unknown keys asked about.
    pub(crate) fn new(settings: &Settings) -> Self {
        let host_keys = Arc::new(HostKeyStoreSlot::new(
            Arc::new(MemoryHostKeyStore::locked()),
        ));
        let home = directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf());
        let verifier: Arc<dyn HostKeyVerifier> = Arc::new(TrustStoreVerifier::new(
            host_keys.clone(),
            known_hosts::default_paths(home.as_deref()),
        ));
        let credentials = CredentialCache::new();
        let sftp = SftpBackendFactory::new(settings.clone(), verifier)
            .with_credentials(credentials.clone());
        let certs = Arc::new(CertTrustStoreSlot::new(Arc::new(
            MemoryCertTrustStore::locked(),
        )));
        let ftp = FtpBackendFactory::new(settings.clone(), Arc::new(TlsTrust::new(certs.clone())));
        Self {
            sftp,
            ftp,
            certs,
            host_keys,
            credentials,
        }
    }
}

impl BackendFactory for Backends {
    fn create(
        &self,
        info: &ConnectInfo,
        session: SessionId,
        events: EventSender,
    ) -> Box<dyn Backend> {
        match info.address.protocol {
            Protocol::Sftp => self.sftp.create(info, session, events),
            Protocol::Ftp | Protocol::FtpsExplicit | Protocol::FtpsImplicit => {
                self.ftp.create(info, session, events)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use courier_ftp_core::{Error, events, model::LogonType, model::ServerAddress};
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[tokio::test]
    async fn ftp_goes_to_the_ftp_backend() {
        let backends = Backends::new(&Settings::default());
        let (tx, _rx) = events::channel(2);
        // A port nothing listens on: the FTP backend tries to connect.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut address = ServerAddress::new(Protocol::Ftp, "127.0.0.1");
        address.port = port;
        let info = ConnectInfo::new(address, LogonType::Anonymous);
        let mut b = backends.create(&info, SessionId(1), tx);
        assert!(b.capabilities().ascii_mode);
        let err = b.connect(CancellationToken::new()).await.unwrap_err();
        assert!(matches!(err, Error::Connection(_)), "{err}");
    }
}
