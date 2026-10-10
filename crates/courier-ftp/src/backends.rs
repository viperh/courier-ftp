//! The program's [`BackendFactory`] (T03): picks the protocol crate for a
//! connection. SFTP (T22) is wired up; FTP and FTPS arrive with T14.

use std::sync::Arc;

use async_trait::async_trait;
use courier_ftp_core::{
    Error, Result,
    backend::{
        Backend, BackendFactory, Capabilities, ConnectInfo, Listing, ReadStream, TransferOpts,
        WriteMode, WriteStream,
    },
    events::{EventSender, LogKind, SessionId},
    model::{Entry, Protocol, RemotePath, ServerAddress},
    settings::Settings,
    trust::{HostKeyStoreSlot, MemoryHostKeyStore, known_hosts},
};
use courier_ftp_proto_sftp::{
    SftpBackendFactory,
    ssh::{CredentialCache, HostKeyVerifier, trust::TrustStoreVerifier},
};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

/// Creates the backend for each protocol.
#[derive(Debug)]
pub(crate) struct Backends {
    sftp: SftpBackendFactory,
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
        Self {
            sftp,
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
                Box::new(Unsupported {
                    address: info.address.clone(),
                    session,
                    events,
                })
            }
        }
    }
}

const FTP_LATER: &str = "FTP and FTPS connections are not available yet (T14)";

/// A backend for a protocol this build can't speak yet: connecting fails
/// with a clear message.
struct Unsupported {
    address: ServerAddress,
    session: SessionId,
    events: EventSender,
}

#[async_trait]
impl Backend for Unsupported {
    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }

    fn address(&self) -> Option<&ServerAddress> {
        Some(&self.address)
    }

    async fn connect(&mut self, _: CancellationToken) -> Result<()> {
        let err = Error::Unsupported(FTP_LATER);
        self.events
            .log(self.session, LogKind::Error, err.to_string());
        Err(err)
    }

    async fn disconnect(&mut self) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        false
    }

    async fn home_dir(&mut self) -> Result<RemotePath> {
        Err(Error::Unsupported(FTP_LATER))
    }

    async fn list(&mut self, _: &RemotePath, _: CancellationToken) -> Result<Listing> {
        Err(Error::Unsupported(FTP_LATER))
    }

    async fn stat(&mut self, _: &RemotePath) -> Result<Entry> {
        Err(Error::Unsupported(FTP_LATER))
    }

    async fn mkdir(&mut self, _: &RemotePath) -> Result<()> {
        Err(Error::Unsupported(FTP_LATER))
    }

    async fn rmdir(&mut self, _: &RemotePath) -> Result<()> {
        Err(Error::Unsupported(FTP_LATER))
    }

    async fn remove_file(&mut self, _: &RemotePath) -> Result<()> {
        Err(Error::Unsupported(FTP_LATER))
    }

    async fn rename(&mut self, _: &RemotePath, _: &RemotePath) -> Result<()> {
        Err(Error::Unsupported(FTP_LATER))
    }

    async fn chmod(&mut self, _: &RemotePath, _: u32) -> Result<()> {
        Err(Error::Unsupported(FTP_LATER))
    }

    async fn set_mtime(&mut self, _: &RemotePath, _: OffsetDateTime) -> Result<()> {
        Err(Error::Unsupported(FTP_LATER))
    }

    async fn open_read(&mut self, _: &RemotePath, _: u64, _: &TransferOpts) -> Result<ReadStream> {
        Err(Error::Unsupported(FTP_LATER))
    }

    async fn open_write(
        &mut self,
        _: &RemotePath,
        _: WriteMode,
        _: &TransferOpts,
    ) -> Result<WriteStream> {
        Err(Error::Unsupported(FTP_LATER))
    }

    async fn finish_transfer(&mut self) -> Result<()> {
        Err(Error::Unsupported(FTP_LATER))
    }

    async fn raw_command(&mut self, _: &str) -> Result<String> {
        Err(Error::Unsupported(FTP_LATER))
    }

    async fn keepalive(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use courier_ftp_core::{events, model::LogonType};

    use super::*;

    #[tokio::test]
    async fn ftp_is_refused_until_t14() {
        let backends = Backends::new(&Settings::default());
        let (tx, _rx) = events::channel(2);
        let info = ConnectInfo::new(
            ServerAddress::new(Protocol::Ftp, "example.com"),
            LogonType::Anonymous,
        );
        let mut b = backends.create(&info, SessionId(1), tx);
        let err = b.connect(CancellationToken::new()).await.unwrap_err();
        assert!(err.to_string().contains("T14"), "{err}");
    }
}
