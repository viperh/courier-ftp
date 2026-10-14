//! The russh client handler: host-key check (delegated to the
//! [`HostKeyVerifier`]), negotiated algorithms, the auth banner and why the
//! connection ended.

use std::sync::{Arc, Mutex};

use courier_ftp_core::{
    Error,
    events::{EventSender, LogKind, SessionId},
    net::HostPort,
};
use russh::{
    client::{self, DisconnectReason, Session},
    keys::{PublicKey, PublicKeyOrCertificate},
};
use tokio_util::sync::CancellationToken;

use super::{
    hostkey::{HostKeyContext, HostKeyVerifier, describe_key},
    text::sanitize_server_text,
};

/// What the handler learned, read by the connect flow and the session.
#[derive(Debug, Default)]
pub(crate) struct Shared {
    /// The server's identification string (`SSH-2.0-OpenSSH_9.6`).
    pub(crate) server_version: String,
    /// Key exchange algorithm.
    pub(crate) kex: String,
    /// Host key algorithm.
    pub(crate) host_key_alg: String,
    /// Cipher (client to server).
    pub(crate) cipher: String,
    /// MAC (client to server; meaningless for AEAD ciphers).
    pub(crate) mac: String,
    /// The accepted host key (`type SHA256:…`).
    pub(crate) host_key: String,
    /// Why the host key was refused (the verifier's error or a rejection).
    pub(crate) host_key_error: Option<Error>,
    /// Why the connection ended, when the server or russh ended it.
    pub(crate) end: Option<String>,
    /// The host-key verifier is running (the handshake timeout pauses).
    pub(crate) verifying: bool,
}

/// Locks `shared`, recovering from a poisoned lock (the data is plain).
pub(crate) fn lock(shared: &Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
    shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The russh handler of one connection (opaque; it appears in [`super::SshHandle`]).
pub struct ClientHandler {
    pub(crate) verifier: Arc<dyn HostKeyVerifier>,
    pub(crate) host: HostPort,
    pub(crate) session: SessionId,
    pub(crate) events: EventSender,
    pub(crate) cancel: CancellationToken,
    pub(crate) shared: Arc<Mutex<Shared>>,
}

impl std::fmt::Debug for ClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandler")
            .field("host", &self.host)
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

impl ClientHandler {
    fn reject(&self, err: Error) -> bool {
        lock(&self.shared).host_key_error = Some(err);
        false
    }
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(cert) => PublicKey::from(cert.public_key().clone()),
        };
        let ctx = HostKeyContext {
            host: &self.host,
            session: self.session,
            events: &self.events,
            cancel: &self.cancel,
        };
        let described = describe_key(&key);
        lock(&self.shared).verifying = true;
        let verdict = self.verifier.verify(ctx, &key).await;
        lock(&self.shared).verifying = false;
        Ok(match verdict {
            Ok(true) => {
                lock(&self.shared).host_key = described;
                true
            }
            Ok(false) => self.reject(Error::HostKey(format!(
                "the host key of {} was rejected ({described})",
                self.host
            ))),
            Err(err) => self.reject(err),
        })
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let version = sanitize_server_text(&String::from_utf8_lossy(session.remote_sshid()));
        let mut shared = lock(&self.shared);
        let first = shared.server_version.is_empty();
        shared.server_version = version;
        shared.kex = names.kex.as_ref().to_owned();
        shared.host_key_alg = names.key.to_string();
        shared.cipher = names.cipher.as_ref().to_owned();
        shared.mac = names.client_mac.as_ref().to_owned();
        let line = format!(
            "Negotiated: kex {}, host key {}, cipher {}, MAC {}",
            shared.kex, shared.host_key_alg, shared.cipher, shared.mac
        );
        let version = shared.server_version.clone();
        drop(shared);
        if first {
            self.events.log(
                self.session,
                LogKind::Status,
                format!("Server version: {version}"),
            );
        }
        self.events.log(self.session, LogKind::Debug(3), line);
        Ok(())
    }

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        for line in sanitize_server_text(banner).lines() {
            self.events.log(self.session, LogKind::Status, line);
        }
        Ok(())
    }

    async fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        match reason {
            DisconnectReason::ReceivedDisconnect(info) => {
                let message = sanitize_server_text(&info.message);
                tracing::debug!(code = ?info.reason_code, %message, "server disconnected");
                lock(&self.shared).end.get_or_insert(if message.is_empty() {
                    "the server closed the connection".to_owned()
                } else {
                    format!("the server closed the connection: {message}")
                });
                Ok(())
            }
            DisconnectReason::Error(err) => {
                let text = match &err {
                    russh::Error::KeepaliveTimeout => {
                        "the server stopped answering keep-alives".to_owned()
                    }
                    russh::Error::InactivityTimeout => "inactivity timeout".to_owned(),
                    other => other.to_string(),
                };
                lock(&self.shared).end.get_or_insert(text);
                Err(err)
            }
        }
    }
}
