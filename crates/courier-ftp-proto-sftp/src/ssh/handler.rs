//! The russh client handler and the host-key seam (T20; adapted from sverb
//! `ssh/handler.rs`, D13).
//!
//! `ClientHandler` runs inside russh's session task. It asks the
//! [`HostKeyVerifier`] about the server's key (T21 plugs in the trust store and the
//! prompt; the handshake is suspended meanwhile), records the negotiated algorithms,
//! logs the authentication banner and records why the transport ended.

use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use async_trait::async_trait;
use base64::Engine as _;
use courier_ftp_core::{
    events::{EventSender, SessionId, SessionLog},
    text::sanitize_server_text,
};
use md5::{Digest as _, Md5};
use russh::{
    client::{self, Session},
    keys::{HashAlg, PublicKey, PublicKeyOrCertificate},
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::{SshSessionInfo, errors::EndCause};
use crate::keys::key_bits;

/// Banner lines shown at most.
pub const MAX_BANNER_LINES: usize = 40;
/// Banner characters shown at most.
pub const MAX_BANNER_CHARS: usize = 4096;
/// Server version / disconnect text is capped at this many characters.
const MAX_SERVER_LINE: usize = 512;

/// The key the server presented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKey {
    /// `"ssh-ed25519"`, `"ecdsa-sha2-nistp256"`, `"ssh-rsa"`, …
    pub key_type: String,
    /// 256 for Ed25519, the modulus size for RSA, the curve size for ECDSA.
    pub bits: u32,
    /// The known_hosts key field (base64 of the SSH wire key).
    pub blob_base64: String,
    /// `"SHA256:<base64 no padding>"`.
    pub fingerprint_sha256: String,
    /// `"MD5:aa:bb:…"`.
    pub fingerprint_md5: String,
}

impl ServerKey {
    /// The description of `key`.
    pub fn from_public_key(key: &PublicKey) -> Self {
        let blob = key.to_bytes().unwrap_or_default();
        let md5 = Md5::digest(&blob);
        let hex: Vec<String> = md5.iter().map(|b| format!("{b:02x}")).collect();
        Self {
            key_type: key.algorithm().as_str().to_owned(),
            bits: key_bits(key),
            blob_base64: base64::engine::general_purpose::STANDARD.encode(&blob),
            fingerprint_sha256: key.fingerprint(HashAlg::Sha256).to_string(),
            fingerprint_md5: format!("MD5:{}", hex.join(":")),
        }
    }
}

/// Session id, event sender and cancel token for host-key prompts.
#[derive(Debug, Clone, Copy)]
pub struct VerifyCtx<'a> {
    /// The session that connects.
    pub session: SessionId,
    /// Where to send the prompt.
    pub events: &'a EventSender,
    /// The connect's cancel token.
    pub cancel: &'a CancellationToken,
}

/// What the verifier decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyVerdict {
    /// Trusted.
    Accept,
    /// Rejected, with the user-facing reason.
    Reject(String),
}

/// Decides whether a server's host key is trusted (T21 provides the real one).
#[async_trait]
pub trait HostKeyVerifier: Send + Sync + fmt::Debug {
    /// Decide about `key` for `host:port`. May ask the user (T21 sends the prompt and
    /// awaits it here; the handshake is suspended meanwhile and the time does not count
    /// against the handshake timeout).
    async fn verify(
        &self,
        host: &str,
        port: u16,
        key: &ServerKey,
        ctx: &VerifyCtx<'_>,
    ) -> HostKeyVerdict;

    /// Key types already trusted for `host:port`, moved to the front of the host-key
    /// algorithm preference (avoids a needless "unknown key" for a second key type).
    fn known_key_types(&self, host: &str, port: u16) -> Vec<String> {
        let _ = (host, port);
        Vec::new()
    }
}

/// The reason [`UnverifiedHostKeys`] gives.
pub const UNVERIFIED_REASON: &str = "host key verification is not available yet";

/// Rejects every key (the real verifier is [`crate::verify::TrustVerifier`], T21).
#[derive(Debug, Clone, Copy, Default)]
pub struct UnverifiedHostKeys;

#[async_trait]
impl HostKeyVerifier for UnverifiedHostKeys {
    async fn verify(&self, _: &str, _: u16, _: &ServerKey, _: &VerifyCtx<'_>) -> HostKeyVerdict {
        HostKeyVerdict::Reject(UNVERIFIED_REASON.to_owned())
    }
}

/// **Tests only** (`test-util`): accepts every host key and logs a warning. It
/// disables protection against man-in-the-middle attacks; the binary never enables
/// `test-util`.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct InsecureAcceptAnyHostKey;

#[cfg(any(test, feature = "test-util"))]
#[async_trait]
impl HostKeyVerifier for InsecureAcceptAnyHostKey {
    async fn verify(&self, _: &str, _: u16, key: &ServerKey, _: &VerifyCtx<'_>) -> HostKeyVerdict {
        tracing::warn!(
            key_type = %key.key_type,
            "host key accepted WITHOUT verification (insecure test verifier)"
        );
        HostKeyVerdict::Accept
    }
}

/// Lock a mutex, ignoring poisoning (the data are plain values).
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// State shared between the handler (in russh's task) and the connection.
#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) info: Mutex<SshSessionInfo>,
    /// The key the server presented (T22 server info dialog).
    pub(crate) host_key: Mutex<Option<ServerKey>>,
    pub(crate) host_key_rejection: Mutex<Option<String>>,
    /// Why the transport ended (set once).
    pub(crate) end: watch::Sender<Option<EndCause>>,
    /// The transport's read side saw EOF or an error.
    pub(crate) closed: watch::Sender<bool>,
    /// The verifier is deciding (the handshake deadline is paused).
    pub(crate) verifying: watch::Sender<bool>,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            info: Mutex::default(),
            host_key: Mutex::default(),
            host_key_rejection: Mutex::default(),
            end: watch::Sender::new(None),
            closed: watch::Sender::new(false),
            verifying: watch::Sender::new(false),
        }
    }
}

impl Shared {
    /// Record the end cause (the first one wins) and mark the transport closed.
    pub(crate) fn set_end(&self, cause: EndCause) {
        self.end.send_if_modified(|end| {
            if end.is_some() {
                return false;
            }
            *end = Some(cause);
            true
        });
        self.closed.send_replace(true);
    }

    /// The end cause, waiting up to `wait` for the handler to record it (russh fails
    /// pending requests before it calls `disconnected`).
    pub(crate) async fn end_cause(&self, wait: std::time::Duration) -> Option<EndCause> {
        let mut rx = self.end.subscribe();
        let found = tokio::time::timeout(wait, rx.wait_for(Option::is_some)).await;
        match found {
            Ok(Ok(end)) => end.clone(),
            _ => self.end.borrow().clone(),
        }
    }
}

/// The russh handler.
pub(crate) struct ClientHandler {
    pub(crate) verifier: Arc<dyn HostKeyVerifier>,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) shared: Arc<Shared>,
    pub(crate) log: SessionLog,
    pub(crate) cancel: CancellationToken,
    pub(crate) banner_lines: usize,
    pub(crate) banner_chars: usize,
}

impl fmt::Debug for ClientHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientHandler").finish_non_exhaustive()
    }
}

/// The handler's error: russh's.
#[derive(Debug)]
pub(crate) struct HandlerError(pub(crate) russh::Error);

impl From<russh::Error> for HandlerError {
    fn from(err: russh::Error) -> Self {
        Self(err)
    }
}

/// Whether `cipher` authenticates itself (no separate MAC).
fn is_aead(cipher: &str) -> bool {
    cipher.contains("gcm") || cipher.starts_with("chacha20-poly1305")
}

impl ClientHandler {
    /// Log the banner, sanitized and capped at [`MAX_BANNER_LINES`] lines and
    /// [`MAX_BANNER_CHARS`] characters over the whole connection.
    fn banner(&mut self, banner: &str) {
        let text = sanitize_server_text(banner, MAX_BANNER_CHARS);
        for line in text.lines() {
            if self.banner_lines >= MAX_BANNER_LINES || self.banner_chars >= MAX_BANNER_CHARS {
                return;
            }
            let left = MAX_BANNER_CHARS - self.banner_chars;
            let line: String = if line.chars().count() > left {
                line.chars()
                    .take(left)
                    .chain(std::iter::once('…'))
                    .collect()
            } else {
                line.to_owned()
            };
            self.banner_lines += 1;
            self.banner_chars += line.chars().count();
            self.log.status(line);
        }
    }
}

impl client::Handler for ClientHandler {
    type Error = HandlerError;

    async fn auth_banner(&mut self, banner: &str, _: &mut Session) -> Result<(), Self::Error> {
        self.banner(banner);
        Ok(())
    }

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = ServerKey::from_public_key(&key.public_key());
        {
            let mut info = lock(&self.shared.info);
            info.host_key_fingerprint = key.fingerprint_sha256.clone();
        }
        *lock(&self.shared.host_key) = Some(key.clone());
        self.shared.verifying.send_replace(true);
        let verifier = Arc::clone(&self.verifier);
        let ctx = VerifyCtx {
            session: self.log.session,
            events: &self.log.events,
            cancel: &self.cancel,
        };
        let verdict = tokio::select! {
            v = verifier.verify(&self.host, self.port, &key, &ctx) => v,
            () = self.cancel.cancelled() => HostKeyVerdict::Reject("cancelled".to_owned()),
        };
        self.shared.verifying.send_replace(false);
        match verdict {
            HostKeyVerdict::Accept => Ok(true),
            HostKeyVerdict::Reject(why) => {
                debug!(session = self.log.session.get(), "host key rejected");
                *lock(&self.shared.host_key_rejection) = Some(why);
                Ok(false)
            }
        }
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut info = lock(&self.shared.info);
        info.server_version = sanitize_server_text(
            String::from_utf8_lossy(session.remote_sshid()).trim(),
            MAX_SERVER_LINE,
        );
        info.kex = names.kex.as_ref().to_owned();
        info.host_key_algorithm = names.key.to_string();
        info.cipher = names.cipher.as_ref().to_owned();
        info.mac = if is_aead(&info.cipher) {
            "(implicit)".to_owned()
        } else {
            names.client_mac.as_ref().to_owned()
        };
        // Only `none` is offered (russh is built without zlib).
        info.compression = "none".to_owned();
        debug!(
            kex = %info.kex,
            host_key = %info.host_key_algorithm,
            cipher = %info.cipher,
            mac = %info.mac,
            "negotiated algorithms"
        );
        Ok(())
    }

    async fn disconnected(
        &mut self,
        reason: client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        match reason {
            client::DisconnectReason::ReceivedDisconnect(info) => {
                let code = info.reason_code as u32;
                debug!(
                    session = self.log.session.get(),
                    code, "server disconnected"
                );
                self.shared.set_end(EndCause::Remote {
                    code,
                    message: sanitize_server_text(&info.message, MAX_SERVER_LINE),
                });
                Ok(())
            }
            client::DisconnectReason::Error(err) => {
                let cause = match &err.0 {
                    russh::Error::KeepaliveTimeout => EndCause::KeepaliveTimeout,
                    other => {
                        EndCause::Error(sanitize_server_text(&other.to_string(), MAX_SERVER_LINE))
                    }
                };
                self.shared.set_end(cause);
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use russh::keys::{PrivateKey, ssh_key::private::Ed25519Keypair};

    use super::*;

    #[test]
    fn server_key_description() {
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[1; 32]));
        let sk = ServerKey::from_public_key(key.public_key());
        assert_eq!(sk.key_type, "ssh-ed25519");
        assert_eq!(sk.bits, 256);
        assert!(sk.fingerprint_sha256.starts_with("SHA256:"));
        assert!(sk.fingerprint_md5.starts_with("MD5:"));
        assert_eq!(sk.fingerprint_md5.len(), 4 + 16 * 3 - 1);
        assert!(sk.blob_base64.starts_with("AAAAC3NzaC1lZDI1NTE5"));
    }

    #[test]
    fn aead_ciphers_have_implicit_macs() {
        assert!(is_aead("aes128-gcm@openssh.com"));
        assert!(is_aead("chacha20-poly1305@openssh.com"));
        assert!(!is_aead("aes128-ctr"));
    }

    #[tokio::test]
    async fn end_cause_first_one_wins() {
        let shared = Shared::default();
        shared.set_end(EndCause::KeepaliveTimeout);
        shared.set_end(EndCause::Error("later".into()));
        assert_eq!(
            shared.end_cause(std::time::Duration::ZERO).await,
            Some(EndCause::KeepaliveTimeout)
        );
        assert!(*shared.closed.borrow());
    }
}
