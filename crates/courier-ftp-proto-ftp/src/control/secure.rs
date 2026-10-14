//! FTPS on the control connection (T12): implicit TLS, `AUTH TLS`, `PBSZ 0`
//! and `PROT P`, per [`FtpEncryption`].

use std::sync::Arc;

use courier_ftp_core::{Error, Result, events::LogKind, model::FtpEncryption};

use super::ControlConnection;
use crate::tls::TlsSession;

impl ControlConnection {
    /// The TLS session when the control connection is encrypted.
    pub fn tls_session(&self) -> Option<&Arc<TlsSession>> {
        self.tls.as_ref()
    }

    /// The TLS session data connections must use (`PROT P` accepted), or
    /// `None` for clear data connections.
    pub fn data_tls(&self) -> Option<Arc<TlsSession>> {
        if self.prot_private {
            self.tls.clone()
        } else {
            None
        }
    }

    /// Run the TLS handshake on the current stream (implicit FTPS before the
    /// greeting, or after `234`).
    ///
    /// # Errors
    ///
    /// The errors of [`TlsSession::handshake_control`]; the connection is
    /// closed on failure.
    pub async fn start_tls(&mut self, tls: Arc<TlsSession>) -> Result<()> {
        let events = self.ctx.events.clone();
        let session = self.ctx.session;
        let timeout = self.timeout;
        let cancel = self.ctx.cancel.clone();
        let handshake = Arc::clone(&tls);
        self.upgrade_stream(|stream| async move {
            handshake
                .handshake_control(stream, &events, session, timeout, &cancel)
                .await
        })
        .await?;
        self.tls = Some(tls);
        Ok(())
    }

    /// Explicit FTPS: `AUTH TLS` and the handshake. In
    /// [`FtpEncryption::ExplicitIfAvailable`] a refusal continues in plain
    /// text with a warning; in [`FtpEncryption::RequireExplicit`] it fails.
    ///
    /// # Errors
    ///
    /// [`Error::Tls`] when TLS is required and refused, or the handshake
    /// fails; connection-level errors.
    pub async fn auth_tls(
        &mut self,
        encryption: FtpEncryption,
        tls: Arc<TlsSession>,
    ) -> Result<()> {
        let reply = self.send("AUTH TLS").await?;
        if reply.code == 234 {
            return self.start_tls(tls).await;
        }
        if encryption == FtpEncryption::RequireExplicit {
            let err = Error::Tls(format!(
                "the server does not support FTP over TLS ({})",
                reply.text()
            ));
            self.log(LogKind::Error, err.to_string());
            self.close();
            return Err(err);
        }
        self.log(
            LogKind::Error,
            "Warning: the server does not support FTP over TLS; the connection is NOT encrypted (insecure)",
        );
        Ok(())
    }

    /// After login on a TLS connection: `PBSZ 0`, `PROT P`. When `PROT P` is
    /// refused, [`FtpEncryption::ExplicitIfAvailable`] falls back to `PROT C`
    /// with a warning; the other modes fail.
    ///
    /// # Errors
    ///
    /// [`Error::Tls`] when `PROT P` is required and refused; connection-level
    /// errors.
    pub async fn protect_data(&mut self, encryption: FtpEncryption) -> Result<()> {
        if self.tls.is_none() {
            return Ok(());
        }
        let pbsz = self.send("PBSZ 0").await?;
        if !pbsz.is_ok() {
            tracing::debug!(code = pbsz.code, "PBSZ refused");
        }
        let prot = self.send("PROT P").await?;
        if prot.is_ok() {
            self.prot_private = true;
            return Ok(());
        }
        if encryption != FtpEncryption::ExplicitIfAvailable {
            let err = Error::Tls(format!(
                "the server refused to encrypt data connections (PROT P: {})",
                prot.text()
            ));
            self.log(LogKind::Error, err.to_string());
            return Err(err);
        }
        self.log(
            LogKind::Error,
            "Warning: the server refused PROT P; file transfers and listings are NOT encrypted",
        );
        let clear = self.send("PROT C").await?;
        if !clear.is_ok() {
            tracing::debug!(code = clear.code, "PROT C refused");
        }
        self.prot_private = false;
        Ok(())
    }
}
