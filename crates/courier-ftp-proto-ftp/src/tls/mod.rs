//! FTPS (T12, D9): rustls with the ring provider, certificate trust and TLS
//! session resumption for data connections.
//!
//! # Certificate verification
//!
//! rustls verifies certificates synchronously inside the handshake, but our
//! decision may need the user (`Prompt(TrustCertificate)`). So the handshake
//! runs with a verifier that checks the server's handshake signature (proof
//! that it holds the certificate's key) and defers the trust decision; right
//! after the handshake, **before a single byte of application data is
//! sent**, [`TlsSession::handshake_control`]:
//!
//! 1. verifies the chain and host name with the OS trust store
//!    (`rustls-platform-verifier`);
//! 2. builds [`CertificateDetails`] (subject, issuer, validity, serial,
//!    SHA-256/SHA-1 fingerprints, SANs, key and signature algorithm, TLS
//!    version, cipher suite, full chain);
//! 3. applies [`decide_certificate`]: a valid chain is accepted silently; an
//!    invalid one (self-signed, expired, wrong host, unknown CA) is accepted
//!    when its fingerprint is in the [`CertTrustStore`] for `host:port` or was
//!    trusted once this run; otherwise the user is asked, with the old
//!    fingerprint when an "always trusted" certificate changed. *Always
//!    trust* stores it (replacing the old one), *Trust once* keeps it until
//!    exit, *Reject* fails with [`Error::Tls`].
//!
//! # Data connections
//!
//! Each control connection gets its own `rustls::ClientConfig` whose session
//! cache (TLS 1.2 session IDs/tickets, TLS 1.3 tickets) is shared by its
//! data connections, which use the control connection's server name: so
//! every data connection resumes the control session, as servers with
//! `require_ssl_reuse` (vsftpd) or FileZilla Server demand. A data
//! connection must present the certificate accepted for the control
//! connection (or one the OS trusts); there is no prompt for it.
//!
//! # Not supported
//!
//! `CCC` (clear command channel) is not supported: once the control
//! connection is encrypted it stays encrypted. Client certificates are not
//! supported either.

mod details;

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use courier_ftp_core::{
    Error, Result,
    backend::SecurityInfo,
    events::{EventSender, LogKind, PromptKind, PromptResponse, SessionId, TrustDecision},
    model::CertificateDetails,
    net::HostPort,
    trust::{
        CertDecision, CertTrustInputs, CertTrustSource, CertTrustStore, TrustedCertificate,
        cert_sha256, decide_certificate, normalize_host,
    },
};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

pub use self::details::{certificate_info, hostname_matches};
use crate::control::BoxedStream;

/// Fingerprints trusted once, per `(host, port)`; shared by clones.
type TrustMap = HashMap<(String, u16), Vec<[u8; 32]>>;
type SessionTrust = Arc<Mutex<TrustMap>>;

/// The certificate trust shared by all FTPS connections of the program: the
/// [`CertTrustStore`], the OS verifier and the "Trust once" answers.
pub struct TlsTrust {
    store: Arc<dyn CertTrustStore>,
    system: Option<Arc<dyn ServerCertVerifier>>,
    provider: Arc<CryptoProvider>,
    session: SessionTrust,
}

impl fmt::Debug for TlsTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsTrust")
            .field("store", &self.store)
            .field("system", &self.system.is_some())
            .finish_non_exhaustive()
    }
}

/// The crypto provider: ring (one provider for TLS and SSH, D9).
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

impl TlsTrust {
    /// Trust backed by `store` and the OS trust store. When the OS store
    /// can't be loaded every certificate needs the user's approval (logged).
    pub fn new(store: Arc<dyn CertTrustStore>) -> Self {
        let provider = provider();
        let system = match rustls_platform_verifier::Verifier::new(Arc::clone(&provider)) {
            Ok(v) => Some(Arc::new(v) as Arc<dyn ServerCertVerifier>),
            Err(err) => {
                tracing::warn!(%err, "the OS certificate store could not be loaded");
                None
            }
        };
        Self::with_system_verifier(store, system)
    }

    /// Trust with an explicit verifier in place of the OS one (tests: a
    /// verifier with a test root, or `None` to trust nothing by default).
    pub fn with_system_verifier(
        store: Arc<dyn CertTrustStore>,
        system: Option<Arc<dyn ServerCertVerifier>>,
    ) -> Self {
        Self {
            store,
            system,
            provider: provider(),
            session: SessionTrust::default(),
        }
    }

    /// The store "Always trust" goes to.
    pub fn store(&self) -> &Arc<dyn CertTrustStore> {
        &self.store
    }

    /// Forget every "Trust once" answer.
    pub fn clear_session_trust(&self) {
        self.session_map().clear();
    }

    fn session_map(&self) -> std::sync::MutexGuard<'_, TrustMap> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn trust_once(&self, host: &str, port: u16, sha: [u8; 32]) {
        let mut map = self.session_map();
        let list = map.entry((host.to_owned(), port)).or_default();
        if !list.contains(&sha) {
            list.push(sha);
        }
    }

    /// Verify `chain` for `name` with the OS store: `None` when valid, else
    /// why not.
    async fn system_problem(
        &self,
        chain: &[CertificateDer<'static>],
        name: &ServerName<'static>,
    ) -> Option<String> {
        let Some(system) = self.system.clone() else {
            return Some("no system certificate store is available".into());
        };
        let chain = chain.to_vec();
        let name = name.clone();
        let result = tokio::task::spawn_blocking(move || {
            let (leaf, rest) = chain.split_first()?;
            Some(system.verify_server_cert(leaf, rest, &name, &[], UnixTime::now()))
        })
        .await;
        match result {
            Ok(Some(Ok(_))) => None,
            Ok(Some(Err(err))) => Some(describe(&err)),
            Ok(None) => Some("the server sent no certificate".into()),
            Err(err) => Some(format!("verification failed: {err}")),
        }
    }
}

/// A readable reason for a verification error.
fn describe(err: &rustls::Error) -> String {
    match err {
        rustls::Error::InvalidCertificate(cert) => match cert {
            CertificateError::UnknownIssuer => {
                "the certificate is not signed by a trusted authority (self-signed or unknown CA)"
                    .into()
            }
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                "the certificate has expired".into()
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                "the certificate is not valid yet".into()
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                "the certificate is not valid for this host name".into()
            }
            CertificateError::Revoked => "the certificate has been revoked".into(),
            CertificateError::BadSignature => "the certificate has a bad signature".into(),
            other => format!("invalid certificate: {other:?}"),
        },
        other => other.to_string(),
    }
}

/// The handshake-time verifier: checks the handshake signatures and leaves
/// the trust decision to [`TlsSession`] (see the [module docs](self)).
#[derive(Debug)]
struct DeferredVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for DeferredVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // Decided after the handshake, before any data is sent.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The negotiated TLS parameters and the server's certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    /// `TLS 1.3` or `TLS 1.2`.
    pub version: String,
    /// The cipher suite, e.g. `TLS13_AES_256_GCM_SHA384`.
    pub cipher: String,
    /// The certificate chain and why it wasn't trusted by the OS (if so).
    pub details: CertificateDetails,
}

#[derive(Debug, Default)]
struct SessionState {
    leaf: Option<CertificateDer<'static>>,
    info: Option<TlsInfo>,
}

/// TLS for one control connection and its data connections.
pub struct TlsSession {
    trust: Arc<TlsTrust>,
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    host: HostPort,
    state: Mutex<SessionState>,
}

impl fmt::Debug for TlsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsSession")
            .field("host", &self.host)
            .field("info", &self.info())
            .finish_non_exhaustive()
    }
}

fn version_name(v: rustls::ProtocolVersion) -> String {
    match v {
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".into(),
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".into(),
        other => format!("{other:?}"),
    }
}

impl TlsSession {
    /// A session for the server `host` (its name is the TLS server name and,
    /// with the port, the trust store key).
    ///
    /// # Errors
    ///
    /// [`Error::Tls`] when `host` is not a valid DNS name or IP address.
    pub fn new(trust: Arc<TlsTrust>, host: &HostPort) -> Result<Self> {
        Self::with_versions(trust, host, rustls::DEFAULT_VERSIONS)
    }

    /// [`TlsSession::new`] limited to the given protocol versions (tests:
    /// TLS 1.2 only).
    ///
    /// # Errors
    ///
    /// As [`TlsSession::new`].
    pub fn with_versions(
        trust: Arc<TlsTrust>,
        host: &HostPort,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Result<Self> {
        let server_name = ServerName::try_from(host.host.clone()).map_err(|e| {
            Error::Tls(format!("{} is not a valid TLS server name: {e}", host.host))
        })?;
        let provider = Arc::clone(&trust.provider);
        let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(versions)
            .map_err(|e| Error::Tls(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DeferredVerifier { provider }))
            .with_no_client_auth();
        Ok(Self {
            trust,
            config: Arc::new(config),
            server_name,
            host: host.clone(),
            state: Mutex::new(SessionState::default()),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, SessionState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The negotiated parameters, once the control handshake is done.
    pub fn info(&self) -> Option<TlsInfo> {
        self.state().info.clone()
    }

    /// The status bar / server info view of this session.
    pub fn security_info(&self) -> SecurityInfo {
        match self.info() {
            Some(info) => SecurityInfo::Tls {
                version: info.version,
                cipher: info.cipher,
                certificate: Some(info.details),
            },
            None => SecurityInfo::Plain,
        }
    }

    async fn connect(
        &self,
        stream: BoxedStream,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<tokio_rustls::client::TlsStream<BoxedStream>> {
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.config));
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(Error::Cancelled),
            r = tokio::time::timeout(timeout, connector.connect(self.server_name.clone(), stream)) => match r {
                Err(_) => Err(Error::Timeout),
                Ok(Err(err)) => Err(Error::Tls(format!("TLS handshake failed: {err}"))),
                Ok(Ok(s)) => Ok(s),
            },
        }
    }

    /// The TLS handshake on the control connection and the trust decision
    /// (may ask the user). See the [module docs](self).
    ///
    /// # Errors
    ///
    /// [`Error::Tls`] for a failed handshake or a rejected certificate,
    /// [`Error::Timeout`], [`Error::Cancelled`].
    pub async fn handshake_control(
        &self,
        stream: BoxedStream,
        events: &EventSender,
        session: SessionId,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<BoxedStream> {
        let log = |kind, text: String| events.log(session, kind, text);
        log(LogKind::Status, "Initializing TLS...".into());
        let tls = self.connect(stream, timeout, cancel).await?;
        let conn = tls.get_ref().1;
        let chain: Vec<CertificateDer<'static>> = conn
            .peer_certificates()
            .map(<[_]>::to_vec)
            .unwrap_or_default();
        let Some(leaf) = chain.first().cloned() else {
            return Err(Error::Tls("the server sent no certificate".into()));
        };
        let version = conn
            .protocol_version()
            .map_or_else(|| "TLS".to_owned(), version_name);
        let cipher = conn
            .negotiated_cipher_suite()
            .map_or_else(String::new, |s| format!("{:?}", s.suite()));
        let problem = self.trust.system_problem(&chain, &self.server_name).await;
        let infos: Vec<_> = chain.iter().map(|c| certificate_info(c)).collect();
        let host_matches = infos
            .first()
            .is_some_and(|leaf| hostname_matches(leaf, &self.host.host));
        let details = CertificateDetails {
            host: self.host.to_string(),
            chain: infos,
            hostname_matches: host_matches,
            tls_version: version.clone(),
            cipher: cipher.clone(),
            problem: problem.clone().unwrap_or_default(),
        };
        let host = normalize_host(&self.host.host);
        let port = self.host.port;
        let sha = cert_sha256(&leaf);
        let stored = self.trust.store.certs_for(&host, port).await?;
        let session_trusted = self
            .trust
            .session_map()
            .get(&(host.clone(), port))
            .cloned()
            .unwrap_or_default();
        let can_remember = self.trust.store.can_remember().await;
        let decision = decide_certificate(&CertTrustInputs {
            system_ok: problem.is_none(),
            sha256: &sha,
            stored: &stored,
            session: &session_trusted,
            can_remember,
        });
        match decision {
            CertDecision::Accept(source) => {
                let why = match source {
                    CertTrustSource::System => "valid",
                    CertTrustSource::Store => "trusted by you",
                    CertTrustSource::Session => "trusted for this session",
                };
                log(
                    LogKind::Status,
                    format!("Server certificate of {} is {why}", self.host),
                );
            }
            CertDecision::Ask {
                known,
                can_remember,
            } => {
                match &known {
                    Some(old) => log(
                        LogKind::Error,
                        format!(
                            "WARNING: the certificate of {} has changed! Trusted: {}, offered: {}",
                            self.host,
                            old.fingerprint(),
                            details
                                .leaf()
                                .map(|l| l.fingerprint_sha256.clone())
                                .unwrap_or_default()
                        ),
                    ),
                    None => log(
                        LogKind::Status,
                        format!(
                            "The certificate of {} is not trusted: {}",
                            self.host, details.problem
                        ),
                    ),
                }
                let response = events
                    .ask(
                        Some(session),
                        PromptKind::TrustCertificate {
                            details: Box::new(details.clone()),
                            known_sha256: known.as_ref().map(TrustedCertificate::fingerprint),
                            can_remember,
                        },
                        cancel,
                    )
                    .await?;
                match response {
                    PromptResponse::Trust(TrustDecision::Always) if can_remember => {
                        let subject = details
                            .leaf()
                            .map(|l| l.subject.clone())
                            .unwrap_or_default();
                        let entry = TrustedCertificate::new(
                            &host,
                            port,
                            leaf.as_ref().to_vec(),
                            subject,
                            OffsetDateTime::now_utc(),
                        );
                        match self.trust.store.remember(entry).await {
                            Ok(()) => log(
                                LogKind::Status,
                                format!("Certificate of {} saved as trusted", self.host),
                            ),
                            Err(err) => {
                                log(
                                    LogKind::Error,
                                    format!(
                                        "Could not save the certificate of {} ({err}); trusted for this session only",
                                        self.host
                                    ),
                                );
                                self.trust.trust_once(&host, port, sha);
                            }
                        }
                    }
                    PromptResponse::Trust(TrustDecision::Once | TrustDecision::Always) => {
                        self.trust.trust_once(&host, port, sha);
                        log(
                            LogKind::Status,
                            format!("Certificate of {} trusted for this session", self.host),
                        );
                    }
                    _ => {
                        return Err(Error::Tls(format!(
                            "the certificate of {} was rejected",
                            self.host
                        )));
                    }
                }
            }
        }
        log(
            LogKind::Status,
            format!("TLS connection established ({version}, {cipher})"),
        );
        let mut state = self.state();
        state.leaf = Some(leaf);
        state.info = Some(TlsInfo {
            version,
            cipher,
            details,
        });
        drop(state);
        Ok(Box::new(tls))
    }

    /// TLS on a data connection: resumes the control session; the server
    /// must present the control connection's certificate (or one the OS
    /// trusts).
    ///
    /// # Errors
    ///
    /// [`Error::Tls`], [`Error::Timeout`], [`Error::Cancelled`].
    pub async fn handshake_data(
        &self,
        stream: BoxedStream,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<BoxedStream> {
        let tls = self.connect(stream, timeout, cancel).await?;
        let conn = tls.get_ref().1;
        let resumed = conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed);
        tracing::debug!(resumed, "TLS data connection");
        let chain: Vec<CertificateDer<'static>> = conn
            .peer_certificates()
            .map(<[_]>::to_vec)
            .unwrap_or_default();
        let accepted = self.state().leaf.clone();
        let same = chain.first().is_some_and(|l| Some(l) == accepted.as_ref());
        if !same && let Some(problem) = self.trust.system_problem(&chain, &self.server_name).await {
            return Err(Error::Tls(format!(
                "the data connection presented a different certificate ({problem})"
            )));
        }
        Ok(Box::new(tls))
    }
}

#[cfg(test)]
pub(crate) mod tests;
