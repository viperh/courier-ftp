//! FTPS against the in-process server with `rcgen` certificates and a
//! `tokio-rustls` acceptor: the four encryption modes, the trust prompt,
//! "always trust", changed certificates, `PROT P` and TLS session reuse on
//! data connections (TLS 1.3 tickets and TLS 1.2 session ids).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::type_complexity)]

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{
    Error,
    events::{self, CoreEvent, EventReceiver, LogKind, PromptKind, PromptResponse, SessionId},
    model::{FtpEncryption, LogonType},
    net::HostPort,
    settings::{FtpProxy, FtpTransferMode, ProxyServer, Settings},
    trust::{CertTrustStore, MemoryCertTrustStore},
};
use pretty_assertions::assert_eq;
use rustls::{
    RootCertStore,
    client::WebPkiServerVerifier,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use secrecy::SecretString;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::{
    control::{ControlConnection, FtpContext, FtpOptions, connect},
    data::{DataOpen, DataOptions, DataSession, finish},
    test_server::{ServerConfig, ServerTls, TestServer},
};

/// A certificate (signed by `ca` when given, else self-signed) for
/// 127.0.0.1 and localhost.
pub(crate) struct TestCert {
    pub der: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

pub(crate) fn self_signed() -> TestCert {
    let key = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    TestCert {
        der: cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    }
}

/// A CA and a leaf for 127.0.0.1 signed by it.
fn ca_signed() -> (CertificateDer<'static>, TestCert) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    let leaf = params.signed_by(&key, &issuer).unwrap();
    (
        ca.der().clone(),
        TestCert {
            der: leaf.der().clone(),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        },
    )
}

pub(crate) fn acceptor(
    cert: &TestCert,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> tokio_rustls::TlsAcceptor {
    let config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der.clone()], cert.key.clone_key())
        .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

pub(crate) fn tls_server_config(cert: &TestCert, implicit: bool) -> ServerConfig {
    ServerConfig {
        tls: Some(ServerTls {
            acceptor: acceptor(cert, rustls::DEFAULT_VERSIONS),
            implicit,
            require_reuse: true,
            refuse_prot_p: false,
        }),
        ..ServerConfig::default()
    }
}

/// Trust with no system roots: every test certificate needs the user.
pub(crate) fn untrusting(store: Arc<dyn CertTrustStore>) -> Arc<TlsTrust> {
    Arc::new(TlsTrust::with_system_verifier(store, None))
}

/// Answers every certificate prompt with `answer` and records the prompts.
pub(crate) struct Prompter {
    pub prompts: Arc<std::sync::Mutex<Vec<(Option<String>, bool, String)>>>,
    pub logs: Arc<std::sync::Mutex<Vec<(LogKind, String)>>>,
    task: JoinHandle<()>,
}

impl Drop for Prompter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) fn prompter(mut rx: EventReceiver, answer: TrustDecision) -> Prompter {
    let prompts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let logs = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (p, l) = (Arc::clone(&prompts), Arc::clone(&logs));
    let task = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CoreEvent::Prompt(req) => {
                    if let PromptKind::TrustCertificate {
                        details,
                        known_sha256,
                        can_remember,
                    } = &req.kind
                    {
                        p.lock().unwrap().push((
                            known_sha256.clone(),
                            *can_remember,
                            details.problem.clone(),
                        ));
                        let _ = req.reply.send(PromptResponse::Trust(answer));
                    }
                }
                CoreEvent::Log(msg) => l.lock().unwrap().push((msg.kind, msg.text)),
                _ => {}
            }
        }
    });
    Prompter {
        prompts,
        logs,
        task,
    }
}

fn options(server: &TestServer, encryption: FtpEncryption, trust: &Arc<TlsTrust>) -> FtpOptions {
    let mut opts = FtpOptions::new(
        HostPort::from(server.addr),
        LogonType::Normal {
            user: "bob".into(),
            password: SecretString::from("secret".to_owned()),
        },
        &Settings::default(),
    );
    opts.timeout = Duration::from_secs(5);
    opts.encryption = encryption;
    opts.tls = Some(Arc::clone(trust));
    opts
}

async fn open(
    server: &TestServer,
    encryption: FtpEncryption,
    trust: &Arc<TlsTrust>,
    answer: TrustDecision,
) -> (Result<ControlConnection>, Prompter) {
    let (tx, rx) = events::channel(4);
    let p = prompter(rx, answer);
    let conn = connect(
        &options(server, encryption, trust),
        FtpContext::new(SessionId::next(), tx),
    )
    .await;
    (conn, p)
}

fn data_session(server: &TestServer) -> DataSession {
    let settings = Settings::default();
    DataSession::new(DataOptions::new(
        &settings,
        Some(FtpTransferMode::Passive),
        HostPort::from(server.addr),
        &courier_ftp_core::net::NetOpts::from_settings(&settings),
        Duration::from_secs(5),
    ))
}

async fn put_and_get(conn: &mut ControlConnection, data: &mut DataSession, name: &str) {
    let bytes: Vec<u8> = (0..50_000u32).map(|i| (i % 249) as u8).collect();
    let cancel = CancellationToken::new();
    let DataOpen::Stream(mut w) = data
        .open(conn, &format!("STOR {name}"), None, &cancel)
        .await
        .unwrap()
    else {
        panic!("STOR refused")
    };
    assert!(w.is_tls());
    let flags = w.flags();
    w.write_all(&bytes).await.unwrap();
    w.shutdown().await.unwrap();
    drop(w);
    finish(conn, &flags, true).await.unwrap();
    for _ in 0..3 {
        let DataOpen::Stream(mut r) = data
            .open(conn, &format!("RETR {name}"), None, &cancel)
            .await
            .unwrap()
        else {
            panic!("RETR refused")
        };
        let flags = r.flags();
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        drop(r);
        finish(conn, &flags, false).await.unwrap();
        assert_eq!(got, bytes);
    }
}

#[tokio::test]
async fn explicit_tls_with_a_self_signed_certificate_trusted_once() {
    let cert = self_signed();
    let server = TestServer::start(tls_server_config(&cert, false)).await;
    let trust = untrusting(Arc::new(MemoryCertTrustStore::locked()));
    let (conn, p) = open(
        &server,
        FtpEncryption::RequireExplicit,
        &trust,
        TrustDecision::Once,
    )
    .await;
    let mut conn = conn.unwrap();
    {
        let prompts = p.prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        let (known, can_remember, problem) = &prompts[0];
        assert_eq!(*known, None);
        assert!(!can_remember, "the vault is locked");
        assert!(!problem.is_empty());
    }
    let info = conn.tls_session().unwrap().info().unwrap();
    assert_eq!(info.version, "TLS 1.3");
    assert!(info.details.hostname_matches);
    assert_eq!(
        info.details.leaf().unwrap().fingerprint_sha256,
        courier_ftp_core::trust::sha256_fingerprint(&cert.der)
    );
    assert!(conn.data_tls().is_some(), "PROT P accepted");
    let cmds = server.commands();
    let first: Vec<&str> = cmds.iter().take(3).map(String::as_str).collect();
    assert_eq!(first, ["AUTH TLS", "USER bob", "PASS ****"]);
    assert!(cmds.contains(&"PBSZ 0".to_owned()) && cmds.contains(&"PROT P".to_owned()));

    // Data connections resume the control session (the server requires it).
    let mut data = data_session(&server);
    put_and_get(&mut conn, &mut data, "f.bin").await;
    let data_tls = server.data_tls();
    assert_eq!(data_tls.len(), 4);
    assert!(
        data_tls.iter().all(|(tls, resumed)| *tls && *resumed),
        "{data_tls:?}"
    );

    // Trusted once: a second connection in this run doesn't ask again.
    let (conn2, p2) = open(
        &server,
        FtpEncryption::RequireExplicit,
        &trust,
        TrustDecision::Reject,
    )
    .await;
    conn2.unwrap();
    assert!(p2.prompts.lock().unwrap().is_empty());
    conn.quit().await;
}

#[tokio::test]
async fn tls12_session_ids_are_resumed_too() {
    let cert = self_signed();
    let server = TestServer::start(ServerConfig {
        tls: Some(ServerTls {
            acceptor: acceptor(&cert, &[&rustls::version::TLS12]),
            implicit: false,
            require_reuse: true,
            refuse_prot_p: false,
        }),
        ..ServerConfig::default()
    })
    .await;
    let trust = untrusting(Arc::new(MemoryCertTrustStore::new()));
    let (conn, _p) = open(
        &server,
        FtpEncryption::RequireExplicit,
        &trust,
        TrustDecision::Once,
    )
    .await;
    let mut conn = conn.unwrap();
    assert_eq!(
        conn.tls_session().unwrap().info().unwrap().version,
        "TLS 1.2"
    );
    let mut data = data_session(&server);
    put_and_get(&mut conn, &mut data, "g.bin").await;
    assert!(
        server.data_tls().iter().all(|(t, r)| *t && *r),
        "{:?}",
        server.data_tls()
    );
}

#[tokio::test]
async fn always_trust_is_stored_and_a_changed_certificate_warns() {
    let cert = self_signed();
    let server = TestServer::start(tls_server_config(&cert, false)).await;
    let store = Arc::new(MemoryCertTrustStore::new());
    let trust = untrusting(store.clone());
    let (conn, p) = open(
        &server,
        FtpEncryption::RequireExplicit,
        &trust,
        TrustDecision::Always,
    )
    .await;
    conn.unwrap();
    assert_eq!(p.prompts.lock().unwrap().len(), 1);
    let stored = store.list().await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].der, cert.der.as_ref());
    assert_eq!(stored[0].host, "127.0.0.1");
    assert_eq!(stored[0].port, server.addr.port());

    // Next connect (fresh trust object, same store): silent.
    let trust = untrusting(store.clone());
    let (conn, p) = open(
        &server,
        FtpEncryption::RequireExplicit,
        &trust,
        TrustDecision::Reject,
    )
    .await;
    conn.unwrap();
    assert!(p.prompts.lock().unwrap().is_empty());

    // The server's certificate changes: warning prompt with the old one.
    let other = self_signed();
    let changed = TestServer::start(tls_server_config(&other, false)).await;
    store
        .remember(courier_ftp_core::trust::TrustedCertificate::new(
            "127.0.0.1",
            changed.addr.port(),
            cert.der.to_vec(),
            "old",
            time::OffsetDateTime::now_utc(),
        ))
        .await
        .unwrap();
    let (conn, p) = open(
        &changed,
        FtpEncryption::RequireExplicit,
        &trust,
        TrustDecision::Reject,
    )
    .await;
    let err = conn.unwrap_err();
    assert!(matches!(err, Error::Tls(_)), "{err}");
    let prompts = p.prompts.lock().unwrap();
    assert_eq!(
        prompts[0].0.as_deref(),
        Some(courier_ftp_core::trust::sha256_fingerprint(&cert.der).as_str())
    );
    assert!(
        p.logs
            .lock()
            .unwrap()
            .iter()
            .any(|(k, t)| *k == LogKind::Error && t.contains("has changed"))
    );
}

#[tokio::test]
async fn a_valid_chain_is_accepted_silently() {
    let (ca, leaf) = ca_signed();
    let server = TestServer::start(tls_server_config(&leaf, false)).await;
    let mut roots = RootCertStore::empty();
    roots.add(ca).unwrap();
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
        .build()
        .unwrap();
    let trust = Arc::new(TlsTrust::with_system_verifier(
        Arc::new(MemoryCertTrustStore::new()),
        Some(verifier),
    ));
    let (conn, p) = open(
        &server,
        FtpEncryption::RequireExplicit,
        &trust,
        TrustDecision::Reject,
    )
    .await;
    let conn = conn.unwrap();
    assert!(p.prompts.lock().unwrap().is_empty());
    let info = conn.tls_session().unwrap().info().unwrap();
    assert_eq!(info.details.problem, "");
    assert_eq!(info.details.chain.len(), 1);
}

#[tokio::test]
async fn implicit_tls() {
    let cert = self_signed();
    let server = TestServer::start(tls_server_config(&cert, true)).await;
    let trust = untrusting(Arc::new(MemoryCertTrustStore::new()));
    let (conn, _p) = open(
        &server,
        FtpEncryption::RequireImplicit,
        &trust,
        TrustDecision::Once,
    )
    .await;
    let mut conn = conn.unwrap();
    assert!(!server.commands().contains(&"AUTH TLS".to_owned()));
    assert!(conn.data_tls().is_some());
    let mut data = data_session(&server);
    put_and_get(&mut conn, &mut data, "i.bin").await;
}

#[tokio::test]
async fn explicit_if_available_falls_back_to_plain_with_a_warning() {
    let server = TestServer::start(ServerConfig::default()).await;
    let trust = untrusting(Arc::new(MemoryCertTrustStore::new()));
    let (conn, p) = open(
        &server,
        FtpEncryption::ExplicitIfAvailable,
        &trust,
        TrustDecision::Once,
    )
    .await;
    let conn = conn.unwrap();
    assert!(conn.tls_session().is_none());
    assert!(
        p.logs
            .lock()
            .unwrap()
            .iter()
            .any(|(k, t)| *k == LogKind::Error && t.contains("NOT encrypted")),
        "a warning is logged"
    );
    // Required: refused.
    let (conn, _p) = open(
        &server,
        FtpEncryption::RequireExplicit,
        &trust,
        TrustDecision::Once,
    )
    .await;
    assert!(matches!(conn.unwrap_err(), Error::Tls(_)));
    // Plain only: no AUTH at all.
    let before = server
        .commands()
        .iter()
        .filter(|c| c.starts_with("AUTH"))
        .count();
    let (conn, _p) = open(
        &server,
        FtpEncryption::PlainOnly,
        &trust,
        TrustDecision::Once,
    )
    .await;
    conn.unwrap();
    let after = server
        .commands()
        .iter()
        .filter(|c| c.starts_with("AUTH"))
        .count();
    assert_eq!(before, after);
}

#[tokio::test]
async fn refused_prot_p() {
    let cert = self_signed();
    let mut config = tls_server_config(&cert, false);
    if let Some(tls) = config.tls.as_mut() {
        tls.refuse_prot_p = true;
        tls.require_reuse = false;
    }
    let server = TestServer::start(config).await;
    let trust = untrusting(Arc::new(MemoryCertTrustStore::new()));
    let (conn, p) = open(
        &server,
        FtpEncryption::ExplicitIfAvailable,
        &trust,
        TrustDecision::Once,
    )
    .await;
    let conn = conn.unwrap();
    assert!(conn.tls_session().is_some() && conn.data_tls().is_none());
    assert!(server.commands().contains(&"PROT C".to_owned()));
    assert!(
        p.logs
            .lock()
            .unwrap()
            .iter()
            .any(|(k, t)| *k == LogKind::Error && t.contains("PROT P"))
    );
    let (conn, _p) = open(
        &server,
        FtpEncryption::RequireExplicit,
        &trust,
        TrustDecision::Once,
    )
    .await;
    assert!(matches!(conn.unwrap_err(), Error::Tls(_)));
}

#[tokio::test]
async fn rejecting_the_certificate_fails() {
    let cert = self_signed();
    let server = TestServer::start(tls_server_config(&cert, false)).await;
    let trust = untrusting(Arc::new(MemoryCertTrustStore::new()));
    let (conn, _p) = open(
        &server,
        FtpEncryption::RequireExplicit,
        &trust,
        TrustDecision::Reject,
    )
    .await;
    assert!(matches!(conn.unwrap_err(), Error::Tls(_)));
    // Nothing but AUTH TLS reached the server.
    assert_eq!(server.commands(), ["AUTH TLS"]);
}

#[tokio::test]
async fn auth_tls_comes_before_the_ftp_proxy_login() {
    let cert = self_signed();
    let mut config = tls_server_config(&cert, false);
    config.user = "bob@real.example.com".into();
    let proxy = TestServer::start(config).await;
    let mut settings = Settings::default();
    settings.proxy.ftp_proxy = FtpProxy::UserAtHost(ProxyServer {
        host: proxy.addr.ip().to_string(),
        port: proxy.addr.port(),
        user: None,
        password_ref: None,
    });
    let mut opts = FtpOptions::new(
        HostPort::new("real.example.com", 21),
        LogonType::Normal {
            user: "bob".into(),
            password: SecretString::from("secret".to_owned()),
        },
        &settings,
    );
    opts.timeout = Duration::from_secs(5);
    opts.encryption = FtpEncryption::RequireExplicit;
    let trust = untrusting(Arc::new(MemoryCertTrustStore::new()));
    opts.tls = Some(trust);
    let (tx, rx) = events::channel(4);
    let _p = prompter(rx, TrustDecision::Once);
    let conn = connect(&opts, FtpContext::new(SessionId::next(), tx))
        .await
        .unwrap();
    // TLS is with the proxy (its address is the TLS identity).
    assert_eq!(
        conn.tls_session().unwrap().info().unwrap().details.host,
        HostPort::from(proxy.addr).to_string()
    );
    let cmds = proxy.commands();
    assert_eq!(
        cmds.iter().take(3).map(String::as_str).collect::<Vec<_>>(),
        ["AUTH TLS", "USER bob@real.example.com", "PASS ****"]
    );
}
