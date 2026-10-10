//! Tests of the server information view and dialog (T57), with the
//! `SessionSecurityInfo` fixtures the app tests reuse.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::net::SocketAddr;

use courier_ftp_core::{
    backend::SessionSecurityInfo,
    events::{CertificateDetails, DataProtection, HostKeyInfo, TlsSessionInfo, TrustSource},
    model::{FtpEncryption, Protocol, ServerAddress},
};
use pretty_assertions::assert_eq;
use time::{OffsetDateTime, macros::datetime};

use super::*;

/// "Now" for the fixtures: 21 days before the certificate expires.
pub(crate) const NOW: OffsetDateTime = datetime!(2026-10-09 00:00 UTC);

/// FTP that fell back from "explicit TLS if available" to plain.
pub(crate) fn ftp_plain() -> (SessionSecurityInfo, ServerAddress) {
    let addr = ServerAddress::new(
        Protocol::Ftp,
        FtpEncryption::ExplicitIfAvailable,
        "ftp.example.com",
        None,
        None,
    )
    .unwrap();
    let info = SessionSecurityInfo {
        encrypted: false,
        summary: "plain".into(),
        peer_addr: Some(SocketAddr::from(([203, 0, 113, 5], 21))),
        server_software: Some("220 (vsFTPd 3.0.5)".into()),
        tls: None,
        host_key: None,
        details: vec![("System".into(), "UNIX Type: L8".into())],
    };
    (info, addr)
}

/// FTPS (explicit, required) with a Let's Encrypt leaf.
pub(crate) fn ftps() -> (SessionSecurityInfo, ServerAddress) {
    let addr = ServerAddress::new(
        Protocol::Ftp,
        FtpEncryption::RequireExplicit,
        "ftp.example.com",
        None,
        None,
    )
    .unwrap();
    let mut sha256 = [0u8; 32];
    for (i, b) in sha256.iter_mut().enumerate() {
        *b = u8::try_from((i * 7 + 0x4F) % 256).unwrap();
    }
    let leaf = CertificateDetails {
        subject: "CN=ftp.example.com".into(),
        subject_cn: Some("ftp.example.com".into()),
        issuer: "CN=R11, O=Let's Encrypt, C=US".into(),
        serial: "01:02".into(),
        not_before: datetime!(2026-08-01 00:00 UTC),
        not_after: datetime!(2026-10-30 00:00 UTC),
        sha256,
        sha1: [0; 20],
        sans: vec!["DNS:ftp.example.com".into()],
        public_key: "EC P-256".into(),
        signature_algorithm: "ecdsa-with-SHA384".into(),
        is_ca: false,
        self_signed: false,
        parse_error: None,
    };
    let info = SessionSecurityInfo {
        encrypted: true,
        summary: "TLS 1.3".into(),
        peer_addr: Some(SocketAddr::from(([203, 0, 113, 5], 21))),
        server_software: Some("220 (vsFTPd 3.0.5)".into()),
        tls: Some(TlsSessionInfo {
            protocol: "TLSv1.3".into(),
            cipher_suite: "TLS_AES_256_GCM_SHA384".into(),
            server_name: "ftp.example.com".into(),
            chain: vec![leaf],
            trusted_by: TrustSource::Platform,
            data_protection: DataProtection::Private,
        }),
        host_key: None,
        details: vec![
            ("System".into(), "UNIX Type: L8".into()),
            (
                "Features".into(),
                "MLSD MLST SIZE MDTM REST STREAM UTF8 EPSV".into(),
            ),
        ],
    };
    (info, addr)
}

/// SFTP with an Ed25519 host key.
pub(crate) fn sftp() -> (SessionSecurityInfo, ServerAddress) {
    let addr = ServerAddress::new(
        Protocol::Sftp,
        FtpEncryption::default(),
        "web01.example.com",
        None,
        Some("deploy".into()),
    )
    .unwrap();
    let info = SessionSecurityInfo {
        encrypted: true,
        summary: "SSH".into(),
        peer_addr: Some(SocketAddr::from(([198, 51, 100, 7], 22))),
        server_software: Some("SSH-2.0-OpenSSH_9.6".into()),
        tls: None,
        host_key: Some(HostKeyInfo {
            key_type: "ssh-ed25519".into(),
            bits: 256,
            fingerprint_sha256: "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM".into(),
        }),
        details: vec![
            ("Key exchange".into(), "curve25519-sha256".into()),
            ("Cipher".into(), "chacha20-poly1305@openssh.com".into()),
            ("MAC".into(), "implicit (AEAD cipher)".into()),
            ("Compression".into(), "none".into()),
        ],
    };
    (info, addr)
}

fn rows(v: &ServerInfoView) -> Vec<(&str, &str)> {
    v.rows
        .iter()
        .map(|(l, r)| (l.as_str(), r.as_str()))
        .collect()
}

#[test]
fn server_info_rows_ftp_ftps_sftp() {
    let (i, a) = ftp_plain();
    let v = ServerInfoView::from_session_at(&i, &a, "Tab 1", NOW);
    assert_eq!(v.title, "Server information · Tab 1");
    assert_eq!(
        rows(&v),
        vec![
            (
                "Protocol",
                "FTP (plain, not encrypted: the server offered no TLS)"
            ),
            ("Server", "ftp.example.com:21 (203.0.113.5)"),
            ("Software", "220 (vsFTPd 3.0.5)"),
            ("System", "UNIX Type: L8"),
        ]
    );
    assert!(!v.has_details);

    let (i, a) = ftps();
    let v = ServerInfoView::from_session_at(&i, &a, "Tab 1", NOW);
    assert_eq!(
        rows(&v),
        vec![
            ("Protocol", "FTP over TLS (explicit, required)"),
            ("Server", "ftp.example.com:21 (203.0.113.5)"),
            ("Software", "220 (vsFTPd 3.0.5)"),
            ("System", "UNIX Type: L8"),
            ("Features", "MLSD MLST SIZE MDTM REST STREAM UTF8 EPSV"),
            ("", ""),
            ("TLS version", "TLS 1.3"),
            ("Cipher suite", "TLS_AES_256_GCM_SHA384"),
            ("Data channel", "TLS (PROT P)"),
            ("", ""),
            ("Subject", "CN=ftp.example.com"),
            ("Issuer", "CN=R11, O=Let's Encrypt, C=US"),
            ("Valid", "2026-08-01 to 2026-10-30 (21 days left)"),
            ("Host name", "matches"),
            (
                "SHA-256",
                "4F:56:5D:64:6B:72:79:80:87:8E:95:9C:A3:AA:B1:B8:BF:C6:CD:D4:DB:E2:E9:F0:F7:FE:05:0C:13:1A:21:28"
            ),
            ("Trust", "system trust roots"),
        ]
    );
    assert!(v.has_details);

    let (i, a) = sftp();
    let v = ServerInfoView::from_session_at(&i, &a, "Tab 2 · web01", NOW);
    assert_eq!(v.title, "Server information · Tab 2 · web01");
    assert_eq!(
        rows(&v),
        vec![
            ("Protocol", "SFTP (SSH-2)"),
            ("Server", "web01.example.com:22 (198.51.100.7)"),
            ("Software", "SSH-2.0-OpenSSH_9.6"),
            ("", ""),
            ("Host key", "ssh-ed25519 256"),
            (
                "Fingerprint",
                "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM"
            ),
            ("Key exchange", "curve25519-sha256"),
            ("Cipher", "chacha20-poly1305@openssh.com"),
            ("MAC", "implicit (AEAD cipher)"),
            ("Compression", "none"),
        ]
    );
    assert!(!v.has_details);
}

#[test]
fn server_info_not_connected() {
    let v = ServerInfoView::not_connected();
    assert_eq!(v.title, "Server information");
    assert_eq!(rows(&v), vec![("", NOT_CONNECTED)]);
    assert_eq!(
        ServerInfoView::not_connected_in("Tab 1").title,
        "Server information · Tab 1"
    );
}

#[test]
fn server_info_values_are_sanitised_and_host_mismatch_shown() {
    let (mut i, a) = ftps();
    i.server_software = Some("220 evil\x1b[2J\r\n".into());
    if let Some(t) = i.tls.as_mut() {
        t.server_name = "other.example.org".into();
    }
    let v = ServerInfoView::from_session_at(&i, &a, "Tab 1", NOW);
    let r = rows(&v);
    assert!(r.contains(&("Software", "220 evil^[[2J^M^J")), "{r:?}");
    assert!(r.contains(&("Host name", "DOES NOT match")));
    assert!(name_matches("*.example.com", "ftp.example.com"));
    assert!(!name_matches("*.example.com", "example.com"));
}

#[test]
fn server_info_wraps_long_values_at_characters() {
    let (i, a) = ftps();
    let d = ServerInfoDialog::new(ServerInfoView::from_session_at(&i, &a, "Tab 1", NOW), true);
    let lines = d.lines(72);
    let sha: Vec<_> = lines
        .iter()
        .skip_while(|(l, _)| l != "SHA-256")
        .take(2)
        .collect();
    assert_eq!(sha[0].1.len(), 56);
    assert_eq!(sha[1].0, "");
    assert!(sha[1].1.starts_with(':'), "{sha:?}");
    assert_eq!(d.view().rows.len() + 1, lines.len());
}
