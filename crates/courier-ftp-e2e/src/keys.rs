//! Committed, **TEST-ONLY** fixture credentials: users and passwords of the images,
//! the SSH client keys (`tests/fixtures/sshd/keys/`) and the TLS CA
//! (`tests/fixtures/tls/`). Never trust any of them outside these tests.

use std::path::PathBuf;

use crate::{E2eError, Result};

/// The regular user of the sshd and ftpd images.
pub const USER: &str = "test";
/// Its password.
pub const PASSWORD: &str = "test";
/// Passphrase of the encrypted fixture keys.
pub const PASSPHRASE: &str = "fixture";
/// The one-time code the `kbd` sshd profile accepts.
pub const OTP: &str = "424242";
/// A second user whose password is a canary value (T91 scans artifacts for it).
pub const CANARY_USER: &str = "canary";
/// The canary user's password.
pub const CANARY_PASSWORD: &str = "CANARY-PW-e2e-7f3a";
/// Proxy credentials (`http-auth`, `socks5-auth`, `FtpRelayProxy`).
pub const PROXY_USER: &str = "proxyuser";
/// The proxy password.
pub const PROXY_PASSWORD: &str = "proxypass";
/// The comment of every fixture key.
pub const KEY_COMMENT: &str = "courier-ftp-e2e-fixture-TEST-ONLY";

/// `<repo>/tests/fixtures`.
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
}

/// The SSH client keys in `tests/fixtures/sshd/keys/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureKey {
    /// `id_ed25519` (OpenSSH format, unencrypted).
    Ed25519,
    /// `id_ecdsa` (P-256).
    Ecdsa,
    /// `id_rsa` (4096 bits).
    Rsa,
    /// `id_ed25519_encrypted` (passphrase [`PASSPHRASE`]).
    Ed25519Encrypted,
    /// `id_ed25519.ppk` (PuTTY v2, unencrypted; the `id_ed25519` key).
    PpkV2,
    /// `id_ed25519_v3.ppk` (PuTTY v3, unencrypted; the `id_ed25519` key).
    PpkV3,
    /// `id_ed25519_v3_encrypted.ppk` (PuTTY v3, Argon2id, passphrase [`PASSPHRASE`];
    /// the `id_ed25519` key).
    PpkV3Encrypted,
}

impl FixtureKey {
    /// Every fixture key.
    pub const ALL: [Self; 7] = [
        Self::Ed25519,
        Self::Ecdsa,
        Self::Rsa,
        Self::Ed25519Encrypted,
        Self::PpkV2,
        Self::PpkV3,
        Self::PpkV3Encrypted,
    ];

    /// The private key file name.
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "id_ed25519",
            Self::Ecdsa => "id_ecdsa",
            Self::Rsa => "id_rsa",
            Self::Ed25519Encrypted => "id_ed25519_encrypted",
            Self::PpkV2 => "id_ed25519.ppk",
            Self::PpkV3 => "id_ed25519_v3.ppk",
            Self::PpkV3Encrypted => "id_ed25519_v3_encrypted.ppk",
        }
    }

    /// The private key file.
    pub fn path(self) -> PathBuf {
        fixtures_dir()
            .join("sshd")
            .join("keys")
            .join(self.file_name())
    }

    /// The OpenSSH public key line (`type base64 comment`).
    ///
    /// Panics when the fixture file is missing (a broken checkout).
    pub fn public(self) -> String {
        let base = match self {
            Self::PpkV2 | Self::PpkV3 | Self::PpkV3Encrypted => "id_ed25519",
            other => other.file_name(),
        };
        let path = fixtures_dir()
            .join("sshd")
            .join("keys")
            .join(format!("{base}.pub"));
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("fixture key {}: {e}", path.display()))
            .trim()
            .to_owned()
    }

    /// The passphrase, for the encrypted keys.
    pub fn passphrase(self) -> Option<&'static str> {
        match self {
            Self::Ed25519Encrypted | Self::PpkV3Encrypted => Some(PASSPHRASE),
            _ => None,
        }
    }
}

/// The TEST-ONLY certificate authority of the ftpd image (`tests/fixtures/tls/`).
#[derive(Debug, Clone, Copy)]
pub struct TlsFixture;

impl TlsFixture {
    /// `ca.pem`.
    ///
    /// # Errors
    /// The file is missing.
    pub fn ca_pem() -> Result<String> {
        Ok(std::fs::read_to_string(
            fixtures_dir().join("tls").join("ca.pem"),
        )?)
    }

    /// The CA certificate as DER.
    ///
    /// # Errors
    /// The file is missing or not PEM.
    pub fn ca_der() -> Result<Vec<u8>> {
        pem_to_der(&Self::ca_pem()?)
    }
}

/// The DER of the first `CERTIFICATE` block of `pem`.
///
/// # Errors
/// No certificate block, or bad base64.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .collect();
    if body.is_empty() {
        return Err(E2eError::new("no CERTIFICATE block in PEM"));
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| E2eError::new(format!("PEM base64: {e}")))
}
