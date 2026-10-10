//! Private-key loading for the `KeyFile` logon type (T20), copied from sverb
//! `keychain/formats` (D13):
//!
//! - [`openssh`]: `-----BEGIN OPENSSH PRIVATE KEY-----` (plain or bcrypt-encrypted);
//! - [`pem`]: PKCS#1 RSA / SEC1 EC, plain or legacy-encrypted (`Proc-Type: 4,ENCRYPTED`,
//!   AES-128/192/256-CBC);
//! - [`pkcs8`]: `BEGIN PRIVATE KEY` / `BEGIN ENCRYPTED PRIVATE KEY` (PBES2);
//! - [`ppk`]: PuTTY `.ppk` v2 and v3 (MAC checked before use, Argon2 cost bounded).
//!
//! [`decode`] returns an `ssh_key::PrivateKey` (zeroized on drop). Key types: Ed25519,
//! ECDSA P-256/P-384/P-521 and RSA ≥ 2048 bits; DSA, PPK v1 and shorter RSA keys are
//! [`KeyError::Unsupported`]. Key files are read with a [`MAX_KEY_FILE_BYTES`] cap
//! ([`read_key_file`]). Nothing here logs key material.

pub mod openssh;
pub mod pem;
pub mod pkcs8;
pub mod ppk;

use std::{io::Read as _, path::Path};

use base64::Engine as _;
use ssh_key::{Algorithm, PrivateKey, PublicKey, public::KeyData};
use zeroize::Zeroizing;

/// Larger files are not private keys (an RSA 16384 key is about 13 KiB).
pub const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// Smallest RSA modulus accepted (bits).
pub const MIN_RSA_BITS: u32 = 2048;

/// Why a key could not be loaded. The messages never contain key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// The key is encrypted and no passphrase was given.
    #[error("the key is encrypted; a passphrase is needed")]
    NeedsPassphrase,
    /// The passphrase does not decrypt the key.
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// Not a private key format courier-ftp can read.
    #[error("Not a private key format courier-ftp can read (OpenSSH, PEM, PKCS#8, PuTTY)")]
    Format,
    /// A public key (`.pub`) was chosen instead of the private key.
    #[error("This is a public key; choose the private key file (without .pub)")]
    PublicKey,
    /// A recognised but unsupported key type, cipher or file version.
    #[error("unsupported key: {0}")]
    Unsupported(String),
    /// A recognised format whose content is invalid (damaged file, bounds exceeded).
    #[error("invalid key: {0}")]
    Invalid(String),
    /// The file is larger than [`MAX_KEY_FILE_BYTES`].
    #[error("not a private key (larger than 64 KiB)")]
    TooLarge,
    /// The file could not be read.
    #[error("{0}")]
    Read(String),
}

/// The format of a key text, by its armor or header line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// OpenSSH private key.
    OpenSsh,
    /// PEM PKCS#1 RSA private key.
    PemPkcs1Rsa,
    /// PEM SEC1 EC private key.
    PemSec1Ec,
    /// PKCS#8 private key (plain).
    Pkcs8,
    /// PKCS#8 encrypted private key (PBES2).
    Pkcs8Encrypted,
    /// PuTTY `.ppk` version 2.
    PpkV2,
    /// PuTTY `.ppk` version 3.
    PpkV3,
    /// An OpenSSH public key line (`.pub`) or a PuTTY / RFC 4716 public key file.
    PublicOnly,
    /// Not recognized.
    Unknown,
}

impl KeyFormat {
    /// A short name for messages.
    pub fn name(self) -> &'static str {
        match self {
            Self::OpenSsh => "OpenSSH",
            Self::PemPkcs1Rsa => "PEM PKCS#1",
            Self::PemSec1Ec => "PEM SEC1",
            Self::Pkcs8 => "PKCS#8",
            Self::Pkcs8Encrypted => "PKCS#8 (encrypted)",
            Self::PpkV2 => "PuTTY v2",
            Self::PpkV3 => "PuTTY v3",
            Self::PublicOnly => "public key",
            Self::Unknown => "unknown",
        }
    }
}

/// The format of `text` (first armor / header line).
pub fn detect(text: &str) -> KeyFormat {
    let t = text.trim_start_matches('\u{feff}').trim_start();
    if let Some(rest) = t.strip_prefix("PuTTY-User-Key-File-") {
        return match rest.split_once(':').map(|(v, _)| v) {
            Some("2") => KeyFormat::PpkV2,
            Some("3") => KeyFormat::PpkV3,
            _ => KeyFormat::Unknown,
        };
    }
    for line in t.lines().map(str::trim) {
        match line {
            "-----BEGIN OPENSSH PRIVATE KEY-----" => return KeyFormat::OpenSsh,
            "-----BEGIN RSA PRIVATE KEY-----" => return KeyFormat::PemPkcs1Rsa,
            "-----BEGIN EC PRIVATE KEY-----" => return KeyFormat::PemSec1Ec,
            "-----BEGIN PRIVATE KEY-----" => return KeyFormat::Pkcs8,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----" => return KeyFormat::Pkcs8Encrypted,
            "---- BEGIN SSH2 PUBLIC KEY ----" => return KeyFormat::PublicOnly,
            l if l.starts_with("-----BEGIN ") => return KeyFormat::Unknown,
            _ => {}
        }
    }
    let first = t
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    if PublicKey::from_openssh(first).is_ok() {
        return KeyFormat::PublicOnly;
    }
    KeyFormat::Unknown
}

/// Whether `text` is an encrypted private key (a passphrase is needed to use it).
pub fn is_encrypted(text: &str) -> bool {
    match detect(text) {
        KeyFormat::OpenSsh => openssh::is_encrypted(text),
        f @ (KeyFormat::PemPkcs1Rsa | KeyFormat::PemSec1Ec) => pem::is_encrypted(text, f),
        KeyFormat::Pkcs8Encrypted => true,
        KeyFormat::PpkV2 | KeyFormat::PpkV3 => ppk::parse(text).is_ok_and(|f| f.encrypted),
        KeyFormat::Pkcs8 | KeyFormat::PublicOnly | KeyFormat::Unknown => false,
    }
}

/// Parse `text` (and decrypt it with `passphrase` when encrypted) into a private key.
///
/// # Errors
/// [`KeyError::NeedsPassphrase`] (encrypted, no passphrase), [`KeyError::WrongPassphrase`],
/// [`KeyError::Format`] (unknown format), [`KeyError::PublicKey`] (a `.pub` file),
/// [`KeyError::Unsupported`] (DSA, RSA < 2048, PPK v1, an unknown cipher),
/// [`KeyError::Invalid`] (damaged, over a PPK bound), [`KeyError::TooLarge`].
pub fn decode(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeyError> {
    if text.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(KeyError::TooLarge);
    }
    let key = match detect(text) {
        KeyFormat::OpenSsh => openssh::decode(text, passphrase)?,
        f @ (KeyFormat::PemPkcs1Rsa | KeyFormat::PemSec1Ec) => pem::decode(text, f, passphrase)?,
        KeyFormat::Pkcs8 => pkcs8::decode(text)?,
        KeyFormat::Pkcs8Encrypted => pkcs8::decode_encrypted(text, passphrase)?,
        KeyFormat::PpkV2 | KeyFormat::PpkV3 => ppk::decode(text, passphrase)?,
        KeyFormat::PublicOnly => return Err(KeyError::PublicKey),
        KeyFormat::Unknown => {
            if text.contains("-----BEGIN DSA PRIVATE KEY-----") {
                return Err(KeyError::Unsupported("DSA keys".to_owned()));
            }
            if text.trim_start().starts_with("PuTTY-User-Key-File-1") {
                return Err(KeyError::Unsupported(
                    "PuTTY key file version 1 (re-save it with a current PuTTYgen)".to_owned(),
                ));
            }
            return Err(KeyError::Format);
        }
    };
    check_supported(key.public_key())?;
    Ok(key)
}

/// Refuse DSA and RSA keys shorter than [`MIN_RSA_BITS`].
pub(crate) fn check_supported(key: &PublicKey) -> Result<(), KeyError> {
    match key.algorithm() {
        Algorithm::Dsa => Err(KeyError::Unsupported("DSA keys (ssh-dss)".to_owned())),
        Algorithm::Rsa { .. } => {
            let bits = key_bits(key);
            if bits < MIN_RSA_BITS {
                Err(KeyError::Unsupported(format!(
                    "RSA keys shorter than {MIN_RSA_BITS} bits ({bits} bits)"
                )))
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

/// The key size in bits: the RSA modulus size, the curve size for ECDSA, 256 for Ed25519.
pub fn key_bits(key: &PublicKey) -> u32 {
    match key.key_data() {
        KeyData::Rsa(rsa) => rsa.n().as_positive_bytes().map_or(0, |b| {
            let lead = b.first().copied().unwrap_or(0);
            let len = u32::try_from(b.len()).unwrap_or(u32::MAX);
            len.saturating_mul(8).saturating_sub(lead.leading_zeros())
        }),
        KeyData::Ecdsa(ec) => match ec.curve() {
            ssh_key::EcdsaCurve::NistP256 => 256,
            ssh_key::EcdsaCurve::NistP384 => 384,
            ssh_key::EcdsaCurve::NistP521 => 521,
        },
        KeyData::Ed25519(_) => 256,
        _ => 0,
    }
}

/// Read a key file with the [`MAX_KEY_FILE_BYTES`] cap (the buffer is zeroized on drop).
///
/// # Errors
/// [`KeyError::TooLarge`]; [`KeyError::Read`] (missing, unreadable, not UTF-8).
pub fn read_key_file(path: &Path) -> Result<Zeroizing<String>, KeyError> {
    let file = std::fs::File::open(path).map_err(|e| KeyError::Read(e.to_string()))?;
    let mut buf = Zeroizing::new(Vec::new());
    file.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| KeyError::Read(e.to_string()))?;
    if buf.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(KeyError::TooLarge);
    }
    let text = std::str::from_utf8(&buf).map_err(|_| KeyError::Format)?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// A decoded PEM block: its RFC 1421 headers and DER body.
pub(crate) struct PemBlock {
    /// `Name: value` headers (legacy encryption).
    pub(crate) headers: Vec<(String, String)>,
    /// The DER bytes (zeroized on drop).
    pub(crate) der: Zeroizing<Vec<u8>>,
}

impl PemBlock {
    /// A header's value.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Decode the first PEM block labelled `label` (`RSA PRIVATE KEY`, …).
pub(crate) fn pem_block(text: &str, label: &str) -> Result<PemBlock, KeyError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut lines = text.lines().map(str::trim);
    lines
        .by_ref()
        .find(|l| *l == begin)
        .ok_or(KeyError::Format)?;
    let mut headers = Vec::new();
    let mut body = Zeroizing::new(String::new());
    let mut ended = false;
    let mut in_headers = true;
    for line in lines {
        if line == end {
            ended = true;
            break;
        }
        if in_headers {
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_owned(), v.trim().to_owned()));
                continue;
            }
            in_headers = false;
            if line.is_empty() {
                continue;
            }
        }
        body.push_str(line);
    }
    if !ended {
        return Err(KeyError::Format);
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|_| KeyError::Format)?;
    Ok(PemBlock {
        headers,
        der: Zeroizing::new(der),
    })
}

#[cfg(test)]
mod tests;
