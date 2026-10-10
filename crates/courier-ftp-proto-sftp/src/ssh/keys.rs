//! Private key files: format detection, passphrase handling and decoding.
//!
//! Formats (decoded by russh / `ssh-key`):
//!
//! - OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`), plain or encrypted;
//! - PEM RSA (PKCS#1, `BEGIN RSA PRIVATE KEY`), plain or encrypted with
//!   AES-128-CBC (what `ssh-keygen -m PEM` writes);
//! - PEM EC (SEC1, `BEGIN EC PRIVATE KEY`), plain;
//! - PKCS#8 (`BEGIN PRIVATE KEY` / `BEGIN ENCRYPTED PRIVATE KEY`);
//! - PuTTY `.ppk` versions 2 and 3, plain or encrypted (`ssh-key`'s `ppk`
//!   support; v3's Argon2 parameters are bounded here first, so a crafted file
//!   can't make the key derivation allocate gigabytes).
//!
//! Decoding runs on the blocking pool: bcrypt (OpenSSH) and Argon2 (PPK v3)
//! key derivation take noticeable CPU time.

use std::fmt;

use courier_ftp_core::model::LocalPath;
use russh::keys::{PrivateKey, decode_secret_key};
use secrecy::{ExposeSecret, SecretString};

/// Larger files are not private keys (an RSA 16384 key is about 13 KiB).
pub const MAX_KEY_FILE_BYTES: u64 = 256 * 1024;
/// PPK v3: Argon2 memory limit (KiB): 1 GiB.
pub const MAX_ARGON2_MEMORY_KIB: u64 = 1024 * 1024;
/// PPK v3: Argon2 passes limit.
pub const MAX_ARGON2_PASSES: u64 = 1000;
/// PPK v3: Argon2 lanes limit.
pub const MAX_ARGON2_PARALLELISM: u64 = 64;
/// PPK v3: memory (KiB) × passes limit (16 passes over 1 GiB).
pub const MAX_ARGON2_WORK: u64 = 16 * 1024 * 1024;

/// A key file's format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyFormat {
    /// `-----BEGIN OPENSSH PRIVATE KEY-----`.
    OpenSsh,
    /// PEM PKCS#1 RSA.
    PemRsa,
    /// PEM SEC1 EC.
    PemEc,
    /// PKCS#8, plain or encrypted.
    Pkcs8,
    /// PuTTY `.ppk` (version 2 or 3).
    Ppk(u8),
}

impl fmt::Display for KeyFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyFormat::OpenSsh => f.write_str("OpenSSH"),
            KeyFormat::PemRsa => f.write_str("PEM (PKCS#1 RSA)"),
            KeyFormat::PemEc => f.write_str("PEM (SEC1 EC)"),
            KeyFormat::Pkcs8 => f.write_str("PKCS#8"),
            KeyFormat::Ppk(v) => write!(f, "PuTTY PPK v{v}"),
        }
    }
}

/// Why a key could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// The file could not be read.
    #[error("cannot read key file {path}: {reason}")]
    Read {
        /// The file.
        path: String,
        /// The I/O error.
        reason: String,
    },
    /// The key is encrypted and no passphrase was given.
    #[error("the key is encrypted; a passphrase is needed")]
    NeedsPassphrase,
    /// The passphrase does not decrypt the key.
    #[error("wrong passphrase")]
    WrongPassphrase,
    /// A key type or format variant that is not supported.
    #[error("unsupported key: {0}")]
    Unsupported(String),
    /// Not a private key, or damaged.
    #[error("invalid key file: {0}")]
    Invalid(String),
}

/// A private key file read into memory (contents zeroized on drop), not yet
/// decrypted.
pub struct KeyFile {
    label: String,
    text: SecretString,
    format: KeyFormat,
    encrypted: bool,
}

impl fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyFile")
            .field("label", &self.label)
            .field("format", &self.format)
            .field("encrypted", &self.encrypted)
            .finish_non_exhaustive()
    }
}

impl KeyFile {
    /// Read and inspect the key file at `path`.
    ///
    /// # Errors
    /// [`KeyError::Read`] when it can't be read or is too large; otherwise as
    /// [`KeyFile::from_text`].
    pub async fn read(path: &LocalPath) -> Result<Self, KeyError> {
        let label = path.to_display();
        let read_err = |reason: String| KeyError::Read {
            path: label.clone(),
            reason,
        };
        let meta = tokio::fs::metadata(path.as_path())
            .await
            .map_err(|e| read_err(e.to_string()))?;
        if meta.len() > MAX_KEY_FILE_BYTES {
            return Err(read_err("file is too large for a private key".to_owned()));
        }
        let bytes = tokio::fs::read(path.as_path())
            .await
            .map_err(|e| read_err(e.to_string()))?;
        let text = String::from_utf8(bytes)
            .map_err(|_| KeyError::Invalid("not a text key file".to_owned()))?;
        Self::from_text(label, SecretString::from(text))
    }

    /// Inspect a key given as text (e.g. from the vault). `label` names it in
    /// messages and prompts.
    ///
    /// # Errors
    /// [`KeyError::Unsupported`] or [`KeyError::Invalid`] when the text is no
    /// private key in a supported format.
    pub fn from_text(label: impl Into<String>, text: SecretString) -> Result<Self, KeyError> {
        // Keys saved on Windows may have CRLF line endings; the parsers want LF.
        let text = if text.expose_secret().contains('\r') {
            SecretString::from(text.expose_secret().replace("\r\n", "\n"))
        } else {
            text
        };
        let (format, encrypted) = inspect(text.expose_secret())?;
        Ok(Self {
            label: label.into(),
            text,
            format,
            encrypted,
        })
    }

    /// The label (the file path).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The format.
    pub fn format(&self) -> KeyFormat {
        self.format
    }

    /// Whether a passphrase is needed.
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// Decode (and decrypt with `passphrase`) on the blocking pool.
    ///
    /// # Errors
    /// [`KeyError::NeedsPassphrase`], [`KeyError::WrongPassphrase`], or
    /// [`KeyError::Invalid`] / [`KeyError::Unsupported`].
    pub async fn decode(&self, passphrase: Option<&SecretString>) -> Result<PrivateKey, KeyError> {
        if self.encrypted && passphrase.is_none() {
            return Err(KeyError::NeedsPassphrase);
        }
        let text = self.text.clone();
        let pass = passphrase.cloned();
        let (format, encrypted) = (self.format, self.encrypted);
        tokio::task::spawn_blocking(move || decode(format, encrypted, &text, pass.as_ref()))
            .await
            .map_err(|e| KeyError::Invalid(format!("key decoding failed: {e}")))?
    }
}

/// The format of `text` and whether it is encrypted.
fn inspect(text: &str) -> Result<(KeyFormat, bool), KeyError> {
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if let Some(rest) = trimmed.strip_prefix("PuTTY-User-Key-File-") {
        let version = match rest.split_once(':').map(|(v, _)| v) {
            Some("2") => 2,
            Some("3") => 3,
            Some("1") => {
                return Err(KeyError::Unsupported(
                    "PuTTY key file version 1 (re-save it with a current PuTTYgen)".to_owned(),
                ));
            }
            _ => {
                return Err(KeyError::Invalid(
                    "unknown PuTTY key file version".to_owned(),
                ));
            }
        };
        let encrypted = ppk_header(trimmed, "Encryption").is_some_and(|v| v != "none");
        check_ppk_kdf(trimmed)?;
        return Ok((KeyFormat::Ppk(version), encrypted));
    }
    let begins = |label: &str| {
        trimmed
            .lines()
            .any(|l| l.trim() == format!("-----BEGIN {label}-----"))
    };
    let proc_encrypted = trimmed
        .lines()
        .any(|l| l.trim().starts_with("Proc-Type:") && l.contains("ENCRYPTED"));
    if begins("OPENSSH PRIVATE KEY") {
        let key = PrivateKey::from_openssh(trimmed)
            .map_err(|e| KeyError::Invalid(format!("OpenSSH key: {e}")))?;
        return Ok((KeyFormat::OpenSsh, key.is_encrypted()));
    }
    if begins("RSA PRIVATE KEY") {
        if proc_encrypted && !trimmed.contains("DEK-Info: AES-128-CBC,") {
            return Err(KeyError::Unsupported(
                "PEM key encrypted with a cipher other than AES-128-CBC (convert it with `ssh-keygen -p`)"
                    .to_owned(),
            ));
        }
        return Ok((KeyFormat::PemRsa, proc_encrypted));
    }
    if begins("EC PRIVATE KEY") {
        if proc_encrypted {
            return Err(KeyError::Unsupported(
                "encrypted PEM EC key (convert it with `ssh-keygen -p`)".to_owned(),
            ));
        }
        return Ok((KeyFormat::PemEc, false));
    }
    if begins("ENCRYPTED PRIVATE KEY") {
        return Ok((KeyFormat::Pkcs8, true));
    }
    if begins("PRIVATE KEY") {
        return Ok((KeyFormat::Pkcs8, false));
    }
    if begins("DSA PRIVATE KEY") {
        return Err(KeyError::Unsupported("DSA keys".to_owned()));
    }
    if trimmed.starts_with("ssh-") || trimmed.starts_with("ecdsa-") {
        return Err(KeyError::Invalid(
            "this is a public key; choose the private key file".to_owned(),
        ));
    }
    Err(KeyError::Invalid("not a private key".to_owned()))
}

/// The value of the PPK header `name`.
fn ppk_header<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k == name).then(|| v.trim())
    })
}

/// Bound the PPK v3 Argon2 parameters before `ssh-key` runs the derivation.
fn check_ppk_kdf(text: &str) -> Result<(), KeyError> {
    let num = |name: &str| -> Result<Option<u64>, KeyError> {
        ppk_header(text, name)
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| KeyError::Invalid(format!("PuTTY key: bad {name}")))
            })
            .transpose()
    };
    let memory = num("Argon2-Memory")?.unwrap_or(0);
    let passes = num("Argon2-Passes")?.unwrap_or(0);
    let lanes = num("Argon2-Parallelism")?.unwrap_or(0);
    if memory > MAX_ARGON2_MEMORY_KIB
        || passes > MAX_ARGON2_PASSES
        || lanes > MAX_ARGON2_PARALLELISM
        || memory.saturating_mul(passes) > MAX_ARGON2_WORK
    {
        return Err(KeyError::Invalid(
            "PuTTY key: Argon2 parameters are over the limits".to_owned(),
        ));
    }
    Ok(())
}

fn decode(
    format: KeyFormat,
    encrypted: bool,
    text: &SecretString,
    pass: Option<&SecretString>,
) -> Result<PrivateKey, KeyError> {
    let text = text.expose_secret().trim_start_matches('\u{feff}').trim();
    let pass = pass.map(ExposeSecret::expose_secret);
    if format == KeyFormat::OpenSsh {
        let key = PrivateKey::from_openssh(text)
            .map_err(|e| KeyError::Invalid(format!("OpenSSH key: {e}")))?;
        if !key.is_encrypted() {
            return Ok(key);
        }
        let pass = pass.ok_or(KeyError::NeedsPassphrase)?;
        return key.decrypt(pass).map_err(|e| match e {
            russh::keys::ssh_key::Error::Crypto => KeyError::WrongPassphrase,
            other => KeyError::Invalid(format!("OpenSSH key: {other}")),
        });
    }
    // An empty passphrase never decrypts anything; russh would treat `Some("")`
    // as a real one.
    let pass = if encrypted { pass } else { None };
    decode_secret_key(text, pass).map_err(|e| {
        if encrypted {
            // The formats verify the decryption (MAC, padding, DER), so a
            // failure with a passphrase almost always means a wrong one.
            tracing::debug!(error = %e, %format, "decrypting the key failed");
            KeyError::WrongPassphrase
        } else {
            match e {
                russh::keys::Error::UnsupportedKeyType { .. } => {
                    KeyError::Unsupported(format!("{format} key: {e}"))
                }
                other => KeyError::Invalid(format!("{format} key: {other}")),
            }
        }
    })
}

/// Fuzz body (T91 §7, cargo-fuzz target `key_parse`): format detection of a
/// hostile private key file (OpenSSH, PEM, PKCS#8, PuTTY `.ppk` v2/v3 including
/// the Argon2 bounds) and, for unencrypted keys, the decoding. Encrypted keys are
/// not decrypted: the KDF (bcrypt, Argon2) is bounded but deliberately slow.
/// Must never panic.
#[doc(hidden)]
pub fn fuzz_key_parse(data: &[u8]) {
    let text = SecretString::from(String::from_utf8_lossy(data).into_owned());
    if let Ok(file) = KeyFile::from_text("fuzz", text) {
        let _ = file.format().to_string();
        if !file.is_encrypted() {
            let _ = decode(file.format, false, &file.text, None);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::path::PathBuf;

    use pretty_assertions::assert_eq;
    use russh::keys::{Algorithm, HashAlg, PublicKey};

    use super::*;

    const PASS: &str = "fixture";

    fn dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/keys")
    }

    async fn load(name: &str) -> KeyFile {
        KeyFile::read(&LocalPath::new(dir().join(name)))
            .await
            .unwrap()
    }

    fn public(name: &str) -> PublicKey {
        let text = std::fs::read_to_string(dir().join(format!("{name}.pub"))).unwrap();
        PublicKey::from_openssh(text.trim()).unwrap()
    }

    fn secret(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    #[tokio::test]
    async fn every_openssh_and_pem_fixture_decodes() {
        for (name, format, encrypted) in [
            ("ed25519", KeyFormat::OpenSsh, false),
            ("ed25519_enc", KeyFormat::OpenSsh, true),
            ("rsa", KeyFormat::OpenSsh, false),
            ("rsa_enc", KeyFormat::OpenSsh, true),
            ("ecdsa", KeyFormat::OpenSsh, false),
            ("ecdsa_enc", KeyFormat::OpenSsh, true),
            ("rsa_pem", KeyFormat::PemRsa, false),
            ("rsa_pem_enc", KeyFormat::PemRsa, true),
            ("ecdsa_pem", KeyFormat::PemEc, false),
            ("rsa_pkcs8", KeyFormat::Pkcs8, false),
            ("ecdsa_pkcs8_enc", KeyFormat::Pkcs8, true),
        ] {
            let file = load(name).await;
            assert_eq!(file.format(), format, "{name}");
            assert_eq!(file.is_encrypted(), encrypted, "{name}");
            let pass = secret(PASS);
            let key = file
                .decode(encrypted.then_some(&pass))
                .await
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(
                key.public_key().key_data(),
                public(name).key_data(),
                "{name}"
            );
            if encrypted {
                assert_eq!(
                    file.decode(None).await.unwrap_err(),
                    KeyError::NeedsPassphrase,
                    "{name}"
                );
                assert_eq!(
                    file.decode(Some(&secret("wrong"))).await.unwrap_err(),
                    KeyError::WrongPassphrase,
                    "{name}"
                );
            }
        }
    }

    #[tokio::test]
    async fn every_ppk_fixture_decodes() {
        let fps = std::fs::read_to_string(dir().join("ppk/fingerprints.txt")).unwrap();
        for version in [2, 3] {
            for alg in ["ed25519", "ecdsa256", "rsa2048"] {
                let fp = fps
                    .lines()
                    .find_map(|l| l.strip_prefix(&format!("{alg} ")))
                    .unwrap()
                    .trim();
                for enc in [false, true] {
                    let name = format!("ppk/v{version}_{alg}{}.ppk", if enc { "_enc" } else { "" });
                    let file = load(&name).await;
                    assert_eq!(file.format(), KeyFormat::Ppk(version), "{name}");
                    assert_eq!(file.is_encrypted(), enc, "{name}");
                    let pass = secret(PASS);
                    let key = file
                        .decode(enc.then_some(&pass))
                        .await
                        .unwrap_or_else(|e| panic!("{name}: {e}"));
                    assert_eq!(
                        key.public_key().fingerprint(HashAlg::Sha256).to_string(),
                        fp,
                        "{name}"
                    );
                    if enc {
                        assert_eq!(
                            file.decode(Some(&secret("nope"))).await.unwrap_err(),
                            KeyError::WrongPassphrase,
                            "{name}"
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn rsa_keys_are_recognised_as_rsa() {
        let key = load("rsa").await.decode(None).await.unwrap();
        assert!(matches!(key.algorithm(), Algorithm::Rsa { .. }));
    }

    #[test]
    fn rejects_what_is_no_private_key() {
        let text = |s: &str| KeyFile::from_text("t", secret(s)).unwrap_err();
        assert!(matches!(text("hello"), KeyError::Invalid(_)));
        assert!(matches!(
            text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJQYW plain@test"),
            KeyError::Invalid(m) if m.contains("public key")
        ));
        assert!(matches!(
            text("-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----"),
            KeyError::Unsupported(_)
        ));
        assert!(matches!(
            text("PuTTY-User-Key-File-1: ssh-rsa\n"),
            KeyError::Unsupported(_)
        ));
    }

    #[tokio::test]
    async fn crlf_line_endings_are_accepted() {
        for name in ["ed25519", "ppk/v3_ed25519.ppk", "rsa_pem"] {
            let text = std::fs::read_to_string(dir().join(name)).unwrap();
            let file = KeyFile::from_text(name, secret(&text.replace('\n', "\r\n"))).unwrap();
            file.decode(None)
                .await
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[test]
    fn hostile_argon2_parameters_are_refused() {
        let good = std::fs::read_to_string(dir().join("ppk/v3_ed25519_enc.ppk")).unwrap();
        let bad = good.replace("Argon2-Memory: 8192", "Argon2-Memory: 4194304");
        assert!(matches!(
            KeyFile::from_text("t", secret(&bad)).unwrap_err(),
            KeyError::Invalid(m) if m.contains("Argon2")
        ));
    }

    #[tokio::test]
    async fn missing_and_oversized_files_are_read_errors() {
        let err = KeyFile::read(&LocalPath::new("/nonexistent/courier/id_ed25519"))
            .await
            .unwrap_err();
        assert!(matches!(err, KeyError::Read { .. }));
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big");
        std::fs::write(&big, vec![b'a'; (MAX_KEY_FILE_BYTES + 1) as usize]).unwrap();
        assert!(matches!(
            KeyFile::read(&LocalPath::new(big)).await.unwrap_err(),
            KeyError::Read { .. }
        ));
    }

    #[test]
    fn debug_never_shows_the_key() {
        let text = std::fs::read_to_string(dir().join("ed25519")).unwrap();
        let file = KeyFile::from_text("k", secret(&text)).unwrap();
        let shown = format!("{file:?}");
        assert!(!shown.contains("OPENSSH"), "{shown}");
    }

    /// Every fixture key file (OpenSSH, PEM, PKCS#8, PPK v2/v3), the seed
    /// corpus of the `key_parse` fuzz target.
    fn fixtures() -> Vec<String> {
        let mut out = Vec::new();
        for d in [dir(), dir().join("ppk")] {
            for entry in std::fs::read_dir(d).unwrap() {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                let is_key = !name.ends_with(".pub")
                    && !name.ends_with(".py")
                    && !name.ends_with(".txt")
                    && path.is_file();
                if is_key {
                    out.push(std::fs::read_to_string(&path).unwrap());
                }
            }
        }
        out
    }

    #[test]
    fn fuzz_key_parse_seeds() {
        let all = fixtures();
        assert!(all.len() > 20, "fixtures found: {}", all.len());
        for text in &all {
            fuzz_key_parse(text.as_bytes());
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 128,
            ..proptest::prelude::ProptestConfig::default()
        })]

        // The `key_parse` fuzz body (T91 §7): arbitrary bytes, and fixture
        // keys with one byte changed or the tail cut off.
        #[test]
        fn fuzz_key_parse_never_panics(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512),
        ) {
            fuzz_key_parse(&data);
        }

        #[test]
        fn fuzz_key_parse_mutated_fixture_never_panics(
            which in proptest::prelude::any::<proptest::sample::Index>(),
            at in proptest::prelude::any::<proptest::sample::Index>(),
            byte in proptest::prelude::any::<u8>(),
            cut in proptest::prelude::any::<proptest::sample::Index>(),
        ) {
            let all = fixtures();
            let mut bytes = all[which.index(all.len())].clone().into_bytes();
            let i = at.index(bytes.len());
            bytes[i] = byte;
            fuzz_key_parse(&bytes);
            fuzz_key_parse(&bytes[..cut.index(bytes.len())]);
        }
    }
}
