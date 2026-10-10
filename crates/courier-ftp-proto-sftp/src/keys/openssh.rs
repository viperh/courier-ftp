//! OpenSSH private keys (`-----BEGIN OPENSSH PRIVATE KEY-----`), plain or encrypted
//! (bcrypt-pbkdf + aes256-ctr / aes256-gcm). The public key is readable without the
//! passphrase. Copied from sverb `keychain/formats/openssh.rs` (D13).

use ssh_key::PrivateKey;

use super::{KeyError, check_supported};

/// Parse without decrypting.
///
/// # Errors
/// [`KeyError::Format`]; [`KeyError::Unsupported`] for DSA keys.
pub fn parse(text: &str) -> Result<PrivateKey, KeyError> {
    let key = PrivateKey::from_openssh(text.trim()).map_err(|_| {
        if declares_dsa(text) {
            KeyError::Unsupported("DSA keys (ssh-dss)".to_owned())
        } else {
            KeyError::Format
        }
    })?;
    check_supported(key.public_key())?;
    Ok(key)
}

/// Whether the key is passphrase-encrypted.
pub fn is_encrypted(text: &str) -> bool {
    parse(text).is_ok_and(|k| k.is_encrypted())
}

/// Parse and decrypt (with `passphrase` when encrypted).
///
/// # Errors
/// [`KeyError::Format`], [`KeyError::Unsupported`], [`KeyError::NeedsPassphrase`],
/// [`KeyError::WrongPassphrase`].
pub fn decode(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeyError> {
    let key = parse(text)?;
    if !key.is_encrypted() {
        return Ok(key);
    }
    let pass = passphrase.ok_or(KeyError::NeedsPassphrase)?;
    key.decrypt(pass.as_bytes())
        .map_err(|_| KeyError::WrongPassphrase)
}

/// The body names `ssh-dss` as the public key algorithm (ssh-key is built without DSA,
/// so such a key does not parse at all).
fn declares_dsa(text: &str) -> bool {
    use base64::Engine as _;
    let body: String = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .is_ok_and(|raw| raw.windows(7).take(256).any(|w| w == b"ssh-dss"))
}
