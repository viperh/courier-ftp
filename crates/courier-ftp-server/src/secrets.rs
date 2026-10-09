//! At-rest encryption of server-side secrets.
//!
//! Key: `K = HKDF-SHA256(ikm = COURIER_SERVER_SECRET, salt = none,
//! info = "courier-ftp/server-secret/v1")`. Values are XChaCha20-Poly1305 from
//! `courier-ftp-crypto`, stored as `nonce (24 bytes) || ciphertext`. Rows of
//! `server_secrets` use the row name as AAD; TOTP seeds and OPAQUE login states use
//! their own AADs (see [`crate::routes::account`] and [`crate::auth::opaque`]).
//!
//! On start [`ServerSecrets::verify_or_init`] writes a canary row (first start)
//! and then decrypts every row. A failure means the configured secret is not the
//! one the database was created with: the server refuses to start (exit code 2).

use courier_ftp_crypto::keys::{NONCE_LEN, Nonce24};
use courier_ftp_crypto::{Key32, aead, kdf, random};
use zeroize::Zeroizing;

use crate::auth::store::Store;
use crate::config::ServerSecret;
use crate::error::ApiError;

/// HKDF `info` for the server-secret key.
pub const SERVER_SECRET_INFO: &[u8] = b"courier-ftp/server-secret/v1";
/// Name of the canary row written on first start.
pub const CANARY_NAME: &str = "secret_check";
/// Name of the sealed OPAQUE `ServerSetup` row.
pub const OPAQUE_SERVER_SETUP: &str = "opaque_server_setup";
/// Plaintext of the canary row.
pub const CANARY_PLAINTEXT: &[u8] = b"courier-ftp server secret check v1";

/// Errors from `server_secrets`.
#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    /// Store failure.
    #[error("database error: {0}")]
    Store(#[from] ApiError),
    /// A row can't be decrypted with the configured secret.
    #[error(
        "cannot decrypt server_secrets row {name}: COURIER_SERVER_SECRET differs from the one \
         this database was created with. Refusing to start."
    )]
    WrongSecret {
        /// The row that failed.
        name: String,
    },
    /// Encryption failed (only for absurdly large values).
    #[error("encryption failed: {0}")]
    Crypto(#[from] courier_ftp_crypto::CryptoError),
}

/// The derived key plus helpers for the `server_secrets` table.
pub struct ServerSecrets {
    key: Key32,
}

impl std::fmt::Debug for ServerSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerSecrets([REDACTED])")
    }
}

impl ServerSecrets {
    /// Derives the key from the configured secret.
    #[must_use]
    pub fn new(secret: &ServerSecret) -> Self {
        Self {
            key: kdf::hkdf_key32(secret.expose(), None, SERVER_SECRET_INFO),
        }
    }

    /// Encrypts `plaintext` bound to `aad`; returns `nonce || ciphertext`.
    ///
    /// # Errors
    /// [`SecretsError::Crypto`].
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SecretsError> {
        let nonce = random::random_nonce24(&mut random::os_rng());
        let ct = aead::seal(&self.key, &nonce, aad, plaintext)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(nonce.as_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// [`Self::seal`] for handlers (`Internal` on failure).
    ///
    /// # Errors
    /// [`ApiError::Internal`].
    pub fn seal_api(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ApiError> {
        self.seal(aad, plaintext).map_err(ApiError::internal)
    }

    /// Decrypts a value from [`Self::seal`]; `None` when it is malformed or was
    /// not sealed with this key and AAD.
    #[must_use]
    pub fn open(&self, aad: &[u8], blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if blob.len() < NONCE_LEN {
            return None;
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
        aead::open(&self.key, &Nonce24::from_bytes(nonce), aad, ct).ok()
    }

    /// Writes the canary on first start, then checks that every
    /// `server_secrets` row decrypts.
    ///
    /// # Errors
    /// [`SecretsError::WrongSecret`] naming the first row that fails.
    pub async fn verify_or_init(&self, store: &Store) -> Result<(), SecretsError> {
        let canary = self.seal(CANARY_NAME.as_bytes(), CANARY_PLAINTEXT)?;
        store.insert_secret_if_absent(CANARY_NAME, &canary).await?;
        for (name, blob) in store.all_secrets().await? {
            if self.open(name.as_bytes(), &blob).is_none() {
                return Err(SecretsError::WrongSecret { name });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn secrets(byte: &str) -> ServerSecrets {
        ServerSecrets::new(&ServerSecret::parse(&byte.repeat(32)).unwrap())
    }

    #[test]
    fn seal_open_roundtrip_and_aad_binding() {
        let s = secrets("11");
        let blob = s.seal(b"opaque_server_setup", b"payload").unwrap();
        assert_eq!(
            s.open(b"opaque_server_setup", &blob).unwrap().as_slice(),
            b"payload"
        );
        // Wrong AAD, wrong key, truncated blob: all fail.
        assert!(s.open(b"other_row", &blob).is_none());
        assert!(secrets("22").open(b"opaque_server_setup", &blob).is_none());
        assert!(s.open(b"opaque_server_setup", &blob[..10]).is_none());
        // Fresh nonce per seal.
        assert_ne!(blob, s.seal(b"opaque_server_setup", b"payload").unwrap());
    }

    #[test]
    fn wrong_secret_message_is_the_documented_one() {
        let e = SecretsError::WrongSecret {
            name: "secret_check".into(),
        };
        assert_eq!(
            e.to_string(),
            "cannot decrypt server_secrets row secret_check: COURIER_SERVER_SECRET differs \
             from the one this database was created with. Refusing to start."
        );
    }
}
