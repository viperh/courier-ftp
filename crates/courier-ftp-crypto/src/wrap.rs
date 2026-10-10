//! Generic key wrapping under the LMK or a KEK.
//!
//! `aad = "courier-ftp-wrap-v1" || purpose`; output `nonce (24) || ct || tag`.
//! Used for the LMK under the password KEK and the keyring KEK, vault keys
//! and sync tokens under the LMK, and device-local data keys under the LMK
//! (T30).

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::aead;
use crate::canon::{self, Id16};
use crate::error::{CryptoError, Result};
use crate::keys::{Key32, NONCE_LEN, Nonce24, random_nonce24};

/// What a wrapped secret is. Encoded into the AAD, so a blob wrapped for one
/// purpose (or one vault) never unwraps as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapPurpose {
    /// The LMK under the password KEK or the keyring KEK.
    Lmk,
    /// A vault key under the LMK, bound to its vault id.
    VaultKey(Id16),
    /// Sync access / refresh tokens under the LMK.
    SyncTokens,
    /// A device-local data key (persisted queue, recent history) under the
    /// LMK. Never synced.
    Device,
}

impl WrapPurpose {
    /// The stable ASCII name encoded (length-prefixed) into the AAD.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Lmk => "lmk",
            Self::VaultKey(_) => "vault-key",
            Self::SyncTokens => "sync-tokens",
            Self::Device => "device",
        }
    }

    /// The canonical AAD for this purpose ([`canon::aad_wrap`]).
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        match self {
            Self::VaultKey(id) => canon::aad_wrap(self.name(), Some(id)),
            _ => canon::aad_wrap(self.name(), None),
        }
    }
}

/// Wraps `secret` (a key, or any small secret such as sync tokens) under `kek`.
///
/// # Errors
/// [`CryptoError::InvalidParams`] only for absurdly large inputs.
pub fn wrap_key<R: CryptoRng + ?Sized>(
    kek: &Key32,
    purpose: &WrapPurpose,
    secret: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    wrap_key_with_nonce(kek, purpose, secret, &random_nonce24(rng))
}

/// [`wrap_key`] with an explicit nonce, for known-answer tests only.
///
/// # Errors
/// As [`wrap_key`].
#[doc(hidden)]
pub fn wrap_key_with_nonce(
    kek: &Key32,
    purpose: &WrapPurpose,
    secret: &[u8],
    nonce: &Nonce24,
) -> Result<Vec<u8>> {
    let ct = aead::seal(kek, nonce, &purpose.aad(), secret)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwraps a blob produced by [`wrap_key`].
///
/// # Errors
/// [`CryptoError::Auth`] for a wrong KEK, wrong purpose or tampering;
/// [`CryptoError::Malformed`] if the blob is shorter than nonce + tag.
pub fn unwrap_key(
    kek: &Key32,
    purpose: &WrapPurpose,
    wrapped: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if wrapped.len() < NONCE_LEN + aead::TAG_LEN {
        return Err(CryptoError::Malformed("wrapped key too short"));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&wrapped[..NONCE_LEN]);
    aead::open(
        kek,
        &Nonce24::from_bytes(nonce),
        &purpose.aad(),
        &wrapped[NONCE_LEN..],
    )
}

/// [`unwrap_key`] for a 32-byte key.
///
/// # Errors
/// As [`unwrap_key`], plus [`CryptoError::Malformed`] if the authenticated
/// payload is not 32 bytes.
pub fn unwrap_key32(kek: &Key32, purpose: &WrapPurpose, wrapped: &[u8]) -> Result<Key32> {
    Key32::from_slice(&unwrap_key(kek, purpose, wrapped)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purpose_names_are_stable() {
        assert_eq!(WrapPurpose::Lmk.name(), "lmk");
        assert_eq!(WrapPurpose::VaultKey([0; 16]).name(), "vault-key");
        assert_eq!(WrapPurpose::SyncTokens.name(), "sync-tokens");
        assert_eq!(WrapPurpose::Device.name(), "device");
    }

    #[test]
    fn wrap_roundtrip_and_tamper() {
        let kek = Key32::from_bytes([1; 32]);
        let p = WrapPurpose::VaultKey([2; 16]);
        let w = wrap_key_with_nonce(&kek, &p, &[3; 32], &Nonce24::from_bytes([4; 24]))
            .unwrap_or_default();
        assert_eq!(w.len(), NONCE_LEN + 32 + aead::TAG_LEN);
        assert_eq!(
            unwrap_key32(&kek, &p, &w).ok(),
            Some(Key32::from_bytes([3; 32]))
        );
        for i in 0..w.len() {
            let mut t = w.clone();
            t[i] ^= 0x01;
            assert_eq!(
                unwrap_key(&kek, &p, &t).err(),
                Some(CryptoError::Auth),
                "byte {i}"
            );
        }
    }
}
