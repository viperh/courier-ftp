//! Generic key wrapping under the LMK or a KEK (sverb SPEC §5.3).
//!
//! `aad = "courier-ftp-lmk-wrap-v1" || purpose`; output `nonce (24) || ct || tag`.
//! Used for the LMK under the password KEK and the keyring KEK, vault keys
//! sync tokens and the per-device blob key under the LMK. A wrapped 32-byte key
//! is 72 bytes.

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::aead;
use crate::canon::{self, Id16};
use crate::error::{CryptoError, Result};
use crate::keys::{Key32, NONCE_LEN, Nonce24};
use crate::random::random_nonce24;

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
    /// The random per-device blob key ([`crate::device_blob`]) under the LMK.
    DeviceKey,
}

impl WrapPurpose {
    /// The stable ASCII name encoded (length-prefixed) into the AAD.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Lmk => "lmk",
            Self::VaultKey(_) => "vault-key",
            Self::SyncTokens => "sync-tokens",
            Self::DeviceKey => "device-key",
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

    fn seq(start: u8, n: usize) -> Vec<u8> {
        (0..n).map(|i| start.wrapping_add(i as u8)).collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn wrap_lmk_kat() {
        let kek = Key32::from_slice(&seq(0, 32)).unwrap_or_else(|_| Key32::from_bytes([0; 32]));
        let secret = seq(0x80, 32);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&seq(0x40, 24));
        let nonce = Nonce24::from_bytes(nonce);
        let wrapped =
            wrap_key_with_nonce(&kek, &WrapPurpose::Lmk, &secret, &nonce).unwrap_or_default();
        assert_eq!(wrapped.len(), 72);
        assert_eq!(
            hex(&wrapped),
            concat!(
                "404142434445464748494a4b4c4d4e4f5051525354555657",
                "54b887f35465ff91077d0d352311eb1d022b3f5787ccc50df2a867de9599bd0f",
                "6670a3f3de3f5a94c085a4c75a22237a"
            )
        );
        let back = unwrap_key(&kek, &WrapPurpose::Lmk, &wrapped).map(|z| z.to_vec());
        assert_eq!(back, Ok(secret));
    }

    #[test]
    fn purpose_binding() {
        let kek = Key32::from_bytes([7; 32]);
        let mut rng = crate::random::os_rng();
        let a = WrapPurpose::VaultKey([0xA; 16]);
        let wrapped = wrap_key(&kek, &a, &[1; 32], &mut rng).unwrap_or_default();
        assert!(unwrap_key32(&kek, &a, &wrapped).is_ok());
        for other in [
            WrapPurpose::VaultKey([0xB; 16]),
            WrapPurpose::Lmk,
            WrapPurpose::SyncTokens,
            WrapPurpose::DeviceKey,
        ] {
            assert_eq!(
                unwrap_key(&kek, &other, &wrapped).map(|_| ()),
                Err(CryptoError::Auth)
            );
        }
        assert_eq!(
            unwrap_key(&kek, &a, &wrapped[..39]).map(|_| ()),
            Err(CryptoError::Malformed("wrapped key too short"))
        );
    }

    #[test]
    fn purpose_aad_lengths() {
        assert_eq!(WrapPurpose::Lmk.aad().len(), 30);
        assert_eq!(WrapPurpose::VaultKey([0; 16]).aad().len(), 52);
        assert_eq!(WrapPurpose::SyncTokens.aad().len(), 38);
        assert_eq!(WrapPurpose::DeviceKey.aad().len(), 37);
    }
}
