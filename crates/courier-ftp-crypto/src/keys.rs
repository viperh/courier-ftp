//! Key types, randomness and HKDF helpers.
//!
//! `courier-ftp-crypto` sits below `courier-ftp-core`, so it defines its own
//! small zeroizing secret types; core re-exports or wraps them.
//!
//! Every random function takes the RNG as a parameter so tests can inject a
//! deterministic generator. Production code passes [`os_rng()`], the operating
//! system CSPRNG.

use hkdf::Hkdf;
use rand_core::{CryptoRng, UnwrapErr};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CryptoError, Result};

/// Length of a symmetric key in bytes.
pub const KEY_LEN: usize = 32;
/// Length of an XChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LEN: usize = 24;
/// Length of an Argon2id salt in bytes.
pub const SALT_LEN: usize = 16;
/// Maximum HKDF-SHA256 output length (255 * 32 bytes, RFC 5869).
pub const HKDF_MAX_OUT: usize = 255 * 32;

// ------------------------------------------------------------------ types --

/// A 256-bit secret key. Zeroized on drop; `Debug` never prints the bytes;
/// equality is constant-time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key32([u8; KEY_LEN]);

impl Key32 {
    /// Wraps raw key bytes. The caller should zeroize its own copy.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Copies a key from a slice; the slice must be exactly 32 bytes.
    ///
    /// # Errors
    /// [`CryptoError::Malformed`] if the length is not 32.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::Malformed("key must be 32 bytes"))?;
        Ok(Self(arr))
    }

    /// Generates a fresh random key from `rng`.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        random_key32(rng)
    }

    /// Exposes the raw key bytes. Keep the borrow as short as possible.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key32([REDACTED])")
    }
}

impl PartialEq for Key32 {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Key32 {}

/// A 192-bit XChaCha20-Poly1305 nonce. Nonces are public, but the type keeps
/// them from being confused with other 24-byte values.
#[derive(Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct Nonce24([u8; NONCE_LEN]);

impl Nonce24 {
    /// Wraps raw nonce bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Nonce24 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Nonce24(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

// ------------------------------------------------------------- randomness --

/// The operating-system CSPRNG. `getrandom` failures are unrecoverable and
/// panic, which is the conventional behaviour of `OsRng`.
pub type OsRng = UnwrapErr<getrandom::SysRng>;

/// Returns the operating-system CSPRNG.
#[must_use]
pub const fn os_rng() -> OsRng {
    UnwrapErr(getrandom::SysRng)
}

/// Generates a fresh random 256-bit key.
pub fn random_key32<R: CryptoRng + ?Sized>(rng: &mut R) -> Key32 {
    let mut bytes = [0u8; KEY_LEN];
    rng.fill_bytes(&mut bytes);
    let key = Key32::from_bytes(bytes);
    bytes.zeroize();
    key
}

/// Generates a fresh random 16-byte salt (Argon2id salt).
pub fn random_salt16<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    salt
}

/// Generates a fresh random 24-byte XChaCha20-Poly1305 nonce.
pub fn random_nonce24<R: CryptoRng + ?Sized>(rng: &mut R) -> Nonce24 {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    Nonce24::from_bytes(nonce)
}

// ------------------------------------------------------------------- HKDF --

/// HKDF-SHA256 extract-and-expand (RFC 5869).
///
/// `info` must come from a builder in [`crate::canon`].
///
/// # Errors
/// [`CryptoError::InvalidParams`] if `out_len` is 0 or exceeds [`HKDF_MAX_OUT`].
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if out_len == 0 || out_len > HKDF_MAX_OUT {
        return Err(CryptoError::InvalidParams("hkdf output length"));
    }
    let mut okm = Zeroizing::new(vec![0u8; out_len]);
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, &mut okm)
        .map_err(|_| CryptoError::InvalidParams("hkdf output length"))?;
    Ok(okm)
}

/// HKDF-SHA256 producing a 32-byte key (cannot fail: 32 bytes is always
/// within the output limit).
#[must_use]
pub fn hkdf_key32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Key32 {
    let mut okm = [0u8; KEY_LEN];
    let expanded = Hkdf::<Sha256>::new(salt, ikm).expand(info, &mut okm);
    debug_assert!(expanded.is_ok(), "32-byte HKDF output is always valid");
    let key = Key32::from_bytes(okm);
    okm.zeroize();
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_default())
            .collect()
    }

    /// RFC 5869 test case 1 through our wrapper.
    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = [0x0b; 22];
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let okm = hkdf_sha256(&ikm, Some(&salt), &info, 42).unwrap_or_default();
        assert_eq!(
            okm.as_slice(),
            unhex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
        // The Key32 helper agrees with the first 32 bytes.
        let k = hkdf_key32(&ikm, Some(&salt), &info);
        assert_eq!(&k.expose_secret()[..], &okm[..32]);
    }

    #[test]
    fn hkdf_bounds() {
        assert!(hkdf_sha256(b"k", None, b"", 0).is_err());
        assert!(hkdf_sha256(b"k", None, b"", HKDF_MAX_OUT + 1).is_err());
        assert!(hkdf_sha256(b"k", None, b"", HKDF_MAX_OUT).is_ok());
    }

    #[test]
    fn random_keys_differ() {
        let mut rng = os_rng();
        assert_ne!(Key32::generate(&mut rng), Key32::generate(&mut rng));
        assert_ne!(random_nonce24(&mut rng), random_nonce24(&mut rng));
    }
}
