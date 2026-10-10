//! Encrypted device-local blobs (transfer queue, saved tabs).
//!
//! ```text
//! aad  = "courier-ftp-device-blob-v1" || u32 BE len(name) || name (UTF-8)
//! blob = 0x01 || nonce (24) || XChaCha20-Poly1305(device_key, nonce, aad, zstd3(plaintext)) || tag (16)
//! ```
//!
//! No padding: a blob never leaves the device. The name binds a blob to its
//! slot, so a `transfer-queue` blob does not open as `tabs`. Adapted from
//! sverb's recording chunks (single chunk, no index).

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::aead::{self, TAG_LEN};
use crate::canon;
use crate::envelope::{ZSTD_LEVEL, decompress_capped};
use crate::error::{CryptoError, Result};
use crate::keys::{Key32, NONCE_LEN, Nonce24};
use crate::random::random_nonce24;

/// Device blob format version written by this build.
pub const BLOB_V1: u8 = 0x01;
/// Header length: version (1) + nonce (24).
pub const HEADER_LEN: usize = 1 + NONCE_LEN;
/// Smallest structurally valid blob (header + tag).
pub const MIN_LEN: usize = HEADER_LEN + TAG_LEN;
/// Largest plaintext a blob may hold (and the decompression cap when opening).
/// A 100 000-item transfer queue is about 30 MiB.
pub const MAX_BLOB_PLAINTEXT: usize = 256 * 1024 * 1024;

/// Compresses and seals `plaintext` under `device_key`, bound to `name`, with
/// a fresh random nonce from `rng`.
///
/// # Errors
/// [`CryptoError::InvalidParams`] if `plaintext` exceeds
/// [`MAX_BLOB_PLAINTEXT`] or compression fails.
pub fn seal_device_blob<R: CryptoRng + ?Sized>(
    device_key: &Key32,
    name: &str,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let nonce = random_nonce24(rng);
    seal_device_blob_with_nonce(device_key, name, plaintext, &nonce)
}

/// [`seal_device_blob`] with an explicit nonce, for known-answer tests only.
///
/// # Errors
/// As [`seal_device_blob`].
#[doc(hidden)]
pub fn seal_device_blob_with_nonce(
    device_key: &Key32,
    name: &str,
    plaintext: &[u8],
    nonce: &Nonce24,
) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_BLOB_PLAINTEXT {
        return Err(CryptoError::InvalidParams("device blob too large"));
    }
    let compressed = Zeroizing::new(
        zstd::bulk::compress(plaintext, ZSTD_LEVEL)
            .map_err(|_| CryptoError::InvalidParams("zstd compression failed"))?,
    );
    let aad = canon::aad_device_blob(name);
    let ct = aead::seal(device_key, nonce, &aad, &compressed)?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.push(BLOB_V1);
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens a blob sealed by [`seal_device_blob`] under the same key and name.
///
/// # Errors
/// - [`CryptoError::Auth`] for a wrong key, a wrong name or any tampering,
/// - [`CryptoError::UnsupportedVersion`] for an unknown version byte,
/// - [`CryptoError::Malformed`] if shorter than header + tag,
/// - [`CryptoError::Decompress`] if the authenticated payload is not valid
///   zstd or expands beyond [`MAX_BLOB_PLAINTEXT`].
pub fn open_device_blob(device_key: &Key32, name: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let Some(&version) = blob.first() else {
        return Err(CryptoError::Malformed("empty device blob"));
    };
    if version != BLOB_V1 {
        return Err(CryptoError::UnsupportedVersion(version));
    }
    if blob.len() < MIN_LEN {
        return Err(CryptoError::Malformed("device blob too short"));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[1..HEADER_LEN]);
    let aad = canon::aad_device_blob(name);
    let compressed = aead::open(
        device_key,
        &Nonce24::from_bytes(nonce),
        &aad,
        &blob[HEADER_LEN..],
    )?;
    decompress_capped(&compressed, MAX_BLOB_PLAINTEXT)
}

/// Fuzz entry point: feeds arbitrary bytes to [`open_device_blob`] with a
/// fixed key. Must never panic.
#[doc(hidden)]
pub fn fuzz_open_device_blob(data: &[u8]) {
    let key = Key32::from_bytes([0x42; 32]);
    let _ = open_device_blob(&key, "transfer-queue", data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_layout() {
        let key = Key32::from_bytes([3; 32]);
        let blob =
            seal_device_blob_with_nonce(&key, "tabs", b"hello", &Nonce24::from_bytes([5; 24]))
                .unwrap_or_default();
        assert_eq!(blob[0], BLOB_V1);
        assert_eq!(&blob[1..25], &[5; 24]);
        let back = open_device_blob(&key, "tabs", &blob).map(|b| b.to_vec());
        assert_eq!(back, Ok(b"hello".to_vec()));
        assert_eq!(
            open_device_blob(&key, "transfer-queue", &blob).map(|_| ()),
            Err(CryptoError::Auth)
        );
    }

    #[test]
    fn header_errors() {
        let key = Key32::from_bytes([3; 32]);
        assert!(matches!(
            open_device_blob(&key, "x", &[]),
            Err(CryptoError::Malformed(_))
        ));
        assert_eq!(
            open_device_blob(&key, "x", &[2; 64]).map(|_| ()),
            Err(CryptoError::UnsupportedVersion(2))
        );
        assert!(matches!(
            open_device_blob(&key, "x", &[1; 40]),
            Err(CryptoError::Malformed(_))
        ));
    }
}
