//! XChaCha20-Poly1305 with 24-byte random nonces (§11.1).

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::keys::{Key32, Nonce24};

/// Length of the Poly1305 authentication tag appended to every ciphertext.
pub const TAG_LEN: usize = 16;

fn cipher(key: &Key32) -> XChaCha20Poly1305 {
    let key: &Key = key.expose_secret().into();
    XChaCha20Poly1305::new(key)
}

/// Encrypts `pt` under `key`/`nonce`, authenticating `aad`. Returns
/// `ciphertext || tag` (`pt.len() + 16` bytes).
///
/// The nonce must never repeat under the same key; draw it from
/// [`crate::random::random_nonce24`].
///
/// # Errors
/// [`CryptoError::InvalidParams`] if the plaintext exceeds the XChaCha20
/// block-counter limit (~256 GiB).
pub fn seal(key: &Key32, nonce: &Nonce24, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let nonce: &XNonce = nonce.as_bytes().into();
    cipher(key)
        .encrypt(nonce, Payload { msg: pt, aad })
        .map_err(|_| CryptoError::InvalidParams("plaintext too long"))
}

/// Decrypts and authenticates `ct` (`ciphertext || tag`).
///
/// # Errors
/// [`CryptoError::Auth`] on any failure: wrong key, wrong nonce, wrong AAD,
/// tampered or truncated ciphertext. The causes are indistinguishable by design.
pub fn open(key: &Key32, nonce: &Nonce24, aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let nonce: &XNonce = nonce.as_bytes().into();
    cipher(key)
        .decrypt(nonce, Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Auth)
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

    /// draft-irtf-cfrg-xchacha-03 §2.2.1: the HChaCha20 test vector.
    #[test]
    fn hchacha20_draft_221() {
        let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let input = unhex("000000090000004a0000000031415927");
        let key: [u8; 32] = key.try_into().unwrap_or_default();
        let input: [u8; 16] = input.try_into().unwrap_or_default();
        let out = chacha20::hchacha::<chacha20::R20>(&key.into(), &input.into());
        assert_eq!(
            out.as_slice(),
            unhex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
        );
    }

    /// draft-irtf-cfrg-xchacha-03 Appendix A.3.1: XChaCha20-Poly1305 AEAD.
    #[test]
    fn xchacha_draft_a31() {
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let key = Key32::from_slice(&unhex(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        ))
        .unwrap_or_else(|_| Key32::from_bytes([0; 32]));
        let nonce: [u8; 24] = unhex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap_or_default();
        let nonce = Nonce24::from_bytes(nonce);
        let expected = unhex(concat!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
            "21f9664c97637da9768812f615c68b13b52e",
            "c0875924c1c7987947deafd8780acf49"
        ));
        let ct = seal(&key, &nonce, &aad, pt).unwrap_or_default();
        assert_eq!(ct, expected);
        let back = open(&key, &nonce, &aad, &ct).map(|p| p.to_vec());
        assert_eq!(back, Ok(pt.to_vec()));
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_eq!(
            open(&key, &nonce, &aad, &bad).map(|_| ()),
            Err(CryptoError::Auth)
        );
        assert_eq!(
            open(&key, &nonce, b"", &ct).map(|_| ()),
            Err(CryptoError::Auth)
        );
    }
}
