//! Padding, wrapping, KDF params, canonical builders, key-type hygiene and
//! the fuzz entry point.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chacha20::ChaCha20Rng;
use courier_ftp_crypto::canon::{aad_item, len_prefixed};
use courier_ftp_crypto::envelope::fuzz_open_item;
use courier_ftp_crypto::kdf::{Argon2Cost, KdfParams, argon2id, fuzz_kdf_params};
use courier_ftp_crypto::keys::{random_key32, random_salt16};
use courier_ftp_crypto::pad::{pad256, unpad256};
use courier_ftp_crypto::wrap::{WrapPurpose, unwrap_key, unwrap_key32, wrap_key};
use courier_ftp_crypto::{CryptoError, Key32, Nonce24};
use proptest::prelude::*;
use rand_core::SeedableRng;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([9; 32])
}

proptest! {
    #[test]
    fn pad_roundtrip(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let p = pad256(&data);
        prop_assert_eq!(p.len() % 256, 0);
        prop_assert!(p.len() > data.len());
        prop_assert!(p.len() <= data.len() + 256);
        prop_assert_eq!(unpad256(&p).unwrap(), &data[..]);
    }

    // The fuzz target body must never panic on arbitrary input.
    #[test]
    fn fuzz_open_item_never_panics(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        fuzz_open_item(&data);
        let mut v1 = data.clone();
        if let Some(b) = v1.first_mut() { *b = 0x01; }
        fuzz_open_item(&v1);
    }

    #[test]
    fn unpad_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = unpad256(&data);
    }

    // The `kdf_params` fuzz body (T91 §7): arbitrary bytes, and valid
    // encodings with one byte changed.
    #[test]
    fn fuzz_kdf_params_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..256),
        at in any::<prop::sample::Index>(),
        byte in any::<u8>(),
    ) {
        fuzz_kdf_params(&data);
        let mut valid = KdfParams::new(Argon2Cost::DEFAULT, [3; 16]).to_cbor();
        let i = at.index(valid.len());
        valid[i] = byte;
        fuzz_kdf_params(&valid);
    }
}

#[test]
fn wrap_purposes_are_domain_separated() {
    let kek = random_key32(&mut rng());
    let vk = random_key32(&mut rng());
    let (v1, v2) = ([1u8; 16], [2u8; 16]);
    let w = wrap_key(
        &kek,
        &WrapPurpose::VaultKey(v1),
        vk.expose_secret(),
        &mut rng(),
    )
    .unwrap();
    assert_eq!(
        unwrap_key32(&kek, &WrapPurpose::VaultKey(v1), &w).unwrap(),
        vk
    );
    for wrong in [
        WrapPurpose::VaultKey(v2),
        WrapPurpose::SyncTokens,
        WrapPurpose::Lmk,
        WrapPurpose::Device,
    ] {
        assert_eq!(
            unwrap_key(&kek, &wrong, &w).unwrap_err(),
            CryptoError::Auth,
            "{wrong:?}"
        );
    }
    // Wrong KEK.
    let other = Key32::from_bytes([0xee; 32]);
    assert_eq!(
        unwrap_key(&other, &WrapPurpose::VaultKey(v1), &w).unwrap_err(),
        CryptoError::Auth
    );
    // Truncation never panics.
    for len in 0..w.len() {
        assert!(unwrap_key(&kek, &WrapPurpose::VaultKey(v1), &w[..len]).is_err());
    }
}

#[test]
fn wrap_variable_length_secret() {
    let kek = Key32::from_bytes([5; 32]);
    let tokens = b"access=abc;refresh=def".to_vec();
    let w = wrap_key(&kek, &WrapPurpose::SyncTokens, &tokens, &mut rng()).unwrap();
    assert_eq!(
        *unwrap_key(&kek, &WrapPurpose::SyncTokens, &w).unwrap(),
        tokens
    );
    assert!(matches!(
        unwrap_key32(&kek, &WrapPurpose::SyncTokens, &w),
        Err(CryptoError::Malformed(_))
    ));
}

#[test]
fn kdf_params_validation() {
    let salt = random_salt16(&mut rng());
    let bad = KdfParams::new(
        Argon2Cost {
            m_kib: 1024,
            t: 3,
            p: 1,
        },
        salt,
    );
    assert!(matches!(
        argon2id(b"pw", &bad),
        Err(CryptoError::InvalidParams(_))
    ));
    assert!(matches!(
        argon2id(
            b"pw",
            &KdfParams {
                t: 0,
                ..KdfParams::new(Argon2Cost::DEFAULT, salt)
            }
        ),
        Err(CryptoError::InvalidParams(_))
    ));
    let d = KdfParams::new(Argon2Cost::default(), salt);
    assert_eq!((d.m_kib, d.t, d.p), (262_144, 3, 1));
    assert_eq!(d.cost(), Argon2Cost::DEFAULT);
    let g = KdfParams::generate(Argon2Cost::TEST, &mut rng());
    assert_eq!(g.salt, salt, "same seeded RNG, same salt");
}

#[test]
fn argon2_wrong_password_differs() {
    let params = KdfParams::new(Argon2Cost::TEST, [4; 16]);
    let a = argon2id(b"right", &params).unwrap();
    let b = argon2id(b"wrong", &params).unwrap();
    assert_ne!(a, b);
    assert_eq!(a, argon2id(b"right", &params).unwrap());
}

/// Password -> KEK -> wrapped LMK -> wrapped VK, the local vault chain (T30),
/// with the test cost.
#[test]
fn local_key_chain_with_test_cost() {
    let params = KdfParams::generate(Argon2Cost::TEST, &mut rng());
    let stored = params.to_cbor();
    let kek = argon2id(b"master password", &KdfParams::from_cbor(&stored).unwrap()).unwrap();
    let lmk = random_key32(&mut rng());
    let w = wrap_key(&kek, &WrapPurpose::Lmk, lmk.expose_secret(), &mut rng()).unwrap();
    let wrong = argon2id(b"master passwore", &params).unwrap();
    assert_eq!(
        unwrap_key(&wrong, &WrapPurpose::Lmk, &w).unwrap_err(),
        CryptoError::Auth
    );
    assert_eq!(unwrap_key32(&kek, &WrapPurpose::Lmk, &w).unwrap(), lmk);
}

#[test]
fn canonical_builders() {
    let aad = aad_item(&[0xaa; 16], &[0xbb; 16], 7);
    assert_eq!(aad.len(), 19 + 16 + 16 + 4);
    assert_eq!(&aad[..19], b"courier-ftp-item-v1");
    assert_eq!(&aad[19..35], &[0xaa; 16]);
    assert_eq!(&aad[35..51], &[0xbb; 16]);
    assert_eq!(&aad[51..], &[0, 0, 0, 7]);
    assert_eq!(
        len_prefixed(b"abc"),
        [0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63]
    );
}

#[test]
fn key_debug_is_redacted() {
    let bytes = [0xab; 32];
    let k = Key32::from_bytes(bytes);
    let dbg = format!("{k:?}");
    assert!(!dbg.contains("ab"), "{dbg}");
    assert!(!dbg.contains("171"), "{dbg}");
    assert!(dbg.contains("REDACTED"));
    let k2 = Key32::from_bytes([0x5c; 32]);
    let dbg2 = format!("{k2:#?}");
    assert!(
        !dbg2.to_lowercase().contains("5c") && !dbg2.contains("92"),
        "{dbg2}"
    );
    // Nonces are public and may print.
    assert!(format!("{:?}", Nonce24::from_bytes([0; 24])).starts_with("Nonce24("));
}

#[test]
fn key_types_zeroize() {
    use zeroize::Zeroize;
    let mut k = Key32::from_bytes([0xff; 32]);
    k.zeroize();
    assert_eq!(k.expose_secret(), &[0u8; 32]);
}
