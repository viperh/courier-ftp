//! Padding, wrapping, Argon2 params, canonical builders, the zip-bomb guard,
//! key-type hygiene and the fuzz entry points (T-03, T-10, T-11, T-13, T-15, T-16).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chacha20::ChaCha20Rng;
use courier_ftp_crypto::account::fuzz_open_bundle;
use courier_ftp_crypto::canon::{aad_item, len_prefixed};
use courier_ftp_crypto::device_blob::fuzz_open_device_blob;
use courier_ftp_crypto::envelope::{MAX_DECOMPRESSED, decode_plaintext, fuzz_open_item};
use courier_ftp_crypto::grant::fuzz_open_grant;
use courier_ftp_crypto::kdf::{Argon2Params, argon2id};
use courier_ftp_crypto::pad::{pad256, unpad256};
use courier_ftp_crypto::random::{random_key32, random_salt16};
use courier_ftp_crypto::wrap::{WrapPurpose, unwrap_key, unwrap_key32, wrap_key};
use courier_ftp_crypto::{CryptoError, Key32, Nonce24};
use proptest::prelude::*;
use rand_core::SeedableRng;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([9; 32])
}

proptest! {
    // T-03
    #[test]
    fn pad_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let p = pad256(&data);
        prop_assert_eq!(p.len() % 256, 0);
        prop_assert!(p.len() > data.len());
        prop_assert!(p.len() <= data.len() + 256);
        prop_assert_eq!(unpad256(&p).unwrap(), &data[..]);
    }

    // T-16: the fuzz target body must never panic on arbitrary input.
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
}

// T-10
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
        WrapPurpose::DeviceKey,
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

// T-11
#[test]
fn argon2_params_validation() {
    let salt = random_salt16(&mut rng());
    let bad = Argon2Params {
        m_kib: 1024,
        t: 3,
        p: 1,
        salt,
    };
    assert!(matches!(
        argon2id(b"pw", &bad),
        Err(CryptoError::InvalidParams(_))
    ));
    assert!(matches!(
        argon2id(
            b"pw",
            &Argon2Params {
                t: 0,
                ..Argon2Params::with_salt(salt)
            }
        ),
        Err(CryptoError::InvalidParams(_))
    ));
    let d = Argon2Params::with_salt(salt);
    assert_eq!((d.m_kib, d.t, d.p), (262_144, 3, 1));
}

#[test]
fn argon2_wrong_password_differs() {
    let params = Argon2Params {
        m_kib: 19_456,
        t: 1,
        p: 1,
        salt: [4; 16],
    };
    let a = argon2id(b"right", &params).unwrap();
    let b = argon2id(b"wrong", &params).unwrap();
    assert_ne!(a, b);
    assert_eq!(a, argon2id(b"right", &params).unwrap());
}

// T-13
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

// AC7: a small frame that expands past the 16 MiB cap, with and without a
// declared content size, is rejected without decompressing it all.
#[test]
fn zstd_bomb_rejected() {
    let size = 17 * 1024 * 1024;
    let declared = zstd::bulk::compress(&vec![0u8; size], 3).unwrap();
    assert!(declared.len() < 64 * 1024, "{}", declared.len());
    assert_eq!(
        decode_plaintext(&pad256(&declared)).unwrap_err(),
        CryptoError::Decompress
    );

    // Streaming encoder: the frame header carries no content size.
    let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
    enc.include_contentsize(false).unwrap();
    std::io::Write::write_all(&mut enc, &vec![0u8; size]).unwrap();
    let undeclared = enc.finish().unwrap();
    assert!(undeclared.len() < 64 * 1024, "{}", undeclared.len());
    assert_eq!(
        zstd::zstd_safe::get_frame_content_size(&undeclared)
            .ok()
            .flatten(),
        None
    );
    assert_eq!(
        decode_plaintext(&pad256(&undeclared)).unwrap_err(),
        CryptoError::Decompress
    );
    assert!(MAX_DECOMPRESSED < size);
}

// AC10: the bodies of the four fuzz targets never panic.
#[test]
fn fuzz_bodies_never_panic() {
    use rand_core::Rng;
    let mut r = ChaCha20Rng::from_seed([0xf0; 32]);
    let mut buf = vec![0u8; 512];
    for i in 0..10_000u32 {
        let len = (r.next_u32() as usize) % buf.len();
        r.fill_bytes(&mut buf[..len]);
        // Half of the inputs start with the v1 version byte to get past the header.
        if i % 2 == 0 && len > 0 {
            buf[0] = 0x01;
        }
        let data = &buf[..len];
        fuzz_open_item(data);
        fuzz_open_device_blob(data);
        fuzz_open_bundle(data);
        fuzz_open_grant(data);
    }
}

// T-15
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
