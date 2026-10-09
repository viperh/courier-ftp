//! Device blobs: round-trip, name binding, tampering and the zip-bomb guard
//! (T80 AC5, AC7).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chacha20::ChaCha20Rng;
use courier_ftp_crypto::canon;
use courier_ftp_crypto::device_blob::{
    BLOB_V1, MAX_BLOB_PLAINTEXT, MIN_LEN, open_device_blob, seal_device_blob,
};
use courier_ftp_crypto::random::random_nonce24;
use courier_ftp_crypto::{CryptoError, Key32, aead};
use proptest::prelude::*;
use rand_core::SeedableRng;

fn key() -> Key32 {
    Key32::from_bytes([0x5a; 32])
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([4; 32])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn roundtrip(
        body in prop::collection::vec(any::<u8>(), 0..16 * 1024),
        k in any::<[u8; 32]>(),
        name in "[a-z-]{0,24}",
        seed in any::<[u8; 32]>(),
    ) {
        let k = Key32::from_bytes(k);
        let blob = seal_device_blob(&k, &name, &body, &mut ChaCha20Rng::from_seed(seed)).unwrap();
        prop_assert_eq!(blob[0], BLOB_V1);
        prop_assert!(blob.len() >= MIN_LEN);
        let back = open_device_blob(&k, &name, &blob).unwrap();
        prop_assert_eq!(&*back, &body);
    }
}

#[test]
fn name_binding() {
    let blob = seal_device_blob(&key(), "transfer-queue", b"[1,2,3]", &mut rng()).unwrap();
    assert_eq!(
        *open_device_blob(&key(), "transfer-queue", &blob).unwrap(),
        b"[1,2,3]"
    );
    for wrong in ["tabs", "transfer-queue ", "", "Transfer-queue"] {
        assert_eq!(
            open_device_blob(&key(), wrong, &blob).unwrap_err(),
            CryptoError::Auth,
            "{wrong:?}"
        );
    }
    // Wrong key is the same opaque error.
    assert_eq!(
        open_device_blob(&Key32::from_bytes([1; 32]), "transfer-queue", &blob).unwrap_err(),
        CryptoError::Auth
    );
}

#[test]
fn bitflip() {
    let body: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
    let blob = seal_device_blob(&key(), "tabs", &body, &mut rng()).unwrap();
    for pos in 0..blob.len() {
        for flip in [0x01u8, 0x80] {
            let mut t = blob.clone();
            t[pos] ^= flip;
            let err = open_device_blob(&key(), "tabs", &t).unwrap_err();
            if pos == 0 {
                assert!(matches!(err, CryptoError::UnsupportedVersion(_)), "{err:?}");
            } else {
                assert_eq!(err, CryptoError::Auth, "pos {pos}");
            }
        }
    }
    for len in 0..blob.len() {
        assert!(open_device_blob(&key(), "tabs", &blob[..len]).is_err());
    }
}

/// Seals an arbitrary zstd payload exactly as `seal_device_blob` does.
fn blob_with_payload(payload: &[u8]) -> Vec<u8> {
    let nonce = random_nonce24(&mut rng());
    let ct = aead::seal(&key(), &nonce, &canon::aad_device_blob("tabs"), payload).unwrap();
    let mut b = vec![BLOB_V1];
    b.extend_from_slice(nonce.as_bytes());
    b.extend_from_slice(&ct);
    b
}

/// A hand-built zstd frame of `blocks` RLE blocks of 128 KiB zeros each
/// (4 bytes per block), with or without a declared content size.
fn rle_bomb(blocks: usize, declared: bool) -> Vec<u8> {
    const BLOCK: u32 = 128 * 1024;
    let mut f = vec![0x28, 0xb5, 0x2f, 0xfd];
    if declared {
        // FCS field 8 bytes, no single segment, window descriptor 2^17.
        f.push(0xc0);
        f.push(0x38);
        f.extend_from_slice(&(blocks as u64 * u64::from(BLOCK)).to_le_bytes());
    } else {
        f.push(0x00);
        f.push(0x38);
    }
    for i in 0..blocks {
        let last = u32::from(i + 1 == blocks);
        let header = (BLOCK << 3) | (1 << 1) | last;
        f.extend_from_slice(&header.to_le_bytes()[..3]);
        f.push(0);
    }
    f
}

#[test]
fn bomb_rejected() {
    // 2 049 blocks of 128 KiB = 256 MiB + 128 KiB, about 8 KiB compressed.
    let blocks = MAX_BLOB_PLAINTEXT / (128 * 1024) + 1;

    // Declared content size above the cap: rejected before allocating.
    let declared = rle_bomb(blocks, true);
    assert_eq!(
        zstd::zstd_safe::get_frame_content_size(&declared)
            .ok()
            .flatten(),
        Some((blocks * 128 * 1024) as u64)
    );
    assert_eq!(
        open_device_blob(&key(), "tabs", &blob_with_payload(&declared)).unwrap_err(),
        CryptoError::Decompress
    );

    // Exactly at the cap still opens (the frame format is right).
    let at_cap = open_device_blob(
        &key(),
        "tabs",
        &blob_with_payload(&rle_bomb(blocks - 1, false)),
    )
    .unwrap();
    assert_eq!(at_cap.len(), MAX_BLOB_PLAINTEXT);
    drop(at_cap);

    // No declared size: the counting pass stops at cap + 1 bytes.
    let undeclared = rle_bomb(blocks, false);
    assert_eq!(
        zstd::zstd_safe::get_frame_content_size(&undeclared)
            .ok()
            .flatten(),
        None
    );
    assert_eq!(
        open_device_blob(&key(), "tabs", &blob_with_payload(&undeclared)).unwrap_err(),
        CryptoError::Decompress
    );

    // Garbage that authenticates is a decompression error, not a panic.
    assert_eq!(
        open_device_blob(&key(), "tabs", &blob_with_payload(b"not zstd")).unwrap_err(),
        CryptoError::Decompress
    );
}
