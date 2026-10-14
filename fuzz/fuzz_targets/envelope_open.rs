//! Item envelope open (T80): version byte, key version, nonce, AEAD, unpad and
//! capped zstd. Same body as
//! `crates/courier-ftp-crypto/tests/primitives.rs::fuzz_open_item_never_panics`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_crypto::envelope::fuzz_open_item(data);
});
