//! Feeds arbitrary bytes to the device-blob decoder (T80;
//! `fuzz_open_device_blob`, including the capped zstd path). It must never panic. Run it
//! with `cargo +nightly fuzz run device_blob_open` from `fuzz/`; the same body is run on
//! stable by `crates/courier-ftp-crypto/tests/primitives.rs::fuzz_bodies_never_panic`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_crypto::device_blob::fuzz_open_device_blob(data);
});
