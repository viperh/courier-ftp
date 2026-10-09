//! Feeds arbitrary bytes to the item-envelope decoder (T80;
//! `fuzz_open_item`, which also exercises the unpad + capped zstd path). It must never
//! panic. Run it with `cargo +nightly fuzz run envelope_open` from `fuzz/`; the same body
//! is run on stable by
//! `crates/courier-ftp-crypto/tests/primitives.rs::fuzz_bodies_never_panic`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_crypto::envelope::fuzz_open_item(data);
});
