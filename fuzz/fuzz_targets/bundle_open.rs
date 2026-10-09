//! Feeds arbitrary bytes to the account bundle decoders (T80;
//! `fuzz_open_bundle`: private and recovery bundles plus the strict CBOR decoder). It
//! must never panic. Run it with `cargo +nightly fuzz run bundle_open` from `fuzz/`; the
//! same body is run on stable by
//! `crates/courier-ftp-crypto/tests/account.rs::t09_decoders_never_panic`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_crypto::account::fuzz_open_bundle(data);
});
