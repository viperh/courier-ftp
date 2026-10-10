//! Account bundle open (T80). Same body as
//! `crates/courier-ftp-crypto/tests/account.rs::t09_decoders_never_panic`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_crypto::account::fuzz_open_bundle(data);
});
