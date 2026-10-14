//! Vault-key grant decode, HPKE open and signature check (T80). Same body as
//! `crates/courier-ftp-crypto/tests/account.rs::t09_decoders_never_panic`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_crypto::grant::fuzz_open_grant(data);
});
