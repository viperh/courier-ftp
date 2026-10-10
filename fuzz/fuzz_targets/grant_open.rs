//! Feeds arbitrary bytes to the vault-key grant decoders (T80; `fuzz_open_grant`:
//! `Grant::from_bytes`, signature check and HPKE open). It must never panic. Run it with
//! `cargo +nightly fuzz run grant_open` from `fuzz/`; the same body is run on stable by
//! `crates/courier-ftp-crypto/tests/account.rs::t09_decoders_never_panic`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_crypto::grant::fuzz_open_grant(data);
});
