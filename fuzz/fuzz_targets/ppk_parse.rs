//! Feeds arbitrary bytes to the PuTTY `.ppk` parser (T20; `fuzz_ppk_parse`): parse,
//! public key and decode. It must never panic. Run it with `cargo +nightly fuzz run
//! ppk_parse` from `fuzz/`; the same body is run on stable by
//! `crates/courier-ftp-proto-sftp/src/keys/ppk_tests.rs::props::parse_never_panics`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_proto_sftp::keys::ppk::fuzz_ppk_parse(data);
});
