//! Feeds arbitrary bytes to the FTP listing parsers (T13; `fuzz_listing`: the first byte
//! picks MLSD or LIST, the format hint, the decoder and the offset). It must never
//! panic. Run it with `cargo +nightly fuzz run ftp_listing` from `fuzz/`; the same body
//! is run on stable by
//! `crates/courier-ftp-proto-ftp/tests/listing.rs::prop_parsers_never_panic`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_proto_ftp::listing::fuzz_listing(data);
});
