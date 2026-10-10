//! Feeds arbitrary bytes to the FTP passive/active address parsers (T11;
//! `fuzz_pasv_epsv`: `parse_pasv`, `parse_epsv` and `parse_eprt` on the lossy UTF-8
//! text, plus a format → parse round trip of whatever parses). It must never panic.
//! Run it with `cargo +nightly fuzz run ftp_pasv` from `fuzz/`; the same body is run on
//! stable by `crates/courier-ftp-proto-ftp/src/passive/tests.rs::prop_pasv_epsv_never_panic`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_proto_ftp::passive::fuzz_pasv_epsv(data);
});
