//! Feeds arbitrary bytes to the FTP control reply parser (T10; `fuzz_reply_parser`: the
//! first byte picks the chunk split points, the rest is the server's byte stream; every
//! parsed reply also goes through `parse_feat` and the PWD parser). It must never panic,
//! and the split and unsplit parses must agree. Run it with
//! `cargo +nightly fuzz run ftp_reply` from `fuzz/`; the same body is run on stable by
//! `crates/courier-ftp-proto-ftp/src/reply/tests.rs::prop_reply_parser_never_panics`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_proto_ftp::reply::fuzz_reply_parser(data);
});
