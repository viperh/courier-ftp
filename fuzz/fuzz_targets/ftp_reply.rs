//! Hostile FTP control connection replies (T10), in split reads. Same body as
//! `crates/courier-ftp-proto-ftp/tests/no_panic.rs` `reply_parser_*`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_proto_ftp::control::fuzz_reply_parser(data);
});
