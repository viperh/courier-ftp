//! Feeds arbitrary bytes to the four SOCKS reply parsers (T07; `fuzz_socks_reply`).
//! It must never panic. Run it with `cargo +nightly fuzz run socks_reply` from `fuzz/`;
//! the same body is run on stable by
//! `crates/courier-ftp-core/src/net/tests/props.rs::prop_fuzz_socks_reply_never_panics`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_core::net::fuzz_socks_reply(data);
});
