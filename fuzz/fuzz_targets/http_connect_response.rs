//! Feeds arbitrary bytes to the HTTP CONNECT response parser (T07;
//! `fuzz_http_connect_response`: the whole input and every 2-way read split). It must
//! never panic. Run it with `cargo +nightly fuzz run http_connect_response` from
//! `fuzz/`; the same body is run on stable by
//! `crates/courier-ftp-core/src/net/tests/props.rs::prop_fuzz_http_connect_response_never_panics`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_core::net::fuzz_http_connect_response(data);
});
