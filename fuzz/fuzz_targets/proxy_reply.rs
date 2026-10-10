//! Hostile proxy replies to HTTP CONNECT, SOCKS4/4a and SOCKS5 (T07), in split
//! reads. Same body as `courier-ftp-core` `net::tests::fuzz_proxy_reply_*`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_core::net::fuzz_proxy_reply(data);
});
