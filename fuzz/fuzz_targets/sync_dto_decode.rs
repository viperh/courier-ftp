//! Feeds arbitrary bytes to every sync protocol JSON decoder and validator (T83;
//! `fuzz_decode_all`: each request and response DTO, `ServerMsg`, `ClientMsg`,
//! `RotateRequest`, version negotiation). It must never panic. Run it with
//! `cargo +nightly fuzz run sync_dto_decode` from `fuzz/`; the same body is run on
//! stable by `crates/courier-ftp-proto/tests/props.rs::fuzz_body_never_panics`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_proto::fuzz_decode_all(data);
});
