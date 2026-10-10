//! Feeds arbitrary bytes to the OpenSSH `known_hosts` parser (T21;
//! `fuzz_known_hosts_parse`): parse, look hosts up and fingerprint every key. It must
//! never panic. Run it with `cargo +nightly fuzz run known_hosts_parse` from `fuzz/`; the
//! same body is run on stable by
//! `crates/courier-ftp-proto-sftp/src/known_hosts/props.rs::parse_never_panics`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_proto_sftp::known_hosts::fuzz_known_hosts_parse(data);
});
