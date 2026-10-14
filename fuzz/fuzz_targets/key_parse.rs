//! Private key files (T20): OpenSSH, PEM, PKCS#8 and PuTTY `.ppk` v2/v3 detection
//! (with the Argon2 bounds) and unencrypted decoding. Same body as
//! `courier-ftp-proto-sftp` `ssh::keys::tests::fuzz_key_parse_*`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_proto_sftp::ssh::keys::fuzz_key_parse(data);
});
