//! Feeds arbitrary bytes to the backup container reader (T30;
//! `vault::backup::fuzz_backup_decrypt`: header, KDF bound checks, base64 fields, a
//! fixed key in place of Argon2, and the capped zstd + CBOR payload decoder). It must
//! never panic. The same body runs on stable in
//! `courier_ftp_core::vault::backup::tests::fuzz_body_never_panics`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_core::vault::backup::fuzz_backup_decrypt(data);
});
