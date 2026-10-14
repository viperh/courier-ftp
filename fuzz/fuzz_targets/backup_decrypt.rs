//! `.cftp-backup` files (T30): header, KDF bounds, base64 fields, AEAD, capped
//! zstd and the CBOR item list, without Argon2. Same body as `courier-ftp-core`
//! `vault::backup::tests::fuzz_backup_decrypt_*`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_core::vault::backup::fuzz_backup_decrypt(data);
});
