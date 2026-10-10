//! Item body CBOR (T81), as carried by decrypted envelopes and backups. Same body
//! as `courier-ftp-core` `model::item::tests::fuzz_item_body_*`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_core::model::item::fuzz_item_body(data);
});
