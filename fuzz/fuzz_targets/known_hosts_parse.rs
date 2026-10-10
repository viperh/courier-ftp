//! OpenSSH `known_hosts` parser and host matching (T21; hashed entries, globs,
//! markers). Same body as `courier-ftp-core`
//! `trust::known_hosts::tests::fuzz_known_hosts_*`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_core::trust::known_hosts::fuzz_known_hosts(data);
});
