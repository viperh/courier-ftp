//! Feeds arbitrary names to the local file name sanitiser (T06, T91 §7;
//! `fuzz_sanitize_local_name`): the result is never empty, "." or "..", and has no
//! separator, NUL or control character. Run it with
//! `cargo +nightly fuzz run remote_name_sanitize` from `fuzz/`; the same body is run on
//! stable by `crates/courier-ftp-core/src/local/sanitize.rs::prop_sanitized_name_is_valid`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_core::local::fuzz_sanitize_local_name(data);
});
