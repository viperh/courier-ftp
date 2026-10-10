//! KDF parameter CBOR (T80; vault `meta`, account bundles), never running Argon2.
//! Same body as `crates/courier-ftp-crypto/tests/primitives.rs::fuzz_kdf_params_never_panics`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    courier_ftp_crypto::kdf::fuzz_kdf_params(data);
});
