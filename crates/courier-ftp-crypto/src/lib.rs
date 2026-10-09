//! Cryptography for courier-ftp's vault and sync (T80, adapted from sverb).
//!
//! The key hierarchy (Argon2id master key, vault keys), item envelopes
//! (XChaCha20-Poly1305), encrypted device-local blobs, account keys,
//! vault-key grants (HPKE), the recovery phrase and the OPAQUE login.
//!
//! This crate performs no I/O of any kind: no files, no sockets, no async
//! runtime. Callers hand it bytes and get bytes back, which keeps it usable
//! from the client, the server and tests alike.
//!
//! Randomness is always injected as a `rand_core::CryptoRng` parameter;
//! production code passes [`random::os_rng()`]. Every byte string fed to an
//! AEAD or KDF is built in [`canon`].
#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Primitives, canonical encodings, item envelopes, device blobs.
pub mod aead;
pub mod canon;
pub mod device_blob;
pub mod envelope;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod pad;
pub mod random;
pub mod wrap;

// Account keys, recovery key, vault-key grants, fingerprints.
pub mod account;
pub mod fingerprint;
pub mod grant;
pub mod hpke;
pub mod recovery;
pub mod sign;

// The shared OPAQUE cipher suite and client/server wrappers.
pub mod opaque;

pub use error::{CryptoError, Result};
pub use keys::{Key32, Nonce24};
