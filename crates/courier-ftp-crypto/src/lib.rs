//! Cryptographic primitives for the courier-ftp vault and sync (T80).
//!
//! Key derivation (Argon2id, HKDF), authenticated encryption
//! (XChaCha20-Poly1305), item envelopes, key wrapping, OPAQUE, account keys,
//! recovery keys, HPKE vault-key grants, Ed25519 signatures and safety numbers.
//! Adapted from sverb's `sverb-crypto` (D13) with every name and
//! domain-separation label changed to courier-ftp.
//!
//! This crate performs no I/O of any kind: no files, no sockets, no async
//! runtime. Callers hand it bytes and get bytes back, which keeps it usable
//! from the client, the sync server and tests alike.
//!
//! Randomness is always injected as a `rand_core::CryptoRng` parameter;
//! production code passes [`keys::os_rng()`]. Every byte string fed to an
//! AEAD, KDF or signature is built in [`canon`].

#![forbid(unsafe_code)]

// Primitives, canonical encodings, item envelopes.
pub mod aead;
pub mod canon;
pub mod envelope;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod pad;
pub mod wrap;

// Account keys, recovery key, vault-key grants, signatures, fingerprints.
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
