//! Cryptography for courier-ftp's vault and sync (T80, adapted from sverb).
//!
//! The key hierarchy (Argon2id master key, vault keys), item envelopes
//! (XChaCha20-Poly1305), account keys, vault-key grants (HPKE), the recovery
//! phrase and the OPAQUE login. Pure computation: no I/O, no async runtime.
//!
//! Layering: depends on no other courier-ftp crate; `store`, `proto`, `core`,
//! `sync` and the server build on it.

#![forbid(unsafe_code)]
