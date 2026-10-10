//! Cryptographic primitives for the courier-ftp vault and sync (T80).
//!
//! Key derivation (Argon2id, HKDF), authenticated encryption
//! (XChaCha20-Poly1305), item envelopes, signing and key agreement, adapted from
//! sverb (D13). Pure: no I/O, no async runtime, no storage.
