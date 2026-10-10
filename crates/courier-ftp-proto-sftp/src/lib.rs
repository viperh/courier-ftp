//! SFTP client for courier-ftp, built on `russh` and `russh-sftp` (D2).
//!
//! Implements the `Backend` trait from `courier-ftp-core`: the SSH connection
//! and authentication (T20), host key verification (T21) and the SFTP
//! operations and backend (T22).
//!
//! - [`ssh`]: the connection flow, authentication chain and host-key seam (T20);
//! - [`keys`]: private-key loading (OpenSSH, PEM, PKCS#8, PuTTY);
//! - [`agent`]: the SSH agent / Pageant client;
//! - [`known_hosts`]: read-only OpenSSH `known_hosts` files (T21);
//! - [`verify`]: host-key trust, [`verify::TrustVerifier`] (T21).
//!
//! All russh / ssh-key usage stays in `ssh`, `keys` and `agent`.
//!
//! Layering: depends only on `courier-ftp-core`; never on a UI crate.

pub mod agent;
pub mod convert;
pub mod keys;
pub mod known_hosts;
pub mod ssh;
pub mod verify;
