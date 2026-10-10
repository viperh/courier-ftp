//! SFTP client for courier-ftp (D2: `russh` + `russh-sftp`).
//!
//! Implements `courier_ftp_core::backend::Backend` over SSH: connection and
//! authentication (T20, [`ssh`]), host key verification (T21, plugs into
//! [`ssh::HostKeyVerifier`]) and the SFTP operations (T22, on an
//! [`ssh::SshSession`]).
//!
//! This crate never depends on `ratatui`, `crossterm` or `clap`.

pub mod ssh;
