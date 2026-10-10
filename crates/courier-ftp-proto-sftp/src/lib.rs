//! SFTP client for courier-ftp (D2: `russh` + `russh-sftp`).
//!
//! Implements `courier_ftp_core::backend::Backend` over SSH: connection and
//! authentication (T20), host key verification (T21) and the SFTP operations
//! (T22).
//!
//! This crate never depends on `ratatui`, `crossterm` or `clap`.
