//! FTP and FTPS client for courier-ftp (D1: our own implementation on tokio).
//!
//! Implements `courier_ftp_core::backend::Backend` for FTP, explicit FTPS and
//! implicit FTPS: the control connection (T10), data connections and transfer
//! modes (T11), TLS through rustls (T12), directory listing parsers (T13), the
//! backend operations (T14) and FTP proxies (T15).
//!
//! This crate never depends on `ratatui`, `crossterm` or `clap`.

pub mod control;
pub mod data;
pub mod listing;
pub mod proxy;

#[cfg(test)]
pub(crate) mod test_server;
