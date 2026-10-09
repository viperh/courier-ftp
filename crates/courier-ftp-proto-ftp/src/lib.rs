//! FTP and FTPS client for courier-ftp, written from scratch on tokio (D1).
//!
//! Implements the `Backend` trait from `courier-ftp-core`: the control
//! connection (T10), data connections and transfer modes (T11), FTPS with
//! rustls (T12), directory listing parsers (T13), the operations and the
//! backend itself (T14) and FTP proxies (T15).
