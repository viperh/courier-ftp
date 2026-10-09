//! SFTP client for courier-ftp, built on `russh` and `russh-sftp` (D2).
//!
//! Implements the `Backend` trait from `courier-ftp-core`: the SSH connection
//! and authentication (T20), host key verification (T21) and the SFTP
//! operations and backend (T22).
