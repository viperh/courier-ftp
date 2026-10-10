//! The [`Backend`] trait that FTP, SFTP and the local filesystem implement
//! (T03, D5), so the UI, transfer engine, search and comparison never care
//! which protocol is in use.
//!
//! # One connection, one operation
//!
//! A `Backend` is a single protocol session: its methods take `&mut self`
//! because sessions are stateful (FTP's working directory and data connection,
//! SFTP's channel). Only one operation runs at a time. The transfer engine
//! (T41) opens extra backends for parallel transfers; [`SessionHandle`] wraps
//! one backend for shared use with keep-alive and reconnect.
//!
//! Every path is an absolute [`RemotePath`], so nothing depends on a working
//! directory. A backend that has one (FTP) restores it itself after
//! reconnecting.
//!
//! # Why `async-trait`
//!
//! Native `async fn` in traits is not dyn-compatible, and the program holds
//! backends as `Box<dyn Backend>` chosen at runtime from the protocol. The
//! `async-trait` macro boxes each returned future, which costs one allocation
//! per call: negligible next to a network round trip.

#[cfg(any(test, feature = "test-util"))]
pub mod conformance;
mod connect;
#[cfg(any(test, feature = "test-util"))]
mod mock;
mod session;

use std::time::Instant;

use async_trait::async_trait;
pub use connect::{BackendFactory, ConnectInfo, KeySource, ProxyChoice, StoredSecret, VaultKey};
#[cfg(any(test, feature = "test-util"))]
pub use mock::{MockBackend, MockServer};
pub use session::SessionHandle;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

use crate::{
    Result,
    model::{CertificateDetails, Entry, RemotePath, ServerAddress},
    settings::FileTypeSettings,
};

/// A boxed reader returned by [`Backend::open_read`].
pub type ReadStream = Box<dyn AsyncRead + Send + Unpin>;
/// A boxed writer returned by [`Backend::open_write`].
pub type WriteStream = Box<dyn AsyncWrite + Send + Unpin>;

/// One protocol session. See the [module docs](self).
#[async_trait]
pub trait Backend: Send + Sync {
    /// What this backend can do; the UI greys out the rest.
    fn capabilities(&self) -> Capabilities;

    /// The server, or `None` for the local filesystem.
    fn address(&self) -> Option<&ServerAddress>;

    /// Connect and log in.
    async fn connect(&mut self, cancel: CancellationToken) -> Result<()>;

    /// Log out and close the connection.
    async fn disconnect(&mut self) -> Result<()>;

    /// Whether the session is believed to be connected.
    fn is_connected(&self) -> bool;

    /// The directory the server puts the user in (`PWD`, `realpath(".")`).
    async fn home_dir(&mut self) -> Result<RemotePath>;

    /// List a directory.
    async fn list(&mut self, dir: &RemotePath, cancel: CancellationToken) -> Result<Listing>;

    /// Information about one entry.
    async fn stat(&mut self, path: &RemotePath) -> Result<Entry>;

    /// Create a directory.
    async fn mkdir(&mut self, path: &RemotePath) -> Result<()>;

    /// Remove an empty directory.
    async fn rmdir(&mut self, path: &RemotePath) -> Result<()>;

    /// Remove a file.
    async fn remove_file(&mut self, path: &RemotePath) -> Result<()>;

    /// Rename or move an entry.
    async fn rename(&mut self, from: &RemotePath, to: &RemotePath) -> Result<()>;

    /// Change permissions (Unix mode bits).
    async fn chmod(&mut self, path: &RemotePath, mode: u32) -> Result<()>;

    /// Set the modification time.
    async fn set_mtime(&mut self, path: &RemotePath, time: OffsetDateTime) -> Result<()>;

    /// Open a file for reading from `offset`. Call
    /// [`Backend::finish_transfer`] after the stream is drained and dropped.
    async fn open_read(
        &mut self,
        path: &RemotePath,
        offset: u64,
        opts: &TransferOpts,
    ) -> Result<ReadStream>;

    /// Open a file for writing. Shut the stream down, drop it, then call
    /// [`Backend::finish_transfer`].
    async fn open_write(
        &mut self,
        path: &RemotePath,
        mode: WriteMode,
        opts: &TransferOpts,
    ) -> Result<WriteStream>;

    /// Complete the transfer started by `open_read`/`open_write` (FTP reads the
    /// `226` reply here) and report whether it succeeded.
    async fn finish_transfer(&mut self) -> Result<()>;

    /// Send a raw command (FileZilla's "Enter custom command") and return the
    /// reply text.
    async fn raw_command(&mut self, cmd: &str) -> Result<String>;

    /// Keep an idle connection alive (`NOOP`, an SSH keep-alive…).
    async fn keepalive(&mut self) -> Result<()>;

    /// What the connection looks like (status bar and server info dialog,
    /// T57), once connected.
    fn session_info(&self) -> Option<SessionInfo> {
        None
    }
}

/// Details of an established session, for the status bar's security
/// indicator and the server info dialog (T57).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// The server.
    pub address: ServerAddress,
    /// What the server says it is (FTP greeting or `SYST`, SSH banner).
    pub server_software: Option<String>,
    /// How the connection is protected.
    pub security: SecurityInfo,
}

/// How a session is protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityInfo {
    /// Plain FTP: nothing is encrypted.
    Plain,
    /// FTP over TLS.
    Tls {
        /// e.g. `TLS 1.3`.
        version: String,
        /// e.g. `TLS13_AES_256_GCM_SHA384`.
        cipher: String,
        /// The server certificate.
        certificate: Option<CertificateDetails>,
    },
    /// SFTP over SSH.
    Ssh {
        /// Key exchange algorithm.
        kex: String,
        /// Cipher.
        cipher: String,
        /// MAC (empty for AEAD ciphers).
        mac: String,
        /// Host key type and `SHA256:` fingerprint.
        host_key: String,
    },
}

/// What a backend supports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Capabilities {
    /// Permissions can be changed.
    pub chmod: bool,
    /// Modification times can be set.
    pub set_mtime: bool,
    /// Downloads can resume at an offset.
    pub resume_download: bool,
    /// Uploads can resume at an offset.
    pub resume_upload: bool,
    /// Files can be appended to.
    pub append: bool,
    /// Raw commands can be sent.
    pub raw_commands: bool,
    /// Symlinks are reported.
    pub symlinks: bool,
    /// `rename` can move entries between directories.
    pub server_side_rename_across_dirs: bool,
    /// ASCII transfer mode exists.
    pub ascii_mode: bool,
    /// Several connections to the server are allowed at once.
    pub parallel_connections_allowed: bool,
}

/// A directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// The listed directory.
    pub dir: RemotePath,
    /// Its entries, without `.` and `..`.
    pub entries: Vec<Entry>,
    /// When the listing was fetched (for the cache, T46).
    pub fetched_at: Instant,
    /// The raw listing text, when the protocol has one (T71).
    pub raw: Option<String>,
}

/// How [`Backend::open_write`] treats an existing file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WriteMode {
    /// Fail with [`Error::AlreadyExists`](crate::Error::AlreadyExists) if it
    /// exists.
    Create,
    /// Replace its contents.
    Truncate,
    /// Append to it.
    Append,
    /// Keep the first `n` bytes and write from there (resume).
    ResumeAt(u64),
}

/// FTP transfer type, resolved from the settings for one file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum TransferType {
    /// Line endings converted (`TYPE A`).
    Ascii,
    /// Bytes as they are (`TYPE I`).
    #[default]
    Binary,
}

/// The transfer type for `file_name` (T11): `settings.default_type` when it
/// is ASCII or binary, otherwise decided from the extension, dotfile and
/// no-extension rules ([`FileTypeSettings::is_ascii`]).
pub fn decide_transfer_type(file_name: &str, settings: &FileTypeSettings) -> TransferType {
    if settings.is_ascii(file_name) {
        TransferType::Ascii
    } else {
        TransferType::Binary
    }
}

/// Per-transfer options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct TransferOpts {
    /// ASCII or binary.
    pub transfer_type: TransferType,
    /// The expected size, so a writer can preallocate.
    pub preallocate_hint: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::TransferTypeChoice;

    #[test]
    fn transfer_type_follows_the_file_type_settings() {
        let auto = FileTypeSettings::default();
        assert_eq!(decide_transfer_type("a.txt", &auto), TransferType::Ascii);
        assert_eq!(decide_transfer_type("a.zip", &auto), TransferType::Binary);
        let binary = FileTypeSettings {
            default_type: TransferTypeChoice::Binary,
            ..FileTypeSettings::default()
        };
        assert_eq!(decide_transfer_type("a.txt", &binary), TransferType::Binary);
        let ascii = FileTypeSettings {
            default_type: TransferTypeChoice::Ascii,
            ..FileTypeSettings::default()
        };
        assert_eq!(decide_transfer_type("a.zip", &ascii), TransferType::Ascii);
    }
}
