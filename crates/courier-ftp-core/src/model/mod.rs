//! Domain types shared by every crate: remote paths, directory entries,
//! permissions, protocols and server types (T02), and the vault item model
//! (`model::item`, T81).

pub mod charset;
pub mod entry;
pub mod ids; // T81
pub mod item; // T81
pub mod logon;
pub mod path;
pub mod server;
pub mod transfer;

pub use charset::Charset;
pub use entry::{Entry, EntryKind, Permissions, Precision, SymlinkTarget, Timestamp};
pub use logon::{KeySource, LogonKind, LogonType};
pub use path::{LocalPath, PathStyle, RemotePath, ServerTypeOverride};
pub use server::{FtpEncryption, ParsedUrl, Protocol, ServerAddress, ServerIdentity, UrlOptions};
pub use transfer::{Direction, TransferType};
