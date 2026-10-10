//! Shared vocabulary every other module uses: paths, directory entries,
//! permissions, timestamps, protocols, server addresses, credentials,
//! charsets (T02) and server identities (host keys, certificates; T69).

mod address;
mod charset;
mod credentials;
mod direction;
mod entry;
mod path;
mod permissions;
mod protocol;
mod server_identity;
mod timestamp;

pub use address::{ServerAddress, ServerUrl};
pub use charset::Charset;
pub use credentials::LogonType;
pub use direction::Direction;
pub use entry::{Entry, EntryKind};
pub use path::{LocalPath, PathStyle, RemotePath};
pub use permissions::Permissions;
pub use protocol::{FtpEncryption, Protocol};
pub use server_identity::{
    CertificateDetails, CertificateInfo, CertificateValidity, HostKeyFingerprint,
};
pub use timestamp::{Precision, Timestamp};
