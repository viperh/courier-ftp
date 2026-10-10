//! Domain logic for courier-ftp: protocol-agnostic file management, transfers, the
//! vault and settings. No terminal, no ratatui/crossterm/clap (checked in CI).
//!
//! The `courier-ftp` binary owns rendering, key handling and the event loop; this
//! crate owns the domain model, the `Backend` trait the protocol crates
//! (`courier-ftp-proto-ftp`, `courier-ftp-proto-sftp`) implement, settings, the
//! vault, sites, the transfer queue and engine, and the file logic (filters,
//! comparison, search, listing cache). Everything here is testable without a TTY.
//! The core never reads the environment: callers pass explicit paths.

pub mod backend; // T03
pub mod bookmarks; // T33
pub mod cache; // T46
pub mod compare; // T48
pub mod edit; // T05 (`Association`, `EditorChoice` data types), T63 (logic)
pub mod error; // T02 (`Error`, `Result`; re-exported at the crate root)
pub mod events; // T04
pub mod filters; // T47
pub mod hardening; // T91 (the only module allowed to use `unsafe`)
pub mod listing; // T13 (shared Unix `ls -l` parser, reused by SFTP longnames)
pub mod local; // T06
pub mod model; // T02, T81 (`model::item`)
pub mod net; // T07
pub mod queue; // T40
pub mod search; // T49
pub mod secret; // T02 (`Secret<T>`, `SecretString`), T30/T91 extend it
pub mod settings; // T05
pub mod sites; // T31, T32
pub mod text; // T20 (`sanitize_server_text`), T75 (`Localizable`, `loc!`)
pub mod transfer; // T41–T44, T41b
pub mod trust; // T12, T21 (`CertTrustStore`, `HostKeyStore`)
pub mod vault; // T30

pub use error::{Error, Result};
