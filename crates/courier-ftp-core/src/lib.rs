//! Domain logic for courier-ftp, a terminal FTP, FTPS and SFTP client.
//!
//! Everything here is UI-agnostic: the `courier-ftp` binary owns rendering, key
//! handling and the event loop, and the protocol crates (`courier-ftp-proto-ftp`,
//! `courier-ftp-proto-sftp`) implement the [`backend`] trait defined here. This
//! crate owns the domain model and the rules that govern it, so it can be unit
//! tested without a terminal or a server.
//!
//! This crate never depends on `ratatui`, `crossterm` or `clap`.

mod error;

pub mod backend;
pub mod cache;
pub mod compare;
pub mod events;
pub mod filters;
pub mod listing;
pub mod local;
pub mod model;
pub mod net;
pub mod queue;
pub mod search;
pub mod settings;
pub mod sites;
pub mod transfer;
pub mod vault;

pub use error::{Error, Result};
