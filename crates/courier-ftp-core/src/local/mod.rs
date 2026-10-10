//! The local filesystem backend (T06).
//!
//! The local pane uses the same [`Backend`](crate::backend::Backend) trait as remote
//! panes, so file lists, search, filters, comparison, recursive operations and the
//! transfer engine share one code path for both sides. The trait always takes
//! [`RemotePath`]s; [`LocalBackend`] maps them to native paths with [`path_map`] at its
//! boundary (Windows drives become `/C:/…`, UNC shares `/UNC/server/share/…`).
//!
//! Local-only helpers for other tasks: [`sanitize_local_name`] (T42 "replace invalid
//! characters"), [`available_space`] (T41/T42) and [`LocalBackend::canonicalize`]
//! (T43 loop detection).
//!
//! Non-UTF-8 names cannot be represented (every layer uses `String` names): `list`
//! skips them and logs one Status line with the count.

mod backend;
mod owners;
pub mod path_map;
mod sanitize;
mod space;

#[cfg(test)]
mod tests;

use std::io;
use std::path::Path;

pub use backend::LocalBackend;
pub use sanitize::{fuzz_sanitize_local_name, is_valid_local_name, sanitize_local_name};
pub use space::available_space;

use crate::Error;
use crate::model::RemotePath;

/// Maps an I/O error on `path` to the crate error: `NotFound`, `PermissionDenied`
/// (with the native display path), `AlreadyExists`, otherwise `Io`.
pub(crate) fn map_io(err: io::Error, path: &RemotePath) -> Error {
    match err.kind() {
        io::ErrorKind::NotFound => Error::NotFound(path.clone()),
        io::ErrorKind::PermissionDenied => Error::PermissionDenied(
            path_map::to_native(path).map_or_else(|_| path.to_string(), |p| p.to_display()),
        ),
        io::ErrorKind::AlreadyExists => Error::AlreadyExists(path.clone()),
        _ => Error::Io(err),
    }
}

/// [`map_io`] for a native path (falls back to `Io` when it has no trait spelling).
pub(crate) fn map_io_native(err: io::Error, native: &Path) -> Error {
    match path_map::from_native(native) {
        Ok(p) => map_io(err, &p),
        Err(_) => Error::Io(err),
    }
}
