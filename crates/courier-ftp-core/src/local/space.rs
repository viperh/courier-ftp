//! Free-space queries (T42 preallocate warning, T41 disk-full handling).

use crate::model::LocalPath;
use crate::{Error, Result};

/// Free bytes available to this user on the volume holding `path` (`fs4::available_space`).
///
/// # Errors
///
/// `NotFound` / `PermissionDenied` (native display path) / `Io` from the OS query.
pub async fn available_space(path: &LocalPath) -> Result<u64> {
    let native = path.as_path().to_path_buf();
    tokio::task::spawn_blocking(move || fs4::available_space(&native).map_err(|e| (e, native)))
        .await
        .map_err(|e| Error::Internal(format!("free-space task failed: {e}")))?
        .map_err(|(e, native)| super::map_io_native(e, &native))
}
