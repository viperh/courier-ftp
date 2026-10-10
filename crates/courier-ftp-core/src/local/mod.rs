//! The local filesystem as a [`Backend`] (T06), so the local pane shares one
//! code path with remote panes: file lists, search, filters, comparison and
//! recursive operations.
//!
//! The backend speaks [`RemotePath`]s like every other backend; [`paths`]
//! maps them to native paths (identity on Unix, drive letters, UNC paths and a
//! virtual drive-list root on Windows). The UI shows paths with
//! [`display_native`].

mod paths;
mod sanitize;

use std::{
    collections::HashMap,
    fs::{self, Metadata},
    io::SeekFrom,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};

use async_trait::async_trait;
pub use paths::{display_native, local_to_remote, remote_to_local};
pub use sanitize::{NameRules, sanitize_local_name, sanitize_name};
use time::OffsetDateTime;
use tokio::io::AsyncSeekExt;
use tokio_util::sync::CancellationToken;

use crate::{
    Error, Result,
    backend::{Backend, Capabilities, Listing, ReadStream, TransferOpts, WriteMode, WriteStream},
    model::{
        Entry, EntryKind, LocalPath, Permissions, Precision, RemotePath, ServerAddress, Timestamp,
    },
};

/// Bytes free for the current user on the filesystem holding `path` (for
/// preallocation warnings, T42).
pub fn available_space(path: &LocalPath) -> Result<u64> {
    Ok(fs4::available_space(path.as_path())?)
}

/// uid/gid → name, cached across listings.
type NameCache = Arc<Mutex<HashMap<(bool, u32), Option<String>>>>;

/// The local filesystem.
#[derive(Debug, Default)]
pub struct LocalBackend {
    connected: bool,
    names: NameCache,
}

impl LocalBackend {
    /// A local backend. "Connecting" it always succeeds.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Map an I/O error on `path` to the shared error vocabulary.
fn io_error(err: std::io::Error, path: &RemotePath) -> Error {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::NotFound => Error::NotFound(path.clone()),
        ErrorKind::PermissionDenied => Error::PermissionDenied,
        ErrorKind::AlreadyExists => Error::AlreadyExists,
        _ => Error::Io(err),
    }
}

/// The native path, or an error for the virtual root.
fn native(path: &RemotePath) -> Result<PathBuf> {
    remote_to_local(path).ok_or(Error::PermissionDenied)
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))?
}

fn kind_of(meta: &Metadata) -> EntryKind {
    let ft = meta.file_type();
    if ft.is_dir() {
        EntryKind::Dir
    } else if ft.is_file() {
        EntryKind::File
    } else if ft.is_symlink() {
        EntryKind::Symlink {
            target: None,
            target_kind: None,
        }
    } else {
        EntryKind::Other
    }
}

fn entry_from(name: String, path: &Path, meta: &Metadata, names: &NameCache) -> Entry {
    let mut entry = Entry::new(name, kind_of(meta));
    let mut size_meta = meta;
    let target_meta;
    if let EntryKind::Symlink {
        target,
        target_kind,
    } = &mut entry.kind
    {
        *target = fs::read_link(path)
            .ok()
            .map(|t| t.to_string_lossy().into_owned());
        if let Ok(m) = fs::metadata(path) {
            target_meta = m;
            *target_kind = Some(Box::new(kind_of(&target_meta)));
            size_meta = &target_meta;
        }
    }
    if size_meta.is_file() {
        entry.size = Some(size_meta.len());
    }
    entry.modified = meta
        .modified()
        .ok()
        .map(|t| Timestamp::new(OffsetDateTime::from(t), Precision::Millis));
    fill_platform(&mut entry, meta, names);
    entry
}

#[cfg(unix)]
fn fill_platform(entry: &mut Entry, meta: &Metadata, names: &NameCache) {
    use std::os::unix::fs::MetadataExt;
    entry.permissions = Some(Permissions::from_mode(meta.mode()));
    let mut cache = names.lock().unwrap_or_else(|e| e.into_inner());
    let mut lookup = |group: bool, id: u32| -> String {
        cache
            .entry((group, id))
            .or_insert_with(|| {
                if group {
                    uzers::get_group_by_gid(id).map(|g| g.name().to_string_lossy().into_owned())
                } else {
                    uzers::get_user_by_uid(id).map(|u| u.name().to_string_lossy().into_owned())
                }
            })
            .clone()
            .unwrap_or_else(|| id.to_string())
    };
    entry.owner = Some(lookup(false, meta.uid()));
    entry.group = Some(lookup(true, meta.gid()));
}

#[cfg(windows)]
fn fill_platform(entry: &mut Entry, meta: &Metadata, _names: &NameCache) {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    let readonly = meta.permissions().readonly();
    let kind_bits = if meta.is_dir() { 0o040_000 } else { 0o100_000 };
    let perm_bits = if readonly { 0o444 } else { 0o644 };
    entry.permissions = Some(Permissions {
        mode: Some(kind_bits | perm_bits),
        raw: Some(if readonly { "R" } else { "" }.to_owned()),
    });
    entry.hidden = meta.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0;
}

#[cfg(not(any(unix, windows)))]
fn fill_platform(_: &mut Entry, _: &Metadata, _: &NameCache) {}

fn list_dir(dir: &RemotePath, names: &NameCache, cancel: &CancellationToken) -> Result<Vec<Entry>> {
    let Some(native_dir) = remote_to_local(dir) else {
        return Ok(drives());
    };
    let read = fs::read_dir(&native_dir).map_err(|e| io_error(e, dir))?;
    let mut entries = Vec::new();
    for item in read {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let Ok(item) = item else { continue };
        let name = item.file_name().to_string_lossy().into_owned();
        let path = item.path();
        match fs::symlink_metadata(&path) {
            Ok(meta) => entries.push(entry_from(name, &path, &meta, names)),
            // Vanished or unreadable: still show it, without details.
            Err(_) => entries.push(Entry::new(name, EntryKind::Other)),
        }
    }
    Ok(entries)
}

/// The drives that exist, as directory entries of the virtual root (Windows).
fn drives() -> Vec<Entry> {
    (b'A'..=b'Z')
        .map(|d| format!("{}:", d as char))
        .filter(|d| Path::new(&format!(r"{d}\")).exists())
        .map(Entry::dir)
        .collect()
}

#[async_trait]
impl Backend for LocalBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            chmod: cfg!(unix),
            set_mtime: true,
            resume_download: true,
            resume_upload: true,
            append: true,
            raw_commands: false,
            symlinks: true,
            server_side_rename_across_dirs: true,
            ascii_mode: false,
            parallel_connections_allowed: true,
        }
    }

    fn address(&self) -> Option<&ServerAddress> {
        None
    }

    async fn connect(&mut self, _cancel: CancellationToken) -> Result<()> {
        self.connected = true;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    async fn home_dir(&mut self) -> Result<RemotePath> {
        match std::env::home_dir() {
            Some(home) => local_to_remote(&home),
            None => Ok(RemotePath::root()),
        }
    }

    async fn list(&mut self, dir: &RemotePath, cancel: CancellationToken) -> Result<Listing> {
        let names = Arc::clone(&self.names);
        let d = dir.clone();
        let entries = blocking(move || list_dir(&d, &names, &cancel)).await?;
        Ok(Listing {
            dir: dir.clone(),
            entries,
            fetched_at: Instant::now(),
            raw: None,
        })
    }

    async fn stat(&mut self, path: &RemotePath) -> Result<Entry> {
        let Some(native_path) = remote_to_local(path) else {
            return Ok(Entry::dir("/"));
        };
        let names = Arc::clone(&self.names);
        let p = path.clone();
        blocking(move || {
            let meta = fs::symlink_metadata(&native_path).map_err(|e| io_error(e, &p))?;
            let name = p.file_name().unwrap_or("/").to_owned();
            Ok(entry_from(name, &native_path, &meta, &names))
        })
        .await
    }

    async fn mkdir(&mut self, path: &RemotePath) -> Result<()> {
        tokio::fs::create_dir(native(path)?)
            .await
            .map_err(|e| io_error(e, path))
    }

    async fn rmdir(&mut self, path: &RemotePath) -> Result<()> {
        tokio::fs::remove_dir(native(path)?)
            .await
            .map_err(|e| io_error(e, path))
    }

    async fn remove_file(&mut self, path: &RemotePath) -> Result<()> {
        tokio::fs::remove_file(native(path)?)
            .await
            .map_err(|e| io_error(e, path))
    }

    async fn rename(&mut self, from: &RemotePath, to: &RemotePath) -> Result<()> {
        let (src, dst) = (native(from)?, native(to)?);
        // `rename` silently replaces files on Unix; never overwrite by accident.
        if tokio::fs::symlink_metadata(&dst).await.is_ok() {
            return Err(Error::AlreadyExists);
        }
        tokio::fs::rename(&src, &dst)
            .await
            .map_err(|e| io_error(e, from))
    }

    #[cfg(unix)]
    async fn chmod(&mut self, path: &RemotePath, mode: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(native(path)?, fs::Permissions::from_mode(mode & 0o7777))
            .await
            .map_err(|e| io_error(e, path))
    }

    #[cfg(not(unix))]
    async fn chmod(&mut self, _path: &RemotePath, _mode: u32) -> Result<()> {
        Err(Error::Unsupported("chmod on this platform"))
    }

    async fn set_mtime(&mut self, path: &RemotePath, time: OffsetDateTime) -> Result<()> {
        let native_path = native(path)?;
        let p = path.clone();
        blocking(move || {
            let file = fs::OpenOptions::new()
                .write(true)
                .open(&native_path)
                .or_else(|_| fs::File::open(&native_path))
                .map_err(|e| io_error(e, &p))?;
            file.set_modified(time.into()).map_err(|e| io_error(e, &p))
        })
        .await
    }

    async fn open_read(
        &mut self,
        path: &RemotePath,
        offset: u64,
        _opts: &TransferOpts,
    ) -> Result<ReadStream> {
        let mut file = tokio::fs::File::open(native(path)?)
            .await
            .map_err(|e| io_error(e, path))?;
        if offset > 0 {
            file.seek(SeekFrom::Start(offset))
                .await
                .map_err(|e| io_error(e, path))?;
        }
        Ok(Box::new(file))
    }

    async fn open_write(
        &mut self,
        path: &RemotePath,
        mode: WriteMode,
        _opts: &TransferOpts,
    ) -> Result<WriteStream> {
        let native_path = native(path)?;
        let mut options = tokio::fs::OpenOptions::new();
        match mode {
            WriteMode::Create => options.write(true).create_new(true),
            WriteMode::Truncate => options.write(true).create(true).truncate(true),
            WriteMode::Append => options.append(true).create(true),
            WriteMode::ResumeAt(_) => options.write(true).create(true).truncate(false),
        };
        let mut file = options
            .open(&native_path)
            .await
            .map_err(|e| io_error(e, path))?;
        if let WriteMode::ResumeAt(n) = mode {
            file.set_len(n).await.map_err(|e| io_error(e, path))?;
            file.seek(SeekFrom::Start(n))
                .await
                .map_err(|e| io_error(e, path))?;
        }
        Ok(Box::new(file))
    }

    async fn finish_transfer(&mut self) -> Result<()> {
        Ok(())
    }

    async fn raw_command(&mut self, _cmd: &str) -> Result<String> {
        Err(Error::Unsupported("raw commands on the local filesystem"))
    }

    async fn keepalive(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::backend::conformance;

    fn temp_root() -> (tempfile::TempDir, RemotePath) {
        let dir = tempfile::tempdir().unwrap();
        let root = local_to_remote(&dir.path().canonicalize().unwrap()).unwrap();
        (dir, root)
    }

    #[tokio::test]
    async fn passes_the_conformance_suite() {
        let (_dir, root) = temp_root();
        let mut backend = LocalBackend::new();
        conformance::run(&mut backend, &root).await;
    }

    #[tokio::test]
    async fn mock_passes_the_conformance_suite() {
        let server = crate::backend::MockServer::new();
        server.add_dir("/base");
        let mut backend = server.backend();
        conformance::run(&mut backend, &RemotePath::new("/base")).await;
    }

    #[tokio::test]
    async fn hidden_files_and_owner() {
        let (dir, root) = temp_root();
        fs::write(dir.path().join(".secret"), b"x").unwrap();
        let mut b = LocalBackend::new();
        b.connect(CancellationToken::new()).await.unwrap();
        let listing = b.list(&root, CancellationToken::new()).await.unwrap();
        let e = &listing.entries[0];
        if cfg!(unix) {
            assert!(e.hidden);
            assert!(e.owner.is_some() && e.group.is_some());
        }
        assert_eq!(e.size, Some(1));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_are_resolved() {
        let (dir, root) = temp_root();
        fs::create_dir(dir.path().join("real")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("missing"), dir.path().join("dangling"))
            .unwrap();
        let mut b = LocalBackend::new();
        let listing = b.list(&root, CancellationToken::new()).await.unwrap();
        let get = |n: &str| {
            listing
                .entries
                .iter()
                .find(|e| e.name == n)
                .unwrap()
                .clone()
        };
        assert!(get("link").kind.is_symlink());
        assert!(get("link").is_dir_like());
        assert!(get("dangling").kind.is_symlink());
        assert!(!get("dangling").is_dir_like());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unreadable_dir_is_a_clear_error() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, root) = temp_root();
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let mut b = LocalBackend::new();
        // Still listed in its parent…
        let listing = b.list(&root, CancellationToken::new()).await.unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|e| e.name == "locked" && e.is_dir_like())
        );
        // …and listing it fails with PermissionDenied (unless running as root).
        let result = b
            .list(&root.join("locked").unwrap(), CancellationToken::new())
            .await;
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        if let Err(e) = result {
            assert!(matches!(e, Error::PermissionDenied), "{e:?}");
        }
    }

    #[tokio::test]
    async fn rename_never_overwrites() {
        let (dir, root) = temp_root();
        fs::write(dir.path().join("a"), b"a").unwrap();
        fs::write(dir.path().join("b"), b"b").unwrap();
        let mut b = LocalBackend::new();
        let result = b
            .rename(&root.join("a").unwrap(), &root.join("b").unwrap())
            .await;
        assert!(matches!(result, Err(Error::AlreadyExists)));
        assert_eq!(fs::read(dir.path().join("b")).unwrap(), b"b");
    }

    #[tokio::test]
    async fn free_space_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        assert!(available_space(&LocalPath::new(dir.path())).unwrap() > 0);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_root_lists_drives() {
        let mut b = LocalBackend::new();
        let listing = b
            .list(&RemotePath::root(), CancellationToken::new())
            .await
            .unwrap();
        assert!(
            listing
                .entries
                .iter()
                .any(|e| e.name == "C:" && e.is_dir_like()),
            "{listing:?}"
        );
        let c = b
            .list(&RemotePath::new("/C:"), CancellationToken::new())
            .await
            .unwrap();
        assert!(!c.entries.is_empty());
    }
}
