//! An SFTP v3 server backed by a local directory, for the in-process tests
//! (served by `ssh::test_server` when `Policy::sftp` is set).
//!
//! It behaves like OpenSSH's `sftp-server` where the backend cares: `RENAME`
//! refuses an existing target, `posix-rename@openssh.com` (optional) replaces
//! it, `OPEN` with `EXCL` fails on an existing file with `SSH_FX_FAILURE`,
//! `READDIR` sends `longname` lines with owner and group names. The directory
//! is the server's `/` (and the home directory).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::HashMap,
    fs::{self, File as FsFile, FileTimes, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use courier_ftp_core::model::Permissions;
use russh_sftp::{
    protocol::{
        Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Packet, Status, StatusCode,
        Version,
    },
    server::{Handler, StatusReply},
};

use super::client::POSIX_RENAME;

/// Owner and group names in `longname` (the attributes carry only ids).
pub(crate) const OWNER: &str = "tester";
pub(crate) const GROUP: &str = "staff";

/// What the `sftp` subsystem serves.
#[derive(Debug, Clone)]
pub(crate) struct SftpRoot {
    pub(crate) root: PathBuf,
    pub(crate) posix_rename: bool,
}

impl SftpRoot {
    pub(crate) fn new(root: &Path, posix_rename: bool) -> Self {
        Self {
            root: root.to_path_buf(),
            posix_rename,
        }
    }

    pub(crate) fn handler(&self) -> FsHandler {
        FsHandler {
            root: self.root.clone(),
            posix_rename: self.posix_rename,
            handles: HashMap::new(),
            next: 0,
            #[cfg(not(unix))]
            modes: HashMap::new(),
        }
    }
}

enum Open {
    File(FsFile, PathBuf),
    Dir(Option<Vec<File>>),
}

pub(crate) struct FsHandler {
    root: PathBuf,
    posix_rename: bool,
    handles: HashMap<String, Open>,
    next: u32,
    /// Permission bits set with chmod, where the filesystem has none.
    #[cfg(not(unix))]
    modes: HashMap<PathBuf, u32>,
}

fn reply(err: io::Error) -> StatusReply {
    let code = match err.kind() {
        io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    };
    StatusReply::new(code).with_message(err.to_string())
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Success".to_owned(),
        language_tag: "en".to_owned(),
    }
}

fn failure() -> StatusReply {
    StatusReply::new(StatusCode::Failure)
}

fn month(m: time::Month) -> &'static str {
    use time::Month::*;
    match m {
        January => "Jan",
        February => "Feb",
        March => "Mar",
        April => "Apr",
        May => "May",
        June => "Jun",
        July => "Jul",
        August => "Aug",
        September => "Sep",
        October => "Oct",
        November => "Nov",
        December => "Dec",
    }
}

/// Two SSH strings (`posix-rename` data).
fn two_strings(data: &[u8]) -> Option<(String, String)> {
    let take = |d: &[u8]| -> Option<(String, usize)> {
        let len = u32::from_be_bytes(d.get(..4)?.try_into().ok()?) as usize;
        let s = d.get(4..4 + len)?;
        Some((String::from_utf8(s.to_vec()).ok()?, 4 + len))
    };
    let (a, used) = take(data)?;
    let (b, _) = take(&data[used..])?;
    Some((a, b))
}

impl FsHandler {
    /// The virtual path components of `path` (relative paths start at `/`).
    fn components(path: &str) -> Vec<String> {
        let mut parts: Vec<String> = Vec::new();
        for c in path.split('/') {
            match c {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                c => parts.push(c.to_owned()),
            }
        }
        parts
    }

    fn real(&self, path: &str) -> PathBuf {
        let mut p = self.root.clone();
        for c in Self::components(path) {
            p.push(c);
        }
        p
    }

    fn handle(&mut self, open: Open) -> String {
        self.next += 1;
        let h = format!("h{}", self.next);
        self.handles.insert(h.clone(), open);
        h
    }

    #[cfg_attr(unix, allow(clippy::unused_self))]
    fn mode_bits(&self, path: &Path, meta: &fs::Metadata) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = path;
            meta.permissions().mode() & 0o7777
        }
        #[cfg(not(unix))]
        {
            if let Some(m) = self.modes.get(path) {
                return *m;
            }
            if meta.is_dir() { 0o755 } else { 0o644 }
        }
    }

    fn attrs(&self, path: &Path, meta: &fs::Metadata) -> FileAttributes {
        let ft = meta.file_type();
        let kind = if ft.is_symlink() {
            0o120_000
        } else if ft.is_dir() {
            0o040_000
        } else if ft.is_file() {
            0o100_000
        } else {
            0o010_000
        };
        let secs = |t: io::Result<std::time::SystemTime>| {
            t.ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
        };
        FileAttributes {
            size: Some(meta.len()),
            uid: Some(1000),
            gid: Some(100),
            permissions: Some(kind | self.mode_bits(path, meta)),
            atime: Some(secs(meta.accessed())),
            mtime: Some(secs(meta.modified())),
            ..FileAttributes::default()
        }
    }

    fn longname(name: &str, attrs: &FileAttributes, link: Option<String>) -> String {
        let mode = attrs.permissions.unwrap_or(0);
        let rwx = Permissions::from_mode(mode)
            .to_rwx_string()
            .unwrap_or_else(|| "----------".to_owned());
        let t =
            time::OffsetDateTime::from_unix_timestamp(i64::from(attrs.mtime.unwrap_or(0))).unwrap();
        let mut line = format!(
            "{rwx}    1 {OWNER}    {GROUP}    {:>8} {} {:>2}  {} {name}",
            attrs.size.unwrap_or(0),
            month(t.month()),
            t.day(),
            t.year()
        );
        if let Some(target) = link {
            line.push_str(" -> ");
            line.push_str(&target);
        }
        line
    }

    fn list(&self, dir: &Path) -> io::Result<Vec<File>> {
        let mut files = Vec::new();
        for e in fs::read_dir(dir)? {
            let e = e?;
            let path = e.path();
            let meta = fs::symlink_metadata(&path)?;
            let name = e.file_name().to_string_lossy().into_owned();
            let attrs = self.attrs(&path, &meta);
            let link = meta
                .file_type()
                .is_symlink()
                .then(|| fs::read_link(&path).ok())
                .flatten()
                .map(|t| t.to_string_lossy().into_owned());
            files.push(File {
                longname: Self::longname(&name, &attrs, link),
                filename: name,
                attrs,
            });
        }
        Ok(files)
    }

    fn apply(
        &mut self,
        path: &Path,
        file: Option<&FsFile>,
        attrs: &FileAttributes,
    ) -> io::Result<()> {
        let open = || -> io::Result<FsFile> {
            match OpenOptions::new().write(true).open(path) {
                Ok(f) => Ok(f),
                Err(_) => FsFile::open(path),
            }
        };
        if let Some(size) = attrs.size {
            match file {
                Some(f) => f.set_len(size)?,
                None => open()?.set_len(size)?,
            }
        }
        if let Some(mode) = attrs.permissions {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777))?;
            }
            #[cfg(not(unix))]
            {
                self.modes.insert(path.to_path_buf(), mode & 0o7777);
            }
        }
        if let (Some(atime), Some(mtime)) = (attrs.atime, attrs.mtime) {
            let times = FileTimes::new()
                .set_accessed(UNIX_EPOCH + Duration::from_secs(u64::from(atime)))
                .set_modified(UNIX_EPOCH + Duration::from_secs(u64::from(mtime)));
            match file {
                Some(f) => f.set_times(times)?,
                None => open()?.set_times(times)?,
            }
        }
        Ok(())
    }
}

impl Handler for FsHandler {
    type Error = StatusReply;

    fn unimplemented(&self) -> Self::Error {
        StatusReply::new(StatusCode::OpUnsupported)
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        let mut v = Version::new();
        if self.posix_rename {
            v.extensions.insert(POSIX_RENAME.to_owned(), "1".to_owned());
        }
        Ok(v)
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = self.real(&filename);
        let file = OpenOptions::from(pflags).open(&path).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                failure()
            } else {
                reply(e)
            }
        })?;
        let handle = self.handle(Open::File(file, path));
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        match self.handles.remove(&handle) {
            Some(_) => Ok(ok(id)),
            None => Err(failure()),
        }
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let Some(Open::File(file, _)) = self.handles.get_mut(&handle) else {
            return Err(failure());
        };
        file.seek(SeekFrom::Start(offset)).map_err(reply)?;
        let mut data = Vec::new();
        file.take(u64::from(len))
            .read_to_end(&mut data)
            .map_err(reply)?;
        if data.is_empty() {
            return Err(StatusReply::new(StatusCode::Eof));
        }
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let Some(Open::File(file, _)) = self.handles.get_mut(&handle) else {
            return Err(failure());
        };
        file.seek(SeekFrom::Start(offset)).map_err(reply)?;
        file.write_all(&data).map_err(reply)?;
        Ok(ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let real = self.real(&path);
        let meta = fs::symlink_metadata(&real).map_err(reply)?;
        Ok(Attrs {
            id,
            attrs: self.attrs(&real, &meta),
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let real = self.real(&path);
        let meta = fs::metadata(&real).map_err(reply)?;
        Ok(Attrs {
            id,
            attrs: self.attrs(&real, &meta),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let Some(Open::File(file, path)) = self.handles.get(&handle) else {
            return Err(failure());
        };
        let meta = file.metadata().map_err(reply)?;
        Ok(Attrs {
            id,
            attrs: self.attrs(path, &meta),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let real = self.real(&path);
        fs::symlink_metadata(&real).map_err(reply)?;
        self.apply(&real, None, &attrs).map_err(reply)?;
        Ok(ok(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let Some(Open::File(file, path)) = self.handles.remove(&handle) else {
            return Err(failure());
        };
        let result = self.apply(&path, Some(&file), &attrs);
        self.handles.insert(handle, Open::File(file, path));
        result.map_err(reply)?;
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let real = self.real(&path);
        let files = self.list(&real).map_err(reply)?;
        let handle = self.handle(Open::Dir(Some(files)));
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        match self.handles.get_mut(&handle) {
            Some(Open::Dir(files)) => match files.take() {
                Some(files) => Ok(Name { id, files }),
                None => Err(StatusReply::new(StatusCode::Eof)),
            },
            _ => Err(failure()),
        }
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        fs::remove_file(self.real(&filename)).map_err(reply)?;
        Ok(ok(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        fs::create_dir(self.real(&path)).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                failure()
            } else {
                reply(e)
            }
        })?;
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        fs::remove_dir(self.real(&path)).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => reply(e),
            _ => failure(),
        })?;
        Ok(ok(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let virt = format!("/{}", Self::components(&path).join("/"));
        Ok(Name {
            id,
            files: vec![File::dummy(virt)],
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let (from, to) = (self.real(&oldpath), self.real(&newpath));
        fs::symlink_metadata(&from).map_err(reply)?;
        if fs::symlink_metadata(&to).is_ok() {
            return Err(failure());
        }
        fs::rename(from, to).map_err(reply)?;
        Ok(ok(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let target = fs::read_link(self.real(&path)).map_err(reply)?;
        Ok(Name {
            id,
            files: vec![File::dummy(target.to_string_lossy().into_owned())],
        })
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        data: Vec<u8>,
    ) -> Result<Packet, Self::Error> {
        if request != POSIX_RENAME || !self.posix_rename {
            return Err(self.unimplemented());
        }
        let (old, new) =
            two_strings(&data).ok_or_else(|| StatusReply::new(StatusCode::BadMessage))?;
        fs::rename(self.real(&old), self.real(&new)).map_err(reply)?;
        Ok(Packet::Status(ok(id)))
    }
}
