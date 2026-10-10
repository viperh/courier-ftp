//! The in-process SFTP v3 server engine: requests are answered from a directory on
//! the local disk (a chroot-like virtual root), replies are delayed by the configured
//! latency (a link model: requests are handled on arrival, the reply leaves
//! `per_request_latency` later, so many requests can be in flight), and the knobs
//! inject faults and hostile data.

use std::{
    collections::{HashMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::{Buf, Bytes};
use russh_sftp::protocol::{
    Attrs, Data, ExtendedReply, File as NameEntry, FileAttributes, Handle, Name, OpenFlags, Packet,
    Status, StatusCode, Version,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
    time::Instant,
};

use super::Shared;
use crate::convert::SftpOp;

/// Largest packet the server accepts.
const MAX_PACKET: u32 = 512 * 1024;
/// Largest READ answer (OpenSSH: 255 KiB).
const MAX_READ: u32 = 261_120;

/// What a reply was for (in-flight accounting).
#[derive(Debug, Clone, Copy)]
enum Flight {
    Read(u64),
    Write(u64),
    Other,
}

enum OpenHandle {
    File {
        file: File,
        path: PathBuf,
    },
    Dir {
        names: VecDeque<NameEntry>,
    },
    Synthetic {
        next: u64,
        count: u64,
        longnames: bool,
    },
}

struct Engine {
    root: PathBuf,
    shared: Arc<Shared>,
    handles: HashMap<String, OpenHandle>,
    next_handle: u64,
    reads: u64,
    #[cfg(not(unix))]
    modes: HashMap<PathBuf, u32>,
}

/// Run the server on `stream` (until EOF). Spawns the reader and writer tasks.
pub(super) fn serve<S>(stream: S, root: PathBuf, shared: Arc<Shared>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::unbounded_channel::<(Instant, Bytes, Flight)>();
    let writer_shared = Arc::clone(&shared);
    tokio::spawn(async move {
        while let Some((at, bytes, flight)) = rx.recv().await {
            tokio::time::sleep_until(at).await;
            let ok = wr.write_all(&bytes).await.is_ok();
            writer_shared.landed(flight);
            if !ok {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });
    tokio::spawn(async move {
        let mut engine = Engine {
            root,
            shared,
            handles: HashMap::new(),
            next_handle: 1,
            reads: 0,
            #[cfg(not(unix))]
            modes: HashMap::new(),
        };
        while let Ok(len) = rd.read_u32().await {
            if len == 0 || len > MAX_PACKET {
                break;
            }
            let mut buf = vec![0; len as usize];
            if rd.read_exact(&mut buf).await.is_err() {
                break;
            }
            let mut bytes = Bytes::from(buf);
            let Ok(packet) = Packet::try_from(&mut bytes) else {
                let reply = Packet::error(0, StatusCode::BadMessage);
                if let Ok(b) = Bytes::try_from(reply) {
                    let _ = tx.send((Instant::now(), b, Flight::Other));
                }
                continue;
            };
            let flight = engine.flight(&packet);
            let latency = lock(&engine.shared.knobs).per_request_latency;
            for reply in engine.handle(packet) {
                let Ok(b) = Bytes::try_from(reply) else {
                    continue;
                };
                if tx.send((Instant::now() + latency, b, flight)).is_err() {
                    return;
                }
            }
        }
        lock(&engine.shared.stats).connections_ended += 1;
    });
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Shared {
    fn landed(&self, flight: Flight) {
        let mut s = lock(&self.stats);
        match flight {
            Flight::Read(n) => {
                s.reads_in_flight = s.reads_in_flight.saturating_sub(1);
                s.bytes_in_flight = s.bytes_in_flight.saturating_sub(n);
            }
            Flight::Write(n) => {
                s.writes_in_flight = s.writes_in_flight.saturating_sub(1);
                s.bytes_in_flight = s.bytes_in_flight.saturating_sub(n);
            }
            Flight::Other => {}
        }
    }
}

fn op_of(packet: &Packet) -> Option<(SftpOp, &'static str)> {
    Some(match packet {
        Packet::Init(_) => (SftpOp::Connect, "INIT"),
        Packet::Open(_) => (SftpOp::Open, "OPEN"),
        Packet::Close(_) => (SftpOp::Close, "CLOSE"),
        Packet::Read(_) => (SftpOp::Read, "READ"),
        Packet::Write(_) => (SftpOp::Write, "WRITE"),
        Packet::Lstat(_) => (SftpOp::Stat, "LSTAT"),
        Packet::Fstat(_) => (SftpOp::Stat, "FSTAT"),
        Packet::Stat(_) => (SftpOp::Stat, "STAT"),
        Packet::SetStat(_) => (SftpOp::SetStat, "SETSTAT"),
        Packet::FSetStat(_) => (SftpOp::SetStat, "FSETSTAT"),
        Packet::OpenDir(_) => (SftpOp::List, "OPENDIR"),
        Packet::ReadDir(_) => (SftpOp::List, "READDIR"),
        Packet::Remove(_) => (SftpOp::Remove, "REMOVE"),
        Packet::MkDir(_) => (SftpOp::Mkdir, "MKDIR"),
        Packet::RmDir(_) => (SftpOp::Rmdir, "RMDIR"),
        Packet::RealPath(_) => (SftpOp::RealPath, "REALPATH"),
        Packet::Rename(_) => (SftpOp::Rename, "RENAME"),
        Packet::ReadLink(_) => (SftpOp::ReadLink, "READLINK"),
        Packet::Symlink(_) => (SftpOp::Remove, "SYMLINK"),
        Packet::Extended(e) if e.request == "posix-rename@openssh.com" => {
            (SftpOp::Rename, "EXTENDED")
        }
        Packet::Extended(_) => (SftpOp::Connect, "EXTENDED"),
        _ => return None,
    })
}

fn status(id: u32, code: StatusCode, msg: &str) -> Packet {
    Packet::Status(Status {
        id,
        status_code: code,
        error_message: msg.to_owned(),
        language_tag: "en".to_owned(),
    })
}

fn ok(id: u32) -> Packet {
    status(id, StatusCode::Ok, "Success")
}

fn io_status(id: u32, err: &io::Error) -> Packet {
    let code = match err.kind() {
        io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    };
    let msg = match code {
        StatusCode::NoSuchFile => "No such file".to_owned(),
        StatusCode::PermissionDenied => "Permission denied".to_owned(),
        _ => err.to_string(),
    };
    status(id, code, &msg)
}

/// `/a/./b/../c` → `/a/c` (never above `/`). Relative paths are taken from `/`.
pub fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    format!("/{}", parts.join("/"))
}

fn unix_secs(t: io::Result<SystemTime>) -> Option<u32> {
    t.ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .and_then(|d| u32::try_from(d.as_secs()).ok())
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// An `ls -l` style longname (`-rw-r--r--    1 tester   testers  10 Jan 01  2020 x`).
pub(super) fn longname(name: &str, a: &FileAttributes, owner: &str, group: &str) -> String {
    let mode = a.permissions.unwrap_or(0);
    let t = match mode & 0o170_000 {
        0o040_000 => 'd',
        0o120_000 => 'l',
        0o100_000 => '-',
        _ => '?',
    };
    let mut rwx = String::new();
    for shift in [6, 3, 0] {
        let b = (mode >> shift) & 7;
        rwx.push(if b & 4 != 0 { 'r' } else { '-' });
        rwx.push(if b & 2 != 0 { 'w' } else { '-' });
        rwx.push(if b & 1 != 0 { 'x' } else { '-' });
    }
    let (y, m, d) = civil(i64::from(a.mtime.unwrap_or(0)) / 86_400);
    let month = MONTHS
        .get(usize::try_from(m - 1).unwrap_or(0))
        .copied()
        .unwrap_or("Jan");
    format!(
        "{t}{rwx}    1 {owner:<8} {group:<8} {:>8} {month} {d:>2}  {y} {name}",
        a.size.unwrap_or(0)
    )
}

/// Days since 1970-01-01 → (year, month, day) (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

impl Engine {
    fn flight(&self, packet: &Packet) -> Flight {
        match packet {
            Packet::Read(r) => Flight::Read(u64::from(r.len)),
            Packet::Write(w) => Flight::Write(w.data.len() as u64),
            _ => Flight::Other,
        }
    }

    fn local(&self, path: &str) -> PathBuf {
        let norm = normalize(path);
        let mut p = self.root.clone();
        for c in norm.split('/').filter(|c| !c.is_empty()) {
            p.push(c);
        }
        p
    }

    fn record(&self, packet: &Packet) {
        let Some((_, name)) = op_of(packet) else {
            return;
        };
        let mut s = lock(&self.shared.stats);
        *s.counts.entry(name).or_insert(0) += 1;
        match packet {
            Packet::Read(r) => {
                s.reads_in_flight += 1;
                s.bytes_in_flight += u64::from(r.len);
                s.max_reads_in_flight = s.max_reads_in_flight.max(s.reads_in_flight);
                s.max_read_len = s.max_read_len.max(r.len);
                if s.record {
                    s.reads.push((r.offset, r.len));
                }
            }
            Packet::Write(w) => {
                s.writes_in_flight += 1;
                s.bytes_in_flight += w.data.len() as u64;
                s.max_writes_in_flight = s.max_writes_in_flight.max(s.writes_in_flight);
                s.max_write_len = s.max_write_len.max(w.data.len() as u32);
                if s.record {
                    s.writes.push((w.offset, w.data.len() as u32));
                }
            }
            Packet::Close(c) => s.closed.push(c.handle.clone()),
            Packet::Extended(e) => s.extended.push(e.request.clone()),
            Packet::SetStat(st) => s.setstats.push(st.attrs.clone()),
            _ => {}
        }
        s.max_bytes_in_flight = s.max_bytes_in_flight.max(s.bytes_in_flight);
    }

    /// The one-shot injected failure for `packet`, if any.
    fn injected(&self, packet: &Packet) -> Option<StatusCode> {
        let (op, _) = op_of(packet)?;
        let mut k = lock(&self.shared.knobs);
        match k.fail_next {
            Some((o, code)) if o == op => {
                k.fail_next = None;
                Some(code)
            }
            _ => None,
        }
    }

    fn handle(&mut self, packet: Packet) -> Vec<Packet> {
        self.record(&packet);
        let id = packet.get_request_id();
        if let Some(code) = self.injected(&packet) {
            // Opens still answer with the status only (no handle leaks).
            return vec![status(id, code, &format!("injected {code}"))];
        }
        vec![self.answer(packet, id)]
    }

    fn answer(&mut self, packet: Packet, id: u32) -> Packet {
        match packet {
            Packet::Init(_) => self.version(),
            Packet::Open(o) => self.open(id, &o.filename, o.pflags),
            Packet::Close(c) => match self.handles.remove(&c.handle) {
                Some(_) => ok(id),
                None => status(id, StatusCode::Failure, "invalid handle"),
            },
            Packet::Read(r) => self.read(id, &r.handle, r.offset, r.len),
            Packet::Write(w) => self.write(id, &w.handle, w.offset, &w.data),
            Packet::Lstat(s) => self.stat(id, &s.path, false),
            Packet::Stat(s) => self.stat(id, &s.path, true),
            Packet::Fstat(f) => self.fstat(id, &f.handle),
            Packet::SetStat(s) => self.setstat(id, &s.path, &s.attrs),
            Packet::FSetStat(f) => match self.handles.get(&f.handle) {
                Some(OpenHandle::File { path, .. }) => {
                    let path = path.clone();
                    self.setstat_local(id, &path, &f.attrs)
                }
                _ => status(id, StatusCode::Failure, "invalid handle"),
            },
            Packet::OpenDir(o) => self.opendir(id, &o.path),
            Packet::ReadDir(r) => self.readdir(id, &r.handle),
            Packet::Remove(r) => {
                let p = self.local(&r.filename);
                match fs::symlink_metadata(&p) {
                    Ok(m) if m.is_dir() => status(id, StatusCode::Failure, "Is a directory"),
                    Ok(_) => fs::remove_file(&p).map_or_else(|e| io_status(id, &e), |()| ok(id)),
                    Err(e) => io_status(id, &e),
                }
            }
            Packet::MkDir(m) => {
                let p = self.local(&m.path);
                if fs::symlink_metadata(&p).is_ok() {
                    return status(id, StatusCode::Failure, "File exists");
                }
                fs::create_dir(&p).map_or_else(|e| io_status(id, &e), |()| ok(id))
            }
            Packet::RmDir(r) => {
                let p = self.local(&r.path);
                match fs::read_dir(&p).map(|mut it| it.next().is_some()) {
                    Ok(true) => status(id, StatusCode::Failure, "Directory not empty"),
                    Ok(_) => fs::remove_dir(&p).map_or_else(|e| io_status(id, &e), |()| ok(id)),
                    Err(e) => io_status(id, &e),
                }
            }
            Packet::RealPath(r) => {
                let norm = normalize(&r.path);
                Packet::Name(Name {
                    id,
                    files: vec![NameEntry::dummy(norm)],
                })
            }
            Packet::Rename(r) => {
                let (from, to) = (self.local(&r.oldpath), self.local(&r.newpath));
                if fs::symlink_metadata(&to).is_ok() {
                    return status(id, StatusCode::Failure, "Failure");
                }
                fs::rename(&from, &to).map_or_else(|e| io_status(id, &e), |()| ok(id))
            }
            Packet::ReadLink(r) => match fs::read_link(self.local(&r.path)) {
                Ok(target) => Packet::Name(Name {
                    id,
                    files: vec![NameEntry::dummy(
                        target.to_string_lossy().replace('\\', "/"),
                    )],
                }),
                Err(e) => io_status(id, &e),
            },
            Packet::Symlink(s) => self.symlink(id, &s.linkpath, &s.targetpath),
            Packet::Extended(e) => self.extended(id, &e.request, e.data),
            _ => status(id, StatusCode::OpUnsupported, "unsupported"),
        }
    }

    fn version(&self) -> Packet {
        let k = lock(&self.shared.knobs);
        let mut v = Version::new();
        if k.advertise_posix_rename {
            v.extensions
                .insert("posix-rename@openssh.com".into(), "1".into());
        }
        if k.advertise_limits.is_some() {
            v.extensions.insert("limits@openssh.com".into(), "1".into());
        }
        v.extensions.insert("fsync@openssh.com".into(), "1".into());
        Packet::Version(v)
    }

    fn new_handle(&mut self, h: OpenHandle) -> String {
        let name = format!("h{}", self.next_handle);
        self.next_handle += 1;
        self.handles.insert(name.clone(), h);
        name
    }

    fn open(&mut self, id: u32, path: &str, flags: OpenFlags) -> Packet {
        let p = self.local(path);
        if flags.contains(OpenFlags::CREATE | OpenFlags::EXCLUDE)
            && fs::symlink_metadata(&p).is_ok()
        {
            return status(id, StatusCode::Failure, "Failure");
        }
        if fs::metadata(&p).is_ok_and(|m| m.is_dir()) {
            return status(id, StatusCode::Failure, "Is a directory");
        }
        let opts: OpenOptions = flags.into();
        match opts.open(&p) {
            Ok(file) => {
                let handle = self.new_handle(OpenHandle::File { file, path: p });
                Packet::Handle(Handle { id, handle })
            }
            Err(e) => io_status(id, &e),
        }
    }

    fn read(&mut self, id: u32, handle: &str, offset: u64, len: u32) -> Packet {
        let cap = {
            let k = lock(&self.shared.knobs);
            let mut cap = len.min(MAX_READ);
            if let Some(m) = k.max_read_len {
                cap = cap.min(m);
            }
            if !k.read_caps.is_empty() {
                let i = usize::try_from(self.reads).unwrap_or(0) % k.read_caps.len();
                cap = cap.min(k.read_caps[i].max(1));
            }
            cap
        };
        self.reads += 1;
        let Some(OpenHandle::File { file, .. }) = self.handles.get_mut(handle) else {
            return status(id, StatusCode::Failure, "invalid handle");
        };
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        if offset >= size {
            return status(id, StatusCode::Eof, "End of file");
        }
        let n = u64::from(cap).min(size - offset);
        let mut buf = vec![0; usize::try_from(n).unwrap_or(0)];
        let res = file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| file.read_exact(&mut buf));
        match res {
            Ok(()) => Packet::Data(Data { id, data: buf }),
            Err(e) => io_status(id, &e),
        }
    }

    fn write(&mut self, id: u32, handle: &str, offset: u64, data: &[u8]) -> Packet {
        let Some(OpenHandle::File { file, .. }) = self.handles.get_mut(handle) else {
            return status(id, StatusCode::Failure, "invalid handle");
        };
        let res = file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| file.write_all(data));
        res.map_or_else(|e| io_status(id, &e), |()| ok(id))
    }

    fn attrs_of(&self, path: &Path, meta: &fs::Metadata) -> FileAttributes {
        let ft = meta.file_type();
        let type_bits = if ft.is_symlink() {
            0o120_000
        } else if ft.is_dir() {
            0o040_000
        } else if ft.is_file() {
            0o100_000
        } else {
            0o010_000
        };
        #[cfg(unix)]
        let (perm, uid, gid) = {
            use std::os::unix::fs::MetadataExt;
            let _ = path;
            (meta.mode() & 0o7777, Some(meta.uid()), Some(meta.gid()))
        };
        #[cfg(not(unix))]
        let (perm, uid, gid) = {
            let default = if ft.is_dir() { 0o755 } else { 0o644 };
            (self.modes.get(path).copied().unwrap_or(default), None, None)
        };
        FileAttributes {
            size: Some(meta.len()),
            uid,
            gid,
            permissions: Some(type_bits | perm),
            atime: unix_secs(meta.accessed()),
            mtime: unix_secs(meta.modified()),
            ..FileAttributes::default()
        }
    }

    fn stat(&mut self, id: u32, path: &str, follow: bool) -> Packet {
        let p = self.local(path);
        let meta = if follow {
            fs::metadata(&p)
        } else {
            fs::symlink_metadata(&p)
        };
        match meta {
            Ok(m) => Packet::Attrs(Attrs {
                id,
                attrs: self.attrs_of(&p, &m),
            }),
            Err(e) => io_status(id, &e),
        }
    }

    fn fstat(&mut self, id: u32, handle: &str) -> Packet {
        let Some(OpenHandle::File { file, path }) = self.handles.get(handle) else {
            return status(id, StatusCode::Failure, "invalid handle");
        };
        match file.metadata() {
            Ok(m) => Packet::Attrs(Attrs {
                id,
                attrs: self.attrs_of(path, &m),
            }),
            Err(e) => io_status(id, &e),
        }
    }

    fn setstat(&mut self, id: u32, path: &str, attrs: &FileAttributes) -> Packet {
        let p = self.local(path);
        self.setstat_local(id, &p, attrs)
    }

    fn setstat_local(&mut self, id: u32, p: &Path, attrs: &FileAttributes) -> Packet {
        if let Err(e) = fs::symlink_metadata(p) {
            return io_status(id, &e);
        }
        if let Some(size) = attrs.size {
            let res = OpenOptions::new()
                .write(true)
                .open(p)
                .and_then(|f| f.set_len(size));
            if let Err(e) = res {
                return io_status(id, &e);
            }
        }
        if let Some(mode) = attrs.permissions {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) = fs::set_permissions(p, fs::Permissions::from_mode(mode & 0o7777)) {
                    return io_status(id, &e);
                }
            }
            #[cfg(not(unix))]
            {
                self.modes.insert(p.to_path_buf(), mode & 0o7777);
            }
        }
        if attrs.atime.is_some() || attrs.mtime.is_some() {
            let to_time =
                |s: Option<u32>| s.map(|s| UNIX_EPOCH + Duration::from_secs(u64::from(s)));
            let mut times = fs::FileTimes::new();
            if let Some(a) = to_time(attrs.atime) {
                times = times.set_accessed(a);
            }
            if let Some(m) = to_time(attrs.mtime) {
                times = times.set_modified(m);
            }
            let res = File::options()
                .write(true)
                .open(p)
                .or_else(|_| File::open(p))
                .and_then(|f| f.set_times(times));
            if let Err(e) = res {
                return io_status(id, &e);
            }
        }
        ok(id)
    }

    fn opendir(&mut self, id: u32, path: &str) -> Packet {
        let norm = normalize(path);
        let synthetic = lock(&self.shared.knobs).synthetic_dirs.get(&norm).copied();
        if let Some((count, longnames)) = synthetic {
            let handle = self.new_handle(OpenHandle::Synthetic {
                next: 0,
                count,
                longnames,
            });
            return Packet::Handle(Handle { id, handle });
        }
        let p = self.local(path);
        let rd = match fs::read_dir(&p) {
            Ok(rd) => rd,
            Err(e) => return io_status(id, &e),
        };
        let (owner, group, inject) = {
            let k = lock(&self.shared.knobs);
            (k.owner.clone(), k.group.clone(), k.inject_names.clone())
        };
        let mut names = VecDeque::new();
        for dot in [".", ".."] {
            let a = FileAttributes {
                permissions: Some(0o040_755),
                ..FileAttributes::default()
            };
            names.push_back(NameEntry {
                filename: dot.to_owned(),
                longname: longname(dot, &a, &owner, &group),
                attrs: a,
            });
        }
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let ep = entry.path();
            let Ok(meta) = fs::symlink_metadata(&ep) else {
                continue;
            };
            let a = self.attrs_of(&ep, &meta);
            names.push_back(NameEntry {
                longname: longname(&name, &a, &owner, &group),
                filename: name,
                attrs: a,
            });
        }
        for name in inject {
            let a = FileAttributes {
                size: Some(1),
                permissions: Some(0o100_644),
                mtime: Some(1_600_000_000),
                ..FileAttributes::default()
            };
            names.push_back(NameEntry {
                longname: longname(&name, &a, &owner, &group),
                filename: name,
                attrs: a,
            });
        }
        let handle = self.new_handle(OpenHandle::Dir { names });
        Packet::Handle(Handle { id, handle })
    }

    fn readdir(&mut self, id: u32, handle: &str) -> Packet {
        let (batch, owner, group) = {
            let k = lock(&self.shared.knobs);
            (k.readdir_batch.max(1), k.owner.clone(), k.group.clone())
        };
        match self.handles.get_mut(handle) {
            Some(OpenHandle::Dir { names }) => {
                if names.is_empty() {
                    return status(id, StatusCode::Eof, "End of file");
                }
                let n = batch.min(names.len());
                let files: Vec<NameEntry> = names.drain(..n).collect();
                Packet::Name(Name { id, files })
            }
            Some(OpenHandle::Synthetic {
                next,
                count,
                longnames,
            }) => {
                if *next >= *count {
                    return status(id, StatusCode::Eof, "End of file");
                }
                let end = (*next + batch as u64).min(*count);
                let files = (*next..end)
                    .map(|i| {
                        let name = format!("file-{i:07}");
                        let a = FileAttributes {
                            size: Some(i),
                            uid: Some(1000),
                            gid: Some(1000),
                            permissions: Some(0o100_644),
                            mtime: Some(1_600_000_000),
                            ..FileAttributes::default()
                        };
                        NameEntry {
                            longname: if *longnames {
                                longname(&name, &a, &owner, &group)
                            } else {
                                String::new()
                            },
                            filename: name,
                            attrs: a,
                        }
                    })
                    .collect();
                *next = end;
                Packet::Name(Name { id, files })
            }
            _ => status(id, StatusCode::Failure, "invalid handle"),
        }
    }

    #[cfg(unix)]
    fn symlink(&mut self, id: u32, linkpath: &str, targetpath: &str) -> Packet {
        std::os::unix::fs::symlink(targetpath, self.local(linkpath))
            .map_or_else(|e| io_status(id, &e), |()| ok(id))
    }

    #[cfg(not(unix))]
    fn symlink(&mut self, id: u32, _linkpath: &str, _targetpath: &str) -> Packet {
        status(
            id,
            StatusCode::OpUnsupported,
            "symlinks are not supported here",
        )
    }

    fn extended(&mut self, id: u32, request: &str, data: Vec<u8>) -> Packet {
        match request {
            "posix-rename@openssh.com" if lock(&self.shared.knobs).advertise_posix_rename => {
                let mut b = Bytes::from(data);
                let (Some(from), Some(to)) = (ssh_string(&mut b), ssh_string(&mut b)) else {
                    return status(id, StatusCode::BadMessage, "bad posix-rename");
                };
                fs::rename(self.local(&from), self.local(&to))
                    .map_or_else(|e| io_status(id, &e), |()| ok(id))
            }
            "limits@openssh.com" => {
                let Some(l) = lock(&self.shared.knobs).advertise_limits else {
                    return status(id, StatusCode::OpUnsupported, "unsupported");
                };
                let mut out = Vec::with_capacity(32);
                for v in [
                    l.max_packet_len,
                    l.max_read_len,
                    l.max_write_len,
                    l.max_open_handles,
                ] {
                    out.extend_from_slice(&v.to_be_bytes());
                }
                Packet::ExtendedReply(ExtendedReply { id, data: out })
            }
            _ => status(id, StatusCode::OpUnsupported, "unsupported"),
        }
    }
}

/// One SSH `string` (u32 length + bytes) as UTF-8.
fn ssh_string(b: &mut Bytes) -> Option<String> {
    if b.remaining() < 4 {
        return None;
    }
    let len = usize::try_from(b.get_u32()).ok()?;
    if b.remaining() < len {
        return None;
    }
    let s = b.split_to(len);
    String::from_utf8(s.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_paths() {
        assert_eq!(normalize("/a/./b/../c"), "/a/c");
        assert_eq!(normalize("../../x"), "/x");
        assert_eq!(normalize("."), "/");
        assert_eq!(normalize(""), "/");
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(18_262), (2020, 1, 1));
        assert_eq!(civil(-1), (1969, 12, 31));
    }
}
