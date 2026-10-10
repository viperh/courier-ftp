//! Integration tests of [`LocalBackend`] in temporary directories (T06).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::path_map::{from_native, to_native};
use super::*;
use crate::Error;
use crate::backend::conformance::ConformanceEnv;
use crate::backend::mock::test_context;
use crate::backend::{Backend, TransferEnd, TransferOpts, WriteMode};
use crate::events::{CoreEvent, EventReceiver, LogKind};
use crate::model::{EntryKind, LocalPath, PathStyle, RemotePath, SymlinkTarget};

/// Creates a symlink natively; false when the OS refuses (Windows without developer
/// mode).
fn make_link(target: &Path, link: &Path, dir: bool) -> bool {
    #[cfg(unix)]
    {
        let _ = dir;
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        if dir {
            std::os::windows::fs::symlink_dir(target, link).is_ok()
        } else {
            std::os::windows::fs::symlink_file(target, link).is_ok()
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link, dir);
        false
    }
}

/// The conformance environment: a fresh temporary directory as scratch.
fn local_env() -> ConformanceEnv {
    let tmp = TempDir::new().unwrap();
    let scratch = from_native(tmp.path()).unwrap();
    // Probe whether this OS lets us create symlinks.
    let probe = tmp.path().join("probe-link");
    let symlinks = make_link(Path::new("probe-target"), &probe, false);
    let _ = std::fs::remove_file(&probe);
    ConformanceEnv {
        scratch,
        make: Box::new(move || {
            // The closure owns the TempDir, so it lives as long as the environment.
            let _keep = &tmp;
            let (ctx, _rx) = test_context();
            Ok(Box::new(LocalBackend::new(ctx)) as Box<dyn Backend>)
        }),
        // NTFS zero-fills the 5 GiB gap of a non-sparse file (see Implementation notes).
        large_files: !cfg!(windows),
        // Windows marks hidden files with an attribute (tested by
        // `hidden_attribute_is_hidden`) and its file API drops trailing spaces.
        skip: if cfg!(windows) {
            vec![
                (
                    "dotfile_is_hidden",
                    "Windows hides by attribute, not by a leading dot",
                ),
                (
                    "names_with_spaces_unicode_and_leading_dash",
                    "Windows strips trailing spaces from file names",
                ),
            ]
        } else {
            Vec::new()
        },
        make_symlink: symlinks.then(|| {
            Box::new(|link: &RemotePath, target: &str| {
                let native = to_native(link)?;
                if make_link(Path::new(target), native.as_path(), false) {
                    Ok(())
                } else {
                    Err(Error::Unsupported("cannot create symlinks".into()))
                }
            }) as crate::backend::conformance::MakeSymlink
        }),
    }
}

crate::backend_conformance_tests!(local_env);

struct Fixture {
    tmp: TempDir,
    root: RemotePath,
    b: LocalBackend,
    rx: EventReceiver,
}

impl Fixture {
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let root = from_native(tmp.path()).unwrap();
        let (ctx, rx) = test_context();
        Self {
            tmp,
            root,
            b: LocalBackend::new(ctx),
            rx,
        }
    }

    fn path(&self, name: &str) -> RemotePath {
        self.root.join_all(name.split('/')).unwrap()
    }

    fn native(&self, name: &str) -> std::path::PathBuf {
        self.tmp.path().join(name)
    }

    async fn write(&mut self, name: &str, mode: WriteMode, data: &[u8]) {
        let p = self.path(name);
        let mut w = self
            .b
            .open_write(&p, mode, &TransferOpts::default())
            .await
            .unwrap();
        w.write_all(data).await.unwrap();
        w.shutdown().await.unwrap();
        drop(w);
        self.b.finish_transfer(TransferEnd::Complete).await.unwrap();
    }

    async fn read(&mut self, name: &str) -> Vec<u8> {
        let p = self.path(name);
        let mut r = self
            .b
            .open_read(&p, 0, &TransferOpts::default())
            .await
            .unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        drop(r);
        self.b.finish_transfer(TransferEnd::Complete).await.unwrap();
        out
    }

    fn status_lines(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(ev) = self.rx.try_recv() {
            if let CoreEvent::Log(m) = ev
                && m.kind == LogKind::Status
            {
                out.push(m.text);
            }
        }
        out
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

#[cfg(unix)]
fn is_root() -> bool {
    uzers::get_current_uid() == 0
}

#[test]
fn capabilities_per_os() {
    let (ctx, _rx) = test_context();
    let b = LocalBackend::new(ctx);
    let c = b.capabilities();
    assert_eq!(c.chmod, cfg!(unix));
    assert!(c.set_mtime && c.resume_download && c.resume_upload && c.append);
    assert!(c.symlinks && c.server_side_rename_across_dirs);
    assert!(c.parallel_connections_allowed && c.positional_writes);
    assert!(!c.raw_commands && !c.ascii_mode);
    assert_eq!(
        c.case_insensitive_names,
        cfg!(any(windows, target_os = "macos"))
    );
    assert_eq!(c.path_style, PathStyle::Unix);
    assert!(b.address().is_none());
    assert!(b.is_connected());
    let info = b.security_info();
    assert!(!info.encrypted);
    assert_eq!(info.summary, "local");
}

#[tokio::test]
async fn raw_command_is_unsupported() {
    let mut f = Fixture::new();
    let res = f.b.raw_command("SITE X").await;
    assert!(
        matches!(&res, Err(Error::Unsupported(m)) if m == "custom commands are not available for local files"),
        "{res:?}"
    );
    f.b.keepalive().await.unwrap();
}

#[tokio::test]
async fn symlink_to_dir_and_dangling_link() {
    let mut f = Fixture::new();
    std::fs::create_dir(f.native("real")).unwrap();
    std::fs::write(f.native("real").join("inner"), b"x").unwrap();
    if !make_link(&f.native("real"), &f.native("dirlink"), true)
        || !make_link(&f.native("missing"), &f.native("dangling"), false)
    {
        eprintln!("symlink_to_dir_and_dangling_link skipped: the OS refuses to create symlinks");
        return;
    }
    let listing = f.b.list(&f.root, CancellationToken::new()).await.unwrap();
    let find = |n: &str| {
        listing
            .entries
            .iter()
            .find(|e| e.name == n)
            .unwrap()
            .clone()
    };
    let dirlink = find("dirlink");
    assert!(
        matches!(
            dirlink.kind,
            EntryKind::Symlink {
                target_kind: Some(SymlinkTarget::Dir),
                target: Some(_)
            }
        ),
        "{dirlink:?}"
    );
    assert!(dirlink.is_dir_like());
    let dangling = find("dangling");
    assert!(
        matches!(
            dangling.kind,
            EntryKind::Symlink {
                target_kind: Some(SymlinkTarget::Broken),
                ..
            }
        ),
        "{dangling:?}"
    );
    // Listing through the link.
    let inner =
        f.b.list(&f.path("dirlink"), CancellationToken::new())
            .await
            .unwrap();
    assert_eq!(inner.entries.len(), 1);
    assert_eq!(inner.entries[0].name, "inner");
    // stat does not follow the final link.
    let st = f.b.stat(&f.path("dirlink")).await.unwrap();
    assert!(matches!(st.kind, EntryKind::Symlink { .. }));
}

#[tokio::test]
async fn remove_symlink_keeps_target() {
    let mut f = Fixture::new();
    std::fs::create_dir(f.native("real")).unwrap();
    std::fs::write(f.native("real").join("inner"), b"x").unwrap();
    std::fs::write(f.native("file"), b"keep").unwrap();
    if !make_link(&f.native("real"), &f.native("dirlink"), true)
        || !make_link(&f.native("file"), &f.native("filelink"), false)
    {
        eprintln!("remove_symlink_keeps_target skipped: the OS refuses to create symlinks");
        return;
    }
    f.b.remove_file(&f.path("dirlink")).await.unwrap();
    f.b.remove_file(&f.path("filelink")).await.unwrap();
    assert!(!f.native("dirlink").exists());
    assert!(!f.native("filelink").exists());
    assert!(f.native("real").join("inner").exists());
    assert_eq!(std::fs::read(f.native("file")).unwrap(), b"keep");
}

#[cfg(unix)]
#[tokio::test]
async fn dotfiles_are_hidden() {
    let mut f = Fixture::new();
    std::fs::write(f.native(".dot"), b"x").unwrap();
    std::fs::create_dir(f.native(".dotdir")).unwrap();
    std::fs::write(f.native("plain"), b"x").unwrap();
    let listing = f.b.list(&f.root, CancellationToken::new()).await.unwrap();
    for e in &listing.entries {
        assert_eq!(e.hidden, e.name.starts_with('.'), "{e:?}");
    }
    assert_eq!(listing.entries.len(), 3);
}

#[cfg(windows)]
#[tokio::test]
async fn hidden_attribute_is_hidden() {
    let mut f = Fixture::new();
    std::fs::write(f.native("secret"), b"x").unwrap();
    std::fs::write(f.native("plain"), b"x").unwrap();
    std::fs::write(f.native(".dot"), b"x").unwrap();
    let status = std::process::Command::new("attrib")
        .arg("+h")
        .arg(f.native("secret"))
        .status()
        .unwrap();
    assert!(status.success());
    let listing = f.b.list(&f.root, CancellationToken::new()).await.unwrap();
    let hidden = |n: &str| listing.entries.iter().find(|e| e.name == n).unwrap().hidden;
    assert!(hidden("secret"));
    assert!(!hidden("plain"));
    // Dotfiles are not hidden on Windows.
    assert!(!hidden(".dot"));
}

#[cfg(unix)]
#[tokio::test]
async fn unreadable_dir_is_permission_denied() {
    use std::os::unix::fs::PermissionsExt;
    if is_root() {
        eprintln!("unreadable_dir_is_permission_denied skipped: running as root");
        return;
    }
    let mut f = Fixture::new();
    std::fs::create_dir(f.native("locked")).unwrap();
    std::fs::set_permissions(f.native("locked"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let res = f.b.list(&f.path("locked"), CancellationToken::new()).await;
    std::fs::set_permissions(f.native("locked"), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(res, Err(Error::PermissionDenied(_))), "{res:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn unsearchable_dir_lists_entries_as_other() {
    use std::os::unix::fs::PermissionsExt;
    if is_root() {
        eprintln!("unsearchable_dir_lists_entries_as_other skipped: running as root");
        return;
    }
    let mut f = Fixture::new();
    std::fs::create_dir(f.native("d")).unwrap();
    std::fs::write(f.native("d").join("a"), b"x").unwrap();
    std::fs::write(f.native("d").join(".b"), b"x").unwrap();
    std::fs::set_permissions(f.native("d"), std::fs::Permissions::from_mode(0o444)).unwrap();
    let res = f.b.list(&f.path("d"), CancellationToken::new()).await;
    std::fs::set_permissions(f.native("d"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut entries = res.unwrap().entries;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(entries.len(), 2);
    for e in &entries {
        assert_eq!(e.kind, EntryKind::Other, "{e:?}");
        assert!(e.size.is_none() && e.modified.is_none() && e.permissions.is_none());
    }
    assert!(entries[0].hidden && !entries[1].hidden);
}

#[cfg(windows)]
#[tokio::test]
async fn virtual_root_lists_system_drive() {
    let mut f = Fixture::new();
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    let start = std::time::Instant::now();
    let listing =
        f.b.list(&RemotePath::root(), CancellationToken::new())
            .await
            .unwrap();
    assert!(start.elapsed() < std::time::Duration::from_millis(1500));
    assert!(
        listing
            .entries
            .iter()
            .any(|e| e.name.eq_ignore_ascii_case(&drive) && e.is_dir()),
        "{:?}",
        listing.entries
    );
    let st = f.b.stat(&RemotePath::root()).await.unwrap();
    assert!(st.is_dir() && st.name == "/");
    let sys = RemotePath::parse(&format!("/{drive}")).unwrap();
    let st = f.b.stat(&sys).await.unwrap();
    assert!(st.is_dir(), "{st:?}");
    let windows = sys.join("Windows").unwrap();
    assert!(
        !f.b.list(&windows, CancellationToken::new())
            .await
            .unwrap()
            .entries
            .is_empty()
    );
    assert!(matches!(
        f.b.mkdir(&RemotePath::parse("/foo").unwrap()).await,
        Err(Error::InvalidInput(_))
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn non_utf8_names_are_skipped_and_reported() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let mut f = Fixture::new();
    let bad = f.tmp.path().join(OsStr::from_bytes(b"bad\xff"));
    if std::fs::write(&bad, b"x").is_err() {
        // APFS rejects non-UTF-8 names.
        eprintln!(
            "non_utf8_names_are_skipped_and_reported skipped: the filesystem refuses the name"
        );
        return;
    }
    std::fs::write(f.native("good"), b"x").unwrap();
    std::fs::write(f.native("also good"), b"x").unwrap();
    f.status_lines();
    let listing = f.b.list(&f.root, CancellationToken::new()).await.unwrap();
    let mut names: Vec<_> = listing.entries.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["also good", "good"]);
    assert_eq!(
        f.status_lines(),
        ["1 entries with names that are not valid UTF-8 are not shown"]
    );
}

#[tokio::test]
async fn listing_metadata_is_mapped() {
    let mut f = Fixture::new();
    f.write("f.bin", WriteMode::Create, &pattern(1234, 1)).await;
    f.b.mkdir(&f.path("sub")).await.unwrap();
    let listing = f.b.list(&f.root, CancellationToken::new()).await.unwrap();
    assert!(listing.raw.is_none());
    assert_eq!(listing.dir, f.root);
    let file = listing.entries.iter().find(|e| e.name == "f.bin").unwrap();
    assert_eq!(file.kind, EntryKind::File);
    assert_eq!(file.size, Some(1234));
    let m = file.modified.unwrap();
    assert_eq!(m.precision, crate::model::Precision::Millis);
    let age = time::OffsetDateTime::now_utc() - m.time;
    assert!(age.abs() < time::Duration::minutes(5), "{m:?}");
    let perms = file.permissions.clone().unwrap();
    assert!(perms.mode.is_some());
    #[cfg(unix)]
    {
        assert!(file.owner.is_some() && file.group.is_some());
    }
    #[cfg(windows)]
    {
        assert_eq!(perms.mode, Some(0o666));
        assert_eq!(perms.raw.as_deref(), Some(""));
    }
    let sub = listing.entries.iter().find(|e| e.name == "sub").unwrap();
    assert!(sub.is_dir() && sub.size.is_none());
}

#[tokio::test]
async fn list_honours_cancellation() {
    let mut f = Fixture::new();
    let token = CancellationToken::new();
    token.cancel();
    let res = f.b.list(&f.root, token).await;
    assert!(matches!(res, Err(Error::Cancelled)), "{res:?}");
}

#[tokio::test]
async fn errors_are_mapped() {
    let mut f = Fixture::new();
    let res = f.b.stat(&f.path("missing")).await;
    assert!(
        matches!(&res, Err(Error::NotFound(p)) if *p == f.path("missing")),
        "{res:?}"
    );
    f.b.mkdir(&f.path("d")).await.unwrap();
    let res = f.b.mkdir(&f.path("d")).await;
    assert!(
        matches!(&res, Err(Error::AlreadyExists(p)) if *p == f.path("d")),
        "{res:?}"
    );
    f.write("d/x", WriteMode::Create, b"x").await;
    let res = f.b.rmdir(&f.path("d")).await;
    assert!(matches!(res, Err(Error::Io(_))), "{res:?}");
    let res =
        f.b.open_write(&f.path("d/x"), WriteMode::Create, &TransferOpts::default())
            .await
            .map(|_| ());
    assert!(matches!(res, Err(Error::AlreadyExists(_))), "{res:?}");
}

#[tokio::test]
async fn rename_replace_and_no_replace() {
    let mut f = Fixture::new();
    f.write("a", WriteMode::Create, b"AAA").await;
    f.write("b", WriteMode::Create, b"BB").await;
    let res = f.b.rename(&f.path("a"), &f.path("b"), false).await;
    assert!(matches!(res, Err(Error::AlreadyExists(_))), "{res:?}");
    f.b.rename(&f.path("a"), &f.path("b"), true).await.unwrap();
    assert_eq!(f.read("b").await, b"AAA");
    // A case-only rename works on case-insensitive filesystems too.
    f.b.rename(&f.path("b"), &f.path("B"), false).await.unwrap();
    assert_eq!(f.read("B").await, b"AAA");
}

#[tokio::test]
async fn resume_at_offset_is_byte_identical() {
    let mut f = Fixture::new();
    let full = pattern(300_000, 7);
    // A partial download of 123 456 bytes plus a few garbage bytes beyond the resume
    // point (they are truncated away).
    let mut partial = full[..123_456].to_vec();
    partial.extend_from_slice(b"garbage");
    std::fs::write(f.native("f"), &partial).unwrap();
    f.write("f", WriteMode::ResumeAt(123_456), &full[123_456..])
        .await;
    assert_eq!(std::fs::read(f.native("f")).unwrap(), full);
    // A ranged read of the middle.
    let mut r =
        f.b.open_read(
            &f.path("f"),
            100_000,
            &TransferOpts {
                range_len: Some(50_000),
                ..TransferOpts::default()
            },
        )
        .await
        .unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).await.unwrap();
    drop(r);
    f.b.finish_transfer(TransferEnd::Complete).await.unwrap();
    assert_eq!(out, full[100_000..150_000]);
    // Reading past the end returns EOF at once.
    let mut r =
        f.b.open_read(&f.path("f"), 10_000_000, &TransferOpts::default())
            .await
            .unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).await.unwrap();
    assert!(out.is_empty());
    drop(r);
    f.b.finish_transfer(TransferEnd::Abort).await.unwrap();
}

#[tokio::test]
async fn write_at_preserves_existing_bytes() {
    let mut f = Fixture::new();
    let mut want = pattern(10_000, 3);
    std::fs::write(f.native("f"), &want).unwrap();
    let patch = pattern(500, 9);
    f.write("f", WriteMode::WriteAt(2_000), &patch).await;
    want[2_000..2_500].copy_from_slice(&patch);
    assert_eq!(std::fs::read(f.native("f")).unwrap(), want);
    // Past the end: a hole of zeros.
    f.write("f", WriteMode::WriteAt(12_000), b"end").await;
    let got = std::fs::read(f.native("f")).unwrap();
    assert_eq!(got.len(), 12_003);
    assert!(got[10_000..12_000].iter().all(|&b| b == 0));
    assert_eq!(&got[12_000..], b"end");
}

#[tokio::test]
async fn resume_offset_beyond_eof_is_invalid_input() {
    let mut f = Fixture::new();
    std::fs::write(f.native("f"), b"short").unwrap();
    let res =
        f.b.open_write(
            &f.path("f"),
            WriteMode::ResumeAt(6),
            &TransferOpts::default(),
        )
        .await
        .map(|_| ());
    assert!(
        matches!(&res, Err(Error::InvalidInput(m)) if m == "resume offset beyond end of file"),
        "{res:?}"
    );
    assert_eq!(std::fs::read(f.native("f")).unwrap(), b"short");
    let res =
        f.b.open_write(
            &f.path("nope"),
            WriteMode::ResumeAt(0),
            &TransferOpts::default(),
        )
        .await
        .map(|_| ());
    assert!(matches!(res, Err(Error::NotFound(_))), "{res:?}");
}

#[tokio::test]
async fn append_and_truncate_modes() {
    let mut f = Fixture::new();
    f.write("f", WriteMode::Append, b"one ").await;
    f.write("f", WriteMode::Append, b"two").await;
    assert_eq!(f.read("f").await, b"one two");
    f.write("f", WriteMode::Truncate, b"3").await;
    assert_eq!(f.read("f").await, b"3");
}

/// Writes `len` bytes in 64 KiB chunks; shuts the stream down unless `abort`.
async fn write_chunks(f: &mut Fixture, name: &str, len: usize, abort: bool) -> usize {
    let p = f.path(name);
    let mut w =
        f.b.open_write(&p, WriteMode::Truncate, &TransferOpts::default())
            .await
            .unwrap();
    let chunk = vec![0x5a_u8; 64 * 1024];
    let mut left = len;
    while left > 0 {
        let n = left.min(chunk.len());
        w.write_all(&chunk[..n]).await.unwrap();
        left -= n;
    }
    w.flush().await.unwrap();
    // Never synced while writing.
    let during = f.b.sync_count();
    assert_eq!(during, 0);
    if abort {
        drop(w);
        f.b.finish_transfer(TransferEnd::Abort).await.unwrap();
    } else {
        w.shutdown().await.unwrap();
        // A second shutdown is a no-op.
        w.shutdown().await.unwrap();
        drop(w);
        f.b.finish_transfer(TransferEnd::Complete).await.unwrap();
    }
    assert_eq!(std::fs::metadata(f.native(name)).unwrap().len(), len as u64);
    f.b.sync_count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_only_at_end_of_large_files() {
    const MIB: usize = 1024 * 1024;
    let mut f = Fixture::new();
    assert_eq!(write_chunks(&mut f, "seven", 7 * MIB, false).await, 0);
    let mut f = Fixture::new();
    assert_eq!(write_chunks(&mut f, "nine", 9 * MIB, false).await, 1);
    let mut f = Fixture::new();
    assert_eq!(write_chunks(&mut f, "aborted", 9 * MIB, true).await, 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn preallocate_keeps_length() {
    use std::os::unix::fs::MetadataExt;
    const HINT: u64 = 10 * 1024 * 1024;
    let mut f = Fixture::new();
    let opts = TransferOpts {
        preallocate_hint: Some(HINT),
        ..TransferOpts::default()
    };
    let w =
        f.b.open_write(&f.path("big"), WriteMode::Create, &opts)
            .await
            .unwrap();
    let meta = std::fs::metadata(f.native("big")).unwrap();
    assert_eq!(meta.len(), 0);
    let allocated = meta.blocks() * 512;
    if allocated < HINT {
        eprintln!(
            "preallocate_keeps_length: the filesystem did not preallocate ({allocated} bytes)"
        );
    }
    drop(w);
    f.b.finish_transfer(TransferEnd::Abort).await.unwrap();
    assert_eq!(std::fs::metadata(f.native("big")).unwrap().len(), 0);
}

#[tokio::test]
async fn available_space_is_positive() {
    let tmp = TempDir::new().unwrap();
    let free = available_space(&LocalPath::new(tmp.path())).await.unwrap();
    assert!(free > 0);
    let missing = available_space(&LocalPath::new(tmp.path().join("nope").join("deeper"))).await;
    assert!(missing.is_err());
}

#[tokio::test]
async fn canonicalize_resolves_symlink_loop_entry() {
    let f = Fixture::new();
    std::fs::create_dir(f.native("a")).unwrap();
    if !make_link(Path::new(".."), &f.native("a").join("loop"), true) {
        eprintln!(
            "canonicalize_resolves_symlink_loop_entry skipped: the OS refuses to create symlinks"
        );
        return;
    }
    let canon_root = f.b.canonicalize(&f.root).await.unwrap();
    let looped = f.root.join_all(["a", "loop"]).unwrap();
    assert_eq!(f.b.canonicalize(&looped).await.unwrap(), canon_root);
    let res = f.b.canonicalize(&f.path("missing")).await;
    assert!(matches!(res, Err(Error::NotFound(_))), "{res:?}");
}

#[tokio::test]
async fn home_dir_and_disconnect_flag() {
    let mut f = Fixture::new();
    let home = f.b.home_dir().await.unwrap();
    assert!(home.as_str().starts_with('/'));
    f.b.disconnect().await.unwrap();
    assert!(!f.b.is_connected());
    f.b.connect(CancellationToken::new()).await.unwrap();
    assert!(f.b.is_connected());
    // No events from connect/disconnect.
    assert!(f.status_lines().is_empty());
}

/// Benchmark (T06): 10 000 files listed in < 300 ms (release build). Run with
/// `cargo test --release -p courier-ftp-core list_10k_entries -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "benchmark"]
async fn list_10k_entries() {
    let mut f = Fixture::new();
    for i in 0..10_000 {
        std::fs::write(f.native(&format!("file-{i:05}")), b"").unwrap();
    }
    let start = std::time::Instant::now();
    let listing = f.b.list(&f.root, CancellationToken::new()).await.unwrap();
    let took = start.elapsed();
    eprintln!(
        "list_10k_entries: {} entries in {took:?}",
        listing.entries.len()
    );
    assert_eq!(listing.entries.len(), 10_000);
    assert!(took < std::time::Duration::from_millis(300), "{took:?}");
}
