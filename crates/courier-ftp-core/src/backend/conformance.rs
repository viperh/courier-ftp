//! A behaviour suite every [`Backend`] must pass (T06; reused against real
//! FTP and SFTP servers by T76). Feature `test-util`.
//!
//! [`run`] works inside `base`, an existing empty directory, and panics with a
//! description of the first step that fails.

use time::macros::datetime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::{Backend, TransferOpts, WriteMode};
use crate::{
    Error, Result,
    model::{EntryKind, Precision, RemotePath, Timestamp},
};

fn ok<T>(result: Result<T>, step: &str) -> T {
    match result {
        Ok(v) => v,
        Err(e) => panic!("conformance: {step}: unexpected error {e:?}"),
    }
}

fn expect_err<T>(result: Result<T>, step: &str, check: impl Fn(&Error) -> bool) {
    match result {
        Err(e) if check(&e) => {}
        Err(e) => panic!("conformance: {step}: unexpected error {e:?}"),
        Ok(_) => panic!("conformance: {step}: succeeded but should have failed"),
    }
}

fn join(dir: &RemotePath, name: &str) -> RemotePath {
    match dir.join(name) {
        Ok(p) => p,
        Err(e) => panic!("conformance: bad test name {name}: {e}"),
    }
}

async fn names(b: &mut dyn Backend, dir: &RemotePath) -> Vec<String> {
    let listing = ok(b.list(dir, CancellationToken::new()).await, "list");
    let mut names: Vec<String> = listing.entries.into_iter().map(|e| e.name).collect();
    names.sort();
    names
}

async fn write(b: &mut dyn Backend, path: &RemotePath, mode: WriteMode, data: &[u8]) {
    let step = format!("write {path} {mode:?}");
    let mut w = ok(
        b.open_write(path, mode, &TransferOpts::default()).await,
        &step,
    );
    if let Err(e) = w.write_all(data).await {
        panic!("conformance: {step}: {e}");
    }
    if let Err(e) = w.shutdown().await {
        panic!("conformance: {step}: shutdown: {e}");
    }
    drop(w);
    ok(b.finish_transfer().await, &step);
}

async fn read(b: &mut dyn Backend, path: &RemotePath, offset: u64) -> Vec<u8> {
    let step = format!("read {path} at {offset}");
    let mut r = ok(
        b.open_read(path, offset, &TransferOpts::default()).await,
        &step,
    );
    let mut data = Vec::new();
    if let Err(e) = r.read_to_end(&mut data).await {
        panic!("conformance: {step}: {e}");
    }
    drop(r);
    ok(b.finish_transfer().await, &step);
    data
}

/// Run the suite in the empty directory `base`.
pub async fn run(b: &mut dyn Backend, base: &RemotePath) {
    if !b.is_connected() {
        ok(b.connect(CancellationToken::new()).await, "connect");
    }
    let caps = b.capabilities();
    assert!(
        names(b, base).await.is_empty(),
        "conformance: base must be empty"
    );

    // Directories.
    let dir = join(base, "dir");
    ok(b.mkdir(&dir).await, "mkdir");
    expect_err(b.mkdir(&dir).await, "mkdir existing", |e| {
        matches!(e, Error::AlreadyExists | Error::Protocol { .. })
    });
    let missing_parent = join(&join(base, "no"), "such");
    expect_err(
        b.mkdir(&missing_parent).await,
        "mkdir without parent",
        |_| true,
    );
    let listing = ok(b.list(base, CancellationToken::new()).await, "list base");
    assert!(
        listing
            .entries
            .iter()
            .any(|e| e.name == "dir" && e.kind == EntryKind::Dir),
        "conformance: dir not listed as a directory: {listing:?}"
    );

    // Writing and reading.
    let a = join(&dir, "a.txt");
    write(b, &a, WriteMode::Create, b"hello world").await;
    let entry = ok(b.stat(&a).await, "stat");
    assert_eq!(entry.size, Some(11), "conformance: size after write");
    assert_eq!(entry.kind, EntryKind::File, "conformance: kind after write");
    assert_eq!(names(b, &dir).await, ["a.txt"]);
    assert_eq!(read(b, &a, 0).await, b"hello world");
    assert_eq!(read(b, &a, 6).await, b"world");

    // Write modes.
    if caps.resume_upload {
        write(b, &a, WriteMode::ResumeAt(5), b" there").await;
        assert_eq!(read(b, &a, 0).await, b"hello there", "conformance: resume");
    }
    if caps.append {
        write(b, &a, WriteMode::Append, b"!").await;
        assert_eq!(read(b, &a, 0).await, b"hello there!", "conformance: append");
    }
    write(b, &a, WriteMode::Truncate, b"x").await;
    assert_eq!(read(b, &a, 0).await, b"x", "conformance: truncate");
    expect_err(
        b.open_write(&a, WriteMode::Create, &TransferOpts::default())
            .await,
        "create existing",
        |e| matches!(e, Error::AlreadyExists),
    );

    // Rename across directories.
    let moved = join(base, "b.txt");
    ok(b.rename(&a, &moved).await, "rename");
    expect_err(b.stat(&a).await, "stat after rename", |e| {
        matches!(e, Error::NotFound(_))
    });
    assert_eq!(read(b, &moved, 0).await, b"x");

    // Metadata.
    if caps.chmod {
        ok(b.chmod(&moved, 0o600).await, "chmod");
        let bits = ok(b.stat(&moved).await, "stat after chmod")
            .permissions
            .and_then(|p| p.bits());
        assert_eq!(bits, Some(0o600), "conformance: chmod");
    }
    if caps.set_mtime {
        let when = datetime!(2001-02-03 04:05:06 UTC);
        ok(b.set_mtime(&moved, when).await, "set_mtime");
        let modified = ok(b.stat(&moved).await, "stat after set_mtime").modified;
        let expected = Timestamp::new(when, Precision::Second);
        assert!(
            modified.is_some_and(|m| m.cmp_coarse(&expected).is_eq()),
            "conformance: set_mtime: got {modified:?}"
        );
    }

    // Removing.
    let inner = join(&dir, "inner");
    write(b, &inner, WriteMode::Create, b"1").await;
    expect_err(b.rmdir(&dir).await, "rmdir non-empty", |_| true);
    ok(b.remove_file(&inner).await, "remove inner");
    ok(b.rmdir(&dir).await, "rmdir");
    ok(b.remove_file(&moved).await, "remove");
    assert!(
        names(b, base).await.is_empty(),
        "conformance: base not empty at the end"
    );
    expect_err(b.stat(&moved).await, "stat missing", |e| {
        matches!(e, Error::NotFound(_))
    });
    expect_err(b.remove_file(&moved).await, "remove missing", |e| {
        matches!(e, Error::NotFound(_))
    });
    expect_err(
        b.list(&dir, CancellationToken::new()).await,
        "list missing",
        |e| matches!(e, Error::NotFound(_)),
    );
}
