//! The reusable backend conformance suite (feature `test-util`).
//!
//! Every [`Backend`] implementation runs these cases: `MockBackend` here, the local
//! backend in T06, FTP/SFTP against Docker servers in T76. Use
//! [`backend_conformance_tests!`](crate::backend_conformance_tests) to get one
//! `#[tokio::test]` per case:
//!
//! ```ignore
//! courier_ftp_core::backend_conformance_tests!(my_env);          // normal tests
//! courier_ftp_core::backend_conformance_tests!(ignored, my_env); // #[ignore] (Docker)
//! ```
//!
//! Each case runs in a fresh subdirectory `<scratch>/<case>-<8 hex>` and removes it
//! afterwards (best effort). Cases whose capability is false are skipped and reported
//! as skipped (on stderr), not passed.

use std::fmt;

use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::{Backend, TransferEnd, TransferOpts, WriteMode};
use crate::model::{EntryKind, RemotePath, SymlinkTarget};
use crate::{Error, Result};

/// Creates a symlink `link` → `target` on the target system (the [`Backend`] trait has
/// no symlink operation).
pub type MakeSymlink = Box<dyn Fn(&RemotePath, &str) -> Result<()> + Send + Sync>;

/// What a conformance run needs from the backend under test.
pub struct ConformanceEnv {
    /// An existing, empty, writable directory on the target.
    pub scratch: RemotePath,
    /// Creates a new, not yet connected backend for the same target.
    pub make: Box<dyn Fn() -> Result<Box<dyn Backend>> + Send + Sync>,
    /// Run `large_offset_*` cases (needs sparse files on the target).
    pub large_files: bool,
    /// Case names to skip, with the reason printed (e.g. a server quirk).
    pub skip: Vec<(&'static str, &'static str)>,
    /// Creates symlinks for `remove_symlink_keeps_target`; None skips that case.
    pub make_symlink: Option<MakeSymlink>,
}

impl fmt::Debug for ConformanceEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConformanceEnv")
            .field("scratch", &self.scratch)
            .field("large_files", &self.large_files)
            .field("skip", &self.skip)
            .field("make_symlink", &self.make_symlink.is_some())
            .finish_non_exhaustive()
    }
}

/// Result of one case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaseOutcome {
    /// The case ran and passed.
    Passed,
    /// The case did not run (capability missing, listed in `skip`, …).
    Skipped(String),
}

/// Every case name.
pub const CASES: &[&str] = &[
    "home_dir_is_absolute",
    "scratch_starts_empty",
    "mkdir_then_list_shows_dir",
    "mkdir_existing_is_already_exists",
    "mkdir_missing_parent_fails",
    "write_then_read_roundtrip_1mib",
    "write_empty_file",
    "stat_file_reports_size_and_kind",
    "stat_missing_is_not_found",
    "list_missing_dir_is_not_found",
    "names_with_spaces_unicode_and_leading_dash",
    "dotfile_is_hidden",
    "rename_in_same_dir",
    "rename_across_dirs",
    "rename_without_replace_fails_if_target_exists",
    "rename_with_replace_overwrites",
    "remove_file_then_stat_not_found",
    "remove_symlink_keeps_target",
    "rmdir_empty_dir",
    "rmdir_non_empty_fails",
    "read_from_offset",
    "read_range_len_stops_at_length",
    "abort_read_midway_leaves_session_usable",
    "resume_write_at_offset",
    "append_write",
    "write_at_offset_keeps_existing_bytes",
    "ops_rejected_while_stream_open",
    "chmod_roundtrip",
    "set_mtime_roundtrip",
    "large_offset_resume_beyond_4gib",
    "second_session_sees_changes",
    "keepalive_ok",
    "disconnect_then_connect_again",
];

/// Runs one case. A skipped case prints `conformance case <name> skipped: <reason>` on
/// stderr and returns Ok.
///
/// # Errors
///
/// The first failed expectation (`Error::Internal` with a description) or the
/// backend's own error; `InvalidInput` for an unknown case name.
pub async fn run_case(name: &str, env: &ConformanceEnv) -> Result<()> {
    if let CaseOutcome::Skipped(reason) = run_case_outcome(name, env).await? {
        eprintln!("conformance case {name} skipped: {reason}");
    }
    Ok(())
}

/// As [`run_case`], returning whether the case ran.
///
/// # Errors
///
/// As [`run_case`].
pub async fn run_case_outcome(name: &str, env: &ConformanceEnv) -> Result<CaseOutcome> {
    if !CASES.contains(&name) {
        return Err(Error::InvalidInput(format!(
            "unknown conformance case {name}"
        )));
    }
    if let Some((_, reason)) = env.skip.iter().find(|(n, _)| *n == name) {
        return Ok(CaseOutcome::Skipped((*reason).to_owned()));
    }
    let mut b = (env.make)()?;
    b.connect(CancellationToken::new()).await?;
    let hex = uuid::Uuid::new_v4().simple().to_string();
    let dir = env.scratch.join(&format!("{name}-{}", &hex[..8]))?;
    b.mkdir(&dir).await?;
    let mut cx = Cx { env, b, dir };
    let result = dispatch(name, &mut cx).await;
    // Best-effort cleanup.
    if !cx.b.is_connected() {
        let _ = cx.b.connect(CancellationToken::new()).await;
    }
    let _ = remove_tree(cx.b.as_mut(), &cx.dir).await;
    let _ = cx.b.disconnect().await;
    result
}

struct Cx<'a> {
    env: &'a ConformanceEnv,
    b: Box<dyn Backend>,
    dir: RemotePath,
}

impl Cx<'_> {
    fn path(&self, name: &str) -> Result<RemotePath> {
        self.dir.join(name)
    }
}

type Outcome = Result<CaseOutcome>;

fn skipped(reason: &str) -> Outcome {
    Ok(CaseOutcome::Skipped(reason.to_owned()))
}

async fn dispatch(name: &str, cx: &mut Cx<'_>) -> Outcome {
    match name {
        "home_dir_is_absolute" => home_dir_is_absolute(cx).await,
        "scratch_starts_empty" => scratch_starts_empty(cx).await,
        "mkdir_then_list_shows_dir" => mkdir_then_list_shows_dir(cx).await,
        "mkdir_existing_is_already_exists" => mkdir_existing_is_already_exists(cx).await,
        "mkdir_missing_parent_fails" => mkdir_missing_parent_fails(cx).await,
        "write_then_read_roundtrip_1mib" => write_then_read_roundtrip_1mib(cx).await,
        "write_empty_file" => write_empty_file(cx).await,
        "stat_file_reports_size_and_kind" => stat_file_reports_size_and_kind(cx).await,
        "stat_missing_is_not_found" => stat_missing_is_not_found(cx).await,
        "list_missing_dir_is_not_found" => list_missing_dir_is_not_found(cx).await,
        "names_with_spaces_unicode_and_leading_dash" => {
            names_with_spaces_unicode_and_leading_dash(cx).await
        }
        "dotfile_is_hidden" => dotfile_is_hidden(cx).await,
        "rename_in_same_dir" => rename_in_same_dir(cx).await,
        "rename_across_dirs" => rename_across_dirs(cx).await,
        "rename_without_replace_fails_if_target_exists" => {
            rename_without_replace_fails_if_target_exists(cx).await
        }
        "rename_with_replace_overwrites" => rename_with_replace_overwrites(cx).await,
        "remove_file_then_stat_not_found" => remove_file_then_stat_not_found(cx).await,
        "remove_symlink_keeps_target" => remove_symlink_keeps_target(cx).await,
        "rmdir_empty_dir" => rmdir_empty_dir(cx).await,
        "rmdir_non_empty_fails" => rmdir_non_empty_fails(cx).await,
        "read_from_offset" => read_from_offset(cx).await,
        "read_range_len_stops_at_length" => read_range_len_stops_at_length(cx).await,
        "abort_read_midway_leaves_session_usable" => {
            abort_read_midway_leaves_session_usable(cx).await
        }
        "resume_write_at_offset" => resume_write_at_offset(cx).await,
        "append_write" => append_write(cx).await,
        "write_at_offset_keeps_existing_bytes" => write_at_offset_keeps_existing_bytes(cx).await,
        "ops_rejected_while_stream_open" => ops_rejected_while_stream_open(cx).await,
        "chmod_roundtrip" => chmod_roundtrip(cx).await,
        "set_mtime_roundtrip" => set_mtime_roundtrip(cx).await,
        "large_offset_resume_beyond_4gib" => large_offset_resume_beyond_4gib(cx).await,
        "second_session_sees_changes" => second_session_sees_changes(cx).await,
        "keepalive_ok" => keepalive_ok(cx).await,
        "disconnect_then_connect_again" => disconnect_then_connect_again(cx).await,
        other => Err(Error::InvalidInput(format!(
            "unknown conformance case {other}"
        ))),
    }
}

// ---------------------------------------------------------------- helpers

fn check(cond: bool, what: impl FnOnce() -> String) -> Result<()> {
    if cond {
        Ok(())
    } else {
        Err(Error::Internal(format!("conformance: {}", what())))
    }
}

fn expect_err<T: fmt::Debug>(
    res: Result<T>,
    what: &str,
    pred: impl FnOnce(&Error) -> bool,
) -> Result<()> {
    match res {
        Err(e) if pred(&e) => Ok(()),
        other => Err(Error::Internal(format!(
            "conformance: {what}: unexpected result {other:?}"
        ))),
    }
}

/// Deterministic pseudo-random bytes.
fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

async fn write_with(
    b: &mut dyn Backend,
    path: &RemotePath,
    mode: WriteMode,
    data: &[u8],
) -> Result<()> {
    let mut w = b.open_write(path, mode, &TransferOpts::default()).await?;
    let io = async {
        w.write_all(data).await?;
        w.shutdown().await
    }
    .await;
    drop(w);
    if let Err(e) = io {
        let _ = b.finish_transfer(TransferEnd::Abort).await;
        return Err(e.into());
    }
    b.finish_transfer(TransferEnd::Complete).await
}

async fn write(b: &mut dyn Backend, path: &RemotePath, data: &[u8]) -> Result<()> {
    write_with(b, path, WriteMode::Truncate, data).await
}

async fn read_with(
    b: &mut dyn Backend,
    path: &RemotePath,
    offset: u64,
    range_len: Option<u64>,
) -> Result<Vec<u8>> {
    let opts = TransferOpts {
        range_len,
        ..TransferOpts::default()
    };
    let mut r = b.open_read(path, offset, &opts).await?;
    let mut out = Vec::new();
    let io = r.read_to_end(&mut out).await;
    drop(r);
    if let Err(e) = io {
        let _ = b.finish_transfer(TransferEnd::Abort).await;
        return Err(e.into());
    }
    b.finish_transfer(TransferEnd::Complete).await?;
    Ok(out)
}

async fn read(b: &mut dyn Backend, path: &RemotePath) -> Result<Vec<u8>> {
    read_with(b, path, 0, None).await
}

async fn names(b: &mut dyn Backend, dir: &RemotePath) -> Result<Vec<String>> {
    let listing = b.list(dir, CancellationToken::new()).await?;
    let mut names: Vec<String> = listing.entries.into_iter().map(|e| e.name).collect();
    names.sort();
    Ok(names)
}

async fn exists(b: &mut dyn Backend, path: &RemotePath) -> Result<bool> {
    match b.stat(path).await {
        Ok(_) => Ok(true),
        Err(Error::NotFound(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

async fn remove_tree(b: &mut dyn Backend, dir: &RemotePath) -> Result<()> {
    let listing = b.list(dir, CancellationToken::new()).await?;
    for e in listing.entries {
        let p = dir.join(&e.name)?;
        if e.kind == EntryKind::Dir {
            Box::pin(remove_tree(b, &p)).await?;
        } else {
            b.remove_file(&p).await?;
        }
    }
    b.rmdir(dir).await
}

// ---------------------------------------------------------------- cases

async fn home_dir_is_absolute(cx: &mut Cx<'_>) -> Outcome {
    let home = cx.b.home_dir().await?;
    check(home.as_str().starts_with('/'), || {
        format!("home dir {home} is not absolute")
    })?;
    let listing = cx.b.list(&home, CancellationToken::new()).await;
    check(listing.is_ok(), || {
        format!("home dir not listable: {listing:?}")
    })?;
    Ok(CaseOutcome::Passed)
}

async fn scratch_starts_empty(cx: &mut Cx<'_>) -> Outcome {
    let entries = names(cx.b.as_mut(), &cx.dir.clone()).await?;
    check(entries.is_empty(), || {
        format!("fresh case dir not empty: {entries:?}")
    })?;
    let scratch = names(cx.b.as_mut(), &cx.env.scratch).await?;
    let own = cx.dir.file_name().unwrap_or_default().to_owned();
    check(scratch.contains(&own), || {
        format!("scratch listing {scratch:?} lacks {own}")
    })?;
    Ok(CaseOutcome::Passed)
}

async fn mkdir_then_list_shows_dir(cx: &mut Cx<'_>) -> Outcome {
    let sub = cx.path("sub")?;
    cx.b.mkdir(&sub).await?;
    let listing = cx.b.list(&cx.dir, CancellationToken::new()).await?;
    let found = listing.entries.iter().find(|e| e.name == "sub");
    check(found.is_some_and(|e| e.is_dir()), || {
        format!("listing lacks dir sub: {:?}", listing.entries)
    })?;
    check(listing.dir == cx.dir, || "listing.dir differs".into())?;
    Ok(CaseOutcome::Passed)
}

async fn mkdir_existing_is_already_exists(cx: &mut Cx<'_>) -> Outcome {
    let sub = cx.path("sub")?;
    cx.b.mkdir(&sub).await?;
    let res = cx.b.mkdir(&sub).await;
    expect_err(res, "mkdir of an existing dir", |e| {
        matches!(e, Error::AlreadyExists(_))
    })?;
    Ok(CaseOutcome::Passed)
}

async fn mkdir_missing_parent_fails(cx: &mut Cx<'_>) -> Outcome {
    let deep = cx.dir.join_all(["missing", "child"])?;
    let res = cx.b.mkdir(&deep).await;
    expect_err(res, "mkdir with a missing parent", |_| true)?;
    let missing = cx.path("missing")?;
    check(!exists(cx.b.as_mut(), &missing).await?, || {
        "mkdir created the missing parent".into()
    })?;
    Ok(CaseOutcome::Passed)
}

async fn write_then_read_roundtrip_1mib(cx: &mut Cx<'_>) -> Outcome {
    let data = pattern(1024 * 1024, 1);
    let p = cx.path("one-mib.bin")?;
    write_with(cx.b.as_mut(), &p, WriteMode::Create, &data).await?;
    let back = read(cx.b.as_mut(), &p).await?;
    check(back == data, || {
        format!("read {} bytes, contents differ", back.len())
    })?;
    Ok(CaseOutcome::Passed)
}

async fn write_empty_file(cx: &mut Cx<'_>) -> Outcome {
    let p = cx.path("empty")?;
    write_with(cx.b.as_mut(), &p, WriteMode::Create, &[]).await?;
    let e = cx.b.stat(&p).await?;
    check(e.kind == EntryKind::File && e.size == Some(0), || {
        format!("stat of empty file: {e:?}")
    })?;
    check(read(cx.b.as_mut(), &p).await?.is_empty(), || {
        "empty file read back non-empty".into()
    })?;
    Ok(CaseOutcome::Passed)
}

async fn stat_file_reports_size_and_kind(cx: &mut Cx<'_>) -> Outcome {
    let p = cx.path("f.txt")?;
    write(cx.b.as_mut(), &p, &pattern(1234, 2)).await?;
    let e = cx.b.stat(&p).await?;
    check(
        e.name == "f.txt" && e.kind == EntryKind::File && e.size == Some(1234),
        || format!("stat: {e:?}"),
    )?;
    let d = cx.b.stat(&cx.dir).await?;
    check(d.is_dir(), || format!("stat of a dir: {d:?}"))?;
    Ok(CaseOutcome::Passed)
}

async fn stat_missing_is_not_found(cx: &mut Cx<'_>) -> Outcome {
    let res = cx.b.stat(&cx.path("nope")?).await;
    expect_err(res, "stat of a missing path", |e| {
        matches!(e, Error::NotFound(_))
    })?;
    Ok(CaseOutcome::Passed)
}

async fn list_missing_dir_is_not_found(cx: &mut Cx<'_>) -> Outcome {
    let res = cx.b.list(&cx.path("nope")?, CancellationToken::new()).await;
    expect_err(res, "list of a missing dir", |e| {
        matches!(e, Error::NotFound(_))
    })?;
    Ok(CaseOutcome::Passed)
}

async fn names_with_spaces_unicode_and_leading_dash(cx: &mut Cx<'_>) -> Outcome {
    let tricky = [" a", "b ", "ü ñ 日本", "-rf", "#x", "a;b"];
    for name in tricky {
        let p = cx.path(name)?;
        write(cx.b.as_mut(), &p, name.as_bytes()).await?;
    }
    let listed = names(cx.b.as_mut(), &cx.dir.clone()).await?;
    let mut want: Vec<String> = tricky.iter().map(|s| (*s).to_owned()).collect();
    want.sort();
    check(listed == want, || {
        format!("listed {listed:?}, want {want:?}")
    })?;
    for name in tricky {
        let p = cx.path(name)?;
        let back = read(cx.b.as_mut(), &p).await?;
        check(back == name.as_bytes(), || format!("contents of {name:?}"))?;
    }
    Ok(CaseOutcome::Passed)
}

async fn dotfile_is_hidden(cx: &mut Cx<'_>) -> Outcome {
    let (hidden_path, shown_path) = (cx.path(".hidden")?, cx.path("shown")?);
    write(cx.b.as_mut(), &hidden_path, b"x").await?;
    write(cx.b.as_mut(), &shown_path, b"x").await?;
    let listing = cx.b.list(&cx.dir, CancellationToken::new()).await?;
    let hidden = listing.entries.iter().find(|e| e.name == ".hidden");
    let shown = listing.entries.iter().find(|e| e.name == "shown");
    check(hidden.is_some_and(|e| e.hidden), || {
        format!("dotfile not hidden: {hidden:?}")
    })?;
    check(shown.is_some_and(|e| !e.hidden), || {
        format!("plain file hidden: {shown:?}")
    })?;
    Ok(CaseOutcome::Passed)
}

async fn rename_in_same_dir(cx: &mut Cx<'_>) -> Outcome {
    let (a, b) = (cx.path("a")?, cx.path("b")?);
    write(cx.b.as_mut(), &a, b"hello").await?;
    cx.b.rename(&a, &b, false).await?;
    check(!exists(cx.b.as_mut(), &a).await?, || {
        "source still exists".into()
    })?;
    check(read(cx.b.as_mut(), &b).await? == b"hello", || {
        "renamed contents differ".into()
    })?;
    Ok(CaseOutcome::Passed)
}

async fn rename_across_dirs(cx: &mut Cx<'_>) -> Outcome {
    if !cx.b.capabilities().server_side_rename_across_dirs {
        return skipped("server_side_rename_across_dirs is false");
    }
    let sub = cx.path("sub")?;
    cx.b.mkdir(&sub).await?;
    let a = cx.path("a")?;
    let moved = sub.join("a")?;
    write(cx.b.as_mut(), &a, b"move me").await?;
    cx.b.rename(&a, &moved, false).await?;
    check(!exists(cx.b.as_mut(), &a).await?, || {
        "source still exists".into()
    })?;
    check(read(cx.b.as_mut(), &moved).await? == b"move me", || {
        "moved contents differ".into()
    })?;
    Ok(CaseOutcome::Passed)
}

async fn rename_without_replace_fails_if_target_exists(cx: &mut Cx<'_>) -> Outcome {
    let (a, b) = (cx.path("a")?, cx.path("b")?);
    write(cx.b.as_mut(), &a, b"AAA").await?;
    write(cx.b.as_mut(), &b, b"BB").await?;
    let res = cx.b.rename(&a, &b, false).await;
    expect_err(res, "rename onto an existing file", |e| {
        matches!(e, Error::AlreadyExists(_))
    })?;
    check(read(cx.b.as_mut(), &a).await? == b"AAA", || {
        "source changed".into()
    })?;
    check(read(cx.b.as_mut(), &b).await? == b"BB", || {
        "target changed".into()
    })?;
    Ok(CaseOutcome::Passed)
}

async fn rename_with_replace_overwrites(cx: &mut Cx<'_>) -> Outcome {
    let (a, b) = (cx.path("a")?, cx.path("b")?);
    write(cx.b.as_mut(), &a, b"AAA").await?;
    write(cx.b.as_mut(), &b, b"BB").await?;
    match cx.b.rename(&a, &b, true).await {
        Ok(()) => {
            check(!exists(cx.b.as_mut(), &a).await?, || {
                "source still exists".into()
            })?;
            check(read(cx.b.as_mut(), &b).await? == b"AAA", || {
                "target not overwritten".into()
            })?;
        }
        Err(Error::AlreadyExists(_)) => {
            // A protocol that cannot overwrite must leave both files unchanged.
            check(read(cx.b.as_mut(), &a).await? == b"AAA", || {
                "source changed".into()
            })?;
            check(read(cx.b.as_mut(), &b).await? == b"BB", || {
                "target changed".into()
            })?;
        }
        Err(e) => return Err(e),
    }
    Ok(CaseOutcome::Passed)
}

async fn remove_file_then_stat_not_found(cx: &mut Cx<'_>) -> Outcome {
    let p = cx.path("f")?;
    write(cx.b.as_mut(), &p, b"x").await?;
    cx.b.remove_file(&p).await?;
    let res = cx.b.stat(&p).await;
    expect_err(res, "stat after remove", |e| {
        matches!(e, Error::NotFound(_))
    })?;
    Ok(CaseOutcome::Passed)
}

async fn remove_symlink_keeps_target(cx: &mut Cx<'_>) -> Outcome {
    if !cx.b.capabilities().symlinks {
        return skipped("symlinks is false");
    }
    let Some(make_symlink) = &cx.env.make_symlink else {
        return skipped("the environment cannot create symlinks");
    };
    let target = cx.path("target")?;
    let link = cx.path("link")?;
    write(cx.b.as_mut(), &target, b"keep").await?;
    make_symlink(&link, "target")?;
    let e = cx.b.stat(&link).await?;
    check(
        matches!(
            e.kind,
            EntryKind::Symlink {
                target_kind: Some(SymlinkTarget::File),
                ..
            }
        ),
        || format!("stat of a symlink: {e:?}"),
    )?;
    cx.b.remove_file(&link).await?;
    check(!exists(cx.b.as_mut(), &link).await?, || {
        "link still exists".into()
    })?;
    check(read(cx.b.as_mut(), &target).await? == b"keep", || {
        "target changed".into()
    })?;
    Ok(CaseOutcome::Passed)
}

async fn rmdir_empty_dir(cx: &mut Cx<'_>) -> Outcome {
    let sub = cx.path("sub")?;
    cx.b.mkdir(&sub).await?;
    cx.b.rmdir(&sub).await?;
    check(!exists(cx.b.as_mut(), &sub).await?, || {
        "dir still exists".into()
    })?;
    Ok(CaseOutcome::Passed)
}

async fn rmdir_non_empty_fails(cx: &mut Cx<'_>) -> Outcome {
    let sub = cx.path("sub")?;
    cx.b.mkdir(&sub).await?;
    write(cx.b.as_mut(), &sub.join("f")?, b"x").await?;
    let res = cx.b.rmdir(&sub).await;
    expect_err(res, "rmdir of a non-empty dir", |_| true)?;
    check(exists(cx.b.as_mut(), &sub.join("f")?).await?, || {
        "contents removed".into()
    })?;
    Ok(CaseOutcome::Passed)
}

async fn read_from_offset(cx: &mut Cx<'_>) -> Outcome {
    if !cx.b.capabilities().resume_download {
        return skipped("resume_download is false");
    }
    let data = pattern(10_000, 3);
    let p = cx.path("f")?;
    write(cx.b.as_mut(), &p, &data).await?;
    let back = read_with(cx.b.as_mut(), &p, 4_000, None).await?;
    check(back == data[4_000..], || {
        format!("read {} bytes from offset 4000", back.len())
    })?;
    Ok(CaseOutcome::Passed)
}

async fn read_range_len_stops_at_length(cx: &mut Cx<'_>) -> Outcome {
    let data = pattern(10_000, 4);
    let p = cx.path("f")?;
    write(cx.b.as_mut(), &p, &data).await?;
    let back = read_with(cx.b.as_mut(), &p, 0, Some(100)).await?;
    check(back == data[..100], || {
        format!("range read returned {} bytes", back.len())
    })?;
    if cx.b.capabilities().resume_download {
        let back = read_with(cx.b.as_mut(), &p, 9_950, Some(100)).await?;
        check(back == data[9_950..], || {
            format!("range read at the end returned {} bytes", back.len())
        })?;
    }
    Ok(CaseOutcome::Passed)
}

async fn abort_read_midway_leaves_session_usable(cx: &mut Cx<'_>) -> Outcome {
    let data = pattern(1024 * 1024, 5);
    let p = cx.path("f")?;
    write(cx.b.as_mut(), &p, &data).await?;
    let mut r = cx.b.open_read(&p, 0, &TransferOpts::default()).await?;
    let mut buf = vec![0; 4096];
    r.read_exact(&mut buf).await?;
    drop(r);
    cx.b.finish_transfer(TransferEnd::Abort).await?;
    check(buf == data[..4096], || "first bytes differ".into())?;
    let e = cx.b.stat(&p).await?;
    check(e.size == Some(data.len() as u64), || format!("stat: {e:?}"))?;
    check(read(cx.b.as_mut(), &p).await? == data, || {
        "re-read after abort differs".into()
    })?;
    Ok(CaseOutcome::Passed)
}

async fn resume_write_at_offset(cx: &mut Cx<'_>) -> Outcome {
    if !cx.b.capabilities().resume_upload {
        return skipped("resume_upload is false");
    }
    let p = cx.path("f")?;
    let first = pattern(100, 6);
    let rest = pattern(30, 7);
    write(cx.b.as_mut(), &p, &first).await?;
    write_with(cx.b.as_mut(), &p, WriteMode::ResumeAt(50), &rest).await?;
    let mut want = first[..50].to_vec();
    want.extend_from_slice(&rest);
    check(read(cx.b.as_mut(), &p).await? == want, || {
        "resumed contents differ".into()
    })?;
    Ok(CaseOutcome::Passed)
}

async fn append_write(cx: &mut Cx<'_>) -> Outcome {
    if !cx.b.capabilities().append {
        return skipped("append is false");
    }
    let p = cx.path("f")?;
    write(cx.b.as_mut(), &p, b"hello ").await?;
    write_with(cx.b.as_mut(), &p, WriteMode::Append, b"world").await?;
    check(read(cx.b.as_mut(), &p).await? == b"hello world", || {
        "appended contents differ".into()
    })?;
    Ok(CaseOutcome::Passed)
}

async fn write_at_offset_keeps_existing_bytes(cx: &mut Cx<'_>) -> Outcome {
    if !cx.b.capabilities().positional_writes {
        return skipped("positional_writes is false");
    }
    let p = cx.path("f")?;
    let mut want = pattern(100, 8);
    write(cx.b.as_mut(), &p, &want).await?;
    let patch = pattern(10, 9);
    write_with(cx.b.as_mut(), &p, WriteMode::WriteAt(20), &patch).await?;
    want[20..30].copy_from_slice(&patch);
    check(read(cx.b.as_mut(), &p).await? == want, || {
        "contents after WriteAt differ".into()
    })?;
    // WriteAt creates a missing file.
    let q = cx.path("g")?;
    write_with(cx.b.as_mut(), &q, WriteMode::WriteAt(0), b"new").await?;
    check(read(cx.b.as_mut(), &q).await? == b"new", || {
        "WriteAt(0) on a missing file".into()
    })?;
    Ok(CaseOutcome::Passed)
}

async fn ops_rejected_while_stream_open(cx: &mut Cx<'_>) -> Outcome {
    let p = cx.path("f")?;
    write(cx.b.as_mut(), &p, &pattern(1000, 10)).await?;
    let r = cx.b.open_read(&p, 0, &TransferOpts::default()).await?;
    let busy = |e: &Error| matches!(e, Error::Internal(m) if m.contains("transfer in progress"));
    expect_err(cx.b.stat(&p).await, "stat during a transfer", busy)?;
    expect_err(
        cx.b.list(&cx.dir, CancellationToken::new()).await,
        "list during a transfer",
        busy,
    )?;
    expect_err(
        cx.b.mkdir(&cx.path("d")?).await,
        "mkdir during a transfer",
        busy,
    )?;
    expect_err(
        cx.b.open_read(&p, 0, &TransferOpts::default())
            .await
            .map(|_| ()),
        "second open_read",
        busy,
    )?;
    drop(r);
    cx.b.finish_transfer(TransferEnd::Abort).await?;
    cx.b.stat(&p).await?;
    // A stream dropped without finish_transfer is aborted by the next call.
    let r = cx.b.open_read(&p, 0, &TransferOpts::default()).await?;
    drop(r);
    let e = cx.b.stat(&p).await?;
    check(e.size == Some(1000), || {
        format!("stat after implicit abort: {e:?}")
    })?;
    Ok(CaseOutcome::Passed)
}

async fn chmod_roundtrip(cx: &mut Cx<'_>) -> Outcome {
    if !cx.b.capabilities().chmod {
        return skipped("chmod is false");
    }
    let p = cx.path("f")?;
    write(cx.b.as_mut(), &p, b"x").await?;
    cx.b.chmod(&p, 0o640).await?;
    let e = cx.b.stat(&p).await?;
    let mode = e.permissions.as_ref().and_then(|p| p.mode);
    check(mode.map(|m| m & 0o7777) == Some(0o640), || {
        format!("mode after chmod: {mode:?}")
    })?;
    Ok(CaseOutcome::Passed)
}

async fn set_mtime_roundtrip(cx: &mut Cx<'_>) -> Outcome {
    if !cx.b.capabilities().set_mtime {
        return skipped("set_mtime is false");
    }
    let p = cx.path("f")?;
    write(cx.b.as_mut(), &p, b"x").await?;
    let when = OffsetDateTime::from_unix_timestamp(1_577_934_245)
        .map_err(|e| Error::Internal(e.to_string()))?;
    cx.b.set_mtime(&p, when).await?;
    let e = cx.b.stat(&p).await?;
    let got = e.modified.map(|t| t.time);
    let ok = got.is_some_and(|t| (t - when).abs() <= time::Duration::SECOND);
    check(ok, || {
        format!("mtime after set_mtime: {got:?}, want {when}")
    })?;
    Ok(CaseOutcome::Passed)
}

async fn large_offset_resume_beyond_4gib(cx: &mut Cx<'_>) -> Outcome {
    if !cx.env.large_files {
        return skipped("large_files is false");
    }
    let caps = cx.b.capabilities();
    if !caps.positional_writes || !caps.resume_download {
        return skipped("positional_writes or resume_download is false");
    }
    const OFF: u64 = 5 << 30;
    let p = cx.path("big")?;
    let tail = pattern(10, 11);
    write_with(cx.b.as_mut(), &p, WriteMode::WriteAt(OFF), &tail).await?;
    let e = cx.b.stat(&p).await?;
    check(e.size == Some(OFF + 10), || format!("stat: {e:?}"))?;
    let back = read_with(cx.b.as_mut(), &p, OFF, None).await?;
    check(back == tail, || "bytes beyond 4 GiB differ".into())?;
    if caps.resume_upload {
        write_with(cx.b.as_mut(), &p, WriteMode::ResumeAt(OFF + 5), b"xy").await?;
        let e = cx.b.stat(&p).await?;
        check(e.size == Some(OFF + 7), || {
            format!("stat after resume: {e:?}")
        })?;
    }
    Ok(CaseOutcome::Passed)
}

async fn second_session_sees_changes(cx: &mut Cx<'_>) -> Outcome {
    let mut other = (cx.env.make)()?;
    other.connect(CancellationToken::new()).await?;
    let p = cx.path("shared")?;
    write(cx.b.as_mut(), &p, b"from one").await?;
    let res = async {
        let back = read(other.as_mut(), &p).await?;
        check(back == b"from one", || "second session read differs".into())?;
        let n = names(other.as_mut(), &cx.dir).await?;
        check(n == ["shared"], || format!("second session lists {n:?}"))
    }
    .await;
    let _ = other.disconnect().await;
    res?;
    Ok(CaseOutcome::Passed)
}

async fn keepalive_ok(cx: &mut Cx<'_>) -> Outcome {
    cx.b.keepalive().await?;
    check(cx.b.is_connected(), || {
        "disconnected after keepalive".into()
    })?;
    cx.b.stat(&cx.dir).await?;
    Ok(CaseOutcome::Passed)
}

async fn disconnect_then_connect_again(cx: &mut Cx<'_>) -> Outcome {
    cx.b.disconnect().await?;
    check(!cx.b.is_connected(), || "connected after disconnect".into())?;
    cx.b.connect(CancellationToken::new()).await?;
    check(cx.b.is_connected(), || "not connected after connect".into())?;
    let n = names(cx.b.as_mut(), &cx.dir.clone()).await?;
    check(n.is_empty(), || format!("case dir lists {n:?}"))?;
    Ok(CaseOutcome::Passed)
}

/// Expands to one `#[tokio::test]` per conformance case (module `conformance_cases`),
/// each calling `$env()` to build a [`ConformanceEnv`].
///
/// `backend_conformance_tests!(ignored, env_fn)` adds `#[ignore]` (Docker targets, T76).
/// The calling crate needs `tokio` with the `macros` and `rt` features.
#[macro_export]
macro_rules! backend_conformance_tests {
    (ignored, $env:path) => {
        $crate::backend_conformance_tests!(@expand [#[ignore = "needs the target server (COURIER_E2E=1)"]] $env);
    };
    ($env:path) => {
        $crate::backend_conformance_tests!(@expand [] $env);
    };
    (@expand [$($attr:tt)*] $env:path) => {
        $crate::backend_conformance_tests!(@cases [$($attr)*] $env;
            home_dir_is_absolute,
            scratch_starts_empty,
            mkdir_then_list_shows_dir,
            mkdir_existing_is_already_exists,
            mkdir_missing_parent_fails,
            write_then_read_roundtrip_1mib,
            write_empty_file,
            stat_file_reports_size_and_kind,
            stat_missing_is_not_found,
            list_missing_dir_is_not_found,
            names_with_spaces_unicode_and_leading_dash,
            dotfile_is_hidden,
            rename_in_same_dir,
            rename_across_dirs,
            rename_without_replace_fails_if_target_exists,
            rename_with_replace_overwrites,
            remove_file_then_stat_not_found,
            remove_symlink_keeps_target,
            rmdir_empty_dir,
            rmdir_non_empty_fails,
            read_from_offset,
            read_range_len_stops_at_length,
            abort_read_midway_leaves_session_usable,
            resume_write_at_offset,
            append_write,
            write_at_offset_keeps_existing_bytes,
            ops_rejected_while_stream_open,
            chmod_roundtrip,
            set_mtime_roundtrip,
            large_offset_resume_beyond_4gib,
            second_session_sees_changes,
            keepalive_ok,
            disconnect_then_connect_again,
        );
    };
    (@cases $attrs:tt $env:path; $($case:ident,)*) => {
        mod conformance_cases {
            #[allow(unused_imports)]
            use super::*;
            $(
                $crate::backend_conformance_tests!(@one $attrs $env; $case);
            )*
        }
    };
    (@one [$($attr:tt)*] $env:path; $case:ident) => {
        #[::tokio::test]
        $($attr)*
        async fn $case() {
            let env = $env();
            if let Err(e) = $crate::backend::conformance::run_case(stringify!($case), &env).await {
                panic!("conformance case {} failed: {e}", stringify!($case));
            }
        }
    };
}
