//! Every view snapshotted with `assert_view_snapshots!` has both sizes (T76 AC9): a
//! `*@80x24.snap` without its `*@160x48.snap` twin (or vice versa) fails.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

const SMALL: &str = "@80x24.snap";
const LARGE: &str = "@160x48.snap";

fn snap_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            snap_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "snap") {
            out.push(path);
        }
    }
}

/// The snapshot files under `root` that lack their other-size twin.
fn missing_twins(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    snap_files(root, &mut files);
    let names: BTreeSet<String> = files
        .iter()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .collect();
    let mut missing = Vec::new();
    for name in &names {
        let twin = if let Some(stem) = name.strip_suffix(SMALL) {
            format!("{stem}{LARGE}")
        } else if let Some(stem) = name.strip_suffix(LARGE) {
            format!("{stem}{SMALL}")
        } else {
            continue;
        };
        if !names.contains(&twin) {
            missing.push(format!("{name} has no twin {twin}"));
        }
    }
    missing
}

#[test]
fn every_view_has_both_sizes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let missing = missing_twins(&root);
    assert!(missing.is_empty(), "{missing:#?}");
}

#[test]
fn a_missing_twin_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let snaps = dir.path().join("snapshots");
    std::fs::create_dir(&snaps).unwrap();
    for f in [
        "m__both@80x24.snap",
        "m__both@160x48.snap",
        "m__small_only@80x24.snap",
        "m__large_only@160x48.snap",
        "m__other.snap",
    ] {
        std::fs::write(snaps.join(f), "").unwrap();
    }
    let missing = missing_twins(dir.path());
    assert_eq!(missing.len(), 2, "{missing:#?}");
    assert!(missing.iter().any(|m| m.contains("small_only")));
    assert!(missing.iter().any(|m| m.contains("large_only")));
}
