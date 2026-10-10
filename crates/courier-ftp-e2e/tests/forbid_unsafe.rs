//! `unsafe_code = "deny"` is inherited by every crate from `[workspace.lints]`.
//!
//! The level is `deny`, not `forbid`: the one documented `unsafe` module
//! (`crates/courier-ftp-core/src/hardening/`, T91) lifts it with an inner `allow`,
//! which `forbid` would reject; `scripts/check-unsafe.py` confines that `allow`.
//!
//! trybuild cannot prove this: the project it generates for compile-fail cases
//! does not carry over the crate's `[lints]` table, so an `unsafe` block compiles
//! there. Instead this test builds a throwaway workspace whose `[workspace.lints]`
//! is copied verbatim from the real root manifest, adds a probe crate with
//! `[lints] workspace = true` (exactly what every real crate declares, which is
//! checked too), and asserts that a probe containing an `unsafe` block is rejected
//! with the `deny(unsafe_code)` diagnostic.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{fs, path::PathBuf, process::Command};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn read_toml(path: &std::path::Path) -> toml::Table {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .parse()
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Every workspace member opts into the workspace lints.
#[test]
fn every_crate_inherits_workspace_lints() {
    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(workspace_root().join("Cargo.toml"))
        .no_deps()
        .exec()
        .unwrap();
    let mut missing = Vec::new();
    for package in metadata.workspace_packages() {
        let manifest = read_toml(package.manifest_path.as_std_path());
        let inherits = manifest
            .get("lints")
            .and_then(|l| l.get("workspace"))
            .and_then(toml::Value::as_bool)
            == Some(true);
        if !inherits {
            missing.push(package.name.to_string());
        }
    }
    assert!(
        missing.is_empty(),
        "crates without `[lints] workspace = true`: {missing:?}"
    );
}

/// The workspace lints, applied through `[lints] workspace = true`, reject `unsafe`.
/// (`-D unsafe-code`, the `deny` level.)
#[test]
fn unsafe_block_is_rejected_by_workspace_lints() {
    let root = workspace_root();
    let lints = read_toml(&root.join("Cargo.toml"))["workspace"]["lints"].clone();

    let mut workspace = toml::Table::new();
    let mut ws = toml::Table::new();
    ws.insert("resolver".into(), "3".into());
    ws.insert("members".into(), toml::Value::Array(vec!["probe".into()]));
    ws.insert("lints".into(), lints);
    workspace.insert("workspace".into(), ws.into());

    let probe_manifest = r#"[package]
name = "probe"
version = "0.0.0"
edition = "2024"
publish = false

[lints]
workspace = true

[lib]
path = "src/lib.rs"
"#;

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("forbid-unsafe-probe");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("probe/src")).unwrap();
    fs::write(dir.join("Cargo.toml"), toml::to_string(&workspace).unwrap()).unwrap();
    fs::write(dir.join("probe/Cargo.toml"), probe_manifest).unwrap();
    fs::write(
        dir.join("probe/src/lib.rs"),
        "//! Probe.\n\n/// Uses `unsafe`.\npub fn probe() -> u8 {\n    let x = 1_u8;\n    \
         let p = &raw const x;\n    unsafe { *p }\n}\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO"))
        .args(["check", "--offline", "--quiet", "--manifest-path"])
        .arg(dir.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", dir.join("target"))
        // Plain diagnostics: CI sets CARGO_TERM_COLOR=always.
        .env("CARGO_TERM_COLOR", "never")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "unsafe block compiled; workspace lints not applied:\n{stderr}"
    );
    assert!(
        stderr.contains("error: usage of an `unsafe` block"),
        "unexpected diagnostic:\n{stderr}"
    );
    assert!(
        stderr.contains("-D unsafe-code"),
        "error not caused by deny(unsafe_code):\n{stderr}"
    );
}
