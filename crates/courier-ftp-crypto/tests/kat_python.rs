//! Runs `scripts/kat/gen_crypto.py --check`, an independent Python
//! re-derivation of the non-zstd vectors in `tests/kat/*.json`.
//!
//! Skipped when `python3` or its `cryptography` package is missing, unless
//! `COURIER_KAT_PYTHON_REQUIRED` is set (the CI job `test-local-only` sets it and
//! installs the package), where a missing interpreter or package fails.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

#[test]
fn python_rederives_kats() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let script = crate_dir.join("../../scripts/kat/gen_crypto.py");
    let required = std::env::var_os("COURIER_KAT_PYTHON_REQUIRED").is_some();
    let out = match Command::new("python3")
        .arg(&script)
        .arg("--check")
        .arg("--kat-dir")
        .arg(crate_dir.join("tests/kat"))
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            assert!(!required, "python3 is required: {e}");
            eprintln!("skipped: python3 not available ({e})");
            return;
        }
    };
    // Exit code 3: the `cryptography` package is missing. Other non-zero codes
    // without our output (e.g. a Windows `python3` store stub) also count as
    // "no usable interpreter".
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let ran = stdout.contains("re-derived") || stderr.contains("MISMATCH");
    if !out.status.success() && !ran {
        assert!(
            !required,
            "gen_crypto.py could not run (exit {:?}):\n{stdout}{stderr}",
            out.status.code()
        );
        eprintln!("skipped: gen_crypto.py could not run ({stderr})");
        return;
    }
    assert!(
        out.status.success(),
        "gen_crypto.py --check failed:\n{stdout}{stderr}"
    );
}
