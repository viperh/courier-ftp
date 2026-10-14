//! The real binary hardens itself at startup (T91 §1): `harden_process()` runs
//! before logging starts and its report says the process is not dumpable and has
//! core dumps off. The in-process twin, which checks `PR_GET_DUMPABLE` and
//! `RLIMIT_CORE` directly, is `crates/courier-ftp-core/tests/hardening.rs`.
//!
//! The binary is started in a new session (`setsid`) with no controlling
//! terminal, so the TUI can't open `/dev/tty` and the process exits right after
//! startup; the debug log it leaves behind is checked.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::{Command, Stdio};

#[test]
fn binary_hardens_itself_at_startup() {
    let Ok(setsid) = which("setsid") else {
        eprintln!("SKIP: `setsid` (util-linux) is not installed");
        return;
    };
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(setsid)
        .arg("--wait")
        .arg(env!("CARGO_BIN_EXE_courier-ftp"))
        .env("COURIER_FTP_HOME", home.path())
        .env("COURIER_FTP_LOG_LEVEL", "debug")
        .env_remove("RUST_LOG")
        .env_remove("COURIER_FTP_CONFIG")
        .env_remove("COURIER_FTP_DATA")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    // Without a terminal the TUI fails to start; the log is written before that.
    assert!(
        !output.status.success(),
        "the TUI started without a terminal"
    );

    let log = find_log(home.path()).unwrap_or_else(|| {
        panic!(
            "no log file under {}; stderr: {}",
            home.path().display(),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let line = log
        .lines()
        .find(|l| l.contains("process hardening"))
        .unwrap_or_else(|| panic!("no hardening report in the log:\n{log}"));
    assert!(line.contains("non_dumpable=true"), "{line}");
    assert!(line.contains("core_dumps_disabled=true"), "{line}");
    assert!(line.contains("failures=[]"), "{line}");
}

fn which(name: &str) -> Result<std::path::PathBuf, ()> {
    let path = std::env::var_os("PATH").ok_or(())?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
        .ok_or(())
}

fn find_log(dir: &std::path::Path) -> Option<String> {
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(log) = find_log(&path) {
                return Some(log);
            }
        } else if path.extension().is_some_and(|e| e == "log") {
            return std::fs::read_to_string(&path).ok();
        }
    }
    None
}
