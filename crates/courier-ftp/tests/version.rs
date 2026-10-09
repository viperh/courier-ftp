//! `courier-ftp --version` and directory resolution from the outside (T01, AC5, AC6).

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_courier-ftp");

#[test]
fn version_prints_overridden_dirs() {
    let tmp = tempfile::TempDir::new().unwrap_or_else(|e| panic!("tempdir: {e}"));
    let home = tmp.path().join("x");
    let out = Command::new(BIN)
        .arg("--version")
        .env("COURIER_FTP_HOME", &home)
        .env_remove("COURIER_FTP_CONFIG")
        .env_remove("COURIER_FTP_DATA")
        .output()
        .unwrap_or_else(|e| panic!("run courier-ftp: {e}"));
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!(
            "Config directory: {}",
            home.join("config").display()
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("Data directory: {}", home.join("data").display())),
        "{stdout}"
    );
    // `--version` creates nothing.
    assert!(!home.exists());

    // COURIER_FTP_CONFIG wins over COURIER_FTP_HOME for the config directory.
    let config = tmp.path().join("c");
    let out = Command::new(BIN)
        .arg("--version")
        .env("COURIER_FTP_HOME", &home)
        .env("COURIER_FTP_CONFIG", &config)
        .env_remove("COURIER_FTP_DATA")
        .output()
        .unwrap_or_else(|e| panic!("run courier-ftp: {e}"));
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("Config directory: {}", config.display())),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("Data directory: {}", home.join("data").display())),
        "{stdout}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn no_home_fails_without_writing_cwd() {
    let cwd = tempfile::TempDir::new().unwrap_or_else(|e| panic!("tempdir: {e}"));
    let out = Command::new(BIN)
        .env_clear()
        .current_dir(cwd.path())
        .output()
        .unwrap_or_else(|e| panic!("run courier-ftp: {e}"));
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("COURIER_FTP_HOME"), "{stderr}");
    let entries: Vec<_> = std::fs::read_dir(cwd.path())
        .unwrap_or_else(|e| panic!("read_dir: {e}"))
        .collect();
    assert!(entries.is_empty(), "{entries:?}");
}
