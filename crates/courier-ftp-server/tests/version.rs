//! The server skeleton's command line (T01, AC7).

use std::process::Command;

#[test]
fn server_version() {
    let out = Command::new(env!("CARGO_BIN_EXE_courier-ftp-server"))
        .arg("--version")
        .output()
        .unwrap_or_else(|e| panic!("run courier-ftp-server: {e}"));
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim_end(),
        format!("courier-ftp-server {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn server_without_arguments_is_not_implemented() {
    let out = Command::new(env!("CARGO_BIN_EXE_courier-ftp-server"))
        .output()
        .unwrap_or_else(|e| panic!("run courier-ftp-server: {e}"));
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not implemented yet (T84)"));
}
