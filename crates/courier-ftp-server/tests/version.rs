//! The server's command line (T01 skeleton, T84 `serve`/`migrate`).

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
fn server_without_a_command_prints_usage() {
    let out = Command::new(env!("CARGO_BIN_EXE_courier-ftp-server"))
        .output()
        .unwrap_or_else(|e| panic!("run courier-ftp-server: {e}"));
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Usage"));
}

#[test]
fn serve_without_a_secret_is_a_config_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_courier-ftp-server"))
        .arg("serve")
        .env_remove("COURIER_SERVER_SECRET")
        .env("COURIER_LOG", "off")
        .output()
        .unwrap_or_else(|e| panic!("run courier-ftp-server: {e}"));
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("COURIER_SERVER_SECRET is required"));
}
