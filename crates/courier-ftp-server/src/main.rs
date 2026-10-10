//! Self-hosted, end-to-end encrypted sync server for courier-ftp (T84–T86).
//!
//! The server only ever sees ciphertext: accounts, devices and vaults of
//! encrypted items. It shares wire types with the client through
//! `courier-ftp-proto` and never links client crates.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "courier-ftp-server {}: not implemented yet (T84)",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::FAILURE
}
