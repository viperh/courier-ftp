//! courier-ftp-server: the self-hosted sync server (D12).
//!
//! Accounts, OPAQUE login and devices (T84), vaults, pull/push and live
//! updates (T85), configuration, the admin CLI and deployment (T86). It only
//! stores end-to-end encrypted items it cannot read.
//!
//! Layering: depends only on `courier-ftp-proto` and `courier-ftp-crypto`; never on
//! a client crate, a UI crate, russh or rusqlite.

use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_some_and(|a| a == "--version") {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    eprintln!("courier-ftp-server: not implemented yet (T84)");
    ExitCode::from(2)
}
