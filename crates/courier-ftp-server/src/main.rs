//! `courier-ftp-server` entry point; see [`courier_ftp_server::cli`].

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    courier_ftp_server::cli::main().await
}
