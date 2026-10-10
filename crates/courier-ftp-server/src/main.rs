//! `courier-ftp-server` entry point.
//!
//! Until the admin CLI exists (T86) the binary only serves:
//! `courier-ftp-server [serve] [--migrate]`, configured from the environment.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let mut migrate = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "serve" => {}
            "--migrate" => migrate = true,
            "--version" | "-V" => {
                println!("courier-ftp-server {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!(
                    "courier-ftp-server: unknown argument `{other}` (usage: serve [--migrate])"
                );
                return ExitCode::from(2);
            }
        }
    }
    let config = match courier_ftp_server::Config::load(None) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("courier-ftp-server: {e}");
            return ExitCode::FAILURE;
        }
    };
    courier_ftp_server::logging::init(config.log_format);
    match courier_ftp_server::serve::run(config, migrate).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "courier-ftp-server cannot start");
            eprintln!("courier-ftp-server: {e}");
            ExitCode::FAILURE
        }
    }
}
