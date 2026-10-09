//! `courier-ftp-server` entry point.
//!
//! ```text
//! courier-ftp-server serve [--migrate]
//! courier-ftp-server migrate
//! courier-ftp-server --version
//! ```
//!
//! T86 adds `--config`, the admin commands and `healthcheck`. Exit codes: 0
//! normal, 2 configuration or secret error, 3 database or migration error, 4
//! bind or TLS error.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use courier_ftp_server::config::Config;
use courier_ftp_server::serve::{self, ServeError};

/// courier-ftp sync server.
#[derive(Debug, Parser)]
#[command(name = "courier-ftp-server", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the HTTP server.
    Serve {
        /// Apply pending migrations instead of refusing to start.
        #[arg(long)]
        migrate: bool,
    },
    /// Apply pending database migrations and exit.
    Migrate,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    serve::init_logging();
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => return serve::fail(&ServeError::from(e)),
    };
    let result = match cli.command {
        Command::Serve { migrate } => serve::run(config, migrate).await,
        Command::Migrate => serve::migrate(&config).await.map(|applied| {
            tracing::info!(?applied, "migrations up to date");
        }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => serve::fail(&e),
    }
}
