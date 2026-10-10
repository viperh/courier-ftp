//! courier-ftp: a terminal FTP, FTPS and SFTP client.
//!
//! The binary owns everything terminal-related; domain logic lives in the
//! `courier-ftp-core` crate and the protocols in `courier-ftp-proto-ftp` and
//! `courier-ftp-proto-sftp`, so they stay testable without a TTY.

use clap::Parser;
use cli::{Cli, Command};

use crate::app::App;

mod action;
mod app;
mod cli;
mod config;
mod errors;
mod logging;
mod tui;
mod ui;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    let args = Cli::parse();
    // Non-interactive subcommands run before the panic hook and the log file are
    // set up: they must not touch the terminal or the data directory.
    if let Some(Command::Generate { what }) = &args.command {
        cli::generate(what, &mut std::io::stdout().lock())?;
        return Ok(());
    }

    crate::errors::init()?;
    crate::logging::init()?;

    let mut app = App::new(args.tick_rate, args.frame_rate)?;
    app.run().await?;
    Ok(())
}
