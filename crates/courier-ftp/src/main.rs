//! Entry point.
//!
//! The binary owns everything terminal-related; domain logic lives in the
//! `courier-ftp-core` crate so it stays testable without a TTY.

use clap::{CommandFactory, FromArgMatches};
use cli::Cli;

use crate::{
    app::App,
    paths::{AppPaths, SystemEnv},
};

mod action;
mod app;
mod cli;
mod components;
mod config;
mod errors;
mod logging;
mod paths;
mod tui;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    crate::errors::init()?;

    // Resolved before argument parsing: `--version` prints the directories. On
    // failure the user gets the one-line reason and exit code 1, before any
    // terminal setup and without writing anything.
    let paths = match AppPaths::resolve(None, None, &SystemEnv) {
        Ok(paths) => paths,
        Err(e) => {
            eprintln!("courier-ftp: {e}");
            std::process::exit(1);
        }
    };

    let matches = Cli::command().version(cli::version(&paths)).get_matches();
    let args = Cli::from_arg_matches(&matches)?;

    paths.ensure_dirs()?;
    crate::logging::init(&paths)?;
    let mut app = App::new(args.tick_rate, args.frame_rate, &paths)?;
    app.run().await?;
    Ok(())
}
