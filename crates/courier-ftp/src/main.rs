//! Entry point.
//!
//! The binary owns everything terminal-related; domain logic lives in the
//! `courier-ftp-core` crate so it stays testable without a TTY.

use clap::{CommandFactory, FromArgMatches};
use cli::Cli;

use crate::{
    app::App,
    config::Config,
    paths::{AppPaths, SystemEnv},
    ui::symbols::TermEnv,
};

mod action;
mod app;
#[cfg(test)]
mod app_tests;
mod cli;
mod components;
mod config;
mod errors;
mod keymap;
mod logging;
mod paths;
mod runtime;
#[cfg(test)]
mod snapshot_tests;
mod tabs;
mod test_hooks;
#[cfg(test)]
mod testing;
mod tui;
mod ui;

fn main() -> color_eyre::Result<()> {
    // `time` reads the local UTC offset only while the process is single-threaded,
    // so before the runtime starts (message log timestamps, T55).
    crate::components::message_log::init_local_offset();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> color_eyre::Result<()> {
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
    let config = Config::new(&paths)?;
    let mut app = App::new(
        config,
        args.tick_rate,
        args.frame_rate,
        TermEnv::from_process(),
    );
    app.run().await?;
    Ok(())
}
