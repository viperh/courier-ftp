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
mod archive;
mod backends;
mod bookmarks;
mod cli;
mod clipboard;
mod completion;
mod config;
mod diagnostics;
mod errors;
mod file_ops;
mod keymap;
mod logging;
mod sites;
#[cfg(feature = "sync")]
mod sync;
mod transfers;
mod tui;
mod ui;
mod update;
mod vault;

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
    // No core dumps, no same-user ptrace (Linux), before any secret exists (T91).
    let hardening = courier_ftp_core::hardening::harden_process();
    crate::logging::init(crate::logging::LogOptions { debug: args.debug })?;
    if args.debug {
        // Seen after quitting (the TUI covers it), and in the message log.
        eprintln!("courier-ftp: {}", crate::logging::DEBUG_WARNING);
    }
    tracing::debug!(
        core_dumps_disabled = hardening.core_dumps_disabled,
        non_dumpable = hardening.non_dumpable,
        failures = ?hardening.failures,
        "process hardening"
    );

    let result = async {
        // Boxed: `App` is large, and this future would hold it inline.
        let mut app = Box::new(App::new(args.tick_rate, args.frame_rate)?);
        if args.no_update_check || crate::update::env_opt_out() {
            app.disable_update_check();
        }
        if let Some(level) = args.debug_level {
            app.set_debug_level(level);
        }
        if args.debug {
            app.log_status(&format!("Warning: {}", crate::logging::DEBUG_WARNING));
        }
        Box::pin(app.run()).await
    }
    .await;
    // The log is written by a background thread: write it out before exiting.
    crate::logging::flush();
    result
}
