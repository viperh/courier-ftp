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
mod services;
#[cfg(test)]
mod snapshot_tests;
mod tabs;
mod test_hooks;
#[cfg(test)]
mod testing;
mod timers;
mod tui;
mod ui;
mod views;

fn main() -> color_eyre::Result<()> {
    // `time` reads the local UTC offset only while the process is single-threaded,
    // so before the runtime starts (message log timestamps, T55).
    crate::components::message_log::init_local_offset();
    crate::components::file_list::format::capture_local_offset();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> color_eyre::Result<()> {
    crate::errors::init()?;
    // First thing after the panic hook, before anything secret exists (T30, T91).
    let hardening = courier_ftp_core::hardening::harden_process();

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
    tracing::debug!(
        core_dumps_disabled = hardening.core_dumps_disabled,
        non_dumpable = hardening.non_dumpable,
        failures = ?hardening.failures,
        "process hardening"
    );
    let config = Config::new(&paths)?;
    let vault_opts = courier_ftp_core::vault::VaultOptions::from_settings(&config.settings);
    let start = app::vault::VaultStartOptions {
        no_vault: args.no_vault,
        no_keyring: args.no_keyring || services::keyring::keyring_env_off(),
    };
    let mut app = App::new(
        config,
        args.tick_rate,
        args.frame_rate,
        TermEnv::from_process(),
    )
    .with_vault(start);
    if !start.no_vault {
        let keyring: std::sync::Arc<dyn courier_ftp_core::vault::KeyringStore> = if start.no_keyring
        {
            std::sync::Arc::new(courier_ftp_core::vault::NoKeyring)
        } else {
            services::keyring::keyring_from_env()
        };
        let host_keys = std::sync::Arc::new(courier_ftp_core::trust::SwitchableHostKeyStore::new(
            std::sync::Arc::new(courier_ftp_core::trust::MemoryHostKeyStore::new()),
        ));
        let service = services::vault::VaultService::spawn(
            services::vault::VaultConfig {
                db_path: paths.data_dir.join(services::vault::VAULT_DB),
                keyring,
                opts: vault_opts,
                host_keys,
            },
            app.action_sender(),
        );
        app.attach_vault_service(service);
    }
    app.run().await?;
    Ok(())
}
