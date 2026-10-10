//! The application log (T71, T91 §4): `tracing` output for developers.
//!
//! Written to `<data dir>/courier-ftp.<YYYY-MM-DD>.log`, a new file per UTC
//! day, the newest [`MAX_LOG_FILES`] kept, appended to (never truncated),
//! `0600` on Unix. A background thread writes it ([`BackgroundWriter`]), so
//! the UI never waits on the disk; when the disk can't keep up, lines are
//! dropped and a note says how many.
//!
//! The level comes from `COURIER_FTP_LOG_LEVEL` (else `RUST_LOG`), default
//! `info`, or `debug` with `--debug`. An invalid value never stops startup:
//! the default is used and a warning logged.
//!
//! Policy (T91 §4): nothing at `info` and above names a host, user, path or
//! command; those go to `debug`. `--debug` therefore warns that the log may
//! contain hostnames ([`DEBUG_WARNING`]). Secrets are never logged at any
//! level. The session log (the message log written to a file, the user's
//! choice) is separate: see [`courier_ftp_core::logfile::SessionLogFile`].

use std::{path::Path, sync::OnceLock, time::Duration};

use courier_ftp_core::logfile::{BackgroundWriter, DailyRotating};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tracing::Subscriber;
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    EnvFilter, Layer, filter::LevelFilter, fmt, prelude::*, registry::LookupSpan,
};

use crate::config;

/// The variable that sets the log filter.
pub(crate) const LOG_ENV: &str = "COURIER_FTP_LOG_LEVEL";
/// Log files are `<prefix>.<YYYY-MM-DD>.<suffix>`.
pub(crate) const LOG_FILE_PREFIX: &str = "courier-ftp";
/// See [`LOG_FILE_PREFIX`].
pub(crate) const LOG_FILE_SUFFIX: &str = "log";
/// Daily log files kept (T91 §4: 7 days).
pub(crate) const MAX_LOG_FILES: usize = 7;
/// Lines buffered for the writer thread before lines are dropped.
const LOG_CAPACITY: usize = 10_000;
/// Shown when `--debug` is on (stderr before the TUI starts, then the
/// message log).
pub(crate) const DEBUG_WARNING: &str =
    "Debug logging is on: the application log may contain hostnames, user names and paths.";

/// How the process wants logging set up.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LogOptions {
    /// `--debug`: default level `debug` instead of `info`.
    pub(crate) debug: bool,
}

/// The writer thread, for [`flush`] at exit and in the panic hook.
static WRITER: OnceLock<BackgroundWriter> = OnceLock::new();

/// Install the global subscriber writing to the data directory.
pub(crate) fn init(opts: LogOptions) -> color_eyre::Result<()> {
    let directory = config::get_data_dir();
    std::fs::create_dir_all(&directory)?;
    let writer = writer(&directory)?;
    let env = std::env::var(LOG_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| std::env::var("RUST_LOG").ok());
    let (filter, warning) = filter(opts, env.as_deref());
    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer(writer.clone()))
        .with(ErrorLayer::default())
        .try_init()?;
    let _ = WRITER.set(writer);
    if let Some(warning) = warning {
        tracing::warn!("{warning}");
    }
    Ok(())
}

/// The background writer over the daily files in `dir`.
pub(crate) fn writer(dir: &Path) -> std::io::Result<BackgroundWriter> {
    let file = DailyRotating::new(dir, LOG_FILE_PREFIX, LOG_FILE_SUFFIX, MAX_LOG_FILES);
    BackgroundWriter::spawn(
        "courier-ftp-log",
        file,
        LOG_CAPACITY,
        Box::new(|n| {
            let now = OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default();
            format!(
                "{now}  WARN courier_ftp::logging: {n} log lines were dropped \
                 (the disk could not keep up)\n"
            )
        }),
    )
}

/// The file layer: RFC 3339 UTC time, level, target, file:line, no colours.
/// `scripts/canary-scan.sh` reads the level from this format. The filter is
/// a separate (global) layer: per-layer filters miss events when tests run
/// several thread-local subscribers at once.
pub(crate) fn file_layer<S>(writer: BackgroundWriter) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fmt::layer()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        // stdout and stderr belong to the TUI.
        .log_internal_errors(false)
}

/// The filter from `value` (`COURIER_FTP_LOG_LEVEL`) over the default level,
/// and a warning when `value` doesn't parse.
pub(crate) fn filter(opts: LogOptions, value: Option<&str>) -> (EnvFilter, Option<String>) {
    let default = if opts.debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let raw = value.map(str::trim).unwrap_or_default();
    match EnvFilter::builder()
        .with_default_directive(default.into())
        .parse(raw)
    {
        Ok(filter) => (filter, None),
        Err(err) => (
            EnvFilter::default().add_directive(default.into()),
            Some(format!(
                "ignoring invalid {LOG_ENV} ({err}); using the default level `{default}`"
            )),
        ),
    }
}

/// Write out everything logged so far (at exit and in the panic hook). Waits
/// at most one second.
pub(crate) fn flush() {
    if let Some(writer) = WRITER.get() {
        writer.flush_timeout(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests;
