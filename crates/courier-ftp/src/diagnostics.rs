//! Diagnostics for users (T71): the message log written to a file, the raw
//! listing of the directory each pane shows, and "Save log as…".

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use courier_ftp_core::{
    backend::Listing,
    events::LogMessage,
    logfile::{self, SessionLogFile},
    model::RemotePath,
    settings::LoggingSettings,
};
use time::{OffsetDateTime, UtcOffset, macros::format_description};
use tokio::sync::mpsc;

use crate::{
    action::Action,
    ui::{Modal, Side, TextViewer, dialog},
};

/// File name of the session log when `logging.log_file` is unset.
pub(crate) const SESSION_LOG_FILE: &str = "session.log";

/// The last listing a pane showed, for "Show raw listing".
#[derive(Debug, Clone)]
struct RawListing {
    dir: RemotePath,
    raw: Option<String>,
}

/// What the app keeps for diagnostics.
#[derive(Debug)]
pub(crate) struct Diagnostics {
    session_log: Option<SessionLogFile>,
    /// The settings the open session log was opened with.
    session_log_key: Option<(PathBuf, u64, u32)>,
    offset: UtcOffset,
    raw: [Option<RawListing>; 2],
}

/// Where the session log goes.
pub(crate) fn session_log_path(logging: &LoggingSettings, data_dir: &Path) -> PathBuf {
    logging
        .log_file
        .clone()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| data_dir.join(SESSION_LOG_FILE))
}

fn index(side: Side) -> usize {
    match side {
        Side::Local => 0,
        Side::Remote => 1,
    }
}

impl Diagnostics {
    /// Times in the session log are shown in `offset`.
    pub(crate) fn new(offset: UtcOffset) -> Self {
        Self {
            session_log: None,
            session_log_key: None,
            offset,
            raw: [None, None],
        }
    }

    /// Start, stop or move the session log for `logging`. Returns a message
    /// for the message log when the file can't be written.
    pub(crate) fn apply(&mut self, logging: &LoggingSettings, data_dir: &Path) -> Option<String> {
        if !logging.log_to_file {
            self.close_session_log();
            return None;
        }
        let path = session_log_path(logging, data_dir);
        let key = (
            path.clone(),
            logging.log_file_max_mib,
            logging.log_file_keep,
        );
        if self.session_log_key.as_ref() == Some(&key) {
            return None;
        }
        self.close_session_log();
        // Open once now so a bad path is reported instead of silently lost.
        if let Err(e) = logfile::open_private(&path) {
            return Some(format!(
                "Can't write the session log {}: {e}",
                path.display()
            ));
        }
        match SessionLogFile::open(path, key.1, key.2, self.offset) {
            Ok(file) => {
                self.session_log = Some(file);
                self.session_log_key = Some(key);
                None
            }
            Err(e) => Some(format!("Can't start the session log: {e}")),
        }
    }

    fn close_session_log(&mut self) {
        if let Some(log) = self.session_log.take() {
            log.flush_timeout(Duration::from_secs(1));
        }
        self.session_log_key = None;
    }

    /// The open session log, if `logging.log_to_file` is on.
    pub(crate) fn session_log(&self) -> Option<&SessionLogFile> {
        self.session_log.as_ref()
    }

    /// A message-log line: also into the session log file.
    pub(crate) fn record(&self, msg: &LogMessage) {
        if let Some(log) = &self.session_log {
            log.record(msg);
        }
    }

    /// A pane now shows `listing`.
    pub(crate) fn listing_shown(&mut self, side: Side, listing: &Listing) {
        self.raw[index(side)] = Some(RawListing {
            dir: listing.dir.clone(),
            raw: listing.raw.clone(),
        });
    }

    /// A pane shows nothing any more (disconnected).
    pub(crate) fn forget(&mut self, side: Side) {
        self.raw[index(side)] = None;
    }

    /// The dialog with the raw listing of `side`'s directory, or why there is
    /// none (for the status bar).
    pub(crate) fn raw_listing_viewer(&self, side: Side) -> Result<TextViewer, &'static str> {
        let Some(listing) = &self.raw[index(side)] else {
            return Err("No directory listed");
        };
        match &listing.raw {
            Some(raw) if !raw.is_empty() => Ok(TextViewer::new(
                format!("Raw listing of {}", listing.dir),
                raw.trim_end_matches(['\r', '\n']),
            )),
            _ if side == Side::Local => Err("Local directories have no raw listing"),
            _ => Err("The server sent no raw listing for this directory"),
        }
    }
}

/// The path "Save log as…" suggests: `<data dir>/message-log-<time>.txt`.
pub(crate) fn default_save_path(data_dir: &Path, now: OffsetDateTime) -> PathBuf {
    let format = format_description!("[year][month][day]-[hour][minute][second]");
    let stamp = now.format(&format).unwrap_or_default();
    data_dir.join(format!("message-log-{stamp}.txt"))
}

/// "Save log as…": ask for a file name, then write `text` there (`0600`) in
/// the background; [`Action::LogSaved`] reports the result.
pub(crate) fn save_log_dialog(
    text: String,
    suggested: &Path,
    tx: mpsc::UnboundedSender<Action>,
) -> Box<dyn Modal> {
    let (modal, rx) = dialog::prompt_text("Save log as", "File", &suggested.display().to_string());
    tokio::spawn(async move {
        let Ok(Some(path)) = rx.await else {
            return;
        };
        let path = expand_home(path.trim());
        let target = path.clone();
        let result = tokio::task::spawn_blocking(move || logfile::write_private(&target, &text))
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r.map_err(|e| e.to_string()));
        let _ = tx.send(Action::LogSaved { path, result });
    });
    modal
}

/// `~/x` → `<home>/x`.
fn expand_home(path: &str) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => directories::BaseDirs::new()
            .map(|b| b.home_dir().join(rest))
            .unwrap_or_else(|| PathBuf::from(path)),
        None => PathBuf::from(path),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use courier_ftp_core::events::{LogKind, SessionId};

    use super::*;

    fn listing(dir: &str, raw: Option<&str>) -> Listing {
        Listing {
            dir: RemotePath::new(dir),
            entries: Vec::new(),
            fetched_at: Instant::now(),
            raw: raw.map(str::to_owned),
        }
    }

    #[test]
    fn raw_listing_per_side() {
        let mut d = Diagnostics::new(UtcOffset::UTC);
        assert_eq!(
            d.raw_listing_viewer(Side::Remote).err(),
            Some("No directory listed")
        );
        d.listing_shown(Side::Local, &listing("/home", None));
        assert_eq!(
            d.raw_listing_viewer(Side::Local).err(),
            Some("Local directories have no raw listing")
        );
        d.listing_shown(Side::Remote, &listing("/srv", None));
        assert_eq!(
            d.raw_listing_viewer(Side::Remote).err(),
            Some("The server sent no raw listing for this directory")
        );
        d.listing_shown(Side::Remote, &listing("/srv", Some("type=dir; www\r\n")));
        assert!(d.raw_listing_viewer(Side::Remote).is_ok());
        d.forget(Side::Remote);
        assert!(d.raw_listing_viewer(Side::Remote).is_err());
    }

    #[test]
    fn session_log_follows_the_settings() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Diagnostics::new(UtcOffset::UTC);
        let mut logging = LoggingSettings::default();
        assert_eq!(d.apply(&logging, dir.path()), None);
        assert!(d.session_log().is_none());

        logging.log_to_file = true;
        assert_eq!(d.apply(&logging, dir.path()), None);
        let log = d.session_log().unwrap().clone();
        assert_eq!(log.path(), dir.path().join(SESSION_LOG_FILE));
        d.record(&LogMessage {
            time: OffsetDateTime::now_utc(),
            session: SessionId(9),
            kind: LogKind::Command,
            text: "PASS CANARY-PW-diag".into(),
        });
        assert!(log.flush_timeout(Duration::from_secs(10)));
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert!(text.ends_with(" #9 Command: PASS ****\n"), "{text}");

        // Same settings: same file. A new path: moved.
        assert_eq!(d.apply(&logging, dir.path()), None);
        logging.log_file = Some(dir.path().join("other.log"));
        assert_eq!(d.apply(&logging, dir.path()), None);
        assert_eq!(
            d.session_log().unwrap().path(),
            dir.path().join("other.log")
        );

        // A path that can't be written is reported.
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, "").unwrap();
        logging.log_file = Some(blocker.join("x.log"));
        assert!(d.apply(&logging, dir.path()).is_some());
        assert!(d.session_log().is_none());

        logging.log_to_file = false;
        assert_eq!(d.apply(&logging, dir.path()), None);
        assert!(d.session_log().is_none());
    }

    #[test]
    fn save_path_and_home_expansion() {
        let now = OffsetDateTime::from_unix_timestamp(1_791_547_200).unwrap();
        assert_eq!(
            default_save_path(Path::new("/d"), now),
            Path::new("/d/message-log-20261009-120000.txt")
        );
        assert_eq!(expand_home("/abs/x"), Path::new("/abs/x"));
        assert!(!expand_home("~/x").starts_with("~"));
    }
}
