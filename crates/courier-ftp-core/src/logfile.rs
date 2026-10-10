//! Log files on disk (T71): rotation, private permissions and a background
//! writer that never blocks the caller.
//!
//! Two logs use this:
//! - the **application log** (`tracing`, for developers) goes through a
//!   [`DailyRotating`] file, `<prefix>.<YYYY-MM-DD>.<suffix>`, a new file per
//!   UTC day, the newest [`DailyRotating::keep`] kept;
//! - the **session log** (the message log, setting `logging.log_to_file`) goes
//!   through a [`SizeRotating`] file, `session.log` → `session.log.1` → … when
//!   it reaches `logging.log_file_max_mib`, `logging.log_file_keep` old files
//!   kept. [`SessionLogFile`] formats each [`LogMessage`] as
//!   `2026-10-09 12:00:00 #3 Status: text`.
//!
//! Both are written by a [`BackgroundWriter`]: a thread fed through a bounded
//! channel. When the disk can't keep up, lines are dropped and counted, and the
//! count is written as a note before the next line that gets through.
//!
//! Files are created `0600` on Unix (an existing file is narrowed to `0600`
//! when opened), since the session log names servers, users and paths.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread,
    time::Duration,
};

use time::{Date, OffsetDateTime, UtcOffset, macros::format_description};

use crate::events::{LogKind, LogMessage, mask_command};

/// Open `path` for appending, creating it (and its directory) if needed,
/// readable and writable by the owner only on Unix.
///
/// # Errors
/// The directory or file can't be created or opened.
pub fn open_private(path: &Path) -> io::Result<File> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        let file = options.open(path)?;
        // `mode` applies only when the file is created; narrow older files.
        let perms = file.metadata()?.permissions();
        if perms.mode() & 0o077 != 0 {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        options.open(path)
    }
}

/// Write `text` to `path` (replacing it), owner-only on Unix. For "Save log
/// as…".
///
/// # Errors
/// The file can't be created or written.
pub fn write_private(path: &Path, text: &str) -> io::Result<()> {
    let mut file = open_private(path)?;
    file.set_len(0)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()
}

/// A file rotated by size: `path` is renamed to `path.1` (and `path.1` to
/// `path.2`, …) when the next write would make it larger than the limit.
#[derive(Debug)]
pub struct SizeRotating {
    path: PathBuf,
    max_bytes: u64,
    keep: u32,
    file: Option<File>,
    size: u64,
}

impl SizeRotating {
    /// `max_bytes == 0` never rotates; `keep == 0` keeps no old file (the log
    /// starts over when full).
    pub fn new(path: impl Into<PathBuf>, max_bytes: u64, keep: u32) -> Self {
        Self {
            path: path.into(),
            max_bytes,
            keep,
            file: None,
            size: 0,
        }
    }

    /// The current file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `path.n`.
    pub fn rotated_path(&self, n: u32) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    }

    fn file(&mut self) -> io::Result<&mut File> {
        match &mut self.file {
            Some(file) => Ok(file),
            slot @ None => {
                let file = open_private(&self.path)?;
                self.size = file.metadata()?.len();
                Ok(slot.insert(file))
            }
        }
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file = None;
        self.size = 0;
        if self.keep == 0 {
            return match fs::remove_file(&self.path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            };
        }
        let _ = fs::remove_file(self.rotated_path(self.keep));
        for n in (1..self.keep).rev() {
            let from = self.rotated_path(n);
            if from.exists() {
                fs::rename(&from, self.rotated_path(n + 1))?;
            }
        }
        fs::rename(&self.path, self.rotated_path(1))
    }
}

impl Write for SizeRotating {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file()?;
        let len = buf.len() as u64;
        if self.max_bytes > 0 && self.size > 0 && self.size + len > self.max_bytes {
            self.rotate()?;
        }
        let file = self.file()?;
        file.write_all(buf)?;
        self.size += len;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.file {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

type Clock = Box<dyn Fn() -> Date + Send>;

/// A file per UTC day, `<dir>/<prefix>.<YYYY-MM-DD>.<suffix>`; appended to,
/// never truncated. Only the newest [`keep`](Self::keep) such files are kept.
pub struct DailyRotating {
    dir: PathBuf,
    prefix: String,
    suffix: String,
    keep: usize,
    clock: Clock,
    current: Option<(Date, File)>,
}

impl std::fmt::Debug for DailyRotating {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DailyRotating")
            .field("dir", &self.dir)
            .field("prefix", &self.prefix)
            .field("suffix", &self.suffix)
            .field("keep", &self.keep)
            .finish_non_exhaustive()
    }
}

impl DailyRotating {
    /// Files in `dir` named `<prefix>.<date>.<suffix>`; at least one is kept.
    pub fn new(dir: impl Into<PathBuf>, prefix: &str, suffix: &str, keep: usize) -> Self {
        Self::with_clock(dir, prefix, suffix, keep, || {
            OffsetDateTime::now_utc().date()
        })
    }

    /// [`new`](Self::new) with a fake clock (tests).
    pub fn with_clock(
        dir: impl Into<PathBuf>,
        prefix: &str,
        suffix: &str,
        keep: usize,
        clock: impl Fn() -> Date + Send + 'static,
    ) -> Self {
        Self {
            dir: dir.into(),
            prefix: prefix.to_owned(),
            suffix: suffix.to_owned(),
            keep: keep.max(1),
            clock: Box::new(clock),
            current: None,
        }
    }

    /// How many daily files are kept.
    pub fn keep(&self) -> usize {
        self.keep
    }

    /// The file for `date`.
    pub fn path_for(&self, date: Date) -> PathBuf {
        let format = format_description!("[year]-[month]-[day]");
        let day = date.format(&format).unwrap_or_else(|_| date.to_string());
        self.dir
            .join(format!("{}.{day}.{}", self.prefix, self.suffix))
    }

    /// The daily files in the directory, oldest first.
    pub fn existing(&self) -> Vec<PathBuf> {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let head = format!("{}.", self.prefix);
        let tail = format!(".{}", self.suffix);
        let mut found: Vec<PathBuf> = entries
            .flatten()
            .filter(|e| {
                let name = e.file_name();
                let Some(name) = name.to_str() else {
                    return false;
                };
                name.strip_prefix(&head)
                    .and_then(|rest| rest.strip_suffix(&tail))
                    .is_some_and(is_date)
            })
            .map(|e| e.path())
            .collect();
        // YYYY-MM-DD sorts by date.
        found.sort();
        found
    }

    fn prune(&self) {
        let files = self.existing();
        let excess = files.len().saturating_sub(self.keep);
        for old in &files[..excess] {
            let _ = fs::remove_file(old);
        }
    }

    fn file(&mut self) -> io::Result<&mut File> {
        let today = (self.clock)();
        if self.current.as_ref().is_none_or(|(day, _)| *day != today) {
            self.current = None;
            let file = open_private(&self.path_for(today))?;
            self.current = Some((today, file));
            self.prune();
        }
        match &mut self.current {
            Some((_, file)) => Ok(file),
            None => Err(io::Error::other("log file not open")),
        }
    }
}

fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        })
}

impl Write for DailyRotating {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file()?.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.current {
            Some((_, file)) => file.flush(),
            None => Ok(()),
        }
    }
}

enum Msg {
    Line(Vec<u8>),
    Flush(mpsc::Sender<()>),
}

/// Formats the "N lines dropped" note in the log's own format.
pub type DropNote = Box<dyn Fn(u64) -> String + Send>;

/// A thread that writes lines to a file, fed through a bounded channel.
///
/// Cheap to clone. [`write_line`](Self::write_line) never blocks: when the
/// channel is full the line is dropped and counted. The thread stops after
/// every clone is gone and the channel is drained.
#[derive(Debug, Clone)]
pub struct BackgroundWriter {
    tx: SyncSender<Msg>,
    dropped: Arc<AtomicU64>,
    dropped_total: Arc<AtomicU64>,
}

impl BackgroundWriter {
    /// Start a thread named `name` writing to `out`, buffering at most
    /// `capacity` lines. `note` formats the dropped-lines note.
    ///
    /// # Errors
    /// The thread can't be started.
    pub fn spawn(
        name: &str,
        out: impl Write + Send + 'static,
        capacity: usize,
        note: DropNote,
    ) -> io::Result<Self> {
        let (tx, rx) = mpsc::sync_channel(capacity.max(1));
        let dropped = Arc::new(AtomicU64::new(0));
        let pending = Arc::clone(&dropped);
        thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || run_writer(rx, out, &pending, &note))?;
        Ok(Self {
            tx,
            dropped,
            dropped_total: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Queue `line` (with its newline). `false` when it was dropped.
    pub fn write_line(&self, line: Vec<u8>) -> bool {
        match self.tx.try_send(Msg::Line(line)) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                self.dropped_total.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Lines dropped so far by this writer (all clones).
    pub fn dropped(&self) -> u64 {
        self.dropped_total.load(Ordering::Relaxed)
    }

    /// Wait until everything queued so far is written and flushed, at most
    /// `timeout`. `false` on timeout or when the thread is gone.
    pub fn flush_timeout(&self, timeout: Duration) -> bool {
        let (done, wait) = mpsc::channel();
        // Blocks only while the channel is full; the thread is draining it.
        if self.tx.send(Msg::Flush(done)).is_err() {
            return false;
        }
        wait.recv_timeout(timeout).is_ok()
    }
}

impl Write for BackgroundWriter {
    /// Queues the whole buffer as one line (`tracing`'s formatter writes each
    /// event with one call).
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_line(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn run_writer(rx: Receiver<Msg>, mut out: impl Write, dropped: &AtomicU64, note: &DropNote) {
    // Write errors are ignored: there is nowhere to report them (the log
    // itself is what failed), and the next line retries opening the file.
    for msg in rx {
        match msg {
            Msg::Line(line) => {
                let lost = dropped.swap(0, Ordering::Relaxed);
                if lost > 0 {
                    let _ = out.write_all(note(lost).as_bytes());
                }
                let _ = out.write_all(&line);
            }
            Msg::Flush(done) => {
                let lost = dropped.swap(0, Ordering::Relaxed);
                if lost > 0 {
                    let _ = out.write_all(note(lost).as_bytes());
                }
                let _ = out.flush();
                let _ = done.send(());
            }
        }
    }
    let _ = out.flush();
}

/// Lines the session log buffers before dropping.
pub const SESSION_LOG_CAPACITY: usize = 4096;

/// The label of a message-log line, as the log pane shows it.
pub fn kind_label(kind: LogKind) -> &'static str {
    match kind {
        LogKind::Status => "Status:",
        LogKind::Command => "Command:",
        LogKind::Response => "Response:",
        LogKind::Error => "Error:",
        LogKind::ListingRaw => "Listing:",
        LogKind::Debug(_) => "Trace:",
    }
}

/// One message-log line for the session log file:
/// `2026-10-09 12:00:00 #3 Status: text`, in `offset`'s time. A multi-line
/// text gives one line each. Commands are masked again ([`mask_command`]) in
/// case a caller logged one without [`EventSender::log_command`](crate::events::EventSender::log_command).
pub fn format_session_line(msg: &LogMessage, offset: UtcOffset) -> String {
    let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    let time = msg
        .time
        .to_offset(offset)
        .format(&format)
        .unwrap_or_default();
    let label = kind_label(msg.kind);
    let mut out = String::new();
    for line in msg.text.split('\n').map(|l| l.trim_end_matches('\r')) {
        let line = match msg.kind {
            LogKind::Command => mask_command(line),
            _ => std::borrow::Cow::Borrowed(line),
        };
        out.push_str(&format!("{time} {} {label} {line}\n", msg.session));
    }
    out
}

/// The message log written to a file (`logging.log_to_file`).
#[derive(Debug, Clone)]
pub struct SessionLogFile {
    path: PathBuf,
    writer: BackgroundWriter,
    offset: UtcOffset,
}

impl SessionLogFile {
    /// Start writing to `path`, rotating at `max_mib` MiB and keeping `keep`
    /// old files. Times are shown in `offset`. The file is opened on the first
    /// line.
    ///
    /// # Errors
    /// The writer thread can't be started.
    pub fn open(path: PathBuf, max_mib: u64, keep: u32, offset: UtcOffset) -> io::Result<Self> {
        let file = SizeRotating::new(path.clone(), max_mib.saturating_mul(1024 * 1024), keep);
        let note: DropNote = Box::new(move |n| {
            let now = OffsetDateTime::now_utc().to_offset(offset);
            let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
            let time = now.format(&format).unwrap_or_default();
            format!("{time} - Error: {n} log lines were dropped (the disk could not keep up)\n")
        });
        let writer =
            BackgroundWriter::spawn("courier-ftp-session-log", file, SESSION_LOG_CAPACITY, note)?;
        Ok(Self {
            path,
            writer,
            offset,
        })
    }

    /// The file written to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Queue one message-log line.
    pub fn record(&self, msg: &LogMessage) {
        self.writer
            .write_line(format_session_line(msg, self.offset).into_bytes());
    }

    /// Lines dropped because the disk couldn't keep up.
    pub fn dropped(&self) -> u64 {
        self.writer.dropped()
    }

    /// Wait (at most `timeout`) until everything queued is on disk.
    pub fn flush_timeout(&self, timeout: Duration) -> bool {
        self.writer.flush_timeout(timeout)
    }
}

#[cfg(test)]
mod tests;
