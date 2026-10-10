//! [`OpenSshKnownHosts`]: the user's and the system's OpenSSH `known_hosts` files, read
//! only and cached (T21).
//!
//! [`OpenSshKnownHosts::entries`] stats every path and re-reads a file only when its
//! size or mtime changed. A missing or unreadable file contributes nothing (debug
//! log). Files larger than [`MAX_FILE_BYTES`] or with more than [`MAX_FILE_LINES`]
//! lines are skipped with one warning per file and process (handed to the session log
//! through [`OpenSshKnownHosts::take_notices`]). Parse warnings are logged at `debug`
//! with file and line only; `@cert-authority` lines are ignored (debug, once per file).
//! The files are never opened for writing.

use std::{
    collections::HashSet,
    fmt,
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::SystemTime,
};

use courier_ftp_core::settings::SftpSettings;
use tracing::{debug, warn};

use super::{Marker, OpenSshEntry, parse_known_hosts};

/// Files larger than this are skipped (4 MiB).
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Files with more lines than this are skipped.
pub const MAX_FILE_LINES: usize = 100_000;

/// What a file looked like when it was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    len: u64,
    mtime: Option<SystemTime>,
}

#[derive(Debug, Default)]
struct FileState {
    /// `None`: missing / unreadable / not yet seen.
    stamp: Option<Stamp>,
    entries: Vec<OpenSshEntry>,
}

#[derive(Debug, Default)]
struct State {
    files: Vec<FileState>,
    combined: Arc<Vec<OpenSshEntry>>,
    /// Files already reported as too large or as holding CA lines.
    warned_large: HashSet<PathBuf>,
    noted_ca: HashSet<PathBuf>,
    /// User-facing warnings not yet logged.
    notices: Vec<String>,
}

/// Reads and caches the OpenSSH `known_hosts` files (read-only).
pub struct OpenSshKnownHosts {
    paths: Vec<PathBuf>,
    state: Mutex<State>,
}

impl fmt::Debug for OpenSshKnownHosts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenSshKnownHosts")
            .field("paths", &self.paths)
            .finish_non_exhaustive()
    }
}

fn lock(m: &Mutex<State>) -> MutexGuard<'_, State> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The default file list for this OS (see the T21 "Data formats" table).
pub fn default_paths() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let mut paths = Vec::new();
        if let Some(home) = std::env::var_os("USERPROFILE") {
            let ssh = PathBuf::from(home).join(".ssh");
            paths.push(ssh.join("known_hosts"));
            paths.push(ssh.join("known_hosts2"));
        }
        if let Some(data) = std::env::var_os("PROGRAMDATA") {
            paths.push(PathBuf::from(data).join("ssh").join("ssh_known_hosts"));
        }
        paths
    }
    #[cfg(not(windows))]
    {
        let mut paths = Vec::new();
        if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
            let ssh = PathBuf::from(home).join(".ssh");
            paths.push(ssh.join("known_hosts"));
            paths.push(ssh.join("known_hosts2"));
        }
        paths.push(PathBuf::from("/etc/ssh/ssh_known_hosts"));
        paths.push(PathBuf::from("/etc/ssh/ssh_known_hosts2"));
        paths
    }
}

fn stamp(path: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok()?;
    meta.is_file().then(|| Stamp {
        len: meta.len(),
        mtime: meta.modified().ok(),
    })
}

/// Why a file was not used.
enum Skip {
    Unreadable(std::io::Error),
    TooLarge,
}

/// Read at most [`MAX_FILE_BYTES`] + 1 bytes (the file may grow after the stat).
fn read_capped(path: &Path) -> Result<String, Skip> {
    let file = File::open(path).map_err(Skip::Unreadable)?;
    let mut buf = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(Skip::Unreadable)?;
    if buf.len() as u64 > MAX_FILE_BYTES || bytecount_newlines(&buf) > MAX_FILE_LINES {
        return Err(Skip::TooLarge);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn bytecount_newlines(buf: &[u8]) -> usize {
    // A last line without '\n' still counts.
    let n = buf.iter().filter(|b| **b == b'\n').count();
    n + usize::from(buf.last().is_some_and(|b| *b != b'\n'))
}

impl OpenSshKnownHosts {
    /// The OS default files (Linux/macOS/BSD: `~/.ssh/known_hosts{,2}`,
    /// `/etc/ssh/ssh_known_hosts{,2}`; Windows: `%USERPROFILE%\.ssh\known_hosts{,2}`,
    /// `%PROGRAMDATA%\ssh\ssh_known_hosts`).
    pub fn system_default() -> Self {
        Self::with_paths(default_paths())
    }

    /// Exactly these files (tests).
    pub fn with_paths(paths: Vec<PathBuf>) -> Self {
        let files = paths.iter().map(|_| FileState::default()).collect();
        Self {
            paths,
            state: Mutex::new(State {
                files,
                ..State::default()
            }),
        }
    }

    /// Reads nothing (`sftp.use_openssh_known_hosts = false`).
    pub fn disabled() -> Self {
        Self::with_paths(Vec::new())
    }

    /// [`system_default`](Self::system_default) or [`disabled`](Self::disabled) per
    /// `sftp.use_openssh_known_hosts`.
    pub fn from_settings(sftp: &SftpSettings) -> Self {
        if sftp.use_openssh_known_hosts {
            Self::system_default()
        } else {
            Self::disabled()
        }
    }

    /// The files this reader looks at.
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Every entry of every file, in file order (re-reads changed files).
    pub fn entries(&self) -> Arc<Vec<OpenSshEntry>> {
        let mut state = lock(&self.state);
        let mut changed = false;
        for (i, path) in self.paths.iter().enumerate() {
            let now = stamp(path);
            if state.files[i].stamp == now {
                continue;
            }
            changed = true;
            let entries = match now {
                None => {
                    debug!(path = %path.display(), "known_hosts file not found");
                    Vec::new()
                }
                Some(_) => self.load(&mut state, path),
            };
            state.files[i] = FileState {
                stamp: now,
                entries,
            };
        }
        if changed {
            let all: Vec<OpenSshEntry> = state
                .files
                .iter()
                .flat_map(|f| f.entries.iter().cloned())
                .collect();
            state.combined = Arc::new(all);
        }
        Arc::clone(&state.combined)
    }

    fn load(&self, state: &mut State, path: &Path) -> Vec<OpenSshEntry> {
        let text = match read_capped(path) {
            Ok(text) => text,
            Err(Skip::Unreadable(e)) => {
                debug!(path = %path.display(), error = %e, "known_hosts file not readable");
                return Vec::new();
            }
            Err(Skip::TooLarge) => {
                if state.warned_large.insert(path.to_path_buf()) {
                    warn!(path = %path.display(), "known_hosts file too large, skipped");
                    state.notices.push(format!(
                        "Warning: {} is larger than 4 MiB or 100000 lines and was skipped",
                        path.display()
                    ));
                }
                return Vec::new();
            }
        };
        let (entries, warnings) = parse_known_hosts(&text, path);
        for w in &warnings {
            debug!(path = %path.display(), line = w.line, "known_hosts line skipped or kept with a caveat");
        }
        if entries.iter().any(|e| e.marker == Marker::CertAuthority)
            && state.noted_ca.insert(path.to_path_buf())
        {
            debug!(path = %path.display(), "@cert-authority lines are ignored");
        }
        entries
    }

    /// User-facing warnings (oversized files) not yet logged; each is returned once.
    pub fn take_notices(&self) -> Vec<String> {
        std::mem::take(&mut lock(&self.state).notices)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::{fs, time::Duration};

    use courier_ftp_core::settings::Settings;

    use super::*;

    const ED: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBhYxpK5M9dWWLkngJsG1h11alcrHTyZO7bn447uw5it";

    fn set_mtime(path: &Path, secs: u64) {
        let f = File::options().write(true).open(path).unwrap();
        f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
            .unwrap();
    }

    #[test]
    fn reload_on_mtime_change_and_skip_large_file() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("known_hosts");
        let big = dir.path().join("big");
        let missing = dir.path().join("missing");
        fs::write(&a, format!("one.example ssh-ed25519 {ED}\n")).unwrap();
        set_mtime(&a, 1_000);
        let reader = OpenSshKnownHosts::with_paths(vec![missing.clone(), a.clone(), big.clone()]);
        let first = reader.entries();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].host_pattern, "one.example");
        assert_eq!(first[0].source, a);
        assert_eq!(first[0].line, 1);
        // Unchanged: the same snapshot.
        assert!(Arc::ptr_eq(&first, &reader.entries()));

        // Same size, new mtime → re-read.
        fs::write(&a, format!("two.example ssh-ed25519 {ED}\n")).unwrap();
        set_mtime(&a, 2_000);
        let second = reader.entries();
        assert_eq!(second[0].host_pattern, "two.example");

        // A file over 4 MiB is skipped with one notice.
        let line = format!("big.example ssh-ed25519 {ED}\n");
        let n = usize::try_from(MAX_FILE_BYTES).unwrap() / line.len() + 1;
        fs::write(&big, line.repeat(n)).unwrap();
        let third = reader.entries();
        assert_eq!(third.len(), 1, "the large file contributes nothing");
        let notices = reader.take_notices();
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(notices[0].contains("larger than 4 MiB"), "{notices:?}");
        // Changed again: still skipped, no second notice.
        fs::write(&big, line.repeat(n + 1)).unwrap();
        assert_eq!(reader.entries().len(), 1);
        assert!(reader.take_notices().is_empty());

        // More than 100 000 (short) lines: skipped too.
        fs::write(&big, "#\n".repeat(MAX_FILE_LINES + 1)).unwrap();
        assert_eq!(reader.entries().len(), 1);

        // Deleting a file drops its entries.
        fs::remove_file(&a).unwrap();
        assert!(reader.entries().is_empty());
        // A missing file appearing later is read.
        fs::write(&missing, format!("m.example ssh-ed25519 {ED}\n")).unwrap();
        assert_eq!(reader.entries()[0].host_pattern, "m.example");
    }

    #[test]
    fn disabled_reads_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("known_hosts");
        fs::write(&a, format!("one.example ssh-ed25519 {ED}\n")).unwrap();
        let disabled = OpenSshKnownHosts::disabled();
        assert!(disabled.paths().is_empty());
        assert!(disabled.entries().is_empty());

        let mut settings = Settings::default();
        assert!(settings.sftp.use_openssh_known_hosts);
        let on = OpenSshKnownHosts::from_settings(&settings.sftp);
        assert_eq!(on.paths(), default_paths().as_slice());
        settings.sftp.use_openssh_known_hosts = false;
        let off = OpenSshKnownHosts::from_settings(&settings.sftp);
        assert!(off.paths().is_empty());
        assert!(off.entries().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn default_paths_are_the_openssh_ones() {
        let paths = default_paths();
        assert!(paths.contains(&PathBuf::from("/etc/ssh/ssh_known_hosts")));
        assert!(paths.contains(&PathBuf::from("/etc/ssh/ssh_known_hosts2")));
    }
}
