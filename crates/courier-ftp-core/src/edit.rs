//! Viewing and editing files in external programs (T63), without the UI:
//!
//! - choosing the program: [`resolve_program`] (associations by glob, first
//!   match wins; then `$VISUAL`, `$EDITOR`, the platform opener; F3 View
//!   uses `$PAGER`/`less` for text);
//! - the private temporary copies: [`EditArea`]
//!   (`<cache>/edit/<run>/<random>/<name>`, directories `0700`, files
//!   `0600` on Unix);
//! - noticing saves: [`ChangeTracker`] (size and modification time, then a
//!   SHA-256 of the content, so a save without changes is not a change);
//! - noticing that the server's copy changed meanwhile: [`RemoteStamp`].
//!
//! Programs are started without a shell: the command line is split with
//! [`split_command`] and the file path is appended as its own argument.

use std::{
    ffi::OsString,
    fs, io,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use sha2::{Digest, Sha256};

use crate::{
    filters::glob_match,
    local::sanitize_local_name,
    model::{Entry, Timestamp},
    settings::{EditingSettings, EditorChoice, FileAssociation},
    transfer::completion::split_command,
};

/// The directory below the cache directory that holds the copies.
pub const EDIT_DIR: &str = "edit";

/// How many bytes [`looks_like_text`] needs to decide.
pub const SNIFF_LEN: usize = 8192;

/// Why a file is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenKind {
    /// F3: look at it; a remote copy is not watched.
    View,
    /// F4: change it; a remote copy is watched and offered for upload.
    Edit,
}

/// A program to open a file with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// The program and its arguments; the file path goes after them.
    pub argv: Vec<String>,
    /// Run in the terminal (the UI suspends itself and waits) instead of
    /// detached.
    pub terminal: bool,
}

impl Launch {
    /// `line` split without a shell; `None` when it is empty or has an
    /// unterminated quote.
    pub fn parse(line: &str, terminal: bool) -> Option<Self> {
        let argv = split_command(line)?;
        (!argv.is_empty()).then_some(Self { argv, terminal })
    }

    /// The program (first word).
    pub fn program(&self) -> &str {
        self.argv.first().map_or("", String::as_str)
    }

    /// The program and its arguments for `file`.
    pub fn command_for(&self, file: &Path) -> (OsString, Vec<OsString>) {
        let mut words = self.argv.iter().map(OsString::from);
        let program = words.next().unwrap_or_default();
        let mut args: Vec<OsString> = words.collect();
        args.push(file.as_os_str().to_owned());
        (program, args)
    }
}

/// The environment the default program comes from (`$VISUAL`, `$EDITOR`,
/// `$PAGER`). Tests build their own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EditorEnv {
    pub visual: Option<String>,
    pub editor: Option<String>,
    pub pager: Option<String>,
}

impl EditorEnv {
    /// This process's environment (empty values count as unset).
    pub fn from_process() -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        Self {
            visual: var("VISUAL"),
            editor: var("EDITOR"),
            pager: var("PAGER"),
        }
    }
}

/// Programs that open a window of their own (or hand the file to one) and
/// so run detached; everything else given as an editor command runs in the
/// terminal. Compared with the program's file name, without `.exe`.
const GUI_PROGRAMS: &[&str] = &[
    "code",
    "code-insiders",
    "codium",
    "cursor",
    "zed",
    "subl",
    "sublime_text",
    "atom",
    "gedit",
    "gnome-text-editor",
    "kate",
    "kwrite",
    "mousepad",
    "xed",
    "pluma",
    "leafpad",
    "featherpad",
    "geany",
    "gvim",
    "mvim",
    "notepad",
    "notepad++",
    "wordpad",
    "bbedit",
    "textmate",
    "mate",
    "xdg-open",
    "open",
    "explorer",
    "gio",
];

/// Whether `program` opens its own window (`code`, `gedit`, `xdg-open`…).
pub fn is_gui_program(program: &str) -> bool {
    let name = Path::new(program)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(program);
    let name = name.strip_suffix(".exe").unwrap_or(name).to_lowercase();
    GUI_PROGRAMS.contains(&name.as_str())
}

/// The program that opens a file with its default application: `xdg-open`,
/// `open` (macOS), `explorer` (Windows; `start` is a `cmd` built-in, and a
/// shell is never used).
pub fn platform_opener() -> Launch {
    let program = if cfg!(windows) {
        "explorer"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    Launch {
        argv: vec![program.to_owned()],
        terminal: false,
    }
}

/// The pager when `$PAGER` is unset.
fn default_pager() -> Launch {
    Launch {
        argv: vec![if cfg!(windows) { "more" } else { "less" }.to_owned()],
        terminal: true,
    }
}

/// The first association whose glob matches `name` (case-insensitive).
pub fn find_association<'a>(
    associations: &'a [FileAssociation],
    name: &str,
) -> Option<&'a FileAssociation> {
    let name = name.to_lowercase();
    associations
        .iter()
        .find(|a| glob_match(&a.pattern.trim().to_lowercase(), &name))
}

/// An editor command from the settings or the environment: in the terminal
/// unless it is a known windowed program.
fn editor_launch(line: &str) -> Option<Launch> {
    let mut launch = Launch::parse(line, true)?;
    launch.terminal = !is_gui_program(launch.program());
    Some(launch)
}

/// The program that opens `name` for `kind`:
///
/// 1. the first association matching `name` (both View and Edit);
/// 2. Edit: the configured editor command, else `$VISUAL`, then `$EDITOR`,
///    else the platform opener;
/// 3. View: for text (`is_text`) `$PAGER`, else `less` (`more` on Windows);
///    other files the platform opener.
///
/// An association or setting that can't be split (an unterminated quote) is
/// an error rather than silently skipped.
pub fn resolve_program(
    settings: &EditingSettings,
    name: &str,
    kind: OpenKind,
    is_text: bool,
    env: &EditorEnv,
) -> Result<Launch, String> {
    if let Some(a) = find_association(&settings.associations, name) {
        return Launch::parse(&a.command, a.terminal)
            .ok_or_else(|| format!("the association for {} has no valid command", a.pattern));
    }
    match kind {
        OpenKind::Edit => {
            if let EditorChoice::Command(line) = &settings.editor {
                return editor_launch(line)
                    .ok_or_else(|| "the editor command is not valid".to_owned());
            }
            for (var, value) in [("VISUAL", &env.visual), ("EDITOR", &env.editor)] {
                if let Some(line) = value {
                    return editor_launch(line).ok_or_else(|| format!("${var} is not valid"));
                }
            }
            Ok(platform_opener())
        }
        OpenKind::View if is_text => match &env.pager {
            Some(line) => Launch::parse(line, true).ok_or_else(|| "$PAGER is not valid".to_owned()),
            None => Ok(default_pager()),
        },
        OpenKind::View => Ok(platform_opener()),
    }
}

/// Whether the start of a file looks like text: no NUL byte (git's rule).
pub fn looks_like_text(head: &[u8]) -> bool {
    !head.contains(&0)
}

/// [`looks_like_text`] on the first [`SNIFF_LEN`] bytes of `path`.
pub fn file_looks_like_text(path: &Path) -> io::Result<bool> {
    let mut head = Vec::with_capacity(SNIFF_LEN);
    fs::File::open(path)?
        .take(SNIFF_LEN as u64)
        .read_to_end(&mut head)?;
    Ok(looks_like_text(&head))
}

// ------------------------------------------------------------ temp copies

/// Create `dir` (and missing parents) private to the user: `0700` on Unix
/// for every level created and for `dir` itself.
fn private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// A new empty file only the user can read (`0600` on Unix); fails if it
/// exists.
fn private_file(path: &Path) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).map(drop)
}

fn random_name() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// This run's directory of temporary copies, `<root>/edit/<run>`; each copy
/// gets a directory of its own so names never clash and the file keeps its
/// name (editors pick their mode from it).
#[derive(Debug, Clone)]
pub struct EditArea {
    run_dir: PathBuf,
}

impl EditArea {
    /// Create this run's directory below `root` (the cache directory).
    pub fn create(root: &Path) -> io::Result<Self> {
        let edit = root.join(EDIT_DIR);
        private_dir(&edit)?;
        let run_dir = edit.join(random_name());
        private_dir(&run_dir)?;
        Ok(Self { run_dir })
    }

    /// This run's directory.
    pub fn dir(&self) -> &Path {
        &self.run_dir
    }

    /// A new private, empty file named after `name` (made safe for the local
    /// filesystem) in a directory of its own.
    pub fn new_file(&self, name: &str) -> io::Result<PathBuf> {
        let dir = self.run_dir.join(random_name());
        private_dir(&dir)?;
        let path = dir.join(sanitize_local_name(name, '_'));
        private_file(&path)?;
        Ok(path)
    }

    /// Delete the copy `file` with its directory. Paths outside this run's
    /// directory are left alone.
    pub fn remove(&self, file: &Path) -> io::Result<()> {
        match file.parent() {
            Some(dir) if dir.parent() == Some(self.run_dir.as_path()) => {
                match fs::remove_dir_all(dir) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                    other => other,
                }
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a copy in this run's directory",
            )),
        }
    }

    /// Delete every copy except those in `keep`; the run's directory goes
    /// too when nothing is kept. Returns the number of copies kept.
    pub fn cleanup(&self, keep: &[PathBuf]) -> io::Result<usize> {
        let keep_dirs: Vec<&Path> = keep.iter().filter_map(|p| p.parent()).collect();
        let entries = match fs::read_dir(&self.run_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let mut kept = 0;
        for entry in entries {
            let path = entry?.path();
            if keep_dirs.contains(&path.as_path()) {
                kept += 1;
            } else {
                fs::remove_dir_all(&path)?;
            }
        }
        if kept == 0 {
            fs::remove_dir(&self.run_dir)?;
        }
        Ok(kept)
    }

    /// Delete the directories of earlier runs below `root` not touched for
    /// `max_age` (left behind by a crash, or kept with unsaved changes).
    /// Returns how many were deleted.
    pub fn sweep_stale(root: &Path, max_age: Duration, now: SystemTime) -> io::Result<usize> {
        let entries = match fs::read_dir(root.join(EDIT_DIR)) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let mut removed = 0;
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let old = meta
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age > max_age);
            if meta.is_dir() && old && fs::remove_dir_all(entry.path()).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

// ------------------------------------------------------- change detection

/// What a cheap `stat` says about a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStamp {
    pub len: u64,
    pub modified: Option<SystemTime>,
}

impl FileStamp {
    pub fn of(path: &Path) -> io::Result<Self> {
        let meta = fs::metadata(path)?;
        Ok(Self {
            len: meta.len(),
            modified: meta.modified().ok(),
        })
    }
}

/// SHA-256 of a file's content.
pub type ContentHash = [u8; 32];

/// SHA-256 of the file at `path`, read in chunks.
pub fn hash_file(path: &Path) -> io::Result<ContentHash> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// What [`ChangeTracker::poll`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll {
    /// Same content as last time (maybe saved again unchanged).
    Unchanged,
    /// New content since the last poll.
    Changed,
    /// The file is gone or unreadable.
    Missing,
}

/// Notices when a watched copy is saved with new content, and whether it
/// differs from what the server has.
#[derive(Debug, Clone)]
pub struct ChangeTracker {
    stamp: FileStamp,
    /// The content seen at the last poll.
    seen: ContentHash,
    /// The content the server has (downloaded or uploaded last).
    synced: ContentHash,
}

impl ChangeTracker {
    /// Start tracking `path`, whose content is what the server has.
    pub fn new(path: &Path) -> io::Result<Self> {
        let stamp = FileStamp::of(path)?;
        let hash = hash_file(path)?;
        Ok(Self {
            stamp,
            seen: hash,
            synced: hash,
        })
    }

    /// Look at the file again: a `stat`, and only when that changed, a hash.
    pub fn poll(&mut self, path: &Path) -> Poll {
        let Ok(stamp) = FileStamp::of(path) else {
            return Poll::Missing;
        };
        if stamp == self.stamp {
            return Poll::Unchanged;
        }
        let Ok(hash) = hash_file(path) else {
            return Poll::Missing;
        };
        self.stamp = stamp;
        if hash == self.seen {
            return Poll::Unchanged;
        }
        self.seen = hash;
        Poll::Changed
    }

    /// Whether the content last seen differs from the server's.
    pub fn is_dirty(&self) -> bool {
        self.seen != self.synced
    }

    /// The content last seen.
    pub fn seen(&self) -> ContentHash {
        self.seen
    }

    /// Content `hash` is now on the server (an upload of it finished).
    pub fn synced(&mut self, hash: ContentHash) {
        self.synced = hash;
    }
}

/// The server's size and modification time of a file, to notice that it
/// changed on the server between download and upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RemoteStamp {
    pub size: Option<u64>,
    pub modified: Option<Timestamp>,
}

impl RemoteStamp {
    pub fn of(entry: &Entry) -> Self {
        Self {
            size: entry.size,
            modified: entry.modified,
        }
    }

    /// Whether `now` shows a different file: the size or the time differs
    /// where both are known. Unknown values never conflict.
    pub fn changed_since(&self, now: &RemoteStamp) -> bool {
        let size = matches!((self.size, now.size), (Some(a), Some(b)) if a != b);
        let time = matches!((self.modified, now.modified), (Some(a), Some(b)) if a.time != b.time);
        size || time
    }
}

#[cfg(test)]
mod tests;
