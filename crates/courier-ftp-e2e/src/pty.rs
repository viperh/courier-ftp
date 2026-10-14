//! [`PtyApp`]: the real `courier-ftp` binary in a pseudo-terminal.
//!
//! Output is fed into a `vt100` parser, so tests read the *screen* rather than
//! raw bytes (ratatui only writes changed cells). Cursor-position queries
//! (`CSI 6n`) are answered like a real terminal would. Keys are sent in a
//! small chord syntax: `"ctrl-x v"`, `"alt-c"`, `"enter"`, `"F10"`, `"g g"`.
//!
//! Adapted from sverb's `sverb-e2e` PTY driver.

use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::{OnceLock, mpsc},
    time::{Duration, Instant},
};

use portable_pty::{
    Child, CommandBuilder, ExitStatus, MasterPty, PtySize, SlavePty, native_pty_system,
};

use crate::{E2eError, Result, TestHome, diag};

/// The pause after a lone Esc, so the next key isn't read as Alt+key.
const ESC_SETTLE: Duration = Duration::from_millis(150);

/// How to launch the binary.
#[derive(Debug, Clone)]
pub struct PtyOptions {
    /// Terminal columns.
    pub cols: u16,
    /// Terminal rows.
    pub rows: u16,
    /// Command-line arguments.
    pub args: Vec<String>,
    /// Extra environment, after the home's own (`None` removes a variable).
    pub env: Vec<(String, Option<String>)>,
}

impl Default for PtyOptions {
    fn default() -> Self {
        Self {
            cols: 120,
            rows: 36,
            args: Vec::new(),
            env: Vec::new(),
        }
    }
}

/// The `courier-ftp` binary to run: `COURIER_FTP_BIN`, else the binary of
/// this build profile next to the test executable, built once per process
/// with `cargo build -p courier-ftp` (a no-op when it is fresh).
///
/// # Errors
/// The build failed or the binary is missing.
pub fn courier_ftp_binary() -> Result<PathBuf> {
    static BIN: OnceLock<std::result::Result<PathBuf, String>> = OnceLock::new();
    BIN.get_or_init(|| locate_or_build().map_err(|e| e.0))
        .clone()
        .map_err(E2eError)
}

fn locate_or_build() -> Result<PathBuf> {
    if let Ok(bin) = std::env::var("COURIER_FTP_BIN")
        && !bin.is_empty()
    {
        return Ok(PathBuf::from(bin));
    }
    // <target>/<profile>/deps/<test-exe>
    let exe = std::env::current_exe()?;
    let profile_dir = exe
        .parent()
        .and_then(|deps| deps.parent())
        .ok_or_else(|| E2eError::new(format!("unexpected test path {}", exe.display())))?;
    let bin = profile_dir.join(format!("courier-ftp{}", std::env::consts::EXE_SUFFIX));
    let target_dir = profile_dir
        .parent()
        .ok_or_else(|| E2eError::new("no target directory"))?;
    let profile = profile_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("debug");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let mut cmd = std::process::Command::new(cargo);
    cmd.args([
        "build",
        "-p",
        "courier-ftp",
        "--bin",
        "courier-ftp",
        "--manifest-path",
    ])
    .arg(&manifest)
    .arg("--target-dir")
    .arg(target_dir);
    match profile {
        "debug" => {}
        "release" => {
            cmd.arg("--release");
        }
        other => {
            cmd.args(["--profile", other]);
        }
    }
    match cmd.output() {
        Ok(out) if out.status.success() => {}
        // Fall back to an existing binary, but say so.
        result if bin.exists() => {
            let why = match result {
                Ok(out) => diag::tail(&String::from_utf8_lossy(&out.stderr), 15),
                Err(e) => e.to_string(),
            };
            eprintln!(
                "courier-ftp-e2e: `cargo build -p courier-ftp` failed; using the existing {}\n{why}",
                bin.display()
            );
        }
        Ok(out) => {
            return Err(E2eError::new(format!(
                "`cargo build -p courier-ftp` failed ({}); build it first or set COURIER_FTP_BIN\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Err(e) => {
            return Err(E2eError::new(format!(
                "cannot run cargo ({e}); build courier-ftp first or set COURIER_FTP_BIN"
            )));
        }
    }
    if bin.exists() {
        Ok(bin)
    } else {
        Err(E2eError::new(format!("{} is missing", bin.display())))
    }
}

/// A rendered screen, one string per row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screen {
    /// The rows (trailing spaces trimmed).
    pub lines: Vec<String>,
}

impl Screen {
    /// Whether any row contains `needle`.
    pub fn contains(&self, needle: &str) -> bool {
        self.lines.iter().any(|l| l.contains(needle))
    }

    /// The screen as text (rows joined with `\n`).
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }
}

impl std::fmt::Display for Screen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

/// The `courier-ftp` binary on a PTY. Killed when dropped; the last screen
/// is dumped first if the test is failing.
pub struct PtyApp {
    child: Box<dyn Child + Send + Sync>,
    master: Box<dyn MasterPty + Send>,
    _slave: Box<dyn SlavePty + Send>,
    writer: Box<dyn Write + Send>,
    rx: mpsc::Receiver<Vec<u8>>,
    parser: vt100::Parser,
    raw: Vec<u8>,
    exit: Option<ExitStatus>,
    timeout: Duration,
}

impl std::fmt::Debug for PtyApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtyApp")
            .field("pid", &self.child.process_id())
            .field("bytes", &self.raw.len())
            .field("exit", &self.exit)
            .finish_non_exhaustive()
    }
}

impl PtyApp {
    /// Launch `courier-ftp` in `home` (its `COURIER_FTP_HOME`, keyring off,
    /// no update check).
    ///
    /// # Errors
    /// The binary is missing or the PTY could not be opened.
    pub fn launch(home: &TestHome, opts: PtyOptions) -> Result<Self> {
        let bin = courier_ftp_binary()?;
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: opts.rows,
                cols: opts.cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| E2eError::new(format!("openpty: {e}")))?;
        let mut cmd = CommandBuilder::new(&bin);
        cmd.args(&opts.args);
        cmd.cwd(home.path());
        cmd.env("TERM", "xterm-256color");
        cmd.env("COURIER_FTP_NO_UPDATE_CHECK", "1");
        cmd.env_remove("RUST_LOG");
        cmd.env_remove("COURIER_FTP_LOG_LEVEL");
        let env = home
            .env()
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .chain(opts.env);
        for (k, v) in env {
            match v {
                Some(v) => cmd.env(k, v),
                None => cmd.env_remove(k),
            }
        }
        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| E2eError::new(format!("spawn {}: {e}", bin.display())))?;
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| E2eError::new(format!("pty reader: {e}")))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| E2eError::new(format!("pty writer: {e}")))?;
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut buf = [0_u8; 8192];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            master: pair.master,
            _slave: pair.slave,
            writer,
            rx,
            parser: vt100::Parser::new(opts.rows, opts.cols, 0),
            raw: Vec::new(),
            exit: None,
            timeout: crate::timeout().max(Duration::from_secs(30)),
        })
    }

    /// Use `timeout` for the waits.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn feed(&mut self, chunk: &[u8]) {
        let before = self.raw.len().saturating_sub(3);
        self.raw.extend_from_slice(chunk);
        self.parser.process(chunk);
        // Answer cursor-position queries (`ESC [ 6 n`), also when the query
        // was split across chunks.
        let queries = count(&self.raw[before..], b"\x1b[6n");
        for _ in 0..queries {
            let (row, col) = self.parser.screen().cursor_position();
            let reply = format!("\x1b[{};{}R", row + 1, col + 1);
            let _ = self.writer.write_all(reply.as_bytes());
        }
        let _ = self.writer.flush();
    }

    /// Process output, waiting up to `wait` for the first chunk.
    fn pump(&mut self, wait: Duration) {
        if let Ok(chunk) = self.rx.recv_timeout(wait) {
            self.feed(&chunk);
        }
        while let Ok(chunk) = self.rx.try_recv() {
            self.feed(&chunk);
        }
    }

    /// The current screen (after processing pending output).
    pub fn screen(&mut self) -> Screen {
        self.pump(Duration::ZERO);
        self.render()
    }

    fn render(&self) -> Screen {
        let screen = self.parser.screen();
        let (_, cols) = screen.size();
        let lines = screen
            .rows(0, cols)
            .map(|l| l.trim_end().to_owned())
            .collect();
        Screen { lines }
    }

    /// Every byte the app wrote so far.
    pub fn raw_output(&self) -> &[u8] {
        &self.raw
    }

    /// Wait until `pred` holds for the screen. Returns that screen.
    ///
    /// # Errors
    /// Not within the timeout (or the app exited first); the error shows the
    /// screen.
    pub fn wait_for_screen(
        &mut self,
        what: &str,
        pred: impl Fn(&Screen) -> bool,
    ) -> Result<Screen> {
        let started = Instant::now();
        loop {
            self.pump(Duration::from_millis(25));
            let screen = self.render();
            if pred(&screen) {
                return Ok(screen);
            }
            let exited = self.poll_exit();
            if exited.is_some() || started.elapsed() > self.timeout {
                let why = match exited {
                    Some(status) => format!("the app exited ({status:?})"),
                    None => "timed out".into(),
                };
                return Err(E2eError::new(format!(
                    "{what}: {why} after {:?}\n--- screen ---\n{}",
                    started.elapsed(),
                    screen.text()
                )));
            }
        }
    }

    /// Wait until the screen contains `needle`.
    ///
    /// # Errors
    /// As [`PtyApp::wait_for_screen`].
    pub fn wait_for_text(&mut self, needle: &str) -> Result<Screen> {
        self.wait_for_screen(&format!("{needle:?} on screen"), |s| s.contains(needle))
    }

    /// Write raw bytes.
    ///
    /// # Errors
    /// The PTY is closed.
    pub fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.write_all(bytes)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Type `text` literally (bracketed paste is not used).
    ///
    /// # Errors
    /// The PTY is closed.
    pub fn send_text(&mut self, text: &str) -> Result<()> {
        self.send_raw(text.as_bytes())
    }

    /// Press keys: chords separated by spaces (`"ctrl-x v"`, `"alt-c"`,
    /// `"enter"`, `"F10"`, `"down down enter"`). See [`encode_chord`].
    ///
    /// # Errors
    /// An unknown key name, or a closed PTY.
    pub fn send_keys(&mut self, chords: &str) -> Result<()> {
        for chord in chords.split_whitespace() {
            self.pump(Duration::ZERO);
            let bytes = encode_chord(chord)
                .ok_or_else(|| E2eError::new(format!("unknown key {chord:?}")))?;
            self.send_raw(&bytes)?;
            if bytes == b"\x1b" {
                // A lone ESC is only known to be Esc (not the start of an
                // Alt chord or escape sequence) once nothing follows it, as
                // in a real terminal: give the app's input parser time to
                // decide before the next key.
                self.pump(ESC_SETTLE);
            }
        }
        Ok(())
    }

    /// Resize the PTY (the app gets `SIGWINCH`) and the local screen.
    ///
    /// # Errors
    /// The resize failed.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.pump(Duration::ZERO);
        self.parser.screen_mut().set_size(rows, cols);
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| E2eError::new(format!("resize: {e}")))
    }

    fn poll_exit(&mut self) -> Option<ExitStatus> {
        if self.exit.is_none()
            && let Ok(Some(status)) = self.child.try_wait()
        {
            self.exit = Some(status);
        }
        self.exit.clone()
    }

    /// Wait for the process to exit (processing its output meanwhile).
    ///
    /// # Errors
    /// It did not exit within the timeout (it is killed).
    pub fn wait_exit(&mut self) -> Result<ExitStatus> {
        let started = Instant::now();
        loop {
            self.pump(Duration::from_millis(25));
            if let Some(status) = self.poll_exit() {
                let drain_until = Instant::now() + Duration::from_millis(500);
                while Instant::now() < drain_until {
                    match self.rx.recv_timeout(Duration::from_millis(50)) {
                        Ok(chunk) => self.feed(&chunk),
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                return Ok(status);
            }
            if started.elapsed() > self.timeout {
                let _ = self.child.kill();
                return Err(E2eError::new(format!(
                    "the app did not exit within {:?}\n--- screen ---\n{}",
                    self.timeout,
                    self.render().text()
                )));
            }
        }
    }

    /// Dump the screen now ([`diag::dump`]).
    pub fn dump(&mut self) {
        let screen = self.screen();
        diag::dump(
            &format!("courier-ftp screen (pid {:?})", self.child.process_id()),
            &screen.text(),
        );
    }
}

impl Drop for PtyApp {
    fn drop(&mut self) {
        if diag::failing() {
            self.dump();
        }
        if self.poll_exit().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

/// The bytes a terminal sends for one chord: a key name (`enter`, `esc`,
/// `tab`, `backtab`, `backspace`, `space`, `up`, `down`, `left`, `right`,
/// `home`, `end`, `pgup`, `pgdn`, `insert`, `delete`, `F1`–`F12`) or one
/// character, optionally with `ctrl-` and/or `alt-` (`ctrl-x`, `alt-c`).
pub fn encode_chord(chord: &str) -> Option<Vec<u8>> {
    let mut rest = chord;
    let (mut ctrl, mut alt) = (false, false);
    loop {
        if let Some(r) = rest.strip_prefix("ctrl-").filter(|r| !r.is_empty()) {
            ctrl = true;
            rest = r;
        } else if let Some(r) = rest.strip_prefix("alt-").filter(|r| !r.is_empty()) {
            alt = true;
            rest = r;
        } else {
            break;
        }
    }
    let mut out = Vec::new();
    if alt {
        out.push(0x1b);
    }
    let named: Option<&[u8]> = match rest.to_ascii_lowercase().as_str() {
        "enter" => Some(b"\r"),
        "esc" => Some(b"\x1b"),
        "tab" => Some(b"\t"),
        "backtab" => Some(b"\x1b[Z"),
        "backspace" => Some(b"\x7f"),
        "space" => Some(b" "),
        "up" => Some(b"\x1b[A"),
        "down" => Some(b"\x1b[B"),
        "right" => Some(b"\x1b[C"),
        "left" => Some(b"\x1b[D"),
        "home" => Some(b"\x1b[H"),
        "end" => Some(b"\x1b[F"),
        "pgup" => Some(b"\x1b[5~"),
        "pgdn" => Some(b"\x1b[6~"),
        "insert" => Some(b"\x1b[2~"),
        "delete" => Some(b"\x1b[3~"),
        "f1" => Some(b"\x1bOP"),
        "f2" => Some(b"\x1bOQ"),
        "f3" => Some(b"\x1bOR"),
        "f4" => Some(b"\x1bOS"),
        "f5" => Some(b"\x1b[15~"),
        "f6" => Some(b"\x1b[17~"),
        "f7" => Some(b"\x1b[18~"),
        "f8" => Some(b"\x1b[19~"),
        "f9" => Some(b"\x1b[20~"),
        "f10" => Some(b"\x1b[21~"),
        "f11" => Some(b"\x1b[23~"),
        "f12" => Some(b"\x1b[24~"),
        _ => None,
    };
    if let Some(bytes) = named {
        if ctrl {
            return None;
        }
        out.extend_from_slice(bytes);
        return Some(out);
    }
    let mut chars = rest.chars();
    let c = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    if ctrl {
        let lower = c.to_ascii_lowercase();
        if !lower.is_ascii_lowercase() {
            return None;
        }
        out.push(lower as u8 - b'a' + 1);
    } else {
        let mut buf = [0; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::encode_chord;

    #[test]
    fn chords() {
        assert_eq!(encode_chord("ctrl-x").unwrap(), [0x18]);
        assert_eq!(encode_chord("alt-c").unwrap(), b"\x1bc");
        assert_eq!(encode_chord("enter").unwrap(), b"\r");
        assert_eq!(encode_chord("F10").unwrap(), b"\x1b[21~");
        assert_eq!(encode_chord("g").unwrap(), b"g");
        assert_eq!(encode_chord("G").unwrap(), b"G");
        assert!(encode_chord("ctrl-enter").is_none());
        assert!(encode_chord("nope").is_none());
    }
}
