//! [`PtyApp`]: the real `courier-ftp` binary in a PTY.
//!
//! Output is fed into a `vt100` emulator, so tests read the *screen* rather than raw
//! bytes (ratatui only writes changed cells). Keys are sent as space-separated chords
//! (`"ctrl-s"`, `"F5"`, `"g g"`), encoded as an xterm would ([`encode_chord`]).

use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::{OnceLock, mpsc},
    time::{Duration, Instant},
};

use portable_pty::{Child, CommandBuilder, ExitStatus, MasterPty, PtySize, native_pty_system};

use crate::{E2eError, Result, TestHome, WaitError, diag, home::MASTER_PASSWORD};

/// How often the PTY output is polled while waiting.
const READ_EVERY: Duration = Duration::from_millis(20);

/// How to launch the binary.
#[derive(Debug, Clone)]
pub struct PtyOptions {
    /// Terminal columns (default 120).
    pub cols: u16,
    /// Terminal rows (default 40).
    pub rows: u16,
    /// Command-line arguments.
    pub args: Vec<String>,
    /// Extra environment (after [`TestHome::env`]).
    pub env: Vec<(String, String)>,
    /// Limit of every wait (default: [`crate::timeout`], at least 20 s: the first
    /// launch may include a debug build's slow start).
    pub timeout: Option<Duration>,
}

impl Default for PtyOptions {
    fn default() -> Self {
        Self {
            cols: 120,
            rows: 40,
            args: Vec::new(),
            env: Vec::new(),
            timeout: None,
        }
    }
}

/// The `courier-ftp` binary to run: `COURIER_E2E_BINARY` if set, else
/// `<target>/<profile>/courier-ftp`, built once per process with
/// `cargo build -p courier-ftp --features test-hooks --locked` (a no-op when fresh; an
/// existing binary is used if the build fails).
///
/// # Errors
/// The build failed and there is no binary.
pub fn courier_ftp_binary() -> Result<PathBuf> {
    static BIN: OnceLock<std::result::Result<PathBuf, String>> = OnceLock::new();
    BIN.get_or_init(|| locate_or_build().map_err(|e| e.0))
        .clone()
        .map_err(E2eError)
}

fn locate_or_build() -> Result<PathBuf> {
    if let Ok(bin) = std::env::var("COURIER_E2E_BINARY")
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
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("Cargo.toml");
    let mut cmd = std::process::Command::new(cargo);
    cmd.args([
        "build",
        "-p",
        "courier-ftp",
        "--bin",
        "courier-ftp",
        "--features",
        "test-hooks",
        "--locked",
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
                "`cargo build -p courier-ftp --features test-hooks` failed ({}); build it \
                 first or set COURIER_E2E_BINARY\n{}",
                out.status,
                diag::tail(&String::from_utf8_lossy(&out.stderr), 40)
            )));
        }
        Err(e) => {
            return Err(E2eError::new(format!(
                "cannot run cargo ({e}); build courier-ftp first or set COURIER_E2E_BINARY"
            )));
        }
    }
    if bin.exists() {
        Ok(bin)
    } else {
        Err(E2eError::new(format!("{} is missing", bin.display())))
    }
}

/// A rendered screen: one string per row, and the cursor `(row, col)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screen {
    /// The rows (trailing blanks trimmed by the emulator).
    pub rows: Vec<String>,
    /// Cursor `(row, col)`.
    pub cursor: (u16, u16),
}

impl Screen {
    /// Whether any row contains `needle`.
    pub fn contains(&self, needle: &str) -> bool {
        self.rows.iter().any(|l| l.contains(needle))
    }

    /// The screen as text (rows joined with `\n`, trailing spaces trimmed).
    pub fn text(&self) -> String {
        self.rows
            .iter()
            .map(|l| l.trim_end())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Row `i` (`""` past the end).
    pub fn row(&self, i: usize) -> &str {
        self.rows.get(i).map_or("", String::as_str)
    }
}

impl std::fmt::Display for Screen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

/// The bytes an xterm sends for one chord (see the table in `tasks/76`):
/// `ctrl-a`…`ctrl-z`, `alt-<chord>`, `enter`, `esc`, `tab`, `shift-tab`, `backspace`,
/// `space`, `up`/`down`/`right`/`left`, `home`/`end`, `pgup`/`pgdn`/`delete`,
/// `F1`–`F12` (any case), or any other single character (as UTF-8).
///
/// # Errors
/// Unknown chord names (never silently sent as text).
pub fn encode_chord(chord: &str) -> Result<Vec<u8>> {
    let unknown = || E2eError::new(format!("unknown chord {chord:?}"));
    if chord.is_empty() {
        return Err(unknown());
    }
    let mut chars = chord.chars();
    if let (Some(c), None) = (chars.next(), chars.next()) {
        return Ok(c.to_string().into_bytes());
    }
    let lower = chord.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("ctrl-") {
        let mut cs = rest.chars();
        return match (cs.next(), cs.next()) {
            (Some(c @ 'a'..='z'), None) => Ok(vec![c as u8 - b'a' + 1]),
            _ => Err(unknown()),
        };
    }
    if let Some(rest) = chord
        .strip_prefix("alt-")
        .or_else(|| chord.strip_prefix("Alt-"))
    {
        let mut bytes = vec![0x1b];
        bytes.extend(encode_chord(rest).map_err(|_| unknown())?);
        return Ok(bytes);
    }
    let seq: &[u8] = match lower.as_str() {
        "enter" => b"\r",
        "esc" => b"\x1b",
        "tab" => b"\t",
        "shift-tab" => b"\x1b[Z",
        "backspace" => b"\x7f",
        "space" => b" ",
        "up" => b"\x1b[A",
        "down" => b"\x1b[B",
        "right" => b"\x1b[C",
        "left" => b"\x1b[D",
        "home" => b"\x1b[H",
        "end" => b"\x1b[F",
        "pgup" => b"\x1b[5~",
        "pgdn" => b"\x1b[6~",
        "delete" => b"\x1b[3~",
        "f1" => b"\x1bOP",
        "f2" => b"\x1bOQ",
        "f3" => b"\x1bOR",
        "f4" => b"\x1bOS",
        "f5" => b"\x1b[15~",
        "f6" => b"\x1b[17~",
        "f7" => b"\x1b[18~",
        "f8" => b"\x1b[19~",
        "f9" => b"\x1b[20~",
        "f10" => b"\x1b[21~",
        "f11" => b"\x1b[23~",
        "f12" => b"\x1b[24~",
        _ => return Err(unknown()),
    };
    Ok(seq.to_vec())
}

/// The `courier-ftp` binary on a PTY. Killed when dropped; the last screen and the
/// last 4 KiB of raw output are dumped first if the test is failing.
pub struct PtyApp {
    child: Box<dyn Child + Send + Sync>,
    master: Box<dyn MasterPty + Send>,
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
    /// Launch `courier-ftp` with `home`'s environment (working directory: the home).
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
        for k in [
            "COURIER_FTP_CONFIG",
            "COURIER_FTP_DATA",
            "COURIER_FTP_TEST_HOOK",
            "NO_COLOR",
        ] {
            cmd.env_remove(k);
        }
        for (k, v) in home.env().into_iter().chain(opts.env) {
            cmd.env(k, v);
        }
        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| E2eError::new(format!("spawn {}: {e}", bin.display())))?;
        // The child holds its own copy of the slave; ours must go, or the reader
        // never sees EOF after the child exits.
        drop(pair.slave);
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
            writer,
            rx,
            parser: vt100::Parser::new(opts.rows, opts.cols, 0),
            raw: Vec::new(),
            exit: None,
            timeout: opts
                .timeout
                .unwrap_or_else(|| crate::timeout().max(Duration::from_secs(20))),
        })
    }

    /// The process id.
    pub fn pid(&self) -> Option<u32> {
        self.child.process_id()
    }

    fn feed(&mut self, chunk: &[u8]) {
        self.raw.extend_from_slice(chunk);
        self.parser.process(chunk);
        // Answer cursor position requests (`ESC [ 6 n`) like a terminal would.
        if chunk.windows(4).any(|w| w == b"\x1b[6n") {
            let (row, col) = self.parser.screen().cursor_position();
            let reply = format!("\x1b[{};{}R", row + 1, col + 1);
            let _ = self.writer.write_all(reply.as_bytes());
            let _ = self.writer.flush();
        }
    }

    /// Process output, waiting up to `wait` for the first chunk (the PTY reader loop).
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
        Screen {
            rows: screen.rows(0, cols).collect(),
            cursor: screen.cursor_position(),
        }
    }

    /// Whether the app currently shows the alternate screen.
    pub fn alternate_screen(&mut self) -> bool {
        self.pump(Duration::ZERO);
        self.parser.screen().alternate_screen()
    }

    /// Every byte the app wrote so far.
    pub fn raw_output(&self) -> &[u8] {
        &self.raw
    }

    /// Wait until `pred` holds for the screen. Returns that screen.
    ///
    /// # Errors
    /// Not within the timeout (or the app exited first); `last` is the screen.
    pub fn wait_for_screen(
        &mut self,
        what: &str,
        pred: impl Fn(&Screen) -> bool,
    ) -> std::result::Result<Screen, WaitError> {
        let started = Instant::now();
        loop {
            self.pump(READ_EVERY);
            let screen = self.render();
            if pred(&screen) {
                return Ok(screen);
            }
            let exited = self.poll_exit();
            if exited.is_some() || started.elapsed() > self.timeout {
                // Take what the app wrote while exiting.
                self.pump(READ_EVERY);
                let screen = self.render();
                if pred(&screen) {
                    return Ok(screen);
                }
                let why = match exited {
                    Some(status) => format!(" (the app exited: {status:?})"),
                    None => String::new(),
                };
                return Err(WaitError {
                    what: format!("{what}{why}"),
                    waited: started.elapsed(),
                    last: screen.text(),
                });
            }
        }
    }

    /// Wait until the screen contains `needle`.
    ///
    /// # Errors
    /// As [`PtyApp::wait_for_screen`].
    pub fn wait_for_text(&mut self, needle: &str) -> std::result::Result<Screen, WaitError> {
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

    /// Type `text` literally.
    ///
    /// # Errors
    /// The PTY is closed.
    pub fn send_text(&mut self, text: &str) -> Result<()> {
        self.send_raw(text.as_bytes())
    }

    /// Press space-separated chords (`"ctrl-s"`, `"F5"`, `"g g"`, `"shift-tab"`); see
    /// [`encode_chord`]. All chords are validated before anything is sent.
    ///
    /// # Errors
    /// An unknown chord, or a closed PTY.
    pub fn send_keys(&mut self, chords: &str) -> Result<()> {
        let encoded = chords
            .split_whitespace()
            .map(encode_chord)
            .collect::<Result<Vec<_>>>()?;
        for bytes in encoded {
            self.pump(Duration::ZERO);
            self.send_raw(&bytes)?;
        }
        Ok(())
    }

    /// Resize the PTY (the app gets `SIGWINCH`) and the local emulator.
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
            .map_err(|e| E2eError::new(format!("resize: {e}")))?;
        // Let the app handle SIGWINCH before the next key: crossterm 0.29 drops an input
        // notification that arrives in the same epoll batch as the signal.
        let until = Instant::now() + Duration::from_millis(300);
        while Instant::now() < until {
            self.pump(READ_EVERY);
        }
        Ok(())
    }

    /// Press `ctrl-q` and wait for the app to exit, pressing it again every 2 s (up to
    /// 5 times). A repeated key also wakes crossterm if it missed the first one (see
    /// [`PtyApp::resize`]); with nothing blocking, extra Quit actions are harmless.
    ///
    /// # Errors
    /// Sending failed, or the app did not exit within the timeout (it is killed).
    pub fn quit(&mut self) -> std::result::Result<ExitStatus, WaitError> {
        for _ in 0..5 {
            self.send_keys("ctrl-q").map_err(|e| WaitError {
                what: "pressing ctrl-q".into(),
                waited: Duration::ZERO,
                last: e.to_string(),
            })?;
            let until = Instant::now() + Duration::from_secs(2);
            while Instant::now() < until {
                self.pump(READ_EVERY);
                if self.poll_exit().is_some() {
                    return self.wait_exit();
                }
            }
        }
        self.wait_exit()
    }

    /// Wait for the unlock screen (T60), type [`MASTER_PASSWORD`] and Enter, and wait
    /// for the file panes.
    ///
    /// # Errors
    /// A wait timed out.
    pub fn unlock(&mut self) -> std::result::Result<Screen, WaitError> {
        self.wait_for_text("Unlock")?;
        self.send_text(MASTER_PASSWORD)
            .and_then(|()| self.send_raw(b"\r"))
            .map_err(|e| WaitError {
                what: "typing the master password".into(),
                waited: Duration::ZERO,
                last: e.to_string(),
            })?;
        self.wait_for_screen("the file panes after unlocking", |s| {
            s.contains("Local") && !s.contains("Unlock")
        })
    }

    fn poll_exit(&mut self) -> Option<ExitStatus> {
        if self.exit.is_none()
            && let Ok(Some(status)) = self.child.try_wait()
        {
            self.exit = Some(status);
        }
        self.exit.clone()
    }

    /// Wait for the process to exit (processing its output meanwhile, including what it
    /// wrote while exiting).
    ///
    /// # Errors
    /// It did not exit within the timeout (it is killed).
    pub fn wait_exit(&mut self) -> std::result::Result<ExitStatus, WaitError> {
        let started = Instant::now();
        loop {
            self.pump(READ_EVERY);
            if let Some(status) = self.poll_exit() {
                // Drain until the reader sees EOF (bounded).
                let drain_until = Instant::now() + Duration::from_secs(2);
                while Instant::now() < drain_until {
                    match self.rx.recv_timeout(READ_EVERY) {
                        Ok(chunk) => self.feed(&chunk),
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                return Ok(status);
            }
            if started.elapsed() > self.timeout {
                let _ = self.child.kill();
                return Err(WaitError {
                    what: "the app to exit".into(),
                    waited: started.elapsed(),
                    last: self.render().text(),
                });
            }
        }
    }

    /// Dump the screen and the last 4 KiB of raw output now ([`diag::dump`]).
    pub fn dump(&mut self) {
        let screen = self.screen();
        let pid = self.child.process_id();
        diag::dump(&format!("courier-ftp screen (pid {pid:?})"), &screen.text());
        diag::dump(
            &format!("courier-ftp raw output, last 4 KiB (pid {pid:?})"),
            &format!("{:?}", diag::tail_bytes(&self.raw, 4096)),
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn chord_table_encodes_every_named_key() {
        let table: &[(&str, &[u8])] = &[
            ("ctrl-a", b"\x01"),
            ("ctrl-s", b"\x13"),
            ("ctrl-z", b"\x1a"),
            ("F1", b"\x1bOP"),
            ("F2", b"\x1bOQ"),
            ("F3", b"\x1bOR"),
            ("f4", b"\x1bOS"),
            ("F5", b"\x1b[15~"),
            ("F6", b"\x1b[17~"),
            ("F7", b"\x1b[18~"),
            ("F8", b"\x1b[19~"),
            ("F9", b"\x1b[20~"),
            ("F10", b"\x1b[21~"),
            ("F11", b"\x1b[23~"),
            ("F12", b"\x1b[24~"),
            ("enter", b"\r"),
            ("esc", b"\x1b"),
            ("tab", b"\t"),
            ("shift-tab", b"\x1b[Z"),
            ("backspace", b"\x7f"),
            ("space", b" "),
            ("up", b"\x1b[A"),
            ("down", b"\x1b[B"),
            ("right", b"\x1b[C"),
            ("left", b"\x1b[D"),
            ("home", b"\x1b[H"),
            ("end", b"\x1b[F"),
            ("pgup", b"\x1b[5~"),
            ("pgdn", b"\x1b[6~"),
            ("delete", b"\x1b[3~"),
            ("alt-x", b"\x1bx"),
            ("alt-enter", b"\x1b\r"),
            ("x", b"x"),
            ("G", b"G"),
            ("ü", "ü".as_bytes()),
        ];
        for (chord, bytes) in table {
            assert_eq!(encode_chord(chord).unwrap(), *bytes, "{chord}");
        }
    }

    #[test]
    fn unknown_chord_is_an_error() {
        for chord in [
            "", "ctrl-1", "ctrl-ab", "hyper-x", "f13", "enterr", "alt-nope",
        ] {
            let err = encode_chord(chord).unwrap_err();
            assert!(err.0.contains("unknown chord"), "{chord}: {err}");
        }
    }

    #[test]
    fn screen_helpers() {
        let s = Screen {
            rows: vec!["Local  ".into(), "Remote".into()],
            cursor: (0, 0),
        };
        assert!(s.contains("Remote"));
        assert_eq!(s.text(), "Local\nRemote");
        assert_eq!(s.row(1), "Remote");
        assert_eq!(s.row(9), "");
    }
}
