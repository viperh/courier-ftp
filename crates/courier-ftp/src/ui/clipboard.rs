//! The clipboard (T55): OSC 52 to the outer terminal plus the platform clipboard tool
//! (sverb `crates/sverb-tui/src/services/clipboard.rs` approach, D13; no `arboard`).
//!
//! Strategy:
//! - courier-ftp runs over SSH (`SSH_CONNECTION` or `SSH_TTY` set): **OSC 52 only** —
//!   the local clipboard would be the server's, and the outer terminal is on the
//!   user's machine.
//! - Otherwise: the platform tool when one was found, **plus** OSC 52 — except when the
//!   text is over [`OSC52_MAX_TEXT_BYTES`] and the tool took it, because a truncated
//!   OSC 52 copy would overwrite the full local one.
//!
//! OSC 52 is `ESC ] 52 ; c ; <base64> BEL`. Many terminals reject large payloads, so the
//! base64 payload is capped at [`OSC52_MAX_PAYLOAD`] (100 KiB): the text is cut at a
//! character boundary and [`CopyReport::truncated`] is set. The payload is base64, so it
//! cannot carry escape sequences. Copied text may hold a password (T62 copies URLs):
//! the buffers are zeroized and the text is never logged.

use std::{
    fmt,
    io::{self, Write},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tracing::debug;
use zeroize::Zeroizing;

use crate::ui::symbols::TermEnv;

/// Maximum OSC 52 payload (base64 bytes): 100 KiB.
pub(crate) const OSC52_MAX_PAYLOAD: usize = 100 * 1024;
/// Maximum text (UTF-8 bytes) whose base64 fits in [`OSC52_MAX_PAYLOAD`] (76 800).
pub(crate) const OSC52_MAX_TEXT_BYTES: usize = OSC52_MAX_PAYLOAD / 4 * 3;

const OSC52_PREFIX: &[u8] = b"\x1b]52;c;";

/// `ESC ] 52 ; c ; <base64> BEL` for `text`, cut to [`OSC52_MAX_TEXT_BYTES`] at a char
/// boundary. The flag says whether it was cut. The buffer is zeroized on drop.
pub(crate) fn osc52_sequence(text: &str) -> (Zeroizing<Vec<u8>>, bool) {
    let mut end = text.len().min(OSC52_MAX_TEXT_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let input = &text.as_bytes()[..end];
    let b64_len = base64::encoded_len(input.len(), true).unwrap_or(0);
    // Allocated once at its final size, so no unzeroized copy is left behind.
    let mut out = Zeroizing::new(vec![0u8; OSC52_PREFIX.len() + b64_len + 1]);
    out[..OSC52_PREFIX.len()].copy_from_slice(OSC52_PREFIX);
    let body = &mut out[OSC52_PREFIX.len()..OSC52_PREFIX.len() + b64_len];
    // The slice has exactly the encoded length, so this cannot fail.
    let _ = STANDARD.encode_slice(input, body);
    let last = out.len() - 1;
    out[last] = 0x07;
    (out, end < text.len())
}

/// A local (platform) clipboard; the seam for tests.
pub(crate) trait LocalClipboard: Send + fmt::Debug {
    /// Start setting the clipboard to `text` (may finish on a background thread).
    fn set_text(&mut self, text: &str) -> io::Result<()>;
}

/// The platform clipboard tool: macOS `pbcopy`; Windows `clip.exe`; elsewhere
/// `wl-copy` (if `WAYLAND_DISPLAY`), `xclip -selection clipboard` or
/// `xsel --clipboard --input` (if `DISPLAY`) — the first one found in `PATH`.
#[derive(Debug, Clone)]
pub(crate) struct CommandClipboard {
    program: &'static str,
    args: &'static [&'static str],
}

impl CommandClipboard {
    /// The first clipboard tool found for this platform and session, if any.
    pub(crate) fn detect() -> Option<Self> {
        let candidates: &[(&'static str, &'static [&'static str], bool)] =
            if cfg!(target_os = "macos") {
                &[("pbcopy", &[], true)]
            } else if cfg!(windows) {
                &[("clip.exe", &[], true)]
            } else {
                let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
                let x11 = std::env::var_os("DISPLAY").is_some();
                &[
                    ("wl-copy", &[], wayland),
                    ("xclip", &["-selection", "clipboard"], x11),
                    ("xsel", &["--clipboard", "--input"], x11),
                ]
            };
        candidates
            .iter()
            .find(|(program, _, usable)| *usable && in_path(program))
            .map(|&(program, args, _)| Self { program, args })
    }
}

fn in_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
}

impl LocalClipboard for CommandClipboard {
    fn set_text(&mut self, text: &str) -> io::Result<()> {
        // Fixed program and arguments: no shell, nothing user-controlled.
        let mut child = Command::new(self.program)
            .args(self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .inspect_err(|e| debug!(program = self.program, error = %e, "clipboard tool"))?;
        let text = Zeroizing::new(text.to_owned());
        let program = self.program;
        // The tool may keep running to own the selection (xclip): never wait on the UI
        // thread.
        std::thread::spawn(move || {
            if let Some(mut stdin) = child.stdin.take()
                && let Err(e) = stdin.write_all(text.as_bytes())
            {
                debug!(program, error = %e, "clipboard tool rejected input");
            }
            drop(text);
            match child.wait() {
                Ok(status) if !status.success() => {
                    debug!(program, %status, "clipboard tool failed");
                }
                Err(e) => debug!(program, error = %e, "clipboard tool failed"),
                Ok(_) => {}
            }
        });
        Ok(())
    }
}

/// What a copy did (status message and tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct CopyReport {
    /// An OSC 52 sequence was written.
    pub osc52: bool,
    /// The OSC 52 payload was cut at the cap.
    pub truncated: bool,
    /// The platform tool was given the text.
    pub local: bool,
}

/// Why nothing was copied.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ClipboardError {
    /// Neither the platform tool nor OSC 52 worked.
    #[error("no clipboard available")]
    NothingCopied,
    /// The platform tool could not be started and OSC 52 did not work either.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// The app's clipboard: one instance created by `App` at startup and shared with
/// components as a [`ClipboardHandle`]. [`Clipboard::copy`] never blocks on the
/// platform tool (it runs on a background thread).
pub(crate) struct Clipboard {
    over_ssh: bool,
    local: Option<Box<dyn LocalClipboard>>,
    out: Box<dyn Write + Send>,
}

impl fmt::Debug for Clipboard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Clipboard")
            .field("over_ssh", &self.over_ssh)
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

/// The shared clipboard.
pub(crate) type ClipboardHandle = Arc<Mutex<Clipboard>>;

impl Clipboard {
    /// A clipboard with explicit parts (tests).
    pub(crate) fn new(
        over_ssh: bool,
        local: Option<Box<dyn LocalClipboard>>,
        out: Box<dyn Write + Send>,
    ) -> Self {
        Self {
            over_ssh,
            local,
            out,
        }
    }

    /// Real setup: [`TermEnv::over_ssh`], [`CommandClipboard::detect`] when not over
    /// SSH, stdout for OSC 52.
    pub(crate) fn from_env(env: &TermEnv) -> Self {
        let over_ssh = env.over_ssh();
        let local = if over_ssh {
            None
        } else {
            CommandClipboard::detect().map(|c| Box::new(c) as Box<dyn LocalClipboard>)
        };
        Self::new(over_ssh, local, Box::new(io::stdout()))
    }

    /// Wraps it for sharing.
    pub(crate) fn into_handle(self) -> ClipboardHandle {
        Arc::new(Mutex::new(self))
    }

    /// Copies `text` (see the module docs for the strategy).
    pub(crate) fn copy(&mut self, text: &str) -> Result<CopyReport, ClipboardError> {
        let mut report = CopyReport::default();
        let mut tool_error = None;
        if !self.over_ssh
            && let Some(local) = &mut self.local
        {
            match local.set_text(text) {
                Ok(()) => report.local = true,
                Err(e) => {
                    debug!(error = %e, "local clipboard unavailable");
                    tool_error = Some(e);
                }
            }
        }
        let too_big = text.len() > OSC52_MAX_TEXT_BYTES;
        if !(report.local && too_big) {
            let (seq, truncated) = osc52_sequence(text);
            match self.out.write_all(&seq).and_then(|()| self.out.flush()) {
                Ok(()) => {
                    report.osc52 = true;
                    report.truncated = truncated;
                }
                Err(e) => debug!(error = %e, "cannot write OSC 52"),
            }
        }
        if report.osc52 || report.local {
            Ok(report)
        } else if let Some(e) = tool_error {
            Err(ClipboardError::Io(e))
        } else {
            Err(ClipboardError::NothingCopied)
        }
    }
}

/// The status-line text after copying `lines` lines: `Copied N lines`, the cut note, or
/// `Could not copy: <reason>`.
pub(crate) fn copy_status(lines: usize, result: &Result<CopyReport, ClipboardError>) -> String {
    match result {
        Ok(r) => {
            let s = if lines == 1 { "" } else { "s" };
            if r.truncated {
                format!("Copied {lines} line{s} (cut to 100 KiB for the terminal clipboard)")
            } else {
                format!("Copied {lines} line{s}")
            }
        }
        Err(e) => format!("Could not copy: {e}"),
    }
}

/// Test doubles shared with the message log tests.
#[cfg(test)]
pub(crate) mod fakes {
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    use super::LocalClipboard;

    /// Records what it was given; fails when `fail` is set.
    #[derive(Debug, Default, Clone)]
    pub(crate) struct FakeLocal {
        pub texts: Arc<Mutex<Vec<String>>>,
        pub fail: bool,
    }

    impl LocalClipboard for FakeLocal {
        fn set_text(&mut self, text: &str) -> io::Result<()> {
            if self.fail {
                return Err(io::Error::other("tool missing"));
            }
            self.texts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(text.to_owned());
            Ok(())
        }
    }

    /// A writer whose bytes the test can read; fails every write when `fail` is set.
    #[derive(Debug, Default, Clone)]
    pub(crate) struct SharedOut {
        pub bytes: Arc<Mutex<Vec<u8>>>,
        pub fail: bool,
    }

    impl SharedOut {
        /// Everything written so far.
        pub(crate) fn taken(&self) -> Vec<u8> {
            self.bytes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl io::Write for SharedOut {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail {
                return Err(io::Error::other("closed"));
            }
            self.bytes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::{fakes::*, *};

    fn decode(seq: &[u8]) -> String {
        let payload = &seq[OSC52_PREFIX.len()..seq.len() - 1];
        assert!(payload.len() <= OSC52_MAX_PAYLOAD, "{}", payload.len());
        match STANDARD.decode(payload) {
            Ok(b) => match String::from_utf8(b) {
                Ok(s) => s,
                Err(e) => panic!("utf8: {e}"),
            },
            Err(e) => panic!("base64: {e}"),
        }
    }

    #[test]
    fn osc52_sequence_format() {
        let (seq, cut) = osc52_sequence("hello");
        assert_eq!(seq.as_slice(), b"\x1b]52;c;aGVsbG8=\x07");
        assert!(!cut);
        let (seq, cut) = osc52_sequence("");
        assert_eq!(seq.as_slice(), b"\x1b]52;c;\x07");
        assert!(!cut);
    }

    #[test]
    fn osc52_cuts_at_char_boundary_and_cap() {
        let big = "é".repeat(OSC52_MAX_TEXT_BYTES);
        let (seq, cut) = osc52_sequence(&big);
        assert!(cut);
        let text = decode(&seq);
        assert!(text.len() <= OSC52_MAX_TEXT_BYTES);
        assert!(text.chars().all(|c| c == 'é'));
        assert_eq!(text.len(), OSC52_MAX_TEXT_BYTES);

        let exact = "a".repeat(OSC52_MAX_TEXT_BYTES);
        let (seq, cut) = osc52_sequence(&exact);
        assert!(!cut);
        assert_eq!(seq.len() - OSC52_PREFIX.len() - 1, OSC52_MAX_PAYLOAD);
        assert_eq!(decode(&seq), exact);
    }

    fn clipboard(over_ssh: bool, local: Option<FakeLocal>, out: &SharedOut) -> Clipboard {
        Clipboard::new(
            over_ssh,
            local.map(|l| Box::new(l) as Box<dyn LocalClipboard>),
            Box::new(out.clone()),
        )
    }

    #[test]
    fn copy_over_ssh_uses_osc52_only() {
        let local = FakeLocal::default();
        let out = SharedOut::default();
        let mut c = clipboard(true, Some(local.clone()), &out);
        let r = c.copy("hello").ok();
        assert_eq!(
            r,
            Some(CopyReport {
                osc52: true,
                truncated: false,
                local: false
            })
        );
        assert!(local.texts.lock().is_ok_and(|t| t.is_empty()));
        assert_eq!(out.taken(), b"\x1b]52;c;aGVsbG8=\x07");
    }

    #[test]
    fn copy_local_and_osc52() {
        let local = FakeLocal::default();
        let out = SharedOut::default();
        let mut c = clipboard(false, Some(local.clone()), &out);
        let r = c.copy("hello").ok();
        assert_eq!(
            r,
            Some(CopyReport {
                osc52: true,
                truncated: false,
                local: true
            })
        );
        assert!(local.texts.lock().is_ok_and(|t| *t == ["hello"]));
        assert_eq!(out.taken(), b"\x1b]52;c;aGVsbG8=\x07");
    }

    #[test]
    fn copy_oversize_skips_osc52_when_local_succeeds() {
        let big = "x".repeat(OSC52_MAX_TEXT_BYTES + 1);
        let local = FakeLocal::default();
        let out = SharedOut::default();
        let mut c = clipboard(false, Some(local.clone()), &out);
        let r = c.copy(&big).ok();
        assert_eq!(
            r,
            Some(CopyReport {
                osc52: false,
                truncated: false,
                local: true
            })
        );
        assert!(local.texts.lock().is_ok_and(|t| t[0] == big));
        assert!(out.taken().is_empty());

        // Without a tool the oversize text is cut for OSC 52.
        let out = SharedOut::default();
        let mut c = clipboard(false, None, &out);
        let r = c.copy(&big);
        assert!(matches!(
            r,
            Ok(CopyReport {
                osc52: true,
                truncated: true,
                local: false
            })
        ));
        assert_eq!(
            copy_status(3, &r),
            "Copied 3 lines (cut to 100 KiB for the terminal clipboard)"
        );
        // A failing tool falls back to the cut OSC 52 copy.
        let out = SharedOut::default();
        let failing = FakeLocal {
            fail: true,
            ..FakeLocal::default()
        };
        let mut c = clipboard(false, Some(failing), &out);
        assert!(matches!(
            c.copy(&big),
            Ok(CopyReport {
                osc52: true,
                truncated: true,
                local: false
            })
        ));
    }

    #[test]
    fn copy_with_nothing_available_errors() {
        let out = SharedOut {
            fail: true,
            ..SharedOut::default()
        };
        let mut c = clipboard(false, None, &out);
        let r = c.copy("hello");
        assert!(matches!(r, Err(ClipboardError::NothingCopied)));
        assert_eq!(copy_status(1, &r), "Could not copy: no clipboard available");

        let failing = FakeLocal {
            fail: true,
            ..FakeLocal::default()
        };
        let mut c = clipboard(false, Some(failing), &out);
        let r = c.copy("hello");
        assert!(matches!(r, Err(ClipboardError::Io(_))));
        assert_eq!(copy_status(1, &r), "Could not copy: tool missing");
    }

    #[test]
    fn copy_status_texts() {
        let ok: Result<CopyReport, ClipboardError> = Ok(CopyReport::default());
        assert_eq!(copy_status(1, &ok), "Copied 1 line");
        assert_eq!(copy_status(4, &ok), "Copied 4 lines");
    }

    #[test]
    fn from_env_over_ssh_has_no_local_tool() {
        let env = TermEnv {
            ssh_tty: true,
            ..TermEnv::default()
        };
        let c = Clipboard::from_env(&env);
        assert!(c.over_ssh);
        assert!(c.local.is_none());
    }
}
