//! Failure diagnostics.
//!
//! Harness objects ([`Sshd`](crate::Sshd), [`Ftpd`](crate::Ftpd),
//! [`Headless`](crate::Headless), [`PtyApp`](crate::PtyApp), …) call [`dump`] from their
//! `Drop` when the thread is panicking, so a failed assertion anywhere in a test prints
//! the container log tail, the last screen and the message-log tail. Waits that time out
//! carry the last observed state in their error as well.
//!
//! Dumps go to stderr (captured by the test harness and shown for failed tests).
//! [`capture`] additionally collects them on the current thread, so the harness can
//! test its own diagnostics.

use std::cell::RefCell;

thread_local! {
    static CAPTURE: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

/// Print a diagnostics section: `----- diag: <title> -----` followed by `body`.
pub fn dump(title: &str, body: &str) {
    let text = format!("\n----- diag: {title} -----\n{}\n", body.trim_end());
    eprint!("{text}");
    CAPTURE.with(|c| {
        if let Some(buf) = c.borrow_mut().as_mut() {
            buf.push(text);
        }
    });
}

/// Run `f`, collecting every [`dump`] made on this thread while it runs (also during a
/// panic unwinding out of `f`). Returns `f`'s result (`Err` with the panic payload if it
/// panicked) and the dumps.
pub fn capture<R>(f: impl FnOnce() -> R) -> (std::thread::Result<R>, Vec<String>) {
    CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    let dumps = CAPTURE.with(|c| c.borrow_mut().take()).unwrap_or_default();
    (result, dumps)
}

/// Whether diagnostics should be dumped now (the thread is unwinding from a panic).
pub fn failing() -> bool {
    std::thread::panicking()
}

/// The last `max_lines` lines of `text` (with a `[… N earlier lines]` marker).
pub fn tail(text: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let skip = lines.len().saturating_sub(max_lines);
    let mut out = String::new();
    if skip > 0 {
        out.push_str(&format!("[… {skip} earlier lines]\n"));
    }
    out.push_str(&lines[skip..].join("\n"));
    out
}

/// The last `max` bytes of `bytes` as lossy text.
pub(crate) fn tail_bytes(bytes: &[u8], max: usize) -> String {
    let start = bytes.len().saturating_sub(max);
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn tail_keeps_last_lines() {
        assert_eq!(tail("a\nb\nc", 5), "a\nb\nc");
        assert_eq!(tail("a\nb\nc", 2), "[… 1 earlier lines]\nb\nc");
    }

    #[test]
    fn capture_collects_dumps_during_panic() {
        struct Dumper;
        impl Drop for Dumper {
            fn drop(&mut self) {
                if failing() {
                    dump("dumper", "state");
                }
            }
        }
        let (res, dumps) = capture(|| {
            let _d = Dumper;
            panic!("boom");
        });
        assert!(res.is_err());
        assert_eq!(dumps.len(), 1);
        assert!(dumps[0].contains("----- diag: dumper -----"));
        assert!(dumps[0].contains("state"));
    }
}
