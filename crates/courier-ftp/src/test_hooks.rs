//! Startup and shutdown hooks for the PTY tests (T76) — feature `test-hooks` only,
//! never in release builds.
//!
//! `COURIER_FTP_TEST_HOOK`, read once after the TUI entered the alternate screen:
//! - `exit-after-panes`: quit right after the file panes were drawn the first time
//!   (startup benchmark);
//! - `exit:<ms>`: normal shutdown after `<ms>` milliseconds.
//!
//! The crash hooks (`panic-ui`, `panic-thread`, `panic-blocking`) are added by T91.
//! Without the feature the variable is ignored.
//!
//! `COURIER_FTP_TEST_ARGON2=test` (T60): the vault is created and re-wrapped with
//! `Argon2Cost::TEST`, so a debug binary's first run takes milliseconds.

use std::time::Duration;

/// The environment variable.
pub(crate) const HOOK_ENV: &str = "COURIER_FTP_TEST_HOOK";

/// The Argon2 override variable.
pub(crate) const ARGON2_ENV: &str = "COURIER_FTP_TEST_ARGON2";

/// `Argon2Cost::TEST` when `COURIER_FTP_TEST_ARGON2=test` (test-hooks builds only).
pub(crate) fn argon2_cost_override() -> Option<courier_ftp_core::vault::Argon2Cost> {
    if !cfg!(feature = "test-hooks") {
        return None;
    }
    (std::env::var(ARGON2_ENV).ok().as_deref() == Some("test"))
        .then_some(courier_ftp_core::vault::Argon2Cost::TEST)
}

/// A parsed hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestHook {
    /// Quit after the first frame.
    ExitAfterPanes,
    /// Quit after this long.
    ExitAfter(Duration),
}

/// Parses a hook value; `None` for unknown values.
pub(crate) fn parse(value: &str) -> Option<TestHook> {
    match value {
        "exit-after-panes" => Some(TestHook::ExitAfterPanes),
        v => v
            .strip_prefix("exit:")
            .and_then(|ms| ms.parse::<u64>().ok())
            .map(|ms| TestHook::ExitAfter(Duration::from_millis(ms))),
    }
}

/// The hook from the environment (test-hooks builds only; always `None` otherwise).
pub(crate) fn from_env() -> Option<TestHook> {
    if !cfg!(feature = "test-hooks") {
        return None;
    }
    std::env::var(HOOK_ENV).ok().as_deref().and_then(parse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hooks() {
        assert_eq!(parse("exit-after-panes"), Some(TestHook::ExitAfterPanes));
        assert_eq!(
            parse("exit:250"),
            Some(TestHook::ExitAfter(Duration::from_millis(250)))
        );
        assert_eq!(parse("exit:"), None);
        assert_eq!(parse("panic-ui"), None);
    }
}
