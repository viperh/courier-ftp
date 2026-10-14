//! What happens when the queue finishes (T45): the action of
//! `queue.on_complete`, or a one-shot override for the next run (FileZilla's
//! "Action after queue completion" menu, which resets after use), and the
//! command line of [`OnComplete::RunCommand`].
//!
//! The engine reports a finished run as
//! [`CoreEvent::QueueFinished`](crate::events::CoreEvent::QueueFinished); a
//! run the user stopped never finishes, so it never triggers an action. The
//! UI calls [`QueueCompletion::on_finished`] with the event's totals and
//! carries out what comes back (the side effects — terminal notifications,
//! starting processes, disconnecting, quitting — belong to the program).

use crate::{
    events::QueueStats,
    settings::{OnComplete, Settings},
};

/// The one-shot override of `queue.on_complete`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueueCompletion {
    oneshot: Option<OnComplete>,
}

impl QueueCompletion {
    /// Do `action` when the next run finishes, then go back to the setting
    /// (`None`: no override).
    pub fn set_oneshot(&mut self, action: Option<OnComplete>) {
        self.oneshot = action;
    }

    /// The override waiting for the next run, if any.
    pub fn oneshot(&self) -> Option<&OnComplete> {
        self.oneshot.as_ref()
    }

    /// The action for a run that finished with `stats`: the one-shot
    /// override (used up) or `queue.on_complete`. `None` when there is
    /// nothing to do, including a run that processed no file at all
    /// (processing an empty queue); the override then stays for the next
    /// real run.
    pub fn on_finished(&mut self, settings: &Settings, stats: &QueueStats) -> Option<OnComplete> {
        if stats.files_ok + stats.files_failed + stats.files_skipped == 0 {
            return None;
        }
        let action = self
            .oneshot
            .take()
            .unwrap_or_else(|| settings.queue.on_complete.clone());
        (action != OnComplete::None).then_some(action)
    }
}

/// The environment of a [`OnComplete::RunCommand`] command:
/// `COURIER_FTP_FILES_OK`, `COURIER_FTP_FILES_FAILED`, `COURIER_FTP_BYTES`.
pub fn command_env(stats: &QueueStats) -> Vec<(&'static str, String)> {
    vec![
        ("COURIER_FTP_FILES_OK", stats.files_ok.to_string()),
        ("COURIER_FTP_FILES_FAILED", stats.files_failed.to_string()),
        ("COURIER_FTP_BYTES", stats.bytes.to_string()),
    ]
}

/// How to start a command line: a program and its arguments, run directly
/// (never through a shell, so nothing in the line is interpreted beyond
/// quoting; write `sh -c '…'` for shell syntax).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLine {
    /// The program.
    pub program: String,
    /// Its arguments.
    pub args: Vec<String>,
}

/// How to run `line` (split into words without a shell, see
/// [`split_command`]). `None` for an empty line or an unterminated quote.
pub fn command_line(line: &str) -> Option<CommandLine> {
    let mut words = split_command(line.trim())?;
    let program = words.remove(0);
    Some(CommandLine {
        program,
        args: words,
    })
}

/// Split a command line into program and arguments, without a shell:
/// whitespace separates words; `'…'` is literal, `"…"` allows `\"` and
/// `\\`, and a backslash outside quotes escapes the next character (on Unix;
/// on Windows backslashes are path separators and stay). `None` for an
/// empty line or an unterminated quote.
pub fn split_command(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        c => cur.push(c),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' if matches!(chars.peek(), Some('"' | '\\')) => {
                            cur.extend(chars.next());
                        }
                        c => cur.push(c),
                    }
                }
            }
            '\\' if !cfg!(windows) => {
                in_word = true;
                cur.push(chars.next()?);
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    (!words.is_empty()).then_some(words)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use pretty_assertions::assert_eq;

    use super::*;

    fn stats(ok: u64, failed: u64) -> QueueStats {
        QueueStats {
            files_ok: ok,
            files_failed: failed,
            files_skipped: 0,
            bytes: 1234,
            elapsed: Duration::from_secs(3),
        }
    }

    #[test]
    fn oneshot_overrides_once_then_the_setting_applies() {
        let mut settings = Settings::default();
        settings.queue.on_complete = OnComplete::ShowMessage;
        let mut c = QueueCompletion::default();
        c.set_oneshot(Some(OnComplete::Disconnect));
        assert_eq!(c.oneshot(), Some(&OnComplete::Disconnect));
        // An empty run doesn't use it up.
        assert_eq!(c.on_finished(&settings, &stats(0, 0)), None);
        assert_eq!(
            c.on_finished(&settings, &stats(1, 0)),
            Some(OnComplete::Disconnect)
        );
        assert_eq!(c.oneshot(), None);
        assert_eq!(
            c.on_finished(&settings, &stats(0, 2)),
            Some(OnComplete::ShowMessage)
        );
        // "None" as the one-shot: nothing this time.
        c.set_oneshot(Some(OnComplete::None));
        assert_eq!(c.on_finished(&settings, &stats(1, 0)), None);
        assert_eq!(
            c.on_finished(&settings, &stats(1, 0)),
            Some(OnComplete::ShowMessage)
        );
        settings.queue.on_complete = OnComplete::None;
        assert_eq!(c.on_finished(&settings, &stats(1, 0)), None);
    }

    #[test]
    fn env_vars() {
        assert_eq!(
            command_env(&stats(3, 1)),
            [
                ("COURIER_FTP_FILES_OK", "3".to_owned()),
                ("COURIER_FTP_FILES_FAILED", "1".to_owned()),
                ("COURIER_FTP_BYTES", "1234".to_owned()),
            ]
        );
    }

    #[test]
    fn commands_run_without_a_shell() {
        assert_eq!(
            command_line(r#"notify-send "Queue done" 'all files'"#),
            Some(CommandLine {
                program: "notify-send".into(),
                args: vec!["Queue done".into(), "all files".into()],
            })
        );
        // Shell syntax is just text: no pipes, variables or redirections.
        assert_eq!(
            command_line("echo $HOME > out; rm x | y"),
            Some(CommandLine {
                program: "echo".into(),
                args: ["$HOME", ">", "out;", "rm", "x", "|", "y"]
                    .map(String::from)
                    .to_vec(),
            })
        );
        assert_eq!(command_line("   "), None);
        assert_eq!(command_line("echo 'open"), None);
    }

    #[test]
    fn splitting() {
        assert_eq!(
            split_command(r#"a "b \"c\" \\ d" e'f g'"#).unwrap(),
            ["a", r#"b "c" \ d"#, "ef g"]
        );
        if !cfg!(windows) {
            assert_eq!(split_command(r"a\ b c").unwrap(), ["a b", "c"]);
        }
        assert_eq!(split_command(""), None);
        assert_eq!(split_command("\"open"), None);
    }
}
