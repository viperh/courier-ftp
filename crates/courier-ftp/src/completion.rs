//! The side effects of the action after the queue finishes (T45): the
//! terminal bell or an OSC 9 / OSC 777 desktop notification, and starting
//! the `RunCommand` command detached. They go through [`Effects`] so tests
//! can record them instead.

use std::{future::Future, io, pin::Pin, process::Stdio, time::Duration};

use courier_ftp_core::{
    events::QueueStats, settings::NotifyMethod, transfer::completion::CommandLine,
};

/// The exit code of a finished command (`None`: killed by a signal).
pub(crate) type Exit = Pin<Box<dyn Future<Output = io::Result<Option<i32>>> + Send>>;

/// What carrying out a completion action does outside the app.
pub(crate) trait Effects: Send + Sync {
    /// Write a control sequence (bell, notification) to the terminal.
    fn terminal(&self, sequence: &str);
    /// Start `command` with `env` added, detached (no input, output
    /// discarded); the future resolves when it exits. Failing to start is
    /// an error of the future.
    fn spawn(&self, command: &CommandLine, env: &[(&'static str, String)]) -> Exit;
}

/// The real terminal and processes.
#[derive(Debug, Default)]
pub(crate) struct SystemEffects;

impl Effects for SystemEffects {
    fn terminal(&self, sequence: &str) {
        use std::io::Write;
        let mut out = io::stdout().lock();
        let _ = out.write_all(sequence.as_bytes());
        let _ = out.flush();
    }

    fn spawn(&self, command: &CommandLine, env: &[(&'static str, String)]) -> Exit {
        let mut cmd = tokio::process::Command::new(&command.program);
        cmd.args(&command.args)
            .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // Keeps running when courier-ftp quits (CloseApp after it).
            .kill_on_drop(false);
        match cmd.spawn() {
            Ok(mut child) => Box::pin(async move { child.wait().await.map(|s| s.code()) }),
            Err(e) => Box::pin(async move { Err(e) }),
        }
    }
}

/// Printable text for a terminal sequence: control characters and `;`
/// (the OSC 777 field separator) become spaces.
fn osc_text(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() || c == ';' { ' ' } else { c })
        .collect()
}

/// The sequence announcing a finished queue: BEL, or OSC 9 (iTerm2, Windows
/// Terminal, kitty…) followed by OSC 777 (urxvt, foot, VTE…). Terminals
/// ignore the ones they don't know.
pub(crate) fn notification(method: NotifyMethod, title: &str, body: &str) -> Option<String> {
    match method {
        NotifyMethod::None => None,
        NotifyMethod::Bell => Some("\x07".to_owned()),
        NotifyMethod::Osc => {
            let (title, body) = (osc_text(title), osc_text(body));
            Some(format!(
                "\x1b]9;{title}: {body}\x07\x1b]777;notify;{title};{body}\x07"
            ))
        }
    }
}

/// `00:01:02`.
pub(crate) fn hms(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

/// "Queue finished: 3 files, 1.2 MiB transferred in 00:00:04, 1 failed".
pub(crate) fn summary(stats: &QueueStats) -> String {
    let mut text = format!(
        "Queue finished: {} file{}, {} transferred in {}",
        stats.files_ok,
        if stats.files_ok == 1 { "" } else { "s" },
        crate::ui::human_bytes(stats.bytes),
        hms(stats.elapsed)
    );
    if stats.files_failed > 0 {
        text.push_str(&format!(", {} failed", stats.files_failed));
    }
    if stats.files_skipped > 0 {
        text.push_str(&format!(", {} skipped", stats.files_skipped));
    }
    text
}

#[cfg(test)]
pub(crate) mod testing {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// The commands started, with their environment.
    pub(crate) type Started = Vec<(CommandLine, Vec<(&'static str, String)>)>;

    /// Records the effects; commands "exit" with `exit_code`.
    #[derive(Debug, Default, Clone)]
    pub(crate) struct Recorder {
        pub(crate) terminal: Arc<Mutex<Vec<String>>>,
        pub(crate) commands: Arc<Mutex<Started>>,
        pub(crate) exit_code: Option<i32>,
    }

    impl Effects for Recorder {
        fn terminal(&self, sequence: &str) {
            self.terminal.lock().unwrap().push(sequence.to_owned());
        }

        fn spawn(&self, command: &CommandLine, env: &[(&'static str, String)]) -> Exit {
            self.commands
                .lock()
                .unwrap()
                .push((command.clone(), env.to_vec()));
            let code = self.exit_code;
            Box::pin(async move { Ok(code) })
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn notifications() {
        assert_eq!(notification(NotifyMethod::None, "t", "b"), None);
        assert_eq!(
            notification(NotifyMethod::Bell, "t", "b").as_deref(),
            Some("\x07")
        );
        assert_eq!(
            notification(NotifyMethod::Osc, "courier-ftp", "Queue finished; 2\nfiles").as_deref(),
            Some(
                "\x1b]9;courier-ftp: Queue finished  2 files\x07\
                 \x1b]777;notify;courier-ftp;Queue finished  2 files\x07"
            )
        );
    }

    #[test]
    fn summary_text() {
        let stats = QueueStats {
            files_ok: 3,
            files_failed: 1,
            files_skipped: 2,
            bytes: 1_258_291,
            elapsed: Duration::from_secs(64),
        };
        assert_eq!(
            summary(&stats),
            "Queue finished: 3 files, 1.2 MiB transferred in 00:01:04, 1 failed, 2 skipped"
        );
    }

    /// The real thing: a command gets the environment and its exit code
    /// comes back.
    #[cfg(unix)]
    #[tokio::test]
    async fn system_effects_run_commands_with_the_env() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("env.txt");
        // A shell only because the test asks for one: the app never adds it.
        let command = CommandLine {
            program: "sh".into(),
            args: vec![
                "-c".into(),
                format!(
                    "echo $COURIER_FTP_FILES_OK $COURIER_FTP_FILES_FAILED $COURIER_FTP_BYTES > '{}'; exit 3",
                    out.display()
                ),
            ],
        };
        let env = vec![
            ("COURIER_FTP_FILES_OK", "4".to_owned()),
            ("COURIER_FTP_FILES_FAILED", "1".to_owned()),
            ("COURIER_FTP_BYTES", "99".to_owned()),
        ];
        let code = SystemEffects.spawn(&command, &env).await.unwrap();
        assert_eq!(code, Some(3));
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "4 1 99\n");
        // A program that doesn't exist fails to start.
        let missing = courier_ftp_core::transfer::completion::command_line(
            "courier-ftp-no-such-program --flag",
        )
        .unwrap();
        assert!(SystemEffects.spawn(&missing, &env).await.is_err());
    }
}
