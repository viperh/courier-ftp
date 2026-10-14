//! T45: what the app does when the queue finishes — the summary, the
//! action of `queue.on_complete` or the queue pane's one-shot override
//! ("Action after queue completion", `a` in the queue pane), and the
//! countdown that lets the user cancel a disconnect or quit.

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{
    events::{LogKind, QueueStats},
    settings::OnComplete,
    transfer::completion::{QueueCompletion, command_env, command_line},
};
use tokio::time::Instant;

use super::App;
use crate::{
    action::Action,
    completion::{Effects, SystemEffects, notification, summary},
    ui::dialog::{ProgressDialog, choose, prompt_text},
};

/// How long the user has to cancel a disconnect or quit after the queue
/// finished.
const COUNTDOWN: Duration = Duration::from_secs(10);

/// The app's completion state.
pub(crate) struct Completion {
    /// The one-shot override.
    pub(super) state: QueueCompletion,
    /// Terminal output and processes (recorded in tests).
    pub(super) effects: Arc<dyn Effects>,
    /// The countdown before a disconnect or quit (short in tests).
    pub(super) countdown: Duration,
}

impl Default for Completion {
    fn default() -> Self {
        Self {
            state: QueueCompletion::default(),
            effects: Arc::new(SystemEffects),
            countdown: COUNTDOWN,
        }
    }
}

/// The action as the menu and the queue pane name it.
pub(crate) fn action_name(action: &OnComplete) -> &'static str {
    match action {
        OnComplete::None => "nothing",
        OnComplete::ShowMessage => "show a message",
        OnComplete::RunCommand(_) => "run the command",
        OnComplete::Disconnect => "disconnect",
        OnComplete::CloseApp => "close courier-ftp",
    }
}

impl App {
    /// The completion-related part of [`App::dispatch`].
    pub(super) fn completion_action(&mut self, action: &Action) {
        match action {
            Action::QueueAfterMenu => self.after_menu(),
            Action::QueueAskCommand(initial) => self.ask_after_command(initial),
            Action::QueueSetAfter(choice) => {
                self.completion.state.set_oneshot(choice.clone());
                self.screen
                    .set_queue_after(choice.as_ref().map(action_name));
                self.screen.flash(match choice {
                    Some(a) => format!(
                        "When the queue finishes: {} (this time only)",
                        action_name(a)
                    ),
                    None => "When the queue finishes: as in the settings".to_owned(),
                });
            }
            Action::QueueAfterDue(action) => match action {
                // Every tab's connection; the tabs stay.
                OnComplete::Disconnect => self.disconnect_all(),
                OnComplete::CloseApp => self.request_quit(),
                _ => {}
            },
            Action::QueueAfterCommandExited(result) => {
                let (kind, text) = match result {
                    Ok(Some(0)) => (
                        LogKind::Status,
                        "The command after the queue finished exited successfully".to_owned(),
                    ),
                    Ok(Some(code)) => (
                        LogKind::Error,
                        format!("The command after the queue finished exited with code {code}"),
                    ),
                    Ok(None) => (
                        LogKind::Error,
                        "The command after the queue finished was killed by a signal".to_owned(),
                    ),
                    Err(e) => (
                        LogKind::Error,
                        format!("The command after the queue finished could not be started: {e}"),
                    ),
                };
                self.events_tx.log(self.local_session, kind, text);
            }
            _ => {}
        }
    }

    /// The queue finished a run (not stopped by the user, the engine never
    /// reports that): log the summary and carry out the action.
    pub(super) fn queue_finished(&mut self, stats: &QueueStats) {
        let text = summary(stats);
        self.events_tx
            .log(self.local_session, LogKind::Status, text.clone());
        self.screen.flash(text.clone());
        let Some(action) = self.completion.state.on_finished(&self.settings, stats) else {
            return;
        };
        self.screen.set_queue_after(None);
        match action {
            OnComplete::None => {}
            OnComplete::ShowMessage => {
                if let Some(seq) = notification(self.settings.queue.notify, "courier-ftp", &text) {
                    self.completion.effects.terminal(&seq);
                }
                let (modal, _) = crate::ui::dialog::message("Queue finished", &text);
                self.screen.push_modal(modal);
            }
            OnComplete::RunCommand(line) => self.run_command(&line, stats),
            OnComplete::Disconnect | OnComplete::CloseApp => self.countdown(action),
        }
    }

    /// Start the `RunCommand` command (no shell) with the totals in its
    /// environment; its exit is logged.
    fn run_command(&mut self, line: &str, stats: &QueueStats) {
        let Some(command) = command_line(line) else {
            self.events_tx.log(
                self.local_session,
                LogKind::Error,
                "The command after the queue finished is empty or has an unterminated quote",
            );
            return;
        };
        tracing::debug!("queue finished: running {}", command.program);
        let exit = self.completion.effects.spawn(&command, &command_env(stats));
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            let result = exit.await.map_err(|e| e.to_string());
            let _ = tx.send(Action::QueueAfterCommandExited(result));
        });
    }

    /// Disconnect or quit after a countdown the user can cancel.
    fn countdown(&mut self, action: OnComplete) {
        let what = match action {
            OnComplete::Disconnect if !self.any_connection() => return,
            OnComplete::Disconnect => "Disconnecting",
            _ => "Closing courier-ftp",
        };
        let (dialog, handle) = ProgressDialog::new("Queue finished");
        let total = self.completion.countdown;
        let total_secs = total.as_secs().max(1);
        handle.update(
            format!("{what} in {total_secs} s (Esc cancels)"),
            0,
            Some(total_secs),
        );
        self.screen.push_modal(Box::new(dialog));
        let tx = self.action_tx.clone();
        let events = self.events_tx.clone();
        let session = self.local_session;
        tokio::spawn(async move {
            let deadline = Instant::now() + total;
            let step = total.min(Duration::from_millis(250));
            loop {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let left = deadline - now;
                let secs = left.as_secs() + u64::from(left.subsec_nanos() > 0);
                handle.update(
                    format!("{what} in {secs} s (Esc cancels)"),
                    total_secs.saturating_sub(secs),
                    Some(total_secs),
                );
                tokio::select! {
                    () = handle.cancel_token().cancelled() => {
                        events.log(session, LogKind::Status, format!("{what} cancelled"));
                        return;
                    }
                    () = tokio::time::sleep(step.min(left)) => {}
                }
            }
            handle.finish();
            let _ = tx.send(Action::QueueAfterDue(action));
        });
    }

    /// The "Action after queue completion" menu: a one-shot override for the
    /// next run (FileZilla resets it after use too).
    fn after_menu(&mut self) {
        let setting = self.settings.queue.on_complete.clone();
        let current = self.completion.state.oneshot().cloned();
        let mark = |a: Option<&OnComplete>, label: String| {
            if current.as_ref() == a {
                format!("{label} (current)")
            } else {
                label
            }
        };
        let options = vec![
            mark(
                None,
                format!("As in the settings ({})", action_name(&setting)),
            ),
            mark(Some(&OnComplete::None), "Nothing".to_owned()),
            mark(Some(&OnComplete::ShowMessage), "Show a message".to_owned()),
            match &current {
                Some(OnComplete::RunCommand(c)) => format!("Run a command… ({c}) (current)"),
                _ => "Run a command…".to_owned(),
            },
            mark(Some(&OnComplete::Disconnect), "Disconnect".to_owned()),
            mark(Some(&OnComplete::CloseApp), "Close courier-ftp".to_owned()),
        ];
        let (modal, rx) = choose("Action after queue completion (this time)", options);
        self.screen.push_modal(modal);
        let tx = self.action_tx.clone();
        let command = match (&current, &setting) {
            (Some(OnComplete::RunCommand(c)), _) | (_, OnComplete::RunCommand(c)) => c.clone(),
            _ => String::new(),
        };
        tokio::spawn(async move {
            let choice = match rx.await {
                Ok(Some(0)) => None,
                Ok(Some(1)) => Some(OnComplete::None),
                Ok(Some(2)) => Some(OnComplete::ShowMessage),
                Ok(Some(3)) => {
                    let _ = tx.send(Action::QueueAskCommand(command));
                    return;
                }
                Ok(Some(4)) => Some(OnComplete::Disconnect),
                Ok(Some(5)) => Some(OnComplete::CloseApp),
                _ => return,
            };
            let _ = tx.send(Action::QueueSetAfter(choice));
        });
    }

    /// Ask for the command to run when the queue finishes this time.
    fn ask_after_command(&mut self, initial: &str) {
        let (modal, rx) = prompt_text(
            "Run a command when the queue finishes",
            "Command (no shell; the totals are in COURIER_FTP_* variables)",
            initial,
        );
        self.screen.push_modal(modal);
        let tx = self.action_tx.clone();
        tokio::spawn(async move {
            if let Ok(Some(line)) = rx.await {
                let line = line.trim().to_owned();
                if command_line(&line).is_some() {
                    let _ = tx.send(Action::QueueSetAfter(Some(OnComplete::RunCommand(line))));
                }
            }
        });
    }
}
