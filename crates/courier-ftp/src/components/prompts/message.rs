//! Informational prompts (`PromptKind::Message`), answered with `Ack`.

use courier_ftp_core::events::{MessagePrompt, NoticeLevel, PromptResponse};
use ratatui::style::Style;

use super::{
    PromptDialog, Step,
    layout::{Body, BodyCx, Btn, K, Row, classify, clean, clean_multiline},
};
use crate::keymap::chord::KeyChord;

/// A message from the core with an `OK` button.
#[derive(Debug)]
pub(crate) struct MessagePromptDialog {
    level: NoticeLevel,
    title: String,
    text: String,
    /// Answer `Cancel` instead of `Ack` (a kind this build does not know).
    cancel: bool,
}

impl MessagePromptDialog {
    /// The dialog for `p`.
    pub(crate) fn new(p: MessagePrompt) -> Self {
        Self {
            level: p.level,
            title: clean(&p.title),
            text: clean_multiline(&p.text),
            cancel: false,
        }
    }

    /// A prompt kind this build does not know (answered `Cancel`).
    pub(crate) fn unsupported() -> Self {
        Self {
            level: NoticeLevel::Warning,
            title: "Question".to_owned(),
            text: "This question is not supported by this version of courier-ftp.".to_owned(),
            cancel: true,
        }
    }
}

impl PromptDialog for MessagePromptDialog {
    fn kind(&self) -> &'static str {
        "message"
    }

    fn title(&self, _unicode: bool) -> String {
        self.title.clone()
    }

    fn danger(&self) -> bool {
        self.level == NoticeLevel::Error
    }

    fn handle_key(&mut self, key: KeyChord) -> Step {
        match classify(key) {
            K::Enter | K::Esc | K::Space | K::Plain('o') | K::Alt('o') => {
                Step::Answer(if self.cancel {
                    PromptResponse::Cancel
                } else {
                    PromptResponse::Ack
                })
            }
            _ => Step::Continue,
        }
    }

    fn body(&self, width: u16, _cx: &BodyCx) -> Body {
        let mut b = Body::default();
        b.para(&self.text, usize::from(width), Style::default());
        b.blank();
        b.focus_row = b.push(Row::Buttons(vec![Btn::new("OK", true)]));
        b
    }
}
