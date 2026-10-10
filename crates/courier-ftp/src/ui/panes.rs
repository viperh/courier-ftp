//! The regions of the main screen. These are the T50 shells: the file list
//! (T53), message log (T55), queue (T56), status bar (T57), quickconnect bar
//! (T58) and tab bar (T61) tasks replace their bodies.

use std::collections::VecDeque;

use courier_ftp_core::{
    events::{LogKind, LogMessage},
    local::display_native,
    model::{Entry, RemotePath},
};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Paragraph},
};

use super::{Side, theme::Theme};

/// Braille spinner shown in a pane title while it waits for the network.
const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

pub(crate) fn spinner_frame(tick: u64) -> char {
    SPINNER[(tick % SPINNER.len() as u64) as usize]
}

pub(crate) fn block<'a>(title: impl Into<Line<'a>>, focused: bool, theme: &Theme) -> Block<'a> {
    Block::bordered().title(title).border_style(if focused {
        theme.focused_border
    } else {
        theme.border
    })
}

/// One side's directory listing.
#[derive(Debug)]
pub(crate) struct FilePane {
    pub(crate) side: Side,
    pub(crate) dir: Option<RemotePath>,
    pub(crate) entries: Vec<Entry>,
    pub(crate) busy: bool,
    pub(crate) error: Option<String>,
}

impl FilePane {
    pub(crate) fn new(side: Side) -> Self {
        Self {
            side,
            dir: None,
            entries: Vec::new(),
            busy: false,
            error: None,
        }
    }

    pub(crate) fn draw(
        &self,
        frame: &mut Frame,
        area: Rect,
        focused: bool,
        tick: u64,
        theme: &Theme,
    ) {
        let label = match self.side {
            Side::Local => "Local",
            Side::Remote => "Remote",
        };
        let place = match (&self.dir, self.side) {
            (Some(d), Side::Local) => display_native(d),
            (Some(d), Side::Remote) => d.to_string(),
            (None, Side::Remote) => "not connected".to_owned(),
            (None, Side::Local) => String::new(),
        };
        let mut title = vec![Span::styled(format!(" {label}: {place} "), theme.title)];
        if self.busy {
            title.push(Span::raw(format!("{} ", spinner_frame(tick))));
        }
        let lines: Vec<Line> = if let Some(err) = &self.error {
            vec![Line::styled(err.clone(), theme.error)]
        } else if self.dir.is_none() && self.side == Side::Remote {
            vec![Line::styled(
                "Ctrl-k: quickconnect · Ctrl-s: Site Manager",
                theme.dim,
            )]
        } else {
            let mut sorted: Vec<&Entry> = self.entries.iter().collect();
            sorted.sort_by(|a, b| {
                b.is_dir_like()
                    .cmp(&a.is_dir_like())
                    .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            });
            std::iter::once(Line::raw(".."))
                .chain(sorted.into_iter().map(|e| {
                    if e.is_dir_like() {
                        Line::styled(format!("{}/", e.name), theme.dir)
                    } else {
                        Line::raw(e.name.clone())
                    }
                }))
                .collect()
        };
        frame.render_widget(
            Paragraph::new(lines).block(block(Line::from(title), focused, theme)),
            area,
        );
    }
}

/// The message log: the last lines the core reported.
#[derive(Debug, Default)]
pub(crate) struct LogPane {
    lines: VecDeque<LogMessage>,
}

const LOG_CAPACITY: usize = 1000;

impl LogPane {
    pub(crate) fn push(&mut self, msg: LogMessage) {
        if self.lines.len() == LOG_CAPACITY {
            self.lines.pop_front();
        }
        self.lines.push_back(msg);
    }

    pub(crate) fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        let rows = usize::from(area.height.saturating_sub(2));
        let skip = self.lines.len().saturating_sub(rows);
        let lines: Vec<Line> = self
            .lines
            .iter()
            .skip(skip)
            .map(|m| {
                let label = match m.kind {
                    LogKind::Status => "Status:",
                    LogKind::Command => "Command:",
                    LogKind::Response => "Response:",
                    LogKind::Error => "Error:",
                    LogKind::ListingRaw => "Listing:",
                    LogKind::Debug(_) => "Trace:",
                };
                Line::styled(format!("{label:<10}{}", m.text), theme.log(m.kind))
            })
            .collect();
        frame.render_widget(
            Paragraph::new(lines).block(block(" Message log ", focused, theme)),
            area,
        );
    }
}

pub(crate) fn draw_quickconnect(frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
    let field = |label: &str| {
        vec![
            Span::styled(format!("{label}: "), theme.title),
            Span::styled("________   ", theme.dim),
        ]
    };
    let mut spans = Vec::new();
    for label in ["Host", "User", "Pass", "Port"] {
        spans.extend(field(label));
    }
    spans.push(Span::styled("[Connect]", theme.key_hint));
    frame.render_widget(
        Paragraph::new(Line::from(spans)).block(block(" Quickconnect ", focused, theme)),
        area,
    );
}

pub(crate) fn draw_tabs(frame: &mut Frame, area: Rect, theme: &Theme) {
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" Tabs: ", theme.dim),
            Span::styled("[1 local]", theme.title),
        ])),
        area,
    );
}

pub(crate) fn draw_queue(frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
    frame.render_widget(
        Paragraph::new(Line::styled("The queue is empty.", theme.dim)).block(block(
            " Queue (0) · Failed (0) · Successful (0) ",
            focused,
            theme,
        )),
        area,
    );
}

pub(crate) fn draw_status(frame: &mut Frame, area: Rect, theme: &Theme) {
    let hints = [("F1", "help"), ("Tab", "switch pane"), ("Ctrl-q", "quit")];
    let mut spans = vec![Span::raw(" Queue: empty   ")];
    for (key, what) in hints {
        spans.push(Span::styled(key, theme.status_bar.patch(theme.key_hint)));
        spans.push(Span::raw(format!(" {what}  ")));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(theme.status_bar),
        area,
    );
}

pub(crate) fn draw_hint(frame: &mut Frame, area: Rect, theme: &Theme) {
    frame.render_widget(
        Paragraph::new(Line::styled(
            "Small terminal: one pane at a time, Tab switches",
            theme.dim,
        )),
        area,
    );
}
