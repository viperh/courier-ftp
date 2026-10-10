//! `TextInput`: a single-line editor with grapheme-cluster cursor movement, horizontal
//! scrolling, a validator and the paste rules. The editing core is shared with
//! `TextArea` (one line at a time), `NumberInput` and `PathInput`.

use std::{cell::Cell, fmt, sync::Arc};

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Position, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use unicode_segmentation::UnicodeSegmentation;

use super::{
    Notice, Widget, WidgetCx, WidgetOutcome, clean_single_line, is_control, is_word_separator,
    paste_cut_message,
};
use crate::{
    keymap::chord::{KeyChord, Mods},
    ui::text::{sanitize, width},
};

/// Checks a field value; `Err` is the message shown under the field.
pub(crate) type Validator = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// Byte offsets of every grapheme start, plus `s.len()`.
pub(super) fn grapheme_bounds(s: &str) -> Vec<usize> {
    let mut v: Vec<usize> = s.grapheme_indices(true).map(|(i, _)| i).collect();
    v.push(s.len());
    v
}

/// Number of grapheme clusters.
pub(super) fn grapheme_len(s: &str) -> usize {
    s.graphemes(true).count()
}

/// What an editing key did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Edit {
    /// Not an editing key.
    NotEditing,
    /// Only the cursor moved (or nothing happened).
    Moved,
    /// The text changed.
    Changed,
}

impl Edit {
    pub(super) fn outcome(self) -> WidgetOutcome {
        match self {
            Self::NotEditing => WidgetOutcome::Ignored,
            Self::Moved => WidgetOutcome::Consumed,
            Self::Changed => WidgetOutcome::Changed,
        }
    }
}

fn word_left(s: &str, b: &[usize], cursor: usize) -> usize {
    let g = |i: usize| &s[b[i]..b[i + 1]];
    let mut i = cursor;
    while i > 0 && is_word_separator(g(i - 1)) {
        i -= 1;
    }
    while i > 0 && !is_word_separator(g(i - 1)) {
        i -= 1;
    }
    i
}

fn word_right(s: &str, b: &[usize], cursor: usize) -> usize {
    let n = b.len() - 1;
    let g = |i: usize| &s[b[i]..b[i + 1]];
    let mut i = cursor;
    while i < n && is_word_separator(g(i)) {
        i += 1;
    }
    while i < n && !is_word_separator(g(i)) {
        i += 1;
    }
    i
}

/// Applies the fixed text editing keys (T51) to one line. `cursor` is a grapheme
/// index; `room` is how many more chars may be inserted.
pub(super) fn apply_edit(
    value: &mut String,
    cursor: &mut usize,
    key: KeyChord,
    room: usize,
) -> Edit {
    let b = grapheme_bounds(value);
    let n = b.len() - 1;
    *cursor = (*cursor).min(n);
    let ctrl = key.mods.contains(Mods::CTRL);
    let alt = key.mods.contains(Mods::ALT);
    let remove = |value: &mut String, from: usize, to: usize, cursor: &mut usize| {
        if from >= to {
            return Edit::Moved;
        }
        value.replace_range(b[from]..b[to], "");
        *cursor = from;
        Edit::Changed
    };
    match key.code {
        KeyCode::Char(c) if !ctrl && !alt && !key.mods.contains(Mods::SUPER) => {
            if is_control(c) || room == 0 {
                return Edit::Moved;
            }
            value.insert(b[*cursor], c);
            // A combining mark joins the previous cluster: recount.
            let before = grapheme_len(&value[..b[*cursor] + c.len_utf8()]);
            *cursor = before;
            Edit::Changed
        }
        KeyCode::Char('a') if ctrl => {
            *cursor = 0;
            Edit::Moved
        }
        KeyCode::Char('e') if ctrl => {
            *cursor = n;
            Edit::Moved
        }
        KeyCode::Char('b') if alt => {
            *cursor = word_left(value, &b, *cursor);
            Edit::Moved
        }
        KeyCode::Char('f') if alt => {
            *cursor = word_right(value, &b, *cursor);
            Edit::Moved
        }
        KeyCode::Char('w') if ctrl => {
            let from = word_left(value, &b, *cursor);
            let to = *cursor;
            remove(value, from, to, cursor)
        }
        KeyCode::Char('d') if alt => {
            let to = word_right(value, &b, *cursor);
            let from = *cursor;
            remove(value, from, to, cursor)
        }
        KeyCode::Char('u') if ctrl => {
            let to = *cursor;
            remove(value, 0, to, cursor)
        }
        KeyCode::Char('k') if ctrl => {
            let from = *cursor;
            remove(value, from, n, cursor)
        }
        KeyCode::Backspace if alt || ctrl => {
            let from = word_left(value, &b, *cursor);
            let to = *cursor;
            remove(value, from, to, cursor)
        }
        KeyCode::Backspace => {
            let to = *cursor;
            remove(value, to.saturating_sub(1), to, cursor)
        }
        KeyCode::Delete => {
            let from = *cursor;
            remove(value, from, (from + 1).min(n), cursor)
        }
        KeyCode::Left if ctrl || alt => {
            *cursor = word_left(value, &b, *cursor);
            Edit::Moved
        }
        KeyCode::Right if ctrl || alt => {
            *cursor = word_right(value, &b, *cursor);
            Edit::Moved
        }
        KeyCode::Left => {
            *cursor = cursor.saturating_sub(1);
            Edit::Moved
        }
        KeyCode::Right => {
            *cursor = (*cursor + 1).min(n);
            Edit::Moved
        }
        KeyCode::Home => {
            *cursor = 0;
            Edit::Moved
        }
        KeyCode::End => {
            *cursor = n;
            Edit::Moved
        }
        _ => Edit::NotEditing,
    }
}

/// Inserts `text` (already cleaned) at grapheme `cursor`, at most `room` chars.
/// Returns the number of chars inserted.
pub(super) fn insert_str(value: &mut String, cursor: &mut usize, text: &str, room: usize) -> usize {
    let b = grapheme_bounds(value);
    *cursor = (*cursor).min(b.len() - 1);
    let take: String = text.chars().take(room).collect();
    let n = take.chars().count();
    let at = b[*cursor];
    value.insert_str(at, &take);
    *cursor = grapheme_len(&value[..at + take.len()]);
    n
}

/// One display cell group: a grapheme as drawn (sanitised) and its width.
pub(super) fn display_cells(s: &str) -> Vec<(String, usize)> {
    s.graphemes(true)
        .map(|g| {
            let shown = sanitize(g).into_owned();
            let w = width(&shown);
            (shown, w)
        })
        .collect()
}

/// Draws a single line of `cells` with grapheme `cursor`, keeping it visible by
/// adjusting `scroll` (first visible cell). Returns the cursor position.
pub(super) fn render_line(
    frame: &mut Frame,
    area: Rect,
    cells: &[(String, usize)],
    cursor: usize,
    scroll: &Cell<usize>,
    style: Style,
) -> Position {
    let w = usize::from(area.width);
    let cursor = cursor.min(cells.len());
    let mut start = scroll.get().min(cursor);
    // Room for the cursor cell itself.
    while start < cursor && cells[start..cursor].iter().map(|c| c.1).sum::<usize>() + 1 > w {
        start += 1;
    }
    scroll.set(start);
    let mut used = 0;
    let mut text = String::new();
    for (g, gw) in &cells[start..] {
        if used + gw > w {
            break;
        }
        used += gw;
        text.push_str(g);
    }
    let pad = w.saturating_sub(used);
    let line = Line::from(vec![
        Span::styled(text, style),
        Span::styled(" ".repeat(pad), style),
    ]);
    frame.render_widget(Paragraph::new(line), area);
    let cx: usize = cells[start..cursor].iter().map(|c| c.1).sum();
    let x = u16::try_from(cx)
        .unwrap_or(u16::MAX)
        .min(area.width.saturating_sub(1));
    Position::new(area.x.saturating_add(x), area.y)
}

/// Draws the placeholder (dim) or nothing.
pub(super) fn render_placeholder(
    frame: &mut Frame,
    area: Rect,
    text: &str,
    input: Style,
    style: Style,
) {
    let shown = crate::ui::text::truncate_to_width(text, usize::from(area.width), "");
    let pad = usize::from(area.width).saturating_sub(width(&shown));
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(sanitize(&shown).into_owned(), style),
            Span::styled(" ".repeat(pad), input),
        ])),
        area,
    );
}

/// A single-line text field.
pub(crate) struct TextInput {
    value: String,
    /// Grapheme index.
    cursor: usize,
    /// First visible grapheme (kept between frames).
    scroll: Cell<usize>,
    max_chars: usize,
    placeholder: String,
    validator: Option<Validator>,
    error: Option<String>,
    notice: Option<Notice>,
}

impl fmt::Debug for TextInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The value may be a path or a user name: not in `Debug` either.
        f.debug_struct("TextInput")
            .field("len", &self.value.len())
            .field("cursor", &self.cursor)
            .field("error", &self.error.is_some())
            .finish_non_exhaustive()
    }
}

impl TextInput {
    /// A field holding `initial`, cursor at the end; at most 4096 chars.
    pub(crate) fn new(initial: &str) -> Self {
        let mut t = Self {
            value: String::new(),
            cursor: 0,
            scroll: Cell::new(0),
            max_chars: 4096,
            placeholder: String::new(),
            validator: None,
            error: None,
            notice: None,
        };
        t.set_value(initial);
        t
    }

    /// Limits the length in chars.
    #[must_use]
    pub(crate) fn max_chars(mut self, n: usize) -> Self {
        self.max_chars = n;
        let v = self.value.clone();
        self.set_value(&v);
        self
    }

    /// Text shown dim while the field is empty.
    #[must_use]
    pub(crate) fn placeholder(mut self, text: &str) -> Self {
        text.clone_into(&mut self.placeholder);
        self
    }

    /// Checks the value when focus leaves the field and on submit.
    #[must_use]
    pub(crate) fn validator(mut self, f: Validator) -> Self {
        self.validator = Some(f);
        self
    }

    /// The value.
    pub(crate) fn value(&self) -> &str {
        &self.value
    }

    /// Replaces the value (cut to `max_chars`, controls removed); cursor to the end.
    pub(crate) fn set_value(&mut self, v: &str) {
        self.value = v
            .chars()
            .filter(|c| !is_control(*c))
            .take(self.max_chars)
            .collect();
        self.cursor = grapheme_len(&self.value);
    }

    /// The cursor (grapheme index).
    pub(crate) fn cursor_index(&self) -> usize {
        self.cursor
    }

    /// Moves the cursor (clamped).
    pub(crate) fn set_cursor(&mut self, i: usize) {
        self.cursor = i.min(grapheme_len(&self.value));
    }

    /// The message of the last failed validation.
    pub(crate) fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Sets or clears the error shown under the field.
    pub(crate) fn set_error(&mut self, msg: Option<String>) {
        self.error = msg;
    }

    /// Runs the validator; returns whether the value is valid.
    pub(crate) fn validate(&mut self) -> bool {
        self.error = match &self.validator {
            Some(v) => v(&self.value).err(),
            None => None,
        };
        self.error.is_none()
    }

    fn room(&self) -> usize {
        self.max_chars.saturating_sub(self.value.chars().count())
    }

    /// Inserts already-cleaned text at the cursor (used by `NumberInput`).
    pub(super) fn insert_clean(&mut self, text: &str) -> usize {
        let room = self.room();
        insert_str(&mut self.value, &mut self.cursor, text, room)
    }

    /// Draws `value` (or the placeholder) and returns the cursor position.
    fn draw(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx) -> Position {
        let input = cx.theme.style("input");
        if self.value.is_empty() && !self.placeholder.is_empty() {
            render_placeholder(
                frame,
                area,
                &self.placeholder,
                input,
                input.patch(cx.theme.style("input_placeholder")),
            );
            return Position::new(area.x, area.y);
        }
        let style = if cx.enabled {
            input
        } else {
            input.patch(cx.theme.style("field_help"))
        };
        let cells = display_cells(&self.value);
        render_line(frame, area, &cells, self.cursor, &self.scroll, style)
    }
}

impl Widget for TextInput {
    fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome {
        let room = self.room();
        apply_edit(&mut self.value, &mut self.cursor, key, room).outcome()
    }

    fn handle_paste(&mut self, text: &str) -> WidgetOutcome {
        let clean = clean_single_line(text);
        let total = clean.chars().count();
        let n = self.insert_clean(&clean);
        if n < total {
            self.notice = Some(Notice::Status(paste_cut_message(n)));
        }
        if n > 0 {
            WidgetOutcome::Changed
        } else {
            WidgetOutcome::Consumed
        }
    }

    fn render(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let area = Rect { height: 1, ..area };
        self.draw(frame, area, cx);
    }

    fn is_text(&self) -> bool {
        true
    }

    fn cursor(&self, area: Rect) -> Option<Position> {
        if area.width == 0 || area.height == 0 {
            return None;
        }
        let start = self.scroll.get().min(self.cursor);
        let cells = display_cells(&self.value);
        let cx: usize = cells
            .get(start..self.cursor.min(cells.len()))
            .map_or(0, |c| c.iter().map(|c| c.1).sum());
        let x = u16::try_from(cx)
            .unwrap_or(u16::MAX)
            .min(area.width.saturating_sub(1));
        Some(Position::new(area.x.saturating_add(x), area.y))
    }

    fn take_notice(&mut self) -> Option<Notice> {
        self.notice.take()
    }
}
