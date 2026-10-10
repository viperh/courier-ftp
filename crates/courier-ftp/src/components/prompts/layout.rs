//! Shared drawing of the prompt dialogs (T69): a dialog describes its content as
//! [`Row`]s at a given width; [`render_body`] draws them, scrolls when they do not
//! fit (keeping the focused row visible) and places text fields with their widgets.
//! Every server- or file-provided string goes through [`clean`] first.

use std::cell::Cell;

use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Position, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};
use tokio::time::Instant;

use crate::{
    components::{
        DrawCx,
        dialog::wrap_text,
        widgets::{WidgetCx, is_control},
    },
    keymap::chord::{KeyChord, Mods},
    ui::{
        symbols::Symbols,
        text::{sanitize, truncate_to_width, width},
        theme::Theme,
    },
};

/// Width of the label column (`Host:       `).
pub(crate) const LABEL_W: usize = 12;
/// Widest prompt dialog.
pub(crate) const DIALOG_W: u16 = 76;
/// Narrowest prompt dialog (below it: "terminal too small").
pub(crate) const MIN_W: u16 = 30;

/// Untrusted text made safe to draw: C0/C1 controls and DEL are removed, then the
/// rest goes through [`sanitize`] (bidi controls become `<U+XXXX>`).
pub(crate) fn clean(s: &str) -> String {
    let stripped: String = s.chars().filter(|c| !is_control(*c)).collect();
    sanitize(&stripped).into_owned()
}

/// As [`clean`], but keeps line breaks (multi-line server text).
pub(crate) fn clean_multiline(s: &str) -> String {
    s.split('\n')
        .map(|l| clean(l.strip_suffix('\r').unwrap_or(l)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Wrapped lines of `text` (already clean) at `width` columns.
pub(crate) fn wrap(text: &str, width: usize) -> Vec<String> {
    wrap_text(text, u16::try_from(width.max(1)).unwrap_or(u16::MAX))
}

/// One button of a button row.
#[derive(Debug, Clone)]
pub(crate) struct Btn {
    /// Label.
    pub label: &'static str,
    /// Has the focus.
    pub focused: bool,
    /// Can be pressed (disabled buttons are dim and skipped by `Tab`).
    pub enabled: bool,
    /// Drawn in the `button_danger` style.
    pub danger: bool,
}

impl Btn {
    /// An enabled, plain button.
    pub(crate) fn new(label: &'static str, focused: bool) -> Self {
        Self {
            label,
            focused,
            enabled: true,
            danger: false,
        }
    }
}

/// A row of a dialog body.
#[derive(Debug, Clone)]
pub(crate) enum Row {
    /// Static text.
    Line(Line<'static>),
    /// A text field: `label [widget] suffix`.
    Input {
        /// The label (already padded).
        label: Line<'static>,
        /// Which field of the dialog (passed back to `draw_input`).
        field: usize,
        /// Width of the field between the brackets.
        width: u16,
        /// Has the focus.
        focused: bool,
        /// Can be used.
        enabled: bool,
        /// Drawn after the closing bracket (an inline error).
        suffix: Option<Span<'static>>,
    },
    /// Centred buttons.
    Buttons(Vec<Btn>),
}

/// A dialog's content at one width.
#[derive(Debug, Clone, Default)]
pub(crate) struct Body {
    /// Every row, top first.
    pub rows: Vec<Row>,
    /// The row that must stay visible when the body scrolls.
    pub focus_row: usize,
}

impl Body {
    /// Adds a row; returns its index.
    pub(crate) fn push(&mut self, row: Row) -> usize {
        self.rows.push(row);
        self.rows.len() - 1
    }

    /// Adds a text line.
    pub(crate) fn line(&mut self, line: Line<'static>) -> usize {
        self.push(Row::Line(line))
    }

    /// Adds a plain text line.
    pub(crate) fn text(&mut self, text: impl Into<String>, style: Style) -> usize {
        self.line(Line::from(Span::styled(text.into(), style)))
    }

    /// Adds an empty line.
    pub(crate) fn blank(&mut self) -> usize {
        self.line(Line::default())
    }

    /// Adds `text` wrapped at `width`.
    pub(crate) fn para(&mut self, text: &str, width: usize, style: Style) {
        for l in wrap(text, width) {
            self.text(l, style);
        }
    }

    /// Adds `label` (padded to [`LABEL_W`]) and `value` wrapped at `width`; wrapped
    /// lines are indented to the value column.
    pub(crate) fn labeled(&mut self, label: &str, value: &str, width: usize, style: Style) {
        self.labeled_spans(label, vec![Span::styled(value.to_owned(), style)], width);
    }

    /// As [`Self::labeled`] with styled parts (wrapping keeps each part's style).
    pub(crate) fn labeled_spans(&mut self, label: &str, parts: Vec<Span<'static>>, width: usize) {
        for l in labeled_lines(label, parts, width) {
            self.line(l);
        }
    }
}

/// `label` padded to [`LABEL_W`].
pub(crate) fn pad_label(label: &str) -> String {
    let w = width(label);
    if w >= LABEL_W {
        format!("{label} ")
    } else {
        format!("{label}{}", " ".repeat(LABEL_W - w))
    }
}

/// `label value…` lines: the value parts wrapped at `width - LABEL_W` columns (at
/// spaces, long words split), continuation lines indented.
pub(crate) fn labeled_lines(
    label: &str,
    parts: Vec<Span<'static>>,
    width: usize,
) -> Vec<Line<'static>> {
    use unicode_width::UnicodeWidthChar;
    let avail = width.saturating_sub(LABEL_W).max(8);
    let mut lines: Vec<Vec<Span<'static>>> = vec![Vec::new()];
    let mut used = 0;
    for part in parts {
        let style = part.style;
        let text = part.content.into_owned();
        let mut first_word = true;
        for word in text.split(' ') {
            let word_w = width_of(word);
            let space = if first_word { 0 } else { 1 };
            first_word = false;
            if used > 0 && used + space + word_w > avail {
                lines.push(Vec::new());
                used = 0;
            } else if space == 1 {
                push_span(&mut lines, " ", style);
                used += 1;
            }
            if word_w <= avail.saturating_sub(used) {
                push_span(&mut lines, word, style);
                used += word_w;
                continue;
            }
            // Longer than a line: split at character boundaries.
            let mut chunk = String::new();
            for c in word.chars() {
                let cw = c.width().unwrap_or(0);
                if used + cw > avail && used > 0 {
                    push_span(&mut lines, &std::mem::take(&mut chunk), style);
                    lines.push(Vec::new());
                    used = 0;
                }
                chunk.push(c);
                used += cw;
            }
            push_span(&mut lines, &chunk, style);
        }
    }
    let indent = " ".repeat(LABEL_W);
    lines
        .into_iter()
        .enumerate()
        .map(|(i, spans)| {
            let head = if i == 0 {
                pad_label(label)
            } else {
                indent.clone()
            };
            let mut v = vec![Span::raw(head)];
            v.extend(spans);
            Line::from(v)
        })
        .collect()
}

fn width_of(s: &str) -> usize {
    width(s)
}

fn push_span(lines: &mut [Vec<Span<'static>>], text: &str, style: Style) {
    if text.is_empty() {
        return;
    }
    if let Some(last) = lines.last_mut() {
        last.push(Span::styled(text.to_owned(), style));
    }
}

/// A checkbox row: `[x] label`.
pub(crate) fn checkbox(
    label: &str,
    checked: bool,
    focused: bool,
    enabled: bool,
    theme: &Theme,
) -> Line<'static> {
    mark_line(
        if checked { "[x]" } else { "[ ]" },
        label,
        focused,
        enabled,
        theme,
    )
}

/// A radio row: `(•) label`.
pub(crate) fn radio(
    label: &str,
    on: bool,
    focused: bool,
    enabled: bool,
    cx: &BodyCx,
) -> Line<'static> {
    let mark = if on {
        cx.symbols.radio_on
    } else {
        cx.symbols.radio_off
    };
    mark_line(mark, label, focused, enabled, cx.theme)
}

fn mark_line(
    mark: &str,
    label: &str,
    focused: bool,
    enabled: bool,
    theme: &Theme,
) -> Line<'static> {
    let base = if enabled {
        Style::default()
    } else {
        theme.style("field_help")
    };
    let mark_style = if focused {
        base.add_modifier(Modifier::REVERSED)
    } else {
        base
    };
    let label_style = if focused {
        base.patch(theme.style("field_label_focused"))
    } else {
        base
    };
    Line::from(vec![
        Span::styled(mark.to_owned(), mark_style),
        Span::styled(" ".to_owned(), base),
        Span::styled(label.to_owned(), label_style),
    ])
}

/// Context for building a body.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BodyCx<'a> {
    /// Styles.
    pub theme: &'a Theme,
    /// Glyphs.
    pub symbols: &'a Symbols,
    /// The input guard is active (buttons are drawn dim).
    pub guard: bool,
}

impl BodyCx<'_> {
    /// `✔` / `ok`.
    pub(crate) fn ok_mark(&self) -> &'static str {
        if self.symbols.unicode { "✔" } else { "ok" }
    }

    /// `✘` / `x`.
    pub(crate) fn bad_mark(&self) -> &'static str {
        if self.symbols.unicode { "✘" } else { "x" }
    }

    /// The error style (changed keys, problems, retry lines).
    pub(crate) fn danger(&self) -> Style {
        self.theme.style("prompt.danger")
    }

    /// The style of a good check.
    pub(crate) fn good(&self) -> Style {
        self.theme.style("prompt.ok")
    }
}

/// Draws a button row centred in `area` (one line).
fn render_buttons(frame: &mut Frame, area: Rect, buttons: &[Btn], cx: &BodyCx) {
    let widths: Vec<usize> = buttons.iter().map(|b| width(b.label) + 4).collect();
    let total: usize = widths.iter().sum();
    let n = buttons.len().saturating_sub(1);
    let avail = usize::from(area.width);
    let gap = [8, 6, 4, 2, 1]
        .into_iter()
        .find(|g| total + g * n <= avail)
        .unwrap_or(1);
    let pad = avail.saturating_sub(total + gap * n) / 2;
    let mut spans = vec![Span::raw(" ".repeat(pad))];
    for (i, b) in buttons.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" ".repeat(gap)));
        }
        let mut style = if b.danger {
            cx.theme.style("button_danger")
        } else {
            cx.theme.style("button")
        };
        if b.focused {
            style = style.patch(cx.theme.style("button_focused"));
        }
        if !b.enabled || cx.guard {
            style = style.patch(cx.theme.style("field_help"));
        }
        spans.push(Span::styled(format!("[ {} ]", b.label), style));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect { height: 1, ..area },
    );
}

/// Draws `body` into `area`: rows from `scroll` on, adjusted so the focused row is
/// visible; `▲`/`▼` in the right column when rows are hidden above/below. Inputs are
/// drawn by `draw_input(field, rect, focused, enabled)`, which returns the cursor.
pub(crate) fn render_body(
    frame: &mut Frame,
    area: Rect,
    body: &Body,
    scroll: &Cell<usize>,
    cx: &BodyCx,
    now: Instant,
    mut draw_input: impl FnMut(&mut Frame, usize, Rect, &WidgetCx) -> Option<Position>,
) {
    let h = usize::from(area.height);
    if h == 0 || area.width == 0 {
        return;
    }
    let n = body.rows.len();
    let max_top = n.saturating_sub(h);
    let mut top = scroll.get().min(max_top);
    if body.focus_row < top {
        top = body.focus_row;
    } else if body.focus_row >= top + h {
        top = body.focus_row + 1 - h;
    }
    let top = top.min(max_top);
    scroll.set(top);
    for (i, row) in body.rows.iter().enumerate().skip(top).take(h) {
        let y = area.y + u16::try_from(i - top).unwrap_or(0);
        let r = Rect {
            y,
            height: 1,
            ..area
        };
        match row {
            Row::Line(l) => frame.render_widget(Paragraph::new(l.clone()), r),
            Row::Buttons(b) => render_buttons(frame, r, b, cx),
            Row::Input {
                label,
                field,
                width: fw,
                focused,
                enabled,
                suffix,
            } => {
                let lw = u16::try_from(label.width())
                    .unwrap_or(u16::MAX)
                    .min(r.width);
                frame.render_widget(Paragraph::new(label.clone()), Rect { width: lw, ..r });
                let rest = r.width.saturating_sub(lw);
                if rest < 3 {
                    continue;
                }
                let fw = (*fw).min(rest - 2).max(1);
                let bracket = if *enabled {
                    Style::default()
                } else {
                    cx.theme.style("field_help")
                };
                let x0 = r.x + lw;
                frame.render_widget(
                    Paragraph::new(Span::styled("[", bracket)),
                    Rect {
                        x: x0,
                        width: 1,
                        ..r
                    },
                );
                let field_rect = Rect {
                    x: x0 + 1,
                    width: fw,
                    ..r
                };
                let wcx = WidgetCx {
                    theme: cx.theme,
                    symbols: cx.symbols,
                    focused: *focused,
                    enabled: *enabled,
                    now,
                };
                let cursor = draw_input(frame, *field, field_rect, &wcx);
                frame.render_widget(
                    Paragraph::new(Span::styled("]", bracket)),
                    Rect {
                        x: x0 + 1 + fw,
                        width: 1,
                        ..r
                    },
                );
                let after = x0 + 2 + fw;
                if let Some(s) = suffix
                    && after + 1 < r.x + r.width
                {
                    frame.render_widget(
                        Paragraph::new(Line::from(vec![Span::raw(" "), s.clone()])),
                        Rect {
                            x: after,
                            width: r.x + r.width - after,
                            ..r
                        },
                    );
                }
                if *focused && let Some(p) = cursor {
                    frame.set_cursor_position(p);
                }
            }
        }
    }
    let right = area.x + area.width - 1;
    let marker = cx.theme.style("field_help");
    if top > 0 {
        frame.render_widget(
            Paragraph::new(Span::styled(cx.symbols.scroll_up, marker)),
            Rect::new(right, area.y, 1, 1),
        );
    }
    if top + h < n {
        frame.render_widget(
            Paragraph::new(Span::styled(cx.symbols.scroll_down, marker)),
            Rect::new(right, area.y + area.height - 1, 1, 1),
        );
    }
}

/// Clears `r` and draws the prompt's border and title (`danger`: error style, title
/// bold so it reads without colour); returns the content area (one column of
/// padding left and right).
pub(crate) fn draw_prompt_frame(
    frame: &mut Frame,
    r: Rect,
    title: &str,
    danger: bool,
    cx: &DrawCx,
) -> Rect {
    frame.render_widget(Clear, r);
    let (border, title_style) = if danger {
        let s = cx.theme.style("prompt.danger");
        (s, s.add_modifier(Modifier::BOLD))
    } else {
        (
            cx.theme.style("dialog_border"),
            cx.theme.style("dialog_title"),
        )
    };
    let max = usize::from(r.width.saturating_sub(4));
    let shown = truncate_to_width(&clean(title), max, cx.symbols.ellipsis).into_owned();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(cx.symbols.border)
        .border_style(border)
        .title(Line::from(vec![
            Span::styled(" ", border),
            Span::styled(shown, title_style),
            Span::styled(" ", border),
        ]));
    let inner = block.inner(r);
    frame.render_widget(block, r);
    Rect {
        x: inner.x.saturating_add(1),
        width: inner.width.saturating_sub(2),
        ..inner
    }
}

/// Keys as the prompt dialogs read them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum K {
    /// `tab`.
    Tab,
    /// `shift-tab`.
    BackTab,
    /// `enter`.
    Enter,
    /// `esc`.
    Esc,
    /// `space`.
    Space,
    /// `↑`.
    Up,
    /// `↓`.
    Down,
    /// `←`.
    Left,
    /// `→`.
    Right,
    /// `PgUp`.
    PageUp,
    /// `PgDn`.
    PageDown,
    /// A letter without modifiers (shift allowed).
    Plain(char),
    /// `alt-<letter>` (lower case).
    Alt(char),
    /// Anything else.
    Other,
}

/// Classifies a key.
pub(crate) fn classify(key: KeyChord) -> K {
    let ctrl = key.mods.contains(Mods::CTRL) || key.mods.contains(Mods::SUPER);
    let alt = key.mods.contains(Mods::ALT);
    let shift = key.mods.contains(Mods::SHIFT);
    if ctrl {
        return K::Other;
    }
    match key.code {
        KeyCode::Tab if shift => K::BackTab,
        KeyCode::Tab if !alt => K::Tab,
        KeyCode::BackTab => K::BackTab,
        KeyCode::Enter if !alt => K::Enter,
        KeyCode::Esc => K::Esc,
        KeyCode::Char(' ') if !alt => K::Space,
        KeyCode::Up if !alt => K::Up,
        KeyCode::Down if !alt => K::Down,
        KeyCode::Left if !alt => K::Left,
        KeyCode::Right if !alt => K::Right,
        KeyCode::PageUp if !alt => K::PageUp,
        KeyCode::PageDown if !alt => K::PageDown,
        KeyCode::Char(c) if alt => K::Alt(c.to_ascii_lowercase()),
        KeyCode::Char(c) => K::Plain(c),
        _ => K::Other,
    }
}

/// Moves `cur` to the next (or previous) index in `0..n` for which `ok` holds,
/// wrapping around; stays when none does.
pub(crate) fn step_focus(cur: usize, n: usize, forward: bool, ok: impl Fn(usize) -> bool) -> usize {
    if n == 0 {
        return cur;
    }
    let mut i = cur;
    for _ in 0..n {
        i = if forward {
            (i + 1) % n
        } else {
            (i + n - 1) % n
        };
        if ok(i) {
            return i;
        }
    }
    cur
}

/// `path` cut in the middle with `…` to `max` columns.
pub(crate) fn middle_truncate(path: &str, max: usize, ellipsis: &str) -> String {
    let w = width(path);
    if w <= max {
        return path.to_owned();
    }
    let ew = width(ellipsis);
    if max <= ew {
        return truncate_to_width(path, max, "").into_owned();
    }
    let keep = max - ew;
    let tail_w = keep / 2 + keep % 2;
    let head_w = keep - tail_w;
    let chars: Vec<char> = path.chars().collect();
    let head: String = take_width(chars.iter().copied(), head_w);
    let tail: String = take_width(chars.iter().rev().copied(), tail_w)
        .chars()
        .rev()
        .collect();
    format!("{head}{ellipsis}{tail}")
}

fn take_width(chars: impl Iterator<Item = char>, max: usize) -> String {
    use unicode_width::UnicodeWidthChar;
    let mut out = String::new();
    let mut used = 0;
    for c in chars {
        let cw = c.width().unwrap_or(0);
        if used + cw > max {
            break;
        }
        used += cw;
        out.push(c);
    }
    out
}

/// Colon-separated upper-case hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
