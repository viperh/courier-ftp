//! Drawing a pane: title, address bar, header, the visible rows, footer and the body
//! states. A pure function of the state: only rows `offset..offset + body_rows` are
//! formatted, and every name, target, owner, group and message goes through
//! [`sanitize`](crate::ui::text::sanitize).

use courier_ftp_core::{
    model::{Entry, EntryKind},
    settings::{Column, SizeFormat},
};
use ratatui::{
    Frame,
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
};

use super::{
    columns::{ColumnLayout, fit, title},
    format::{
        DateFormats, format_modified, format_owner, format_permissions, format_size, shows_size,
        type_description,
    },
    state::{FileListState, FooterSummary, PaneStatus, Side},
};
use crate::{
    components::{DrawCx, region_block, widgets::PathInput},
    ui::{
        symbols::Symbols,
        text::{sanitize_spans, truncate_to_width, width},
        theme::Theme,
    },
};

/// Minimum pane size (outer).
pub(crate) const MIN_W: u16 = 20;
/// Minimum pane height (outer).
pub(crate) const MIN_H: u16 = 6;
/// Below this inner width the footer uses the short form.
const NARROW_FOOTER: u16 = 46;

/// How values are formatted (from the settings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RowFormat {
    /// `interface.size_format`.
    pub size: SizeFormat,
    /// `interface.thousands_separator`.
    pub thousands: bool,
    /// Date and time formats.
    pub dates: DateFormats,
}

/// What [`draw`] needs besides the state.
#[derive(Debug)]
pub(crate) struct RenderCx<'a> {
    /// Styles, glyphs, focus, spinner.
    pub draw: &'a DrawCx<'a>,
    /// Formats.
    pub format: &'a RowFormat,
    /// The address bar editor while editing.
    pub address: Option<&'a PathInput>,
    /// `Ctrl-s Site Manager · Ctrl-k Quickconnect` (from the active keymap).
    pub not_connected_hint: &'a str,
}

#[cfg(test)]
thread_local! {
    /// Rows formatted on this thread (AC6 counter test).
    pub(crate) static ROWS_FORMATTED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Spans of `text` sanitised and cut to `max` columns (escapes in `escape`).
fn fit_spans<'a>(
    text: &'a str,
    max: usize,
    base: Style,
    escape: Style,
    ellipsis: &str,
) -> (Vec<Span<'a>>, usize) {
    let spans = sanitize_spans(text, base, escape);
    let total: usize = spans.iter().map(|s| width(&s.content)).sum();
    if total <= max {
        return (spans, total);
    }
    let budget = max.saturating_sub(width(ellipsis));
    let mut out = Vec::new();
    let mut used = 0;
    for s in spans {
        let w = width(&s.content);
        if used + w <= budget {
            used += w;
            out.push(s);
            continue;
        }
        let cut = truncate_to_width(&s.content, budget - used, "").into_owned();
        used += width(&cut);
        if !cut.is_empty() {
            out.push(Span::styled(cut, s.style));
        }
        break;
    }
    if width(ellipsis) <= max {
        out.push(Span::styled(ellipsis.to_owned(), base));
        used += width(ellipsis);
    }
    (out, used)
}

fn put(buf: &mut Buffer, x: u16, y: u16, spans: Vec<Span<'_>>, max: u16) {
    let line = Line::from(spans);
    buf.set_line(x, y, &line, max);
}

#[expect(clippy::too_many_arguments, reason = "a small drawing helper")]
/// Draws a cell of `w` columns at `x` (left- or right-aligned plain text).
fn cell(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    w: u16,
    text: &str,
    right: bool,
    style: Style,
    ell: &str,
) {
    let t = truncate_to_width(text, usize::from(w), ell);
    let tw = u16::try_from(width(&t)).unwrap_or(w);
    let x = if right { x + w.saturating_sub(tw) } else { x };
    buf.set_stringn(x, y, &t, usize::from(w), style);
}

fn centered(buf: &mut Buffer, area: Rect, lines: &[(String, Style)], ell: &str) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    let n = u16::try_from(lines.len()).unwrap_or(0).min(area.height);
    let top = area.y + (area.height - n) / 2;
    for (i, (text, style)) in lines.iter().take(usize::from(n)).enumerate() {
        let t = truncate_to_width(text, usize::from(area.width), ell);
        let tw = u16::try_from(width(&t)).unwrap_or(0);
        let x = area.x + (area.width.saturating_sub(tw)) / 2;
        let y = top + u16::try_from(i).unwrap_or(0);
        buf.set_stringn(x, y, &t, usize::from(area.width), *style);
    }
}

/// The pane title: `Local` / `Remote · web01` (+ ` [filtered]`).
pub(crate) fn pane_title(state: &FileListState, symbols: &Symbols) -> String {
    let mut t = match state.id.side {
        Side::Local => "Local".to_owned(),
        Side::Remote => "Remote".to_owned(),
    };
    if let (Side::Remote, Some(label), true) = (
        state.id.side,
        &state.label,
        state.status != PaneStatus::NotConnected,
    ) {
        t.push_str(if symbols.unicode { " · " } else { " - " });
        t.push_str(&crate::ui::text::sanitize(label));
    }
    if state.is_filtered() {
        t.push_str(" [filtered]");
    }
    t
}

/// Draws the pane into `area`.
pub(crate) fn draw(state: &FileListState, frame: &mut Frame, area: Rect, rcx: &RenderCx<'_>) {
    let cx = rcx.draw;
    let theme = cx.theme;
    let symbols = cx.symbols;
    let ell = symbols.ellipsis;
    if area.width < MIN_W || area.height < MIN_H {
        if area.width > 0 && area.height > 0 {
            let t = truncate_to_width("Terminal too small", usize::from(area.width), ell);
            frame.buffer_mut().set_stringn(
                area.x,
                area.y,
                &t,
                usize::from(area.width),
                Style::default(),
            );
        }
        return;
    }
    let block = region_block(&pane_title(state, symbols), cx);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let buf = frame.buffer_mut();
    let w = inner.width;
    let address = Rect { height: 1, ..inner };
    let header_y = inner.y + 1;
    let footer_y = inner.bottom() - 1;
    let body = Rect {
        y: inner.y + 2,
        height: inner.height.saturating_sub(3),
        ..inner
    };
    let escape = theme.style("text.escape");

    // Body states without a listing.
    if state.status == PaneStatus::NotConnected {
        centered(
            buf,
            body,
            &[
                ("Not connected to any server".to_owned(), Style::default()),
                (
                    if symbols.unicode {
                        rcx.not_connected_hint.to_owned()
                    } else {
                        rcx.not_connected_hint.replace('·', "-")
                    },
                    theme.style("placeholder"),
                ),
            ],
            ell,
        );
        return;
    }

    // Address bar.
    match (rcx.address, &state.dir) {
        (Some(input), _) => {
            use crate::components::widgets::Widget as _;
            input.render(
                frame,
                address,
                &crate::components::widgets::WidgetCx {
                    theme,
                    symbols,
                    focused: true,
                    enabled: true,
                    now: cx.now,
                },
            );
        }
        (None, Some(dir)) => {
            let text = dir.display();
            let (spans, _) = fit_spans(&text, usize::from(w), Style::default(), escape, ell);
            put(frame.buffer_mut(), address.x, address.y, spans, w);
        }
        (None, None) => {}
    }
    let buf = frame.buffer_mut();

    let Some(listing) = &state.listing else {
        let lines: Vec<(String, Style)> = match &state.status {
            PaneStatus::Loading { .. } => {
                let mut t = format!("Loading{ell}");
                if let Some(s) = cx.spinner {
                    t.push(' ');
                    t.push_str(s);
                }
                vec![(t, Style::default())]
            }
            PaneStatus::Error { message, .. } => {
                let msg = crate::ui::text::sanitize(message).into_owned();
                vec![(format!("Error: {msg}"), theme.style("file_list.error"))]
            }
            _ => Vec::new(),
        };
        centered(buf, body, &lines, ell);
        draw_footer(state, buf, inner.x, footer_y, w, rcx, None);
        return;
    };

    // Header.
    let layout = fit(w, &state.columns);
    draw_header(state, buf, inner.x, header_y, &layout, theme, symbols);

    // Rows.
    let rows = usize::from(body.height);
    let count = state.row_count();
    let mut offset = state.offset.min(count.saturating_sub(rows));
    if state.cursor < offset {
        offset = state.cursor;
    } else if rows > 0 && state.cursor >= offset + rows {
        offset = state.cursor + 1 - rows;
    }
    if count == 0 && listing.entries.len() > state.view().len() {
        let n = listing.entries.len();
        let s = if n == 1 { "entry is" } else { "entries are" };
        let all = if n == 1 { "The" } else { "All" };
        centered(
            buf,
            body,
            &[(
                format!("{all} {n} {s} hidden by filters"),
                theme.style("placeholder"),
            )],
            ell,
        );
    }
    let visual = state.visual_range();
    let cursor_style = theme.style(if cx.focused {
        "file_list.cursor"
    } else {
        "file_list.cursor_inactive"
    });
    for (i, row) in (offset..count.min(offset + rows)).enumerate() {
        let y = body.y + u16::try_from(i).unwrap_or(0);
        let row_area = Rect::new(inner.x, y, w, 1);
        #[cfg(test)]
        ROWS_FORMATTED.with(|c| c.set(c.get() + 1));
        match state.entry_index(row) {
            None => {
                buf.set_stringn(
                    inner.x + 1,
                    y,
                    "..",
                    usize::from(w.saturating_sub(1)),
                    theme.style("file_list.dir"),
                );
            }
            Some(idx) => {
                let Some(entry) = listing.entries.get(idx as usize) else {
                    continue;
                };
                let marked = state.is_marked(idx);
                draw_row(buf, inner.x, y, entry, marked, &layout, rcx);
                if marked {
                    buf.set_style(row_area, theme.style("file_list.marked"));
                }
                if let Some(style) = state
                    .decoration
                    .as_ref()
                    .and_then(|d| d.style_for(Some(idx)))
                {
                    buf.set_style(row_area, theme.style(style));
                }
            }
        }
        if visual.is_some_and(|(a, b)| row >= a && row <= b) {
            buf.set_style(row_area, theme.style("file_list.marked"));
        }
        if row == state.cursor {
            buf.set_style(row_area, cursor_style);
        }
    }
    draw_footer(
        state,
        buf,
        inner.x,
        footer_y,
        w,
        rcx,
        Some(listing.entries.len()),
    );
}

fn draw_header(
    state: &FileListState,
    buf: &mut Buffer,
    x0: u16,
    y: u16,
    layout: &ColumnLayout,
    theme: &Theme,
    symbols: &Symbols,
) {
    let style = theme.style("file_list.header");
    let mut x = x0 + 1;
    for (i, (col, cw)) in layout.cols.iter().enumerate() {
        if i > 0 {
            x += 1;
        }
        let mut t = title(*col).to_owned();
        if state.sort.column == *col {
            let arrow = match (symbols.unicode, state.sort.descending) {
                (true, false) => "▲",
                (true, true) => "▼",
                (false, false) => "^",
                (false, true) => "v",
            };
            t.push(' ');
            t.push_str(arrow);
        }
        cell(
            buf,
            x,
            y,
            *cw,
            &t,
            *col == Column::Size,
            style,
            symbols.ellipsis,
        );
        x += cw;
    }
}

fn draw_row(
    buf: &mut Buffer,
    x0: u16,
    y: u16,
    e: &Entry,
    marked: bool,
    layout: &ColumnLayout,
    rcx: &RenderCx<'_>,
) {
    let theme = rcx.draw.theme;
    let symbols = rcx.draw.symbols;
    let ell = symbols.ellipsis;
    let escape = theme.style("text.escape");
    if marked {
        buf.set_stringn(x0, y, "*", 1, theme.style("file_list.marked"));
    }
    let mut x = x0 + 1;
    for (i, (col, cw)) in layout.cols.iter().enumerate() {
        if i > 0 {
            x += 1;
        }
        let cw = *cw;
        match col {
            Column::Name => {
                let base = match &e.kind {
                    EntryKind::Dir => theme.style("file_list.dir"),
                    EntryKind::Other => theme.style("file_list.special"),
                    _ if e.hidden => theme.style("file_list.hidden"),
                    _ => Style::default(),
                };
                let base = if e.hidden && e.is_dir() {
                    base.patch(theme.style("file_list.hidden"))
                } else {
                    base
                };
                let mut spans = sanitize_spans(&e.name, base, escape);
                match &e.kind {
                    EntryKind::Dir => spans.push(Span::styled("/", base)),
                    EntryKind::Symlink { target, .. } => {
                        if let Some(t) = target {
                            let arrow = if symbols.unicode { " → " } else { " -> " };
                            let ts = theme.style("file_list.symlink_target");
                            spans.push(Span::styled(arrow, ts));
                            spans.extend(sanitize_spans(t, ts, escape.patch(ts)));
                        } else if e.is_dir_like() {
                            spans.push(Span::styled("/", base));
                        }
                    }
                    _ => {}
                }
                let text_w: usize = spans.iter().map(|s| width(&s.content)).sum();
                let spans = if text_w > usize::from(cw) {
                    // Cut the composed text.
                    let mut out = Vec::new();
                    let budget = usize::from(cw).saturating_sub(width(ell));
                    let mut used = 0;
                    for s in spans {
                        let sw = width(&s.content);
                        if used + sw <= budget {
                            used += sw;
                            out.push(s);
                            continue;
                        }
                        let cut = truncate_to_width(&s.content, budget - used, "").into_owned();
                        if !cut.is_empty() {
                            out.push(Span::styled(cut, s.style));
                        }
                        break;
                    }
                    if width(ell) <= usize::from(cw) {
                        out.push(Span::styled(ell, base));
                    }
                    out
                } else {
                    spans
                };
                put(buf, x, y, spans, cw);
            }
            Column::Size => {
                if shows_size(e)
                    && let Some(s) = e.size
                {
                    let t = format_size(s, rcx.format.size, rcx.format.thousands);
                    cell(buf, x, y, cw, &t, true, Style::default(), ell);
                }
            }
            Column::Type => {
                cell(
                    buf,
                    x,
                    y,
                    cw,
                    &type_description(e),
                    false,
                    Style::default(),
                    ell,
                );
            }
            Column::Modified => {
                if let Some(ts) = &e.modified {
                    let t = format_modified(ts, &rcx.format.dates, layout.compact_date);
                    cell(buf, x, y, cw, &t, false, Style::default(), ell);
                }
            }
            Column::Permissions => {
                let t = format_permissions(e);
                let (spans, _) = fit_spans(&t, usize::from(cw), Style::default(), escape, ell);
                put(buf, x, y, spans, cw);
            }
            Column::OwnerGroup => {
                let t = format_owner(e);
                let (spans, _) = fit_spans(&t, usize::from(cw), Style::default(), escape, ell);
                put(buf, x, y, spans, cw);
            }
        }
        x += cw;
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The footer text for `s` (normal or selected form).
pub(crate) fn summary_text(s: &FooterSummary, narrow: bool, format: &RowFormat) -> String {
    let size = format_size(s.bytes, format.size, format.thousands);
    if narrow {
        let mut t = format!(
            "{}, {}. {size}",
            plural(s.files, "file", "files"),
            plural(s.dirs, "dir", "dirs")
        );
        if s.selected {
            t.insert_str(0, "Sel. ");
        }
        return t;
    }
    let mut parts = Vec::new();
    if s.files > 0 || s.dirs == 0 {
        parts.push(plural(s.files, "file", "files"));
    }
    if s.dirs > 0 {
        parts.push(plural(s.dirs, "directory", "directories"));
    }
    let what = parts.join(" and ");
    let at_least = if s.unknown_size { "at least " } else { "" };
    let prefix = if s.selected { "Selected " } else { "" };
    format!("{prefix}{what}. Total size: {at_least}{size}")
}

fn draw_footer(
    state: &FileListState,
    buf: &mut Buffer,
    x: u16,
    y: u16,
    w: u16,
    rcx: &RenderCx<'_>,
    total: Option<usize>,
) {
    let theme = rcx.draw.theme;
    let ell = rcx.draw.symbols.ellipsis;
    let escape = theme.style("text.escape");
    let footer = theme.style("file_list.footer");
    let max = usize::from(w);
    if let Some((text, is_error, _)) = &state.notice {
        let (style, prefix) = if *is_error {
            (theme.style("file_list.error"), "Error: ")
        } else {
            (footer, "")
        };
        let full = format!("{prefix}{text}");
        let (spans, _) = fit_spans(&full, max, style, escape, ell);
        put(buf, x, y, spans, w);
        return;
    }
    let Some(total) = total else {
        return;
    };
    if let Some(q) = &state.quick_filter
        && q.editing
    {
        let counts = format!("  ({} of {total})", state.view().len());
        let (mut spans, used) = fit_spans(
            &q.text,
            max.saturating_sub(2 + width(&counts)),
            footer,
            escape,
            ell,
        );
        spans.insert(0, Span::styled("/", footer));
        spans.push(Span::styled(
            " ",
            Style::default().add_modifier(Modifier::REVERSED),
        ));
        spans.push(Span::styled(counts, footer));
        let _ = used;
        put(buf, x, y, spans, w);
        return;
    }
    let mut text = if total == 0 {
        "Empty directory.".to_owned()
    } else {
        summary_text(&state.footer(), w < NARROW_FOOTER, rcx.format)
    };
    if let Some(q) = &state.quick_filter
        && !q.text.is_empty()
    {
        text.push_str(&format!("  [/{}]", q.text));
    }
    let (spans, _) = fit_spans(&text, max, footer, escape, ell);
    put(buf, x, y, spans, w);
}
