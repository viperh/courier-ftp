//! Line layout and the anchor-based renderer of the message log (T55).
//!
//! The renderer lays lines out **upwards** from the anchor (the line on the bottom row)
//! and computes wrap heights only for the lines it draws, so its cost does not depend
//! on the ring size. Like `store.rs`, this file depends only on `super::store` and
//! external crates so the benchmarks can include it.

use std::{
    collections::VecDeque,
    ops::Range,
    sync::{Arc, OnceLock},
};

use courier_ftp_core::events::LogKind;
use ratatui::{buffer::Buffer, layout::Rect, style::Style};
use time::{OffsetDateTime, UtcOffset};
use unicode_width::UnicodeWidthChar;

use super::store::{LineOrigin, LogLine};

static LOCAL_OFFSET: OnceLock<UtcOffset> = OnceLock::new();

/// Reads the local UTC offset once. Must run while the process is single-threaded
/// (`time` refuses to read it otherwise on Unix), so `main` calls it before starting
/// the runtime. Without it, times are shown in UTC (tests, benches).
pub(crate) fn init_local_offset() {
    if let Ok(o) = UtcOffset::current_local_offset() {
        let _ = LOCAL_OFFSET.set(o);
    }
}

/// The offset times are shown in.
pub(crate) fn local_offset() -> UtcOffset {
    LOCAL_OFFSET.get().copied().unwrap_or(UtcOffset::UTC)
}

/// Kind filter of a view (`e` cycles).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum KindFilter {
    /// Every line.
    #[default]
    Everything,
    /// No `Trace:` lines.
    HideTrace,
    /// Only `Error:` lines.
    ErrorsOnly,
}

impl KindFilter {
    /// Whether `line` is shown.
    pub(crate) fn passes(self, line: &LogLine) -> bool {
        match self {
            Self::Everything => true,
            Self::HideTrace => !matches!(line.kind, LogKind::Debug(_)),
            Self::ErrorsOnly => line.kind == LogKind::Error,
        }
    }

    /// The next filter in the cycle.
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Everything => Self::HideTrace,
            Self::HideTrace => Self::ErrorsOnly,
            Self::ErrorsOnly => Self::Everything,
        }
    }

    /// Title suffix.
    pub(crate) fn label(self) -> Option<&'static str> {
        match self {
            Self::Everything => None,
            Self::HideTrace => Some("[no trace]"),
            Self::ErrorsOnly => Some("[errors only]"),
        }
    }
}

/// Resolved styles of the log (`log.*` keys and `text.escape`).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct LogStyles {
    /// `log.status`.
    pub status: Style,
    /// `log.warning`.
    pub warning: Style,
    /// `log.command`.
    pub command: Style,
    /// `log.response`.
    pub response: Style,
    /// `log.error`.
    pub error: Style,
    /// `log.trace`.
    pub trace: Style,
    /// `log.listing`.
    pub listing: Style,
    /// `log.time` (timestamps and tags).
    pub time: Style,
    /// `log.cursor`.
    pub cursor: Style,
    /// `log.visual`.
    pub visual: Style,
    /// `log.search_match`.
    pub search_match: Style,
    /// `text.escape`.
    pub escape: Style,
}

impl LogStyles {
    /// The style of `line`'s prefix and text.
    pub(crate) fn for_line(&self, line: &LogLine) -> Style {
        match line.kind {
            LogKind::Status if line.is_warning() => self.warning,
            LogKind::Status => self.status,
            LogKind::Command => self.command,
            LogKind::Response => self.response,
            LogKind::Error => self.error,
            LogKind::ListingRaw => self.listing,
            LogKind::Debug(_) => self.trace,
        }
    }

    /// The style key of `line` (tests).
    #[cfg(test)]
    pub(crate) fn key_for(line: &LogLine) -> &'static str {
        match line.kind {
            LogKind::Status if line.is_warning() => "log.warning",
            LogKind::Status => "log.status",
            LogKind::Command => "log.command",
            LogKind::Response => "log.response",
            LogKind::Error => "log.error",
            LogKind::ListingRaw => "log.listing",
            LogKind::Debug(_) => "log.trace",
        }
    }
}

/// `Status:` or `S:` for `kind`.
pub(crate) fn prefix(kind: LogKind, short: bool) -> &'static str {
    match (kind, short) {
        (LogKind::Status, false) => "Status:",
        (LogKind::Command, false) => "Command:",
        (LogKind::Response, false) => "Response:",
        (LogKind::Error, false) => "Error:",
        (LogKind::Debug(_), false) => "Trace:",
        (LogKind::ListingRaw, false) => "Listing:",
        (LogKind::Status, true) => "S:",
        (LogKind::Command, true) => "C:",
        (LogKind::Response, true) => "R:",
        (LogKind::Error, true) => "E:",
        (LogKind::Debug(_), true) => "T:",
        (LogKind::ListingRaw, true) => "L:",
    }
}

/// How the `All` view tags a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagMode {
    /// Tab views: no tag.
    None,
    /// `1`…`9`, `+`, `T`, `-` (narrow).
    Short,
    /// `[1]`, `[T]`, `[-]`.
    Full,
}

/// The column layout at one width (narrow rules applied).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Columns {
    /// Timestamps shown.
    pub time: bool,
    /// Tag column.
    pub tag: TagMode,
    /// `S:` instead of `Status:`.
    pub short_prefix: bool,
    /// Column where the text starts.
    pub text_col: usize,
    /// Columns left for the text (at least 1).
    pub text_w: usize,
}

const TIME_W: usize = 9;
const PREFIX_W: usize = 10;
const SHORT_PREFIX_W: usize = 3;

impl Columns {
    /// The layout for an inner width of `width` columns.
    pub(crate) fn new(width: u16, all_view: bool, show_timestamps: bool) -> Self {
        let w = usize::from(width);
        let tag = match (all_view, w < 70) {
            (false, _) => TagMode::None,
            (true, true) => TagMode::Short,
            (true, false) => TagMode::Full,
        };
        let time = show_timestamps && w >= 60;
        let short_prefix = w < 45;
        let text_col = if time { TIME_W } else { 0 }
            + match tag {
                TagMode::None => 0,
                TagMode::Short => 2,
                TagMode::Full => 4,
            }
            + if short_prefix {
                SHORT_PREFIX_W
            } else {
                PREFIX_W
            };
        Self {
            time,
            tag,
            short_prefix,
            text_col,
            text_w: w.saturating_sub(text_col).max(1),
        }
    }
}

fn tag_text(origin: LineOrigin, mode: TagMode) -> String {
    let core = match origin {
        LineOrigin::Tab(t) if t.0 < 9 => char::from_digit(t.0 + 1, 10).unwrap_or('+'),
        LineOrigin::Tab(_) => '+',
        LineOrigin::Transfer => 'T',
        LineOrigin::App => '-',
    };
    match mode {
        TagMode::None => String::new(),
        TagMode::Short => format!("{core} "),
        TagMode::Full => format!("[{core}] "),
    }
}

fn time_text(t: OffsetDateTime, offset: UtcOffset) -> String {
    let t = t.to_offset(offset);
    format!("{:02}:{:02}:{:02} ", t.hour(), t.minute(), t.second())
}

/// The line as displayed, unwrapped: timestamp, tag, padded prefix, text (copy).
pub(crate) fn plain_line(line: &LogLine, cols: &Columns, offset: UtcOffset) -> String {
    let mut s = String::with_capacity(cols.text_col + line.text.len());
    if cols.time {
        s.push_str(&time_text(line.time, offset));
    }
    s.push_str(&tag_text(line.origin, cols.tag));
    let p = prefix(line.kind, cols.short_prefix);
    let w = if cols.short_prefix {
        SHORT_PREFIX_W
    } else {
        PREFIX_W
    };
    s.push_str(&format!("{p:<w$}"));
    s.push_str(&line.text);
    s
}

/// Plain substring search with smart case: case-sensitive only when the query has an
/// uppercase letter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Matcher {
    query: String,
    case_sensitive: bool,
}

impl Matcher {
    /// None for an empty query.
    pub(crate) fn new(query: &str) -> Option<Self> {
        if query.is_empty() {
            return None;
        }
        Some(Self {
            query: query.to_owned(),
            case_sensitive: query.chars().any(char::is_uppercase),
        })
    }

    /// Whether `text` contains the query.
    pub(crate) fn is_match(&self, text: &str) -> bool {
        if self.case_sensitive {
            return text.contains(&self.query);
        }
        if self.query.is_ascii() {
            let q = self.query.as_bytes();
            return text.len() >= q.len()
                && text
                    .as_bytes()
                    .windows(q.len())
                    .any(|w| w.eq_ignore_ascii_case(q));
        }
        !self.ranges(text).is_empty()
    }

    /// Byte ranges of the non-overlapping matches in `text`.
    pub(crate) fn ranges(&self, text: &str) -> Vec<Range<usize>> {
        if self.case_sensitive {
            return text
                .match_indices(&self.query)
                .map(|(i, m)| i..i + m.len())
                .collect();
        }
        let mut out = Vec::new();
        if self.query.is_ascii() {
            let q = self.query.as_bytes();
            let t = text.as_bytes();
            let mut i = 0;
            while i + q.len() <= t.len() {
                if t[i..i + q.len()].eq_ignore_ascii_case(q) {
                    out.push(i..i + q.len());
                    i += q.len();
                } else {
                    i += 1;
                }
            }
            return out;
        }
        let q: Vec<char> = self.query.chars().flat_map(char::to_lowercase).collect();
        let mut starts = text.char_indices().peekable();
        while let Some((start, _)) = starts.next() {
            // Try to match the lower-cased query from `start`.
            let mut qi = 0;
            let mut end = None;
            for (i, c) in text[start..].char_indices() {
                for lc in c.to_lowercase() {
                    if q.get(qi) == Some(&lc) {
                        qi += 1;
                    } else {
                        qi = usize::MAX;
                        break;
                    }
                }
                if qi == usize::MAX {
                    break;
                }
                if qi == q.len() {
                    end = Some(start + i + c.len_utf8());
                    break;
                }
            }
            if let Some(e) = end {
                out.push(start..e);
                while starts.peek().is_some_and(|(i, _)| *i < e) {
                    starts.next();
                }
            }
        }
        out
    }
}

/// Splits `text` into rows of at most `width` columns: breaks at spaces (the space is
/// dropped), words longer than a row are hard-broken. Always at least one row.
pub(crate) fn wrap_ranges(text: &str, width: usize, out: &mut Vec<Range<usize>>) {
    out.clear();
    if width == 0 || text.is_empty() {
        out.push(0..text.len());
        return;
    }
    let mut start = 0;
    let mut col = 0;
    let mut space: Option<usize> = None;
    let mut col_after_space = 0;
    for (i, c) in text.char_indices() {
        let w = c.width().unwrap_or(0);
        if col + w > width {
            if c == ' ' {
                out.push(start..i);
                start = i + 1;
                col = 0;
                space = None;
                continue;
            }
            if let Some(sp) = space {
                out.push(start..sp);
                start = sp + 1;
                col -= col_after_space;
                space = None;
            }
            if col + w > width && col > 0 {
                out.push(start..i);
                start = i;
                col = 0;
                space = None;
            }
        }
        if c == ' ' {
            space = Some(i);
            col_after_space = col + w;
        }
        col += w;
    }
    if start < text.len() || out.is_empty() {
        out.push(start..text.len());
    }
}

/// Byte offset in `text` where column `cols` starts (horizontal scroll).
fn skip_columns(text: &str, cols: usize) -> usize {
    let mut used = 0;
    for (i, c) in text.char_indices() {
        if used >= cols {
            return i;
        }
        used += c.width().unwrap_or(0);
    }
    text.len()
}

/// Ranges of sanitiser escapes (`^[`, `^?`, `<U+202E>`) in stored text.
fn escape_ranges(text: &str) -> Vec<Range<usize>> {
    let b = text.as_bytes();
    if !b.iter().any(|&c| c == b'^' || c == b'<') {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'^'
            && b.get(i + 1)
                .is_some_and(|&n| (0x40..=0x5F).contains(&n) || n == b'?')
        {
            out.push(i..i + 2);
            i += 2;
            continue;
        }
        if b[i..].starts_with(b"<U+") {
            let hex = b[i + 3..]
                .iter()
                .take_while(|c| c.is_ascii_hexdigit())
                .count();
            if (4..=6).contains(&hex) && b.get(i + 3 + hex) == Some(&b'>') {
                out.push(i..i + 4 + hex);
                i += 4 + hex;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Style runs covering `text`: `base`, patched with the escape style and the search
/// match style where they apply.
fn style_runs(
    text: &str,
    base: Style,
    styles: &LogStyles,
    matcher: Option<&Matcher>,
) -> Vec<(Range<usize>, Style)> {
    let escapes = escape_ranges(text);
    let matches = matcher.map(|m| m.ranges(text)).unwrap_or_default();
    if escapes.is_empty() && matches.is_empty() {
        return vec![(0..text.len(), base)];
    }
    let mut cuts: Vec<usize> = vec![0, text.len()];
    for r in escapes.iter().chain(&matches) {
        cuts.push(r.start);
        cuts.push(r.end);
    }
    cuts.sort_unstable();
    cuts.dedup();
    let inside = |rs: &[Range<usize>], a: usize| rs.iter().any(|r| r.start <= a && a < r.end);
    cuts.windows(2)
        .map(|w| {
            let mut s = base;
            if inside(&escapes, w[0]) {
                s = s.patch(styles.escape);
            }
            if inside(&matches, w[0]) {
                s = s.patch(styles.search_match);
            }
            (w[0]..w[1], s)
        })
        .collect()
}

/// What the renderer needs besides the lines.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RenderParams<'a> {
    /// Pinned to the newest line.
    pub follow: bool,
    /// The line on the bottom row when not following.
    pub anchor_seq: Option<u64>,
    /// The cursor line (drawn only when focused).
    pub cursor_seq: Option<u64>,
    /// Inclusive visual range (`lo`, `hi`).
    pub visual: Option<(u64, u64)>,
    /// Wrap long lines.
    pub wrap: bool,
    /// Horizontal scroll in columns (no wrap).
    pub hscroll: usize,
    /// Kind filter.
    pub filter: KindFilter,
    /// Search highlight.
    pub matcher: Option<&'a Matcher>,
    /// The `All` view (tags).
    pub all_view: bool,
    /// `logging.show_timestamps`.
    pub show_timestamps: bool,
    /// Unicode glyphs (`«`/`»` markers).
    pub unicode: bool,
    /// Offset for timestamps.
    pub offset: UtcOffset,
}

/// What a render showed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Visible {
    /// Sequence numbers of the lines with at least one drawn row, top to bottom.
    pub seqs: Vec<u64>,
    /// The first line's first rows were cut off.
    pub top_clipped: bool,
    /// The last line's last rows were cut off.
    pub bottom_clipped: bool,
}

/// Index of the line with `seq` (or of the first newer one; 0 when it was evicted).
pub(crate) fn index_of(lines: &VecDeque<Arc<LogLine>>, seq: u64) -> usize {
    lines.partition_point(|l| l.seq < seq)
}

fn anchor_index(lines: &VecDeque<Arc<LogLine>>, p: &RenderParams) -> Option<usize> {
    let last = lines.len().checked_sub(1)?;
    let start = match (p.follow, p.anchor_seq) {
        (false, Some(s)) => index_of(lines, s).min(last),
        _ => last,
    };
    (0..=start)
        .rev()
        .find(|i| p.filter.passes(&lines[*i]))
        .or_else(|| (start + 1..lines.len()).find(|i| p.filter.passes(&lines[*i])))
}

fn line_ranges(line: &LogLine, cols: &Columns, p: &RenderParams, out: &mut Vec<Range<usize>>) {
    if p.wrap {
        wrap_ranges(&line.text, cols.text_w, out);
    } else {
        out.clear();
        let start = skip_columns(&line.text, p.hscroll);
        out.push(start..line.text.len());
    }
}

/// Number of rows `line` takes.
pub(crate) fn line_rows(
    line: &LogLine,
    cols: &Columns,
    p: &RenderParams,
    scratch: &mut Vec<Range<usize>>,
) -> usize {
    line_ranges(line, cols, p, scratch);
    scratch.len()
}

/// The anchor (bottom line) that shows the line at `top_idx` on the top row of a view
/// `width`×`height`.
pub(crate) fn anchor_for_top(
    lines: &VecDeque<Arc<LogLine>>,
    top_idx: usize,
    width: u16,
    height: usize,
    p: &RenderParams,
) -> Option<u64> {
    let cols = Columns::new(width, p.all_view, p.show_timestamps);
    let mut scratch = Vec::new();
    let mut rows = 0;
    let mut anchor = None;
    for l in lines.iter().skip(top_idx).filter(|l| p.filter.passes(l)) {
        rows += line_rows(l, &cols, p, &mut scratch);
        if rows > height && anchor.is_some() {
            break;
        }
        anchor = Some(l.seq);
        if rows >= height {
            break;
        }
    }
    anchor
}

/// Draws the visible lines into `area` (the pane's body).
pub(crate) fn render_body(
    buf: &mut Buffer,
    area: Rect,
    lines: &VecDeque<Arc<LogLine>>,
    p: &RenderParams,
    styles: &LogStyles,
) -> Visible {
    let mut vis = Visible::default();
    if area.width < 12 || area.height == 0 {
        return vis;
    }
    let Some(anchor) = anchor_index(lines, p) else {
        return vis;
    };
    let cols = Columns::new(area.width, p.all_view, p.show_timestamps);
    let h = usize::from(area.height);
    let mut picked: Vec<(usize, Vec<Range<usize>>)> = Vec::new();
    let mut rows = 0;
    let mut i = anchor + 1;
    while i > 0 && rows < h {
        i -= 1;
        let l = &lines[i];
        if !p.filter.passes(l) {
            continue;
        }
        let mut r = Vec::new();
        line_ranges(l, &cols, p, &mut r);
        rows += r.len();
        picked.push((i, r));
    }
    picked.reverse();
    let mut skip = rows.saturating_sub(h);
    vis.top_clipped = skip > 0;
    // Room left below the anchor (the view starts at the oldest line): fill it.
    let mut j = anchor + 1;
    while rows < h && j < lines.len() {
        let l = &lines[j];
        j += 1;
        if !p.filter.passes(l) {
            continue;
        }
        let mut r = Vec::new();
        line_ranges(l, &cols, p, &mut r);
        rows += r.len();
        picked.push((j - 1, r));
    }

    let (left, right) = if p.unicode { ("«", "»") } else { ("<", ">") };
    let mut y = 0usize;
    'lines: for (idx, ranges) in &picked {
        let l = &lines[*idx];
        let base = styles.for_line(l);
        let runs = style_runs(&l.text, base, styles, p.matcher);
        let row_style = if p.cursor_seq == Some(l.seq) {
            Some(styles.cursor)
        } else {
            p.visual
                .filter(|(lo, hi)| (*lo..=*hi).contains(&l.seq))
                .map(|_| styles.visual)
        };
        let mut drawn = false;
        for (k, seg) in ranges.iter().enumerate() {
            if skip > 0 {
                skip -= 1;
                continue;
            }
            if y >= h {
                vis.bottom_clipped = true;
                break 'lines;
            }
            let row_y = area.y + u16::try_from(y).unwrap_or(u16::MAX);
            let text_x = area.x + u16::try_from(cols.text_col).unwrap_or(u16::MAX);
            if k == 0 {
                draw_header(buf, area.x, row_y, l, &cols, base, styles, p.offset);
            }
            let mut x = text_x;
            let max_x = area.x + area.width;
            for (r, style) in &runs {
                let a = r.start.max(seg.start);
                let b = r.end.min(seg.end);
                if a >= b || x >= max_x {
                    continue;
                }
                x = buf
                    .set_stringn(x, row_y, &l.text[a..b], usize::from(max_x - x), *style)
                    .0;
            }
            if !p.wrap {
                if seg.start > 0 {
                    buf.set_string(text_x, row_y, left, styles.time);
                }
                let shown: usize = l.text[seg.start..]
                    .chars()
                    .map(|c| c.width().unwrap_or(0))
                    .sum();
                if shown > cols.text_w {
                    buf.set_string(max_x - 1, row_y, right, styles.time);
                }
            }
            if let Some(s) = row_style {
                buf.set_style(Rect::new(area.x, row_y, area.width, 1), s);
            }
            drawn = true;
            y += 1;
        }
        if drawn {
            vis.seqs.push(l.seq);
        }
    }
    vis
}

#[expect(clippy::too_many_arguments, reason = "one row's header, all needed")]
fn draw_header(
    buf: &mut Buffer,
    x0: u16,
    y: u16,
    line: &LogLine,
    cols: &Columns,
    base: Style,
    styles: &LogStyles,
    offset: UtcOffset,
) {
    let mut x = x0;
    if cols.time {
        x = buf
            .set_stringn(x, y, time_text(line.time, offset), usize::MAX, styles.time)
            .0;
    }
    if cols.tag != TagMode::None {
        x = buf
            .set_stringn(
                x,
                y,
                tag_text(line.origin, cols.tag),
                usize::MAX,
                styles.time,
            )
            .0;
    }
    buf.set_string(x, y, prefix(line.kind, cols.short_prefix), base);
}
