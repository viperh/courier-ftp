//! The tab bar (T61): one `[1 web01 ●]` label per connection tab.
//!
//! `●` connected, `○` not connected, `◌` connecting, `!` the last connection
//! attempt failed (ASCII: `*`, `-`, `~`, `!`). A saved site's colour tints
//! the label's brackets. When the labels don't fit, the bar shows a window
//! around the current tab with `«`/`»` (ASCII `<`/`>`) marking hidden tabs.

use courier_ftp_core::model::item::SiteColor;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{site_manager::color_style, theme::Theme};

/// Longest title shown in a label (characters).
const MAX_TITLE: usize = 24;

/// A tab's connection state, as its label shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TabState {
    Disconnected,
    Connecting,
    Connected,
    /// The last connection attempt failed.
    Error,
}

/// What the bar shows for one tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TabLabel {
    pub(crate) title: String,
    pub(crate) state: TabState,
    /// The saved site's colour (`None` for quickconnect or no site colour).
    pub(crate) color: SiteColor,
}

impl TabLabel {
    /// A tab without a connection.
    pub(crate) fn local() -> Self {
        Self {
            title: "local".to_owned(),
            state: TabState::Disconnected,
            color: SiteColor::None,
        }
    }
}

/// The labels of every tab and which one is current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TabBar {
    pub(crate) labels: Vec<TabLabel>,
    pub(crate) active: usize,
}

impl Default for TabBar {
    fn default() -> Self {
        Self {
            labels: vec![TabLabel::local()],
            active: 0,
        }
    }
}

fn symbol(state: TabState, unicode: bool) -> &'static str {
    match (state, unicode) {
        (TabState::Connected, true) => "●",
        (TabState::Disconnected, true) => "○",
        (TabState::Connecting, true) => "◌",
        (TabState::Connected, false) => "*",
        (TabState::Disconnected, false) => "-",
        (TabState::Connecting, false) => "~",
        (TabState::Error, _) => "!",
    }
}

fn short(title: &str, unicode: bool) -> String {
    if title.chars().count() <= MAX_TITLE {
        return title.to_owned();
    }
    let mut out: String = title.chars().take(MAX_TITLE - 1).collect();
    out.push_str(if unicode { "…" } else { "~" });
    out
}

/// The spans of tab `i`'s label: `[`, `1 title `, symbol, `]`.
fn label_spans(
    i: usize,
    label: &TabLabel,
    active: bool,
    unicode: bool,
    theme: &Theme,
) -> Vec<Span<'static>> {
    let text = if active {
        theme.title.add_modifier(Modifier::REVERSED)
    } else {
        Style::new()
    };
    let bracket = match label.color {
        SiteColor::None => text,
        c => text.patch(color_style(c)).add_modifier(Modifier::BOLD),
    };
    let state = match label.state {
        TabState::Error => text.patch(theme.error),
        TabState::Disconnected => text.patch(theme.dim),
        _ => text,
    };
    vec![
        Span::styled("[", bracket),
        Span::styled(format!("{} {} ", i + 1, short(&label.title, unicode)), text),
        Span::styled(symbol(label.state, unicode), state),
        Span::styled("]", bracket),
    ]
}

/// Which labels fit in `width` columns: `(first, end)` (exclusive), always
/// including `active`. When some are left out, two columns on each side are
/// kept for the `«`/`»` markers.
fn window(widths: &[usize], active: usize, width: usize) -> (usize, usize) {
    let n = widths.len();
    // A leading space, then the labels separated by spaces.
    let all = 1 + widths.iter().sum::<usize>() + n.saturating_sub(1);
    if all <= width {
        return (0, n);
    }
    let budget = width.saturating_sub(1 + 4);
    let active = active.min(n.saturating_sub(1));
    let (mut first, mut end) = (active, active + 1);
    let mut used = widths.get(active).copied().unwrap_or(0);
    loop {
        if end < n && used + 1 + widths[end] <= budget {
            used += 1 + widths[end];
            end += 1;
        } else if first > 0 && used + 1 + widths[first - 1] <= budget {
            first -= 1;
            used += 1 + widths[first];
        } else {
            return (first, end);
        }
    }
}

/// Draw the bar.
pub(crate) fn draw(frame: &mut Frame, area: Rect, bar: &TabBar, unicode: bool, theme: &Theme) {
    let labels: Vec<Vec<Span<'static>>> = bar
        .labels
        .iter()
        .enumerate()
        .map(|(i, l)| label_spans(i, l, i == bar.active, unicode, theme))
        .collect();
    let widths: Vec<usize> = labels
        .iter()
        .map(|spans| spans.iter().map(Span::width).sum())
        .collect();
    let (first, end) = window(&widths, bar.active, usize::from(area.width));
    let mut spans = vec![Span::raw(" ")];
    if first > 0 {
        spans.push(Span::styled(
            if unicode { "«" } else { "<" },
            theme.key_hint,
        ));
        spans.push(Span::raw(" "));
    }
    for (n, label) in labels.into_iter().enumerate().take(end).skip(first) {
        if n > first {
            spans.push(Span::raw(" "));
        }
        spans.extend(label);
    }
    if end < bar.labels.len() {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            if unicode { "»" } else { ">" },
            theme.key_hint,
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

#[cfg(test)]
mod tests {
    use insta::assert_snapshot;
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;

    fn label(title: &str, state: TabState) -> TabLabel {
        TabLabel {
            title: title.to_owned(),
            state,
            color: SiteColor::None,
        }
    }

    fn render(bar: &TabBar, width: u16, unicode: bool) -> String {
        let theme = Theme::new(None, true);
        let mut terminal = Terminal::new(TestBackend::new(width, 1)).unwrap();
        terminal
            .draw(|f| draw(f, f.area(), bar, unicode, &theme))
            .unwrap();
        terminal.backend().to_string()
    }

    fn states() -> TabBar {
        let mut web = label("web01", TabState::Connected);
        web.color = SiteColor::Red;
        TabBar {
            labels: vec![
                web,
                label("backup", TabState::Disconnected),
                label("alice@files.example.com:2222", TabState::Connecting),
                label("staging", TabState::Error),
            ],
            active: 1,
        }
    }

    #[test]
    fn tab_bar_states() {
        assert_snapshot!("tab_bar_states", render(&states(), 80, true));
        assert_snapshot!("tab_bar_states_ascii", render(&states(), 80, false));
        assert_snapshot!(
            "tab_bar_one_local_tab",
            render(&TabBar::default(), 40, true)
        );
    }

    #[test]
    fn tab_bar_overflow_scrolls_to_the_current_tab() {
        let labels: Vec<TabLabel> = (1..=12)
            .map(|i| label(&format!("server{i:02}"), TabState::Connected))
            .collect();
        let mut bar = TabBar { labels, active: 0 };
        assert_snapshot!("tab_bar_overflow_start", render(&bar, 60, true));
        bar.active = 6;
        assert_snapshot!("tab_bar_overflow_middle", render(&bar, 60, true));
        bar.active = 11;
        assert_snapshot!("tab_bar_overflow_end", render(&bar, 60, true));
        bar.active = 6;
        assert_snapshot!("tab_bar_overflow_ascii", render(&bar, 60, false));
    }

    #[test]
    fn the_window_always_holds_the_current_tab() {
        let widths = [10; 8];
        for active in 0..8 {
            for width in [5, 20, 40, 100] {
                let (first, end) = window(&widths, active, width);
                assert!(first <= active && active < end, "{active} {width}");
            }
        }
        assert_eq!(window(&widths, 3, 200), (0, 8));
    }
}
