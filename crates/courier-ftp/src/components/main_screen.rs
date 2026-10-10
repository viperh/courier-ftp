//! The main screen: quickconnect bar, tab bar, message log, the local and remote sides
//! (tree + file list) of each tab, the queue and the status bar, laid out by
//! [`layout::compute_layout`]. Until their tasks land, regions are [`Placeholder`]s.

pub(crate) mod layout;

use std::time::Duration;

use courier_ftp_core::{events::CoreEvent, settings::InterfaceSettings};
use ratatui::{
    Frame,
    layout::{Alignment, Rect, Size},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};
use tokio::time::Instant;

use self::layout::{LayoutOptions, Region, ScreenLayout, compute_layout, focus_order};
use super::{Component, DrawCx, placeholder::Placeholder};
use crate::{
    action::Action,
    tabs::TabId,
    ui::{
        symbols::Symbols,
        text::{sanitize_spans, truncate_to_width, width},
        theme::Theme,
    },
};

/// How long a status message stays.
pub(crate) const STATUS_MESSAGE_TTL: Duration = Duration::from_secs(3);

/// One side of a tab.
pub(crate) struct SideView {
    /// Directory tree (T54).
    pub tree: Box<dyn Component>,
    /// File list (T53).
    pub list: Box<dyn Component>,
}

/// A connection tab (exactly one until T61).
pub(crate) struct TabView {
    /// Its id.
    #[expect(dead_code, reason = "read by connection tabs (T61)")]
    pub id: TabId,
    /// Title in the tab bar.
    pub title: String,
    /// Local side.
    pub local: SideView,
    /// Remote side.
    pub remote: SideView,
}

impl TabView {
    fn placeholder(id: TabId, title: &str) -> Self {
        Self {
            id,
            title: title.to_owned(),
            local: SideView {
                tree: Box::new(Placeholder::new(Region::LocalTree)),
                list: Box::new(Placeholder::new(Region::LocalList)),
            },
            remote: SideView {
                tree: Box::new(Placeholder::new(Region::RemoteTree)),
                list: Box::new(Placeholder::new(Region::RemoteList)),
            },
        }
    }
}

/// A transient status-line message.
#[derive(Debug, Clone)]
pub(crate) struct StatusMessage {
    /// Text (sanitised when drawn).
    pub text: String,
    /// Drawn in the error style.
    pub error: bool,
    /// When it was set.
    pub at: Instant,
}

/// What the status bar shows besides the message (filled by `App`).
#[derive(Debug, Clone, Default)]
pub(crate) struct StatusInfo {
    /// `NORMAL`, `INPUT`, `DIALOG`.
    pub mode: &'static str,
    /// The keys of a pending sequence (`ctrl-x`), shown in the key-hint area.
    pub pending: Option<String>,
}

/// The screen.
pub(crate) struct MainScreen {
    quickconnect: Box<dyn Component>,
    log: Box<dyn Component>,
    queue: Box<dyn Component>,
    tabs: Vec<TabView>,
    active: usize,
    focus: Region,
    last_list: Region,
    opts: LayoutOptions,
    size: Size,
    status: Option<StatusMessage>,
}

impl std::fmt::Debug for MainScreen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MainScreen")
            .field("focus", &self.focus)
            .field("opts", &self.opts)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl MainScreen {
    /// The screen with the message log `log`, placeholders for the other regions and
    /// one tab titled "Local".
    pub(crate) fn new(interface: &InterfaceSettings, log: Box<dyn Component>) -> Self {
        let mut me = Self {
            quickconnect: Box::new(Placeholder::new(Region::Quickconnect)),
            log,
            queue: Box::new(Placeholder::new(Region::Queue)),
            tabs: vec![TabView::placeholder(TabId::FIRST, "Local")],
            active: 0,
            focus: Region::LocalList,
            last_list: Region::LocalList,
            opts: LayoutOptions::default(),
            size: Size::new(80, 24),
            status: None,
        };
        me.set_options(interface);
        me
    }

    /// Takes the layout options from the settings.
    pub(crate) fn set_options(&mut self, i: &InterfaceSettings) {
        self.opts = LayoutOptions {
            layout: i.layout,
            swap_panes: i.swap_panes,
            show_tree: i.show_tree,
            show_log: i.show_log,
            show_queue: i.show_queue,
            show_quickconnect: i.show_quickconnect,
            focus: self.focus,
        };
        self.fix_focus();
    }

    /// The terminal size changed.
    pub(crate) fn set_size(&mut self, size: Size) {
        self.size = size;
        self.fix_focus();
    }

    /// The layout options in effect (with the current focus).
    pub(crate) fn options(&self) -> LayoutOptions {
        LayoutOptions {
            focus: self.focus,
            ..self.opts
        }
    }

    /// The layout for the current size.
    pub(crate) fn layout(&self) -> ScreenLayout {
        compute_layout(
            Rect::new(0, 0, self.size.width, self.size.height),
            &self.options(),
        )
    }

    /// The focused region.
    pub(crate) fn focus(&self) -> Region {
        self.focus
    }

    /// The last focused file list.
    pub(crate) fn last_list(&self) -> Region {
        self.last_list
    }

    /// Focuses `region` (no visibility check; see [`Self::fix_focus`]).
    pub(crate) fn set_focus(&mut self, region: Region) {
        self.focus = region;
        if region.is_list() {
            self.last_list = region;
        }
        self.fix_focus();
    }

    /// Moves the focus to a visible region when the focused one disappeared: the last
    /// focused list, else `LocalList`.
    pub(crate) fn fix_focus(&mut self) {
        let order = focus_order(&self.layout());
        if order.is_empty() || order.contains(&self.focus) {
            return;
        }
        self.focus = if order.contains(&self.last_list) {
            self.last_list
        } else {
            Region::LocalList
        };
    }

    /// Next region in visual order (wraps).
    pub(crate) fn focus_next(&mut self) {
        let order = focus_order(&self.layout());
        let Some(first) = order.first().copied() else {
            return;
        };
        let next = match order.iter().position(|r| *r == self.focus) {
            Some(i) => order[(i + 1) % order.len()],
            None => first,
        };
        self.set_focus(next);
    }

    /// The region `region` can be focused in the current layout.
    pub(crate) fn is_focusable(&self, region: Region) -> bool {
        focus_order(&self.layout()).contains(&region)
    }

    fn tab(&mut self) -> Option<&mut TabView> {
        self.tabs.get_mut(self.active)
    }

    /// The component drawn in `region`.
    pub(crate) fn component_mut(&mut self, region: Region) -> Option<&mut dyn Component> {
        let c: &mut Box<dyn Component> = match region {
            Region::Quickconnect => &mut self.quickconnect,
            Region::Log => &mut self.log,
            Region::Queue => &mut self.queue,
            Region::LocalTree => &mut self.tab()?.local.tree,
            Region::LocalList => &mut self.tab()?.local.list,
            Region::RemoteTree => &mut self.tab()?.remote.tree,
            Region::RemoteList => &mut self.tab()?.remote.list,
            Region::TabBar | Region::StatusBar => return None,
        };
        Some(&mut **c)
    }

    /// Replaces the component of `region` (later tasks and tests).
    pub(crate) fn set_component(&mut self, region: Region, component: Box<dyn Component>) {
        let slot: Option<&mut Box<dyn Component>> = match region {
            Region::Quickconnect => Some(&mut self.quickconnect),
            Region::Log => Some(&mut self.log),
            Region::Queue => Some(&mut self.queue),
            Region::LocalTree => self.tabs.get_mut(self.active).map(|t| &mut t.local.tree),
            Region::LocalList => self.tabs.get_mut(self.active).map(|t| &mut t.local.list),
            Region::RemoteTree => self.tabs.get_mut(self.active).map(|t| &mut t.remote.tree),
            Region::RemoteList => self.tabs.get_mut(self.active).map(|t| &mut t.remote.list),
            Region::TabBar | Region::StatusBar => None,
        };
        if let Some(slot) = slot {
            *slot = component;
        }
    }

    /// The focused component.
    pub(crate) fn focused_mut(&mut self) -> Option<&mut dyn Component> {
        self.component_mut(self.focus)
    }

    /// Every component (all tabs).
    pub(crate) fn components_mut(&mut self) -> Vec<&mut dyn Component> {
        let mut v: Vec<&mut dyn Component> =
            vec![&mut *self.quickconnect, &mut *self.log, &mut *self.queue];
        for t in &mut self.tabs {
            v.push(&mut *t.local.tree);
            v.push(&mut *t.local.list);
            v.push(&mut *t.remote.tree);
            v.push(&mut *t.remote.list);
        }
        v
    }

    /// Forwards a core event to every component; returns their actions.
    pub(crate) fn on_core_event(&mut self, ev: &CoreEvent) -> color_eyre::Result<Vec<Action>> {
        let mut out = Vec::new();
        for c in self.components_mut() {
            if let Some(a) = c.on_core_event(ev)? {
                out.push(a);
            }
        }
        Ok(out)
    }

    /// Regions whose component reports [`Component::is_busy`].
    pub(crate) fn busy_regions(&mut self) -> Vec<Region> {
        layout::Region::FOCUSABLE
            .into_iter()
            .filter(|r| self.component_mut(*r).is_some_and(|c| c.is_busy()))
            .collect()
    }

    /// Reasons to confirm before quitting.
    pub(crate) fn quit_blockers(&mut self) -> Vec<String> {
        self.components_mut()
            .into_iter()
            .filter_map(|c| c.quit_blocker())
            .collect()
    }

    /// Shows a status message.
    pub(crate) fn set_status(&mut self, text: String, error: bool, now: Instant) {
        self.status = Some(StatusMessage {
            text,
            error,
            at: now,
        });
    }

    /// The current status message.
    pub(crate) fn status(&self) -> Option<&StatusMessage> {
        self.status.as_ref()
    }

    /// Drops an expired status message; true if one was dropped.
    pub(crate) fn expire_status(&mut self, now: Instant) -> bool {
        if self
            .status
            .as_ref()
            .is_some_and(|m| now.duration_since(m.at) >= STATUS_MESSAGE_TTL)
        {
            self.status = None;
            return true;
        }
        false
    }

    /// Draws the screen. `spinner(region)` gives the region's spinner frame.
    pub(crate) fn draw(
        &mut self,
        frame: &mut Frame,
        theme: &Theme,
        symbols: &Symbols,
        now: Instant,
        info: &StatusInfo,
        spinner: &dyn Fn(Region) -> Option<&'static str>,
    ) -> Vec<Action> {
        let area = frame.area();
        self.size = Size::new(area.width, area.height);
        let layout = self.layout();
        let mut errors = Vec::new();
        let areas = match &layout {
            ScreenLayout::TooSmall { width, height } => {
                let x = if symbols.unicode { "×" } else { "x" };
                let text = format!(
                    "Terminal too small: {width}{x}{height} (need {}{x}{})",
                    layout::MIN_WIDTH,
                    layout::MIN_HEIGHT
                );
                // Wrapped when narrower than the message.
                let rows = u16::try_from(
                    crate::ui::text::width(&text).div_ceil(usize::from(area.width.max(1))),
                )
                .unwrap_or(1)
                .min(area.height);
                frame.render_widget(
                    Paragraph::new(text)
                        .alignment(Alignment::Center)
                        .wrap(Wrap { trim: true }),
                    Rect {
                        y: area.y + (area.height - rows) / 2,
                        height: rows + u16::from(rows < area.height),
                        ..area
                    },
                );
                return errors;
            }
            ScreenLayout::Regions { areas, .. } => areas.clone(),
        };
        for (region, rect) in &areas {
            match region {
                Region::TabBar => self.draw_tab_bar(frame, *rect, theme),
                Region::StatusBar => {
                    self.draw_status_bar(frame, *rect, theme, symbols, info, layout.is_compact());
                }
                r => {
                    let cx = DrawCx {
                        theme,
                        symbols,
                        focused: *r == self.focus,
                        now,
                        spinner: spinner(*r),
                    };
                    if let Some(c) = self.component_mut(*r)
                        && let Err(e) = c.draw(frame, *rect, &cx)
                    {
                        errors.push(Action::Error(format!("Failed to draw: {e}")));
                    }
                }
            }
        }
        errors
    }

    fn draw_tab_bar(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let mut spans = Vec::new();
        for (i, t) in self.tabs.iter().enumerate() {
            let style = if i == self.active {
                theme.style("title_focused")
            } else {
                theme.style("title")
            };
            spans.push(Span::styled(format!(" {} {} ", i + 1, t.title), style));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn draw_status_bar(
        &self,
        frame: &mut Frame,
        area: Rect,
        theme: &Theme,
        symbols: &Symbols,
        info: &StatusInfo,
        compact: bool,
    ) {
        let bar = theme.style("status_bar");
        let sep = format!(" {} ", symbols.separator);
        let mut spans = vec![Span::styled(
            format!(" {}", info.mode),
            theme.style("status_mode"),
        )];
        if let Some(p) = &info.pending {
            // The keys of a pending sequence come first so they always fit.
            spans.push(Span::raw(sep.clone()));
            spans.push(Span::styled(
                format!("{} {}", crate::ui::text::sanitize(p), symbols.ellipsis),
                theme.style("help_key"),
            ));
        }
        if compact && info.pending.is_none() {
            spans.push(Span::raw(sep.clone()));
            spans.push(Span::raw(
                "compact: Tab = other side, Shift-Tab = log/queue",
            ));
        }
        if let Some(m) = &self.status {
            spans.push(Span::raw(sep));
            let style = theme.style(if m.error {
                "status_error"
            } else {
                "status_message"
            });
            spans.extend(sanitize_spans(&m.text, style, theme.style("text.escape")));
        }
        let right = "F1 help  F10 quit ";
        let used: usize = spans.iter().map(|s| width(&s.content)).sum();
        let total = usize::from(area.width);
        if used + width(right) < total {
            spans.push(Span::raw(" ".repeat(total - used - width(right))));
            spans.push(Span::raw(right));
        }
        let line: String = spans.iter().map(|s| s.content.as_ref()).collect();
        let fits = width(&line) <= total;
        let line = if fits {
            Line::from(spans)
        } else {
            // Too long: cut the plain text (escapes were already made safe).
            Line::from(truncate_to_width(&line, total, symbols.ellipsis).into_owned())
        };
        frame.render_widget(Paragraph::new(line).style(bar), area);
    }
}
