//! The main screen: quickconnect bar, tab bar, message log, the local and remote sides
//! (tree + file list) of each tab, the queue and the status bar, laid out by
//! [`layout::compute_layout`]. Until their tasks land, regions are [`Placeholder`]s.

pub(crate) mod layout;

use courier_ftp_core::{events::CoreEvent, settings::InterfaceSettings};
use ratatui::{
    Frame,
    layout::{Alignment, Rect, Size},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};
use tokio::time::Instant;

use self::layout::{LayoutOptions, Region, ScreenLayout, compute_layout, focus_order};
use super::{
    Component, DrawCx,
    placeholder::Placeholder,
    status_bar::{self, MessageLevel, StatusBar, StatusInfo, TransientMessage},
};
use crate::{
    action::Action,
    tabs::TabId,
    ui::{symbols::Symbols, theme::Theme},
};

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
    status_bar: StatusBar,
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
            status_bar: StatusBar::default(),
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

    /// Shows a status message (`error`: Error level, else Info).
    pub(crate) fn set_status(&mut self, text: String, error: bool, now: Instant) {
        let level = if error {
            MessageLevel::Error
        } else {
            MessageLevel::Info
        };
        self.status_bar.show(&text, level, now);
    }

    /// The status bar (transient message).
    pub(crate) fn status_bar_mut(&mut self) -> &mut StatusBar {
        &mut self.status_bar
    }

    /// The current status message.
    pub(crate) fn status(&self) -> Option<&TransientMessage> {
        self.status_bar.message()
    }

    /// Draws the screen. `spinner(region)` gives the region's spinner frame.
    pub(crate) fn draw(
        &mut self,
        frame: &mut Frame,
        theme: &Theme,
        symbols: &Symbols,
        now: Instant,
        info: &StatusInfo<'_>,
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
                    let info = StatusInfo {
                        message: self.status_bar.message(),
                        ..info.clone()
                    };
                    status_bar::render(frame, *rect, &info, symbols, theme);
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
}
