//! [`MainScreen`]: the courier-ftp main window (T50).

use courier_ftp_core::{events::CoreEvent, settings::InterfaceSettings};
use crossterm::event::KeyEvent;
use ratatui::Frame;

use super::{
    Side,
    focus::Region,
    layout::{self, LayoutOptions, Regions, Visibility},
    modal::{HelpOverlay, Modal, ModalOutcome, PromptDialog},
    panes::{self, FilePane, LogPane},
    theme::Theme,
};
use crate::{action::Action, app::Mode, config::Config};

/// What the screen did with a key.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeyOutcome {
    /// Handled here (a modal or the focused region took it).
    Consumed,
    /// Not handled; look it up in the keymap of the current [`Mode`].
    NotHandled,
}

/// The main window: regions, focus, the modal stack.
pub(crate) struct MainScreen {
    config: Config,
    theme: Theme,
    opts: LayoutOptions,
    focus: Region,
    pub(crate) local: FilePane,
    pub(crate) remote: FilePane,
    log: LogPane,
    modals: Vec<Box<dyn Modal>>,
    tick: u64,
    /// The regions of the last frame, for focus checks.
    last: Regions,
}

impl MainScreen {
    pub(crate) fn new(config: Config, theme: Theme) -> Self {
        let ui: &InterfaceSettings = &config.settings.interface;
        let opts = LayoutOptions {
            layout: ui.layout,
            swap_panes: ui.swap_panes,
            visible: Visibility {
                quickconnect: true,
                log: ui.show_log,
                queue: ui.show_queue,
                tree: ui.show_tree,
            },
            compact_side: Side::Local,
        };
        Self {
            config,
            theme,
            opts,
            focus: Region::LocalList,
            local: FilePane::new(Side::Local),
            remote: FilePane::new(Side::Remote),
            log: LogPane::default(),
            modals: Vec::new(),
            tick: 0,
            last: Regions::default(),
        }
    }

    /// The current input mode, which selects the keymap.
    pub(crate) fn mode(&self) -> Mode {
        if !self.modals.is_empty() {
            Mode::Dialog
        } else if self.focus == Region::Quickconnect {
            Mode::Input
        } else {
            Mode::Normal
        }
    }

    #[cfg(test)]
    pub(crate) fn focus(&self) -> Region {
        self.focus
    }

    #[cfg(test)]
    pub(crate) fn has_modal(&self) -> bool {
        !self.modals.is_empty()
    }

    /// Route a key: the top modal first, then the focused region. Keys nobody
    /// takes go to the keymap.
    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> KeyOutcome {
        if let Some(top) = self.modals.last_mut() {
            if top.handle_key(key) == ModalOutcome::Close {
                self.modals.pop();
            }
            return KeyOutcome::Consumed;
        }
        // The focused regions take no keys of their own yet: the file list
        // (T53), log (T55), queue (T56) and quickconnect (T58) add them.
        KeyOutcome::NotHandled
    }

    /// Apply an action. May return a follow-up action.
    pub(crate) fn update(&mut self, action: &Action) -> Option<Action> {
        match action {
            Action::Tick => self.tick = self.tick.wrapping_add(1),
            Action::Help => self.open_help(),
            Action::CloseDialog => {
                self.modals.pop();
            }
            Action::FocusNext | Action::FocusPrev => {
                self.focus = self.focus.toggled();
                if let Some(side) = self.focus.side() {
                    self.opts.compact_side = side;
                }
            }
            Action::FocusLocal => self.set_focus(Region::LocalList),
            Action::FocusRemote => self.set_focus(Region::RemoteList),
            Action::FocusLog => self.set_focus(Region::Log),
            Action::FocusQueue => self.set_focus(Region::Queue),
            Action::FocusQuickconnect => self.set_focus(Region::Quickconnect),
            Action::ToggleLog => self.opts.visible.log = !self.opts.visible.log,
            Action::ToggleQueue => self.opts.visible.queue = !self.opts.visible.queue,
            Action::ToggleTree => self.opts.visible.tree = !self.opts.visible.tree,
            Action::ToggleQuickconnect => {
                self.opts.visible.quickconnect = !self.opts.visible.quickconnect;
            }
            Action::ListingLoaded { side, result } => {
                let pane = self.pane_mut(*side);
                pane.busy = false;
                match result {
                    Ok(listing) => {
                        pane.dir = Some(listing.dir.clone());
                        pane.entries = listing.entries.clone();
                        pane.error = None;
                    }
                    Err(e) => pane.error = Some(e.clone()),
                }
            }
            _ => {}
        }
        None
    }

    fn set_focus(&mut self, region: Region) {
        self.focus = region;
        if let Some(side) = region.side() {
            self.opts.compact_side = side;
        }
        // Focusing a hidden log/queue/quickconnect shows it.
        match region {
            Region::Log => self.opts.visible.log = true,
            Region::Queue => self.opts.visible.queue = true,
            Region::Quickconnect => self.opts.visible.quickconnect = true,
            _ => {}
        }
    }

    pub(crate) fn pane_mut(&mut self, side: Side) -> &mut FilePane {
        match side {
            Side::Local => &mut self.local,
            Side::Remote => &mut self.remote,
        }
    }

    /// Something from the core (T04).
    pub(crate) fn handle_core(&mut self, event: CoreEvent) {
        match event {
            CoreEvent::Log(msg) => self.log.push(msg),
            CoreEvent::Prompt(request) => self.modals.push(Box::new(PromptDialog::new(request))),
            // Connection, listing, transfer and queue events get their UI in
            // T53/T56/T57/T61.
            _ => {}
        }
    }

    fn open_help(&mut self) {
        let mode = self.mode();
        let bindings = self
            .config
            .keybindings
            .0
            .get(&mode)
            .map(|map| {
                map.iter()
                    .map(|(keys, action)| {
                        let keys: Vec<String> = keys
                            .iter()
                            .map(crate::config::key_event_to_string)
                            .collect();
                        (keys.join(" "), action.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.modals
            .push(Box::new(HelpOverlay::new(&format!("{mode:?}"), bindings)));
    }

    /// Draw everything.
    pub(crate) fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let r = layout::compute(area, &self.opts);
        if !self.focus.visible_in(&r) {
            self.focus = Region::list(self.opts.compact_side);
            if !self.focus.visible_in(&r) {
                self.focus = Region::LocalList;
            }
        }
        self.last = r;
        let theme = &self.theme;
        let f = self.focus;
        if let Some(a) = r.quickconnect {
            panes::draw_quickconnect(frame, a, f == Region::Quickconnect, theme);
        }
        if let Some(a) = r.tabs {
            panes::draw_tabs(frame, a, theme);
        }
        if let Some(a) = r.log {
            self.log.draw(frame, a, f == Region::Log, theme);
        }
        for (tree, region) in [
            (r.local_tree, Region::LocalTree),
            (r.remote_tree, Region::RemoteTree),
        ] {
            if let Some(a) = tree {
                let focused = f == region;
                frame.render_widget(
                    ratatui::widgets::Paragraph::new("(directory tree: T54)")
                        .style(theme.dim)
                        .block(panes::block(" Tree ", focused, theme)),
                    a,
                );
            }
        }
        if let Some(a) = r.local_list {
            self.local
                .draw(frame, a, f == Region::LocalList, self.tick, theme);
        }
        if let Some(a) = r.remote_list {
            self.remote
                .draw(frame, a, f == Region::RemoteList, self.tick, theme);
        }
        if let Some(a) = r.queue {
            panes::draw_queue(frame, a, f == Region::Queue, theme);
        }
        if let Some(a) = r.status {
            panes::draw_status(frame, a, theme);
        }
        if let Some(a) = r.hint {
            panes::draw_hint(frame, a, theme);
        }
        for modal in &mut self.modals {
            modal.draw(frame, area, theme);
        }
    }
}
