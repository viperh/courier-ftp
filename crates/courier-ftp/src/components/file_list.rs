//! The file list pane (T53): a sortable, multi-select list with an editable address
//! bar, used for both the local and the remote side. The pure state and reducer live
//! in [`state`], the filter/sort pipeline in [`view`], drawing in [`render`]; this
//! module is the [`Component`] that turns keymap actions into [`PaneCommand`]s and
//! sends the reducer's [`PaneRequest`]s to the app as [`Action::Pane`].

pub(crate) mod column_menu;
pub(crate) mod columns;
pub(crate) mod format;
pub(crate) mod natural;
pub(crate) mod render;
pub(crate) mod service;
pub(crate) mod state;
pub(crate) mod view;

#[cfg(test)]
mod snapshot_tests;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use courier_ftp_core::{
    events::CoreEvent,
    filters::FilterEngine,
    settings::{Column, Settings},
};
use crossterm::event::KeyCode;
use ratatui::{Frame, layout::Rect};
use tokio::{sync::mpsc::UnboundedSender, time::Instant};

pub(crate) use self::state::{
    FileListState, FileOp, PaneCommand, PaneCtx, PaneDir, PaneId, PaneInput, PaneRequest,
    PaneStatus, Side,
};
use self::{
    format::DateFormats,
    render::{RenderCx, RowFormat},
};
use super::{
    Component, DrawCx, KeyOutcome,
    widgets::{LocalPathCompleter, PathCompleter, PathInput, Widget, WidgetOutcome},
};
use crate::{
    action::Action,
    app::Mode,
    config::Config,
    keymap::chord::{KeyChord, Mods},
};

/// Every bindable action the pane handles (T51 `handled_actions`).
const HANDLED: &[Action] = &[
    Action::CursorDown,
    Action::CursorUp,
    Action::HalfPageDown,
    Action::HalfPageUp,
    Action::PageDown,
    Action::PageUp,
    Action::Top,
    Action::Bottom,
    Action::Open,
    Action::Parent,
    Action::Back,
    Action::Forward,
    Action::EditAddress,
    Action::MirrorOtherPane,
    Action::Escape,
    Action::ToggleMark,
    Action::VisualMode,
    Action::MarkAll,
    Action::InvertMarks,
    Action::MarkPattern,
    Action::UnmarkPattern,
    Action::QuickFilter,
    Action::SortByName,
    Action::SortBySize,
    Action::SortByType,
    Action::SortByModified,
    Action::SortByPermissions,
    Action::SortByOwner,
    Action::ToggleHidden,
    Action::ColumnMenu,
    Action::Transfer,
    Action::QueueOnly,
    Action::Move,
    Action::Rename,
    Action::Mkdir,
    Action::MkdirEnter,
    Action::Delete,
    Action::View,
    Action::Edit,
    Action::Chmod,
    Action::CopyUrl,
    Action::CopyUrlOptions,
    Action::CustomCommand,
    Action::NewFile,
    Action::Refresh,
    Action::FilterAccept,
    Action::FilterClear,
    Action::InputSubmit,
    Action::InputCancel,
];

/// The keymap action → reducer command table.
fn command_for(action: &Action) -> Option<PaneCommand> {
    use PaneCommand as C;
    Some(match action {
        Action::CursorDown => C::CursorDown,
        Action::CursorUp => C::CursorUp,
        Action::HalfPageDown => C::HalfPageDown,
        Action::HalfPageUp => C::HalfPageUp,
        Action::PageDown => C::PageDown,
        Action::PageUp => C::PageUp,
        Action::Top => C::Top,
        Action::Bottom => C::Bottom,
        Action::Open => C::Open,
        Action::Parent => C::Parent,
        Action::Back => C::Back,
        Action::Forward => C::Forward,
        Action::EditAddress => C::EditAddress,
        Action::MirrorOtherPane => C::MirrorOtherPane,
        Action::Escape => C::Escape,
        Action::ToggleMark => C::ToggleMark,
        Action::VisualMode => C::VisualMode,
        Action::MarkAll => C::MarkAll,
        Action::InvertMarks => C::InvertMarks,
        Action::MarkPattern => C::MarkPattern,
        Action::UnmarkPattern => C::UnmarkPattern,
        Action::QuickFilter => C::QuickFilter,
        Action::FilterAccept => C::FilterAccept,
        Action::FilterClear => C::FilterClear,
        Action::SortByName => C::SortBy(Column::Name),
        Action::SortBySize => C::SortBy(Column::Size),
        Action::SortByType => C::SortBy(Column::Type),
        Action::SortByModified => C::SortBy(Column::Modified),
        Action::SortByPermissions => C::SortBy(Column::Permissions),
        Action::SortByOwner => C::SortBy(Column::OwnerGroup),
        Action::ToggleHidden => C::ToggleHidden,
        Action::ColumnMenu => C::ColumnMenu,
        Action::Cancel => C::Cancel,
        Action::Transfer => C::FileOp(FileOp::Transfer),
        Action::QueueOnly => C::FileOp(FileOp::QueueOnly),
        Action::Move => C::FileOp(FileOp::Move),
        Action::Rename => C::FileOp(FileOp::Rename),
        Action::Mkdir => C::FileOp(FileOp::Mkdir),
        Action::MkdirEnter => C::FileOp(FileOp::MkdirEnter),
        Action::Delete => C::FileOp(FileOp::Delete),
        Action::View => C::FileOp(FileOp::View),
        Action::Edit => C::FileOp(FileOp::Edit),
        Action::Chmod => C::FileOp(FileOp::Chmod),
        Action::CopyUrl => C::FileOp(FileOp::CopyUrl),
        Action::CopyUrlOptions => C::FileOp(FileOp::CopyUrlOptions),
        Action::CustomCommand => C::FileOp(FileOp::CustomCommand),
        Action::NewFile => C::FileOp(FileOp::NewFile),
        Action::Refresh => C::FileOp(FileOp::Refresh),
        _ => return None,
    })
}

/// The bindable action of a file operation (its description is the "not available
/// yet" text until T62/T63 land).
pub(crate) fn file_op_action(op: FileOp) -> Action {
    match op {
        FileOp::Transfer => Action::Transfer,
        FileOp::QueueOnly => Action::QueueOnly,
        FileOp::Move => Action::Move,
        FileOp::Rename => Action::Rename,
        FileOp::Mkdir => Action::Mkdir,
        FileOp::MkdirEnter => Action::MkdirEnter,
        FileOp::NewFile => Action::NewFile,
        FileOp::Delete => Action::Delete,
        FileOp::View => Action::View,
        FileOp::Edit => Action::Edit,
        FileOp::Chmod => Action::Chmod,
        FileOp::CopyUrl => Action::CopyUrl,
        FileOp::CopyUrlOptions => Action::CopyUrlOptions,
        FileOp::CustomCommand => Action::CustomCommand,
        FileOp::Refresh => Action::Refresh,
    }
}

/// The pane component.
pub(crate) struct FileListPane {
    state: FileListState,
    settings: Arc<Settings>,
    filters: Arc<FilterEngine>,
    format: RowFormat,
    action_tx: Option<UnboundedSender<Action>>,
    address: Option<PathInput>,
    hint: String,
    /// Requests sent (tests read them when no action channel is registered).
    #[cfg(test)]
    pub(crate) sent: Vec<PaneRequest>,
}

impl std::fmt::Debug for FileListPane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileListPane")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

fn row_format(settings: &Settings) -> RowFormat {
    let i = &settings.interface;
    RowFormat {
        size: i.size_format,
        thousands: i.thousands_separator,
        dates: DateFormats::from_settings(i, time::OffsetDateTime::now_utc()),
    }
}

fn filters_for(settings: &Settings, side: Side) -> Arc<FilterEngine> {
    let (engine, _errors) = FilterEngine::new(
        &settings.filters,
        side.filter_side(),
        format::local_offset(),
    );
    Arc::new(engine)
}

impl FileListPane {
    /// A pane for `id` with `settings`.
    pub(crate) fn new(id: PaneId, settings: Arc<Settings>) -> Self {
        Self {
            state: FileListState::new(id, &settings),
            filters: filters_for(&settings, id.side),
            format: row_format(&settings),
            settings,
            action_tx: None,
            address: None,
            hint: "Ctrl-s Site Manager · Ctrl-k Quickconnect".to_owned(),
            #[cfg(test)]
            sent: Vec::new(),
        }
    }

    /// Applies an input and sends the resulting requests.
    pub(crate) fn input(&mut self, input: PaneInput) {
        if let PaneInput::FiltersChanged(f) = &input {
            self.filters = Arc::clone(f);
        }
        let ctx = PaneCtx {
            settings: &self.settings,
            filters: &self.filters,
            now: Instant::now(),
        };
        let requests = self.state.reduce(input, &ctx);
        if self.state.address_editing && self.address.is_none() {
            self.open_address();
        } else if !self.state.address_editing {
            self.address = None;
        }
        for r in requests {
            self.send(r);
        }
    }

    fn send(&mut self, r: PaneRequest) {
        if let Some(tx) = &self.action_tx {
            let _ = tx.send(Action::Pane(r));
        } else {
            #[cfg(test)]
            self.sent.push(r);
        }
    }

    fn open_address(&mut self) {
        let Some(tx) = self.action_tx.clone() else {
            // Without the action channel (unit tests) the editor still works.
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
            self.address = Some(self.new_address(tx));
            return;
        };
        self.address = Some(self.new_address(tx));
    }

    fn new_address(&self, tx: UnboundedSender<Action>) -> PathInput {
        let initial = self
            .state
            .dir
            .as_ref()
            .map(PaneDir::display)
            .unwrap_or_default();
        let completer: Option<Arc<dyn PathCompleter>> = match self.state.id.side {
            Side::Local => Some(Arc::new(LocalPathCompleter)),
            Side::Remote => None,
        };
        PathInput::new(&initial, completer, tx)
    }

    /// New settings (from the app after a change).
    pub(crate) fn set_settings(&mut self, settings: Arc<Settings>) {
        if settings.filters != self.settings.filters {
            self.filters = filters_for(&settings, self.state.id.side);
        }
        self.format = row_format(&settings);
        self.settings = settings;
        self.input(PaneInput::SettingsChanged);
    }
}

/// `ctrl-s` → `Ctrl-s`.
fn pretty(keys: &str) -> String {
    keys.split(' ')
        .map(|c| {
            c.replace("ctrl-", "Ctrl-")
                .replace("alt-", "Alt-")
                .replace("shift-", "Shift-")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl Component for FileListPane {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> color_eyre::Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn register_config_handler(&mut self, config: Arc<Config>) -> color_eyre::Result<()> {
        let (resolver, _) = crate::keymap::resolver::KeyResolver::from_config(&config);
        let rows = resolver.keymap().bindings_for(&[Mode::Normal]);
        let key = |name: &str, fallback: &str| {
            rows.iter()
                .find(|r| r.action.to_string() == name)
                .map_or_else(
                    || fallback.to_owned(),
                    |r| pretty(&crate::keymap::chord::display_sequence(&r.keys)),
                )
        };
        self.hint = format!(
            "{} Site Manager · {} Quickconnect",
            key("SiteManager", "ctrl-s"),
            key("FocusQuickconnect", "ctrl-k")
        );
        self.set_settings(Arc::new(config.settings.clone()));
        Ok(())
    }

    fn key_mode(&self) -> Mode {
        if self.address.is_some() {
            Mode::Input
        } else if self.state.quick_filter.as_ref().is_some_and(|q| q.editing) {
            Mode::Filter
        } else {
            Mode::FileList
        }
    }

    fn handle_key(&mut self, key: KeyChord) -> color_eyre::Result<KeyOutcome> {
        if let Some(input) = &mut self.address {
            return Ok(match input.handle_key(key) {
                WidgetOutcome::Ignored => KeyOutcome::Ignored,
                _ => KeyOutcome::Consumed(None),
            });
        }
        if self.state.quick_filter.as_ref().is_some_and(|q| q.editing) {
            if key.code == KeyCode::Backspace && !key.mods.contains(Mods::CTRL) {
                self.input(PaneInput::Key(PaneCommand::FilterBackspace));
                return Ok(KeyOutcome::Consumed(None));
            }
            if let Some(c) = key.printable() {
                self.input(PaneInput::Key(PaneCommand::FilterInsert(c)));
                return Ok(KeyOutcome::Consumed(None));
            }
        }
        Ok(KeyOutcome::Ignored)
    }

    fn handle_paste(&mut self, text: &str) -> color_eyre::Result<KeyOutcome> {
        if let Some(input) = &mut self.address {
            input.handle_paste(text);
            return Ok(KeyOutcome::Consumed(None));
        }
        if self.state.quick_filter.as_ref().is_some_and(|q| q.editing) {
            for c in text.chars().filter(|c| !c.is_control()) {
                self.input(PaneInput::Key(PaneCommand::FilterInsert(c)));
            }
            return Ok(KeyOutcome::Consumed(None));
        }
        Ok(KeyOutcome::Ignored)
    }

    fn handled_actions(&self) -> &'static [Action] {
        HANDLED
    }

    fn update(&mut self, action: &Action) -> color_eyre::Result<Option<Action>> {
        match action {
            Action::Tick => {
                let mut changed = self.state.expire_notice(Instant::now());
                if let Some(a) = &mut self.address {
                    changed |= a.poll();
                }
                return Ok(changed.then_some(Action::Wake));
            }
            Action::Wake => {
                if let Some(a) = &mut self.address {
                    a.poll();
                }
            }
            Action::PaneInput(id, input) if *id == self.state.id => {
                self.input(input.clone());
            }
            Action::PaneSettings(id, settings) if *id == self.state.id => {
                self.set_settings(Arc::clone(settings));
            }
            Action::InputSubmit => {
                if let Some(a) = self.address.take() {
                    let text = a.value().to_owned();
                    self.input(PaneInput::Key(PaneCommand::AddressSubmit(text)));
                }
            }
            Action::InputCancel => {
                self.address = None;
                self.input(PaneInput::Key(PaneCommand::AddressCancel));
            }
            other => {
                if let Some(cmd) = command_for(other) {
                    self.input(PaneInput::Key(cmd));
                }
            }
        }
        Ok(None)
    }

    fn on_core_event(&mut self, event: &CoreEvent) -> color_eyre::Result<Option<Action>> {
        if let CoreEvent::ListingUpdated { server, dir } = event {
            let shown = self.state.dir.as_ref().and_then(|d| d.backend_path().ok());
            let same_server = match (&self.state.id.side, server) {
                (Side::Local, None) => true,
                (Side::Remote, Some(s)) => self.state.server.as_ref() == Some(s),
                _ => false,
            };
            if same_server && shown.as_ref() == Some(dir) && self.state.status == PaneStatus::Ready
            {
                // Re-read (the cache answers; local panes relist).
                self.input(PaneInput::Reload);
            }
        }
        Ok(None)
    }

    fn is_busy(&self) -> bool {
        matches!(self.state.status, PaneStatus::Loading { .. })
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) -> color_eyre::Result<()> {
        let body_rows = area.height.saturating_sub(5);
        if body_rows != self.state.body_rows() {
            let ctx = PaneCtx {
                settings: &self.settings,
                filters: &self.filters,
                now: cx.now,
            };
            self.state.reduce(PaneInput::Resize { body_rows }, &ctx);
        }
        let rcx = RenderCx {
            draw: cx,
            format: &self.format,
            address: self.address.as_ref(),
            not_connected_hint: &self.hint,
        };
        render::draw(&self.state, frame, area, &rcx);
        Ok(())
    }
}
