//! The component trait every UI piece implements, and drawing helpers shared by them.

use std::sync::Arc;

use courier_ftp_core::events::CoreEvent;
use ratatui::{
    Frame,
    layout::{Rect, Size},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders},
};
use tokio::{sync::mpsc::UnboundedSender, time::Instant};

use crate::{
    action::Action,
    app::Mode,
    config::Config,
    keymap::chord::KeyChord,
    ui::{symbols::Symbols, theme::Theme},
};

pub(crate) mod help;
pub(crate) mod main_screen;
pub(crate) mod modal;
pub(crate) mod placeholder;
pub(crate) mod quit_confirm;
pub(crate) mod which_key;

/// What a component did with a raw key.
#[derive(Debug)]
pub(crate) enum KeyOutcome {
    /// Used; the optional action is dispatched.
    Consumed(Option<Action>),
    /// Not used; the keymap resolves it.
    Ignored,
}

/// Read-only context for drawing.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DrawCx<'a> {
    /// Resolved styles.
    pub theme: &'a Theme,
    /// Glyphs.
    pub symbols: &'a Symbols,
    /// The component has the focus.
    pub focused: bool,
    /// Now (tokio `Instant`, virtual in tests); spinners derive frames from it.
    #[expect(dead_code, reason = "read by the panes' own timers (T53, T55, T57)")]
    pub now: Instant,
    /// The spinner frame to show in the title while the component's owner has been
    /// busy for more than 150 ms.
    pub spinner: Option<&'static str>,
}

/// A visual and interactive element. Mouse handling is gone (D7).
pub(crate) trait Component {
    /// Gives the component the action channel.
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> color_eyre::Result<()> {
        let _ = tx;
        Ok(())
    }

    /// Gives the component the configuration.
    fn register_config_handler(&mut self, config: Arc<Config>) -> color_eyre::Result<()> {
        let _ = config;
        Ok(())
    }

    /// Called once with the terminal size.
    fn init(&mut self, area: Size) -> color_eyre::Result<()> {
        let _ = area;
        Ok(())
    }

    /// Key table this component wants while focused (e.g. `FileList`, or `Filter`
    /// while typing).
    fn key_mode(&self) -> Mode {
        Mode::Normal
    }

    /// Raw key before the keymap. Text widgets consume printable and editing keys here;
    /// everything else returns `Ignored`.
    fn handle_key(&mut self, key: KeyChord) -> color_eyre::Result<KeyOutcome> {
        let _ = key;
        Ok(KeyOutcome::Ignored)
    }

    /// Bracketed paste.
    fn handle_paste(&mut self, text: &str) -> color_eyre::Result<KeyOutcome> {
        let _ = text;
        Ok(KeyOutcome::Ignored)
    }

    /// Bindable actions this component implements. A bindable action that no component
    /// lists and the app does not handle itself shows "… is not available yet" (T51).
    fn handled_actions(&self) -> &'static [Action] {
        &[]
    }

    /// Actions (from the keymap or other components); most logic lives here.
    fn update(&mut self, action: &Action) -> color_eyre::Result<Option<Action>> {
        let _ = action;
        Ok(None)
    }

    /// An event from the core (T04).
    fn on_core_event(&mut self, event: &CoreEvent) -> color_eyre::Result<Option<Action>> {
        let _ = event;
        Ok(None)
    }

    /// True while this component waits for async work (drives the spinner).
    fn is_busy(&self) -> bool {
        false
    }

    /// Reason to confirm before quitting ("2 transfers are running"), if any.
    fn quit_blocker(&self) -> Option<String> {
        None
    }

    /// Draws into `area`.
    fn draw(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) -> color_eyre::Result<()>;
}

/// The bordered block of a region: the focused one gets the `border_focused` style,
/// the thick (or ASCII `#`) border and the focus marker before its title, so focus is
/// visible without colour.
pub(crate) fn region_block<'a>(title: &str, cx: &DrawCx) -> Block<'a> {
    let (border_style, title_style, set) = if cx.focused {
        (
            cx.theme.style("border_focused"),
            cx.theme.style("title_focused"),
            cx.symbols.border_focused,
        )
    } else {
        (
            cx.theme.style("border"),
            cx.theme.style("title"),
            cx.symbols.border,
        )
    };
    let mut spans = vec![if cx.focused {
        Span::styled(cx.symbols.focus_marker.to_owned(), border_style)
    } else {
        Span::styled(" ".to_owned(), border_style)
    }];
    spans.push(Span::styled(title.to_owned(), title_style));
    if let Some(frame) = cx.spinner {
        spans.push(Span::styled(format!(" {frame}"), title_style));
    }
    spans.push(Span::styled(" ".to_owned(), border_style));
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_set(set)
        .border_style(border_style)
        .title(Line::from(spans))
}
