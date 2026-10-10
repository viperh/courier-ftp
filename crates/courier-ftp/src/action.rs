use serde::{Deserialize, Serialize};
use strum::Display;

use crate::{components::main_screen::layout::Region, runtime::TaskId};

/// Messages between the event loop, [`App`](crate::app::App) and components.
///
/// Unit variants that are not `#[serde(skip)]` are **bindable**: they can appear in
/// `keybindings` (T51 adds the rest of the list). No `PartialEq`: later variants carry
/// `Arc<Error>` payloads (T53, T62); tests compare with `matches!`.
#[derive(Debug, Clone, Display, Serialize, Deserialize)]
pub(crate) enum Action {
    // ---- internal (never bindable) ----
    /// Timer tick (4 Hz by default) for component timers.
    #[serde(skip)]
    Tick,
    /// Frame tick: draws when something changed.
    #[serde(skip)]
    Render,
    /// The terminal was resized.
    #[serde(skip)]
    Resize(u16, u16),
    /// Back from suspend.
    #[serde(skip)]
    Resume,
    /// Clear the terminal before the next frame.
    #[serde(skip)]
    ClearScreen,
    /// An error to log and show.
    #[serde(skip)]
    Error(String),
    /// A transient status-line message (3 s).
    #[serde(skip)]
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "sent by later components (T53, T62) and tests")
    )]
    StatusMessage(String),
    /// Focus a region.
    #[serde(skip)]
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "sent by later components (T54, T58) and tests")
    )]
    FocusRegion(Region),
    /// A runner task finished (after its output action).
    #[serde(skip)]
    TaskFinished(TaskId),
    /// The debounced settings save finished.
    #[serde(skip)]
    SettingsSaved(Result<(), String>),
    /// Quit despite blockers (from the confirm modal).
    #[serde(skip)]
    QuitConfirmed,

    // ---- bindable ----
    /// Show the help overlay.
    Help,
    /// Quit (asks first when something would be lost).
    Quit,
    /// Suspend to the shell (Unix).
    Suspend,
    /// Clear and redraw the screen.
    Redraw,
    /// Cancel the focused region's running work.
    Cancel,
    /// Switch between the local and the remote file list.
    FocusOtherSide,
    /// Next region in visual order.
    FocusNextRegion,
    /// Focus the message log.
    FocusLog,
    /// Focus the queue.
    FocusQueue,
    /// Focus the last focused file list.
    FocusFiles,
    /// Focus the quickconnect bar.
    FocusRegion1,
    /// Focus the local tree.
    FocusRegion2,
    /// Focus the local list.
    FocusRegion3,
    /// Focus the remote tree.
    FocusRegion4,
    /// Focus the remote list.
    FocusRegion5,
    /// Focus the message log.
    FocusRegion6,
    /// Focus the queue.
    FocusRegion7,
    /// Show or hide the message log.
    ToggleLog,
    /// Show or hide the queue.
    ToggleQueuePane,
    /// Show or hide the directory trees.
    ToggleTree,
    /// Show or hide the quickconnect bar.
    ToggleQuickconnect,
    /// Swap the local and remote sides.
    SwapPanes,
    /// Classic layout.
    LayoutClassic,
    /// Explorer layout.
    LayoutExplorer,
    /// Widescreen layout.
    LayoutWidescreen,
}

impl Action {
    /// The action named `name` if it is bindable.
    pub(crate) fn bindable_from_name(name: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(name.to_owned())).ok()
    }

    /// Whether this action can appear in `keybindings`.
    pub(crate) fn is_bindable(&self) -> bool {
        Self::bindable_from_name(&self.to_string()).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_unit_public_variants_are_bindable() {
        assert!(matches!(
            Action::bindable_from_name("Quit"),
            Some(Action::Quit)
        ));
        assert!(matches!(
            Action::bindable_from_name("ToggleLog"),
            Some(Action::ToggleLog)
        ));
        for internal in ["Tick", "Render", "Resize", "Error", "QuitConfirmed", "Nope"] {
            assert!(Action::bindable_from_name(internal).is_none(), "{internal}");
        }
        assert!(!Action::Tick.is_bindable());
        assert!(Action::Help.is_bindable());
    }
}
