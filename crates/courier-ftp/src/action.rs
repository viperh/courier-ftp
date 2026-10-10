use courier_ftp_core::backend::Listing;
use serde::{Deserialize, Serialize};
use strum::Display;

use crate::ui::Side;

/// Messages passed between the event loop, [`App`](crate::app::App) and the
/// [`MainScreen`](crate::ui::MainScreen).
///
/// Unit variants can be bound to keys in the config (by name, e.g.
/// `"<F1>": "Help"`). Variants marked `#[serde(skip)]` carry results of
/// background tasks and are never bound to keys. T51 adds the full keymap's
/// actions.
#[derive(Debug, Clone, PartialEq, Eq, Display, Serialize, Deserialize)]
pub(crate) enum Action {
    Tick,
    Render,
    Resize(u16, u16),
    Suspend,
    Resume,
    Quit,
    ClearScreen,
    Error(String),
    /// Show the help overlay with the keybindings of the current mode.
    Help,
    /// Close the topmost dialog.
    CloseDialog,
    /// `Tab`: switch between the two file lists (Midnight Commander style).
    FocusNext,
    /// `Shift-Tab`: the same, backwards.
    FocusPrev,
    FocusLocal,
    FocusRemote,
    FocusLog,
    FocusQueue,
    FocusQuickconnect,
    ToggleLog,
    ToggleQueue,
    ToggleTree,
    ToggleQuickconnect,
    /// Re-list the directories shown in both panes.
    Refresh,
    /// A directory listing finished in the background.
    #[serde(skip)]
    ListingLoaded {
        side: Side,
        result: Result<Listing, String>,
    },
}
