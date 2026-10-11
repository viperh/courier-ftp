//! The terminal user interface (T50): the main screen, its layout, focus,
//! theme and modal stack.

pub(crate) mod bookmarks;
mod compare;
pub(crate) mod dialog;
mod dir_tree;
mod file_exists;
mod file_list;
mod filters;
mod focus;
mod layout;
mod log;
mod modal;
mod panes;
mod queue;
mod quickconnect;
mod screen;
pub(crate) mod site_manager;
mod status;
#[cfg(feature = "sync")]
pub(crate) mod sync;
mod text_viewer;
mod theme;
mod trust;
mod vault;

pub(crate) use courier_ftp_core::filters::Side;
#[cfg(test)]
pub(crate) use focus::Region;
pub(crate) use modal::Modal;
pub(crate) use quickconnect::HistoryItem;
#[cfg(test)]
pub(crate) mod file_list_effect {
    pub(crate) use super::file_list::Effect;
}
pub(crate) use screen::{KeyOutcome, MainScreen};
#[cfg(feature = "sync")]
pub(crate) use status::SyncLevel;
pub(crate) use text_viewer::TextViewer;
pub(crate) use theme::Theme;
#[cfg(test)]
pub(crate) use vault::VaultPage;
pub(crate) use vault::{VaultFacts, VaultRequest, VaultView};

#[cfg(test)]
mod tests;

/// Whether the UI draws Unicode symbols (`interface.unicode_symbols`).
pub(crate) fn unicode_symbols(settings: &courier_ftp_core::settings::Settings) -> bool {
    status::unicode_enabled(settings.interface.unicode_symbols)
}
