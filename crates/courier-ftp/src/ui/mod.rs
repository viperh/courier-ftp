//! The terminal user interface (T50): the main screen, its layout, focus,
//! theme and modal stack.

mod compare;
pub(crate) mod dialog;
mod dir_tree;
mod file_list;
mod focus;
mod layout;
mod log;
mod modal;
mod panes;
mod quickconnect;
mod screen;
mod status;
mod text_viewer;
mod theme;
mod trust;
mod vault;

pub(crate) use courier_ftp_core::filters::Side;
#[cfg(test)]
pub(crate) use focus::Region;
pub(crate) use modal::Modal;
pub(crate) use quickconnect::HistoryItem;
pub(crate) use screen::{KeyOutcome, MainScreen};
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
