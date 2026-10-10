//! The terminal user interface (T50): the main screen, its layout, focus,
//! theme and modal stack.

mod focus;
mod layout;
mod modal;
mod panes;
mod screen;
mod theme;

pub(crate) use courier_ftp_core::filters::Side;
#[cfg(test)]
pub(crate) use focus::Region;
pub(crate) use screen::{KeyOutcome, MainScreen};
pub(crate) use theme::Theme;

#[cfg(test)]
mod tests;
