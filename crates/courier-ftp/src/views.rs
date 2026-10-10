//! The vault screens (T60; sverb `views/{unlock,first_run,lock_overlay}.rs`, D13):
//! plain data, pure key handling and infallible rendering. The reducer
//! (`app/vault.rs`) owns the forms and turns their [`unlock::FormAction`]s into vault
//! effects; nothing here holds key material, only typed passwords in zeroizing
//! [`unlock::MaskedField`]s.

pub(crate) mod first_run;
pub(crate) mod forgot;
pub(crate) mod lock_overlay;
pub(crate) mod unlock;

#[cfg(test)]
mod snapshot_tests;
#[cfg(test)]
mod tests;

use std::borrow::Cow;

use ratatui::style::Style;

use crate::ui::{symbols::Symbols, theme::Theme};

/// Styles and glyphs of the vault screens.
#[derive(Clone, Copy)]
pub(crate) struct Look<'a> {
    /// Resolved styles (`vault.*` keys).
    pub theme: &'a Theme,
    /// Glyph set (Unicode or ASCII).
    pub symbols: &'a Symbols,
}

impl<'a> Look<'a> {
    /// A look for `theme` and `symbols`.
    pub(crate) fn new(theme: &'a Theme, symbols: &'a Symbols) -> Self {
        Self { theme, symbols }
    }

    /// The style of `vault.<key>`.
    pub(crate) fn style(&self, key: &str) -> Style {
        self.theme.style(&format!("vault.{key}"))
    }

    /// ASCII glyphs only.
    pub(crate) fn ascii(&self) -> bool {
        !self.symbols.unicode
    }

    /// `text` with the non-ASCII punctuation of the vault screens replaced in ASCII
    /// mode (`·`, `…`, `—`, `🔒`).
    pub(crate) fn text<'t>(&self, text: &'t str) -> Cow<'t, str> {
        if !self.ascii() || text.is_ascii() {
            return Cow::Borrowed(text);
        }
        let mut out = String::with_capacity(text.len());
        for c in text.chars() {
            match c {
                '·' | '—' | '–' => out.push('-'),
                '…' => out.push_str("..."),
                '🔒' => out.push_str("[locked]"),
                '→' => out.push_str("->"),
                c if c.is_ascii() => out.push(c),
                _ => out.push('?'),
            }
        }
        Cow::Owned(out)
    }

    /// The masked-character glyph (`•` / `*`).
    pub(crate) fn mask(&self) -> &'static str {
        if self.ascii() { "*" } else { "•" }
    }

    /// The text cursor of a focused field (`▏` / `_`).
    pub(crate) fn cursor(&self) -> &'static str {
        if self.ascii() { "_" } else { "▏" }
    }

    /// The lock glyph of titles (`🔒` / `[locked]`).
    pub(crate) fn lock(&self) -> &'static str {
        if self.ascii() { "[locked]" } else { "🔒" }
    }

    /// The (static) spinner glyph shown while Argon2 runs: a running unlock causes no
    /// redraws (sverb).
    pub(crate) fn spinner(&self) -> &'static str {
        if self.ascii() { "|" } else { "⠋" }
    }
}
