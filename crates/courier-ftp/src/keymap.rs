//! Keys: normalised chords and their grammar, the effective keymap (built-in tables ⊕
//! user config, with problem reports), the sequence resolver, and the generated
//! `docs/keybindings.md` (T50, T51).

pub(crate) mod chord;
#[cfg(test)]
mod docs;
pub(crate) mod dump;
pub(crate) mod map;
pub(crate) mod resolver;

#[cfg(test)]
mod app_tests;
#[cfg(test)]
mod tests;
