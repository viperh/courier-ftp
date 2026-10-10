//! Key chords: one key with modifiers, normalised so lookups never depend on how a
//! terminal encodes a key (adapted from sverb `keymap/chord.rs`, D13).
//!
//! - a shifted ASCII letter is stored as the uppercase letter **without** SHIFT
//!   (`G` means shift-g; terminals differ in whether they report SHIFT),
//! - SHIFT is dropped from other printable characters (`?` arrives with or without it),
//!   except `space`,
//! - `BackTab` is `Tab`+SHIFT,
//! - the legacy control bytes 0x1C–0x1F (reported by crossterm as `Char('4')`…`Char('7')`
//!   with CONTROL) are `ctrl-\`, `ctrl-]`, `ctrl-^` and `ctrl-_`.
//!
//! The parser accepts `[ctrl-][alt-][shift-]<key>`, where `<key>` is one printable
//! character or a named key (`enter esc tab backtab space backspace delete insert home
//! end pageup pagedown up down left right f1…f24`). T51 extends the grammar.

use std::{fmt, str::FromStr};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

/// Key modifiers courier-ftp distinguishes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Mods(u8);

impl Mods {
    /// No modifier.
    pub(crate) const NONE: Self = Self(0);
    /// Control.
    pub(crate) const CTRL: Self = Self(1);
    /// Alt / Option / Meta.
    pub(crate) const ALT: Self = Self(1 << 1);
    /// Shift.
    pub(crate) const SHIFT: Self = Self(1 << 2);

    /// Whether every modifier in `other` is set.
    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Both sets.
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    fn from_crossterm(m: KeyModifiers) -> Self {
        let mut out = Self::NONE;
        for (ct, ours) in [
            (KeyModifiers::CONTROL, Self::CTRL),
            (KeyModifiers::ALT, Self::ALT),
            (KeyModifiers::SHIFT, Self::SHIFT),
        ] {
            if m.contains(ct) {
                out.insert(ours);
            }
        }
        out
    }

    #[cfg_attr(not(test), expect(dead_code, reason = "used by the harness"))]
    fn to_crossterm(self) -> KeyModifiers {
        let mut out = KeyModifiers::NONE;
        for (ct, ours) in [
            (KeyModifiers::CONTROL, Self::CTRL),
            (KeyModifiers::ALT, Self::ALT),
            (KeyModifiers::SHIFT, Self::SHIFT),
        ] {
            if self.contains(ours) {
                out.insert(ct);
            }
        }
        out
    }
}

impl std::ops::BitOr for Mods {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// A normalised key (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct KeyChord {
    /// The key.
    pub code: KeyCode,
    /// Modifiers.
    pub mods: Mods,
}

impl KeyChord {
    /// A normalised chord.
    pub(crate) fn new(code: KeyCode, mods: Mods) -> Self {
        let (code, mods) = normalize(code, mods);
        Self { code, mods }
    }

    /// The chord for a crossterm key event.
    pub(crate) fn from_key_event(ev: KeyEvent) -> Self {
        Self::new(ev.code, Mods::from_crossterm(ev.modifiers))
    }

    /// A printable character without modifiers.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by tests and T51"))]
    pub(crate) fn char(c: char) -> Self {
        Self::new(KeyCode::Char(c), Mods::NONE)
    }

    /// `ctrl-<c>`.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by tests and T51"))]
    pub(crate) fn ctrl(c: char) -> Self {
        Self::new(KeyCode::Char(c), Mods::CTRL)
    }

    /// A key without modifiers.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by tests and T51"))]
    pub(crate) fn key(code: KeyCode) -> Self {
        Self::new(code, Mods::NONE)
    }

    /// A press event for this chord (tests).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the harness and T76's PtyApp")
    )]
    pub(crate) fn to_key_event(self) -> KeyEvent {
        KeyEvent {
            code: self.code,
            modifiers: self.mods.to_crossterm(),
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    /// The printable character this chord types into a text field, if any.
    pub(crate) fn printable(&self) -> Option<char> {
        match self.code {
            KeyCode::Char(c)
                if !self.mods.contains(Mods::CTRL) && !self.mods.contains(Mods::ALT) =>
            {
                Some(c)
            }
            _ => None,
        }
    }
}

fn normalize(code: KeyCode, mut mods: Mods) -> (KeyCode, Mods) {
    match code {
        KeyCode::BackTab => {
            mods.insert(Mods::SHIFT);
            (KeyCode::Tab, mods)
        }
        KeyCode::Char(c) => normalize_char(c, mods),
        other => (other, mods),
    }
}

fn normalize_char(c: char, mut mods: Mods) -> (KeyCode, Mods) {
    let c = if mods.contains(Mods::CTRL) {
        match c {
            '4' => '\\',
            '5' => ']',
            '6' => '^',
            '7' | '/' => '_',
            c => c,
        }
    } else {
        c
    };
    let c = match u32::from(c) {
        0x1C => {
            mods.insert(Mods::CTRL);
            '\\'
        }
        0x1D => {
            mods.insert(Mods::CTRL);
            ']'
        }
        0x1E => {
            mods.insert(Mods::CTRL);
            '^'
        }
        0x1F => {
            mods.insert(Mods::CTRL);
            '_'
        }
        _ => c,
    };
    let c = if c.is_ascii_alphabetic() {
        if mods.contains(Mods::SHIFT) || c.is_ascii_uppercase() {
            mods.remove(Mods::SHIFT);
            c.to_ascii_uppercase()
        } else {
            c
        }
    } else {
        if c != ' ' {
            mods.remove(Mods::SHIFT);
        }
        c
    };
    (KeyCode::Char(c), mods)
}

/// Why a chord string did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChordParseError {
    /// The text that failed.
    pub input: String,
    /// What is wrong with it.
    pub reason: String,
}

impl fmt::Display for ChordParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid key `{}`: {}", self.input, self.reason)
    }
}

impl std::error::Error for ChordParseError {}

const NAMED: &[(&str, KeyCode)] = &[
    ("space", KeyCode::Char(' ')),
    ("enter", KeyCode::Enter),
    ("esc", KeyCode::Esc),
    ("tab", KeyCode::Tab),
    ("backtab", KeyCode::BackTab),
    ("backspace", KeyCode::Backspace),
    ("delete", KeyCode::Delete),
    ("insert", KeyCode::Insert),
    ("home", KeyCode::Home),
    ("end", KeyCode::End),
    ("pageup", KeyCode::PageUp),
    ("pagedown", KeyCode::PageDown),
    ("up", KeyCode::Up),
    ("down", KeyCode::Down),
    ("left", KeyCode::Left),
    ("right", KeyCode::Right),
];

impl FromStr for KeyChord {
    type Err = ChordParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = |reason: &str| ChordParseError {
            input: s.to_owned(),
            reason: reason.to_owned(),
        };
        if s.is_empty() {
            return Err(err("empty key"));
        }
        let mut mods = Mods::NONE;
        let mut explicit_shift = false;
        let mut rest = s;
        while let Some((head, tail)) = rest.split_once('-') {
            if head.is_empty() {
                break;
            }
            let m = match head.to_ascii_lowercase().as_str() {
                "ctrl" => Mods::CTRL,
                "alt" => Mods::ALT,
                "shift" => {
                    explicit_shift = true;
                    Mods::SHIFT
                }
                _ => break,
            };
            if tail.is_empty() {
                return Err(err("missing key after the modifier"));
            }
            mods.insert(m);
            rest = tail;
        }
        let mut chars = rest.chars();
        let code = match (chars.next(), chars.next()) {
            (Some(c), None) if !c.is_control() && !c.is_whitespace() => {
                if mods.contains(Mods::CTRL) && !explicit_shift {
                    KeyCode::Char(c.to_ascii_lowercase())
                } else {
                    KeyCode::Char(c)
                }
            }
            _ => {
                let lower = rest.to_ascii_lowercase();
                if let Some((_, code)) = NAMED.iter().find(|(n, _)| *n == lower) {
                    *code
                } else if let Some(n) = lower.strip_prefix('f').and_then(|n| n.parse::<u8>().ok()) {
                    if !(1..=24).contains(&n) {
                        return Err(err("function keys go from f1 to f24"));
                    }
                    KeyCode::F(n)
                } else {
                    return Err(err(
                        "unknown key (expected one character, a named key such as `enter`, or f1…f24)",
                    ));
                }
            }
        };
        Ok(Self::new(code, mods))
    }
}

impl fmt::Display for KeyChord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (shown, shift_letter) = match self.code {
            KeyCode::Char(c) if c.is_ascii_uppercase() && self.mods.contains(Mods::CTRL) => {
                (KeyCode::Char(c.to_ascii_lowercase()), true)
            }
            code => (code, false),
        };
        // shift-tab is written `backtab`, as in the config.
        if shown == KeyCode::Tab && self.mods.contains(Mods::SHIFT) {
            for (m, name) in [(Mods::CTRL, "ctrl-"), (Mods::ALT, "alt-")] {
                if self.mods.contains(m) {
                    f.write_str(name)?;
                }
            }
            return f.write_str("backtab");
        }
        for (m, name) in [
            (Mods::CTRL, "ctrl-"),
            (Mods::ALT, "alt-"),
            (Mods::SHIFT, "shift-"),
        ] {
            if self.mods.contains(m) || (m == Mods::SHIFT && shift_letter) {
                f.write_str(name)?;
            }
        }
        match shown {
            KeyCode::Char(' ') => f.write_str("space"),
            KeyCode::Char(c) => write!(f, "{c}"),
            KeyCode::F(n) => write!(f, "f{n}"),
            code => match NAMED.iter().find(|(_, c)| *c == code) {
                Some((name, _)) => f.write_str(name),
                None => write!(f, "<{}>", format!("{code:?}").to_ascii_lowercase()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn ev(code: KeyCode, m: KeyModifiers) -> KeyChord {
        KeyChord::from_key_event(KeyEvent::new(code, m))
    }

    #[test]
    fn keychord_normalisation() {
        // shift-letter → uppercase without SHIFT, whether or not SHIFT is reported.
        let g = KeyChord::new(KeyCode::Char('G'), Mods::NONE);
        assert_eq!(ev(KeyCode::Char('g'), KeyModifiers::SHIFT), g);
        assert_eq!(ev(KeyCode::Char('G'), KeyModifiers::SHIFT), g);
        assert_eq!(g.mods, Mods::NONE);
        // SHIFT dropped from other printables.
        assert_eq!(
            ev(KeyCode::Char('?'), KeyModifiers::SHIFT),
            KeyChord::char('?')
        );
        // BackTab → shift-tab.
        assert_eq!(
            ev(KeyCode::BackTab, KeyModifiers::SHIFT),
            KeyChord::new(KeyCode::Tab, Mods::SHIFT)
        );
        assert_eq!(ev(KeyCode::BackTab, KeyModifiers::NONE).mods, Mods::SHIFT);
        // Legacy control bytes.
        assert_eq!(
            ev(KeyCode::Char('4'), KeyModifiers::CONTROL),
            KeyChord::ctrl('\\')
        );
        assert_eq!(
            ev(KeyCode::Char('\u{1d}'), KeyModifiers::NONE),
            KeyChord::ctrl(']')
        );
        assert_eq!(
            ev(KeyCode::Char('7'), KeyModifiers::CONTROL),
            KeyChord::ctrl('_')
        );
    }

    #[test]
    fn parse_and_display() -> Result<(), ChordParseError> {
        for (input, canonical) in [
            ("ctrl-q", "ctrl-q"),
            ("CTRL-Q", "ctrl-q"),
            ("?", "?"),
            ("G", "G"),
            ("shift-g", "G"),
            ("f1", "f1"),
            ("F10", "f10"),
            ("tab", "tab"),
            ("backtab", "backtab"),
            ("shift-tab", "backtab"),
            ("-", "-"),
            ("ctrl--", "ctrl--"),
            ("alt-enter", "alt-enter"),
            ("space", "space"),
            ("ctrl-\\", "ctrl-\\"),
        ] {
            let c: KeyChord = input.parse()?;
            assert_eq!(c.to_string(), canonical, "{input}");
            assert_eq!(canonical.parse::<KeyChord>()?, c, "{input}");
        }
        for bad in ["", "ctrl-", "f25", "nokey", "ctrl-abc"] {
            assert!(bad.parse::<KeyChord>().is_err(), "{bad}");
        }
        Ok(())
    }
}
