//! Key chords: one key with modifiers, normalised so lookups never depend on how a
//! terminal encodes a key (adapted from sverb `keymap/chord.rs`, D13).
//!
//! - a shifted ASCII letter is stored as the uppercase letter **without** SHIFT
//!   (`G` means shift-g; terminals differ in whether they report SHIFT),
//! - SHIFT is dropped from other printable characters (`?` arrives with or without it),
//!   except `space`,
//! - `BackTab` is `Tab`+SHIFT,
//! - raw control characters are the keys they encode (0x08 backspace, 0x09 tab, 0x0D
//!   enter, 0x1B esc, 0x01–0x1A ctrl-a…ctrl-z, NUL ctrl-space),
//! - the legacy control bytes 0x1C–0x1F (reported by crossterm as `Char('4')`…`Char('7')`
//!   with CONTROL) are `ctrl-\`, `ctrl-]`, `ctrl-^` and `ctrl-_`; `ctrl-/` is `ctrl-_`.
//!
//! # Grammar (T51)
//!
//! ```text
//! binding   = sequence | angle-seq
//! sequence  = chord { WS chord }                 (1..=4 chords)
//! angle-seq = "<" chord ">" { "<" chord ">" }    (template form)
//! chord     = { modifier "-" } key
//! modifier  = ctrl | alt | shift | super         (case-insensitive, any order, each once)
//! key       = named | f1…f24 | one printable character (case-sensitive)
//! ```
//!
//! A lone `-` is the minus key (`ctrl--` is ctrl + minus). Without `ctrl` an uppercase
//! letter means shift (`G`, `alt-G`); with `ctrl` the letter case is ignored, so the
//! shifted chord is written `ctrl-shift-a`. [`KeyChord`]'s `Display` is the canonical
//! form (modifier order `ctrl-alt-shift-super-`) and round-trips through `FromStr`.

use std::{fmt, str::FromStr};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

/// The longest key sequence a binding may have.
pub(crate) const MAX_SEQUENCE_LEN: usize = 4;

/// The longest key string read from a config file, in bytes.
pub(crate) const MAX_KEY_STRING_BYTES: usize = 64;

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
    /// Super / Windows / Command (kitty keyboard protocol only).
    pub(crate) const SUPER: Self = Self(1 << 3);

    /// Whether every modifier in `other` is set.
    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Both sets.
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// From raw bits (tests); unknown bits are dropped.
    #[cfg(test)]
    pub(crate) const fn from_bits(bits: u8) -> Self {
        Self(bits & 0b1111)
    }

    fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    const TABLE: [(KeyModifiers, Self); 4] = [
        (KeyModifiers::CONTROL, Self::CTRL),
        (KeyModifiers::ALT, Self::ALT),
        (KeyModifiers::SHIFT, Self::SHIFT),
        (KeyModifiers::SUPER, Self::SUPER),
    ];

    fn from_crossterm(m: KeyModifiers) -> Self {
        let mut out = Self::NONE;
        for (ct, ours) in Self::TABLE {
            if m.contains(ct) {
                out.insert(ours);
            }
        }
        out
    }

    #[cfg_attr(not(test), expect(dead_code, reason = "used by the harness"))]
    fn to_crossterm(self) -> KeyModifiers {
        let mut out = KeyModifiers::NONE;
        for (ct, ours) in Self::TABLE {
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
    #[cfg_attr(not(test), expect(dead_code, reason = "used by tests and T53"))]
    pub(crate) fn char(c: char) -> Self {
        Self::new(KeyCode::Char(c), Mods::NONE)
    }

    /// `ctrl-<c>`.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by tests and T53"))]
    pub(crate) fn ctrl(c: char) -> Self {
        Self::new(KeyCode::Char(c), Mods::CTRL)
    }

    /// A key without modifiers.
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
                if !self.mods.contains(Mods::CTRL)
                    && !self.mods.contains(Mods::ALT)
                    && !self.mods.contains(Mods::SUPER) =>
            {
                Some(c)
            }
            _ => None,
        }
    }
}

fn normalize(code: KeyCode, mut mods: Mods) -> (KeyCode, Mods) {
    match code {
        KeyCode::Null => {
            mods.insert(Mods::CTRL);
            (KeyCode::Char(' '), mods)
        }
        KeyCode::BackTab => {
            mods.insert(Mods::SHIFT);
            (KeyCode::Tab, mods)
        }
        KeyCode::Char(c) => normalize_char(c, mods),
        other => (other, mods),
    }
}

fn normalize_char(c: char, mut mods: Mods) -> (KeyCode, Mods) {
    // Raw control characters (a terminal or a test sending the byte itself).
    let c = match u32::from(c) {
        0x00 => {
            mods.insert(Mods::CTRL);
            ' '
        }
        0x08 | 0x7F => return (KeyCode::Backspace, mods),
        0x09 => return (KeyCode::Tab, mods),
        0x0A | 0x0D => return (KeyCode::Enter, mods),
        0x1B => return (KeyCode::Esc, mods),
        n @ (0x01..=0x1A | 0x1C..=0x1F) => {
            mods.insert(Mods::CTRL);
            match n {
                0x1C => '\\',
                0x1D => ']',
                0x1E => '^',
                0x1F => '_',
                // 0x01..=0x1A: `n + 0x60` is a lowercase letter.
                n => char::from_u32(n + 0x60).unwrap_or('?'),
            }
        }
        _ => c,
    };
    let c = if mods.contains(Mods::CTRL) {
        // Legacy encodings: crossterm reports 0x1C..0x1F as ctrl-4..ctrl-7, NUL as ctrl-@.
        match c {
            '4' => '\\',
            '5' => ']',
            '6' => '^',
            '7' | '/' => '_',
            '@' => ' ',
            c => c,
        }
    } else {
        c
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

/// Why a key string did not parse. `Display`: `invalid key "…": reason`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChordParseError {
    /// The text that failed (shortened to 64 bytes).
    pub input: String,
    /// What is wrong with it.
    pub reason: String,
}

impl ChordParseError {
    fn new(input: &str, reason: impl Into<String>) -> Self {
        Self {
            input: shorten(input),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for ChordParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid key \"{}\": {}", self.input, self.reason)
    }
}

impl std::error::Error for ChordParseError {}

/// `s` cut to [`MAX_KEY_STRING_BYTES`] (at a character boundary) with `…` appended, so
/// untrusted key strings stay short in messages and logs.
pub(crate) fn shorten(s: &str) -> String {
    if s.len() <= MAX_KEY_STRING_BYTES {
        return s.to_owned();
    }
    let mut end = MAX_KEY_STRING_BYTES;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Named keys, canonical spelling first; later entries for a code are aliases.
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
    ("minus", KeyCode::Char('-')),
    ("lt", KeyCode::Char('<')),
    ("gt", KeyCode::Char('>')),
    // Aliases.
    ("escape", KeyCode::Esc),
    ("return", KeyCode::Enter),
    ("del", KeyCode::Delete),
    ("ins", KeyCode::Insert),
    ("pgup", KeyCode::PageUp),
    ("pgdn", KeyCode::PageDown),
    ("hyphen", KeyCode::Char('-')),
];

/// Every named key and alias the parser accepts (tests, docs).
#[cfg(test)]
pub(crate) fn named_keys() -> impl Iterator<Item = (&'static str, KeyCode)> {
    NAMED.iter().copied()
}

impl FromStr for KeyChord {
    type Err = ChordParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ChordParseError::new(s, "empty key"));
        }
        if s.len() > MAX_KEY_STRING_BYTES {
            return Err(ChordParseError::new(
                s,
                format!("longer than {MAX_KEY_STRING_BYTES} bytes"),
            ));
        }
        let mut mods = Mods::NONE;
        let mut explicit_shift = false;
        let mut rest = s;
        while let Some((head, tail)) = rest.split_once('-') {
            // A lone `-` (in `ctrl--` or `-`) is the key itself.
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
                "super" => Mods::SUPER,
                _ => break,
            };
            if tail.is_empty() {
                return Err(ChordParseError::new(
                    s,
                    format!("missing key after \"{head}-\""),
                ));
            }
            if mods.contains(m) {
                return Err(ChordParseError::new(
                    s,
                    format!("modifier \"{}\" is given twice", head.to_ascii_lowercase()),
                ));
            }
            mods.insert(m);
            rest = tail;
        }
        let mut chars = rest.chars();
        let code = match (chars.next(), chars.next()) {
            (Some(c), None) if !c.is_control() && !c.is_whitespace() => {
                // With ctrl a letter's case is ignored: `ctrl-A` is `ctrl-a`.
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
                } else if let Some(n) = lower
                    .strip_prefix('f')
                    .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
                {
                    match n.parse::<u8>() {
                        Ok(n @ 1..=24) => KeyCode::F(n),
                        _ => {
                            return Err(ChordParseError::new(s, "function keys go from f1 to f24"));
                        }
                    }
                } else {
                    return Err(ChordParseError::new(
                        s,
                        format!("unknown key name \"{rest}\""),
                    ));
                }
            }
        };
        Ok(Self::new(code, mods))
    }
}

impl fmt::Display for KeyChord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // An uppercase letter with ctrl is written `ctrl-shift-x` (the parser folds the
        // case of letters after `ctrl-`); without ctrl it is written as the letter.
        let (shown, shift_letter) = match self.code {
            KeyCode::Char(c) if c.is_ascii_uppercase() && self.mods.contains(Mods::CTRL) => {
                (KeyCode::Char(c.to_ascii_lowercase()), true)
            }
            code => (code, false),
        };
        // shift-tab is written `backtab`, as in the config.
        let backtab = shown == KeyCode::Tab && self.mods.contains(Mods::SHIFT);
        for (m, name) in [
            (Mods::CTRL, "ctrl-"),
            (Mods::ALT, "alt-"),
            (Mods::SHIFT, "shift-"),
            (Mods::SUPER, "super-"),
        ] {
            let set = self.mods.contains(m) || (m == Mods::SHIFT && shift_letter);
            if set && !(backtab && m == Mods::SHIFT) {
                f.write_str(name)?;
            }
        }
        if backtab {
            return f.write_str("backtab");
        }
        match shown {
            KeyCode::Char(' ') => f.write_str("space"),
            KeyCode::Char(c) => write!(f, "{c}"),
            KeyCode::F(n) => write!(f, "f{n}"),
            code => match NAMED.iter().find(|(_, c)| *c == code) {
                Some((name, _)) => f.write_str(name),
                // Keys outside the grammar (media keys, …) can't be bound; shown for
                // logs only.
                None => write!(f, "<{}>", format!("{code:?}").to_ascii_lowercase()),
            },
        }
    }
}

/// Parses a binding: space-separated chords (`"ctrl-x d"`) or the template's angle form
/// (`"<g><g>"`, where `<` and `>` are written `lt` and `gt`). At most
/// [`MAX_SEQUENCE_LEN`] chords and [`MAX_KEY_STRING_BYTES`] bytes.
pub(crate) fn parse_sequence(s: &str) -> Result<Vec<KeyChord>, ChordParseError> {
    if s.len() > MAX_KEY_STRING_BYTES {
        return Err(ChordParseError::new(
            s,
            format!("longer than {MAX_KEY_STRING_BYTES} bytes"),
        ));
    }
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(ChordParseError::new(s, "empty key"));
    }
    let parts: Vec<&str> = if trimmed.len() > 1
        && trimmed.starts_with('<')
        && !trimmed.contains(char::is_whitespace)
    {
        angle_parts(s, trimmed)?
    } else {
        trimmed.split_whitespace().collect()
    };
    if parts.len() > MAX_SEQUENCE_LEN {
        return Err(ChordParseError::new(
            s,
            format!("sequences are limited to {MAX_SEQUENCE_LEN} keys"),
        ));
    }
    parts
        .into_iter()
        .map(|p| {
            p.parse::<KeyChord>()
                .map_err(|e| ChordParseError::new(s, e.reason))
        })
        .collect()
}

/// Splits `<a><ctrl-b>` into `["a", "ctrl-b"]`.
fn angle_parts<'a>(input: &str, s: &'a str) -> Result<Vec<&'a str>, ChordParseError> {
    let mut out = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        let Some(after) = rest.strip_prefix('<') else {
            return Err(ChordParseError::new(
                input,
                "expected \"<\" (write each key as <key>)",
            ));
        };
        let Some(end) = after.find('>') else {
            return Err(ChordParseError::new(input, "unbalanced \"<\""));
        };
        let inner = &after[..end];
        if inner.is_empty() {
            return Err(ChordParseError::new(input, "empty key in \"<>\""));
        }
        if inner.contains('<') {
            return Err(ChordParseError::new(input, "unbalanced \"<\""));
        }
        out.push(inner);
        rest = &after[end + 1..];
        if out.len() > MAX_SEQUENCE_LEN {
            break;
        }
    }
    Ok(out)
}

/// `"ctrl-x d"`: chords in canonical form, separated by one space.
pub(crate) fn display_sequence(seq: &[KeyChord]) -> String {
    seq.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
#[path = "chord_tests.rs"]
mod tests;
