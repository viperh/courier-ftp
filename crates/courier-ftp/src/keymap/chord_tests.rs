//! Chord grammar and normalisation tests (T51 AC3, AC6).

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use proptest::prelude::*;

use super::*;

fn p(s: &str) -> KeyChord {
    s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
}

fn seq(s: &str) -> Vec<KeyChord> {
    parse_sequence(s).unwrap_or_else(|e| panic!("{s}: {e}"))
}

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
    // Raw control characters.
    assert_eq!(
        ev(KeyCode::Char('\u{8}'), KeyModifiers::NONE),
        KeyChord::key(KeyCode::Backspace)
    );
    assert_eq!(ev(KeyCode::Char('\u{7}'), KeyModifiers::NONE), p("ctrl-g"));
    assert_eq!(ev(KeyCode::Null, KeyModifiers::NONE), p("ctrl-space"));
}

#[test]
fn legacy_control_bytes_normalise() {
    let backslash = p("ctrl-\\");
    assert_eq!(ev(KeyCode::Char('4'), KeyModifiers::CONTROL), backslash);
    assert_eq!(ev(KeyCode::Char('\u{1c}'), KeyModifiers::NONE), backslash);
    assert_eq!(ev(KeyCode::Char('\\'), KeyModifiers::CONTROL), backslash);
    assert_eq!(p("ctrl-4"), backslash);
    assert_eq!(ev(KeyCode::Char('5'), KeyModifiers::CONTROL), p("ctrl-]"));
    assert_eq!(ev(KeyCode::Char('\u{1d}'), KeyModifiers::NONE), p("ctrl-]"));
    assert_eq!(p("ctrl-5"), p("ctrl-]"));
    assert_eq!(ev(KeyCode::Char('6'), KeyModifiers::CONTROL), p("ctrl-^"));
    assert_eq!(p("ctrl-6"), p("ctrl-^"));
    assert_eq!(ev(KeyCode::Char('7'), KeyModifiers::CONTROL), p("ctrl-_"));
    assert_eq!(ev(KeyCode::Char('/'), KeyModifiers::CONTROL), p("ctrl-_"));
    assert_eq!(p("ctrl-/"), p("ctrl-_"));
    assert_eq!(p("ctrl-7"), p("ctrl-_"));
    assert_eq!(p("ctrl-/").to_string(), "ctrl-_");
}

#[test]
fn parse_named_keys_table() {
    for (name, code) in named_keys() {
        let c = p(name);
        assert_eq!(c, KeyChord::key(code), "{name}");
        assert_eq!(p(&name.to_ascii_uppercase()), c, "{name} upper case");
        assert_eq!(p(&c.to_string()), c, "{name} round trip");
    }
    for (alias, canonical) in [
        ("escape", "esc"),
        ("return", "enter"),
        ("del", "delete"),
        ("ins", "insert"),
        ("pgup", "pageup"),
        ("pgdn", "pagedown"),
        ("hyphen", "-"),
        ("minus", "-"),
        ("lt", "<"),
        ("gt", ">"),
        ("space", "space"),
        ("backtab", "backtab"),
        ("shift-tab", "backtab"),
    ] {
        assert_eq!(p(alias).to_string(), canonical, "{alias}");
    }
    for n in 1..=24u8 {
        assert_eq!(p(&format!("f{n}")), KeyChord::key(KeyCode::F(n)));
        assert_eq!(p(&format!("F{n}")).to_string(), format!("f{n}"));
    }
    assert_eq!(p("space").code, KeyCode::Char(' '));
    assert_eq!(p("shift-space").to_string(), "shift-space");
}

#[test]
fn parse_modifiers_any_order_and_case() {
    for (input, canonical) in [
        ("Alt-Ctrl-x", "ctrl-alt-x"),
        ("ctrl-alt-x", "ctrl-alt-x"),
        ("ALT-CTRL-x", "ctrl-alt-x"),
        ("super-ctrl-k", "ctrl-super-k"),
        ("shift-alt-ctrl-X", "ctrl-alt-shift-x"),
        ("alt-enter", "alt-enter"),
        ("AlT-eNtEr", "alt-enter"),
        ("ctrl-shift-enter", "ctrl-shift-enter"),
        ("super-shift-f5", "shift-super-f5"),
        ("ctrl-pagedown", "ctrl-pagedown"),
        ("alt-left", "alt-left"),
        ("ctrl-alt-backtab", "ctrl-alt-backtab"),
    ] {
        let c = p(input);
        assert_eq!(c.to_string(), canonical, "{input}");
        assert_eq!(p(canonical), c, "{canonical}");
    }
    assert_eq!(p("Alt-Ctrl-x"), p("ctrl-alt-x"));
}

#[test]
fn parse_uppercase_means_shift() {
    let g = p("G");
    assert_eq!(p("shift-g"), g);
    assert_eq!(p("shift-G"), g);
    assert_eq!(seq("<G>"), vec![g]);
    assert_ne!(p("g"), g);
    assert_eq!(g.to_string(), "G");
    assert_eq!(p("ctrl-G"), p("ctrl-g"));
    assert_eq!(p("ctrl-A"), p("ctrl-a"));
    assert_ne!(p("ctrl-shift-a"), p("ctrl-a"));
    assert_eq!(p("ctrl-shift-a").to_string(), "ctrl-shift-a");
    let alt_g = p("alt-G");
    assert_eq!(
        alt_g,
        KeyChord::new(KeyCode::Char('g'), Mods::ALT | Mods::SHIFT)
    );
    assert_eq!(alt_g, p("alt-shift-g"));
    assert_eq!(alt_g.to_string(), "alt-G");
    // SHIFT on other printables is dropped.
    assert_eq!(p("shift-?"), p("?"));
    assert_eq!(p("shift-+"), p("+"));
    assert_eq!(p("*").to_string(), "*");
}

#[test]
fn parse_minus_and_ctrl_minus() {
    assert_eq!(p("-"), KeyChord::char('-'));
    assert_eq!(p("ctrl--"), KeyChord::ctrl('-'));
    assert_eq!(p("ctrl--").to_string(), "ctrl--");
    assert_eq!(p("alt--").to_string(), "alt--");
    assert_eq!(p("minus"), p("-"));
    assert_eq!(p("ctrl-minus"), p("ctrl--"));
    assert_eq!(seq("- -"), vec![KeyChord::char('-'); 2]);
}

#[test]
fn parse_angle_form_compat() {
    assert_eq!(seq("<ctrl-q>"), vec![KeyChord::ctrl('q')]);
    assert_eq!(seq("<g><g>"), seq("g g"));
    assert_eq!(seq("<lt>"), vec![KeyChord::char('<')]);
    assert_eq!(seq("<gt><lt>"), seq("> <"));
    assert_eq!(seq("<ctrl-x><d>"), seq("ctrl-x d"));
    // `<` and `>` are plain characters in the space-separated form.
    assert_eq!(seq("<"), vec![KeyChord::char('<')]);
    assert_eq!(
        seq("ctrl-x <"),
        vec![KeyChord::ctrl('x'), KeyChord::char('<')]
    );
    assert_eq!(
        seq("ctrl-x >"),
        vec![KeyChord::ctrl('x'), KeyChord::char('>')]
    );
    assert_eq!(display_sequence(&seq("<ctrl-x><d>")), "ctrl-x d");
    assert_eq!(seq("  g   g "), seq("g g"));
}

#[test]
fn parse_errors_are_readable() {
    let long = "a".repeat(65);
    for (input, message) in [
        (
            "ctrl-foo",
            "invalid key \"ctrl-foo\": unknown key name \"foo\"".to_owned(),
        ),
        (
            "ctrl-",
            "invalid key \"ctrl-\": missing key after \"ctrl-\"".to_owned(),
        ),
        (
            "<ctrl-q",
            "invalid key \"<ctrl-q\": unbalanced \"<\"".to_owned(),
        ),
        (
            "g g g g g",
            "invalid key \"g g g g g\": sequences are limited to 4 keys".to_owned(),
        ),
        ("", "invalid key \"\": empty key".to_owned()),
        (
            long.as_str(),
            format!("invalid key \"{}…\": longer than 64 bytes", "a".repeat(64)),
        ),
        (
            "f25",
            "invalid key \"f25\": function keys go from f1 to f24".to_owned(),
        ),
        (
            "ctrl-ctrl-x",
            "invalid key \"ctrl-ctrl-x\": modifier \"ctrl\" is given twice".to_owned(),
        ),
        (
            "ctrl-x nokey",
            "invalid key \"ctrl-x nokey\": unknown key name \"nokey\"".to_owned(),
        ),
    ] {
        match parse_sequence(input) {
            Ok(s) => panic!("{input:?} parsed as {s:?}"),
            Err(e) => assert_eq!(e.to_string(), message, "{input:?}"),
        }
    }
    for bad in [
        "", "ctrl-", "f25", "f0", "nokey", "ctrl-abc", "hyper-x", "ab",
    ] {
        assert!(bad.parse::<KeyChord>().is_err(), "{bad}");
    }
    assert!(parse_sequence("<>").is_err());
    assert!(parse_sequence("<g>x").is_err());
    assert!(parse_sequence("<g><g><g><g><g>").is_err());
    assert!(parse_sequence("g g g g").is_ok());
}

#[test]
fn parse_and_display_table() {
    for (input, canonical) in [
        ("ctrl-q", "ctrl-q"),
        ("CTRL-Q", "ctrl-q"),
        ("?", "?"),
        ("f1", "f1"),
        ("F10", "f10"),
        ("tab", "tab"),
        ("ctrl-space", "ctrl-space"),
        ("ctrl-@", "ctrl-space"),
        ("|", "|"),
        ("[", "["),
        ("é", "é"),
        (":", ":"),
        ("=", "="),
        (".", "."),
    ] {
        let c = p(input);
        assert_eq!(c.to_string(), canonical, "{input}");
        assert_eq!(p(canonical), c, "{input}");
    }
}

fn any_code() -> impl Strategy<Value = KeyCode> {
    prop_oneof![
        (0x20u8..0x7F).prop_map(|b| KeyCode::Char(char::from(b))),
        prop::sample::select(vec!['é', 'ß', 'Ä', '€', 'ж', '中']).prop_map(KeyCode::Char),
        (0u8..0x20).prop_map(|b| KeyCode::Char(char::from(b))),
        Just(KeyCode::Char('\u{7f}')),
        (1u8..=24).prop_map(KeyCode::F),
        prop::sample::select(vec![
            KeyCode::Enter,
            KeyCode::Esc,
            KeyCode::Tab,
            KeyCode::BackTab,
            KeyCode::Backspace,
            KeyCode::Delete,
            KeyCode::Insert,
            KeyCode::Home,
            KeyCode::End,
            KeyCode::PageUp,
            KeyCode::PageDown,
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::Null,
        ]),
    ]
}

proptest! {
    // AC6: parse(display(c)) == c for every chord.
    #[test]
    fn prop_chord_display_roundtrip(code in any_code(), bits in 0u8..16) {
        let chord = KeyChord::new(code, Mods::from_bits(bits));
        let shown = chord.to_string();
        let back: KeyChord = shown
            .parse()
            .map_err(|e| TestCaseError::fail(format!("{chord:?} → {shown}: {e}")))?;
        prop_assert_eq!(back, chord, "{}", shown);
        // Normalisation is idempotent and survives a key event.
        prop_assert_eq!(KeyChord::new(chord.code, chord.mods), chord);
        prop_assert_eq!(KeyChord::from_key_event(chord.to_key_event()), chord);
        // Sequences round-trip too.
        let s = vec![chord, KeyChord::char('g'), chord];
        let shown = display_sequence(&s);
        prop_assert_eq!(parse_sequence(&shown).ok(), Some(s), "{}", shown);
    }

    // AC3: arbitrary input never panics, and errors name the input.
    #[test]
    fn prop_parse_never_panics(s in "\\PC{0,80}", t in "[a-z<>\\- ]{0,20}") {
        for input in [&s, &t] {
            match parse_sequence(input) {
                Ok(seq) => {
                    prop_assert!(!seq.is_empty() && seq.len() <= MAX_SEQUENCE_LEN);
                }
                Err(e) => {
                    prop_assert!(e.to_string().starts_with("invalid key \""));
                    prop_assert!(e.input.len() <= MAX_KEY_STRING_BYTES + '…'.len_utf8());
                }
            }
            let _ = input.parse::<KeyChord>();
        }
    }
}
