//! Widget unit and property tests (T52).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::{collections::BTreeMap, time::Duration};

use pretty_assertions::assert_eq;
use proptest::prelude::*;
use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use tokio::time::Instant;

use super::*;
use crate::{
    keymap::chord::KeyChord,
    testing::buffer_to_string,
    ui::{
        symbols::Symbols,
        theme::{Theme, ThemePreset},
    },
};

fn k(s: &str) -> KeyChord {
    s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
}

fn theme() -> Theme {
    Theme::load(ThemePreset::Default, &BTreeMap::new(), false).0
}

/// Draws `w` into a `width`×`height` buffer; returns the text and the cursor.
fn draw(w: &dyn Widget, width: u16, height: u16, focused: bool) -> (String, Option<Position>) {
    let theme = theme();
    let symbols = Symbols::unicode();
    let mut t = Terminal::new(TestBackend::new(width, height)).unwrap();
    let mut cursor = None;
    t.draw(|f| {
        let area = f.area();
        let cx = WidgetCx {
            theme: &theme,
            symbols: &symbols,
            focused,
            enabled: true,
            now: Instant::now(),
        };
        w.render(f, area, &cx);
        w.render_overlay(f, Rect { height: 1, ..area }, area, &cx);
        cursor = w.cursor(area);
    })
    .unwrap();
    (buffer_to_string(t.backend().buffer()), cursor)
}

#[test]
fn text_input_editing_table() {
    let family = "a\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}b";
    let rows: &[(&str, usize, &str, &str, usize)] = &[
        ("abc", 3, "left", "abc", 2),
        ("abc", 0, "left", "abc", 0),
        ("abc", 0, "right", "abc", 1),
        ("abc", 3, "right", "abc", 3),
        ("abc", 3, "home", "abc", 0),
        ("abc", 0, "end", "abc", 3),
        ("abc", 3, "ctrl-a", "abc", 0),
        ("abc", 0, "ctrl-e", "abc", 3),
        ("ab", 2, "backspace", "a", 1),
        ("ab", 0, "backspace", "ab", 0),
        ("ab", 0, "delete", "b", 0),
        ("ab", 2, "delete", "ab", 2),
        ("foo bar", 7, "ctrl-left", "foo bar", 4),
        ("foo bar", 7, "alt-b", "foo bar", 4),
        ("foo bar", 0, "ctrl-right", "foo bar", 3),
        ("foo bar", 0, "alt-f", "foo bar", 3),
        ("foo bar", 7, "ctrl-w", "foo ", 4),
        ("foo bar", 7, "alt-backspace", "foo ", 4),
        ("foo bar", 0, "alt-d", " bar", 0),
        ("foo bar", 3, "ctrl-u", " bar", 0),
        ("foo bar", 3, "ctrl-k", "foo", 3),
        ("ab", 1, "x", "axb", 2),
        ("ab", 1, "space", "a b", 2),
        // Grapheme clusters: e + combining acute is one step.
        ("e\u{301}x", 2, "left", "e\u{301}x", 1),
        ("e\u{301}x", 1, "backspace", "x", 0),
        ("e\u{301}x", 0, "delete", "x", 0),
        // An emoji ZWJ sequence is one cluster.
        (family, 2, "backspace", "ab", 1),
        (family, 1, "right", family, 2),
        // Wide characters.
        ("日本語", 3, "left", "日本語", 2),
        ("日本語", 1, "delete", "日語", 1),
    ];
    for &(initial, cursor, key, value, after) in rows {
        let mut t = TextInput::new(initial);
        t.set_cursor(cursor);
        t.handle_key(k(key));
        assert_eq!(
            (t.value(), t.cursor_index()),
            (value, after),
            "{initial:?} @{cursor} {key}"
        );
    }
    // A combining mark typed after a letter joins its cluster.
    let mut t = TextInput::new("e");
    assert_eq!(
        t.handle_key(KeyChord::char('\u{301}')),
        WidgetOutcome::Changed
    );
    assert_eq!((t.value(), t.cursor_index()), ("e\u{301}", 1));
    // Not an editing key.
    assert_eq!(t.handle_key(k("f5")), WidgetOutcome::Ignored);
    assert_eq!(t.handle_key(k("ctrl-x")), WidgetOutcome::Ignored);
}

#[test]
fn text_input_word_separators() {
    let mut t = TextInput::new("/var/www/html");
    t.handle_key(k("ctrl-w"));
    assert_eq!(t.value(), "/var/www/");
    t.handle_key(k("ctrl-w"));
    assert_eq!(t.value(), "/var/");
    let mut t = TextInput::new("user@host.example-1_2:21");
    t.handle_key(k("alt-b"));
    assert_eq!(t.cursor_index(), "user@host.example-1_2:".len());
    t.handle_key(k("ctrl-left"));
    assert_eq!(t.cursor_index(), "user@host.example-1_".len());
}

#[test]
fn text_input_scrolls_to_cursor() {
    let value: String = (0..200)
        .map(|i| char::from(b'a' + (i % 26) as u8))
        .collect();
    let t = TextInput::new(&value);
    let (screen, cursor) = draw(&t, 20, 1, true);
    let shown = screen.trim_end_matches('\n');
    assert_eq!(shown, format!("{} ", &value[181..]));
    assert_eq!(cursor, Some(Position::new(19, 0)));
    let mut t = t;
    t.handle_key(k("home"));
    let (screen, cursor) = draw(&t, 20, 1, true);
    assert_eq!(screen.trim_end_matches('\n'), &value[..20]);
    assert_eq!(cursor, Some(Position::new(0, 0)));
    // Placeholder while empty.
    let t = TextInput::new("").placeholder("host name");
    let (screen, _) = draw(&t, 20, 1, false);
    assert!(screen.starts_with("host name"), "{screen}");
}

#[test]
fn text_input_max_chars_and_validator() {
    let mut t = TextInput::new("").max_chars(3);
    for c in "abcd".chars() {
        t.handle_key(KeyChord::char(c));
    }
    assert_eq!(t.value(), "abc");
    assert_eq!(TextInput::new("abcdef").max_chars(4).value(), "abcd");
    let mut t = TextInput::new("").validator(std::sync::Arc::new(|v: &str| {
        if v.is_empty() {
            Err("Required".to_owned())
        } else {
            Ok(())
        }
    }));
    assert!(!t.validate());
    assert_eq!(t.error(), Some("Required"));
    t.handle_key(k("x"));
    assert!(t.validate());
    assert_eq!(t.error(), None);
}

#[test]
fn secret_input_never_exposes_value() {
    let mut s = SecretInput::new();
    for c in "hunter2".chars() {
        assert_eq!(s.handle_key(KeyChord::char(c)), WidgetOutcome::Changed);
    }
    assert_eq!(s.len_chars(), 7);
    let (screen, cursor) = draw(&s, 30, 1, true);
    assert!(screen.starts_with("•••••••"), "{screen}");
    for sub in ["hunter2", "hunt", "er2", "h", "2"] {
        assert!(!screen.contains(sub), "{sub} in {screen}");
    }
    assert_eq!(cursor, Some(Position::new(7, 0)));
    assert_eq!(format!("{s:?}"), "SecretInput(****)");
    assert_eq!(format!("{s:#?}"), "SecretInput(****)");
    // No cursor movement that could reveal structure; editing still works.
    assert_eq!(s.handle_key(k("left")), WidgetOutcome::Consumed);
    s.handle_key(k("backspace"));
    assert_eq!(s.len_chars(), 6);
    s.handle_key(k("ctrl-u"));
    assert!(s.is_empty());
    // ASCII mask.
    let mut s = SecretInput::new();
    s.handle_paste("pw\n");
    let theme = theme();
    let symbols = Symbols::ascii();
    let mut t = Terminal::new(TestBackend::new(10, 1)).unwrap();
    t.draw(|f| {
        let cx = WidgetCx {
            theme: &theme,
            symbols: &symbols,
            focused: true,
            enabled: true,
            now: Instant::now(),
        };
        s.render(f, f.area(), &cx);
    })
    .unwrap();
    assert!(buffer_to_string(t.backend().buffer()).starts_with("** "));
}

#[test]
fn secret_input_take_clears_and_zeroizes() {
    let mut s = SecretInput::new();
    s.handle_paste("hunter2");
    assert_eq!(s.wipes, 0);
    let v = s.take();
    assert_eq!(v.expose(), "hunter2");
    assert!(s.is_empty());
    assert_eq!(s.len_chars(), 0);
    assert_eq!(s.wipes, 1, "take() zeroes the buffer");
    assert_eq!(s.take().expose(), "");
    // Over the limit: cut with a notice.
    let mut s = SecretInput::new();
    s.handle_paste(&"x".repeat(2000));
    assert_eq!(s.len_chars(), 1024);
    assert_eq!(
        s.take_notice(),
        Some(Notice::Status(
            "Pasted text was cut to 1024 characters".into()
        ))
    );
}

#[test]
fn number_input_digits_range_and_arrows() {
    let mut n = NumberInput::new(Some(21), 0, 65535);
    assert_eq!(n.handle_key(k("a")), WidgetOutcome::Consumed);
    assert_eq!(n.handle_key(k("-")), WidgetOutcome::Consumed);
    assert_eq!(n.value(), Some(21));
    assert_eq!(n.handle_key(k("up")), WidgetOutcome::Changed);
    assert_eq!(n.value(), Some(22));
    n.handle_key(k("pagedown"));
    assert_eq!(n.value(), Some(12));
    n.handle_key(k("pagedown"));
    n.handle_key(k("pagedown"));
    assert_eq!(n.value(), Some(0), "clamped at min");
    n.set_value(Some(65535));
    assert_eq!(n.handle_key(k("up")), WidgetOutcome::Consumed);
    assert_eq!(n.value(), Some(65535), "up at max stays");
    // Typed out of range: validation error.
    n.handle_key(k("1"));
    assert_eq!(n.value(), Some(655_351));
    assert!(!n.validate());
    assert_eq!(n.error(), Some("Enter a number from 0 to 65535"));
    // Required unless optional.
    let mut n = NumberInput::new(None, 1, 10);
    assert!(!n.validate());
    assert!(NumberInput::new(None, 1, 10).optional().validate());
    // Negative ranges accept a leading minus.
    let mut n = NumberInput::new(None, -5, 5);
    n.handle_key(k("-"));
    n.handle_key(k("3"));
    assert_eq!(n.value(), Some(-3));
    n.handle_key(k("down"));
    n.handle_key(k("down"));
    n.handle_key(k("down"));
    assert_eq!(n.value(), Some(-5));
    assert!(n.uses_vertical_keys());
}

#[test]
fn tristate_cycle_with_and_without_unchanged() {
    let mut t = TriStateCheckbox::new("", TriState::On, true);
    let mut seen = Vec::new();
    for _ in 0..4 {
        t.handle_key(k("space"));
        seen.push(t.state);
    }
    assert_eq!(
        seen,
        [
            TriState::Off,
            TriState::Unchanged,
            TriState::On,
            TriState::Off
        ]
    );
    let mut t = TriStateCheckbox::new("", TriState::On, false);
    let mut seen = Vec::new();
    for _ in 0..3 {
        t.handle_key(k("space"));
        seen.push(t.state);
    }
    assert_eq!(seen, [TriState::Off, TriState::On, TriState::Off]);
    assert_eq!(t.handle_key(k("x")), WidgetOutcome::Ignored);
    let t = TriStateCheckbox::new("Read", TriState::Unchanged, true);
    assert!(draw(&t, 10, 1, false).0.starts_with("[-] Read"));
    let mut c = Checkbox::new("Passive", false);
    assert_eq!(c.handle_key(k("space")), WidgetOutcome::Changed);
    assert!(c.checked);
    assert!(draw(&c, 12, 1, false).0.starts_with("[x] Passive"));
}

fn fruit() -> Select<&'static str> {
    let mut opts = vec![
        SelectOption::new("apple", "a"),
        SelectOption::new("apricot", "ap"),
        SelectOption::new("banana", "b"),
        SelectOption::new("blueberry", "bl"),
        SelectOption::new("cherry", "c"),
    ];
    opts[1].disabled = Some("out of season".into());
    Select::new(opts)
}

#[test]
fn select_popup_type_to_jump_and_disabled_skip() {
    let t0 = Instant::now();
    let mut s = fruit();
    // Closed: right skips the disabled option.
    assert_eq!(s.handle_key_at(k("right"), t0), WidgetOutcome::Changed);
    assert_eq!(s.index(), 2);
    assert_eq!(s.handle_key_at(k("h"), t0), WidgetOutcome::Changed);
    assert_eq!(s.index(), 0);
    assert_eq!(s.handle_key_at(k("down"), t0), WidgetOutcome::Ignored);
    // Open; down skips the disabled option.
    assert_eq!(s.handle_key_at(k("space"), t0), WidgetOutcome::Consumed);
    assert!(s.is_open());
    s.handle_key_at(k("j"), t0);
    s.handle_key_at(k("enter"), t0);
    assert_eq!(s.index(), 2);
    assert!(!s.is_open());
    // Type-to-jump: "bl" within a second, then "c" after the buffer reset.
    s.handle_key_at(k("alt-down"), t0);
    s.handle_key_at(k("b"), t0);
    s.handle_key_at(k("l"), t0 + Duration::from_millis(500));
    s.handle_key_at(k("enter"), t0 + Duration::from_millis(600));
    assert_eq!(s.value(), Some(&"bl"));
    s.handle_key_at(k("space"), t0);
    s.handle_key_at(k("c"), t0);
    s.handle_key_at(k("h"), t0 + Duration::from_millis(1100));
    // "ch" would be cherry too; after the reset "h" alone matches nothing.
    s.handle_key_at(k("enter"), t0 + Duration::from_millis(1200));
    assert_eq!(s.value(), Some(&"c"));
    // "apr" never lands on the disabled apricot: the cursor stays on apple.
    s.handle_key_at(k("space"), t0);
    for c in ["a", "p", "r"] {
        s.handle_key_at(k(c), t0);
    }
    s.handle_key_at(k("enter"), t0);
    assert_eq!(
        s.value(),
        Some(&"a"),
        "only apricot matches `apr`, disabled"
    );
    // Esc closes without change; End/Home.
    s.handle_key_at(k("space"), t0);
    s.handle_key_at(k("end"), t0);
    assert_eq!(s.handle_key_at(k("esc"), t0), WidgetOutcome::Consumed);
    assert_eq!(s.value(), Some(&"a"));
    s.handle_key_at(k("space"), t0);
    s.handle_key_at(k("end"), t0);
    s.handle_key_at(k("enter"), t0);
    assert_eq!(s.value(), Some(&"c"));
}

#[test]
fn radio_group_vertical_and_horizontal() {
    let mut r = RadioGroup::new(&["Ask", "Overwrite", "Skip"]).disable(1);
    assert_eq!(r.handle_key(k("down")), WidgetOutcome::Changed);
    assert_eq!(r.value(), 2, "disabled option skipped");
    assert_eq!(r.handle_key(k("j")), WidgetOutcome::Consumed);
    assert_eq!(r.handle_key(k("k")), WidgetOutcome::Changed);
    assert_eq!(r.value(), 0);
    assert_eq!(r.height(20), 3);
    let (screen, _) = draw(&r, 20, 3, false);
    assert!(screen.starts_with("(•) Ask"), "{screen}");
    let mut h = RadioGroup::new(&["Auto", "ASCII", "Binary"]).horizontal();
    assert_eq!(h.handle_key(k("down")), WidgetOutcome::Ignored);
    assert_eq!(h.handle_key(k("right")), WidgetOutcome::Changed);
    assert_eq!(h.handle_key(k("l")), WidgetOutcome::Changed);
    assert_eq!(h.value(), 2);
    assert_eq!(h.height(40), 1);
    assert!(
        draw(&h, 40, 1, false)
            .0
            .starts_with("( ) Auto  ( ) ASCII  (•) Binary")
    );
}

fn sections() -> ListView<String> {
    ListView::new(vec![
        ListRow::Header("Local".into()),
        ListRow::check("alpha", "a".into(), false),
        ListRow::check("beta", "b".into(), true),
        ListRow::Header("Remote".into()),
        ListRow::check("gamma", "c".into(), false),
    ])
}

#[test]
fn list_view_sections_filter_marks_reorder() {
    let mut l = sections().reorderable(true);
    assert_eq!(
        l.cursor_value().map(String::as_str),
        Some("a"),
        "header skipped"
    );
    l.handle_key(k("j"));
    l.handle_key(k("j"));
    assert_eq!(
        l.cursor_value().map(String::as_str),
        Some("c"),
        "header skipped"
    );
    l.handle_key(k("k"));
    assert_eq!(l.cursor_value().map(String::as_str), Some("b"));
    l.handle_key(k("home"));
    assert_eq!(l.cursor_value().map(String::as_str), Some("a"));
    l.handle_key(k("end"));
    assert_eq!(l.cursor_value().map(String::as_str), Some("c"));
    // Checkboxes.
    assert_eq!(l.handle_key(k("space")), WidgetOutcome::Changed);
    assert_eq!(l.checked(), [false, true, true]);
    assert_eq!(l.handle_key(k("enter")), WidgetOutcome::Activated);
    // Filter.
    l.handle_key(k("/"));
    assert!(l.is_text());
    for c in "ALP".chars() {
        l.handle_key(KeyChord::char(c));
    }
    l.handle_key(k("enter"));
    assert_eq!(l.filter(), "ALP");
    assert_eq!(l.cursor_value().map(String::as_str), Some("a"));
    let (screen, _) = draw(&l, 20, 4, true);
    assert!(screen.contains("[ ] alpha"), "{screen}");
    assert!(!screen.contains("gamma"), "{screen}");
    assert!(screen.contains("/ALP"), "{screen}");
    l.handle_key(k("esc"));
    assert_eq!(l.filter(), "");
    // Reorder: beta moves above alpha; never across a header.
    l.handle_key(k("home"));
    l.handle_key(k("j"));
    assert_eq!(l.handle_key(k("K")), WidgetOutcome::Changed);
    let order: Vec<_> = l
        .rows()
        .iter()
        .filter_map(|r| match r {
            ListRow::Item { value, .. } => Some(value.as_str()),
            ListRow::Header(_) => None,
        })
        .collect();
    assert_eq!(order, ["b", "a", "c"]);
    assert_eq!(
        l.handle_key(k("K")),
        WidgetOutcome::Consumed,
        "header above"
    );
    // Marks.
    let mut m = ListView::new(vec![
        ListRow::item("one", 1),
        ListRow::item("two", 2),
        ListRow::item("three", 3),
    ])
    .markable(true);
    m.handle_key(k("space"));
    m.handle_key(k("j"));
    m.handle_key(k("space"));
    assert_eq!(m.marked(), [&1, &3]);
    // 1 000 000 rows: only the visible ones are drawn.
    let rows: Vec<ListRow<u32>> = (0..1_000_000)
        .map(|i| ListRow::item(&format!("row {i}"), i))
        .collect();
    let mut big = ListView::new(rows).visible_rows(10);
    big.handle_key(k("end"));
    let start = std::time::Instant::now();
    let (screen, _) = draw(&big, 30, 10, true);
    assert!(screen.contains("row 999999"), "{screen}");
    assert!(!screen.contains("row 0 "), "{screen}");
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn paste_single_line_rules() {
    let mut t = TextInput::new("");
    assert_eq!(
        t.handle_paste("a\r\nb\tc\x1b[31m\n"),
        WidgetOutcome::Changed
    );
    assert_eq!(t.value(), "a b c[31m");
    assert_eq!(clean_single_line("x\ry\n\nz\r\n\r\n"), "x y  z");
    assert_eq!(clean_single_line("\u{7f}a\u{85}b\u{9b}"), "ab");
    // Inserted at the cursor.
    let mut t = TextInput::new("[]");
    t.set_cursor(1);
    t.handle_paste("x\n");
    assert_eq!((t.value(), t.cursor_index()), ("[x]", 2));
    // Buttons and lists ignore pastes.
    let mut b = ButtonRow::new(vec![Button::new("ok", "OK", ButtonRole::Default)]);
    assert_eq!(b.handle_paste("x"), WidgetOutcome::Ignored);
}

#[test]
fn paste_text_area_rules() {
    let mut a = TextArea::new("");
    a.handle_paste("a\r\nb\tc\x1b[31m\n");
    assert_eq!(a.lines(), ["a", "b    c[31m"]);
    assert_eq!(clean_multi_line("1\r2\r\n3\u{7}"), "1\n2\n3");
    // Editing keys and line handling.
    let mut a = TextArea::new("one\ntwo");
    assert_eq!(a.cursor_pos(), (1, 3));
    a.handle_key(k("home"));
    a.handle_key(k("backspace"));
    assert_eq!(a.value(), "onetwo");
    a.handle_key(k("enter"));
    assert_eq!(a.lines(), ["one", "two"]);
    a.handle_key(k("up"));
    a.handle_key(k("end"));
    a.handle_key(k("delete"));
    assert_eq!(a.value(), "onetwo");
    assert_eq!(a.handle_key(k("tab")), WidgetOutcome::Ignored, "tab leaves");
}

#[test]
fn paste_truncation_message() {
    let mut t = TextInput::new("").max_chars(5);
    t.handle_paste("abcdefgh");
    assert_eq!(t.value(), "abcde");
    assert_eq!(
        t.take_notice(),
        Some(Notice::Status("Pasted text was cut to 5 characters".into()))
    );
    assert_eq!(t.take_notice(), None);
    let mut a = TextArea::new(&"x".repeat(65530));
    a.handle_paste("0123456789");
    assert_eq!(a.value().len(), 65536);
    assert_eq!(
        a.take_notice(),
        Some(Notice::Status("Pasted text was cut to 6 characters".into()))
    );
}

#[test]
fn text_view_scroll_and_search() {
    let text: String = (0..100).map(|i| format!("line {i}\n")).collect();
    let mut v = TextView::new(&text);
    assert_eq!(v.lines().len(), 100);
    let (screen, _) = draw(&v, 20, 5, true);
    assert!(screen.starts_with("line 0"), "{screen}");
    v.handle_key(k("j"));
    v.handle_key(k("pagedown"));
    assert_eq!(v.scroll().0, 5);
    v.handle_key(k("/"));
    for c in "LINE 42".chars() {
        v.handle_key(KeyChord::char(c));
    }
    v.handle_key(k("enter"));
    assert_eq!(v.scroll().0, 42);
    v.handle_key(k("n"));
    assert_eq!(v.scroll().0, 42, "only one match");
    v.handle_key(k("end"));
    let (screen, _) = draw(&v, 20, 5, true);
    assert!(screen.contains("line 99"), "{screen}");
    v.handle_key(k("l"));
    assert_eq!(v.scroll().1, 4);
    // Untrusted content is sanitised.
    let v = TextView::new("a\x1b]52;c;x\x07b");
    assert_eq!(v.lines(), ["a^[]52;c;x^Gb"]);
}

#[test]
fn button_row_keys_and_mnemonics() {
    let mut b = ButtonRow::new(vec![
        Button::new("ok", "OK", ButtonRole::Default),
        Button::new("cancel", "Cancel", ButtonRole::Normal),
    ]);
    assert_eq!(b.focused_id(), Some("ok"));
    b.handle_key(k("l"));
    assert_eq!(b.focused_id(), Some("cancel"));
    assert_eq!(b.handle_key(k("enter")), WidgetOutcome::Activated);
    assert_eq!(
        b.mnemonic(k("o"), false),
        None,
        "plain letters need permission"
    );
    assert_eq!(b.mnemonic(k("o"), true), Some(0));
    assert_eq!(b.mnemonic(k("alt-c"), false), Some(1));
    assert_eq!(b.mnemonic(k("ctrl-c"), true), None);
    let (screen, _) = draw(&b, 20, 1, true);
    assert!(screen.contains("[ OK ]  [ Cancel ]"), "{screen}");
}

proptest! {
    #[test]
    fn prop_text_input_never_panics(
        ops in proptest::collection::vec(
            prop_oneof![
                any::<char>().prop_map(|c| (Some(KeyChord::char(c)), None)),
                proptest::sample::select(vec![
                    "left", "right", "home", "end", "backspace", "delete", "ctrl-w", "alt-d",
                    "ctrl-u", "ctrl-k", "ctrl-left", "ctrl-right", "alt-b", "alt-f",
                    "alt-backspace", "ctrl-a", "ctrl-e",
                ]).prop_map(|s| (Some(k(s)), None)),
                any::<String>().prop_map(|s| (None, Some(s))),
            ],
            0..60,
        ),
        max in 1usize..50,
    ) {
        let mut t = TextInput::new("").max_chars(max);
        let mut a = TextArea::new("");
        for (key, paste) in ops {
            if let Some(key) = key {
                t.handle_key(key);
                a.handle_key(key);
            }
            if let Some(p) = paste {
                t.handle_paste(&p);
                a.handle_paste(&p);
            }
            let n = super::text_input::grapheme_len(t.value());
            prop_assert!(t.cursor_index() <= n);
            prop_assert!(t.value().chars().count() <= max);
            prop_assert!(!t.value().chars().any(is_control));
        }
        let _ = draw(&t, 7, 1, true);
        let _ = draw(&a, 7, 3, true);
    }

    #[test]
    fn prop_paste_single_line_has_no_controls(s in any::<String>()) {
        let out = clean_single_line(&s);
        prop_assert!(!out.chars().any(is_control), "{out:?}");
        let multi = clean_multi_line(&s);
        prop_assert!(!multi.chars().any(|c| c != '\n' && is_control(c)), "{multi:?}");
    }
}
