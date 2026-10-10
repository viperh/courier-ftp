//! Unit tests of the message log (T55).

use std::{collections::BTreeMap, sync::Arc};

use courier_ftp_core::{
    events::{CoreEvent, LogKind, LogMessage, SessionId, SessionPurpose},
    model::ServerAddress,
    settings::LoggingSettings,
};
use pretty_assertions::assert_eq;
use proptest::prelude::*;
use ratatui::{
    Terminal,
    backend::TestBackend,
    buffer::Buffer,
    style::{Color, Modifier},
};
use time::{OffsetDateTime, macros::datetime};

use super::{
    render::{Columns, Matcher, TagMode, wrap_ranges},
    store::{LineOrigin, MAX_LINE_CHARS},
    *,
};
use crate::{
    components::{Component, DrawCx},
    tabs::TabRoute,
    ui::{
        clipboard::{
            Clipboard, LocalClipboard,
            fakes::{FakeLocal, SharedOut},
        },
        symbols::Symbols,
        theme::{Theme, ThemePreset},
    },
};

pub(super) const T0: OffsetDateTime = datetime!(2026-10-10 12:00:01 UTC);

pub(super) fn msg(session: SessionId, kind: LogKind, text: &str) -> LogMessage {
    LogMessage {
        time: T0,
        session,
        kind,
        text: text.to_owned(),
    }
}

pub(super) fn log_event(session: SessionId, kind: LogKind, text: &str) -> CoreEvent {
    CoreEvent::Log(msg(session, kind, text))
}

fn ok<T, E: std::fmt::Debug>(r: Result<T, E>) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{e:?}"),
    }
}

fn address(url: &str) -> ServerAddress {
    ok(url.parse::<ServerAddress>())
}

/// A pane with a fake clipboard (the tool records, the writer collects OSC 52).
pub(super) fn pane_with(capacity: u32) -> (MessageLogPane, SharedOut, FakeLocal) {
    let out = SharedOut::default();
    let local = FakeLocal::default();
    let clip = Clipboard::new(
        false,
        Some(Box::new(local.clone()) as Box<dyn LocalClipboard>),
        Box::new(out.clone()),
    )
    .into_handle();
    let logging = LoggingSettings {
        pane_max_lines: capacity,
        ..LoggingSettings::default()
    };
    (MessageLogPane::new(clip, &logging), out, local)
}

pub(super) fn pane() -> MessageLogPane {
    pane_with(5000).0
}

pub(super) fn theme(no_color: bool) -> Theme {
    Theme::load(ThemePreset::Default, &BTreeMap::new(), no_color).0
}

/// Draws the pane alone into `w`×`h`.
pub(super) fn draw_buf(
    p: &mut MessageLogPane,
    w: u16,
    h: u16,
    focused: bool,
    mono_ascii: bool,
) -> Buffer {
    let theme = theme(mono_ascii);
    let symbols = if mono_ascii {
        Symbols::ascii()
    } else {
        Symbols::unicode()
    };
    let mut terminal = match Terminal::new(TestBackend::new(w, h)) {
        Ok(t) => t,
        Err(e) => match e {},
    };
    let cx = DrawCx {
        theme: &theme,
        symbols: &symbols,
        focused,
        now: tokio::time::Instant::now(),
        spinner: None,
    };
    if let Err(e) = terminal.draw(|f| {
        if let Err(e) = p.draw(f, f.area(), &cx) {
            panic!("draw: {e}");
        }
    }) {
        match e {}
    }
    terminal.backend().buffer().clone()
}

fn draw(p: &mut MessageLogPane, w: u16, h: u16) -> String {
    crate::testing::buffer_to_string(&draw_buf(p, w, h, false, false))
}

fn feed(p: &mut MessageLogPane, ev: &CoreEvent) {
    ok(p.on_core_event(ev));
}

fn act(p: &mut MessageLogPane, a: Action) -> Option<Action> {
    ok(p.update(&a))
}

fn push_n(p: &mut MessageLogPane, n: usize) {
    for i in 0..n {
        feed(
            p,
            &log_event(SessionId::APP, LogKind::Status, &format!("line {i}")),
        );
    }
}

fn texts(store: &LogStore, scope: LogScope) -> Vec<String> {
    store
        .lines(scope)
        .iter()
        .map(|l| l.text.to_string())
        .collect()
}

fn tab(n: u32) -> LogScope {
    LogScope::Tab(TabId(n))
}

// ---------------------------------------------------------------- store

#[test]
fn push_stores_sanitised_text() {
    let mut s = LogStore::new(10);
    s.push(
        msg(SessionId::APP, LogKind::Response, "a\x1b[31mb\x7f"),
        TabId::FIRST,
    );
    s.push(
        msg(SessionId::APP, LogKind::Response, "\u{202e}txt.exe"),
        TabId::FIRST,
    );
    s.push(msg(SessionId::APP, LogKind::Status, "a\tb"), TabId::FIRST);
    assert_eq!(
        texts(&s, LogScope::All),
        ["a^[[31mb^?", "<U+202E>txt.exe", "a    b"]
    );
    assert_eq!(s.lines(LogScope::All)[0].session, SessionId::APP);
}

/// Step 2: T50's `ui::text` helpers on escape-heavy server replies.
#[test]
fn ui_text_helpers_on_escape_heavy_replies() {
    use crate::ui::text::{sanitize, sanitize_spans, truncate_to_width, width};
    let reply = "220-\x1b]0;pwned\x07Welcome\x1b[2J\r\n\u{9b}31m\u{2066}evil\u{2069}";
    let clean = sanitize(reply);
    assert_eq!(
        clean,
        "220-^[]0;pwned^GWelcome^[[2J^M^J<U+009B>31m<U+2066>evil<U+2069>"
    );
    let spans = sanitize_spans(
        reply,
        ratatui::style::Style::default(),
        ratatui::style::Style::default().add_modifier(Modifier::DIM),
    );
    let joined: String = spans.iter().map(|s| s.content.as_ref()).collect();
    assert_eq!(joined, clean);
    let cut = truncate_to_width(&clean, 12, "…");
    assert_eq!(cut, "220-^[]0;pw…");
    assert_eq!(width(&cut), 12);
}

#[test]
fn ring_drops_oldest_at_capacity() {
    let mut s = LogStore::new(3);
    for i in 0..5 {
        s.push(
            msg(SessionId::APP, LogKind::Status, &format!("l{i}")),
            TabId::FIRST,
        );
    }
    assert_eq!(texts(&s, LogScope::All), ["l2", "l3", "l4"]);
    assert_eq!(texts(&s, tab(0)), ["l2", "l3", "l4"]);
    assert_eq!(s.len(LogScope::All), 3);
    assert_eq!(s.capacity(), 3);
    s.set_capacity(2);
    assert_eq!(texts(&s, LogScope::All), ["l3", "l4"]);
}

#[test]
fn long_line_is_capped_with_suffix() {
    let mut s = LogStore::new(3);
    let long = "x".repeat(MAX_LINE_CHARS + 10);
    s.push(msg(SessionId::APP, LogKind::Status, &long), TabId::FIRST);
    let stored = &s.lines(LogScope::All)[0].text;
    assert_eq!(
        stored.as_ref(),
        format!("{} … [10 more characters]", "x".repeat(MAX_LINE_CHARS))
    );
    // Exactly the limit: not cut.
    let exact = "é".repeat(MAX_LINE_CHARS);
    s.push(msg(SessionId::APP, LogKind::Status, &exact), TabId::FIRST);
    assert_eq!(s.lines(LogScope::All)[1].text.as_ref(), exact);
}

#[test]
fn routes_browsing_session_to_its_tab() {
    let mut s = LogStore::new(10);
    let a = SessionId::next();
    let b = SessionId::next();
    s.set_tab_route(
        TabId(0),
        TabRoute {
            browsing: Some(a),
            server: None,
        },
    );
    s.set_tab_route(
        TabId(1),
        TabRoute {
            browsing: Some(b),
            server: None,
        },
    );
    s.push(msg(a, LogKind::Command, "PWD"), TabId(1));
    s.push(msg(b, LogKind::Command, "LIST"), TabId(0));
    assert_eq!(texts(&s, tab(0)), ["PWD"]);
    assert_eq!(texts(&s, tab(1)), ["LIST"]);
    assert_eq!(texts(&s, LogScope::All), ["PWD", "LIST"]);
    assert_eq!(s.lines(LogScope::All)[0].origin, LineOrigin::Tab(TabId(0)));
    assert_eq!(s.lines(LogScope::All)[1].origin, LineOrigin::Tab(TabId(1)));
    // Lines are shared, not copied.
    assert!(Arc::ptr_eq(&s.lines(LogScope::All)[0], &s.lines(tab(0))[0]));
}

#[test]
fn routes_transfer_session_by_server_identity() {
    let mut s = LogStore::new(10);
    let browse = SessionId::next();
    let transfer = SessionId::next();
    let addr = address("sftp://deploy@Web01.Example.com");
    s.on_connected(browse, &addr);
    s.set_tab_route(
        TabId(0),
        TabRoute {
            browsing: Some(browse),
            server: Some(ServerKey::from(&addr)),
        },
    );
    s.on_session_opened(transfer, SessionPurpose::Transfer);
    // Same server, written differently (host case, explicit default port).
    s.on_connected(transfer, &address("sftp://deploy@web01.example.com:22"));
    s.push(msg(transfer, LogKind::Status, "Starting upload"), TabId(3));
    assert_eq!(texts(&s, tab(0)), ["Starting upload"]);
    assert_eq!(s.len(tab(3)), 0);
    assert_eq!(s.lines(LogScope::All)[0].origin, LineOrigin::Transfer);
    // After the transfer session disconnects its lines are unrelated.
    s.on_disconnected(transfer);
    s.push(msg(transfer, LogKind::Status, "late"), TabId(3));
    assert_eq!(texts(&s, tab(3)), ["late"]);
    s.on_session_closed(transfer);
    s.push(msg(transfer, LogKind::Status, "later"), TabId(3));
    assert_eq!(s.lines(LogScope::All)[2].origin, LineOrigin::App);
}

#[test]
fn unknown_session_goes_to_all_and_active_tab() {
    let mut s = LogStore::new(10);
    s.set_tab_route(
        TabId(0),
        TabRoute {
            browsing: Some(SessionId::next()),
            server: None,
        },
    );
    let scopes = s.push(msg(SessionId::next(), LogKind::Error, "who am I"), TabId(2));
    assert_eq!(scopes, [LogScope::All, tab(2)]);
    assert_eq!(texts(&s, tab(2)), ["who am I"]);
    assert_eq!(s.len(tab(0)), 0);
    assert_eq!(s.lines(LogScope::All)[0].origin, LineOrigin::App);
}

#[test]
fn remove_tab_drops_its_ring() {
    let mut s = LogStore::new(10);
    s.push(msg(SessionId::APP, LogKind::Status, "x"), TabId(1));
    assert_eq!(s.len(tab(1)), 1);
    s.remove_tab(TabId(1));
    assert_eq!(s.len(tab(1)), 0);
    assert_eq!(s.len(LogScope::All), 1);
    s.clear(LogScope::All);
    assert_eq!(s.len(LogScope::All), 0);
}

// ---------------------------------------------------------------- layout

#[test]
fn wrap_breaks_at_spaces_and_hard_breaks_long_words() {
    let mut out = Vec::new();
    let text = "the quick brown fox";
    wrap_ranges(text, 10, &mut out);
    let rows: Vec<&str> = out.iter().map(|r| &text[r.clone()]).collect();
    assert_eq!(rows, ["the quick", "brown fox"]);
    let text = "abcdefghijklmnopqrstuvwxyz end";
    wrap_ranges(text, 10, &mut out);
    let rows: Vec<&str> = out.iter().map(|r| &text[r.clone()]).collect();
    assert_eq!(rows, ["abcdefghij", "klmnopqrst", "uvwxyz end"]);
    wrap_ranges("", 10, &mut out);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0], 0..0);
    let text = "日本語テキスト";
    wrap_ranges(text, 5, &mut out);
    let rows: Vec<&str> = out.iter().map(|r| &text[r.clone()]).collect();
    assert_eq!(rows, ["日本", "語テ", "キス", "ト"]);
}

#[test]
fn narrow_rules_shorten_tag_time_prefix() {
    let c = Columns::new(100, true, true);
    assert_eq!(
        (c.time, c.tag, c.short_prefix, c.text_col),
        (true, TagMode::Full, false, 23)
    );
    let c = Columns::new(65, true, true);
    assert_eq!(
        (c.time, c.tag, c.short_prefix, c.text_col),
        (true, TagMode::Short, false, 21)
    );
    let c = Columns::new(55, true, true);
    assert_eq!(
        (c.time, c.tag, c.short_prefix, c.text_col),
        (false, TagMode::Short, false, 12)
    );
    let c = Columns::new(40, true, true);
    assert_eq!(
        (c.time, c.tag, c.short_prefix, c.text_col),
        (false, TagMode::Short, true, 5)
    );
    let c = Columns::new(40, false, true);
    assert_eq!((c.tag, c.text_col), (TagMode::None, 3));

    // Drawn: a 40-column pane shows `S: text`, no time.
    let mut p = pane();
    feed(&mut p, &log_event(SessionId::APP, LogKind::Status, "hello"));
    let screen = draw(&mut p, 42, 5);
    assert!(screen.contains("│S: hello"), "{screen}");
    // Too narrow: border only, no panic.
    let screen = draw(&mut p, 13, 5);
    assert!(!screen.contains("hello"), "{screen}");
    let _ = draw(&mut p, 30, 2);
}

#[test]
fn warning_status_line_uses_warning_style() {
    let mut s = LogStore::new(10);
    s.push(
        msg(SessionId::APP, LogKind::Status, "Warning: clock skew"),
        TabId::FIRST,
    );
    s.push(
        msg(SessionId::APP, LogKind::Status, "Warnings"),
        TabId::FIRST,
    );
    let l = s.lines(LogScope::All);
    assert_eq!(LogStyles::key_for(&l[0]), "log.warning");
    assert_eq!(LogStyles::key_for(&l[1]), "log.status");
    let t = theme(false);
    let styles = log_styles(&t);
    assert_eq!(styles.for_line(&l[0]), t.style("log.warning"));
    assert_eq!(styles.for_line(&l[0]).fg, Some(Color::Indexed(3)));
}

/// AC2: each kind's row uses its style key; with `NO_COLOR` error is bold, trace dim,
/// and no cell has a colour.
#[test]
fn style_keys_per_kind_and_no_color() {
    let kinds = [
        (LogKind::Status, "plain status"),
        (LogKind::Status, "Warning: careful"),
        (LogKind::Command, "LIST"),
        (LogKind::Response, "226 ok"),
        (LogKind::Error, "boom"),
        (LogKind::Debug(3), "trace"),
        (LogKind::ListingRaw, "drwxr-xr-x"),
    ];
    let mut p = pane();
    for (k, t) in kinds {
        feed(&mut p, &log_event(SessionId::APP, k, t));
    }
    let lines: Vec<_> = p.store().lines(p.view().scope).iter().cloned().collect();
    for no_color in [false, true] {
        let th = theme(no_color);
        let buf = draw_buf(&mut p, 80, 12, false, no_color);
        for (row, line) in lines.iter().enumerate() {
            let y = u16::try_from(row + 1).unwrap_or(0);
            // Column 10 (inside the border, after `HH:MM:SS `) is the prefix's first cell.
            let cell = &buf[(10, y)];
            assert_eq!(
                cell.style().fg.unwrap_or(Color::Reset),
                th.style(LogStyles::key_for(line))
                    .fg
                    .unwrap_or(Color::Reset),
                "row {row}"
            );
            assert_eq!(
                cell.style().add_modifier,
                th.style(LogStyles::key_for(line)).add_modifier,
                "row {row}"
            );
            // The timestamp uses log.time.
            assert_eq!(
                buf[(1, y)].style().add_modifier,
                th.style("log.time").add_modifier
            );
        }
        if no_color {
            let error = &buf[(10, 5)];
            assert!(error.style().add_modifier.contains(Modifier::BOLD));
            let trace = &buf[(10, 6)];
            assert!(trace.style().add_modifier.contains(Modifier::DIM));
            for c in buf.content() {
                assert!(
                    matches!(c.fg, Color::Reset) && matches!(c.bg, Color::Reset),
                    "{c:?}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------- scrolling

#[test]
fn follow_keeps_bottom_and_scroll_up_counts_unseen() {
    let mut p = pane();
    push_n(&mut p, 30);
    let screen = draw(&mut p, 40, 7);
    // 5 body rows, the newest line on the last one.
    assert!(
        screen.lines().nth(5).is_some_and(|l| l.contains("line 29")),
        "{screen}"
    );
    assert!(p.view().follow);
    push_n(&mut p, 1);
    assert_eq!(p.view().unseen, 0);
    let screen = draw(&mut p, 40, 7);
    assert!(screen.lines().nth(5).is_some_and(|l| l.contains("line 0")));

    // Scroll up: follow stops at the bottom line, new lines are counted.
    act(&mut p, Action::LogCursorUp);
    assert!(!p.view().follow);
    assert!(p.view().anchor_seq.is_some());
    for i in 0..3 {
        feed(
            &mut p,
            &log_event(SessionId::APP, LogKind::Status, &format!("new {i}")),
        );
    }
    assert_eq!(p.view().unseen, 3);
    let screen = draw(&mut p, 40, 7);
    assert!(screen.contains("▼ 3 new"), "{screen}");
    assert!(!screen.contains("new 2"), "{screen}");
}

#[test]
fn g_resumes_follow() {
    let mut p = pane();
    push_n(&mut p, 30);
    let _ = draw(&mut p, 40, 7);
    act(&mut p, Action::LogTop);
    assert!(!p.view().follow);
    let screen = draw(&mut p, 40, 7);
    assert!(
        screen.lines().nth(1).is_some_and(|l| l.contains("line 0 ")),
        "{screen}"
    );
    push_n(&mut p, 2);
    assert_eq!(p.view().unseen, 2);
    act(&mut p, Action::LogBottom);
    assert!(p.view().follow);
    assert_eq!(p.view().unseen, 0);
    let screen = draw(&mut p, 40, 7);
    assert!(
        screen.lines().nth(5).is_some_and(|l| l.contains("line 1")),
        "{screen}"
    );
    assert!(!screen.contains("new"), "{screen}");
}

#[test]
fn cursor_moves_and_scrolls_into_view() {
    let mut p = pane();
    push_n(&mut p, 30);
    let _ = draw_buf(&mut p, 40, 7, true, false);
    // Focus puts the cursor on the bottom visible line.
    assert_eq!(p.view().cursor_seq, Some(29));
    for _ in 0..7 {
        act(&mut p, Action::LogCursorUp);
    }
    assert_eq!(p.view().cursor_seq, Some(22));
    let screen = draw(&mut p, 40, 7);
    assert!(
        screen.lines().nth(1).is_some_and(|l| l.contains("line 22")),
        "{screen}"
    );
    act(&mut p, Action::LogPageUp);
    assert_eq!(p.view().cursor_seq, Some(17));
    act(&mut p, Action::LogHalfPageDown);
    assert_eq!(p.view().cursor_seq, Some(19));
    act(&mut p, Action::LogTop);
    assert_eq!(p.view().cursor_seq, Some(0));
    act(&mut p, Action::LogCursorUp);
    assert_eq!(p.view().cursor_seq, Some(0));
    act(&mut p, Action::LogPageDown);
    let screen = draw(&mut p, 40, 7);
    assert!(screen.contains("line 5"), "{screen}");
}

#[test]
fn anchor_moves_to_oldest_when_evicted() {
    let (mut p, ..) = pane_with(10);
    push_n(&mut p, 10);
    let _ = draw(&mut p, 40, 7);
    act(&mut p, Action::LogTop);
    let anchor = p.view().anchor_seq;
    assert!(anchor.is_some_and(|a| a < 10));
    push_n(&mut p, 9);
    let oldest = p.store().lines(p.view().scope).front().map(|l| l.seq);
    assert_eq!(oldest, Some(9));
    assert_eq!(p.view().anchor_seq, oldest);
    assert_eq!(p.view().cursor_seq, oldest);
    let screen = draw(&mut p, 40, 7);
    assert!(screen.contains("line 9"), "{screen}");
}

// ---------------------------------------------------------------- search

#[test]
fn search_smart_case() {
    let m = Matcher::new("abc").unwrap_or_else(|| panic!("matcher"));
    assert!(m.is_match("xxABCxx"));
    assert_eq!(m.ranges("aBc abc"), [0..3, 4..7]);
    let m = Matcher::new("Abc").unwrap_or_else(|| panic!("matcher"));
    assert!(!m.is_match("abc"));
    assert!(m.is_match("xAbc"));
    let m = Matcher::new("straße").unwrap_or_else(|| panic!("matcher"));
    assert!(m.is_match("STRAßE ok"));
    let r = m.ranges("é STRAßE");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0], 3..10);
    assert!(Matcher::new("").is_none());

    let mut p = pane();
    for t in ["550 Failed", "550 failed", "226 ok", "FAILED"] {
        feed(&mut p, &log_event(SessionId::APP, LogKind::Response, t));
    }
    let _ = draw_buf(&mut p, 60, 10, true, false);
    act(&mut p, Action::LogSearch);
    assert_eq!(p.key_mode(), Mode::Input);
    for c in "failed".chars() {
        ok(p.handle_key(KeyChord::char(c)));
    }
    assert_eq!(p.view().search.as_ref().map(|s| s.total), Some(3));
    for c in [KeyCode::Backspace; 6] {
        ok(p.handle_key(KeyChord::key(c)));
    }
    for c in "Failed".chars() {
        ok(p.handle_key(KeyChord::char(c)));
    }
    assert_eq!(p.view().search.as_ref().map(|s| s.total), Some(1));
    ok(p.handle_key(KeyChord::key(KeyCode::Enter)));
    assert_eq!(p.key_mode(), Mode::Log);
    assert_eq!(p.view().cursor_seq, Some(0));
    let screen = draw(&mut p, 60, 10);
    assert!(screen.contains("/Failed  match 1 of 1"), "{screen}");
    // Esc clears the search.
    act(&mut p, Action::Escape);
    let _ = draw_buf(&mut p, 60, 10, true, false);
    act(&mut p, Action::Escape);
    assert!(p.view().search.is_none());
}

#[test]
fn search_next_prev_wrap() {
    let mut p = pane();
    for i in 0..10 {
        let t = if i % 3 == 0 {
            format!("{i} hit")
        } else {
            format!("{i} miss")
        };
        feed(&mut p, &log_event(SessionId::APP, LogKind::Status, &t));
    }
    let _ = draw_buf(&mut p, 60, 6, true, false);
    act(&mut p, Action::LogSearch);
    for c in "hit".chars() {
        ok(p.handle_key(KeyChord::char(c)));
    }
    ok(p.handle_key(KeyChord::key(KeyCode::Enter)));
    let cur = |p: &MessageLogPane| p.view().search.as_ref().and_then(|s| s.current);
    let idx = |p: &MessageLogPane| p.view().search.as_ref().map(|s| (s.index, s.total));
    assert_eq!(cur(&p), Some(9));
    assert_eq!(idx(&p), Some((4, 4)));
    act(&mut p, Action::LogSearchNext);
    assert_eq!(cur(&p), Some(6));
    assert_eq!(p.view().cursor_seq, Some(6));
    assert!(!p.view().follow);
    act(&mut p, Action::LogSearchNext);
    act(&mut p, Action::LogSearchNext);
    assert_eq!(cur(&p), Some(0));
    assert_eq!(idx(&p), Some((1, 4)));
    act(&mut p, Action::LogSearchNext);
    assert_eq!(cur(&p), Some(9));
    assert!(p.view().search.as_ref().is_some_and(|s| s.wrapped));
    let screen = draw(&mut p, 60, 6);
    assert!(screen.contains("match 4 of 4 (search wrapped)"), "{screen}");
    act(&mut p, Action::LogSearchPrev);
    assert_eq!(cur(&p), Some(0));
    assert!(p.view().search.as_ref().is_some_and(|s| s.wrapped));
    act(&mut p, Action::LogSearchPrev);
    assert_eq!(cur(&p), Some(3));
    assert!(p.view().search.as_ref().is_some_and(|s| !s.wrapped));
}

#[test]
fn search_count_is_debounced_on_large_rings() {
    let (mut p, ..) = pane_with(30_000);
    push_n(&mut p, 25_000);
    act(&mut p, Action::LogSearch);
    ok(p.handle_key(KeyChord::char('9')));
    assert!(p.count_due.is_some());
    assert!(draw(&mut p, 60, 6).contains("counting…"));
    // Enter counts at once.
    ok(p.handle_key(KeyChord::key(KeyCode::Enter)));
    assert!(p.count_due.is_none());
    assert!(p.view().search.as_ref().is_some_and(|s| s.total > 0));
}

#[test]
fn kind_filter_errors_only_hides_other_kinds() {
    let mut p = pane();
    feed(
        &mut p,
        &log_event(SessionId::APP, LogKind::Status, "status"),
    );
    feed(&mut p, &log_event(SessionId::APP, LogKind::Error, "bad"));
    feed(
        &mut p,
        &log_event(SessionId::APP, LogKind::Debug(2), "trace"),
    );
    act(&mut p, Action::LogCycleKindFilter);
    let screen = draw(&mut p, 60, 6);
    assert!(screen.contains("[no trace]"), "{screen}");
    assert!(
        screen.contains("status") && !screen.contains("Trace:"),
        "{screen}"
    );
    act(&mut p, Action::LogCycleKindFilter);
    let screen = draw(&mut p, 60, 6);
    assert!(screen.contains("[errors only]"), "{screen}");
    assert!(
        screen.contains("bad") && !screen.contains("status"),
        "{screen}"
    );
    // Lines stay in the ring.
    assert_eq!(p.store().len(p.view().scope), 3);
    act(&mut p, Action::LogCycleKindFilter);
    assert!(draw(&mut p, 60, 6).contains("Trace:"));
}

// ---------------------------------------------------------------- copy, clear, scope

#[test]
fn copy_visual_range_formats_displayed_text() {
    let (mut p, out, local) = pane_with(100);
    feed(
        &mut p,
        &log_event(SessionId::APP, LogKind::Command, "USER alice"),
    );
    feed(
        &mut p,
        &log_event(SessionId::APP, LogKind::Response, "331 Password"),
    );
    feed(
        &mut p,
        &log_event(SessionId::APP, LogKind::Command, "PASS ****"),
    );
    let _ = draw_buf(&mut p, 80, 10, true, false);
    // One line: the cursor (bottom line).
    let a = act(&mut p, Action::LogCopy);
    assert!(matches!(a, Some(Action::StatusMessage(ref m)) if m == "Copied 1 line"));
    assert!(
        local
            .texts
            .lock()
            .is_ok_and(|t| t[0] == "12:00:01 Command:  PASS ****")
    );
    let (seq, _) = crate::ui::clipboard::osc52_sequence("12:00:01 Command:  PASS ****");
    assert_eq!(out.taken(), seq.as_slice());

    // A visual range over two lines.
    act(&mut p, Action::LogVisual);
    act(&mut p, Action::LogCursorUp);
    act(&mut p, Action::LogCursorUp);
    let screen = draw(&mut p, 80, 10);
    assert!(screen.contains("USER alice"));
    let a = act(&mut p, Action::LogCopy);
    assert!(matches!(a, Some(Action::StatusMessage(ref m)) if m == "Copied 3 lines"));
    let expected = "12:00:01 Command:  USER alice\n12:00:01 Response: 331 Password\n12:00:01 Command:  PASS ****";
    assert!(local.texts.lock().is_ok_and(|t| t[1] == expected));
    assert!(p.view().visual_anchor.is_none());

    // The All view copies the tag too.
    act(&mut p, Action::LogToggleScope);
    let _ = draw_buf(&mut p, 80, 10, true, false);
    let (text, n) = p.copy_text().unwrap_or_default();
    assert_eq!((text.as_str(), n), ("12:00:01 [-] Command:  PASS ****", 1));
}

#[test]
fn clear_log_empties_the_shown_scope_only() {
    let mut p = pane();
    push_n(&mut p, 3);
    let a = act(&mut p, Action::ClearLog);
    assert!(matches!(a, Some(Action::StatusMessage(ref m)) if m == "Log cleared"));
    assert_eq!(p.store().len(tab(0)), 0);
    assert_eq!(p.store().len(LogScope::All), 3);
    act(&mut p, Action::LogToggleScope);
    assert_eq!(p.view().scope, LogScope::All);
    act(&mut p, Action::ClearLog);
    assert_eq!(p.store().len(LogScope::All), 0);
}

#[test]
fn scope_toggle_keeps_each_view_state() {
    let mut p = pane();
    push_n(&mut p, 20);
    let _ = draw(&mut p, 40, 7);
    act(&mut p, Action::LogToggleWrap);
    act(&mut p, Action::LogTop);
    act(&mut p, Action::LogToggleScope);
    assert_eq!(p.view().scope, LogScope::All);
    assert!(p.view().follow && p.view().wrap);
    assert!(draw(&mut p, 40, 7).contains("Message log · All"));
    act(&mut p, Action::LogToggleScope);
    assert_eq!(p.view().scope, tab(0));
    assert!(!p.view().follow && !p.view().wrap);
    p.set_active_tab(TabId(1));
    assert_eq!(p.view().scope, tab(1));
    // A tab route sends its browsing session's lines to that tab only.
    let s = SessionId::next();
    p.store_mut().set_tab_route(
        TabId(0),
        TabRoute {
            browsing: Some(s),
            server: None,
        },
    );
    feed(&mut p, &log_event(s, LogKind::Status, "tab zero"));
    assert_eq!(p.store().len(tab(1)), 0);
    assert_eq!(
        texts(p.store(), tab(0)).last().map(String::as_str),
        Some("tab zero")
    );
}

#[test]
fn no_wrap_scrolls_horizontally_with_markers() {
    let mut p = pane();
    let long: String = (0..30).map(|i| format!("w{i:02} ")).collect();
    feed(&mut p, &log_event(SessionId::APP, LogKind::Status, &long));
    act(&mut p, Action::LogToggleWrap);
    let screen = draw(&mut p, 50, 4);
    assert!(screen.contains("w00") && screen.contains('»'), "{screen}");
    act(&mut p, Action::LogScrollRight);
    assert_eq!(p.view().hscroll, 8);
    let screen = draw(&mut p, 50, 4);
    assert!(screen.contains("«") && !screen.contains("w01"), "{screen}");
    act(&mut p, Action::LogScrollLeft);
    act(&mut p, Action::LogScrollLeft);
    assert_eq!(p.view().hscroll, 0);
    act(&mut p, Action::LogScrollRight);
    act(&mut p, Action::LogScrollHome);
    assert_eq!(p.view().hscroll, 0);
    // With wrap on, h/l do nothing.
    act(&mut p, Action::LogToggleWrap);
    act(&mut p, Action::LogScrollRight);
    assert_eq!(p.view().hscroll, 0);
}

#[test]
fn handled_actions_cover_the_log_table() {
    let p = pane();
    let handled = p.handled_actions();
    for (a, meta) in crate::action::BINDABLE {
        if meta.owner == "T55" {
            assert!(handled.iter().any(|h| h.same_variant(a)), "{}", meta.name);
        }
    }
}

#[test]
fn unseen_label_caps() {
    assert_eq!(super::unseen_label(3, true), "▼ 3 new");
    assert_eq!(super::unseen_label(12_000, false), "v 9999+ new");
}

// ---------------------------------------------------------------- properties

fn is_control(c: char) -> bool {
    let n = u32::from(c);
    n < 0x20
        || (0x7F..=0x9F).contains(&n)
        || matches!(
            n,
            0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0x2028 | 0x2029
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_stored_lines_have_no_control_chars(s in any::<String>(), k in 0u8..7) {
        let kind = match k {
            0 => LogKind::Status,
            1 => LogKind::Command,
            2 => LogKind::Response,
            3 => LogKind::Error,
            4 => LogKind::ListingRaw,
            _ => LogKind::Debug(k - 4),
        };
        let mut p = pane();
        feed(&mut p, &log_event(SessionId::APP, kind, &s));
        for l in p.store().lines(LogScope::All) {
            prop_assert!(!l.text.chars().any(is_control), "{:?}", l.text);
        }
        let buf = draw_buf(&mut p, 60, 8, true, false);
        for c in buf.content() {
            prop_assert!(!c.symbol().chars().any(is_control), "{:?}", c.symbol());
        }
    }

    #[test]
    fn prop_ring_len_bounded(
        cap in 1usize..40,
        ops in proptest::collection::vec((0u8..10, 0u32..3), 0..200),
    ) {
        let mut s = LogStore::new(cap);
        for (op, t) in ops {
            if op == 0 {
                s.clear(LogScope::Tab(TabId(t)));
            } else {
                s.push(msg(SessionId::APP, LogKind::Status, &"y".repeat(usize::from(op) * 900)), TabId(t));
            }
            for scope in [LogScope::All, tab(0), tab(1), tab(2)] {
                prop_assert!(s.len(scope) <= cap);
                for l in s.lines(scope) {
                    prop_assert!(l.text.chars().count() <= MAX_LINE_CHARS + 32);
                }
            }
        }
    }

    #[test]
    fn prop_render_never_panics_any_size(
        lines in proptest::collection::vec(".{0,300}", 0..30),
        w in 0u16..200,
        h in 0u16..60,
        wrap in any::<bool>(),
        all in any::<bool>(),
        up in 0usize..20,
    ) {
        let mut p = pane();
        for (i, l) in lines.iter().enumerate() {
            let kind = if i % 2 == 0 { LogKind::Command } else { LogKind::Error };
            feed(&mut p, &log_event(SessionId::APP, kind, l));
        }
        if !wrap {
            act(&mut p, Action::LogToggleWrap);
            act(&mut p, Action::LogScrollRight);
        }
        if all {
            act(&mut p, Action::LogToggleScope);
        }
        let _ = draw_buf(&mut p, w, h, true, false);
        for _ in 0..up {
            act(&mut p, Action::LogCursorUp);
        }
        act(&mut p, Action::LogVisual);
        act(&mut p, Action::LogPageDown);
        let _ = draw_buf(&mut p, w, h, true, true);
    }
}

// ---------------------------------------------------------------- with the app

mod app {
    use courier_ftp_core::{
        backend::{BackendContext, SessionHandle, SessionOptions, mock::MockServer},
        model::RemotePath,
        settings::Settings,
    };
    use pretty_assertions::assert_eq;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::{components::main_screen::layout::Region, config::Config, testing::AppHarness};

    fn harness() -> AppHarness {
        AppHarness::new(Config::default())
    }

    /// Integration: core log events from a mock session reach the pane, masked.
    #[test]
    fn core_log_events_reach_the_pane() {
        let mut h = harness();
        let server = MockServer::new();
        server.add_dir("/home/test");
        let events = h.app().events_sender().clone();
        let (_tx, settings) = tokio::sync::watch::channel(Arc::new(Settings::default()));
        let ctx = BackendContext {
            session: SessionId::next(),
            events,
            settings,
        };
        let backend = Box::new(server.backend(ctx.clone()));
        let session = {
            let _g = h.runtime().enter();
            SessionHandle::new(
                backend,
                ctx.clone(),
                SessionOptions::new(SessionPurpose::Browse),
                "test@mock".into(),
            )
        };
        let token = CancellationToken::new();
        let res = h.runtime().block_on(async {
            session.connect(&token).await?;
            ctx.log().command("USER test");
            ctx.log().command("PASS hunter2");
            session
                .list(&RemotePath::parse("/home/test")?, &token)
                .await
                .map(|_| ())
        });
        ok(res);
        h.settle();
        h.action(Action::FocusLog);
        let _ = h.render(160, 48);
        h.keys("g g");
        let screen = h.render(160, 48);
        assert!(screen.contains("Command:  PASS ****"), "{screen}");
        assert!(screen.contains("Command:  USER test"), "{screen}");
        assert!(!screen.contains("hunter2"), "{screen}");
        drop(session);
    }

    #[test]
    fn log_keys_reach_the_pane_and_clear_works_from_any_pane() {
        let mut h = harness();
        for i in 0..20 {
            h.core_event(log_event(
                SessionId::APP,
                LogKind::Status,
                &format!("entry {i}"),
            ));
        }
        h.action(Action::FocusLog);
        assert_eq!(h.focus(), Region::Log);
        let _ = h.render(160, 48);
        h.keys("k k g g");
        let screen = h.render(160, 48);
        assert!(!screen.contains("is not available yet"), "{screen}");
        assert!(screen.contains("entry 0 "), "{screen}");
        h.keys("G / e n t r y space 1 enter");
        let screen = h.render(160, 48);
        assert!(screen.contains("/entry 1  match"), "{screen}");
        h.keys("esc");
        assert!(!h.render(160, 48).contains("/entry 1"));
        // Clear from the file list (global ctrl-x l).
        h.action(Action::FocusRegion3);
        h.keys("ctrl-x l");
        let screen = h.render(160, 48);
        assert!(screen.contains("Log cleared"), "{screen}");
        assert!(!screen.contains("entry 19"), "{screen}");
    }

    #[test]
    fn copy_through_the_app_clipboard() {
        let mut h = harness();
        let out = SharedOut::default();
        if let Ok(mut c) = h.app().clipboard().lock() {
            *c = Clipboard::new(true, None, Box::new(out.clone()));
        }
        h.core_event(log_event(SessionId::APP, LogKind::Error, "copy me"));
        h.action(Action::FocusLog);
        let _ = h.render(160, 48);
        h.keys("y");
        let screen = h.render(160, 48);
        assert!(screen.contains("Copied 1 line"), "{screen}");
        let (seq, _) = crate::ui::clipboard::osc52_sequence("12:00:01 Error:    copy me");
        assert_eq!(out.taken(), seq.as_slice());
    }
}
