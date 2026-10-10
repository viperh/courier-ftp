//! Snapshot tests of the message log (T55, AC1, AC2): the pane alone at 80×24 and
//! 160×48, each also as `*_mono_ascii` (`NO_COLOR` + ASCII symbols). Every snapshot
//! carries the style legend of `crate::testing`.

use courier_ftp_core::{
    events::{CoreEvent, LogKind, LogMessage, SessionId, SessionPurpose},
    model::ServerAddress,
};
use insta::assert_snapshot;
use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use time::Duration;

use super::{
    tests::{T0, pane, theme},
    *,
};
use crate::{
    components::{Component, DrawCx},
    tabs::TabRoute,
    testing::{SIZES, buffer_to_string, style_legend},
    ui::symbols::Symbols,
};

fn at(session: SessionId, secs: i64, kind: LogKind, text: &str) -> CoreEvent {
    CoreEvent::Log(LogMessage {
        time: T0 + Duration::seconds(secs),
        session,
        kind,
        text: text.to_owned(),
    })
}

fn feed(p: &mut MessageLogPane, ev: &CoreEvent) {
    if let Err(e) = p.on_core_event(ev) {
        panic!("{e}");
    }
}

fn act(p: &mut MessageLogPane, a: Action) {
    if let Err(e) = p.update(&a) {
        panic!("{e}");
    }
}

fn key(p: &mut MessageLogPane, k: KeyChord) {
    if let Err(e) = p.handle_key(k) {
        panic!("{e}");
    }
}

fn address(url: &str) -> ServerAddress {
    match url.parse() {
        Ok(a) => a,
        Err(e) => panic!("{e}"),
    }
}

/// The session of the mock-ups: tab 1 browses an FTPS server, a transfer session
/// uploads to an SFTP server, the app logs a status line.
fn mockup(p: &mut MessageLogPane) {
    let browse = SessionId::next();
    let transfer = SessionId::next();
    feed(
        p,
        &CoreEvent::SessionOpened {
            session: browse,
            purpose: SessionPurpose::Browse,
            label: "alice@203.0.113.5".into(),
        },
    );
    p.store_mut().set_tab_route(
        TabId::FIRST,
        TabRoute {
            browsing: Some(browse),
            server: None,
        },
    );
    use LogKind::{Command as C, Debug as D, Error as E, Response as R, Status as S};
    let tab: &[(i64, LogKind, &str)] = &[
        (0, S, "Connecting to 203.0.113.5:21..."),
        (
            0,
            S,
            "Connection established, waiting for welcome message...",
        ),
        (0, R, "220 (vsFTPd 3.0.5)"),
        (0, C, "AUTH TLS"),
        (0, R, "234 Proceed with negotiation."),
        (0, S, "Initializing TLS..."),
        (
            1,
            S,
            "TLS connection established (TLS 1.3, TLS_AES_256_GCM_SHA384).",
        ),
        (1, C, "USER alice"),
        (1, R, "331 Please specify the password."),
        (1, C, "PASS ****"),
        (1, R, "230 Login successful."),
        (1, S, "Logged in"),
        (1, S, "Retrieving directory listing..."),
        (1, C, "PWD"),
        (1, R, "257 \"/var/www\" is the current directory"),
        (1, C, "PASV"),
        (1, R, "227 Entering Passive Mode (203,0,113,5,195,80)."),
        (1, C, "MLSD"),
        (2, R, "150 Here comes the directory listing."),
        (2, R, "226 Directory send OK."),
        (2, S, "Directory listing of \"/var/www\" successful"),
        (8, C, "CWD /root"),
        (8, R, "550 Failed to change directory."),
        (
            8,
            E,
            "Failed to retrieve directory listing: the server sent a reply that is long enough to wrap onto a second line of the pane",
        ),
    ];
    for (s, k, t) in tab {
        feed(p, &at(browse, *s, *k, t));
    }
    feed(
        p,
        &CoreEvent::Connected {
            session: browse,
            address: address("ftpes://alice@203.0.113.5"),
        },
    );
    feed(
        p,
        &CoreEvent::SessionOpened {
            session: transfer,
            purpose: SessionPurpose::Transfer,
            label: "deploy@web01.example.com".into(),
        },
    );
    let xfer: &[(i64, LogKind, &str)] = &[
        (189, S, "Connecting to web01.example.com:22..."),
        (189, S, "Using username \"deploy\"."),
        (189, D(1), "Server version: SSH-2.0-OpenSSH_9.6"),
        (
            189,
            D(2),
            "kex curve25519-sha256, cipher chacha20-poly1305@openssh.com, mac <implicit>",
        ),
        (190, S, "Connected to web01.example.com"),
        (190, S, "Starting upload of /home/alice/site/index.html"),
        (
            190,
            S,
            "File transfer successful, transferred 4,198 bytes in 1 second",
        ),
        (
            219,
            E,
            "Disk full: /home/alice/Downloads (needed 1.21 GiB, 812 MiB free); queue paused",
        ),
    ];
    for (s, k, t) in xfer {
        feed(p, &at(transfer, *s, *k, t));
    }
    feed(
        p,
        &at(
            SessionId::APP,
            220,
            S,
            "Warning: the vault is locked; saved passwords are not available",
        ),
    );
    let tail: &[(i64, LogKind, &str)] = &[
        (241, C, "NOOP"),
        (241, R, "200 NOOP ok."),
        (269, C, "CWD /var/www/html"),
        (269, R, "250 Directory successfully changed."),
        (269, C, "PASV"),
        (269, R, "227 Entering Passive Mode (203,0,113,5,195,81)."),
        (269, C, "MLSD"),
        (269, R, "150 Here comes the directory listing."),
        (269, R, "226 Directory send OK."),
        (269, S, "Directory listing of \"/var/www/html\" successful"),
    ];
    for (s, k, t) in tail {
        feed(p, &at(browse, *s, *k, t));
    }
}

/// Thirty application lines before the mock-up session (so it does not fit).
fn earlier(p: &mut MessageLogPane) {
    for i in 0..30 {
        feed(
            p,
            &at(
                SessionId::APP,
                i - 60,
                LogKind::Status,
                &format!("Bookmark {i} checked"),
            ),
        );
    }
}

/// Draws `p` at `w`×`h` (the pane `pane_w` columns wide) and returns the screen plus
/// the style legend.
fn shot(p: &mut MessageLogPane, w: u16, h: u16, pane_w: u16, focused: bool, mono: bool) -> String {
    let th = theme(mono);
    let symbols = if mono {
        Symbols::ascii()
    } else {
        Symbols::unicode()
    };
    let mut terminal = match Terminal::new(TestBackend::new(w, h)) {
        Ok(t) => t,
        Err(e) => match e {},
    };
    let cx = DrawCx {
        theme: &th,
        symbols: &symbols,
        focused,
        now: tokio::time::Instant::now(),
        spinner: None,
    };
    if let Err(e) = terminal.draw(|f| {
        if let Err(e) = p.draw(f, Rect::new(0, 0, pane_w.min(w), h), &cx) {
            panic!("draw: {e}");
        }
    }) {
        match e {}
    }
    let buf = terminal.backend().buffer().clone();
    let mut out = buffer_to_string(&buf);
    out.push_str(&style_legend(&buf));
    out
}

/// Snapshots `name` at both sizes, in colour and mono/ASCII. `setup(pane, w, h, mono)`
/// prepares a fresh pane (it may draw first to learn its size).
fn snap_both(name: &str, focused: bool, setup: impl Fn(&mut MessageLogPane, u16, u16, bool)) {
    for (w, h) in SIZES {
        for mono in [false, true] {
            let mut p = pane();
            setup(&mut p, w, h, mono);
            let text = shot(&mut p, w, h, w, focused, mono);
            let suffix = if mono { "_mono_ascii" } else { "" };
            assert_snapshot!(format!("{name}{suffix}@{w}x{h}"), text);
        }
    }
}

fn warm(p: &mut MessageLogPane, w: u16, h: u16, mono: bool) {
    let _ = shot(p, w, h, w, true, mono);
}

#[test]
fn log_all_kinds() {
    snap_both("log_all_kinds", false, |p, _, _, _| {
        let s = SessionId::APP;
        feed(
            p,
            &at(s, 0, LogKind::Status, "Resolving address of example.com"),
        );
        feed(
            p,
            &at(
                s,
                1,
                LogKind::Status,
                "Warning: server clock is 3 minutes ahead",
            ),
        );
        feed(p, &at(s, 2, LogKind::Command, "LIST -a"));
        feed(
            p,
            &at(s, 3, LogKind::Response, "150 Opening data connection"),
        );
        feed(
            p,
            &at(
                s,
                4,
                LogKind::Error,
                "Connection timed out after 20 seconds",
            ),
        );
        feed(p, &at(s, 5, LogKind::Debug(3), "send_packet(len=52)"));
        feed(
            p,
            &at(
                s,
                6,
                LogKind::ListingRaw,
                "drwxr-xr-x    2 www      www          4096 May  2 10:02 html",
            ),
        );
        feed(
            p,
            &at(
                s,
                7,
                LogKind::Response,
                "220 \x1b[31mred\x1b[0m banner \u{202e}gpj.exe",
            ),
        );
    });
}

#[test]
fn log_wrapped() {
    snap_both("log_wrapped", false, |p, _, _, _| {
        mockup(p);
        let long = "Failed to retrieve directory listing: ".to_owned()
            + &"the server sent a very long reply that keeps going ".repeat(5)
            + "end-of-a-word-that-is-much-longer-than-anything-sensible-and-must-be-broken-hard-because-it-has-no-spaces-at-all-0123456789";
        feed(p, &at(SessionId::APP, 300, LogKind::Error, &long));
    });
}

#[test]
fn log_all_view_tags() {
    snap_both("log_all_view_tags", false, |p, _, _, _| {
        mockup(p);
        act(p, Action::LogToggleScope);
    });
}

#[test]
fn log_scrolled_unseen() {
    snap_both("log_scrolled_unseen", true, |p, w, h, mono| {
        earlier(p);
        mockup(p);
        act(p, Action::LogToggleScope);
        warm(p, w, h, mono);
        for _ in 0..12 {
            act(p, Action::LogCursorUp);
        }
        for i in 0..3 {
            feed(
                p,
                &at(
                    SessionId::APP,
                    400 + i,
                    LogKind::Status,
                    &format!("Background task {i} finished"),
                ),
            );
        }
    });
}

#[test]
fn log_search_active() {
    snap_both("log_search_active", true, |p, w, h, mono| {
        earlier(p);
        mockup(p);
        act(p, Action::LogToggleScope);
        warm(p, w, h, mono);
        act(p, Action::LogPageUp);
        act(p, Action::LogSearch);
        for c in "550".chars() {
            key(p, KeyChord::char(c));
        }
    });
}

#[test]
fn log_errors_only() {
    snap_both("log_errors_only", false, |p, _, _, _| {
        mockup(p);
        act(p, Action::LogToggleScope);
        act(p, Action::LogCycleKindFilter);
        act(p, Action::LogCycleKindFilter);
    });
}

#[test]
fn log_no_wrap_hscroll() {
    snap_both("log_no_wrap_hscroll", false, |p, _, _, _| {
        mockup(p);
        act(p, Action::LogToggleWrap);
        act(p, Action::LogScrollRight);
    });
}

#[test]
fn log_empty() {
    snap_both("log_empty", false, |_, _, _, _| {});
}

fn narrow(name: &str, pane_w: u16) {
    for mono in [false, true] {
        let mut p = pane();
        mockup(&mut p);
        act(&mut p, Action::LogToggleScope);
        let text = shot(&mut p, 80, 24, pane_w + 2, false, mono);
        let suffix = if mono { "_mono_ascii" } else { "" };
        assert_snapshot!(format!("{name}{suffix}"), text);
    }
}

#[test]
fn log_narrow_40() {
    narrow("log_narrow_40", 40);
}

#[test]
fn log_narrow_55() {
    narrow("log_narrow_55", 55);
}

#[test]
fn log_narrow_65() {
    narrow("log_narrow_65", 65);
}
