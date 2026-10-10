//! Snapshot tests of the status bar (states A, B, C of the T57 mock-ups at several
//! widths, Unicode and ASCII), full screens with the bar, the server information
//! dialog, and the `NO_COLOR` styles. Snapshots live in `status_bar/snapshots/`.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::collections::BTreeMap;

use insta::assert_snapshot;
use ratatui::{buffer::Buffer, style::Modifier};

use super::{
    tests::{hints, message, state_a, state_b, state_c},
    *,
};
use crate::{
    app::status::{SessionSnapshot, StatusSources},
    components::server_info::{
        ServerInfoDialog, ServerInfoView,
        tests::{NOW, ftps, sftp},
    },
    config::Config,
    testing::{self, AppHarness},
    ui::{
        symbols::{Symbols, TermEnv},
        theme::{Theme, ThemePreset},
    },
};

fn theme(no_color: bool) -> Theme {
    Theme::load(ThemePreset::Default, &BTreeMap::new(), no_color).0
}

fn bar(info: &StatusInfo, w: u16, sym: &Symbols, theme: &Theme) -> String {
    testing::render(w, 1, |f| render(f, f.area(), info, sym, theme))
}

#[test]
fn status_bar_states_unicode() {
    let sym = Symbols::unicode();
    let t = theme(false);
    let h = hints();
    let msg = message();
    for w in [40, 60, 80, 120, 160] {
        assert_snapshot!(
            format!("status_bar_state_a_{w}"),
            bar(&state_a(&h), w, &sym, &t)
        );
        assert_snapshot!(
            format!("status_bar_state_b_{w}"),
            bar(&state_b(&h), w, &sym, &t)
        );
        assert_snapshot!(
            format!("status_bar_state_c_{w}"),
            bar(&state_c(&h, &msg, &sym), w, &sym, &t)
        );
    }
}

#[test]
fn status_bar_states_ascii() {
    let sym = Symbols::ascii();
    let t = theme(false);
    let h = hints();
    for w in [40, 80, 160] {
        assert_snapshot!(
            format!("status_bar_state_a_ascii_{w}"),
            bar(&state_a(&h), w, &sym, &t)
        );
    }
}

/// The sources of state A on a running app.
fn state_a_sources() -> StatusSources {
    let (info, addr) = ftps();
    StatusSources {
        session: Some(SessionSnapshot { info, addr }),
        filters_active: true,
        sync_browsing: true,
        comparison: true,
        queue: Some(QueueSummary {
            files: 12,
            bytes: 31_666_995,
            down_bps: 1_258_291,
            up_bps: 0,
            eta_secs: Some(25),
        }),
        ..StatusSources::default()
    }
}

fn state_a_app(env: TermEnv) -> AppHarness {
    let mut c = Config::default();
    c.settings.transfers.download_limit_kib = 500;
    c.settings.transfers.upload_limit_kib = 100;
    c.settings.transfers.speed_limit_enabled = true;
    let mut h = AppHarness::with_env(c, env);
    h.app_mut().status_sources = state_a_sources();
    h
}

#[test]
fn snap_status_bar_full_screen() {
    for (w, hh) in testing::SIZES {
        let mut h = state_a_app(testing::unicode_env());
        assert_snapshot!(format!("snap_status_bar_state_a_{w}x{hh}"), h.render(w, hh));
    }
}

fn open_info(h: &mut AppHarness, view: ServerInfoView, unicode: bool) {
    h.app_mut()
        .modals
        .push_then(ServerInfoDialog::new(view, unicode), |_| None);
}

#[test]
fn server_info_ftps_80x24() {
    let mut h = AppHarness::new(Config::default());
    h.render(80, 24);
    let (i, a) = ftps();
    open_info(
        &mut h,
        ServerInfoView::from_session_at(&i, &a, "Tab 1", NOW),
        true,
    );
    assert_snapshot!("server_info_ftps_80x24", h.render(80, 24));
}

#[test]
fn server_info_sftp_160x48() {
    let mut h = AppHarness::new(Config::default());
    h.render(160, 48);
    let (i, a) = sftp();
    open_info(
        &mut h,
        ServerInfoView::from_session_at(&i, &a, "Tab 2 · web01", NOW),
        true,
    );
    assert_snapshot!("server_info_sftp_160x48", h.render(160, 48));
}

#[test]
fn server_info_not_connected_80x24() {
    let mut h = AppHarness::new(Config::default());
    h.render(80, 24);
    h.action(crate::action::Action::ServerInfo);
    assert_snapshot!("server_info_not_connected_80x24", h.render(80, 24));
}

fn row_text(buf: &Buffer, y: u16) -> String {
    (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect()
}

#[test]
fn no_color_insecure_and_attention_styles() {
    let t = theme(true);
    let insecure = t.style("status.insecure");
    assert!(
        insecure
            .add_modifier
            .contains(Modifier::REVERSED | Modifier::BOLD)
    );
    assert_eq!((insecure.fg, insecure.bg), (None, None));
    let attention = t.style("status.attention");
    assert!(attention.add_modifier.contains(Modifier::REVERSED));
    assert_eq!(t.style("status.bar").add_modifier, Modifier::empty());
    // The plain-FTP cells carry the insecure style (colour themes too).
    for no_color in [false, true] {
        let t = theme(no_color);
        let info = StatusInfo {
            security: SecurityIndicator::Plain,
            ..StatusInfo::default()
        };
        let sym = Symbols::unicode();
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(40, 1)).unwrap();
        term.draw(|f| render(f, f.area(), &info, &sym, &t)).unwrap();
        let buf = term.backend().buffer().clone();
        let x = (0..40).find(|&x| buf[(x, 0)].symbol() == "p").unwrap();
        let style = buf[(x, 0)].style();
        let want = t.style("status.bar").patch(t.style("status.insecure"));
        assert_eq!(style.add_modifier, want.add_modifier, "no_color={no_color}");
        if !no_color {
            assert_eq!(style.bg, want.bg);
        }
    }
}

#[test]
fn ascii_mode_bar_and_dialog_cells_are_ascii() {
    // `interface.unicode_symbols = never`.
    let mut c = Config::default();
    c.settings.interface.unicode_symbols = crate::ui::symbols::UnicodeSymbols::Never;
    c.settings.transfers.download_limit_kib = 500;
    c.settings.transfers.speed_limit_enabled = true;
    let mut h = AppHarness::with_env(c, testing::unicode_env());
    let mut sources = state_a_sources();
    sources.vault = Some(VaultIndicator::Locked);
    sources.prompts_badge = Some("! 2 prompts".into());
    h.app_mut().status_sources = sources;
    for (w, hh) in [(40, 24), (80, 24), (160, 48)] {
        let buf = h.buffer(w, hh);
        let last = row_text(&buf, hh - 1);
        assert!(last.is_ascii(), "{last}");
        assert!(last.contains("[TLS"), "{last}");
    }
    let (i, a) = ftps();
    open_info(
        &mut h,
        ServerInfoView::from_session_at(&i, &a, "Tab 1", NOW),
        false,
    );
    for (w, hh) in testing::SIZES {
        let buf = h.buffer(w, hh);
        for y in 0..hh {
            let row = row_text(&buf, y);
            assert!(row.is_ascii(), "row {y}: {row}");
        }
    }
}
