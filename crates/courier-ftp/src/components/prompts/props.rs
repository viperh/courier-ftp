//! Property test: prompt dialogs never panic and never draw control characters, at
//! any terminal size and with any server-provided text (T69 AC13).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use courier_ftp_core::{
    events::{KbdField, KbdInteractivePrompt, MessagePrompt, NoticeLevel, PromptKind},
    model::Direction,
};
use proptest::prelude::*;
use ratatui::{Terminal, backend::TestBackend};
use tokio::time::Instant;

use super::{
    PromptEnv, build_dialog,
    layout::{BodyCx, DIALOG_W, render_body},
    tests::{cert_prompt, changed_host_key, file_exists_prompt, password_prompt, pw_key},
};
use crate::ui::{
    symbols::Symbols,
    theme::{Theme, ThemePreset},
};

fn kinds(s: &str) -> Vec<PromptKind> {
    let mut host = changed_host_key(true);
    host.host = s.to_owned();
    host.key_type = s.to_owned();
    host.other_known_types = vec![s.to_owned()];
    let mut unknown = host.clone();
    unknown.changed = None;
    let mut cert = cert_prompt(false, true);
    cert.host = s.to_owned();
    cert.session.chain[0].subject = s.to_owned();
    cert.session.chain[0].sans = vec![s.to_owned(); 3];
    cert.problems
        .push(courier_ftp_core::events::CertProblem::Other(s.to_owned()));
    let mut changed = cert.clone();
    changed.previous = cert_prompt(true, true).previous;
    let mut pw = password_prompt(pw_key("h"), true);
    pw.target = s.to_owned();
    let mut fe = file_exists_prompt(Direction::Upload, false);
    fe.source_path = s.to_owned();
    fe.target.name = s.to_owned();
    fe.suggested_name = Some(s.to_owned());
    vec![
        PromptKind::TrustHostKey(host),
        PromptKind::TrustHostKey(unknown),
        PromptKind::TrustCertificate(Box::new(cert)),
        PromptKind::TrustCertificate(Box::new(changed)),
        PromptKind::Password(pw),
        PromptKind::KeyboardInteractive(KbdInteractivePrompt {
            host: s.to_owned(),
            name: s.to_owned(),
            instructions: s.to_owned(),
            prompts: vec![
                KbdField {
                    text: s.to_owned(),
                    echo: true,
                },
                KbdField {
                    text: s.to_owned(),
                    echo: false,
                },
            ],
        }),
        PromptKind::FileExists(Box::new(fe)),
        PromptKind::Message(MessagePrompt {
            level: NoticeLevel::Error,
            title: s.to_owned(),
            text: s.to_owned(),
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn rendering_never_panics(
        w in 1u16..=300,
        h in 1u16..=100,
        text in "(\\PC|[\\x00-\\x1f\\x7f\\u{80}-\\u{9f}\\u{202e}]){0,120}",
        details in any::<bool>(),
    ) {
        let theme = Theme::load(ThemePreset::Default, &std::collections::BTreeMap::new(), false).0;
        let symbols = Symbols::unicode();
        let env = PromptEnv::default();
        for kind in kinds(&text) {
            let mut d = build_dialog(&kind, &env);
            if details {
                d.handle_key(crate::components::prompts::tests::k("d"));
            }
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| {
                let area = f.area();
                let cx = BodyCx { theme: &theme, symbols: &symbols, guard: false };
                let width = DIALOG_W.min(area.width.saturating_sub(4)).saturating_sub(4).max(1);
                let dcx = crate::components::DrawCx {
                    theme: &theme,
                    symbols: &symbols,
                    focused: true,
                    now: Instant::now(),
                    spinner: None,
                };
                let area = super::layout::draw_prompt_frame(f, area, &d.title(true), d.danger(), &dcx);
                let body = d.body(width, &cx);
                let scroll = std::cell::Cell::new(0);
                render_body(f, area, &body, &scroll, &cx, Instant::now(), |f, field, r, wcx| {
                    d.draw_input(f, field, r, wcx)
                });
            }).unwrap();
            let buf = term.backend().buffer();
            for cell in &buf.content {
                for c in cell.symbol().chars() {
                    prop_assert!(!crate::components::widgets::is_control(c), "control {c:?}");
                }
            }
        }
    }
}
