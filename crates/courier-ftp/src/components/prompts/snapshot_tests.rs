//! Snapshots of every prompt dialog over the dimmed main screen at 80×24 and 160×48,
//! input guard elapsed (T69 AC1, AC7, AC13). Snapshots live in `prompts/snapshots/`.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::time::Duration;

use courier_ftp_core::{
    events::{CoreEvent, PromptKind, SessionId, SessionPurpose},
    model::Direction,
};
use insta::assert_snapshot;
use time::macros::datetime;

use super::{
    PromptEnv,
    tests::{
        Prompter, cert_prompt, cert_prompt_at, changed_host_key, file_exists_prompt, kbd_prompt,
        now_2026, passphrase_prompt, password_prompt, pw_key, unknown_host_key,
    },
};
use crate::{
    config::Config,
    keymap::chord::KeyChord,
    testing::{AppHarness, style_legend},
};

const SIZES: [(u16, u16); 2] = [(80, 24), (160, 48)];

/// A harness whose prompts judge certificates at 2026-10-10 12:00 UTC.
pub(crate) fn harness() -> AppHarness {
    let mut h = AppHarness::new(Config::default());
    h.app_mut().prompts.set_env(PromptEnv {
        now: Some(now_2026()),
        ..PromptEnv::default()
    });
    h
}

/// Shows `kind` as a foreground prompt, waits out the input guard, runs `setup`.
pub(crate) fn show(h: &mut AppHarness, p: &mut Prompter, kind: PromptKind) {
    let req = p.request(kind);
    h.core_event(CoreEvent::Prompt(req));
    // Opens on the next tick (≤ 250 ms); the input guard ends 500 ms later.
    h.advance(Duration::from_millis(800));
}

/// Snapshots `name_80x24` and `name_160x48`.
fn snap(name: &str, kind: impl Fn() -> PromptKind, setup: impl Fn(&mut AppHarness)) {
    for (w, h) in SIZES {
        let mut hs = harness();
        let mut p = Prompter::new();
        hs.render(w, h);
        show(&mut hs, &mut p, kind());
        setup(&mut hs);
        let text = hs.render(w, h);
        // The styles show what text cannot: dim (disabled, guard), error style, focus.
        let legend = style_legend(&hs.buffer(w, h));
        assert!(!text.contains("CANARY"), "typed secrets are never drawn");
        assert_snapshot!(format!("{name}_{w}x{h}"), format!("{text}{legend}"));
    }
}

fn type_text(h: &mut AppHarness, text: &str) {
    for c in text.chars() {
        h.key(KeyChord::char(c));
    }
}

#[test]
fn host_key_unknown() {
    snap(
        "host_key_unknown",
        || PromptKind::TrustHostKey(unknown_host_key(true)),
        |_| {},
    );
}

#[test]
fn host_key_unknown_vault_locked() {
    snap(
        "host_key_unknown_vault_locked",
        || PromptKind::TrustHostKey(unknown_host_key(false)),
        |_| {},
    );
}

#[test]
fn host_key_unknown_other_type_note() {
    snap(
        "host_key_unknown_other_type_note",
        || {
            let mut p = unknown_host_key(true);
            p.other_known_types = vec!["ssh-rsa".into()];
            PromptKind::TrustHostKey(p)
        },
        |_| {},
    );
}

#[test]
fn host_key_changed_empty() {
    snap(
        "host_key_changed_empty",
        || PromptKind::TrustHostKey(changed_host_key(true)),
        |_| {},
    );
}

#[test]
fn host_key_changed_matching() {
    snap(
        "host_key_changed_matching",
        || PromptKind::TrustHostKey(changed_host_key(true)),
        |h| {
            h.keys("backtab");
            type_text(h, "web01.example.com");
            h.keys("enter");
        },
    );
}

#[test]
fn password_first() {
    snap(
        "password_first",
        || {
            let mut p = password_prompt(pw_key("web01.example.com"), false);
            p.can_save = false;
            PromptKind::Password(p)
        },
        |h| type_text(h, "CANARY-pw"),
    );
}

#[test]
fn password_retry_with_save() {
    snap(
        "password_retry_with_save",
        || PromptKind::Password(password_prompt(pw_key("web01.example.com"), true)),
        |_| {},
    );
}

#[test]
fn passphrase() {
    snap(
        "passphrase",
        || PromptKind::KeyPassphrase(passphrase_prompt()),
        |_| {},
    );
}

#[test]
fn kbd_one_prompt() {
    snap(
        "kbd_one_prompt",
        || PromptKind::KeyboardInteractive(kbd_prompt(&[("Verification code:", true)], "")),
        |h| type_text(h, "123456"),
    );
}

#[test]
fn kbd_two_prompts() {
    snap(
        "kbd_two_prompts",
        || {
            PromptKind::KeyboardInteractive(kbd_prompt(
                &[("Password:", false), ("Verification code:", true)],
                "Enter your password, then the 6-digit code from your authenticator app.",
            ))
        },
        |h| {
            type_text(h, "CANARY-kbd");
            h.keys("enter");
            type_text(h, "123456");
        },
    );
}

#[test]
fn kbd_long_instructions() {
    snap(
        "kbd_long_instructions",
        || {
            let text = (1..=14)
                .map(|i| format!("Line {i} of the login banner from the server."))
                .collect::<Vec<_>>()
                .join("\n");
            PromptKind::KeyboardInteractive(kbd_prompt(
                &[("A very long prompt label that goes on and on:", false)],
                &text,
            ))
        },
        |_| {},
    );
}

#[test]
fn certificate_unknown() {
    snap(
        "certificate_unknown",
        || PromptKind::TrustCertificate(Box::new(cert_prompt(false, true))),
        |_| {},
    );
}

#[test]
fn certificate_details_page_1() {
    snap(
        "certificate_details_page_1",
        || PromptKind::TrustCertificate(Box::new(cert_prompt(false, true))),
        |h| {
            h.keys("d");
        },
    );
}

#[test]
fn certificate_details_page_2() {
    snap(
        "certificate_details_page_2",
        || PromptKind::TrustCertificate(Box::new(cert_prompt(false, true))),
        |h| {
            h.keys("d ]");
        },
    );
}

#[test]
fn certificate_expired() {
    snap(
        "certificate_expired",
        || {
            PromptKind::TrustCertificate(Box::new(cert_prompt_at(
                false,
                false,
                datetime!(2026-09-28 00:00 UTC),
            )))
        },
        |_| {},
    );
}

#[test]
fn certificate_changed() {
    snap(
        "certificate_changed",
        || PromptKind::TrustCertificate(Box::new(cert_prompt(true, true))),
        |_| {},
    );
}

#[test]
fn file_exists_download() {
    snap(
        "file_exists_download",
        || PromptKind::FileExists(Box::new(file_exists_prompt(Direction::Download, true))),
        |_| {},
    );
}

#[test]
fn file_exists_upload_resume_disabled() {
    snap(
        "file_exists_upload_resume_disabled",
        || PromptKind::FileExists(Box::new(file_exists_prompt(Direction::Upload, false))),
        |h| {
            h.keys("a");
        },
    );
}

#[test]
fn file_exists_rename_invalid() {
    snap(
        "file_exists_rename_invalid",
        || PromptKind::FileExists(Box::new(file_exists_prompt(Direction::Download, true))),
        |h| {
            h.keys("m ctrl-u");
            type_text(h, "a/b.html");
            h.keys("enter");
        },
    );
}

#[test]
fn status_badge_two_prompts() {
    for (w, hgt) in SIZES {
        let mut h = harness();
        let mut p = Prompter::new();
        h.render(w, hgt);
        let transfer = SessionId::next();
        h.core_event(CoreEvent::SessionOpened {
            session: transfer,
            purpose: SessionPurpose::Transfer,
            label: "transfer".into(),
        });
        // A key was just pressed: background prompts wait (badge only).
        h.keys("tab");
        for _ in 0..2 {
            let req = p.request_from(transfer, PromptKind::TrustHostKey(unknown_host_key(true)));
            h.core_event(CoreEvent::Prompt(req));
        }
        h.advance(Duration::from_millis(500));
        let screen = h.render(w, hgt);
        assert!(!h.app().prompts.is_visible());
        assert_snapshot!(format!("status_badge_two_prompts_{w}x{hgt}"), screen);
    }
}

#[test]
fn password_60x20_scrolls() {
    let mut h = harness();
    let mut p = Prompter::new();
    h.render(60, 20);
    show(
        &mut h,
        &mut p,
        PromptKind::Password(password_prompt(pw_key("web01"), true)),
    );
    assert_snapshot!("password_60x20_scrolls", h.render(60, 20));
    // Moving to the buttons scrolls them into view.
    h.keys("tab tab tab");
    let screen = h.render(60, 20);
    assert!(screen.contains("[ OK ]"), "{screen}");
    // Even smaller: the buttons scroll into view instead of being cut off.
    let mut h = harness();
    h.render(40, 12);
    show(
        &mut h,
        &mut p,
        PromptKind::Password(password_prompt(pw_key("web01"), true)),
    );
    h.keys("tab tab tab");
    let screen = h.render(40, 12);
    assert!(screen.contains("[ OK ]"), "{screen}");
}

#[test]
fn too_small_shows_message_and_sends_nothing() {
    let mut h = harness();
    let mut p = Prompter::new();
    h.render(25, 7);
    show(
        &mut h,
        &mut p,
        PromptKind::TrustHostKey(unknown_host_key(true)),
    );
    let screen = h.render(25, 7);
    assert!(screen.contains("small"), "{screen}");
    h.keys("enter");
    h.keys("esc");
    assert!(h.app().prompts.is_visible(), "no answer while too small");
    // Back to a usable size: the dialog shows and answers.
    h.render(80, 24);
    h.keys("esc");
    assert!(!h.app().prompts.is_visible());
    assert!(matches!(
        p.answer(),
        Some(courier_ftp_core::events::PromptResponse::HostKey(
            courier_ftp_core::events::TrustAnswer::Reject
        ))
    ));
}

#[test]
fn typed_secrets_never_rendered() {
    const CANARY: &str = "CANARY-5ec7e7";
    for (w, hgt) in [(80, 24), (160, 48), (60, 20)] {
        let mut h = harness();
        let mut p = Prompter::new();
        h.render(w, hgt);
        show(
            &mut h,
            &mut p,
            PromptKind::Password(password_prompt(pw_key("x"), false)),
        );
        type_text(&mut h, CANARY);
        let buf = h.render(w, hgt);
        assert!(!buf.contains(CANARY) && !buf.contains("CANARY"), "{buf}");
        h.keys("enter");
        show(
            &mut h,
            &mut p,
            PromptKind::KeyboardInteractive(kbd_prompt(&[("Password:", false)], "")),
        );
        type_text(&mut h, CANARY);
        let buf = h.render(w, hgt);
        assert!(!buf.contains("CANARY"), "{buf}");
        assert!(!format!("{:?}", h.app()).contains("CANARY"));
        assert!(!format!("{:?}", h.app().prompts).contains("CANARY"));
    }
}
