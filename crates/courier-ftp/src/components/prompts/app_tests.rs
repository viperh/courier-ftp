//! UI-flow tests: the app with synthetic keys and prompts from a fake core (T69's
//! `prompts_flow` scenarios; the binary crate has no library for `tests/`).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::time::Duration;

use courier_ftp_core::events::{
    CoreEvent, DisconnectReason, PromptKind, PromptResponse, SessionId, SessionPurpose, TrustAnswer,
};

use super::{
    queue::WITHDRAWN_MESSAGE,
    secrets::PENDING_DROPS,
    snapshot_tests::{harness, show},
    tests::{Prompter, password_prompt, pw_key, unknown_host_key},
};
use crate::{
    action::Action, app::Mode, components::main_screen::layout::Region, keymap::chord::KeyChord,
    testing::AppHarness,
};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn host_key() -> PromptKind {
    PromptKind::TrustHostKey(unknown_host_key(true))
}

fn transfer_session(h: &mut AppHarness) -> SessionId {
    let s = SessionId::next();
    h.core_event(CoreEvent::SessionOpened {
        session: s,
        purpose: SessionPurpose::Transfer,
        label: "transfer".into(),
    });
    s
}

fn status(h: &AppHarness) -> Option<String> {
    h.app().main.status().map(|m| m.text.clone())
}

fn type_text(h: &mut AppHarness, text: &str) {
    for c in text.chars() {
        h.key(KeyChord::char(c));
    }
}

#[test]
fn three_concurrent_prompts_flow() {
    let mut h = harness();
    let mut p = Prompter::new();
    h.render(80, 24);
    let transfer = transfer_session(&mut h);
    let bg1 = p.request_from(transfer, host_key());
    let fg = p.request(host_key());
    let bg2 = p.request_from(transfer, host_key());
    let ids = [fg.id, bg1.id, bg2.id];
    for r in [bg1, fg, bg2] {
        h.core_event(CoreEvent::Prompt(r));
    }
    h.advance(ms(250));
    assert_eq!(h.mode(), Mode::Dialog);
    let mut seen = Vec::new();
    for i in 0..3 {
        h.advance(ms(500));
        let id = h.app().prompts.visible_id().expect("a prompt is visible");
        assert_eq!(h.app().prompts.visible_kind(), Some("host_key_unknown"));
        seen.push(id);
        assert_eq!(h.app().prompts.queued_len(), 2 - i);
        h.keys("c");
        assert!(!h.app().prompts.is_visible() || i < 2);
        // The next one opens on the following tick.
        h.advance(ms(250));
    }
    assert_eq!(seen, ids);
    for id in ids {
        assert!(matches!(
            p.answer_of(id),
            Some(PromptResponse::HostKey(TrustAnswer::Reject))
        ));
    }
    assert!(!h.app().prompts.is_visible());
    assert_eq!(h.app().status_sources.prompts_badge, None);
}

#[test]
fn background_prompt_during_quickconnect_typing() {
    let mut h = harness();
    let mut p = Prompter::new();
    h.render(80, 24);
    // A text field has the focus (the log search; T58's quickconnect is the same mode).
    h.action(Action::FocusRegion(Region::Log));
    h.keys("/");
    assert_eq!(h.mode(), Mode::Input);
    let transfer = transfer_session(&mut h);
    h.core_event(CoreEvent::Prompt(p.request_from(transfer, host_key())));
    h.advance(ms(5000));
    assert!(!h.app().prompts.is_visible(), "never steals the text field");
    assert_eq!(
        h.app().status_sources.prompts_badge.as_deref(),
        Some("⚠ 1 prompt")
    );
    assert!(h.render(80, 24).contains("1 prompt"));
    // Typing goes on into the field.
    type_text(&mut h, "abc");
    assert_eq!(h.mode(), Mode::Input);
    // ctrl-x p opens it at once.
    h.keys("ctrl-x p");
    assert!(h.app().prompts.is_visible());
    assert_eq!(h.app().status_sources.prompts_badge, None);
    h.advance(ms(600));
    h.keys("esc");
    assert!(!h.app().prompts.is_visible());
    assert_eq!(h.mode(), Mode::Input, "back in the text field");

    // Leaving the field: after 2 s without keys the next one opens by itself.
    h.core_event(CoreEvent::Prompt(p.request_from(transfer, host_key())));
    h.keys("esc");
    assert_ne!(h.mode(), Mode::Input);
    h.advance(ms(1500));
    assert!(!h.app().prompts.is_visible());
    h.advance(ms(750));
    assert!(h.app().prompts.is_visible());
}

#[test]
fn lock_unlock_restores_prompt() {
    let mut h = harness();
    let mut p = Prompter::new();
    h.render(80, 24);
    show(&mut h, &mut p, host_key());
    let before = h.render(80, 24);
    assert!(before.contains("Unknown host key"));
    h.with_app(|a| a.set_vault_locked(true));
    h.advance(ms(1000));
    assert!(!h.app().prompts.is_visible());
    assert!(!h.render(80, 24).contains("Unknown host key"));
    assert_eq!(h.app().prompts.queued_len(), 1, "not cancelled by locking");
    h.with_app(|a| a.set_vault_locked(false));
    h.advance(ms(600));
    assert_eq!(
        h.render(80, 24),
        before,
        "shown again with its original content"
    );
    h.keys("enter");
    assert!(matches!(
        p.answer(),
        Some(PromptResponse::HostKey(TrustAnswer::AlwaysTrust))
    ));
}

#[test]
fn password_remember_then_second_connection_silent() {
    let mut h = harness();
    let mut p = Prompter::new();
    h.render(80, 24);
    let kind = || PromptKind::Password(password_prompt(pw_key("web01.example.com"), false));
    show(&mut h, &mut p, kind());
    let id = h.app().prompts.visible_id().unwrap();
    type_text(&mut h, "s3cret");
    h.keys("tab space enter");
    assert!(!h.app().prompts.is_visible());
    assert!(matches!(
        p.answer_of(id),
        Some(PromptResponse::Secret {
            remember_session: true,
            ..
        })
    ));
    assert_eq!(
        h.app().secret_cache.len(),
        0,
        "not before the server accepts it"
    );
    h.core_event(CoreEvent::CredentialAccepted {
        session: p.session(),
        prompt_id: id,
    });
    assert_eq!(h.app().secret_cache.len(), 1);
    // The next connection's prompt is answered without a dialog.
    h.core_event(CoreEvent::Prompt(p.request(kind())));
    h.advance(ms(250));
    assert!(!h.app().prompts.is_visible());
    match p.answer() {
        Some(PromptResponse::Secret {
            value,
            remember_session,
            save_in_vault,
        }) => {
            assert_eq!(value.expose(), "s3cret");
            assert!(!remember_session && !save_in_vault);
        }
        other => panic!("unexpected {other:?}"),
    }
    // A retry always shows.
    h.core_event(CoreEvent::Prompt(p.request(PromptKind::Password(
        password_prompt(pw_key("web01.example.com"), true),
    ))));
    h.advance(ms(250));
    assert!(h.app().prompts.is_visible());
    // Locking the vault clears the cache.
    h.with_app(|a| a.set_vault_locked(true));
    assert_eq!(h.app().secret_cache.len(), 0);
}

#[test]
fn save_in_vault_only_after_credential_accepted() {
    let mut h = harness();
    let mut p = Prompter::new();
    h.render(80, 24);
    let kind = || PromptKind::Password(password_prompt(pw_key("web01.example.com"), false));
    let drops = PENDING_DROPS.with(std::cell::Cell::get);
    // A failed connect: nothing is saved and the typed secret is dropped.
    show(&mut h, &mut p, kind());
    type_text(&mut h, "first");
    h.keys("tab tab space enter");
    assert_eq!(h.app().pending_credentials.len(), 1);
    h.core_event(CoreEvent::Disconnected {
        session: p.session(),
        reason: DisconnectReason::Failed("Permission denied".into()),
    });
    assert_eq!(h.app().pending_credentials.len(), 0);
    assert_eq!(PENDING_DROPS.with(std::cell::Cell::get) - drops, 1);
    assert_eq!(h.app().secret_cache.len(), 0);

    // Accepted: `SaveCredential` is emitted (T31 is not there yet: a notice).
    show(&mut h, &mut p, kind());
    let id = h.app().prompts.visible_id().unwrap();
    type_text(&mut h, "second");
    h.keys("tab tab space enter");
    h.core_event(CoreEvent::CredentialAccepted {
        session: p.session(),
        prompt_id: id,
    });
    assert_eq!(h.app().pending_credentials.len(), 0);
    assert_eq!(
        status(&h).as_deref(),
        Some("Saving credentials in the vault is not available yet")
    );
    assert_eq!(h.app().secret_cache.len(), 0, "remember was not checked");
}

#[test]
fn withdrawn_prompt_closes_and_says_so() {
    let mut h = harness();
    let mut p = Prompter::new();
    h.render(80, 24);
    show(&mut h, &mut p, host_key());
    let id = h.app().prompts.visible_id().unwrap();
    p.withdraw(id);
    h.advance(ms(250));
    assert!(!h.app().prompts.is_visible());
    assert_eq!(status(&h).as_deref(), Some(WITHDRAWN_MESSAGE));
    assert!(h.render(80, 24).contains("Prompt withdrawn"));
    h.advance(ms(3100));
    assert_eq!(status(&h), None, "shown for 3 s");
}

#[test]
fn keys_within_guard_after_open_do_nothing() {
    let mut h = harness();
    let mut p = Prompter::new();
    h.render(80, 24);
    h.core_event(CoreEvent::Prompt(p.request(host_key())));
    assert!(!h.app().prompts.is_visible(), "opens on the next tick");
    // Find the tick that opens it (to the nearest 10 ms).
    for _ in 0..30 {
        if h.app().prompts.is_visible() {
            break;
        }
        h.advance(ms(10));
    }
    assert!(h.app().prompts.is_visible());
    h.keys("enter esc c t");
    assert!(h.app().prompts.is_visible());
    h.advance(ms(480));
    h.keys("enter");
    assert!(h.app().prompts.is_visible());
    h.advance(ms(30));
    h.keys("enter");
    assert!(!h.app().prompts.is_visible());
}

#[test]
fn open_next_prompt_without_prompts() {
    let mut h = harness();
    h.render(80, 24);
    h.keys("ctrl-x p");
    assert_eq!(status(&h).as_deref(), Some("No prompts are waiting"));
}

#[test]
fn certificate_chain_from_server_info() {
    use crate::components::prompts::{CertificateChainDialog, tests::cert};
    let mut h = harness();
    h.render(80, 24);
    let chain = vec![cert(
        "CN=ftp.example.com",
        "CN=CA",
        time::macros::datetime!(2027-01-01 00:00 UTC),
        false,
    )];
    h.app_mut()
        .modals
        .push(CertificateChainDialog::new(chain, super::tests::now_2026()));
    let screen = h.render(80, 24);
    assert!(screen.contains("Certificate 1 of 1: server"), "{screen}");
    assert!(screen.contains("CN=ftp.example.com"), "{screen}");
    h.keys("j esc");
    assert!(h.app().modals.is_empty());
}
