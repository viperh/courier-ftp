#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use courier_ftp_core::events::{PromptKind, PromptResponse, TrustAnswer};
use pretty_assertions::assert_eq;

use super::*;
use crate::components::prompts::tests::{Prompter, k, ui_normal, unknown_host_key};

fn host_key() -> PromptKind {
    PromptKind::TrustHostKey(unknown_host_key(true))
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Answers the visible prompt with `Enter` (`Trust` → AlwaysTrust) after the guard.
fn enter(q: &mut PromptQueue, at: Instant) -> PromptAnswered {
    q.handle_key(k("enter"), at).expect("answered")
}

#[test]
fn foreground_before_background_fifo() {
    let mut p = Prompter::new();
    let mut q = PromptQueue::default();
    let t0 = Instant::now();
    let bg1 = p.request(host_key());
    let fg = p.request(host_key());
    let bg2 = p.request(host_key());
    let (bg1_id, fg_id, bg2_id) = (bg1.id, fg.id, bg2.id);
    q.push(bg1, PromptOrigin::Background, t0);
    q.push(fg, PromptOrigin::Foreground, t0);
    q.push(bg2, PromptOrigin::Background, t0);
    assert_eq!(q.badge(true).as_deref(), Some("⚠ 3 prompts"));

    let mut t = t0;
    let mut order = Vec::new();
    for _ in 0..3 {
        let ticks = q.tick(t, &ui_normal());
        let Some(PromptTick::Opened(id)) = ticks.first().copied() else {
            panic!("nothing opened: {ticks:?}");
        };
        // One at a time.
        assert_eq!(q.tick(t, &ui_normal()), Vec::new());
        assert_eq!(q.visible_id(), Some(id));
        order.push(id);
        t += ms(600);
        let a = enter(&mut q, t);
        assert!(a.delivered);
        assert!(!q.is_visible());
        // The next one opens on the following tick.
        t += ms(250);
    }
    assert_eq!(order, [fg_id, bg1_id, bg2_id]);
    for id in order {
        assert!(matches!(
            p.answer_of(id),
            Some(PromptResponse::HostKey(TrustAnswer::AlwaysTrust))
        ));
    }
    assert_eq!(q.badge(true), None);
}

#[tokio::test(start_paused = true)]
async fn background_waits_for_normal_mode_and_idle() {
    let mut p = Prompter::new();
    let mut q = PromptQueue::default();
    let input = UiFocusState {
        mode: Mode::Input,
        ..ui_normal()
    };
    let t0 = Instant::now();
    q.note_key(t0);
    let req = p.request(host_key());
    q.push(req, PromptOrigin::Background, t0);
    // Typing in a text field: only the badge.
    tokio::time::advance(ms(5000)).await;
    assert_eq!(q.tick(Instant::now(), &input), Vec::new());
    assert!(!q.is_visible());
    assert_eq!(q.badge(false).as_deref(), Some("! 1 prompt"));
    // Back in a browsing mode, but a key was pressed 1 s ago.
    q.note_key(Instant::now());
    tokio::time::advance(ms(1000)).await;
    assert_eq!(q.tick(Instant::now(), &ui_normal()), Vec::new());
    let file_list = UiFocusState {
        mode: Mode::FileList,
        ..ui_normal()
    };
    tokio::time::advance(ms(999)).await;
    assert_eq!(q.tick(Instant::now(), &file_list), Vec::new());
    // 2 s without keys: opens.
    tokio::time::advance(ms(1)).await;
    assert!(matches!(
        q.tick(Instant::now(), &file_list).as_slice(),
        [PromptTick::Opened(_)]
    ));
    // A foreground prompt opens at once even while typing.
    let mut q = PromptQueue::default();
    q.note_key(Instant::now());
    let req = p.request(host_key());
    q.push(req, PromptOrigin::Foreground, Instant::now());
    assert!(matches!(
        q.tick(Instant::now(), &input).as_slice(),
        [PromptTick::Opened(_)]
    ));
}

#[test]
fn ctrl_x_p_opens_next() {
    let mut p = Prompter::new();
    let mut q = PromptQueue::default();
    let input = UiFocusState {
        mode: Mode::Input,
        ..ui_normal()
    };
    let t0 = Instant::now();
    q.note_key(t0);
    assert!(!q.open_next(t0), "nothing waits");
    let req = p.request(host_key());
    q.push(req, PromptOrigin::Background, t0);
    assert!(q.tick(t0, &input).is_empty());
    // Another dialog is open: ctrl-x p opens the prompt right after it closes.
    let other = UiFocusState {
        other_dialog_open: true,
        ..input
    };
    assert!(q.open_next(t0));
    assert!(q.tick(t0, &other).is_empty());
    assert!(!q.is_visible());
    assert!(matches!(
        q.tick(t0, &input).as_slice(),
        [PromptTick::Opened(_)]
    ));
}

#[test]
fn withdrawn_prompt_removed_within_one_tick() {
    let mut p = Prompter::new();
    let mut q = PromptQueue::default();
    let t0 = Instant::now();
    let a = p.request(host_key());
    let b = p.request(host_key());
    let (a_id, b_id) = (a.id, b.id);
    q.push(a, PromptOrigin::Foreground, t0);
    q.push(b, PromptOrigin::Foreground, t0);
    q.tick(t0, &ui_normal());
    assert_eq!(q.visible_id(), Some(a_id));
    // A queued prompt withdrawn: the badge changes.
    p.withdraw(b_id);
    assert_eq!(q.tick(t0, &ui_normal()), [PromptTick::BadgeChanged]);
    assert_eq!(q.queued_len(), 0);
    // The visible one withdrawn: closed within one tick.
    p.withdraw(a_id);
    assert_eq!(q.tick(t0, &ui_normal()), [PromptTick::Withdrawn(a_id)]);
    assert!(!q.is_visible());
    assert_eq!(
        WITHDRAWN_MESSAGE,
        "Prompt withdrawn: the connection was closed"
    );
}

#[test]
fn input_guard_500ms() {
    let mut p = Prompter::new();
    let mut q = PromptQueue::default();
    let t0 = Instant::now();
    let req = p.request(host_key());
    q.push(req, PromptOrigin::Foreground, t0);
    q.tick(t0, &ui_normal());
    for at in [0, 100, 499] {
        assert!(q.handle_key(k("enter"), t0 + ms(at)).is_none(), "{at} ms");
        assert!(q.handle_key(k("esc"), t0 + ms(at)).is_none(), "{at} ms");
        assert!(q.is_visible());
    }
    let a = q
        .handle_key(k("esc"), t0 + ms(500))
        .expect("answered after 500 ms");
    assert!(a.delivered);
    assert!(matches!(
        p.answer(),
        Some(PromptResponse::HostKey(TrustAnswer::Reject))
    ));
}

#[test]
fn suspend_requeues_visible_at_front() {
    let mut p = Prompter::new();
    let mut q = PromptQueue::default();
    let t0 = Instant::now();
    let a = p.request(host_key());
    let b = p.request(host_key());
    let a_id = a.id;
    q.push(a, PromptOrigin::Foreground, t0);
    q.push(b, PromptOrigin::Foreground, t0);
    q.tick(t0, &ui_normal());
    assert_eq!(q.visible_id(), Some(a_id));
    // Toggle the checkbox, then lock.
    q.handle_key(k("a"), t0 + ms(600));
    q.set_suspended(true);
    assert!(!q.is_visible());
    assert_eq!(q.queued_len(), 2);
    let locked = UiFocusState {
        vault_locked: true,
        ..ui_normal()
    };
    assert!(q.tick(t0 + ms(700), &locked).is_empty());
    assert!(q.tick(t0 + ms(700), &ui_normal()).is_empty(), "suspended");
    q.set_suspended(false);
    let t1 = t0 + ms(800);
    assert_eq!(q.tick(t1, &ui_normal()), [PromptTick::Opened(a_id)]);
    // Rebuilt from the payload: the checkbox is checked again.
    let ans = q.handle_key(k("enter"), t1 + ms(500)).unwrap();
    assert_eq!(ans.id, a_id);
    assert!(matches!(
        p.answer_of(a_id),
        Some(PromptResponse::HostKey(TrustAnswer::AlwaysTrust))
    ));
}

#[test]
fn badge_text_unicode_and_ascii() {
    let mut p = Prompter::new();
    let mut q = PromptQueue::default();
    assert_eq!(q.badge(true), None);
    let t0 = Instant::now();
    q.push(p.request(host_key()), PromptOrigin::Background, t0);
    assert_eq!(q.badge(true).as_deref(), Some("⚠ 1 prompt"));
    assert_eq!(q.badge(false).as_deref(), Some("! 1 prompt"));
    q.push(p.request(host_key()), PromptOrigin::Background, t0);
    assert_eq!(q.badge(true).as_deref(), Some("⚠ 2 prompts"));
    assert_eq!(q.badge(false).as_deref(), Some("! 2 prompts"));
}

#[test]
fn answer_to_withdrawn_reply_is_not_delivered() {
    let mut p = Prompter::new();
    let mut q = PromptQueue::default();
    let t0 = Instant::now();
    let req = p.request(PromptKind::Password(
        crate::components::prompts::tests::password_prompt(
            crate::components::prompts::tests::pw_key("h"),
            false,
        ),
    ));
    let id = req.id;
    q.push(req, PromptOrigin::Foreground, t0);
    q.tick(t0, &ui_normal());
    // Remember for this session.
    q.handle_key(k("tab"), t0 + ms(600));
    q.handle_key(k("space"), t0 + ms(600));
    p.withdraw(id);
    let a = q.handle_key(k("enter"), t0 + ms(600)).unwrap();
    assert!(!a.delivered);
    assert!(a.pending.is_none(), "nothing kept for a withdrawn prompt");
}
