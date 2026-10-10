//! T69: trust prompt snapshots and key handling.

use courier_ftp_core::{
    events::{PromptResponse, TrustDecision},
    model::{CertificateDetails, CertificateInfo, HostKeyFingerprint},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};
use time::{OffsetDateTime, macros::datetime};
use tokio::sync::oneshot;

use super::{TrustDialog, certificate_dialog, host_key_dialog, wrap};
use crate::ui::{
    modal::{Modal, ModalOutcome},
    theme::Theme,
};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}
fn alt(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::ALT)
}

fn draw(modal: &mut dyn Modal, w: u16, h: u16) -> Terminal<TestBackend> {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    let theme = Theme::new(None, true);
    t.draw(|f| modal.draw(f, f.area(), &theme)).unwrap();
    t
}
fn text(t: &Terminal<TestBackend>) -> String {
    t.backend().to_string()
}

fn new_key() -> HostKeyFingerprint {
    HostKeyFingerprint {
        algorithm: "ssh-ed25519".into(),
        bits: Some(256),
        sha256: "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s".into(),
        md5: Some("MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48".into()),
    }
}
fn old_key() -> HostKeyFingerprint {
    HostKeyFingerprint {
        algorithm: "ssh-ed25519".into(),
        bits: Some(256),
        sha256: "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU".into(),
        md5: Some("MD5:d4:1d:8c:d9:8f:00:b2:04:e9:80:09:98:ec:f8:42:7e".into()),
    }
}

fn unknown(can_remember: bool) -> (TrustDialog, oneshot::Receiver<PromptResponse>) {
    let (tx, rx) = oneshot::channel();
    let d = host_key_dialog(
        "web01.example.com:22",
        &new_key(),
        None,
        can_remember,
        true,
        tx,
    );
    (d, rx)
}
fn changed(can_remember: bool) -> (TrustDialog, oneshot::Receiver<PromptResponse>) {
    let (tx, rx) = oneshot::channel();
    let old = old_key();
    let d = host_key_dialog(
        "web01.example.com:22",
        &new_key(),
        Some(&old),
        can_remember,
        true,
        tx,
    );
    (d, rx)
}

const NOW: OffsetDateTime = datetime!(2026-10-10 12:00 UTC);

fn cert_info(subject: &str, issuer: &str, until: OffsetDateTime) -> CertificateInfo {
    CertificateInfo {
        subject: subject.into(),
        issuer: issuer.into(),
        serial: "3A:F1:09:7C".into(),
        not_before: datetime!(2026-01-01 0:00 UTC),
        not_after: until,
        subject_alt_names: vec!["ftp.example.com".into(), "www.example.com".into()],
        public_key: "RSA 2048".into(),
        signature_algorithm: "sha256WithRSAEncryption".into(),
        fingerprint_sha256: "9F:86:D0:81:88:4C:7D:65:9A:2F:EA:A0:C5:5A:D0:15:A3:BF:4F:1B:2B:0B:\
                             82:2C:D1:5D:6C:15:B0:F0:0A:08"
            .into(),
        fingerprint_sha1: "A9:4A:8F:E5:CC:B1:9B:A6:1C:4C:08:73:D3:91:E9:87:98:2F:BB:D3".into(),
    }
}

fn certificate() -> CertificateDetails {
    CertificateDetails {
        host: "ftp.example.com:990".into(),
        chain: vec![
            cert_info(
                "CN=ftp.example.com, O=Example Ltd",
                "CN=Example CA, O=Example Ltd",
                datetime!(2027-01-01 0:00 UTC),
            ),
            cert_info(
                "CN=Example CA, O=Example Ltd",
                "CN=Example CA, O=Example Ltd",
                datetime!(2036-01-01 0:00 UTC),
            ),
        ],
        hostname_matches: true,
        tls_version: "TLS 1.3".into(),
        cipher: "TLS13_AES_256_GCM_SHA384".into(),
        problem: "unknown issuer".into(),
    }
}

fn cert_dialog(
    details: &CertificateDetails,
    known: Option<&str>,
    can_remember: bool,
) -> (TrustDialog, oneshot::Receiver<PromptResponse>) {
    let (tx, rx) = oneshot::channel();
    (
        certificate_dialog(details, known, can_remember, NOW, true, tx),
        rx,
    )
}

fn decision(rx: &mut oneshot::Receiver<PromptResponse>) -> Option<TrustDecision> {
    match rx.try_recv() {
        Ok(PromptResponse::Trust(d)) => Some(d),
        Ok(other) => panic!("not a trust answer: {other:?}"),
        Err(_) => None,
    }
}

// --- snapshots ---

#[test]
fn unknown_host_key_snapshot() {
    let (mut d, _rx) = unknown(true);
    insta::assert_snapshot!("unknown_host_key", draw(&mut d, 80, 24).backend());
}

#[test]
fn unknown_host_key_vault_locked_snapshot() {
    let (mut d, _rx) = unknown(false);
    insta::assert_snapshot!(
        "unknown_host_key_vault_locked",
        draw(&mut d, 80, 24).backend()
    );
}

#[test]
fn changed_host_key_snapshots() {
    let (mut d, _rx) = changed(true);
    // 80 columns: old and new one after the other.
    insta::assert_snapshot!("changed_host_key", draw(&mut d, 80, 30).backend());
    // Wide enough for the fingerprints side by side.
    insta::assert_snapshot!("changed_host_key_wide", draw(&mut d, 130, 26).backend());
}

#[test]
fn certificate_snapshot() {
    let (mut d, _rx) = cert_dialog(&certificate(), None, true);
    insta::assert_snapshot!("certificate", draw(&mut d, 80, 30).backend());
}

#[test]
fn certificate_problems_are_highlighted() {
    let mut details = certificate();
    details.chain[0].not_after = datetime!(2026-06-01 0:00 UTC);
    details.hostname_matches = false;
    details.problem = "certificate expired".into();
    let (mut d, _rx) = cert_dialog(&details, None, false);
    let t = draw(&mut d, 80, 30);
    insta::assert_snapshot!("certificate_expired_mismatch", t.backend());
    let s = text(&t);
    assert!(s.contains("2026-06-01 00:00 UTC (expired)"), "{s}");
    assert!(s.contains("✘ does not match ftp.example.com"), "{s}");
    assert!(!s.contains("Always trust"), "vault locked: {s}");
}

#[test]
fn certificate_details_snapshot() {
    let (mut d, _rx) = cert_dialog(&certificate(), None, true);
    assert_eq!(d.handle_key(alt('d')), ModalOutcome::Keep);
    insta::assert_snapshot!("certificate_details", draw(&mut d, 80, 30).backend());
    // Scroll to the issuer certificate.
    for _ in 0..12 {
        d.handle_key(key(KeyCode::Down));
    }
    let s = text(&draw(&mut d, 80, 30));
    assert!(s.contains("Certificate 2 of 2"), "{s}");
    // Back to the summary.
    d.handle_key(alt('s'));
    let s = text(&draw(&mut d, 80, 30));
    assert!(
        s.contains("unknown issuer") && s.contains("[ Details ]"),
        "{s}"
    );
}

#[test]
fn changed_certificate_snapshot() {
    let (mut d, _rx) = cert_dialog(
        &certificate(),
        Some(
            "1F:2E:3D:4C:5B:6A:79:88:97:A6:B5:C4:D3:E2:F1:00:1F:2E:3D:4C:5B:6A:79:88:97:A6:\
             B5:C4:D3:E2:F1:00",
        ),
        true,
    );
    insta::assert_snapshot!("changed_certificate", draw(&mut d, 80, 34).backend());
}

#[test]
fn small_terminals_scroll_the_body() {
    let (mut d, _rx) = changed(true);
    let s = text(&draw(&mut d, 60, 16));
    // Buttons and checkboxes stay visible; the body scrolls.
    assert!(
        s.contains("[ Cancel ]") && s.contains("[ ] I have verified"),
        "{s}"
    );
    assert!(s.contains("↓ more"), "{s}");
    d.handle_key(key(KeyCode::PageDown));
    d.handle_key(key(KeyCode::PageDown));
    d.handle_key(key(KeyCode::PageDown));
    let s = text(&draw(&mut d, 60, 16));
    assert!(s.contains("↑ more") && !s.contains("↓ more"), "{s}");
    // Too small for any dialog.
    assert!(text(&draw(&mut d, 15, 4)).contains("terminal"));
}

// --- keys ---

#[test]
fn unknown_key_enter_trusts_and_remembers_by_default() {
    let (mut d, mut rx) = unknown(true);
    assert_eq!(d.handle_key(key(KeyCode::Enter)), ModalOutcome::Close);
    assert_eq!(decision(&mut rx), Some(TrustDecision::Always));
}

#[test]
fn unknown_key_unticked_box_trusts_once() {
    let (mut d, mut rx) = unknown(true);
    d.handle_key(key(KeyCode::Tab)); // to the checkbox
    d.handle_key(key(KeyCode::Char(' ')));
    assert!(text(&draw(&mut d, 80, 24)).contains("[ ] Always trust"));
    assert_eq!(d.handle_key(key(KeyCode::Enter)), ModalOutcome::Close);
    assert_eq!(decision(&mut rx), Some(TrustDecision::Once));
}

#[test]
fn unknown_key_with_locked_vault_never_remembers() {
    let (mut d, mut rx) = unknown(false);
    // The disabled checkbox can't be focused or ticked.
    d.handle_key(key(KeyCode::Tab));
    d.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(d.handle_key(alt('o')), ModalOutcome::Close);
    assert_eq!(decision(&mut rx), Some(TrustDecision::Once));
}

#[test]
fn letters_alone_do_nothing_and_esc_rejects() {
    let (mut d, mut rx) = unknown(true);
    for c in ['o', 'y', 'c', 'a', 't'] {
        assert_eq!(d.handle_key(key(KeyCode::Char(c))), ModalOutcome::Keep);
    }
    assert_eq!(decision(&mut rx), None);
    assert_eq!(d.handle_key(key(KeyCode::Esc)), ModalOutcome::Close);
    assert_eq!(decision(&mut rx), Some(TrustDecision::Reject));
}

#[test]
fn changed_key_enter_cancels() {
    let (mut d, mut rx) = changed(true);
    assert_eq!(d.handle_key(key(KeyCode::Enter)), ModalOutcome::Close);
    assert_eq!(decision(&mut rx), Some(TrustDecision::Reject));
}

#[test]
fn changed_key_enter_on_a_checkbox_cancels() {
    let (mut d, mut rx) = changed(true);
    d.handle_key(key(KeyCode::Tab));
    d.handle_key(key(KeyCode::Char(' '))); // tick "I have verified"
    assert_eq!(d.handle_key(key(KeyCode::Enter)), ModalOutcome::Close);
    assert_eq!(decision(&mut rx), Some(TrustDecision::Reject));
}

#[test]
fn changed_key_needs_the_explicit_checkbox() {
    let (mut d, mut rx) = changed(true);
    // Moving to "Trust new key" and pressing it without the tick refuses.
    d.handle_key(key(KeyCode::Right));
    assert_eq!(d.handle_key(key(KeyCode::Enter)), ModalOutcome::Keep);
    assert_eq!(d.handle_key(alt('t')), ModalOutcome::Keep);
    assert_eq!(decision(&mut rx), None);
    let s = text(&draw(&mut d, 80, 30));
    assert!(s.contains("first, or choose Cancel"), "{s}");
    // The refusal focused the checkbox: tick it, go to the buttons, trust.
    d.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(d.handle_key(alt('t')), ModalOutcome::Close);
    assert_eq!(decision(&mut rx), Some(TrustDecision::Once));
}

#[test]
fn changed_key_replacing_the_cached_key_trusts_always() {
    let (mut d, mut rx) = changed(true);
    d.handle_key(key(KeyCode::Tab));
    d.handle_key(key(KeyCode::Char(' ')));
    d.handle_key(key(KeyCode::Tab));
    d.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(d.handle_key(alt('t')), ModalOutcome::Close);
    assert_eq!(decision(&mut rx), Some(TrustDecision::Always));
}

#[test]
fn changed_key_with_locked_vault_skips_the_replace_box() {
    let (mut d, mut rx) = changed(false);
    d.handle_key(key(KeyCode::Tab));
    d.handle_key(key(KeyCode::Char(' '))); // confirm
    d.handle_key(key(KeyCode::Tab)); // skips the disabled box: buttons
    d.handle_key(key(KeyCode::Char(' ')));
    assert!(text(&draw(&mut d, 80, 30)).contains("[-] Replace the cached key"));
    assert_eq!(d.handle_key(alt('t')), ModalOutcome::Close);
    assert_eq!(decision(&mut rx), Some(TrustDecision::Once));
}

#[test]
fn certificate_buttons() {
    let details = certificate();
    let (mut d, mut rx) = cert_dialog(&details, None, true);
    assert_eq!(d.handle_key(key(KeyCode::Enter)), ModalOutcome::Close);
    assert_eq!(decision(&mut rx), Some(TrustDecision::Reject), "default");

    let (mut d, mut rx) = cert_dialog(&details, None, true);
    assert_eq!(d.handle_key(alt('t')), ModalOutcome::Close);
    assert_eq!(decision(&mut rx), Some(TrustDecision::Once));

    let (mut d, mut rx) = cert_dialog(&details, None, true);
    assert_eq!(d.handle_key(alt('a')), ModalOutcome::Close);
    assert_eq!(decision(&mut rx), Some(TrustDecision::Always));

    // Vault locked: there is no "Always trust".
    let (mut d, mut rx) = cert_dialog(&details, None, false);
    assert_eq!(d.handle_key(alt('a')), ModalOutcome::Keep);
    assert_eq!(decision(&mut rx), None);
}

#[test]
fn changed_certificate_needs_the_checkbox() {
    let details = certificate();
    let (mut d, mut rx) = cert_dialog(&details, Some("00:11"), true);
    assert_eq!(d.handle_key(alt('a')), ModalOutcome::Keep);
    assert_eq!(decision(&mut rx), None);
    d.handle_key(key(KeyCode::Char(' ')));
    assert_eq!(d.handle_key(alt('a')), ModalOutcome::Close);
    assert_eq!(decision(&mut rx), Some(TrustDecision::Always));

    let (mut d, mut rx) = cert_dialog(&details, Some("00:11"), true);
    assert_eq!(d.handle_key(key(KeyCode::Enter)), ModalOutcome::Close);
    assert_eq!(decision(&mut rx), Some(TrustDecision::Reject));
}

#[test]
fn dialog_is_done_when_the_core_stops_waiting() {
    let (d, rx) = unknown(true);
    assert!(!d.is_done());
    drop(rx);
    assert!(d.is_done());
}

#[test]
fn wrap_breaks_at_spaces_and_cuts_long_words() {
    assert_eq!(wrap("aa bb cc", 5), vec!["aa bb", "cc"]);
    assert_eq!(wrap("abcdefgh", 3), vec!["abc", "def", "gh"]);
    assert_eq!(wrap("a\n\nb", 10), vec!["a", "", "b"]);
    assert_eq!(wrap("ab abcdefg", 4), vec!["ab", "abcd", "efg"]);
    // Fingerprints break after a colon.
    assert_eq!(wrap("AB:CD:EF:01", 7), vec!["AB:CD:", "EF:01"]);
}
