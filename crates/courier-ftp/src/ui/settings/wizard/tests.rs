//! T72: the wizard on its own: a snapshot per page, navigation, cancel,
//! validation, the test requests and replies, and what *Apply* returns.
//! The probe itself is tested in `courier_ftp_proto_ftp::probe` against
//! an in-process server; the flow through the app (config file written)
//! is in `app/wizard_tests.rs`.

use std::net::IpAddr;

use courier_ftp_core::settings::SymbolMode;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};

use super::*;

fn settings() -> Settings {
    let mut s = Settings::default();
    s.interface.unicode_symbols = SymbolMode::Unicode;
    s
}

fn wizard() -> NetworkWizard {
    let mut w = NetworkWizard::new(&settings());
    assert!(matches!(
        w.take_requests().as_slice(),
        [WizardRequest::LoadSites]
    ));
    w
}

fn press(w: &mut NetworkWizard, code: KeyCode) {
    w.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
}

fn alt(w: &mut NetworkWizard, c: char) {
    w.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::ALT));
}

fn typed(w: &mut NetworkWizard, text: &str) {
    for c in text.chars() {
        press(w, KeyCode::Char(c));
    }
}

fn render(w: &NetworkWizard) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(84, 30)).unwrap();
    terminal
        .draw(|f| w.draw(f, f.area(), &Theme::default()))
        .unwrap();
    terminal
}

fn screen(w: &NetworkWizard) -> String {
    render(w).backend().to_string()
}

fn sites() -> Vec<(ItemId, String)> {
    vec![
        (ItemId::new(), "Work/Intranet".to_owned()),
        (ItemId::new(), "Web host".to_owned()),
    ]
}

fn result(step: ProbeStep, status: StepStatus, detail: &str) -> StepResult {
    StepResult {
        step,
        status,
        detail: detail.to_owned(),
        advice: None,
    }
}

/// A finished test where passive fails and active works.
fn only_active_works(w: &mut NetworkWizard, run: u64) {
    let mut steps = vec![
        result(
            ProbeStep::Connect,
            StepStatus::Ok,
            "Logged in to 192.0.2.1:21.",
        ),
        result(
            ProbeStep::PassiveAddress,
            StepStatus::Warning,
            "The server is behind NAT: it announces its private address 10.0.0.5 instead of 192.0.2.1.",
        ),
        result(
            ProbeStep::Passive,
            StepStatus::Failed,
            "Could not open the passive data connection: timed out",
        ),
        result(
            ProbeStep::ExternalAddress,
            StepStatus::Ok,
            "Your address 198.51.100.7 is public and is announced as it is.",
        ),
        result(
            ProbeStep::Active,
            StepStatus::Ok,
            "Active mode works: the listing arrived (512 bytes).",
        ),
    ];
    steps[1].advice = Some("Turn on “Use the server's external IP address instead”.".into());
    for r in steps {
        w.apply_reply(WizardReply::Probe {
            run,
            event: ProbeEvent::Started(r.step),
        });
        w.apply_reply(WizardReply::Probe {
            run,
            event: ProbeEvent::Finished(r),
        });
    }
    w.apply_reply(WizardReply::ProbeDone { run });
}

/// Go to the test page and start a test against `url`; the request.
fn start_test(w: &mut NetworkWizard, url: &str) -> (u64, Box<Settings>, CancellationToken) {
    while w.page() != WizardPage::Test {
        alt(w, 'n');
    }
    // Address (no saved sites loaded, so it is already selected).
    press(w, KeyCode::Tab);
    press(w, KeyCode::Tab);
    typed(w, url);
    alt(w, 'r');
    match w.take_requests().pop() {
        Some(WizardRequest::Probe {
            run,
            target: ProbeTarget::Address { url: got, password },
            settings,
            cancel,
        }) => {
            assert_eq!(got, url);
            assert!(password.is_none());
            (run, settings, cancel)
        }
        other => panic!("expected a probe request, got {other:?}"),
    }
}

#[test]
fn pages() {
    let mut w = wizard();
    insta::assert_snapshot!("wizard_intro", render(&w).backend());
    alt(&mut w, 'n');
    assert_eq!(w.page(), WizardPage::Passive);
    insta::assert_snapshot!("wizard_passive", render(&w).backend());
    alt(&mut w, 'n');
    insta::assert_snapshot!("wizard_active", render(&w).backend());
    alt(&mut w, 'n');
    w.apply_reply(WizardReply::Sites(Ok(sites())));
    insta::assert_snapshot!("wizard_test", render(&w).backend());
}

#[test]
fn test_results_and_summary() {
    let mut w = wizard();
    w.apply_reply(WizardReply::Sites(Ok(Vec::new())));
    let (run, _, _) = start_test(&mut w, "ftp://bob@192.0.2.1");
    assert!(w.is_testing());
    assert!(screen(&w).contains("[ Stop test ]"));
    assert!(screen(&w).contains("Connect and log in…"));
    only_active_works(&mut w, run);
    assert!(!w.is_testing());
    insta::assert_snapshot!("wizard_test_results", render(&w).backend());
    alt(&mut w, 'n');
    assert_eq!(w.page(), WizardPage::Summary);
    insta::assert_snapshot!("wizard_summary", render(&w).backend());
}

#[test]
fn ascii_symbols() {
    let mut s = settings();
    s.interface.unicode_symbols = SymbolMode::Ascii;
    let mut w = NetworkWizard::new(&s);
    w.apply_reply(WizardReply::Sites(Ok(Vec::new())));
    let (run, _, _) = start_test(&mut w, "h");
    only_active_works(&mut w, run);
    let text = screen(&w);
    assert!(text.contains("XX Passive mode listing"), "{text}");
    assert!(text.contains("ok Active mode listing"), "{text}");
    assert!(!text.contains('✔'));
}

#[test]
fn back_and_forward_keep_what_was_entered() {
    let mut w = wizard();
    alt(&mut w, 'n');
    // Passive: turn the fallback off.
    press(&mut w, KeyCode::Tab);
    press(&mut w, KeyCode::Char(' '));
    alt(&mut w, 'n');
    assert!(!w.ftp().fallback_to_active);
    // Active: a fixed IP and a port range.
    press(&mut w, KeyCode::Right); // Use this IP
    press(&mut w, KeyCode::Tab);
    typed(&mut w, "203.0.113.9");
    press(&mut w, KeyCode::Tab);
    press(&mut w, KeyCode::Right); // Range
    alt(&mut w, 'b');
    assert_eq!(w.page(), WizardPage::Passive);
    alt(&mut w, 'n');
    assert_eq!(w.page(), WizardPage::Active);
    let text = screen(&w);
    assert!(text.contains("203.0.113.9"), "{text}");
    assert!(text.contains("(•) Range"), "{text}");
    alt(&mut w, 'n');
    assert_eq!(
        w.ftp().active_external_ip,
        ExternalIp::Fixed("203.0.113.9".parse::<IpAddr>().unwrap())
    );
    assert_eq!(w.ftp().active_port_range, Some((50_000, 50_100)));
    // Back from the first page does nothing; Esc cancels.
    alt(&mut w, 'b');
    alt(&mut w, 'b');
    alt(&mut w, 'b');
    assert_eq!(w.page(), WizardPage::Intro);
    alt(&mut w, 'b');
    assert_eq!(w.page(), WizardPage::Intro);
    press(&mut w, KeyCode::Esc);
    assert_eq!(w.take_outcome(), Some(WizardOutcome::Cancel));
}

#[test]
fn invalid_active_settings_block_next() {
    let mut w = wizard();
    alt(&mut w, 'n');
    alt(&mut w, 'n');
    // Get from URL with an https URL: refused (the lookup is plain HTTP).
    press(&mut w, KeyCode::Right);
    press(&mut w, KeyCode::Right);
    press(&mut w, KeyCode::Tab);
    typed(&mut w, "https://ip.example.com");
    alt(&mut w, 'n');
    assert_eq!(w.page(), WizardPage::Active);
    assert!(screen(&w).contains("must start with http://"));
    // A range backwards.
    let mut w = wizard();
    alt(&mut w, 'n');
    alt(&mut w, 'n');
    press(&mut w, KeyCode::Tab);
    press(&mut w, KeyCode::Tab);
    press(&mut w, KeyCode::Right); // Range
    press(&mut w, KeyCode::Tab);
    press(&mut w, KeyCode::Tab);
    for _ in 0..6 {
        press(&mut w, KeyCode::Backspace);
    }
    typed(&mut w, "2000");
    alt(&mut w, 'n');
    assert_eq!(w.page(), WizardPage::Active);
    assert!(screen(&w).contains("must not be above"), "{}", screen(&w));
}

#[test]
fn the_test_uses_the_settings_entered() {
    let mut w = wizard();
    alt(&mut w, 'n');
    press(&mut w, KeyCode::Char(' ')); // external IP instead: off
    let (run, settings, cancel) = start_test(&mut w, "ftp.example.com");
    assert_eq!(run, 1);
    assert!(!settings.ftp.passive_ignore_unroutable_ip);
    // Running it again cancels the first run; its late replies are dropped.
    alt(&mut w, 's'); // Stop test
    assert!(cancel.is_cancelled());
    alt(&mut w, 'r');
    let Some(WizardRequest::Probe { run: second, .. }) = w.take_requests().pop() else {
        panic!("no second run");
    };
    assert_eq!(second, 2);
    w.apply_reply(WizardReply::Probe {
        run: 1,
        event: ProbeEvent::Finished(result(ProbeStep::Connect, StepStatus::Failed, "old")),
    });
    assert!(w.report().unwrap().steps.is_empty());
    // A test that can't start says why.
    w.apply_reply(WizardReply::ProbeFailed {
        run: 2,
        message: "Enter the password for bob in the Password field".into(),
    });
    assert!(!w.is_testing());
    assert!(screen(&w).contains("Enter the password for bob"));
}

#[test]
fn a_saved_site_and_its_password() {
    let mut w = wizard();
    let list = sites();
    w.apply_reply(WizardReply::Sites(Ok(list.clone())));
    for _ in 0..3 {
        alt(&mut w, 'n');
    }
    // Saved site is selected; pick the second one and type a password.
    press(&mut w, KeyCode::Tab);
    press(&mut w, KeyCode::Right);
    press(&mut w, KeyCode::Tab);
    press(&mut w, KeyCode::Tab);
    typed(&mut w, "pw");
    press(&mut w, KeyCode::Enter); // Enter runs the test.
    match w.take_requests().pop() {
        Some(WizardRequest::Probe {
            target: ProbeTarget::Site { id, password },
            ..
        }) => {
            assert_eq!(id, list[1].0);
            assert_eq!(password.unwrap().expose_secret(), "pw");
        }
        other => panic!("expected a site probe, got {other:?}"),
    }
}

#[test]
fn sites_unavailable() {
    let mut w = wizard();
    w.apply_reply(WizardReply::Sites(Err(
        "Unlock the vault to test with a saved site".into(),
    )));
    for _ in 0..3 {
        alt(&mut w, 'n');
    }
    // "Address" is preselected without sites; choosing the site fails.
    press(&mut w, KeyCode::Left);
    alt(&mut w, 'r');
    assert!(w.take_requests().is_empty());
    assert!(screen(&w).contains("Unlock the vault"));
}

#[test]
fn apply_returns_the_settings_with_the_suggested_mode() {
    let mut w = wizard();
    w.apply_reply(WizardReply::Sites(Ok(Vec::new())));
    let (run, _, _) = start_test(&mut w, "h");
    only_active_works(&mut w, run);
    alt(&mut w, 'n');
    alt(&mut w, 'a');
    let Some(WizardOutcome::Apply(ftp)) = w.take_outcome() else {
        panic!("not applied");
    };
    assert_eq!(ftp.transfer_mode, FtpTransferMode::Active);
    // The user can still pick passive.
    let mut w = wizard();
    for _ in 0..4 {
        alt(&mut w, 'n');
    }
    assert_eq!(w.page(), WizardPage::Summary);
    assert!(screen(&w).contains("Not tested."));
    press(&mut w, KeyCode::Right);
    press(&mut w, KeyCode::Enter);
    let Some(WizardOutcome::Apply(ftp)) = w.take_outcome() else {
        panic!("not applied");
    };
    assert_eq!(ftp.transfer_mode, FtpTransferMode::Active);
    assert_eq!(
        ftp,
        FtpSettings {
            transfer_mode: FtpTransferMode::Active,
            ..FtpSettings::default()
        }
    );
}

#[test]
fn cancel_stops_a_running_test() {
    let mut w = wizard();
    let (_, _, cancel) = start_test(&mut w, "h");
    press(&mut w, KeyCode::Esc);
    assert!(cancel.is_cancelled());
    assert_eq!(w.take_outcome(), Some(WizardOutcome::Cancel));
    // Dropping a wizard stops its test too.
    let mut w = wizard();
    let (_, _, cancel) = start_test(&mut w, "h");
    drop(w);
    assert!(cancel.is_cancelled());
}
