//! T90 view tests: a snapshot of every sync screen (80×24, and 160×48 where
//! the layout changes), plus the keys that move between them. The flows
//! against a real server are in `app::sync_tests`.

use courier_ftp_core::model::item::{ItemId, ItemKind, VaultId};
use courier_ftp_proto::auth::DeviceSummary;
use courier_ftp_store::VaultKind;
use courier_ftp_sync::{
    SyncStatus, TotpSetup,
    account::{DuplicateChoice, DuplicateRow},
    info::{LocalSyncInfo, VaultInfo},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};
use secrecy::SecretString;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{SyncPage, SyncRequest, SyncView};
use crate::ui::Theme;

const PHRASE: &str = "abandon ability able about above absent absorb abstract absurd abuse \
                      access accident account accuse achieve acid acoustic acquire across act \
                      action actor actress actual";

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn press(v: &mut SyncView, codes: &[KeyCode]) {
    for c in codes {
        v.handle_key(key(*c));
    }
}

fn typed(v: &mut SyncView, text: &str) {
    for c in text.chars() {
        v.handle_key(key(KeyCode::Char(c)));
    }
}

fn render(v: &SyncView, w: u16, h: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    let theme = Theme::new(None, true);
    terminal.draw(|f| v.draw(f, f.area(), &theme)).unwrap();
    terminal.backend().to_string()
}

fn names(requests: &[SyncRequest]) -> Vec<String> {
    requests.iter().map(|r| format!("{r:?}")).collect()
}

fn signed_in_info() -> LocalSyncInfo {
    LocalSyncInfo {
        server_url: Some("https://sync.example.test".to_owned()),
        signed_in: true,
        email: Some("alice@example.test".to_owned()),
        // 2026-10-11 09:30 UTC.
        last_sync_ms: Some(1_791_711_000_000),
        vaults: vec![VaultInfo {
            vault: VaultId::from_bytes([7; 16]),
            kind: VaultKind::Personal,
            cursor: 42,
            pending: 3,
        }],
    }
}

/// The panel of a device that isn't connected to a sync server.
fn local_only() -> SyncView {
    let mut v = SyncView::new(true, "laptop".to_owned());
    assert_eq!(names(&v.take_requests()), ["Refresh"]);
    v.set_state(Some(LocalSyncInfo::default()), None, false, Vec::new());
    v
}

/// The panel of a signed-in device.
fn signed_in() -> SyncView {
    let mut v = SyncView::new(true, "laptop".to_owned());
    v.take_requests();
    v.set_state(
        Some(signed_in_info()),
        Some(SyncStatus::Offline { pending: 3 }),
        true,
        Vec::new(),
    );
    v
}

fn devices() -> Vec<DeviceSummary> {
    let at = time::macros::datetime!(2026-10-01 12:00 UTC);
    vec![
        DeviceSummary {
            id: Uuid::from_bytes([1; 16]),
            name: "laptop".to_owned(),
            platform: "linux".to_owned(),
            created_at: at,
            last_seen_at: Some(time::macros::datetime!(2026-10-11 09:00 UTC)),
            current: true,
        },
        DeviceSummary {
            id: Uuid::from_bytes([2; 16]),
            name: "work desktop".to_owned(),
            platform: "windows".to_owned(),
            created_at: at,
            last_seen_at: None,
            current: false,
        },
    ]
}

fn totp() -> TotpSetup {
    TotpSetup {
        otpauth_uri: SecretString::from(
            "otpauth://totp/courier-ftp:alice%40example.test?secret=JBSWY3DPEHPK3PXP\
             &issuer=courier-ftp&algorithm=SHA1&digits=6&period=30"
                .to_owned(),
        ),
        secret_base32: SecretString::from("JBSWY3DPEHPK3PXP".to_owned()),
    }
}

#[test]
fn overview_of_a_local_only_device() {
    let v = local_only();
    assert_eq!(v.page(), SyncPage::Overview);
    insta::assert_snapshot!("overview_local_80x24", render(&v, 80, 24));
}

#[test]
fn overview_of_a_signed_in_device_with_held_back_items() {
    let mut v = signed_in();
    v.set_state(
        None,
        Some(SyncStatus::Offline { pending: 3 }),
        true,
        vec![(
            "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".to_owned(),
            "item too large".to_owned(),
        )],
    );
    insta::assert_snapshot!("overview_signed_in_80x24", render(&v, 80, 24));
    insta::assert_snapshot!("overview_signed_in_160x48", render(&v, 160, 48));
}

#[test]
fn login_needed_offers_logging_in_again() {
    let mut v = signed_in();
    v.set_state(None, Some(SyncStatus::NeedsLogin), true, Vec::new());
    let text = render(&v, 80, 24);
    assert!(text.contains("› Log in again"), "{text}");
    assert!(text.contains("sign-in required"), "{text}");
    press(&mut v, &[KeyCode::Enter]);
    assert_eq!(v.page(), SyncPage::Login);
}

#[test]
fn sync_now_and_close() {
    let mut v = signed_in();
    press(&mut v, &[KeyCode::Enter]);
    assert_eq!(names(&v.take_requests()), ["SyncNow"]);
    assert_eq!(v.note(), Some("Sync requested."));
    press(&mut v, &[KeyCode::Esc]);
    assert!(v.is_closed());
}

#[test]
fn register_form_validates_and_asks() {
    let mut v = local_only();
    press(&mut v, &[KeyCode::Enter]);
    assert_eq!(v.page(), SyncPage::Register);
    insta::assert_snapshot!("register_80x24", render(&v, 80, 24));

    // Plain http to a remote host is refused by the field.
    typed(&mut v, "http://sync.example.test");
    press(&mut v, &[KeyCode::Tab]);
    let text = render(&v, 80, 24);
    assert!(text.to_lowercase().contains("https"), "{text}");
    assert!(v.take_requests().is_empty());
}

#[test]
fn login_form() {
    let mut v = local_only();
    press(&mut v, &[KeyCode::Down, KeyCode::Enter]);
    assert_eq!(v.page(), SyncPage::Login);
    insta::assert_snapshot!("login_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Esc]);
    assert_eq!(v.page(), SyncPage::Overview);
}

#[test]
fn recovery_words_are_shown_then_checked_then_dropped() {
    let mut v = local_only();
    v.show_words(Zeroizing::new(PHRASE.to_owned()), [3, 11, 20]);
    assert_eq!(v.page(), SyncPage::Words);
    insta::assert_snapshot!("words_80x24", render(&v, 80, 24));

    // Continue needs the box ticked.
    press(&mut v, &[KeyCode::Tab, KeyCode::Enter]);
    assert_eq!(v.page(), SyncPage::Words);
    assert!(v.error().is_some_and(|e| e.contains("wrote them down")));
    press(&mut v, &[KeyCode::Tab, KeyCode::Char(' '), KeyCode::Tab]);
    press(&mut v, &[KeyCode::Enter]);
    assert_eq!(v.page(), SyncPage::Confirm);
    insta::assert_snapshot!("confirm_words_80x24", render(&v, 80, 24));

    typed(&mut v, "able");
    press(&mut v, &[KeyCode::Tab]);
    typed(&mut v, "Accident");
    press(&mut v, &[KeyCode::Tab]);
    typed(&mut v, "achieve ");
    press(&mut v, &[KeyCode::Enter]);
    let requests = v.take_requests();
    let [SyncRequest::ConfirmWords(answers)] = requests.as_slice() else {
        panic!("{requests:?}");
    };
    // Trimmed and lower-cased before the check.
    assert_eq!(
        answers.iter().map(|a| a.as_str()).collect::<Vec<_>>(),
        ["able", "accident", "achieve"]
    );
    assert!(v.shown_phrase().is_some());

    // Wrong: the words stay, the inputs are cleared.
    v.words_wrong();
    assert_eq!(v.page(), SyncPage::Confirm);
    assert!(v.error().is_some_and(|e| e.contains("don't match")));
    // Esc goes back to the words, still there.
    press(&mut v, &[KeyCode::Esc]);
    assert_eq!(v.page(), SyncPage::Words);
    assert_eq!(v.shown_phrase().unwrap().0, PHRASE);

    // Confirmed: the phrase is gone from the view.
    v.words_confirmed();
    assert_eq!(v.shown_phrase(), None);
    assert_eq!(v.page(), SyncPage::Overview);
    let text = render(&v, 80, 24);
    assert!(text.contains("Creating the account"), "{text}");
    assert!(!text.contains("abandon"), "{text}");
}

#[test]
fn cancelling_the_registration_asks_first() {
    let mut v = local_only();
    v.show_words(Zeroizing::new(PHRASE.to_owned()), [3, 11, 20]);
    press(&mut v, &[KeyCode::Esc]);
    insta::assert_snapshot!("cancel_registration_80x24", render(&v, 80, 24));
    // "Keep going" is the default.
    press(&mut v, &[KeyCode::Enter]);
    assert_eq!(v.page(), SyncPage::Words);
    press(&mut v, &[KeyCode::Esc, KeyCode::Left, KeyCode::Enter]);
    assert_eq!(names(&v.take_requests()), ["CancelRegistration", "Refresh"]);
    assert_eq!(v.page(), SyncPage::Overview);
    assert_eq!(v.shown_phrase(), None);
}

#[test]
fn token_page_after_a_refused_registration() {
    let mut v = local_only();
    v.show_token("registration requires an invite token");
    assert_eq!(v.page(), SyncPage::Token);
    insta::assert_snapshot!("token_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Right, KeyCode::Tab]);
    typed(&mut v, "setup-123");
    press(&mut v, &[KeyCode::Enter]);
    let requests = v.take_requests();
    assert!(
        matches!(
            requests.as_slice(),
            [SyncRequest::FinishRegistration(Some(
                courier_ftp_sync::account::RegistrationToken::Setup(_)
            ))]
        ),
        "{requests:?}"
    );
}

#[test]
fn login_preview_with_duplicates() {
    let mut v = local_only();
    let rows = vec![
        DuplicateRow {
            local: ItemId::from_bytes([1; 16]),
            account: ItemId::from_bytes([2; 16]),
            kind: ItemKind::Site,
            label: "prod db".to_owned(),
            matched: "sftp root@db.example.com:22".to_owned(),
            choice: DuplicateChoice::KeepBoth,
        },
        DuplicateRow {
            local: ItemId::from_bytes([3; 16]),
            account: ItemId::from_bytes([4; 16]),
            kind: ItemKind::Site,
            label: "web".to_owned(),
            matched: "ftp deploy@web.example.com:21".to_owned(),
            choice: DuplicateChoice::KeepBoth,
        },
    ];
    v.show_login(
        super::LoginSummary {
            email: "alice@example.test".to_owned(),
            password_differs: true,
            will_import: true,
            new_items: 4,
            skipped_deleted: 1,
        },
        rows,
    );
    assert_eq!(v.page(), SyncPage::LoginConfirm);
    insta::assert_snapshot!("login_confirm_80x24", render(&v, 80, 24));

    // First row: keep local; second: keep account; then log in.
    press(
        &mut v,
        &[KeyCode::Right, KeyCode::Down, KeyCode::Left, KeyCode::Tab],
    );
    press(&mut v, &[KeyCode::Enter]);
    let requests = v.take_requests();
    let [SyncRequest::CommitLogin(choices)] = requests.as_slice() else {
        panic!("{requests:?}");
    };
    assert_eq!(
        choices,
        &vec![
            (ItemId::from_bytes([1; 16]), DuplicateChoice::KeepLocal),
            (ItemId::from_bytes([3; 16]), DuplicateChoice::KeepAccount),
        ]
    );
}

#[test]
fn devices_list_and_revoke() {
    let mut v = signed_in();
    press(&mut v, &[KeyCode::Down, KeyCode::Enter]);
    assert_eq!(v.page(), SyncPage::Devices);
    assert_eq!(names(&v.take_requests()), ["Devices"]);
    v.show_devices(devices());
    insta::assert_snapshot!("devices_80x24", render(&v, 80, 24));

    press(&mut v, &[KeyCode::Down, KeyCode::Char('d')]);
    insta::assert_snapshot!("revoke_80x24", render(&v, 80, 24));
    // Cancel is the default.
    press(&mut v, &[KeyCode::Enter]);
    assert!(v.take_requests().is_empty());
    press(&mut v, &[KeyCode::Char('d'), KeyCode::Left, KeyCode::Enter]);
    let requests = v.take_requests();
    assert!(
        matches!(
            requests.as_slice(),
            [SyncRequest::Revoke { id, this_device: false }] if *id == Uuid::from_bytes([2; 16])
        ),
        "{requests:?}"
    );
}

#[test]
fn account_screens() {
    let mut v = signed_in();
    press(&mut v, &[KeyCode::Down, KeyCode::Down, KeyCode::Enter]);
    assert_eq!(v.page(), SyncPage::Account);
    insta::assert_snapshot!("account_80x24", render(&v, 80, 24));

    press(&mut v, &[KeyCode::Enter]);
    assert_eq!(v.page(), SyncPage::ChangePassword);
    insta::assert_snapshot!("change_password_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Esc]);
    assert_eq!(v.page(), SyncPage::Account);

    press(&mut v, &[KeyCode::Down, KeyCode::Down, KeyCode::Enter]);
    assert_eq!(v.page(), SyncPage::TotpDisable);
    insta::assert_snapshot!("totp_disable_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Esc]);

    press(
        &mut v,
        &[KeyCode::Down, KeyCode::Down, KeyCode::Down, KeyCode::Down],
    );
    press(&mut v, &[KeyCode::Down, KeyCode::Enter]);
    assert_eq!(v.page(), SyncPage::DeleteAccount);
    insta::assert_snapshot!("delete_account_80x24", render(&v, 80, 24));
}

#[test]
fn logout_asks_first() {
    let mut v = signed_in();
    press(&mut v, &[KeyCode::Down, KeyCode::Down, KeyCode::Enter]);
    for _ in 0..4 {
        press(&mut v, &[KeyCode::Down]);
    }
    press(&mut v, &[KeyCode::Enter]);
    let text = render(&v, 80, 24);
    assert!(text.contains("Log out of sync on this device?"), "{text}");
    press(&mut v, &[KeyCode::Left, KeyCode::Enter]);
    assert_eq!(names(&v.take_requests()), ["Logout"]);
}

#[test]
fn totp_setup_with_and_without_room_for_the_qr_code() {
    let mut v = signed_in();
    v.show_totp(&totp());
    assert_eq!(v.page(), SyncPage::TotpSetup);
    let small = render(&v, 80, 24);
    assert!(small.contains("too small for the QR code"), "{small}");
    assert!(small.contains("JBSW Y3DP EHPK 3PXP"), "{small}");
    insta::assert_snapshot!("totp_setup_80x24", small);
    let large = render(&v, 160, 48);
    assert!(large.contains('█'), "{large}");
    insta::assert_snapshot!("totp_setup_160x48", large);

    typed(&mut v, "123456");
    press(&mut v, &[KeyCode::Enter]);
    assert_eq!(names(&v.take_requests()), ["TotpConfirm"]);
}

#[test]
fn teams_placeholder() {
    let mut v = signed_in();
    press(
        &mut v,
        &[KeyCode::Down, KeyCode::Down, KeyCode::Down, KeyCode::Enter],
    );
    assert_eq!(v.page(), SyncPage::Teams);
    insta::assert_snapshot!("teams_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Esc]);
    assert_eq!(v.page(), SyncPage::Overview);
}

#[test]
fn ascii_mode() {
    let mut v = SyncView::new(false, "laptop".to_owned());
    v.set_state(
        Some(signed_in_info()),
        Some(SyncStatus::Synced),
        true,
        Vec::new(),
    );
    let text = render(&v, 80, 24);
    assert!(text.contains("> Sync now"), "{text}");
    assert!(!text.contains('›'), "{text}");
}

#[test]
fn keys_are_ignored_while_busy() {
    let mut v = signed_in();
    press(&mut v, &[KeyCode::Down, KeyCode::Enter]);
    assert!(v.is_busy());
    v.take_requests();
    press(&mut v, &[KeyCode::Esc, KeyCode::Char('r')]);
    assert!(v.take_requests().is_empty());
    assert_eq!(v.page(), SyncPage::Devices);
    v.failed("network unreachable");
    assert!(!v.is_busy());
    assert_eq!(v.error(), Some("Network unreachable"));
}
