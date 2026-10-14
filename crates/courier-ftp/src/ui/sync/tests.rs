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

use super::{Safety, SyncPage, SyncRequest, SyncView, TeamPage, TeamReply, TeamRequest};
use crate::ui::Theme;
use courier_ftp_core::model::item::UserId;
use courier_ftp_proto::{
    orgs::{AuditEventView, InviteCreated, MemberView, OrgView, Role},
    sync::Permission,
    vaults::{OrgVaultView, VaultMemberView, VaultMembersView},
};
use courier_ftp_store::{KeyChange, PinState, PinnedKey};
use courier_ftp_sync::{MemberEntry, OrgVaultEntry};

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

// ---- teams (T90 §5)

fn org(name: &str, role: Role) -> OrgView {
    OrgView {
        id: Uuid::from_bytes([9; 16]),
        name: name.to_owned(),
        role,
        created_at: time::macros::datetime!(2026-10-01 12:00 UTC),
    }
}

fn pin(user: Uuid, verified: bool, changed: bool) -> PinnedKey {
    PinnedKey {
        user_id: UserId::from_uuid(user),
        label: None,
        fingerprint: [1; 32],
        x25519_pub: [2; 32],
        ed25519_pub: [3; 32],
        pinned_at: 0,
        verified,
        verified_at: None,
        is_self: false,
        changed: changed.then_some(KeyChange {
            fingerprint: [4; 32],
            x25519_pub: [5; 32],
            ed25519_pub: [6; 32],
            seen_at: 0,
        }),
    }
}

const ALICE: Uuid = Uuid::from_bytes([1; 16]);
const BOB: Uuid = Uuid::from_bytes([2; 16]);
const CAROL: Uuid = Uuid::from_bytes([3; 16]);

fn members() -> Vec<MemberEntry> {
    let m = |user, email: &str, role| MemberView {
        user_id: user,
        email: email.to_owned(),
        role,
    };
    vec![
        MemberEntry {
            member: m(ALICE, "alice@example.test", Role::Owner),
            pin: None,
            is_me: true,
        },
        MemberEntry {
            member: m(BOB, "bob@example.test", Role::Member),
            pin: Some(pin(BOB, true, false)),
            is_me: false,
        },
        MemberEntry {
            member: m(CAROL, "carol@example.test", Role::Admin),
            pin: Some(pin(CAROL, false, true)),
            is_me: false,
        },
    ]
}

const NUMBER: &str = "12345 67890 13579 24680 11223 34455 66778 89900 01234 56789 98765 43210";

/// Signed in, on the teams list with "Ops".
fn teams() -> SyncView {
    let mut v = signed_in();
    press(
        &mut v,
        &[KeyCode::Down, KeyCode::Down, KeyCode::Down, KeyCode::Enter],
    );
    assert_eq!(v.page(), SyncPage::Teams);
    assert_eq!(names(&v.take_requests()), ["Team"]);
    v.team_reply(Ok(TeamReply::Orgs(vec![org("Ops", Role::Owner)])));
    v
}

fn team_requests(v: &mut SyncView) -> Vec<TeamRequest> {
    v.take_requests()
        .into_iter()
        .filter_map(|r| match r {
            SyncRequest::Team(t) => Some(t),
            _ => None,
        })
        .collect()
}

#[test]
fn teams_list_new_team_and_join() {
    let mut v = signed_in();
    press(
        &mut v,
        &[KeyCode::Down, KeyCode::Down, KeyCode::Down, KeyCode::Enter],
    );
    assert_eq!(team_requests(&mut v), [TeamRequest::Orgs]);
    v.team_reply(Ok(TeamReply::Orgs(Vec::new())));
    insta::assert_snapshot!("teams_empty_80x24", render(&v, 80, 24));

    let mut v = teams();
    insta::assert_snapshot!("teams_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Char('n')]);
    assert_eq!(v.team_page(), Some(TeamPage::NewOrg));
    typed(&mut v, "Infra");
    insta::assert_snapshot!("teams_new_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Enter]);
    assert_eq!(
        team_requests(&mut v),
        [TeamRequest::CreateOrg("Infra".to_owned())]
    );
    // Done: the note, and the list again.
    v.team_reply(Ok(TeamReply::Done("Team “Infra” created.".to_owned())));
    assert_eq!(team_requests(&mut v), [TeamRequest::Orgs]);
    assert_eq!(v.note(), Some("Team “Infra” created."));

    v.team_reply(Ok(TeamReply::Orgs(vec![org("Ops", Role::Owner)])));
    press(&mut v, &[KeyCode::Char('a')]);
    assert_eq!(v.team_page(), Some(TeamPage::Accept));
    typed(&mut v, "not a link!");
    press(&mut v, &[KeyCode::Enter]);
    assert!(team_requests(&mut v).is_empty(), "refused");
    insta::assert_snapshot!("teams_join_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Esc]);
    assert_eq!(v.team_page(), Some(TeamPage::Orgs));
    v.team_reply(Ok(TeamReply::Orgs(Vec::new())));
    press(&mut v, &[KeyCode::Esc]);
    assert_eq!(v.page(), SyncPage::Overview);
}

#[test]
fn team_menu_members_and_invite() {
    let mut v = teams();
    press(&mut v, &[KeyCode::Enter]);
    assert_eq!(v.team_page(), Some(TeamPage::Org));
    insta::assert_snapshot!("team_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Enter]);
    assert_eq!(
        team_requests(&mut v),
        [TeamRequest::Members(org("Ops", Role::Owner).id)]
    );
    v.team_reply(Ok(TeamReply::Members(members())));
    assert_eq!(v.team_page(), Some(TeamPage::Members));
    insta::assert_snapshot!("team_members_80x24", render(&v, 80, 24));

    // Remove asks first.
    press(&mut v, &[KeyCode::Down, KeyCode::Char('x')]);
    insta::assert_snapshot!("team_remove_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Left, KeyCode::Enter]);
    assert!(matches!(
        team_requests(&mut v).as_slice(),
        [TeamRequest::Remove { user, .. }] if *user == BOB
    ));
    v.team_reply(Err("network unreachable".to_owned()));
    assert_eq!(v.error(), Some("Network unreachable"));

    // Invite.
    press(&mut v, &[KeyCode::Char('i')]);
    assert_eq!(v.team_page(), Some(TeamPage::Invite));
    typed(&mut v, "dave@example.test");
    press(&mut v, &[KeyCode::Tab, KeyCode::Right]);
    insta::assert_snapshot!("team_invite_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Enter]);
    assert!(matches!(
        team_requests(&mut v).as_slice(),
        [TeamRequest::Invite { email: Some(e), role: Role::Admin, .. }] if e == "dave@example.test"
    ));
    v.team_reply(Ok(TeamReply::Invited(InviteCreated {
        id: Uuid::from_bytes([5; 16]),
        org_id: org("Ops", Role::Owner).id,
        email: Some("dave@example.test".to_owned()),
        role: Role::Admin,
        expires_at: time::macros::datetime!(2026-10-18 12:00 UTC),
        link: Some("https://sync.example.test/invite/AbC-12_x".to_owned()),
        emailed: false,
    })));
    assert_eq!(v.team_page(), Some(TeamPage::InviteLink));
    insta::assert_snapshot!("team_invite_link_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Enter]);
    assert_eq!(v.team_page(), Some(TeamPage::Members));
}

#[test]
fn safety_number_and_key_change_warning() {
    let mut v = teams();
    press(&mut v, &[KeyCode::Enter, KeyCode::Enter]);
    v.take_requests();
    v.team_reply(Ok(TeamReply::Members(members())));
    press(&mut v, &[KeyCode::Down, KeyCode::Enter]);
    assert_eq!(
        team_requests(&mut v),
        [TeamRequest::Safety {
            user: BOB,
            email: "bob@example.test".to_owned()
        }]
    );
    v.team_reply(Ok(TeamReply::Safety(Safety {
        user: BOB,
        email: "bob@example.test".to_owned(),
        number: NUMBER.to_owned(),
        state: PinState::Pinned,
    })));
    assert_eq!(v.team_page(), Some(TeamPage::Safety));
    insta::assert_snapshot!("team_safety_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Left, KeyCode::Enter]);
    assert_eq!(
        team_requests(&mut v),
        [TeamRequest::Verify {
            user: BOB,
            email: "bob@example.test".to_owned()
        }]
    );
    assert_eq!(v.team_page(), Some(TeamPage::Members));

    // Carol's key changed: the warning; accepting with the numbers compared.
    v.team_reply(Ok(TeamReply::Done("ok".to_owned())));
    v.take_requests();
    v.team_reply(Ok(TeamReply::Members(members())));
    press(&mut v, &[KeyCode::Down, KeyCode::Enter]);
    v.take_requests();
    v.team_reply(Ok(TeamReply::KeyChanged(Safety {
        user: CAROL,
        email: "carol@example.test".to_owned(),
        number: NUMBER.to_owned(),
        state: PinState::KeyChanged,
    })));
    assert_eq!(v.team_page(), Some(TeamPage::KeyChanged));
    insta::assert_snapshot!("team_key_changed_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Left, KeyCode::Enter]);
    assert_eq!(
        team_requests(&mut v),
        [TeamRequest::AcceptKey {
            user: CAROL,
            email: "carol@example.test".to_owned(),
            verified: true
        }]
    );
}

#[test]
fn shared_vaults_permissions_and_audit() {
    let ops = org("Ops", Role::Owner);
    let vault = Uuid::from_bytes([8; 16]);
    let mut v = teams();
    press(&mut v, &[KeyCode::Enter, KeyCode::Down, KeyCode::Enter]);
    assert_eq!(team_requests(&mut v), [TeamRequest::Vaults(ops.id)]);
    let entry = |id, name: Option<&str>, permission, has_key| OrgVaultEntry {
        view: OrgVaultView {
            id,
            name_enc: Vec::new(),
            key_version: 2,
            permission,
            has_key,
        },
        name: name.map(str::to_owned),
    };
    v.team_reply(Ok(TeamReply::Vaults(vec![
        entry(vault, Some("Ops servers"), Permission::Manage, true),
        entry(Uuid::from_bytes([7; 16]), None, Permission::Manage, false),
    ])));
    assert_eq!(v.team_page(), Some(TeamPage::Vaults));
    insta::assert_snapshot!("team_vaults_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Char('n')]);
    assert_eq!(v.team_page(), Some(TeamPage::NewVault));
    typed(&mut v, "Databases");
    insta::assert_snapshot!("team_new_vault_80x24", render(&v, 80, 24));
    press(&mut v, &[KeyCode::Enter]);
    assert_eq!(
        team_requests(&mut v),
        [TeamRequest::CreateVault {
            org: ops.id,
            name: "Databases".to_owned()
        }]
    );
    v.team_reply(Ok(TeamReply::Vaults(vec![entry(
        vault,
        Some("Ops servers"),
        Permission::Manage,
        true,
    )])));

    // Rotating asks first.
    press(&mut v, &[KeyCode::Char('R')]);
    assert!(render(&v, 80, 24).contains("Rotate the key of “Ops servers”?"));
    press(&mut v, &[KeyCode::Esc]);
    assert!(team_requests(&mut v).is_empty());

    press(&mut v, &[KeyCode::Enter]);
    let vid = courier_ftp_core::model::item::VaultId::from_uuid(vault);
    assert_eq!(team_requests(&mut v), [TeamRequest::VaultMembers(vid)]);
    let vm = |user, email: &str, org_role, permission: Option<Permission>| VaultMemberView {
        user_id: user,
        email: Some(email.to_owned()),
        org_role,
        permission,
        has_key: permission.is_some(),
        granted_by: None,
    };
    v.team_reply(Ok(TeamReply::VaultMembers(VaultMembersView {
        vault_id: vault,
        org_id: ops.id,
        key_version: 2,
        created_by: Some(ALICE),
        members: vec![
            vm(
                ALICE,
                "alice@example.test",
                Role::Owner,
                Some(Permission::Manage),
            ),
            vm(
                BOB,
                "bob@example.test",
                Role::Member,
                Some(Permission::Read),
            ),
            vm(CAROL, "carol@example.test", Role::Member, None),
        ],
    })));
    assert_eq!(v.team_page(), Some(TeamPage::VaultMembers));
    insta::assert_snapshot!("team_vault_members_80x24", render(&v, 80, 24));
    // Bob: read → write.
    press(&mut v, &[KeyCode::Down, KeyCode::Right]);
    assert!(matches!(
        team_requests(&mut v).as_slice(),
        [TeamRequest::Grant { user, permission: Permission::Write, .. }] if *user == BOB
    ));
    v.team_reply(Err("offline".to_owned()));
    // Bob: read → nothing is a revoke (asks first).
    press(&mut v, &[KeyCode::Left]);
    assert!(render(&v, 80, 24).contains("Revoke bob@example.test's access"));
    press(&mut v, &[KeyCode::Left, KeyCode::Enter]);
    assert!(matches!(
        team_requests(&mut v).as_slice(),
        [TeamRequest::Revoke { user, .. }] if *user == BOB
    ));
    v.team_reply(Err("offline".to_owned()));

    // The audit log.
    press(&mut v, &[KeyCode::Esc]);
    v.take_requests();
    v.team_reply(Ok(TeamReply::Vaults(Vec::new())));
    press(&mut v, &[KeyCode::Esc]);
    assert_eq!(v.team_page(), Some(TeamPage::Org));
    press(
        &mut v,
        &[KeyCode::Down, KeyCode::Down, KeyCode::Down, KeyCode::Enter],
    );
    assert_eq!(team_requests(&mut v), [TeamRequest::Audit(ops.id)]);
    let at = time::macros::datetime!(2026-10-11 09:30 UTC);
    let event = |id, kind: &str, target| AuditEventView {
        id,
        kind: kind.to_owned(),
        actor: Some(ALICE),
        target,
        at,
        meta: serde_json::Value::Null,
    };
    v.team_reply(Ok(TeamReply::Audit {
        events: vec![
            event(3, "vault.member_granted", Some(BOB)),
            event(2, "invite.accepted", Some(BOB)),
            event(1, "org.created", None),
        ],
        names: [
            (ALICE, "alice@example.test".to_owned()),
            (BOB, "bob@example.test".to_owned()),
        ]
        .into(),
    }));
    assert_eq!(v.team_page(), Some(TeamPage::Audit));
    insta::assert_snapshot!("team_audit_80x24", render(&v, 80, 24));
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
