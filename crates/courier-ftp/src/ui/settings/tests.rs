//! T68: the settings screen on its own: one snapshot per section,
//! validation, the requests it sends and the answers it takes. The flows
//! against a real vault and the config file are in `app/settings_tests.rs`.

use courier_ftp_core::{
    settings::{ExistsAction, FtpProxy, GenericProxy, Layout, ProxyServer, Settings},
    trust::{HostKey, KnownHost, TrustedCertificate},
};
use courier_ftp_crypto::kdf::Argon2Cost;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};
use secrecy::ExposeSecret;
use time::macros::datetime;

use super::*;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn press(view: &mut SettingsView, code: KeyCode) {
    view.handle_key(key(code));
}

fn typed(view: &mut SettingsView, text: &str) {
    for c in text.chars() {
        press(view, KeyCode::Char(c));
    }
}

/// Empty the focused text field.
fn clear(view: &mut SettingsView) {
    view.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::CONTROL));
    view.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
}

fn opts() -> SettingsOpts {
    SettingsOpts {
        config_file: "/home/me/.config/courier-ftp/config.json".into(),
        default_log_file: "/home/me/.local/share/courier-ftp/session.log".into(),
        keybindings: vec![
            ("Normal".into(), "<F1>".into(), "Help".into()),
            ("Normal".into(), "<F9>".into(), "Settings".into()),
            ("Normal".into(), "<Ctrl-s>".into(), "SiteManager".into()),
            ("FileList".into(), "<j>".into(), "CursorDown".into()),
        ],
    }
}

fn view() -> SettingsView {
    let mut view = SettingsView::new(Settings::default(), opts());
    let first = view.take_requests();
    assert!(matches!(first[0], SettingsRequest::LoadSecurity));
    assert!(matches!(first[1], SettingsRequest::LoadTrust));
    view
}

fn render(view: &mut SettingsView, w: u16, h: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    terminal
        .draw(|f| view.draw(f, f.area(), &Theme::default()))
        .unwrap();
    terminal.backend().to_string()
}

/// Select `section` in the list (the loads it asks for are dropped).
fn go_to(view: &mut SettingsView, section: Section) {
    while view.section() != section {
        press(view, KeyCode::Down);
    }
    view.take_requests();
}

/// Tab through the page until the field labelled `label` has focus.
fn focus_field(view: &mut SettingsView, key_name: &str) {
    if view.focus() != Pane::Page {
        press(view, KeyCode::Enter);
    }
    for _ in 0..40 {
        if view.page.rows.get(view.row).map(|r| r.key) == Some(key_name) {
            return;
        }
        press(view, KeyCode::Tab);
        if view.focus() != Pane::Page {
            press(view, KeyCode::Tab);
            press(view, KeyCode::Enter);
        }
    }
    panic!("no field {key_name}");
}

fn host_key() -> KnownHost {
    let mut blob = Vec::new();
    for part in [b"ssh-ed25519".as_slice(), &[7u8; 32]] {
        blob.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
        blob.extend_from_slice(part);
    }
    KnownHost::new(
        "sftp.example.com",
        22,
        HostKey::from_blob(blob).unwrap(),
        datetime!(2026-03-01 12:00 UTC),
    )
}

fn cert() -> TrustedCertificate {
    TrustedCertificate::new(
        "ftp.example.com",
        990,
        vec![1, 2, 3],
        "CN=ftp.example.com",
        datetime!(2026-04-02 08:30 UTC),
    )
}

fn loaded(view: &mut SettingsView) {
    view.apply_reply(&SettingsReply::Trust {
        host_keys: Trust::Loaded(vec![host_key()]),
        certs: Trust::Loaded(vec![cert()]),
    });
    view.apply_reply(&SettingsReply::Security(SecurityInfo {
        state: VaultState::Unlocked,
        keyring_enabled: true,
        cost: Some(Argon2Cost::DEFAULT),
    }));
}

#[test]
fn snapshot_of_every_section() {
    let mut view = view();
    loaded(&mut view);
    for (section, _, _) in SECTIONS {
        go_to(&mut view, section);
        view.take_requests();
        let mut text = render(&mut view, 110, 36);
        if section == Section::FileLists {
            // The preview shows the current time.
            text = text
                .lines()
                .map(|l| match l.find("Preview: ") {
                    Some(i) => format!("{}Preview: <now>", &l[..i]),
                    None => l.to_owned(),
                })
                .collect::<Vec<_>>()
                .join("\n");
        }
        let mut name = format!("section_{section:?}").to_lowercase();
        if section == Section::Sync && !cfg!(feature = "sync") {
            name.push_str("_without_feature");
        }
        insta::assert_snapshot!(name, text);
    }
}

#[test]
fn locked_vault_pages() {
    let mut view = view();
    view.apply_reply(&SettingsReply::Trust {
        host_keys: Trust::Locked,
        certs: Trust::Locked,
    });
    view.apply_reply(&SettingsReply::Security(SecurityInfo {
        state: VaultState::Locked,
        keyring_enabled: false,
        cost: None,
    }));
    go_to(&mut view, Section::Sftp);
    let text = render(&mut view, 110, 20);
    assert!(text.contains("Unlock the vault"), "{text}");
    go_to(&mut view, Section::Security);
    let text = render(&mut view, 110, 20);
    assert!(text.contains("Vault: locked"), "{text}");
    assert!(!text.contains("Change master password"), "{text}");
}

#[test]
fn entering_trust_and_security_pages_reloads_them() {
    let mut view = view();
    for _ in 0..4 {
        press(&mut view, KeyCode::Down);
    }
    assert_eq!(view.section(), Section::Sftp);
    assert!(matches!(
        view.take_requests().as_slice(),
        [SettingsRequest::LoadTrust]
    ));
    press(&mut view, KeyCode::End);
    assert_eq!(view.section(), Section::Security);
    assert!(matches!(
        view.take_requests().as_slice(),
        [SettingsRequest::LoadSecurity]
    ));
}

#[test]
fn edit_and_apply_sends_the_draft() {
    let mut view = view();
    go_to(&mut view, Section::Transfers);
    focus_field(&mut view, "transfers.max_concurrent");
    clear(&mut view);
    typed(&mut view, "8");
    assert!(view.is_dirty());
    assert_eq!(view.draft().transfers.max_concurrent, 8);
    view.handle_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
    let requests = view.take_requests();
    let [
        SettingsRequest::Save {
            settings,
            proxy_passwords,
        },
    ] = requests.as_slice()
    else {
        panic!("{requests:?}");
    };
    assert_eq!(settings.transfers.max_concurrent, 8);
    assert!(proxy_passwords.is_empty());
    assert!(view.is_busy());
    // Keys wait while saving.
    press(&mut view, KeyCode::Char('9'));
    assert_eq!(view.draft().transfers.max_concurrent, 8);
    view.apply_reply(&SettingsReply::Saved);
    assert!(!view.is_busy());
    assert!(!view.is_dirty());
    assert!(!view.is_closed());
    assert_eq!(view.message().unwrap().0, "Settings saved");
}

#[test]
fn ok_closes_after_saving_and_a_failure_keeps_the_screen() {
    let mut view = view();
    go_to(&mut view, Section::Interface);
    focus_field(&mut view, "interface.layout");
    press(&mut view, KeyCode::Right);
    assert_eq!(view.draft().interface.layout, Layout::Explorer);
    view.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::ALT));
    assert_eq!(view.take_requests().len(), 1);
    view.apply_reply(&SettingsReply::Failed("disk full".into()));
    assert!(!view.is_closed());
    assert!(view.is_dirty());
    assert_eq!(view.message(), Some(&("disk full".to_owned(), true)));
    view.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::ALT));
    assert_eq!(view.take_requests().len(), 1);
    view.apply_reply(&SettingsReply::Saved);
    assert!(view.is_closed());
}

#[test]
fn ok_without_changes_just_closes() {
    let mut view = view();
    view.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::ALT));
    assert!(view.take_requests().is_empty());
    assert!(view.is_closed());
}

#[test]
fn cancel_asks_before_dropping_edits() {
    let mut view = view();
    go_to(&mut view, Section::Connection);
    focus_field(&mut view, "connection.prefer_ipv6");
    press(&mut view, KeyCode::Char(' '));
    assert!(view.draft().connection.prefer_ipv6);
    press(&mut view, KeyCode::Esc); // back to the sections
    press(&mut view, KeyCode::Esc); // cancel
    assert!(view.has_overlay());
    press(&mut view, KeyCode::Char('n'));
    assert!(!view.is_closed());
    view.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::ALT));
    press(&mut view, KeyCode::Char('y'));
    assert!(view.is_closed());
    assert!(view.take_requests().is_empty());
}

#[test]
fn reset_section_restores_only_that_section() {
    let mut settings = Settings::default();
    settings.connection.timeout_secs = 99;
    settings.connection.prefer_ipv6 = true;
    settings.transfers.max_concurrent = 9;
    let mut view = SettingsView::new(settings, opts());
    view.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::ALT));
    assert_eq!(view.draft().connection, Settings::default().connection);
    assert_eq!(view.draft().transfers.max_concurrent, 9);
    assert!(view.is_dirty());
    let text = render(&mut view, 110, 30);
    assert!(text.contains("reset to the defaults"), "{text}");
}

#[test]
fn out_of_range_numbers_show_inline_and_block_saving() {
    let mut view = view();
    focus_field(&mut view, "connection.timeout_secs");
    clear(&mut view);
    typed(&mut view, "0");
    assert_eq!(
        view.errors(),
        &[(
            "connection.timeout_secs",
            "must be between 1 and 9999".to_owned()
        )]
    );
    let text = render(&mut view, 110, 30);
    assert!(text.contains("must be between 1 and 9999"), "{text}");
    // Neither another section nor saving.
    press(&mut view, KeyCode::Esc);
    press(&mut view, KeyCode::Down);
    assert_eq!(view.section(), Section::Connection);
    view.handle_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
    assert!(view.take_requests().is_empty());
    assert_eq!(view.focus(), Pane::Page);
}

#[test]
fn validation_matches_the_settings_model() {
    let mut view = view();
    go_to(&mut view, Section::Ftp);
    focus_field(&mut view, "ftp.active_port_range");
    typed(&mut view, "5000-4000");
    // The message is Settings::validate's.
    assert_eq!(
        view.errors(),
        &[(
            "ftp.active_port_range",
            "must be a non-empty range of ports 1-65535 with start <= end".to_owned()
        )]
    );
    clear(&mut view);
    typed(&mut view, "fifty");
    assert_eq!(view.errors()[0].0, "ftp.active_port_range");
    clear(&mut view);
    typed(&mut view, "50000-50100");
    assert!(view.errors().is_empty());
    assert_eq!(view.draft().ftp.active_port_range, Some((50000, 50100)));

    go_to_from_page(&mut view, Section::Transfers);
    focus_field(&mut view, "transfers.invalid_char_replacement");
    clear(&mut view);
    typed(&mut view, "/");
    assert_eq!(
        view.errors(),
        &[(
            "transfers.invalid_char_replacement",
            "is itself not allowed in local file names".to_owned()
        )]
    );
}

fn go_to_from_page(view: &mut SettingsView, section: Section) {
    if view.focus() == Pane::Page {
        press(view, KeyCode::Esc);
    }
    go_to(view, section);
}

#[test]
fn generic_and_ftp_proxy_conflict_is_reported_on_both_pages() {
    let mut settings = Settings::default();
    settings.proxy.generic = GenericProxy::Socks5(ProxyServer {
        host: "socks".into(),
        port: 1080,
        user: None,
        password_ref: None,
    });
    let mut view = SettingsView::new(settings, opts());
    go_to(&mut view, Section::FtpProxy);
    focus_field(&mut view, "proxy.ftp_proxy");
    press(&mut view, KeyCode::Right); // USER user@host
    assert_eq!(view.errors()[0].0, "proxy.ftp_proxy.host");
    focus_field(&mut view, "proxy.ftp_proxy.host");
    typed(&mut view, "proxy.example.com");
    assert_eq!(
        view.errors(),
        &[(
            "proxy.ftp_proxy",
            "can't be used together with a generic proxy (proxy.generic)".to_owned()
        )]
    );
    // Back to None: fine again.
    focus_field(&mut view, "proxy.ftp_proxy");
    press(&mut view, KeyCode::Left);
    assert!(view.errors().is_empty());
    assert_eq!(view.draft().proxy.ftp_proxy, FtpProxy::None);
}

#[test]
fn proxy_password_goes_with_the_save_request_only() {
    let mut view = view();
    go_to(&mut view, Section::GenericProxy);
    focus_field(&mut view, "proxy.generic");
    press(&mut view, KeyCode::Char('s')); // SOCKS 4
    press(&mut view, KeyCode::Right); // SOCKS 5
    focus_field(&mut view, "proxy.generic.host");
    typed(&mut view, "socks.example.com");
    focus_field(&mut view, "proxy.generic.user");
    typed(&mut view, "me");
    focus_field(&mut view, "proxy.generic.password");
    typed(&mut view, "hunter2-canary");
    let text = render(&mut view, 110, 30);
    assert!(!text.contains("hunter2"), "{text}");
    // Kept while visiting another page.
    press(&mut view, KeyCode::Esc);
    press(&mut view, KeyCode::Down);
    press(&mut view, KeyCode::Up);
    view.take_requests();
    let text = render(&mut view, 110, 30);
    assert!(text.contains("(typed, saved with the settings)"), "{text}");
    view.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::ALT));
    let requests = view.take_requests();
    let [
        SettingsRequest::Save {
            settings,
            proxy_passwords,
        },
    ] = requests.as_slice()
    else {
        panic!("{requests:?}");
    };
    let GenericProxy::Socks5(server) = &settings.proxy.generic else {
        panic!("{:?}", settings.proxy.generic);
    };
    assert_eq!(server.host, "socks.example.com");
    assert_eq!(server.user.as_deref(), Some("me"));
    assert_eq!(proxy_passwords.len(), 1);
    assert_eq!(proxy_passwords[0].0, ProxyTarget::Generic);
    assert_eq!(proxy_passwords[0].1.expose_secret(), "hunter2-canary");
    // The request never prints the password.
    assert!(!format!("{requests:?}").contains("hunter2"));
    // Nothing of it ends up in the settings.
    assert!(
        !serde_json::to_string(&**settings)
            .unwrap()
            .contains("hunter2")
    );
}

#[test]
fn exists_actions_and_columns() {
    let mut view = view();
    go_to(&mut view, Section::FileExists);
    focus_field(&mut view, "transfers.on_exists_upload");
    press(&mut view, KeyCode::Char('s')); // Skip
    assert_eq!(view.draft().transfers.on_exists_upload, ExistsAction::Skip);
    go_to_from_page(&mut view, Section::FileLists);
    focus_field(&mut view, "interface.columns.local");
    clear(&mut view);
    typed(&mut view, "name owner size");
    assert_eq!(
        view.draft().interface.columns.local,
        vec![
            courier_ftp_core::settings::Column::Name,
            courier_ftp_core::settings::Column::Owner,
            courier_ftp_core::settings::Column::Size
        ]
    );
    clear(&mut view);
    typed(&mut view, "size colour");
    assert_eq!(
        view.errors(),
        &[(
            "interface.columns.local",
            "unknown column colour".to_owned()
        )]
    );
}

#[test]
fn date_format_preview_follows_the_field() {
    let mut view = view();
    go_to(&mut view, Section::FileLists);
    focus_field(&mut view, "interface.date_format");
    clear(&mut view);
    typed(&mut view, "%d.%m.%Y");
    let year = time::OffsetDateTime::now_utc().year().to_string();
    let text = render(&mut view, 110, 30);
    let preview = text
        .lines()
        .find(|l| l.contains("Preview:"))
        .unwrap()
        .to_owned();
    assert!(preview.contains(&format!(".{year} ")), "{preview}");
    assert!(preview.contains("1.2 MiB"), "{preview}");
}

#[test]
fn editing_associations_round_trip() {
    let mut view = view();
    go_to(&mut view, Section::Editing);
    focus_field(&mut view, "editing.associations");
    typed(&mut view, "*.php = code --wait");
    press(&mut view, KeyCode::Enter);
    typed(&mut view, "*.txt = vim [terminal]");
    let a = &view.draft().editing.associations;
    assert_eq!(a.len(), 2);
    assert_eq!(a[0].command, "code --wait");
    assert!(!a[0].terminal);
    assert_eq!(a[1].command, "vim");
    assert!(a[1].terminal);
    press(&mut view, KeyCode::Enter);
    typed(&mut view, "oops");
    assert_eq!(
        view.errors(),
        &[(
            "editing.associations",
            "line 3: use pattern = command".to_owned()
        )]
    );
}

#[test]
fn forget_host_key_asks_then_requests() {
    let mut view = view();
    loaded(&mut view);
    go_to(&mut view, Section::Sftp);
    view.take_requests();
    focus_field(&mut view, "sftp.host_keys");
    press(&mut view, KeyCode::Char('x'));
    assert!(view.has_overlay());
    let text = render(&mut view, 110, 30);
    assert!(text.contains("Forget host key"), "{text}");
    press(&mut view, KeyCode::Char('y'));
    let requests = view.take_requests();
    let [
        SettingsRequest::ForgetHostKey {
            host,
            port,
            key_type,
        },
    ] = requests.as_slice()
    else {
        panic!("{requests:?}");
    };
    assert_eq!(
        (host.as_str(), *port, key_type.as_str()),
        ("sftp.example.com", 22, "ssh-ed25519")
    );
    // The updated list replaces the page.
    view.apply_reply(&SettingsReply::Done("Forgot the key".into()));
    view.apply_reply(&SettingsReply::Trust {
        host_keys: Trust::Loaded(Vec::new()),
        certs: Trust::Loaded(vec![cert()]),
    });
    let text = render(&mut view, 110, 30);
    assert!(text.contains("No trusted host keys yet."), "{text}");
    assert!(text.contains("Forgot the key"), "{text}");
}

#[test]
fn certificate_details_and_forget() {
    let mut view = view();
    loaded(&mut view);
    go_to(&mut view, Section::Tls);
    focus_field(&mut view, "tls.certificates");
    press(&mut view, KeyCode::Enter);
    assert!(view.has_overlay());
    let text = render(&mut view, 110, 36);
    assert!(text.contains("ftp.example.com:990"), "{text}");
    assert!(text.contains("SHA-256"), "{text}");
    press(&mut view, KeyCode::Enter);
    assert!(!view.has_overlay());
    press(&mut view, KeyCode::Delete);
    press(&mut view, KeyCode::Char('y'));
    let requests = view.take_requests();
    assert!(
        matches!(
            requests.as_slice(),
            [SettingsRequest::ForgetCert { port: 990, .. }]
        ),
        "{requests:?}"
    );
}

#[test]
fn security_buttons() {
    let mut view = view();
    loaded(&mut view);
    go_to(&mut view, Section::Security);
    view.take_requests();
    press(&mut view, KeyCode::Enter); // into the page
    press(&mut view, KeyCode::Enter); // Change master password…
    assert!(view.has_overlay());
    typed(&mut view, "old password here");
    press(&mut view, KeyCode::Tab);
    typed(&mut view, "weak");
    press(&mut view, KeyCode::Tab);
    typed(&mut view, "weak");
    press(&mut view, KeyCode::Enter);
    // Too weak: the dialog stays.
    assert!(view.has_overlay());
    let text = render(&mut view, 110, 30);
    assert!(text.contains("Too weak"), "{text}");
    press(&mut view, KeyCode::Esc);
    assert!(!view.has_overlay());
    assert!(view.take_requests().is_empty());

    press(&mut view, KeyCode::Enter);
    typed(&mut view, "old password here");
    press(&mut view, KeyCode::Tab);
    typed(&mut view, "correct horse battery staple violin");
    press(&mut view, KeyCode::Tab);
    typed(&mut view, "correct horse battery staple violin");
    press(&mut view, KeyCode::Enter);
    let requests = view.take_requests();
    let [SettingsRequest::ChangePassword { old, new }] = requests.as_slice() else {
        panic!("{requests:?}");
    };
    assert_eq!(old.expose_secret(), "old password here");
    assert_eq!(new.expose_secret(), "correct horse battery staple violin");

    press(&mut view, KeyCode::Tab);
    press(&mut view, KeyCode::Enter); // keyring toggle
    assert!(matches!(
        view.take_requests().as_slice(),
        [SettingsRequest::SetKeyring(false)]
    ));
    press(&mut view, KeyCode::Tab);
    press(&mut view, KeyCode::Enter); // lock now
    assert!(matches!(
        view.take_requests().as_slice(),
        [SettingsRequest::LockNow]
    ));
}

#[test]
fn keybindings_are_listed_read_only() {
    let mut view = view();
    go_to(&mut view, Section::Keybindings);
    let text = render(&mut view, 110, 30);
    assert!(text.contains("<F9>"), "{text}");
    assert!(text.contains("Settings"), "{text}");
    focus_field(&mut view, "keybindings");
    press(&mut view, KeyCode::Down);
    assert!(!view.is_dirty());
}

#[test]
fn small_terminal_does_not_panic() {
    let mut view = view();
    for (w, h) in [(10, 3), (40, 10), (60, 12)] {
        let _ = render(&mut view, w, h);
    }
}
