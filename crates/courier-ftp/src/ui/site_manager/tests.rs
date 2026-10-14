//! T59: the Site Manager screen on its own: rendering of the tree and each
//! editor tab, field visibility, dirty tracking, validation and the
//! keyboard flows (the requests it sends). The flows against a real vault
//! are in `app/site_tests.rs`.

use std::collections::HashMap;

use courier_ftp_core::{
    model::{
        Charset, FtpEncryption, LocalPath, Protocol, RemotePath,
        item::{ItemId, ServerType, SiteColor, SiteTransferMode},
    },
    sites::{Folder, Site, SiteKey, SiteLogon, SiteTree},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};
use secrecy::{ExposeSecret, SecretString};

use super::{editor::visible_fields, picker::score, *};
use crate::sites::{OverrideForm, VaultRoot};
use crate::sites::{SiteOutcome, SitesReply};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

fn alt(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::ALT)
}

fn typed(view: &mut SiteManagerView, text: &str) {
    for c in text.chars() {
        view.handle_key(key(KeyCode::Char(c)));
    }
}

fn opts() -> ViewOpts {
    ViewOpts {
        unicode: true,
        store_passwords: true,
        import_default: "/home/me/.config/filezilla/sitemanager.xml".into(),
        export_default: "/home/me/courier-ftp-sites.json".into(),
    }
}

fn render(view: &mut SiteManagerView, w: u16, h: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    terminal
        .draw(|f| view.draw(f, f.area(), &Theme::default()))
        .unwrap();
    terminal.backend().to_string()
}

struct Fixture {
    snapshot: Snapshot,
    work: ItemId,
    production: ItemId,
    web01: ItemId,
    db01: ItemId,
    ftp: ItemId,
}

/// Work/Production/{web01 (SFTP key file, red), db01 (SFTP normal)},
/// Personal/ (collapsed, one FTP site with account logon) .
fn fixture() -> Fixture {
    let mut work = Folder::new("Work");
    work.expanded = true;
    let mut production = Folder::new("Production");
    production.parent = Some(work.id);
    production.expanded = true;
    let mut personal = Folder::new("Personal");
    personal.expanded = false;

    let mut web01 = Site::new("web01", Protocol::Sftp, "web01.example.com");
    web01.parent = Some(production.id);
    web01.logon = SiteLogon::KeyFile {
        user: "deploy".into(),
        key: Some(SiteKey::File(LocalPath::new("/nonexistent/id_ed25519"))),
        passphrase: None,
    };
    web01.color = SiteColor::Red;
    web01.comments = "Main web server\nPatched weekly".into();
    web01.default_remote_dir = Some(RemotePath::new("/var/www"));
    web01.default_local_dir = Some(LocalPath::new("/home/me/www"));
    web01.sync_browsing = true;
    web01.timezone_offset_minutes = -90;
    web01.server_type = ServerType::Unix;

    let mut db01 = Site::new("db01", Protocol::Sftp, "db01.example.com");
    db01.parent = Some(production.id);
    db01.port = Some(2222);
    db01.logon = SiteLogon::Normal {
        user: "admin".into(),
        password: Some(SecretString::from("hunter2")),
    };

    let mut ftp = Site::new("legacy", Protocol::Ftp, "ftp.example.org");
    ftp.parent = Some(personal.id);
    ftp.encryption = Some(FtpEncryption::RequireExplicit);
    ftp.protocol = Protocol::FtpsExplicit;
    ftp.logon = SiteLogon::Account {
        user: "me".into(),
        password: Some(SecretString::from("pw")),
        account: "acct42".into(),
    };
    ftp.transfer_mode = SiteTransferMode::Passive;
    ftp.limit_connections = Some(3);
    ftp.charset = Charset::Custom(encoding_rs::WINDOWS_1250);

    let ids = (work.id, production.id, web01.id, db01.id, ftp.id);
    let tree = SiteTree::from_items(vec![work, production, personal], vec![web01, db01, ftp]);
    let mut bookmarks = HashMap::new();
    bookmarks.insert(ids.2, vec!["logs".to_owned(), "uploads".to_owned()]);
    Fixture {
        snapshot: Snapshot { tree, bookmarks },
        work: ids.0,
        production: ids.1,
        web01: ids.2,
        db01: ids.3,
        ftp: ids.4,
    }
}

fn view_at(fx: &Fixture, id: ItemId) -> SiteManagerView {
    let mut view = SiteManagerView::new(Some(fx.snapshot.clone()), opts());
    view.run(Cmd::Select(Some(id)));
    view
}

fn reply(view: &mut SiteManagerView, snapshot: Option<Snapshot>, outcome: SiteOutcome) {
    view.apply_reply(&SitesReply { snapshot, outcome });
}

#[test]
fn tree_and_general_tab_sftp_key_file() {
    let fx = fixture();
    let mut view = view_at(&fx, fx.web01);
    let text = render(&mut view, 110, 30);
    for want in [
        "▾ Work",
        "▾ Production",
        "● web01",
        "▸ Personal",
        "Key file:",
    ] {
        assert!(text.contains(want), "{want}:\n{text}");
    }
    // SFTP: no encryption, no account; key-file login: no password.
    assert!(!text.contains("Encryption:"), "{text}");
    assert!(!text.contains("Password:"), "{text}");
    assert!(
        text.contains("the key file does not exist on this device"),
        "{text}"
    );
    insta::assert_snapshot!("site_manager_general_sftp_key_110x30", text);
    insta::assert_snapshot!(
        "site_manager_general_sftp_key_80x24",
        render(&mut view, 80, 24)
    );
}

#[test]
fn general_tab_sftp_password_is_masked() {
    let fx = fixture();
    let mut view = view_at(&fx, fx.db01);
    let text = render(&mut view, 110, 30);
    assert!(!text.contains("hunter2"), "{text}");
    assert!(text.contains("•••••••"), "{text}");
    assert!(text.contains("stored in the vault"), "{text}");
    assert!(text.contains("Try agent first:"), "{text}");
    insta::assert_snapshot!("site_manager_general_sftp_normal_110x30", text);
}

#[test]
fn general_tab_ftp_account() {
    let fx = fixture();
    let mut view = SiteManagerView::new(Some(fx.snapshot.clone()), opts());
    // Expand Personal (folders first: the top row) with the keys.
    view.handle_key(key(KeyCode::Char('g')));
    view.handle_key(key(KeyCode::Right));
    view.handle_key(key(KeyCode::Down));
    assert_eq!(view.selected(), Some(fx.ftp));
    let text = render(&mut view, 110, 30);
    for want in [
        "Encryption:",
        "Require explicit FTP over TLS",
        "Account:",
        "acct42",
    ] {
        assert!(text.contains(want), "{want}:\n{text}");
    }
    assert!(!text.contains("Key file:"), "{text}");
    assert!(!text.contains("Try agent first:"), "{text}");
    insta::assert_snapshot!("site_manager_general_ftp_account_110x30", text);
}

#[test]
fn advanced_transfer_charset_and_bookmarks_tabs() {
    let fx = fixture();
    let mut view = view_at(&fx, fx.web01);
    view.editor_mut().unwrap().set_tab(1);
    let text = render(&mut view, 110, 30);
    for want in [
        "Server type:",
        "Unix",
        "/var/www",
        "/home/me/www",
        "Time zone h:",
    ] {
        assert!(text.contains(want), "{want}:\n{text}");
    }
    insta::assert_snapshot!("site_manager_advanced_110x30", text);

    // Transfer: SFTP has no transfer mode.
    view.editor_mut().unwrap().set_tab(2);
    let text = render(&mut view, 110, 30);
    assert!(!text.contains("Transfer mode:"), "{text}");
    assert!(text.contains("Limit connections:"), "{text}");
    assert!(!text.contains("Maximum:"), "{text}");
    // Charset: nothing to set for SFTP.
    view.editor_mut().unwrap().set_tab(3);
    let text = render(&mut view, 110, 30);
    assert!(text.contains("SFTP file names are always UTF-8"), "{text}");
    // Bookmarks: listed.
    view.editor_mut().unwrap().set_tab(4);
    let text = render(&mut view, 110, 30);
    assert!(
        text.contains("• logs") && text.contains("• uploads"),
        "{text}"
    );
    insta::assert_snapshot!("site_manager_bookmarks_110x30", text);

    // FTP site: transfer mode, maximum and a custom charset.
    let mut view = view_at(&fx, fx.ftp);
    view.editor_mut().unwrap().set_tab(2);
    let text = render(&mut view, 110, 30);
    for want in ["Transfer mode:", "Passive", "Maximum:", "3"] {
        assert!(text.contains(want), "{want}:\n{text}");
    }
    insta::assert_snapshot!("site_manager_transfer_ftp_110x30", text);
    view.editor_mut().unwrap().set_tab(3);
    let text = render(&mut view, 110, 30);
    assert!(
        text.contains("(•) Custom") && text.contains("windows-1250"),
        "{text}"
    );
    insta::assert_snapshot!("site_manager_charset_ftp_110x30", text);
}

#[test]
fn field_visibility_follows_protocol_and_logon() {
    use FieldId as F;
    let mut site = Site::new("s", Protocol::Ftp, "h");
    let general = visible_fields(&site, 0);
    assert!(general.contains(&F::Encryption));
    assert!(general.contains(&F::Password));
    assert!(!general.contains(&F::KeyFile) && !general.contains(&F::TryAgent));
    site.logon = SiteLogon::Anonymous;
    let general = visible_fields(&site, 0);
    assert!(!general.contains(&F::User) && !general.contains(&F::Password));
    site.protocol = Protocol::Sftp;
    site.logon = SiteLogon::Agent { user: "u".into() };
    let general = visible_fields(&site, 0);
    assert!(!general.contains(&F::Encryption) && !general.contains(&F::Password));
    assert!(!general.contains(&F::TryAgent));
    assert_eq!(visible_fields(&site, 2), vec![F::LimitConnections]);
    assert!(visible_fields(&site, 3).is_empty());
    site.protocol = Protocol::Ftp;
    site.limit_connections = Some(2);
    site.charset = Charset::Custom(encoding_rs::KOI8_R);
    assert_eq!(
        visible_fields(&site, 2),
        vec![F::TransferMode, F::LimitConnections, F::MaxConnections]
    );
    assert_eq!(
        visible_fields(&site, 3),
        vec![F::CharsetMode, F::CustomCharset]
    );
}

#[test]
fn switching_protocol_and_logon_changes_the_fields() {
    let fx = fixture();
    let mut view = view_at(&fx, fx.db01);
    view.handle_key(key(KeyCode::Tab)); // editor: Protocol
    assert_eq!(view.focus(), Pane::Editor);
    assert_eq!(view.editor().unwrap().focused(), Some(FieldId::Protocol));
    // SFTP → FTP: encryption appears, the port placeholder follows.
    view.handle_key(key(KeyCode::Left));
    let site = &view.editor().unwrap().site;
    assert_eq!(site.protocol, Protocol::Ftp);
    let text = render(&mut view, 110, 30);
    assert!(text.contains("Encryption:"), "{text}");
    // Logon: FTP Normal keeps the password; Account adds the account.
    for _ in 0..4 {
        view.handle_key(key(KeyCode::Tab));
    }
    assert_eq!(view.editor().unwrap().focused(), Some(FieldId::Logon));
    view.handle_key(key(KeyCode::Char('a'))); // "Anonymous"
    view.handle_key(key(KeyCode::Char('a'))); // "Account"
    let site = &view.editor().unwrap().site;
    assert!(
        matches!(site.logon, SiteLogon::Account { .. }),
        "{:?}",
        site.logon
    );
    assert_eq!(
        view.editor().unwrap().password().unwrap().expose_secret(),
        "hunter2"
    );
    assert!(render(&mut view, 110, 30).contains("Account:"));
    // Back to SFTP: Account isn't available there, so it becomes Normal.
    view.editor_mut().unwrap().focus_field(FieldId::Protocol);
    view.handle_key(key(KeyCode::Right));
    let site = &view.editor().unwrap().site;
    assert_eq!(site.protocol, Protocol::Sftp);
    assert!(matches!(site.logon, SiteLogon::Normal { .. }));
}

#[test]
fn dirty_tracking_and_the_guard() {
    let fx = fixture();
    let mut view = view_at(&fx, fx.db01);
    assert!(!view.editor().unwrap().is_dirty());
    view.editor_mut().unwrap().focus_field(FieldId::Host);
    view.focus = Pane::Editor;
    view.handle_key(key(KeyCode::Char('x')));
    assert!(view.editor().unwrap().is_dirty());
    let text = render(&mut view, 110, 30);
    assert!(text.contains("db01 *"), "{text}");
    // Undo the edit: clean again.
    view.handle_key(key(KeyCode::Backspace));
    assert!(!view.editor().unwrap().is_dirty());

    // Dirty, then move in the tree: asked first; Cancel stays.
    view.handle_key(key(KeyCode::Char('x')));
    view.handle_key(key(KeyCode::Esc));
    assert_eq!(view.focus(), Pane::Tree);
    view.handle_key(key(KeyCode::Up));
    assert!(view.has_overlay());
    assert!(render(&mut view, 110, 30).contains("has unsaved changes"));
    view.handle_key(key(KeyCode::Esc));
    assert_eq!(view.selected(), Some(fx.db01));
    // Discard: moves on, the change is gone.
    view.handle_key(key(KeyCode::Up));
    view.handle_key(key(KeyCode::Char('d')));
    assert_ne!(view.selected(), Some(fx.db01));
    view.run(Cmd::Select(Some(fx.db01)));
    assert_eq!(view.editor().unwrap().site.host, "db01.example.com");

    // Save: the move waits for the save to succeed.
    view.editor_mut().unwrap().focus_field(FieldId::Host);
    view.focus = Pane::Editor;
    typed(&mut view, "z");
    view.handle_key(key(KeyCode::Esc));
    view.handle_key(key(KeyCode::Up));
    view.handle_key(key(KeyCode::Char('s')));
    let requests = view.take_requests();
    let [SiteOp::Save(site)] = requests.as_slice() else {
        panic!("save expected: {requests:?}");
    };
    assert_eq!(site.host, "db01.example.comz");
    assert!(view.is_busy());
    assert_eq!(view.selected(), Some(fx.db01));
    let mut stored = fx.snapshot.clone();
    let mut saved = (**site).clone();
    saved.host = "db01.example.comz".into();
    let mut nodes = stored.tree.walk().into_iter().cloned().collect::<Vec<_>>();
    nodes.retain(|n| n.id() != fx.db01);
    stored.tree.remove(fx.db01);
    stored
        .tree
        .insert(Some(fx.production), SiteNode::Site(Box::new(saved)))
        .unwrap();
    reply(
        &mut view,
        Some(stored),
        SiteOutcome::Saved {
            id: fx.db01,
            warnings: Vec::new(),
        },
    );
    assert!(!view.is_busy());
    // The row above db01.
    assert_eq!(view.selected(), Some(fx.production));
}

#[test]
fn validation_messages_inline() {
    let fx = fixture();
    let mut view = view_at(&fx, fx.web01);
    // New site in the selected site's folder.
    view.handle_key(key(KeyCode::Char('n')));
    assert!(view.has_overlay());
    view.handle_key(key(KeyCode::Enter)); // "New site"
    let ed = view.editor().unwrap();
    assert!(ed.is_new());
    assert_eq!(ed.site.parent, Some(fx.production));
    assert_eq!(ed.focused(), Some(FieldId::Host));
    assert_eq!(view.focus(), Pane::Editor);
    // No errors shown before the first save attempt.
    let text = render(&mut view, 110, 30);
    assert!(!text.contains("the host is empty"), "{text}");
    assert!(text.contains("New site * (new, not saved)"), "{text}");
    view.handle_key(ctrl('s'));
    assert!(view.take_requests().is_empty());
    let text = render(&mut view, 110, 30);
    assert!(text.contains("the host is empty"), "{text}");
    assert!(text.contains("the user is empty"), "{text}");
    assert!(text.contains("Can't save"), "{text}");
    insta::assert_snapshot!("site_manager_validation_110x30", text);
    // Host with a space, port out of range.
    typed(&mut view, "bad host");
    view.handle_key(key(KeyCode::Tab));
    typed(&mut view, "99999");
    let text = render(&mut view, 110, 30);
    assert!(text.contains("the host can't contain spaces"), "{text}");
    assert!(
        text.contains("the port must be between 1 and 65535"),
        "{text}"
    );
}

#[test]
fn new_site_is_saved_with_what_was_typed() {
    let fx = fixture();
    let mut view = view_at(&fx, fx.web01);
    view.handle_key(key(KeyCode::Char('n')));
    // Replace the suggested name.
    view.handle_key(ctrl('u'));
    typed(&mut view, "api");
    view.handle_key(key(KeyCode::Enter));
    typed(&mut view, "api.example.com");
    view.handle_key(key(KeyCode::Tab)); // port
    typed(&mut view, "22x2");
    view.handle_key(key(KeyCode::Tab)); // logon
    view.handle_key(key(KeyCode::Tab)); // user
    typed(&mut view, "svc");
    view.handle_key(key(KeyCode::Tab)); // password
    typed(&mut view, "s3cret");
    let text = render(&mut view, 110, 30);
    assert!(text.contains("● api *"), "{text}");
    assert!(!text.contains("s3cret"), "{text}");
    view.handle_key(alt('s'));
    let requests = view.take_requests();
    let [SiteOp::Save(site)] = requests.as_slice() else {
        panic!("save expected: {requests:?}");
    };
    assert_eq!(site.name, "api");
    assert_eq!(site.host, "api.example.com");
    assert_eq!(site.port, Some(222));
    assert_eq!(site.parent, Some(fx.production));
    let SiteLogon::Normal { user, password } = &site.logon else {
        panic!("normal logon expected");
    };
    assert_eq!(user, "svc");
    assert_eq!(password.as_ref().unwrap().expose_secret(), "s3cret");

    // Discarding a new site drops it from the tree.
    let mut view = view_at(&fx, fx.web01);
    view.handle_key(key(KeyCode::Char('n')));
    view.handle_key(key(KeyCode::Enter));
    view.handle_key(key(KeyCode::Esc));
    view.handle_key(key(KeyCode::Char('x')));
    assert!(view.editor().is_none_or(|e| !e.is_new()));
    assert!(!render(&mut view, 110, 30).contains("New site"));
}

#[test]
fn folder_rename_duplicate_delete_and_move_requests() {
    let fx = fixture();
    let mut view = view_at(&fx, fx.web01);

    view.handle_key(key(KeyCode::Char('f')));
    view.handle_key(key(KeyCode::Enter));
    assert!(matches!(
        view.take_requests().as_slice(),
        [SiteOp::AddFolder { parent: Some(p), name, vault: None }] if *p == fx.production && name == "New folder"
    ));
    reply(&mut view, Some(fx.snapshot.clone()), SiteOutcome::Renamed);

    // Rename in place.
    view.handle_key(key(KeyCode::F(2)));
    view.handle_key(ctrl('u'));
    typed(&mut view, "web02");
    assert!(render(&mut view, 110, 30).contains("web02"));
    view.handle_key(key(KeyCode::Enter));
    assert!(matches!(
        view.take_requests().as_slice(),
        [SiteOp::Rename { id, name }] if *id == fx.web01 && name == "web02"
    ));
    reply(&mut view, Some(fx.snapshot.clone()), SiteOutcome::Renamed);

    view.handle_key(key(KeyCode::Char('d')));
    assert!(matches!(view.take_requests().as_slice(), [SiteOp::Duplicate(id)] if *id == fx.web01));
    reply(
        &mut view,
        Some(fx.snapshot.clone()),
        SiteOutcome::Created(fx.db01),
    );
    assert_eq!(view.selected(), Some(fx.db01));

    // Delete a site: confirm, "No" is the default.
    view.handle_key(key(KeyCode::Delete));
    assert!(render(&mut view, 110, 30).contains("Delete the site “db01”?"));
    view.handle_key(key(KeyCode::Enter));
    assert!(view.take_requests().is_empty());
    view.handle_key(key(KeyCode::Char('x')));
    view.handle_key(key(KeyCode::Char('y')));
    assert!(matches!(view.take_requests().as_slice(), [SiteOp::Delete(id)] if *id == fx.db01));
    reply(
        &mut view,
        Some(fx.snapshot.clone()),
        SiteOutcome::Deleted(1),
    );

    // Delete a folder: the count is shown.
    view.run(Cmd::Select(Some(fx.work)));
    view.handle_key(key(KeyCode::Char('x')));
    let text = render(&mut view, 110, 30);
    assert!(
        text.contains("Delete the folder “Work” with 1 folder and 2 sites?"),
        "{text}"
    );
    view.handle_key(key(KeyCode::Esc));

    // Cut web01, paste into Work.
    view.run(Cmd::Select(Some(fx.web01)));
    view.handle_key(ctrl('x'));
    assert!(render(&mut view, 110, 30).contains("web01 (cut)"));
    view.run(Cmd::Select(Some(fx.work)));
    view.handle_key(ctrl('v'));
    assert!(matches!(
        view.take_requests().as_slice(),
        [SiteOp::Move { id, parent: Some(p) }] if *id == fx.web01 && *p == fx.work
    ));
    reply(
        &mut view,
        None,
        SiteOutcome::Failed("a folder can't be moved into itself".into()),
    );
    assert!(render(&mut view, 110, 30).contains("a folder can't be moved into itself"));
}

#[test]
fn connect_saves_first_when_dirty() {
    let fx = fixture();
    let mut view = view_at(&fx, fx.db01);
    view.handle_key(key(KeyCode::Enter));
    assert!(matches!(view.take_requests().as_slice(), [SiteOp::Connect(id)] if *id == fx.db01));
    assert!(view.is_closed());

    let mut view = view_at(&fx, fx.db01);
    view.editor_mut().unwrap().focus_field(FieldId::Comments);
    view.focus = Pane::Editor;
    typed(&mut view, "hi");
    view.handle_key(alt('c'));
    assert!(matches!(view.take_requests().as_slice(), [SiteOp::Save(_)]));
    assert!(!view.is_closed());
    reply(
        &mut view,
        Some(fx.snapshot.clone()),
        SiteOutcome::Saved {
            id: fx.db01,
            warnings: Vec::new(),
        },
    );
    assert!(matches!(view.take_requests().as_slice(), [SiteOp::Connect(id)] if *id == fx.db01));
    assert!(view.is_closed());
}

#[test]
fn search_reveals_and_selects() {
    let fx = fixture();
    let mut view = SiteManagerView::new(Some(fx.snapshot.clone()), opts());
    view.handle_key(key(KeyCode::Char('/')));
    typed(&mut view, "leg");
    assert_eq!(view.selected(), Some(fx.ftp));
    let text = render(&mut view, 110, 30);
    assert!(
        text.contains("▾ Personal") && text.contains("/leg"),
        "{text}"
    );
    view.handle_key(key(KeyCode::Enter));
    typed(&mut view, "j");
    assert_ne!(view.selected(), Some(fx.ftp));
}

#[test]
fn import_and_export_dialogs_ask_the_app() {
    let fx = fixture();
    let mut view = view_at(&fx, fx.web01);
    view.handle_key(alt('i'));
    let text = render(&mut view, 110, 30);
    assert!(
        text.contains("/home/me/.config/filezilla/sitemanager.xml"),
        "{text}"
    );
    view.handle_key(key(KeyCode::Enter));
    assert!(matches!(
        view.take_requests().as_slice(),
        [SiteOp::Import { path, passphrase: None }]
            if path.ends_with(".config/filezilla/sitemanager.xml")
    ));
    // An encrypted export: the passphrase is asked, then the import retried.
    reply(
        &mut view,
        None,
        SiteOutcome::NeedPassphrase("/tmp/x.cftp".into()),
    );
    typed(&mut view, "pass phrase");
    view.handle_key(key(KeyCode::Enter));
    let requests = view.take_requests();
    let [
        SiteOp::Import {
            passphrase: Some(p),
            ..
        },
    ] = requests.as_slice()
    else {
        panic!("{requests:?}");
    };
    assert_eq!(p.expose_secret(), "pass phrase");
    reply(
        &mut view,
        None,
        SiteOutcome::Failed("wrong passphrase".into()),
    );

    // Export the selected site, encrypted: the passphrases must match.
    view.handle_key(alt('e'));
    assert!(render(&mut view, 110, 30).contains("Site Work/Production/web01"));
    view.handle_key(key(KeyCode::Tab)); // format
    view.handle_key(key(KeyCode::Right));
    view.handle_key(key(KeyCode::Tab)); // file
    view.handle_key(key(KeyCode::Tab)); // passphrase
    typed(&mut view, "one");
    view.handle_key(key(KeyCode::Tab));
    typed(&mut view, "two");
    view.handle_key(key(KeyCode::Enter));
    assert!(render(&mut view, 110, 30).contains("The passphrases don't match"));
    view.handle_key(key(KeyCode::Backspace));
    view.handle_key(key(KeyCode::Backspace));
    view.handle_key(key(KeyCode::Backspace));
    typed(&mut view, "one");
    view.handle_key(key(KeyCode::Enter));
    let requests = view.take_requests();
    let [
        SiteOp::Export {
            scope,
            format,
            passphrase: Some(p),
            path,
        },
    ] = requests.as_slice()
    else {
        panic!("{requests:?}");
    };
    assert_eq!(*scope, ExportScope::Site(fx.web01));
    assert_eq!(*format, ExportFormat::Encrypted);
    assert_eq!(p.expose_secret(), "one");
    assert!(path.ends_with("courier-ftp-sites.json"));
}

#[test]
fn locked_and_loading_states() {
    let mut view = SiteManagerView::locked(opts());
    let text = render(&mut view, 100, 20);
    assert!(text.contains("Unlock the vault to view sites."), "{text}");
    insta::assert_snapshot!("site_manager_locked_100x20", text);
    view.handle_key(key(KeyCode::Esc));
    assert!(view.is_closed());

    // Opened before the first load finished: the tree arrives later, with
    // the "Save as site" site added as new.
    let fx = fixture();
    let mut prefill = Site::new("db01", Protocol::Sftp, "db01.example.com");
    prefill.logon = SiteLogon::Normal {
        user: "u".into(),
        password: Some(SecretString::from("typed")),
    };
    let mut view = SiteManagerView::new(None, opts()).with_new_site(prefill);
    assert!(render(&mut view, 100, 20).contains("Loading"));
    reply(&mut view, Some(fx.snapshot.clone()), SiteOutcome::Loaded);
    let ed = view.editor().unwrap();
    assert!(ed.is_new());
    // A free name at the top level, the typed password kept.
    assert_eq!(ed.site.name, "db01");
    assert_eq!(ed.password().unwrap().expose_secret(), "typed");
    assert_eq!(ed.site.parent, None);
}

#[test]
fn passwords_off_explains_the_missing_field() {
    let fx = fixture();
    let mut opts = opts();
    opts.store_passwords = false;
    let mut view = SiteManagerView::new(Some(fx.snapshot.clone()), opts);
    view.run(Cmd::Select(Some(fx.db01)));
    let text = render(&mut view, 110, 30);
    assert!(
        text.contains("not stored (vault.store_passwords is off)"),
        "{text}"
    );
    assert!(!text.contains("•••"), "{text}");
}

#[test]
fn picker_scores_names_first() {
    assert!(score("web", "Work/Production/web01").unwrap() > score("web", "web/zzz").unwrap());
    assert!(score("wb1", "Work/Production/web01").is_some());
    assert!(score("xyz", "Work/Production/web01").is_none());
    assert_eq!(score("", "anything"), Some(0));

    let fx = fixture();
    let (mut modal, mut rx) = site_picker(site_paths(&fx.snapshot.tree));
    for c in "db".chars() {
        assert_eq!(modal.handle_key(key(KeyCode::Char(c))), ModalOutcome::Keep);
    }
    let mut terminal = Terminal::new(TestBackend::new(80, 20)).unwrap();
    terminal
        .draw(|f| modal.draw(f, f.area(), &Theme::default()))
        .unwrap();
    let text = terminal.backend().to_string();
    assert!(text.contains("Work/Production/db01"), "{text}");
    insta::assert_snapshot!("site_picker_80x20", text);
    // Two letters and Enter connect.
    assert_eq!(modal.handle_key(key(KeyCode::Enter)), ModalOutcome::Close);
    assert_eq!(rx.try_recv().unwrap(), Some(fx.db01));
}

// ---- team vault roots (T90 §6)

struct Vaults {
    view: SiteManagerView,
    personal: VaultId,
    ops: VaultId,
    dev: VaultId,
    mine: ItemId,
    shared: ItemId,
}

/// Personal (site "mine"), "Team: Dev" (empty, writable) and "Team: Ops"
/// (site "shared", read-only for this account).
fn vaults() -> Vaults {
    let (personal, ops, dev) = (VaultId::new(), VaultId::new(), VaultId::new());
    let mut mine = Site::new("mine", Protocol::Sftp, "mine.example.com");
    mine.vault = Some(personal);
    let mut shared = Site::new("shared", Protocol::Sftp, "shared.example.com");
    shared.vault = Some(ops);
    shared.read_only = true;
    let ids = (mine.id, shared.id);
    let tree = SiteTree::from_items(Vec::new(), vec![mine, shared]);
    let mut view = SiteManagerView::new(
        Some(Snapshot {
            tree,
            bookmarks: HashMap::new(),
        }),
        opts(),
    );
    let root = |id, name: &str, personal, read_only| VaultRoot {
        id,
        name: name.to_owned(),
        personal,
        read_only,
    };
    view.set_vaults(vec![
        root(personal, "Personal", true, false),
        root(dev, "Dev", false, false),
        root(ops, "Ops", false, true),
    ]);
    Vaults {
        view,
        personal,
        ops,
        dev,
        mine: ids.0,
        shared: ids.1,
    }
}

#[test]
fn vaults_are_roots_and_read_only_items_are_locked() {
    let mut v = vaults();
    let view = &mut v.view;
    assert_eq!(view.selected(), Some(v.mine), "the first site");
    view.handle_key(key(KeyCode::Home));
    assert_eq!(view.root, Some(v.personal));
    insta::assert_snapshot!("vault_roots_100x24", render(view, 100, 24));

    view.handle_key(key(KeyCode::End));
    assert_eq!(view.selected(), Some(v.shared));
    insta::assert_snapshot!("read_only_site_100x24", render(view, 100, 24));
    // Nothing can be changed.
    view.handle_key(key(KeyCode::Tab));
    typed(view, "zzz");
    view.handle_key(ctrl('s'));
    assert!(render(view, 100, 24).contains("🔒 Team: Ops is read-only for you"));
    view.handle_key(key(KeyCode::Esc));
    for c in ['x', 'r', 'd', 'm'] {
        view.handle_key(key(KeyCode::Char(c)));
        assert!(
            render(view, 100, 24).contains("is read-only for you"),
            "{c}"
        );
    }
    assert!(view.take_requests().is_empty());
    assert_eq!(
        view.tree_ref().unwrap().site(v.shared).unwrap().host,
        "shared.example.com"
    );

    // New items in a read-only vault are refused too.
    view.handle_key(key(KeyCode::Up));
    assert_eq!(view.root, Some(v.ops));
    view.handle_key(key(KeyCode::Char('n')));
    assert!(!view.has_overlay());
    // Collapsing a root hides its items.
    view.handle_key(key(KeyCode::Left));
    view.handle_key(key(KeyCode::End));
    assert_eq!(view.root, Some(v.ops));
}

#[test]
fn copy_and_move_to_vault_and_new_items_in_a_team_root() {
    let mut v = vaults();
    let view = &mut v.view;
    view.handle_key(key(KeyCode::End));
    // Copy the read-only site somewhere this account can write.
    view.handle_key(key(KeyCode::Char('c')));
    assert!(view.has_overlay());
    insta::assert_snapshot!("copy_to_vault_100x24", render(view, 100, 24));
    view.handle_key(key(KeyCode::Down));
    view.handle_key(key(KeyCode::Enter));
    assert!(matches!(
        view.take_requests().as_slice(),
        [SiteOp::CopyToVault { id, vault, remove: false }] if *id == v.shared && *vault == v.dev
    ));
    reply(
        view,
        None,
        SiteOutcome::CopiedToVault {
            id: v.shared,
            moved: false,
        },
    );

    // Move "mine" to Dev.
    view.handle_key(key(KeyCode::Home));
    view.handle_key(key(KeyCode::Down));
    assert_eq!(view.selected(), Some(v.mine));
    view.handle_key(key(KeyCode::Char('m')));
    view.handle_key(key(KeyCode::Enter));
    assert!(matches!(
        view.take_requests().as_slice(),
        [SiteOp::CopyToVault { id, vault, remove: true }] if *id == v.mine && *vault == v.dev
    ));
    reply(view, None, SiteOutcome::Failed("offline".to_owned()));

    // Cut and paste into another vault is refused.
    view.handle_key(ctrl('x'));
    view.handle_key(key(KeyCode::Down));
    assert_eq!(view.root, Some(v.dev));
    view.handle_key(ctrl('v'));
    assert!(render(view, 100, 24).contains("That is another vault"));
    assert!(view.take_requests().is_empty());

    // A new folder and a new site at the top of the Dev root go into Dev.
    view.handle_key(key(KeyCode::Char('f')));
    view.handle_key(key(KeyCode::Enter));
    assert!(matches!(
        view.take_requests().as_slice(),
        [SiteOp::AddFolder { parent: None, vault: Some(d), .. }] if *d == v.dev
    ));
    reply(view, None, SiteOutcome::Failed("offline".to_owned()));
    view.handle_key(key(KeyCode::Char('n')));
    view.handle_key(key(KeyCode::Enter));
    let ed = view.editor().unwrap();
    assert!(ed.is_new());
    assert_eq!(ed.site.vault, Some(v.dev));
    let text = render(view, 100, 24);
    assert!(text.contains("▾ Team: Dev"), "{text}");
}

#[test]
fn credential_override_editor() {
    let mut v = vaults();
    let view = &mut v.view;
    // Not for personal sites.
    assert_eq!(view.selected(), Some(v.mine));
    view.handle_key(key(KeyCode::Char('o')));
    assert!(render(view, 100, 24).contains("only be set for sites in a team vault"));
    view.handle_key(key(KeyCode::End));
    view.handle_key(key(KeyCode::Char('o')));
    assert!(matches!(
        view.take_requests().as_slice(),
        [SiteOp::LoadOverride(id)] if *id == v.shared
    ));
    let key_id = ItemId::new();
    let mut current = CredentialOverride::new(v.shared);
    current.user = Some("me".to_owned());
    reply(
        view,
        None,
        SiteOutcome::Override(Box::new(OverrideForm {
            site: v.shared,
            site_name: "shared".to_owned(),
            current: Some(current),
            keys: vec![(key_id, "laptop key".to_owned())],
        })),
    );
    assert!(view.has_overlay());
    insta::assert_snapshot!("override_100x24", render(view, 100, 24));
    // User, password, key, passphrase.
    view.handle_key(key(KeyCode::Tab));
    typed(view, "s3cret");
    view.handle_key(key(KeyCode::Tab));
    view.handle_key(key(KeyCode::Right));
    view.handle_key(key(KeyCode::Tab));
    view.handle_key(key(KeyCode::Enter));
    let requests = view.take_requests();
    let [SiteOp::SetOverride(ov)] = requests.as_slice() else {
        panic!("{requests:?}");
    };
    assert_eq!(ov.shared_site_id, v.shared);
    assert_eq!(ov.user.as_deref(), Some("me"));
    assert_eq!(
        ov.password.as_ref().map(|p| p.expose_secret().to_owned()),
        Some("s3cret".to_owned())
    );
    assert_eq!(ov.key_id, Some(key_id));
    reply(view, None, SiteOutcome::OverrideSaved(true));
    assert!(render(view, 100, 24).contains("Your own login for this site was saved"));
}
