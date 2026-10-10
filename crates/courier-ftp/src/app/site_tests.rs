//! T59: the Site Manager through the app, with the real vault engine
//! (cheap Argon2) and the core's `MockServer`: create a site and connect to
//! it, connect again after a restart with the saved password, import a
//! FileZilla file, export and import an encrypted export, "Save as site"
//! from quickconnect, the site picker and the locked vault.

use std::path::Path;

use courier_ftp_core::{
    backend::MockServer,
    model::LogonType,
    sites::{SiteLogon, SiteNode},
    vault::MemKeyring,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use secrecy::ExposeSecret;

use super::vault_tests::{Rig, STRONG, config, start};
use super::*;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../courier-ftp-core/tests/fixtures/filezilla/sitemanager.xml"
);

impl Rig {
    fn ctrl(&mut self, code: KeyCode) {
        self.app
            .handle_key_event(KeyEvent::new(code, KeyModifiers::CONTROL))
            .unwrap();
    }

    fn manager_open(&self) -> bool {
        self.app.screen.site_manager().is_some()
    }

    fn snapshot(&self) -> &crate::sites::Snapshot {
        self.app.site_snapshot.as_ref().expect("sites loaded")
    }

    /// Replace the text of the focused path field with `path`.
    fn replace_text(&mut self, path: &str) {
        self.ctrl(KeyCode::Char('e'));
        self.ctrl(KeyCode::Char('u'));
        self.app.screen.handle_paste(path);
    }

    /// A fresh vault with the sites loaded.
    async fn fresh(dir: &Path, keyring: &MemKeyring) -> Self {
        let mut rig = start(dir, keyring, config()).await;
        rig.create(STRONG, false).await;
        rig.until("sites loaded", |a| a.site_snapshot.is_some())
            .await;
        rig
    }

    /// Create a site for the mock server in the Site Manager and save it:
    /// `mock`, SFTP, alice / s3cret, remote directory `/srv`.
    async fn create_mock_site(&mut self) {
        self.ctrl(KeyCode::Char('s'));
        self.settle().await;
        assert!(self.manager_open());
        self.key(KeyCode::Char('n'));
        self.ctrl(KeyCode::Char('u'));
        self.typed("mock");
        self.key(KeyCode::Enter);
        self.typed("mock.invalid");
        self.key(KeyCode::Tab); // port
        self.key(KeyCode::Tab); // logon type
        self.key(KeyCode::Tab); // user
        self.typed("alice");
        self.key(KeyCode::Tab); // password
        self.typed("s3cret");
        // Advanced: server type, bypass proxy, local dir, remote dir.
        self.ctrl(KeyCode::PageDown);
        for _ in 0..3 {
            self.key(KeyCode::Tab);
        }
        self.typed("/srv");
        let text = self.screen(120, 40);
        assert!(text.contains("mock *"), "{text}");
        self.ctrl(KeyCode::Char('s'));
        self.settle().await;
        assert!(self.screen(120, 40).contains("Saved"));
    }
}

fn server() -> MockServer {
    let server = MockServer::new();
    server.add_file("/srv/www/index.html", b"<html>");
    server.add_file("/srv/readme.txt", b"hello");
    server
}

async fn start_with(dir: &Path, keyring: &MemKeyring, server: &MockServer) -> Rig {
    let host_keys = Arc::new(courier_ftp_core::trust::HostKeyStoreSlot::new(Arc::new(
        courier_ftp_core::trust::MemoryHostKeyStore::locked(),
    )));
    let app = App::with_backends(config(), Arc::new(server.clone()), 4.0, 60.0).with_vault(
        super::vault_tests::opener(dir, keyring),
        host_keys,
        courier_ftp_proto_sftp::ssh::CredentialCache::new(),
    );
    let mut rig = Rig {
        app: Box::new(app),
        host_keys: Arc::new(courier_ftp_core::trust::HostKeyStoreSlot::new(Arc::new(
            courier_ftp_core::trust::MemoryHostKeyStore::locked(),
        ))),
    };
    rig.app.start_vault();
    rig.settle().await;
    rig
}

#[tokio::test]
async fn create_connect_restart_and_connect_with_the_saved_password() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let server = server();
    let mut rig = start_with(dir.path(), &keyring, &server).await;
    rig.create(STRONG, false).await;
    rig.until("sites loaded", |a| a.site_snapshot.is_some())
        .await;
    rig.create_mock_site().await;

    let site = rig.snapshot().tree.find_site("mock").unwrap().clone();
    assert_eq!(site.host, "mock.invalid");
    let SiteLogon::Normal { user, password } = &site.logon else {
        panic!("normal logon expected: {:?}", site.logon);
    };
    assert_eq!(user, "alice");
    assert_eq!(password.as_ref().unwrap().expose_secret(), "s3cret");
    assert_eq!(site.default_remote_dir.as_ref().unwrap().as_str(), "/srv");
    let text = rig.screen(120, 40);
    assert!(!text.contains("s3cret"), "{text}");

    // Connect: the manager closes, the remote pane opens the site's directory.
    rig.alt('c');
    rig.until("connected", Rig::connected).await;
    assert!(!rig.manager_open());
    let remote = rig.app.remote.as_ref().unwrap();
    assert_eq!(remote.site, Some(site.id));
    assert_eq!(
        rig.app.screen.remote.dir.as_ref().map(ToString::to_string),
        Some("/srv".to_owned())
    );
    // A site connect isn't quickconnect history; the connect time is kept.
    rig.until("connect recorded", |app| {
        app.sites.try_lock().ok().is_some_and(|g| {
            g.as_ref()
                .and_then(|m| m.site(site.id))
                .is_some_and(|s| s.last_connected_at.is_some())
        })
    })
    .await;
    assert_eq!(
        rig.app.screen.quickconnect().history().map(<[_]>::len),
        Some(0)
    );
    // Reconnect goes through the site again (saved password, no prompt).
    rig.app.dispatch(Action::Disconnect).unwrap();
    rig.settle().await;
    rig.ctrl_x('r');
    rig.until("reconnected", Rig::connected).await;
    assert!(matches!(
        rig.app.remote.as_ref().unwrap().info.logon,
        LogonType::Normal { .. }
    ));

    // Restart: unlock, open the Site Manager, Enter on the site connects
    // with the stored password, nothing asked.
    drop(rig);
    let mut rig = start_with(dir.path(), &keyring, &server).await;
    rig.unlock(STRONG).await;
    rig.until("sites loaded", |a| a.site_snapshot.is_some())
        .await;
    rig.ctrl(KeyCode::Char('s'));
    rig.settle().await;
    let text = rig.screen(120, 40);
    assert!(text.contains("● mock"), "{text}");
    rig.key(KeyCode::Enter);
    rig.until("connected", Rig::connected).await;
    let LogonType::Normal { user, password } = &rig.app.remote.as_ref().unwrap().info.logon else {
        panic!("saved password expected");
    };
    assert_eq!(user, "alice");
    assert_eq!(password.expose_secret(), "s3cret");
    assert_eq!(rig.app.screen.queued_prompts(), 0);
    assert!(!rig.app.screen.has_modal());
}

#[tokio::test]
async fn import_filezilla_then_export_and_reimport_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let mut rig = Rig::fresh(dir.path(), &keyring).await;
    rig.ctrl(KeyCode::Char('s'));
    rig.settle().await;
    assert!(rig.screen(120, 40).contains("No sites yet."));

    // Import… → the FileZilla file.
    rig.alt('i');
    rig.replace_text(FIXTURE);
    rig.key(KeyCode::Enter);
    rig.settle().await;
    let text = rig.screen(120, 40);
    assert!(
        text.contains("8 sites imported, 3 passwords imported, 2 skipped"),
        "{text}"
    );
    rig.key(KeyCode::Enter); // close the report
    let tree = &rig.snapshot().tree;
    let root = tree
        .roots()
        .iter()
        .find(|n| n.name().starts_with("Imported from FileZilla"))
        .expect("import folder");
    let (folders, sites) = root.count();
    assert_eq!((folders, sites), (4, 8));
    let web01 = tree
        .walk()
        .into_iter()
        .find(|n| n.name() == "web01")
        .and_then(SiteNode::as_site)
        .unwrap()
        .clone();
    let text = rig.screen(120, 40);
    assert!(text.contains("Imported from FileZilla"), "{text}");

    // Export everything, encrypted with a passphrase.
    let out = dir.path().join("sites.cftp");
    rig.alt('e');
    rig.key(KeyCode::Right); // What: all sites
    rig.key(KeyCode::Tab);
    rig.key(KeyCode::Right); // Format: encrypted
    rig.key(KeyCode::Tab);
    rig.replace_text(&out.display().to_string());
    rig.key(KeyCode::Tab);
    rig.typed("export pass");
    rig.key(KeyCode::Tab);
    rig.typed("export pass");
    rig.key(KeyCode::Enter);
    rig.settle().await;
    let text = rig.screen(120, 40);
    assert!(text.contains("Exported 8 sites to"), "{text}");
    let bytes = std::fs::read(&out).unwrap();
    assert!(courier_ftp_core::sites::import::is_encrypted_export(&bytes));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // And a FileZilla XML of the selected site, without passwords.
    let xml = dir.path().join("one.xml");
    rig.key(KeyCode::Char('/'));
    rig.typed("web01");
    rig.key(KeyCode::Enter);
    rig.alt('e');
    rig.key(KeyCode::Tab);
    rig.key(KeyCode::Right);
    rig.key(KeyCode::Right); // FileZilla XML
    rig.key(KeyCode::Tab);
    rig.replace_text(&xml.display().to_string());
    rig.key(KeyCode::Enter);
    rig.settle().await;
    let text = std::fs::read_to_string(&xml).unwrap();
    assert!(text.contains("<Name>web01</Name>"), "{text}");
    assert!(!text.contains("<Pass"), "{text}");
    assert!(rig.screen(120, 40).contains("Exported 1 site to"));

    // Import the encrypted export again: the passphrase is asked.
    rig.alt('i');
    rig.replace_text(&out.display().to_string());
    rig.key(KeyCode::Enter);
    rig.settle().await;
    assert!(rig.screen(120, 40).contains("Encrypted export"));
    rig.typed("export pass");
    rig.key(KeyCode::Enter);
    rig.settle().await;
    let text = rig.screen(120, 40);
    assert!(text.contains("8 sites imported"), "{text}");
    rig.key(KeyCode::Enter);
    // Ids already in the vault get new ones: both copies exist, passwords
    // included.
    let copies: Vec<_> = rig
        .snapshot()
        .tree
        .sites()
        .filter(|s| s.name == "web01")
        .cloned()
        .collect();
    assert_eq!(copies.len(), 2);
    assert!(
        copies
            .iter()
            .all(|s| s.logon.password().map(ExposeSecret::expose_secret)
                == web01.logon.password().map(ExposeSecret::expose_secret))
    );
}

#[tokio::test]
async fn save_as_site_from_quickconnect_keeps_the_typed_password() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let server = server();
    let mut rig = start_with(dir.path(), &keyring, &server).await;
    rig.create(STRONG, false).await;
    rig.until("sites loaded", |a| a.site_snapshot.is_some())
        .await;

    // Not connected: nothing to save.
    rig.ctrl_x('a');
    rig.settle().await;
    assert!(rig.screen(120, 40).contains("Not connected"));

    rig.quickconnect("sftp://alice:typed-pw@mock.invalid:2200/srv")
        .await;
    rig.until("connected", Rig::connected).await;
    rig.ctrl_x('a');
    rig.settle().await;
    assert!(rig.manager_open());
    let text = rig.screen(120, 40);
    assert!(text.contains("mock.invalid * (new, not saved)"), "{text}");
    assert!(!text.contains("typed-pw"), "{text}");
    rig.ctrl(KeyCode::Char('s'));
    rig.settle().await;
    let site = rig
        .snapshot()
        .tree
        .find_site("mock.invalid")
        .unwrap()
        .clone();
    assert_eq!(site.port, Some(2200));
    assert_eq!(
        site.logon.password().map(ExposeSecret::expose_secret),
        Some("typed-pw")
    );

    // The picker: two letters and Enter connect to it.
    rig.key(KeyCode::Esc);
    rig.key(KeyCode::Esc);
    assert!(!rig.manager_open());
    rig.app.dispatch(Action::Disconnect).unwrap();
    rig.settle().await;
    rig.ctrl_x('g');
    rig.settle().await;
    assert!(rig.screen(120, 40).contains("Connect to site"));
    rig.typed("mo");
    rig.key(KeyCode::Enter);
    rig.until("connected", Rig::connected).await;
    assert_eq!(rig.app.remote.as_ref().unwrap().site, Some(site.id));
}

#[tokio::test]
async fn locked_vault_shows_the_unlock_message_and_lock_closes_the_manager() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let mut rig = Rig::fresh(dir.path(), &keyring).await;
    rig.ctrl(KeyCode::Char('s'));
    rig.settle().await;
    assert!(rig.manager_open());
    // Locking drops the sites and closes the manager.
    rig.app.dispatch(Action::LockVault).unwrap();
    rig.settle().await;
    assert!(!rig.manager_open());
    assert!(rig.app.site_snapshot.is_none());
    assert!(rig.app.sites.lock().await.is_none());

    // Continue without the vault, then Ctrl-s: asked to unlock; "No"
    // leaves the read-only message.
    rig.alt('c');
    rig.settle().await;
    rig.ctrl(KeyCode::Char('s'));
    rig.settle().await;
    assert!(
        rig.screen(120, 40)
            .contains("The vault is locked. Unlock it")
    );
    rig.key(KeyCode::Char('n'));
    rig.settle().await;
    let text = rig.screen(120, 40);
    assert!(text.contains("Unlock the vault to view sites."), "{text}");
    // Enter there unlocks; afterwards the sites are shown.
    rig.key(KeyCode::Enter);
    rig.settle().await;
    rig.unlock(STRONG).await;
    rig.until("sites loaded", |a| a.site_snapshot.is_some())
        .await;
    let text = rig.screen(120, 40);
    assert!(text.contains("No sites yet."), "{text}");
}
