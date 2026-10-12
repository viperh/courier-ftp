//! T70: command-line launch intents through the app, with the real vault
//! engine (cheap Argon2) and the core's `MockServer`: URLs and site paths
//! connect only after unlock (one tab each), the local directory, unknown
//! site paths with close matches, skipping the vault and `--no-vault`.

use std::{path::Path, sync::Arc};

use clap::Parser;
use courier_ftp_core::{backend::MockServer, vault::MemKeyring};

use super::{
    site_tests::{server, start_with},
    vault_tests::{Rig, STRONG, config},
    *,
};
use crate::{cli::Cli, ui::VaultRequest};

/// The launch intents for `args` (after the program name).
fn launch(args: &[&str]) -> crate::cli::Launch {
    let mut argv = vec!["courier-ftp"];
    argv.extend_from_slice(args);
    Cli::try_parse_from(argv).unwrap().launch().unwrap()
}

/// A first run that creates the vault (and with `site`, the mock site),
/// then quits: the next start finds a locked vault.
async fn first_run(dir: &Path, keyring: &MemKeyring, server: &MockServer, site: bool) {
    let mut rig = start_with(dir, keyring, server).await;
    rig.create(STRONG, false).await;
    rig.until("sites loaded", |a| a.site_snapshot.is_some())
        .await;
    if site {
        rig.create_mock_site().await;
    }
}

/// A second start with `launch`, as `main` and the event loop do it.
async fn start_launched(
    dir: &Path,
    keyring: &MemKeyring,
    server: &MockServer,
    launch: crate::cli::Launch,
) -> Rig {
    let host_keys = Arc::new(courier_ftp_core::trust::HostKeyStoreSlot::new(Arc::new(
        courier_ftp_core::trust::MemoryHostKeyStore::locked(),
    )));
    let mut config = config();
    config.settings.interface.restore_tabs = true;
    let app = App::with_backends(config, Arc::new(server.clone()), 4.0, 60.0).with_vault(
        super::vault_tests::opener(dir, keyring),
        Arc::clone(&host_keys),
        courier_ftp_proto_sftp::ssh::CredentialCache::new(),
    );
    let mut rig = Rig {
        app: Box::new(app),
        host_keys,
    };
    rig.app.set_launch(launch);
    rig.app.begin();
    rig.settle().await;
    rig
}

fn remote_dir(app: &App) -> Option<String> {
    app.screen.remote.dir.as_ref().map(ToString::to_string)
}

fn local_of(dir: &Path) -> RemotePath {
    courier_ftp_core::local::local_to_remote(&std::path::absolute(dir).unwrap()).unwrap()
}

#[tokio::test]
async fn urls_connect_after_unlock_one_tab_each_in_the_local_dir() {
    let dir = tempfile::tempdir().unwrap();
    let local = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let server = server();
    first_run(dir.path(), &keyring, &server, false).await;

    let connects = server.connects();
    let launch = launch(&[
        "sftp://alice:pw@one.invalid/srv/www",
        "ftp://bob:pw@two.invalid:2121/srv",
        "--local",
        local.path().to_str().unwrap(),
    ]);
    assert!(launch.password_in_url);
    let mut rig = start_launched(dir.path(), &keyring, &server, launch).await;
    // The local pane starts in --local right away; nothing connects while
    // the vault is locked.
    rig.until("local listing", |a| a.screen.local.dir.is_some())
        .await;
    assert_eq!(rig.app.screen.local.dir, Some(local_of(local.path())));
    assert!(rig.app.remote.is_none());
    assert_eq!(server.connects(), connects);

    rig.unlock(STRONG).await;
    rig.until("both connected", |a| {
        a.tabs.len() == 2 && (0..2).all(|i| a.tab_conn(i).0.is_some_and(|r| r.connected))
    })
    .await;
    assert_eq!(server.connects(), connects + 2);
    // The second URL is shown (its tab opened last), in its directory.
    assert_eq!(rig.app.tabs.active, 1);
    let remote = rig.app.remote.as_ref().unwrap();
    assert_eq!(remote.info.address.host, "two.invalid");
    assert_eq!(remote.info.address.port, 2121);
    assert_eq!(remote_dir(&rig.app).as_deref(), Some("/srv"));
    assert_eq!(rig.app.screen.local.dir, Some(local_of(local.path())));
    rig.app.dispatch(Action::Tab1).unwrap();
    rig.settle().await;
    let remote = rig.app.remote.as_ref().unwrap();
    assert_eq!(remote.info.address.host, "one.invalid");
    assert_eq!(remote_dir(&rig.app).as_deref(), Some("/srv/www"));
    assert_eq!(rig.app.screen.local.dir, Some(local_of(local.path())));
    // The password never shows on screen.
    let text = rig.screen(120, 40);
    assert!(!text.contains(":pw@"), "{text}");
}

#[tokio::test]
async fn site_paths_connect_once_the_sites_load_and_unknown_ones_get_suggestions() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let server = server();
    first_run(dir.path(), &keyring, &server, true).await;

    let connects = server.connects();
    let launch = launch(&["--site", "mokc", "-s", "/mock/"]);
    let mut rig = start_launched(dir.path(), &keyring, &server, launch).await;
    assert!(rig.app.remote.is_none());
    rig.unlock(STRONG).await;
    rig.until("site connected", Rig::connected).await;
    assert_eq!(server.connects(), connects + 1);
    assert_eq!(rig.app.tabs.len(), 1);
    let site = rig.snapshot().tree.find_site("mock").unwrap().id;
    assert_eq!(rig.app.remote.as_ref().unwrap().site, Some(site));
    // The site's remote directory, with its saved password (no prompt).
    assert_eq!(remote_dir(&rig.app).as_deref(), Some("/srv"));
    assert_eq!(rig.app.screen.queued_prompts(), 0);
    let text = rig.screen(160, 50);
    assert!(
        text.contains("No site \"mokc\" in the Site Manager. Did you mean: mock?"),
        "{text}"
    );
}

#[tokio::test]
async fn skipping_the_vault_connects_the_urls_and_reports_the_sites() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let server = server();
    first_run(dir.path(), &keyring, &server, true).await;

    let launch = launch(&["sftp://alice:pw@one.invalid/srv", "--site", "mock"]);
    let mut rig = start_launched(dir.path(), &keyring, &server, launch).await;
    assert!(rig.app.remote.is_none());
    rig.app.vault_request(VaultRequest::Skip);
    rig.until("url connected", Rig::connected).await;
    assert_eq!(rig.app.tabs.len(), 1);
    assert_eq!(rig.app.remote.as_ref().unwrap().site, None);
    let text = rig.screen(160, 50);
    assert!(text.contains("--site needs the vault"), "{text}");

    // Unlocking later still opens the site, in a new tab.
    rig.app.dispatch(Action::UnlockVault).unwrap();
    rig.settle().await;
    rig.unlock(STRONG).await;
    rig.until("site connected", |a| {
        a.tabs.len() == 2
            && a.remote
                .as_ref()
                .is_some_and(|r| r.connected && r.site.is_some())
    })
    .await;
}

#[tokio::test]
async fn without_a_vault_urls_connect_at_once() {
    let server = server();
    let local = tempfile::tempdir().unwrap();
    let mut app = Box::new(App::with_backends(
        config(),
        Arc::new(server.clone()),
        4.0,
        60.0,
    ));
    let target = local.path().to_str().unwrap().to_owned();
    app.set_launch(launch(&["sftp://alice:pw@one.invalid/srv", &target]));
    app.begin();
    let mut rig = Rig {
        app,
        host_keys: Arc::new(courier_ftp_core::trust::HostKeyStoreSlot::new(Arc::new(
            courier_ftp_core::trust::MemoryHostKeyStore::locked(),
        ))),
    };
    rig.until("connected", Rig::connected).await;
    assert_eq!(remote_dir(&rig.app).as_deref(), Some("/srv"));
    assert_eq!(rig.app.screen.local.dir, Some(local_of(local.path())));
}

#[tokio::test]
async fn no_keyring_asks_for_the_master_password() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = MemKeyring::new();
    let server = server();
    // A vault with keyring unlock on.
    let mut rig = start_with(dir.path(), &keyring, &server).await;
    rig.create(STRONG, true).await;
    drop(rig);
    // Normally the keyring unlocks it silently ...
    let rig = start_with(dir.path(), &keyring, &server).await;
    assert_eq!(
        rig.app.vault.as_ref().map(|v| v.phase),
        Some(Phase::Unlocked)
    );
    drop(rig);
    // ... with --no-keyring the unlock screen asks.
    let host_keys = Arc::new(courier_ftp_core::trust::HostKeyStoreSlot::new(Arc::new(
        courier_ftp_core::trust::MemoryHostKeyStore::locked(),
    )));
    let app = App::with_backends(config(), Arc::new(server.clone()), 4.0, 60.0).with_vault(
        super::vault_tests::opener(dir.path(), &keyring),
        Arc::clone(&host_keys),
        courier_ftp_proto_sftp::ssh::CredentialCache::new(),
    );
    let mut rig = Rig {
        app: Box::new(app),
        host_keys,
    };
    rig.app.set_no_keyring();
    rig.app.begin();
    rig.settle().await;
    assert_eq!(rig.app.vault.as_ref().map(|v| v.phase), Some(Phase::Locked));
    rig.unlock(STRONG).await;
    assert_eq!(
        rig.app.vault.as_ref().map(|v| v.phase),
        Some(Phase::Unlocked)
    );
}

#[test]
fn close_matches_for_unknown_site_paths() {
    use courier_ftp_core::{
        model::Protocol,
        sites::{Folder, Site, SiteNode, SiteTree},
    };
    let site = |name: &str| SiteNode::Site(Box::new(Site::new(name, Protocol::Sftp, "h.invalid")));
    let mut tree = SiteTree::new();
    let work = Folder::new("Work");
    let prod = Folder::new("Production");
    let (work_id, prod_id) = (work.id, prod.id);
    tree.insert(None, SiteNode::Folder(work)).unwrap();
    tree.insert(Some(work_id), SiteNode::Folder(prod)).unwrap();
    for name in ["web01", "web02", "db01"] {
        tree.insert(Some(prod_id), site(name)).unwrap();
    }
    tree.insert(None, site("home")).unwrap();
    let close = super::launch::close_matches(&tree, "Work/Production/web1");
    assert_eq!(close[0], "Work/Production/web01", "{close:?}");
    // A typo the in-order match misses still finds the site by name.
    let close = super::launch::close_matches(&tree, "Work/Prodcution/wbe01");
    assert!(
        close.contains(&"Work/Production/web01".to_owned()),
        "{close:?}"
    );
    assert!(super::launch::close_matches(&tree, "zzzzzzzz").is_empty());
}
