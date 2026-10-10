//! Tests for site import and export (T32).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fmt::Write as _;
use std::sync::Arc;

use courier_ftp_crypto::kdf::Argon2Cost;
use courier_ftp_crypto::keys::os_rng;
use pretty_assertions::assert_eq;
use secrecy::{ExposeSecret, SecretString};

use super::export::{self, ExportScope};
use super::import::{self, ImportError, ImportNode};
use super::*;
use crate::model::item::{ItemId, ItemKind, SiteColor, SiteTransferMode, SshKey, UnixMillis};
use crate::model::{Charset, FtpEncryption, LocalPath, Protocol, RemotePath};
use crate::vault::{ItemVault, ItemVaultExt, MemItemVault};

const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/filezilla/sitemanager.xml");

fn secret(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

struct Fixture {
    vault: Arc<MemItemVault>,
    local: Arc<MemSiteLocalStore>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            vault: Arc::new(MemItemVault::unlocked()),
            local: Arc::new(MemSiteLocalStore::new()),
        }
    }

    async fn sites(&self) -> SiteManager {
        SiteManager::load(self.vault.clone(), self.local.clone())
            .await
            .unwrap()
    }

    async fn bookmarks(&self) -> Bookmarks {
        Bookmarks::load(self.vault.clone(), self.local.clone())
            .await
            .unwrap()
    }
}

/// One line per site with every imported field; secrets only as "set".
fn describe(site: &Site) -> String {
    let logon = match &site.logon {
        SiteLogon::Anonymous => "anonymous".to_owned(),
        SiteLogon::Normal { user, password } => {
            format!("normal {user} pw={}", password.is_some())
        }
        SiteLogon::AskForPassword { user } => format!("ask {user}"),
        SiteLogon::Interactive { user } => format!("interactive {user}"),
        SiteLogon::Agent { user } => format!("agent {user}"),
        SiteLogon::Account {
            user,
            password,
            account,
        } => format!("account {user} pw={} acct={account}", password.is_some()),
        SiteLogon::KeyFile {
            user,
            key,
            passphrase,
        } => format!("key {user} {key:?} pp={}", passphrase.is_some()),
    };
    format!(
        "{} | {:?}/{:?} {}:{} | {logon} | type={:?} tz={} mode={:?} conns={:?} charset={} proxy_bypass={} color={:?} local={:?} remote={:?} sync={} cmp={} comments={:?}",
        site.name,
        site.protocol,
        site.encryption,
        site.host,
        site.effective_port(),
        site.server_type,
        site.timezone_offset_minutes,
        site.transfer_mode,
        site.limit_connections,
        site.charset.label(),
        site.bypass_proxy,
        site.color,
        site.default_local_dir
            .as_ref()
            .map(|p| p.as_path().to_string_lossy().into_owned()),
        site.default_remote_dir.as_ref().map(RemotePath::as_str),
        site.sync_browsing,
        site.directory_comparison,
        site.comments,
    )
}

fn render_import(nodes: &[ImportNode], depth: usize, out: &mut String) {
    for n in nodes {
        let pad = "  ".repeat(depth);
        match n {
            ImportNode::Folder { name, children, .. } => {
                let _ = writeln!(out, "{pad}[{name}]");
                render_import(children, depth + 1, out);
            }
            ImportNode::Site(s) => {
                let _ = writeln!(out, "{pad}{}", describe(&s.site));
                for b in &s.bookmarks {
                    let _ = writeln!(out, "{pad}  * {b:?}");
                }
            }
        }
    }
}

fn render_tree(sites: &SiteManager, bookmarks: &Bookmarks) -> String {
    let mut out = String::new();
    for row in sites.tree().walk() {
        let depth = sites.tree().ancestors(row.id()).len();
        let pad = "  ".repeat(depth);
        match row {
            SiteNode::Folder(f) => {
                let _ = writeln!(out, "{pad}[{}]", f.name);
            }
            SiteNode::Site(s) => {
                let _ = writeln!(out, "{pad}{}", describe(s));
                for b in bookmarks.for_site(s.id) {
                    let _ = writeln!(
                        out,
                        "{pad}  * {} local={:?} remote={:?} sync={} cmp={}",
                        b.name,
                        b.local_dir
                            .as_ref()
                            .map(|p| p.as_path().to_string_lossy().into_owned()),
                        b.remote_dir.as_ref().map(RemotePath::as_str),
                        b.sync_browsing,
                        b.comparison
                    );
                }
            }
        }
    }
    out
}

// ------------------------------------------------------------------ FileZilla

#[test]
fn filezilla_fixture_parses() {
    let tree = import::parse_filezilla(FIXTURE).unwrap();
    assert_eq!(tree.count(), (3, 8));
    let mut out = String::new();
    render_import(&tree.nodes, 0, &mut out);
    for s in &tree.skipped {
        let _ = writeln!(out, "skipped: {} — {}", s.path, s.reason);
    }
    insta::assert_snapshot!("filezilla_fixture_parsed", out);
    assert!(!out.contains("s3cr3t"));
}

#[test]
fn filezilla_passwords_are_decoded() {
    let tree = import::parse_filezilla(FIXTURE).unwrap();
    let mut sites = Vec::new();
    fn collect<'a>(nodes: &'a [ImportNode], out: &mut Vec<&'a import::ImportSite>) {
        for n in nodes {
            match n {
                ImportNode::Folder { children, .. } => collect(children, out),
                ImportNode::Site(s) => out.push(s),
            }
        }
    }
    collect(&tree.nodes, &mut sites);
    let pw = |name: &str| {
        sites
            .iter()
            .find(|s| s.site.name == name)
            .unwrap()
            .site
            .logon
            .password()
            .map(|p| p.expose_secret().to_owned())
    };
    assert_eq!(pw("web01").as_deref(), Some("s3cr3t-Pässwörd"));
    assert_eq!(pw("Build server (account)").as_deref(), Some("acct-pw"));
    // Pre-3.26 files store it in plain text.
    assert_eq!(pw("Legacy (no Name element)").as_deref(), Some("hunter2"));
    // Master-password protected: imported without, and reported.
    let mp = sites
        .iter()
        .find(|s| s.site.name == "Master-password protected")
        .unwrap();
    assert!(mp.site.logon.password().is_none());
    assert!(
        mp.password_skipped
            .as_ref()
            .unwrap()
            .contains("master password")
    );
}

#[tokio::test]
async fn filezilla_fixture_imports_into_a_dated_folder() {
    let f = Fixture::new();
    let mut sites = f.sites().await;
    // An existing top-level folder with the same name gets a suffix.
    let name = import::filezilla_folder_name(
        time::Date::from_calendar_date(2026, time::Month::October, 10).unwrap(),
    );
    assert_eq!(name, "Imported from FileZilla 2026-10-10");
    sites.add_folder(None, &name).await.unwrap();

    let tree = import::parse_filezilla(FIXTURE).unwrap();
    let report = import::apply(&mut sites, tree, None, Some(&name))
        .await
        .unwrap();
    assert_eq!(report.sites, 8);
    assert_eq!(report.folders, 4);
    assert_eq!(report.passwords, 3);
    assert_eq!(report.bookmarks, 2);
    assert_eq!(
        report.summary(),
        "8 sites imported, 3 passwords imported, 2 skipped"
    );
    let root = report.root.unwrap();
    assert_eq!(
        sites.tree().folder(root).unwrap().name,
        "Imported from FileZilla 2026-10-10 (2)"
    );

    let bookmarks = f.bookmarks().await;
    let text = render_tree(&sites, &bookmarks);
    insta::assert_snapshot!("filezilla_fixture_imported", text);

    // The whole tree reloads from the vault the same way.
    let reloaded = f.sites().await;
    assert_eq!(render_tree(&reloaded, &bookmarks), text);
    let web = reloaded
        .find_site("Imported from FileZilla 2026-10-10 (2)/Work/Production/web01")
        .unwrap();
    assert_eq!(
        web.logon.password().unwrap().expose_secret(),
        "s3cr3t-Pässwörd"
    );
}

#[tokio::test]
async fn import_reports_invalid_sites() {
    let xml = br#"<FileZilla3><Servers>
        <Server><Host>key.example.com</Host><Protocol>1</Protocol><User>u</User><Logontype>5</Logontype><Name>no key</Name></Server>
        <Server><Protocol>1</Protocol><Name>no host</Name></Server>
        <Server><Host>ok.example.com</Host><Protocol>0</Protocol><Logontype>0</Logontype><Name>ok</Name></Server>
    </Servers></FileZilla3>"#;
    let tree = import::parse_filezilla(xml).unwrap();
    assert_eq!(tree.skipped.len(), 1);
    assert_eq!(tree.skipped[0].path, "no host");
    let f = Fixture::new();
    let mut sites = f.sites().await;
    let report = import::apply(&mut sites, tree, None, None).await.unwrap();
    assert_eq!(report.sites, 1);
    assert_eq!(report.skipped.len(), 2);
    assert_eq!(report.skipped[1].path, "no key");
    assert!(report.skipped[1].reason.contains("key"), "{report:?}");
}

#[test]
fn remote_dirs_decode() {
    let d = |s: &str| decode_remote_dir(s).map(|p| p.as_str().to_owned());
    assert_eq!(d("1 0 4 home 4 user").as_deref(), Some("/home/user"));
    assert_eq!(d("1 0").as_deref(), Some("/"));
    assert_eq!(
        d("1 0 10 My Uploads 3 a b").as_deref(),
        Some("/My Uploads/a b")
    );
    assert_eq!(d("1 0 2 ☃☃ 1 x").as_deref(), Some("/☃☃/x"));
    assert_eq!(d("3 2 C: 3 pub").as_deref(), Some("/C:/pub"));
    assert_eq!(d("1 0 4  sp  1 x").as_deref(), Some("/ sp /x"));
    for bad in [
        "",
        "x",
        "1",
        "1 0 9 short",
        "1 0 2 ..",
        "1 0 3 a/b",
        "1 0 0 ",
        "1 0 -1 a",
    ] {
        assert_eq!(d(bad), None, "{bad:?}");
    }
    let p = RemotePath::new("/var/www/My Site ☃");
    assert_eq!(encode_remote_dir(&p), "1 0 3 var 3 www 9 My Site ☃");
    assert_eq!(decode_remote_dir(&encode_remote_dir(&p)), Some(p));
    assert_eq!(encode_remote_dir(&RemotePath::root()), "1 0");
}

#[test]
fn filezilla_locations_are_suggested() {
    let home = std::path::PathBuf::from("/home/me");
    let appdata = std::path::PathBuf::from("C:/Users/me/AppData/Roaming");
    let got = import::filezilla_locations(Some(home), Some(appdata));
    let want = if cfg!(windows) {
        "C:/Users/me/AppData/Roaming/FileZilla/sitemanager.xml"
    } else {
        "/home/me/.config/filezilla/sitemanager.xml"
    };
    assert_eq!(got[0], std::path::PathBuf::from(want));
}

// ------------------------------------------------------------------ hostile XML

#[test]
fn entity_expansion_is_refused() {
    let laughs = br#"<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<FileZilla3><Servers><Server><Host>&lol3;</Host></Server></Servers></FileZilla3>"#;
    assert!(matches!(
        import::parse_filezilla(laughs),
        Err(ImportError::Malformed(m)) if m.contains("document type")
    ));
    // External entities can't be declared either.
    let xxe =
        br#"<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><FileZilla3>&e;</FileZilla3>"#;
    assert!(import::parse_filezilla(xxe).is_err());
    // Undeclared entities are an error, not silently dropped.
    let undeclared =
        b"<FileZilla3><Servers><Server><Host>&e;</Host></Server></Servers></FileZilla3>";
    assert!(import::parse_filezilla(undeclared).is_err());
}

#[test]
fn huge_and_deep_files_are_refused() {
    let big = vec![b' '; MAX_XML_LEN + 1];
    assert!(matches!(
        import::parse_filezilla(&big),
        Err(ImportError::TooLarge)
    ));
    let mut deep = String::from("<FileZilla3><Servers>");
    for _ in 0..(MAX_DEPTH + 5) {
        deep.push_str("<Folder>x");
    }
    for _ in 0..(MAX_DEPTH + 5) {
        deep.push_str("</Folder>");
    }
    deep.push_str("</Servers></FileZilla3>");
    assert!(import::parse_filezilla(deep.as_bytes()).is_err());
    // Many elements (but under the cap) parse fine and fast.
    let mut wide = String::from("<FileZilla3><Servers>");
    for i in 0..5000 {
        let _ = write!(
            wide,
            "<Server><Host>h{i}.example.com</Host><Logontype>0</Logontype><Name>s{i}</Name></Server>"
        );
    }
    wide.push_str("</Servers></FileZilla3>");
    assert_eq!(
        import::parse_filezilla(wide.as_bytes()).unwrap().count(),
        (0, 5000)
    );
}

#[test]
fn malformed_files_are_errors() {
    for bad in [
        &b""[..],
        b"not xml",
        b"<Other/>",
        b"<FileZilla3><Servers>",
        b"<FileZilla3></Servers></FileZilla3>",
        b"<FileZilla3/><FileZilla3/>",
        &[0xff, 0xfe, 0x00][..],
    ] {
        assert!(import::parse_filezilla(bad).is_err(), "{bad:?}");
    }
    // A file without servers is empty, not an error.
    let empty = import::parse_filezilla(b"<FileZilla3 version=\"3\"/>").unwrap();
    assert_eq!(empty.count(), (0, 0));
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig {
        cases: 256,
        ..proptest::prelude::ProptestConfig::default()
    })]

    // The `filezilla_xml` fuzz body.
    #[test]
    fn fuzz_filezilla_xml_never_panics(
        data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..1024),
    ) {
        fuzz_filezilla_xml(&data);
    }

    // FileZilla-shaped input reaches the field parsers.
    #[test]
    fn filezilla_shaped_input_never_panics(
        values in proptest::collection::vec("[ -~☃]{0,12}", 12),
        dir in "[0-9 a-z./]{0,24}",
    ) {
        let tags = ["Host", "Port", "Protocol", "Type", "User", "Logontype", "TimezoneOffset",
                    "PasvMode", "MaximumMultipleConnections", "EncodingType", "Colour", "Pass"];
        let mut xml = String::from("<FileZilla3><Servers><Folder>f<Server>");
        for (t, v) in tags.iter().zip(&values) {
            let v = v.replace('&', "&amp;").replace('<', "&lt;");
            let _ = write!(xml, "<{t} encoding=\"base64\">{v}</{t}>");
        }
        let _ = write!(xml, "<RemoteDir>{dir}</RemoteDir><Bookmark><Name>b</Name><RemoteDir>{dir}</RemoteDir></Bookmark>");
        xml.push_str("</Server></Folder></Servers></FileZilla3>");
        fuzz_filezilla_xml(xml.as_bytes());
        let _ = decode_remote_dir(&dir);
    }
}

// ------------------------------------------------------------------ courier-ftp format

/// Work/web01 (password, bookmark), Work/keyed (vault key + passphrase),
/// top-level ftp (account).
async fn populated(f: &Fixture) -> SiteManager {
    let mut sites = f.sites().await;
    let work = sites.add_folder(None, "Work").await.unwrap();
    let mut web = Site::new("web01", Protocol::Sftp, "web01.example.com");
    web.parent = Some(work);
    web.port = Some(2222);
    web.logon = SiteLogon::Normal {
        user: "deploy".into(),
        password: Some(secret("CANARY-PW-7f3a")),
    };
    web.color = SiteColor::Green;
    web.comments = "comment".into();
    web.default_local_dir = Some(LocalPath::new("/home/me/web"));
    web.default_remote_dir = Some(RemotePath::new("/var/www"));
    web.sync_browsing = true;
    web.timezone_offset_minutes = -60;
    web.try_agent_first = true;
    let web_id = web.id;
    sites.save_site(web).await.unwrap();

    let key_id = ItemId::new();
    f.vault
        .put_view(
            key_id,
            None,
            SshKey {
                label: "laptop".into(),
                algorithm: "ssh-ed25519".into(),
                public_key: "ssh-ed25519 AAAA laptop".into(),
                private_key: secret("CANARY-PRIVATE-KEY-91c2"),
                passphrase: Some(secret("CANARY-KEYPP-0d1e")),
                read_only: false,
            },
        )
        .await
        .unwrap();
    let mut keyed = Site::new("keyed", Protocol::Sftp, "keyed.example.com");
    keyed.parent = Some(work);
    keyed.logon = SiteLogon::KeyFile {
        user: "k".into(),
        key: Some(SiteKey::Vault(key_id)),
        passphrase: Some(secret("CANARY-SITEPP-55aa")),
    };
    sites.save_site(keyed).await.unwrap();

    let mut ftp = Site::new("ftp", Protocol::Ftp, "ftp.example.org");
    ftp.encryption = Some(FtpEncryption::RequireExplicit);
    ftp.logon = SiteLogon::Account {
        user: "acct".into(),
        password: Some(secret("CANARY-ACCTPW-3b3b")),
        account: "CANARY-ACCOUNT-8e8e".into(),
    };
    ftp.transfer_mode = SiteTransferMode::Active;
    ftp.limit_connections = Some(3);
    ftp.charset = Charset::from_label("windows-1252").unwrap();
    sites.save_site(ftp).await.unwrap();

    let mut b = f.bookmarks().await;
    let mut bm = Bookmark::for_site(web_id, "logs", RemotePath::new("/var/log"));
    bm.local_dir = Some(LocalPath::new("/home/me/logs"));
    b.add(bm).await.unwrap();
    sites
}

const CANARIES: [&str; 6] = [
    "CANARY-PW",
    "CANARY-PRIVATE-KEY",
    "CANARY-KEYPP",
    "CANARY-SITEPP",
    "CANARY-ACCTPW",
    "CANARY-ACCOUNT",
];

#[tokio::test]
async fn plain_export_contains_no_secrets() {
    let f = Fixture::new();
    let sites = populated(&f).await;
    let set = export::collect(&sites, ExportScope::All).await.unwrap();
    assert_eq!(set.count(), (1, 3));
    let json = export::to_json(&set, UnixMillis(1)).unwrap();
    for canary in CANARIES {
        assert!(!json.contains(canary), "{canary} leaked:\n{json}");
    }
    assert!(json.contains("\"passwords\": false"));
    // FileZilla export: no secrets either.
    let xml = export::to_filezilla_xml(&set);
    for canary in CANARIES {
        assert!(!xml.contains(canary), "{canary} leaked:\n{xml}");
    }
    assert!(!xml.contains("<Pass"));
}

#[tokio::test]
async fn plain_export_round_trips_without_secrets() {
    let f = Fixture::new();
    let sites = populated(&f).await;
    let set = export::collect(&sites, ExportScope::All).await.unwrap();
    let json = export::to_json(&set, UnixMillis(1)).unwrap();

    let g = Fixture::new();
    let mut other = g.sites().await;
    let tree = import::parse_export(json.as_bytes(), None).unwrap();
    let report = import::apply(&mut other, tree, None, None).await.unwrap();
    assert_eq!((report.folders, report.sites, report.passwords), (1, 3, 0));
    assert_eq!(report.bookmarks, 1);
    let text = render_tree(&other, &g.bookmarks().await);
    insta::assert_snapshot!("courier_plain_round_trip", text);
    // Same ids on a fresh install.
    for s in sites.tree().sites() {
        assert!(other.site(s.id).is_some(), "{}", s.name);
    }
}

#[tokio::test]
async fn encrypted_export_round_trips_with_secrets() {
    let f = Fixture::new();
    let sites = populated(&f).await;
    let set = export::collect(&sites, ExportScope::All).await.unwrap();
    let pass = secret("export passphrase");
    let file =
        export::to_encrypted(&set, &pass, Argon2Cost::TEST, UnixMillis(1), &mut os_rng()).unwrap();
    assert!(import::is_encrypted_export(&file));
    for canary in CANARIES {
        assert!(
            !file.windows(canary.len()).any(|w| w == canary.as_bytes()),
            "{canary} in plaintext"
        );
    }
    assert!(matches!(
        import::parse_export(&file, None),
        Err(ImportError::PassphraseNeeded)
    ));
    assert!(matches!(
        import::parse_export(&file, Some(&secret("wrong"))),
        Err(ImportError::WrongPassphrase)
    ));
    let mut tampered = file.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(matches!(
        import::parse_export(&tampered, Some(&pass)),
        Err(ImportError::WrongPassphrase)
    ));

    // Into another install: everything back, the vault key re-created.
    let g = Fixture::new();
    let mut other = g.sites().await;
    let tree = import::parse_export(&file, Some(&pass)).unwrap();
    let report = import::apply(&mut other, tree, None, None).await.unwrap();
    assert_eq!((report.sites, report.passwords, report.keys), (3, 3, 1));
    for s in sites.tree().sites() {
        let mut got = other.site(s.id).unwrap().clone();
        let mut want = s.clone();
        // The vault key has a new id; compare it separately.
        if let SiteLogon::KeyFile { key, .. } = &mut got.logon {
            let Some(SiteKey::Vault(id)) = key.take() else {
                panic!("vault key not linked");
            };
            let k: SshKey = g.vault.get(id).await.unwrap().unwrap().view().unwrap();
            assert_eq!(k.private_key.expose_secret(), "CANARY-PRIVATE-KEY-91c2");
            assert_eq!(k.passphrase.unwrap().expose_secret(), "CANARY-KEYPP-0d1e");
            if let SiteLogon::KeyFile { key, .. } = &mut want.logon {
                *key = None;
            }
        }
        got.vault = None;
        want.vault = None;
        got.last_connected_at = None;
        want.last_connected_at = None;
        assert_eq!(got, want);
    }

    // Into the same install: the ids collide, so the copies get new ones.
    let mut same = f.sites().await;
    let tree = import::parse_export(&file, Some(&pass)).unwrap();
    let report = import::apply(&mut same, tree, None, None).await.unwrap();
    assert_eq!(report.sites, 3);
    assert_eq!(same.tree().sites().count(), 6);
    assert_eq!(same.tree().roots()[0].name(), "Work");
    assert_eq!(same.tree().roots()[1].name(), "Work (2)");
}

#[tokio::test]
async fn export_scopes() {
    let f = Fixture::new();
    let sites = populated(&f).await;
    let work = sites.tree().roots()[0].id();
    let web = sites.find_site("Work/web01").unwrap().id;
    let set = export::collect(&sites, ExportScope::Folder(work))
        .await
        .unwrap();
    assert_eq!(set.count(), (1, 2));
    let set = export::collect(&sites, ExportScope::Site(web))
        .await
        .unwrap();
    assert_eq!(set.count(), (0, 1));
    assert!(matches!(
        export::collect(&sites, ExportScope::Folder(web)).await,
        Err(SiteError::NotAFolder(_))
    ));
    assert!(matches!(
        export::collect(&sites, ExportScope::Site(ItemId::new())).await,
        Err(SiteError::NotFound(_))
    ));
}

#[tokio::test]
async fn filezilla_export_round_trips() {
    let f = Fixture::new();
    let mut sites = f.sites().await;
    let tree = import::parse_filezilla(FIXTURE).unwrap();
    import::apply(&mut sites, tree, None, None).await.unwrap();
    let set = export::collect(&sites, ExportScope::All).await.unwrap();
    let xml = export::to_filezilla_xml(&set);

    let g = Fixture::new();
    let mut other = g.sites().await;
    let tree = import::parse_filezilla(xml.as_bytes()).unwrap();
    assert!(tree.skipped.is_empty(), "{:?}", tree.skipped);
    import::apply(&mut other, tree, None, None).await.unwrap();

    // Same tree, except passwords: logins that had one now ask for it.
    let strip = |text: String| {
        text.replace("normal deploy pw=true", "ask deploy")
            .replace("normal old pw=true", "ask old")
            .replace("normal me pw=false", "ask me")
            .replace("account builder pw=true acct=BILLING-42", "ask builder")
    };
    let want = strip(render_tree(&sites, &f.bookmarks().await));
    let got = render_tree(&other, &g.bookmarks().await);
    assert_eq!(got, want);
}

#[test]
fn courier_import_rejects_bad_files() {
    for bad in [
        &b""[..],
        b"{}",
        br#"{"format":"other","version":1}"#,
        br#"{"format":"courier-ftp-sites","version":99}"#,
        b"CFTPEXP\0garbage",
    ] {
        assert!(
            import::parse_export(bad, Some(&secret("x"))).is_err(),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    // Unknown values skip the site, not the file.
    let json = br#"{"format":"courier-ftp-sites","version":1,"nodes":[
        {"type":"site","name":"bad","protocol":"gopher","host":"h","logon":{"type":"anonymous"}},
        {"type":"site","name":"good","protocol":"ftp","host":"h","logon":{"type":"anonymous"}}]}"#;
    let tree = import::parse_export(json, None).unwrap();
    assert_eq!(tree.count(), (0, 1));
    assert_eq!(tree.skipped[0].path, "bad");
    assert!(tree.skipped[0].reason.contains("gopher"));
}

#[tokio::test]
async fn store_passwords_off_imports_without_passwords() {
    let f = Fixture::new();
    f.vault.set_store_passwords(false);
    let mut sites = f.sites().await;
    let tree = import::parse_filezilla(FIXTURE).unwrap();
    let report = import::apply(&mut sites, tree, None, None).await.unwrap();
    assert_eq!(report.sites, 8);
    assert_eq!(report.passwords, 0);
    let bodies = format!("{:?}", f.vault.raw_bodies());
    assert!(!bodies.contains("s3cr3t"));
    let n = f.vault.list(ItemKind::Bookmark).await.unwrap().len();
    assert_eq!(n, 2);
}
