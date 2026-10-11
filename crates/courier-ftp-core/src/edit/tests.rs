use std::time::{Duration, SystemTime};

use pretty_assertions::assert_eq;

use super::*;
use crate::model::{EntryKind, Precision};

fn assoc(pattern: &str, command: &str, terminal: bool) -> FileAssociation {
    FileAssociation {
        pattern: pattern.to_owned(),
        command: command.to_owned(),
        terminal,
    }
}

fn settings(associations: Vec<FileAssociation>) -> EditingSettings {
    EditingSettings {
        associations,
        ..EditingSettings::default()
    }
}

fn env(visual: Option<&str>, editor: Option<&str>, pager: Option<&str>) -> EditorEnv {
    EditorEnv {
        visual: visual.map(str::to_owned),
        editor: editor.map(str::to_owned),
        pager: pager.map(str::to_owned),
    }
}

fn argv(launch: &Launch) -> Vec<&str> {
    launch.argv.iter().map(String::as_str).collect()
}

#[test]
fn associations_match_by_glob_first_match_wins() {
    let list = vec![
        assoc("*.php", "code --wait", false),
        assoc("index.*", "vim", true),
        assoc("*", "nano", true),
    ];
    assert_eq!(
        find_association(&list, "a.php").unwrap().command,
        "code --wait"
    );
    // Both the first and second match: the first wins.
    assert_eq!(
        find_association(&list, "index.php").unwrap().command,
        "code --wait"
    );
    assert_eq!(
        find_association(&list, "index.html").unwrap().command,
        "vim"
    );
    assert_eq!(find_association(&list, "README").unwrap().command, "nano");
    // Case-insensitive, `?` is one character.
    let list = vec![assoc("*.TX?", "less", true)];
    assert!(find_association(&list, "notes.txt").is_some());
    assert!(find_association(&list, "notes.text").is_none());
    assert!(find_association(&[], "a").is_none());
}

#[test]
fn an_association_beats_the_environment_for_view_and_edit() {
    let s = settings(vec![assoc("*.log", "'my viewer' -x", false)]);
    let e = env(Some("vim"), None, Some("most"));
    for kind in [OpenKind::View, OpenKind::Edit] {
        let l = resolve_program(&s, "app.log", kind, true, &e).unwrap();
        assert_eq!(argv(&l), ["my viewer", "-x"]);
        assert!(!l.terminal);
    }
}

#[test]
fn edit_defaults_visual_then_editor_then_opener() {
    let s = settings(Vec::new());
    let l = resolve_program(
        &s,
        "a.txt",
        OpenKind::Edit,
        true,
        &env(Some("vim -p"), Some("nano"), None),
    )
    .unwrap();
    assert_eq!(argv(&l), ["vim", "-p"]);
    assert!(l.terminal);
    let l = resolve_program(
        &s,
        "a.txt",
        OpenKind::Edit,
        true,
        &env(None, Some("nano"), None),
    )
    .unwrap();
    assert_eq!(argv(&l), ["nano"]);
    // A windowed editor in $EDITOR runs detached.
    let l = resolve_program(
        &s,
        "a.txt",
        OpenKind::Edit,
        true,
        &env(None, Some("/usr/bin/code --wait"), None),
    )
    .unwrap();
    assert!(!l.terminal);
    let l = resolve_program(&s, "a.txt", OpenKind::Edit, true, &EditorEnv::default()).unwrap();
    assert_eq!(l, platform_opener());
    // The configured command wins over the environment.
    let s = EditingSettings {
        editor: EditorChoice::Command("micro".into()),
        ..EditingSettings::default()
    };
    let l = resolve_program(
        &s,
        "a.txt",
        OpenKind::Edit,
        true,
        &env(Some("vim"), None, None),
    )
    .unwrap();
    assert_eq!(argv(&l), ["micro"]);
    assert!(l.terminal);
}

#[test]
fn view_uses_the_pager_for_text_and_the_opener_otherwise() {
    let s = settings(Vec::new());
    let l = resolve_program(
        &s,
        "a.txt",
        OpenKind::View,
        true,
        &env(Some("vim"), None, Some("most -s")),
    )
    .unwrap();
    assert_eq!(argv(&l), ["most", "-s"]);
    assert!(l.terminal);
    let l = resolve_program(&s, "a.txt", OpenKind::View, true, &EditorEnv::default()).unwrap();
    assert_eq!(argv(&l), [if cfg!(windows) { "more" } else { "less" }]);
    let l = resolve_program(
        &s,
        "a.png",
        OpenKind::View,
        false,
        &env(None, None, Some("less")),
    )
    .unwrap();
    assert_eq!(l, platform_opener());
}

#[test]
fn bad_command_lines_are_errors() {
    let s = settings(vec![assoc("*.c", "vim 'oops", true)]);
    assert!(resolve_program(&s, "a.c", OpenKind::Edit, true, &EditorEnv::default()).is_err());
    let s = settings(Vec::new());
    assert!(
        resolve_program(
            &s,
            "a.c",
            OpenKind::Edit,
            true,
            &env(Some("\"x"), None, None)
        )
        .is_err()
    );
}

#[test]
fn the_file_is_its_own_last_argument() {
    let l = Launch::parse("code --wait", false).unwrap();
    let (program, args) = l.command_for(Path::new("/tmp/a b; rm -rf x.txt"));
    assert_eq!(program, "code");
    assert_eq!(args, ["--wait", "/tmp/a b; rm -rf x.txt"]);
    assert!(Launch::parse("   ", true).is_none());
}

#[test]
fn gui_programs() {
    assert!(is_gui_program("code"));
    assert!(is_gui_program("/usr/bin/xdg-open"));
    assert!(is_gui_program("Notepad++.exe"));
    assert!(!is_gui_program("vim"));
    assert!(!is_gui_program("nano"));
}

#[test]
fn text_sniffing() {
    assert!(looks_like_text(b"hello\nworld\n"));
    assert!(looks_like_text("café".as_bytes()));
    assert!(!looks_like_text(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR"));
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x");
    std::fs::write(&p, b"text").unwrap();
    assert!(file_looks_like_text(&p).unwrap());
}

#[test]
fn copies_are_private_and_cleaned_up() {
    let root = tempfile::tempdir().unwrap();
    let area = EditArea::create(root.path()).unwrap();
    assert!(area.dir().starts_with(root.path().join(EDIT_DIR)));
    let a = area.new_file("index.php").unwrap();
    let b = area.new_file("index.php").unwrap();
    assert_ne!(a, b, "same name, different directories");
    assert_eq!(a.file_name().unwrap(), "index.php");
    assert_eq!(std::fs::read(&a).unwrap(), b"");
    // A hostile name stays inside its directory.
    let c = area.new_file("../../etc/passwd").unwrap();
    assert_eq!(c.parent().unwrap().parent().unwrap(), area.dir());
    let d = area.new_file("..").unwrap();
    assert_eq!(d.parent().unwrap().parent().unwrap(), area.dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&a), 0o600);
        assert_eq!(mode(a.parent().unwrap()), 0o700);
        assert_eq!(mode(area.dir()), 0o700);
        assert_eq!(mode(&root.path().join(EDIT_DIR)), 0o700);
    }

    area.remove(&a).unwrap();
    assert!(!a.exists() && !a.parent().unwrap().exists());
    area.remove(&a).unwrap();
    assert!(area.remove(&root.path().join("elsewhere/x")).is_err());

    // Cleanup keeps what is asked for, then the run directory goes too.
    assert_eq!(area.cleanup(std::slice::from_ref(&b)).unwrap(), 1);
    assert!(b.exists() && !c.exists() && !d.exists());
    assert_eq!(area.cleanup(&[]).unwrap(), 0);
    assert!(!area.dir().exists());
    assert_eq!(area.cleanup(&[]).unwrap(), 0);
}

#[test]
fn stale_runs_are_swept() {
    let root = tempfile::tempdir().unwrap();
    let old = EditArea::create(root.path()).unwrap();
    old.new_file("a").unwrap();
    let current = EditArea::create(root.path()).unwrap();
    let now = SystemTime::now();
    assert_eq!(
        EditArea::sweep_stale(root.path(), Duration::from_secs(3600), now).unwrap(),
        0
    );
    let later = now + Duration::from_secs(7200);
    assert_eq!(
        EditArea::sweep_stale(root.path(), Duration::from_secs(3600), later).unwrap(),
        2
    );
    assert!(!old.dir().exists() && !current.dir().exists());
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(
        EditArea::sweep_stale(empty.path(), Duration::ZERO, now).unwrap(),
        0
    );
}

#[test]
fn change_detection() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("f.txt");
    std::fs::write(&p, b"one").unwrap();
    let mut t = ChangeTracker::new(&p).unwrap();
    assert_eq!(t.poll(&p), Poll::Unchanged);
    assert!(!t.is_dirty());

    // Saved again with the same content and a new time: not a change.
    let touch = |secs: u64| {
        let f = std::fs::File::options().write(true).open(&p).unwrap();
        f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
            .unwrap();
    };
    touch(1_000_000);
    assert_eq!(t.poll(&p), Poll::Unchanged);

    // New content of the same length, with a new time.
    std::fs::write(&p, b"two").unwrap();
    touch(2_000_000);
    assert_eq!(t.poll(&p), Poll::Changed);
    assert!(t.is_dirty());
    assert_eq!(t.poll(&p), Poll::Unchanged, "reported once");
    assert!(t.is_dirty(), "still differs from the server");

    // Uploaded: clean until the next change.
    t.synced(t.seen());
    assert!(!t.is_dirty());
    std::fs::write(&p, b"three").unwrap();
    assert_eq!(t.poll(&p), Poll::Changed);

    // Changed back to what the server has: a change, but not dirty.
    std::fs::write(&p, b"two").unwrap();
    touch(3_000_000);
    assert_eq!(t.poll(&p), Poll::Changed);
    assert!(!t.is_dirty());

    std::fs::remove_file(&p).unwrap();
    assert_eq!(t.poll(&p), Poll::Missing);
}

#[test]
fn remote_changes_compare_known_values_only() {
    let at = |s: i64| Timestamp {
        time: time::OffsetDateTime::from_unix_timestamp(s).unwrap(),
        precision: Precision::Second,
    };
    let mut entry = Entry::new("a", EntryKind::File);
    entry.size = Some(10);
    entry.modified = Some(at(100));
    let base = RemoteStamp::of(&entry);
    assert!(!base.changed_since(&base));
    assert!(base.changed_since(&RemoteStamp {
        size: Some(11),
        ..base
    }));
    assert!(base.changed_since(&RemoteStamp {
        modified: Some(at(101)),
        ..base
    }));
    // Unknown on either side: no conflict.
    assert!(!base.changed_since(&RemoteStamp::default()));
    assert!(!RemoteStamp::default().changed_since(&base));
}
