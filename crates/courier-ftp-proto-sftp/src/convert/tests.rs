#![allow(clippy::unwrap_used, clippy::expect_used)]

use courier_ftp_core::{
    Error,
    model::{EntryKind, Permissions, Precision, RemotePath},
};
use pretty_assertions::assert_eq;
use russh_sftp::{
    client::error::Error as SftpError,
    protocol::{FileAttributes, Status, StatusCode},
};

use super::*;

fn attrs(mode: Option<u32>) -> FileAttributes {
    FileAttributes {
        permissions: mode,
        ..FileAttributes::default()
    }
}

#[test]
fn kind_from_mode_all_types_and_longname_fallback() {
    assert_eq!(kind_from_mode(Some(0o040_755), ""), EntryKind::Dir);
    assert_eq!(kind_from_mode(Some(0o100_644), ""), EntryKind::File);
    assert!(matches!(
        kind_from_mode(Some(0o120_777), ""),
        EntryKind::Symlink {
            target: None,
            target_kind: None
        }
    ));
    for other in [0o010_000, 0o020_000, 0o060_000, 0o140_000] {
        assert_eq!(kind_from_mode(Some(other | 0o644), ""), EntryKind::Other);
    }
    // No type bits: the longname decides.
    assert_eq!(
        kind_from_mode(Some(0o755), "drwxr-xr-x 2 a b 0 x"),
        EntryKind::Dir
    );
    assert_eq!(kind_from_mode(None, "drwxr-xr-x 2 a b 0 x"), EntryKind::Dir);
    assert!(matches!(
        kind_from_mode(None, "lrwxrwxrwx 1 a b 3 x"),
        EntryKind::Symlink { .. }
    ));
    assert_eq!(
        kind_from_mode(None, "-rw-r--r-- 1 a b 3 x"),
        EntryKind::File
    );
    assert_eq!(kind_from_mode(None, ""), EntryKind::File);
    assert_eq!(kind_from_mode(None, "?weird"), EntryKind::File);
}

#[test]
fn entry_from_name_fields() {
    let a = FileAttributes {
        size: Some(1234),
        permissions: Some(0o104_755),
        mtime: Some(1_577_934_245),
        atime: Some(1),
        ..FileAttributes::default()
    };
    let e = entry_from_name("run.sh", "", &a).unwrap();
    assert_eq!(e.name, "run.sh");
    assert_eq!(e.kind, EntryKind::File);
    assert_eq!(e.size, Some(1234));
    let m = e.modified.unwrap();
    assert_eq!(m.precision, Precision::Second);
    assert_eq!(m.time.unix_timestamp(), 1_577_934_245);
    assert_eq!(e.permissions, Some(Permissions::from_mode(0o4755)));
    assert!(!e.hidden);

    let d = FileAttributes {
        size: Some(4096),
        permissions: Some(0o040_700),
        ..FileAttributes::default()
    };
    let e = entry_from_name(".config", "", &d).unwrap();
    assert_eq!(e.kind, EntryKind::Dir);
    assert_eq!(e.size, None, "directories have no size");
    assert!(e.hidden);
    assert_eq!(e.modified, None);

    let l = FileAttributes {
        size: Some(7),
        permissions: Some(0o120_777),
        ..FileAttributes::default()
    };
    let e = entry_from_name("link", "", &l).unwrap();
    assert!(matches!(e.kind, EntryKind::Symlink { .. }));
    assert_eq!(e.size, Some(7));
}

#[test]
fn owner_group_from_longname_else_uid_gid() {
    let a = FileAttributes {
        size: Some(10),
        uid: Some(1000),
        gid: Some(100),
        permissions: Some(0o100_644),
        mtime: Some(1_600_000_000),
        ..FileAttributes::default()
    };
    let long = "-rw-r--r--    1 alice    staff          10 Sep 13  2020 notes.txt";
    let e = entry_from_name("notes.txt", long, &a).unwrap();
    assert_eq!(e.owner.as_deref(), Some("alice"));
    assert_eq!(e.group.as_deref(), Some("staff"));

    // No (or unparsable) longname: uid/gid as decimals.
    let e = entry_from_name("notes.txt", "", &a).unwrap();
    assert_eq!(e.owner.as_deref(), Some("1000"));
    assert_eq!(e.group.as_deref(), Some("100"));
    let e = entry_from_name("notes.txt", "not an ls line", &a).unwrap();
    assert_eq!(e.owner.as_deref(), Some("1000"));

    // Neither: None.
    let e = entry_from_name("notes.txt", "", &attrs(Some(0o100_644))).unwrap();
    assert_eq!((e.owner, e.group), (None, None));

    // Permissions from the longname when the attributes have none.
    let e = entry_from_name("notes.txt", long, &FileAttributes::default()).unwrap();
    assert_eq!(e.permissions.and_then(|p| p.mode), Some(0o644));
}

#[test]
fn invalid_names_skipped() {
    let a = attrs(Some(0o100_644));
    for bad in [
        "",
        ".",
        "..",
        "a/b",
        "/",
        "nul\0byte",
        &"x".repeat(MAX_NAME_BYTES + 1),
        &"y".repeat(5000),
    ] {
        assert!(entry_from_name(bad, "", &a).is_none(), "{bad:?}");
    }
    assert!(entry_from_name(&"z".repeat(MAX_NAME_BYTES), "", &a).is_some());
    // Control characters are kept verbatim (sanitized at render time).
    let esc = "evil\u{1b}[31mred";
    assert_eq!(entry_from_name(esc, "", &a).unwrap().name, esc);
    assert_eq!(entry_from_name("...", "", &a).unwrap().name, "...");
}

fn status(code: StatusCode, msg: &str) -> SftpError {
    SftpError::Status(Status {
        id: 1,
        status_code: code,
        error_message: msg.to_owned(),
        language_tag: "en".to_owned(),
    })
}

#[test]
fn map_status_table() {
    let p = RemotePath::parse("/srv/x").unwrap();
    let m = |e: SftpError| map_status(e, SftpOp::Stat, &p);

    assert!(matches!(m(status(StatusCode::NoSuchFile, "nope")), Error::NotFound(x) if x == p));
    assert!(matches!(
        m(status(StatusCode::PermissionDenied, "")),
        Error::PermissionDenied(x) if x == "/srv/x"
    ));
    assert!(matches!(
        m(status(StatusCode::Failure, "Directory not empty")),
        Error::Protocol { code: Some(4), message } if message == "Directory not empty"
    ));
    assert!(matches!(
        m(status(StatusCode::Failure, "")),
        Error::Protocol { code: Some(4), message } if message == "Failure"
    ));
    // Server text is sanitized and capped.
    let long = format!("\u{1b}[31m{}", "a".repeat(2000));
    match m(status(StatusCode::Failure, &long)) {
        Error::Protocol { message, .. } => {
            assert!(!message.contains('\u{1b}'));
            assert!(message.chars().count() <= MAX_SERVER_MESSAGE + 1);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        m(status(StatusCode::BadMessage, "bad")),
        Error::Protocol { code: Some(5), .. }
    ));
    let lost = m(status(StatusCode::NoConnection, "x"));
    assert!(matches!(lost, Error::Connection(_)) && lost.is_transient());
    assert!(matches!(
        m(status(StatusCode::ConnectionLost, "x")),
        Error::Connection(_)
    ));
    assert!(matches!(
        m(status(StatusCode::OpUnsupported, "x")),
        Error::Unsupported(msg) if msg == "The server does not support this operation"
    ));
    assert!(matches!(
        m(status(StatusCode::Eof, "")),
        Error::Protocol { code: Some(1), .. }
    ));
    let t = m(SftpError::Timeout);
    assert!(matches!(t, Error::Timeout) && t.is_transient());
    assert!(matches!(
        m(SftpError::IO("reset".into())),
        Error::Connection(_)
    ));
    assert!(matches!(
        m(SftpError::UnexpectedBehavior("session closed".into())),
        Error::Connection(_)
    ));
    assert!(matches!(
        m(SftpError::Limited("read limit reached".into())),
        Error::Protocol { code: None, .. }
    ));
    assert!(matches!(
        m(SftpError::UnexpectedPacket),
        Error::Protocol { code: None, .. }
    ));
    assert!(matches!(
        m(SftpError::UnexpectedBehavior("odd".into())),
        Error::Protocol { code: None, .. }
    ));
}

#[test]
fn io_error_roundtrip_keeps_the_core_error() {
    let io = io_error(Error::Connection("gone".into()));
    assert_eq!(io.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(matches!(core_error(&io), Some(Error::Connection(m)) if m == "gone"));
    assert!(matches!(from_io(io), Error::Connection(_)));
    let plain = std::io::Error::other("x");
    assert!(matches!(from_io(plain), Error::Io(_)));
    let t = io_error(Error::Timeout);
    assert_eq!(t.kind(), std::io::ErrorKind::TimedOut);
}
