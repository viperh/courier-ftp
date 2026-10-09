#![allow(clippy::unwrap_used, clippy::expect_used)]

use courier_ftp_core::model::{EntryKind, Precision};
use time::macros::datetime;

use super::*;

fn opts(hint: Option<ListFormat>, tz: i32) -> ParseOptions {
    ParseOptions {
        ctx: ListingContext::new(datetime!(2024-06-15 12:00 UTC), tz),
        decoder: TextDecoder::Utf8,
        hint,
    }
}

fn list(text: &str) -> ParsedListing {
    parse_list(text.as_bytes(), &opts(None, 0))
}

fn mlsd(text: &str) -> ParsedListing {
    parse_mlsd(text.as_bytes(), &opts(None, 0))
}

fn names(p: &ParsedListing) -> Vec<&str> {
    p.entries.iter().map(|e| e.name.as_str()).collect()
}

#[test]
fn mlsd_name_with_semicolon_and_spaces_preserved() {
    let p = mlsd(
        "type=file;size=1048576;modify=20240131120000.123;perm=adfrw;unix.ownername=alice; a; tricky name.txt\r\n\
         type=file;size=1;  two leading and trailing  \r\n\
         type=dir; with;semi;colons; \n",
    );
    assert_eq!(
        names(&p),
        [
            "a; tricky name.txt",
            " two leading and trailing  ",
            "with;semi;colons; "
        ]
    );
    assert_eq!(p.entries[0].size, Some(1_048_576));
    assert_eq!(p.entries[0].owner.as_deref(), Some("alice"));
    assert_eq!(p.format, Some(ListFormat::Mlsd));
    assert!(p.skipped.is_empty());
    // A line starting with SP has no facts.
    let p = mlsd("  spaced\n");
    assert_eq!(names(&p), [" spaced"]);
    assert_eq!(p.entries[0].kind, EntryKind::File);
}

#[test]
fn mlsd_cdir_pdir_skipped() {
    let p = mlsd(
        "type=cdir;modify=20240131120000;perm=flcdmpe; .\n\
         type=pdir;modify=20240131120000;perm=flcdmpe; ..\n\
         type=cdir; /home/alice\n\
         type=dir;modify=20240131120000;perm=flcdmpe;unix.mode=0755;unix.owner=1000;unix.group=1000; public_html\n",
    );
    assert_eq!(names(&p), ["public_html"]);
    assert!(p.skipped.is_empty());
    let e = &p.entries[0];
    assert_eq!(e.kind, EntryKind::Dir);
    assert_eq!(e.owner.as_deref(), Some("1000"));
    assert_eq!(e.group.as_deref(), Some("1000"));
}

#[test]
fn mlsd_unix_mode_preferred_over_perm() {
    let p = mlsd(
        "type=file;perm=adfrw;unix.mode=0644; a\n\
         type=file;perm=adfrw; b\n\
         type=file;UNIX.MODE=4755; c\n\
         type=file;unix.mode=bogus;perm=r; d\n",
    );
    let perms: Vec<_> = p
        .entries
        .iter()
        .map(|e| e.permissions.clone().unwrap())
        .collect();
    assert_eq!(perms[0].mode, Some(0o644));
    assert_eq!(perms[0].raw, None);
    assert_eq!(perms[1].raw.as_deref(), Some("adfrw"));
    assert_eq!(perms[1].mode, None);
    assert_eq!(perms[2].mode, Some(0o4755));
    assert_eq!(perms[3].raw.as_deref(), Some("r"));
}

#[test]
fn mlsd_fractional_modify_is_millis() {
    let p = mlsd(
        "type=file;modify=20240131120000.123; a\n\
         type=file;modify=20240131120000.5; b\n\
         type=file;modify=20240131120000.123456; c\n\
         type=file;modify=20240131120000; d\n\
         type=file;modify=2024013112000; e\n\
         type=file;modify=20240231120000; f\n",
    );
    let m: Vec<_> = p.entries.iter().map(|e| e.modified).collect();
    let a = m[0].unwrap();
    assert_eq!(a.precision, Precision::Millis);
    assert_eq!(a.time, datetime!(2024-01-31 12:00:00.123 UTC));
    assert_eq!(m[1].unwrap().time, datetime!(2024-01-31 12:00:00.5 UTC));
    assert_eq!(m[2].unwrap().time, datetime!(2024-01-31 12:00:00.123 UTC));
    assert_eq!(m[3].unwrap().precision, Precision::Second);
    assert_eq!(m[3].unwrap().time, datetime!(2024-01-31 12:00 UTC));
    assert_eq!(m[4], None);
    assert_eq!(m[5], None);
    // MLSD times are UTC: no site offset.
    let p = parse_mlsd(b"type=file;modify=20240131120000; a\n", &opts(None, 840));
    assert_eq!(
        p.entries[0].modified.unwrap().time,
        datetime!(2024-01-31 12:00 UTC)
    );
}

#[test]
fn mlsd_slink_target() {
    let p = mlsd(
        "type=OS.unix=slink:/var/www;modify=20240131120000;unix.mode=0777; www\n\
         type=OS.unix=symlink; link2\n\
         type=OS.unix=chrdev; null\n\
         type=OS.z/OS=whatever; other\n",
    );
    assert_eq!(
        p.entries[0].kind,
        EntryKind::Symlink {
            target: Some("/var/www".into()),
            target_kind: None
        }
    );
    assert_eq!(
        p.entries[1].kind,
        EntryKind::Symlink {
            target: None,
            target_kind: None
        }
    );
    assert_eq!(p.entries[2].kind, EntryKind::Other);
    assert_eq!(p.entries[3].kind, EntryKind::Other);
}

#[test]
fn mlst_line_returns_full_path() {
    let (e, path) =
        parse_mlst_line("type=file;size=12;modify=20240131120000; /home/alice/notes.txt").unwrap();
    assert_eq!(path, "/home/alice/notes.txt");
    assert_eq!(e.name, "notes.txt");
    assert_eq!(e.size, Some(12));
    let (e, path) = parse_mlst_line("type=cdir;perm=el; /home/alice/").unwrap();
    assert_eq!((e.name.as_str(), path.as_str()), ("alice", "/home/alice/"));
    assert_eq!(e.kind, EntryKind::Dir);
    let (e, _) = parse_mlst_line("type=cdir; /").unwrap();
    assert_eq!(e.name, "/");
    assert!(parse_mlst_line("garbage").is_none());
}

#[test]
fn dos_12h_24h_and_year_variants() {
    let p = list(
        "01-31-24  12:00PM       <DIR>          wwwroot\r\n\
         01-31-2024  09:05AM              1,234 report.txt\r\n\
         2024-01-31  23:59                  42 iso-date.txt\r\n\
         31.01.2024  12:00    <DIR>          Ordner\r\n\
         01-31-99  12:30AM                 7 old.txt\r\n\
         02-01-24  01:15 PM                 1.024 spaced-ampm.txt\r\n",
    );
    assert!(p.skipped.is_empty(), "{:?}", p.skipped);
    assert_eq!(p.format, Some(ListFormat::Dos));
    let t: Vec<_> = p.entries.iter().map(|e| e.modified.unwrap().time).collect();
    assert_eq!(t[0], datetime!(2024-01-31 12:00 UTC));
    assert_eq!(t[1], datetime!(2024-01-31 09:05 UTC));
    assert_eq!(t[2], datetime!(2024-01-31 23:59 UTC));
    assert_eq!(t[3], datetime!(2024-01-31 12:00 UTC));
    assert_eq!(t[4], datetime!(1999-01-31 00:30 UTC));
    assert_eq!(t[5], datetime!(2024-02-01 13:15 UTC));
    assert_eq!(p.entries[0].kind, EntryKind::Dir);
    assert_eq!(p.entries[1].size, Some(1234));
    assert_eq!(p.entries[5].size, Some(1024));
    assert_eq!(p.entries[0].modified.unwrap().precision, Precision::Minute);
    // Site offset applied.
    let p = parse_list(
        b"01-31-24  12:00PM       <DIR>          wwwroot\n",
        &opts(None, 60),
    );
    assert_eq!(
        p.entries[0].modified.unwrap().time,
        datetime!(2024-01-31 11:00 UTC)
    );
}

#[test]
fn dos_junction_is_symlink() {
    let p = list(
        "01-31-24  12:00PM    <JUNCTION>     Documents [C:\\Users\\alice\\Documents]\n\
         01-31-24  12:00PM    <SYMLINKD>     Data [D:\\data]\n\
         01-31-24  12:00PM    <SYMLINK>      plain\n",
    );
    assert_eq!(names(&p), ["Documents", "Data", "plain"]);
    assert_eq!(
        p.entries[0].kind,
        EntryKind::Symlink {
            target: Some("C:\\Users\\alice\\Documents".into()),
            target_kind: None
        }
    );
    assert_eq!(
        p.entries[2].kind,
        EntryKind::Symlink {
            target: None,
            target_kind: None
        }
    );
}

#[test]
fn eplf_dir_and_file() {
    let p = list(
        "+i8388621.48594,m825718503,r,s280,\tdjb.html\n\
         +i8388621.50690,m824255907,/,\t514\n\
         +m1706702400,up644,s1024,\tnotes.txt\n",
    );
    assert!(p.skipped.is_empty());
    assert_eq!(p.format, Some(ListFormat::Eplf));
    assert_eq!(names(&p), ["djb.html", "514", "notes.txt"]);
    assert_eq!(p.entries[0].kind, EntryKind::File);
    assert_eq!(p.entries[0].size, Some(280));
    assert_eq!(p.entries[1].kind, EntryKind::Dir);
    assert_eq!(p.entries[2].permissions.as_ref().unwrap().mode, Some(0o644));
}

#[test]
fn eplf_time_is_utc_without_offset() {
    for tz in [-720, 0, 840] {
        let p = parse_list(b"+m1706702400,r,s1,\tnotes.txt\n", &opts(None, tz));
        let m = p.entries[0].modified.unwrap();
        assert_eq!(m.time, datetime!(2024-01-31 12:00 UTC));
        assert_eq!(m.precision, Precision::Second);
    }
}

#[test]
fn vms_wrapped_entry_joined() {
    let p = list(
        "Directory DISK$USER:[ALICE]\n\
         \n\
         A_VERY_LONG_FILE_NAME_THAT_WRAPS.TXT;12\n\
         \x20                        10/12       01-FEB-2024 09:15        [STAFF,ALICE]   (RWED,RWED,R,)\n\
         \n\
         Total of 1 file, 10/12 blocks.\n",
    );
    assert!(p.skipped.is_empty(), "{:?}", p.skipped);
    assert_eq!(names(&p), ["A_VERY_LONG_FILE_NAME_THAT_WRAPS.TXT"]);
    let e = &p.entries[0];
    assert_eq!(e.size, Some(10 * 512));
    assert_eq!(e.owner.as_deref(), Some("ALICE"));
    assert_eq!(e.group.as_deref(), Some("STAFF"));
    assert_eq!(
        e.permissions.as_ref().unwrap().raw.as_deref(),
        Some("(RWED,RWED,R,)")
    );
    let m = e.modified.unwrap();
    assert_eq!(m.time, datetime!(2024-02-01 09:15 UTC));
    assert_eq!(m.precision, Precision::Minute);
}

#[test]
fn vms_keeps_highest_version_only() {
    let p = list(
        "LOGIN.COM;3               2/4        31-JAN-2024 12:00:05.32  [STAFF,ALICE]   (RWED,RWED,RE,)\n\
         LOGIN.COM;2               1/4        30-JAN-2024 12:00:05.32  [STAFF,ALICE]   (RWED,RWED,RE,)\n\
         %RMS-E-PRV, insufficient privilege or file protection violation\n",
    );
    assert_eq!(names(&p), ["LOGIN.COM"]);
    assert_eq!(p.entries[0].size, Some(1024));
    assert_eq!(p.entries[0].modified.unwrap().precision, Precision::Second);
    // The error message is logged, not an entry.
    assert_eq!(p.skipped.len(), 1);
    assert!(matches!(p.skipped[0].reason, SkipReason::Unrecognised));
}

#[test]
fn vms_dir_suffix_removed() {
    let p = list(
        "WWW.DIR;1                 1/3        15-MAR-2023 08:00:00.00  [ALICE]         (RWE,RWE,RE,RE)\n",
    );
    assert_eq!(names(&p), ["WWW"]);
    assert_eq!(p.entries[0].kind, EntryKind::Dir);
    assert_eq!(p.entries[0].size, None);
    assert_eq!(p.entries[0].owner.as_deref(), Some("ALICE"));
    assert_eq!(p.entries[0].group, None);
}

#[test]
fn mvs_dataset_dsorg_po_is_dir() {
    let p = parse_list(
        b"Volume Unit    Referred Ext Used Recfm Lrecl BlkSz Dsorg Dsname\n\
          WYOSPT 3390   2024/01/31  1   15  FB      80  6160  PO  ALICE.SOURCE\n\
          WYOSPT 3390   2024/01/30  1    2  FB      80 27920  PS  ALICE.DATA.TXT\n\
          Migrated                                                ALICE.OLD.DATA\n\
          Pseudo Directory                                        ALICE.PROJECTS\n",
        &opts(None, 840),
    );
    assert!(p.skipped.is_empty(), "{:?}", p.skipped);
    assert_eq!(
        names(&p),
        [
            "ALICE.SOURCE",
            "ALICE.DATA.TXT",
            "ALICE.OLD.DATA",
            "ALICE.PROJECTS"
        ]
    );
    let kinds: Vec<_> = p.entries.iter().map(|e| e.kind.clone()).collect();
    assert_eq!(
        kinds,
        [
            EntryKind::Dir,
            EntryKind::File,
            EntryKind::File,
            EntryKind::Dir
        ]
    );
    // Day precision: the offset is not applied.
    let m = p.entries[0].modified.unwrap();
    assert_eq!(m.time, datetime!(2024-01-31 0:00 UTC));
    assert_eq!(m.precision, Precision::Day);
    assert_eq!(p.entries[0].size, None);
}

#[test]
fn mvs_member_without_stats() {
    let p = list(
        " Name     VV.MM   Created       Changed      Size  Init   Mod   Id\n\
         MEMBER1   01.03 2024/01/30 2024/01/31 12:00    15    10     0 ALICE\n\
         MEMBER2\n",
    );
    assert!(p.skipped.is_empty(), "{:?}", p.skipped);
    assert_eq!(names(&p), ["MEMBER1", "MEMBER2"]);
    let m = p.entries[0].modified.unwrap();
    assert_eq!(m.time, datetime!(2024-01-31 12:00 UTC));
    assert_eq!(m.precision, Precision::Minute);
    assert_eq!(p.entries[0].size, None);
    assert_eq!(p.entries[1].modified, None);
    assert_eq!(p.entries[1].kind, EntryKind::File);
    // A bare name without a member header is not an entry.
    let p = list("MEMBER2\n");
    assert!(p.entries.is_empty());
    assert_eq!(p.skipped_count, 1);
}

#[test]
fn ibmi_types_and_continuation_rows() {
    let p = list(
        "ALICE          36864 01/31/24 12:00:05 *DIR       projects/\n\
         ALICE         102400 01/31/24 12:00:05 *STMF      report.csv\n\
         QSYS           12288 01/30/24 08:00:00 *LIB       MYLIB.LIB\n\
         QSYS           77824 01/30/24 08:00:00 *FILE      MYLIB.LIB/MYFILE.FILE\n\
         \x20                                      *MEM       MYLIB.LIB/MYFILE.FILE/MBR1.MBR\n\
         BOB             4096 31.01.24 07:00:00 *FLR       folder\n",
    );
    assert!(p.skipped.is_empty(), "{:?}", p.skipped);
    assert_eq!(p.format, Some(ListFormat::IbmI));
    assert_eq!(
        names(&p),
        [
            "projects",
            "report.csv",
            "MYLIB.LIB",
            "MYFILE.FILE",
            "MBR1.MBR",
            "folder"
        ]
    );
    let kinds: Vec<_> = p.entries.iter().map(|e| e.kind.clone()).collect();
    assert_eq!(
        kinds,
        [
            EntryKind::Dir,
            EntryKind::File,
            EntryKind::Dir,
            EntryKind::Dir,
            EntryKind::File,
            EntryKind::Dir
        ]
    );
    let r = &p.entries[1];
    assert_eq!(r.size, Some(102_400));
    assert_eq!(r.owner.as_deref(), Some("ALICE"));
    let m = r.modified.unwrap();
    assert_eq!(m.time, datetime!(2024-01-31 12:00:05 UTC));
    assert_eq!(m.precision, Precision::Second);
    assert_eq!(p.entries[4].modified, None);
    assert_eq!(
        p.entries[5].modified.unwrap().time,
        datetime!(2024-01-31 07:00 UTC)
    );
}

#[test]
fn hostile_names_dropped() {
    let p = mlsd(
        "type=dir; ..\n\
         type=dir; .\n\
         type=file; a/b\n\
         type=file; nul\0name\n\
         type=file; \n\
         type=file; ok\n",
    );
    assert_eq!(names(&p), ["ok"]);
    let hostile = p
        .skipped
        .iter()
        .filter(|s| matches!(s.reason, SkipReason::HostileName))
        .count();
    assert_eq!(hostile, 3);
    let p = list(
        "drwxr-xr-x 2 a b 4096 Jan 31 12:00 .\n\
         drwxr-xr-x 2 a b 4096 Jan 31 12:00 ..\n\
         -rw-r--r-- 1 a b 1 Jan 31 12:00 x/y\n\
         -rw-r--r-- 1 a b 1 Jan 31 12:00 .hidden\n",
    );
    assert_eq!(names(&p), [".hidden"]);
    assert!(p.entries[0].hidden);
}

#[test]
fn limits_and_skipped_lines() {
    let mut data = vec![b'x'; MAX_LINE_LEN + 1];
    data.extend_from_slice(b"\n-rw-r--r-- 1 a b 1 Jan 31 12:00 ok\nnot a listing line\n");
    let p = parse_list(&data, &opts(None, 0));
    assert_eq!(names(&p), ["ok"]);
    assert_eq!(p.skipped_count, 2);
    assert!(matches!(p.skipped[0].reason, SkipReason::LineTooLong));
    assert_eq!(p.skipped[1].line_no, 3);
    assert!(matches!(p.skipped[1].reason, SkipReason::Unrecognised));
    // Size overflow is a bad number.
    let p = list("-rw-r--r-- 1 a b 99999999999999999999999 Jan 31 12:00 big\n");
    assert!(p.entries.is_empty());
    assert!(matches!(p.skipped[0].reason, SkipReason::BadNumber));
    let p = mlsd("type=file;size=99999999999999999999999; big\n");
    assert!(matches!(p.skipped[0].reason, SkipReason::BadNumber));
}

#[test]
fn hint_and_last_format_preferred() {
    // A line that is valid in two formats: an MVS bare member name after a header vs
    // nothing else; and the hint order is respected.
    let p = parse_list(
        b"+m1706702400,r,s1,\tnotes.txt\n",
        &opts(Some(ListFormat::Eplf), 0),
    );
    assert_eq!(p.format, Some(ListFormat::Eplf));
    let p = list(
        "drwxr-xr-x 2 a b 4096 Jan 31 12:00 unix\n\
         01-31-24  12:00PM       <DIR>          dos\n",
    );
    assert_eq!(names(&p), ["unix", "dos"]);
    assert_eq!(p.format, Some(ListFormat::Dos));
}

#[test]
fn raw_and_fallback_encoding() {
    let o = ParseOptions {
        decoder: TextDecoder::Utf8OrFallback(encoding_rs::WINDOWS_1252),
        ..opts(None, 0)
    };
    let p = parse_list(b"-rw-r--r-- 1 a b 1 Jan 31 12:00 gr\xfc\xdfe.txt\r\n", &o);
    assert_eq!(names(&p), ["grüße.txt"]);
    assert!(p.used_fallback_encoding);
    assert_eq!(p.raw, "-rw-r--r-- 1 a b 1 Jan 31 12:00 grüße.txt\n");
}

#[test]
fn fuzz_listing_smoke() {
    fuzz_listing(b"");
    for sel in 0..=255u8 {
        let mut d = vec![sel];
        d.extend_from_slice(b"type=file; a\n-rw-r--r-- 1 a b 1 Jan 31 12:00 x\nLOGIN.COM;3\n");
        fuzz_listing(&d);
    }
}
