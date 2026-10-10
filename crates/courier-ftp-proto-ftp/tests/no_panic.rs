//! The listing parsers never panic, whatever the server sends (T13, T91 §7).
//!
//! The same bodies run as the `listing` cargo-fuzz target in `fuzz/`.

use courier_ftp_core::model::Charset;
use courier_ftp_proto_ftp::listing::{ListCommand, ListingContext, parse_listing};
use proptest::prelude::*;
use time::{Duration, macros::datetime};

fn parse_all(bytes: &[u8], offset_minutes: i16) {
    let ctx = ListingContext::at(
        datetime!(2024-01-01 00:30 UTC),
        Duration::minutes(i64::from(offset_minutes)),
    );
    for command in [ListCommand::Mlsd, ListCommand::List] {
        for charset in [Charset::Auto, Charset::Utf8] {
            let _ = parse_listing(bytes, charset, command, &ctx);
        }
    }
}

/// Fragments of real listing lines, glued together at random.
fn listing_like() -> impl Strategy<Value = String> {
    let pieces = prop::sample::select(vec![
        "-rw-r--r--",
        "drwxr-xr-x+",
        "lrwxrwxrwx",
        "crw-rw-rw-",
        " ",
        "  ",
        "\t",
        "1",
        "0",
        "4,",
        "99999999999999999999999",
        "alice",
        "Jan",
        "Feb",
        "29",
        "31",
        "12:00",
        "23:59:60",
        "2024",
        "9999",
        "-",
        "->",
        " -> ",
        "01-31-24",
        "12:00PM",
        "<DIR>",
        "<JUNCTION>",
        "[x]",
        "type=file;",
        "type=cdir;",
        "modify=20240131120000.5;",
        "size=1;",
        "UNIX.mode=0777;",
        "OS.unix=slink:",
        "+i1,m825718503,r,s280,",
        "/",
        ",",
        ";",
        "=",
        "NAME.TXT;1",
        "5/6",
        "31-JAN-2024",
        "[STAFF,ALICE]",
        "(RWED,RWED,RE,)",
        "%RMS-E",
        "Directory ",
        "total 5",
        "2024/01/31",
        "PO",
        "PS",
        "01.03",
        "*DIR",
        "*MEM",
        "QSYS",
        "d",
        "[RWCEAFMS]",
        "月",
        "日",
        "é",
        "\r",
        "\n",
        "\r\n",
        "+0100",
        "2024-02-30",
        ".",
        "..",
    ]);
    prop::collection::vec(pieces, 0..40).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn random_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512), offset in -1440i16..=1440) {
        parse_all(&bytes, offset);
    }

    #[test]
    fn listing_like_text_never_panics(text in listing_like(), offset in -1440i16..=1440) {
        parse_all(text.as_bytes(), offset);
    }
}

#[test]
fn extreme_offsets_and_dates_never_panic() {
    for line in [
        "-rw-r--r-- 1 u g 1 Dec 31 9999 f",
        "-rw-r--r-- 1 u g 1 Jan 1 0000 f",
        "-rw-r--r-- 1 u g 1 9999-12-31 23:59:59 -2359 f",
        "type=file;modify=99991231235959; f",
        "+m99999999999999999,\tf",
        "+m-99999999999,\tf",
        "BIG.TXT;1 99999999999/1 31-DEC-9999 23:59:59",
        "12-31-9999  11:59PM  18446744073709551615 f",
        "12-31-9999  11:59PM  18446744073709551616 f",
    ] {
        for minutes in [-1440, 0, 1440, i16::MAX] {
            parse_all(line.as_bytes(), minutes);
        }
    }
}
