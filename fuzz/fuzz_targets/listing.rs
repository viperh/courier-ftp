//! FTP `LIST` / `MLSD` listing parsers (T13) must never panic. Same body as
//! `crates/courier-ftp-proto-ftp/tests/no_panic.rs`.

#![no_main]

use courier_ftp_core::model::Charset;
use courier_ftp_proto_ftp::listing::{ListCommand, ListingContext, parse_listing};
use libfuzzer_sys::fuzz_target;
use time::{Duration, macros::datetime};

fuzz_target!(|data: &[u8]| {
    // The first two bytes pick the server time-zone offset (within ±24 h).
    let (offset, bytes) = match data {
        [a, b, rest @ ..] => (i16::from_le_bytes([*a, *b]) % 1441, rest),
        _ => (0, data),
    };
    let ctx = ListingContext::at(
        datetime!(2024-01-01 00:30 UTC),
        Duration::minutes(i64::from(offset)),
    );
    for command in [ListCommand::Mlsd, ListCommand::List] {
        for charset in [Charset::Auto, Charset::Utf8] {
            let _ = parse_listing(bytes, charset, command, &ctx);
        }
    }
});
