//! Unix `ls -l` parser (T13): fixture snapshots and property tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use courier_ftp_core::listing::unix::{LineError, try_parse_line};
use courier_ftp_core::listing::{ListingContext, TextDecoder, infer_year, unix};
use courier_ftp_core::model::{Charset, Entry, EntryKind, Permissions, Precision, Timestamp};
use proptest::prelude::*;
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time};

/// Fixture options (`<case>.opts.json`).
struct Opts {
    ctx: ListingContext,
    decoder: TextDecoder,
}

fn load_opts(fixture: &Path) -> Opts {
    let opts_path = fixture.with_extension("opts.json");
    let v: serde_json::Value = match std::fs::read_to_string(&opts_path) {
        Ok(s) => serde_json::from_str(&s).unwrap(),
        Err(_) => serde_json::json!({}),
    };
    let now = v["now"].as_str().unwrap_or("2024-06-15T12:00:00Z");
    let now = OffsetDateTime::parse(now, &Rfc3339).unwrap();
    let tz = v["tz_offset_minutes"].as_i64().unwrap_or(0);
    let charset = Charset::from_label(v["charset"].as_str().unwrap_or("utf-8")).unwrap();
    Opts {
        ctx: ListingContext::new(now, i32::try_from(tz).unwrap()),
        decoder: TextDecoder::for_charset(charset),
    }
}

/// Snapshot view of an entry (readable times and permissions).
#[derive(Serialize)]
struct EntryView {
    name: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    size: Option<u64>,
    modified: Option<String>,
    permissions: Option<String>,
    owner: Option<String>,
    group: Option<String>,
    hidden: bool,
}

fn view(e: &Entry) -> EntryView {
    let (kind, target) = match &e.kind {
        EntryKind::File => ("file", None),
        EntryKind::Dir => ("dir", None),
        EntryKind::Symlink { target, .. } => ("symlink", target.clone()),
        EntryKind::Other => ("other", None),
    };
    EntryView {
        name: e.name.clone(),
        kind,
        target,
        size: e.size,
        modified: e
            .modified
            .map(|m| format!("{} ({:?})", m.time.format(&Rfc3339).unwrap(), m.precision)),
        permissions: e
            .permissions
            .as_ref()
            .map(|p| match (&p.raw, p.to_octal_string()) {
                (Some(raw), _) => format!("raw {raw}"),
                (None, Some(oct)) => format!("{} ({oct})", p.to_rwx_string().unwrap_or_default()),
                (None, None) => String::new(),
            }),
        owner: e.owner.clone(),
        group: e.group.clone(),
        hidden: e.hidden,
    }
}

#[derive(Serialize)]
struct LineView {
    line: usize,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry: Option<EntryView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
}

#[derive(Serialize)]
struct Snapshot {
    used_fallback_encoding: bool,
    lines: Vec<LineView>,
}

#[test]
fn unix_fixtures_snapshot() {
    insta::glob!("listings/unix/*.txt", |path| {
        let opts = load_opts(path);
        let data = std::fs::read(path).unwrap();
        let mut out = Vec::new();
        let mut used_fallback = false;
        for (i, raw) in data.split(|&b| b == b'\n').enumerate() {
            let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
            let (line, fb) = opts.decoder.decode(raw);
            used_fallback |= fb;
            if line.trim().is_empty() {
                continue;
            }
            let (outcome, entry, text) = match try_parse_line(&line, &opts.ctx) {
                Ok(e) => ("entry", Some(view(&e)), None),
                Err(LineError::Header) => ("header", None, None),
                Err(LineError::NotUnix) => ("not-unix", None, Some(line.clone())),
                Err(LineError::BadNumber) => ("bad-number", None, Some(line.clone())),
            };
            out.push(LineView {
                line: i + 1,
                outcome,
                entry,
                text,
            });
        }
        insta::assert_yaml_snapshot!(Snapshot {
            used_fallback_encoding: used_fallback,
            lines: out,
        });
    });
}

#[test]
fn unix_cp1252_fixture_reports_fallback() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listings/unix/cp1252-auto.txt");
    let data = std::fs::read(&path).unwrap();
    let opts = load_opts(&path);
    let lines: Vec<(String, bool)> = data
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| opts.decoder.decode(l.strip_suffix(b"\r").unwrap_or(l)))
        .collect();
    assert!(lines[0].1 && !lines[1].1);
    let e = unix::parse_line(&lines[0].0, &opts.ctx).unwrap();
    assert_eq!(e.name, "café €.txt");
    let e = unix::parse_line(&lines[1].0, &opts.ctx).unwrap();
    assert_eq!(e.name, "utf8-ü.txt");
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn local_now(ctx: &ListingContext) -> PrimitiveDateTime {
    let l = ctx.now + Duration::minutes(i64::from(ctx.tz_offset_minutes));
    PrimitiveDateTime::new(l.date(), l.time())
}

fn arb_name() -> impl Strategy<Value = String> {
    "[^/\u{0}\r\n]{1,24}"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn prop_unix_render_parse_roundtrip(
        now_secs in 946_684_800i64..3_000_000_000i64,
        tz in -720i32..=840,
        kind in 0u8..3,
        mode in 0u32..=0o7777,
        links in 1u32..200,
        owner in "[a-z][a-z0-9_]{0,7}",
        group in proptest::option::of("[a-z][a-z0-9_]{0,7}"),
        size in 0u64..(1u64 << 60),
        recent in any::<bool>(),
        minutes_ago in 0i64..(300 * 24 * 60),
        old in (1990i32..2000, 1u8..=12, 1u8..=28),
        name in arb_name(),
        target in "[^\r\n]{1,24}",
    ) {
        let ctx = ListingContext::new(OffsetDateTime::from_unix_timestamp(now_secs).unwrap(), tz);
        let (date_text, expected) = if recent {
            let local = local_now(&ctx) - Duration::minutes(minutes_ago);
            let local = local.replace_second(0).unwrap().replace_nanosecond(0).unwrap();
            let text = format!(
                "{} {:2} {:02}:{:02}",
                MONTHS[usize::from(u8::from(local.month())) - 1],
                local.day(),
                local.hour(),
                local.minute()
            );
            let utc = local.assume_utc() - Duration::minutes(i64::from(tz));
            (text, Timestamp::new(utc, Precision::Minute))
        } else {
            let (y, m, d) = old;
            let date = Date::from_calendar_date(y, Month::try_from(m).unwrap(), d).unwrap();
            let text = format!("{} {:2}  {y}", MONTHS[usize::from(m) - 1], d);
            (text, Timestamp::new(PrimitiveDateTime::new(date, Time::MIDNIGHT).assume_utc(), Precision::Day))
        };
        let perms = Permissions::from_mode(mode);
        let (type_char, shown_name, expected_kind) = match kind {
            0 => ('-', name.clone(), EntryKind::File),
            1 => ('d', name.clone(), EntryKind::Dir),
            _ => {
                prop_assume!(!name.contains(" -> "));
                (
                    'l',
                    format!("{name} -> {target}"),
                    EntryKind::Symlink { target: Some(target.clone()), target_kind: None },
                )
            }
        };
        let group_col = group.as_deref().map(|g| format!(" {g}")).unwrap_or_default();
        let line = format!(
            "{type_char}{} {links:>3} {owner}{group_col} {size:>8} {date_text} {shown_name}",
            perms.to_rwx_string().unwrap()
        );
        let e = unix::parse_line(&line, &ctx).unwrap_or_else(|| panic!("no entry for {line:?}"));
        prop_assert_eq!(&e.name, &name);
        prop_assert_eq!(&e.kind, &expected_kind);
        prop_assert_eq!(e.size, Some(size));
        prop_assert_eq!(e.permissions.and_then(|p| p.mode), Some(mode));
        prop_assert_eq!(e.owner.as_deref(), Some(owner.as_str()));
        prop_assert_eq!(e.group.as_deref(), group.as_deref());
        prop_assert_eq!(e.modified, Some(expected));
        prop_assert_eq!(e.hidden, name.starts_with('.'));
    }

    #[test]
    fn prop_infer_year_never_more_than_one_day_ahead(
        now_secs in 946_684_800i64..3_000_000_000i64,
        tz in -720i32..=840,
        month in 1u8..=12,
        day in 1u8..=31,
        hour in 0u8..24,
        minute in 0u8..60,
    ) {
        let ctx = ListingContext::new(OffsetDateTime::from_unix_timestamp(now_secs).unwrap(), tz);
        let local = local_now(&ctx);
        if let Some(y) = infer_year(month, day, hour, minute, &ctx) {
            let date = Date::from_calendar_date(y, Month::try_from(month).unwrap(), day).unwrap();
            let dt = PrimitiveDateTime::new(date, Time::from_hms(hour, minute, 0).unwrap());
            prop_assert!(dt <= local + Duration::days(1), "{dt} vs {local}");
            if !(month == 2 && day == 29) {
                prop_assert!(y >= local.year() - 1);
            }
        } else {
            // Only dates that never exist (or Feb 29 too far away) are rejected.
            prop_assert!(Date::from_calendar_date(2024, Month::try_from(month).unwrap(), day).is_err());
        }
    }

    #[test]
    fn prop_unix_parse_line_never_panics(line in "\\PC{0,200}") {
        let ctx = ListingContext::new(OffsetDateTime::UNIX_EPOCH, 0);
        let _ = unix::parse_line(&line, &ctx);
    }
}
