//! FTP listing parsers (T13): fixture snapshots and property tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use courier_ftp_core::model::{Charset, Entry, EntryKind, Permissions};
use courier_ftp_proto_ftp::listing::{
    ListFormat, ListingContext, ParseOptions, ParsedListing, SkipReason, TextDecoder, fuzz_listing,
    parse_list, parse_mlsd,
};
use proptest::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use time::macros::datetime;

/// Fixture options (`<case>.opts.json`).
fn load_opts(fixture: &Path) -> ParseOptions {
    let opts_path = fixture.with_extension("opts.json");
    let v: serde_json::Value = match std::fs::read_to_string(&opts_path) {
        Ok(s) => serde_json::from_str(&s).unwrap(),
        Err(_) => serde_json::json!({}),
    };
    let now = v["now"].as_str().unwrap_or("2024-06-15T12:00:00Z");
    let now = OffsetDateTime::parse(now, &Rfc3339).unwrap();
    let tz = v["tz_offset_minutes"].as_i64().unwrap_or(0);
    let charset = Charset::from_label(v["charset"].as_str().unwrap_or("utf-8")).unwrap();
    let hint = v["hint"].as_str().map(|h| match h {
        "mlsd" => ListFormat::Mlsd,
        "unix" => ListFormat::Unix,
        "dos" => ListFormat::Dos,
        "eplf" => ListFormat::Eplf,
        "vms" => ListFormat::Vms,
        "mvs-dataset" => ListFormat::MvsDataset,
        "mvs-member" => ListFormat::MvsMember,
        "ibm-i" => ListFormat::IbmI,
        other => panic!("unknown hint {other}"),
    });
    ParseOptions {
        ctx: ListingContext::new(now, i32::try_from(tz).unwrap()),
        decoder: TextDecoder::for_charset(charset),
        hint,
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
        permissions: e.permissions.as_ref().map(perm_text),
        owner: e.owner.clone(),
        group: e.group.clone(),
        hidden: e.hidden,
    }
}

fn perm_text(p: &Permissions) -> String {
    match (&p.raw, p.to_octal_string()) {
        (Some(raw), _) => format!("raw {raw}"),
        (None, Some(oct)) => format!("{} ({oct})", p.to_rwx_string().unwrap_or_default()),
        (None, None) => String::new(),
    }
}

#[derive(Serialize)]
struct SkippedView {
    line: usize,
    reason: String,
    text: String,
}

#[derive(Serialize)]
struct Snapshot {
    format: Option<ListFormat>,
    used_fallback_encoding: bool,
    skipped_count: usize,
    entries: Vec<EntryView>,
    skipped: Vec<SkippedView>,
}

fn snapshot(p: &ParsedListing) -> Snapshot {
    Snapshot {
        format: p.format,
        used_fallback_encoding: p.used_fallback_encoding,
        skipped_count: p.skipped_count,
        entries: p.entries.iter().map(view).collect(),
        skipped: p
            .skipped
            .iter()
            .map(|s| SkippedView {
                line: s.line_no,
                reason: format!("{:?}", s.reason),
                text: s.text.clone(),
            })
            .collect(),
    }
}

fn parse_fixture(path: &Path) -> ParsedListing {
    let opts = load_opts(path);
    let data = std::fs::read(path).unwrap();
    let is_mlsd = path
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|d| d == "mlsd");
    if is_mlsd {
        parse_mlsd(&data, &opts)
    } else {
        parse_list(&data, &opts)
    }
}

#[test]
fn listing_fixtures_snapshot() {
    insta::glob!("listings/*/*.txt", |path| {
        let parsed = parse_fixture(path);
        insta::assert_yaml_snapshot!(snapshot(&parsed));
    });
}

#[test]
fn fixtures_have_no_hostile_names_and_crlf_matches_lf() {
    insta::glob!("listings/*/*.txt", |path| {
        let opts = load_opts(path);
        let data = std::fs::read(path).unwrap();
        let lf: Vec<u8> = data.iter().copied().filter(|&b| b != b'\r').collect();
        let crlf: Vec<u8> = lf
            .split(|&b| b == b'\n')
            .collect::<Vec<_>>()
            .join(&b"\r\n"[..]);
        let mlsd = path.parent().unwrap().ends_with("mlsd");
        let parse = |d: &[u8]| {
            if mlsd {
                parse_mlsd(d, &opts)
            } else {
                parse_list(d, &opts)
            }
        };
        let (a, b) = (parse(&lf), parse(&crlf));
        assert_eq!(a.entries, b.entries, "{}", path.display());
        for e in &a.entries {
            assert!(Entry::is_valid_name(&e.name));
        }
    });
}

#[test]
fn fixture_counts_per_format() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listings");
    let count = |sub: &str, prefix: &str| {
        std::fs::read_dir(dir.join(sub))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.ends_with(".txt") && !n.ends_with(".opts.json") && n.starts_with(prefix)
            })
            .count()
    };
    for (sub, prefix) in [
        ("mlsd", ""),
        ("dos", ""),
        ("eplf", ""),
        ("vms", ""),
        ("mvs", "dataset-"),
        ("mvs", "member-"),
        ("ibmi", ""),
    ] {
        assert!(count(sub, prefix) >= 5, "{sub}/{prefix}*");
    }
}

#[test]
fn skip_reasons_reported() {
    let opts = ParseOptions {
        ctx: ListingContext::new(datetime!(2024-06-15 12:00 UTC), 0),
        decoder: TextDecoder::Utf8,
        hint: None,
    };
    let p = parse_list(b"garbage\n", &opts);
    assert!(matches!(p.skipped[0].reason, SkipReason::Unrecognised));
}

// ---------------------------------------------------------------------------------
// Property tests

fn opts_for(tz: i32, hint: Option<ListFormat>) -> ParseOptions {
    ParseOptions {
        ctx: ListingContext::new(datetime!(2024-06-15 12:00 UTC), tz),
        decoder: TextDecoder::Utf8,
        hint,
    }
}

const HINTS: [Option<ListFormat>; 9] = [
    None,
    Some(ListFormat::Mlsd),
    Some(ListFormat::Unix),
    Some(ListFormat::Dos),
    Some(ListFormat::Eplf),
    Some(ListFormat::Vms),
    Some(ListFormat::MvsDataset),
    Some(ListFormat::MvsMember),
    Some(ListFormat::IbmI),
];

/// Lines that look like real listings, to reach deep parser states.
fn listing_like() -> impl Strategy<Value = Vec<u8>> {
    let line = prop_oneof![
        "[-dlcbps][rwxsStT-]{9}[+.@]? {1,3}[0-9]{1,3} [a-z]{1,8} [a-z]{1,8} [0-9,]{1,22} (Jan|Feb|Jän|1月|31\\.) [0-9]{1,2} ([0-9]{1,2}:[0-9]{2}|[0-9]{4}) [^\n]{0,20}",
        "type=[a-zA-Z.=:/]{0,20};(size=[0-9]{0,25};)?(modify=[0-9.]{0,20};)?(unix.mode=[0-9]{0,6};)? [^\n]{0,20}",
        "[0-9]{1,4}[-./][0-9]{1,2}[-./][0-9]{1,4} +[0-9]{1,2}:[0-9]{2}(AM|PM)? +(<DIR>|<JUNCTION>|[0-9,.]{1,25}) +[^\n]{0,20}",
        "\\+[a-z0-9.,/]{0,30}\t[^\n]{0,20}",
        "[A-Z_]{1,12}(\\.[A-Z]{1,3})?;[0-9]{1,6}( +[0-9/]{1,12})?( +[0-9]{1,2}-[A-Z]{3}-[0-9]{4})?( +[0-9:.]{1,11})?( +\\[[A-Z,]{0,12}\\])?( +\\([RWED,]{0,16}\\))?",
        "[A-Z0-9]{1,6} +[0-9]{4} +[0-9/*A-Z]{8,10} +[0-9]{1,2} +[0-9]{1,4} +[A-Z?]{1,2} +[0-9?]{1,5} +[0-9?]{1,5} +[A-Z-]{1,4} +[A-Z.']{1,20}",
        "[A-Z@#$]{1,8}( +[0-9]{2}\\.[0-9]{2} +[0-9/]{10} +[0-9/]{10} +[0-9:]{4,8} +[0-9 ]{0,20})?",
        "( Name +VV\\.MM.*|Volume Unit.*Dsname|Directory .*|Total of .*|%[A-Z]{1,6}-[EWF]-[A-Z]{1,6}, .*)",
        "[A-Z]{0,10} +[0-9]{0,20} +[0-9/.]{0,10} +[0-9:]{0,8} +\\*[A-Z]{1,6} +[^\n]{0,20}",
        "\\PC{0,60}",
    ];
    (proptest::collection::vec(line, 0..16), any::<bool>()).prop_map(|(lines, crlf)| {
        let sep = if crlf { "\r\n" } else { "\n" };
        lines.join(sep).into_bytes()
    })
}

fn arb_mlsd_name() -> impl Strategy<Value = String> {
    "[^/\u{0}\r\n]{1,24}".prop_filter("not . or ..", |n| n != "." && n != "..")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn prop_parsers_never_panic(
        data in proptest::collection::vec(any::<u8>(), 0..2048),
        sel in any::<u8>(),
    ) {
        let mut input = vec![sel];
        input.extend_from_slice(&data);
        fuzz_listing(&input);
    }
}

proptest! {
    // Generating listing-like lines is slow; random bytes above give the 10 000 cases.
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn prop_parsers_never_panic_listing_like(data in listing_like(), sel in any::<u8>()) {
        let mut input = vec![sel];
        input.extend_from_slice(&data);
        fuzz_listing(&input);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Large random inputs (up to 64 KiB) with every hint.
    #[test]
    fn prop_parsers_never_panic_large(
        data in proptest::collection::vec(any::<u8>(), 0..65_536),
    ) {
        for (i, hint) in HINTS.iter().enumerate() {
            let o = opts_for(i32::try_from(i).unwrap() * 97 - 400, *hint);
            let _ = parse_list(&data, &o);
            let _ = parse_mlsd(&data, &o);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    #[test]
    fn prop_mlsd_render_parse_roundtrip(
        name in arb_mlsd_name(),
        kind in 0u8..4,
        size in proptest::option::of(any::<u64>()),
        modify in proptest::option::of((1970i32..2100, 1u8..=12, 1u8..=28, 0u8..24, 0u8..60, 0u8..60, proptest::option::of(0u16..1000))),
        mode in proptest::option::of(0u32..=0o7777),
        perm in proptest::option::of("[adfrwelcmp]{1,8}"),
        owner in proptest::option::of("[a-z][a-z0-9]{0,7}"),
        group in proptest::option::of("[a-z][a-z0-9]{0,7}"),
        target in "[^;\r\n]{1,20}",
        upper_case_facts in any::<bool>(),
    ) {
        let mut facts = Vec::new();
        let (type_fact, expected_kind) = match kind {
            0 => ("file".to_owned(), EntryKind::File),
            1 => ("dir".to_owned(), EntryKind::Dir),
            2 => (format!("OS.unix=slink:{target}"), EntryKind::Symlink { target: Some(target.clone()), target_kind: None }),
            _ => ("OS.unix=socket".to_owned(), EntryKind::Other),
        };
        facts.push(format!("type={type_fact}"));
        if let Some(s) = size { facts.push(format!("size={s}")); }
        if let Some((y, mo, d, h, mi, s, ms)) = modify {
            match ms {
                Some(ms) => facts.push(format!("modify={y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}.{ms:03}")),
                None => facts.push(format!("modify={y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}")),
            }
        }
        if let Some(m) = mode { facts.push(format!("unix.mode={m:04o}")); }
        if let Some(p) = &perm { facts.push(format!("perm={p}")); }
        if let Some(o) = &owner { facts.push(format!("unix.ownername={o}")); }
        if let Some(g) = &group { facts.push(format!("unix.groupname={g}")); }
        let mut block = facts.join(";");
        if upper_case_facts {
            // Fact names are case-insensitive.
            block = block.replace("size=", "SIZE=").replace("modify=", "Modify=");
        }
        let line = format!("{block}; {name}\r\n");
        let p = parse_mlsd(line.as_bytes(), &opts_for(840, None));
        prop_assert_eq!(p.entries.len(), 1, "{:?} {:?}", line, p.skipped);
        let e = &p.entries[0];
        prop_assert_eq!(&e.name, &name);
        prop_assert_eq!(&e.kind, &expected_kind);
        let expected_size = if kind == 1 { None } else { size };
        prop_assert_eq!(e.size, expected_size);
        match modify {
            None => prop_assert_eq!(e.modified, None),
            Some((y, mo, d, h, mi, s, ms)) => {
                let m = e.modified.unwrap();
                prop_assert_eq!(m.time.year(), y);
                prop_assert_eq!(u8::from(m.time.month()), mo);
                prop_assert_eq!(m.time.day(), d);
                prop_assert_eq!((m.time.hour(), m.time.minute(), m.time.second()), (h, mi, s));
                prop_assert_eq!(m.time.millisecond(), ms.unwrap_or(0));
            }
        }
        match (mode, &perm) {
            (Some(m), _) => prop_assert_eq!(e.permissions.as_ref().and_then(|p| p.mode), Some(m)),
            (None, Some(p)) => prop_assert_eq!(e.permissions.as_ref().and_then(|x| x.raw.clone()), Some(p.clone())),
            (None, None) => prop_assert!(e.permissions.is_none()),
        }
        prop_assert_eq!(&e.owner, &owner);
        prop_assert_eq!(&e.group, &group);
        prop_assert_eq!(e.hidden, name.starts_with('.'));
    }

}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn prop_line_endings_crlf_lf_equivalent(data in listing_like(), hint in 0usize..9) {
        let lf: Vec<u8> = data.iter().copied().filter(|&b| b != b'\r').collect();
        let crlf: Vec<u8> = lf.split(|&b| b == b'\n').collect::<Vec<_>>().join(&b"\r\n"[..]);
        let o = opts_for(60, HINTS[hint]);
        prop_assert_eq!(parse_list(&lf, &o).entries, parse_list(&crlf, &o).entries);
        prop_assert_eq!(parse_mlsd(&lf, &o).entries, parse_mlsd(&crlf, &o).entries);
    }
}
