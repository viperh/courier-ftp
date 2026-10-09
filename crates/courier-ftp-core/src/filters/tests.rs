#![allow(clippy::unwrap_used, clippy::expect_used)]

use pretty_assertions::assert_eq;
use proptest::prelude::*;
use time::macros::{date, datetime, offset};
use time::{OffsetDateTime, UtcOffset};

use super::engine::combine;
use super::*;
use crate::model::{Entry, EntryKind, Permissions, Precision, SymlinkTarget, Timestamp};

fn filter(
    applies_to: AppliesTo,
    match_mode: MatchMode,
    case_sensitive: bool,
    conditions: Vec<Condition>,
) -> Filter {
    Filter {
        name: "f".to_owned(),
        applies_to,
        match_mode,
        case_sensitive,
        scope: FilterScope::Both,
        conditions,
        builtin: false,
    }
}

fn one(c: Condition, case_sensitive: bool) -> Filter {
    filter(AppliesTo::Both, MatchMode::All, case_sensitive, vec![c])
}

fn file(name: &str) -> Entry {
    Entry::new(name, EntryKind::File)
}

fn matches_in(f: &Filter, e: &Entry, parent: &str, offset: UtcOffset) -> bool {
    CompiledFilter::compile(f, offset)
        .unwrap_or_else(|e| panic!("{e}"))
        .matches(e, parent)
}

fn matches(f: &Filter, e: &Entry) -> bool {
    matches_in(f, e, "/", UtcOffset::UTC)
}

fn name(op: StringOp, value: &str) -> Condition {
    Condition::Name {
        op,
        value: value.to_owned(),
    }
}

fn named(n: &str, conditions: Vec<Condition>) -> Filter {
    Filter {
        name: n.to_owned(),
        ..filter(AppliesTo::Both, MatchMode::Any, true, conditions)
    }
}

fn settings_with(filters: Vec<Filter>, local: &[&str], remote: &[&str]) -> FilterSettings {
    FilterSettings {
        filters,
        sets: vec![FilterSet {
            name: "s".to_owned(),
            local: local.iter().map(|s| (*s).to_owned()).collect(),
            remote: remote.iter().map(|s| (*s).to_owned()).collect(),
        }],
        active_set: "s".to_owned(),
        apply_to_transfers: true,
    }
}

// ---- conditions -----------------------------------------------------------------------

#[test]
fn string_ops_table() {
    use StringOp::*;
    // (op, case_sensitive, value, name, expected)
    let rows: &[(StringOp, bool, &str, &str, bool)] = &[
        (Contains, true, "ab", "xaby", true),
        (Contains, true, "AB", "xaby", false),
        (Contains, false, "AB", "xaby", true),
        (Contains, false, "zz", "xaby", false),
        (NotContains, true, "ab", "xaby", false),
        (NotContains, true, "AB", "xaby", true),
        (NotContains, false, "AB", "xaby", false),
        (NotContains, false, "zz", "xaby", true),
        (Equals, true, "Read.me", "Read.me", true),
        (Equals, true, "read.me", "Read.me", false),
        (Equals, false, "READ.ME", "Read.me", true),
        (Equals, false, "read", "Read.me", false),
        (NotEquals, true, "read.me", "Read.me", true),
        (NotEquals, true, "Read.me", "Read.me", false),
        (NotEquals, false, "READ.ME", "Read.me", false),
        (NotEquals, false, "read", "Read.me", true),
        (BeginsWith, true, "Abc", "Abcdef", true),
        (BeginsWith, true, "abc", "Abcdef", false),
        (BeginsWith, false, "ABC", "Abcdef", true),
        (BeginsWith, false, "def", "Abcdef", false),
        (EndsWith, true, ".TXT", "a.TXT", true),
        (EndsWith, true, ".txt", "a.TXT", false),
        (EndsWith, false, ".txt", "a.TXT", true),
        (EndsWith, false, ".md", "a.TXT", false),
        (Regex, true, r"^a\d+\.log$", "a12.log", true),
        (Regex, true, r"^A\d+", "a12.log", false),
        (Regex, false, r"^A\d+", "a12.log", true),
        (Regex, true, r"\d", "abc", false),
        (Regex, true, "b", "abc", true), // unanchored
        (Regex, true, "É", "café", false),
        (Regex, false, "É", "café", true),
        (Glob, true, "*.txt", "a.txt", true),
        (Glob, true, "*.TXT", "a.txt", false),
        (Glob, false, "*.TXT", "a.txt", true),
        (Glob, false, "a?c", "abc", true),
        (Glob, true, "a", "ab", false), // whole string
        (Glob, true, r"a\*b", "a*b", true),
        (Glob, true, r"a\*b", "axb", false),
        (Glob, true, "#*#", "#autosave#", true),
        (Glob, true, "[ab]x", "bx", true),
        // Unicode case folding.
        (Equals, false, "ÄRGER", "ärger", true),
        (Contains, false, "STRASSE", "die strasse", true),
    ];
    for (op, cs, value, n, expected) in rows {
        let f = one(name(*op, value), *cs);
        assert_eq!(
            matches(&f, &file(n)),
            *expected,
            "{op:?} cs={cs} {value:?} vs {n:?}"
        );
        // The same ops on `Path` read the parent.
        let p = one(
            Condition::Path {
                op: *op,
                value: (*value).to_owned(),
            },
            *cs,
        );
        assert_eq!(
            matches_in(&p, &file("unrelated"), n, UtcOffset::UTC),
            *expected,
            "Path {op:?} cs={cs} {value:?} vs {n:?}"
        );
    }
}

#[test]
fn path_condition_uses_parent_not_name() {
    let f = one(
        Condition::Path {
            op: StringOp::Contains,
            value: "www".to_owned(),
        },
        true,
    );
    assert!(matches_in(&f, &file("x"), "/var/www", UtcOffset::UTC));
    assert!(!matches_in(&f, &file("www"), "/var/log", UtcOffset::UTC));
    // Glob over a path: `*` crosses separators.
    let g = one(
        Condition::Path {
            op: StringOp::Glob,
            value: "/var/*".to_owned(),
        },
        true,
    );
    assert!(matches_in(&g, &file("x"), "/var/www/html", UtcOffset::UTC));
    // Windows local paths.
    let w = one(
        Condition::Path {
            op: StringOp::BeginsWith,
            value: r"c:\users".to_owned(),
        },
        false,
    );
    assert!(matches_in(&w, &file("x"), r"C:\Users\me", UtcOffset::UTC));
}

#[test]
fn size_ops_table() {
    use NumOp::*;
    let rows: &[(NumOp, u64, Option<u64>, bool)] = &[
        (Equals, 0, Some(0), true),
        (Equals, 0, Some(1), false),
        (Equals, u64::MAX, Some(u64::MAX), true),
        (NotEquals, 0, Some(0), false),
        (NotEquals, 0, Some(1), true),
        (NotEquals, 5, None, false),
        (Greater, 0, Some(0), false),
        (Greater, 0, Some(1), true),
        (Greater, u64::MAX, Some(u64::MAX), false),
        (Greater, u64::MAX - 1, Some(u64::MAX), true),
        (Less, 0, Some(0), false),
        (Less, 1, Some(0), true),
        (Less, u64::MAX, Some(u64::MAX - 1), true),
        (Less, u64::MAX, Some(u64::MAX), false),
        (Equals, 0, None, false),
        (Greater, 0, None, false),
        (Less, u64::MAX, None, false),
    ];
    for (op, value, size, expected) in rows {
        let f = one(
            Condition::Size {
                op: *op,
                value: *value,
            },
            true,
        );
        let mut e = file("a");
        e.size = *size;
        assert_eq!(matches(&f, &e), *expected, "{op:?} {value} vs {size:?}");
        // Directories (and symlinks to them) never match.
        e.kind = EntryKind::Dir;
        assert!(!matches(&f, &e), "dir {op:?} {value} vs {size:?}");
        e.kind = EntryKind::Symlink {
            target: None,
            target_kind: Some(SymlinkTarget::Dir),
        };
        assert!(!matches(&f, &e), "dir link {op:?} {value} vs {size:?}");
    }
}

fn dated(t: OffsetDateTime, p: Precision) -> Entry {
    let mut e = file("a");
    e.modified = Some(Timestamp::new(t, p));
    e
}

#[test]
fn date_ops_table() {
    use DateOp::*;
    let late = dated(datetime!(2026-10-08 23:30 UTC), Precision::Minute);
    let early = dated(datetime!(2026-10-08 00:00 UTC), Precision::Second);
    let day = dated(datetime!(2026-10-08 00:00 UTC), Precision::Day);
    let none = file("a");
    // (entry, offset, op, value, expected)
    let rows: Vec<(&Entry, UtcOffset, DateOp, time::Date, bool)> = vec![
        (&late, offset!(+00:00), Equals, date!(2026 - 10 - 08), true),
        (&late, offset!(+02:00), Equals, date!(2026 - 10 - 08), false),
        (&late, offset!(+02:00), Equals, date!(2026 - 10 - 09), true),
        (
            &late,
            offset!(+00:00),
            NotEquals,
            date!(2026 - 10 - 08),
            false,
        ),
        (
            &late,
            offset!(+02:00),
            NotEquals,
            date!(2026 - 10 - 08),
            true,
        ),
        (&late, offset!(+00:00), Before, date!(2026 - 10 - 09), true),
        (&late, offset!(+02:00), Before, date!(2026 - 10 - 09), false),
        (&late, offset!(+00:00), After, date!(2026 - 10 - 08), false),
        (&late, offset!(+02:00), After, date!(2026 - 10 - 08), true),
        (&early, offset!(+00:00), Equals, date!(2026 - 10 - 08), true),
        (&early, offset!(-02:00), Equals, date!(2026 - 10 - 07), true),
        (
            &early,
            offset!(+02:00),
            Before,
            date!(2026 - 10 - 08),
            false,
        ),
        (&early, offset!(+00:00), After, date!(2026 - 10 - 07), true),
        (
            &early,
            offset!(+00:00),
            Before,
            date!(2026 - 10 - 08),
            false,
        ),
        (&none, offset!(+00:00), Equals, date!(2026 - 10 - 08), false),
        (
            &none,
            offset!(+00:00),
            NotEquals,
            date!(2026 - 10 - 08),
            false,
        ),
        (&none, offset!(+00:00), Before, date!(2030 - 01 - 01), false),
        (&none, offset!(+00:00), After, date!(2000 - 01 - 01), false),
    ];
    for (e, off, op, value, expected) in rows {
        let f = one(Condition::Date { op, value }, true);
        assert_eq!(
            matches_in(&f, e, "/", off),
            expected,
            "{:?} at {off} {op:?} {value}",
            e.modified
        );
    }
    // Day precision: no shift under any offset.
    for off in [
        offset!(+00:00),
        offset!(+02:00),
        offset!(-12:00),
        offset!(+14:00),
    ] {
        let eq = one(
            Condition::Date {
                op: Equals,
                value: date!(2026 - 10 - 08),
            },
            true,
        );
        assert!(matches_in(&eq, &day, "/", off), "{off}");
    }
}

#[test]
fn permission_bits_table() {
    let expected = |mode: u32, bit: PermBit| mode & bit.mask() != 0;
    for mode in [0o000, 0o777, 0o644] {
        for bit in PermBit::ALL {
            for set in [true, false] {
                let f = one(Condition::Permission { bit, set }, true);
                let mut e = file("a");
                e.permissions = Some(Permissions::from_mode(mode));
                assert_eq!(
                    matches(&f, &e),
                    expected(mode, bit) == set,
                    "{mode:o} {bit:?} {set}"
                );
                // Unknown mode → false.
                e.permissions = Some(Permissions::from_raw("R"));
                assert!(!matches(&f, &e));
                e.permissions = None;
                assert!(!matches(&f, &e));
            }
        }
    }
    assert_eq!(
        PermBit::ALL.map(PermBit::mask),
        [
            0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001
        ]
    );
}

#[test]
fn attribute_hidden_and_readonly() {
    let hidden = |set| {
        one(
            Condition::Attribute {
                attr: AttrFlag::Hidden,
                set,
            },
            true,
        )
    };
    let ro = |set| {
        one(
            Condition::Attribute {
                attr: AttrFlag::ReadOnly,
                set,
            },
            true,
        )
    };
    let mut e = file("a");
    assert!(!matches(&hidden(true), &e));
    assert!(matches(&hidden(false), &e));
    e.hidden = true;
    assert!(matches(&hidden(true), &e));
    assert!(!matches(&hidden(false), &e));

    // Unknown permissions: both read-only conditions are false.
    assert!(!matches(&ro(true), &e));
    assert!(!matches(&ro(false), &e));
    e.permissions = Some(Permissions {
        mode: None,
        raw: None,
    });
    assert!(!matches(&ro(true), &e) && !matches(&ro(false), &e));

    for (perms, read_only) in [
        (Permissions::from_mode(0o444), true),
        (Permissions::from_mode(0o000), true),
        (Permissions::from_mode(0o644), false),
        (Permissions::from_mode(0o440), true),
        (Permissions::from_mode(0o642), false),
        (Permissions::from_raw("R"), true),
        (Permissions::from_raw("HR"), true),
        (Permissions::from_raw("adfrw"), false),
    ] {
        e.permissions = Some(perms.clone());
        assert_eq!(matches(&ro(true), &e), read_only, "{perms:?}");
        assert_eq!(matches(&ro(false), &e), !read_only, "{perms:?}");
    }
}

// ---- combining and kinds --------------------------------------------------------------

/// Three conditions on the name "abc" of which the first `n` are true.
fn n_true(n: usize, mode: MatchMode) -> Filter {
    let conds = (0..3)
        .map(|i| name(StringOp::Equals, if i < n { "abc" } else { "zzz" }))
        .collect();
    filter(AppliesTo::Both, mode, true, conds)
}

#[test]
fn match_modes_truth_table() {
    use MatchMode::*;
    // n true out of 3 → [All, Any, None, NotAll]
    let table = [
        (0, [false, false, true, true]),
        (1, [false, true, false, true]),
        (2, [false, true, false, true]),
        (3, [true, true, false, false]),
    ];
    for (n, expected) in table {
        let got = [All, Any, None, NotAll].map(|m| matches(&n_true(n, m), &file("abc")));
        assert_eq!(got, expected, "n = {n}");
    }
    // Order of the true conditions does not matter.
    let mixed = filter(
        AppliesTo::Both,
        All,
        true,
        vec![name(StringOp::Equals, "zzz"), name(StringOp::Equals, "abc")],
    );
    assert!(!matches(&mixed, &file("abc")));
}

#[test]
fn zero_conditions_never_match() {
    for mode in [
        MatchMode::All,
        MatchMode::Any,
        MatchMode::None,
        MatchMode::NotAll,
    ] {
        let f = filter(AppliesTo::Both, mode, true, vec![]);
        assert!(!matches(&f, &file("a")), "{mode:?}");
        assert!(!combine(mode, 0, std::iter::empty()));
    }
}

#[test]
fn applies_to_kinds_including_symlinks() {
    let link = |target_kind| {
        Entry::new(
            "x",
            EntryKind::Symlink {
                target: None,
                target_kind,
            },
        )
    };
    let cases = [
        (Entry::new("x", EntryKind::File), false),
        (Entry::new("x", EntryKind::Dir), true),
        (Entry::new("x", EntryKind::Other), false),
        (link(Some(SymlinkTarget::Dir)), true),
        (link(Some(SymlinkTarget::File)), false),
        (link(Some(SymlinkTarget::Broken)), false),
        (link(Some(SymlinkTarget::Other)), false),
        (link(None), false),
    ];
    for (e, is_dir) in cases {
        for (applies, expected) in [
            (AppliesTo::Files, !is_dir),
            (AppliesTo::Dirs, is_dir),
            (AppliesTo::Both, true),
        ] {
            let f = filter(
                applies,
                MatchMode::All,
                true,
                vec![name(StringOp::Equals, "x")],
            );
            assert_eq!(matches(&f, &e), expected, "{applies:?} {:?}", e.kind);
        }
    }
}

// ---- defaults and built-ins -----------------------------------------------------------

#[test]
fn defaults_have_builtins_and_default_set() {
    let (s, warnings) = crate::settings::Settings::from_json_lenient(&serde_json::json!({}));
    assert!(warnings.is_empty(), "{warnings:?}");
    let f = &s.filters;
    let names: Vec<_> = f.filters.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "CVS and SVN directories",
            "Git directories",
            "Temporary and backup files",
            "Configuration files",
            "OS metadata files"
        ]
    );
    assert!(f.filters.iter().all(|f| f.builtin));
    assert_eq!(f.sets, vec![FilterSet::empty("default")]);
    assert_eq!(f.active_set, "default");
    assert!(f.apply_to_transfers);
    assert_eq!(f.active(), Some(&FilterSet::empty("default")));
    assert!(validate_settings(f).is_empty());
    // None enabled: the engines are inactive.
    for side in [Side::Local, Side::Remote] {
        let (e, errors) = FilterEngine::new(f, side, UtcOffset::UTC);
        assert!(errors.is_empty() && !e.is_active());
    }
}

#[test]
fn builtins_behave() {
    let all: Vec<String> = builtin_filters().into_iter().map(|f| f.name).collect();
    let all: Vec<&str> = all.iter().map(String::as_str).collect();
    let s = settings_with(builtin_filters(), &all, &all);
    let (engine, errors) = FilterEngine::new(&s, Side::Remote, UtcOffset::UTC);
    assert!(errors.is_empty());
    let dir = |n: &str| Entry::new(n, EntryKind::Dir);
    for (e, excluded) in [
        (dir("CVS"), true),
        (dir("cvs"), false),
        (dir(".svn"), true),
        (dir(".git"), true),
        (file("CVS"), false),
        (file("notes.txt~"), true),
        (file("A.BAK"), true),
        (file("x.Tmp"), true),
        (file(".main.rs.swp"), true),
        (file("#draft#"), true),
        (file(".bashrc"), true),
        (dir(".config"), true),
        (file("THUMBS.DB"), true),
        (file(".DS_Store"), true),
        (file("Desktop.ini"), true),
        (dir("Thumbs.db"), false),
        (file("main.rs"), false),
        (dir("src"), false),
    ] {
        assert_eq!(engine.excluded(&e, "/"), excluded, "{e:?}");
    }
}

#[test]
fn restore_builtins_readds_and_resets() {
    let mut s = FilterSettings::default();
    let user = named("mine", vec![name(StringOp::Contains, "x")]);
    s.filters.push(user.clone());
    // Delete one built-in, edit another.
    s.filters.retain(|f| f.name != "Git directories");
    let tmp = s
        .filters
        .iter_mut()
        .find(|f| f.name == "Temporary and backup files")
        .unwrap();
    tmp.conditions.pop();
    tmp.case_sensitive = true;
    let mut restored = s.restore_builtins();
    restored.sort();
    assert_eq!(restored, ["Git directories", "Temporary and backup files"]);
    assert_eq!(s.filter("mine"), Some(&user));
    for b in builtin_filters() {
        assert_eq!(s.filter(&b.name), Some(&b));
    }
    assert_eq!(s.filters.len(), 6);
    // Idempotent.
    assert!(s.restore_builtins().is_empty());
    // A user filter that took a built-in's name is left alone.
    let mut s = FilterSettings::default();
    let squatter = named("Git directories", vec![name(StringOp::Equals, "x")]);
    s.filters.retain(|f| f.name != "Git directories");
    s.filters.push(squatter.clone());
    assert!(s.restore_builtins().is_empty());
    assert_eq!(s.filter("Git directories"), Some(&squatter));
}

// ---- validation -----------------------------------------------------------------------

#[test]
fn invalid_regex_reported_by_validate() {
    let f = named(
        "bad",
        vec![
            name(StringOp::Regex, "(unclosed"),
            name(StringOp::Equals, "ok"),
            Condition::Path {
                op: StringOp::Regex,
                value: "[z-a]".to_owned(),
            },
        ],
    );
    let errors = validate_filter(&f, &[]);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors.iter().all(|e| matches!(
        e,
        FilterError::InvalidRegex { filter, .. } if filter == "bad"
    )));
    assert!(errors.iter().all(FilterError::is_blocking));
    let core: crate::Error = errors[0].clone().into();
    assert!(
        matches!(core, crate::Error::InvalidInput(m) if m.contains("invalid regular expression"))
    );
    // Invalid glob.
    let g = named("g", vec![name(StringOp::Glob, "a[")]);
    assert!(matches!(
        validate_filter(&g, &[]).as_slice(),
        [FilterError::InvalidGlob { .. }]
    ));
    // Huge regex beyond the size limit.
    let big = named("big", vec![name(StringOp::Regex, r"\w{1000}")]);
    assert!(matches!(
        validate_filter(&big, &[]).as_slice(),
        [FilterError::InvalidRegex { .. }]
    ));
}

#[test]
fn lenient_load_disables_bad_filter_only() {
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if let Ok(mut v) = self.0.lock() {
                v.extend_from_slice(data);
            }
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let s = settings_with(
        vec![
            named("bad", vec![name(StringOp::Regex, "(")]),
            named("good", vec![name(StringOp::EndsWith, ".log")]),
        ],
        &["bad", "good"],
        &["bad", "good"],
    );
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let (engine, errors) = tracing::subscriber::with_default(subscriber, || {
        FilterEngine::new(&s, Side::Local, UtcOffset::UTC)
    });
    assert!(
        matches!(errors.as_slice(), [FilterError::InvalidRegex { filter, .. }] if filter == "bad")
    );
    assert!(engine.is_active());
    assert_eq!(engine.filters().len(), 1);
    assert_eq!(engine.filters()[0].name(), "good");
    assert!(engine.excluded(&file("a.log"), "/"));
    assert!(!engine.excluded(&file("a.txt"), "/"));
    let log = String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned();
    assert!(log.contains("WARN") && log.contains("bad"), "{log}");
}

#[test]
fn duplicate_and_empty_names_rejected() {
    let a = named("a", vec![name(StringOp::Equals, "x")]);
    let errors = validate_filter(&a, std::slice::from_ref(&a));
    assert_eq!(errors, vec![FilterError::DuplicateName("a".to_owned())]);
    let empty = named("", vec![name(StringOp::Equals, "x")]);
    assert_eq!(
        validate_filter(&empty, std::slice::from_ref(&empty)),
        vec![FilterError::EmptyName]
    );
    let long = named(&"n".repeat(65), vec![name(StringOp::Equals, "x")]);
    assert!(matches!(
        validate_filter(&long, &[]).as_slice(),
        [FilterError::NameTooLong(_)]
    ));
    assert!(
        validate_filter(
            &named(&"é".repeat(64), vec![name(StringOp::Equals, "x")]),
            &[]
        )
        .is_empty()
    );
    let ctl = named("a\tb", vec![name(StringOp::Equals, "x")]);
    assert!(matches!(
        validate_filter(&ctl, &[]).as_slice(),
        [FilterError::ControlCharsInName(_)]
    ));
    // In settings, the duplicate is reported once.
    let s = settings_with(vec![a.clone(), a.clone()], &[], &[]);
    assert_eq!(
        validate_settings(&s),
        vec![FilterError::DuplicateName("a".to_owned())]
    );
    // No conditions: a non-blocking warning.
    let none = named("n", vec![]);
    let errors = validate_filter(&none, &[]);
    assert_eq!(
        errors,
        vec![FilterError::NoConditions {
            filter: "n".to_owned()
        }]
    );
    assert!(!errors[0].is_blocking());
}

#[test]
fn pattern_too_long_rejected() {
    let ok = named("ok", vec![name(StringOp::Contains, &"é".repeat(1024))]);
    assert!(validate_filter(&ok, &[]).is_empty());
    for op in [StringOp::Contains, StringOp::Regex, StringOp::Glob] {
        let f = named("long", vec![name(op, &"a".repeat(1025))]);
        assert_eq!(
            validate_filter(&f, &[]),
            vec![FilterError::PatternTooLong {
                filter: "long".to_owned()
            }],
            "{op:?}"
        );
        assert!(CompiledFilter::compile(&f, UtcOffset::UTC).is_err());
    }
}

#[test]
fn too_many_conditions_rejected() {
    let ok = named("ok", vec![name(StringOp::Contains, "a"); 32]);
    assert!(validate_filter(&ok, &[]).is_empty());
    let f = named("many", vec![name(StringOp::Contains, "a"); 33]);
    let expected = FilterError::TooManyConditions {
        filter: "many".to_owned(),
    };
    assert_eq!(validate_filter(&f, &[]), vec![expected.clone()]);
    assert_eq!(
        CompiledFilter::compile(&f, UtcOffset::UTC).err(),
        Some(expected)
    );
}

#[test]
fn unknown_filter_in_set_reported() {
    let s = settings_with(
        vec![named("a", vec![name(StringOp::Equals, "x")])],
        &["a", "ghost"],
        &["ghost"],
    );
    let expected = FilterError::UnknownFilter {
        set: "s".to_owned(),
        filter: "ghost".to_owned(),
    };
    assert_eq!(validate_settings(&s), vec![expected.clone()]);
    let (engine, errors) = FilterEngine::new(&s, Side::Local, UtcOffset::UTC);
    assert_eq!(errors, vec![expected]);
    assert!(engine.excluded(&file("x"), "/"));
}

// ---- engine ---------------------------------------------------------------------------

#[test]
fn scope_local_only_not_applied_remote() {
    let mut f = named("lo", vec![name(StringOp::Equals, "x")]);
    f.scope = FilterScope::LocalOnly;
    let mut r = named("ro", vec![name(StringOp::Equals, "y")]);
    r.scope = FilterScope::RemoteOnly;
    let s = settings_with(vec![f, r], &["lo", "ro"], &["lo", "ro"]);
    let (local, e1) = FilterEngine::new(&s, Side::Local, UtcOffset::UTC);
    let (remote, e2) = FilterEngine::new(&s, Side::Remote, UtcOffset::UTC);
    assert!(e1.is_empty() && e2.is_empty());
    assert!(local.excluded(&file("x"), "/") && !local.excluded(&file("y"), "/"));
    assert!(!remote.excluded(&file("x"), "/") && remote.excluded(&file("y"), "/"));
    assert_eq!(local.side(), Side::Local);
}

#[test]
fn equivalent_cases() {
    let a = named("a", vec![name(StringOp::Equals, "x")]);
    let b = named("b", vec![name(StringOp::EndsWith, ".log")]);
    let off = UtcOffset::UTC;

    // Identical selections on both sides.
    let s = settings_with(vec![a.clone(), b.clone()], &["a", "b"], &["b", "a"]);
    let (l, _) = FilterEngine::new(&s, Side::Local, off);
    let (r, _) = FilterEngine::new(&s, Side::Remote, off);
    assert!(l.equivalent(&r) && r.equivalent(&l));

    // A LocalOnly filter active on the local side only.
    let mut lo = b.clone();
    lo.scope = FilterScope::LocalOnly;
    let s = settings_with(vec![a.clone(), lo], &["a", "b"], &["a", "b"]);
    let (l, _) = FilterEngine::new(&s, Side::Local, off);
    let (r, _) = FilterEngine::new(&s, Side::Remote, off);
    assert!(!l.equivalent(&r));

    // Same definition under another name and scope: equivalent.
    let mut a2 = a.clone();
    a2.name = "a2".to_owned();
    a2.builtin = true;
    let s = settings_with(vec![a.clone(), a2], &["a"], &["a2"]);
    let (l, _) = FilterEngine::new(&s, Side::Local, off);
    let (r, _) = FilterEngine::new(&s, Side::Remote, off);
    assert!(l.equivalent(&r));

    // Multisets: [a, a'] vs [a] differ; case sensitivity matters.
    let mut a3 = a.clone();
    a3.name = "a3".to_owned();
    let s = settings_with(vec![a.clone(), a3], &["a", "a3"], &["a"]);
    let (l, _) = FilterEngine::new(&s, Side::Local, off);
    let (r, _) = FilterEngine::new(&s, Side::Remote, off);
    assert!(!l.equivalent(&r));
    let mut ci = a.clone();
    ci.name = "ci".to_owned();
    ci.case_sensitive = false;
    let s = settings_with(vec![a, ci], &["a"], &["ci"]);
    let (l, _) = FilterEngine::new(&s, Side::Local, off);
    let (r, _) = FilterEngine::new(&s, Side::Remote, off);
    assert!(!l.equivalent(&r));

    // Empty engines.
    assert!(FilterEngine::empty(Side::Local).equivalent(&FilterEngine::empty(Side::Remote)));
    assert!(!FilterEngine::empty(Side::Local).equivalent(&l));
    assert!(!FilterEngine::empty(Side::Local).is_active());
}

#[test]
fn visible_indices_preserves_order() {
    let s = settings_with(
        vec![named("logs", vec![name(StringOp::EndsWith, ".log")])],
        &[],
        &["logs"],
    );
    let (engine, _) = FilterEngine::new(&s, Side::Remote, UtcOffset::UTC);
    let entries: Vec<Entry> = ["b.log", "z.txt", "a.txt", "c.log", "m"]
        .into_iter()
        .map(file)
        .collect();
    assert_eq!(engine.visible_indices(&entries, "/"), vec![1, 2, 4]);
    assert_eq!(
        FilterEngine::empty(Side::Remote).visible_indices(&entries, "/"),
        vec![0, 1, 2, 3, 4]
    );
    assert!(engine.visible_indices(&[], "/").is_empty());
}

#[test]
fn active_set_selection() {
    let a = named("a", vec![name(StringOp::Equals, "x")]);
    let mut s = settings_with(vec![a], &[], &[]);
    s.sets.push(FilterSet {
        name: "other".to_owned(),
        local: vec!["a".to_owned(), "a".to_owned()],
        remote: vec![],
    });
    let (e, _) = FilterEngine::new(&s, Side::Local, UtcOffset::UTC);
    assert!(!e.is_active());
    s.active_set = "other".to_owned();
    let (e, _) = FilterEngine::new(&s, Side::Local, UtcOffset::UTC);
    assert_eq!(e.filters().len(), 1, "duplicates in a set compile once");
    // Unknown active set → first set.
    s.active_set = "nope".to_owned();
    assert_eq!(s.active().map(|s| s.name.as_str()), Some("s"));
    s.sets.clear();
    assert_eq!(s.active(), None);
    let (e, errors) = FilterEngine::new(&s, Side::Local, UtcOffset::UTC);
    assert!(!e.is_active() && errors.is_empty());
}

#[test]
fn settings_validation_fixes_sets() {
    let (s, warnings) = crate::settings::Settings::from_json_lenient(&serde_json::json!({
        "filters": {"sets": [], "active_set": "x"}
    }));
    assert_eq!(s.filters.sets, vec![FilterSet::empty("default")]);
    assert_eq!(s.filters.active_set, "default");
    let paths: Vec<_> = warnings.iter().map(|w| w.path.as_str()).collect();
    assert_eq!(paths, ["filters.sets", "filters.active_set"]);

    let (s, warnings) = crate::settings::Settings::from_json_lenient(&serde_json::json!({
        "filters": {"sets": [{"name": "work", "local": [], "remote": ["Git directories"]}],
                    "active_set": "nope"}
    }));
    assert_eq!(s.filters.active_set, "work");
    assert_eq!(warnings.len(), 1);
    let (e, _) = FilterEngine::new(&s.filters, Side::Remote, UtcOffset::UTC);
    assert!(e.excluded(&Entry::new(".git", EntryKind::Dir), "/"));
}

// ---- quick filter ---------------------------------------------------------------------

#[test]
fn quick_filter_glob_vs_substring() {
    let g = QuickFilter::parse("*.txt").unwrap();
    assert!(g.is_glob());
    assert!(g.matches("a.txt") && g.matches("A.TXT") && !g.matches("a.txt.bak"));
    let s = QuickFilter::parse("report").unwrap();
    assert!(!s.is_glob());
    assert!(s.matches("Q3 REPORT final.pdf") && s.matches("report") && !s.matches("repo"));
    let q = QuickFilter::parse("file?.[ch]").unwrap();
    assert!(q.matches("FILE1.C") && !q.matches("file10.c"));
    // Spaces are meaningful.
    let sp = QuickFilter::parse(" a").unwrap();
    assert!(sp.matches("x a") && !sp.matches("a"));
}

#[test]
fn quick_filter_invalid_glob_falls_back_to_substring() {
    let q = QuickFilter::parse("a[b").unwrap();
    assert!(!q.is_glob());
    assert!(q.matches("XA[BY") && !q.matches("ab"));
}

#[test]
fn quick_filter_empty_is_none() {
    assert!(QuickFilter::parse("").is_none());
    assert!(QuickFilter::parse(" ").is_some());
}

// ---- serde ----------------------------------------------------------------------------

#[test]
fn serde_representation() {
    let f = Filter {
        name: "x".to_owned(),
        applies_to: AppliesTo::Dirs,
        match_mode: MatchMode::NotAll,
        case_sensitive: false,
        scope: FilterScope::RemoteOnly,
        conditions: vec![
            name(StringOp::BeginsWith, "a"),
            Condition::Size {
                op: NumOp::Greater,
                value: 10,
            },
            Condition::Attribute {
                attr: AttrFlag::ReadOnly,
                set: true,
            },
            Condition::Permission {
                bit: PermBit::OtherWrite,
                set: false,
            },
            Condition::Date {
                op: DateOp::Before,
                value: date!(2026 - 10 - 08),
            },
        ],
        builtin: false,
    };
    let json = serde_json::to_value(&f).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "name": "x", "applies_to": "dirs", "match_mode": "not_all",
            "case_sensitive": false, "scope": "remote_only", "builtin": false,
            "conditions": [
                {"type": "name", "op": "begins_with", "value": "a"},
                {"type": "size", "op": "greater", "value": 10},
                {"type": "attribute", "attr": "read_only", "set": true},
                {"type": "permission", "bit": "other_write", "set": false},
                {"type": "date", "op": "before", "value": "2026-10-08"}
            ]
        })
    );
    assert_eq!(serde_json::from_value::<Filter>(json).unwrap(), f);
    // `builtin` defaults to false; bad dates are rejected.
    let no_builtin = serde_json::json!({
        "name": "x", "applies_to": "both", "match_mode": "any", "case_sensitive": true,
        "scope": "both", "conditions": []
    });
    assert!(
        !serde_json::from_value::<Filter>(no_builtin)
            .unwrap()
            .builtin
    );
    assert!(
        serde_json::from_value::<Condition>(
            serde_json::json!({"type": "date", "op": "equals", "value": "2026-13-01"})
        )
        .is_err()
    );
}

#[test]
fn settings_filters_section_snapshot() {
    let text = serde_json::to_string_pretty(&FilterSettings::default()).unwrap();
    insta::assert_snapshot!(text);
}

// ---- property tests -------------------------------------------------------------------

fn arb_entry() -> impl Strategy<Value = Entry> {
    let kind = prop_oneof![
        Just(EntryKind::File),
        Just(EntryKind::Dir),
        Just(EntryKind::Other),
        prop::option::of(prop_oneof![
            Just(SymlinkTarget::Dir),
            Just(SymlinkTarget::File),
            Just(SymlinkTarget::Broken),
            Just(SymlinkTarget::Other),
        ])
        .prop_map(|target_kind| EntryKind::Symlink {
            target: None,
            target_kind
        }),
    ];
    let perms = prop::option::of(
        (
            prop::option::of(0u32..0o7777),
            prop::option::of("\\PC{0,4}"),
        )
            .prop_map(|(mode, raw)| Permissions { mode, raw }),
    );
    let modified = prop::option::of(
        (
            -2_000_000_000i64..4_000_000_000,
            prop_oneof![
                Just(Precision::Day),
                Just(Precision::Minute),
                Just(Precision::Second),
                Just(Precision::Millis)
            ],
        )
            .prop_map(|(secs, p)| {
                Timestamp::new(
                    OffsetDateTime::from_unix_timestamp(secs).unwrap_or(OffsetDateTime::UNIX_EPOCH),
                    p,
                )
            }),
    );
    (
        any::<String>(),
        kind,
        prop::option::of(any::<u64>()),
        modified,
        perms,
        any::<bool>(),
    )
        .prop_map(|(name, kind, size, modified, permissions, hidden)| Entry {
            name,
            kind,
            size,
            modified,
            permissions,
            owner: None,
            group: None,
            hidden,
        })
}

fn arb_condition() -> impl Strategy<Value = Condition> {
    let sop = prop_oneof![
        Just(StringOp::Contains),
        Just(StringOp::NotContains),
        Just(StringOp::Equals),
        Just(StringOp::NotEquals),
        Just(StringOp::BeginsWith),
        Just(StringOp::EndsWith),
        Just(StringOp::Regex),
        Just(StringOp::Glob),
    ];
    let value = prop_oneof!["\\PC{0,8}", Just(".*".to_owned()), Just("*".to_owned())];
    prop_oneof![
        (sop.clone(), value.clone()).prop_map(|(op, value)| Condition::Name { op, value }),
        (sop, value).prop_map(|(op, value)| Condition::Path { op, value }),
        (
            prop_oneof![
                Just(NumOp::Equals),
                Just(NumOp::NotEquals),
                Just(NumOp::Greater),
                Just(NumOp::Less)
            ],
            any::<u64>()
        )
            .prop_map(|(op, value)| Condition::Size { op, value }),
        (any::<bool>(), any::<bool>()).prop_map(|(h, set)| Condition::Attribute {
            attr: if h {
                AttrFlag::Hidden
            } else {
                AttrFlag::ReadOnly
            },
            set
        }),
        (0usize..9, any::<bool>()).prop_map(|(i, set)| Condition::Permission {
            bit: PermBit::ALL[i],
            set
        }),
        (
            prop_oneof![
                Just(DateOp::Equals),
                Just(DateOp::NotEquals),
                Just(DateOp::Before),
                Just(DateOp::After)
            ],
            -100_000i32..100_000
        )
            .prop_map(|(op, days)| Condition::Date {
                op,
                value: date!(2000 - 01 - 01)
                    .checked_add(time::Duration::days(days.into()))
                    .unwrap_or(date!(2000 - 01 - 01)),
            }),
    ]
}

fn arb_filter() -> impl Strategy<Value = Filter> {
    (
        prop_oneof![
            Just(AppliesTo::Files),
            Just(AppliesTo::Dirs),
            Just(AppliesTo::Both)
        ],
        prop_oneof![
            Just(MatchMode::All),
            Just(MatchMode::Any),
            Just(MatchMode::None),
            Just(MatchMode::NotAll)
        ],
        any::<bool>(),
        prop::collection::vec(arb_condition(), 0..5),
    )
        .prop_map(|(a, m, cs, conds)| filter(a, m, cs, conds))
}

proptest! {
    #[test]
    fn prop_match_mode_identities(truths in prop::collection::vec(any::<bool>(), 1..8)) {
        let conds: Vec<Condition> = truths
            .iter()
            .map(|t| name(StringOp::Equals, if *t { "abc" } else { "zzz" }))
            .collect();
        let m = |mode| matches(&filter(AppliesTo::Both, mode, true, conds.clone()), &file("abc"));
        let n = truths.iter().filter(|t| **t).count();
        prop_assert_eq!(m(MatchMode::None), !m(MatchMode::Any));
        prop_assert_eq!(m(MatchMode::NotAll), !m(MatchMode::All));
        prop_assert_eq!(m(MatchMode::All), n == truths.len());
        prop_assert_eq!(m(MatchMode::Any), n >= 1);
    }

    #[test]
    fn prop_never_panics_on_arbitrary_entries(
        entry in arb_entry(),
        parent in any::<String>(),
        filters in prop::collection::vec(arb_filter(), 0..4),
        offset_h in -12i8..=14,
    ) {
        let offset = UtcOffset::from_hms(offset_h, 0, 0).unwrap_or(UtcOffset::UTC);
        for f in builtin_filters().iter().chain(&filters) {
            if let Ok(c) = CompiledFilter::compile(f, offset) {
                let _ = c.matches(&entry, &parent);
            }
            let _ = validate_filter(f, &[]);
        }
        let _ = QuickFilter::parse(&entry.name).map(|q| q.matches(&parent));
    }

    #[test]
    fn prop_case_insensitive_equals_matches_lowercased(s in "[ -~]{0,16}") {
        let f = one(name(StringOp::Equals, &s), false);
        let lower = s.to_lowercase();
        let upper = s.to_uppercase();
        prop_assert!(matches(&f, &file(&lower)));
        prop_assert!(matches(&f, &file(&upper)));
        prop_assert!(matches(&f, &file(&s)));
    }
}
