use pretty_assertions::assert_eq;
use proptest::prelude::*;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

use super::*;
use crate::filters::{AppliesTo, Condition, Filter, FilterScope, MatchMode, StringOp};
use crate::model::{EntryKind, Precision};

use RowStatus::*;

fn ts(t: OffsetDateTime, p: Precision) -> Timestamp {
    Timestamp::new(t, p)
}

fn file_at(name: &str, size: u64, t: OffsetDateTime, p: Precision) -> Entry {
    Entry {
        modified: Some(ts(t, p)),
        ..Entry::file(name, size)
    }
}

fn time_opts() -> CompareOpts {
    CompareOpts {
        mode: CompareMode::ModificationTime,
        ..CompareOpts::default()
    }
}

/// `(left name, right name, status)` per row, `-` for a placeholder.
fn render(
    left: &[Entry],
    right: &[Entry],
    listing: &ComparedListing,
) -> Vec<(String, String, RowStatus)> {
    let name =
        |side: &[Entry], i: Option<usize>| i.map_or("-".to_owned(), |i| side[i].name.clone());
    listing
        .rows
        .iter()
        .map(|r| (name(left, r.left), name(right, r.right), r.status))
        .collect()
}

fn rows(left: &[Entry], right: &[Entry], opts: &CompareOpts) -> Vec<(String, String, RowStatus)> {
    render(left, right, &compare(left, right, opts))
}

fn row(l: &str, r: &str, s: RowStatus) -> (String, String, RowStatus) {
    (l.to_owned(), r.to_owned(), s)
}

#[test]
fn file_statuses_by_size() {
    let cases: &[(Entry, Entry, RowStatus)] = &[
        (Entry::file("f", 10), Entry::file("f", 10), Equal),
        (Entry::file("f", 10), Entry::file("f", 11), SizeDiffers),
        (Entry::file("f", 0), Entry::file("f", 0), Equal),
        (
            Entry::new("f", EntryKind::File),
            Entry::file("f", 1),
            Unknown,
        ),
        (
            Entry::file("f", 1),
            Entry::new("f", EntryKind::File),
            Unknown,
        ),
        (Entry::dir("d"), Entry::dir("d"), DirBoth),
        // Size mode ignores times.
        (
            file_at("f", 5, datetime!(2020-01-01 0:00 UTC), Precision::Second),
            file_at("f", 5, datetime!(2024-01-01 0:00 UTC), Precision::Second),
            Equal,
        ),
    ];
    for (l, r, want) in cases {
        let listing = compare(
            std::slice::from_ref(l),
            std::slice::from_ref(r),
            &CompareOpts::default(),
        );
        assert_eq!(
            listing.rows,
            [ComparedRow {
                left: Some(0),
                right: Some(0),
                status: *want
            }],
            "{l:?} vs {r:?}"
        );
    }
}

#[test]
fn file_statuses_by_time() {
    use Precision::*;
    let t = datetime!(2021-01-05 12:30:00 UTC);
    // (left time, left precision, right time, right precision, threshold, status)
    let cases: &[(
        OffsetDateTime,
        Precision,
        OffsetDateTime,
        Precision,
        u32,
        RowStatus,
    )] = &[
        (t, Second, t, Second, 1, Equal),
        (t, Second, t, Second, 0, Equal),
        // Within the threshold (inclusive).
        (t + Duration::seconds(59), Second, t, Second, 1, Equal),
        (t + Duration::seconds(60), Second, t, Second, 1, Equal),
        (t + Duration::seconds(61), Second, t, Second, 1, LeftNewer),
        (t, Second, t + Duration::seconds(61), Second, 1, RightNewer),
        // Threshold 0: any whole-second difference counts.
        (t + Duration::seconds(1), Second, t, Second, 0, LeftNewer),
        (t, Second, t + Duration::seconds(1), Second, 0, RightNewer),
        (t + Duration::minutes(10), Second, t, Second, 9, LeftNewer),
        (t + Duration::minutes(10), Second, t, Second, 10, Equal),
        // Minute vs second precision: the seconds carry no meaning.
        (t, Minute, t + Duration::seconds(59), Second, 0, Equal),
        (t + Duration::seconds(59), Second, t, Minute, 0, Equal),
        (t, Minute, t + Duration::seconds(60), Second, 0, RightNewer),
        (t + Duration::seconds(60), Second, t, Minute, 0, LeftNewer),
        (t, Minute, t + Duration::seconds(119), Second, 1, Equal),
        (t, Minute, t + Duration::seconds(120), Second, 1, RightNewer),
        // Millisecond noise against seconds.
        (t + Duration::milliseconds(999), Millis, t, Second, 0, Equal),
        (
            t + Duration::milliseconds(1_000),
            Millis,
            t,
            Second,
            0,
            LeftNewer,
        ),
        // Day precision: any time on the same day is equal, the next day is newer.
        (
            datetime!(2021-01-05 0:00 UTC),
            Day,
            datetime!(2021-01-05 23:59:59 UTC),
            Second,
            0,
            Equal,
        ),
        (
            datetime!(2021-01-05 0:00 UTC),
            Day,
            datetime!(2021-01-06 0:00:01 UTC),
            Second,
            1,
            RightNewer,
        ),
        (
            datetime!(2021-01-06 0:00 UTC),
            Day,
            datetime!(2021-01-05 23:59 UTC),
            Minute,
            1,
            LeftNewer,
        ),
    ];
    for &(lt, lp, rt, rp, threshold, want) in cases {
        let opts = CompareOpts {
            threshold_minutes: threshold,
            ..time_opts()
        };
        let l = [file_at("f", 1, lt, lp)];
        let r = [file_at("f", 2, rt, rp)];
        let got = compare(&l, &r, &opts).rows[0].status;
        assert_eq!(
            got, want,
            "{lt} {lp:?} vs {rt} {rp:?}, threshold {threshold}"
        );
        // Mirrored.
        let got = compare(&r, &l, &opts).rows[0].status;
        assert_eq!(got, want.mirrored(), "mirrored: {lt} {lp:?} vs {rt} {rp:?}");
    }
}

#[test]
fn time_mode_unknown_and_offsets() {
    let opts = time_opts();
    let dated = file_at("f", 1, datetime!(2021-01-05 12:00 UTC), Precision::Second);
    let undated = Entry::file("f", 1);
    assert_eq!(
        compare(
            std::slice::from_ref(&dated),
            std::slice::from_ref(&undated),
            &opts
        )
        .rows[0]
            .status,
        Unknown
    );
    assert_eq!(compare(&[undated], &[dated], &opts).rows[0].status, Unknown);

    // The same instant in two offsets is equal.
    let a = file_at(
        "f",
        1,
        datetime!(2021-01-05 14:00 +02:00),
        Precision::Second,
    );
    let b = file_at("f", 1, datetime!(2021-01-05 12:00 UTC), Precision::Second);
    assert_eq!(compare(&[a], &[b], &opts).rows[0].status, Equal);

    // A day-precision date in +02:00 covers 22:00 UTC the day before.
    let day = file_at("f", 1, datetime!(2021-01-05 0:00 +02:00), Precision::Day);
    let late = file_at("f", 1, datetime!(2021-01-04 23:00 UTC), Precision::Second);
    assert_eq!(
        compare(std::slice::from_ref(&day), &[late], &opts).rows[0].status,
        Equal
    );
    let earlier = file_at("f", 1, datetime!(2021-01-04 21:00 UTC), Precision::Second);
    assert_eq!(compare(&[day], &[earlier], &opts).rows[0].status, LeftNewer);
}

#[test]
fn only_one_side_and_dirs() {
    let left = [Entry::file("a", 1), Entry::dir("d1"), Entry::dir("shared")];
    let right = [Entry::dir("shared"), Entry::file("b", 1), Entry::dir("d2")];
    assert_eq!(
        rows(&left, &right, &CompareOpts::default()),
        [
            row("d1", "-", OnlyLeft),
            row("-", "d2", OnlyRight),
            row("shared", "shared", DirBoth),
            row("a", "-", OnlyLeft),
            row("-", "b", OnlyRight),
        ]
    );
}

#[test]
fn alignment_dirs_first_and_mixed() {
    let left = [
        Entry::file("zeta.txt", 1),
        Entry::dir("src"),
        Entry::file("Makefile", 2),
        Entry::file("file10", 3),
        Entry::file("file2", 3),
    ];
    let right = [
        Entry::file("file2", 3),
        Entry::dir("docs"),
        Entry::file("readme", 1),
        Entry::dir("src"),
        Entry::file("zeta.txt", 9),
    ];
    assert_eq!(
        rows(&left, &right, &CompareOpts::default()),
        [
            row("-", "docs", OnlyRight),
            row("src", "src", DirBoth),
            row("file2", "file2", Equal),
            row("file10", "-", OnlyLeft),
            row("Makefile", "-", OnlyLeft),
            row("-", "readme", OnlyRight),
            row("zeta.txt", "zeta.txt", SizeDiffers),
        ]
    );
    let mixed = CompareOpts {
        dirs_first: false,
        ..CompareOpts::default()
    };
    assert_eq!(
        rows(&left, &right, &mixed),
        [
            row("-", "docs", OnlyRight),
            row("file2", "file2", Equal),
            row("file10", "-", OnlyLeft),
            row("Makefile", "-", OnlyLeft),
            row("-", "readme", OnlyRight),
            row("src", "src", DirBoth),
            row("zeta.txt", "zeta.txt", SizeDiffers),
        ]
    );
    let plain = CompareOpts {
        natural_sort: false,
        ..CompareOpts::default()
    };
    let names: Vec<_> = rows(&left, &right, &plain)
        .into_iter()
        .map(|r| r.0)
        .collect();
    assert_eq!(
        names,
        ["-", "src", "file10", "file2", "Makefile", "-", "zeta.txt"]
    );
}

#[test]
fn dir_and_file_of_same_name_do_not_pair() {
    let left = [Entry::dir("x")];
    let right = [Entry::file("x", 1)];
    for dirs_first in [true, false] {
        let opts = CompareOpts {
            dirs_first,
            ..CompareOpts::default()
        };
        assert_eq!(
            rows(&left, &right, &opts),
            [row("x", "-", OnlyLeft), row("-", "x", OnlyRight)]
        );
        assert_eq!(
            rows(&right, &left, &opts),
            [row("-", "x", OnlyRight), row("x", "-", OnlyLeft)]
        );
    }
}

#[test]
fn symlinks_follow_their_target_kind() {
    let link_to_dir = Entry::new(
        "www",
        EntryKind::Symlink {
            target: Some("/srv/www".into()),
            target_kind: Some(Box::new(EntryKind::Dir)),
        },
    );
    assert_eq!(
        rows(
            &[link_to_dir],
            &[Entry::dir("www")],
            &CompareOpts::default()
        ),
        [row("www", "www", DirBoth)]
    );
    let link = Entry {
        size: Some(4),
        ..Entry::new(
            "l",
            EntryKind::Symlink {
                target: None,
                target_kind: None,
            },
        )
    };
    assert_eq!(
        rows(&[link], &[Entry::file("l", 4)], &CompareOpts::default()),
        [row("l", "l", Equal)]
    );
}

#[test]
fn case_sensitivity_of_names() {
    let left = [Entry::file("README", 1), Entry::file("b", 1)];
    let right = [Entry::file("readme", 1), Entry::file("B", 2)];
    assert_eq!(
        rows(&left, &right, &CompareOpts::default()),
        [
            row("-", "B", OnlyRight),
            row("b", "-", OnlyLeft),
            row("README", "-", OnlyLeft),
            row("-", "readme", OnlyRight),
        ]
    );
    let insensitive = CompareOpts {
        case_sensitive_names: false,
        ..CompareOpts::default()
    };
    assert_eq!(
        rows(&left, &right, &insensitive),
        [row("b", "B", SizeDiffers), row("README", "readme", Equal)]
    );
    // A Unix server may have both `A` and `a`: the first pairs, the other is alone.
    let left = [Entry::file("a", 1)];
    let right = [Entry::file("a", 1), Entry::file("A", 1)];
    assert_eq!(
        rows(&left, &right, &insensitive),
        [row("a", "A", Equal), row("-", "a", OnlyRight)]
    );
}

#[test]
fn windows_like_sides_match_case_insensitively() {
    use PathStyle as P;
    use ServerType as S;
    assert!(names_case_sensitive_on(false, P::Unix, S::Auto));
    assert!(names_case_sensitive_on(false, P::Unix, S::Unix));
    assert!(names_case_sensitive_on(false, P::Vms, S::Vms));
    assert!(!names_case_sensitive_on(true, P::Unix, S::Auto));
    assert!(!names_case_sensitive_on(false, P::Dos, S::Auto));
    assert!(!names_case_sensitive_on(false, P::Unix, S::Dos));
    assert_eq!(names_case_sensitive(P::Unix, S::Auto), !cfg!(windows));
}

#[test]
fn hide_identical() {
    let left = [
        Entry::dir("d"),
        Entry::file("same", 1),
        Entry::file("diff", 1),
        Entry::file("mine", 1),
    ];
    let right = [
        Entry::dir("d"),
        Entry::file("same", 1),
        Entry::file("diff", 2),
    ];
    let opts = CompareOpts {
        hide_identical: true,
        ..CompareOpts::default()
    };
    assert_eq!(
        rows(&left, &right, &opts),
        [
            row("d", "d", DirBoth),
            row("diff", "diff", SizeDiffers),
            row("mine", "-", OnlyLeft)
        ]
    );
    let opts = CompareOpts {
        hide_identical_dirs: true,
        ..opts
    };
    assert_eq!(
        rows(&left, &right, &opts),
        [row("diff", "diff", SizeDiffers), row("mine", "-", OnlyLeft)]
    );
    // `hide_identical_dirs` alone hides nothing.
    let opts = CompareOpts {
        hide_identical: false,
        ..opts
    };
    assert_eq!(rows(&left, &right, &opts).len(), 4);
}

#[test]
fn highlights_and_helpers() {
    use Highlight as H;
    use Side::{Local, Remote};
    let table = [
        (Equal, H::None, H::None),
        (OnlyLeft, H::Lonely, H::None),
        (OnlyRight, H::None, H::Lonely),
        (LeftNewer, H::Newer, H::None),
        (RightNewer, H::None, H::Newer),
        (SizeDiffers, H::Different, H::Different),
        (DirBoth, H::None, H::None),
        (Unknown, H::None, H::None),
    ];
    for (status, local, remote) in table {
        assert_eq!(
            (status.highlight(Local), status.highlight(Remote)),
            (local, remote),
            "{status:?}"
        );
        assert_eq!(status.mirrored().highlight(Local), remote, "{status:?}");
        assert_eq!(status.mirrored().mirrored(), status);
    }

    let left = [
        Entry::file("a", 1),
        Entry::file("b", 1),
        Entry::file("c", 1),
    ];
    let right = [
        Entry::file("c", 2),
        Entry::file("b", 1),
        Entry::file("d", 1),
    ];
    let listing = compare(&left, &right, &CompareOpts::default());
    assert_eq!(listing.indices(Local, |h| h == H::Lonely), [0]);
    assert_eq!(listing.indices(Remote, |h| h == H::Lonely), [2]);
    assert_eq!(listing.indices(Remote, |h| h == H::Different), [0]);
    assert_eq!(listing.indices(Local, |h| h != H::None), [0, 2]);
    assert_eq!(listing.row_of(Remote, 0), Some(2));
    assert_eq!(listing.row_of(Local, 0), Some(0));
    assert_eq!(listing.row_of(Local, 9), None);
    let row = listing.rows[3];
    assert_eq!((row.index(Local), row.index(Remote)), (None, Some(2)));
}

#[test]
fn warns_when_filters_differ() {
    let tmp = Filter {
        name: "tmp".into(),
        applies_to: AppliesTo::Both,
        match_mode: MatchMode::Any,
        case_sensitive: false,
        conditions: vec![Condition::Name {
            op: StringOp::EndsWith,
            value: ".tmp".into(),
        }],
        scope: FilterScope::Both,
    };
    let (with, _) = FilterEngine::new([&tmp]);
    let (with2, _) = FilterEngine::new([&tmp]);
    let none = FilterEngine::default();
    let entries = [Entry::file("a", 1)];
    let opts = CompareOpts::default();
    assert!(compare_with_filters(&entries, &entries, &opts, &with, &none).filters_differ);
    assert!(!compare_with_filters(&entries, &entries, &opts, &with, &with2).filters_differ);
    let plain = compare(&entries, &entries, &opts);
    assert!(!plain.filters_differ);
    assert_eq!(
        compare_with_filters(&entries, &entries, &opts, &none, &none),
        plain
    );
}

#[test]
fn empty_listings() {
    let opts = CompareOpts::default();
    assert!(compare(&[], &[], &opts).rows.is_empty());
    assert_eq!(
        rows(&[Entry::file("a", 1)], &[], &opts),
        [row("a", "-", OnlyLeft)]
    );
    assert_eq!(
        rows(&[], &[Entry::dir("d")], &opts),
        [row("-", "d", OnlyRight)]
    );
}

#[test]
fn opts_serde_defaults() {
    let opts: CompareOpts = serde_json::from_str(r#"{"mode":"modification_time"}"#).unwrap();
    assert_eq!(
        opts,
        CompareOpts {
            mode: CompareMode::ModificationTime,
            ..CompareOpts::default()
        }
    );
    assert_eq!(CompareOpts::default().threshold_minutes, 1);
}

#[test]
fn natural_order() {
    let mut names = vec!["file10", "file2", "file1", "file02", "a", "file"];
    names.sort_by(|a, b| natural_cmp(a, b));
    assert_eq!(names, ["a", "file", "file1", "file2", "file02", "file10"]);
    assert_eq!(natural_cmp("v1.10", "v1.9"), Ordering::Greater);
    assert_eq!(
        natural_cmp("99999999999999999999a", "99999999999999999999b"),
        Ordering::Less
    );
}

// --- property tests ---

fn arb_entry() -> impl Strategy<Value = Entry> {
    let name = prop::sample::select(vec![
        "a", "A", "b", "B", "f1", "f2", "f10", "F10", "x", "Zed",
    ]);
    let time = (
        0i64..5,
        prop::sample::select(vec![Precision::Day, Precision::Minute, Precision::Second]),
    );
    (
        name,
        any::<bool>(),
        prop::option::of(0u64..3),
        prop::option::of(time),
    )
        .prop_map(|(name, dir, size, time)| {
            let mut e = if dir {
                Entry::dir(name)
            } else {
                Entry::new(name, EntryKind::File)
            };
            if !dir {
                e.size = size;
            }
            e.modified = time.map(|(m, p)| {
                ts(
                    datetime!(2021-01-05 12:00 UTC) + Duration::seconds(m * 40),
                    p,
                )
            });
            e
        })
}

/// A listing as a directory has it: no two entries with the same name.
fn arb_listing() -> impl Strategy<Value = Vec<Entry>> {
    prop::collection::vec(arb_entry(), 0..10).prop_map(|mut v| {
        let mut seen = std::collections::HashSet::new();
        v.retain(|e| seen.insert(e.name.clone()));
        v
    })
}

fn arb_opts() -> impl Strategy<Value = CompareOpts> {
    (
        any::<bool>(),
        0u32..3,
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(time, threshold_minutes, dirs_first, case_sensitive_names, natural_sort)| {
                CompareOpts {
                    mode: if time {
                        CompareMode::ModificationTime
                    } else {
                        CompareMode::Size
                    },
                    threshold_minutes,
                    dirs_first,
                    case_sensitive_names,
                    natural_sort,
                    ..CompareOpts::default()
                }
            },
        )
}

fn same_name(a: &str, b: &str, opts: &CompareOpts) -> bool {
    if opts.case_sensitive_names {
        a == b
    } else {
        a.to_lowercase() == b.to_lowercase()
    }
}

proptest! {
    #[test]
    fn every_entry_shows_exactly_once(left in arb_listing(), right in arb_listing(), opts in arb_opts()) {
        let listing = compare(&left, &right, &opts);
        let mut l: Vec<_> = listing.rows.iter().filter_map(|r| r.left).collect();
        let mut r: Vec<_> = listing.rows.iter().filter_map(|r| r.right).collect();
        l.sort_unstable();
        r.sort_unstable();
        prop_assert_eq!(l, (0..left.len()).collect::<Vec<_>>());
        prop_assert_eq!(r, (0..right.len()).collect::<Vec<_>>());
        for row in &listing.rows {
            prop_assert!(row.left.is_some() || row.right.is_some());
            match (row.left, row.right) {
                (Some(_), None) => prop_assert_eq!(row.status, OnlyLeft),
                (None, Some(_)) => prop_assert_eq!(row.status, OnlyRight),
                (Some(i), Some(j)) => {
                    let (a, b) = (&left[i], &right[j]);
                    prop_assert!(same_name(&a.name, &b.name, &opts));
                    prop_assert_eq!(a.is_dir_like(), b.is_dir_like());
                    prop_assert_eq!(row.status == DirBoth, a.is_dir_like());
                    prop_assert!(!matches!(row.status, OnlyLeft | OnlyRight));
                }
                (None, None) => unreachable!(),
            }
        }
    }

    #[test]
    fn unpaired_entries_have_no_partner(left in arb_listing(), right in arb_listing(), opts in arb_opts()) {
        // With unique names under the case rule, an entry is alone only when
        // the other side has nothing of the same name and kind.
        let unique = |v: &[Entry]| {
            let mut seen = std::collections::HashSet::new();
            v.iter().all(|e| seen.insert((if opts.case_sensitive_names { e.name.clone() } else { e.name.to_lowercase() }, e.is_dir_like())))
        };
        prop_assume!(unique(&left) && unique(&right));
        let listing = compare(&left, &right, &opts);
        for row in &listing.rows {
            if let (Some(i), None) = (row.left, row.right) {
                prop_assert!(!right.iter().any(|b| same_name(&left[i].name, &b.name, &opts) && b.is_dir_like() == left[i].is_dir_like()));
            }
            if let (None, Some(j)) = (row.left, row.right) {
                prop_assert!(!left.iter().any(|a| same_name(&a.name, &right[j].name, &opts) && a.is_dir_like() == right[j].is_dir_like()));
            }
        }
    }

    #[test]
    fn swapping_sides_mirrors(left in arb_listing(), right in arb_listing(), opts in arb_opts()) {
        let ab = compare(&left, &right, &opts);
        let ba = compare(&right, &left, &opts);
        let mirrored: Vec<_> = ba.rows.iter().map(|r| ComparedRow { left: r.right, right: r.left, status: r.status.mirrored() }).collect();
        prop_assert_eq!(ab.rows, mirrored);
    }

    #[test]
    fn rows_follow_display_order(left in arb_listing(), right in arb_listing(), opts in arb_opts()) {
        let listing = compare(&left, &right, &opts);
        let keys: Vec<Key<'_>> = listing.rows.iter().map(|r| {
            let e = r.left.map_or_else(|| &right[r.right.unwrap_or_default()], |i| &left[i]);
            Key { index: 0, dir: e.is_dir_like(), folded: e.name.to_lowercase(), name: &e.name }
        }).collect();
        for w in keys.windows(2) {
            prop_assert_ne!(match_order(&w[0], &w[1], &opts), Ordering::Greater, "{} then {}", w[0].name, w[1].name);
        }
        if opts.dirs_first {
            let first_file = keys.iter().position(|k| !k.dir).unwrap_or(keys.len());
            prop_assert!(keys[first_file..].iter().all(|k| !k.dir));
        }
    }

    #[test]
    fn hide_identical_only_filters(left in arb_listing(), right in arb_listing(), opts in arb_opts(), dirs in any::<bool>()) {
        let all = compare(&left, &right, &opts);
        let hidden = compare(&left, &right, &CompareOpts { hide_identical: true, hide_identical_dirs: dirs, ..opts.clone() });
        let expected: Vec<_> = all.rows.into_iter().filter(|r| r.status != Equal && !(dirs && r.status == DirBoth)).collect();
        prop_assert_eq!(hidden.rows, expected);
    }

    #[test]
    fn a_listing_equals_itself(entries in arb_listing(), opts in arb_opts()) {
        let listing = compare(&entries, &entries, &opts);
        prop_assert_eq!(listing.rows.len(), entries.len());
        for row in &listing.rows {
            prop_assert_eq!(row.left, row.right);
            let e = &entries[row.left.unwrap_or_default()];
            let known = match opts.mode {
                CompareMode::Size => e.size.is_some(),
                CompareMode::ModificationTime => e.modified.is_some(),
            };
            let want = if e.is_dir_like() { DirBoth } else if known { Equal } else { Unknown };
            prop_assert_eq!(row.status, want);
        }
    }

    #[test]
    fn statuses_match_the_mode(left in arb_listing(), right in arb_listing(), opts in arb_opts()) {
        for row in compare(&left, &right, &opts).rows {
            match opts.mode {
                CompareMode::Size => prop_assert!(!matches!(row.status, LeftNewer | RightNewer)),
                CompareMode::ModificationTime => prop_assert!(row.status != SizeDiffers),
            }
        }
    }
}
