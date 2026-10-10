//! The view pipeline: hidden entries, T47 filters, the quick filter, then the sort.
//! Pure and `Send`, so large listings are built on the blocking pool.

use std::{borrow::Cow, cmp::Ordering};

use courier_ftp_core::{
    backend::Listing,
    filters::{FilterEngine, QuickFilter},
    model::Entry,
    settings::{Column, SortSpec},
};

use super::{format::type_description, natural::natural_key};

/// Above this many entries the view is built off the UI thread.
pub(crate) const INLINE_LIMIT: usize = 10_000;

/// Everything [`build`] reads besides the listing and the filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ViewParams {
    /// Show `Entry.hidden` entries.
    pub show_hidden: bool,
    /// Quick filter text (empty: none).
    pub quick: String,
    /// Sort column and direction.
    pub sort: SortSpec,
    /// `interface.natural_sort`.
    pub natural: bool,
    /// `interface.sort_case_sensitive`.
    pub case_sensitive: bool,
    /// `interface.dirs_first`.
    pub dirs_first: bool,
}

/// The result of [`build`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BuiltView {
    /// Indices into `listing.entries`, sorted.
    pub view: Vec<u32>,
    /// Entries hidden by T47 filters.
    pub filtered: usize,
}

/// The precomputed sort key of one entry.
struct SortKey<'a> {
    name: NameKey<'a>,
    secondary: Secondary<'a>,
    dir: bool,
}

/// The name part of a sort key: a natural key (`memcmp` order) or the folded name.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum NameKey<'a> {
    Natural(Vec<u8>),
    Plain(Cow<'a, str>),
}

enum Secondary<'a> {
    None,
    Size(Option<u64>),
    Text(Cow<'a, str>),
    Time(Option<time::OffsetDateTime>),
}

fn secondary<'a>(e: &'a Entry, col: Column) -> Secondary<'a> {
    match col {
        Column::Name => Secondary::None,
        Column::Size => Secondary::Size(if e.is_dir_like() { None } else { e.size }),
        Column::Type => Secondary::Text(type_description(e)),
        Column::Modified => Secondary::Time(e.modified.map(|t| t.time)),
        Column::Permissions => Secondary::Text(Cow::Owned(super::format::format_permissions(e))),
        Column::OwnerGroup => Secondary::Text(Cow::Owned(super::format::format_owner(e))),
    }
}

fn cmp_secondary(a: &Secondary<'_>, b: &Secondary<'_>) -> Ordering {
    match (a, b) {
        (Secondary::Size(x), Secondary::Size(y)) => x.cmp(y),
        (Secondary::Text(x), Secondary::Text(y)) => x.cmp(y),
        (Secondary::Time(x), Secondary::Time(y)) => x.cmp(y),
        _ => Ordering::Equal,
    }
}

/// The name as sorted: unchanged when case-sensitive or already lower case.
fn fold(name: &str, case_sensitive: bool) -> Cow<'_, str> {
    if case_sensitive {
        return Cow::Borrowed(name);
    }
    if name.is_ascii() {
        if name.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(name.to_ascii_lowercase())
        } else {
            Cow::Borrowed(name)
        }
    } else {
        Cow::Owned(name.to_lowercase())
    }
}

/// Builds the view of `listing` (see the T53 pipeline). `parent` is the directory as
/// the filters see it.
pub(crate) fn build(
    listing: &Listing,
    params: &ViewParams,
    filters: &FilterEngine,
    parent: &str,
) -> BuiltView {
    let quick = if params.quick.is_empty() {
        None
    } else {
        QuickFilter::parse(&params.quick)
    };
    let mut filtered = 0;
    let mut view: Vec<u32> = Vec::with_capacity(listing.entries.len());
    for (i, e) in listing.entries.iter().enumerate() {
        if e.hidden && !params.show_hidden {
            continue;
        }
        if filters.excluded(e, parent) {
            filtered += 1;
            continue;
        }
        if quick.as_ref().is_some_and(|q| !q.matches(&e.name)) {
            continue;
        }
        if let Ok(i) = u32::try_from(i) {
            view.push(i);
        }
    }
    sort(&listing.entries, &mut view, params);
    BuiltView { view, filtered }
}

/// Sorts `view` (indices into `entries`) by `params`: directories first (both
/// directions) when `dirs_first`, then the column, then the name, then bytes, then the
/// index, so the order is total.
pub(crate) fn sort(entries: &[Entry], view: &mut [u32], params: &ViewParams) {
    let keys: Vec<SortKey<'_>> = view
        .iter()
        .map(|&i| {
            let e = &entries[i as usize];
            SortKey {
                name: {
                    let folded = fold(&e.name, params.case_sensitive);
                    if params.natural {
                        NameKey::Natural(natural_key(&folded))
                    } else {
                        NameKey::Plain(folded)
                    }
                },
                secondary: secondary(e, params.sort.column),
                dir: e.is_dir_like(),
            }
        })
        .collect();
    // Sort positions into `keys`, then map back to entry indices.
    let mut order: Vec<u32> = (0..u32::try_from(view.len()).unwrap_or(u32::MAX)).collect();
    order.sort_unstable_by(|&x, &y| {
        let (ka, kb) = (&keys[x as usize], &keys[y as usize]);
        if params.dirs_first && ka.dir != kb.dir {
            return if ka.dir {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        let (ia, ib) = (view[x as usize], view[y as usize]);
        let primary = cmp_secondary(&ka.secondary, &kb.secondary)
            .then_with(|| ka.name.cmp(&kb.name))
            .then_with(|| entries[ia as usize].name.cmp(&entries[ib as usize].name))
            .then_with(|| ia.cmp(&ib));
        if params.sort.descending {
            primary.reverse()
        } else {
            primary
        }
    });
    let sorted: Vec<u32> = order.iter().map(|&p| view[p as usize]).collect();
    view.copy_from_slice(&sorted);
}

#[cfg(test)]
mod tests {
    use courier_ftp_core::{filters::Side as FilterSide, model::EntryKind};
    use proptest::prelude::*;

    use super::*;

    pub(crate) fn listing(entries: Vec<Entry>) -> Listing {
        Listing {
            dir: courier_ftp_core::model::RemotePath::root(),
            entries,
            fetched_at: tokio::time::Instant::now(),
            raw: None,
        }
    }

    fn params() -> ViewParams {
        ViewParams {
            show_hidden: true,
            quick: String::new(),
            sort: SortSpec::default(),
            natural: true,
            case_sensitive: false,
            dirs_first: true,
        }
    }

    fn names(l: &Listing, v: &[u32]) -> Vec<String> {
        v.iter()
            .map(|&i| l.entries[i as usize].name.clone())
            .collect()
    }

    fn file(n: &str) -> Entry {
        Entry::new(n, EntryKind::File)
    }

    fn dir(n: &str) -> Entry {
        Entry::new(n, EntryKind::Dir)
    }

    #[test]
    fn sort_dirs_first_in_both_directions() {
        let l = listing(vec![file("b"), dir("z"), file("a"), dir("c")]);
        let none = FilterEngine::empty(FilterSide::Local);
        let mut p = params();
        let v = build(&l, &p, &none, "/").view;
        assert_eq!(names(&l, &v), ["c", "z", "a", "b"]);
        p.sort.descending = true;
        let v = build(&l, &p, &none, "/").view;
        assert_eq!(names(&l, &v), ["z", "c", "b", "a"]);
        p.dirs_first = false;
        p.sort.descending = false;
        let v = build(&l, &p, &none, "/").view;
        assert_eq!(names(&l, &v), ["a", "b", "c", "z"]);
    }

    #[test]
    fn sort_is_total_with_duplicate_folded_names() {
        let l = listing(vec![file("a"), file("B"), file("A"), file("b")]);
        let none = FilterEngine::empty(FilterSide::Local);
        let v = build(&l, &params(), &none, "/").view;
        assert_eq!(names(&l, &v), ["A", "a", "B", "b"]);
        let mut p = params();
        p.case_sensitive = true;
        let v = build(&l, &p, &none, "/").view;
        assert_eq!(names(&l, &v), ["A", "B", "a", "b"]);
    }

    #[test]
    fn natural_and_size_sort() {
        let mut big = file("file2");
        big.size = Some(100);
        let mut small = file("file10");
        small.size = Some(1);
        let l = listing(vec![big, small, file("file1")]);
        let none = FilterEngine::empty(FilterSide::Local);
        let v = build(&l, &params(), &none, "/").view;
        assert_eq!(names(&l, &v), ["file1", "file2", "file10"]);
        let mut p = params();
        p.natural = false;
        let v = build(&l, &p, &none, "/").view;
        assert_eq!(names(&l, &v), ["file1", "file10", "file2"]);
        p.sort.column = Column::Size;
        let v = build(&l, &p, &none, "/").view;
        assert_eq!(names(&l, &v), ["file1", "file10", "file2"]);
    }

    #[test]
    fn quick_filter_substring_and_glob() {
        let l = listing(vec![
            file("Index.HTML"),
            file("style.css"),
            file("x.html.bak"),
        ]);
        let none = FilterEngine::empty(FilterSide::Local);
        let mut p = params();
        p.quick = "html".into();
        assert_eq!(
            names(&l, &build(&l, &p, &none, "/").view),
            ["Index.HTML", "x.html.bak"]
        );
        p.quick = "*.html".into();
        assert_eq!(names(&l, &build(&l, &p, &none, "/").view), ["Index.HTML"]);
        p.quick = "s?yle*".into();
        assert_eq!(names(&l, &build(&l, &p, &none, "/").view), ["style.css"]);
    }

    #[test]
    fn hidden_entries_are_dropped_unless_shown() {
        let mut h = file(".env");
        h.hidden = true;
        let l = listing(vec![h, file("a")]);
        let none = FilterEngine::empty(FilterSide::Local);
        let mut p = params();
        p.show_hidden = false;
        assert_eq!(names(&l, &build(&l, &p, &none, "/").view), ["a"]);
    }

    fn arb_entry() -> impl Strategy<Value = Entry> {
        (
            "[a-cA-C0-9.]{1,6}",
            any::<bool>(),
            any::<bool>(),
            proptest::option::of(0u64..5000),
        )
            .prop_map(|(n, d, h, s)| {
                let mut e = if d { dir(&n) } else { file(&n) };
                e.hidden = h;
                e.size = s;
                e
            })
    }

    proptest! {
        #[test]
        fn prop_view_is_permutation_of_unfiltered_entries(
            entries in proptest::collection::vec(arb_entry(), 0..60),
            show_hidden in any::<bool>(),
            natural in any::<bool>(),
            cs in any::<bool>(),
            desc in any::<bool>(),
            col in 0usize..6,
            quick in "[a.0-9]{0,2}",
        ) {
            let (kept, _) = Listing::clean_entries(entries);
            let l = listing(kept);
            let p = ViewParams {
                show_hidden,
                quick: quick.clone(),
                sort: SortSpec { column: Column::ALL[col], descending: desc },
                natural,
                case_sensitive: cs,
                dirs_first: true,
            };
            let none = FilterEngine::empty(FilterSide::Local);
            let v = build(&l, &p, &none, "/").view;
            let mut seen = v.clone();
            seen.sort_unstable();
            seen.dedup();
            prop_assert_eq!(seen.len(), v.len());
            let q = QuickFilter::parse(&quick);
            let expected: Vec<u32> = l.entries.iter().enumerate()
                .filter(|(_, e)| show_hidden || !e.hidden)
                .filter(|(_, e)| q.as_ref().is_none_or(|q| q.matches(&e.name)))
                .map(|(i, _)| u32::try_from(i).unwrap_or(0))
                .collect();
            prop_assert_eq!(seen, expected);
            // Same input, same order.
            prop_assert_eq!(build(&l, &p, &none, "/").view, v);
        }
    }
}
