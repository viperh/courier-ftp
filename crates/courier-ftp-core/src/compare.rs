//! Directory comparison engine (T48), as FileZilla's directory comparison.
//!
//! [`compare`] takes the two listings the panes currently show (left = local,
//! right = remote, already filtered by the T47 filters and with the site's
//! server time-zone offset applied by the listing parser, T13) and returns
//! [`ComparedListing`]: one [`ComparedRow`] per line, aligned so that both panes
//! show the same name on the same line, with an empty placeholder on the side
//! where an entry is missing.
//!
//! # Using it from the UI (T66)
//!
//! ```
//! use courier_ftp_core::compare::{compare, CompareMode, CompareOpts, Highlight, RowStatus};
//! use courier_ftp_core::filters::Side;
//! use courier_ftp_core::model::Entry;
//!
//! let local = vec![Entry::file("a.txt", 1), Entry::file("b.txt", 2)];
//! let remote = vec![Entry::file("b.txt", 3), Entry::dir("www")];
//! let opts = CompareOpts { mode: CompareMode::Size, ..CompareOpts::default() };
//! let listing = compare(&local, &remote, &opts);
//!
//! // Directories first, then files, by name.
//! let statuses: Vec<_> = listing.rows.iter().map(|r| r.status).collect();
//! assert_eq!(statuses, [RowStatus::OnlyRight, RowStatus::OnlyLeft, RowStatus::SizeDiffers]);
//!
//! // Row 0 is a placeholder on the local side and yellow on the remote side.
//! let row = listing.rows[0];
//! assert_eq!(row.index(Side::Local), None);
//! assert_eq!(row.index(Side::Remote), Some(1)); // index into `remote`
//! assert_eq!(row.highlight(Side::Remote), Highlight::Lonely);
//! ```
//!
//! - Render `listing.rows` in order in both panes; a row whose
//!   [`ComparedRow::index`] is `None` on a side is a blank placeholder line there.
//!   The rows have their own order (name, directories first when
//!   [`CompareOpts::dirs_first`]); the pane's sort column does not apply while
//!   comparing. Both cursors use the same row index.
//! - Colour each side with [`ComparedRow::highlight`]: [`Highlight::Lonely`]
//!   yellow, [`Highlight::Newer`] green, [`Highlight::Different`] red.
//! - "Select all yellow/green/red rows on this side":
//!   [`ComparedListing::indices`] with a predicate on [`Highlight`].
//! - Use [`compare_with_filters`] to get [`ComparedListing::filters_differ`],
//!   and warn once when it is set (FileZilla requires identical filtering).
//! - Name matching: set [`CompareOpts::case_sensitive_names`] from
//!   [`names_case_sensitive`] (case-insensitive when either side is Windows-like).
//! - Rebuild the listing whenever either listing, the filters or the options
//!   change; it holds indices into the slices it was built from.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use time::Duration;

use crate::filters::{FilterEngine, Side};
use crate::model::item::ServerType;
use crate::model::{Entry, PathStyle, Timestamp};

/// What two files with the same name are compared by.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompareMode {
    /// Sizes: different sizes are [`RowStatus::SizeDiffers`].
    #[default]
    Size,
    /// Modification times, with [`CompareOpts::threshold_minutes`] of tolerance:
    /// [`RowStatus::LeftNewer`] / [`RowStatus::RightNewer`].
    ModificationTime,
}

/// Options for [`compare`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default)]
pub struct CompareOpts {
    /// Compare files by size or by modification time.
    pub mode: CompareMode,
    /// In [`CompareMode::ModificationTime`], times that differ by at most this
    /// many minutes (after truncating both to the coarser precision) are equal.
    /// Default 1 (FileZilla's default).
    pub threshold_minutes: u32,
    /// Directories before files (the `interface.dirs_first` setting).
    pub dirs_first: bool,
    /// Drop [`RowStatus::Equal`] rows.
    pub hide_identical: bool,
    /// With `hide_identical`, also drop [`RowStatus::DirBoth`] rows.
    pub hide_identical_dirs: bool,
    /// Match names case-sensitively. See [`names_case_sensitive`].
    pub case_sensitive_names: bool,
    /// Order names naturally (`file2` before `file10`), like the panes
    /// (`interface.natural_sort`).
    pub natural_sort: bool,
}

impl Default for CompareOpts {
    fn default() -> Self {
        Self {
            mode: CompareMode::Size,
            threshold_minutes: 1,
            dirs_first: true,
            hide_identical: false,
            hide_identical_dirs: false,
            case_sensitive_names: true,
            natural_sort: true,
        }
    }
}

/// Whether names should match case-sensitively: not when the local machine is
/// Windows, nor when the remote server is a DOS/Windows one (the site's server
/// type is `dos`, or the detected path style is [`PathStyle::Dos`]).
pub fn names_case_sensitive(remote_style: PathStyle, server_type: ServerType) -> bool {
    names_case_sensitive_on(cfg!(windows), remote_style, server_type)
}

/// [`names_case_sensitive`] with the local platform given explicitly.
pub fn names_case_sensitive_on(
    local_is_windows: bool,
    remote_style: PathStyle,
    server_type: ServerType,
) -> bool {
    !(local_is_windows || remote_style == PathStyle::Dos || server_type == ServerType::Dos)
}

/// How one aligned row compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowStatus {
    /// Files on both sides that compare equal.
    Equal,
    /// Only the left (local) side has this entry.
    OnlyLeft,
    /// Only the right (remote) side has this entry.
    OnlyRight,
    /// Time mode: the left file is newer.
    LeftNewer,
    /// Time mode: the right file is newer.
    RightNewer,
    /// Size mode: the sizes differ.
    SizeDiffers,
    /// A directory on both sides (not compared further, no recursion).
    DirBoth,
    /// Files on both sides, but the compared attribute (size or time) is
    /// missing on at least one side.
    Unknown,
}

/// The colour of one side of a row (T66: yellow, green, red).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Highlight {
    /// No colour (also used for a placeholder line).
    None,
    /// Yellow: the entry exists on this side only.
    Lonely,
    /// Green: this side's file is newer.
    Newer,
    /// Red: the sizes differ.
    Different,
}

impl RowStatus {
    /// The colour of `side` (left = [`Side::Local`]). Only the newer file of a
    /// pair is green; both sides of a size difference are red; a placeholder
    /// line has no colour.
    pub fn highlight(self, side: Side) -> Highlight {
        match (self, side) {
            (RowStatus::OnlyLeft, Side::Local) | (RowStatus::OnlyRight, Side::Remote) => {
                Highlight::Lonely
            }
            (RowStatus::LeftNewer, Side::Local) | (RowStatus::RightNewer, Side::Remote) => {
                Highlight::Newer
            }
            (RowStatus::SizeDiffers, _) => Highlight::Different,
            _ => Highlight::None,
        }
    }

    /// The same status seen with the sides swapped.
    pub fn mirrored(self) -> Self {
        match self {
            RowStatus::OnlyLeft => RowStatus::OnlyRight,
            RowStatus::OnlyRight => RowStatus::OnlyLeft,
            RowStatus::LeftNewer => RowStatus::RightNewer,
            RowStatus::RightNewer => RowStatus::LeftNewer,
            other => other,
        }
    }
}

/// One aligned line of a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ComparedRow {
    /// Index into the left (local) slice, `None` for a placeholder.
    pub left: Option<usize>,
    /// Index into the right (remote) slice, `None` for a placeholder.
    pub right: Option<usize>,
    /// How the two sides compare.
    pub status: RowStatus,
}

impl ComparedRow {
    /// The entry index on `side` (left = [`Side::Local`]).
    pub fn index(&self, side: Side) -> Option<usize> {
        match side {
            Side::Local => self.left,
            Side::Remote => self.right,
        }
    }

    /// The colour of `side`, see [`RowStatus::highlight`].
    pub fn highlight(&self, side: Side) -> Highlight {
        self.status.highlight(side)
    }
}

/// The result of [`compare`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComparedListing {
    /// The aligned rows, in display order.
    pub rows: Vec<ComparedRow>,
    /// The active filters differ between the sides ([`compare_with_filters`]);
    /// the UI should warn, since rows may be "only on one side" merely because
    /// the other side hides them.
    pub filters_differ: bool,
}

impl ComparedListing {
    /// The entry indices on `side` whose row colour on that side satisfies
    /// `pred`, in row order ("select all green rows on this side").
    pub fn indices(&self, side: Side, pred: impl Fn(Highlight) -> bool) -> Vec<usize> {
        self.rows
            .iter()
            .filter(|r| pred(r.highlight(side)))
            .filter_map(|r| r.index(side))
            .collect()
    }

    /// The row showing entry `index` of `side`, to move both cursors there.
    pub fn row_of(&self, side: Side, index: usize) -> Option<usize> {
        self.rows.iter().position(|r| r.index(side) == Some(index))
    }
}

/// Compare two listings. See the [module docs](self).
pub fn compare(left: &[Entry], right: &[Entry], opts: &CompareOpts) -> ComparedListing {
    let left_keys = sorted_keys(left, opts);
    let right_keys = sorted_keys(right, opts);
    let mut rows = Vec::with_capacity(left_keys.len().max(right_keys.len()));
    let (mut i, mut j) = (0, 0);
    while i < left_keys.len() || j < right_keys.len() {
        let ord = match (left_keys.get(i), right_keys.get(j)) {
            (Some(l), Some(r)) => match_order(l, r, opts),
            (Some(_), None) => Ordering::Less,
            _ => Ordering::Greater,
        };
        let row = match ord {
            Ordering::Less => {
                let row = ComparedRow {
                    left: Some(left_keys[i].index),
                    right: None,
                    status: RowStatus::OnlyLeft,
                };
                i += 1;
                row
            }
            Ordering::Greater => {
                let row = ComparedRow {
                    left: None,
                    right: Some(right_keys[j].index),
                    status: RowStatus::OnlyRight,
                };
                j += 1;
                row
            }
            Ordering::Equal => {
                let (l, r) = (left_keys[i].index, right_keys[j].index);
                i += 1;
                j += 1;
                ComparedRow {
                    left: Some(l),
                    right: Some(r),
                    status: pair_status(&left[l], &right[r], opts),
                }
            }
        };
        if !hidden(row.status, opts) {
            rows.push(row);
        }
    }
    ComparedListing {
        rows,
        filters_differ: false,
    }
}

/// [`compare`], also setting [`ComparedListing::filters_differ`] when the
/// filters active on the two sides are not [`FilterEngine::equivalent`].
pub fn compare_with_filters(
    left: &[Entry],
    right: &[Entry],
    opts: &CompareOpts,
    left_filters: &FilterEngine,
    right_filters: &FilterEngine,
) -> ComparedListing {
    ComparedListing {
        filters_differ: !left_filters.equivalent(right_filters),
        ..compare(left, right, opts)
    }
}

/// Compare with runs of ASCII digits as numbers: `file2` < `file10`. Only
/// identical strings compare `Equal` (`01` and `1` differ: shorter first).
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let mut a = a.chars().peekable();
    let mut b = b.chars().peekable();
    loop {
        match (a.peek(), b.peek()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let take = |it: &mut std::iter::Peekable<std::str::Chars>| {
                    let mut s = String::new();
                    while let Some(c) = it.peek().filter(|c| c.is_ascii_digit()) {
                        s.push(*c);
                        it.next();
                    }
                    s
                };
                let (na, nb) = (take(&mut a), take(&mut b));
                let (ta, tb) = (na.trim_start_matches('0'), nb.trim_start_matches('0'));
                let ord = ta
                    .len()
                    .cmp(&tb.len())
                    .then_with(|| ta.cmp(tb))
                    .then_with(|| na.len().cmp(&nb.len()));
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            (Some(x), Some(y)) => {
                let ord = x.cmp(y);
                if ord != Ordering::Equal {
                    return ord;
                }
                a.next();
                b.next();
            }
        }
    }
}

/// An entry prepared for sorting and merging.
struct Key<'a> {
    index: usize,
    dir: bool,
    folded: String,
    name: &'a str,
}

fn sorted_keys<'a>(entries: &'a [Entry], opts: &CompareOpts) -> Vec<Key<'a>> {
    let mut keys: Vec<Key<'a>> = entries
        .iter()
        .enumerate()
        .map(|(index, e)| Key {
            index,
            dir: e.is_dir_like(),
            folded: e.name.to_lowercase(),
            name: &e.name,
        })
        .collect();
    // Total order: the merge order, then the exact name (case-insensitive
    // duplicates such as `A` and `a` on a Unix server), then the input index.
    keys.sort_by(|a, b| {
        match_order(a, b, opts)
            .then_with(|| a.name.cmp(b.name))
            .then_with(|| a.index.cmp(&b.index))
    });
    keys
}

/// The display order; `Equal` exactly when two entries are the same item (same
/// name under the case rule, both directories or both not).
fn match_order(a: &Key<'_>, b: &Key<'_>, opts: &CompareOpts) -> Ordering {
    // `true` sorts after `false`, so compare b to a to put directories first.
    let dirs = b.dir.cmp(&a.dir);
    if opts.dirs_first && dirs != Ordering::Equal {
        return dirs;
    }
    let names = if opts.natural_sort {
        natural_cmp(&a.folded, &b.folded)
    } else {
        a.folded.cmp(&b.folded)
    };
    let names = if opts.case_sensitive_names {
        names.then_with(|| a.name.cmp(b.name))
    } else {
        names
    };
    // A directory and a file of the same name are different items; the
    // directory comes first.
    names.then(dirs)
}

fn pair_status(l: &Entry, r: &Entry, opts: &CompareOpts) -> RowStatus {
    if l.is_dir_like() {
        return RowStatus::DirBoth;
    }
    match opts.mode {
        CompareMode::Size => match (l.size, r.size) {
            (Some(a), Some(b)) if a == b => RowStatus::Equal,
            (Some(_), Some(_)) => RowStatus::SizeDiffers,
            _ => RowStatus::Unknown,
        },
        CompareMode::ModificationTime => match (&l.modified, &r.modified) {
            (Some(a), Some(b)) => time_status(a, b, opts.threshold_minutes),
            _ => RowStatus::Unknown,
        },
    }
}

/// Compare two times at the coarser precision, with `threshold_minutes` of
/// tolerance.
///
/// The finer time is first moved to the coarser one's UTC offset, so a
/// day-precision `2021-01-05` listed at `+02:00` truncates the other side to the
/// same calendar day.
fn time_status(l: &Timestamp, r: &Timestamp, threshold_minutes: u32) -> RowStatus {
    // Truncate the finer time to the coarser precision in the coarser one's offset.
    let coarsened = |fine: &Timestamp, coarse: &Timestamp| {
        Timestamp::new(fine.time.to_offset(coarse.time.offset()), coarse.precision).time
    };
    let (a, b) = match l.precision.cmp(&r.precision) {
        Ordering::Equal => (l.time, r.time),
        Ordering::Less => (l.time, coarsened(r, l)),
        Ordering::Greater => (coarsened(l, r), r.time),
    };
    let diff = a - b;
    let threshold = Duration::minutes(i64::from(threshold_minutes));
    if diff > threshold {
        RowStatus::LeftNewer
    } else if diff < -threshold {
        RowStatus::RightNewer
    } else {
        RowStatus::Equal
    }
}

fn hidden(status: RowStatus, opts: &CompareOpts) -> bool {
    opts.hide_identical
        && (status == RowStatus::Equal
            || (opts.hide_identical_dirs && status == RowStatus::DirBoth))
}

#[cfg(test)]
mod tests;
