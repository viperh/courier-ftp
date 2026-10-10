# T48 — Directory comparison engine

**Phase:** E Transfers · **Milestone:** M6 · **Depends on:** T02, T47 · **Crate(s):** `courier-ftp-core` (`compare` module) · **FEATURES.md:** §7
**Related (integrates with, not blocking):** T13, T66

## Goal

Compare the local and remote listings currently shown and classify every name the
way FileZilla's directory comparison does: present on one side only, newer on one
side, different size, or identical. The result is a list of aligned rows so both panes
can show the same name on the same line, with placeholder rows where one side has
no entry. The engine is pure (no I/O) and fast enough for 100 000 entries per side.

## Context

- Before: T02 gives `Entry`, `EntryKind`, `SymlinkTarget`, `Timestamp { time, precision }` (helpers `truncated`, `cmp_coarse`, `abs_diff_coarse`) with
  `Precision { Day, Minute, Second, Millis }`; T13 already converted LIST times to UTC
  using the site's time zone offset (MLSD is UTC); T47 gives `FilterEngine::equivalent`.
- After: T66 renders the rows in both panes (colours, lockstep cursor, "select all rows
  with status X") and turns comparison on/off; T53 shares the name ordering rules
  (natural sort, folders first).
- The inputs are the entries **after** filters (T47) and quick filter (T53) were
  applied; the engine does not filter again.

## Technical specification

### Types and APIs

Module `courier_ftp_core::compare`.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompareMode { Size, ModificationTime }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameCase { Sensitive, Insensitive }

impl NameCase {
    /// Insensitive when either side is case-insensitive.
    pub fn for_sides(left_insensitive: bool, right_insensitive: bool) -> Self;
    /// Local side: true on Windows and macOS.
    pub fn local_is_insensitive() -> bool;
    /// Remote side: true for server types / path styles `Dos` and `Vms`.
    pub fn remote_is_insensitive(style: PathStyle) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareOpts {
    pub mode: CompareMode,            // default ModificationTime (FileZilla default)
    pub threshold_minutes: u32,       // default 1; 0..=1440
    pub hide_identical: bool,         // default false
    pub name_case: NameCase,
    pub order: NameOrder,
}

/// Row order; the panes use the same order while comparison is on (T66).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameOrder {
    pub dirs_first: bool,             // interface.dirs_first (T05 bool, default true)
    pub natural: bool,                // interface.natural_sort (file2 < file10)
    pub case_sensitive: bool,         // interface.sort_case_sensitive
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RowStatus {
    Equal,          // files: identical by the chosen mode
    OnlyLeft,       // yellow
    OnlyRight,      // yellow
    LeftNewer,      // green on the left
    RightNewer,     // green on the right
    SizeDiffers,    // red
    KindDiffers,    // red: a file on one side, a directory on the other
    DirBoth,        // directory on both sides (not recursed)
    Unknown,        // the needed data is missing on at least one side
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComparedRow {
    pub left: Option<usize>,          // index into the left input slice
    pub right: Option<usize>,         // index into the right input slice
    pub status: RowStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatusCounts { /* one usize per RowStatus */ }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparedListing {
    pub rows: Vec<ComparedRow>,
    pub counts: StatusCounts,         // counted before hide_identical
    /// Active filters differ between sides (FileZilla requires identical filtering).
    pub filters_differ: bool,
}

pub fn compare(
    left: &[Entry],
    right: &[Entry],
    opts: &CompareOpts,
    filters: (&FilterEngine, &FilterEngine),
) -> ComparedListing;

/// The sort key used for names; shared with T53 so both orders agree.
pub fn name_sort_key(name: &str, order: NameOrder) -> NameKey;
```

### Behaviour

**1. Keys.** Each entry's match key = its name normalised to Unicode NFC
(`unicode-normalization` crate; macOS local names are often NFD) and, when
`name_case == Insensitive`, lower-cased with `str::to_lowercase`. Entries named `.` or
`..` are ignored (the UI adds `..`).

**2. Kind class.** `Dir` and symlinks with `target_kind = Some(SymlinkTarget::Dir)` are *dirs*;
everything else is a *file* (same rule as T47).

**3. Pairing.** Group both sides by key (`HashMap<Key, SmallVec<[usize; 1]>>`). For each
key present on both sides:
- If both groups have one entry: pair them.
- Otherwise (only possible with case-insensitive matching, e.g. `A` and `a` on a
  case-sensitive server versus a Windows local dir): first pair entries whose names are
  byte-identical, then pair the remaining ones in sorted-name order one to one;
  leftovers become one-sided rows.

**4. Status of a pair** (first matching rule wins):

| # | Condition | Status |
|---|---|---|
| 1 | dir / dir | `DirBoth` |
| 2 | dir / file or file / dir | `KindDiffers` |
| 3 | mode `Size`: both sizes known, equal | `Equal` |
| 4 | mode `Size`: both sizes known, different | `SizeDiffers` |
| 5 | mode `Size`: a size unknown | `Unknown` |
| 6 | mode `ModificationTime`: both mtimes known, `d = trunc(L) - trunc(R)` with `p` = the coarser precision of the two; `d > threshold` | `LeftNewer` |
| 7 | same, `d < -threshold` | `RightNewer` |
| 8 | same, `|d| <= threshold`: both sizes known and different | `SizeDiffers` |
| 9 | same, `|d| <= threshold`: otherwise | `Equal` |
| 10 | mode `ModificationTime`: an mtime unknown, both sizes known and different | `SizeDiffers` |
| 11 | mode `ModificationTime`: an mtime unknown, otherwise | `Unknown` |

`trunc(t)` truncates the UTC datetime to precision `p` (`Day` → 00:00:00 of the UTC
date, `Minute` → seconds = 0, `Second` → nanoseconds = 0, `Millis` → to the
millisecond); this is T02's `Timestamp::truncated`, and `|d|` is
`Timestamp::abs_diff_coarse`, with the sign from `Timestamp::cmp_coarse`. `threshold = threshold_minutes × 60 s`. With `Day` precision and the
default threshold, dates one day apart are newer and same-day times are equal: the
engine never reports "newer" from precision noise. A one-sided entry is `OnlyLeft` /
`OnlyRight` regardless of kind.

**5. Order.** Rows are sorted by `(class_rank, name_sort_key(display_name), tie)` where
`class_rank` is 0 for dirs and 1 for files when `dirs_first` is true, and 0 for all
when false;
`display_name` is the left name when present, else the right one; for a
`KindDiffers` pair the class is the left entry's class. `name_sort_key` implements
natural ordering (digit runs compared numerically, leading zeros as a tiebreak) and
the case rule of `NameOrder`; `tie` = byte order of the original names, so the
order is total and deterministic.

**6. Hide identical.** When `hide_identical` is set, `Equal` rows are removed after
counting. `DirBoth` rows stay (they are needed to navigate; FileZilla also keeps
directories).

**7. Filter warning.** `filters_differ = !filters.0.equivalent(filters.1)`.

**Complexity.** O((n + m) log(n + m)) time, O(n + m) extra memory. Target: 100 000
entries per side compared in < 50 ms (release).

### Data formats and configuration

The compare options are UI state persisted by T66 as
`pub struct CompareSettings { pub mode: CompareMode, pub threshold_minutes: u32, pub hide_identical: bool }`
(`#[serde(default, rename_all = "snake_case")]`, defined in this module) in the settings section `compare`
(the section is added to T05's `Settings` by this task, so T48 and T66 share one
definition; saved with `Settings::save_user`):

| Key | Type | Default |
|---|---|---|
| `compare.mode` | `"size"` \| `"modification_time"` | `"modification_time"` |
| `compare.threshold_minutes` | u32, 0..=1440 | `1` (out of range → default + warning) |
| `compare.hide_identical` | bool | `false` |

`NameOrder` comes from `interface.dirs_first`, `interface.natural_sort` and
`interface.sort_case_sensitive` (T05/T53). `NameCase` is derived, not configured.

### Errors

Not applicable: `compare` is total and returns no errors. Invalid settings are handled
by T05 validation (fallback to defaults).

### Security and logging

- Names are untrusted server data; they are only compared. NFC normalisation and
  lower-casing never fail and allocate at most a copy of each name.
- No logging inside the engine (it is pure). T66 may log counts at `debug`.

## Implementation steps

1. Types, defaults, `compare` settings section (T05) and `NameCase` helpers.
2. `name_sort_key` with natural sort; tests shared with T53's expectations.
3. Key normalisation (NFC + case) and pairing including case-collision groups.
4. Status rules for `Size` and `ModificationTime` with precision truncation.
5. Ordering, `hide_identical`, counts, `filters_differ`.
6. Criterion bench `compare_100k` and module docs with the rule table.

## Acceptance criteria

- [ ] AC1 Every `RowStatus` is produced by at least one table test, and every row of the status table (rules 1–11) has a test.
- [ ] AC2 Precision: Minute vs Second timestamps 40 s apart → `Equal` with threshold 0; Day precision on one side and the same UTC date on the other → `Equal`; dates one day apart → newer.
- [ ] AC3 Threshold: 61 s difference with Second precision → newer at threshold 1, `Equal` at threshold 2.
- [ ] AC4 Rows are aligned: every row has at least one side, each input index appears exactly once, and the row order matches `NameOrder` for `dirs_first` true and false, with and without natural sort.
- [ ] AC5 Case-insensitive matching pairs `Index.HTML` with `index.html`; with `A` and `a` on one side and `a` on the other, `a`/`a` pair and `A` is one-sided.
- [ ] AC6 NFD `é` (local) pairs with NFC `é` (remote).
- [ ] AC7 `hide_identical` removes `Equal` rows only and `counts` still include them.
- [ ] AC8 `filters_differ` is true exactly when `FilterEngine::equivalent` is false.
- [ ] AC9 100 000 + 100 000 entries compared in < 50 ms (criterion bench `compare_100k`, gated in `scripts/bench-gates.toml`).
- [ ] AC10 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os` pass.

## Tests

### Unit tests
- `status_rules_table` — one row per rule 1–11 (constructed entries) → expected status. AC1.
- `one_sided_entries_are_only_left_or_right` — files and dirs. AC1.
- `kind_differs_file_vs_dir` — AC1.
- `precision_minute_vs_second_is_equal` — AC2.
- `day_precision_same_date_equal_next_date_newer` — AC2.
- `threshold_boundaries` — 59 s, 60 s, 61 s with threshold 1; 61 s with threshold 2. AC3.
- `unknown_mtime_falls_back_to_size` — rules 10 and 11.
- `alignment_dirs_first_and_natural_sort` — `file2`, `file10`, `Dir`, `a` on both sides with gaps. AC4.
- `case_insensitive_pairs_case_variants` and `case_collision_pairs_exact_then_rest` — AC5.
- `nfc_nfd_names_pair` — AC6.
- `hide_identical_keeps_dirs_and_counts` — AC7.
- `filters_differ_flag` — AC8.
- `dot_and_dotdot_ignored`.
- `name_case_for_sides` — Windows/macOS local, `PathStyle::Dos`/`Vms` remote.

### Property / fuzz tests
- `prop_every_index_appears_once` — random entry lists (names with collisions, mixed kinds, optional sizes/mtimes): each left and right index appears exactly once across rows. AC4.
- `prop_rows_sorted_by_name_order` — consecutive rows satisfy the ordering. AC4.
- `prop_swap_sides_mirrors_status` — `compare(a, b)` and `compare(b, a)` give mirrored statuses (`LeftNewer` ↔ `RightNewer`, `OnlyLeft` ↔ `OnlyRight`). AC1.

### Snapshot tests
Not applicable (rendering is T66).

### Integration tests
- Bench `compare_100k` (criterion, `crates/courier-ftp-core/benches/compare.rs`). AC9.

### End-to-end tests
None (T66 covers comparison against real listings).

## Out of scope

- Recursive comparison of subdirectories and any one-way or two-way sync (FileZilla
  has none; FEATURES.md §7).
- Content comparison (checksums).
- The colours, lockstep cursor and selection helpers (T66).

## Open questions

- FileZilla's time mode, as far as documented, compares only dates; rule 8 (equal time
  but different size → `SizeDiffers`) is an addition that flags truncated uploads. Keep
  it, or report `Equal` as FileZilla does? Product decision for the owner.

(Resolved by the coordinator: T66 adopts this task's `CompareOpts { order, name_case, .. }`,
the `filters` argument and `RowStatus::KindDiffers`.)
