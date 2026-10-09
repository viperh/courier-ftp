# T47 — Filename filter engine

**Phase:** E Transfers · **Milestone:** M1 · **Depends on:** T02, T05 · **Crate(s):** `courier-ftp-core` (`filters` module) · **Decisions:** D10 · **FEATURES.md:** §8
**Related (integrates with, not blocking):** T48, T53, T57

## Goal

FileZilla-style directory listing filters: named filters made of conditions that
**hide** matching entries in the panes and **skip** them in recursive operations,
grouped into filter sets with separate local and remote selections. The same
condition evaluator powers search (T49, where matches are *included*) and the pane
quick filter (T53). Evaluation is precompiled and fast enough for 100 000-entry
directories.

## Context

- Before: T02 gives `Entry`, `EntryKind`, `Timestamp`, `Permissions`, `RemotePath`,
  `LocalPath`, `Error`; T05 gives `Settings` with `#[serde(default)]` sections, validation
  that warns and falls back, and `Settings::save_user`. T05 lists `filters` as a section
  added by this task.
- After: T53 hides excluded entries and uses `QuickFilter`; T43 skips excluded entries
  and does not descend excluded directories when `filters.apply_to_transfers` is on;
  T48 uses `FilterEngine::equivalent` to warn; T49 reuses `Condition` and
  `CompiledFilter::matches`; T57 shows the indicator from `FilterEngine::is_active`;
  T67 edits filters and sets through `validate_filter` and `FilterSettings`.
- Workspace deps from T01: `regex`, `globset`, `time`, `serde`.

## Technical specification

### Types and APIs

Module `courier_ftp_core::filters`.

```rust
/// One named filter. A filter **excludes** an entry when it applies to the entry's
/// kind and its conditions match according to `match_mode` (FileZilla semantics).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filter {
    pub name: String,                 // unique, 1..=64 chars, no control chars
    pub applies_to: AppliesTo,        // Files | Dirs | Both
    pub match_mode: MatchMode,        // All | Any | None | NotAll
    pub case_sensitive: bool,
    pub scope: FilterScope,           // Both | LocalOnly | RemoteOnly
    pub conditions: Vec<Condition>,   // 0..=32
    #[serde(default)]
    pub builtin: bool,                // shipped default; T67 shows a tag and offers restore
}

pub enum AppliesTo { Files, Dirs, Both }
pub enum MatchMode { All, Any, None, NotAll }
pub enum FilterScope { Both, LocalOnly, RemoteOnly }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    Name { op: StringOp, value: String },
    /// Matches the path of the directory that contains the entry (not including the name).
    Path { op: StringOp, value: String },
    Size { op: NumOp, value: u64 },                 // bytes
    Attribute { attr: AttrFlag, set: bool },
    Permission { bit: PermBit, set: bool },
    /// Calendar day (`time::Date`, whole day, no time of day, no offset); `Equals` = the
    /// entry was modified on that day. Serialised as `"YYYY-MM-DD"`. T65's `parse_date`
    /// produces the same type.
    Date { op: DateOp, value: time::Date },
}

pub enum StringOp { Contains, NotContains, Equals, NotEquals, BeginsWith, EndsWith, Regex, Glob }
pub enum NumOp { Equals, NotEquals, Greater, Less }
pub enum DateOp { Equals, NotEquals, Before, After }
pub enum AttrFlag { Hidden, ReadOnly }
pub enum PermBit { UserRead, UserWrite, UserExec, GroupRead, GroupWrite, GroupExec,
                   OtherRead, OtherWrite, OtherExec }

/// A named selection of filters per side (FileZilla "filter sets").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterSet {
    pub name: String,
    pub local: Vec<String>,           // names of filters enabled for the local side
    pub remote: Vec<String>,
}

/// The `filters` settings section (added to T05 `Settings`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterSettings {
    pub filters: Vec<Filter>,         // default: builtin_filters()
    pub sets: Vec<FilterSet>,         // default: one empty set named "default"
    pub active_set: String,           // default: "default"
    pub apply_to_transfers: bool,     // default: true
}

impl FilterSettings {
    /// Re-add missing built-ins and reset built-ins whose definition was changed.
    /// User filters are untouched. Returns the names restored.
    pub fn restore_builtins(&mut self) -> Vec<String>;
    pub fn active(&self) -> Option<&FilterSet>;
}

pub fn builtin_filters() -> Vec<Filter>;

pub enum Side { Local, Remote }

/// Precompiled filters for one side. Cheap to share (`Arc` inside); immutable.
#[derive(Debug, Clone)]
pub struct FilterEngine { /* Arc<[CompiledFilter]>, side, local_offset */ }

impl FilterEngine {
    /// Lenient: filters that fail to compile are skipped and reported (used at load).
    pub fn new(settings: &FilterSettings, side: Side, local_offset: UtcOffset)
        -> (Self, Vec<FilterError>);
    /// No filters (nothing excluded).
    pub fn empty(side: Side) -> Self;
    /// True if `entry` (inside directory `parent`) is hidden / skipped.
    pub fn excluded(&self, entry: &Entry, parent: &str) -> bool;
    /// Indices of the entries that stay visible, in input order.
    pub fn visible_indices(&self, entries: &[Entry], parent: &str) -> Vec<usize>;
    pub fn is_active(&self) -> bool;
    /// Same effective filter definitions on both sides (names and scope ignored).
    pub fn equivalent(&self, other: &FilterEngine) -> bool;
}

/// One compiled filter; `matches` ignores `scope` (used directly by search, T49).
#[derive(Debug, Clone)]
pub struct CompiledFilter { /* ... */ }
impl CompiledFilter {
    pub fn compile(filter: &Filter, local_offset: UtcOffset) -> Result<Self, FilterError>;
    /// Applies-to check and conditions combined with the match mode.
    pub fn matches(&self, entry: &Entry, parent: &str) -> bool;
}

/// Pane quick filter (T53): transient, always case-insensitive.
#[derive(Debug, Clone)]
pub struct QuickFilter { /* Glob or substring */ }
impl QuickFilter {
    /// Text containing `*`, `?` or `[` is a glob over the whole name; otherwise a
    /// substring. Empty text → `None` (no filter). Invalid glob → treated as substring.
    pub fn parse(text: &str) -> Option<Self>;
    pub fn matches(&self, name: &str) -> bool;
}

/// Editor-time validation (T67): all problems, not just the first.
pub fn validate_filter(filter: &Filter, others: &[Filter]) -> Vec<FilterError>;
pub fn validate_settings(settings: &FilterSettings) -> Vec<FilterError>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    #[error("filter name is empty")] EmptyName,
    #[error("filter name `{0}` is longer than 64 characters")] NameTooLong(String),
    #[error("a filter named `{0}` already exists")] DuplicateName(String),
    #[error("filter `{filter}` has more than 32 conditions")] TooManyConditions { filter: String },
    #[error("filter `{filter}`: pattern is longer than 1024 characters")] PatternTooLong { filter: String },
    #[error("filter `{filter}`: invalid regular expression: {message}")] InvalidRegex { filter: String, message: String },
    #[error("filter `{filter}`: invalid glob: {message}")] InvalidGlob { filter: String, message: String },
    #[error("filter `{filter}` has no conditions and never matches")] NoConditions { filter: String },
    #[error("filter set `{set}` refers to unknown filter `{filter}`")] UnknownFilter { set: String, filter: String },
}
```

### Behaviour

**Kind resolution.** `EntryKind::Dir` → dir. `Symlink { target_kind: Some(SymlinkTarget::Dir), .. }` →
dir. Every other kind (`File`, `Other`, symlink to file or unknown target) → file.
`applies_to` mismatch → the filter does not match.

**Combining conditions** (`n` = number of conditions true):

| `match_mode` | Filter matches when |
|---|---|
| `All` | `n == len` |
| `Any` | `n >= 1` |
| `None` | `n == 0` |
| `NotAll` | `n < len` |

A filter with zero conditions never matches (FileZilla does the same; `validate_filter`
reports `NoConditions` as a warning-level error that does not block saving).
Evaluation short-circuits (`All` stops at the first false, `Any` at the first true,
and so on).

**Exclusion.** `FilterEngine::excluded` = any compiled filter for this side matches.
Filters for a side are: the names listed in the active set's `local`/`remote` list,
minus filters whose `scope` excludes that side. A set naming an unknown filter is
skipped for that name with `UnknownFilter`.

**Condition semantics** (any condition on data the entry lacks evaluates to `false`):

| Condition | Value compared | Rules |
|---|---|---|
| `Name` | `entry.name` | String op table below |
| `Path` | `parent` as passed by the caller (remote: `RemotePath` display, `/a/b`; local: native display path, `C:\x` or `/home/u`) | String op table below |
| `Size` | `entry.size` | Directories never match (`false`). `Greater`/`Less` strict. |
| `Attribute Hidden` | `entry.hidden` | `set` = expected value |
| `Attribute ReadOnly` | permissions | read-only = `mode` is `Some(m)` with `m & 0o222 == 0`, or `raw` contains `R` (Windows local); unknown permissions → `false` |
| `Permission` | `permissions.mode` (`Option<u32>`) bit (`UserRead` = 0o400 … `OtherExec` = 0o001) | unknown mode → `false` |
| `Date` | the entry's calendar date: `Precision::Day` timestamps use `Timestamp.time.date()` unchanged (T13 attaches no time-zone meaning to day-only dates); finer precisions are converted with `local_offset` first, then `.date()` | compared as whole days: `Equals`/`NotEquals` same day or not, `Before`/`After` strictly earlier/later day |

String operations (`ci` = `!case_sensitive`; case folding with `str::to_lowercase`
computed once per entry and cached for all conditions of all filters):

| Op | Matches when |
|---|---|
| `Contains` / `NotContains` | substring present / absent |
| `Equals` / `NotEquals` | whole string equal / not equal |
| `BeginsWith` / `EndsWith` | prefix / suffix |
| `Regex` | `regex::Regex::is_match` (unanchored; anchors are the user's choice); compiled with `RegexBuilder::case_insensitive(ci).size_limit(1 << 20).dfa_size_limit(1 << 20)` |
| `Glob` | `globset::GlobBuilder::new(v).case_insensitive(ci).literal_separator(false).backslash_escape(true)` matched against the whole string |

**Compilation.** `FilterEngine::new` compiles every selected filter once. Lowercase
values are precomputed. Patterns longer than 1024 characters are rejected
(`PatternTooLong`). On load (`new`), a filter that fails to compile is **disabled**
and returned as an error; the caller logs it with `warn!` (filter name and message,
no entry names) and the pane still works.

**Equivalence.** Two engines are equivalent when the multisets of their compiled
filter *definitions* (applies_to, match_mode, case_sensitive, conditions; ignoring
`name`, `scope`, `builtin`) are equal. Implementation: compare sorted vectors of a
canonical serialisation. Used by T48 to warn that comparison results are unreliable.

**Quick filter.** `QuickFilter::parse` trims nothing (spaces are meaningful), is always
case-insensitive, and matches only the name. It is independent of filter sets and
never affects transfers.

**Built-in filters** (`builtin: true`, none enabled in the default set, as in FileZilla):

| Name | Applies to | Mode | Case | Conditions |
|---|---|---|---|---|
| `CVS and SVN directories` | Dirs | Any | sensitive | Name Equals `CVS`; Name Equals `.svn` |
| `Git directories` | Dirs | Any | sensitive | Name Equals `.git` |
| `Temporary and backup files` | Files | Any | insensitive | Name EndsWith `~`; Name EndsWith `.bak`; Name EndsWith `.tmp`; Name EndsWith `.swp`; Name Glob `#*#` |
| `Configuration files` | Both | Any | sensitive | Name BeginsWith `.` |
| `OS metadata files` | Files | Any | insensitive | Name Equals `Thumbs.db`; Name Equals `.DS_Store`; Name Equals `desktop.ini` |

**Performance limits.** Evaluation is O(filters × conditions) per entry with no
allocation per entry except the cached lowercase name/path (one `String` each, only
when a case-insensitive string condition exists). Target: 10 000 entries × 10 regex
filters in < 10 ms (release build, CI runner); 100 000 entries in < 100 ms.

### Data formats and configuration

Settings section `filters` (in `crates/courier-ftp/config/config.json` defaults and user config, saved
through `Settings::save_user`, T05):

```json
"filters": {
  "filters": [
    { "name": "Git directories", "applies_to": "dirs", "match_mode": "any",
      "case_sensitive": true, "scope": "both", "builtin": true,
      "conditions": [ { "type": "name", "op": "equals", "value": ".git" } ] }
  ],
  "sets": [ { "name": "default", "local": [], "remote": [] } ],
  "active_set": "default",
  "apply_to_transfers": true
}
```

| Key | Type | Default | Notes |
|---|---|---|---|
| `filters.filters` | array of `Filter` | the five built-ins | Enum values serialise in `snake_case`. Dates as `"YYYY-MM-DD"`. |
| `filters.sets` | array of `FilterSet` | `[{"name":"default","local":[],"remote":[]}]` | At least one set; empty array → default restored with a warning. |
| `filters.active_set` | string | `"default"` | Unknown name → first set, warning. |
| `filters.apply_to_transfers` | bool | `true` | T43 skips excluded entries in recursive operations. |

`local_offset` is not a setting: the binary computes the local UTC offset once at
startup (before spawning threads, as `time` requires) and passes it in; fallback UTC.

### Errors

`FilterError` (above) for validation and compilation. When surfaced through the core
API it maps to `courier_ftp_core::Error::InvalidInput(message)`. Load-time problems
never abort startup (T05 rule): the filter is disabled and a warning is logged. In T67
the editor shows the error under the offending condition and blocks OK for every
variant except `NoConditions`.

### Security and logging

- Entry names and paths come from untrusted servers; the `regex` crate guarantees
  linear-time matching, and size limits bound compiled regex memory (1 MiB each).
  User patterns are capped at 1024 characters and 32 conditions per filter.
- Logs: `warn!` for disabled filters names the filter and the error only. Entry names
  and paths are never logged at `info`+; `trace!` may log per-entry decisions.
- No secrets involved.

## Implementation steps

1. Types, serde representation and defaults (`FilterSettings::default`, `builtin_filters`); add `filters: FilterSettings` to `Settings` (T05) and the defaults to `crates/courier-ftp/config/config.json`.
2. `validate_filter` / `validate_settings`, including set references.
3. `CompiledFilter::compile` and `matches` for Name/Path (all string ops), with the per-entry lowercase cache.
4. Size, Attribute, Permission and Date conditions; kind resolution.
5. `FilterEngine` (side selection, lenient load, `excluded`, `visible_indices`, `is_active`, `equivalent`).
6. `QuickFilter`.
7. `restore_builtins`; criterion bench `filters_10k_10_regex`; module docs with the tables above.

## Acceptance criteria

- [x] AC1 Every `Condition` variant and every operator is covered by table-driven tests, including case-sensitive and case-insensitive variants of each string op.
- [x] AC2 Match modes All/Any/None/NotAll give the results in the combining table for 0, 1, 2 and 3 true conditions out of 3.
- [x] AC3 `applies_to` Files/Dirs/Both respected, including symlinks to directories (treated as dirs) and unknown symlink targets (treated as files).
- [x] AC4 A fresh config (`{}`) yields the five built-in filters and one empty `default` set; `restore_builtins` re-adds a deleted built-in and resets an edited one without touching user filters.
- [x] AC5 Missing data (no size, no mtime, no permissions) makes the condition false, never panics.
- [x] AC6 An invalid regex is reported by `validate_filter` as `InvalidRegex`; at load, the filter is disabled, a warning is logged, and other filters still apply.
- [x] AC7 `equivalent` is true for identical selections on both sides and false when a `LocalOnly` filter is active on the local side only.
- [x] AC8 10 000 entries × 10 regex filters evaluated in < 10 ms (criterion bench `filters_10k_10_regex`, gated in `scripts/bench-gates.toml`).
- [x] AC9 `QuickFilter` treats `*.txt` as a glob and `report` as a case-insensitive substring.
- [x] AC10 Filter settings round-trip through `Settings::save_user` and reload unchanged.
- [x] AC11 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os` pass; `bench-build` builds the new bench.

## Tests

### Unit tests
- `string_ops_table` — rows: op × case mode × (value, name) → expected; covers all 8 ops. AC1.
- `size_ops_table` — Equals/NotEquals/Greater/Less at boundaries (`0`, `u64::MAX`), dirs never match, `None` size false. AC1, AC5.
- `date_ops_table` — Before/After/Equals/NotEquals around midnight with offsets `+00:00` and `+02:00`; a `Precision::Day` timestamp `2026-10-08` equals `2026-10-08` under every offset (no shift). AC1, AC5.
- `permission_bits_table` — every `PermBit` with modes `0o000`, `0o777`, `0o644`; unknown mode false. AC1, AC5.
- `attribute_hidden_and_readonly` — `hidden` flag, mode `0o444`, Windows `raw = "R"`, unknown permissions. AC1, AC5.
- `path_condition_uses_parent_not_name` — `Path Contains "www"` matches `/var/www/x` with parent `/var/www`. AC1.
- `match_modes_truth_table` — AC2.
- `zero_conditions_never_match` — AC2.
- `applies_to_kinds_including_symlinks` — AC3.
- `defaults_have_builtins_and_default_set` — AC4.
- `restore_builtins_readds_and_resets` — AC4.
- `invalid_regex_reported_by_validate` — AC6.
- `lenient_load_disables_bad_filter_only` — AC6.
- `duplicate_and_empty_names_rejected`, `pattern_too_long_rejected`, `too_many_conditions_rejected`, `unknown_filter_in_set_reported`.
- `scope_local_only_not_applied_remote` and `equivalent_cases` — AC7.
- `quick_filter_glob_vs_substring`, `quick_filter_invalid_glob_falls_back_to_substring`, `quick_filter_empty_is_none` — AC9.
- `visible_indices_preserves_order`.

### Property / fuzz tests
- `prop_match_mode_identities` — for random condition truth vectors, `None == !Any` and `NotAll == !All` (proptest). AC2.
- `prop_never_panics_on_arbitrary_entries` — random names (any Unicode, control chars, empty), sizes, optional fields against all built-ins and random valid filters. AC5.
- `prop_case_insensitive_equals_matches_lowercased` — for random ASCII strings.

### Snapshot tests
- `settings_filters_section_snapshot` — `insta` JSON snapshot of the default `filters` section (detects accidental format changes). AC4, AC10.

### Integration tests
- `filter_settings_save_user_roundtrip` — modify a filter and a set, `save_user` into a temp `COURIER_FTP_HOME`, reload with `Config::new`, compare. AC10.
- Bench `filters_10k_10_regex` (criterion, `crates/courier-ftp-core/benches/filters.rs`). AC8.

### End-to-end tests
None (T67 and T43 exercise filters end to end).

## Out of scope

- The filter dialogs and editor UI (T67) and the status bar indicator (T57).
- Applying filters during transfers (T43 consumes `apply_to_transfers`).
- Windows attributes other than hidden and read-only (archive, system, compressed,
  encrypted are not in `Entry`).

## Open questions

None.

## Implementation notes

- `FilterError` has one extra variant, `ControlCharsInName(String)`: the spec requires names
  without control characters but listed no variant for it. It is blocking.
- `crates/courier-ftp/config/config.json` holds no settings sections (T05 defaults come from
  `Settings::default()` via `#[serde(default)]`), so the `filters` defaults live in
  `FilterSettings::default()` and `docs/settings.schema.json` was regenerated instead of
  editing `config.json`.
- `settings::validate` gained `validate_filters`: empty `sets` → default set + warning;
  unknown `active_set` → first set + warning. Filter-level problems are not fixed there;
  `FilterEngine::new` disables bad filters (`warn!` with filter name and error only).
- Extra public helpers for dependants: `MAX_NAME_LEN`, `MAX_CONDITIONS`, `MAX_PATTERN_LEN`,
  `DEFAULT_SET`, `FilterScope::allows`, `FilterSet::{empty, names}`, `FilterSettings::filter`,
  `PermBit::{ALL, mask}`, `FilterError::is_blocking` (false only for `NoConditions`, for T67),
  `CompiledFilter::name`, `FilterEngine::{side, filters}`, `QuickFilter::is_glob`,
  `impl From<FilterError> for crate::Error` (→ `InvalidInput`).
- The bench file also has `filters_100k_10_regex` (spec target < 100 ms). Local release
  results: 10k × 10 regex ≈ 2.4 ms (gate 10 ms, CI 20 ms), 100k ≈ 28 ms.
