# T67 — Filters UI

**Phase:** F TUI · **Milestone:** M6 · **Depends on:** T05, T47, T52 · **Crate(s):** `courier-ftp` (`components/filters/`) · **Decisions:** D6, D10 · **FEATURES.md:** §8
**Related (integrates with, not blocking):** T43, T57

## Goal

FileZilla's "Directory listing filters" dialog and its filter rule editor: enable
filters separately for the local and the remote side, save the selection as named
filter sets, create and edit filters with condition rows (with live regex
validation), restore the built-in filters, and choose whether filters also apply to
transfers. Applying re-filters both panes immediately and updates the status bar
indicator; everything is saved to the user config.

## Context

Before this task:
- T47 provides `Filter { name, applies_to: AppliesTo, match_mode: MatchMode,
  case_sensitive, scope: FilterScope, conditions, builtin }`, `Condition` (`Name`,
  `Path` with `StringOp`; `Size` with `NumOp`; `Attribute { attr: AttrFlag, set }`;
  `Permission { bit: PermBit, set }`; `Date { op: DateOp, value: time::Date }`),
  `FilterSet { name, local, remote }`, `FilterSettings { filters, sets, active_set,
  apply_to_transfers }` with `restore_builtins()` and `active()`, `builtin_filters()`,
  `Side`, `FilterEngine::new(settings, side, local_offset) -> (FilterEngine,
  Vec<FilterError>)` with regex precompilation, `is_active()`, `equivalent()`, and
  `validate_filter` / `validate_settings`. Filters are the `filters` settings section
  (`filters.{filters, sets, active_set, apply_to_transfers}`, registered in T05, D10)
  and are saved through `SettingsStore::update` (T05).
- T52 provides `TabbedForm`/forms, `ListView`, `Checkbox`, `RadioGroup`, `Select`,
  `TextInput`, `prompt_text`, `confirm` (destructive confirmations use
  `ConfirmOpts::danger(..)`).

Later tasks use from this task: T43 reads `filters.apply_to_transfers`; T53 and T66
re-filter / recompare on `Action::FiltersChanged`; T57 shows `⚑ filters`; T68 links
to this dialog from its Interface → File lists section.

## Technical specification

### Types and APIs

Module `crates/courier-ftp/src/components/filters/` (`dialog.rs`, `editor.rs`,
`rows.rs`, `state.rs`); shared input parsers in
`crates/courier-ftp/src/components/forms/units.rs` (`parse_size`, `parse_date`;
created by whichever of T65/T67 lands first, used by both).

```rust
/// Editable copy of the whole `filters` settings section. Dialogs work on this;
/// nothing touches the live settings until Apply/OK.
#[derive(Debug, Clone, PartialEq)]
pub struct FiltersDraft {
    pub filters: Vec<Filter>,
    pub sets: Vec<FilterSet>,
    pub active_set: String,
    pub apply_to_transfers: bool,
}

impl FiltersDraft {
    pub fn from_settings(s: &FilterSettings) -> Self;
    pub fn into_settings(self) -> FilterSettings;
    pub fn active(&self) -> &FilterSet;                   // falls back to the first set
    pub fn toggle(&mut self, filter: &str, side: Side);
    pub fn toggle_all(&mut self, side: Side);            // all on if any off, else all off
    pub fn rename_filter(&mut self, old: &str, new: &str) -> Result<(), DraftError>; // updates every set
    pub fn delete_filter(&mut self, name: &str) -> usize; // returns number of sets that referenced it
    pub fn copy_filter(&mut self, name: &str) -> String;  // "<name> (copy)", "(copy 2)", …
    pub fn save_set_as(&mut self, name: &str) -> Result<(), DraftError>;
    pub fn delete_set(&mut self, name: &str) -> Result<(), DraftError>; // "default" can't be deleted
    pub fn restore_builtins(&mut self) -> Vec<String>;   // delegates to FilterSettings::restore_builtins
    /// T47 `validate_filter` per filter plus the UI rules below.
    pub fn validate(&self) -> Result<(), Vec<(String /*filter*/, FilterFieldError)>>;
}

/// Whether a filter is built-in, built-in but modified, or user-made
/// (`Filter.builtin` plus a comparison with T47's `builtin_filters()` by name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOrigin { BuiltIn, BuiltInModified, User }
pub fn origin(f: &Filter) -> FilterOrigin;

/// One editable condition row in the editor.
#[derive(Debug, Clone)]
pub struct ConditionRowDraft { pub kind: ConditionKind, pub op: usize, pub value: String }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionKind { Name, Path, Size, Attribute, Permission, Date }

/// Date values are calendar days (`parse_date` → `time::Date`, T47 whole-day semantics).
pub fn row_to_condition(r: &ConditionRowDraft, case_sensitive: bool)
    -> Result<Condition, String>;
pub fn condition_to_row(c: &Condition) -> ConditionRowDraft;

pub const MAX_FILTER_NAME: usize = 64;           // T47: 1..=64 chars
pub const MAX_CONDITIONS_PER_FILTER: usize = 20; // UI cap (T47 accepts up to 32)
pub const REGEX_SIZE_LIMIT: usize = 1 << 20; // 1 MiB compiled
```

New `Action` variants: `FiltersDialog` (open dialog), `FiltersChanged` (broadcast after
apply; T53 re-filters, T66 recompares, T57 updates the indicator).

### Behaviour

#### Filters dialog (`Ctrl-x f`; also Settings → File lists → "Filters…")

```
┌ Directory listing filters ────────────────────────────────────────────────┐
│ Filter set: [default            ▾]   [ Save as… ]  [ Delete set ]         │
│                                                                           │
│ Local filters                         │ Remote filters                    │
│ > [x] CVS and SVN directories    b    │   [x] CVS and SVN directories  b  │
│   [ ] Git directories            b    │   [ ] Git directories          b  │
│   [ ] Temporary and backup files b    │   [ ] Temporary and backup filesb │
│   [ ] Configuration files        b    │   [ ] Configuration files      b  │
│   [ ] OS metadata files          b    │   [ ] OS metadata files        b  │
│   [x] Build output                    │   ─   Build output (local only)   │
│                                                                           │
│ [x] Apply filters to transfers (recursive uploads, downloads, deletes     │
│     and permission changes skip filtered entries)                         │
│                                                                           │
│ [ Edit filter rules… ] [ Toggle all ] [ Apply ]  [ OK ]  [ Cancel ]       │
└───────────────────────────────────────────────────────────────────────────┘
```
- `b` marks a built-in filter, `b*` a modified built-in; `⚠` marks a filter that
  failed to load (invalid regex in the config, T47) — it can't be enabled until
  fixed in the editor.
- A filter with `scope = LocalOnly` is shown disabled (`─`) in the remote column with
  "(local only)", and vice versa for `RemoteOnly`.
- Keys: `Tab`/`Shift-Tab` move between the set selector, the two lists, the
  checkbox and the buttons (T52); in a list `j`/`k` move, `Space` toggles, `h`/`l`
  or `←`/`→` switch column keeping the row, `t` = *Toggle all* for the focused
  column, `e` = *Edit filter rules…*; `Enter` = OK; `Esc` = Cancel.
- **Filter set** `Select`: switching loads that set's checkboxes into the draft.
  *Save as…* asks for a name (`prompt_text`; 1–64 chars, unique
  case-insensitively, not "default" unless overwriting it — confirm with
  `ConfirmOpts::danger("Overwrite")` on overwrite of an existing set) and makes it the
  active set. *Delete set* (disabled for "default") asks to confirm
  (`ConfirmOpts::danger("Delete")`), then switches to "default".
- **Apply**: `validate()`; `SettingsStore::update(|s| s.filters = draft.into_settings())`
  (T05: validates, saves, then publishes), rebuild the two `FilterEngine`s, broadcast
  `FiltersChanged`.
  Panes re-filter from their current listings (no network); the status bar shows
  `⚑ filters` when any filter is enabled on either side.
- **OK** = Apply + close. **Cancel** = discard changes since the last Apply and close
  (`confirm("Discard changes?", .., ConfirmOpts::danger("Discard"))` when the draft differs).

#### Filter rule editor (*Edit filter rules…*)

```
┌ Edit filter rules ─────────────────────────────────────────────────────────┐
│ Filters                      │ Name:       [Temporary and backup files___] │
│ > CVS and SVN directories b  │ Filter:     [x] Files   [ ] Directories     │
│   Git directories         b  │ Use for:    (•) Local and remote            │
│   Temporary and backup…   b  │             ( ) Local only  ( ) Remote only │
│   Configuration files     b  │ Match:      (•) All  ( ) Any  ( ) None      │
│   OS metadata files       b  │             ( ) Not all                     │
│   Build output               │ [ ] Case sensitive                          │
│                              │ Filter out entries where:                   │
│                              │  [Name      ▾] [ends with     ▾] [~_____] [-]│
│                              │  [Name      ▾] [matches regex ▾] [^#.*#$] [-]│
│                              │  [+ Add condition]                          │
│ n new  c copy  r rename      │                                             │
│ x delete  R restore defaults │                                             │
│                              │                [ OK ]    [ Cancel ]         │
└────────────────────────────────────────────────────────────────────────────┘
```
At 80 columns the filter list narrows to 24 columns and names are truncated with
`…`; the condition row keeps the value field at least 12 columns.

- List keys (list focused): `n` new filter ("New filter", one empty Name
  condition, both sides, files and directories, All), `c` copy, `r` rename
  (`prompt_text`; updates every set that references it), `x`/`Delete` delete
  (confirm "Delete \"Build output\"? It is used in 2 filter sets.",
  `ConfirmOpts::danger("Delete")`, default Cancel), `R` restore defaults (confirm:
  "Restore the built-in filters? Changes to built-in filters are lost; your own
  filters are kept.", `ConfirmOpts::danger("Restore")`).
- Form fields map to `Filter`:

| Field | Widget | Maps to |
|---|---|---|
| Name | `TextInput` | `name` |
| Filter files / directories | two `Checkbox`es | `applies_to` (`Files`, `Dirs`, `Both`; at least one required) |
| Use for | `RadioGroup` | `scope` (`Both`, `LocalOnly`, `RemoteOnly`) |
| Match | `RadioGroup` | `match_mode` (`All`, `Any`, `None`, `NotAll`) |
| Case sensitive | `Checkbox` | `case_sensitive` |
| Condition rows | `Select` kind + `Select` op + value | `conditions` |

- Condition kinds, operators and values (T47):

| Kind | Operators | Value |
|---|---|---|
| Name | contains, doesn't contain, equals, doesn't equal, begins with, ends with, matches regex | text |
| Path | same as Name (full path) | text |
| Size | greater than, equals, doesn't equal, less than | `parse_size` (`10`, `10K`, `10 KiB`, `1.5MB`) |
| Attribute | is set, is not set | `Select`: hidden, read-only (T47 `AttrFlag`) |
| Permission (Unix) | is set, is not set | `Select`: owner/group/other × read/write/execute (T47 `PermBit`) |
| Date | before, equals, doesn't equal, after | `parse_date` (`2026-10-08`; a calendar day, whole-day comparison, T47) |

- Rows: `[+ Add condition]` / `Ctrl-n` adds (max 20), `[-]` / `Ctrl-d` removes (min 1).
- **Live validation** on every keystroke, message under the field:
  - name empty / longer than 64 / control characters / duplicate (case-insensitive)
    → "Enter a unique name";
  - no side selected in Files/Directories → "Choose files, directories or both";
  - empty value → "Enter a value"; size/date parse errors;
  - regex: compiled with `regex::RegexBuilder` (`size_limit` 1 MiB,
    `case_insensitive(!case_sensitive)`); the error text is the regex crate's
    message reduced to its first line, e.g. "regex parse error: unclosed group".
- Switching to another filter in the list while the current one is invalid is
  allowed (the invalid one is marked `⚠` in the list). **OK is blocked** while any
  filter is invalid: focus jumps to the first invalid field with the message "Fix
  the errors in \"Build output\" first".
- OK returns to the Filters dialog with the edited draft (still pending until
  Apply/OK there); Cancel discards the editor's changes only.

#### Built-in filters

T47's defaults (`builtin_filters()`): "CVS and SVN directories", "Git directories",
"Temporary and backup files", "Configuration files", "OS metadata files". They are
editable and deletable; `origin()` marks them. *Restore defaults* calls
`FilterSettings::restore_builtins` (re-adds missing ones and replaces same-named ones
with the original definition); set references stay.

#### Apply filters to transfers

`filters.apply_to_transfers` (default `true`): when on, T43 skips filtered entries
in recursive uploads, downloads, deletes and chmod (and doesn't descend into
filtered directories), and logs how many were skipped. When off, filters only hide
entries in the panes. Changing it affects operations started afterwards.

### Data formats and configuration

`filters` section of the settings (T47 `FilterSettings`, registered in T05), saved
through `SettingsStore::update`:

| Key | Type | Default |
|---|---|---|
| `filters.filters` | `Vec<Filter>` | T47 built-ins |
| `filters.sets` | `Vec<FilterSet>` | `[{"name": "default", "local": [], "remote": []}]` |
| `filters.active_set` | string | `"default"` |
| `filters.apply_to_transfers` | bool | `true` |

```json
"filters": {
  "filters": [
    { "name": "Build output", "applies_to": "dirs", "match_mode": "any",
      "case_sensitive": false, "scope": "local_only", "builtin": false,
      "conditions": [ { "type": "name", "op": "equals", "value": "target" },
                      { "type": "name", "op": "equals", "value": "node_modules" } ] }
  ],
  "sets": [ { "name": "default", "local": ["Build output"], "remote": [] } ],
  "active_set": "default",
  "apply_to_transfers": true
}
```
(The serde shape is T47's.) Load rules (T05/T47): a set referencing an unknown filter
name drops that name with a warning; an unknown `active_set` falls back to the first
set with a warning; an empty `sets` list restores the default set.

Default binding: `Ctrl-x f` → `FiltersDialog` (T51's `Ctrl-x` prefix table, owner T67).

### Errors

| Situation | Error | User sees |
|---|---|---|
| Invalid regex / size / date / name | validation | inline message; OK/Apply blocked |
| Duplicate filter or set name | `DraftError::Duplicate` | inline message |
| Delete "default" set | `DraftError::DefaultSet` | button disabled |
| Save fails (I/O, permissions, invalid `config.json`) | `Error::Io` / `Error::InvalidInput` from `SettingsStore::update` (T05) | error dialog "Could not save settings: …"; the draft is kept and nothing is published (T05: publish only after a successful save) |
| Invalid filter in config at load | logged by T47 | `⚠` in both dialogs; can't be enabled until fixed |

### Security and logging

- Regexes are compiled with a 1 MiB size limit (no pathological memory use).
- Filters are non-secret settings (D10); no vault involvement.
- `tracing` at `debug`: counts of enabled filters per side and apply timings; filter
  names and patterns are not logged at `info`+ (they can reveal project names).

## Implementation steps

1. `FiltersDraft` with all operations, `origin()`, `row_to_condition` /
   `condition_to_row`, shared `units.rs` parsers; unit tests.
2. Filters dialog: two-column checklist, set selector, save-as/delete set, toggle
   all, apply-to-transfers checkbox, Apply/OK/Cancel with `SettingsStore::update`.
3. `FiltersChanged` broadcast; T53 re-filter hook, T57 indicator, T66 recompare.
4. Rule editor: list operations, form, condition rows, live validation, restore defaults.
5. Snapshot tests and UI-flow tests.

## Acceptance criteria

- [ ] AC1 Full round-trip: create a filter with three conditions, enable it for the local side, save a set "Web project", OK; reload the settings from disk (`Config::new` in a temp config dir) and get an identical `FilterSettings`.
- [ ] AC2 An invalid regex shows the regex error under the field and blocks OK in the editor and Apply/OK in the filters dialog.
- [ ] AC3 Apply re-filters both panes in the next frame without a backend call (mock call counter unchanged) and the status bar indicator appears/disappears.
- [ ] AC4 Rename of a filter updates every set; delete removes it from every set; the "default" set can't be deleted.
- [ ] AC5 Restore defaults re-adds deleted built-ins and resets modified ones while keeping user filters.
- [ ] AC6 Filters with `scope = LocalOnly` can't be enabled for the remote side and vice versa for `RemoteOnly`.
- [ ] AC7 `filters.apply_to_transfers = false` makes a recursive upload (T43, mock) include entries that the panes hide.
- [ ] AC8 Cancel after edits restores the state of the last Apply.
- [ ] AC9 Snapshot tests of the filters dialog (default, with sets, local-only and invalid filters) and the editor (each condition kind, validation errors) at 80×24 and 160×48.
- [ ] AC10 CI gates pass: `fmt`, `clippy -D warnings`, `docs`, `test-local-only`, `test-os`.

## Tests

### Unit tests

- `fn draft_toggle_and_toggle_all_per_side` (AC3).
- `fn draft_rename_updates_all_sets` / `fn draft_delete_removes_from_sets_and_counts` (AC4).
- `fn draft_default_set_cannot_be_deleted` (AC4).
- `fn draft_copy_filter_names` — "(copy)", "(copy 2)".
- `fn draft_restore_builtins_keeps_user_filters` (AC5).
- `fn origin_builtin_modified_user` (AC5).
- `fn row_to_condition_each_kind_and_operator` / `fn condition_to_row_round_trip` (AC1).
- `fn regex_error_message_first_line_only` (AC2).
- `fn validate_applies_to_requires_one` / `fn validate_duplicate_names_case_insensitive`.
- `fn local_only_cannot_enable_remote` (AC6).
- `fn unknown_filter_in_set_dropped_on_load`.
- `fn date_row_builds_calendar_day_condition` — `"2026-10-08"` → `Condition::Date { value: Date }`; `"2026-10-08 14:30"` rejected (AC2).
- `fn save_failure_keeps_draft_and_publishes_nothing` — read-only config dir (AC1).

### Property / fuzz tests

- `proptest fn condition_row_round_trip` — any valid `Condition` → row → condition is identical (AC1).

### Snapshot tests

At 80×24 and 160×48 (AC9): `snapshot_filters_dialog_default`,
`snapshot_filters_dialog_sets_and_local_only`, `snapshot_filters_dialog_invalid_filter`,
`snapshot_filter_editor_name_conditions`, `snapshot_filter_editor_all_condition_kinds`,
`snapshot_filter_editor_regex_error`, `snapshot_filter_editor_restore_confirm`,
`snapshot_status_bar_filter_indicator`.

### Integration tests

UI-flow tests with scripted keys, `MockBackend` remote pane, temp-dir local pane,
and a temp config dir:
- `fn filters_round_trip_persisted_to_config` (AC1).
- `fn invalid_regex_blocks_ok_and_apply` (AC2).
- `fn apply_refilters_panes_without_listing` (AC3).
- `fn cancel_restores_last_applied` (AC8).
- `fn apply_to_transfers_off_includes_hidden_entries` (AC7).

### End-to-end tests

Not required; filters are pure UI + settings and are covered above. T76's PtyApp
smoke flow may include opening and closing the dialog.

## Out of scope

- Per-tab or per-site filter selection (filters are global, like FileZilla).
- Importing FileZilla's `filters.xml` (T32 imports sites only).
- The quick filter (`/`, T53).

## Open questions

None.

Resolved (reconciliation): the keys are `filters.{filters, sets, active_set,
apply_to_transfers}` (T05/T47); `Ctrl-x f` = `FiltersDialog` is in T51's table; date
conditions are calendar days (`time::Date`, T47).
