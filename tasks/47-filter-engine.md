# T47 — Filename filter engine

**Phase:** E Transfers · **Depends on:** T02, T05 · **Crate:** `courier-ftp-core` (`filters` module) · **FEATURES.md:** §8

## Goal

FileZilla-style filters that hide entries in the panes and skip them in recursive
operations.

## Scope

1. **Model**
   ```rust
   pub struct Filter {
       pub name: String,
       pub applies_to: AppliesTo,            // Files, Dirs, Both
       pub match_mode: MatchMode,            // All conditions | Any condition | None of the conditions | Not all
       pub case_sensitive: bool,
       pub conditions: Vec<Condition>,
       pub local_only: bool, pub remote_only: bool, // or a "for local/remote" pair
   }
   pub enum Condition {
       Name(StringOp, String),               // contains, not contains, equals, not equals, begins with, ends with, matches regex
       Path(StringOp, String),
       Size(NumOp, u64),                     // greater than, equals, not equals, less than
       Attribute(..), Permission(PermBit, bool), // unix perm bits; Windows attributes for local
       Date(DateOp, OffsetDateTime),         // before, equals, not equals, after
   }
   pub struct FilterSet { pub name: String, pub enabled_local: Vec<FilterName>, pub enabled_remote: Vec<FilterName> }
   ```
   A filter **excludes** matching entries (FileZilla semantics).
2. **Built-in filters** (shipped as defaults, editable, restorable): "CVS and SVN directories" (`CVS`, `.svn`), "Temporary and backup files" (`*~`, `*.bak`, `#*#`), "Configuration files" (dotfiles), "Git", "Thumbs.db / .DS_Store". Plus "Show only…" type examples are user-created.
3. **Storage**: filters and sets are non-secret → stored in the settings config (T05) under `filters`, saved via `Settings::save_user`.
4. **Evaluation**: `FilterEngine::new(active filters, side)` precompiles regexes; `fn excluded(&self, entry, full_path) -> bool`. Invalid regex = validation error at edit time; at load time log and disable that filter.
5. **Quick filter** (TUI `/` on a pane, T53) is separate: a transient case-insensitive substring/glob match — reuse `StringOp::Contains`/glob from this module.
6. Per-session flag "filters active" for the status bar indicator (T57), and FileZilla's rule that **directory comparison requires identical filtering on both sides** — expose `FilterEngine::equivalent(&other)` used by T48 to warn.

## Acceptance criteria

- [ ] Every condition and operator tested.
- [ ] Match modes All/Any/None/Not-all correct.
- [ ] Applies-to Files/Dirs respected.
- [ ] Built-in filters present on first run and restorable.
- [ ] 10 000 entries filtered with 10 regex filters in < 10 ms.

## Tests

- Table-driven tests per condition type.
