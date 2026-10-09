# T64 — Bookmarks UI

**Phase:** F TUI · **Milestone:** M5 · **Depends on:** T33, T52, T53 · **Crate(s):** `courier-ftp` (`components/bookmarks/`) · **Decisions:** D4, D6 · **FEATURES.md:** §2 (bookmarks)
**Related (integrates with, not blocking):** T66

## Goal

Add, manage and jump to bookmarks from the keyboard. `Ctrl-b` opens a fuzzy
bookmark menu with global bookmarks and the current site's bookmarks; Enter
navigates the local and/or remote pane and turns on synchronized browsing and
directory comparison when the bookmark asks for it. The same add/edit dialog is
reused by the Site Manager's bookmark list.

## Context

Before this task:
- T33 provides the bookmark model and storage: `Bookmark { id, name, local_dir:
  Option<LocalPath>, remote_dir: Option<RemotePath>, sync_browsing: bool,
  comparison: bool }`, stored as `bookmark` items (global when no `site_id`, site
  bookmarks with `site_id`), with add / rename / edit / delete / reorder operations
  through `VaultEngine` (T30). Site bookmarks keep their local dir as a device-local
  override (T82 `device_local`).
- T52 provides `ListView`, `TextInput`, `PathInput`, `Checkbox`, `RadioGroup`,
  the modal stack and `confirm`/`message`.
- T53 provides pane navigation (`navigate(PanePath)` with cache and error handling).
- T60 provides the unlock overlay; T31 provides `SiteId` and the tab's site
  association (a tab connected from a saved site knows its `SiteId`).

Later tasks use from this task: T59 calls `BookmarkEditDialog` for its
"Bookmarks" sub-section; T66 is invoked to enable synchronized browsing and
comparison (if T66 isn't merged yet, the flags are stored and the apply step skips them).

## Technical specification

### Types and APIs

Module `crates/courier-ftp/src/components/bookmarks/` (`menu.rs`, `edit.rs`, `apply.rs`).

```rust
/// Where a bookmark lives (maps to T33: global = no `site_id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookmarkScope { Global, Site(SiteId) }

/// One row of the menu after fuzzy filtering.
#[derive(Debug, Clone)]
pub struct BookmarkRow { pub id: ItemId, pub scope: BookmarkScope, pub name: String,
                         pub local: Option<String>, pub remote: Option<String>,
                         pub flags: BookmarkFlags, pub score: u32, pub read_only: bool }

/// The `Ctrl-b` menu (modal).
pub struct BookmarkMenu { /* rows, filter input, cursor, section offsets */ }

/// Add/edit dialog; also used by the Site Manager (T59).
pub struct BookmarkEditDialog { /* form fields, mode Add|Edit(ItemId) */ }

/// Raw form values.
#[derive(Debug, Clone, Default)]
pub struct BookmarkForm {
    pub name: String,
    pub scope: Option<BookmarkScope>,
    pub local_dir: String,
    pub remote_dir: String,
    pub sync_browsing: bool,
    pub comparison: bool,
}

/// Validates the form. `taken_names` = names in the target scope (excluding the
/// bookmark being edited); `site_available` = the tab is connected via a saved site.
pub fn validate_bookmark_form(form: &BookmarkForm, taken_names: &[String],
                              site_available: Option<SiteId>)
    -> Result<Bookmark, Vec<(BookmarkField, String)>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookmarkField { Name, Scope, LocalDir, RemoteDir, SyncBrowsing, Comparison }

/// What applying a bookmark will do in the current tab (pure, testable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyPlan {
    pub local: Option<LocalPath>,
    pub remote: Option<RemotePath>,
    pub enable_sync_browsing: bool,
    pub enable_comparison: bool,
    pub notes: Vec<ApplyNote>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyNote { RemoteSkippedNotConnected, SyncSkippedOneSideOnly }

pub fn plan_apply(b: &Bookmark, remote_connected: bool) -> ApplyPlan;

/// Default name for a new bookmark: last component of the remote dir, else of the
/// local dir, else "Bookmark".
pub fn default_bookmark_name(local: Option<&LocalPath>, remote: Option<&RemotePath>) -> String;
```

New `Action` variants: `Bookmarks` (open menu), `AddBookmark`,
`ApplyBookmark(ItemId)`, `BookmarkApplied { tab, result }`.

### Behaviour

#### Menu (`Ctrl-b`)

```
┌ Bookmarks ────────────────────────────────────────────────────────────┐
│ Filter: [www_______________________]                                  │
│                                                                       │
│ Global                                                                │
│ > Website project      ~/projects/site    ⇄ ≠                         │
│   Downloads            ~/Downloads                                    │
│ Site: web01                                                           │
│   www root             ~/projects/site  ↔  /var/www         ⇄         │
│   Logs                                    /var/log/nginx              │
│                                                                       │
│ Enter go  / filter  a add  e edit  r rename  x delete  J/K move  Esc  │
└───────────────────────────────────────────────────────────────────────┘
```
- Two sections: **Global** and **Site: <site name>** (only when the tab is
  connected through a saved site). Section headers are not selectable.
- Each row: name, local dir (with `~`), remote dir, flags `⇄` (synchronized
  browsing) and `≠` (comparison); ASCII fallback `<>` and `!=` when
  `interface.unicode_symbols` resolves to off (T57). Read-only bookmarks (team vault
  with read permission, T89/T90) show `🔒` (`[ro]` in ASCII) and refuse edit,
  rename, delete and move.
- Keys (list focused by default):

| Key | Action |
|---|---|
| `j`/`k`/`↓`/`↑`, `gg`/`G` | move cursor (skips headers) |
| `Tab` | jump to the first row of the other section |
| `Enter` | apply the bookmark and close the menu |
| `/` | focus the filter input; `Enter`/`↓` returns to the list keeping the filter; `Esc` clears it |
| `a` | add bookmark (opens the edit dialog prefilled from the panes) |
| `e` | edit the selected bookmark |
| `r` | rename (small `prompt_text` dialog) |
| `x` / `Delete` | delete (confirm, default Cancel) |
| `J` / `K` | move down / up within its section (disabled while a filter is active; status hint) |
| `Esc` | clear the filter if set, else close |

- **Fuzzy filter**: the same matcher as the Site Manager's fuzzy site picker (T59,
  `nucleo-matcher`), over `name`, local dir and remote dir; rows sorted by score
  within each section; empty filter keeps the stored order. Matched characters
  are highlighted.
- Empty states: no bookmarks → "No bookmarks yet. Press a to add one."; quickconnect
  tab → the site section shows one dim line "Save this connection as a site to use
  site bookmarks (Site Manager → Save as site)."
- The list is loaded from the vault each time the menu opens.

#### Add / edit dialog (`a` in the menu, `Ctrl-x b` from the panes, T59)

```
┌ Add bookmark ─────────────────────────────────────────────────────┐
│ Name:              [www root_________________________]            │
│ Type:              ( ) Global   (•) Site-specific (web01)         │
│                                                                   │
│ Local directory:   [~/projects/site__________________]            │
│                    (this device only)                             │
│ Remote directory:  [/var/www__________________________]           │
│                                                                   │
│ [x] Use synchronized browsing                                     │
│ [ ] Directory comparison                                          │
│                                                                   │
│                    [ Save ]    [ Cancel ]                         │
└───────────────────────────────────────────────────────────────────┘
```
- Prefill on add: local dir = local pane dir, remote dir = remote pane dir (empty
  when not connected), name = `default_bookmark_name`, type = Site-specific when
  the tab has a `SiteId`, else Global. Edit loads the stored values.
- "Site-specific" is disabled on quickconnect tabs with the note "(save the
  connection as a site first)". In the Site Manager (T59) the type is fixed to that
  site.
- The "(this device only)" note is shown for site bookmarks (local dir stored as a
  device-local override, T33); global bookmark local dirs are part of the synced item.
- Local dir: `PathInput` with local completion; remote dir: `PathInput` with the
  remote completer from the pane's cached listings (no extra network calls while
  typing).
- Ticking *Directory comparison* also ticks *Use synchronized browsing* and locks it
  (FileZilla: comparison implies synchronized browsing); unticking comparison unlocks it.

Validation (`validate_bookmark_form`), shown inline, Save disabled until valid:

| Field | Rule | Message |
|---|---|---|
| Name | 1–100 chars after trim, no control chars | "Enter a name" / "Name too long" |
| Name | unique in its scope, case-insensitive | "A bookmark with this name already exists" |
| Global | local dir required; remote optional | "A global bookmark needs a local directory" |
| Site | remote dir required; local optional | "A site bookmark needs a remote directory" |
| Local dir | absolute after `~` expansion; existence **not** required (warning "Doesn't exist on this device") | "Enter an absolute path" |
| Remote dir | absolute `RemotePath` after normalisation | "Enter an absolute path starting with /" |
| Sync browsing / comparison | both dirs set | "Needs both a local and a remote directory" |

Save calls the T33 add or edit operation; the menu reloads and selects the saved row.
Changing the type of an existing bookmark between Global and Site moves it
(T33 edit with the new `site_id`).

#### Rename, delete, reorder

- Rename: `prompt_text("Rename bookmark", "Name:", current)` with the name rules above.
- Delete: `confirm("Delete bookmark", "Delete \"www root\"?", default = Cancel)`.
- Reorder: `J`/`K` swap with the neighbour in the same section and persist through
  T33's reorder operation immediately; the cursor follows the moved row.

#### Applying (`Enter`)

1. `plan_apply(bookmark, remote_connected)`:
   - `local = bookmark.local_dir` (for site bookmarks the device-local override).
   - `remote = bookmark.remote_dir` if the remote pane is connected, else `None` +
     `RemoteSkippedNotConnected` (global bookmarks apply their remote dir to
     whatever server is connected, T33).
   - sync browsing / comparison only when both `local` and `remote` are applied,
     else `SyncSkippedOneSideOnly`.
2. Close the menu, disable synchronized browsing if it is on (so the two
   navigations don't drive each other), navigate the local pane, then the remote
   pane (T53 navigation: cache, spinner, errors).
3. Navigation error on either side (e.g. `NotFound`, `PermissionDenied`): the pane
   stays where it was, error message "Remote directory /var/www does not exist",
   and steps 4–5 are skipped.
4. `enable_sync_browsing` → T66 enable with base pair (local, remote).
5. `enable_comparison` → T66 enable comparison.
6. Status message "Bookmark \"www root\" applied" plus one line per note
   ("Not connected: remote directory skipped").

#### Vault locked

`Ctrl-b` or `Ctrl-x b` while the vault is locked shows
```
┌ Bookmarks ─────────────────────────────────────────────┐
│ Bookmarks are stored in the vault, which is locked.    │
│            [ Unlock ]    [ Cancel ]                    │
└────────────────────────────────────────────────────────┘
```
*Unlock* opens the T60 unlock overlay; after a successful unlock the requested
menu or dialog opens. If the vault locks while the menu is open (auto-lock, T30),
the menu is discarded with the other dialogs.

### Data formats and configuration

No new settings. Data is T33's `bookmark` items; reordering uses T33's reorder
operation (see Open questions about the order field). Display uses
`interface.unicode_symbols` (T57).

Default bindings (T51): `Ctrl-b` → `Bookmarks` (existing), `Ctrl-x b` → `AddBookmark`
(added to T51's table by this task). Menu-local keys as listed above (mode `Dialog`).

### Errors

| Situation | Error | User sees |
|---|---|---|
| Vault locked | `Error::Vault(Locked)` | unlock dialog above |
| Vault write fails (DB busy, T30 §7) | `Error::Vault(..)` | error dialog "Could not save the bookmark: the database is busy (is another courier-ftp writing?)" with Retry |
| Item from newer schema / read-only | T81 read-only | edit/rename/delete/move refused, status "This bookmark is read-only" |
| Navigation failure | `Error::NotFound`, `Error::PermissionDenied`, `Error::Connection` | error message; pane unchanged; sync/compare not enabled |

### Security and logging

- Bookmark names and paths are vault data: never logged by `tracing` at any level
  above `debug`, and at `debug` only ids. Navigation steps appear in the session
  log as normal listing lines (T55).
- Names and paths from synced items (possibly typed by a teammate) are rendered
  after control-character stripping (T53 rule) and never executed.

## Implementation steps

1. `BookmarkForm`, `validate_bookmark_form`, `default_bookmark_name`, `plan_apply`
   with unit tests.
2. `BookmarkEditDialog` (add/edit, comparison-implies-sync lock, completers).
3. `BookmarkMenu` with sections, fuzzy filter, keys, empty states; rename/delete/reorder.
4. Apply flow with pane navigation and the T66 hooks; vault-locked flow.
5. `AddBookmark` action from the panes; expose the dialog for T59.
6. Snapshot and UI-flow tests.

## Acceptance criteria

- [ ] AC1 Add, edit, rename, delete and reorder each persist through the vault: after lock + unlock (test vault, `Argon2Cost::TEST`) the menu shows the same bookmarks in the same order.
- [ ] AC2 Applying a bookmark with both dirs navigates both panes; with `sync_browsing`/`comparison` set it enables them through T66 (or records the call on a stub before T66 exists).
- [ ] AC3 Applying with the remote pane disconnected navigates only the local pane and shows the "remote directory skipped" note; sync is not enabled.
- [ ] AC4 A navigation error leaves the pane unchanged and does not enable sync/compare.
- [ ] AC5 Validation rules in the table each produce their inline message and block Save.
- [ ] AC6 Quickconnect tabs: site section shows the explanation and the Site-specific type is disabled.
- [ ] AC7 Vault locked: the menu offers unlock and opens after a successful unlock.
- [ ] AC8 Fuzzy filter ranks `www` → "www root" first and highlights the matched characters; reorder keys are disabled while filtering.
- [ ] AC9 Snapshot tests for the menu (both sections, empty, quickconnect, filtered, read-only) and the dialog (add global, add site, validation error) at 80×24 and 160×48.
- [ ] AC10 CI gates pass: `fmt`, `clippy -D warnings`, `docs`, `test-local-only`, `test-os`.

## Tests

### Unit tests

- `fn validate_name_empty_long_duplicate_case_insensitive` (AC5).
- `fn validate_global_requires_local_dir` / `fn validate_site_requires_remote_dir` (AC5).
- `fn validate_remote_dir_must_be_absolute` / `fn validate_local_missing_is_warning_only` (AC5).
- `fn validate_sync_needs_both_dirs` (AC5).
- `fn comparison_ticks_and_locks_sync_browsing` (AC5).
- `fn plan_apply_both_sides`, `fn plan_apply_remote_disconnected`, `fn plan_apply_local_only_bookmark` (AC2, AC3).
- `fn default_bookmark_name_prefers_remote_last_component`.
- `fn fuzzy_rank_and_highlight` (AC8).

### Snapshot tests

At 80×24 and 160×48 (AC9): `snapshot_bookmark_menu_two_sections`,
`snapshot_bookmark_menu_empty`, `snapshot_bookmark_menu_quickconnect_tab`,
`snapshot_bookmark_menu_filtered`, `snapshot_bookmark_menu_read_only_row`,
`snapshot_bookmark_menu_ascii_symbols`, `snapshot_add_bookmark_global`,
`snapshot_add_bookmark_site`, `snapshot_add_bookmark_validation_errors`,
`snapshot_bookmarks_vault_locked`.

### Integration tests

UI-flow tests with scripted keys, `MockBackend` for the remote pane, a temp dir for
the local pane, and a test vault:
- `fn add_edit_rename_delete_reorder_persist_across_lock` (AC1).
- `fn apply_navigates_both_panes_and_enables_sync_and_compare` — T66 stub records calls (AC2).
- `fn apply_when_disconnected_local_only` (AC3).
- `fn apply_remote_not_found_keeps_pane_and_skips_sync` (AC4).
- `fn quickconnect_tab_site_section_disabled` (AC6).
- `fn locked_vault_unlock_then_menu_opens` (AC7).
- `fn reorder_disabled_while_filtering` (AC8).

### End-to-end tests

Not needed beyond T76's PtyApp smoke flow; bookmarks are covered by the
integration tests above with real vault storage.

## Out of scope

- Bookmark folders/hierarchy.
- Importing FileZilla bookmarks (done by T32 as part of site import).
- Applying a bookmark to a different tab than the current one.

## Open questions

1. **Inconsistency with T33**: the `Bookmark` model has no ordering field, but
   reorder must persist and merge across devices. T33 should add an order key (e.g.
   `position: f64` fractional index so concurrent moves merge per field, T81).
2. **T51**: `Ctrl-x b` (add bookmark) needs to be added to the keymap table.
3. Should a global bookmark's local dir also be device-local (like site bookmarks),
   since home directories differ between machines? Current spec: synced.
