# T52 — Dialog and form framework

**Phase:** F TUI · **Depends on:** T50 · **Crate:** `courier-ftp` (`components/dialog/`)
**Related (integrates with, not blocking):** T04, T62

## Goal

Reusable modal widgets so every feature dialog (site editor, chmod, file
exists, trust prompts, settings) is built from the same pieces and behaves
consistently.

## Scope

1. **Modal stack** in `MainScreen`: push/pop, centred overlay, dimmed background, `Esc` = cancel, `Enter` = default button (unless a multiline field is focused).
2. **Widgets**
   - `TextInput`: cursor movement, Home/End, word jump (`Ctrl-←/→`), delete word (`Ctrl-w`), paste (bracketed paste event from crossterm), max length, validation callback with inline error message, `masked` variant for passwords (shows `•`), placeholder text.
   - `NumberInput` (with range).
   - `Checkbox` (bool) and `TriStateCheckbox` (on/off/unchanged — for chmod T62).
   - `Select` / dropdown (popup list, type-to-jump).
   - `RadioGroup`.
   - `Button` row (`[ OK ]  [ Cancel ]`, `←/→` moves, mnemonics with Alt-letter).
   - `ListView` with selection (used in pickers).
   - `TabbedForm`: tab headers switchable with `Ctrl-PageUp/PageDown` or `[`/`]` (for Site Manager tabs, Settings sections).
   - `PathInput`: text input with Tab-completion for local paths (and remote paths via a provided async completer).
   - `ProgressDialog`: message + progress bar + Cancel (recursive delete, search, import).
3. **Form model**: `Form` holds fields with `Tab`/`Shift-Tab` focus traversal (inside a dialog, Tab moves between fields, not panes), collects values into a typed struct via a builder/closure, runs validation before allowing OK.
4. **Standard dialogs**: `confirm(title, text, default)`, `message(title, text)`, `error(err)` (shows error chain from `color_eyre`/core error), `prompt_text(title, label, initial)`, `prompt_password`, `choose(title, options)`.
5. **Async result**: dialogs return results through a `oneshot` so callers (including core prompts from T04) can await them.
6. Rendering: respect terminal size; dialogs scroll if taller than the screen; never panic on tiny terminals (show "terminal too small").

## Acceptance criteria

- [x] All widgets have snapshot tests and key-handling unit tests.
- [x] Password input never renders the real text, including in snapshots.
- [x] Bracketed paste inserts text into inputs (multi-line paste collapsed to one line for single-line fields).
- [x] Nested dialogs (confirm on top of site editor) work.

## Tests

- Snapshot + unit tests per widget; a sample form test exercising validation.
