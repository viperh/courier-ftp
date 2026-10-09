# T52 — Dialog and form framework

**Phase:** F TUI · **Milestone:** M1 · **Depends on:** T50 · **Crate(s):** `courier-ftp` (`components/dialog/`, `components/widgets/`) · **Decisions:** D3, D6, D7 · **FEATURES.md:** §2, §4 (every dialog-based feature builds on this)
**Related (integrates with, not blocking):** T04, T62
**Reference:** sverb `crates/sverb-tui/src/widgets/dialog.rs` (buttons, mnemonics, danger dialogs), `widgets/form/` (form model, validation, secret field), `app/modal.rs` (modal stack, ticks), SPEC §8.6

## Goal

Reusable modal dialogs and form widgets so every feature dialog (site editor, chmod,
file exists, trust prompts, settings, search form) is built from the same pieces and
behaves the same way: centred over a dimmed screen, keyboard-only, `Esc` cancels,
`Enter` presses the default button, `Tab` moves between fields, validation errors appear
inline, password fields never show their content, and results come back either as an
awaited value (for core prompts) or as an `Action`. Widgets also work outside dialogs
(address bar, quickconnect fields, the `:` command line).

## Context

- Before (T50): `ModalStack` slot in `MainScreen` with modal-first key routing, mode
  `Dialog`, `KeyChord`, `DrawCx` (theme, symbols, focus, time), `Runner`,
  `Action::StatusMessage`, `ui::text::sanitize`/`truncate_to_width`, the minimal
  `QuitConfirm` modal and `Config::problems`. T51 provides the `Dialog` key table
  (`enter` `DialogSubmit`, `esc` `DialogCancel`, `tab`/`backtab` `NextField`/`PrevField`,
  `ctrl-s` `DialogSave`, `ctrl-pagedown`/`ctrl-pageup` `NextFormTab`/`PrevFormTab`) and
  the fixed text-editing keys. T04 provides `PromptRequest` (`respond`, `is_withdrawn`).
- After: T53 (`PathInput` address bar, `prompt_text`, `confirm`, `ListView` column menu),
  T55 (`TextInput` search row), T58 (quickconnect fields), T59 (`TabbedForm` site
  editor, `TextArea` comments), T60 (`SecretInput`, full-screen unlock view), T62
  (`TriStateCheckbox`, `RadioGroup`, `ProgressDialog`, `confirm`, `choose`), T63–T69,
  T71 (`text_viewer` for raw listings and the app log).

## Technical specification

### Types and APIs

Modules: `components/widgets/` (standalone widgets) and `components/dialog/` (stack,
forms, standard dialogs).

```rust
// ---- widgets/mod.rs ----
pub trait Widget {
    fn handle_key(&mut self, key: KeyChord) -> WidgetOutcome;
    fn handle_paste(&mut self, text: &str) -> WidgetOutcome { WidgetOutcome::Ignored }
    /// Async results (path completion) arrived; called on `Action::Wake`.
    fn poll(&mut self) -> bool { false }
    fn render(&self, frame: &mut Frame, area: Rect, cx: &WidgetCx);
    /// Rows needed at this width (1 for single-line widgets).
    fn height(&self, width: u16) -> u16 { 1 }
    /// Plain letters are typed into it (so mnemonics need Alt while it has focus).
    fn is_text(&self) -> bool { false }
    /// Where to place the terminal cursor when focused.
    fn cursor(&self, area: Rect) -> Option<Position> { None }
}
pub enum WidgetOutcome { Ignored, Consumed, Changed, Activated /* Enter on a list row, button press */ }
pub struct WidgetCx<'a> { pub theme: &'a Theme, pub symbols: &'a Symbols, pub focused: bool, pub enabled: bool, pub now: Instant }

pub struct TextInput { /* value, cursor (grapheme index), scroll, max_chars, placeholder, error */ }
impl TextInput {
    pub fn new(initial: &str) -> Self;            // max_chars 4096
    pub fn max_chars(self, n: usize) -> Self;
    pub fn placeholder(self, text: &str) -> Self;
    pub fn validator(self, f: Validator) -> Self;  // Validator = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>
    pub fn value(&self) -> &str;
    pub fn set_value(&mut self, v: &str);         // cursor to end
    pub fn error(&self) -> Option<&str>;
    pub fn validate(&mut self) -> bool;
}
pub struct SecretInput { /* Zeroizing<String>; no &str accessor */ }
impl SecretInput {
    pub fn new() -> Self;                          // max_chars 1024
    pub fn take(&mut self) -> SecretString;        // clears the field
    pub fn is_empty(&self) -> bool;
    pub fn len_chars(&self) -> usize;
}
impl fmt::Debug for SecretInput;                   // prints "SecretInput(****)"
pub struct NumberInput { /* TextInput restricted to digits (and '-' when min < 0) */ }
impl NumberInput { pub fn new(value: Option<i64>, min: i64, max: i64) -> Self; pub fn optional(self) -> Self;
                   pub fn value(&self) -> Option<i64>; }
pub struct Checkbox { pub checked: bool, label: String }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum TriState { On, Off, Unchanged }
pub struct TriStateCheckbox { pub state: TriState, pub allow_unchanged: bool, label: String }
pub struct Select<T> { /* options: Vec<SelectOption<T>>, selected, popup: Option<PopupState> */ }
pub struct SelectOption<T> { pub label: String, pub value: T, pub disabled: Option<String> /* reason */ }
pub struct RadioGroup { /* labels, selected, horizontal: bool, disabled per option */ }
pub struct ButtonRow { /* buttons, focused */ }
pub struct Button { pub id: &'static str, pub label: String, pub mnemonic: Option<char>, pub role: ButtonRole }
pub enum ButtonRole { Normal, Default, Safe, Danger }
pub struct ListView<T> { /* rows (items and section headers), cursor, marks, filter, checkboxes, reorderable */ }
pub enum ListRow<T> { Header(String), Item { label: Line<'static>, value: T, checked: Option<bool> } }
pub struct PathInput { /* TextInput + completer state */ }
impl PathInput { pub fn new(initial: &str, completer: Option<Arc<dyn PathCompleter>>, wake: UnboundedSender<Action>) -> Self; }
pub trait PathCompleter: Send + Sync + 'static {
    /// Candidates for `input`; each `replacement` is the whole new field value.
    fn complete(&self, input: String) -> BoxFuture<'static, Result<Vec<Completion>, String>>;
}
pub struct Completion { pub replacement: String, pub display: String, pub is_dir: bool }
pub struct LocalPathCompleter;                     // tokio::fs based, see Behaviour
pub struct TextArea { /* lines: Vec<String>, cursor (row, grapheme col), max_bytes 65536 */ }
pub struct TextView { /* read-only lines, scroll (row, col), search */ }

// ---- dialog/mod.rs ----
pub trait Dialog: Send + 'static {
    type Output: Send + 'static;
    fn title(&self) -> Cow<'_, str>;
    fn size(&self, screen: Rect) -> DialogSize;
    fn handle_key(&mut self, key: KeyChord) -> DialogStep<Self::Output>;
    /// Actions from the `Dialog` key table (DialogSubmit, DialogCancel, NextField, …).
    fn handle_action(&mut self, action: &Action) -> DialogStep<Self::Output>;
    fn handle_paste(&mut self, text: &str) -> DialogStep<Self::Output> { DialogStep::Ignored }
    /// Every `Tick` (4 Hz) and on `Action::Wake`: timers, progress, withdrawn prompts.
    fn poll(&mut self, now: Instant) -> DialogStep<Self::Output> { DialogStep::Continue }
    fn render(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx);
    /// Unsaved edits: `Esc` asks "Discard changes?" first.
    fn is_dirty(&self) -> bool { false }
}
pub enum DialogSize { Fit { min_w: u16, max_w: u16 }, Fixed { w: u16, h: u16 }, Percent { w: u8, h: u8 }, FullScreen }
pub enum DialogStep<T> {
    Continue, Ignored,
    /// Close with a result; `None` = cancelled.
    Close(Option<T>),
    /// Open another dialog on top (e.g. "Discard changes?", a Select popup is not a dialog).
    Push(Box<dyn AnyDialog>),
}

pub struct ModalStack { /* Vec<Box<dyn AnyDialog>>, max depth 8 */ }
impl ModalStack {
    /// Result through a channel (core prompts, async callers). Cancel → `None`.
    pub fn push<D: Dialog>(&mut self, d: D) -> oneshot::Receiver<Option<D::Output>>;
    /// Result mapped to an Action sent on the action channel.
    pub fn push_then<D: Dialog>(&mut self, d: D,
        then: impl FnOnce(Option<D::Output>) -> Option<Action> + Send + 'static);
    pub fn is_empty(&self) -> bool;
    pub fn depth(&self) -> usize;
    /// Close everything (quit, vault lock): every pending receiver gets `None`.
    pub fn close_all(&mut self);
}

// ---- dialog/form.rs ----
pub type FieldId = &'static str;
pub struct Form { /* fields, focus, errors, initial values, cross-field validator, on_change */ }
pub struct FormField { pub id: FieldId, pub label: String, pub help: Option<String>,
                       pub widget: FieldWidget, pub visible: bool, pub enabled: Result<(), String> }
pub enum FieldWidget { Text(TextInput), Secret(SecretInput), Number(NumberInput), Check(Checkbox),
    Tri(TriStateCheckbox), Select(Select<String>), Radio(RadioGroup), Path(PathInput),
    Area(TextArea), List(ListView<String>), Custom(Box<dyn Widget + Send>) }
pub enum FieldValue { Text(String), Secret(SecretString), Number(Option<i64>), Bool(bool),
    Tri(TriState), Choice(usize), Lines(String), Checked(Vec<bool>) }
pub struct FormValues { /* FieldId → FieldValue (visible and hidden fields) */ }
impl Form {
    pub fn builder() -> FormBuilder;
    pub fn values(&self) -> FormValues;
    pub fn set_visible(&mut self, id: FieldId, visible: bool);
    pub fn set_enabled(&mut self, id: FieldId, enabled: Result<(), String /* reason */>);
    pub fn set_error(&mut self, id: FieldId, msg: Option<String>);
    pub fn is_dirty(&self) -> bool;
    /// Runs field validators, then the cross-field validator; focuses the first error.
    pub fn validate(&mut self) -> bool;
}
impl FormBuilder {
    pub fn field(self, id: FieldId, label: &str, widget: FieldWidget) -> Self;
    pub fn help(self, text: &str) -> Self;                        // for the last field
    pub fn cross_validate(self, f: impl Fn(&FormValues) -> Vec<(FieldId, String)> + Send + 'static) -> Self;
    /// Called after any field changes (show/hide fields by protocol, T59).
    pub fn on_change(self, f: impl FnMut(&mut Form, FieldId) + Send + 'static) -> Self;
    pub fn build(self) -> Form;
}
/// A form in a dialog; `map` turns values into the typed result or field errors.
pub struct FormDialog<T> { /* title, Form, ButtonRow, map */ }
impl<T: Send + 'static> FormDialog<T> {
    pub fn new(title: &str, form: Form,
               map: impl Fn(&FormValues) -> Result<T, Vec<(FieldId, String)>> + Send + 'static) -> Self;
    pub fn buttons(self, ok: &str, cancel: &str) -> Self;        // default "OK" / "Cancel"
}
pub struct TabbedForm<T> { /* pages: Vec<(String, Form)>, active, map */ }

// ---- dialog/standard.rs ----
pub struct ConfirmOpts { pub yes: String, pub no: String, pub default_yes: bool, pub danger: bool }
impl ConfirmOpts {
    pub fn new() -> Self;                         // "OK"/"Cancel", default OK, not danger
    pub fn danger(yes: &str) -> Self;             // default and initial focus: Cancel
}
pub fn confirm(title: &str, text: &str, opts: ConfirmOpts) -> impl Dialog<Output = bool>;
pub enum MessageLevel { Info, Warning, Error }
pub fn message(title: &str, text: &str, level: MessageLevel) -> impl Dialog<Output = ()>;
pub fn error(context: &str, err: &(dyn std::error::Error + 'static)) -> impl Dialog<Output = ()>;
pub fn error_report(context: &str, report: &color_eyre::Report) -> impl Dialog<Output = ()>;
pub fn prompt_text(title: &str, label: &str, initial: &str, validate: Option<Validator>)
    -> impl Dialog<Output = String>;
pub fn prompt_password(title: &str, label: &str) -> impl Dialog<Output = SecretString>;
pub struct ChoiceOption { pub label: String, pub mnemonic: Option<char>, pub role: ButtonRole }
pub fn choose(title: &str, text: &str, options: Vec<ChoiceOption>) -> impl Dialog<Output = usize>;
pub struct ProgressOpts { pub show_after: Duration /* 300 ms */, pub cancellable: bool /* true */ }
pub fn progress(title: &str, message: &str, cancel: CancellationToken, opts: ProgressOpts)
    -> (impl Dialog<Output = ()>, ProgressHandle);
#[derive(Clone)] pub struct ProgressHandle { /* watch::Sender<ProgressState> */ }
impl ProgressHandle { pub fn set_message(&self, m: String); pub fn set_progress(&self, done: u64, total: Option<u64>);
                      pub fn finish(&self); }
pub fn text_viewer(title: &str, text: String) -> impl Dialog<Output = ()>;
/// Startup configuration problems collected by T50/T51.
pub fn problems(lines: Vec<String>) -> impl Dialog<Output = ()>;
```

`Action` gains `#[serde(skip)] Wake` (async widget result ready); T51's dialog actions
(`DialogSubmit`, `DialogCancel`, `DialogSave`, `NextField`, `PrevField`, `NextFormTab`,
`PrevFormTab`) are handled here.

### Behaviour

#### Modal stack

- Only the top dialog receives keys, pastes and `Dialog`-table actions (T50 routing).
  Order per key: top dialog `handle_key` (widgets inside consume text and their own keys)
  → if `Ignored`, T51 resolves in mode `Dialog` → `handle_action`.
- Every dialog is polled on each `Tick` and on `Wake`; a dialog showing a core prompt
  closes itself when `PromptRequest::is_withdrawn()` (T69 uses this).
- `Close(result)`: the dialog is popped and its result delivered (channel or `then`).
  Dropping a dialog without closing (e.g. `close_all`) delivers `None`.
- `Esc` (`DialogCancel`) on a dialog with `is_dirty()` pushes
  `confirm("Discard changes?", "Your changes will be lost.", danger("Discard"))`; on
  *Discard* both close with `None`; on cancel the form stays.
- Depth limit 8: a 9th push is refused, logged at `warn!`, and its receiver gets `None`.
- Quit (T50) and vault lock (T60) call `close_all()`. T50's `QuitConfirm` is replaced
  by `confirm(..., ConfirmOpts::danger("Quit"))`; T50/T51 startup problems open
  `problems(lines)` after the first frame.

#### Layout and rendering

- Area: `Fit` → width = clamp(content width + 4, `min_w`, min(`max_w`, screen − 4)),
  height = content rows + 2 borders, at most screen height − 2; `Percent` of the
  screen; `FullScreen` = whole screen (T60 unlock, T65 search view). Centred
  horizontally and vertically (rounded down).
- Background: every cell outside the top dialog gets `Modifier::DIM` added (colours
  kept), lower dialogs included; then `Clear` and the dialog block with `dialog_border`
  style, title left-aligned, sanitised (T55 `sanitize`).
- Content taller than the dialog: the body scrolls so the focused field (label, widget,
  error line) is fully visible; `▲`/`▼` (ASCII `^`/`v`) markers on the right border show
  hidden content.
- Screen smaller than 30×8 (or the dialog's own minimum): the dialog area shows
  `Terminal too small for this dialog` instead; keys still reach it (`Esc` works).
- Focus is visible without colour: the focused widget is drawn reversed (buttons, list
  cursor, checkbox) or shows the terminal cursor (text), and the focused field's label is
  bold with a `▶` (`>`) marker.
- All displayed strings that may come from outside (file names, server messages,
  errors) pass through `sanitize`; widget values typed by the user too (defence in depth).

#### Form

- Rows: `label │ widget`; label column width = min(longest visible label, 24) + 2,
  labels truncated with `…`; the widget gets the rest. Under a field with an error:
  `! message` in the `error` style (readable without colour). The focused field's help
  text is shown dim on the last body row.
- `Tab`/`Shift-Tab` (`NextField`/`PrevField`) move between visible, enabled fields and
  then the button row, wrapping. `↑`/`↓` move between fields too when the focused widget
  does not use them (text, checkbox, number field: number fields use them for ±1, so
  not there).
- Validation: a field's validator runs when focus leaves it and on submit; the
  cross-field validator runs on submit; `map` errors are shown the same way. Submit with
  errors is refused and focuses the first error. OK stays enabled (so the user learns
  why it fails).
- `DialogSubmit` (`Enter`) presses the default button unless the focused widget consumes
  `Enter` (an open `Select` popup, a `TextArea`, a `ListView` row activation, a focused
  button presses itself). `DialogSave` (`ctrl-s`) = submit, even from a `TextArea`.
- Hidden fields keep their values but are not validated and not focusable; disabled
  fields show their reason as help text and cannot be focused.
- `TabbedForm`: header row `[General]  Advanced  Transfer  Charset` (active page
  bracketed and bold); `NextFormTab`/`PrevFormTab` switch pages (wrapping). Submit
  validates all pages and switches to the first page with an error. Focus is kept per
  page.

#### Widget keys (fixed; inside the widget, before any key table)

| Widget | Keys |
|---|---|
| `TextInput`, `SecretInput`, `PathInput`, `NumberInput` | text editing keys from T51 (cursor by grapheme cluster, width by `unicode-width`, horizontal scroll keeps the cursor visible); word separators: whitespace and `/ \ . - _ : @` |
| `NumberInput` | digits (and `-` first when `min < 0`); `↑`/`↓` ±1, `PageUp`/`PageDown` ±10, clamped to the range |
| `Checkbox` | `space` toggles |
| `TriStateCheckbox` | `space` cycles On → Off → Unchanged → On when `allow_unchanged`, else On ↔ Off; rendered `[x]` `[ ]` `[-]` |
| `Select` (closed) | `space`, `alt-down` open the popup; `←`/`→` (`h`/`l`) select previous/next option without opening |
| `Select` (popup open) | `j`/`k`/`↑`/`↓`, `Home`/`End`, `PageUp`/`PageDown`, type-to-jump (case-insensitive prefix, buffer resets after 1 s), `Enter` chooses, `Esc` closes without change; disabled options are skipped |
| `RadioGroup` | `↑`/`↓`/`j`/`k` (or `←`/`→` when horizontal) move and select; `space` selects |
| `ButtonRow` | `←`/`→`/`h`/`l` move, `Enter`/`space` press; mnemonics: `alt-<letter>` always, plain letter when the focused widget is not text-like |
| `ListView` | `j`/`k`/`↑`/`↓`, `PageUp`/`PageDown`, `Home`/`End` (no multi-key sequences inside widgets), `space` marks or toggles the checkbox, `Enter` activates, `/` starts filtering (substring, case-insensitive; `Esc` clears), `K`/`J` move the item when reorderable; headers are skipped |
| `TextArea` | text editing keys plus `Enter` (newline), `↑`/`↓` (line), `PageUp`/`PageDown`; `Tab` leaves the field (no tab characters) |
| `TextView` | `j`/`k`/`↑`/`↓`, `PageUp`/`PageDown`, `Home`/`End`, `h`/`l`/`←`/`→` horizontal scroll, `/` search, `n`/`N` next/previous |

#### Paste

`handle_paste` on the focused text widget (T50 routes bracketed paste):
- Single-line fields: trailing `\r`/`\n` removed, remaining `\r\n`, `\r`, `\n` and `\t`
  each become one space, other C0/C1 controls and DEL are removed; inserted at the
  cursor. `TextArea`: `\r\n`/`\r` → `\n`, `\t` → 4 spaces, other controls removed.
- Pastes over `max_chars` (or 64 KiB for `TextArea`) are truncated and the status line
  says "Pasted text was cut to N characters". Paste content is never logged.
- Non-text focus (button, list): paste ignored.

#### Secret input

- Value kept in `Zeroizing<String>` (zeroed on drop and on `take`); rendered as one `•`
  (ASCII `*`) per character, so the real text never reaches the buffer; no reveal key, no
  copy, `Debug` prints `SecretInput(****)`. The terminal cursor is placed after the last
  bullet. `take()` returns a `SecretString` and clears the field.

#### Path completion

- `Tab` in a `PathInput` with a completer, cursor at the end, and no request in flight:
  spawn `completer.complete(value)` with a 3 s timeout; the task sends `Action::Wake`
  when done; `poll()` applies it. While in flight, further `Tab`s are consumed.
- Results: none → the `Tab` is treated as `NextField` (outcome `Ignored` for that Tab;
  empty results are cached until the value changes). One → replace the value (a
  directory gets a trailing separator). Several → insert the longest common prefix and
  open a popup list (≤ 10 rows) under the field; `Tab`/`↓` next, `Shift-Tab`/`↑` previous,
  `Enter` picks, `Esc` closes, typing closes and filters on the next `Tab`.
- Errors or timeout: status line "Completion failed: <reason>" (sanitised); value unchanged.
- `LocalPathCompleter`: expands a leading `~`; splits at the last separator (`/`, and
  `\` on Windows); lists the directory with `tokio::fs::read_dir`, at most 1 000 entries
  read; hidden entries only when the typed prefix starts with `.`; prefix match
  case-insensitive on Windows and macOS, case-sensitive elsewhere; sorted, directories
  marked. Remote completion is provided by T53/T62 through the listing cache.

#### Standard dialogs

| Function | Buttons (mnemonic) | Default / initial focus | Result |
|---|---|---|---|
| `confirm` | `yes` (first letter), `no` (first letter) | `default_yes` → yes; `danger` → no (Enter never confirms a danger dialog by accident) | `true` only for yes; `Esc` → `None` |
| `message` | `OK` (o) | OK | `()`; title prefixed `Info:`/`Warning:`/`Error:` so the level reads without colour |
| `error` / `error_report` | `OK` (o), `Details` (d) when the chain has > 1 entry | OK | first line = `context: top error`; Details expands `Caused by:` lines (each `source()`), sanitised, max 50 lines |
| `prompt_text` | `OK`, `Cancel` | OK | the text exactly as typed (not trimmed); validator errors inline |
| `prompt_password` | `OK`, `Cancel` | OK | `SecretString`; empty allowed |
| `choose` | one per option, in order | first `Safe` option, else the first | option index |
| `progress` | `Cancel` (c) when cancellable | — | not shown until `show_after`; closes on `finish()`; `Cancel`/`Esc` cancels the token and shows `Cancelling…` until `finish()`; determinate bar when `total` is known, else a moving block and spinner |
| `text_viewer` / `problems` | `Close` | Close | read-only `TextView`, content sanitised, up to 1 000 000 lines |

Dialog text wraps at word boundaries (`textwrap`-style, by display width) to the dialog
width; `Fit` dialogs use max width 76 columns, min 40.

### Data formats and configuration

No settings. Style keys added to the flat `styles` map (T50): `dialog_border`,
`dialog_title`, `field_label`, `field_label_focused`, `field_error`, `field_help`,
`input`, `input_placeholder`, `button`, `button_focused`, `button_danger`,
`list_cursor`, `list_marked`, `list_header`, `popup_border`, `progress_bar`. Under
`NO_COLOR` they reduce to modifiers (T50 rule). Symbols used from T50 `Symbols`:
checkbox and radio marks, `▾` dropdown, `•` mask, `▶` focus, `▲`/`▼` scroll markers,
spinner, progress block characters (`█░`, ASCII `#-`).

### Errors

- Widgets and dialogs do not fail: invalid input is shown inline (`! message`).
- `error()` / `error_report()` display `courier_ftp_core::Error` and `color_eyre`
  chains; messages are sanitised and never contain secrets (T02 errors never echo
  passwords).
- A dialog whose `render` panics is a bug; `render` returns nothing and must not panic
  on any size ≥ 1×1 (property test).
- Refused push (depth > 8) → `warn!` + `None` result.

### Security and logging

- `SecretInput` never renders, logs or `Debug`-prints its content, and zeroes it
  (`zeroize`); a snapshot test asserts the buffer never contains the typed password.
- Paste content and typed text are never logged; dialogs log only their kind at `debug!`
  (`dialog opened: confirm`), never titles or text at `info`+ (they may contain paths).
- All external text is sanitised before drawing (terminal escape injection, T91).
- `PathCompleter` results are untrusted (remote names): sanitised for display; a
  completion is inserted as text only, never executed.

## Implementation steps

1. `Widget` trait, `TextInput` (grapheme editing, scroll, validator, paste rules) with unit tests, using `ui::text` from T50.
2. `SecretInput`, `NumberInput`, `Checkbox`, `TriStateCheckbox`, `RadioGroup`, `ButtonRow`.
3. `Select` with popup and type-to-jump; `ListView` (sections, marks, checkboxes, filter, reorder, virtualised).
4. `Dialog` trait, `AnyDialog` erasure, `ModalStack` (`push`, `push_then`, depth limit, `close_all`), dimmed background, sizing, too-small fallback.
5. Standard dialogs; replace T50's `QuitConfirm`; startup `problems` dialog.
6. `Form`, `FormBuilder`, `FormDialog` (validation, visibility, dirty + discard confirm), `TabbedForm`.
7. `PathInput` + `LocalPathCompleter` + `Action::Wake`; `TextArea`; `TextView`.
8. `progress` dialog with `ProgressHandle`; snapshot tests for every widget and dialog at 80×24 and 160×48.

## Acceptance criteria

- [ ] AC1 Every widget and standard dialog has key-handling unit tests and insta snapshots at 80×24 and 160×48 (focused and unfocused, error state where applicable).
- [ ] AC2 A `SecretInput` containing `hunter2` never puts `hunter2` (or any of its characters in sequence) into the rendered buffer, `Debug` output or logs; the value is zeroed after `take()` (test inspects a `Zeroizing` mock).
- [ ] AC3 Bracketed paste of `"a\r\nb\tc\x1b[31m\n"` into a single-line field yields `a b c[31m`; into a `TextArea` yields two lines `a` and `b    c[31m`; pastes over `max_chars` are cut with a status message.
- [ ] AC4 Nested dialogs: a confirm opened on top of a dirty `FormDialog` receives all keys, closing it returns focus to the form with values intact; `Esc` on the dirty form asks "Discard changes?" and `Enter` there keeps editing (danger default).
- [ ] AC5 `Enter` in a `danger` confirm returns "no" without moving focus; `alt-<mnemonic>` and plain mnemonic letters press buttons (plain letters only when no text widget is focused).
- [ ] AC6 Form validation: a field validator error and a cross-field error both block submit, show `! message` under the right field and focus the first error; fixing them allows submit and the typed result is delivered.
- [ ] AC7 `push` delivers results over `oneshot` (awaited in a tokio test) and `push_then` delivers the mapped `Action`; `close_all` delivers `None` to every pending receiver.
- [ ] AC8 Dialogs and widgets never panic for any screen size from 1×1 to 300×100 (property test) and show `Terminal too small for this dialog` below 30×8 while `Esc` still closes them.
- [ ] AC9 `PathInput` with `LocalPathCompleter` completes a unique match, inserts the common prefix and shows the popup for several, and falls through to the next field when there is no match (temp-dir test).
- [ ] AC10 `progress` is not drawn when `finish()` comes within 300 ms, is drawn after 300 ms, and `Cancel` cancels the token and shows `Cancelling…` until `finish()`.
- [ ] AC11 Dialog text from untrusted sources is sanitised: a title or message containing `\x1b]52;c;…\x07` renders as caret notation.
- [ ] AC12 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os` pass.

## Tests

### Unit tests
- `text_input_editing_table` — rows of (initial, cursor, key) → (value, cursor) for every editing key, including grapheme clusters (`e\u{301}`, emoji ZWJ sequences) and wide chars. AC1.
- `text_input_word_separators` — `ctrl-w` in `/var/www/html` deletes `html`, then `www/`. AC1.
- `text_input_scrolls_to_cursor` — 200-char value in a 20-column field. AC1.
- `text_input_max_chars_and_validator`. AC1, AC6.
- `secret_input_never_exposes_value` — render, `Debug`, `format!("{:?}")`. AC2.
- `secret_input_take_clears_and_zeroizes`. AC2.
- `number_input_digits_range_and_arrows` — rejects letters, clamps 0..=65535, `↑` at max stays. AC1.
- `tristate_cycle_with_and_without_unchanged`. AC1.
- `select_popup_type_to_jump_and_disabled_skip` — buffer resets after 1 s (injected time). AC1.
- `radio_group_vertical_and_horizontal`. AC1.
- `button_mnemonics_alt_and_plain` — plain `c` is typed into a focused text field, `alt-c` presses Cancel. AC5.
- `list_view_sections_filter_marks_reorder` — headers skipped; `/` filter; `K`/`J` reorder; 1 000 000 rows render only visible rows. AC1.
- `paste_single_line_rules` and `paste_text_area_rules` — AC3.
- `paste_truncation_message` — AC3.
- `confirm_danger_default_is_no` — AC5.
- `choose_initial_focus_safe_option`.
- `error_dialog_shows_cause_chain` — three nested `thiserror` errors → three lines after Details. AC1.
- `form_field_and_cross_validation` — AC6.
- `form_hidden_fields_not_validated_nor_focusable`, `form_disabled_field_shows_reason`.
- `form_dirty_tracking` — change and change back → not dirty.
- `tabbed_form_switches_to_first_page_with_error` — AC6.
- `modal_depth_limit_refuses_ninth` — receiver gets `None`.
- `dialog_text_is_sanitised` — AC11.

### Property / fuzz tests
- `prop_text_input_never_panics` — random key sequences and pastes (arbitrary Unicode) keep `cursor <= len` in graphemes and never panic. AC1.
- `prop_render_any_size` — every standard dialog and a sample form rendered at random sizes 1×1…300×100. AC8.
- `prop_paste_single_line_has_no_controls` — arbitrary strings → output has no C0/C1/DEL. AC3.

### Snapshot tests
At 80×24 and 160×48 each (`insta`, `TestBackend`, background = T50 Classic shell, dimmed):
- `snap_confirm`, `snap_confirm_danger`, `snap_message_info|warning|error`, `snap_error_details`,
  `snap_prompt_text_with_error`, `snap_prompt_password` (typed `hunter2`), `snap_choose`,
  `snap_progress_determinate`, `snap_progress_indeterminate`, `snap_progress_cancelling`,
  `snap_text_viewer`, `snap_problems`. AC1, AC2, AC10.
- `snap_form_all_widgets` — one form with every widget kind, focus on each in turn (one snapshot per focus at 80×24, one overview at 160×48). AC1.
- `snap_select_popup_open`, `snap_path_completion_popup`, `snap_list_view_sections_filter`, `snap_tabbed_form_page2`. AC1, AC9.
- `snap_nested_confirm_over_form` — AC4.
- `snap_dialog_too_small_30x8` and `snap_dialog_scrolled_form_80x24` — AC8.
- `snap_ascii_symbols_form` — `unicode_symbols = Off`.

### Integration tests
- `push_returns_result_over_oneshot` and `push_then_sends_action` (`AppHarness`). AC7.
- `close_all_cancels_pending_receivers`. AC7.
- `nested_dialog_focus_returns_to_form` — AC4.
- `escape_on_dirty_form_asks_discard` — AC4.
- `local_path_completion_in_tempdir` — unique, multiple (common prefix + popup), none (falls through), hidden only with `.` prefix, 3 s timeout with a stalled completer (paused time). AC9.
- `progress_show_after_and_cancel` (`start_paused`). AC10.
- `quit_confirm_uses_standard_confirm` — T50 quit flow now shows `confirm` with *Quit* / *Cancel*.
- `startup_problems_dialog_shown` — config with a bad key → `problems` dialog after the first frame.

### End-to-end tests
- `e2e_pty_paste_into_quickconnect_host` (`PtyApp`, after T58) — bracketed paste of a multi-line string arrives as one line. AC3.
- Manual check: bracketed paste in xterm, tmux (`set -g set-clipboard on` not required), Windows Terminal.

## Out of scope

- Mouse interaction (D7).
- Rich text editing (undo/redo, selection with shift+arrows) in `TextInput`/`TextArea`.
- Feature-specific dialogs (they live in their tasks: T59, T60, T62, T69, …).
- A file picker dialog beyond `PathInput` completion.

## Open questions

- **Dependency order with T55 (not owned):** this task (M1, before T55) needs
  `ui::text::sanitize`, which T55 specifies and lists as its first step. T50 now
  implements `ui/text.rs` to T55's specification (see T50 Open questions); T55's owner
  should treat it as existing. No change to T55's API is needed.
- **T62 (not owned)** describes confirm calls as `confirm(title, text, default No)`;
  this task's signature is `confirm(title, text, ConfirmOpts)` with
  `ConfirmOpts::danger(..)` for "default No". T62/T63/T64 should use that form.
