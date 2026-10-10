# T50 — App shell and layout

**Phase:** F TUI · **Milestone:** M1 · **Depends on:** T01, T04, T05 · **Crate(s):** `courier-ftp` (`app.rs`, `action.rs`, `components.rs`, `components/main_screen/`, `ui/`, `runtime.rs`, `tui.rs`, `config.rs`, `crates/courier-ftp/config/config.json`) · **Decisions:** D6, D7, D10 · **FEATURES.md:** §3 (interface layout, layout options, show/hide panes)
**Related (integrates with, not blocking):** T51, T52, T53, T55, T57
**Reference:** sverb `crates/sverb-tui/src/testing.rs` (`AppHarness`), `src/theme/` (themes, `NO_COLOR`, ASCII glyph post-pass), `src/widgets/statusbar.rs`, SPEC §8.1, §8.8

## Goal

Replace the template's `Home` hello-world with the courier-ftp main screen: the
FileZilla-style arrangement of quickconnect bar, tab bar, message log, local and remote
panes (tree + file list), queue and status bar, in three layouts that the user can
switch and toggle at runtime. The task also builds the application skeleton every UI
task plugs into: focus and key routing by mode, a modal stack, the bridge from core
events, a runner for async work that never blocks drawing, the theme and glyph sets,
and a test harness that renders the app into a `TestBackend` for snapshot tests.

## Context

- Before: the template (`app.rs` with a flat `Vec<Box<dyn Component>>` that receives
  every event, `Mode::Normal` only, `last_tick_key_events` cleared on each tick,
  `Home` component, mouse capture off, bracketed paste off, `info!` per action); T01
  removed the `Core { ticks }` placeholder and set up `COURIER_FTP_HOME`; T04 provides
  `EventReceiver` with `CoreEvent` (incl. `Prompt(PromptRequest)`, coalesced
  `TransferProgress`); T05 provides `Settings` inside `Config.settings`, the
  `interface.*` keys (`layout`, `swap_panes`, `show_tree`, `show_log`, `show_queue`,
  `show_quickconnect`, `theme`, `unicode_symbols`) and `Settings::save_user`.
- After: T51 replaces the key resolver with the full keymap (sequences, timeout,
  conflicts) and fills the `Action` list; T52 implements dialogs on the modal stack;
  T53/T54/T55/T56/T57/T58/T61 replace the placeholder regions; T60 shows the unlock
  view as a full-screen modal before the panes; T69 answers prompts from the prompt
  queue; T62/T63/T65 use the runner and the quit-blocker hook.
- This task **owns** the shared UI helpers every later UI task uses: `ui::text`
  (`sanitize`, `sanitize_spans`, `truncate_to_width`), `ui::symbols` (`Symbols`,
  `TermEnv`, `UnicodeSymbols`; T57 only adds status-bar glyphs to `Symbols`) and
  `tabs::TabId(u32)`. Tasks that need only these helpers depend on T50, not on T55/T57.
  `ui::clipboard` is owned by T55.

## Technical specification

### Types and APIs

```rust
// app.rs — key tables and styles in crates/courier-ftp/config/config.json are keyed by these names.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter)]
pub enum Mode {
    /// Global table; consulted last in every non-modal chain.
    #[default] Normal,
    FileList,   // a file list pane has focus (T53)
    Tree,       // a directory tree has focus (T54)
    Log,        // message log (T55)
    Queue,      // queue pane (T56)
    SiteManager,// Site Manager tree (T59); full-screen modal
    Filter,     // typing a pane quick filter (T53)
    Input,      // a single-line text field outside dialogs (quickconnect T58, `:` line T62, log search T55)
    Dialog,     // a modal is open (T52); the only table consulted then
}

impl Mode {
    /// Tables consulted for a key, highest priority first.
    /// Dialog → [Dialog]; SiteManager → [SiteManager]; Normal → [Normal];
    /// any other mode m → [m, Normal].
    pub fn chain(self) -> &'static [Mode];
}

// components/main_screen/layout.rs — pure, unit-tested
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Region { Quickconnect, TabBar, Log, LocalTree, LocalList, RemoteTree, RemoteList, Queue, StatusBar }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutOptions {
    pub layout: Layout,              // T05 enum: Classic | Explorer | Widescreen
    pub swap_panes: bool,
    pub show_tree: bool,
    pub show_log: bool,
    pub show_queue: bool,
    pub show_quickconnect: bool,
    pub focus: Region,               // needed by compact mode
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreenLayout {
    /// Region → area; regions not shown are absent.
    Regions { areas: BTreeMap<Region, Rect>, compact: bool, effective: Layout },
    TooSmall { width: u16, height: u16 },
}

pub fn compute_layout(area: Rect, opts: &LayoutOptions) -> ScreenLayout;
/// Focusable regions in visual order (top→bottom, left→right) for this layout.
pub fn focus_order(layout: &ScreenLayout) -> Vec<Region>;

// action.rs
/// Messages between the event loop, `App` and components. Unit variants that are
/// not `#[serde(skip)]` are **bindable**: they can appear in `keybindings` (T51).
/// No `PartialEq`: later variants carry `Arc<Error>` payloads (T53, T62); tests
/// compare with `matches!`.
#[derive(Debug, Clone, Display, Serialize, Deserialize)]
pub enum Action {
    // internal (never bindable)
    #[serde(skip)] Tick,
    #[serde(skip)] Render,
    #[serde(skip)] Resize(u16, u16),
    #[serde(skip)] Resume,
    #[serde(skip)] ClearScreen,
    #[serde(skip)] Error(String),
    #[serde(skip)] StatusMessage(String),       // transient, 3 s (T57 shows it; T50 placeholder too)
    #[serde(skip)] FocusRegion(Region),
    #[serde(skip)] TaskFinished(TaskId),
    #[serde(skip)] SettingsSaved(Result<(), String>),
    #[serde(skip)] QuitConfirmed,
    // bindable (T50's initial set; T51 adds the rest; keys in T51's table)
    Help, Quit, Suspend, Redraw, Cancel,
    FocusOtherSide, FocusNextRegion, FocusLog, FocusQueue, FocusFiles,
    FocusRegion1, FocusRegion2, FocusRegion3, FocusRegion4, FocusRegion5,
    FocusRegion6, FocusRegion7,
    ToggleLog, ToggleQueuePane, ToggleTree, ToggleQuickconnect, SwapPanes,
    LayoutClassic, LayoutExplorer, LayoutWidescreen,
}

// tabs.rs — created here; T55 adds `TabRoute`, T53/T61 extend it.
/// A tab. Before T61 the only tab is `TabId(0)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TabId(pub u32);

// components.rs — the template trait, extended. Mouse handling is removed (D7).
pub trait Component {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> { Ok(()) }
    fn register_config_handler(&mut self, config: Arc<Config>) -> Result<()> { Ok(()) }
    fn init(&mut self, area: Size) -> Result<()> { Ok(()) }
    /// Key table this component wants while focused (e.g. FileList, or Filter while typing).
    fn key_mode(&self) -> Mode { Mode::Normal }
    /// Raw key before the keymap. Text widgets consume printable/editing keys here;
    /// everything else returns `Ignored`.
    fn handle_key(&mut self, key: KeyChord) -> Result<KeyOutcome> { Ok(KeyOutcome::Ignored) }
    fn handle_paste(&mut self, text: &str) -> Result<KeyOutcome> { Ok(KeyOutcome::Ignored) }
    /// Actions (from the keymap or other components). REQUIRED in spirit: most logic lives here.
    fn update(&mut self, action: &Action) -> Result<Option<Action>> { Ok(None) }
    fn on_core_event(&mut self, event: &CoreEvent) -> Result<Option<Action>> { Ok(None) }
    /// True while this component waits for async work (drives the spinner and redraws).
    fn is_busy(&self) -> bool { false }
    /// Reason to confirm before quitting ("2 transfers are running"), if any.
    fn quit_blocker(&self) -> Option<String> { None }
    fn draw(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) -> Result<()>;
}

pub enum KeyOutcome { Consumed(Option<Action>), Ignored }

/// Read-only context for drawing.
pub struct DrawCx<'a> {
    pub theme: &'a Theme,
    pub symbols: &'a Symbols,
    pub focused: bool,
    pub now: Instant,               // tokio Instant; spinners derive frames from it
}

// keymap/chord.rs — introduced here, parser grammar added in T51.
/// A normalised key: shifted ASCII letters are stored uppercase without SHIFT,
/// SHIFT is dropped from other printable chars, `BackTab` = `Tab`+SHIFT,
/// legacy 0x1C–0x1F map to ctrl-\ ctrl-] ctrl-^ ctrl-_ (adapted from sverb chord.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyChord { pub code: KeyCode, pub mods: Mods }
impl KeyChord { pub fn from_key_event(ev: KeyEvent) -> Self; pub fn new(code: KeyCode, mods: Mods) -> Self; }

// keymap/resolver.rs — T50 version: single-chord lookup only; T51 replaces internals.
pub struct KeyResolver { /* tables: HashMap<Mode, HashMap<Vec<KeyChord>, Action>> */ }
pub enum Resolution { Action(Action), Pending, Unbound }
impl KeyResolver {
    pub fn from_config(config: &Config) -> (Self, Vec<KeymapProblem>);
    pub fn resolve(&mut self, key: KeyChord, mode: Mode, now: Instant) -> Resolution;
    pub fn deadline(&self) -> Option<Instant>;          // always None in T50
    pub fn on_timeout(&mut self, now: Instant);
    pub fn pending_display(&self) -> Option<String>;    // None in T50
    /// Effective bindings for the help overlay.
    pub fn bindings(&self, chain: &[Mode]) -> Vec<(Mode, Vec<KeyChord>, Action)>;
}

// runtime.rs — async work started by the UI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] pub struct TaskId(u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskOwner { Region(Region), Tab(TabId), App }
pub struct Runner { /* JoinSet, action_tx, root CancellationToken, busy: HashMap<TaskOwner, u32> */ }
impl Runner {
    /// Spawn `make(token)`; its output Action is sent to the action channel, then
    /// `Action::TaskFinished(id)`. `token` is a child of the app token.
    pub fn spawn<F, Fut>(&mut self, owner: TaskOwner, make: F) -> TaskId
    where F: FnOnce(CancellationToken) -> Fut, Fut: Future<Output = Action> + Send + 'static;
    pub fn cancel(&mut self, id: TaskId);
    pub fn cancel_owner(&mut self, owner: TaskOwner);
    pub fn is_busy(&self, owner: TaskOwner) -> bool;
    /// Cancel everything; wait up to 2 s, then abort the rest.
    pub async fn shutdown(&mut self);
}

// ui/theme.rs, ui/symbols.rs, ui/text.rs
/// `ThemePreset` = T05 `settings::enums::Theme` (`default` | `high_contrast` | `monochrome`),
/// imported under this name because `Theme` here is the resolved style table.
pub use courier_ftp_core::settings::enums::Theme as ThemePreset;
pub struct Theme { /* named styles, see Data formats */ }
impl Theme {
    pub fn load(preset: ThemePreset, overrides: &HashMap<String, String>, no_color: bool)
        -> (Self, Vec<String /* warnings */>);
    pub fn style(&self, key: &str) -> Style;            // unknown key → Style::default() (debug_assert in tests)
    pub fn site_accent(&self, color: SiteColor) -> Style;
}
// ui/symbols.rs (owned here; T57 adds status-bar glyph fields only)
pub use courier_ftp_core::settings::enums::UnicodeSymbols; // T05: auto | always | never
/// Terminal environment snapshot (read once at startup; tests build it by hand).
#[derive(Debug, Clone, Default)]
pub struct TermEnv { pub term: Option<String>, pub lc_all: Option<String>,
                     pub lc_ctype: Option<String>, pub lang: Option<String>,
                     pub wt_session: bool,              // WT_SESSION set (Windows Terminal)
                     pub term_program: Option<String>,  // TERM_PROGRAM
                     pub no_color: bool,                // NO_COLOR set and non-empty
                     pub ssh_connection: bool, pub ssh_tty: bool, pub windows: bool }
impl TermEnv {
    pub fn from_process() -> Self;
    /// `SSH_CONNECTION` or `SSH_TTY` set (used by T55's clipboard).
    pub fn over_ssh(&self) -> bool;
}
pub struct Symbols { /* glyph set, see Behaviour */ pub unicode: bool }
impl Symbols { pub fn resolve(setting: UnicodeSymbols, env: &TermEnv) -> Self; }

// ui/text.rs (owned here)
/// Make untrusted text safe to draw: C0 controls (incl. TAB, CR, LF) become caret
/// notation (`^[`, `^I`, `^M`), DEL becomes `^?`, C1 controls (U+0080–U+009F), bidi
/// controls (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069) and line/paragraph
/// separators (U+2028, U+2029) become `<U+XXXX>`. Returns `Cow::Borrowed` when the
/// input needs no change (fast path over bytes).
pub fn sanitize(s: &str) -> Cow<'_, str>;
/// As `sanitize`, but returns spans so escapes can be drawn in `text.escape` style.
pub fn sanitize_spans<'a>(s: &'a str, base: Style, escape: Style) -> Vec<Span<'a>>;
/// Cut to `width` display columns (`unicode-width`), appending `ellipsis`
/// (`…`, or `~` in ASCII mode); never splits a wide char.
pub fn truncate_to_width(s: &str, width: usize, ellipsis: &str) -> Cow<'_, str>;

// testing.rs (cfg(test) and feature "test-util")
pub struct AppHarness { /* App without a terminal, virtual clock */ }
impl AppHarness {
    pub fn new(config: Config) -> Self;
    pub fn key(&mut self, key: KeyChord) -> &mut Self;
    pub fn paste(&mut self, text: &str) -> &mut Self;
    pub fn core_event(&mut self, ev: CoreEvent) -> &mut Self;
    pub fn advance(&mut self, by: Duration) -> &mut Self;   // tokio paused time
    pub fn settle(&mut self) -> &mut Self;                   // drain actions and finished tasks
    pub fn render(&mut self, width: u16, height: u16) -> String;  // TestBackend text
    pub fn buffer(&mut self, width: u16, height: u16) -> Buffer;  // with styles
    pub fn focus(&self) -> Region;
    pub fn mode(&self) -> Mode;
}
```

Component tree (one `App`, one root):

```
App ── owns Tui, Config (Arc), KeyResolver, Runner, EventReceiver (T04), PromptQueue
 └─ MainScreen
     ├─ QuickconnectBar            (T58; placeholder until then)
     ├─ TabBar                     (T61; until then one tab titled "Local")
     ├─ MessageLog                 (T55; placeholder)
     ├─ tabs: Vec<TabView>, active (exactly one tab until T61)
     │    └─ TabView { local: SideView { tree: DirTree (T54), list: FileList (T53) },
     │                 remote: SideView { tree, list } }
     ├─ QueuePane                  (T56; placeholder)
     ├─ StatusBar                  (T57; T50 minimal version)
     └─ ModalStack                 (help overlay here; dialogs from T52; T60 unlock)
```

A placeholder is a bordered block titled with the region name and a dim line
`(not available yet)`; it is focusable where the real component will be.

### Behaviour

#### Event loop

```
loop {
  select! (biased) {
    terminal event      => handle_terminal_event        // keys, paste, resize, focus
    core event (T04)    => handle_core_event
    sleep_until(resolver.deadline()), if Some => resolver.on_timeout(now)
    action_rx           => (drained below)
  }
  drain up to 256 actions from action_rx through dispatch (rest next iteration)
  if quit && runner.shutdown() done → break
}
```
- `Tui` is created with `.paste(true)` (bracketed paste on) and mouse capture stays off (D7).
- **Rendering**: a `Render` event draws only when `dirty` (set by any key, paste, action
  that a component handled, core event, resize, task completion) or when animating
  (a busy owner or a status message younger than 3 s) and the spinner frame changed
  (frames every 100 ms). Idle CPU is therefore ~0 even at `--frame-rate 60`.
- `Tick` (4 Hz default) is still sent to components for timers (status message expiry).
- Logging: each dispatched bindable action at `trace!` with its name only; no paths,
  hosts or users at `info`+ (T91). The template's `info!("Got action")` is removed.

#### Key routing (first match wins)

1. **Modal open**: the top modal gets `handle_key`; if `Ignored`, the resolver resolves
   in the top modal's `key_mode()` (`Dialog` for every modal except the Site Manager
   tree, which uses `SiteManager`) and the resulting action goes to the top modal only. Nothing below
   the modal sees the key.
2. **Focused component raw key**: `handle_key` on the focused component (text input in
   modes `Input`/`Filter` consumes printable chars and editing keys).
3. **Keymap**: `resolver.resolve(key, mode, now)` over `mode.chain()`, where `mode` is
   the focused component's `key_mode()`. `Action(a)` → dispatch; `Pending` → wait
   (T51); `Unbound` → ignored (no beep).
4. **Dispatch**: App-level actions (`Quit`, `Suspend`, `Redraw`, `Help`, focus, toggles,
   layouts, `SwapPanes`) are handled by `App`/`MainScreen`; every other action goes to
   the focused component's `update`, and actions a component returns are queued.
   `Cancel` goes to the focused component (cancel its running task).
- **Paste** (`Event::Paste`): to the top modal, else to the focused component's
  `handle_paste`; ignored when nobody consumes it.

#### Focus

- Focusable: `Quickconnect`, `LocalTree`, `LocalList`, `RemoteTree`, `RemoteList`,
  `Log`, `Queue`, only when visible in the current layout. Initial focus: `LocalList`.
- `FocusOtherSide` (default `Tab`, MC): from any local region → `RemoteList`, from any
  remote region → `LocalList`; from `Log`/`Queue`/`Quickconnect` → the last focused list.
- `FocusNextRegion` (default `Shift-Tab`): next region in `focus_order` (wraps).
- `FocusLog`, `FocusQueue`, `FocusFiles` (last focused list); `FocusRegion(r)` internal.
- `FocusRegion1` … `FocusRegion7` (T51 `ctrl-x 1` … `ctrl-x 7`): 1 `Quickconnect`,
  2 `LocalTree`, 3 `LocalList`, 4 `RemoteTree`, 5 `RemoteList`, 6 `Log`, 7 `Queue`.
  A hidden region is handled like `FocusLog` on a hidden log: log/queue/quickconnect
  are shown in compact mode, otherwise status message "‹Region› is hidden (‹key›
  shows it)"; hidden trees → "Directory trees are hidden (Ctrl-e shows them)".
  Focusing a hidden log/queue shows it in compact mode (see below), otherwise it is a
  no-op with status message "Message log is hidden (Ctrl-l shows it)".
- If the focused region disappears (toggle, resize), focus moves to the last focused
  list, else `LocalList`.
- The focused region draws its border with style `border_focused` **and** a different
  border type (`BorderType::Thick`) and title prefix `▶` (`>` in ASCII), so focus is
  visible without colour.

#### Layouts

All sizes in terminal cells; `W`×`H` = terminal size. Rows from the top:
quickconnect (1 row, if `show_quickconnect`), tab bar (1 row), body, status bar
(1 row, last line). Within the body (Classic and Explorer):

| Region | Height rule |
|---|---|
| Log (if `show_log`) | `clamp(H / 6, 3, 10)`, borders included, at the top of the body |
| Queue (if `show_queue`) | `clamp(H / 5, 4, 12)`, at the bottom of the body |
| Sides | the rest; if the rest is < 8 rows, hide the queue, then the log, and recompute |

- **Classic**: sides side by side, left width `ceil(W/2)`; inside a side, the tree (if
  `show_tree` and side height ≥ 14) takes `max(5, side_h * 2 / 5)` rows on top, the list
  the rest.
- **Explorer**: sides stacked (first side on top, `ceil(h/2)` rows); inside a side, the
  tree (if `show_tree` and `W ≥ 60`) takes `clamp(W * 3 / 10, 16, 40)` columns on the
  left, the list the rest.
- **Widescreen** (needs `W ≥ 120`, otherwise rendered as Classic and `effective`
  reports Classic): body split into a left column of `W * 62 / 100` columns holding the
  sides as in Classic, and a right column with the log on top and the queue below
  (each half; one takes the full column if the other is hidden; both hidden → sides
  take the full width).
- `swap_panes`: remote side first (left, or top in Explorer).
- **Compact mode** (`W < 80` or `H < 24`, but at least 40×10): rows = tab bar, body,
  status bar; quickconnect appears as row 0 only while focused. The body shows exactly
  one region: the focused one among `LocalList`, `RemoteList`, `Log`, `Queue` (trees
  are not shown; `FocusNextRegion` skips them). `Tab` switches local/remote as usual.
  The status bar shows `compact` so the user knows panes are hidden.
- **Too small** (`W < 40` or `H < 10`): the whole screen shows a centred
  `Terminal too small: 38×9 (need 40×10)`. Keys keep working (quit, modals).

Mock-ups (illustrative; the insta snapshots are normative).

Classic, 80×24, trees off:
```
 Host: [web01.example.com ] User: [alice   ] Pass: [••••    ] Port: [22 ] Connect
 1 web01 ●
┏▶Message log━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃Status:   Connected to web01                                                  ┃
┃Response: 226 Transfer complete                                               ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
┌ Local ─────────────────────────────────┐┌ Remote · web01 ───────────────────────┐
│~/projects/site                         ││/var/www                               │
│Name             Size Modified          ││Name            Size Modified          │
│..                                      ││..                                     │
│assets/               2026-10-01 12:00  ││html/                2026-09-30 09:12  │
│index.html      4 KiB 2026-10-08 18:22  ││index.html     4 KiB 2026-10-02 10:00  │
│                                        ││                                       │
│                                        ││                                       │
│1 file, 1 directory. Total 4 KiB        ││1 file, 1 directory. Total 4 KiB       │
└────────────────────────────────────────┘└───────────────────────────────────────┘
┌ Queue (1) · Failed (0) · Successful (14) ────────────────────────────────────┐
│↑ index.html → /var/www/index.html  4 KiB  62% ███████░░░░ 1.2 MiB/s 00:01    │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
 NORMAL │ 🔒 SSH │ Queue: 1 file, 4 KiB                       F1 help  F10 quit
```

Explorer, 80×24, trees on, log and queue hidden:
```
 1 web01 ●
┌ Local tree ──────────┐┏▶Local━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
│▾ /                   │┃~/projects/site                                         ┃
│  ▾ home              │┃Name                     Size Modified                  ┃
│    ▾ alice           │┃..                                                      ┃
│      ▸ projects      │┃index.html              4 KiB 2026-10-08 18:22          ┃
│                      │┃1 file. Total 4 KiB                                     ┃
└──────────────────────┘┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
┌ Remote tree ─────────┐┌ Remote · web01 ────────────────────────────────────────┐
│▾ /                   ││/var/www                                                │
│  ▾ var               ││Name                     Size Modified                  │
│    ▸ www             ││..                                                      │
│                      ││html/                         2026-09-30 09:12          │
│                      ││index.html              4 KiB 2026-10-02 10:00          │
│                      ││1 file, 1 directory. Total 4 KiB                        │
└──────────────────────┘└────────────────────────────────────────────────────────┘
 NORMAL │ 🔒 SSH                                             F1 help  F10 quit
```
(Quickconnect hidden in this example; rows not to scale.)

Widescreen, 120 columns (excerpt):
```
 Host: [web01.example.com ] User: [alice ] Pass: [•••• ] Port: [22 ] Connect
 1 web01 ●
┌ Local ──────────────────────────────┐┌ Remote · web01 ─────────────────────┐┌ Message log ────────────────────────────┐
│~/projects/site                      ││/var/www                             ││Status:   Connected to web01             │
│Name            Size Modified        ││Name           Size Modified         ││Response: 226 Transfer complete          │
│..                                   ││..                                   │└─────────────────────────────────────────┘
│index.html     4 KiB 2026-10-08 18:22││index.html    4 KiB 2026-10-02 10:00 │┌ Queue (1) · Failed (0) · Successful (14)┐
│                                     ││                                     ││↑ index.html  62% ████░░ 1.2 MiB/s       │
└─────────────────────────────────────┘└─────────────────────────────────────┘└─────────────────────────────────────────┘
 NORMAL │ 🔒 SSH │ Queue: 1 file, 4 KiB                                                                F1 help  F10 quit
```

Compact, 60×16, focus on the remote list:
```
 1 web01 ●
┏▶Remote · web01━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃/var/www                                                  ┃
┃Name                          Size Modified               ┃
┃..                                                        ┃
┃html/                              2026-09-30 09:12       ┃
┃index.html                   4 KiB 2026-10-02 10:00       ┃
┃                                                          ┃
┃1 file, 1 directory. Total 4 KiB                          ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
 NORMAL │ compact: Tab = other side, Shift-Tab = log/queue
```

#### Toggles and persistence

`ToggleLog` (`ctrl-l`), `ToggleQueuePane` (`ctrl-x j`), `ToggleTree` (`ctrl-e`),
`ToggleQuickconnect` (`ctrl-x q`; T58 owns the bar, this task the layout effect),
`SwapPanes` (`g x`), `LayoutClassic/Explorer/Widescreen` (`z 1`/`z 2`/`z 3`) change `Settings.interface` in memory, mark dirty,
and schedule `Settings::save_user` (T05) 1 s after the last change on a blocking task;
the result arrives as `SettingsSaved`. A failed save shows status message
"Could not save settings: <reason>" and logs `warn!` (reason only, no path at `info`+).

#### Async work (runner)

- UI code never awaits network or disk I/O in `handle_key`/`update`/`draw`. It calls
  `Runner::spawn(owner, |token| async move { …; Action::… })`. The future's output
  comes back through the action channel; `TaskFinished(id)` follows it.
- `is_busy(owner)` drives spinners: a region title shows the spinner frame
  `Symbols::spinner[(now_ms / 100) % len]` while its owner is busy for more than 150 ms.
- On quit, `Runner::shutdown` cancels the root token, waits up to 2 s for tasks to end,
  then aborts the rest (`JoinSet::abort_all`); no task outlives `App::run`.
- `Cancel` (T51 default `Ctrl-c`) cancels the focused owner's tasks; with nothing
  running it shows "Nothing to cancel — press F10 or Ctrl-q to quit".

#### Core event bridge

`handle_core_event(ev)`:
- `Prompt(req)` → `PromptQueue` (FIFO). Until T69 implements the prompt dialogs, each
  kind without a dialog is answered by dropping the request (the core treats a dropped
  reply as cancel, T04) and logs `warn!("prompt kind {kind_name} not supported yet")`.
- Every other event → `MainScreen::on_core_event(&ev)`, which forwards it to every
  component (`on_core_event`) and marks the screen dirty. `TransferProgress` is already
  coalesced by T04's receiver (at most one per transfer per drain).

#### Quit and suspend

- `Quit` (T51 defaults `F10`, `Ctrl-q`): collect `quit_blocker()` from all components
  (queue running, unsaved queue, edited files, unsaved forms). None → quit. Otherwise
  push a confirm modal "Quit courier-ftp?" listing the reasons, buttons *Quit* /
  *Cancel* (default *Cancel*). Pressing `Quit` again while that modal is open confirms.
  T50 ships a minimal `QuitConfirm` modal; T52 replaces it with `confirm()`.
- `Suspend` (`Ctrl-z`): Unix → `Tui::suspend` (raises `SIGTSTP`), on resume `Resume` +
  `ClearScreen`. Windows → status message "Suspend is not supported on Windows".
- `Redraw`: `terminal.clear()` then full redraw.

#### Help overlay

`Help` (T51: `F1`, `?`) pushes a full-screen modal listing the effective bindings for
the chain of the mode that was active when it opened, grouped by table (`FileList`
first, then `Normal`), as rows `keys │ action │ description`. Content comes from
`KeyResolver::bindings` (never hard-coded); T51 adds descriptions and groups. Keys:
`j`/`k`/arrows scroll, `PageUp`/`PageDown`, `/` filters rows by substring, `Esc`, `q`,
`F1` close.

#### Theme, colours and glyphs

- Preset from `interface.theme` (`Default`, `HighContrast`, `Monochrome`); `NO_COLOR`
  set to a non-empty value forces `Monochrome`. Monochrome keeps only modifiers: cursor =
  `REVERSED`, selection = `BOLD | UNDERLINED`, focused border = `BOLD` + thick border,
  dim text = `DIM`. No information is carried by colour alone (glyphs and text carry it).
- `styles` in the config is a flat map of style keys to style strings (template
  syntax: `"bold yellow on blue"`), applied over the preset. Unknown keys → warning.
- `Symbols` (`ui/symbols.rs`): Unicode set (`┌─┐`, `▶`, `▾`/`▸`, `●`/`○`, `•`, `✓`, `⚠`,
  braille spinner `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`) or ASCII set (`+-|`, `>`, `v`/`>`, `*`/`o`, `*`,
  `+`, `!`, spinner `|/-\`). `interface.unicode_symbols` (T05 `UnicodeSymbols`):
  `always`, `never`, or `auto` = ASCII when any of: `TERM` is `linux`, `dumb` or
  `vt100`; on Unix the first non-empty of `LC_ALL`, `LC_CTYPE`, `LANG` is unset or does
  not contain `UTF-8`/`utf8` (case-insensitive); on Windows neither `WT_SESSION` nor
  `TERM_PROGRAM` is set (classic console). Otherwise Unicode. Resolved at startup and on
  settings change. Other tasks add their own glyphs as fields of `Symbols`
  in this module (T53 file-type marks, T57 status-bar glyphs) — never a second type. ASCII mode also
  uses `BorderType::Plain` with ASCII border symbols (`ratatui::symbols::border::Set`).
- `site_accent(SiteColor)` maps T31 site colours to the remote pane border/tab accent.

#### Untrusted text

Every string that can come from a server, a file name or an error message is passed
through `ui::text::sanitize` before it is drawn (rules above: C0/DEL as caret notation,
C1, bidi and line separators as `<U+XXXX>`). The status line applies it to
`StatusMessage` text.

### Data formats and configuration

`crates/courier-ftp/config/config.json` after this task (excerpt; T51 fills the keymap):

```json
{
  "keybindings": {
    "Normal":   { "f1": "Help", "?": "Help", "f10": "Quit", "ctrl-q": "Quit",
                  "ctrl-z": "Suspend", "tab": "FocusOtherSide", "backtab": "FocusNextRegion",
                  "ctrl-l": "ToggleLog", "ctrl-e": "ToggleTree", "ctrl-c": "Cancel" },
    "FileList": {}, "Tree": {}, "Log": {}, "Queue": {}, "SiteManager": {}, "Filter": {},
    "Input": {}, "Dialog": {}
  },
  "styles": {
    "border": "", "border_focused": "bold yellow", "title": "", "title_focused": "bold",
    "status_bar": "on rgb012", "status_mode": "bold", "status_message": "bold",
    "status_error": "bold red", "placeholder": "", "help_key": "bold cyan",
    "help_group": "bold underline", "dialog_border": "bold", "text.escape": "inverse",
    "compare_only_one": "yellow", "compare_newer": "green", "compare_size_differs": "red",
    "compare_placeholder": ""
  },
  "settings": { "interface": { "layout": "classic", "show_log": true } }
}
```

Settings used (all defined in T05): `interface.layout` (Classic), `interface.swap_panes`
(false), `interface.show_tree` (false), `interface.show_log` (true),
`interface.show_queue` (true), `interface.show_quickconnect` (true), `interface.theme`
(Default), `interface.unicode_symbols` (`auto`). CLI `--tick-rate` (4) and `--frame-rate`
(60) keep their template defaults. Style keys of other tasks (`file_list.*` T53, log
kinds T55, …) are added to the same flat map by those tasks.

### Errors

- Config problems (bad style strings, unknown style keys, keymap problems reported by the
  resolver) never abort startup: each is logged with `warn!` and collected; after the
  first frame the status line shows "N configuration problems — see the log" (T52 later
  shows them in a dialog).
- Terminal I/O errors from `Tui::enter/draw` propagate as `color_eyre` reports from
  `App::run` (the template behaviour); `Tui::drop` restores the terminal and must not
  panic (replace the template's `self.exit().unwrap()` with logging the error).
- A component `draw` error is logged and turned into `Action::Error`; the frame still
  completes (template behaviour).
- `Settings::save_user` errors → status message + `warn!` (see Toggles).

### Security and logging

- No secrets pass through this task. Paste content is never logged.
- Logging follows T91: `trace!` for key/action names; never key text typed into fields;
  no hostnames, usernames or paths at `info`+.
- Untrusted text is sanitised before drawing (above); covered by a property test.
- Mouse capture stays off (D7); no OSC sequences are emitted except by T55's
  `ui::clipboard` (OSC 52; used by T55, T62, T71).

## Implementation steps

1. `ui/text.rs`, `ui/symbols.rs` (`Symbols`, `TermEnv`), `ui/theme.rs` with presets, `NO_COLOR`, flat `styles` parsing; `tabs.rs` with `TabId`; unit and property tests.
2. `Mode` variants (incl. `SiteManager`), `Action` restructure (`#[serde(skip)]` internals, initial bindable set), `KeyChord` normalisation, T50 `KeyResolver`; config sections for every mode; fix `test_config` (it expects `<q>`; the default is `ctrl-q`).
3. `layout.rs`: `compute_layout`, `focus_order` (pure) with unit tests for every rule.
4. `MainScreen`, `TabView`, `SideView`, placeholders, focus handling, minimal status bar; remove `Home` and its references.
5. `App` loop rewrite: `select!` with core events and resolver deadline, routing pipeline, paste, render-on-dirty; `Tui` paste on, `Drop` without `unwrap`.
6. `Runner` with busy tracking, spinner, shutdown; `Cancel`.
7. Modal stack, help overlay, `QuitConfirm`, quit blockers, suspend.
8. Toggles/layout actions with debounced `save_user`.
9. `testing.rs` `AppHarness`; snapshot tests at 80×24 and 160×48 (plus compact and too-small).

## Acceptance criteria

- [x] AC1 Classic, Explorer and Widescreen render as specified at 80×24 and 160×48 (Widescreen at 80×24 falls back to Classic), with trees on/off, log/queue hidden and `swap_panes` (insta snapshots).
- [x] AC2 Compact mode at 60×16 shows exactly one body region (the focused one); below 40×10 the "Terminal too small" message is shown and `ctrl-q` still quits.
- [x] AC3 `compute_layout` never returns overlapping or out-of-bounds rects for any size 1×1 … 300×100 and any option combination (property test).
- [x] AC4 `Tab` toggles between local and remote lists from every region; `Shift-Tab` visits every visible focusable region once per cycle in visual order; `ctrl-x 1`…`ctrl-x 7` focus the seven regions in the documented order; focus falls back to a list when its region is hidden.
- [x] AC5 With a modal open, no key reaches components below it; with a text input focused, printable keys go to the input and `F10` still reaches the global table.
- [x] AC6 While a mock task waits 5 s, the focused pane title spinner changes frame at least every 100 ms of virtual time and keys are still processed (focus switch observed during the wait).
- [x] AC7 With `NO_COLOR=1`, no cell of the rendered buffer has a foreground or background colour, and the focused region is still distinguishable (thick border + `▶`).
- [x] AC8 The help overlay lists exactly the effective bindings of the current chain, including a user override from a test config (no hard-coded text).
- [x] AC9 Layout toggles persist: after `ToggleLog` and 1 s of virtual time, the user config file contains `"show_log": false`, and a new `Config::new` reads it back.
- [x] AC10 Quit with a blocker shows the confirm modal; `Enter` keeps the app running (default Cancel); `Quit` pressed twice quits; quit without blockers exits immediately; no task survives `App::run` (runner `JoinSet` empty).
- [x] AC11 The idle app does not draw: 10 s of virtual time with no input → zero `draw` calls after the first frame.
- [x] AC12 `sanitize` property test: output contains no C0, C1, DEL or bidi characters for any input and is `Cow::Borrowed` for safe input; a status message containing `\x1b[2J` renders as `^[[2J`.
- [x] AC13 `Home` and `last_tick_key_events` are gone (`grep -rn "Home\|last_tick_key_events" crates/courier-ftp/src` is empty); `info!("Got action` is gone.
- [ ] AC14 CI gates `fmt`, `clippy`, `docs`, `test-local-only`, `test-os` (Windows/macOS) pass.

## Tests

### Unit tests
- `layout_classic_heights_80x24` / `layout_classic_heights_160x48` — exact rects for log (4 / 8 rows), queue (4 / 9 rows), sides. AC1.
- `layout_hides_queue_then_log_when_body_too_small` — `H = 18`. AC1.
- `layout_classic_tree_threshold` — tree shown at side height 14, hidden at 13. AC1.
- `layout_explorer_tree_width_clamp` — `W = 60, 160, 300`. AC1.
- `layout_widescreen_falls_back_below_120_cols` — `effective == Classic`. AC1.
- `layout_swap_panes_puts_remote_first` — Classic and Explorer. AC1.
- `layout_compact_shows_only_focused_region` — for each of the four regions. AC2.
- `layout_too_small_boundaries` — 39×10 and 40×9 too small, 40×10 compact. AC2.
- `focus_tab_from_every_region` — AC4.
- `focus_shift_tab_cycles_visual_order` — Classic with trees on: Quickconnect, Log, LocalTree, LocalList, RemoteTree, RemoteList, Queue. AC4.
- `focus_falls_back_when_region_hidden` — focus Log, `ToggleLog` → `LocalList`. AC4.
- `focus_region_n_targets` — `FocusRegion1`…`FocusRegion7` focus Quickconnect, LocalTree, LocalList, RemoteTree, RemoteList, Log, Queue (Classic, trees on); `FocusRegion2` with trees off shows the hint message. AC4.
- `mode_chain_table` — `Dialog → [Dialog]`, `SiteManager → [SiteManager]`, `FileList → [FileList, Normal]`, `Normal → [Normal]`. AC5.
- `modal_swallows_all_keys` — harness with a test modal; component key counter stays 0. AC5.
- `input_mode_printables_to_widget_fkeys_to_global` — test text component. AC5.
- `symbols_auto_detection_table` — `TERM=linux`/`dumb`/`vt100` → ASCII; `LANG=C` → ASCII; unset locale → ASCII; Windows without `WT_SESSION`/`TERM_PROGRAM` → ASCII; `LC_ALL=en_US.UTF-8` → Unicode; `LC_ALL` empty falls through to `LANG`; `always`/`never` override. AC7.
- `term_env_over_ssh` — `SSH_CONNECTION` or `SSH_TTY` set → `over_ssh()`.
- `sanitize_plain_text_is_borrowed`, `truncate_to_width_counts_wide_chars`. AC12.
- `theme_overrides_and_unknown_keys_warn`.
- `keychord_normalisation` — shift-letter → uppercase, `BackTab` → shift-tab, `Char('4')+CTRL` → `ctrl-\`. 
- `quit_without_blockers_quits_immediately`, `quit_with_blocker_default_cancel`, `quit_twice_confirms`. AC10.
- `suspend_on_windows_shows_message` (`#[cfg(windows)]`).
- `prompt_without_dialog_is_dropped_and_logged` — core receives cancel (T04 semantics).
- `cancel_without_task_shows_hint`.
- `sanitize_caret_and_codepoints` — `"a\x1b[2Jb"` → `a^[[2Jb`; `\x7f` → `^?`; U+0085, U+202E, U+2066 → `<U+0085>`, `<U+202E>`, `<U+2066>`. AC12.

### Property / fuzz tests
- `prop_layout_rects_disjoint_and_in_bounds` — random size 1..=300 × 1..=100 and random `LayoutOptions`. AC3.
- `prop_focus_order_contains_only_visible_regions` — AC4.
- `prop_sanitize_output_has_no_control_chars` — arbitrary `String`. AC12.

### Snapshot tests
All with `ratatui::backend::TestBackend` + `insta` (`crates/courier-ftp/src/snapshots/`):
- `snap_classic_80x24`, `snap_classic_160x48`, `snap_classic_tree_160x48`,
  `snap_classic_no_log_no_queue_80x24`, `snap_classic_swapped_160x48` — AC1.
- `snap_explorer_80x24`, `snap_explorer_tree_160x48` — AC1.
- `snap_widescreen_160x48`, `snap_widescreen_80x24_falls_back` — AC1.
- `snap_compact_60x16_remote_focused`, `snap_compact_60x16_log_focused`, `snap_too_small_30x8` — AC2.
- `snap_help_overlay_80x24`, `snap_help_overlay_160x48` — AC8.
- `snap_ascii_symbols_classic_80x24` — `unicode_symbols = never`.
- `snap_status_message_sanitised_80x24` — AC12.
- `no_color_buffer_has_no_colours` — buffer style assertions (not a text snapshot). AC7.

### Integration tests
- `spinner_animates_during_slow_task` — `#[tokio::test(start_paused = true)]`, harness spawns a task awaiting a 5 s sleep under `TaskOwner::Region(LocalList)`; renders at t = 200, 300, 400 ms differ in the spinner cell; a `Tab` at t = 1 s changes focus before the task ends. AC6.
- `idle_app_does_not_redraw` — draw counter. AC11.
- `toggle_log_persists_after_debounce` — temp `COURIER_FTP_HOME`, `ToggleLog`, advance 1 s, read the user config JSON. AC9.
- `runner_shutdown_leaves_no_tasks` — 10 never-ending tasks; `shutdown` returns within 2 s virtual time and `JoinSet` is empty. AC10.
- `core_events_reach_components_without_blocking_render` — 10 000 `Log` events injected; one render per drain cycle, all events delivered.
- `template_leftovers_removed` — shell test running the `grep` from AC13 (or a Rust test scanning `src/`). AC13.

### End-to-end tests
- `e2e_pty_starts_and_quits` (`courier-ftp-e2e`, `PtyApp`, runs without Docker) — start the binary with a temp `COURIER_FTP_HOME`, wait for `Local` on screen, press `ctrl-q`, process exits 0 and the terminal is restored (no alternate screen). AC10, AC14.
- `e2e_pty_resize_to_compact_and_back` — resize the PTY to 60×16 and back to 120×40; the screen shows `compact` and then the full layout.

## Out of scope

- Mouse support (D7) and drag and drop (D8).
- The real panes (T53–T58, T61), dialogs (T52), unlock view (T60), prompt dialogs (T69).
- The full keymap, sequences and `docs/keybindings.md` (T51).
- User-defined layouts beyond the three presets and the toggles; resizing regions with keys.

## Open questions

- Explorer layout stacks local over remote with trees on the left (closest to
  FileZilla's Explorer arrangement in a terminal). If the owner prefers side-by-side
  sides in Explorer too, only `compute_layout` changes. Product decision.

(Resolved by the coordinator: this task owns `ui::text`, `ui::symbols` and `TabId`;
focus regions are `ctrl-x 1..7`, tabs `alt-1..9`.)

## Implementation notes

- **Config shape.** `Config.keybindings` is now the user's raw map (mode → key string →
  action name, `keymap::resolver::RawKeymap`) and `Config.styles` the user's flat style
  map; both are read leniently (wrong JSON types become `Config::config_problems`, never
  a load error). The built-in tables come from `config::default_keybindings()` /
  `config::default_styles()` (parsed once from `config/config.json`). The template's
  `parse_key_sequence`, `KeyBindings`, `Styles` and `parse_style` in `config.rs` are
  gone; key strings are parsed by `KeyChord: FromStr` (sverb grammar subset:
  `[ctrl-][alt-][shift-]<key>`, `backtab`, `f1`…`f24`), style strings by
  `ui::theme::parse_style` (adds `dim`, `italic`, `crossed`, `#rrggbb`, and reports
  unknown words). `KeymapProblem`/`ProblemKind` are defined minimally in
  `keymap/resolver.rs`; T51 replaces them.
- **Theme.** The `default` preset *is* the `styles` map of the built-in config; the
  style keys are its keys (unknown user keys warn). `high_contrast` and `monochrome` are
  derived in code. `NO_COLOR` forces monochrome and strips colours from user overrides.
- **`Theme::site_accent(SiteColor)` is not implemented**: `SiteColor` does not exist yet
  (T31). T31/T61 add it next to `Theme::style`.
- **`DrawCx` has an extra `spinner: Option<&str>` field** (the frame to show in the
  title); `App` computes it from `Runner::busy_since` (> 150 ms) and
  `Component::is_busy`.
- **Modals** implement `components::modal::Modal: Component` with `is_done()`; the stack
  closes done modals after every key/action. The `Dialog` key table has `f10`/`ctrl-q` →
  `Quit` and `esc` → `Cancel` so "Quit twice confirms" works through the keymap.
- **Compact focus order** is `Quickconnect, LocalList, RemoteList, Log, Queue` (trees
  skipped; hidden log/queue/quickconnect are reachable there, as specified).
  `focus_order` keeps the spec signature, so in compact mode it lists those five.
- **"Hide the queue, then the log when the sides get < 8 rows"** can never trigger at
  the non-compact sizes (H ≥ 24 always leaves ≥ 12 rows). It is implemented in
  `layout::body_split` and `layout_hides_queue_then_log_when_body_too_small` tests that
  helper directly with H = 18.
- **Settings saves** use `SettingsStore::set_transient` immediately and a debounced
  runner task (1 s, restarted per change) that runs `check_settings_not_shadowed` +
  `Settings::save_user` on `spawn_blocking`. A save still pending at quit is done
  synchronously in `App::finish` before `Runner::shutdown`.
- **Harness.** `testing::AppHarness` owns a current-thread runtime with paused time
  (`#[cfg(test)]` only: the crate is a binary, so there is no `test-util` feature to
  export it). `advance` delivers ticks (4 Hz) and frames (60 Hz); frames go through the
  same `render_if_needed` as the real loop, which counts draws (AC11). `render(w, h)`
  draws directly (not counted) and resizes the app first.
- **AC13** is checked by `app_tests::template_leftovers_removed` (no `Home`
  component/`home.rs`, `last_tick_key_events` or `info!("Got action`). The literal grep
  in AC13 would also match `KeyCode::Home`, which is a real key.
- **Not done here:** `e2e_pty_starts_and_quits` and `e2e_pty_resize_to_compact_and_back`
  need the `courier-ftp-e2e` crate and `PtyApp` (T76), which do not exist yet. AC14's
  `test-os` (Windows/macOS) job could not be run locally; `fmt`, `clippy`, `docs` and
  the Linux tests pass.
- **Done in T76:** `e2e_pty_starts_and_quits` and `e2e_pty_resize_to_compact_and_back`
  are in `crates/courier-ftp-e2e/tests/pty_shell.rs`.
