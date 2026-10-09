# T55 — Message log pane

**Phase:** F TUI · **Milestone:** M1 · **Depends on:** T04, T50, T51, T57 · **Crate(s):** `courier-ftp` (`components/message_log/`, `ui/text.rs`, `ui/clipboard.rs`) · **Decisions:** D6, D7 · **FEATURES.md:** §3 (message log, colours by type), §9 (debug level)
**Related (integrates with, not blocking):** T62

## Goal

FileZilla's message log in the terminal: status lines, protocol commands and
replies, errors and trace output, coloured and prefixed by type, separated per tab
with an "All" view. Users can scroll back without losing new messages, search,
copy lines to the clipboard and clear the log. Memory stays bounded no matter how
chatty a server or debug level is, and server-supplied text can never inject
terminal escape sequences.

## Context

**Before this task:** T04 delivers `CoreEvent::Log(LogMessage)` with `time`,
`session: SessionId`, `kind: LogKind` (`Status`, `Command`, `Response`, `Error`,
`ListingRaw`, `Debug(1..=4)`) and `text` (commands already masked, `PASS ****`),
and drops messages above `logging.level` at the source. T04 also delivers
`CoreEvent::Connected { session, address }` / `Disconnected`. T50 bridges core
events into `Action`s, owns focus, `Theme` and `Mode`. T51 provides the `Log` keymap
mode and the global `Ctrl-x` prefix. T57 provides `Symbols` (Unicode/ASCII glyphs).

**Later tasks need from it:** `crate::ui::text::sanitize` (T53, T54, T56, T59, T61,
T69: every untrusted string), `crate::ui::clipboard::copy_osc52` (T62 extends it with
an `arboard` fallback), the per-tab log store (T61 creates one view per tab), T71
(raw listing lines, "copy/save log" actions), T57 (transient "Copied N lines" message).

## Technical specification

### Types and APIs

```rust
// crates/courier-ftp/src/ui/text.rs
/// Make untrusted text safe to draw: C0 controls (incl. TAB, CR, LF) become caret
/// notation (`^[`, `^I`, `^M`), DEL becomes `^?`, C1 controls (U+0080–U+009F), bidi
/// controls (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069) and line/paragraph
/// separators (U+2028, U+2029) become `<U+XXXX>`. Returns `Cow::Borrowed` when the
/// input needs no change (fast path over bytes).
pub fn sanitize(s: &str) -> Cow<'_, str>;
/// As `sanitize`, but returns spans so escapes can be drawn in `text.escape` style.
pub fn sanitize_spans<'a>(s: &'a str, base: Style, escape: Style) -> Vec<Span<'a>>;
/// Cut to `width` display columns (`unicode-width`), appending `…` / `~` (ASCII).
pub fn truncate_to_width(s: &str, width: usize, ellipsis: &str) -> Cow<'_, str>;

// crates/courier-ftp/src/ui/clipboard.rs
/// Write OSC 52 (`ESC ] 52 ; c ; <base64> ESC \`) to the terminal.
/// Refuses payloads over `OSC52_MAX_BYTES` (74 KiB raw = 100 000 base64 bytes).
pub fn copy_osc52(out: &mut impl std::io::Write, text: &str) -> Result<(), ClipboardError>;
pub const OSC52_MAX_BYTES: usize = 75_000;
#[derive(Debug, thiserror::Error)]
pub enum ClipboardError { #[error("selection too large to copy ({0} bytes, max 75 000)")] TooLarge(usize),
                          #[error(transparent)] Io(#[from] std::io::Error) }

// crates/courier-ftp/src/components/message_log/
/// One stored line. Text is sanitised and capped at insert time.
#[derive(Debug)]
pub struct LogLine {
    pub seq: u64,                 // global, monotonic
    pub time: OffsetDateTime,     // converted to local offset for display
    pub session: SessionId,
    pub origin: LineOrigin,       // Tab(TabId) | Transfer | App
    pub kind: LogKind,
    pub text: Box<str>,           // sanitised, ≤ MAX_LINE_CHARS + suffix
}
pub const MAX_LINE_CHARS: usize = 4096;

/// Which ring a view reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogScope { Tab(TabId), All }

/// Kind filter of a view (`e` cycles).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KindFilter { #[default] Everything, HideTrace, ErrorsOnly }

/// All rings plus routing. Owned by `App`, shared with the pane by reference.
#[derive(Debug)]
pub struct LogStore {
    rings: HashMap<LogScope, VecDeque<Arc<LogLine>>>,
    capacity: usize,                       // logging.pane_max_lines
    session_server: HashMap<SessionId, ServerKey>, // from CoreEvent::Connected
    tab_routes: HashMap<TabId, TabRoute>,  // browsing session + server identity
    next_seq: u64,
}
impl LogStore {
    pub fn new(capacity: usize) -> Self;
    pub fn push(&mut self, msg: LogMessage, active_tab: TabId);
    pub fn on_connected(&mut self, session: SessionId, address: &ServerAddress);
    pub fn on_disconnected(&mut self, session: SessionId);
    pub fn set_tab_route(&mut self, tab: TabId, route: TabRoute);
    pub fn remove_tab(&mut self, tab: TabId);
    pub fn clear(&mut self, scope: LogScope);
    pub fn lines(&self, scope: LogScope) -> &VecDeque<Arc<LogLine>>;
    pub fn len(&self, scope: LogScope) -> usize;
}
/// Server identity used for routing transfer-session messages: protocol, lower-cased
/// host, effective port, user — the same fields T46 uses for its cache key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerKey { pub protocol: Protocol, pub host: String, pub port: u16, pub user: Option<String> }
impl From<&ServerAddress> for ServerKey { /* … */ }

// crates/courier-ftp/src/tabs.rs (created here; T53 and T61 extend it)
/// A tab. Before T61 the only tab is `TabId(0)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TabId(pub u32);
#[derive(Debug, Clone)]
pub struct TabRoute { pub browsing: Option<SessionId>, pub server: Option<ServerKey> }

/// Per-view UI state (one per tab + one for All; the pane shows one at a time).
#[derive(Debug, Default)]
pub struct LogViewState {
    pub scope: LogScope,
    pub follow: bool,              // true = pinned to the newest line
    pub anchor_seq: Option<u64>,   // bottom visible line when not following
    pub cursor_seq: Option<u64>,   // focused line (only drawn when the pane has focus)
    pub visual_anchor: Option<u64>,
    pub unseen: u32,               // new lines since follow was turned off
    pub wrap: bool,                // default true
    pub hscroll: u16,              // columns, only when !wrap
    pub kind_filter: KindFilter,
    pub search: Option<LogSearch>,
}
#[derive(Debug, Clone, Default)]
pub struct LogSearch { pub query: String, pub editing: bool, pub current: Option<u64>, pub total: usize }

pub struct MessageLogPane { view: LogViewState, views: HashMap<LogScope, LogViewState> /* … */ }
impl Component for MessageLogPane { /* handle_key_event, update, draw */ }
```

Actions (T51 names, mode `Log`): `LogCursorDown`, `LogCursorUp`, `LogHalfPageDown`,
`LogHalfPageUp`, `LogPageDown`, `LogPageUp`, `LogTop`, `LogBottom`, `LogSearch`,
`LogSearchNext`, `LogSearchPrev`, `LogVisual`, `LogCopy`, `LogToggleWrap`,
`LogToggleScope`, `LogCycleKindFilter`, `LogScrollLeft`, `LogScrollRight`,
`LogScrollHome`, `LogClear`, `Cancel`. Emitted: `Action::StatusMessage(String)`
(T57 transient message) after copy/clear.

### Behaviour

#### Routing (`LogStore::push`)

1. Text is prepared once: TABs expanded to 4 spaces, then `sanitize`, then cut to
   `MAX_LINE_CHARS` characters with suffix ` … [N more characters]`.
2. The line is appended to the `All` ring.
3. It is appended to every tab ring whose route matches: the tab's browsing
   `SessionId` equals `msg.session`, **or** `session_server[msg.session]` equals the
   tab's server (transfer and keep-alive sessions of the same server). Lines are
   shared (`Arc`), not copied.
4. No tab matched (app-level status, local operations, a server no tab shows):
   appended to the active tab's ring too, with `origin = App` or `Transfer`.
5. Each ring keeps at most `capacity` lines; the oldest is dropped (O(1)).
6. `remove_tab` drops that ring (T61 calls it on tab close).

#### Line layout

`HH:MM:SS` (if `logging.show_timestamps`) + ` ` + (All view only: `[n]` tab number,
`[T]` transfer session, `[-]` app) + ` ` + prefix padded to 10 + text. Wrapped
continuation lines are indented to the text column (hanging indent); words break at
spaces, words longer than the line are hard-broken.

| `LogKind` | Prefix | Style key | Default colour | `NO_COLOR` |
|---|---|---|---|---|
| `Status` | `Status:` | `log.status` | default fg | plain |
| `Command` | `Command:` | `log.command` | blue | plain |
| `Response` | `Response:` | `log.response` | green | plain |
| `Error` | `Error:` | `log.error` | red, bold | bold |
| `Debug(1..=4)` | `Trace:` | `log.trace` | dark grey | dim |
| `ListingRaw` | `Listing:` | `log.listing` | cyan | dim |

Timestamps and tags use `log.time` (dim). Sanitiser escapes use `text.escape` (dim,
underline in monochrome). Search matches use `log.search_match` (reverse). The cursor
line uses `log.cursor` (underline + bold; same in monochrome); visual range `log.visual`
(reverse).

**Narrow widths** (pane inner width `W`), applied in this order:

| Condition | Change |
|---|---|
| `W < 70` in All view | session tag shortened to 1 char (`1`…`9`, `+` for tabs ≥ 10, `T`, `-`) |
| `W < 60` | timestamp hidden (even when enabled) |
| `W < 45` | prefix shortened to `S:` `C:` `R:` `E:` `T:` `L:` (width 3) |
| `W < 12` or height < 3 | body shows nothing; no panic |

#### Mock-up: standalone at 80×24 (Tab 1 view, following, wrap on)

```
┌ Message log · Tab 1 ─────────────────────────────────────────────────────────┐
│12:00:01 Status:   Initializing TLS...                                        │
│12:00:02 Status:   TLS connection established (TLS 1.3,                       │
│                   TLS_AES_256_GCM_SHA384).                                   │
│12:00:02 Command:  USER alice                                                 │
│12:00:02 Response: 331 Please specify the password.                           │
│12:00:02 Command:  PASS ****                                                  │
│12:00:02 Response: 230 Login successful.                                      │
│12:00:02 Status:   Logged in                                                  │
│12:00:02 Status:   Retrieving directory listing...                            │
│12:00:02 Command:  PWD                                                        │
│12:00:02 Response: 257 "/var/www" is the current directory                    │
│12:00:02 Command:  PASV                                                       │
│12:00:02 Response: 227 Entering Passive Mode (203,0,113,5,195,80).            │
│12:00:02 Command:  MLSD                                                       │
│12:00:03 Response: 150 Here comes the directory listing.                      │
│12:00:03 Response: 226 Directory send OK.                                     │
│12:00:03 Status:   Directory listing of "/var/www" successful                 │
│12:00:09 Command:  CWD /root                                                  │
│12:00:09 Response: 550 Failed to change directory.                            │
│12:00:09 Error:    Failed to retrieve directory listing: the server sent a    │
│                   reply that is long enough to wrap onto a second line of the│
│                   pane                                                       │
└──────────────────────────────────────────────────────────────────────────────┘
```

#### Mock-up: standalone at 160×48 (All view, scrolled up, search for `550` active)

The bottom border shows the unseen-lines indicator; the last inner row is the search
input. Rows from transfer sessions carry `[T]`.

```
┌ Message log · All ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│12:00:01 [1] Status:   Connecting to 203.0.113.5:21...                                                                                                        │
│12:00:01 [1] Status:   Connection established, waiting for welcome message...                                                                                 │
│12:00:01 [1] Response: 220 (vsFTPd 3.0.5)                                                                                                                     │
│12:00:01 [1] Command:  AUTH TLS                                                                                                                               │
│12:00:01 [1] Response: 234 Proceed with negotiation.                                                                                                          │
│12:00:01 [1] Status:   Initializing TLS...                                                                                                                    │
│12:00:02 [1] Status:   TLS connection established (TLS 1.3, TLS_AES_256_GCM_SHA384).                                                                          │
│12:00:02 [1] Command:  USER alice                                                                                                                             │
│12:00:02 [1] Response: 331 Please specify the password.                                                                                                       │
│12:00:02 [1] Command:  PASS ****                                                                                                                              │
│12:00:02 [1] Response: 230 Login successful.                                                                                                                  │
│12:00:02 [1] Status:   Logged in                                                                                                                              │
│12:00:02 [1] Status:   Retrieving directory listing...                                                                                                        │
│12:00:02 [1] Command:  PWD                                                                                                                                    │
│12:00:02 [1] Response: 257 "/var/www" is the current directory                                                                                                │
│12:00:02 [1] Command:  PASV                                                                                                                                   │
│12:00:02 [1] Response: 227 Entering Passive Mode (203,0,113,5,195,80).                                                                                        │
│12:00:02 [1] Command:  MLSD                                                                                                                                   │
│12:00:03 [1] Response: 150 Here comes the directory listing.                                                                                                  │
│12:00:03 [1] Response: 226 Directory send OK.                                                                                                                 │
│12:00:03 [1] Status:   Directory listing of "/var/www" successful                                                                                             │
│12:00:09 [1] Command:  CWD /root                                                                                                                              │
│12:00:09 [1] Response: 550 Failed to change directory.                                                                                                        │
│12:00:09 [1] Error:    Failed to retrieve directory listing: the server sent a reply that is long enough to wrap onto a second line of the pane               │
│12:03:10 [T] Status:   Connecting to web01.example.com:22...                                                                                                  │
│12:03:10 [T] Status:   Using username "deploy".                                                                                                               │
│12:03:10 [T] Trace:    Server version: SSH-2.0-OpenSSH_9.6                                                                                                    │
│12:03:10 [T] Trace:    kex curve25519-sha256, cipher chacha20-poly1305@openssh.com, mac <implicit>                                                            │
│12:03:11 [T] Status:   Connected to web01.example.com                                                                                                         │
│12:03:11 [T] Status:   Starting upload of /home/alice/site/index.html                                                                                         │
│12:03:11 [T] Status:   File transfer successful, transferred 4,198 bytes in 1 second                                                                          │
│12:03:11 [T] Status:   Starting upload of /home/alice/site/style.min.css                                                                                      │
│12:03:12 [T] Status:   File transfer successful, transferred 49,869 bytes in 1 second                                                                         │
│12:03:12 [T] Status:   Starting download of /var/www/html/backup-2026-10-01.tar.gz                                                                            │
│12:03:40 [T] Error:    Disk full: /home/alice/Downloads (needed 1.21 GiB, 812 MiB free); queue paused                                                         │
│12:04:02 [1] Command:  NOOP                                                                                                                                   │
│12:04:02 [1] Response: 200 NOOP ok.                                                                                                                           │
│12:04:30 [1] Command:  CWD /var/www/html                                                                                                                      │
│12:04:30 [1] Response: 250 Directory successfully changed.                                                                                                    │
│12:04:30 [1] Command:  PASV                                                                                                                                   │
│12:04:30 [1] Response: 227 Entering Passive Mode (203,0,113,5,195,81).                                                                                        │
│12:04:30 [1] Command:  MLSD                                                                                                                                   │
│12:04:30 [1] Response: 150 Here comes the directory listing.                                                                                                  │
│12:04:30 [1] Response: 226 Directory send OK.                                                                                                                 │
│12:04:30 [1] Status:   Directory listing of "/var/www/html" successful                                                                                        │
│/550▏  match 1 of 3                                                                                                                                           │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── ▼ 3 new ─┘
```

In the Classic layout at 80×24 (T50) the log gets 4 inner rows: the same rendering
rules apply, so it shows the last 4 wrapped rows.

#### Scrolling and follow

- `follow = true` initially and after `LogBottom` (`G`/`End`). While following, new
  lines keep the newest line on the last row and `unseen` stays 0.
- Any upward movement sets `follow = false` and `anchor_seq` to the line at the
  bottom row. New lines then increase `unseen`; the bottom border shows
  `▼ N new` (ASCII `v N new`, capped at `9999+`).
- Scrolling is anchor-based: the renderer lays out lines **upwards** from the anchor
  and computes wrap heights only for lines it draws, so the cost is independent of the
  ring size.
- When the anchor line is evicted from the ring, the anchor moves to the oldest line.
- `LogClear` (`Ctrl-x c`) empties the current scope's ring and resets the view; the All
  ring is cleared only when the All view is shown. Emits `StatusMessage("Log cleared")`.

#### Cursor, visual range, copy

- When the pane gains focus the cursor is on the bottom visible line. `j`/`k` move it;
  the view scrolls to keep it visible (and leaves follow mode when moving up).
- `v` starts a visual line range at the cursor; `y` copies the range (or the cursor
  line) as displayed text (timestamp, tag, prefix, unwrapped text), newline-joined.
- Copy uses `copy_osc52`. Over 75 000 bytes: nothing is copied and the status bar says
  `Selection too large to copy (max 75 000 bytes)`. Success: `Copied N lines`.
- Terminals without OSC 52 silently ignore it; T62 adds the `arboard` fallback.

#### Search

- `/` opens the input row at the bottom of the pane (mode `Input`, T52 `TextInput`,
  max 256 chars). Typing updates matches live; `Enter` closes the input and keeps
  highlights; `Esc` clears the search.
- Plain substring search; smart case (case-sensitive only if the query has an
  uppercase letter). Matches are counted over the current scope (≤ capacity lines,
  ≤ 100 000) on each change; above 20 000 lines the count runs after a 100 ms debounce.
- `n` jumps to the next **older** match, `N` to the next newer one, wrapping around
  with `search wrapped` in the input row. The jumped-to line becomes the cursor and the
  view leaves follow mode.
- The input row shows `match i of n` or `no matches`.

#### Kind filter, wrap, scope

- `e` cycles `Everything` → `HideTrace` → `ErrorsOnly`; the title shows `[no trace]` /
  `[errors only]`. Filtering is applied at render time (lines stay in the ring).
- `w` toggles wrap; without wrap, `h`/`l`/`←`/`→` scroll 8 columns, `0` to column 0, and a
  `«`/`»` marker shows hidden text.
- `t` toggles the scope between the current tab and All. Each scope keeps its own
  `LogViewState` (follow, anchor, search) for the session.

#### Keybindings (mode `Log`, from T51)

| Key | Action |
|---|---|
| `j` `↓` / `k` `↑` | cursor down / up |
| `Ctrl-d` / `Ctrl-u`, `PageDown` / `PageUp` | half page / page |
| `gg` `Home` / `G` `End` | oldest line / newest line + follow |
| `/`, `n`, `N` | search, next older, next newer |
| `v`, `y` | visual range, copy |
| `w`, `t`, `e` | wrap, scope, kind filter |
| `h` `←` / `l` `→` / `0` | horizontal scroll (wrap off) |
| `Esc` | cancel visual / clear search |
| `Ctrl-x c` | clear log |

The pane is focused through T50's focus actions (`FocusLog`); it is hidden with
`Ctrl-l` (T51 `ToggleLog`).

#### Performance targets

| Measure | Target |
|---|---|
| `LogStore::push` incl. sanitise, 200-char line | ≥ 200 000 lines/s on the CI runner (bench `log_push`) |
| Draw at 160×48, full 5 000-line ring, wrap on | ≤ 1 ms median (bench `log_render_full_ring`) |
| Memory per ring | ≤ `capacity` lines; each ≤ 4 096 chars + suffix |
| 10 000 lines arriving in one frame | one redraw; no per-line redraw (T50 coalesces Render) |

### Data formats and configuration

| Key | Type | Default | Notes |
|---|---|---|---|
| `logging.level` | 0–4 | 2 | T05; filters at the source (T04) |
| `logging.show_timestamps` | bool | `true` | added here (planned in T05 §1c) |
| `logging.pane_max_lines` | u32, 500–100 000 | 5 000 | added here; per ring; out of range → warning + default (T05 rule) |
| `logging.show_raw_listing` | bool | `false` | T05; `Listing:` lines come from T13/T71 |

Style keys: `log.status`, `log.command`, `log.response`, `log.error`, `log.trace`,
`log.listing`, `log.time`, `log.cursor`, `log.visual`, `log.search_match`, `text.escape`,
`log.border`, `log.border_focused`.

### Errors

The pane has no fallible I/O except the clipboard write: `ClipboardError::TooLarge`
and `ClipboardError::Io` become a status message (`Could not copy: <reason>`); nothing
is logged at `info`+. Events for unknown sessions are routed as in step 4, never dropped.

### Security and logging

- All text is sanitised before it is stored (T91 §9: escape sequences from servers).
- `Command` lines arrive masked from T04 (`PASS ****`, `ACCT ****`); this pane adds no
  unmasking path. Copy and search operate on the masked, sanitised text.
- The pane's content is user-facing and separate from the application log (T91 §4).
  The pane writes nothing to `tracing` except `debug` counters
  (`log_store lines=<n> dropped=<n>`), never message text.
- Copy payload is size-limited; OSC 52 payload is base64 so it cannot contain escapes.

## Implementation steps

1. `ui/text.rs`: `sanitize`, `sanitize_spans`, `truncate_to_width` with tests and a property test.
2. `ui/clipboard.rs`: `copy_osc52` with size limit.
3. `LogStore` with routing, rings, capacity, `ServerKey` map; unit tests.
4. Line layout + renderer (anchor-based, wrap, narrow rules); snapshot tests.
5. Follow/unseen, cursor, visual, copy; keymap `Log` entries and actions.
6. Search (input row, smart case, n/N), kind filter, scope toggle, clear.
7. Wire `CoreEvent::Log/Connected/Disconnected` from T50's bridge; remove placeholders.
8. Benchmarks `log_push`, `log_render_full_ring` and their gates.

## Acceptance criteria

- [ ] AC1 Snapshot tests at 80×24 and 160×48 for: every `LogKind` prefix, wrapped lines, All view with tags, scrolled up with `▼ N new`, search active, kind filter `errors only`, no-wrap with horizontal scroll, empty log, and the narrow width rules (widths 40, 55, 65).
- [ ] AC2 Style test: each `LogKind` row uses its style key; with `NO_COLOR` the error row is bold and trace dim, and no cell has a colour.
- [ ] AC3 A ring never holds more than `logging.pane_max_lines` lines and no stored line exceeds 4 096 characters plus suffix (unit + property test).
- [ ] AC4 Follow mode keeps the newest line visible; scrolling up stops following, counts unseen lines, and `G` resumes.
- [ ] AC5 Search finds matches with smart case; `n`/`N` move older/newer and wrap.
- [ ] AC6 `y` emits a correct OSC 52 sequence for one line and for a visual range; payloads over 75 000 bytes are refused with a message.
- [ ] AC7 Messages from a transfer session of the same server appear in that tab's view; unrelated sessions appear in All and the active tab.
- [ ] AC8 `sanitize` output contains no C0/C1/DEL/bidi characters for any input, and returns `Cow::Borrowed` for plain text.
- [ ] AC9 Benchmarks meet: push ≥ 200 000 lines/s, full-ring render ≤ 1 ms median (bench gates, T00 §4).
- [ ] AC10 CI gates `fmt`, `clippy`, `test-local-only`, `test-os` pass.

## Tests

### Unit tests
- `sanitize_caret_notation_for_c0_and_del` — `"a\x1b[31mb\x7f"` → `a^[[31mb^?` (AC8).
- `sanitize_c1_and_bidi_as_codepoints` — U+0085, U+202E, U+2066 (AC8).
- `sanitize_plain_text_is_borrowed` (AC8).
- `truncate_to_width_counts_wide_chars`.
- `osc52_sequence_is_base64_and_terminated` (AC6), `osc52_refuses_large_payload` (AC6).
- `ring_drops_oldest_at_capacity` (AC3), `long_line_is_capped_with_suffix` (AC3).
- `routes_browsing_session_to_its_tab`, `routes_transfer_session_by_server_identity`, `unknown_session_goes_to_all_and_active_tab` (AC7).
- `remove_tab_drops_its_ring`.
- `follow_keeps_bottom_and_scroll_up_counts_unseen`, `g_resumes_follow` (AC4).
- `anchor_moves_to_oldest_when_evicted` (AC4).
- `search_smart_case`, `search_next_prev_wrap` (AC5).
- `kind_filter_errors_only_hides_other_kinds`.
- `copy_visual_range_formats_displayed_text` (AC6).
- `narrow_rules_shorten_tag_time_prefix` (AC1).

### Property / fuzz tests
- `prop_sanitize_output_has_no_control_chars` — arbitrary `String` (AC8).
- `prop_sanitize_is_identity_on_safe_text`.
- `prop_ring_len_bounded` — random push/clear sequences, random capacity (AC3).
- `prop_render_never_panics_any_size` — random lines × sizes 0–200 × 0–60.

### Snapshot tests
`TestBackend` + `insta` at 80×24 and 160×48: `log_all_kinds`, `log_wrapped`,
`log_all_view_tags`, `log_scrolled_unseen`, `log_search_active`, `log_errors_only`,
`log_no_wrap_hscroll`, `log_empty`; `log_narrow_40`, `log_narrow_55`, `log_narrow_65`
(80×24 only); each colour snapshot also as `*_mono_ascii` with `NO_COLOR` + ASCII symbols (AC1, AC2).

### Integration tests
- `core_log_events_reach_the_pane` — T04 `EventSender` with a `MockBackend` connect/list; the pane's store contains the masked `PASS ****` line, never the password (AC7).
- Benches `log_push`, `log_render_full_ring` (AC9).

### End-to-end tests
- Covered by T76 PtyApp scenarios that assert log text (`Directory listing of "/" successful`) after connecting; no separate e2e here.

## Out of scope

- Writing the session log to a file, "Save log as…", raw listing dialog (T71).
- Translating prefixes (T75; server text is never translated).
- Regex search.

## Open questions

1. T04 does not say which tab a transfer worker's messages belong to; this task routes them by server identity (any tab connected to the same server shows them). T62's description of the clipboard as "T62's helper" is superseded: T55 creates `ui::clipboard` (OSC 52) and T62 adds the `arboard` fallback. Confirm both with the owners of T04 and T62.
