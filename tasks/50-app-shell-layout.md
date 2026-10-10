# T50 — App shell and layout

**Phase:** F TUI · **Depends on:** T01, T04, T05 · **Crate:** `courier-ftp` · **Decisions:** D7 (no mouse) · **FEATURES.md:** §3
**Related (integrates with, not blocking):** T51, T52, T53, T55, T57

## Goal

Replace the template's `Home` hello-world with the courier-ftp main screen:
pane layout, focus handling, event bridging from core, and layout options.

## Default layout (Classic, 120×40)

```
┌ Quickconnect ─────────────────────────────────────────────────────────────────────────────┐
│ Host: example.com   User: alice   Pass: ****   Port: 22   [Connect]  [History ▾]          │
├ Tabs: [1 web01 ●] [2 backup] [+] ─────────────────────────────────────────────────────────┤
│ Message log                                                                               │
│ Status:   Connecting to 203.0.113.5:22...                                                 │
│ Response: 230 Login successful.                                                           │
├ Local: ~/projects/site ────────────────────────┬ Remote: /var/www ─────────────────────────┤
│ Name            Size  Modified          Perms  │ Name           Size  Modified      Perms   │
│ ..                                             │ ..                                         │
│ assets/               2026-10-01 12:00  rwxr-x │ html/              2026-09-30 09:12 rwxr-x │
│ index.html     4 KiB  2026-10-08 18:22  rw-r-- │ index.html  4 KiB  2026-10-02 10:00 rw-r-- │
│ 3 files, 1 dir. Total 12 KiB                   │ 2 files, 1 dir. Total 9 KiB                │
├ Queue (2) · Failed (0) · Successful (14) ──────┴────────────────────────────────────────────┤
│ ↑ index.html  →  /var/www/index.html    4 KiB   62% ███████░░░░  1.2 MiB/s  00:01         │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│ 🔒 TLS1.3  ⇅ limit off  ⚑ filters  Queue: 2 files, 8 KiB   F1 help  F5 copy  F8 delete      │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

(Directory tree panes, T54, appear above or beside each file list when enabled.)

## Scope

1. **Component tree**: `MainScreen` owns `QuickconnectBar` (T58), `TabBar` (T61), `MessageLog` (T55), per-tab `{ LocalPane, RemotePane }` (T53/T54), `QueuePane` (T56), `StatusBar` (T57), and a modal stack for dialogs (T52).
2. **Layouts** (`interface.layout`):
   - **Classic**: log on top, panes side by side, queue at the bottom (above).
   - **Explorer**: tree + list per side stacked vertically in each column.
   - **Widescreen**: log + queue on the right, panes on the left.
   - `swap_panes`: remote on the left.
   - Toggles at runtime: log (`Ctrl-l`? see T51), queue, tree, quickconnect bar; persisted to settings.
   - Small terminals (< 80×24): collapse to a single-pane mode where Tab switches which pane is visible; show a hint.
3. **Focus**: focusable regions = quickconnect, local tree, local list, remote tree, remote list, log, queue. `Tab`/`Shift-Tab` cycles between the two file lists primarily (MC behaviour); `Alt-1..5` or similar jumps to specific regions (finalise in T51). Focused region has a highlighted border.
4. **Input routing**: modal dialog (if any) gets keys first; then focused component; then global keymap. Replace current "all components get every event" loop in `app.rs` with focus-aware routing.
5. **Mode** enum extended: `Normal`, `Filter` (typing quick filter), `Input` (text field focused), `Dialog`. Keybinding config sections per mode.
6. **Core event bridge**: `App` holds the `EventReceiver` (T04); `tokio::select!` over terminal events, the action channel, and core events; convert core events into `Action`s (`Action::Core(CoreEvent)` or specific variants). Prompts push a dialog onto the modal stack.
7. **Async operations from UI**: actions that need the network (list dir, mkdir…) are spawned as tasks that send results back as actions; the UI never awaits network I/O in `update`/`draw`. Show a spinner in the pane title while busy.
8. **Theme**: default colour scheme using the existing `styles` config; colours for log kinds, comparison states, selection, focused border, site background colour accent. A monochrome fallback when `NO_COLOR` is set.
9. **Help overlay** (`F1`): lists active keybindings for the current mode generated from config (not hard-coded text).
10. **Quit**: `Ctrl-q`/`F10`; if transfers are active or queue unsaved, confirm.
11. Remove `Home` component and its references.

## Acceptance criteria

- [x] Three layouts render correctly at 80×24, 120×40, 200×60 (insta snapshot tests with `ratatui::backend::TestBackend`).
- [x] Focus cycling and modal routing work as described.
- [x] Core events reach the UI without blocking rendering (spinner animates during a slow mock listing).
- [x] `NO_COLOR` honoured.
- [x] Help overlay lists bindings from config.

## Tests

- Snapshot tests per layout/size.
- Unit tests for focus cycling and key routing.
