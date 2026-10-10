# Key bindings

courier-ftp combines Midnight Commander's function keys (`f5` copy, `f6` move, `f7`
mkdir, `f8` delete, `tab` switches sides) with vim motions (`j` `k` `h` `l`, `g g` / `G`,
`/`). Every binding below can be changed in the user configuration; the help overlay
(`f1` or `?`) shows the bindings of the focused region, including your changes.

## How keys are looked up

Each region has a key table (a *mode*). A key is looked up in the focused region's
table first, then in `Normal`, the global table. Dialogs (`Dialog`) and the Site Manager
(`SiteManager`) are modal: only their own table is consulted. Text fields (quickconnect,
dialog fields, filters) take printable keys and the text editing keys first, so typing
never triggers a binding.

| Mode | Used while | Tables consulted |
|---|---|---|
| `Normal` | nothing more specific has the focus | `Normal` |
| `FileList` | a file list has the focus | `FileList`, `Normal` |
| `Tree` | a directory tree has the focus | `Tree`, `Normal` |
| `Log` | the message log has the focus | `Log`, `Normal` |
| `Queue` | the queue has the focus | `Queue`, `Normal` |
| `Filter` | typing a quick filter | `Filter`, `Normal` |
| `Input` | a single-line field outside dialogs | `Input`, `Normal` |
| `SiteManager` | the Site Manager tree | `SiteManager` |
| `Dialog` | a dialog or overlay is open | `Dialog` |

## Key sequences

Several bindings are sequences: `ctrl-x d` means press `ctrl-x`, release, then press
`d`. While a sequence is pending, the typed keys are shown in the status bar; after
500 ms a popup lists the possible next keys. `esc` cancels a pending sequence. A key
that does not continue the sequence drops it and is then used on its own (a stray `g`
followed by `j` still moves down). A sequence expires after
`interface.key_sequence_timeout_ms` (default 1000 ms, 200–5000) without a key.

## Changing bindings

Add a `keybindings` object to `config.json` in the configuration directory. Mode names
and action names are the ones in the tables below (case-sensitive); `"none"` removes a
binding. Your bindings replace the built-in binding of the same key in the same mode.

```json
{ "keybindings": { "FileList": { "ctrl-d": "Delete", "f8": "none", "g h": "Parent" } } }
```

Problems (an unknown key name, mode or action, two spellings of the same key, a
binding that can never fire because another binding is a prefix of it) never stop
courier-ftp: the entry is skipped, the problem is written to the log, and the status bar
says how many problems there are.

### Key syntax

```text
binding   = chord { " " chord }               (1 to 4 chords)
          | "<" chord ">" { "<" chord ">" }   (older form, e.g. "<g><g>")
chord     = { modifier "-" } key
modifier  = ctrl | alt | shift | super        (any case, any order, each once)
key       = a named key | f1 … f24 | one printable character (case-sensitive)
```

- Named keys: `space enter esc tab backtab backspace delete insert home end pageup
  pagedown up down left right minus lt gt`, and the aliases `escape return del ins pgup
  pgdn hyphen`.
- An uppercase letter means shift: `G` is `shift-g`, `alt-G` is alt + shift + g. After
  `ctrl-` the case of a letter is ignored (`ctrl-A` is `ctrl-a`); write `ctrl-shift-a`
  for the shifted chord. Shift is ignored on other printable characters (`?`, `+`, `*`).
- A lone `-` is the minus key and `ctrl--` is ctrl + minus. `<` and `>` are plain
  characters, except in the `<…>` form, where they are written `lt` and `gt`.
- `backtab` is `shift-tab`. `ctrl-4` is `ctrl-\`, `ctrl-5` is `ctrl-]`, `ctrl-6` is
  `ctrl-^`, and `ctrl-7` and `ctrl-/` are `ctrl-_` (what terminals send for them).

## Terminal caveats

| Key | Problem | Default policy |
|---|---|---|
| `ctrl-h`, `ctrl-i`, `ctrl-m`, `ctrl-j`, `ctrl-[` | arrive as `backspace`, `tab`, `enter`, `enter`, `esc` | never bound by default (hidden files are `.`, the queue toggle is `ctrl-x j`) |
| `shift-f1` … `shift-f12` | some terminals send `f13`…`f24`, some nothing | paired with a portable key and the `f13`–`f24` alias |
| `f1`, `f10`, `f11` | terminal help, menu or full screen | `f1` / `f10` paired with `?` / `ctrl-q`; `f11`, `f12` unbound |
| `alt-*` | macOS Terminal and iTerm2 need "Option as Meta" | every `alt-` binding has a portable alternative (`g 1` … `g 9`, `[`, `]`) |
| `ctrl-pageup`, `ctrl-pagedown` | used by some terminals for their own tabs | paired with `g T` / `g t` |
| `ctrl-s`, `ctrl-q` | XON/XOFF flow control | courier-ftp turns flow control off while it runs |
| `ctrl-z` | job control | Unix only; Windows shows a message |

Every action has at least one default key that works in xterm, tmux and Windows
Terminal without configuration.

## Keys that are not in the tables

- **Text fields** (fixed): `left` / `right`, `home` / `ctrl-a`, `end` / `ctrl-e`,
  `ctrl-left` / `alt-b` and `ctrl-right` / `alt-f` (word), `backspace`, `delete`,
  `ctrl-w` / `alt-backspace` (delete word back), `alt-d` (delete word forward), `ctrl-u`
  (delete to start), `ctrl-k` (delete to end), bracketed paste.
- **View buttons**: the unlock screen, trust prompts, the bookmarks menu, the search
  view, the sync panel and dialog mnemonics (`alt-<letter>`) read their own keys, shown
  in each view's hint line. They cannot be rebound.
