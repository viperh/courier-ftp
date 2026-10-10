# Keybindings

<!-- Generated from crates/courier-ftp/config/default.json by
     `COURIER_FTP_BLESS=1 cargo test -p courier-ftp keybindings_doc`. Do not edit. -->

courier-ftp mixes Midnight Commander function keys (F5 copy, F6 move, F7 mkdir,
F8 delete, Tab switches pane) with vim motions (`j`/`k`/`h`/`l`, `gg`/`G`, `/`).
`F1` shows the keys of the current mode in the program.

Every binding can be changed in your `config.json` (see the README): keys are
grouped by mode, a sequence is written `<g><g>`, and `<` and `>` are spelled
`<lt>` and `<gt>`. Up to 1 second may pass between the keys of a sequence
(`settings.interface.key_sequence_timeout_ms`); the keys typed so far show at
the right of the status bar.

## Global

Active everywhere except in text fields and dialogs.

| Key | Action |
|---|---|
| `<Ctrl-b>` | Bookmarks |
| `<Ctrl-x><c>` | ClearLog |
| `<Ctrl-w>` | CloseTab |
| `<Ctrl-x><o>` | CompareOptions |
| `<F5>` | Copy |
| `<Ctrl-x><t>` | CycleTransferType |
| `<Delete>` | Delete |
| `<F8>` | Delete |
| `<Ctrl-x><d>` | Disconnect |
| `<F4>` | Edit |
| `<Tab>` | FocusNext |
| `<BackTab>` | FocusPrev |
| `<Ctrl-k>` | FocusQuickconnect |
| `<?>` | Help |
| `<F1>` | Help |
| `<Ctrl-x><v>` | LockVault |
| `<F7>` | Mkdir |
| `<Shift-F7>` | MkdirEnter |
| `<F6>` | Move |
| `<Ctrl-t>` | NewTab |
| `<g><t>` | NextTab |
| `<Ctrl-x><p>` | OpenPrompt |
| `<g><T>` | PrevTab |
| `<Ctrl-p>` | ProcessQueue |
| `<Shift-F5>` | QueueSelection |
| `<Ctrl-q>` | Quit |
| `<F10>` | Quit |
| `<Ctrl-x><r>` | Reconnect |
| `<Ctrl-F5>` | Refresh |
| `<Ctrl-r>` | Refresh |
| `<F2>` | Rename |
| `<Ctrl-f>` | Search |
| `<Ctrl-x><i>` | ServerInfo |
| `<F9>` | Settings |
| `<Ctrl-s>` | SiteManager |
| `<Ctrl-z>` | Suspend |
| `<Alt-1>` | Tab1 |
| `<Alt-2>` | Tab2 |
| `<Alt-3>` | Tab3 |
| `<Alt-4>` | Tab4 |
| `<Alt-5>` | Tab5 |
| `<Alt-6>` | Tab6 |
| `<Alt-7>` | Tab7 |
| `<Alt-8>` | Tab8 |
| `<Alt-9>` | Tab9 |
| `<Ctrl-o>` | ToggleCompare |
| `<Ctrl-h>` | ToggleHidden |
| `<Ctrl-l>` | ToggleLog |
| `<Alt-j>` | ToggleQueue |
| `<Ctrl-j>` | ToggleQueue |
| `<Ctrl-x><l>` | ToggleSpeedLimit |
| `<Ctrl-y>` | ToggleSyncBrowsing |
| `<Ctrl-e>` | ToggleTree |
| `<Ctrl-x><u>` | UnlockVault |
| `<F3>` | View |

## File lists

When a file list (or directory tree) has focus. Global keys work too, unless listed here.

| Key | Action |
|---|---|
| `<End>` | Bottom |
| `<G>` | Bottom |
| `<c>` | Chmod |
| `<C>` | ColumnMenu |
| `<:>` | CommandLine |
| `<y><u>` | CopyUrl |
| `<Down>` | CursorDown |
| `<j>` | CursorDown |
| `<Up>` | CursorUp |
| `<k>` | CursorUp |
| `<minus>` | DeselectPattern |
| `<e>` | Edit |
| `<a>` | EditAddress |
| `<T>` | FocusTree |
| `<Ctrl-d>` | HalfPageDown |
| `<Ctrl-u>` | HalfPageUp |
| `<Alt-Left>` | HistoryBack |
| `<[>` | HistoryBack |
| `<Alt-Right>` | HistoryForward |
| `<]>` | HistoryForward |
| `<*>` | InvertSelection |
| `<=>` | MirrorDir |
| `<Enter>` | Open |
| `<Right>` | Open |
| `<l>` | Open |
| `<PageDown>` | PageDown |
| `<PageUp>` | PageUp |
| `<Backspace>` | ParentDir |
| `<Left>` | ParentDir |
| `<h>` | ParentDir |
| `</>` | QuickFilter |
| `<Ctrl-a>` | SelectAll |
| `<m><r>` | SelectCompareDifferent |
| `<m><y>` | SelectCompareLonely |
| `<m><g>` | SelectCompareNewer |
| `<+>` | SelectPattern |
| `<s><m>` | SortModified |
| `<s><n>` | SortName |
| `<s><o>` | SortOwner |
| `<s><p>` | SortPermissions |
| `<s><s>` | SortSize |
| `<.>` | ToggleHidden |
| `<Insert>` | ToggleSelect |
| `<Space>` | ToggleSelect |
| `<Home>` | Top |
| `<g><g>` | Top |
| `<o>` | View |
| `<v>` | VisualSelect |

## Queue

When the transfer queue has focus.

| Key | Action |
|---|---|
| `<End>` | Bottom |
| `<G>` | Bottom |
| `<Down>` | CursorDown |
| `<j>` | CursorDown |
| `<Up>` | CursorUp |
| `<k>` | CursorUp |
| `<Ctrl-d>` | HalfPageDown |
| `<Ctrl-u>` | HalfPageUp |
| `<J>` | MoveItemDown |
| `<K>` | MoveItemUp |
| `<PageDown>` | PageDown |
| `<PageUp>` | PageUp |
| `<minus>` | PriorityDown |
| `<+>` | PriorityUp |
| `<2>` | QueueTabFailed |
| `<1>` | QueueTabQueued |
| `<3>` | QueueTabSuccessful |
| `<Space>` | QueueToggleItem |
| `<Delete>` | RemoveItem |
| `<x>` | RemoveItem |
| `<r>` | Requeue |
| `<Home>` | Top |
| `<g><g>` | Top |

## Message log

When the message log has focus.

| Key | Action |
|---|---|
| `<End>` | Bottom |
| `<G>` | Bottom |
| `<c>` | ClearLog |
| `<y>` | CopySelection |
| `<Down>` | CursorDown |
| `<j>` | CursorDown |
| `<Up>` | CursorUp |
| `<k>` | CursorUp |
| `<Ctrl-d>` | HalfPageDown |
| `<Ctrl-u>` | HalfPageUp |
| `<PageDown>` | PageDown |
| `<PageUp>` | PageUp |
| `</>` | QuickFilter |
| `<Left>` | ScrollLeft |
| `<h>` | ScrollLeft |
| `<Right>` | ScrollRight |
| `<l>` | ScrollRight |
| `<n>` | SearchNext |
| `<N>` | SearchPrev |
| `<e>` | ToggleErrorsOnly |
| `<t>` | ToggleLogAll |
| `<w>` | ToggleWrap |
| `<Home>` | Top |
| `<g><g>` | Top |
| `<v>` | VisualSelect |

## Text fields

When a text field such as the quickconnect bar has focus. Other keys are typed.

| Key | Action |
|---|---|
| `<Esc>` | FocusLocal |
| `<Tab>` | FocusNext |
| `<F1>` | Help |
| `<Ctrl-q>` | Quit |
| `<F10>` | Quit |

## Quick filter

While typing a pane's quick filter.

| Key | Action |
|---|---|
| `<Esc>` | FocusLocal |

## Dialogs

While a dialog is open. Dialogs also handle their own keys.

| Key | Action |
|---|---|
| `<Esc>` | CloseDialog |

## Terminal caveats

Some keys never reach terminal programs, or arrive as other keys:

- `Ctrl-j` is sent as Enter and `Ctrl-h` as Backspace by many terminals. Toggle
  queue also has `Alt-j`, and toggle hidden files has `.` in file lists.
- `Ctrl-F5` and `Shift-F5`/`Shift-F7` are not sent by every terminal (and tmux
  needs `xterm-keys on`). Refresh also has `Ctrl-r`; queueing and "mkdir and
  enter" get their own dialogs in T62.
- `Alt-<digit>` may be taken by the terminal or window manager; `gt`/`gT`
  switch tabs too.
- `Ctrl-s` and `Ctrl-q` are flow control in some terminals; courier-ftp turns
  flow control off in raw mode, and `F10` also quits.

`Ctrl-d` scrolls half a page down in file lists (vim), so disconnect is
`<Ctrl-x><d>`.
