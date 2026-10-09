# T49 — Search engine

**Phase:** E Transfers · **Depends on:** T43, T47 · **Crate:** `courier-ftp-core` (`search` module) · **FEATURES.md:** §4 (remote search, local search)

## Goal

Recursive search over a local or remote directory with FileZilla's condition
builder, producing results the UI can download, upload, delete or open.

## Scope

1. `SearchQuery { root: RemotePath/LocalPath, conditions: Vec<Condition> (reuse T47 Condition types), match_mode, case_sensitive, search_type: Files|Dirs|Both }` — note: matching entries are **included** (the inverse of filters).
2. Uses the T43 walker; streams results as found via a channel (`SearchEvent::Found(path, Entry)`, `Progress { dirs_scanned }`, `Done`, `Error`).
3. Remote search runs on a **dedicated session** (not the browsing session) so the tab remains usable; cancellable.
4. Uses the listing cache (T46) for already-cached directories and fills it as it goes.
5. Result actions are UI-side (T65) but the engine provides helpers: "queue downloads of selected results preserving relative paths" or "flatten into one local dir" (FileZilla offers both), "delete selected".

## Acceptance criteria

- [ ] Streaming results appear before the search finishes.
- [ ] Cancel stops within 1 s.
- [ ] Conditions name/size/path/date combine with All/Any.
- [ ] Download helper keeps relative structure or flattens with rename on collision.

## Tests

- Mock backend tree search tests.
