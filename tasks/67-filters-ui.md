# T67 — Filters UI

**Phase:** F TUI · **Depends on:** T47, T52 · **Crate:** `courier-ftp` · **FEATURES.md:** §8

## Goal

FileZilla's "Directory listing filters" dialog and the filter editor.

## Scope

1. **Filters dialog** (`Ctrl-x f` / menu): two columns — *Local filters* and *Remote filters* — each a checklist of all filters; toggling enables the filter for that side. Buttons: *Edit filter rules…*, *Toggle all*, *Apply*, *OK*. Filter set dropdown (save/load named sets, e.g. "Web project").
2. **Filter editor**: list of filters (add, rename, copy, delete); per filter: name, *Filter applies to files / directories*, match *All / Any / None / Not all*, case-sensitive, *local only / remote only / both*, condition rows (type, operator, value) with add/remove; regex validated live with error message.
3. **Built-in filters** shown with a "built-in" tag; *Restore defaults* button.
4. **Apply** immediately re-filters both panes; status bar indicator (T57) updates.
5. Option in the dialog: "Apply filters to transfers" (on by default — recursive operations skip filtered entries, T43) — clarifies FileZilla behaviour.
6. Changes saved to settings via T05 `save_user`.

## Acceptance criteria

- [ ] Full editing round-trip persisted to config.
- [ ] Invalid regex blocks OK with a clear error.
- [ ] Panes update on apply.

## Tests

- UI-flow and snapshot tests.
