# CLAUDE.md

## Working rules

- **Commit and push often.** After every meaningful step (a task file, a module, a passing
  test, a fix), commit and push to the working branch right away. Never leave finished
  work only in the working tree: the session can end at any time and unpushed work is lost.
- Keep each commit small and self-contained, with a clear message.

## Project

- courier-ftp is a terminal (TUI) replacement for the FileZilla client.
- Feature reference: `FEATURES.md`. Implementation plan: `tasks/README.md` (start with T00,
  follow the milestones in order, respect each task's **Depends on** list).
- Implementation status, how the work is run, and open follow-ups: `tasks/handoff/README.md`.
- Decisions D1–D15 in `tasks/README.md` are agreed with the owner; ask before changing them.
- sverb (`github.com/viperh/sverb`) is the reference for the vault, sync, security, CI and tests.
