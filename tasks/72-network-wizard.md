# T72 — Network configuration wizard

**Phase:** G App-level · **Depends on:** T05, T10, T11, T52 · **Crate:** `courier-ftp` + `courier-ftp-proto-ftp` · **FEATURES.md:** §9 (network configuration wizard)

## Goal

Guide users through FTP passive/active settings and test that they work.

## Scope

1. Wizard steps (dialog pages):
   1. Intro: what passive/active means in one paragraph.
   2. Passive mode: *Use server's external IP instead* (ignore unroutable) / *Fall back to active*.
   3. Active mode: external IP (*Ask OS* / *Use this IP* / *Get from URL*), port range (*any* / range), note about router port forwarding.
   4. **Test**: run against a test target.
   5. Summary: apply settings / go back.
2. **Test target — decision needed**: FileZilla tests against its own `probe.filezilla-project.org`, which we must not use. Options to implement: test against **a server the user chooses** (a saved site or URL) — performs connect, `PASV` + `LIST`, then `PORT`/`EPRT` + `LIST`, and reports each step. *(Default chosen; flag for review.)*
3. Results: per step ✔/✘ with explanation and suggested fix (e.g. "Active mode failed: the server could not connect back. Your router probably blocks incoming connections — use passive mode.").
4. Applying writes settings via T05.

## Acceptance criteria

- [ ] Wizard steps navigable back/forward, cancel discards.
- [ ] Test against vsftpd container reports passive ✔, active ✔ (local) and a blocked active port ✘ correctly.

## Tests

- Integration test against Docker vsftpd; snapshot tests of pages.
