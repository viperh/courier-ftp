# Brief: implement courier-ftp task(s) in your own worktree

You run in an isolated git worktree of /home/user/courier-ftp (a separate checkout of the
same repository). Other agents work in parallel in their own worktrees; the coordinator
merges finished work into the main branch `claude/lucid-fermat-bhtbd0`.

## Setup
1. **Your worktree starts from `master`, which is OUTDATED.** First run:
   `git checkout -b impl/<your-lane-name> claude/lucid-fermat-bhtbd0` (the local branch;
   it holds the current code and the revised task files). Verify: your task file contains a
   `## Technical specification` section and `scripts/check-layering.py` exists. If not,
   stop and report.
2. Read `CLAUDE.md`, `tasks/README.md` (decisions D1–D15, project rules), your task file(s)
   completely, and the tasks in their **Depends on** lines (already implemented in the code
   unless your prompt says otherwise). sverb reference: /home/user/viperh/sverb (read-only,
   copy-and-adapt where the task says so, D13).

## Rules
- Implement the Technical specification and Implementation steps; meet every acceptance
  criterion; write every named test. Docker e2e tests are `#[ignore]` + `COURIER_E2E=1`
  (T76); run them if `docker info` works.
- Open questions: use the task's stated default; don't block. If the spec is impossible or
  wrong, make the smallest sensible deviation and record it in the task file under
  `## Implementation notes` at the end.
- Stay inside your task's scope and files. Shared files (root `Cargo.toml`
  `[workspace.dependencies]`, `Cargo.lock`, `lib.rs` module lists, `tasks/README.md`) —
  edit only the lines you need, so the coordinator's merge is easy. Never reformat
  unrelated code.
- Gates before every commit (all must pass, in your worktree):
  `cargo fmt --all --check`,
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
  `cargo clippy -p courier-ftp --all-targets --no-default-features -- -D warnings` (CI runs this too),
  `cargo test --workspace --all-features`,
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --all-features --workspace`,
  plus task-specific scripts (`python3 scripts/check-layering.py`, `python3 scripts/check-unsafe.py` if they exist).
- Commit after every step that passes the gates (small commits, clear messages) ending with:

      Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
      Claude-Session: https://claude.ai/code/session_011d6S7a6iQYXsp7GaP3Yc6k

  **Do not push** and do not touch the main branch; the coordinator merges your branch.
- Tick met acceptance criteria (`- [x]`) in your task file(s) and commit.
- Keep disk use reasonable (4 CPUs, shared machine): use `CARGO_TARGET_DIR` default in your
  worktree; `cargo clean` at the end is NOT needed.

## Final report (last message)
Branch name, final commit SHA, worktree path, gate results, ACs not met and why, deviations
(Implementation notes), anything dependants must know (public API names).

## CI notes (learned)
- GitHub runners hit Docker Hub's anonymous pull limit. Every Docker image reference
  (Dockerfiles `FROM`, compose files, workflow `services`, testcontainers images) must use
  `public.ecr.aws/docker/library/<image>:<tag>` (ECR mirror of Docker official images)
  instead of bare Docker Hub names.
- Pin tool versions installed in CI (`taiki-e/install-action` `tool: name@x.y.z`).
- CI runs tests on Windows and macOS too: never hard-code Unix path strings in test
  expectations (use `std::path::absolute`/`Path::join`), and gate Unix-only behaviour with
  `#[cfg(unix)]`.
- Disk is a shared, fixed allowance. Build with `CARGO_INCREMENTAL=0` (export it in every
  shell), delete `target/doc` after doc checks, and never keep more than one target dir.
  If you hit "No space left on device", delete your worktree's `target/debug/incremental`
  and `target/doc`, then retry; report if it persists.
- Disk: always also export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 (no debug info; halves target size).
- Memory: the machine has 15 GB shared by up to 3 agents. Always `export CARGO_BUILD_JOBS=2`
  and run tests with `-- --test-threads=2`. A previous run exhausted memory and restarted
  the container (all agents were killed).
- When you add dependencies, run `cargo vet regenerate exemptions` and `cargo vet --locked`
  (and `cargo deny --all-features check`) before committing; commit `supply-chain/` changes.
- The local toolchain is rustc 1.99 stable (matches CI clippy). Never run `rustup` commands
  that change the shared toolchain (other agents build at the same time). Windows target
  `x86_64-pc-windows-gnu` is installed for `cargo clippy --target` checks of cfg(windows) code.
- Never run `cargo clean` outside your own worktree.
- Tests that capture tracing output must NOT rely on `tracing::subscriber::set_default`
  (thread-local): callsite interest is cached process-wide and parallel tests leave
  callsites disabled (CI: "tracing captured nothing", ~1 in 5 runs). Install ONE global
  TRACE subscriber once (`std::sync::Once` + `set_global_default`) whose writer routes into
  a thread-local buffer; see `capture_tracing()` in
  crates/courier-ftp-proto-ftp/src/control/tests.rs. Stress such tests:
  `for i in $(seq 1 20); do cargo test ... -- --test-threads=16; done`.
- Real-clock rate-limit / timing tests: measure allowances from the first request.
- Binary crate tests: use `crate::runtime::spawn_blocking`; read saved config only after
  `AppHarness::wait_saved()`; when injecting a fake listing, wait for the real listing to
  land and then use `PaneInput::ListingUpdated`.
- PTY e2e tests (`PtyApp::launch`) must pass `PtyOptions::no_vault()` unless they test the vault
  (otherwise the app shows the first-run vault screen); vault tests use `TestHome::with_vault()`
  and `PtyApp::unlock()`.
