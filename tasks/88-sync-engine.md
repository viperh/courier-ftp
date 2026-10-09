# T88 — Sync engine: pull, push and live updates

**Phase:** H Sync · **Depends on:** T81, T82, T87 · **Crate:** `courier-ftp-sync` · **Decisions:** D12
**Reference:** sverb `crates/sverb-sync/src/{engine,pull,push,resync,ws}.rs`.

## Goal

Keep every unlocked vault in sync in the background, offline-first: local edits
never wait for the network.

## Scope

1. **`SyncEngine`**: one per unlocked session, started after unlock, stopped on lock
   or logout; emits `SyncStatus { Synced, Syncing, Offline { pending }, Error(msg), NeedsLogin }`
   and toasts (resurrected item, clock skew, access revoked) via the event bus (T04).
2. **Pull** (per vault): `GET changes?since=<sync_cursor>&limit=500`; for each page in
   **one** SQLite transaction together with the cursor update:
   decrypt envelope → observe HLC stamps → if the local item is clean, replace it; if it
   is dirty, `merge` (T81), re-seal, keep dirty and rebase its outbox `base_revision` →
   advance `vaults.sync_cursor`. Loop while `more`.
3. **Resync** on `410 gone`: pull from 0, delete clean local items missing on the
   server, re-queue dirty missing items with `base_revision = 0`.
4. **Push**: batches from `outbox` (≤ 500 items, ≤ 8 MiB). Results:
   - `ok` → store revision, clear dirty, delete outbox row (cursor not moved).
   - `conflict` with `current` → merge, re-seal, rebase, retry (max 5 rounds).
   - `conflict` without `current` → rebase on 0 and retry as new.
   - `forbidden` / `too_large` → mark item with an error shown in the UI.
5. **Triggers**: full cycle (vault list, pull, push) at start; local change → push after
   a 2 s debounce (`sync.push_debounce_ms`), then pull; WS `vault_changed` beyond the
   cursor → pull that vault; WS reconnect → pull all; `vault_access` → refresh vault
   list; fallback poll every 300 s (`sync.poll_fallback_secs`).
6. **Offline**: transport errors retry with exponential backoff 1 s → 300 s; edits stay
   in the outbox indefinitely; status shows `offline (N pending)`.
7. **WebSocket client** (`tokio-tungstenite`, rustls): send `auth` first; reconnect with
   1–60 s jittered backoff; on 4401 refresh token once and reconnect.
8. **What syncs** (`SyncPolicy`): all item kinds except `history-entry` unless
   `sync.history = true`. Device-local data (queue, tabs, local dir overrides,
   last-connected) never syncs.
9. **Approvals for synced values that act locally** (sverb `resolve/approval.rs`):
   site fields that can make this device run something or touch local files —
   currently none in core; if later added (e.g. per-site "run command after
   transfer"), they must require per-device approval stored in `local_approvals`
   (`item_id, field, sha256(value)`), re-asked when the value changes. Document this
   rule in `docs/security.md`.

## Acceptance criteria

- [ ] Two devices editing different fields of the same site offline converge after reconnect.
- [ ] Same field edited on both: newest HLC wins on both devices.
- [ ] Delete on one device + edit on the other: newer action wins; resurrect toast shown.
- [ ] Killing the network mid-push loses nothing (outbox intact, push resumes).
- [ ] `410` triggers resync and keeps dirty items.
- [ ] Change made on device A appears on device B within 3 s while both are online.

## Tests

- In-process server tests with simulated network failures; property test: random edit sequences on 3 devices converge to identical state.
