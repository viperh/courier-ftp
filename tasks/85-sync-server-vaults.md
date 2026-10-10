# T85 — Sync server: vaults, pull/push and live updates

**Phase:** H Sync · **Milestone:** M7 · **Depends on:** T83, T84 · **Crate(s):** `courier-ftp-server` · **Decisions:** D12, D14 · **FEATURES.md:** — (D12 sync infrastructure)
**Related (integrates with, not blocking):** T89
**Reference:** sverb `crates/sverb-server/src/sync/{mod,vaults,pull,push,quota,gc,mem}.rs`, `src/ws/{mod,bus,hub,session,pg_notify}.rs`, `src/routes/vaults.rs`, `migrations/server/0003_sync.sql`, `tests/{sync,ws}.rs`; SPEC §10.3–§10.5, §12.1–§12.3, §12.5.

## Goal

The data half of the sync server: list a user's vaults with their wrapped keys, hand out
an ordered, gap-free change feed per vault, accept pushes with optimistic concurrency and
per-item conflict results, enforce size limits and quotas, purge old tombstones, and tell
connected devices about changes over a WebSocket — across several server replicas. The
server only ever handles ciphertext envelopes.

## Context

- **Before:** T84 provides `AppState`, `Store` (`Mem`/`Pg`), `ApiError`, `AuthCtx`, the
  middleware stack, the full `0001_init.sql` schema (`vaults`, `vault_members`, `items`,
  `items_rotation_staging`), `BusEvent` + `EventSink` (with a no-op sink) and the personal
  vault created at registration. T83 provides `VaultView`, `PullQuery`, `PullResponse`,
  `PushRequest`, `PushResponse`, `ServerMsg`, `ClientMsg`, limits and WS constants.
- **After:** T86 exposes GC through `admin gc`, metrics and `/readyz` (which reads the WS
  listener health from here); T88 is the client of pull/push/WS; T89 adds team vault
  creation, grants, revocation and rotation, reusing the vault row lock, the bus and the
  `vault_access` notifications defined here.

## Technical specification

### Types and APIs

New modules: `src/sync/{mod,vaults,pull,push,quota,gc,mem}.rs`, `src/routes/vaults.rs`,
`src/ws/{mod,bus,hub,session,pg_notify}.rs`, `migrations/0002_sync.sql`.

```rust
// src/sync/mod.rs
pub const TEAM_VAULT_CAP_BYTES: u64 = 1024 * 1024 * 1024;        // 1 GiB per team vault
#[derive(Debug, Clone, Copy)]
pub struct SyncLimits {
    pub personal_quota_bytes: u64,        // storage_quota_mib * 1 MiB (default 100 MiB)
    pub team_vault_cap_bytes: u64,        // TEAM_VAULT_CAP_BYTES
    pub tombstone_horizon: time::Duration // tombstone_horizon_days (default 90)
}
/// The caller's relation to a vault, resolved under the same snapshot/lock as the operation.
pub struct Access { pub kind: VaultKind, pub permission: Permission }

impl Store {
    pub async fn list_vaults(&self, user: Uuid, now: OffsetDateTime) -> Result<Vec<VaultView>, ApiError>;
    pub async fn pull(&self, user: Uuid, vault: Uuid, since: u64, limit: u32) -> Result<PullResponse, ApiError>;
    pub async fn push(&self, ctx: AuthCtx, vault: Uuid, req: &PushRequest, limits: SyncLimits, now: OffsetDateTime) -> Result<PushOutcome, ApiError>;
    pub async fn gc_vault(&self, vault: Uuid, horizon_before: OffsetDateTime) -> Result<GcVaultReport, ApiError>;
    pub async fn vault_ids(&self) -> Result<Vec<Uuid>, ApiError>;
    pub async fn vaults_of_user(&self, user: Uuid) -> Result<Vec<Uuid>, ApiError>; // for WS subscriptions
}
pub struct PushOutcome { pub response: PushResponse, pub head_revision: u64, pub accepted: u32 }

// src/sync/push.rs — pure decision shared by both backends
pub struct Stored { pub revision: u64, pub key_version: u32, pub envelope: Vec<u8>, pub deleted: bool }
pub enum Decision { Accept { growth: i64 }, Conflict(Option<RemoteItem>), TooLarge(&'static str) }
/// Decides every change in batch order; `usage`/`limit` is the quota budget,
/// updated as changes are accepted.
pub fn plan(changes: &[PushChange], stored: &HashMap<Uuid, Stored>, usage: u64, limit: u64, cap_msg: &'static str) -> Vec<Decision>;
/// Envelope header sanity (T80 format): len ≥ 45, byte 0 == 0x01, header key_version == change.key_version.
pub fn check_envelope_header(change: &PushChange) -> Result<(), ApiError>;

// src/sync/gc.rs
pub struct GcReport { pub vaults: u64, pub tombstones_purged: u64, pub expired_tokens: u64,
                      pub login_states: u64, pub reauth_tokens: u64, pub recovery_codes: u64,
                      pub invites: u64, pub revoked_devices: u64, pub abandoned_rotations: u64 }
pub async fn run(store: &Store, now: OffsetDateTime, limits: SyncLimits) -> Result<GcReport, ApiError>;
pub fn spawn_background(state: AppState, interval: Option<std::time::Duration>) -> Option<JoinHandle<()>>;

// src/sync/mem.rs
/// In-memory model with PostgreSQL semantics: per-vault async mutex = vault row lock,
/// readers take a consistent snapshot, a push applies all rows at commit in one step.
pub struct MemSync { /* … */ }
impl MemSync {
    /// Test hook: the next push stops right before commit (lock held) until released.
    pub fn pause_next_commit(&self) -> CommitGate;
}

// src/ws/bus.rs
pub const CHANNEL: &str = "courier_events";
pub const MAX_PAYLOAD_BYTES: usize = 7900;       // Postgres NOTIFY limit is 8000
pub const BUS_CAPACITY: usize = 1024;
pub trait Bus: Send + Sync + 'static {
    fn publish(&self, ev: BusEvent);                       // after commit; never blocks
    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<BusEvent>;
    fn healthy(&self) -> bool;                            // PgBus: listener connected
}
pub struct LocalBus;                                       // in-process broadcast
pub struct PgBus;                                          // NOTIFY / LISTEN
impl EventSink for Arc<dyn Bus> { fn publish(&self, ev: BusEvent); } // replaces T84's NoopSink

// src/ws/hub.rs
pub const SESSION_QUEUE: usize = 256;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Topic { User(Uuid), Vault(Uuid), Device(Uuid) }
pub enum HubMsg { Send(ServerMsg), Close(u16, &'static str), Subscribe(Topic), Unsubscribe(Topic) }
pub struct Hub;
impl Hub {
    pub fn register(&self, user: Uuid, device: Uuid) -> (SessionId, mpsc::Receiver<HubMsg>);
    pub fn subscribe(&self, s: SessionId, t: Topic); pub fn unsubscribe(&self, s: SessionId, t: Topic);
    pub fn unregister(&self, s: SessionId);
    pub fn dispatch(&self, ev: &BusEvent);                 // maps events to topics, try_send (drop on full)
    pub fn active(&self) -> usize;
}

// src/ws/session.rs
#[derive(Debug, Clone, Copy)]
pub struct WsTiming { pub auth_timeout: Duration, pub ping_interval: Duration, pub max_missed_pongs: u32 } // 5 s, 30 s, 2
/// One connection, written against a Frame stream/sink so tests run it over channels with paused time.
pub async fn run<S, K>(stream: S, sink: K, state: AppState, timing: WsTiming)
where S: Stream<Item = Frame> + Unpin, K: Sink<Frame> + Unpin;
pub enum Frame { Text(String), Binary(Vec<u8>), Ping(Vec<u8>), Pong(Vec<u8>), Close(Option<(u16, String)>) }
```

### Behaviour

#### Endpoints

| Method | Path | Auth | Request → Response | Success | Errors (in check order) |
|---|---|---|---|---|---|
| GET | `/v1/vaults` | Bearer | → `Vec<VaultView>` | 200 | 401 |
| GET | `/v1/vaults/{id}/changes?since=<u64>&limit=<u32>` | Bearer | → `PullResponse` | 200 | 400 `"limit must be 1..=500"` (0) / bad query; 401; 404 `"vault not found"` (unknown or not a member); 410 `"cursor below the GC floor; resync from 0"` |
| POST | `/v1/vaults/{id}/changes` | Bearer | `PushRequest` → `PushResponse` | 200 | 400 batch shape (`PushRequest::validate` text); 400 `"malformed envelope"`; 401; 404 `"vault not found"`; 403 `"read-only access"`; 409 rotating `"vault key rotation in progress"`; 400 `"key_version_stale: vault is at key version N"` |
| GET | `/v1/ws` | first message | WebSocket | 101 | close 4401 / 4408 (below) |

`limit` larger than 500 is clamped to 500; absent = 500. `since` absent = 0.

#### Vault list

Vaults where the caller has at least one `vault_members` row. Per vault: `permission` =
the highest explicit permission (T89 adds "manage for org owner/admin"); `grants` = all
of the caller's rows, ascending `key_version` (several only during/after a rotation);
`rotation` = parsed `vaults.rotation` with `abandoned = now - started_at >
ROTATION_ABANDON_SECS`. Ordered: personal first, then by `id`.

#### Pull (§12.2)

PostgreSQL: one `REPEATABLE READ, READ ONLY` transaction:
1. `SELECT key_version, head_revision, gc_floor_revision FROM vaults WHERE id = $1` and
   membership (`EXISTS vault_members … user_id = $2`); none → 404.
2. `since > 0 && since < gc_floor_revision` → 410.
3. `SELECT id, revision, key_version, envelope, deleted FROM items WHERE vault_id = $1 AND
   revision > $2 ORDER BY revision LIMIT $3 + 1`; `more = rows > limit` (drop the extra).
4. Response `head_revision` from step 1 (same snapshot).
Any permission may pull, also during a rotation. Because pushes commit in revision order
(below), every snapshot is a gap-free prefix of the history.

#### Push (§12.1, §12.3)

1. `PushRequest::validate` (≤ 500 changes, ≤ 8 MiB total, unique non-nil ids) and
   `check_envelope_header` for every change — before touching the DB.
2. `BEGIN` (READ COMMITTED). `SELECT kind, owner_user_id, org_id, key_version,
   head_revision, rotation FROM vaults WHERE id = $1 FOR UPDATE` — the vault row lock
   serialises all pushes, rotations (T89) and GC of this vault; taken **before** anything
   the decision depends on.
3. Membership: no row → 404; highest permission `read` → 403.
4. `rotation IS NOT NULL` → 409 `rotating` (also when abandoned; it is cleared by the next
   `begin` or by GC, T89).
5. Any `change.key_version != vaults.key_version` → 400 `key_version_stale`.
6. `SELECT id, revision, key_version, envelope, deleted FROM items WHERE vault_id = $1 AND
   id = ANY($2) FOR UPDATE`.
7. Quota budget: personal vault → `SUM(octet_length(envelope))` of the owner's personal
   vault vs `personal_quota_bytes`; team vault → the vault's sum vs `TEAM_VAULT_CAP_BYTES`.
8. `plan` per change, in batch order:
   - `envelope.len() > MAX_ENVELOPE_BYTES` → `too_large` / `ENVELOPE_TOO_LARGE_MESSAGE`;
   - stored item exists and `stored.revision != base_revision` → `conflict` with
     `current = stored`;
   - stored item absent and `base_revision != 0` → `conflict` with `current = None`
     (e.g. its tombstone was purged: the client re-pushes with base 0);
   - `growth = new_len - old_len`; `growth > 0 && usage + growth > limit` → `too_large` /
     `QUOTA_EXCEEDED_MESSAGE` (personal) or `VAULT_CAP_MESSAGE` (team); shrinking or
     equal-size changes are always accepted (users over quota can still delete);
   - else `ok`, `usage += growth`.
9. `n` = accepted count. If `n > 0`: `UPDATE vaults SET head_revision = head_revision + n
   WHERE id = $1 RETURNING head_revision`; accepted changes get `head-n+1 ..= head` in batch
   order. Rejected changes consume no revision.
10. Upsert accepted rows (`INSERT … ON CONFLICT (vault_id, id) DO UPDATE SET revision,
    key_version, envelope, deleted, updated_at = now, updated_by_device = device`).
11. `COMMIT`, then `bus.publish(VaultChanged{vault, head})` if `n > 0`; metrics
    `courier_sync_push_items_total{result}` and `courier_sync_push_bytes_total`.
Response: one `PushResult` per change in request order.

**Why gap-free:** push B can take the row lock only after push A committed, so B's
revisions are larger and become visible after A's; PostgreSQL makes a commit visible before
releasing its locks. A reader of `revision > cursor ORDER BY revision` can never see `k+1`
without `k`.

#### Tombstone GC and housekeeping

`gc::run` (from the background job and `admin gc`, T86):
- Per vault, one transaction with the vault row lock: `DELETE FROM items WHERE vault_id = $1
  AND deleted AND updated_at < now - horizon RETURNING revision`; if any,
  `gc_floor_revision = GREATEST(gc_floor_revision, max(revision))`.
- Deletes: `auth_tokens` with `expires_at < now`; `login_states`, `reauth_tokens`,
  `recovery_codes` past expiry; invites expired more than 30 days ago or accepted more than
  30 days ago; devices revoked more than 30 days ago (with their tokens).
- Abandoned rotations (> 15 min): staging deleted, `rotation = NULL` (T89 semantics).
- Background job: enabled unless `gc_interval_hours = 0`; first run after 5 min plus a random
  0–10 % of the interval; then every interval. Every replica may run it; the row locks make
  concurrent runs harmless. Logs one info line with the `GcReport` counts.

#### WebSocket `/v1/ws` (session state machine)

| State | Event | Action / next state |
|---|---|---|
| `AwaitAuth` (5 s timer) | text `{"type":"auth","token"}` with valid access token | register in hub; subscribe `User(user)`, `Device(device)`, then `Vault(v)` for every vault of the user (user topic first, so a grant racing the listing is not lost); send `ping`; → `Open` |
| `AwaitAuth` | anything else, invalid token, timer fires | close 4401 `"authentication required"` |
| `Open` | hub `Send(msg)` | forward as text frame |
| `Open` | client `ping` | send `pong` |
| `Open` | client `pong` | `missed = 0` |
| `Open` | ping timer (30 s) | if `missed == 2` → close 4408 `"ping timeout"`; else revalidate the token via `Store::authenticate` (fail → close 4401), send `ping`, `missed += 1` |
| `Open` | access token `expires_at` reached | close 4401 `"token expired"` |
| `Open` | hub `Close(4401)` (device revoked, user disabled) | close 4401 |
| `Open` | binary frame / unknown `type` / second `auth` | ignored |
| `Open` | text frame > 16 KiB | close 1009 |
| any | internal error | close 1011 |

Hub dispatch:

| `BusEvent` | Topic | Effect |
|---|---|---|
| `VaultChanged{vault, head}` | `Vault(vault)` | `ServerMsg::VaultChanged` |
| `VaultAccess{user, vault, Granted}` | `User(user)` | subscribe the user's sessions to `Vault(vault)`, then send `vault_access granted` |
| `VaultAccess{user, vault, Revoked}` | `User(user)` | send `vault_access revoked`, then unsubscribe |
| `VaultAccess{user, vault, Rotated}` | `User(user)` | send `vault_access rotated` |
| `AccountChanged{user, v, origin}` | `User(user)` | `account_changed` to every session except device `origin` |
| `DevicesRevoked{ids}` | `Device(id)` each | `Close(4401)` |
| `UserDisabled{user}` | `User(user)` | `Close(4401)` |

Per-session queues hold 256 messages; `try_send` drops on overflow (notifications are hints;
the client's fallback poll repairs it). Metric `courier_ws_connections_active`.

#### Multi-replica fan-out

- `PgBus::publish`: `SELECT pg_notify('courier_events', $1)` with the event as JSON
  (`BusEvent` serde; ids only, ≤ 7900 bytes; `DevicesRevoked` split into chunks of 200 ids),
  executed on the pool **after** the commit. Publishing failures are logged at warn and
  dropped.
- Every replica holds one dedicated connection with `LISTEN courier_events`, feeding a
  `broadcast` channel (capacity 1024) that the hub drains. The publishing replica receives its
  own events the same way (single code path for one or many replicas).
- Listener reconnect backoff 0.5 s → 30 s (doubling). `Bus::healthy()` is false while
  disconnected; `/readyz` (T86) reports `ws_listener: down` and returns 503 once it has been
  down for more than 30 s.
- `LocalBus` (tests, in-memory store): one `broadcast` channel; several `AppState`s sharing
  one `LocalBus` and one `MemDb` model several replicas.

### Data formats and configuration

`migrations/0002_sync.sql`:

```sql
-- Tombstone GC scans old tombstones.
CREATE INDEX items_tombstones_updated_at ON items (updated_at) WHERE deleted;
-- Quota sums per vault.
CREATE INDEX items_vault_id ON items (vault_id);
```

`vaults.rotation` JSON (written by T89, read here):
`{"by":"<uuid>","device":"<uuid>","new_key_version":3,"started_at":"2026-10-09T12:00:00Z"}`.

Bus payload example: `{"e":"vault_changed","vault_id":"0192…","head_revision":42}`.

Configuration used here (variables defined in T86's table):

| Env | Default | Meaning |
|---|---|---|
| `COURIER_STORAGE_QUOTA_MIB` | 100 | personal vault quota (MiB of envelope bytes) |
| `COURIER_TOMBSTONE_HORIZON_DAYS` | 90 | tombstones older than this are purged |
| `COURIER_GC_INTERVAL_HOURS` | 24 | background GC interval; 0 disables |

### Errors

`ApiError` variants from T84: `Invalid` (400), `AuthRequired` (401), `Forbidden` (403),
`NotFound` (404), `Rotating` (409), `Gone` (410), `Unavailable`/`Internal` (503/500).
Per-item outcomes are not errors (`PushStatus`). WebSocket errors are close codes only.
A push or pull that exceeds the 30 s request timeout returns 408 `invalid "request
timeout"` and the transaction is rolled back (no partial push).

### Security and logging

- The server never parses or decrypts envelopes beyond the 29-byte header check.
- Logged at info: `user_id`, `device_id`, `vault_id`, counts, revisions, `request_id`;
  never envelopes, sizes of individual items, emails or tokens.
- Existence of vaults the caller is not a member of is never revealed (404, same message as
  unknown).
- Section **"What the sync server sees"** added to `docs/threat-model.md`: account emails,
  OPAQUE records, public keys, sealed bundles, vault memberships and permissions, org names
  (plaintext, T89), item ids, counts, sizes rounded to 256 bytes (T80 `pad256`), revisions,
  tombstone flags, timing, device names/platforms and IP addresses. Never item kinds, site
  names, hosts, usernames, passwords or keys.

## Implementation steps

1. `0002_sync.sql`; `sync::vaults` + `GET /v1/vaults` (both backends) with tests.
2. `sync::pull` + route; pagination and 404 tests.
3. `sync::push::plan` (pure) with exhaustive unit tests; `check_envelope_header`.
4. Pg push transaction and `MemSync` push with the same semantics; quota; route.
5. `sync::gc` + background job.
6. `ws::bus` (`LocalBus`, `PgBus`) replacing `NoopSink`; `ws::hub`.
7. `ws::session` state machine + `/v1/ws` route; paused-time tests.
8. Two-replica tests (mem and Pg); concurrency test; threat-model section.

## Acceptance criteria

- [ ] AC1 8 concurrent pushers (50 batches × 10 new items each) into one vault produce
  revisions exactly `1..=4000` with no gaps or duplicates (mem and Pg).
- [ ] AC2 A puller running concurrently with AC1 and advancing its cursor per page receives
  every revision exactly once, in order.
- [ ] AC3 Two devices pushing the same item with the same `base_revision`: exactly one `ok`,
  the other `conflict` with `current` equal to the winner's row.
- [ ] AC4 Pull pagination with `limit = 7` over 50 items returns 8 pages, `more` false only
  on the last, `head_revision` constant.
- [ ] AC5 After GC purges tombstones up to revision R, a pull with `0 < since < R` returns
  410 and `since = 0` returns the remaining items.
- [ ] AC6 A `vault_changed` message reaches a WebSocket on replica B within 1 s of a push
  committed through replica A (two `AppState`s; LocalBus and PgBus variants).
- [ ] AC7 Personal quota: with `COURIER_STORAGE_QUOTA_MIB=1`, the change that would exceed
  1 MiB gets `too_large` / `"quota exceeded"`; a shrinking change is still accepted.
- [ ] AC8 `read` permission → 403; active rotation → 409 `rotating`; stale key version → 400
  `key_version_stale`; non-member and unknown vault → identical 404.
- [ ] AC9 WebSocket: no auth within 5 s → 4401; expired token → 4401; 2 missed pongs → 4408;
  device revoked (T84 logout) → 4401 within 1 s.
- [ ] AC10 An uncommitted push (paused before commit) is invisible to a concurrent pull, and
  the pull is not blocked by it.
- [ ] AC11 The Pg DB dump after the sync tests contains no canary plaintext (envelopes are
  ciphertext from the client crate) — `canary` CI job.
- [ ] AC12 CI `server-db`, `fmt`, `clippy`, `docs` pass.

## Tests

Same `Harness` (mem + Pg via `DATABASE_URL`, `both!` macro) as T84. Envelopes in server
tests are real T80 envelopes sealed with a test key (`insecure-test-ksf` not needed).

### Unit tests
- `sync::push::tests::plan_table` — new item, base match, base mismatch, absent with base ≠ 0,
  tombstone, oversize, quota exact boundary, shrink over quota, mixed batch keeps order (AC3, AC7).
- `sync::push::tests::envelope_header_checks` — short, wrong version byte, header key
  version mismatch.
- `ws::hub::tests::dispatch_table` — every row of the dispatch table; overflow drops without
  blocking.
- `ws::bus::tests::payload_size_and_split` — 1000 device ids split into 5 notifications ≤ 7900 B.
- `sync::gc::tests::floor_only_rises`.

### Property / fuzz tests
- `props::push_plan_never_accepts_stale_base` — random stored states and batches: an `ok`
  change always had `base == stored.revision` (or absent and 0), and accepted count == n.
- `props::gap_free_under_random_interleavings_mem` — random interleavings of K pushers and a
  puller on `MemSync` (tokio paused, `pause_next_commit`), invariants of AC1/AC2.

### Snapshot tests
- Not a UI task; no snapshots.

### Integration tests (`tests/sync.rs`, `tests/ws.rs`)
- `t01_push_new_items_and_pull` (AC4).
- `t02_conflicts` (AC3).
- `t03_pagination` (AC4).
- `t04_concurrency_gap_free` — AC1 + AC2 with a concurrent puller (mem and Pg).
- `t04_uncommitted_invisible_mem` — `pause_next_commit` (AC10).
- `t05_read_only_forbidden`, `t06_rotating_blocks_push` (sets `rotation` directly),
  `t11_stale_key_version`, `t10_non_member_404` (AC8).
- `t07_batch_limits` — 501 changes, 8 MiB + 1, duplicate ids, 1 MiB + 1 envelope →
  `too_large` (AC8).
- `t08_quota` (AC7).
- `t09_gc_and_gone` (AC5).
- `t12_ciphertext_only` — pushes envelopes of a canary site; scans all `items.envelope`
  bytes for the canary (AC11).
- `ws::t01_no_auth_within_5s_closes_4401`, `t01_first_message_must_be_auth`,
  `t02_token_validation`, `t03_push_notifies_members_only`, `t04_two_replicas_fan_out_mem`,
  `t04_two_replicas_fan_out_pg` (AC6), `t05_token_expiry_closes_4401`,
  `t06_missed_pongs_close_4408`, `t07_grant_and_revoke_live_subscription` (publishes
  `VaultAccess` directly), `t08_device_revoked_closes_4401`, `t08_user_disabled_closes_4401`,
  `account_changed_skips_origin_device`, `pg_listener_down_marks_unhealthy` (AC9).

### End-to-end tests
- `courier-ftp-e2e/tests/sync_server.rs::two_clients_sync_through_docker_server` (T76 sync
  fixture, `#[ignore]`, `COURIER_E2E=1`): two headless sync clients (T88) against the
  `deploy/docker-compose.yml` stack exchange an item; covers AC6 against a real deployment.

## Out of scope

- Team vault creation, grants, revocation, rotation endpoints and org-admin implicit
  `manage` (T89).
- Admin CLI wiring of GC, metrics exporter, `/readyz` (T86).
- Per-item ACLs (`PushStatus::Forbidden` stays reserved).
- Org-level quotas.

## Open questions

- **Team vault quota.** Team vaults are capped at 1 GiB each and not counted against any
  user (sverb v1 decision). Is a per-org quota wanted?
