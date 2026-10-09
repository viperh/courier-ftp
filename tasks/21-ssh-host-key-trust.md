# T21 — SSH host key verification

**Phase:** C SFTP · **Milestone:** M2 · **Depends on:** T04, T20 · **Crate(s):** `courier-ftp-core` (`trust` module: store trait, entries, session trust), `courier-ftp-proto-sftp` (`known_hosts` module, `TrustVerifier`) · **Decisions:** D4, D13 · **FEATURES.md:** §1 (cached host key fingerprint confirmed on first connect)
**Related (integrates with, not blocking):** T30, T68, T69, T81
**Reference:** sverb `crates/sverb-core/src/known_hosts/{parse,hashed,lookup,fingerprint,check}.rs` and `tests.rs`, `crates/sverb-conn/src/ssh/{verify,verify_tests,handler}.rs`, `crates/sverb-tui/src/views/dialogs/host_key.rs` — copy and adapt (D13).

## Goal

Verify every SSH server's host key like FileZilla: ask on first contact, remember the
answer ("always trust" goes into the vault and syncs to the user's other devices), and
stop with a loud warning when a known host presents a different key. Keys already
trusted in the user's OpenSSH `known_hosts` files are honoured read-only, so people
coming from `ssh` are not asked again.

## Context

- **Before:** T20 defines the seam `HostKeyVerifier` (`verify(host, port, &ServerKey,
  &VerifyCtx) -> HostKeyVerdict`, `known_key_types`) and `ServerKey` (type, bits,
  base64 blob, SHA-256 and MD5 fingerprints); until now every key is rejected
  (`UnverifiedHostKeys`). T04 gives `PromptKind::TrustHostKey(HostKeyPrompt)`,
  `OldKey`, `OldKeySource`, `HostKeyInfo`, `PromptResponse::HostKey(TrustAnswer)`
  (`HostKeyAnswer` = alias of `TrustAnswer`), `prompt_with_cancel` and `LogMessage`.
- **After:** T22 passes a `TrustVerifier` into `SshConnection::connect`. T58 builds it in
  the binary's `BackendFactory`. T30 implements `HostKeyStore` on `known-host` items
  (T81) and swaps it in after unlock through `SwitchableHostKeyStore`. T69 renders the
  unknown/changed prompts. T68 lists and removes stored keys through the management API.
  T76 provides the `sshd` fixture with host-key regeneration for the changed-key e2e test.
- Difference from sverb: sverb stores known hosts in OpenSSH form (patterns, hashing,
  `@cert-authority`) and has a `strict/ask/accept-new` policy. courier-ftp follows
  FileZilla: always ask, store plain `host:port` entries inside encrypted vault items
  (hashing adds nothing there), and only *read* OpenSSH files. The parser, hashed-host
  matching, pattern matching and fingerprints are copied from sverb unchanged.

## Technical specification

### Types and APIs

`courier_ftp_core::trust` (shared with `CertTrustStore` from T12):

```rust
/// Id of a stored host key (UUIDv7; equals the vault ItemId once T30 stores it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KnownHostId(pub Uuid);

/// One trusted host key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownHost {
    pub id: KnownHostId,
    /// Host as configured by the user, normalised: ASCII-lowercase, no trailing dot,
    /// IPv6 literal without brackets. Never the resolved IP.
    pub host: String,
    pub port: u16,
    /// Key algorithm name: "ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa", …
    pub key_type: String,
    /// Base64 public key blob (the OpenSSH known_hosts key field).
    pub public_key: String,
    pub added_at: OffsetDateTime,
    /// Free text (e.g. "imported from ~/.ssh/known_hosts"); shown in Settings (T68).
    pub comment: Option<String>,
}

impl KnownHost {
    pub fn fingerprint_sha256(&self) -> String; // "SHA256:…", "?" if the blob doesn't decode
}

/// Where trusted host keys live: memory (vault locked / before T30) or the vault (T30).
#[async_trait]
pub trait HostKeyStore: Send + Sync + fmt::Debug {
    /// Entries for host:port (snapshot, never blocks on I/O; called during the handshake).
    fn lookup(&self, host: &str, port: u16) -> Vec<KnownHost>;
    /// Every entry, sorted by (host, port, key_type) — for Settings (T68).
    fn list(&self) -> Vec<KnownHost>;
    /// Whether `add` persists beyond this process (false → "Always trust" is disabled).
    fn can_persist(&self) -> bool;
    /// Store `entry` and delete `replaces` in one operation (one vault transaction in T30).
    async fn add(&self, entry: KnownHost, replaces: Vec<KnownHostId>) -> Result<(), Error>;
    async fn remove(&self, id: KnownHostId) -> Result<(), Error>;
}

/// In-memory store. `new()` → can_persist = false (vault locked / pre-T30);
/// `persistent_for_tests()` → can_persist = true.
pub struct MemoryHostKeyStore { /* RwLock<Vec<KnownHost>>, can_persist */ }

/// The store the verifier holds; T30 calls `set` after unlock and on lock.
pub struct SwitchableHostKeyStore { /* RwLock<Arc<dyn HostKeyStore>> */ }
impl SwitchableHostKeyStore {
    pub fn new(initial: Arc<dyn HostKeyStore>) -> Self;
    pub fn set(&self, store: Arc<dyn HostKeyStore>);
}
impl HostKeyStore for SwitchableHostKeyStore { /* delegates to the current store */ }

/// Keys accepted with "Trust once" (and every accepted key) for the life of the process,
/// so the extra transfer connections (T41) don't ask again. Never persisted.
#[derive(Debug, Default)]
pub struct SessionTrust { /* Mutex<HashSet<(String host, u16 port, String key_type, String blob)>> */ }
impl SessionTrust {
    pub fn contains(&self, host: &str, port: u16, key_type: &str, blob: &str) -> bool;
    pub fn insert(&self, host: &str, port: u16, key_type: &str, blob: &str);
    pub fn clear(&self);
}

/// Normalise a host for lookups and storage (see `KnownHost::host`).
pub fn normalize_host(host: &str) -> String;
```

`courier_ftp_proto_sftp::known_hosts` (copied from sverb `sverb-core/src/known_hosts`,
without `randomart` and certificate checking):

```rust
pub struct OpenSshEntry { pub host_pattern: String, pub key_type: String, pub public_key: String, pub marker: Marker, pub source: PathBuf, pub line: usize }
pub enum Marker { None, Revoked, CertAuthority }
pub struct ParseWarning { pub line: usize, pub reason: String }
pub fn parse_known_hosts(text: &str, source: &Path) -> (Vec<OpenSshEntry>, Vec<ParseWarning>);
pub fn lookup_key(host: &str, port: u16) -> String;           // "host" (22) or "[host]:port"
pub fn host_field_matches(field: &str, lookup_key: &str) -> bool; // hashed |1|salt|hash or pattern list
pub struct OpenSshMatches { pub matching: Vec<OpenSshEntry>, pub revoked: Vec<OpenSshEntry> } // CA lines dropped
pub fn lookup(entries: &[OpenSshEntry], host: &str, port: u16) -> OpenSshMatches;
pub fn fingerprint_sha256(blob: &[u8]) -> String;  // "SHA256:<base64 no pad>"
pub fn fingerprint_md5(blob: &[u8]) -> String;     // "MD5:aa:bb:…" (16 hex pairs)
pub fn same_key_type(a: &str, b: &str) -> bool;     // ssh-rsa ≡ rsa-sha2-256 ≡ rsa-sha2-512

/// Reads and caches the OpenSSH files (re-read when size or mtime changed).
pub struct OpenSshKnownHosts { /* paths, Mutex<cache> */ }
impl OpenSshKnownHosts {
    pub fn system_default() -> Self;              // paths listed under Data formats
    pub fn with_paths(paths: Vec<PathBuf>) -> Self; // tests
    pub fn disabled() -> Self;                    // sftp.use_openssh_known_hosts = false
    pub fn entries(&self) -> Arc<Vec<OpenSshEntry>>;
}
```

The decision function (pure) and the verifier:

```rust
pub struct DecisionInput<'a> {
    pub key: &'a ServerKey,                 // T20
    pub store: &'a [KnownHost],             // store.lookup(host, port)
    pub session_trusted: bool,              // SessionTrust::contains(…)
    pub openssh: &'a OpenSshMatches,        // lookup(openssh.entries(), host, port)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Accept(AcceptedBy),
    Reject(String),
    AskUnknown { other_known_types: Vec<String> },
    AskChanged { old: Vec<OldKey> },
}
pub enum AcceptedBy { Store, Session, OpenSshFile(PathBuf) }
// OldKey { fingerprint_sha256, source } and OldKeySource { Vault { id: Uuid (= KnownHostId.0),
// added_at }, OpenSshFile { path, line } } are T04's types (courier_ftp_core::events),
// re-exported from `trust`; not redefined here.

pub fn decide(input: &DecisionInput<'_>) -> Decision;

/// T20's HostKeyVerifier over a store, the session trust and the OpenSSH files.
pub struct TrustVerifier { /* Arc<dyn HostKeyStore>, Arc<SessionTrust>, Arc<OpenSshKnownHosts>, InFlight */ }
impl TrustVerifier {
    pub fn new(store: Arc<dyn HostKeyStore>, session: Arc<SessionTrust>, openssh: Arc<OpenSshKnownHosts>) -> Self;
}
impl HostKeyVerifier for TrustVerifier { /* see Behaviour */ }
```

Prompt payload: T04's `PromptKind::TrustHostKey(HostKeyPrompt { host, port, key_type,
bits, fingerprint_sha256, fingerprint_md5, changed: Option<Vec<OldKey>>,
other_known_types, can_save })`, filled from `ServerKey` and the `Decision`
(`can_save = store.can_persist()`). Answer: `PromptResponse::HostKey(TrustAnswer)` with
`TrustAnswer { TrustOnce, AlwaysTrust, Reject }` (T04; `HostKeyAnswer` is its alias).
`SftpBackend::security_info()` (T22) reports the accepted key as T04 `HostKeyInfo`.

### Behaviour

**Decision table** (`decide`), first matching row wins. "Same key" = same key type (per
`same_key_type`) and identical blob. "Same type" = same key type, any blob.

| # | Condition | Decision |
|---|---|---|
| 1 | an OpenSSH `@revoked` entry matching host:port has the presented blob | `Reject("The host key SHA256:… is marked @revoked in <file>")` — no prompt |
| 2 | `store` has the same key | `Accept(Store)` |
| 3 | `session_trusted` | `Accept(Session)` |
| 4 | `store` has entries of the same type with other blobs | `AskChanged { old: those entries }` |
| 5 | OpenSSH plain entry matching host:port has the same key | `Accept(OpenSshFile(path))` |
| 6 | OpenSSH plain entries of the same type with other blobs | `AskChanged { old: those entries }` |
| 7 | otherwise | `AskUnknown { other_known_types: distinct types in store ∪ OpenSSH matches }` |

Consequences, by design: the vault store wins over OpenSSH files (row 4 before row 5);
"Trust once" on a changed key is remembered for the process (row 3 before row 4) so the
extra transfer connections don't warn again; `@cert-authority` lines are ignored (no
certificate host-key algorithms are offered by T20), logged at debug once per file.

**`TrustVerifier::verify(host, port, key, ctx)`:**

1. `h = normalize_host(host)`; collect `store.lookup(h, port)`, `session.contains(…)`,
   `known_hosts::lookup(openssh.entries(), h, port)`; `decide`.
2. `Accept(_)` → `session.insert(…)`; session log `Debug(3)`: `Host key ssh-ed25519
   SHA256:… is trusted (vault|session|~/.ssh/known_hosts)`; return `Accept`.
3. `Reject(reason)` → session log `Error: <reason>`; return `Reject(reason)`.
4. `AskUnknown`/`AskChanged` → **in-flight dedupe**: key `(h, port, fingerprint_sha256)`.
   If another `verify` for the same key is already asking, wait for its result instead
   of prompting (all parallel transfer connections share one prompt). Otherwise send
   `ctx.events.prompt_with_cancel(ctx.session, PromptKind::TrustHostKey(HostKeyPrompt { …, can_save: store.can_persist() }), ctx.cancel)`
   and wait for the answer:
   - `TrustOnce` → `session.insert`; Accept.
   - `AlwaysTrust` with `can_save` → build `KnownHost { id: new UUIDv7, host: h, port,
     key_type, public_key: blob, added_at: now, comment: None }`; `store.add(entry,
     replaces = ids of store entries of the same type for h:port)`; `session.insert`;
     Accept. If `add` fails, still Accept (this connection was approved) and log
     `Error: Could not save the host key: <error>`.
   - `AlwaysTrust` while `can_save` is false (stale UI) → treated as `TrustOnce`.
   - `Reject`, dropped reply sender, or `PromptResponse::Cancel` →
     `Reject("Host key rejected by the user")` (changed key: `"The host key changed and
     was not accepted"`).
   - `ctx.cancel` fired → `Reject("Connection cancelled")`; the asker's waiters are woken
     with "retry" and the next waiter (if its own token is alive) asks again.
   Waiters receive the same outcome as the asker (accept or reject).
5. Session log before the prompt: unknown → `Status: The server's host key is unknown.
   Fingerprint: SHA256:…`; changed → `Error: WARNING: the host key of <host>:<port> has
   changed!`.

**`known_key_types(host, port)`**: distinct key types from the store and OpenSSH matching
entries, store first, in entry order. T20 moves them to the front of the host-key
algorithm list, so a server with several host keys presents the one already trusted.

**OpenSSH files** (`OpenSshKnownHosts`): read-only; `entries()` stats every path, re-reads
a file only when size or mtime changed; a missing or unreadable file contributes nothing
(debug log, no error). Files larger than 4 MiB or with more than 100 000 lines are
skipped with one `Status` warning per process. Parse warnings (malformed lines, unknown
markers, bad base64, type/blob mismatch) are logged at `debug` with file and line number
only. courier-ftp never opens these files for writing.

**Management API** (used by T68): `list()`, `remove(id)`; "forget host" = `remove` for
each id in `lookup(host, port)`. `SessionTrust::clear()` is called when the user
removes a key in Settings so the removal takes effect immediately.

**Store switching** (T30): the binary starts with
`SwitchableHostKeyStore::new(Arc::new(MemoryHostKeyStore::new()))` (can_persist =
false); T30 calls `set(vault_store)` after unlock and `set(memory)` on lock. Answers
already given stay in `SessionTrust`.

### Data formats and configuration

Setting (registered in T05's `sftp` section, shown in T68 under Connection → SFTP):

| Key | Type | Default | Meaning |
|---|---|---|---|
| `sftp.use_openssh_known_hosts` | bool | `true` | Also trust keys found in the OpenSSH known_hosts files below (read-only) |

OpenSSH files read (in this order):

| OS | Paths |
|---|---|
| Linux, macOS, BSD | `~/.ssh/known_hosts`, `~/.ssh/known_hosts2`, `/etc/ssh/ssh_known_hosts`, `/etc/ssh/ssh_known_hosts2` |
| Windows | `%USERPROFILE%\.ssh\known_hosts`, `%USERPROFILE%\.ssh\known_hosts2`, `%PROGRAMDATA%\ssh\ssh_known_hosts` |

known_hosts line format (sshd(8)): `[@revoked|@cert-authority] patterns key-type base64 [comment]`;
patterns: comma list with `*`, `?`, `!negation`, `[host]:port`; hashed `|1|base64(salt20)|base64(HMAC-SHA1(salt, lookup_key))`.

Vault item (`known-host` kind, T81; written by T30's store) — field names and types:

| Field | Type | Example |
|---|---|---|
| `host` | text | `web01.example.com` |
| `port` | u16 | `22` |
| `key_type` | text | `ssh-ed25519` |
| `public_key` | text (base64 blob) | `AAAAC3NzaC1lZDI1NTE5AAAAI…` |
| `added_at` | RFC 3339 timestamp | `2026-10-09T12:00:00Z` |
| `comment` | text, optional | — |

Fingerprints: SHA-256 = `SHA256:` + base64 (no padding) of SHA-256(blob) (`ssh-keygen -l`);
MD5 = `MD5:` + 16 lowercase hex pairs joined by `:` (`ssh-keygen -l -E md5`).

### Errors

| Situation | `courier_ftp_core::Error` | User sees |
|---|---|---|
| Revoked key | `HostKey(reason)` | "The host key SHA256:… is marked @revoked in /etc/ssh/ssh_known_hosts" |
| User rejected unknown key | `HostKey("Host key rejected by the user")` | same, in the log and the connect error dialog |
| User rejected changed key | `HostKey("The host key changed and was not accepted")` | same |
| Cancelled while asking | `Cancelled` (T20 maps the cancelled connect) | "Connection cancelled" |
| `store.add` failed | none (connection proceeds) | `Error: Could not save the host key: …` log line |
| `remove` failed (T68) | `Vault(..)` from T30 | error dialog in Settings |

T20 turns `HostKeyVerdict::Reject(reason)` into `Error::HostKey(reason)`; it is not
transient, so `SessionHandle` (T03) does not reconnect.

### Security and logging

- TOFU is the residual risk (T91 threat model): the first connection to a host cannot be
  verified; the prompt says so.
- A changed key never connects silently: the only ways forward are an explicit
  per-process "Trust once" or replacing the stored key, both behind T69's typed-hostname
  confirmation.
- The store holds only public data, but host names are sensitive metadata: they live
  only inside encrypted `known-host` items (T30) or in memory; nothing is written to
  disk outside the vault, OpenSSH files are never written.
- Hashed OpenSSH entries are compared with a constant-time HMAC compare (sverb
  `hashed::matches`).
- Logging: `tracing` at info logs only `SessionId` and the decision kind (`accept`,
  `ask_unknown`, `ask_changed`, `reject`); host, port and fingerprints at `debug`. The
  session log (user-facing, T55) shows host and fingerprints.
- Parser input (OpenSSH files) is untrusted: size and line caps above; fuzz target
  `known_hosts_parse` (T91 §7) with a proptest twin.

## Implementation steps

1. `courier_ftp_core::trust`: `KnownHostId`, `KnownHost`, `HostKeyStore`,
   `MemoryHostKeyStore`, `SwitchableHostKeyStore`, `SessionTrust`, `normalize_host` + tests.
2. Read `sftp.use_openssh_known_hosts` (registered by T05) when building `OpenSshKnownHosts`.
3. `known_hosts` module: copy sverb `parse`, `hashed`, `lookup`, `fingerprint`
   (+ MD5), `same_key_type`; port sverb's parser/lookup tests; proptest twin + fuzz target.
4. `OpenSshKnownHosts` loader with mtime cache, size/line caps and OS paths.
5. `decide` + the table test.
6. `TrustVerifier` (prompt, answers, in-flight dedupe, store add/replace, logging) with
   scripted-prompt tests.
7. Loopback tests with T20's in-process server (unknown → always → silent; changed;
   multiple key types; concurrent connections).
8. e2e tests (unknown prompt, changed key after host-key regeneration).

## Acceptance criteria

- [ ] AC1 `decide` returns the documented decision for every row of the decision table and for the precedence cases (store vs OpenSSH conflict, session trust vs changed store entry, revoked vs stored).
- [ ] AC2 Unknown key: exactly one `TrustHostKey` prompt; `AlwaysTrust` with a persistent store adds one entry (replacing nothing); a second connection with a new `SessionTrust` connects without a prompt.
- [ ] AC3 `TrustOnce`: no store write; further connections in the same process (same `SessionTrust`) don't prompt; with a fresh `SessionTrust` the prompt appears again.
- [ ] AC4 Changed key: the prompt carries `changed = Some(old)` with the old SHA-256 fingerprints and their source; `Reject` fails the connect with `Error::HostKey`; `AlwaysTrust` replaces the old same-type entry (store contains only the new key afterwards).
- [ ] AC5 OpenSSH files: plain, hashed (`|1|…`), `[host]:2222`, wildcard and `!negated` patterns match exactly as `ssh-keygen -F` would (fixture file); comments, blank and malformed lines are skipped with warnings.
- [ ] AC6 A key listed `@revoked` is rejected with no prompt, even when the store trusts it.
- [ ] AC7 `can_save` is false with `MemoryHostKeyStore::new()`; an `AlwaysTrust` answer then writes nothing and behaves like `TrustOnce`.
- [ ] AC8 Four concurrent connects to the same unknown key produce exactly one prompt and all four succeed after `TrustOnce` (all four fail after `Reject`).
- [ ] AC9 With an ECDSA key stored, a server holding ed25519 and ECDSA host keys presents ECDSA and connects without a prompt.
- [ ] AC10 OpenSSH files are never modified (test asserts unchanged content and mtime after accept/reject flows); with `sftp.use_openssh_known_hosts = false` they are not read.
- [ ] AC11 MD5 and SHA-256 fingerprints of the fixture keys equal the `ssh-keygen -l` / `-E md5` output recorded in the fixtures.
- [ ] AC12 `list`/`remove` work on the memory store; removing a key clears `SessionTrust` so the next connect prompts again.
- [ ] AC13 The known_hosts parser never panics on arbitrary input (proptest, 10 000 cases; body shared with the `known_hosts_parse` fuzz target) and skips files > 4 MiB.
- [ ] AC14 e2e: first connect to the `password` profile prompts; after `sverb-regen-hostkeys`-style regeneration (T76 fixture) the next connect shows the changed-key prompt and is rejected when answered `Reject`.
- [ ] AC15 T00 gates (`fmt`, `clippy -D warnings`, `docs`, tests) pass for both crates.

## Tests

### Unit tests
- `trust::tests::normalize_host_lowercases_strips_dot_and_brackets`.
- `trust::tests::memory_store_add_replaces_and_lists_sorted` — AC12.
- `trust::tests::switchable_store_delegates_after_set`.
- `trust::tests::session_trust_insert_contains_clear` — AC3/AC12.
- `known_hosts::tests::lookup_key_port_22_and_bracketed` (sverb t01) — AC5.
- `known_hosts::tests::hashed_entry_matches` (sverb t02) — AC5.
- `known_hosts::tests::pattern_globbing_and_negation` (sverb t03) — AC5.
- `known_hosts::tests::parser_fixture_and_edge_cases` (sverb t09 + `parser_edge_cases`) — AC5.
- `known_hosts::tests::rsa_signature_names_share_the_key_type`.
- `known_hosts::tests::fingerprints_match_ssh_keygen` — AC11.
- `verify::tests::decide_table` — one case per row + precedence cases — AC1, AC6.
- `verify::tests::always_trust_adds_and_replaces_same_type` — AC2, AC4.
- `verify::tests::trust_once_only_session` — AC3.
- `verify::tests::always_trust_without_persist_is_trust_once` — AC7.
- `verify::tests::dropped_reply_rejects`.
- `verify::tests::concurrent_verifications_share_one_prompt` (paused time, 4 tasks) — AC8.
- `verify::tests::cancelled_asker_hands_prompt_to_next_waiter`.
- `verify::tests::store_add_failure_still_accepts_and_logs`.
- `openssh::tests::reload_on_mtime_change_and_skip_large_file` — AC13.
- `openssh::tests::disabled_reads_nothing` — AC10.

### Property / fuzz tests
- `known_hosts::props::parse_never_panics` (proptest, 10 000 cases; body shared with `fuzz/fuzz_targets/known_hosts_parse.rs`, T91) — AC13.
- `known_hosts::props::hash_with_salt_round_trips` (random host names match their own hash, not others).

### Snapshot tests
Not applicable (prompt rendering is T69).

### Integration tests
`crates/courier-ftp-proto-sftp/tests/host_keys.rs`, with T20's `ssh::testing::TestServer`
and a scripted prompt responder on the `EventReceiver`:
- `loopback_unknown_always_then_silent` — AC2.
- `loopback_trust_once_same_process_silent` — AC3.
- `loopback_changed_key_prompt_reject_and_replace` — AC4.
- `loopback_revoked_never_prompts` (OpenSSH fixture file with `@revoked`) — AC6.
- `loopback_known_type_preferred` (server with two host keys) — AC9.
- `loopback_openssh_file_untouched` — AC10.
- `loopback_four_parallel_connects_one_prompt` — AC8.

### End-to-end tests
`crates/courier-ftp-e2e/tests/ssh_host_keys.rs`, `#[ignore]`, `require_docker!` (T76):
- `e2e_unknown_host_key_prompt_then_trusted` — AC2 against OpenSSH.
- `e2e_changed_host_key_blocked` — AC14.

## Out of scope

- Writing to OpenSSH known_hosts files; importing them into the vault (could be a later
  Settings action).
- OpenSSH host certificates / `@cert-authority` trust, `CheckHostIP`, DNS SSHFP records.
- Randomart pictures in the prompt.
- The prompt UI (T69), the Settings list UI (T68), the vault-backed store (T30).

## Open questions

1. Should keys found in `~/.ssh/known_hosts` be offered for one-click import into the
   vault (so they sync to devices without OpenSSH)? Not done in v1.
2. Should "Always trust" be pre-checked in the prompt (T69 currently pre-checks it when
   the vault is unlocked, as in FileZilla's dialog sketch in the original task)?
