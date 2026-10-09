# T12 — FTPS (TLS)

**Phase:** B FTP · **Milestone:** M3 · **Depends on:** T04, T10, T11 · **Crate(s):** `courier-ftp-proto-ftp` (`tls` module), `courier-ftp-core` (`trust` module: `CertTrustStore`, certificate types) · **Decisions:** D1, D4, D9 (rustls) · **FEATURES.md:** §1 (FTPS explicit/implicit, encryption modes, certificate check dialog, "trust this certificate" store)
**Related (integrates with, not blocking):** T30, T57, T69, T76, T81
**Reference:** sverb `crates/sverb-conn/src/ssh/verify.rs` (trust decision table, store trait with in-memory implementation, "replace previous entries on accept"), `crates/sverb-core/src/known_hosts/check.rs` (pure decision function), `docs/threat-model.md` (TOFU residual risk).

## Goal

Explicit (`AUTH TLS`, RFC 4217) and implicit (port 990) FTPS on rustls with real
certificate verification against the OS trust store, a FileZilla-style "trust this
certificate" flow backed by a `CertTrustStore` (in memory while the vault is locked,
vault-backed and synced once unlocked — implemented here on T30's API), TLS on every data connection with mandatory session resumption (vsftpd
`require_ssl_reuse`, ProFTPD and FileZilla Server require it), and the negotiated
protocol/cipher/certificate exposed for the status bar and server-info dialog.

## Context

**Exists before this task:** T10 `ControlConnection` (`StreamUpgrade` hook for implicit
TLS, `upgrade_stream` for explicit TLS, login and negotiate phases, `FakeServer`); T11
`DataTlsHook`, data-connection ordering (TLS handshake after the 1xx reply), abort/resync;
T04 `PromptKind::TrustCertificate(Box<CertPromptDetails>)`, the certificate/TLS types
(`CertificateDetails`, `CertProblem`, `TlsSessionInfo`, `PreviousCert`, `TrustSource`,
`DataProtection`) and `PromptResponse::Certificate(TrustAnswer)`, prompt cancellation via
`CancellationToken`; T02 `Protocol::Ftp` + `FtpEncryption { PlainOnly, ExplicitIfAvailable,
RequireExplicit, RequireImplicit }`, `Error::Tls`; T03 `SessionSecurityInfo`; T30
`VaultEngine` (`list`/`put`/`delete`, `subscribe`) and T81 `TrustedCertItem`.

**Later tasks need from this one:**
- T14: `TlsSession` (control upgrade + data hook), the `TlsReuseRequired` signal (reconnect
  with TLS 1.2), `TlsSessionInfo` for `Backend::security_info()` (`SessionSecurityInfo.tls`).
- T15: TLS through an FTP proxy (TLS peer = proxy host).
- The binary: creates the `SwitchableCertTrustStore` (in-memory initially) and calls
  `spawn_cert_store_switch` with the `VaultEngine` (T30 provides only the item view and API).
- T57/T69: `CertPromptDetails`, `TlsSessionInfo`, `CertificateDetails` rendering data.
- T68: `CertTrustStore::list`/`remove` for the TLS settings section.
- T41b: TLS session reuse so segment connections skip full handshakes.

## Technical specification

### Types and APIs

```rust
// courier_ftp_core::trust ---------------------------------------------------------------
/// Re-exported from T04 `events` (defined there, not here): `CertificateDetails`,
/// `CertProblem`, `TlsSessionInfo`, `TrustSource { Platform, Stored, Once }`,
/// `DataProtection { Private, Clear }`, `CertPromptDetails { host, port, session, problems,
/// hostname_matches, previous: Option<PreviousCert>, can_save }`, `PreviousCert`,
/// `TrustAnswer { TrustOnce, AlwaysTrust, Reject }`.
pub use crate::events::{CertificateDetails, CertProblem, CertPromptDetails, DataProtection,
                        PreviousCert, TlsSessionInfo, TrustAnswer, TrustSource};

/// A certificate the user chose to "always trust" for host:port.
/// Persisted by `VaultCertTrustStore` (below) as one `trusted-cert` item per host:port
/// (T81 `TrustedCertItem`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedCert {
    pub host: String,              // lower-case DNS name or IP literal without brackets
    pub port: u16,
    pub sha256: [u8; 32],          // SHA-256 of the end-entity certificate DER
    pub der: Vec<u8>,              // end-entity DER, ≤ 16 KiB (details view, T68)
    pub subject: String,
    pub issuer: String,
    pub not_after: OffsetDateTime,
    pub added_at: OffsetDateTime,
}
impl TrustedCert { pub fn to_previous(&self) -> PreviousCert; }

/// Trusted-certificate storage. In-memory until the vault is unlocked, then vault-backed
/// (synced, D4).
#[async_trait]   // same async-trait choice as T03's `Backend`
pub trait CertTrustStore: Send + Sync + std::fmt::Debug {
    async fn lookup(&self, host: &str, port: u16) -> Result<Vec<TrustedCert>>;
    /// Adds `cert` and removes every other entry for the same host:port
    /// ("always trust" replaces the previous certificate).
    async fn add(&self, cert: TrustedCert) -> Result<()>;
    async fn list(&self) -> Result<Vec<TrustedCert>>;
    async fn remove(&self, host: &str, port: u16, sha256: &[u8; 32]) -> Result<()>;
    /// false for the in-memory store (vault locked / not created): prompts then carry
    /// `can_save = false` and "Always trust" is disabled.
    fn is_persistent(&self) -> bool;
}
#[derive(Debug, Default)]
pub struct MemoryCertTrustStore { /* RwLock<Vec<TrustedCert>> */ }
/// Delegates to the current store; swapped on vault unlock/lock (same pattern as T21's
/// `SwitchableHostKeyStore`).
#[derive(Debug)]
pub struct SwitchableCertTrustStore { /* RwLock<Arc<dyn CertTrustStore>> */ }
impl SwitchableCertTrustStore {
    pub fn new(initial: Arc<dyn CertTrustStore>) -> Self;
    pub fn set(&self, store: Arc<dyn CertTrustStore>);
}
impl CertTrustStore for SwitchableCertTrustStore { /* delegates */ }

// courier_ftp_core::vault::cert_trust (this task; uses T30's VaultEngine API) -----------
/// `CertTrustStore` on `trusted-cert` items (T81 `TrustedCertItem`), implemented here
/// because T30 (M2) precedes this task; T30 provides the item view and `VaultEngine`.
#[derive(Debug, Clone)]
pub struct VaultCertTrustStore { engine: VaultEngine }
impl VaultCertTrustStore { pub fn new(engine: VaultEngine) -> Self; }
impl CertTrustStore for VaultCertTrustStore { /* list/put/delete, see Behaviour §7 */ }
/// Keeps `switch` pointing at the vault store while unlocked: listens to
/// `VaultEngine::subscribe()`; `Unlocked(_)` → `VaultCertTrustStore`, `Locked(_)` → a fresh
/// `MemoryCertTrustStore`. Spawned by the binary next to T30's host-key swap.
pub fn spawn_cert_store_switch(engine: VaultEngine, switch: Arc<SwitchableCertTrustStore>)
    -> tokio::task::JoinHandle<()>;

// courier_ftp_proto_ftp::tls ------------------------------------------------------------
/// Process-wide trust state shared by all FTP backend instances (created by the
/// `BackendFactory`, T14): "trust once" set, prompt de-duplication, TLS 1.2 hints.
pub struct TlsTrustGate {
    store: Arc<dyn CertTrustStore>,                    // a SwitchableCertTrustStore
    once: Mutex<HashSet<(String, u16, [u8; 32])>>,     // lives until the process exits
    pending: Mutex<HashMap<(String, u16, [u8; 32]), Shared<BoxFuture<'static, TrustAnswer>>>>,
    tls12_only_hosts: Mutex<HashSet<(String, u16)>>,   // learned "reuse needs TLS 1.2"
}
impl TlsTrustGate {
    pub fn new(store: Arc<dyn CertTrustStore>) -> Arc<Self>;
    pub fn set_store(&self, store: Arc<dyn CertTrustStore>);
}

/// Base chain verifier: the OS store in production, a fixed root set in tests.
pub enum RootSource { Platform, Custom(rustls::RootCertStore) }

/// One FTPS session: the `rustls::ClientConfig` (with its resumption cache) shared by the
/// control connection and all of its data connections.
pub struct TlsSession { /* config: Arc<ClientConfig>, verifier: Arc<FtpCertVerifier>,
                           server_name: ServerName<'static>, info: Option<TlsSessionInfo> */ }
impl TlsSession {
    pub fn new(server_name: &str, port: u16, roots: RootSource, max_tls12: bool,
               gate: Arc<TlsTrustGate>) -> Result<Self>;
    /// Handshake on the control stream, then the trust decision (may prompt).
    pub async fn secure_control(&mut self, io: BoxedIo, log: &SessionLog,
                                cancel: &CancellationToken) -> Result<BoxedIo>;
    /// `DataTlsHook` for T11 (same config → session resumption, leaf pinned to control).
    pub fn data_hook(&self) -> impl DataTlsHook;
    pub fn info(&self) -> Option<&TlsSessionInfo>;
}

/// rustls verifier with a deferred verdict for the control handshake and a pinned
/// leaf for data handshakes.
struct FtpCertVerifier { inner: Arc<dyn ServerCertVerifier>, state: Mutex<VerifierState> }
enum VerifierState { Control { record: Option<VerifyRecord> }, Data { leaf_sha256: [u8; 32] } }
struct VerifyRecord { chain_der: Vec<CertificateDer<'static>>, platform: Result<(), rustls::Error> }

/// Marker inside `Error::Tls` text is not enough for control flow, so T11/T12 return this
/// crate-internal error to T14, which reconnects with TLS 1.2 (§5).
pub(crate) struct TlsReuseRequired;
```

### Behaviour

**1. Encryption modes** (`FtpEncryption`, T02; FileZilla's four modes).

| Mode | Sequence | On failure |
|---|---|---|
| `PlainOnly` | never sends `AUTH` | – (status bar shows plain, T57) |
| `ExplicitIfAvailable` | after `220`: `AUTH TLS` → `234` → handshake. Reply 500/502/504/431/534 → `AUTH SSL` → `234`/`334` → handshake | both refused → continue **plain**, Status `Warning: Server does not support FTP over TLS. The connection, including your password, is not encrypted.` + `Debug(1)`; T57 shows the open lock |
| `RequireExplicit` | same as above | both refused → `Error::Tls("server does not support FTP over TLS")` before any credential is sent |
| `RequireImplicit` | TLS handshake immediately after TCP connect (T10 `StreamUpgrade`), default port 990; then the `220` greeting arrives inside TLS; `AUTH` never sent | handshake failure → `Error::Tls` |

- A failed **handshake** after `234` is never downgraded to plain text, in any mode
  (`Error::Tls`, connection closed) — prevents a man-in-the-middle forcing plain FTP.
- `AUTH TLS` is sent before `USER` (RFC 4217 §4) and before `FEAT` (T10 negotiates after login).
- `421` to `AUTH` → `Error::Connection`.

**2. Data channel protection (RFC 4217 §8–9, RFC 2228).** After login, when the control
connection is TLS:
- `PBSZ 0` → `200` (reply may contain `PBSZ=0`). Failure is logged and ignored (some
  servers reject PBSZ but accept PROT).
- `PROT P` → `200` → all data connections use TLS (`DataProtection::Private`).
- `PROT P` refused (`536`, `504`, other 5xx): `ExplicitIfAvailable` → `PROT C`, Status
  warning "Data connections will not be encrypted", `DataProtection::Clear`;
  `RequireExplicit`/`RequireImplicit` → `Error::Tls("server refused to encrypt data
  connections (PROT P)")`.
- Re-done after every reconnect. `CCC` (clear command channel) is **never sent** and is
  refused by `raw_command` (T10); documented as unsupported.

**3. rustls configuration (one `ClientConfig` per FTPS session).**
- Crypto provider: `rustls::crypto::ring` (no CMake/NASM build dependency on Windows),
  installed process-wide by the binary; protocol versions TLS 1.3 and 1.2 (TLS 1.2 only
  when the host is in `tls12_only_hosts`). No TLS 1.0/1.1, no SSLv3.
- `resumption = Resumption::in_memory_sessions(64).tls12_resumption(Tls12Resumption::SessionIdOrTickets)`.
- `enable_sni = true` for DNS names (rustls omits SNI for IP literals).
- `ServerName`: the TLS peer host — the site host, or the FTP proxy host when an FTP proxy
  is used (T15; TLS terminates at the proxy). The **same** `ServerName` value is used for
  every data connection, because rustls keys its resumption cache by server name; using
  the PASV IP would break resumption.
- No client certificates, no ALPN, early data disabled.

**4. Certificate verification and trust decision.**

rustls verifiers are synchronous, so the control handshake uses a **deferred verdict**:
`FtpCertVerifier::verify_server_cert` runs the base verifier (`rustls-platform-verifier`,
or a `WebPkiServerVerifier` over `RootSource::Custom` in tests), records the chain and the
result in `VerifyRecord`, and returns `Ok` so the handshake can finish. `verify_tls12_signature`
and `verify_tls13_signature` **always** delegate to the base verifier (proof of key possession
is never deferred). After the handshake and **before writing any byte** on the TLS stream,
`secure_control` evaluates the record:

| Platform result | Stored entries for host:port | Leaf SHA-256 in "once" set | Decision |
|---|---|---|---|
| Ok | any | – | accept, `TrustSource::Platform`; nothing stored |
| Err | contains the leaf SHA-256 | – | accept, `TrustSource::Stored` (even if now expired: the user pinned this exact certificate) |
| Err | none | yes | accept, `TrustSource::Once` |
| Err | none | no | prompt (new certificate) |
| Err | other certificate(s) | no | prompt with `previous = Some(latest by added_at .to_previous())` (changed certificate warning) |

Prompt flow:
- `PromptKind::TrustCertificate(Box<CertPromptDetails>)` via T04 `prompt_with_cancel`,
  awaited with the session `CancellationToken`, `can_save = store.is_persistent()`; the T10
  inactivity timer is paused while waiting. The answer is `PromptResponse::Certificate(TrustAnswer)`.
- **De-duplication:** concurrent connections (browsing session + up to 16 transfer
  sessions, T41b) that hit the same `(host, port, sha256)` share one pending prompt
  (`TlsTrustGate.pending`), so the user is asked once.
- `TrustAnswer::TrustOnce` → add to `once` (process lifetime, never persisted) → accept.
- `TrustAnswer::AlwaysTrust` → `store.add(TrustedCert { .. })` (replaces older entries for
  host:port) → accept. Offered only when `can_save`; with `can_save = false` T04 treats it
  as `TrustOnce`.
- `TrustAnswer::Reject`, dropped sender, or cancellation → close without `close_notify`,
  `Error::Tls("certificate rejected")` / `Error::Cancelled`. The rejected session's
  resumption cache is dropped with its `ClientConfig`.
- If the server closed the connection while the prompt was open (its login timeout), the
  backend (T14) reconnects once; the decision is now in the store or the "once" set, so the
  second attempt does not prompt.
- After acceptance the verifier switches to `VerifierState::Data { leaf_sha256 }`: a data
  connection doing a **full** handshake must present the same leaf certificate
  (`Error::Tls("data connection certificate differs from control connection")` otherwise).
  Resumed handshakes present no certificate and are accepted by rustls itself.

Certificate details (via `x509-parser`, for every chain certificate): subject, CN, issuer,
serial, validity, SHA-256 + SHA-1 fingerprints of the DER, SANs, public key algorithm and
size, signature algorithm, CA flag, self-signed flag. Plus `TlsSessionInfo` (version,
cipher suite) and `hostname_matches` (false when the platform error is `NotValidForName`).
Parsing failures keep the fingerprints and set `parse_error`; they never fail the connection
on their own. `rustls::CertificateError` mapping → `CertProblem`: `UnknownIssuer` (or
`SelfSigned` when subject == issuer), `Expired`/`ExpiredContext` → `Expired`, `NotValidYet`,
`NotValidForName`/`NotValidForNameContext`, `Revoked`, `InvalidPurpose`, `BadSignature`,
everything else → `Other(text)`.

**5. Data-connection TLS and session resumption.**
- Every data connection (passive and active — in active mode we still are the TLS client,
  RFC 4217 §10) is wrapped by `TlsSession::data_hook()` after the `1xx` reply (T11 order),
  with the session's `ClientConfig`, so it resumes the control connection's session.
- TLS 1.3: tickets arrive after the control handshake; T10 always reads at least one reply
  (login) before the first data connection, so the tickets are in the cache. rustls uses
  each TLS 1.3 ticket once; servers send new tickets on every resumed connection.
- Handshake timeout: `connection.timeout_secs`.
- **Reuse-required failure:** if a data handshake fails or the server closes the data
  connection right after it, and the control reply is 4xx/5xx with text matching
  `/reuse|resum/i` (vsftpd: `522 SSL connection failed: session reuse required`), then:
  - control session negotiated TLS 1.3 and host not yet in `tls12_only_hosts` → add it,
    return `TlsReuseRequired`; T14 reconnects with a TLS 1.2-only config and retries the
    operation once (Status "Server requires TLS session resumption; reconnecting with TLS 1.2");
  - otherwise → `Error::Tls("server requires TLS session resumption, which failed")`.
- **Shutdown:** uploads end with TLS `close_notify` then TCP shutdown (T11 `finish`); after a
  download we also send `close_notify` before closing (vsftpd `strict_ssl_read_eof` and
  others report `426` otherwise). A download whose TCP stream ends **without** the server's
  `close_notify` (rustls `UnexpectedEof`) is accepted only if the control reply is
  `226`/`250` (the integrity-protected control channel confirms completion); it is logged at
  `Debug(3)`. On abort (T11 §8) no `close_notify` is sent.

**6. Session info.** `TlsSession::info()` is filled after the control handshake and
exposed by `FtpBackend::security_info()` (T03 `SessionSecurityInfo { encrypted: true,
summary: "TLS 1.3", tls: Some(info), .. }`, T14) for the status-bar lock and the
server-info dialog (T57) and the certificate details view (T69).

**7. Vault-backed store** (`VaultCertTrustStore`, on T30's API):
- `lookup(host, port)` / `list()`: `engine.list::<TrustedCertItem>()` (cache, no
  decryption of secrets needed), filter by lower-cased host and port, convert fields
  (`cert_der` ↔ `der`, UnixMillis ↔ `OffsetDateTime`).
- `add(cert)`: T81 keeps **one item per (host, port)**: if an item exists, `put` the same
  `ItemId` with the new fingerprint/DER/subject/issuer/not_after/added_at (replace);
  otherwise `put` a new item into `engine.personal_vault()`. `is_persistent() = true`.
- `remove(host, port, sha256)`: `delete(id)` of the matching item (no-op if the
  fingerprint differs).
- `VaultError::Locked` (vault locked between swap and call) → `Error::VaultLocked`; the
  connection is then accepted as `Once` (see Errors). Status lines: `Initializing TLS...`,
`TLS connection established.` (FileZilla wording), and at `Debug(3)` the version, cipher
suite, resumed/full handshake per data connection.

### Data formats and configuration

Commands: `AUTH TLS` / `AUTH SSL` → `234` (or `334` for SSL on old servers); `PBSZ 0` →
`200`; `PROT P` / `PROT C` → `200`; `536 Requested PROT level not supported`.

`trusted-cert` item fields (T81 `TrustedCertItem`, written by `VaultCertTrustStore`):
`host` text (lower-case), `port` uint, `sha256` bytes(32), `cert_der` bytes (≤ 16 KiB),
`subject` text, `issuer` text, `not_after` UnixMillis, `added_at` UnixMillis; one item per
(host, port).

Fingerprint display: `SHA256` upper-case hex with `:` separators (`AB:CD:…`), same for SHA-1.

Settings: none added. Read: `connection.timeout_secs` (handshake timeout). The encryption
mode comes from `ConnectInfo` (site `encryption`, T31; quickconnect default
`ExplicitIfAvailable`, T58).

### Errors

| Situation | Error | User sees |
|---|---|---|
| `RequireExplicit` and AUTH refused | `Tls` | "Server does not support FTP over TLS" |
| Handshake failure (any mode) | `Tls` | rustls error text ("peer is incompatible: …") |
| Certificate rejected | `Tls` | "Certificate rejected" |
| Prompt cancelled | `Cancelled` | – |
| PROT P refused (Require*) | `Tls` | "Server refused to encrypt data connections" |
| Data cert differs | `Tls` | "Data connection certificate differs from control connection" |
| Reuse required, already TLS 1.2 | `Tls` | "Server requires TLS session resumption, which failed" |
| Trust store failure (vault) | `VaultLocked` / `Vault(..)` (T30 `From<VaultError>`) | "Could not save trusted certificate"; connection still accepted for this session (`Once`) |

### Security and logging

- No credential is sent before the certificate decision and before the TLS handshake in
  `RequireExplicit`/`RequireImplicit`. A handshake failure is never downgraded.
- Plain-text fallback (`ExplicitIfAvailable`) and `PROT C` produce visible warnings; T57
  shows the open lock; threat model row "plain FTP warnings" (T91).
- Signature verification is never deferred; only chain trust is, and nothing is written on
  the stream until it is resolved.
- "Trust once" lives only in process memory. "Always trust" goes through the vault (T30),
  synced (D4); see Open questions about team vaults.
- Certificate DER and fields from the server are untrusted input: `x509-parser` runs on
  bounded DER (rustls already limits message sizes); display strings have control
  characters replaced before reaching the prompt.
- `tracing` `info`: session id + "tls established"/"certificate rejected", no host names or
  fingerprints; `debug` may include them (T91 §4). The message log shows Status lines only.

## Implementation steps

1. `courier_ftp_core::trust`: `TrustedCert`, `CertTrustStore`, `MemoryCertTrustStore`,
   `SwitchableCertTrustStore`, re-exports of the T04 certificate types and `TrustAnswer`.
2. Certificate details extraction (`x509-parser`) + fingerprints, with `rcgen` test certs.
3. `FtpCertVerifier` (deferred control verdict, data pinning, signature delegation) +
   pure decision function `decide_trust(record, stored, once) -> TrustOutcome` with table tests.
4. `TlsSession` + `ClientConfig` builder (versions, resumption, SNI, `RootSource`).
5. `TlsTrustGate` (once set, prompt de-duplication, store swap, TLS 1.2 hints).
6. Explicit/implicit control upgrade in the T10 sequence, `PBSZ`/`PROT`, mode table.
7. Data hook for T11 with close_notify handling and the reuse-required detection.
8. `FakeServer` TLS steps (`StartTls`, `ImplicitTls`, `RequireResumedDataTls`) with
   `tokio-rustls` acceptors (TLS 1.2-only and TLS 1.3 configs).
9. `VaultCertTrustStore` + `spawn_cert_store_switch` (T30 API, T81 `TrustedCertItem`).
10. Docker e2e against vsftpd TLS profiles, pure-ftpd and proftpd mod_tls.

## Acceptance criteria

- [ ] AC1 All four encryption modes follow the mode table, including `AUTH SSL` fallback
  and the plain-text warning for `ExplicitIfAvailable` (fake server, one test per row).
- [ ] AC2 A handshake failure after `234` never continues in plain text (all modes).
- [ ] AC3 `PROT P` refusal falls back to `PROT C` only in `ExplicitIfAvailable`; the others
  fail with `Error::Tls`.
- [ ] AC4 Data connections resume the control session: against a fake server that rejects
  non-resumed data handshakes, transfers succeed with TLS 1.2-only and TLS 1.3 server
  configs; vsftpd `tls-reuse-required` passes in Docker.
- [ ] AC5 Reuse-required failure with TLS 1.3 triggers one reconnect with TLS 1.2 and the
  transfer succeeds; the hint is remembered for later connections to that host:port.
- [ ] AC6 Self-signed certificate → exactly one prompt even with 4 concurrent connections;
  "Always trust" stores it; the next connection is silent.
- [ ] AC7 A different certificate after "always trust" → prompt with `previous` set (old and
  new fingerprints); "Always" replaces the stored entry.
- [ ] AC8 "Trust once" is not persisted (store unchanged) but suppresses prompts for the
  rest of the process; with the in-memory store the prompt has `can_save == false` and an
  `AlwaysTrust` answer stores nothing.
- [ ] AC9 No byte is written on the TLS control stream before the trust decision (fake
  server asserts it receives nothing until the prompt is answered) and a rejected
  certificate sends no credentials.
- [ ] AC10 A data connection presenting a different leaf certificate in a full handshake
  is refused.
- [ ] AC11 Uploads send `close_notify`; a download without server `close_notify` but with
  `226` succeeds; without `226` it fails.
- [ ] AC12 `TlsSessionInfo` reports version, cipher and chain for explicit and implicit
  FTPS (used by T57's server-info dialog).
- [ ] AC13 Docker e2e: vsftpd `explicit-tls`, `implicit-tls`, `tls-reuse-required`,
  pure-ftpd TLS and proftpd mod_tls each list and transfer a file (SHA-256 verified).
- [ ] AC14 CI gates (T00) pass; `cargo deny` accepts the new TLS crates; no OpenSSL in
  `cargo tree` (D9).
- [ ] AC15 `VaultCertTrustStore` round-trips a `TrustedCert` through a `trusted-cert`
  item, keeps one item per host:port on `add` of a changed certificate, and the switch
  task points the gate at the vault store after `Unlocked` and back to memory after `Locked`.

## Tests

### Unit tests
- `decide_trust_table` — every row of the decision table (platform ok/err × stored
  none/same/other × once yes/no). AC6–AC8.
- `cert_details_from_rcgen_self_signed`, `cert_details_lists_sans_and_key_size`,
  `cert_details_parse_failure_keeps_fingerprints`. AC12.
- `cert_problem_mapping_from_rustls_errors`.
- `verifier_delegates_signature_checks` — a forged CertificateVerify fails even though the
  chain verdict is deferred. AC9.
- `memory_store_add_replaces_same_host_port`, `memory_store_is_not_persistent`. AC7, AC8.
- `switchable_store_delegates_to_current`. AC15.
- `client_config_versions_and_resumption` — TLS 1.2-only hint removes TLS 1.3.

### Property / fuzz tests
- `prop_cert_details_never_panics_on_random_der` — random bytes as DER → `parse_error`
  set, no panic.

### Snapshot tests
- `insta` snapshot of `CertPromptDetails` (Debug) for self-signed, expired, wrong-host and
  changed-certificate cases (rcgen with fixed keys and dates) — the data T69 renders.

### Integration tests (`FakeServer` + `tokio-rustls` acceptor, `rcgen` certificates, `RootSource::Custom`)
- `mode_plain_only_never_sends_auth`, `mode_explicit_if_available_falls_back_with_warning`,
  `mode_explicit_if_available_uses_auth_ssl`, `mode_require_explicit_fails_without_auth`,
  `mode_require_implicit_handshakes_before_greeting`. AC1.
- `explicit_handshake_failure_is_never_downgraded`. AC2.
- `prot_p_refused_falls_back_only_if_available`. AC3.
- `data_tls_resumes_session_tls12`, `data_tls_resumes_session_tls13`. AC4.
- `reuse_required_with_tls13_reconnects_with_tls12`. AC5.
- `self_signed_prompts_once_for_four_connections`, `always_trust_persists_and_is_silent`. AC6.
- `changed_certificate_prompt_has_previous`. AC7.
- `trust_once_not_persisted`, `locked_vault_disallows_always`. AC8.
- `nothing_written_before_trust_decision`, `rejected_cert_sends_no_user`. AC9.
- `data_cert_mismatch_refused`. AC10.
- `upload_sends_close_notify`, `download_without_close_notify_ok_with_226`,
  `download_without_close_notify_fails_without_226`. AC11.
- `session_info_reports_version_and_cipher`. AC12.
- `server_closed_during_prompt_reconnects_without_second_prompt`.
- `vault_cert_store_roundtrip_and_replace` (T30 test vault with `Argon2Cost::TEST`),
  `cert_store_switch_follows_unlock_and_lock`, `vault_locked_during_add_accepts_once`. AC15.

### End-to-end tests (`courier-ftp-e2e`, `#[ignore]` + `COURIER_E2E=1`, T76)
- `ftps_explicit_vsftpd`, `ftps_implicit_vsftpd`, `ftps_reuse_required_vsftpd`,
  `ftps_pureftpd`, `ftps_proftpd_mod_tls` — list + upload + download with hash check;
  the test CA from T76 `keys` is used via `RootSource::Custom`. AC13.
- `ftps_self_signed_prompt_then_always_trust` (Headless answers the prompt, second
  connect silent) and `ftps_changed_certificate_warns` (restart container with the
  alternative certificate). AC6, AC7.

## Out of scope

- `CCC`, `AUTH GSSAPI`/Kerberos (D8), client certificates, `SSCN` (server-to-server TLS),
  OCSP stapling configuration beyond what the platform verifier does.
- The vault engine itself (T30), the prompt and settings UI (T69, T68), the status bar (T57).
- TLS for SFTP (not applicable).

## Open questions

- `trusted-cert` items sync through the vault (D4). Should trusted certificates stored in a
  **team** vault (T89) be honoured on this device, or only those in the personal vault? A
  teammate (or compromised account) could otherwise plant a trust decision for a host;
  T91 §8 covers only locally-acting fields. Same question applies to T21 `known-host` items.
- Resolved: T03 now has `Backend::security_info() -> SessionSecurityInfo`; T04 owns the
  certificate/TLS types and `TrustAnswer`; this task implements the vault-backed store.
