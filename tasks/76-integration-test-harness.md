# T76 — Test strategy and e2e harness (sverb parity)

**Phase:** G App-level (start early, alongside phases B/C) · **Milestone:** M1 (grows through M2–M8) · **Depends on:** T00, T01, T03, T06 · **Crate(s):** all; new `crates/courier-ftp-e2e` (`publish = false`) · **Decisions:** D1, D2, D3, D12, D15 · **FEATURES.md:** — (test infrastructure for §1–§10)
**Related (integrates with, not blocking):** T10, T13, T20, T80, T84, T86, T88, T91
**Reference:** sverb `crates/sverb-e2e/` (`src/{lib,home,keys,pty,session,sshd,diag}.rs`, `tests/{workspace_metadata,forbid_unsafe,fixtures,harness_local,harness_docker}.rs`), `tests/fixtures/sshd/` (`Dockerfile`, `profiles/`, `check-configs.sh`, `entrypoint.sh`, `bin/`, `pam/`, `keys/`, `README.md`), `crates/sverb/tests/{common,startup,hardening,canary}.rs`, SPEC §19, `CONTRIBUTING.md`.

## Goal

Every layer of courier-ftp is tested the way sverb tests its own: fast unit, property and
snapshot tests in each crate, plus a Docker-based end-to-end suite against real FTP, FTPS,
SFTP, proxy and sync servers. The e2e suite is skipped by default and is a required CI
check. Developers get one harness crate (`courier-ftp-e2e`) with server fixtures,
temporary homes, a headless session driver and a PTY driver for the real binary, so
feature tasks only write scenarios, not plumbing.

## Context

**Before this task:**
- T00: CI job `e2e` (skipped by `detect` until `crates/courier-ftp-e2e/Cargo.toml` exists)
  with image build + `--list`/`--check` steps and env `COURIER_E2E`,
  `COURIER_E2E_{SSHD,FTPD,PROXY,SERVER}_IMAGE`; job `layering` runs
  `tests/workspace_metadata.rs` and `tests/forbid_unsafe.rs` once they exist;
  `bench.yml` runs `crates/courier-ftp/tests/startup.rs`.
- T01: all crates, features `test-util` (core, proto-sftp), `test-hooks` (binary),
  `insecure-test-ksf` (crypto), `COURIER_FTP_HOME` with `config/`, `data/`, `cache/`.
- T03: `Backend`, `BackendFactory`, `ConnectInfo`, `SessionHandle`, `MockBackend` and the
  reusable backend conformance suite (`courier_ftp_core::backend::conformance` with
  `ConformanceEnv`, `CASES`, `run_case` and the `backend_conformance_tests!` macro, all
  behind feature `test-util`). T06: `LocalBackend`, which runs that suite in-process.

**Later tasks need from it:** the server profiles (T10–T15 FTP, T20–T22 SFTP, T07/T15
proxies, including the in-process FTP relay proxy for T15), `TestHome` with a vault (T30, T31, T33, T60), `Headless` (T14, T22, T41–T44,
T41b, T71), `PtyApp` (T53, T60, T62, T63, T70), toxiproxy (T41, T41b, T42), the sync
server fixture (T84–T90), the in-process hostile FTP server (T13, T42, T53, T55, T91),
the TUI snapshot helper (all T5x/T6x UI tasks), the startup benchmark test (T00 bench gate).

**Testing strategy per layer (SPEC §19 equivalent):**

| Layer | Approach | Where |
|---|---|---|
| Crypto (T80) | Known-answer tests, `proptest` round-trips, AAD tamper tests, cross-version envelope fixtures | `courier-ftp-crypto/tests/` |
| Merge / sync (T81, T88) | Property tests: random concurrent edit sequences on 3 simulated devices converge to identical state (tombstones, resurrection); parallel pushers against Postgres while a puller asserts no revision is missed; a key rotation killed mid-way recovers | `courier-ftp-core/tests/merge_props.rs`, `courier-ftp-server/tests/`, `courier-ftp-sync/tests/` |
| FTP protocol (T10–T15) | Scripted fake servers over `tokio::io::duplex` / loopback for every command flow; reply/PASV parsers as property tests | `courier-ftp-proto-ftp/tests/` |
| Listing parsers (T13) | Fixture corpus + `insta` snapshots; never-panics property tests (shared with fuzz bodies, T91) | `courier-ftp-proto-ftp/tests/fixtures/listings/` |
| Importers (T32) | FileZilla `sitemanager.xml` fixtures with `insta` snapshots of the result | `courier-ftp-core/tests/fixtures/filezilla/` |
| Backends | One conformance suite (T03, `courier_ftp_core::backend::conformance`, feature `test-util`) run against Mock (T03) and Local (T06) in-process, and against every FTP/FTPS profile and SFTP auth profile in Docker | T03 suite + `courier-ftp-e2e/tests/backend_conformance.rs` |
| Transfer engine (T41, T41b, T42–T44) | Deterministic tests with `tokio::time::pause` and `MockBackend` with per-connection latency/bandwidth; exhaustive table for the file-exists decision | `courier-ftp-core/tests/` |
| Settings / config (T05) | Table tests; schema/doc snapshot (generated docs fail when stale, T77) | `courier-ftp-core`, `courier-ftp` |
| TUI | ratatui `TestBackend` + `insta` snapshots of every view at **80×24 and 160×48**; reducer-style tests that drive `App` with scripted key events | `courier-ftp/src/**` |
| Server (T84–T86) | Per-test Postgres database; HTTP tests through `axum::Router` + `tower::ServiceExt`; in-memory store variants for fast tests; multi-client sync scenarios against a real server | `courier-ftp-server/tests/`, e2e `sync.rs` |
| Security (T91) | Canary scan over all artifacts; hardening test on the real binary; `trybuild` compile-fail tests (secret types are not `Clone`/`Serialize`/`Display`able in plain text) | T91 |
| Fuzzing (T91) | `cargo-fuzz` targets whose bodies are also property tests | `fuzz/`, per crate |
| Performance (T00 §4) | `criterion` benches with CI gates; startup test | `benches/`, `courier-ftp/tests/startup.rs` |

## Technical specification

### Types and APIs

**Crate layout**

```
crates/courier-ftp-e2e/
  Cargo.toml              publish = false; [lints] workspace = true
  src/lib.rs              crate docs (pieces, running, reliability rules), timeout(), on_ci(),
                          e2e_requested(), docker_skip_reason(), require_docker!, poll_until(),
                          E2eError, Result
  src/docker.rs           ping_docker(), fixture_hash(), image(), container IP lookup, networks
  src/sshd.rs             Sshd, SshdProfile, SshdOptions
  src/ftpd.rs             Ftpd, FtpdProfile, FtpdOptions, CertVariant
  src/proxy.rs            ProxyServer, ProxyProfile
  src/ftp_proxy.rs        FtpRelayProxy, FtpRelayMode (in-process FTP proxy for T15, no Docker)
  src/toxi.rs             Toxiproxy, ToxicProxy, Toxic
  src/sync_server.rs      SyncServer, SyncDevice                            (M7)
  src/hostile.rs          HostileFtpd, HostileScript (in-process, no Docker)
  src/keys.rs             USER, PASSWORD, PASSPHRASE, OTP, CANARY_*, FixtureKey, TlsFixture
  src/files.rs            fixture_bytes(), sha256_file(), FIXTURE_TREE
  src/home.rs             TestHome, MASTER_PASSWORD
  src/session.rs          Headless, HeadlessOptions, PromptPolicy, E2eBackendFactory
  src/pty.rs              PtyApp, PtyOptions, Screen, courier_ftp_binary()
  src/diag.rs             dump(), capture(), failing(), tail()
  tests/workspace_metadata.rs  tests/forbid_unsafe.rs  tests/fixtures.rs
  tests/harness_local.rs       tests/harness_docker.rs
  tests/<scenario files, see "E2E scenarios">
tests/fixtures/
  sshd/  ftpd/  proxy/  tls/  editor/
```

**`Cargo.toml` dependencies**: `courier-ftp-core` (features `test-util`),
`courier-ftp-proto-ftp`, `courier-ftp-proto-sftp` (feature `test-util`),
`courier-ftp-store`, `courier-ftp-crypto` (feature `insecure-test-ksf`, dev only),
`courier-ftp-sync` (optional, feature `sync`, default on), `tokio`, `tokio-util`,
`testcontainers` (no default features: talks to the local Docker socket only),
`portable-pty`, `vt100`, `reqwest` (toxiproxy and sync server HTTP), `sha2`, `hex`,
`tempfile`, `serde_json`, `parking_lot`; dev: `cargo_metadata`, `toml`.

**`lib.rs`**

```rust
/// Polling timeout for every wait: 10 s locally, 20 s on CI.
pub fn timeout() -> Duration;
/// `CI` is set to anything but "", "false", "0".
pub fn on_ci() -> bool;
/// `COURIER_E2E` is "1" or "true" (case-insensitive).
pub fn e2e_requested() -> bool;
/// Why a container test must be skipped, `None` to run it:
/// not requested → skip; not Linux → skip ("the e2e suite needs a Linux Docker host:
/// containers are reached by their bridge IP"); Docker does not answer `GET /_ping`
/// within 5 s → skip locally, **panic on CI**.
pub async fn docker_skip_reason() -> Option<String>;
/// Early `return` with `eprintln!("skipped: {reason}")` unless the suite can run.
#[macro_export] macro_rules! require_docker { () => { … } }
/// Poll `probe` every `every` until it returns `Some`, or fail after `limit`.
/// The only place in the harness that sleeps.
pub async fn poll_until<T>(what: &str, limit: Duration, every: Duration,
    probe: impl FnMut() -> BoxFuture<'_, Option<T>>) -> Result<T, WaitError>;

/// Harness failure (Docker, image build, timeout, I/O). `Debug` == `Display` so
/// `unwrap()` output stays readable.
#[derive(Clone, PartialEq, Eq)] pub struct E2eError(pub String);
/// A wait that ran out of time; carries the last observed state (screen, log tail).
#[derive(Debug)] pub struct WaitError { pub what: String, pub waited: Duration, pub last: String }
pub type Result<T, E = E2eError> = std::result::Result<T, E>;
```

**`docker.rs`**

```rust
pub async fn ping_docker() -> Result<()>;
/// sha256 over (relative path, mode, bytes) of every file under `dir`, sorted; first 16 hex.
pub fn fixture_hash(dir: &Path) -> Result<String>;
/// `(name, tag)` for fixture `which` ("sshd" | "ftpd" | "proxy"): the env override
/// `COURIER_E2E_<WHICH>_IMAGE=name:tag`, else `courier-ftp-e2e-<which>:<hash>`, built with
/// `docker build` once per process (a `OnceLock` per image; 600 s limit).
pub async fn image(which: &str) -> Result<(String, String)>;
/// A user-defined bridge network `cftp-e2e-<uuid>`, removed on drop.
pub struct TestNetwork { … }
impl TestNetwork { pub async fn new() -> Result<Self>; pub fn name(&self) -> &str; }
```

**`sshd.rs`**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshdProfile { Password, Key, Kbd, MaxAuth2, Legacy, ChrootSftp, WindowsLike,
                       MaxSessions1, MaxConn1 }
impl SshdProfile {
    pub const ALL: [Self; 9];
    /// "password", "key", "kbd", "maxauth2", "legacy", "chroot-sftp", "windows-like",
    /// "maxsessions1", "maxconn1" — equal to `tests/fixtures/sshd/profiles/<name>.conf`.
    pub fn name(self) -> &'static str;
}
pub struct SshdOptions { pub profile: SshdProfile, pub network: Option<String>,
                         pub env: Vec<(String, String)> }
pub struct Sshd { … }
impl Sshd {
    pub async fn start(profile: SshdProfile) -> Result<Self>;
    pub async fn start_with(opts: SshdOptions) -> Result<Self>;
    /// Container IP on its network and port 22 (no host port is published).
    pub fn addr(&self) -> SocketAddr;
    pub fn host(&self) -> String;                    // IP as text, for ConnectInfo
    pub async fn exec(&self, cmd: &str) -> Result<ExecOutput>;      // as `test`
    pub async fn exec_root(&self, cmd: &str) -> Result<ExecOutput>;
    pub async fn host_keys(&self) -> Result<Vec<String>>;           // OpenSSH public lines
    pub async fn host_fingerprint(&self, key_type: &str) -> Result<String>; // SHA256:…
    pub async fn regenerate_host_key(&self) -> Result<Vec<String>>; // changed-key tests
    pub async fn sha256_of(&self, remote_path: &str) -> Result<String>;
    pub async fn logs(&self) -> Result<String>;
    pub async fn stop(&self) -> Result<()>;  pub async fn restart(&mut self) -> Result<()>;
}
```

**`ftpd.rs`**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpdProfile {
    VsftpdPlain, VsftpdExplicitTls, VsftpdImplicitTls, VsftpdTlsReuse, VsftpdActiveOnly,
    VsftpdPasvUnreachable, VsftpdMaxConn1, VsftpdAnonymous, VsftpdSlow,
    ProftpdPlain, ProftpdExplicitTls, PureftpdPlain, PureftpdExplicitTls,
}
impl FtpdProfile { pub const ALL: [Self; 13]; pub fn name(self) -> &'static str; // "vsftpd-plain", …
                   pub fn control_port(self) -> u16; /* 990 for implicit, else 21 */ }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CertVariant { #[default] CaSigned, SelfSigned, Expired, WrongHost }
pub struct FtpdOptions { pub profile: FtpdProfile, pub cert: CertVariant,
                         pub network: Option<String>,
                         /// Address announced in PASV replies (default: the container IP).
                         pub pasv_address: Option<IpAddr> }
pub struct Ftpd { … }
impl Ftpd {
    pub async fn start(profile: FtpdProfile) -> Result<Self>;
    pub async fn start_with(opts: FtpdOptions) -> Result<Self>;
    pub fn addr(&self) -> SocketAddr;  pub fn host(&self) -> String;
    /// Replace the server certificate and restart the daemon inside the container
    /// (same container, same IP), for changed-certificate tests.
    pub async fn set_cert(&self, cert: CertVariant) -> Result<()>;
    /// DER of the certificate currently served (for `TestHome::trust_cert`).
    pub async fn cert_der(&self) -> Result<Vec<u8>>;
    pub async fn exec(&self, cmd: &str) -> Result<ExecOutput>;
    pub async fn exec_root(&self, cmd: &str) -> Result<ExecOutput>;
    pub async fn sha256_of(&self, remote_path: &str) -> Result<String>;
    pub async fn logs(&self) -> Result<String>;
}
```

**`proxy.rs`, `toxi.rs`**

```rust
pub enum ProxyProfile { Http, HttpAuth, Socks4, Socks5, Socks5Auth }  // "http", …
pub struct ProxyServer { … }  // addr(), host(), logs(); creds PROXY_USER/PROXY_PASSWORD
impl ProxyServer { pub async fn start(profile: ProxyProfile, network: &TestNetwork) -> Result<Self>; }

/// ghcr.io/shopify/toxiproxy:2.9.0 on a TestNetwork, API on :8474.
pub struct Toxiproxy { … }
impl Toxiproxy {
    pub async fn start(network: &TestNetwork) -> Result<Self>;
    /// Proxy `listen_port` on the toxiproxy container to `upstream` ("ip:port").
    pub async fn proxy(&self, name: &str, listen_port: u16, upstream: SocketAddr) -> Result<ToxicProxy>;
    /// Front an Ftpd: control port plus PASV ports 30000–30019; the Ftpd must have been
    /// started with `pasv_address = toxiproxy IP`.
    pub async fn front_ftpd(&self, ftpd: &Ftpd) -> Result<Vec<ToxicProxy>>;
    pub fn ip(&self) -> IpAddr;
}
pub enum Toxic {
    Latency { ms: u32, jitter_ms: u32 },
    Bandwidth { kbytes_per_s: u32 },
    /// Close the connection after this many bytes downstream (resume tests).
    LimitData { bytes: u64 },
    ResetPeer { after_ms: u32 },
}
impl ToxicProxy { pub async fn add(&self, name: &str, toxic: Toxic) -> Result<()>;
                  pub async fn remove(&self, name: &str) -> Result<()>;
                  pub async fn disable(&self) -> Result<()>; pub async fn enable(&self) -> Result<()>;
                  pub fn addr(&self) -> SocketAddr; }
```

**`ftp_proxy.rs`** (in-process FTP proxy for T15; no Docker image)

```rust
/// Which login convention the relay accepts (FileZilla's FTP proxy types, T15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpRelayMode { UserAtHost, Site, Open }
/// A minimal FTP proxy on 127.0.0.1:0 (tokio). It greets with `220 courier-ftp-e2e relay`,
/// accepts optional proxy credentials (`USER proxyuser` / `PASS proxypass`, i.e.
/// PROXY_USER/PROXY_PASSWORD), learns the target from `USER u@host[:port]`, `SITE host[:port]`
/// or `OPEN host[:port]` per mode, then connects to the target (only targets in
/// `allowed_targets`, so the relay is not an open proxy), relays the control connection
/// line by line and rewrites `227`/`229` replies so data connections go through a relayed
/// listener on 127.0.0.1 (passive mode only; active mode → `502`).
pub struct FtpRelayProxy { … }
impl FtpRelayProxy {
    pub async fn start(mode: FtpRelayMode, require_auth: bool,
                       allowed_targets: Vec<SocketAddr>) -> Result<Self>;
    pub fn addr(&self) -> SocketAddr;
    /// Every control line received from the client, with `PASS` arguments masked as `****`.
    pub fn commands(&self) -> Vec<String>;
}
```

The relay only forwards bytes; it never parses listings or inspects data connections. Its
self-test (`harness_local.rs::ftp_relay_proxy_relays_to_hostile_ftpd`) runs it in front of
`HostileFtpd` without Docker.

**`hostile.rs`** (no Docker; runs in the normal suite)

```rust
/// A scripted, deliberately misbehaving FTP server on 127.0.0.1:0 (tokio).
/// Speaks USER/PASS/SYST/FEAT/PWD/CWD/TYPE/PASV/EPSV/LIST/MLSD/NLST/SIZE/MDTM/RETR/QUIT.
pub struct HostileFtpd { … }
pub struct HostileScript {
    pub banner: String,                    // may contain ESC sequences
    pub feat: Vec<String>,
    pub listing: Vec<String>,              // raw LIST/MLSD lines, sent verbatim
    pub files: Vec<(String, Vec<u8>)>,     // RETR name -> bytes
    pub reported_size: Option<u64>,        // SIZE reply override (e.g. u64::MAX)
    pub pasv_reply: Option<String>,        // raw 227 text override
}
impl HostileFtpd { pub async fn start(script: HostileScript) -> Result<Self>;
                   pub fn addr(&self) -> SocketAddr; pub fn commands(&self) -> Vec<String>; }
```

**`keys.rs`, `files.rs`**

```rust
pub const USER: &str = "test";
pub const PASSWORD: &str = "test";
pub const PASSPHRASE: &str = "fixture";           // encrypted fixture keys
pub const OTP: &str = "424242";                   // kbd profile
pub const CANARY_USER: &str = "canary";           // exists in sshd and ftpd images
pub const CANARY_PASSWORD: &str = "CANARY-PW-e2e-7f3a";
pub const PROXY_USER: &str = "proxyuser";  pub const PROXY_PASSWORD: &str = "proxypass";
pub fn fixtures_dir() -> PathBuf;                 // <repo>/tests/fixtures
#[derive(Debug, Clone, Copy)]
pub enum FixtureKey { Ed25519, Ecdsa, Rsa, Ed25519Encrypted, PpkV2, PpkV3, PpkV3Encrypted }
impl FixtureKey { pub fn path(self) -> PathBuf; pub fn public(self) -> String;
                  pub fn passphrase(self) -> Option<&'static str>; }
pub struct TlsFixture;  // ca_pem(), ca_der()

/// The tree baked into the ftpd and sshd images under /home/test/fixtures.
pub const FIXTURE_TREE: &[(&str, u64)];         // (relative path, size)
/// Deterministic content: SHA-256 in counter mode keyed by the relative path.
pub fn fixture_bytes(rel_path: &str, len: u64) -> impl Read;
pub fn sha256_file(path: &Path) -> std::io::Result<String>;
```

**`home.rs`**

```rust
/// Master password of every TestHome vault.
pub const MASTER_PASSWORD: &str = "correct horse battery staple violin";
pub struct TestHome { … }
impl TestHome {
    /// Empty `COURIER_FTP_HOME` in a temp dir, deleted on drop (M1: no vault yet).
    pub fn new() -> Result<Self>;
    /// Kept after the run under `root/<name>-<uuid>` (pass `env!("CARGO_TARGET_TMPDIR")`
    /// so the canary scan finds it, T91).
    pub fn kept(root: &Path, name: &str) -> Result<Self>;
    /// `new()` plus an initialised vault (`VaultEngine::initialize(MASTER_PASSWORD)` with
    /// `Argon2Cost::TEST`), locked again afterwards. (From T30.)
    pub async fn with_vault() -> Result<Self>;
    pub fn path(&self) -> &Path;
    pub fn config_dir(&self) -> PathBuf; pub fn data_dir(&self) -> PathBuf; pub fn cache_dir(&self) -> PathBuf;
    /// Env for child processes: COURIER_FTP_HOME, COURIER_FTP_KEYRING=off,
    /// COURIER_FTP_LOG_LEVEL=debug, TERM=xterm-256color, LANG=C.UTF-8.
    pub fn env(&self) -> Vec<(String, String)>;
    /// Write `<config>/config.json` (merged over existing content).
    pub fn write_settings(&self, json: serde_json::Value) -> Result<()>;
    pub async fn vault(&self) -> Result<VaultEngine>;                  // unlocked
    pub async fn add_site(&self, site: Site) -> Result<ItemId>;       // T31
    pub async fn add_bookmark(&self, bookmark: Bookmark) -> Result<ItemId>; // T33
    pub async fn trust_host_key(&self, host: &str, port: u16, openssh_public: &str) -> Result<ItemId>; // T21
    pub async fn trust_cert(&self, host: &str, port: u16, der: &[u8]) -> Result<ItemId>; // T12
    pub async fn list(&self, kind: ItemKind) -> Result<Vec<(ItemId, ItemBody)>>;
}
```

**`session.rs`**

```rust
/// How Headless answers a trust prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PromptPolicy { #[default] Fail, TrustOnce, TrustAlways, Reject }
#[derive(Debug, Default)]
pub struct HeadlessOptions {
    pub host_key: PromptPolicy, pub certificate: PromptPolicy,
    pub password: Option<String>, pub passphrase: Option<String>,
    pub kbd_answers: Vec<String>,         // in prompt order
    pub settings: Option<Settings>,       // defaults otherwise
}
/// Maps `Protocol` to `FtpBackend` / `SftpBackend` exactly like the binary's factory.
#[derive(Debug, Default)] pub struct E2eBackendFactory;
impl BackendFactory for E2eBackendFactory { … }
/// One session through the real backend, `SessionHandle`, event bus and (from M4) the
/// transfer engine, with no TUI. Prompts are answered from `HeadlessOptions`; any other
/// prompt fails the test with its full content.
pub struct Headless { … }
impl Headless {
    pub async fn connect(home: Option<&TestHome>, info: ConnectInfo, opts: HeadlessOptions) -> Result<Self>;
    pub async fn list(&self, dir: &RemotePath) -> Result<Listing>;
    pub async fn download(&self, remote: &RemotePath, local: &Path) -> Result<()>;   // M4
    pub async fn upload(&self, local: &Path, remote: &RemotePath) -> Result<()>;     // M4
    pub async fn run_queue(&self, items: Vec<QueueItem>) -> Result<QueueStats>;      // M4
    pub async fn wait_for_event(&mut self, what: &str, pred: impl Fn(&CoreEvent) -> bool)
        -> std::result::Result<CoreEvent, WaitError>;
    /// Every `LogMessage` seen so far, formatted like the message log (T55).
    pub fn log_text(&self) -> String;
    pub fn prompts_seen(&self) -> Vec<String>;
}
```

**`pty.rs`**

```rust
pub struct PtyOptions { pub cols: u16 /*120*/, pub rows: u16 /*40*/, pub args: Vec<String>,
                        pub env: Vec<(String, String)>, pub timeout: Option<Duration> }
/// `COURIER_E2E_BINARY` if set, else `<target>/debug/courier-ftp`, built once per process
/// with `cargo build -p courier-ftp --features test-hooks --locked` when missing.
pub fn courier_ftp_binary() -> Result<PathBuf>;
#[derive(Debug, Clone)] pub struct Screen { pub rows: Vec<String>, pub cursor: (u16, u16) }
impl Screen { pub fn contains(&self, needle: &str) -> bool; pub fn text(&self) -> String;
              pub fn row(&self, i: usize) -> &str; }
pub struct PtyApp { … }
impl PtyApp {
    pub fn launch(home: &TestHome, opts: PtyOptions) -> Result<Self>;
    pub fn screen(&mut self) -> Screen;
    pub fn raw_output(&self) -> &[u8];
    pub fn wait_for_text(&mut self, needle: &str) -> std::result::Result<Screen, WaitError>;
    pub fn wait_for_screen(&mut self, what: &str, pred: impl Fn(&Screen) -> bool)
        -> std::result::Result<Screen, WaitError>;
    /// Space-separated chords: "ctrl-s", "alt-x", "F5", "g g", "enter", "esc", "tab",
    /// "shift-tab", "up", "pgdn", "space", "x".
    pub fn send_keys(&mut self, chords: &str) -> Result<()>;
    pub fn send_text(&mut self, text: &str) -> Result<()>;
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<()>;
    /// Wait for the unlock screen (T60), type MASTER_PASSWORD + Enter, wait for the panes.
    pub fn unlock(&mut self) -> std::result::Result<Screen, WaitError>;
    pub fn wait_exit(&mut self) -> std::result::Result<ExitStatus, WaitError>;
    pub fn pid(&self) -> Option<u32>;
    pub fn dump(&mut self);
}
```

**`diag.rs`**: `pub fn dump(title: &str, body: &str)` (prints
`----- diag: <title> -----` + body to stderr, or into the capture buffer),
`pub fn capture<R>(f: impl FnOnce() -> R) -> (std::thread::Result<R>, Vec<String>)`
(harness self-tests), `pub fn failing() -> bool` (`std::thread::panicking()`),
`pub fn tail(text: &str, max_lines: usize) -> String`.

**TUI snapshot helper** (in the binary crate, `crates/courier-ftp/src/testing.rs`,
`#[cfg(test)]`, delivered in M1 for T50):

```rust
pub(crate) const SIZES: [(u16, u16); 2] = [(80, 24), (160, 48)];
/// Render `draw` into a ratatui `TestBackend` of `w`×`h`; return the buffer as text
/// (one line per row, trailing spaces kept) followed by a style legend for cells whose
/// style differs from the default.
pub(crate) fn render(w: u16, h: u16, draw: impl FnMut(&mut Frame)) -> String;
/// `insta::assert_snapshot!` for both SIZES with names `<name>@80x24` / `<name>@160x48`.
macro_rules! assert_view_snapshots { ($name:expr, $draw:expr) => { … } }
```

### Behaviour

#### Container fixtures

All images are `debian:bookworm-slim`, built from `tests/fixtures/<name>/`, with
`ENTRYPOINT` scripts that accept `--list` (print profile names, one per line, exit 0) and
`--check` (set the profile up, validate the configuration, exit 0/1 without serving).
Unknown profile → exit 64 with the list on stderr.

**Addressing:** containers are reached by their bridge IP (testcontainers
`get_bridge_ip_address`, or the IP on a `TestNetwork`); no port is published on the host,
so nothing listens on host interfaces and FTP PASV/PORT work without NAT. Active-mode FTP
connects back to the runner through the bridge gateway IP.

**`tests/fixtures/sshd/`** (copied from sverb, trimmed and extended; env `SSHD_PROFILE`,
default `password`):

| Profile | Essentials | Used by |
|---|---|---|
| `password` | `PasswordAuthentication yes`, `Subsystem sftp internal-sftp` | T20, T22 |
| `key` | public keys only | T20 |
| `kbd` | keyboard-interactive via PAM; `pam_exec` OTP check (code `424242`) after the password: two prompts `Password: `, `Verification code: ` | T20 |
| `maxauth2` | `MaxAuthTries 2`, keys only | T20 |
| `legacy` | `KexAlgorithms diffie-hellman-group14-sha1`, `HostKeyAlgorithms ssh-rsa`, `Ciphers aes128-cbc`, `MACs hmac-sha1` (negative tests) | T20 |
| `chroot-sftp` | `ForceCommand internal-sftp`, `ChrootDirectory /srv/chroot` (shell logins refused) | T22 |
| `windows-like` | `ChrootDirectory /srv/win`, `ForceCommand internal-sftp -d /C:/Users/test` (paths look like OpenSSH for Windows: `/C:/Users/test`) | T22 |
| `maxsessions1` | `MaxSessions 1` (one channel per connection) | T22, T41 |
| `maxconn1` | sshd on 127.0.0.1:2222 behind `bin/conn-limit-proxy` on :22 (python3 asyncio, stdlib only): at most 1 concurrent TCP connection, further connections are accepted and closed immediately | T41, T41b |

Users: `test`/`test` (bash) and `canary`/`CANARY-PW-e2e-7f3a`; both have
`keys/authorized_keys`, `~/upload/` (writable) and `~/fixtures/` (the `FIXTURE_TREE`,
generated at image build by `bin/make-fixture-tree` with the same algorithm as
`files::fixture_bytes`). Host keys are generated per container at first start;
`courier-regen-hostkeys` replaces them (`Sshd::regenerate_host_key`). sshd logs at
`DEBUG1` to stderr. `check-configs.sh` (sverb's, adapted) runs `sshd -t` for every
profile without Docker.

**Keys** (`tests/fixtures/sshd/keys/`, TEST-ONLY, comment `courier-ftp-e2e-fixture-TEST-ONLY`):
`id_ed25519`, `id_ecdsa` (P-256), `id_rsa` (4096), `id_ed25519_encrypted` (passphrase
`fixture`), `id_ed25519.ppk` (PPK v2, unencrypted), `id_ed25519_v3.ppk` (PPK v3),
`id_ed25519_v3_encrypted.ppk` (PPK v3, passphrase `fixture`, Argon2id), `authorized_keys`
(the ed25519, ecdsa, rsa, encrypted public keys), plus `README.md` with the regeneration
commands (`ssh-keygen …`, `puttygen … -O private --ppk-param version=2|3`). sverb's
certificate CAs are not copied (no OpenSSH certificates, see T20 out of scope).

**`tests/fixtures/ftpd/`** (env `FTPD_PROFILE`, default `vsftpd-plain`; `FTPD_CERT`
`ca-signed` | `self-signed` | `expired` | `wrong-host`, default `ca-signed`;
`FTPD_PASV_ADDRESS`, default the container IP from `hostname -i`). Packages: `vsftpd`,
`proftpd-core`, `proftpd-mod-crypto` (mod_tls), `pure-ftpd`, `openssl`, `python3`.
Control port 21 (implicit TLS: 990), passive ports **30000–30019**. Users as in sshd
(`test`, `canary`, chrooted to their home, `~/upload/` writable, `~/fixtures/` tree);
anonymous root `/srv/anon` (read-only, contains `readme.txt`).

| Profile | Server and essentials |
|---|---|
| `vsftpd-plain` | vsftpd, `ssl_enable=NO`; LIST only (vsftpd has no MLSD) |
| `vsftpd-explicit-tls` | `ssl_enable=YES`, `force_local_logins_ssl=YES`, `force_local_data_ssl=YES`, `require_ssl_reuse=NO` |
| `vsftpd-implicit-tls` | `implicit_ssl=YES`, `listen_port=990` |
| `vsftpd-tls-reuse` | explicit TLS with `require_ssl_reuse=YES` |
| `vsftpd-active-only` | `pasv_enable=NO` |
| `vsftpd-pasv-unreachable` | `pasv_address=10.255.255.1`, `pasv_addr_resolve=NO` (data connect times out → fallback to active, T11) |
| `vsftpd-maxconn1` | `max_per_ip=1`, `max_clients=1` (`421` on the second connection) |
| `vsftpd-anonymous` | `anonymous_enable=YES`, `anon_root=/srv/anon`, `write_enable=NO` |
| `vsftpd-slow` | `local_max_rate=262144` (256 KiB/s, cancel/resume tests) |
| `proftpd-plain` | proftpd, MLSD/MLST, `SITE CHMOD`, `MFMT`, `MDTM` |
| `proftpd-explicit-tls` | proftpd + mod_tls, `TLSRequired on`; TLS session reuse on data connections required (proftpd's default: `NoSessionReuseRequired` is **not** set) |
| `pureftpd-plain` | pure-ftpd, its own LIST format, MLSD |
| `pureftpd-explicit-tls` | pure-ftpd `--tls=2` (TLS required for login) |

TLS certificates are generated by the entrypoint at every daemon start with `openssl`,
signed by the TEST-ONLY CA in `tests/fixtures/tls/` (`ca.pem`, `ca.key`), SAN
`IP:<container IP>, DNS:ftpd.test`: `ca-signed` (valid 1 year from now),
`self-signed` (own key, same SAN), `expired` (`openssl ca -startdate 20200101000000Z
-enddate 20210101000000Z`), `wrong-host` (SAN `DNS:wrong.example` only). The daemon runs
under a supervisor loop in the entrypoint; `courier-set-cert <variant>` (used by
`Ftpd::set_cert`) regenerates the cert and restarts the daemon in place (same container IP,
so "changed certificate" is tested against an existing trust entry).

**`tests/fixtures/proxy/`** (env `PROXY_PROFILE`; packages `squid`, `dante-server`):
`http` (squid :3128, CONNECT to ports 21, 22, 990, 30000–30019 allowed), `http-auth`
(squid basic auth `proxyuser`/`proxypass`), `socks4`, `socks5` (dante :1080, no auth),
`socks5-auth` (dante `username` method). `--check` runs `squid -k parse` / `danted -V`.

**FTP proxy (in-process):** `FtpRelayProxy` (above) covers T15's `UserAtHost`, `Site` and
`Open` types in front of the `vsftpd-plain` container; the `Custom` type is covered by T15's
`FakeServer` integration tests. No Docker image is needed (`--list`/`--check` do not apply).

**MLSD:** vsftpd has no MLSD; every MLSD/MLST scenario (T13, T14) uses the `proftpd-*` or
`pureftpd-*` profiles. `vsftpd-*` profiles cover the LIST path.

**Toxiproxy:** upstream image `ghcr.io/shopify/toxiproxy:2.9.0` (pulled, not built),
controlled over its HTTP API (`POST /proxies`, `POST /proxies/<name>/toxics`).

**Sync server (M7):** `SyncServer::start()` creates a `TestNetwork`, runs `postgres:16`
(`POSTGRES_USER/PASSWORD/DB=courier`), waits for `pg_isready`, then runs the server image
(`COURIER_E2E_SERVER_IMAGE`, else built from `deploy/Dockerfile.server` with the repo root
as context, 900 s limit) with `DATABASE_URL`, `COURIER_SERVER_SECRET` (the CI test value),
`COURIER_PUBLIC_URL=http://<ip>:8080`, command `serve --migrate`; waits for `/readyz`;
parses `setup_token` from the logs; opens registration with
`exec(["courier-ftp-server", "admin", "registration", "open"])`. `SyncDevice` wraps a
`TestHome::with_vault()` plus the `courier-ftp-sync` client (API names from T87/T88).

#### Harness rules (copied from sverb)

- Container tests are `#[ignore]` and start with `require_docker!()`; they run only with
  `COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored`.
- On CI (`CI=true`) with `COURIER_E2E=1`, an unreachable Docker daemon **panics**.
- **No fixed sleeps.** Every wait goes through `poll_until` / `timeout()`: readiness
  polls every 100 ms (TCP connect + banner read for FTP/SSH, `/readyz` for the server),
  PTY reads every 20 ms. Explicit longer limits: image build 600 s, server image build
  900 s, a 2 GiB transfer 120 s, sync server start 60 s.
- Each test starts its own containers (and network, when it needs more than one), so
  tests are parallel-safe; CI runs `--test-threads=4`. Containers are removed when their
  handle drops (testcontainers), also on panic.
- **Diagnostics:** every container handle and `PtyApp` implements `Drop`; when
  `diag::failing()`, it dumps the last 200 log lines of the container, the last screen and
  the last 4 KiB of raw PTY output, and `Headless` dumps its last 200 message-log lines.
- Harness self-tests that need no Docker (in-process SFTP server from
  `courier-ftp-proto-sftp` feature `test-util`, `HostileFtpd`, `PtyApp` against the local
  binary) are **not** `#[ignore]`d and run in the normal `test` job.

#### PTY key encoding (`send_keys`)

| Chord | Bytes | Chord | Bytes |
|---|---|---|---|
| `ctrl-a`…`ctrl-z` | `0x01`…`0x1a` | `F1`–`F4` | `ESC O P`…`ESC O S` |
| `enter` | `\r` | `F5`, `F6`, `F7`, `F8` | `ESC[15~`, `ESC[17~`, `ESC[18~`, `ESC[19~` |
| `esc` | `ESC` | `F9`–`F12` | `ESC[20~`, `ESC[21~`, `ESC[23~`, `ESC[24~` |
| `tab` / `shift-tab` | `\t` / `ESC[Z` | `up`/`down`/`right`/`left` | `ESC[A`/`B`/`C`/`D` |
| `backspace` | `0x7f` | `home`/`end` | `ESC[H` / `ESC[F` |
| `space` | `0x20` | `pgup`/`pgdn`/`delete` | `ESC[5~` / `ESC[6~` / `ESC[3~` |
| `alt-<c>` | `ESC <c>` | any other single char | itself (UTF-8) |

Unknown chord names fail the test (`E2eError`), never silently send text.

#### Test hooks in the binary (feature `test-hooks`, never in release builds)

Env `COURIER_FTP_TEST_HOOK`, read once after the TUI entered the alternate screen:
- `exit-after-panes` — exit 0 right after the file panes were drawn for the first time
  (startup benchmark);
- `exit:<ms>` — normal shutdown after `<ms>` ms;
- `panic-ui`, `panic-thread`, `panic-blocking` — the crash paths T91 tests.
Env `COURIER_FTP_KEYRING=file:<dir>` (test-hooks builds only): a file-backed keyring so
the startup test can measure keyring unlock without an OS keyring (T30/T60 implement the
keyring side).

#### Startup benchmark test (`crates/courier-ftp/tests/startup.rs`)

`#[ignore]`, release build with `test-hooks`: creates a kept home with 1 000 sites and
keyring unlock enabled through the file keyring, launches the binary in a PTY 20 times with
`COURIER_FTP_TEST_HOOK=exit-after-panes`, measures spawn → exit, and fails when the median
exceeds `COURIER_FTP_STARTUP_GATE_MS` (default 200). Prints all 20 timings.

### Data formats and configuration

| Variable | Meaning | Default |
|---|---|---|
| `COURIER_E2E` | `1`/`true` runs container tests | unset (skip) |
| `COURIER_E2E_SSHD_IMAGE`, `COURIER_E2E_FTPD_IMAGE`, `COURIER_E2E_PROXY_IMAGE` | prebuilt `name:tag` (CI) | built from `tests/fixtures/<name>/`, tag = `fixture_hash` |
| `COURIER_E2E_SERVER_IMAGE` | prebuilt sync server image | built from `deploy/Dockerfile.server` |
| `COURIER_E2E_BINARY` | path of the `courier-ftp` binary for `PtyApp` | `<target>/debug/courier-ftp` |
| `CI` | CI mode: 20 s timeouts, missing Docker fails | unset |
| `COURIER_FTP_TEST_HOOK` | see Test hooks | unset |
| `COURIER_FTP_STARTUP_GATE_MS` | startup gate | `200` |
| `SSHD_PROFILE`, `FTPD_PROFILE`, `FTPD_CERT`, `FTPD_PASV_ADDRESS`, `PROXY_PROFILE` | container env, set by the harness | see fixtures |

Fixture tree (`FIXTURE_TREE`, under `/home/<user>/fixtures/` in sshd and ftpd images):
`small.bin` (1 024 B), `1MiB.bin` (1 048 576 B), `empty.txt` (0 B),
`names/with space.txt`, `names/ leading-space.txt`, `names/trailing-space.txt ` ,
`names/Zürich – ü.txt`, `names/日本語.txt`, `names/-dash.txt`, `names/semi;colon.txt`,
`sub/dir/deep.txt` (100 B each), and the symlink `link-to-small -> small.bin`.
Content per file = `fixture_bytes(rel_path, size)`: block *i* (32 bytes) =
`SHA-256(rel_path || u64_be(i))`, truncated to `size`.

Snapshot files: `insta` default layout next to the test (`snapshots/<module>__<name>@80x24.snap`).
In CI `insta` runs with `INSTA_UPDATE=no` (and fails on missing or changed snapshots);
locally `cargo insta review`.

### Errors

- Harness functions return `courier_ftp_e2e::Result` (`E2eError` with a readable,
  multi-line message: what was attempted, the Docker/IO error, the container log tail).
- Waits return `WaitError { what, waited, last }`; `last` is the last screen / log tail.
- Backend and engine errors surface unchanged as `courier_ftp_core::Error` inside
  `Headless` results, so scenarios can assert on variants (`Error::Auth`, `Error::Tls`,
  `Error::HostKey`, `Error::Cancelled`, …).
- An unexpected prompt in `Headless` (policy `Fail`, or a kind without an answer) fails
  the operation with `E2eError("unexpected prompt: <kind and content>")`.

### Security and logging

- All key material under `tests/fixtures/{sshd/keys,tls,keys}` is **TEST-ONLY** and
  committed on purpose; every directory has a `README.md` saying so; secret scanners
  skip them (T00 `.gitleaks.toml`, `secret_scanning.yml`). Never trust them anywhere.
- The harness never touches the real home: every child process gets `TestHome::env()`
  (`COURIER_FTP_HOME`, `COURIER_FTP_KEYRING=off`).
- No host ports are published; containers are reachable only from the runner's bridge.
- Canary values: the `canary` user's password is `CANARY-PW-e2e-7f3a`; scenarios that
  store or type it keep their home with `TestHome::kept(env!("CARGO_TARGET_TMPDIR"), …)`
  so the canary scan (T91, T00 `canary` and `e2e` jobs) checks logs, DBs and session logs.
- Harness `eprintln!` diagnostics may contain container IPs and fixture names (test-only
  data); they never print vault contents.
- `test-hooks` and `test-util` must never be enabled in release graphs
  (`workspace_metadata.rs`, T00 `packaging`).

## Implementation steps

1. **M1** Crate skeleton with `lib.rs` (docs, `timeout`, `on_ci`, `e2e_requested`,
   `docker_skip_reason`, `require_docker!`, `poll_until`, `E2eError`), `diag.rs`,
   `docker.rs` (ping, hash, image build); `TestHome::new/kept/env/write_settings`.
2. **M1** `tests/workspace_metadata.rs` and `tests/forbid_unsafe.rs`; T00's `layering`
   job runs them.
3. **M1** TUI snapshot helper `crates/courier-ftp/src/testing.rs`; `PtyApp` and
   `harness_local.rs::pty_app_starts_and_quits` against the template UI; `test-hooks`
   feature with `exit:<ms>` and `exit-after-panes`.
4. **M2** `tests/fixtures/sshd/` image + profiles + keys + `check-configs.sh`;
   `sshd.rs`; `keys.rs`; `files.rs` + `make-fixture-tree`; `Headless::connect/list` with
   `E2eBackendFactory`; self-test against the in-process SFTP server;
   `TestHome::with_vault`, `add_site`, `trust_host_key` (once T30/T31/T21 exist).
5. **M2** `PtyApp::unlock`; `pty_flows.rs::first_run_create_vault_and_unlock`.
6. **M3** `tests/fixtures/ftpd/` image (vsftpd, proftpd, pure-ftpd, TLS CA + cert
   variants, supervisor, `courier-set-cert`); `ftpd.rs`; `hostile.rs`; `trust_cert`.
7. **M3** `tests/fixtures/proxy/` + `proxy.rs` (with T07); `ftp_proxy.rs` (`FtpRelayProxy`) with
   its in-process self-test (with T15).
8. **M4** `toxi.rs`; `Headless::download/upload/run_queue`; transfer scenarios.
9. **M4** `startup.rs` benchmark test (needs T60 + T31; file keyring from T30).
10. **M7–M8** `sync_server.rs` (`SyncServer`, `SyncDevice`) and sync/team scenarios.

## Acceptance criteria

- [ ] AC1 `crates/courier-ftp-e2e` exists with the modules above; its crate docs describe the pieces, how to run the suite and the reliability rules (like sverb's `lib.rs`); `cargo doc -p courier-ftp-e2e` has no warnings.
- [ ] AC2 Without `COURIER_E2E`, `cargo test -p courier-ftp-e2e -- --ignored` passes and every container test prints `skipped: set COURIER_E2E=1 …`; the normal `cargo test --workspace` runs the harness self-tests and no container.
- [ ] AC3 With `COURIER_E2E=1` and `CI=true` but no Docker, `docker_skip_reason` panics (unit test with an injected ping failure); with `CI` unset it skips.
- [ ] AC4 Every fixture image builds, `--list` prints exactly the profiles of its enum (`SshdProfile::ALL`, `FtpdProfile::ALL`, `ProxyProfile`), and `--check` passes for each profile (CI `e2e` job steps).
- [ ] AC5 `tests/fixtures.rs` passes: profile files ↔ enum names, keys present, every fixture key dir has a TEST-ONLY README, `check-configs.sh` passes when `sshd` is installed.
- [ ] AC6 `tests/workspace_metadata.rs` and `tests/forbid_unsafe.rs` pass, and each fails when its rule is broken (self-tests over doctored metadata / a probe crate).
- [ ] AC7 No fixed sleeps: `grep -rnE 'thread::sleep|time::sleep' crates/courier-ftp-e2e/src` matches only inside `poll_until` and the PTY reader loop.
- [ ] AC8 Every scenario in the "E2E scenarios" table for the milestones reached so far exists and passes in the CI `e2e` job.
- [ ] AC9 Every TUI view has snapshots at both 80×24 and 160×48: `crates/courier-ftp/tests/snapshot_sizes.rs` fails if a `*@80x24.snap` has no `*@160x48.snap` twin or vice versa.
- [ ] AC10 The CI `e2e` job finishes in under 30 minutes on `ubuntu-latest` (recorded from the last 5 runs in the PR that completes M4).
- [ ] AC11 A deliberately failing harness self-test (`diag::capture`) shows the container log tail, the last screen and the message-log tail in its captured output.
- [ ] AC12 `startup.rs` reports a median below 200 ms on CI (`bench.yml`) once T60 lands.
- [ ] AC13 `backend_conformance.rs` uses the T03 suite only (`courier_ftp_core::backend::conformance` via `backend_conformance_tests!(ignored, env_fn)`, feature `test-util`); the e2e crate defines no conformance cases of its own.
- [ ] AC14 `FtpRelayProxy` relays a login, a listing and a passive download for each `FtpRelayMode` to `HostileFtpd` in-process (normal `test` job), refuses targets outside `allowed_targets`, and never records an unmasked `PASS` argument in `commands()`.
- [ ] AC15 MLSD scenarios run only on `proftpd-*`/`pureftpd-*` profiles; `mlsd_used_on_proftpd_and_pureftpd` passes and a vsftpd profile is listed via LIST.

## Tests

### Unit tests
In `courier-ftp-e2e/src/*` (`#[cfg(test)]`):
- `lib.rs::skip_reason_without_opt_in`, `skip_reason_panics_on_ci_without_docker`, `skip_reason_skips_locally_without_docker` — ping injected through a private `docker_skip_reason_with(ping)` (AC3).
- `docker.rs::fixture_hash_changes_with_content_and_mode` — temp dir, change one byte / one mode bit.
- `pty.rs::chord_table_encodes_every_named_key`, `pty.rs::unknown_chord_is_an_error`.
- `files.rs::fixture_bytes_matches_make_fixture_tree` — compares with the Python generator's output for 3 known files (hashes committed in the test).
- `ftpd.rs::profile_names_are_unique_and_kebab_case`, `sshd.rs::profile_names_are_unique_and_kebab_case`.
- `ftp_proxy.rs::parses_target_per_mode` — `USER test@10.0.0.2:2121`, `SITE 10.0.0.2`, `OPEN 10.0.0.2:21` → the expected `SocketAddr`; malformed targets → `501` (AC14).
- `ftp_proxy.rs::rewrites_pasv_and_epsv_replies` — `227 (10,0,0,2,117,48)` and `229 (|||30000|)` become the relay's local listener address (AC14).

### Property / fuzz tests
- `hostile.rs` self-test `hostile_listing_lines_round_trip` — proptest: any listing line without CR/LF is sent verbatim (what the parser sees equals the script).

### Snapshot tests
- The helper itself: `crates/courier-ftp/src/testing.rs::render_includes_style_legend` (renders a styled `Paragraph` at 80×24 and 160×48).
- `crates/courier-ftp/tests/snapshot_sizes.rs::every_view_has_both_sizes` (AC9).

### Integration tests
`crates/courier-ftp-e2e/tests/`, all without Docker:
- `workspace_metadata.rs`: `layering_rules_all_features`, `layering_rules_no_default_features` (same table as T00's `check-layering.py`, second implementation), `every_package_is_mit_with_rust_version`, `internal_deps_carry_versions`, `sync_is_optional_and_absent_without_default_features`, `insecure_ksf_only_in_dev` (T80 AC9: no normal/build edge enables `courier-ftp-crypto/insecure-test-ksf`), `test_features_never_default` (`test-hooks`, `test-util` not reachable from any `default` feature) (AC6).
- `forbid_unsafe.rs`: `every_crate_inherits_workspace_lints`, `unsafe_block_is_rejected_by_workspace_lints` (throwaway workspace with the real `[workspace.lints]` and a probe crate containing `unsafe {}`; must fail with `deny(unsafe_code)`) (AC6).
- `fixtures.rs`: `sshd_profiles_match_files`, `ftpd_profiles_match_files`, `proxy_profiles_match_files`, `fixture_keys_present_and_marked_test_only`, `sshd_configs_pass_sshd_t` (skips with a message when no `sshd`) (AC5).
- `harness_local.rs`: `pty_app_starts_and_quits` (M1: template UI, `q`), `pty_app_resize_redraws`, `headless_lists_in_process_sftp_server` (M2), `hostile_ftpd_serves_scripted_listing` (M3), `diag_dumps_on_failure` (AC11), `ftp_relay_proxy_relays_to_hostile_ftpd` (each mode: login, LIST, RETR through the relay; target outside `allowed_targets` refused; `commands()` shows `PASS ****`) (M3, AC14).

### End-to-end tests
`crates/courier-ftp-e2e/tests/`, every test `#[ignore]` + `require_docker!()`. The test
that makes a scenario pass is written in the feature task named in the table (which may
name it differently in its own file); T76 owns the table and the fixtures, and tracks that
every row exists (AC8).

| File | Tests (minimum) | Milestone, owner |
|---|---|---|
| `harness_docker.rs` | `sshd_profiles_start_and_accept_password`, `ftpd_profiles_start_and_greet`, `proxy_profiles_start`, `toxiproxy_cuts_connection`, `ftpd_set_cert_keeps_ip` | M2–M4, T76 |
| `backend_conformance.rs` | `conformance_<profile>` for `vsftpd-plain`, `vsftpd-explicit-tls`, `vsftpd-implicit-tls`, `vsftpd-tls-reuse`, `proftpd-plain`, `proftpd-explicit-tls`, `pureftpd-plain`, `pureftpd-explicit-tls`, and SFTP `password`, `key`, `chroot-sftp`, `windows-like` — the T03 suite (`backend_conformance_tests!(ignored, …)`) with a `ConformanceEnv` whose `make` builds backends through `E2eBackendFactory` (AC13) | M2 (SFTP, T22), M3 (FTP, T14) |
| `ssh_auth.rs` | password, kbd (2 prompts), key ed25519/ecdsa/rsa/encrypted, PPK v2/v3/v3-encrypted, agent (local `ssh-agent`), `maxauth2` method list, `legacy` refused | M2, T20 |
| `ssh_trust.rs` | unknown host key prompts (`PromptPolicy::TrustAlways` stores it, second connect silent); changed key after `regenerate_host_key` is blocked with `Error::HostKey` | M2, T21 |
| `ftp_modes.rs` | `active_only_profile_uses_port`, `pasv_unreachable_falls_back_to_active`, `anonymous_is_read_only`, `fixture_names_listed_exactly_<server>` (all `FIXTURE_TREE` names incl. leading/trailing spaces and the symlink), `mlsd_used_on_proftpd_and_pureftpd`, `list_used_on_vsftpd` (AC15), `maxconn1_second_connection_gets_421` | M3, T11, T13, T14 |
| `ftp_tls.rs` | `tls_reuse_required_transfers`, `self_signed_prompts_then_trust_always_is_silent`, `changed_cert_after_trust_warns`, `expired_cert_prompts`, `wrong_host_cert_prompts`, `explicit_if_available_on_plain_server_warns` | M3, T12 |
| `hostile.rs` (in-process, **not** ignored) | `dotdot_name_does_not_escape_target`, `slash_in_name_is_rejected_or_sanitized`, `nul_and_esc_in_names_are_neutralised`, `huge_reported_size_does_not_preallocate`, `malformed_listing_lines_are_skipped`, `banner_escape_sequences_not_rendered` | M3, T13, T42, T53, T55, T91 |
| `proxies.rs` | `sftp_via_socks5`, `sftp_via_http_connect_auth`, `ftp_passive_via_socks5`, `ftp_active_via_proxy_is_unsupported` | M3, T07 |
| `ftp_proxy.rs` | `ftp_proxy_user_at_host_vsftpd`, `ftp_proxy_site_vsftpd`, `ftp_proxy_open_vsftpd` (`FtpRelayProxy` in front of `vsftpd-plain`: connect, list, download, SHA-256 compare) | M3, T15 |
| `transfers.rs` | `queue_50_mixed_files_up_and_down_<ftp|sftp>` (sizes 0 B–8 MiB, SHA-256 verified), `segmented_download_2gib_sparse_<ftp|sftp>`, `resume_after_cut_<ftp|sftp>` (toxiproxy `LimitData`), `work_stealing_with_throttled_connection`, `connection_limit_backoff_<ftp|sftp>` (`vsftpd-maxconn1`, `maxconn1`), `speed_limit_within_10_percent`, `cancel_on_slow_profile_leaves_session_usable` | M4, T41–T44, T41b |
| `pty_flows.rs` | `first_run_create_vault_and_unlock` (M2), `add_site_with_password_restart_unlock_connect_without_prompt` (M5), `site_manager_connect_upload_verified_on_server` (M5), `edit_in_editor_round_trip` (fake editor `tests/fixtures/editor/fake-editor.sh` appends a line; upload prompt accepted; server file hash changes) (M6) | T60, T31, T59, T62, T63 |
| `sync.rs` | `register_and_second_device_login_with_preview`, `offline_edits_on_both_devices_merge`, `same_field_conflict_newest_wins`, `password_change_logs_out_other_device`, `recovery_with_24_words`, `server_410_triggers_resync` | M7, T84–T88 |
| `teams.rs` | `invite_accept_and_share_site`, `member_removal_rotates_key`, `safety_number_change_blocks_grants` | M8, T89 |

**Running locally:**

```sh
cargo test --workspace                                 # fast suite, no Docker
COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored   # Linux with Docker
COURIER_E2E=1 cargo test -p courier-ftp-e2e --test ftp_tls -- --ignored tls_reuse
cargo test --release -p courier-ftp --features test-hooks --test startup -- --ignored --nocapture
scripts/canary-scan.sh --self-test
```

## Out of scope

- The scenario tests' assertions about feature behaviour (owned by the feature tasks
  listed in the table); this task provides fixtures, drivers and the checklist.
- Windows/macOS e2e (Docker containers must be reachable by bridge IP; the `test-os` job
  covers in-process tests there).
- FileZilla Server and IIS FTP fixtures (not available as Linux containers).
- Load testing of the sync server beyond the T85 concurrency tests.

## Open questions

None. Resolved by the coordinator:
- ~~FTP profile names~~ — feature tasks use `vsftpd-plain` etc. (T71 adopts them).
- ~~Conformance suite location~~ — it lives in T03 at `courier_ftp_core::backend::conformance` behind feature `test-util`.
- ~~`Argon2Cost::TEST` / file keyring~~ — T30 keeps `Argon2Cost::TEST` within its load bounds and honours `COURIER_FTP_KEYRING=file:<dir>` (test-hooks builds only).
- ~~`COURIER_FTP_KEYRING=off`~~ — honoured by T30.
- ~~FTP proxy fixture~~ — the in-process `FtpRelayProxy` is listed above (T15).
- ~~MLSD on vsftpd~~ — MLSD scenarios use proftpd/pure-ftpd profiles.
