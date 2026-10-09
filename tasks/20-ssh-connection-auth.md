# T20 — SSH connection and authentication

**Phase:** C SFTP · **Milestone:** M2 · **Depends on:** T02, T04, T07, T76 · **Crate(s):** `courier-ftp-proto-sftp` (`ssh`, `keys`, `agent` modules), small addition to `courier-ftp-core` (`text::sanitize_server_text`) · **Decisions:** D2 (russh), D3, D13 · **FEATURES.md:** §1 (SFTP keys, Pageant / agent), §2 (logon types)
**Related (integrates with, not blocking):** T21, T30, T59
**Reference:** sverb `crates/sverb-conn/src/ssh/{connect,handler,auth,auth_stub,algorithms,errors,keepalive,testing,test_keys}.rs`, `crates/sverb-conn/src/agent_client.rs`, `crates/sverb-core/src/keychain/formats/{openssh,pem,pkcs8,ppk}.rs`, `tests/fixtures/putty/`, `tests/fixtures/sshd/` — copy and adapt (D13), never depend on sverb.

## Goal

Open an authenticated SSH connection with russh for every SFTP logon type FileZilla
offers: password, ask-for-password, keyboard-interactive (2FA/OTP), key file (OpenSSH,
PEM, PKCS#8, PuTTY `.ppk` v2/v3) and SSH agent / Pageant. The result is an
`SshConnection` on which T22 opens the `sftp` subsystem. Prompts go to the UI through the
core prompt mechanism (T04); no secret is ever logged.

## Context

- **Before:** T02 gives `ServerAddress` (incl. `user`), `LogonType` (incl.
  `KeyFile { key: KeySource, passphrase }`), `KeySource { Path, VaultItem, Inline }`,
  `Charset`, `courier_ftp_core::Error` (incl. `ConnectionLimit`, `Proxy`); T03 gives
  `ConnectInfo` (incl. `try_agent_first`); T04 gives `EventSender`, `SessionLog`,
  `LogMessage`/`LogKind`, `CoreEvent::CredentialAccepted`, `PromptKind::{Password,
  KeyPassphrase, KeyboardInteractive}` with `PasswordPrompt`, `PassphrasePrompt`,
  `KbdInteractivePrompt`, `SecretCacheKey`, and `PromptResponse::{Secret, Answers}`; T07 gives
  `net::connect_tcp(&HostPort, &NetOpts, CancellationToken, &SessionLog) -> Result<NetStream>`
  (DNS, IPv6 preference, HTTP/SOCKS proxies, connect timeout); T76 gives the `sshd` Docker fixture
  with the profiles `password`, `key`, `kbd`, `maxauth2`, `legacy`.
- **After:** T21 plugs a real `HostKeyVerifier` into the seam defined here (until then
  every key is rejected unless a test uses the insecure verifier). T22 builds
  `SftpBackend` on `SshConnection` and calls `SshConnectParams::from_connect_info`. T31
  (saved site), T58 (quickconnect) and T70 (CLI) build the `ConnectInfo`, resolving
  `KeySource::VaultItem` to `Inline` (T03 `ConnectInfo::validate`). T69 renders the password, passphrase and
  keyboard-interactive prompts emitted here. T91 adds the PPK fuzz target body from here.
- sverb already solved this: the auth chain with its two seams (`AuthBackend` = server,
  `AuthIo` = user), RSA signature selection, the attempt cap, server-text sanitising, the
  key format parsers and the agent client. We copy them and change only what differs:
  courier-ftp's logon types decide the method order (sverb uses one fixed order), prompts
  go through `PromptRequest` instead of sverb's session state machine, and there are no
  jump hosts, forwarding, certificates on user keys or connection sharing.

## Technical specification

### Types and APIs

Module layout of `courier-ftp-proto-sftp` added by this task (all russh/ssh-key usage stays
inside `ssh/`, `keys/` and `agent/`, as in sverb):

```
src/lib.rs            pub mod ssh; pub mod keys; pub mod agent; (+ backend in T22)
src/ssh/mod.rs        SshConnection, SshConnectParams, SshSessionInfo
src/ssh/connect.rs    TCP → handshake → auth flow
src/ssh/handler.rs    russh client::Handler impl, HostKeyVerifier seam
src/ssh/algorithms.rs preference lists, to_russh()
src/ssh/auth.rs       the chain (AuthBackend / AuthIo seams), RusshBackend, PromptIo
src/ssh/errors.rs     SshError + mapping to core::Error
src/ssh/testing.rs    in-process russh server (feature "test-util")
src/keys/{mod,openssh,pem,pkcs8,ppk}.rs   private-key loading
src/agent/mod.rs      AgentConnector / Agent (Unix socket, Windows pipe, Pageant)
```

Core addition (in `courier-ftp-core`; key source, logon type and `try_agent_first` are
T02/T03's `KeySource`, `LogonType::KeyFile { key, passphrase }` and
`ConnectInfo.try_agent_first` — no SFTP-specific option struct):

```rust
// courier_ftp_core::text
/// Make server-provided text safe to show: strips ANSI/C1 escape sequences, control
/// characters (keeps `\n`, maps `\t` to a space) and bidi overrides; caps at `max_chars`
/// characters (`…` marks a cut). Copied from sverb `ssh/auth.rs::sanitize_server_text`.
pub fn sanitize_server_text(text: &str, max_chars: usize) -> String;
```

`courier_ftp_proto_sftp::ssh`:

```rust
/// Everything needed to open one SSH connection. Built by T22 from `ConnectInfo` + `Settings`.
pub struct SshConnectParams {
    pub host: String,                       // as configured (not the resolved IP)
    pub port: u16,                          // default 22
    pub user: String,                       // ServerAddress.user (required for SFTP)
    pub logon: SshLogon,
    pub password: Option<SecretString>,     // Normal { password }: stored; otherwise None
    /// LogonType::KeyFile key: `Path` or `Inline` (a `VaultItem` here → InvalidInput).
    pub key: Option<KeySource>,
    /// LogonType::KeyFile passphrase (stored in the vault). Tried before prompting.
    pub key_passphrase: Option<SecretString>,
    /// Shown in passphrase prompts/log: the path, or "vault key of <ConnectInfo.label>".
    pub key_label: String,
    /// ConnectInfo.try_agent_first (FileZilla "try agent first"; T91 §8 approval already
    /// done by the binary).
    pub try_agent_first: bool,
    /// T04 `can_save` for password/passphrase prompts (set by T22, see Behaviour).
    pub can_save: bool,
    pub net: NetOpts,                       // T07: proxy, IPv6 preference, connect timeout
    pub timeout: Duration,                  // connection.timeout_secs (default 20 s)
    pub keepalive: Option<Duration>,        // connection.keepalive ? keepalive_interval_secs (30 s) : None
}
impl SshConnectParams {
    /// Copies secrets with `LogonType::duplicate`. Errors: InvalidInput for Anonymous/
    /// Account logons, missing user, or an unresolved `KeySource::VaultItem`.
    pub fn from_connect_info(info: &ConnectInfo, settings: &Settings, can_save: bool) -> Result<Self, Error>;
}

/// The SFTP-relevant logon types (T02 `LogonType` minus Anonymous/Account).
pub enum SshLogon { Normal, AskForPassword, Interactive, KeyFile, Agent }

impl SshLogon {
    /// `Err(Error::InvalidInput)` for `Anonymous` and `Account` (not valid for SFTP).
    pub fn from_logon_type(t: &LogonType) -> Result<Self, Error>;
}

/// What was negotiated (shown by the server info dialog, T57).
#[derive(Debug, Clone, Default)]
pub struct SshSessionInfo {
    pub server_version: String,   // sanitized, e.g. "SSH-2.0-OpenSSH_9.6p1"
    pub kex: String,
    pub host_key_algorithm: String,
    pub host_key_fingerprint: String, // "SHA256:…"
    pub cipher: String,
    pub mac: String,              // "(implicit)" for AEAD ciphers
    pub compression: String,
    pub auth_method: String,      // method that succeeded: "password", "publickey", …
}

/// An authenticated SSH connection.
pub struct SshConnection { /* russh client::Handle<ClientHandler>, Arc<Shared>, info */ }

impl SshConnection {
    /// TCP (through T07) → SSH handshake (host key via `verifier`) → authentication.
    /// Prompts are sent through `log.events` (T04) for session `log.session` and awaited;
    /// `cancel` aborts at any point.
    pub async fn connect(
        params: SshConnectParams,
        verifier: Arc<dyn HostKeyVerifier>,
        agent: Option<Arc<dyn AgentConnector>>,
        log: &SessionLog,
        cancel: CancellationToken,
    ) -> Result<Self, courier_ftp_core::Error>;

    /// Open a `session` channel and request the `sftp` subsystem (used by T22).
    pub async fn open_subsystem(&self, name: &str) -> Result<russh::ChannelStream<russh::client::Msg>, Error>;
    pub fn info(&self) -> &SshSessionInfo;
    /// False once the transport closed (keepalive timeout, server disconnect).
    pub fn is_open(&self) -> bool;
    /// Why the transport closed, if it did (for the error message).
    pub fn end_cause(&self) -> Option<String>;
    /// `SSH_MSG_DISCONNECT` (reason ByApplication), bounded by 2 s.
    pub async fn disconnect(self);
}
```

`ssh::handler` — the host-key seam (T21 provides the real implementation):

```rust
/// The key the server presented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKey {
    pub key_type: String,       // "ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa", …
    pub bits: u32,              // 256 for ed25519, modulus size for RSA
    pub blob_base64: String,    // the known_hosts key field
    pub fingerprint_sha256: String, // "SHA256:<base64 no padding>"
    pub fingerprint_md5: String,    // "MD5:aa:bb:…"
}

#[async_trait]
pub trait HostKeyVerifier: Send + Sync + fmt::Debug {
    /// Decide about `key` for `host:port`. May ask the user (T21 sends the prompt and
    /// awaits it here; the handshake is suspended meanwhile).
    async fn verify(&self, host: &str, port: u16, key: &ServerKey, ctx: &VerifyCtx<'_>) -> HostKeyVerdict;
    /// Key types already trusted for host:port, moved to the front of the host-key
    /// algorithm preference (avoids a needless "unknown key" for a second key type).
    fn known_key_types(&self, host: &str, port: u16) -> Vec<String> { Vec::new() }
}

/// Session id, event sender and cancel token for prompts.
pub struct VerifyCtx<'a> { pub session: SessionId, pub events: &'a EventSender, pub cancel: &'a CancellationToken }

pub enum HostKeyVerdict { Accept, Reject(String /* user-facing reason */) }

/// Default until T21: rejects every key with "host key verification is not available yet".
pub struct UnverifiedHostKeys;
/// Tests only (`test-util` feature): accepts everything, logs a warning.
#[cfg(any(test, feature = "test-util"))]
pub struct InsecureAcceptAnyHostKey;
```

`ssh::auth` — the chain (sverb's design, logon-type driven):

```rust
#[async_trait] pub trait AuthBackend: Send { /* none, password, publickey(key, hash),
    agent_identity(agent, identity, hash), kbd_start, kbd_respond, rsa_support */ }
#[async_trait] pub trait AuthIo: Send {
    fn log(&mut self, kind: LogKind, text: String);
    /// Ask the user; `Ok(None)` = cancelled.
    async fn ask(&mut self, prompt: AuthPrompt) -> Result<Option<AuthAnswer>, Error>;
    /// The answer to prompt `id` was part of the successful authentication.
    fn accepted(&mut self, id: PromptId);
}
pub async fn run_chain(target: &ChainTarget<'_>, backend: &mut dyn AuthBackend,
                       io: &mut dyn AuthIo, agent: Option<Arc<dyn AgentConnector>>) -> Result<String /*method*/, SshError>;
pub const MAX_AUTH_ATTEMPTS: u32 = 6;   // requests after `none` (OpenSSH MaxAuthTries default)
pub const PASSWORD_PROMPTS: u8 = 3;     // password prompts after a rejected/absent one
pub const PASSPHRASE_TRIES: u8 = 3;     // passphrase prompts per key
pub const KBD_ROUNDS: u8 = 3;           // keyboard-interactive conversations per connection
pub const MAX_KBD_PROMPTS: usize = 10;  // prompts in one info request (more → method fails)
pub const MAX_PROMPT_TEXT: usize = 512; // chars per server prompt/name/instruction
pub const MAX_BANNER_CHARS: usize = 4096; pub const MAX_BANNER_LINES: usize = 40;
```

`keys`:

```rust
pub const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;
pub enum KeyFormat { OpenSsh, PemPkcs1Rsa, PemSec1Ec, Pkcs8, Pkcs8Encrypted, PpkV2, PpkV3, PublicOnly, Unknown }
pub fn detect(text: &str) -> KeyFormat;
pub fn is_encrypted(text: &str) -> bool;
/// Parse (and decrypt with `passphrase` when encrypted) into a russh/ssh-key PrivateKey.
pub fn decode(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, KeyError>;
pub enum KeyError { NeedsPassphrase, WrongPassphrase, Format, Unsupported(String), TooLarge, Read(String) }
```

`agent` (copied from sverb `agent_client.rs`):

```rust
#[async_trait] pub trait AgentConnector: Send + Sync + fmt::Debug { async fn connect(&self) -> Result<Box<dyn Agent>, AgentError>; }
#[async_trait] pub trait Agent: Send { async fn identities(&mut self) -> Result<Vec<AgentIdentity>, AgentError>;
    async fn sign(&mut self, id: &AgentIdentity, hash: Option<HashAlg>, data: Vec<u8>) -> Result<Vec<u8>, AgentError>; }
pub struct SystemAgent; // Unix: $SSH_AUTH_SOCK; Windows: $SSH_AUTH_SOCK if it names a pipe,
                        // then \\.\pipe\openssh-ssh-agent, then Pageant (russh's Pageant client)
```

### Behaviour

**Connect flow** (`SshConnection::connect`), each step logged to the session log
(`LogMessage`, T04) as FileZilla does:

| # | Step | Session log (`LogKind`) | Bound |
|---|---|---|---|
| 1 | `SshLogon::from_logon_type`; Anonymous/Account → `Error::InvalidInput("Anonymous and Account logons are not available for SFTP")`, no network I/O | — | — |
| 2 | `net::connect_tcp` (T07) to `host:port` with `NetOpts` (proxy applies here) | T07's `Resolving…`/`Connecting to …` lines | `timeout` per address (T07) |
| 3 | `russh::client::connect_stream(config, stream, handler)`; the handler calls `verifier.verify` in `check_server_key` | `Status: Server version: <sanitized>` ; `Debug(3): kex=… hostkey=… cipher=… mac=…` | handshake `timeout`, **not counting** time spent in host-key prompts (deadline restarts after the answer, as sverb) |
| 4 | Auth banner (`Handler::auth_banner`) | each line as `Status`, sanitized, capped at 40 lines / 4096 chars | — |
| 5 | Authentication chain (below) | `Status: Using username "alice".`, one `Status` per method tried, `Status: Authenticated using <method>.` or `Error: …` | each auth request `timeout`; prompts not counted |
| 6 | Start keepalive (russh `keepalive_interval`, `keepalive_max = 3`) | — | dead link detected after 3 × interval (90 s at defaults) |

`russh::client::Config` (fixed values unless noted):

| Field | Value | Why |
|---|---|---|
| `client_id` | `SSH-2.0-courier-ftp_<CARGO_PKG_VERSION>` | identifies us in server logs |
| `preferred` | `algorithms::to_russh(&preferences(known_key_types))` | see below |
| `keepalive_interval` | `Some(connection.keepalive_interval_secs)` if `connection.keepalive`, else `None` | T05 defaults 30 s / on |
| `keepalive_max` | 3 | as sverb |
| `inactivity_timeout` | `None` | idle connections are kept alive by keepalive; T03 closes idle sessions |
| `window_size` | 16 MiB (`16 * 1024 * 1024`) | T41b: window must not throttle a fast link |
| `maximum_packet_size` | 65 535 | russh's maximum |
| `nodelay` | true | interactive latency of SFTP requests |

**Algorithm preferences** (`algorithms.rs`; names not implemented by the pinned russh are
dropped by `to_russh`, as in sverb). Faster AEAD ciphers first (T41b §3). The
`compat` entries are appended last, so they are only chosen when the server offers
nothing better; everything else (CBC, 3DES, `diffie-hellman-group1-sha1`, `ssh-dss`) is
not offered at all.

| Kind | Preference order |
|---|---|
| KEX | `mlkem768x25519-sha256`, `curve25519-sha256`, `curve25519-sha256@libssh.org`, `ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, `ecdh-sha2-nistp521`, `diffie-hellman-group16-sha512`, `diffie-hellman-group18-sha512`, `diffie-hellman-group14-sha256`, compat: `diffie-hellman-group14-sha1` |
| Host key | (types from `verifier.known_key_types` first), `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `rsa-sha2-512`, `rsa-sha2-256`, compat: `ssh-rsa` |
| Cipher | `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`, `chacha20-poly1305@openssh.com`, `aes128-ctr`, `aes192-ctr`, `aes256-ctr` |
| MAC | `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256`, `hmac-sha2-512`, compat: `hmac-sha1` |
| Compression | `none` |

No common algorithm → `Error::Connection("No common <kind>: server offers <list>.")`
(sverb `negotiation_message`, without the legacy hint).

**Authentication chain.** First `none` (learns the server's method list; a server that
accepts `none` ends the chain). Then the steps for the logon type, in order, skipping any
step whose method the latest `USERAUTH_FAILURE` does not list. Every request after
`none` counts against `MAX_AUTH_ATTEMPTS` (6; each key and each agent identity is one).

| Logon type | Steps |
|---|---|
| `Normal` | [A] if `try_agent_first` → [P1] stored password → [K] keyboard-interactive (stored password auto-answers once) → [P2] password prompts |
| `AskForPassword` | [A] if `try_agent_first` → [P2] password prompts (first prompt has no "try again" note) → [K] keyboard-interactive (the password typed in [P2] auto-answers once) |
| `Interactive` | [A] if `try_agent_first` → [K] keyboard-interactive, every info request shown to the user → [P2] password prompts **only** if the server lists `password` but not `keyboard-interactive` |
| `KeyFile` | [F] key file only (FileZilla behaviour: no password fallback) |
| `Agent` | [A] agent identities only |

- **[A] agent:** `AgentConnector::connect()`; unreachable agent or zero identities →
  log `Status: No SSH agent available` / `SSH agent has no keys` and continue. One
  `publickey` request per identity, in the agent's order; log
  `Status: Trying agent key "<comment>" (<type> <SHA256 fp>)`.
- **[P1] stored password:** one `password` request.
- **[P2] password prompts:** up to `PASSWORD_PROMPTS` (3) prompts, each followed by one
  `password` request. Prompt payload: `retry` = a previous password for this connection
  was rejected. Cancel → abort the whole connect with `Error::Cancelled`.
- **[K] keyboard-interactive:** up to `KBD_ROUNDS` (3) conversations; within one, each
  `INFO_REQUEST` with zero prompts is answered with zero answers without asking; an
  info request with exactly one non-echo prompt whose text contains `password`
  (case-insensitive) is answered with the stored/typed password **once per
  connection**; everything else becomes one `KeyboardInteractive` prompt (name,
  instruction and prompt texts sanitized with `MAX_PROMPT_TEXT`; more than
  `MAX_KBD_PROMPTS` prompts → this method fails with a logged error). Several rounds
  (password then OTP) are handled by the loop. Answers are `SecretString`s dropped
  right after `kbd_respond`. Cancel → `Error::Cancelled`.
- **[F] key file:** read the file (`KeySource::Path`) with a 64 KiB cap (larger →
  `Error::InvalidInput("<path> is not a private key (larger than 64 KiB)")`), or take
  `KeySource::Inline(text)`. `keys::decode`: unencrypted → use. Encrypted → stored
  `key_passphrase` first (silently), then up to `PASSPHRASE_TRIES` (3) `KeyPassphrase`
  prompts (`retry` set after a wrong one). After 3 wrong passphrases →
  `Error::Auth("Wrong passphrase for key <label> (3 attempts)")` and **no** publickey
  request is sent. Log `Status: Trying public key <label> (<type> <SHA256 fp>)`.
- **RSA signatures** (keys and agent identities): `Handle::best_supported_rsa_hash()`
  → `rsa-sha2-512`, else `rsa-sha2-256`; a server without `server-sig-algs` gets
  `ssh-rsa` (SHA-1) and a `Status` warning line `Server does not support SHA-2 RSA
  signatures; using ssh-rsa (SHA-1)`. A server that offers `server-sig-algs` without any
  RSA algorithm → the RSA key is skipped.
- **Partial success** (`partial_success = true`, e.g. `AuthenticationMethods
  publickey,password`): the step counts as passed; the chain continues with the next
  step that the new method list allows (sverb `partial_success_continues`).
- **End:** success → `Status: Authenticated using <method>.` and `io.accepted(id)` for
  every prompt whose answer was used in a successful or partially successful request
  (T69 saves a typed password/passphrase only after this, see T04 event below). All
  steps exhausted / cap hit / server lists no method we can use →
  `Error::Auth(msg)` with `msg = "Permission denied (tried: password, keyboard-interactive; server accepts: publickey)"`.
- **Prompts** are sent with `EventSender::prompt_tracked(session, kind, Some(&cancel))`
  (T04) so the `PromptId` is known for `CredentialAccepted`; the wait has no timeout (T04) but `cancel` aborts it (`Error::Cancelled`).
  A server that drops the connection while the user is answering (LoginGraceTime,
  default 120 s on OpenSSH) ends the connect with
  `Error::Connection("The server closed the connection while waiting for your answer")`.
- **Prompt payloads** (T04 types):
  `PromptKind::Password(PasswordPrompt { purpose: Login, target: "alice@web01.example.com:22", retry, attempt, max_attempts: 3, cache_key, can_save })`,
  `PromptKind::KeyPassphrase(PassphrasePrompt { key_label, retry, attempt, max_attempts: 3, cache_key, can_save })`,
  `PromptKind::KeyboardInteractive(KbdInteractivePrompt { host: "web01.example.com:22", name, instructions, prompts: Vec<KbdField { text, echo }> })`;
  answers `PromptResponse::Secret { value, .. }` / `PromptResponse::Answers(Vec<SecretString>)`.
  `cache_key` = `SecretCacheKey::Password { protocol: Sftp, host (ASCII-lowercased), port, user }` or
  `SecretCacheKey::Passphrase { key: path or key_label }` (lets T69 answer from its
  "remember for this session" cache; T69 never uses the cache when `retry` is true).
  `can_save` = `SshConnectParams.can_save`, set by T22 (`ConnectInfo.site_id.is_some()`
  and `vault.store_passwords`; T69 additionally disables saving while the vault is locked).
- **Accepted credentials**: after success the chain calls
  `EventSender::credential_accepted(session, prompt_id)` (→ `CoreEvent::CredentialAccepted`)
  for each accepted prompt (no
  secret in the event: the UI still holds what the user typed and saves/caches it only
  now).
- **Cancellation**: `cancel` is checked with `tokio::select!` around TCP connect,
  handshake, every auth request and every prompt wait; cancelled → the TCP stream is
  dropped (no disconnect message) and `Error::Cancelled` is returned within 100 ms.
- **Disconnect**: `disconnect()` sends `SSH_MSG_DISCONNECT(ByApplication, "", "en")`,
  waits at most 2 s, then drops the handle.

### Data formats and configuration

Settings read (all from T05, none added here):

| Key | Type | Default | Use |
|---|---|---|---|
| `connection.timeout_secs` | u32 | 20 | TCP connect per address, handshake, each auth request |
| `connection.keepalive` | bool | true | russh keepalive on/off |
| `connection.keepalive_interval_secs` | u32 | 30 | russh `keepalive_interval` |
| `connection.prefer_ipv6`, `proxy.generic` | — | — | passed through `NetOpts` (T07) |

Private key formats accepted by `keys::decode` (copied from sverb `keychain/formats`):

| Format | Detection (first line) | Encryption |
|---|---|---|
| OpenSSH | `-----BEGIN OPENSSH PRIVATE KEY-----` | bcrypt-pbkdf + aes256-ctr/aes256-gcm (ssh-key) |
| PEM PKCS#1 RSA / SEC1 EC | `-----BEGIN RSA PRIVATE KEY-----` / `-----BEGIN EC PRIVATE KEY-----` | legacy `Proc-Type: 4,ENCRYPTED` AES-128/192/256-CBC (EVP_BytesToKey MD5) |
| PKCS#8 | `-----BEGIN PRIVATE KEY-----` / `-----BEGIN ENCRYPTED PRIVATE KEY-----` | PBES2 (PBKDF2 + AES-CBC) |
| PuTTY v2 | `PuTTY-User-Key-File-2:` | `aes256-cbc`, key = SHA1(0‖pw)‖SHA1(1‖pw), MAC HMAC-SHA1 |
| PuTTY v3 | `PuTTY-User-Key-File-3:` | `aes256-cbc`, Argon2id/i/d (bounded: memory ≤ 1 GiB, passes ≤ 1000, lanes ≤ 64, memory×passes ≤ 16 GiB·pass), MAC HMAC-SHA256 checked before use |

Key types: Ed25519, ECDSA P-256/P-384/P-521, RSA ≥ 2048 bits. DSA, PPK v1, RSA < 2048
→ `KeyError::Unsupported`. A `.pub` file selected as key → `KeyError::Format` with the
message "This is a public key; choose the private key file (without .pub)".

Test fixtures (test-only keys, committed): `crates/courier-ftp-proto-sftp/tests/keys/`
with `id_ed25519`, `id_ed25519_enc` (passphrase `fixture`), `id_ecdsa_p256`, `id_rsa4096`,
`id_rsa_pkcs1.pem`, `id_rsa_pkcs1_enc.pem`, `id_ec_sec1.pem`, `id_ed25519_pkcs8.pem`,
`id_rsa_pkcs8_enc.pem`, `id_ed25519.ppk`/`_v3.ppk`, `id_rsa_v2_enc.ppk`, `id_ecdsa_v3_enc.ppk`
(copied/derived from sverb `tests/fixtures/putty` and `tests/fixtures/sshd/keys`), each
with its expected `SHA256:` fingerprint in `fingerprints.txt`; a `README.md` warning that
they are test-only. The same public keys are in the T76 `sshd` fixture's `authorized_keys`.

### Errors

Internal `SshError` (sverb's enum trimmed: no proxy-command, approval, jump variants)
maps to `courier_ftp_core::Error`:

| Situation | `core::Error` | Message the user sees (log `Error:` line + dialog) |
|---|---|---|
| Anonymous/Account logon | `InvalidInput` | "Anonymous and Account logons are not available for SFTP" |
| DNS / TCP / proxy failure | from T07 (`Connection`, `Timeout`, `Proxy`) | T07's message |
| Handshake not finished in `timeout` | `Timeout` | "Connection timed out during the SSH handshake" |
| No common algorithm | `Connection` | "No common cipher: server offers aes128-cbc, 3des-cbc." |
| Host key rejected (verifier or user) | `HostKey(reason)` | reason from T21, e.g. "Host key rejected by the user" |
| Auth exhausted / cap / no usable method | `Auth` | "Permission denied (tried: …; server accepts: …)" |
| Too many wrong passphrases | `Auth` | "Wrong passphrase for key <label> (3 attempts)" |
| Key unreadable / bad format / too large | `InvalidInput` | "Could not read key file <path>: …" / "Not a private key format courier-ftp can read (OpenSSH, PEM, PKCS#8, PuTTY)" |
| Prompt cancelled / token cancelled | `Cancelled` | "Connection cancelled" (Status, not Error) |
| Keepalive timeout | `Connection` | "Connection lost (no response for 90 s)" |
| Server disconnect with reason code 12 (`SSH_DISCONNECT_TOO_MANY_CONNECTIONS`), e.g. OpenSSH `MaxStartups`/`MaxSessions` | `ConnectionLimit` | "Too many connections: <sanitized reason>" (T41 lowers the per-server limit; T03 does not retry) |
| Server disconnect (other reasons) | `Connection` | "Server closed the connection: <sanitized reason>" |
| Other russh/IO error | `Connection` | "SSH connection failed: <error>" |

`Connection` and `Timeout` are `is_transient()` (T02) so `SessionHandle` (T03) reconnects
once; `Auth`, `HostKey`, `Proxy`, `InvalidInput`, `Cancelled` are not, and
`ConnectionLimit` is transient for T41 but never retried by `SessionHandle::connect`.

### Security and logging

- Passwords, passphrases and keyboard-interactive answers are `SecretString` from the
  prompt until the russh call; russh needs `&str`/`String` for password auth — the
  temporary is created at the call (`expose()`), dropped right after; answer buffers are
  dropped after each request (sverb `Answers` drop counter test). Decrypted private keys
  are `ssh_key::PrivateKey` (zeroizes on drop) behind `Arc`, dropped when auth ends.
- Never logged at any level (tracing or session log): passwords, passphrases, kbd
  answers, private key text, key file contents. Public key fingerprints and comments may
  appear in the session log.
- `tracing` at `info`+ logs only the `SessionId` and outcome (T91 §4: no host, user,
  path). Host, port, user, negotiated algorithms at `debug`.
- Server-controlled strings (version banner, auth banner, kbd name/instruction/prompts,
  disconnect reasons) go through `sanitize_server_text` before reaching any log line or
  prompt; banner capped at 40 lines / 4096 chars, prompt texts at 512 chars.
- Key files: read with a 64 KiB cap; PPK parser bounds memory and Argon2 cost (above) so
  a hostile file cannot hang or exhaust memory; PPK MAC checked before the private blob
  is parsed.
- `try_agent_first` and `KeySource::Path` from a synced site are local-acting fields
  (T91 §8); the approval check happens in the binary before `ConnectInfo` is built —
  this crate trusts its input.
- `InsecureAcceptAnyHostKey` exists only with `cfg(test)` or feature `test-util`; the
  binary never enables `test-util` (checked by `scripts/check-layering.py`, T00).

## Implementation steps

1. Add workspace deps (`russh = "0.64.1"`, `ssh-key = "=0.7.0-rc.11"` with `ed25519`,
   `encryption`; `async-trait`, `md-5`, `aes`, `cbc`, `argon2`, `hmac`, `sha1`, `sha2`,
   `base64`, `rsa`, `pkcs8`, `sec1`, `zeroize`) to `courier-ftp-proto-sftp`; module
   skeleton; `test-util` feature. Bump `rust-version` if russh requires it (see Open
   questions).
2. `courier_ftp_core::text::sanitize_server_text` (copy + tests);
   `SshConnectParams::from_connect_info` (T02 `KeySource`/`LogonType::KeyFile`, T03
   `ConnectInfo.try_agent_first`).
3. `keys/`: copy sverb's OpenSSH, PEM, PKCS#8 and PPK parsers; fixtures; `detect`,
   `decode`; unit tests; PPK property test (fuzz twin).
4. `agent/`: copy sverb `agent_client.rs` (Unix socket, Windows pipe, Pageant) with the
   `AgentConnector` seam; fake agent for tests.
5. `ssh/algorithms.rs` + `ssh/errors.rs` (mapping table above).
6. `ssh/handler.rs`: `ClientHandler` (check_server_key → verifier, kex_done → info,
   auth_banner → log, disconnected → end cause), `HostKeyVerifier` seam,
   `UnverifiedHostKeys`, `InsecureAcceptAnyHostKey`.
7. `ssh/auth.rs`: chain with `AuthBackend`/`AuthIo`, logon-type step table, scripted unit
   tests (port sverb `auth_tests.rs`).
8. `ssh/connect.rs` + `SshConnection`: flow, timeouts, cancellation, keepalive,
   `PromptIo` (AuthIo over `EventSender` prompts), `CredentialAccepted`.
9. `ssh/testing.rs`: in-process russh server (configurable methods, kbd script,
   accepted keys, silent mode) and loopback tests.
10. e2e tests in `courier-ftp-e2e` against the `sshd` profiles; PPK fuzz target registered
    with T91.

## Acceptance criteria

- [ ] AC1 `cargo clippy -p courier-ftp-proto-sftp --all-targets --all-features -- -D warnings`, `cargo test -p courier-ftp-proto-sftp`, `cargo doc` (T00 gates) pass; `cargo tree -p courier-ftp-proto-sftp -i ratatui` and `-i clap` print nothing.
- [ ] AC2 `Normal` with the right stored password authenticates against the in-process server and the `password` Docker profile; with a wrong stored password the user gets exactly 3 `Password` prompts (`retry = true`) before `Error::Auth`.
- [ ] AC3 `Interactive` completes a two-round keyboard-interactive conversation (password, then OTP `424242`) against the in-process server and the `kbd` profile; each round produces one `KeyboardInteractive` prompt with the sanitized texts and echo flags.
- [ ] AC4 `KeyFile` authenticates with every fixture key (ed25519, ECDSA P-256, RSA 4096; OpenSSH, PEM PKCS#1/SEC1, PKCS#8, PPK v2 and v3; encrypted and unencrypted) against the in-process server; ed25519, RSA (OpenSSH) and ed25519 PPK v3 also against the `key` profile; RSA uses `rsa-sha2-512` (asserted on the server side).
- [ ] AC5 `keys::decode` yields the fingerprint listed in `fingerprints.txt` for every fixture.
- [ ] AC6 Wrong passphrase: exactly 3 `KeyPassphrase` prompts, then `Error::Auth("Wrong passphrase …")`; the server records zero `publickey` requests.
- [ ] AC7 `Agent` and `try_agent_first` authenticate through an in-process agent (Unix socket test); unreachable agent is skipped with a `Status` line. Windows OpenSSH agent and Pageant: manual check recorded in this file.
- [ ] AC8 The chain never sends more than 6 requests after `none`; against `maxauth2` the error is `Error::Auth` naming the tried methods.
- [ ] AC9 Cancelling the token during TCP connect, handshake, an auth request or a pending prompt returns `Error::Cancelled` within 100 ms (paused-time and loopback tests).
- [ ] AC10 A server that accepts TCP but never sends its version string fails with `Error::Timeout` after `timeout` (test with `timeout = 1 s`, asserts 1.0–1.5 s).
- [ ] AC11 Host-key prompt time does not count against the handshake timeout (verifier that sleeps 3 s with `timeout = 1 s` still connects).
- [ ] AC12 Anonymous/Account logon, a missing user and an unresolved `KeySource::VaultItem`
  return `Error::InvalidInput` without opening a socket.
- [ ] AC18 A server that disconnects with reason 12 (too many connections) yields
  `Error::ConnectionLimit`; other disconnect reasons yield `Error::Connection`.
- [ ] AC13 Against the `legacy` profile (group14-sha1 + aes128-cbc only) the connect fails with `Error::Connection` whose message starts with "No common"; against default OpenSSH the negotiated cipher is `aes128-gcm@openssh.com` or `aes256-gcm@openssh.com` (asserted via `SshSessionInfo`).
- [ ] AC14 Auth banner and kbd texts containing ESC sequences, C1 controls and bidi overrides reach the log/prompt without them, and are capped as specified.
- [ ] AC15 `CredentialAccepted` is emitted only for prompts whose answers led to (partial) success; rejected answers produce none.
- [ ] AC16 Canary test: with `COURIER_FTP_LOG_LEVEL=trace`, session log captured, and canary password/passphrase/OTP values used in AC2–AC6, no canary appears in the tracing output or session log (T91 canary scan also passes in CI).
- [ ] AC17 PPK parser never panics on arbitrary input (proptest twin of the `ppk_parse` fuzz target, 10 000 cases) and rejects Argon2 parameters above the bounds without running Argon2.

## Tests

### Unit tests
- `keys::tests::decode_every_fixture_matches_fingerprint` — AC5.
- `keys::tests::encrypted_fixtures_need_passphrase` / `wrong_passphrase_is_reported` — AC6 (key side).
- `keys::tests::public_key_file_is_rejected_with_hint`, `dsa_and_small_rsa_are_unsupported`, `file_over_64k_rejected` — formats.
- `keys::ppk::tests::{v2_mac_checked_before_parse, v3_argon2_bounds_rejected, tampered_private_blob}` (port sverb `ppk_tests.rs` t02–t04) — AC17.
- `text::tests::sanitize_strips_csi_osc_c1_and_bidi`, `sanitize_caps_length_with_ellipsis` — AC14.
- `auth::tests::normal_tries_stored_password_then_prompts_three_times` — AC2.
- `auth::tests::ask_for_password_typed_password_answers_kbd_once` — chain table.
- `auth::tests::interactive_two_rounds_two_prompts` — AC3.
- `auth::tests::interactive_falls_back_to_password_prompt_when_no_kbd` — chain table.
- `auth::tests::keyfile_never_falls_back_to_password` — chain table.
- `auth::tests::wrong_passphrase_three_times_sends_no_publickey` — AC6.
- `auth::tests::try_agent_first_offers_each_identity_before_password` — AC7.
- `auth::tests::attempt_cap_is_six` — AC8.
- `auth::tests::rsa_hash_selection_sha512_sha256_sha1_skip` — RSA rules.
- `auth::tests::partial_success_continues_with_next_allowed_method`.
- `auth::tests::cancelled_prompt_aborts_with_cancelled` — AC9.
- `auth::tests::accepted_only_after_success` — AC15.
- `auth::tests::answer_buffers_dropped_after_request` (sverb t18) — security.
- `auth::tests::kbd_more_than_ten_prompts_fails_method`.
- `errors::tests::mapping_table` — every row of the Errors table.
- `algorithms::tests::known_key_types_move_to_front`, `compat_entries_are_last`, `unsupported_names_dropped`.
- `logon::tests::anonymous_and_account_are_invalid_input`,
  `params_reject_missing_user_and_unresolved_vault_key` — AC12.
- `errors::tests::disconnect_reason_12_is_connection_limit` — AC18.

### Property / fuzz tests
- `keys::ppk::props::parse_never_panics` (proptest, 10 000 cases; body shared with `fuzz/fuzz_targets/ppk_parse.rs`, T91) — AC17.
- `text::props::sanitize_output_has_no_control_chars` (proptest over arbitrary strings) — AC14.

### Snapshot tests
Not applicable (no UI in this task; prompts are rendered by T69).

### Integration tests
In `crates/courier-ftp-proto-sftp/tests/`, against `ssh::testing::TestServer` (in-process
russh server on `127.0.0.1:0`):
- `loopback_password_auth` — AC2.
- `loopback_kbd_two_rounds` — AC3.
- `loopback_keyfile_every_fixture` — AC4 (server asserts `rsa-sha2-512` for RSA).
- `loopback_agent_auth_unix` (`#[cfg(unix)]`, in-process agent on a temp socket) — AC7.
- `loopback_handshake_timeout_silent_server` — AC10.
- `loopback_prompt_time_not_counted` — AC11.
- `loopback_cancel_at_each_stage` — AC9.
- `loopback_banner_sanitized` — AC14.
- `loopback_no_secrets_in_logs` (trace subscriber + session-log capture, canary values) — AC16.
- `loopback_server_disconnect_while_prompting` — "server closed the connection while waiting" message.
- `loopback_too_many_connections_disconnect` (test server sends `DISCONNECT` code 12 after the handshake) — AC18.

### End-to-end tests
In `crates/courier-ftp-e2e/tests/ssh_auth.rs`, `#[ignore]`, `require_docker!`, `COURIER_E2E=1` (T76):
- `e2e_password_profile` — AC2.
- `e2e_kbd_profile_otp` — AC3.
- `e2e_key_profile_ed25519_rsa_ppk` — AC4.
- `e2e_maxauth2_reports_methods` — AC8.
- `e2e_legacy_profile_no_common_algorithm` and `e2e_default_negotiates_gcm` — AC13.

Manual check (recorded below when done): Windows 11 OpenSSH agent and Pageant 0.80+ with
an ed25519 key — AC7.

## Out of scope

- Host-key decisions and the trust store (T21); SFTP subsystem and file operations (T22).
- Jump hosts, port/agent forwarding, OpenSSH user certificates, GSSAPI/Kerberos (D8),
  `exec` channels, connection multiplexing across backends.
- Per-site opt-in for CBC/3DES/`ssh-dss`/`diffie-hellman-group1-sha1` (see Open questions).
- Importing keys into the vault (`ssh-key` items, T31/T59) and the UI for prompts (T69).

## Open questions

1. **MSRV:** russh 0.64.1 declares `rust-version = 1.89`; the workspace says `1.85`
   (T01/T00 own `rust-version`). Raise the workspace MSRV to at least 1.89 (sverb uses 1.95)?
2. **Legacy servers:** should a site be able to opt into CBC ciphers, `ssh-dss` and
   `diffie-hellman-group1-sha1` (very old embedded SFTP servers)? FileZilla still
   supports some of them; this task does not.
3. **`ssh-rsa` (SHA-1) fallback** is used automatically for servers without
   `server-sig-algs` (OpenSSH < 7.2), with a warning line. Keep automatic, or require a
   per-site opt-in like sverb?
