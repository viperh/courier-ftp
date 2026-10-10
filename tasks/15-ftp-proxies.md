# T15 — FTP proxies

**Phase:** B FTP · **Milestone:** M3 · **Depends on:** T05, T10 · **Crate(s):** `courier-ftp-proto-ftp` (`ftp_proxy` module), `courier-ftp-core` (`settings` module: `validate_ftp_proxy` for T05's `FtpProxySettings`) · **Decisions:** D1, D3/D4 (proxy password in the vault) · **FEATURES.md:** §1 (FTP proxies: USER@HOST, SITE, OPEN, custom scripts)
**Reference:** sverb `crates/sverb-conn/src/proxy/command.rs` and `proxy/tests.rs` (proxy configuration validated up front, credentials never logged, scripted proxy tests).

## Goal

Support FileZilla's "FTP Proxy" types: the client connects to an FTP proxy server and
tells it, with FTP commands, which real server to reach — `USER user@host`, `SITE host`,
`OPEN host`, or a user-defined login script with placeholders. The proxy login is just
another `LoginScript` run by T10's login state machine, so TLS, logging and secret masking
work the same way. The result is a `LoginPlan` that T14's `connect` uses.

## Context

**Exists before this task:** T05 `Settings` (`proxy.generic`, `proxy.ftp_proxy`), T10
`ControlConnection`, `LoginScript`/`LoginStep`/`StepKind`/`StepValue`/`LoginTarget`,
login state machine (incl. `Other` steps and prompts), `FakeServer`, T04 `mask_command`
and `PasswordPrompt { purpose: FtpProxy, cache_key: SecretCacheKey::Proxy { .. }, .. }`,
T02 `ServerAddress` (incl. `user`) + `LogonType`, `Error::Proxy`, T03 `ConnectInfo`
(`proxy: ProxyChoice`, `ftp_proxy_password`).

**Later tasks need from this one:**
- T14: `login_plan(&ConnectInfo, &Settings) -> Result<LoginPlan>` in `connect` (this is
  why T14 now depends on T15).
- T31/T58/T70: when building `ConnectInfo` they resolve `proxy.ftp_proxy.password_ref`
  (vault `proxy-credential` item, T81) into `ConnectInfo.ftp_proxy_password` (T03).
- T68: settings form (type, host, port, user, password → vault, custom script editor)
  and `validate_ftp_proxy` for inline errors.
- T32: FileZilla settings import may map FileZilla's FTP proxy settings (if imported).

## Technical specification

### Types and APIs

```rust
// courier_ftp_core::settings — types owned by T05 (not redefined here):
//   FtpProxyKind { None*, UserAtHost, Site, Open, Custom }   (snake_case: "user_at_host")
//   FtpProxySettings { kind, host: String, port: u16 /* 21 */, user: String /* %s */,
//                      password_ref: Option<Uuid> /* proxy-credential item, T81 */,
//                      custom_script: Vec<String> /* one line per element, kind == Custom */ }
//   GenericProxySettings (T07)

/// Validation used at settings load (T05 `validate`) and inline in the settings UI (T68).
pub fn validate_ftp_proxy(ftp: &FtpProxySettings, generic: &GenericProxySettings) -> Vec<ProxySettingError>;
pub enum ProxySettingError {
    BothProxiesActive,                   // generic and FTP proxy cannot both be on
    EmptyHost, InvalidPort,
    UnknownPlaceholder { line: usize, placeholder: char },
    ScriptTooLong, LineTooLong { line: usize },
    MissingHostPlaceholder,              // custom script never uses %h
}

// courier_ftp_proto_ftp::ftp_proxy -------------------------------------------------------
/// FTP proxy settings resolved for one connection. No Clone (holds a secret).
pub struct FtpProxyConfig {
    pub kind: FtpProxyKind,              // never None here
    pub host: String,
    pub port: u16,
    pub user: String,
    /// `ConnectInfo.ftp_proxy_password` (resolved from the vault); None → prompt if needed.
    pub password: Option<SecretString>,
    pub custom_script: Vec<String>,
}
impl FtpProxyConfig {
    /// None when `s.kind == None`. The password is copied with `SecretString::from(p.expose())`.
    pub fn from_settings(s: &FtpProxySettings, password: Option<&SecretString>) -> Option<Self>;
}
impl std::fmt::Debug for FtpProxyConfig { /* password printed as "****" */ }

/// What T14 needs to open the control connection.
pub struct LoginPlan {
    pub connect_to: HostPort,            // the proxy, or the server when no FTP proxy
    pub tls_server_name: String,         // TLS peer = proxy host when proxied (T12)
    pub script: LoginScript,
    pub via_ftp_proxy: bool,
}

/// Builds the plan from `ConnectInfo` (address incl. user and encryption, logon, proxy
/// choice, `ftp_proxy_password`) and `settings.proxy.ftp_proxy`.
pub fn login_plan(info: &ConnectInfo, settings: &Settings) -> Result<LoginPlan>;

/// Built-in and custom scripts → `LoginScript` with substituted values and masked log text.
pub fn build_script(kind: &FtpProxyKind, custom: &[String], vars: &ScriptVars) -> Result<LoginScript>;

pub struct ScriptVars {
    pub host: String,                    // %h, already formatted (see "Placeholders")
    pub user: String,                    // %u
    pub password: VarSecret,             // %p
    pub account: Option<SecretString>,   // %a
    pub proxy_user: String,              // %s
    pub proxy_password: VarSecret,       // %w
}
pub enum VarSecret { Value(SecretString), Ask, Empty }
```

### Behaviour

**1. When an FTP proxy is used.** `login_plan` uses an FTP proxy only if
`settings.proxy.ftp_proxy.kind != None`, `info.address.protocol == Protocol::Ftp` (any
`FtpEncryption`; never SFTP), and `info.proxy != ProxyChoice::Bypass` (site "Bypass
proxy", T31). The generic proxy (T07) and the FTP proxy
are mutually exclusive (validation below), so a connection has at most one of them.

**2. Placeholders.**

| Placeholder | Value | Empty when |
|---|---|---|
| `%h` | target host; `host:port` when port ≠ 21; IPv6 literal bracketed only with a port (`[2001:db8::1]:2121`) | never |
| `%u` | target user (`anonymous` for anonymous logon) | never |
| `%p` | target password (`anonymous@example.com` for anonymous; `AskForPassword`/`Interactive` → prompt when the line is reached) | `Normal` with an empty password |
| `%a` | account (`Account` logon) | no account |
| `%s` | proxy user | proxy user empty |
| `%w` | proxy password (`ConnectInfo.ftp_proxy_password`; `None` with non-empty `%s` → `PromptKind::Password(PasswordPrompt { purpose: FtpProxy, target: "proxy-host:port", cache_key: SecretCacheKey::Proxy { host, port, user }, can_save: false, .. })`) | proxy user empty |
| `%%` | literal `%` | – |

A line in which **any** placeholder substitutes to an empty value is skipped (FileZilla
rule), so `USER %s`/`PASS %w` disappear when no proxy user is set. Substituted values
containing CR, LF or NUL → `Error::InvalidInput` (T10 command check), so a user name can't
inject extra proxy commands.

**3. Built-in sequences** (exact; `ACCT %a` is sent only when the server replies `332`, by
T10's state machine).

| Kind | Lines (after skipping) |
|---|---|
| `UserAtHost` | `USER %s` · `PASS %w` · `USER %u@%h` · `PASS %p` |
| `Site` | `USER %s` · `PASS %w` · `SITE %h` · `USER %u` · `PASS %p` |
| `Open` | `USER %s` · `PASS %w` · `OPEN %h` · `USER %u` · `PASS %p` |
| `Custom` | user lines; default template shown in the settings UI: `USER %s` / `PASS %w` / `USER %u@%h` / `PASS %p` |

Example on the wire (`Site`, proxy user `proxyuser`, target `ftp.example.com:2121`, user `alice`):
```
> USER proxyuser          < 331 Password required
> PASS ****               < 230 Proxy login ok
> SITE ftp.example.com:2121   < 220-Connected to ftp.example.com
                              < 220 ftp.example.com ready
> USER alice              < 331 Password required for alice
> PASS ****               < 230 Logged in
```

**4. Custom script rules.** One line per `custom_script` element (an element containing
`\n` is split further), trailing `\r` and surrounding whitespace trimmed, empty lines
ignored. First token = verb (ASCII letters, 3–4 chars, upper-cased);
`USER` → `StepKind::User`, `PASS` → `Pass`, `ACCT` → `Acct`, anything else → `Other(verb)`.
Limits: ≤ 32 lines, ≤ 512 bytes per line after substitution. Unknown `%x` → validation
error. `LoginTarget`: lines with `%s`/`%w` or `SITE`/`OPEN` verbs → `Proxy`; lines with
`%u`/`%p`/`%a` → `Server` (used for error messages: "FTP proxy login failed" vs
"Authentication failed").

**5. Reply handling** (T10 login state machine, plus proxy specifics).
- `USER`/`PASS`/`ACCT` steps: as T10 (230 after `USER` skips the directly following `PASS`).
- Steps with `LoginTarget::Proxy` answered 530/430/other 5xx → `Error::Proxy("FTP proxy
  login failed: <text>")` (not `Auth`, so the target credentials are not blamed).
- `Other` steps (`SITE`, `OPEN`, custom verbs): 2xx or 3xx → next line; 4xx/5xx →
  `Error::Proxy("FTP proxy could not connect to the server: <text>")`.
- Relayed greeting: proxies often answer `SITE`/`OPEN`/`USER u@h` with the target's `220`
  greeting **and then** the real reply; a `220` reply to a proxy step is logged and the next
  reply is read (at most 3 extra replies).
- The login is complete when all lines ran and the last reply was `230`/`202`; otherwise
  `Error::Auth`.

**6. TLS through an FTP proxy.**
- Explicit FTPS: `AUTH TLS` is sent to the proxy right after its greeting, before the
  script (T12 order). TLS terminates at the proxy, so the certificate is verified against
  the **proxy host** name (`LoginPlan.tls_server_name`) and trust entries are stored for
  `proxy-host:port`. Whether the proxy-to-server leg is encrypted depends on the proxy:
  the settings UI (T68) and the docs state this; a Status line is logged on connect
  ("Using FTP proxy; encryption between the proxy and the server depends on the proxy").
- Implicit FTPS (`RequireImplicit`) through an FTP proxy → `Error::Unsupported("implicit
  FTPS through an FTP proxy")` (there is no greeting to send the script after).

**7. Data connections.** Passive replies come from the proxy, so T11's address rules use
the proxy as the control peer. Active mode works (the proxy relays `PORT`/`EPRT`) and
accepted connections must come from the proxy's address.

**8. Validation.** `validate_ftp_proxy` runs at settings load (T05: errors → warning in
the app log + `ftp_proxy.kind` reset to `None` for this run, generic proxy kept) and in the
settings UI (T68: inline error, save blocked). Rules: generic proxy ≠ `None` and FTP proxy
≠ `None` → `BothProxiesActive`; empty host; port 0; custom script checks (§4) and
`MissingHostPlaceholder` (a script that never sends `%h` cannot reach a server).

### Data formats and configuration

`config.json` (non-secret settings, D10; keys registered in T05):
```json
"proxy": {
  "generic": { "kind": "none" },
  "ftp_proxy": {
    "kind": "custom",
    "host": "proxy.corp.example",
    "port": 21,
    "user": "proxyuser",
    "password_ref": "0190f5b2-6c1e-7c3a-9a51-2f0e8d1c4b77",
    "custom_script": ["USER %s", "PASS %w", "USER %u@%h", "PASS %p"]
  }
}
```
| Key | Type | Default |
|---|---|---|
| `proxy.ftp_proxy.kind` | `none` \| `user_at_host` \| `site` \| `open` \| `custom` | `none` |
| `proxy.ftp_proxy.host` | string | `""` |
| `proxy.ftp_proxy.port` | u16 | `21` |
| `proxy.ftp_proxy.user` | string | `""` |
| `proxy.ftp_proxy.password_ref` | UUID of a `proxy-credential` item, or null | `null` |
| `proxy.ftp_proxy.custom_script` | array of strings (≤ 32 lines, each ≤ 512 chars) | `[]` |

The proxy password lives only in the vault (`proxy-credential` item: fields `user`,
`password`), never in `config.json`.

### Errors

| Situation | Error | User sees |
|---|---|---|
| Proxy login refused (`USER %s`/`PASS %w` → 530) | `Proxy` | "FTP proxy login failed: <text>" |
| `SITE`/`OPEN`/custom verb refused | `Proxy` | "FTP proxy could not connect to the server: <text>" |
| Target login refused | `Auth` | "Authentication failed: <text>" |
| CR/LF/NUL in a substituted value | `InvalidInput` | "user name or password contains a line break" |
| Implicit FTPS via FTP proxy | `Unsupported` | as above |
| Invalid script at connect time | `InvalidInput` | the validation message |
| Proxy password prompt cancelled | `Cancelled` | – |

### Security and logging

- Log text is built during substitution: every value from `%p`, `%w` and `%a` is replaced
  with `****` in `LoginStep.log_text`, whatever the verb (custom lines like
  `SITE LOGIN %s %w` are masked too); T04 `mask_command` runs as a second guard.
- Proxy password: `SecretString` from the vault, exposed only into T10's zeroizing write
  buffer; `FtpProxyConfig`/`ScriptVars` `Debug` print `****`; settings never contain it.
- `tracing` `info`: "ftp proxy login ok/failed" with the session id only; proxy host and
  script lines at `debug` with secrets masked (T91 §4).
- The custom script comes from local settings (not synced), so it is not a T91 §8
  "synced local-acting value".

## Implementation steps

1. `validate_ftp_proxy` on T05's `FtpProxySettings` + T05 load hook (warning + reset)
   with unit tests.
2. Placeholder substitution, empty-skip rule, `%h` formatting, masked log text.
3. Built-in scripts and custom script parsing → `LoginScript`.
4. `login_plan` (direct vs proxied target, TLS name, implicit refusal).
5. T10 login state machine additions: relayed `220` handling for proxy steps, proxy vs
   server error messages.
6. `FakeServer` tests per type; in-process relay proxy for e2e (T76 addition).

## Acceptance criteria

- [ ] AC1 Each built-in type sends exactly the documented sequence (fake server asserts
  every line), with and without a proxy user.
- [ ] AC2 Custom scripts: all placeholders substituted, `%%` literal, lines with an empty
  substitution skipped, unknown placeholders and over-long scripts rejected by validation.
- [ ] AC3 Secrets masked for every type: canary target password, account and proxy password
  never appear in `LogMessage`s, `Debug` output or `tracing` output; the log shows `****`.
- [ ] AC4 Settings validation rejects generic + FTP proxy combined (load: warning + FTP
  proxy disabled; UI helper returns `BothProxiesActive`).
- [ ] AC5 Relayed `220` greetings after `SITE`/`OPEN`/`USER u@h` are tolerated.
- [ ] AC6 Explicit FTPS through a proxy sends `AUTH TLS` before the script and verifies the
  certificate against the proxy host name; implicit FTPS through a proxy fails with
  `Unsupported`.
- [ ] AC7 CR/LF in a user name or password used by a script → `InvalidInput`, nothing sent.
- [ ] AC8 Docker e2e: login, listing and a hash-verified download through the harness
  proxy for `UserAtHost`, `Site` and `Open` against vsftpd.
- [ ] AC9 CI gates (T00) pass.

## Tests

### Unit tests
- `validate_rejects_both_proxies`, `validate_rejects_unknown_placeholder`,
  `validate_rejects_script_without_host`, `validate_limits`. AC2, AC4.
- `host_placeholder_port_21_omitted`, `host_placeholder_ipv6_bracketed_with_port`.
- `empty_substitution_skips_line`, `percent_percent_is_literal`. AC2.
- `log_text_masks_p_w_a_in_custom_lines`. AC3.
- `substitution_with_crlf_is_invalid_input`. AC7.
- `login_plan_direct_vs_proxied`, `login_plan_implicit_via_proxy_unsupported`. AC6.
- `settings_load_with_both_proxies_warns_and_disables_ftp_proxy`. AC4.

### Property / fuzz tests
- `prop_custom_script_never_panics` — random script text and variable values → `Ok`
  script or validation error, never a panic; every produced line is free of CR/LF/NUL.

### Snapshot tests
Not applicable (no UI; T68 snapshots the settings form).

### Integration tests (`FakeServer` acting as the proxy)
- `proxy_user_at_host_sequence`, `proxy_user_at_host_with_proxy_auth_sequence`,
  `proxy_site_sequence`, `proxy_open_sequence`, `proxy_custom_sequence`. AC1, AC2.
- `proxy_relayed_greeting_tolerated`. AC5.
- `proxy_site_refused_is_proxy_error`, `proxy_login_refused_is_proxy_error`,
  `target_login_refused_is_auth_error`.
- `proxy_password_prompted_when_not_in_vault`.
- `proxy_explicit_tls_auth_before_script` (T12 fake TLS acceptor, cert for the proxy name). AC6.
- `canary_secrets_never_logged_all_types`. AC3.

### End-to-end tests (`courier-ftp-e2e`, `#[ignore]` + `COURIER_E2E=1`, T76)
- `ftp_proxy_user_at_host_vsftpd`, `ftp_proxy_site_vsftpd`, `ftp_proxy_open_vsftpd` — the
  harness runs a small in-process relay proxy (`courier-ftp-e2e/src/ftp_proxy.rs`) in front
  of the vsftpd `plain` container; connect, list, download, compare SHA-256. AC8.

## Out of scope

- Generic HTTP/SOCKS proxies (T07); proxies for SFTP.
- Proxy auto-configuration (PAC), Kerberos proxy auth (D8).
- Per-site FTP proxy settings (FileZilla only has the global one plus "bypass proxy").

## Open questions

None. (Resolved: T05 registers the full `proxy.ftp_proxy` shape used here; T76 lists the
in-process FTP relay proxy fixture.)
