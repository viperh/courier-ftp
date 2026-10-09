# T72 — Network configuration wizard

**Phase:** G App-level · **Milestone:** M9 · **Depends on:** T05, T10, T11, T52 · **Crate(s):** `courier-ftp` (`components/network_wizard/`), `courier-ftp-proto-ftp` (`probe` module) · **Decisions:** D1 · **FEATURES.md:** §9 (network configuration wizard), §1 (active/passive, fallback, external IP, port range, IP lookup)

## Goal

A step-by-step dialog that explains FTP passive and active mode, lets the user set the
related settings, and **tests** them against an FTP/FTPS server the user chooses. Each
test step shows ✔/⚠/✘ with an explanation and a concrete fix, and the wizard ends with a
recommendation and an Apply/Cancel choice. Nothing is saved until the user applies.

## Context

- T05 defines the `ftp` settings section: `transfer_mode` (`Passive` | `Active`),
  `fallback_to_active` (true), `active_external_ip` (`Auto` | `Fixed(IpAddr)` |
  `FromUrl(String)`), `active_port_range` (`Option<(u16, u16)>`),
  `passive_ignore_unroutable_ip` (true), plus `connection.timeout_secs` (20) and
  `Settings::save_user`. This document calls the section's type `FtpSettings`.
- T10 provides the control connection (`ControlConnection`, login sequence, FEAT, PWD,
  `Error::Connection`/`Timeout`), T11 the data connections (EPSV/PASV/EPRT/PORT, the
  unroutable-address rule, active listener with port range, `FromUrl` lookup over plain
  HTTP, anti-bounce peer check). T12 (FTPS) is used when the chosen server needs TLS.
- T52 provides the modal stack, `Form`, `RadioGroup`, `Checkbox`, `TextInput`,
  `NumberInput`, `Button` rows and `ProgressDialog`.
- FileZilla tests against `probe.filezilla-project.org`; courier-ftp must not use it and
  runs no probe server of its own (see Open questions).
- Entry points (no hard dependency): a button in Settings → Connection → FTP (T68) and the
  `Action::NetworkWizard` action listed in the help overlay (T50).

## Technical specification

### Types and APIs

**Probe** — `courier_ftp_proto_ftp::probe` (no UI types; reusable from tests and `Headless`):

```rust
/// What to test and with which candidate settings (not the saved ones).
#[derive(Debug)]
pub struct ProbeRequest {
    /// Server to test against (from a site, the current tab or typed in the wizard).
    pub info: ConnectInfo,
    /// The settings being edited in the wizard.
    pub ftp: FtpSettings,
    /// Network options (timeouts, proxy, IPv6 preference) from `Settings`.
    pub net: NetOpts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeStepId { Connect, Login, Features, PassiveEpsv, PassivePasv, ExternalIp, Active, Disconnect }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    Running,
    Ok { detail: ProbeDetail },
    Warning { detail: ProbeDetail, hint: Hint },
    Failed { detail: ProbeDetail, hint: Hint },
    Skipped { hint: Hint },
}

/// Structured facts (rendered and translated by the UI, T75).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeDetail {
    Connected { peer: SocketAddr, tls: Option<String> },
    LoggedIn,
    Features { epsv: bool, eprt: bool, mlsd: bool },
    Passive { command: &'static str, server_addr: SocketAddr, used_addr: SocketAddr, bytes: u64 },
    ExternalIp { ip: IpAddr, source: ExternalIpSource },
    Active { command: &'static str, sent_addr: SocketAddr, peer: IpAddr, bytes: u64 },
    Reply { code: Option<u16>, text: String },
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalIpSource { LocalSocket, Fixed, Url }

/// The explanation and fix shown under a step. One variant per row of the hint table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hint {
    CannotReachServer, LoginFailed, TlsFailed,
    EnableIgnoreUnroutable { sent: IpAddr },
    PassiveBlocked,
    PassiveNotSupported,
    NatDetected { local: IpAddr },
    IpLookupFailed,
    PortRangeUnavailable { from: u16, to: u16 },
    ServerRejectedPort { code: u16 },
    IncomingBlocked,
    ActiveThroughProxy,
    EpsvOnly,
    Cancelled,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recommendation {
    /// Passive works with the candidate settings.
    Passive,
    /// Passive works only with `passive_ignore_unroutable_ip = true`.
    PassiveIgnoreUnroutable,
    /// Passive fails, active works.
    Active,
    /// Neither works.
    NoWorkingMode,
    /// Connect or login failed; no data-channel result.
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport { pub steps: Vec<(ProbeStepId, StepOutcome)>, pub recommendation: Recommendation }

/// Progress updates while the probe runs (one per state change of a step).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeProgress { pub step: ProbeStepId, pub outcome: StepOutcome }

/// Runs the whole probe. Never panics; every failure becomes a step outcome.
pub async fn run_probe(
    req: ProbeRequest,
    events: EventSender,
    progress: tokio::sync::mpsc::Sender<ProbeProgress>,
    cancel: CancellationToken,
) -> ProbeReport;

/// Pure: derives the recommendation from step outcomes (unit-testable).
pub fn recommend(steps: &[(ProbeStepId, StepOutcome)]) -> Recommendation;
```

The probe uses crate-internal T10/T11 APIs with an explicit data-channel mode
(`DataChannelMode::{Epsv, Pasv, Eprt, Port}`) that bypasses the session's fallback and
"remember the mode" logic of T11 §3.

**Wizard UI** — `crates/courier-ftp/src/components/network_wizard/{mod,pages,results}.rs`:

```rust
pub(crate) struct NetworkWizard {
    page: WizardPage,
    draft: FtpSettings,        // starts as a clone of Settings.ftp
    original: FtpSettings,
    target: TestTarget,
    report: Option<ProbeReport>,
    running: Option<(JoinHandle<ProbeReport>, CancellationToken)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WizardPage { Intro, Mode, Passive, Active, Target, Running, Results, Summary }

pub(crate) enum TestTarget {
    /// The current tab's FTP/FTPS connection info (pre-selected when present).
    CurrentTab(ConnectInfo),
    /// A saved FTP/FTPS site (needs the vault unlocked).
    Site(ItemId),
    /// Typed in: host, port, encryption, anonymous or user + password (never saved).
    Manual { host: String, port: u16, encryption: FtpEncryption, user: Option<String>, password: Option<SecretString> },
}
```

New `Action::NetworkWizard` opens it.

### Behaviour

**Pages** (Next = `Enter` on the default button, Back = `Alt-b`/`[ Back ]`, `Esc` = Cancel):

| # | Page | Content | Fields → draft |
|---|---|---|---|
| 1 | Intro | One paragraph each on passive and active mode, and that the test needs an FTP server the user can log in to (anonymous is fine). | — |
| 2 | Mode | Default transfer mode: (•) Passive (recommended) ( ) Active | `transfer_mode` |
| 3 | Passive | [x] Use the server's address when it sends an unroutable one · [x] Fall back to active mode if passive fails | `passive_ignore_unroutable_ip`, `fallback_to_active` |
| 4 | Active | External address: (•) Ask the operating system ( ) Use this address `[      ]` ( ) Get it from this URL `[      ]`; [x] Don't use the external address for servers on the local network; Ports: (•) Any ( ) Only from `[ 1024..65535 ]` to `[ ]`; note: "Your router must forward this port range to this computer." | `active_external_ip`, `active_no_external_ip_on_local`, `active_port_range` |
| 5 | Target | (•) Current connection (FTP/FTPS only) ( ) Saved site `[picker]` ( ) Other server: host, port, encryption, [x] anonymous / user, password; `[ Run test ]` `[ Skip test ]` | `target` |
| 6 | Running | Live step list with spinner, wizard log panel (Status lines), `[ Cancel test ]` | — |
| 7 | Results | Each step ✔/⚠/✘/– with detail and hint; the recommendation; `[ Use recommended settings ]` (when it differs from the draft) `[ Test again ]` `[ Next ]` | may update draft |
| 8 | Summary | Table of changed keys `old → new`; `[ Apply ]` `[ Back ]` `[ Cancel ]` | — |

- Page 4 is shown even when Passive is chosen (fallback uses it). Page 5 options that
  are unavailable are disabled with the reason (`Not an FTP connection`, `Unlock the vault
  to choose a saved site`). SFTP sites are not listed.
- Validation before leaving a page (inline errors, T52): fixed IP parses as `IpAddr`
  and is not unspecified/multicast; URL is `http://` or `https://` with a host, ≤ 2 048
  chars; port range `1024 ≤ from ≤ to ≤ 65535`; manual host non-empty, port 1–65535.
- Back from Results/Summary keeps the report; changing any setting after a test marks the
  results "outdated (settings changed)".
- Cancel (`Esc` or button) with a modified draft asks "Discard changes?"; the draft is
  dropped and nothing is written. While Running, `Esc` = Cancel test (token cancelled,
  back to page 5 within 1 s).
- Apply: `Settings.ftp = draft`, `Settings::save_user` (T05), status message
  `Network settings saved; they apply to new connections`. Live sessions are not changed.

**Probe procedure** (sequential; each step's outcome is sent on `progress` as it changes):

1. **Connect** — `net::connect_tcp` to the target (with the generic proxy unless the
   target bypasses it), greeting, implicit/explicit TLS per `info` (T12, including the
   certificate trust prompt via T04). Failure → `Failed(CannotReachServer | TlsFailed)`,
   all remaining steps `Skipped`, recommendation `Inconclusive`.
2. **Login** — T10 login. Failure → `Failed(LoginFailed)`, rest skipped, `Inconclusive`.
3. **Features** — `FEAT` (500/502 = no features), `PWD`. Always `Ok`.
4. **PassiveEpsv** — only if FEAT lists `EPSV` or the control connection is IPv6, else
   `Skipped`. `TYPE A`, `EPSV`, open data connection to control peer + port, `LIST`
   (current directory), read the data (discarding, counting bytes, stop after 1 MiB),
   expect `150|125` then `226|250`. Data connect timeout and inactivity timeout =
   `connection.timeout_secs`. Success → `Ok(Passive{..})`; `500|502` → `Skipped(PassiveNotSupported)`;
   connect timeout/refused → `Failed(PassiveBlocked)`.
5. **PassivePasv** — only on an IPv4 control connection, else `Skipped(EpsvOnly)`. Same
   as 4 with `PASV`. Address rule:
   - sent IP equals control peer → connect to it;
   - sent IP is private/loopback/link-local/unspecified while the control peer is public:
     with `draft.passive_ignore_unroutable_ip` → connect to the control peer, `Ok` with
     both addresses in the detail; without it → try the sent IP: if that fails →
     `Failed(EnableIgnoreUnroutable{sent})`, if it works (same LAN) → `Ok`.
6. **ExternalIp** — the address active mode will send:
   - control peer private/loopback and `active_no_external_ip_on_local` → control socket
     local IP, `Ok(LocalSocket)`;
   - `Auto` → control socket local IP; if it is private while the control peer is public
     → `Warning(NatDetected{local})`;
   - `Fixed(ip)` → `Ok(Fixed)`;
   - `FromUrl(url)` → GET through the net layer with the same helper T11 uses for
     `FromUrl` (plain HTTP; `https://` URLs work once T74's `net::http` client exists —
     before that they fail with `IpLookupFailed`), 10 s timeout, body ≤ 64 bytes, trimmed, must parse as `IpAddr`
     of the same family as the control connection; failure → `Failed(IpLookupFailed)`
     and **Active** is `Skipped(IpLookupFailed)`.
   - Connection through an HTTP/SOCKS proxy → this step and Active `Skipped(ActiveThroughProxy)`.
7. **Active** — bind a listener on the control socket's local IP: port from the range
   (start at a random offset, try ports in order, at most 100 bind attempts) or
   ephemeral. Bind failure for every attempt → `Failed(PortRangeUnavailable)`. Send `EPRT`
   (IPv6, or IPv4 when FEAT lists `EPRT`) else `PORT` with the external IP and port; reply
   `5xx` → `Failed(ServerRejectedPort{code})`. `TYPE A`, `LIST`; accept one connection
   within `connection.timeout_secs`; peer IP must equal the control peer (anti-bounce,
   T11) — another peer is dropped and keeps waiting. Accept timeout or reply `425` →
   `Failed(IncomingBlocked)`. Data read as in step 4. Success → `Ok(Active{..})`.
8. **Disconnect** — `QUIT`, wait ≤ 2 s for `221`, close. Always `Ok` (errors ignored).

Whole-probe limit: **120 s**; when hit, the running step becomes `Failed(Unknown)` with
detail `Timeout`, the rest `Skipped`. Cancellation marks the running step and the rest
`Skipped(Cancelled)` and still sends `QUIT` (best effort, 2 s).

**Recommendation** (`recommend`, first matching row):

| Condition | Recommendation | Draft change offered |
|---|---|---|
| Connect or Login failed | `Inconclusive` | none |
| EPSV or PASV `Ok` with the draft settings | `Passive` | `transfer_mode = Passive` |
| PASV failed with `EnableIgnoreUnroutable` | `PassiveIgnoreUnroutable` | `passive_ignore_unroutable_ip = true`, `transfer_mode = Passive` |
| Passive failed/skipped, Active `Ok` | `Active` | `transfer_mode = Active` |
| otherwise | `NoWorkingMode` | none |

**Hint texts** (English source strings for T75; `{}` = detail values):

| Hint | Text |
|---|---|
| `CannotReachServer` | The server could not be reached. Check host, port and your firewall or proxy settings. |
| `LoginFailed` | Login failed. Check the user name and password, or use anonymous login if the server allows it. |
| `TlsFailed` | The TLS handshake failed. Try another encryption setting for this server. |
| `EnableIgnoreUnroutable` | The server sent the private address {sent} for passive mode. Turn on "Use the server's address when it sends an unroutable one". |
| `PassiveBlocked` | Could not open the passive data connection. A firewall blocks outgoing connections to the server's data ports, or the server's passive ports are not forwarded. Try active mode. |
| `PassiveNotSupported` | The server does not support this passive command. |
| `NatDetected` | This computer's address {local} is private, so a server on the internet cannot connect back to it. Set the external address, or use passive mode. |
| `IpLookupFailed` | The external address could not be read from the URL. Check the URL, or enter the address yourself. |
| `PortRangeUnavailable` | No port between {from} and {to} could be opened on this computer. Choose another range. |
| `ServerRejectedPort` | The server refused the active-mode address (reply {code}). Some servers only accept the address of the control connection; check the external address setting. |
| `IncomingBlocked` | The server could not connect back to this computer. Your router or firewall blocks incoming connections: forward the port range to this computer, or use passive mode. |
| `ActiveThroughProxy` | Active mode does not work through an HTTP or SOCKS proxy. |
| `EpsvOnly` | Not needed: the connection uses IPv6. |
| `Cancelled` | The test was cancelled. |
| `Unknown` | The test did not finish in time. |

### Data formats and configuration

Existing keys (T05) edited by the wizard: `ftp.transfer_mode`, `ftp.fallback_to_active`,
`ftp.active_external_ip`, `ftp.active_port_range`, `ftp.passive_ignore_unroutable_ip`.

New key added by this task to `Settings.ftp` (T05 §1c pattern) and honoured by T11's
active mode:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `ftp.active_no_external_ip_on_local` | bool | `true` | FileZilla's "Don't use external IP address on local connections": when the server's address is private, loopback or link-local, active mode sends the control socket's local address instead of the external one. |

The `FromUrl` string has no default (the user must enter a URL; see Open questions).

### Errors

All probe failures are step outcomes, never `Err`: `Error::Connection`, `Error::Timeout`
→ `CannotReachServer`/`PassiveBlocked`/`IncomingBlocked` by step; `Error::Auth` →
`LoginFailed`; `Error::Tls` → `TlsFailed`; `Error::Protocol { code, .. }` → the step's
reply-based hint with `ProbeDetail::Reply`; `Error::Unsupported` (active via proxy) →
`ActiveThroughProxy`; `Error::Cancelled` → `Cancelled`. A failure to save settings on
Apply shows the T52 error dialog and keeps the wizard open with the draft intact.

### Security and logging

- The wizard contacts only the server the user picked and, if configured, the user's IP
  lookup URL. No built-in probe or lookup host is contacted.
- Credentials typed on the Target page live in `SecretString`, are used for one probe and
  dropped when the wizard closes; `PASS` is masked in all logs (T04 `mask_command`).
- The probe's `LogMessage`s go to the wizard's log panel and, when enabled, the session
  log (T71) under their own `SessionId`. Application log: `info!` only
  `network probe finished` with step ids and outcome kinds (`passive=ok active=failed`),
  no host, IP or user (T91 §4); addresses at `debug`.
- Server reply text shown in details passes through the control-character escaper
  (T71 `escape_controls`). IP lookup responses are parsed strictly (`IpAddr::from_str` on
  ≤ 64 trimmed bytes); anything else is a failure.
- The active listener accepts exactly one connection from the control peer and is
  closed after the step (no open port left behind; test).

## Implementation steps

1. Add `ftp.active_no_external_ip_on_local` to `Settings.ftp` with docs, default and
   validation; honour it in T11's active-mode address selection. Unit test.
2. `probe` module: types, `recommend`, and `run_probe` steps Connect → Features against
   the scripted fake server harness of T10.
3. Passive steps (EPSV, PASV + unroutable rule) with explicit `DataChannelMode`.
4. ExternalIp and Active steps (listener, port range, EPRT/PORT, accept, peer check),
   whole-probe timeout and cancellation.
5. Wizard component: pages 1–5 and 8 with draft handling, validation and Apply/Cancel;
   `Action::NetworkWizard`; Settings → FTP button.
6. Running and Results pages wired to `run_probe` (progress channel → actions), "Use
   recommended settings", "Test again".
7. Snapshot tests for all pages; e2e tests against the vsftpd profiles.

## Acceptance criteria

- [ ] AC1 All 8 pages are reachable with Next/Back in order; Cancel at any page discards
  the draft and leaves the user config file byte-identical.
- [ ] AC2 Invalid inputs (bad IP, non-http URL, port range `5000..4000`, `80..90`) block
  Next with an inline error.
- [ ] AC3 Apply writes exactly the changed `ftp.*` keys via `Settings::save_user`.
- [ ] AC4 Against vsftpd profile `plain`: Connect, Login, PASV (and EPSV if advertised),
  ExternalIp and Active are ✔ and the recommendation is `Passive`.
- [ ] AC5 Against `passive-unroutable`: with the option off, PASV is ✘ with
  `EnableIgnoreUnroutable` and the recommendation is `PassiveIgnoreUnroutable`; with it
  on, PASV is ✔ and the detail shows both addresses.
- [ ] AC6 Against `active-only`: passive ✘, Active ✔, recommendation `Active`.
- [ ] AC7 A blocked active connection is reported ✘ with the right hint: fixed external
  IP `192.0.2.1` against vsftpd → `ServerRejectedPort`; a fake server that never connects
  back → `IncomingBlocked` within `timeout_secs + 1` s.
- [ ] AC8 Cancel during Running returns to the Target page within 1 s, and the listener
  port is closed.
- [ ] AC9 No network connection is made except to the chosen server and the configured
  lookup URL (fake net layer records every connect).
- [ ] AC10 Passwords typed for the test never appear in logs (canary) or in the saved config.
- [ ] AC11 Snapshot tests exist for every page at 80×24 and 160×48.
- [ ] AC12 T00 gates pass (`fmt`, `clippy`, `docs`, `test-local-only`, `test-os`, `e2e`).

## Tests

### Unit tests
- `recommend_table` — one case per row of the recommendation table, plus Connect failed → `Inconclusive` (AC4–AC6).
- `pasv_unroutable_rule_matrix` — sent/peer address classes × option on/off (AC5).
- `external_ip_selection_matrix` — Auto/Fixed/FromUrl × local/public peer × `active_no_external_ip_on_local` (AC4).
- `port_range_bind_tries_at_most_100` — fake binder failing every port → `PortRangeUnavailable` (AC7).
- `ip_lookup_body_parsing` — `"203.0.113.9\n"` ok; 65-byte body, HTML, wrong family rejected (AC9).
- `wizard_page_order_and_back` — Next/Back sequence through all pages with synthetic keys (AC1).
- `wizard_cancel_discards_draft` — config file hash unchanged (AC1).
- `wizard_validation_blocks_next` — each invalid input from AC2 (AC2).
- `wizard_apply_writes_only_changed_keys` — temp config dir, JSON diff (AC3).
- `results_marked_outdated_after_setting_change` (AC1).

### Snapshot tests
- `wizard_intro_80x24`, `wizard_intro_160x48`, and the same pair for `mode`, `passive`, `active`, `target`, `running`, `results_mixed` (✔/⚠/✘/– rows), `summary` (AC11).

### Integration tests
In-process fake FTP server on `127.0.0.1` (real sockets, T10/T11 harness):
- `probe_all_ok_fake_server` — passive and active ✔ (AC4).
- `probe_pasv_private_ip` — server answers PASV with `10.255.255.1`; option off/on (AC5).
- `probe_active_never_connects_back` — server accepts PORT but never connects → `IncomingBlocked` within timeout + 1 s (paused time not used: real 2 s timeout in test settings) (AC7).
- `probe_port_rejected` — server replies `500 Illegal PORT command` → `ServerRejectedPort{500}` (AC7).
- `probe_login_failure_is_inconclusive` (AC4).
- `probe_cancel_closes_listener` — cancel during Active; the port can be bound again immediately (AC8).
- `probe_through_socks_proxy_skips_active` — in-process SOCKS5 fake (T07) (AC9).
- `probe_connects_only_to_target` — net layer wrapper records destinations (AC9).
- `probe_password_canary_not_logged` — events and app log scanned (AC10).

### End-to-end tests
`courier-ftp-e2e`, `#[ignore]` + `COURIER_E2E=1`, Linux only (active mode needs the
container to reach the test host over the Docker bridge; the test connects to the
container's bridge IP, not a mapped localhost port):
- `e2e_wizard_probe_vsftpd_plain` (AC4).
- `e2e_wizard_probe_vsftpd_passive_unroutable` (AC5).
- `e2e_wizard_probe_vsftpd_active_only` (AC6).
- `e2e_wizard_probe_vsftpd_bad_external_ip` — `Fixed(192.0.2.1)` → `ServerRejectedPort` (AC7).
- `e2e_wizard_pty_flow` — `PtyApp`: open the wizard from Settings, pick "Other server", run the test, Apply; the user config contains the new `ftp.transfer_mode` (AC1, AC3).

## Out of scope

- A courier-ftp-hosted probe server or IP lookup service.
- Configuring routers (UPnP/NAT-PMP port forwarding).
- Testing SFTP (it has no separate data connections) or proxies themselves (T07/T15).
- Per-site transfer mode (set in the Site Manager, T59).

## Open questions

- **Probe server**: FileZilla's wizard tests against its own probe server, which can check
  that the server side sees the correct external address. We test only against a server
  the user chooses. Should courier-ftp ever host its own probe server, or is the
  user-chosen server enough for v1? (Current spec: user-chosen only.)
- **IP lookup URL**: FileZilla ships a default lookup URL on its own domain. Should
  courier-ftp suggest a third-party default (e.g. a public "what is my IP" service) in
  the *Get it from this URL* field, or leave it empty as specified? A default would
  contact a third party whenever active mode with `FromUrl` is used.
