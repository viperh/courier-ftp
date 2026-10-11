//! The network configuration wizard's test (T72): log in to a server the
//! user picks, then try a directory listing in passive and in active mode
//! with the settings being tested, reporting every step with a ✔/✘ and a
//! suggested fix.
//!
//! FileZilla tests against its own probe server; courier-ftp has none and
//! never contacts a host the user didn't name, so the test target is a
//! saved site or an address the user types.
//!
//! The steps, in order ([`ProbeStep`]):
//!
//! 1. **Connect**: the normal start sequence ([`control::connect`]).
//! 2. **Passive address**: a bare `PASV`, to see which address the server
//!    announces. A private address while the server was reached over a
//!    public one means the server sits behind NAT and doesn't know its
//!    external address ([`analyze_pasv`]); *use the server's external IP
//!    instead* works around that.
//! 3. **Passive**: `EPSV`/`PASV` + `LIST` through [`DataSession`] in passive
//!    mode, without the fallback to active.
//! 4. **External address**: which address active mode will announce, and
//!    whether this computer looks like it is behind NAT
//!    ([`analyze_external`]); with *get from URL* the lookup is run
//!    against the user's URL (the only host contacted besides the server).
//! 5. **Active**: `EPRT`/`PORT` + `LIST` in active mode. A timeout or a
//!    `425` means the server could not connect back.
//!
//! A step that can't run is [`StepStatus::Skipped`] with the reason. When
//! the control connection is lost during a step, the next one reconnects.

use std::{
    net::{IpAddr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use courier_ftp_core::{
    Error,
    settings::{ExternalIp, FtpTransferMode, Settings},
};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use crate::{
    control::{self, ControlConnection, FtpContext, FtpOptions},
    data::{
        DataOpen, DataOptions, DataSession,
        addr::{is_routable, parse_pasv},
        external_ip, finish,
    },
};

/// The steps of a test, in the order they run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeStep {
    Connect,
    PassiveAddress,
    Passive,
    ExternalAddress,
    Active,
}

impl ProbeStep {
    /// Every step, in order.
    pub const ALL: [ProbeStep; 5] = [
        ProbeStep::Connect,
        ProbeStep::PassiveAddress,
        ProbeStep::Passive,
        ProbeStep::ExternalAddress,
        ProbeStep::Active,
    ];

    /// A short title for the results list.
    pub fn title(self) -> &'static str {
        match self {
            ProbeStep::Connect => "Connect and log in",
            ProbeStep::PassiveAddress => "Server's passive address",
            ProbeStep::Passive => "Passive mode listing",
            ProbeStep::ExternalAddress => "Your external address",
            ProbeStep::Active => "Active mode listing",
        }
    }
}

/// How a step went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StepStatus {
    Ok,
    /// It worked, or may work, but something needs attention.
    Warning,
    Failed,
    /// Not run (no connection, a proxy, cancelled).
    Skipped,
}

/// One step's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepResult {
    pub step: ProbeStep,
    pub status: StepStatus,
    /// What happened, one or two sentences.
    pub detail: String,
    /// What to change, when something failed or needs attention.
    pub advice: Option<String>,
}

impl StepResult {
    fn new(step: ProbeStep, status: StepStatus, detail: impl Into<String>) -> Self {
        Self {
            step,
            status,
            detail: detail.into(),
            advice: None,
        }
    }

    fn advice(mut self, advice: impl Into<String>) -> Self {
        self.advice = Some(advice.into());
        self
    }
}

/// Progress of a running test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeEvent {
    /// A step started.
    Started(ProbeStep),
    /// A step finished.
    Finished(StepResult),
}

/// Which transfer mode the results suggest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recommendation {
    /// Passive mode works (or nothing was learned about the modes).
    Passive,
    /// Only active mode works.
    Active,
    /// Neither mode works.
    Neither,
    /// The test could not log in, so nothing is known.
    Unknown,
}

/// Every step's result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeReport {
    pub steps: Vec<StepResult>,
}

impl ProbeReport {
    /// The result of `step`, when it ran.
    pub fn get(&self, step: ProbeStep) -> Option<&StepResult> {
        self.steps.iter().find(|s| s.step == step)
    }

    fn status(&self, step: ProbeStep) -> Option<StepStatus> {
        self.get(step).map(|s| s.status)
    }

    /// Whether the passive listing worked.
    pub fn passive_works(&self) -> bool {
        matches!(
            self.status(ProbeStep::Passive),
            Some(StepStatus::Ok | StepStatus::Warning)
        )
    }

    /// Whether the active listing worked.
    pub fn active_works(&self) -> bool {
        matches!(
            self.status(ProbeStep::Active),
            Some(StepStatus::Ok | StepStatus::Warning)
        )
    }

    /// The mode to use.
    pub fn recommendation(&self) -> Recommendation {
        if !matches!(self.status(ProbeStep::Connect), Some(StepStatus::Ok)) {
            return Recommendation::Unknown;
        }
        let tested = |s| {
            matches!(
                self.status(s),
                Some(StepStatus::Ok | StepStatus::Warning | StepStatus::Failed)
            )
        };
        match (self.passive_works(), self.active_works()) {
            (true, _) => Recommendation::Passive,
            (false, true) => Recommendation::Active,
            (false, false) if tested(ProbeStep::Passive) && tested(ProbeStep::Active) => {
                Recommendation::Neither
            }
            // Passive failed and active wasn't tried (proxy): passive is
            // still the only option.
            (false, false) if tested(ProbeStep::Passive) => Recommendation::Neither,
            (false, false) => Recommendation::Unknown,
        }
    }
}

/// Limits of a test.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProbeOptions {
    /// How long a data connection may take (in active mode: how long to
    /// wait for the server to connect back).
    pub data_timeout: Duration,
    /// Bytes of listing read before the transfer is aborted (the listing
    /// itself doesn't matter; data arriving does).
    pub max_listing: usize,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            data_timeout: Duration::from_secs(15),
            max_listing: 64 * 1024,
        }
    }
}

impl ProbeOptions {
    /// Options with `data_timeout`.
    pub fn with_timeout(data_timeout: Duration) -> Self {
        Self {
            data_timeout,
            ..Self::default()
        }
    }
}

/// The suggested fix when the server can't connect back in active mode.
const ACTIVE_BLOCKED: &str = "Active mode failed: the server could not connect back. Your router or firewall probably blocks incoming connections — use passive mode.";

/// Run the test against the server of `opts` (its timeout, proxies and
/// TLS apply) with the `ftp.*` settings of `settings`, reporting progress
/// to `on_event`. `ctx.cancel` stops it; the steps not run are then
/// reported as skipped.
pub async fn run(
    opts: &FtpOptions,
    ctx: FtpContext,
    settings: &Settings,
    probe: &ProbeOptions,
    on_event: impl FnMut(ProbeEvent) + Send,
) -> ProbeReport {
    let mut out = Progress {
        report: ProbeReport::default(),
        on_event,
    };
    let cancel = ctx.cancel.clone();

    // 1. Connect.
    out.start(ProbeStep::Connect);
    let mut conn = match connect(opts, &ctx).await {
        Ok(conn) => Some(conn),
        Err(err) => {
            out.finish(connect_failed(&err));
            let why = if matches!(err, Error::Cancelled) {
                "Cancelled."
            } else {
                "Not run: could not log in."
            };
            for step in &ProbeStep::ALL[1..] {
                out.finish(StepResult::new(*step, StepStatus::Skipped, why));
            }
            return out.report;
        }
    };
    let tls = if conn.as_ref().is_some_and(|c| c.data_tls().is_some()) {
        " (TLS)"
    } else {
        ""
    };
    out.finish(StepResult::new(
        ProbeStep::Connect,
        StepStatus::Ok,
        format!("Logged in to {}{tls}.", opts.host),
    ));
    let via_proxy = opts.net.proxy.is_some() || opts.ftp_proxy.is_some();
    let ignore_unroutable = settings.ftp.passive_ignore_unroutable_ip;

    // 2. The address in the PASV reply.
    let mut nat_warning = false;
    if let Some(c) = ensure(&mut conn, opts, &ctx, &cancel).await {
        out.start(ProbeStep::PassiveAddress);
        let result = passive_address(c, via_proxy, ignore_unroutable, &cancel).await;
        nat_warning = result.status == StepStatus::Warning;
        out.finish(result);
    } else {
        out.finish(not_connected(ProbeStep::PassiveAddress, &cancel));
    }

    // 3. Passive listing.
    if let Some(c) = ensure(&mut conn, opts, &ctx, &cancel).await {
        out.start(ProbeStep::Passive);
        let mut data = DataSession::new(data_options(
            opts,
            settings,
            FtpTransferMode::Passive,
            probe,
        ));
        let outcome = list(c, &mut data, probe, &cancel).await;
        out.finish(passive_result(outcome, nat_warning && !ignore_unroutable));
    } else {
        out.finish(not_connected(ProbeStep::Passive, &cancel));
    }

    // 4 and 5: active mode, not through a proxy.
    if via_proxy {
        for step in [ProbeStep::ExternalAddress, ProbeStep::Active] {
            out.finish(StepResult::new(
                step,
                StepStatus::Skipped,
                "Not run: active mode doesn't work through a proxy.",
            ));
        }
    } else if let Some(c) = ensure(&mut conn, opts, &ctx, &cancel).await {
        out.start(ProbeStep::ExternalAddress);
        let data_opts = data_options(opts, settings, FtpTransferMode::Active, probe);
        out.finish(external_address(c, &data_opts, &cancel).await);
        if let Some(c) = ensure(&mut conn, opts, &ctx, &cancel).await {
            out.start(ProbeStep::Active);
            let mut data = DataSession::new(data_opts);
            let outcome = list(c, &mut data, probe, &cancel).await;
            out.finish(active_result(outcome, settings.ftp.active_port_range));
        } else {
            out.finish(not_connected(ProbeStep::Active, &cancel));
        }
    } else {
        for step in [ProbeStep::ExternalAddress, ProbeStep::Active] {
            out.finish(not_connected(step, &cancel));
        }
    }

    if let Some(conn) = conn.take() {
        conn.quit().await;
    }
    out.report
}

/// The report so far and where progress goes.
struct Progress<F> {
    report: ProbeReport,
    on_event: F,
}

impl<F: FnMut(ProbeEvent)> Progress<F> {
    fn start(&mut self, step: ProbeStep) {
        (self.on_event)(ProbeEvent::Started(step));
    }

    fn finish(&mut self, result: StepResult) {
        (self.on_event)(ProbeEvent::Finished(result.clone()));
        self.report.steps.push(result);
    }
}

/// Log in, stopping when `ctx.cancel` fires.
async fn connect(opts: &FtpOptions, ctx: &FtpContext) -> Result<ControlConnection, Error> {
    let token = CancellationToken::new();
    let inner = FtpContext {
        session: ctx.session,
        events: ctx.events.clone(),
        cancel: token.clone(),
    };
    tokio::select! {
        biased;
        () = ctx.cancel.cancelled() => {
            token.cancel();
            Err(Error::Cancelled)
        }
        r = control::connect(opts, inner) => r,
    }
}

/// The connection, reconnecting when a step lost it; `None` when that
/// fails or the test was cancelled.
async fn ensure<'a>(
    conn: &'a mut Option<ControlConnection>,
    opts: &FtpOptions,
    ctx: &FtpContext,
    cancel: &CancellationToken,
) -> Option<&'a mut ControlConnection> {
    if cancel.is_cancelled() {
        return None;
    }
    if !conn.as_ref().is_some_and(ControlConnection::is_connected) {
        *conn = connect(opts, ctx).await.ok();
    }
    conn.as_mut()
}

fn not_connected(step: ProbeStep, cancel: &CancellationToken) -> StepResult {
    let why = if cancel.is_cancelled() {
        "Cancelled."
    } else {
        "Not run: the connection was lost and could not be opened again."
    };
    StepResult::new(step, StepStatus::Skipped, why)
}

fn connect_failed(err: &Error) -> StepResult {
    let result = StepResult::new(
        ProbeStep::Connect,
        if matches!(err, Error::Cancelled) {
            StepStatus::Skipped
        } else {
            StepStatus::Failed
        },
        format!("Could not log in: {err}"),
    );
    match err {
        Error::Auth(_) => result.advice("Check the user name and password."),
        Error::Timeout => result.advice(
            "The server did not answer. Check the address and port, and that a firewall allows connections to it.",
        ),
        Error::Connection(_) | Error::Io(_) => {
            result.advice("Check the address and port, and that the server is running.")
        }
        Error::Tls(_) => result.advice(
            "The TLS connection failed. Check the site's encryption setting or trust the server's certificate.",
        ),
        _ => result,
    }
}

/// The data options for one mode, without the fallback (each mode is
/// tested on its own).
fn data_options(
    opts: &FtpOptions,
    settings: &Settings,
    mode: FtpTransferMode,
    probe: &ProbeOptions,
) -> DataOptions {
    let mut data = DataOptions::new(
        settings,
        Some(mode),
        opts.host.clone(),
        &opts.net,
        probe.data_timeout,
    );
    data.fallback_to_active = false;
    data
}

/// Send a bare `PASV` and look at the address.
async fn passive_address(
    conn: &mut ControlConnection,
    via_proxy: bool,
    ignore_unroutable: bool,
    cancel: &CancellationToken,
) -> StepResult {
    let step = ProbeStep::PassiveAddress;
    let peer = conn.peer_addr();
    if via_proxy {
        return StepResult::new(
            step,
            StepStatus::Skipped,
            "Not checked: the connection goes through a proxy.",
        );
    }
    let Some(peer) = peer else {
        return StepResult::new(step, StepStatus::Skipped, "Not checked.");
    };
    if peer.ip().to_canonical().is_ipv6() {
        return StepResult::new(
            step,
            StepStatus::Ok,
            "IPv6 connection: EPSV is used, which carries no address.",
        );
    }
    let reply = match conn.send_with("PASV", cancel).await {
        Ok(reply) => reply,
        Err(err) => {
            return StepResult::new(step, StepStatus::Failed, format!("PASV failed: {err}"));
        }
    };
    if reply.code != 227 {
        return StepResult::new(
            step,
            if conn.features().epsv {
                StepStatus::Ok
            } else {
                StepStatus::Warning
            },
            format!(
                "The server refused PASV ({}); EPSV may still work.",
                reply.text()
            ),
        );
    }
    match parse_pasv(&reply.text()) {
        Some(addr) => analyze_pasv(addr, peer, ignore_unroutable),
        None => StepResult::new(
            step,
            StepStatus::Warning,
            format!("Could not read the PASV reply: {}", reply.text()),
        ),
    }
}

/// What the `227` address `pasv` says about the server reached at `peer`
/// (server-side NAT detection).
pub fn analyze_pasv(pasv: SocketAddrV4, peer: SocketAddr, ignore_unroutable: bool) -> StepResult {
    let step = ProbeStep::PassiveAddress;
    let announced = IpAddr::V4(*pasv.ip());
    let peer_ip = peer.ip().to_canonical();
    if announced == peer_ip {
        return StepResult::new(
            step,
            StepStatus::Ok,
            format!("The server announces its own address ({announced})."),
        );
    }
    if announced.is_unspecified() {
        return StepResult::new(
            step,
            StepStatus::Ok,
            "The server announces 0.0.0.0; the server's address is used instead.",
        );
    }
    if !is_routable(announced) && is_routable(peer_ip) {
        let detail = format!(
            "The server is behind NAT: it announces its private address {announced} instead of {peer_ip}."
        );
        let result = StepResult::new(step, StepStatus::Warning, detail);
        return if ignore_unroutable {
            result.advice("“Use the server's external IP address instead” is on, so the server's address is used.")
        } else {
            result.advice("Turn on “Use the server's external IP address instead”, or ask the server's administrator to set its external address.")
        };
    }
    StepResult::new(
        step,
        StepStatus::Warning,
        format!(
            "The server announces {announced}, not the address you connected to ({peer_ip}). Data connections go there."
        ),
    )
    .advice("If the passive listing fails, the server's passive address is set up wrongly: ask its administrator, or use active mode.")
}

/// How a listing went.
enum ListOutcome {
    /// Data arrived (bytes read).
    Listed(usize),
    /// The server refused the command or the data connection.
    Refused(String),
    Failed(Error),
}

/// `LIST` through `data`, reading at most `max_listing` bytes.
async fn list(
    conn: &mut ControlConnection,
    data: &mut DataSession,
    probe: &ProbeOptions,
    cancel: &CancellationToken,
) -> ListOutcome {
    let open = match data.open(conn, "LIST", None, cancel).await {
        Ok(open) => open,
        Err(err) => return ListOutcome::Failed(err),
    };
    let mut stream = match open {
        DataOpen::Stream(stream) => stream,
        DataOpen::Done(_) => return ListOutcome::Listed(0),
        DataOpen::Refused(reply) => return ListOutcome::Refused(reply.text()),
    };
    let flags = stream.flags();
    let read = async {
        let mut total = 0usize;
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => return Ok((total, true)),
                Ok(n) => {
                    total += n;
                    if total >= probe.max_listing {
                        return Ok((total, false));
                    }
                }
                Err(err) => return Err(err),
            }
        }
    };
    let read = tokio::select! {
        biased;
        () = cancel.cancelled() => Err(Error::Cancelled),
        r = read => r.map_err(Error::from),
    };
    drop(stream);
    match read {
        Ok((total, complete)) => match finish(conn, &flags, false).await {
            Ok(_) => ListOutcome::Listed(total),
            // Aborted on purpose after enough data.
            Err(Error::Cancelled) if !complete => ListOutcome::Listed(total),
            Err(err) if total > 0 => {
                tracing::debug!(%err, "listing completion");
                ListOutcome::Listed(total)
            }
            Err(err) => ListOutcome::Failed(err),
        },
        Err(err) => {
            let _ = finish(conn, &flags, false).await;
            ListOutcome::Failed(err)
        }
    }
}

fn listed(mode: &str, bytes: usize) -> String {
    format!("{mode} mode works: the listing arrived ({bytes} bytes).")
}

fn passive_result(outcome: ListOutcome, nat_unhandled: bool) -> StepResult {
    let step = ProbeStep::Passive;
    match outcome {
        ListOutcome::Listed(n) => StepResult::new(step, StepStatus::Ok, listed("Passive", n)),
        ListOutcome::Failed(Error::Cancelled) => {
            StepResult::new(step, StepStatus::Skipped, "Cancelled.")
        }
        ListOutcome::Refused(text) => StepResult::new(
            step,
            StepStatus::Failed,
            format!("The server could not open the passive data connection: {text}"),
        )
        .advice("The server's firewall blocks its passive ports. Try active mode, or ask the server's administrator."),
        ListOutcome::Failed(
            err @ (Error::Timeout | Error::Connection(_) | Error::Io(_)),
        ) => {
            let result = StepResult::new(
                step,
                StepStatus::Failed,
                format!("Could not open the passive data connection: {err}"),
            );
            if nat_unhandled {
                result.advice("Passive mode failed because the server announces a private address. Turn on “Use the server's external IP address instead”.")
            } else {
                result.advice("A firewall between you and the server blocks the server's passive ports. Try active mode, or ask the server's administrator.")
            }
        }
        ListOutcome::Failed(err) => StepResult::new(
            step,
            StepStatus::Failed,
            format!("The server refused passive mode: {err}"),
        )
        .advice("Use active mode."),
    }
}

fn active_result(outcome: ListOutcome, range: Option<(u16, u16)>) -> StepResult {
    let step = ProbeStep::Active;
    let blocked = || match range {
        Some((lo, hi)) => format!(
            "{ACTIVE_BLOCKED} To use active mode, forward TCP ports {lo}-{hi} on your router to this computer."
        ),
        None => format!(
            "{ACTIVE_BLOCKED} To use active mode, set a port range and forward those ports on your router to this computer."
        ),
    };
    match outcome {
        ListOutcome::Listed(n) => StepResult::new(step, StepStatus::Ok, listed("Active", n)),
        ListOutcome::Failed(Error::Cancelled) => {
            StepResult::new(step, StepStatus::Skipped, "Cancelled.")
        }
        ListOutcome::Refused(text) => StepResult::new(
            step,
            StepStatus::Failed,
            format!("The server could not connect back: {text}"),
        )
        .advice(blocked()),
        ListOutcome::Failed(Error::Timeout) => StepResult::new(
            step,
            StepStatus::Failed,
            "The server did not connect back in time.",
        )
        .advice(blocked()),
        ListOutcome::Failed(Error::Unsupported(why)) => {
            StepResult::new(step, StepStatus::Skipped, format!("Not run: {why}."))
        }
        ListOutcome::Failed(err @ (Error::Connection(_) | Error::Io(_))) => StepResult::new(
            step,
            StepStatus::Failed,
            format!("Active mode failed: {err}"),
        )
        .advice("Check the active mode port range, or use passive mode."),
        ListOutcome::Failed(err) => StepResult::new(
            step,
            StepStatus::Failed,
            format!("The server refused active mode (PORT/EPRT): {err}"),
        )
        .advice("Use passive mode."),
    }
}

/// The address active mode will announce.
async fn external_address(
    conn: &ControlConnection,
    data: &DataOptions,
    cancel: &CancellationToken,
) -> StepResult {
    let (Some(local), Some(peer)) = (conn.local_addr(), conn.peer_addr()) else {
        return StepResult::new(
            ProbeStep::ExternalAddress,
            StepStatus::Skipped,
            "Not checked.",
        );
    };
    let fetched = match &data.external_ip {
        // Run even for a server on the local network (where the answer
        // isn't announced), so the URL being tested is checked; it is the
        // user's own URL, never a built-in one.
        ExternalIp::FromUrl(url) => {
            let r = tokio::select! {
                biased;
                () = cancel.cancelled() => Err(Error::Cancelled),
                r = external_ip::fetch(url, data, conn.cancel_token(), conn.events(), conn.session()) => r,
            };
            Some(r.map_err(|e| e.to_string()))
        }
        _ => None,
    };
    analyze_external(local.ip(), peer.ip(), &data.external_ip, fetched)
}

/// What active mode will announce from `local` to a server at `peer`
/// with `setting`; `fetched` is the IP lookup's answer (with *get from
/// URL*, for a public server). Detects this computer being behind NAT.
pub fn analyze_external(
    local: IpAddr,
    peer: IpAddr,
    setting: &ExternalIp,
    fetched: Option<Result<IpAddr, String>>,
) -> StepResult {
    let step = ProbeStep::ExternalAddress;
    let (local, peer) = (local.to_canonical(), peer.to_canonical());
    if local.is_ipv6() {
        return StepResult::new(
            step,
            StepStatus::Ok,
            format!("IPv6 connection: your address {local} is announced (no NAT)."),
        );
    }
    if !is_routable(peer) {
        let local_net = format!(
            "The server is on your local network: your local address {local} is announced."
        );
        return match fetched {
            Some(Ok(ip)) => StepResult::new(
                step,
                StepStatus::Ok,
                format!("{local_net} The IP lookup works (it returned {ip}, used for servers on the internet)."),
            ),
            Some(Err(err)) => StepResult::new(
                step,
                StepStatus::Warning,
                format!("{local_net} The IP lookup failed ({err}), so servers on the internet would get {local} too."),
            )
            .advice("Check the lookup URL (http:// only), or enter your address with “Use this IP”."),
            None => StepResult::new(step, StepStatus::Ok, local_net),
        };
    }
    let behind_nat = !is_routable(local);
    match setting {
        ExternalIp::Auto if behind_nat => StepResult::new(
            step,
            StepStatus::Warning,
            format!("You are behind NAT: active mode announces your local address {local}, which the server can't reach."),
        )
        .advice("Choose “Use this IP” with your public address, or “Get from URL”, and forward the active mode ports on your router."),
        ExternalIp::Auto => StepResult::new(
            step,
            StepStatus::Ok,
            format!("Your address {local} is public and is announced as it is."),
        ),
        ExternalIp::Fixed(ip) => {
            let result = StepResult::new(
                step,
                StepStatus::Ok,
                format!("{ip} is announced (your local address is {local})."),
            );
            if behind_nat {
                result.advice("Forward the active mode ports on your router to this computer.")
            } else {
                result
            }
        }
        ExternalIp::FromUrl(_) => match fetched {
            Some(Ok(ip)) if ip == local => StepResult::new(
                step,
                StepStatus::Ok,
                format!("The lookup returned {ip}, your own address: no NAT."),
            ),
            Some(Ok(ip)) => StepResult::new(
                step,
                StepStatus::Ok,
                format!("The lookup returned {ip}; your local address is {local}, so you are behind NAT."),
            )
            .advice("Forward the active mode ports on your router to this computer."),
            Some(Err(err)) => StepResult::new(
                step,
                StepStatus::Failed,
                format!("The IP lookup failed ({err}); your local address {local} would be announced."),
            )
            .advice("Check the lookup URL (http:// only), or enter your address with “Use this IP”."),
            None => StepResult::new(step, StepStatus::Skipped, "The IP lookup was not run."),
        },
    }
}

#[cfg(test)]
mod tests;
