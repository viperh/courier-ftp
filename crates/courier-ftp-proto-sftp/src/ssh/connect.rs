//! The connect flow (T20 "Connect flow"): validate → key file → TCP (T07) → handshake
//! (host-key seam; prompt time not counted against the timeout) → authentication →
//! keepalive (russh's). Every step is logged to the session log; `tracing` at info
//! level carries only the session id and the outcome (T91 §4).

use std::{
    borrow::Cow,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use courier_ftp_core::{
    Error,
    events::SessionLog,
    model::KeySource,
    net::{self, HostPort, NetStream},
};
use russh::{SshId, client};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use zeroize::Zeroizing;

use super::{
    SshConnectParams, SshConnection, SshLogon, algorithms,
    auth::{ChainTarget, KeyMaterial, PromptIo, RusshBackend, key_error, run_chain},
    errors::{SshError, from_russh},
    handler::{ClientHandler, HostKeyVerifier, Shared, lock},
};
use crate::{agent::AgentConnector, keys};

/// Unanswered keepalives before the connection is considered dead.
pub(crate) const KEEPALIVE_MAX: usize = 3;
/// russh channel window (T41b: the window must not throttle a fast link).
pub(crate) const WINDOW_SIZE: u32 = 16 * 1024 * 1024;
/// russh's maximum packet size.
pub(crate) const MAX_PACKET: u32 = 65_535;

/// The client identification string.
fn client_id() -> SshId {
    SshId::Standard(Cow::Owned(format!(
        "SSH-2.0-courier-ftp_{}",
        env!("CARGO_PKG_VERSION")
    )))
}

/// The russh client config.
pub(crate) fn client_config(
    known_key_types: &[String],
    keepalive: Option<Duration>,
) -> client::Config {
    client::Config {
        client_id: client_id(),
        preferred: algorithms::to_russh(&algorithms::preferences(known_key_types)),
        keepalive_interval: keepalive,
        keepalive_max: KEEPALIVE_MAX,
        inactivity_timeout: None,
        window_size: WINDOW_SIZE,
        maximum_packet_size: MAX_PACKET,
        nodelay: true,
        ..client::Config::default()
    }
}

/// The T07 stream, marking the connection closed when the read side ends (EOF or
/// error), so an open prompt is withdrawn at once.
struct WatchedStream {
    inner: NetStream,
    shared: Arc<Shared>,
}

impl AsyncRead for WatchedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        let ended = match &res {
            Poll::Ready(Ok(())) => buf.filled().len() == before && buf.remaining() > 0,
            Poll::Ready(Err(_)) => true,
            Poll::Pending => false,
        };
        if ended {
            self.shared.closed.send_replace(true);
        }
        res
    }
}

impl AsyncWrite for WatchedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// [`SshConnection::connect`].
pub(super) async fn connect(
    params: SshConnectParams,
    verifier: Arc<dyn HostKeyVerifier>,
    agent: Option<Arc<dyn AgentConnector>>,
    log: &SessionLog,
    cancel: CancellationToken,
) -> Result<SshConnection, Error> {
    let session = log.session.get();
    let result = connect_inner(&params, verifier, agent, log, &cancel).await;
    match &result {
        Ok(_) => info!(session, "ssh connection authenticated"),
        Err(SshError::Cancelled) => {
            log.status("Connection cancelled");
            info!(session, code = "cancelled", "ssh connect ended");
        }
        Err(err) => {
            log.error(err.message());
            let code = match err {
                SshError::Net(e) => e.code(),
                _ => "ssh",
            };
            info!(session, code, "ssh connect failed");
        }
    }
    result.map_err(SshError::into_core)
}

fn invalid(err: Error) -> SshError {
    match err {
        Error::InvalidInput(msg) => SshError::InvalidInput(msg),
        other => SshError::Net(other),
    }
}

/// The key text for a `KeyFile` logon (read before any network I/O).
fn key_material(params: &SshConnectParams) -> Result<Option<KeyMaterial>, SshError> {
    if params.logon != SshLogon::KeyFile {
        return Ok(None);
    }
    let text = match &params.key {
        Some(KeySource::Path(path)) => {
            keys::read_key_file(path.as_path()).map_err(|e| key_error(&params.key_label, &e))?
        }
        Some(KeySource::Inline(text)) => Zeroizing::new(text.expose().to_owned()),
        _ => {
            return Err(SshError::InvalidInput(
                "No key file is configured for this site".to_owned(),
            ));
        }
    };
    Ok(Some(KeyMaterial {
        text,
        label: params.key_label.clone(),
        passphrase: params
            .key_passphrase
            .as_ref()
            .map(|p| courier_ftp_core::secret::SecretString::from(p.expose())),
    }))
}

async fn connect_inner(
    params: &SshConnectParams,
    verifier: Arc<dyn HostKeyVerifier>,
    agent: Option<Arc<dyn AgentConnector>>,
    log: &SessionLog,
    cancel: &CancellationToken,
) -> Result<SshConnection, SshError> {
    // 1. Input checks and the key file, before any network I/O.
    params.validate().map_err(invalid)?;
    let key = key_material(params)?;
    debug!(
        session = log.session.get(),
        host = %params.host,
        port = params.port,
        user = %params.user,
        "ssh connect"
    );

    // 2. TCP through the network layer (DNS, IPv6, proxies, connect timeout).
    let target = HostPort::new(params.host.clone(), params.port);
    let stream = net::connect_tcp(&target, &params.net, cancel.clone(), log)
        .await
        .map_err(|e| match e {
            Error::Cancelled => SshError::Cancelled,
            other => SshError::Net(other),
        })?;

    // 3. Handshake; the handler asks the verifier.
    let shared = Arc::new(Shared::default());
    let known = verifier.known_key_types(&params.host, params.port);
    let config = Arc::new(client_config(&known, params.keepalive));
    let handler = ClientHandler {
        verifier,
        host: params.host.clone(),
        port: params.port,
        shared: Arc::clone(&shared),
        log: log.clone(),
        cancel: cancel.clone(),
        banner_lines: 0,
        banner_chars: 0,
    };
    let stream = WatchedStream {
        inner: stream,
        shared: Arc::clone(&shared),
    };
    let keepalive_secs = params.keepalive.map_or(0, |d| d.as_secs());
    let mut handle = handshake(config, stream, handler, &shared, params.timeout, cancel).await?;
    let mut info = lock(&shared.info).clone();
    log.status(format!("Server version: {}", info.server_version));
    log.debug(
        3,
        format!(
            "kex={} hostkey={} cipher={} mac={}",
            info.kex, info.host_key_algorithm, info.cipher, info.mac
        ),
    );

    // 4–5. Authentication (the banner is logged by the handler).
    let chain_target = ChainTarget {
        user: &params.user,
        logon: params.logon,
        password: params.password.as_ref(),
        key: key.as_ref(),
        try_agent_first: params.try_agent_first,
    };
    let method = {
        let mut backend = RusshBackend {
            handle: &mut handle,
            shared: Arc::clone(&shared),
            timeout: params.timeout,
            keepalive_secs,
            cancel: cancel.clone(),
        };
        let mut io = PromptIo::new(log, cancel, Arc::clone(&shared), params);
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(SshError::Cancelled),
            r = run_chain(&chain_target, &mut backend, &mut io, agent) => r,
        }?
    };
    drop(key);
    log.status(format!("Authenticated using {method}."));
    info.auth_method = method.to_owned();
    lock(&shared.info).auth_method = method.to_owned();

    // 6. Keepalive is russh's (`keepalive_interval`, `keepalive_max = 3`).
    Ok(SshConnection {
        handle,
        shared,
        info,
        keepalive_secs,
        timeout: params.timeout,
    })
}

/// The SSH handshake, bounded by `timeout` while the verifier is not deciding (the
/// deadline restarts after its answer) and by `cancel`.
async fn handshake(
    config: Arc<client::Config>,
    stream: WatchedStream,
    handler: ClientHandler,
    shared: &Arc<Shared>,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<client::Handle<ClientHandler>, SshError> {
    let fut = client::connect_stream(config, stream, handler);
    tokio::pin!(fut);
    let mut verifying = shared.verifying.subscribe();
    let mut deadline = Some(Instant::now() + timeout);
    loop {
        let sleep = async {
            match deadline {
                Some(d) => tokio::time::sleep_until(d).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(SshError::Cancelled),
            res = &mut fut => {
                return match res {
                    Ok(handle) => Ok(handle),
                    Err(err) => Err(handshake_error(&err.0, shared)),
                };
            }
            changed = verifying.changed() => {
                if changed.is_err() {
                    // The sender lives in `shared`, which we hold: unreachable.
                    continue;
                }
                deadline = if *verifying.borrow_and_update() {
                    None
                } else {
                    Some(Instant::now() + timeout)
                };
            }
            () = sleep => return Err(SshError::HandshakeTimeout),
        }
    }
}

/// Why the handshake failed: a host-key rejection the handler recorded, the server's
/// disconnect, else russh's error.
fn handshake_error(err: &russh::Error, shared: &Shared) -> SshError {
    if let Some(reason) = lock(&shared.host_key_rejection).clone() {
        return SshError::HostKey(reason);
    }
    if let Some(cause) = shared.end.borrow().clone() {
        return cause.to_error(0);
    }
    from_russh(err, 0)
}
