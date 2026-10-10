//! [`FtpRelayProxy`]: a minimal in-process FTP proxy for the FTP proxy types (T15).
//!
//! It greets with `220 courier-ftp-e2e relay`, optionally requires proxy credentials
//! ([`PROXY_USER`]/[`PROXY_PASSWORD`]), learns the target from `USER u@host[:port]`,
//! `SITE host[:port]` or `OPEN host[:port]` (per [`FtpRelayMode`]), connects to it (only
//! targets in `allowed_targets`, so it is not an open proxy), then relays the control
//! connection line by line. `227`/`229` replies are rewritten so data connections go
//! through a relayed listener on `127.0.0.1` (passive mode only; `PORT`/`EPRT` get
//! `502`). The relay only forwards bytes; it never inspects listings or data.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use parking_lot::Mutex;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, tcp::OwnedWriteHalf},
    sync::mpsc,
    task::JoinHandle,
};

use crate::{
    Result,
    hostile::{mask_pass, split_command},
    keys::{PROXY_PASSWORD, PROXY_USER},
};

/// The relay's greeting.
pub const RELAY_GREETING: &str = "220 courier-ftp-e2e relay";

/// Which login convention the relay accepts (FileZilla's FTP proxy types).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpRelayMode {
    /// `USER user@host[:port]`, then `PASS` for the target.
    UserAtHost,
    /// `SITE host[:port]`, then `USER`/`PASS` for the target.
    Site,
    /// `OPEN host[:port]`, then `USER`/`PASS` for the target.
    Open,
}

impl FtpRelayMode {
    /// Every mode.
    pub const ALL: [Self; 3] = [Self::UserAtHost, Self::Site, Self::Open];
}

/// A parsed target command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TargetCmd {
    /// Not a target command in this mode.
    NotTarget,
    /// The target, and for `USER u@host` the user to log in as.
    Target {
        /// `USER u@host`: `u`.
        user: Option<String>,
        /// The target.
        addr: SocketAddr,
    },
    /// A target command with an unusable host (`501`).
    Malformed,
}

/// `host[:port]` with an IP literal host; port 21 by default.
fn parse_host_port(text: &str) -> Option<SocketAddr> {
    let text = text.trim();
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 21));
    }
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return (addr.port() != 0).then_some(addr);
    }
    None
}

/// Whether `line` names the target in `mode`.
pub(crate) fn parse_target(mode: FtpRelayMode, line: &str) -> TargetCmd {
    let (verb, arg) = split_command(line);
    match (mode, verb.as_str()) {
        (FtpRelayMode::UserAtHost, "USER") => match arg.rsplit_once('@') {
            Some((user, host)) => match parse_host_port(host) {
                Some(addr) if !user.is_empty() => TargetCmd::Target {
                    user: Some(user.to_owned()),
                    addr,
                },
                _ => TargetCmd::Malformed,
            },
            None => TargetCmd::NotTarget,
        },
        (FtpRelayMode::Site, "SITE") | (FtpRelayMode::Open, "OPEN") => match parse_host_port(arg) {
            Some(addr) => TargetCmd::Target { user: None, addr },
            None => TargetCmd::Malformed,
        },
        _ => TargetCmd::NotTarget,
    }
}

/// The data address of a `227 … (h1,h2,h3,h4,p1,p2)` reply.
pub fn parse_pasv(line: &str) -> Option<SocketAddr> {
    if !line.starts_with("227") {
        return None;
    }
    // `(h1,h2,h3,h4,p1,p2)`, or the first run of digits and commas after the code.
    let inner = match (line.find('('), line.rfind(')')) {
        (Some(a), Some(b)) if a < b => &line[a + 1..b],
        _ => {
            let rest = line.get(4..)?;
            let start = rest.find(|c: char| c.is_ascii_digit())?;
            let rest = &rest[start..];
            let end = rest
                .find(|c: char| !(c.is_ascii_digit() || c == ','))
                .unwrap_or(rest.len());
            &rest[..end]
        }
    };
    let nums: Vec<u8> = inner
        .split(',')
        .map(|p| p.trim().parse().ok())
        .collect::<Option<_>>()?;
    let [a, b, c, d, p1, p2] = nums.as_slice() else {
        return None;
    };
    Some(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
        u16::from(*p1) << 8 | u16::from(*p2),
    ))
}

/// The data port of a `229 … (|||port|)` reply.
pub fn parse_epsv(line: &str) -> Option<u16> {
    if !line.starts_with("229") {
        return None;
    }
    let a = line.find('(')?;
    let b = line.rfind(')')?;
    let inner = line.get(a + 1..b)?;
    let delim = inner.chars().next()?;
    let parts: Vec<&str> = inner.split(delim).collect();
    match parts.as_slice() {
        ["", "", "", port, ""] => port.parse().ok(),
        _ => None,
    }
}

/// Where a `227`/`229` reply points the client, given the upstream control IP.
pub(crate) fn data_target(line: &str, upstream_ip: IpAddr) -> Option<SocketAddr> {
    parse_pasv(line).or_else(|| parse_epsv(line).map(|p| SocketAddr::new(upstream_ip, p)))
}

/// The reply that sends the client to `local` instead (same code as `line`).
pub(crate) fn rewrite_data_reply(line: &str, local: SocketAddr) -> String {
    let port = local.port();
    if line.starts_with("229") {
        format!("229 Entering Extended Passive Mode (|||{port}|)")
    } else {
        let ip = match local.ip() {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(_) => [127, 0, 0, 1],
        };
        format!(
            "227 Entering Passive Mode ({},{},{},{},{},{})",
            ip[0],
            ip[1],
            ip[2],
            ip[3],
            port >> 8,
            port & 0xff
        )
    }
}

/// An FTP proxy on `127.0.0.1`. Stops when dropped.
#[derive(Debug)]
pub struct FtpRelayProxy {
    addr: SocketAddr,
    commands: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

struct RelayConfig {
    mode: FtpRelayMode,
    require_auth: bool,
    allowed: Vec<SocketAddr>,
}

impl FtpRelayProxy {
    /// Start a relay in `mode`; `require_auth` demands `USER proxyuser`/`PASS proxypass`
    /// before the target; only `allowed_targets` are connected to.
    ///
    /// # Errors
    /// The listener could not be bound.
    pub async fn start(
        mode: FtpRelayMode,
        require_auth: bool,
        allowed_targets: Vec<SocketAddr>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let commands = Arc::new(Mutex::new(Vec::new()));
        let cfg = Arc::new(RelayConfig {
            mode,
            require_auth,
            allowed: allowed_targets,
        });
        let log = Arc::clone(&commands);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let cfg = Arc::clone(&cfg);
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let _ = serve(stream, &cfg, &log).await;
                });
            }
        });
        Ok(Self {
            addr,
            commands,
            task,
        })
    }

    /// The proxy's control address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every control line received from clients, with `PASS` arguments masked as
    /// `****`.
    pub fn commands(&self) -> Vec<String> {
        self.commands.lock().clone()
    }
}

impl Drop for FtpRelayProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn send(w: &mut OwnedWriteHalf, line: &str) -> std::io::Result<()> {
    w.write_all(line.as_bytes()).await?;
    w.write_all(b"\r\n").await?;
    w.flush().await
}

/// Read one line without CRLF; `None` at EOF.
async fn read_line(
    r: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    if r.read_until(b'\n', &mut buf).await? == 0 {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&buf)
            .trim_end_matches(['\r', '\n'])
            .to_owned(),
    ))
}

/// Read a complete (possibly multi-line) reply; returns its lines.
async fn read_reply(
    r: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> std::io::Result<Vec<String>> {
    let mut lines = Vec::new();
    loop {
        let Some(line) = read_line(r).await? else {
            return Err(std::io::Error::other("upstream closed"));
        };
        let multi_start = lines.is_empty() && line.as_bytes().get(3) == Some(&b'-');
        let code = lines
            .first()
            .and_then(|f: &String| f.get(..3))
            .map(str::to_owned);
        lines.push(line.clone());
        let done = match code {
            None => !multi_start,
            Some(c) => line.starts_with(&c) && line.as_bytes().get(3) == Some(&b' '),
        };
        if done {
            return Ok(lines);
        }
    }
}

async fn serve(stream: TcpStream, cfg: &RelayConfig, log: &Mutex<Vec<String>>) -> Result<()> {
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    send(&mut w, RELAY_GREETING).await?;

    // Phase 1: proxy login and target.
    let mut authed = !cfg.require_auth;
    let mut proxy_user_ok = false;
    let (target, target_user) = loop {
        let Some(line) = read_line(&mut r).await? else {
            return Ok(());
        };
        log.lock().push(mask_pass(&line));
        let (verb, arg) = split_command(&line);
        match parse_target(cfg.mode, &line) {
            TargetCmd::Malformed => send(&mut w, "501 Malformed target host").await?,
            TargetCmd::Target { .. } if !authed => {
                send(&mut w, "530 Log in to the proxy first").await?;
            }
            TargetCmd::Target { addr, .. } if !cfg.allowed.contains(&addr) => {
                send(&mut w, "550 Target not allowed by this proxy").await?;
            }
            TargetCmd::Target { user, addr } => break (addr, user),
            TargetCmd::NotTarget => match verb.as_str() {
                "USER" if !authed => {
                    proxy_user_ok = arg == PROXY_USER;
                    send(&mut w, "331 Proxy password required").await?;
                }
                "PASS" if !authed => {
                    if proxy_user_ok && arg == PROXY_PASSWORD {
                        authed = true;
                        send(&mut w, "230 Proxy login successful").await?;
                    } else {
                        send(&mut w, "530 Proxy login incorrect").await?;
                    }
                }
                "QUIT" => {
                    send(&mut w, "221 Bye").await?;
                    return Ok(());
                }
                _ => send(&mut w, "530 Name the target first").await?,
            },
        }
    };

    // Phase 2: connect to the target.
    let upstream = match TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            send(&mut w, &format!("421 Cannot connect to {target}: {e}")).await?;
            return Ok(());
        }
    };
    let upstream_ip = upstream.peer_addr()?.ip();
    let (ur, mut uw) = upstream.into_split();
    let mut ur = BufReader::new(ur);
    let greeting = read_reply(&mut ur).await?;
    match target_user {
        Some(user) => {
            // USER u@host: log in as `u` and relay the target's answer.
            send(&mut uw, &format!("USER {user}")).await?;
            for line in read_reply(&mut ur).await? {
                send(&mut w, &line).await?;
            }
        }
        None => {
            for line in greeting {
                send(&mut w, &line).await?;
            }
        }
    }

    // Phase 3: relay. Client output goes through one channel (two writers).
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if send(&mut w, &line).await.is_err() {
                break;
            }
        }
    });
    let to_client = tx.clone();
    let upstream_task = tokio::spawn(async move {
        while let Ok(Some(line)) = read_line(&mut ur).await {
            let line = match data_target(&line, upstream_ip) {
                Some(dest) => match relay_data(dest).await {
                    Ok(local) => rewrite_data_reply(&line, local),
                    Err(e) => format!("425 Relay data listener failed: {e}"),
                },
                None => line,
            };
            if to_client.send(line).is_err() {
                break;
            }
        }
    });
    while let Some(line) = read_line(&mut r).await? {
        log.lock().push(mask_pass(&line));
        let (verb, _) = split_command(&line);
        if verb == "PORT" || verb == "EPRT" {
            let _ = tx.send("502 Active mode is not supported by this proxy".into());
            continue;
        }
        if send(&mut uw, &line).await.is_err() {
            break;
        }
    }
    upstream_task.abort();
    drop(tx);
    let _ = writer.await;
    Ok(())
}

/// A one-shot listener on 127.0.0.1 that relays its first connection to `dest`.
async fn relay_data(dest: SocketAddr) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let local = listener.local_addr()?;
    tokio::spawn(async move {
        let Ok(Ok((mut client, _))) =
            tokio::time::timeout(crate::timeout(), listener.accept()).await
        else {
            return;
        };
        let Ok(mut server) = TcpStream::connect(dest).await else {
            return;
        };
        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
    });
    Ok(local)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_target_per_mode() {
        assert_eq!(
            parse_target(FtpRelayMode::UserAtHost, "USER test@10.0.0.2:2121"),
            TargetCmd::Target {
                user: Some("test".into()),
                addr: addr("10.0.0.2:2121")
            }
        );
        assert_eq!(
            parse_target(FtpRelayMode::Site, "SITE 10.0.0.2"),
            TargetCmd::Target {
                user: None,
                addr: addr("10.0.0.2:21")
            }
        );
        assert_eq!(
            parse_target(FtpRelayMode::Open, "open 10.0.0.2:21"),
            TargetCmd::Target {
                user: None,
                addr: addr("10.0.0.2:21")
            }
        );
        // Not a target in that mode.
        assert_eq!(
            parse_target(FtpRelayMode::Site, "OPEN 10.0.0.2"),
            TargetCmd::NotTarget
        );
        assert_eq!(
            parse_target(FtpRelayMode::UserAtHost, "USER proxyuser"),
            TargetCmd::NotTarget
        );
        // Malformed targets (answered with 501).
        for (mode, line) in [
            (FtpRelayMode::UserAtHost, "USER test@"),
            (FtpRelayMode::UserAtHost, "USER @10.0.0.2"),
            (FtpRelayMode::UserAtHost, "USER test@10.0.0.2:99999"),
            (FtpRelayMode::Site, "SITE"),
            (FtpRelayMode::Site, "SITE not a host"),
            (FtpRelayMode::Open, "OPEN 10.0.0.2:0"),
        ] {
            assert_eq!(parse_target(mode, line), TargetCmd::Malformed, "{line}");
        }
    }

    #[test]
    fn rewrites_pasv_and_epsv_replies() {
        let upstream: IpAddr = "10.0.0.2".parse().unwrap();
        let local = addr("127.0.0.1:40001");
        let pasv = "227 Entering Passive Mode (10,0,0,2,117,48)";
        assert_eq!(data_target(pasv, upstream), Some(addr("10.0.0.2:30000")));
        assert_eq!(
            rewrite_data_reply(pasv, local),
            "227 Entering Passive Mode (127,0,0,1,156,65)"
        );
        assert_eq!(parse_pasv(&rewrite_data_reply(pasv, local)), Some(local));

        let epsv = "229 Entering Extended Passive Mode (|||30000|)";
        assert_eq!(data_target(epsv, upstream), Some(addr("10.0.0.2:30000")));
        assert_eq!(
            rewrite_data_reply(epsv, local),
            "229 Entering Extended Passive Mode (|||40001|)"
        );
        // Other replies are left alone.
        assert_eq!(data_target("226 Transfer complete", upstream), None);
        assert_eq!(data_target("227 garbage", upstream), None);
    }
}
