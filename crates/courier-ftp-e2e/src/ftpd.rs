//! [`Ftpd`]: FTP/FTPS servers in Docker (vsftpd, proftpd, pure-ftpd), one image
//! (`tests/fixtures/ftpd/`) with runtime-selected [`FtpdProfile`]s and certificate
//! variants ([`CertVariant`]) signed by the TEST-ONLY CA in `tests/fixtures/tls/`.
//!
//! Control port 21 (implicit TLS: 990), passive ports 30000–30019, users `test` and
//! `canary` chrooted to their homes (`~/upload/` writable, `~/fixtures/` tree).

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use base64::Engine as _;

use crate::{
    E2eError, Result,
    docker::{self, ExecOutput, Fixture, FixtureSpec},
    keys,
};

/// The passive port range of every profile.
pub const PASV_PORTS: std::ops::RangeInclusive<u16> = 30000..=30019;

/// A server configuration of the ftpd image (`tests/fixtures/ftpd/profiles/<name>.conf`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FtpdProfile {
    /// vsftpd, plain FTP (LIST only).
    VsftpdPlain,
    /// vsftpd, explicit TLS required, no session reuse required.
    VsftpdExplicitTls,
    /// vsftpd, implicit TLS on port 990.
    VsftpdImplicitTls,
    /// vsftpd, explicit TLS with `require_ssl_reuse=YES`.
    VsftpdTlsReuse,
    /// vsftpd, `pasv_enable=NO`.
    VsftpdActiveOnly,
    /// vsftpd announcing an unreachable PASV address (`10.255.255.1`).
    VsftpdPasvUnreachable,
    /// vsftpd, one connection at a time (`421` on the second).
    VsftpdMaxConn1,
    /// vsftpd, anonymous read-only (`/srv/anon`).
    VsftpdAnonymous,
    /// vsftpd limited to 256 KiB/s.
    VsftpdSlow,
    /// proftpd, plain (MLSD, `SITE CHMOD`, `MFMT`).
    ProftpdPlain,
    /// proftpd + mod_tls, TLS required, session reuse required.
    ProftpdExplicitTls,
    /// pure-ftpd, plain (its own LIST format, MLSD).
    PureftpdPlain,
    /// pure-ftpd, TLS required for login.
    PureftpdExplicitTls,
}

impl FtpdProfile {
    /// Every profile.
    pub const ALL: [Self; 13] = [
        Self::VsftpdPlain,
        Self::VsftpdExplicitTls,
        Self::VsftpdImplicitTls,
        Self::VsftpdTlsReuse,
        Self::VsftpdActiveOnly,
        Self::VsftpdPasvUnreachable,
        Self::VsftpdMaxConn1,
        Self::VsftpdAnonymous,
        Self::VsftpdSlow,
        Self::ProftpdPlain,
        Self::ProftpdExplicitTls,
        Self::PureftpdPlain,
        Self::PureftpdExplicitTls,
    ];

    /// The profile name (`FTPD_PROFILE=<name>`).
    pub fn name(self) -> &'static str {
        match self {
            Self::VsftpdPlain => "vsftpd-plain",
            Self::VsftpdExplicitTls => "vsftpd-explicit-tls",
            Self::VsftpdImplicitTls => "vsftpd-implicit-tls",
            Self::VsftpdTlsReuse => "vsftpd-tls-reuse",
            Self::VsftpdActiveOnly => "vsftpd-active-only",
            Self::VsftpdPasvUnreachable => "vsftpd-pasv-unreachable",
            Self::VsftpdMaxConn1 => "vsftpd-maxconn1",
            Self::VsftpdAnonymous => "vsftpd-anonymous",
            Self::VsftpdSlow => "vsftpd-slow",
            Self::ProftpdPlain => "proftpd-plain",
            Self::ProftpdExplicitTls => "proftpd-explicit-tls",
            Self::PureftpdPlain => "pureftpd-plain",
            Self::PureftpdExplicitTls => "pureftpd-explicit-tls",
        }
    }

    /// The control port: 990 for implicit TLS, else 21.
    pub fn control_port(self) -> u16 {
        if self == Self::VsftpdImplicitTls {
            990
        } else {
            21
        }
    }

    /// Whether the server speaks MLSD (vsftpd does not).
    pub fn has_mlsd(self) -> bool {
        !self.name().starts_with("vsftpd-")
    }
}

/// Which server certificate the entrypoint generates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CertVariant {
    /// Signed by the fixture CA, valid one year, SAN = container IP and `ftpd.test`.
    #[default]
    CaSigned,
    /// Self-signed, same SAN.
    SelfSigned,
    /// Signed by the CA, expired in 2021.
    Expired,
    /// Signed by the CA, SAN `DNS:wrong.example` only.
    WrongHost,
}

impl CertVariant {
    /// The name (`FTPD_CERT=<name>`, `courier-set-cert <name>`).
    pub fn name(self) -> &'static str {
        match self {
            Self::CaSigned => "ca-signed",
            Self::SelfSigned => "self-signed",
            Self::Expired => "expired",
            Self::WrongHost => "wrong-host",
        }
    }
}

/// How to start an [`Ftpd`].
#[derive(Debug, Clone)]
pub struct FtpdOptions {
    /// The profile.
    pub profile: FtpdProfile,
    /// The server certificate.
    pub cert: CertVariant,
    /// Join this network; default bridge otherwise.
    pub network: Option<String>,
    /// Address announced in PASV replies (default: the container IP).
    pub pasv_address: Option<IpAddr>,
}

impl FtpdOptions {
    /// `profile` with a CA-signed certificate on the default bridge.
    pub fn new(profile: FtpdProfile) -> Self {
        Self {
            profile,
            cert: CertVariant::default(),
            network: None,
            pasv_address: None,
        }
    }
}

/// An FTP server in a container (removed on drop; logs dumped when failing).
#[derive(Debug)]
pub struct Ftpd {
    fixture: Fixture,
    profile: FtpdProfile,
}

impl Ftpd {
    /// Start `profile` and wait until it answers.
    ///
    /// # Errors
    /// Docker or the image build failed, or the server did not come up.
    pub async fn start(profile: FtpdProfile) -> Result<Self> {
        Self::start_with(FtpdOptions::new(profile)).await
    }

    /// Start as described by `opts`.
    ///
    /// # Errors
    /// As [`Ftpd::start`].
    pub async fn start_with(opts: FtpdOptions) -> Result<Self> {
        let mut env = vec![
            ("FTPD_PROFILE".to_owned(), opts.profile.name().to_owned()),
            ("FTPD_CERT".to_owned(), opts.cert.name().to_owned()),
        ];
        if let Some(ip) = opts.pasv_address {
            env.push(("FTPD_PASV_ADDRESS".to_owned(), ip.to_string()));
        }
        let fixture = Fixture::start(FixtureSpec {
            image: docker::image("ftpd").await?,
            label: format!("ftpd {}", opts.profile.name()),
            env,
            network: opts.network,
            // pure-ftpd keeps SYS_NICE and DAC_READ_SEARCH and exits without them.
            cap_add: vec![
                "SYS_CHROOT".into(),
                "SYS_NICE".into(),
                "DAC_READ_SEARCH".into(),
            ],
        })
        .await?;
        let ftpd = Self {
            fixture,
            profile: opts.profile,
        };
        ftpd.wait_ready().await?;
        Ok(ftpd)
    }

    /// Plain profiles: a `220` banner. Implicit TLS: the TCP connect succeeds and the
    /// entrypoint reports the daemon as started (the server waits for a ClientHello).
    async fn wait_ready(&self) -> Result<()> {
        if self.profile == FtpdProfile::VsftpdImplicitTls {
            let addr = self.addr();
            crate::poll_until(
                &format!("{} to accept on {addr}", self.profile.name()),
                crate::timeout(),
                Duration::from_millis(100),
                || async move {
                    let up = tokio::time::timeout(
                        Duration::from_secs(2),
                        tokio::net::TcpStream::connect(addr),
                    )
                    .await;
                    matches!(up, Ok(Ok(_))).then_some(())
                },
            )
            .await?;
            return Ok(());
        }
        docker::wait_banner(&self.fixture, self.addr(), |b| b.starts_with("220")).await?;
        Ok(())
    }

    /// The profile.
    pub fn profile(&self) -> FtpdProfile {
        self.profile
    }

    /// Container IP and control port.
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(self.fixture.ip(), self.profile.control_port())
    }

    /// The container IP as text.
    pub fn host(&self) -> String {
        self.fixture.ip().to_string()
    }

    /// The container IP.
    pub fn ip(&self) -> IpAddr {
        self.fixture.ip()
    }

    /// Replace the server certificate and restart the daemon in place (same
    /// container, same IP); waits until it answers again.
    ///
    /// # Errors
    /// Docker failed or the daemon did not come back.
    pub async fn set_cert(&self, cert: CertVariant) -> Result<()> {
        let out = self
            .exec_root(&format!("courier-set-cert {}", cert.name()))
            .await?;
        if !out.success() {
            return Err(E2eError::new(format!("courier-set-cert: {out:?}")));
        }
        self.wait_ready().await
    }

    /// DER of the certificate currently served.
    ///
    /// # Errors
    /// Docker failed or there is no certificate (plain profiles have one too).
    pub async fn cert_der(&self) -> Result<Vec<u8>> {
        let out = self
            .exec_root("openssl x509 -in /etc/courier-ftpd/tls/cert.pem -outform DER | base64 -w0")
            .await?;
        if !out.success() {
            return Err(E2eError::new(format!("cert_der: {out:?}")));
        }
        base64::engine::general_purpose::STANDARD
            .decode(out.stdout.trim())
            .map_err(|e| E2eError::new(format!("cert_der base64: {e}")))
    }

    /// `sh -c cmd` as `test`.
    ///
    /// # Errors
    /// Docker failed.
    pub async fn exec(&self, cmd: &str) -> Result<ExecOutput> {
        self.fixture.exec_as(keys::USER, cmd).await
    }

    /// `sh -c cmd` as root.
    ///
    /// # Errors
    /// Docker failed.
    pub async fn exec_root(&self, cmd: &str) -> Result<ExecOutput> {
        self.fixture.exec_root(cmd).await
    }

    /// SHA-256 (hex) of a file in the container.
    ///
    /// # Errors
    /// Docker failed or the file is missing.
    pub async fn sha256_of(&self, remote_path: &str) -> Result<String> {
        self.fixture.sha256_of(remote_path).await
    }

    /// The container's complete log.
    ///
    /// # Errors
    /// Docker failed.
    pub async fn logs(&self) -> Result<String> {
        self.fixture.logs().await
    }

    /// The runner's address as seen from the container (for active mode).
    ///
    /// # Errors
    /// Docker failed.
    pub async fn gateway_ip(&self) -> Result<IpAddr> {
        docker::gateway_ip(self.fixture.id()).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn profile_names_are_unique_and_kebab_case() {
        let names: HashSet<&str> = FtpdProfile::ALL.iter().map(|p| p.name()).collect();
        assert_eq!(names.len(), FtpdProfile::ALL.len());
        for n in names {
            assert!(
                n.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    && !n.starts_with('-')
                    && !n.ends_with('-'),
                "{n}"
            );
        }
        assert_eq!(FtpdProfile::VsftpdImplicitTls.control_port(), 990);
        assert_eq!(FtpdProfile::ProftpdPlain.control_port(), 21);
        assert!(FtpdProfile::PureftpdPlain.has_mlsd() && !FtpdProfile::VsftpdPlain.has_mlsd());
    }
}
