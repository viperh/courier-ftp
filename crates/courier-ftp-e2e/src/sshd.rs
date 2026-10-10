//! [`Sshd`]: OpenSSH (SFTP) servers in Docker, one image (`tests/fixtures/sshd/`) with
//! runtime-selected [`SshdProfile`]s.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use crate::{
    E2eError, Result,
    docker::{self, ExecOutput, Fixture, FixtureSpec},
    keys,
};

/// An sshd configuration of the fixture image (`tests/fixtures/sshd/profiles/<name>.conf`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SshdProfile {
    /// `PasswordAuthentication yes`, `Subsystem sftp internal-sftp`.
    Password,
    /// Public keys only.
    Key,
    /// Keyboard-interactive via PAM: password, then the OTP [`keys::OTP`].
    Kbd,
    /// `MaxAuthTries 2`, keys only.
    MaxAuth2,
    /// Only `diffie-hellman-group14-sha1`, `ssh-rsa`, `aes128-cbc`, `hmac-sha1`.
    Legacy,
    /// `ForceCommand internal-sftp`, `ChrootDirectory /srv/chroot`.
    ChrootSftp,
    /// Paths like OpenSSH for Windows (`/C:/Users/test`).
    WindowsLike,
    /// `MaxSessions 1`.
    MaxSessions1,
    /// At most one concurrent TCP connection (`bin/conn-limit-proxy`).
    MaxConn1,
}

impl SshdProfile {
    /// Every profile.
    pub const ALL: [Self; 9] = [
        Self::Password,
        Self::Key,
        Self::Kbd,
        Self::MaxAuth2,
        Self::Legacy,
        Self::ChrootSftp,
        Self::WindowsLike,
        Self::MaxSessions1,
        Self::MaxConn1,
    ];

    /// The profile name (`SSHD_PROFILE=<name>`, `profiles/<name>.conf`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Key => "key",
            Self::Kbd => "kbd",
            Self::MaxAuth2 => "maxauth2",
            Self::Legacy => "legacy",
            Self::ChrootSftp => "chroot-sftp",
            Self::WindowsLike => "windows-like",
            Self::MaxSessions1 => "maxsessions1",
            Self::MaxConn1 => "maxconn1",
        }
    }
}

/// How to start an [`Sshd`].
#[derive(Debug, Clone)]
pub struct SshdOptions {
    /// The profile.
    pub profile: SshdProfile,
    /// Join this network (see [`crate::TestNetwork`]); default bridge otherwise.
    pub network: Option<String>,
    /// Extra environment for the entrypoint.
    pub env: Vec<(String, String)>,
}

impl SshdOptions {
    /// `profile` on the default bridge.
    pub fn new(profile: SshdProfile) -> Self {
        Self {
            profile,
            network: None,
            env: Vec::new(),
        }
    }
}

/// An OpenSSH server in a container (removed on drop; logs dumped when failing).
#[derive(Debug)]
pub struct Sshd {
    fixture: Fixture,
    profile: SshdProfile,
    network: Option<String>,
}

impl Sshd {
    /// Start `profile` and wait for the SSH banner.
    ///
    /// # Errors
    /// Docker or the image build failed, or sshd did not come up.
    pub async fn start(profile: SshdProfile) -> Result<Self> {
        Self::start_with(SshdOptions::new(profile)).await
    }

    /// Start as described by `opts`.
    ///
    /// # Errors
    /// As [`Sshd::start`].
    pub async fn start_with(opts: SshdOptions) -> Result<Self> {
        let mut env = vec![("SSHD_PROFILE".to_owned(), opts.profile.name().to_owned())];
        env.extend(opts.env);
        let fixture = Fixture::start(FixtureSpec {
            image: docker::image("sshd").await?,
            label: format!("sshd {}", opts.profile.name()),
            env,
            network: opts.network.clone(),
            cap_add: vec!["SYS_CHROOT".into(), "AUDIT_WRITE".into()],
        })
        .await?;
        let sshd = Self {
            fixture,
            profile: opts.profile,
            network: opts.network,
        };
        sshd.wait_ready().await?;
        Ok(sshd)
    }

    async fn wait_ready(&self) -> Result<()> {
        docker::wait_banner(&self.fixture, self.addr(), |b| b.starts_with("SSH-2.0-")).await?;
        Ok(())
    }

    /// The profile.
    pub fn profile(&self) -> SshdProfile {
        self.profile
    }

    /// Container IP and port 22.
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(self.fixture.ip(), 22)
    }

    /// The container IP as text (for `ConnectInfo`).
    pub fn host(&self) -> String {
        self.fixture.ip().to_string()
    }

    /// The container IP.
    pub fn ip(&self) -> IpAddr {
        self.fixture.ip()
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

    /// The host public keys (`type base64`), ed25519 first.
    ///
    /// # Errors
    /// Docker failed or the keys are missing.
    pub async fn host_keys(&self) -> Result<Vec<String>> {
        let out = self
            .exec_root(
                "cat /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key.pub \
                 /etc/ssh/ssh_host_rsa_key.pub",
            )
            .await?;
        if !out.success() {
            return Err(E2eError::new(format!("host keys: {}", out.stderr)));
        }
        Ok(out
            .stdout
            .lines()
            .filter_map(|l| {
                let mut parts = l.split_whitespace();
                Some(format!("{} {}", parts.next()?, parts.next()?))
            })
            .collect())
    }

    /// The `SHA256:…` fingerprint of the `key_type` (`ed25519`, `ecdsa`, `rsa`) host key.
    ///
    /// # Errors
    /// Docker failed or there is no such key.
    pub async fn host_fingerprint(&self, key_type: &str) -> Result<String> {
        let out = self
            .exec_root(&format!(
                "ssh-keygen -l -E sha256 -f /etc/ssh/ssh_host_{key_type}_key.pub"
            ))
            .await?;
        out.stdout
            .split_whitespace()
            .nth(1)
            .filter(|f| f.starts_with("SHA256:"))
            .map(str::to_owned)
            .ok_or_else(|| E2eError::new(format!("fingerprint: {out:?}")))
    }

    /// The ed25519 key the running daemon serves (`ssh-keyscan` in the container).
    async fn served_host_key(&self) -> Option<String> {
        let out = self
            .exec_root("ssh-keyscan -T 2 -t ed25519 127.0.0.1 2>/dev/null")
            .await
            .ok()?;
        out.stdout.lines().find_map(|l| {
            let mut parts = l.split_whitespace().skip(1);
            Some(format!("{} {}", parts.next()?, parts.next()?))
        })
    }

    /// Replace every host key (`courier-regen-hostkeys`), wait until sshd serves the
    /// new ed25519 key, and return the new keys.
    ///
    /// # Errors
    /// Docker failed or sshd did not come back with the new key.
    pub async fn regenerate_host_key(&self) -> Result<Vec<String>> {
        let out = self.exec_root("courier-regen-hostkeys").await?;
        if !out.success() {
            return Err(E2eError::new(format!("courier-regen-hostkeys: {out:?}")));
        }
        let keys = self.host_keys().await?;
        let want = keys.first().cloned().unwrap_or_default();
        let want = &want;
        crate::poll_until(
            "sshd to serve the new host key",
            crate::timeout(),
            Duration::from_millis(100),
            || async move {
                self.served_host_key()
                    .await
                    .filter(|k| k == want)
                    .map(|_| ())
            },
        )
        .await?;
        self.wait_ready().await?;
        Ok(keys)
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

    /// Stop the container ([`Sshd::restart`] brings it back).
    ///
    /// # Errors
    /// Docker failed.
    pub async fn stop(&self) -> Result<()> {
        self.fixture.stop().await
    }

    /// Stop and start the container and wait for sshd (host keys are kept; the IP may
    /// change).
    ///
    /// # Errors
    /// Docker failed or sshd did not come up.
    pub async fn restart(&mut self) -> Result<()> {
        self.fixture.stop().await?;
        self.fixture.start_again(self.network.as_deref()).await?;
        self.wait_ready().await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn profile_names_are_unique_and_kebab_case() {
        let names: HashSet<&str> = SshdProfile::ALL.iter().map(|p| p.name()).collect();
        assert_eq!(names.len(), SshdProfile::ALL.len());
        for n in names {
            assert!(
                n.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    && !n.starts_with('-')
                    && !n.ends_with('-'),
                "{n}"
            );
        }
    }
}
