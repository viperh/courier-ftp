//! T76 AC13 / T22 AC1: the T03 backend conformance suite
//! (`backend_conformance_tests!(ignored, …)`) against the OpenSSH fixture profiles
//! `password`, `key`, `chroot-sftp` and `windows-like`, with backends built by
//! [`E2eBackendFactory`] (the FTP profiles join with T14). The e2e crate defines no
//! cases of its own.
//!
//! `ConformanceEnv` is built synchronously, so each profile's container runs on its own
//! thread and runtime, shared by every case of the profile that is running (it stops
//! when the last one finishes). Without Docker / `COURIER_E2E=1` every case reports
//! itself skipped. Run with
//! `COURIER_E2E=1 cargo test -p courier-ftp-e2e --test backend_conformance -- --ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, Weak, mpsc},
    thread::JoinHandle,
};

use courier_ftp_core::{
    Error,
    backend::{
        BackendContext, BackendFactory, ConnectInfo,
        conformance::{CASES, ConformanceEnv},
    },
    events::{CoreEvent, PromptKind, PromptResponse, SessionId, TrustAnswer, channel},
    model::{FtpEncryption, KeySource, LocalPath, LogonType, Protocol, RemotePath, ServerAddress},
    secret::SecretString,
    settings::{DebugLevel, Settings},
};
use courier_ftp_e2e::{
    E2eBackendFactory, Sshd, SshdProfile,
    keys::{FixtureKey, PASSWORD, USER},
};

/// A shell command for the container thread, with the reply channel.
type ExecRequest = (String, mpsc::Sender<Result<(), Error>>);

/// One profile's container, owned by its thread (which also runs `exec`s).
struct Container {
    addr: SocketAddr,
    exec: Mutex<Option<mpsc::Sender<ExecRequest>>>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Container {
    fn drop(&mut self) {
        // Closing the channel stops the thread, which removes the container.
        drop(
            self.exec
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take(),
        );
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Container {
    /// Start `profile` on a new thread with its own runtime.
    fn start(profile: SshdProfile) -> Result<Self, String> {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (exec_tx, exec_rx) = mpsc::channel::<ExecRequest>();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            let sshd = match rt.block_on(Sshd::start(profile)) {
                Ok(sshd) => sshd,
                Err(e) => {
                    let _ = ready_tx.send(Err(e.to_string()));
                    return;
                }
            };
            let _ = ready_tx.send(Ok(sshd.addr()));
            // Until the last user is gone.
            while let Ok((cmd, reply)) = exec_rx.recv() {
                let res = match rt.block_on(sshd.exec_root(&cmd)) {
                    Ok(out) if out.success() => Ok(()),
                    Ok(out) => Err(Error::Internal(format!("{cmd}: {out:?}"))),
                    Err(e) => Err(Error::Internal(e.to_string())),
                };
                let _ = reply.send(res);
            }
            // testcontainers' Drop needs the runtime.
            let _guard = rt.enter();
            drop(sshd);
        });
        let addr = ready_rx.recv().map_err(|e| e.to_string()).and_then(|r| r)?;
        Ok(Self {
            addr,
            exec: Mutex::new(Some(exec_tx)),
            thread: Some(thread),
        })
    }

    /// `sh -c cmd` as root, from synchronous code.
    fn exec_root(&self, cmd: String) -> Result<(), Error> {
        let (tx, rx) = mpsc::channel();
        let sender = self
            .exec
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| Error::Internal("container stopped".into()))?;
        sender
            .send((cmd, tx))
            .map_err(|e| Error::Internal(e.to_string()))?;
        rx.recv().map_err(|e| Error::Internal(e.to_string()))?
    }
}

/// The running container of `profile`, shared while any case uses it.
fn container(profile: SshdProfile) -> Result<Arc<Container>, String> {
    static RUNNING: OnceLock<Mutex<HashMap<SshdProfile, Weak<Container>>>> = OnceLock::new();
    let mut running = RUNNING
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(c) = running.get(&profile).and_then(Weak::upgrade) {
        return Ok(c);
    }
    let c = Arc::new(Container::start(profile)?);
    running.insert(profile, Arc::downgrade(&c));
    Ok(c)
}

/// Why the cases cannot run (no Docker, `COURIER_E2E` unset), checked once.
fn skip_reason() -> Option<&'static str> {
    static REASON: OnceLock<Option<String>> = OnceLock::new();
    REASON
        .get_or_init(|| {
            std::thread::spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(courier_ftp_e2e::docker_skip_reason())
            })
            .join()
            .unwrap()
        })
        .as_deref()
}

/// A backend context whose host-key prompts are answered "trust once" (the trust flow
/// itself is T21's e2e test).
fn context() -> BackendContext {
    let (events, mut rx) = channel(DebugLevel::Debug);
    let (_tx, settings) = tokio::sync::watch::channel(Arc::new(Settings::default()));
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let CoreEvent::Prompt(req) = ev {
                let answer = match &req.kind {
                    PromptKind::TrustHostKey(_) => PromptResponse::HostKey(TrustAnswer::TrustOnce),
                    _ => PromptResponse::Cancel,
                };
                req.respond(answer);
            }
        }
    });
    BackendContext {
        session: SessionId::next(),
        events,
        settings,
    }
}

fn connect_info(profile: SshdProfile, addr: SocketAddr) -> ConnectInfo {
    let address = ServerAddress::new(
        Protocol::Sftp,
        FtpEncryption::ExplicitIfAvailable,
        addr.ip().to_string(),
        Some(addr.port()),
        Some(USER.to_owned()),
    )
    .unwrap();
    let logon = match profile {
        SshdProfile::Key => LogonType::KeyFile {
            key: KeySource::Path(LocalPath::new(FixtureKey::Ed25519.path())),
            passphrase: None,
        },
        _ => LogonType::Normal {
            password: Some(SecretString::from(PASSWORD)),
        },
    };
    ConnectInfo::quick(address, logon)
}

/// The scratch directory and the container directory the SFTP root maps to.
fn layout(profile: SshdProfile) -> (&'static str, &'static str) {
    match profile {
        SshdProfile::ChrootSftp => ("/home/test/upload", "/srv/chroot"),
        SshdProfile::WindowsLike => ("/C:/Users/test/upload", "/srv/win"),
        _ => ("/home/test/upload", ""),
    }
}

fn env_for(profile: SshdProfile) -> ConformanceEnv {
    let (scratch, root) = layout(profile);
    let scratch = RemotePath::parse(scratch).unwrap();
    let skip_all = |why: &'static str| ConformanceEnv {
        scratch: scratch.clone(),
        make: Box::new(|| Err(Error::Internal("not started".into()))),
        large_files: false,
        skip: CASES.iter().map(|c| (*c, why)).collect(),
        make_symlink: None,
    };
    if let Some(why) = skip_reason() {
        return skip_all(why);
    }
    let c = match container(profile) {
        Ok(c) => c,
        Err(e) => panic!("starting sshd {}: {e}", profile.name()),
    };
    let info = Arc::new(connect_info(profile, c.addr));
    let make_c = Arc::clone(&c);
    let link_c = c;
    ConformanceEnv {
        scratch,
        make: Box::new(move || {
            let _keep = &make_c;
            E2eBackendFactory.create(Arc::clone(&info), context())
        }),
        large_files: true,
        skip: Vec::new(),
        make_symlink: Some(Box::new(move |link: &RemotePath, target: &str| {
            let real = format!("{root}{}", link.as_str());
            link_c.exec_root(format!(
                "ln -s '{target}' '{real}' && chown -h test:test '{real}'"
            ))
        })),
    }
}

/// The T03 suite per profile (one module each).
macro_rules! profile_suite {
    ($module:ident, $profile:expr) => {
        mod $module {
            use super::*;

            fn env() -> ConformanceEnv {
                env_for($profile)
            }

            courier_ftp_core::backend_conformance_tests!(ignored, env);
        }
    };
}

profile_suite!(sftp_password, SshdProfile::Password);
profile_suite!(sftp_key, SshdProfile::Key);
profile_suite!(sftp_chroot_sftp, SshdProfile::ChrootSftp);
profile_suite!(sftp_windows_like, SshdProfile::WindowsLike);
