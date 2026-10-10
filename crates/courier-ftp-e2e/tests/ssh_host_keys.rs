//! T21 end to end: host-key trust (`TrustVerifier`) against the OpenSSH fixture
//! (`password` profile), including a host-key regeneration (`courier-regen-hostkeys`).
//! Every test is `#[ignore]` and starts with `require_docker!()`; run with
//! `COURIER_E2E=1 cargo test -p courier-ftp-e2e --test ssh_host_keys -- --ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{sync::Arc, time::Duration};

use courier_ftp_core::{
    Error,
    events::{
        CoreEvent, HostKeyPrompt, PromptKind, PromptRequest, PromptResponse, SessionId, SessionLog,
        TrustAnswer, channel,
    },
    net::{CancellationToken, NetOpts, ProxyConfig, Purpose},
    secret::SecretString,
    settings::{DebugLevel, Settings},
    trust::{HostKeyStore, MemoryHostKeyStore, SessionTrust},
};
use courier_ftp_e2e::{
    Sshd, SshdProfile,
    keys::{PASSWORD, USER},
    require_docker,
};
use courier_ftp_proto_sftp::{
    known_hosts::OpenSshKnownHosts,
    ssh::{SshConnectParams, SshConnection, SshLogon},
    verify::{REJECTED_CHANGED, TrustVerifier},
};
use tokio::{sync::mpsc, task::JoinHandle};

/// Host-key prompts go to the test.
struct Ui {
    log: SessionLog,
    prompts: mpsc::UnboundedReceiver<PromptRequest>,
}

fn ui() -> Ui {
    let (events, mut rx) = channel(DebugLevel::Debug);
    let (tx, prompts) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let CoreEvent::Prompt(req) = event {
                let _ = tx.send(req);
            }
        }
    });
    Ui {
        log: SessionLog {
            events,
            session: SessionId::next(),
        },
        prompts,
    }
}

impl Ui {
    async fn next_prompt(&mut self) -> (PromptRequest, HostKeyPrompt) {
        let req = tokio::time::timeout(Duration::from_secs(30), self.prompts.recv())
            .await
            .expect("a prompt")
            .unwrap();
        let PromptKind::TrustHostKey(p) = req.kind.clone() else {
            panic!("not a host key prompt: {:?}", req.kind);
        };
        (req, p)
    }

    fn no_prompt(&mut self) {
        if let Ok(req) = self.prompts.try_recv() {
            panic!("unexpected prompt: {:?}", req.kind);
        }
    }
}

fn params(sshd: &Sshd) -> SshConnectParams {
    SshConnectParams {
        host: sshd.host(),
        port: 22,
        user: USER.into(),
        logon: SshLogon::Normal,
        password: Some(SecretString::from(PASSWORD)),
        key: None,
        key_passphrase: None,
        key_label: String::new(),
        try_agent_first: false,
        can_save: false,
        net: NetOpts::from_settings(&Settings::default(), Purpose::Control, ProxyConfig::Direct),
        timeout: Duration::from_secs(20),
        keepalive: Some(Duration::from_secs(30)),
    }
}

/// A verifier as a fresh process would build it (new `SessionTrust`), over `store`.
fn verifier(store: &Arc<dyn HostKeyStore>) -> Arc<TrustVerifier> {
    Arc::new(TrustVerifier::new(
        Arc::clone(store),
        Arc::new(SessionTrust::default()),
        Arc::new(OpenSshKnownHosts::disabled()),
    ))
}

fn connect(
    sshd: &Sshd,
    v: &Arc<TrustVerifier>,
    ui: &Ui,
) -> JoinHandle<Result<SshConnection, Error>> {
    let p = params(sshd);
    let v = Arc::clone(v);
    let log = ui.log.clone();
    tokio::spawn(
        async move { SshConnection::connect(p, v, None, &log, CancellationToken::new()).await },
    )
}

/// AC2 against OpenSSH: the first connect asks, "Always trust" stores the key, and the
/// next process connects silently.
#[tokio::test]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn e2e_unknown_host_key_prompt_then_trusted() {
    require_docker!();
    let sshd = Sshd::start(SshdProfile::Password).await.unwrap();
    let mut ui = ui();
    let store: Arc<dyn HostKeyStore> = Arc::new(MemoryHostKeyStore::persistent_for_tests());

    let task = connect(&sshd, &verifier(&store), &ui);
    let (req, p) = ui.next_prompt().await;
    assert_eq!(p.key_type, "ssh-ed25519");
    assert_eq!(
        p.fingerprint_sha256,
        sshd.host_fingerprint("ed25519").await.unwrap()
    );
    assert_eq!(p.changed, None);
    req.respond(PromptResponse::HostKey(TrustAnswer::AlwaysTrust));
    let conn = task.await.unwrap().unwrap();
    assert!(conn.info().server_version.contains("OpenSSH"));
    conn.disconnect().await;
    assert_eq!(store.list().len(), 1);

    let conn = connect(&sshd, &verifier(&store), &ui)
        .await
        .unwrap()
        .unwrap();
    ui.no_prompt();
    conn.disconnect().await;
}

/// AC14: after the host keys are regenerated, the next connect shows the changed-key
/// prompt (with the old fingerprint) and fails when it is rejected.
#[tokio::test]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn e2e_changed_host_key_blocked() {
    require_docker!();
    let sshd = Sshd::start(SshdProfile::Password).await.unwrap();
    let mut ui = ui();
    let store: Arc<dyn HostKeyStore> = Arc::new(MemoryHostKeyStore::persistent_for_tests());
    let old_fp = sshd.host_fingerprint("ed25519").await.unwrap();

    let task = connect(&sshd, &verifier(&store), &ui);
    let (req, _) = ui.next_prompt().await;
    req.respond(PromptResponse::HostKey(TrustAnswer::AlwaysTrust));
    task.await.unwrap().unwrap().disconnect().await;

    sshd.regenerate_host_key().await.unwrap();
    let new_fp = sshd.host_fingerprint("ed25519").await.unwrap();
    assert_ne!(old_fp, new_fp);

    let task = connect(&sshd, &verifier(&store), &ui);
    let (req, p) = ui.next_prompt().await;
    assert_eq!(p.fingerprint_sha256, new_fp);
    let old = p.changed.expect("a changed-key prompt");
    assert_eq!(old.len(), 1);
    assert_eq!(old[0].fingerprint_sha256, old_fp);
    req.respond(PromptResponse::HostKey(TrustAnswer::Reject));
    let err = task.await.unwrap().unwrap_err();
    assert!(
        matches!(&err, Error::HostKey(why) if why == REJECTED_CHANGED),
        "{err:?}"
    );
    // Nothing was replaced.
    let stored = store.list();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].fingerprint_sha256(), old_fp);
}
