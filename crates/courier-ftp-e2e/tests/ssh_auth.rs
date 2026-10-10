//! T20 end to end: `SshConnection::connect` (courier-ftp-proto-sftp) against the
//! OpenSSH fixture profiles (`password`, `kbd`, `key`, `maxauth2`, `legacy`). Every test
//! is `#[ignore]` and starts with `require_docker!()`; run with `COURIER_E2E=1 cargo
//! test -p courier-ftp-e2e --test ssh_auth -- --ignored`.
//!
//! Host keys are accepted with the test-only `InsecureAcceptAnyHostKey` (T21 adds
//! the trust store).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use courier_ftp_core::{
    Error,
    events::{CoreEvent, PromptKind, PromptResponse, SessionId, SessionLog, channel},
    model::{KeySource, LocalPath},
    net::{CancellationToken, NetOpts, ProxyConfig, Purpose},
    secret::SecretString,
    settings::{DebugLevel, Settings},
};
use courier_ftp_e2e::{
    Sshd, SshdProfile,
    keys::{FixtureKey, OTP, PASSWORD, USER},
    require_docker,
};
use courier_ftp_proto_sftp::{
    agent::{AgentConnector, testing::InProcessAgent},
    ssh::{InsecureAcceptAnyHostKey, SshConnectParams, SshConnection, SshLogon},
};

/// Answers to the prompts, in order: one value per prompt field.
type Script = Vec<Vec<&'static str>>;

/// The session log and the prompts the UI saw.
struct Ui {
    log: SessionLog,
    prompts: Arc<Mutex<Vec<PromptKind>>>,
}

fn ui(script: Script) -> Ui {
    let (events, mut rx) = channel(DebugLevel::Debug);
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&prompts);
    tokio::spawn(async move {
        let mut script = VecDeque::from(script);
        while let Some(event) = rx.recv().await {
            let CoreEvent::Prompt(req) = event else {
                continue;
            };
            seen.lock().unwrap().push(req.kind.clone());
            let Some(answer) = script.pop_front() else {
                req.respond(PromptResponse::Cancel);
                continue;
            };
            let response = match &req.kind {
                PromptKind::KeyboardInteractive(_) => {
                    PromptResponse::Answers(answer.into_iter().map(SecretString::from).collect())
                }
                _ => PromptResponse::Secret {
                    value: SecretString::from(answer.first().copied().unwrap_or("")),
                    remember_session: false,
                    save_in_vault: false,
                },
            };
            req.respond(response);
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

fn params(sshd: &Sshd, logon: SshLogon) -> SshConnectParams {
    SshConnectParams {
        host: sshd.host(),
        port: 22,
        user: USER.into(),
        logon,
        password: None,
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

async fn connect(
    p: SshConnectParams,
    ui: &Ui,
    agent: Option<Arc<dyn AgentConnector>>,
) -> Result<SshConnection, Error> {
    SshConnection::connect(
        p,
        Arc::new(InsecureAcceptAnyHostKey),
        agent,
        &ui.log,
        CancellationToken::new(),
    )
    .await
}

fn key_params(sshd: &Sshd, key: FixtureKey) -> SshConnectParams {
    let mut p = params(sshd, SshLogon::KeyFile);
    p.key = Some(KeySource::Path(LocalPath::new(key.path())));
    p.key_label = key.file_name().to_owned();
    p
}

/// AC2: the stored password works; a wrong one gets three prompts, then `Auth`.
#[tokio::test]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn e2e_password_profile() {
    require_docker!();
    let sshd = Sshd::start(SshdProfile::Password).await.unwrap();
    let ui_ok = ui(vec![]);
    let mut p = params(&sshd, SshLogon::Normal);
    p.password = Some(SecretString::from(PASSWORD));
    let conn = connect(p, &ui_ok, None).await.unwrap();
    assert!(conn.info().server_version.contains("OpenSSH"));
    // The sftp subsystem is there for T22.
    conn.open_subsystem("sftp").await.unwrap();
    conn.disconnect().await;

    let ui_bad = ui(vec![vec!["bad1"], vec!["bad2"], vec!["bad3"]]);
    let mut p = params(&sshd, SshLogon::Normal);
    p.password = Some(SecretString::from("wrong-password"));
    let err = connect(p, &ui_bad, None).await.unwrap_err();
    assert!(matches!(&err, Error::Auth(_)), "{err}");
    let prompts = ui_bad.prompts.lock().unwrap().clone();
    assert_eq!(prompts.len(), 3, "{prompts:?}");
    assert!(
        prompts
            .iter()
            .all(|p| matches!(p, PromptKind::Password(pp) if pp.retry))
    );
}

/// AC3: `Interactive` against PAM: "Password: ", then "Verification code: ".
#[tokio::test]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn e2e_kbd_profile_otp() {
    require_docker!();
    let sshd = Sshd::start(SshdProfile::Kbd).await.unwrap();
    let ui = ui(vec![vec![PASSWORD], vec![OTP]]);
    let conn = connect(params(&sshd, SshLogon::Interactive), &ui, None)
        .await
        .unwrap();
    assert_eq!(conn.info().auth_method, "keyboard-interactive");
    let prompts = ui.prompts.lock().unwrap().clone();
    let texts: Vec<(String, bool)> = prompts
        .iter()
        .map(|p| match p {
            PromptKind::KeyboardInteractive(k) => {
                assert_eq!(k.prompts.len(), 1, "{k:?}");
                (k.prompts[0].text.clone(), k.prompts[0].echo)
            }
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        texts,
        [
            ("Password:".to_owned(), false),
            ("Verification code:".to_owned(), false)
        ]
    );
}

/// AC4: ed25519, RSA (OpenSSH format) and ed25519 PPK v3; RSA signs with rsa-sha2-512
/// (sshd's DEBUG1 log names the algorithm).
#[tokio::test]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn e2e_key_profile_ed25519_rsa_ppk() {
    require_docker!();
    let sshd = Sshd::start(SshdProfile::Key).await.unwrap();
    for key in [FixtureKey::Ed25519, FixtureKey::Rsa, FixtureKey::PpkV3] {
        let ui = ui(vec![]);
        let conn = connect(key_params(&sshd, key), &ui, None)
            .await
            .unwrap_or_else(|e| panic!("{key:?}: {e}"));
        assert_eq!(conn.info().auth_method, "publickey");
        conn.disconnect().await;
    }
    // The encrypted PuTTY v3 key with its passphrase.
    let ui_enc = ui(vec![vec!["fixture"]]);
    connect(key_params(&sshd, FixtureKey::PpkV3Encrypted), &ui_enc, None)
        .await
        .unwrap();
    let logs = sshd.logs().await.unwrap();
    assert!(
        logs.contains("public key rsa-sha2-512") || logs.contains("pkalg rsa-sha2-512"),
        "sshd did not see an rsa-sha2-512 signature:\n{logs}"
    );
}

/// AC8: `MaxAuthTries 2`; the error names the tried methods.
#[tokio::test]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn e2e_maxauth2_reports_methods() {
    require_docker!();
    let sshd = Sshd::start(SshdProfile::MaxAuth2).await.unwrap();
    // Three keys the server doesn't know.
    let keys: Vec<_> = (1u8..=3)
        .map(|seed| {
            ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]))
        })
        .collect();
    let agent: Arc<dyn AgentConnector> = Arc::new(InProcessAgent::start(&keys).await.unwrap());
    let ui = ui(vec![]);
    let err = connect(params(&sshd, SshLogon::Agent), &ui, Some(agent))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Auth(m) if m.contains("tried: publickey")),
        "{err}"
    );
}

/// AC13: legacy-only algorithms are refused; OpenSSH defaults negotiate AES-GCM.
#[tokio::test]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn e2e_legacy_profile_no_common_algorithm() {
    require_docker!();
    let sshd = Sshd::start(SshdProfile::Legacy).await.unwrap();
    let ui = ui(vec![]);
    let mut p = params(&sshd, SshLogon::Normal);
    p.password = Some(SecretString::from(PASSWORD));
    let err = connect(p, &ui, None).await.unwrap_err();
    assert!(
        matches!(&err, Error::Connection(m) if m.starts_with("No common")),
        "{err}"
    );
}

#[tokio::test]
#[ignore = "needs Docker (COURIER_E2E=1)"]
async fn e2e_default_negotiates_gcm() {
    require_docker!();
    let sshd = Sshd::start(SshdProfile::Password).await.unwrap();
    let ui = ui(vec![]);
    let mut p = params(&sshd, SshLogon::Normal);
    p.password = Some(SecretString::from(PASSWORD));
    let conn = connect(p, &ui, None).await.unwrap();
    let cipher = conn.info().cipher.clone();
    assert!(
        cipher == "aes128-gcm@openssh.com" || cipher == "aes256-gcm@openssh.com",
        "{cipher}"
    );
    assert_eq!(conn.info().mac, "(implicit)");
}
