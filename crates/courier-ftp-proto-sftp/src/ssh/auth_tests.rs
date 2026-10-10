//! Unit tests of the authentication chain with a scripted server ([`Fake`], an
//! [`AuthBackend`]) and a scripted user ([`User`], an [`AuthIo`]); ported from sverb
//! `auth_tests.rs`. Loopback tests against the in-process russh server are in
//! `tests/loopback.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use courier_ftp_core::{events::LogKind, secret::SecretString};
use pretty_assertions::assert_eq;
use russh::keys::{
    HashAlg, PrivateKey, PublicKey, agent::AgentIdentity, ssh_key::private::Ed25519Keypair,
};

use super::*;
use crate::agent::AgentError;

// ---------------------------------------------------------------- the fake server

/// A scripted server. Every request is recorded in `calls`.
struct Fake {
    /// The method list sent with every failure.
    methods: Vec<&'static str>,
    calls: Vec<String>,
    password: Option<&'static str>,
    accept_key: bool,
    accept_agent: Option<&'static str>,
    /// Agent identity answered with partial success (then `methods_after_partial`).
    partial_agent: Option<&'static str>,
    methods_after_partial: Vec<&'static str>,
    rsa: RsaSigSupport,
    /// Replies to `kbd_start` / `kbd_respond`, in order.
    kbd: VecDeque<KbdReply>,
    kbd_answers: Vec<Vec<String>>,
    /// `ANSWERS_DROPPED` at each `password` request.
    dropped_at_request: Vec<usize>,
}

impl Fake {
    fn new(methods: &[&'static str]) -> Self {
        Self {
            methods: methods.to_vec(),
            calls: Vec::new(),
            password: None,
            accept_key: false,
            accept_agent: None,
            partial_agent: None,
            methods_after_partial: Vec::new(),
            rsa: RsaSigSupport::Sha512,
            kbd: VecDeque::new(),
            kbd_answers: Vec::new(),
            dropped_at_request: Vec::new(),
        }
    }

    fn fail(&self) -> AuthOutcome {
        AuthOutcome::Failure {
            remaining: self.methods.iter().map(|m| (*m).to_owned()).collect(),
            partial: false,
        }
    }

    fn verdict(&self, ok: bool) -> AuthOutcome {
        if ok {
            AuthOutcome::Success
        } else {
            self.fail()
        }
    }

    fn next_kbd(&mut self) -> KbdReply {
        self.kbd.pop_front().unwrap_or_else(|| KbdReply::Failure {
            remaining: self.methods.iter().map(|m| (*m).to_owned()).collect(),
            partial: false,
        })
    }
}

fn hash_name(hash: Option<HashAlg>) -> &'static str {
    match hash {
        Some(HashAlg::Sha512) => "rsa-sha2-512",
        Some(HashAlg::Sha256) => "rsa-sha2-256",
        None => "ssh-rsa",
        _ => "other",
    }
}

#[async_trait]
impl AuthBackend for Fake {
    async fn none(&mut self, _user: &str) -> Result<AuthOutcome, SshError> {
        self.calls.push("none".into());
        Ok(self.fail())
    }

    async fn password(
        &mut self,
        _user: &str,
        password: &SecretString,
    ) -> Result<AuthOutcome, SshError> {
        self.dropped_at_request
            .push(ANSWERS_DROPPED.with(std::cell::Cell::get));
        self.calls.push(format!("password:{}", password.expose()));
        Ok(self.verdict(self.password == Some(password.expose())))
    }

    async fn publickey(
        &mut self,
        _user: &str,
        key: Arc<PrivateKey>,
        hash: Option<HashAlg>,
    ) -> Result<AuthOutcome, SshError> {
        let alg = if key.algorithm().is_rsa() {
            hash_name(hash).to_owned()
        } else {
            key.algorithm().as_str().to_owned()
        };
        self.calls.push(format!("publickey:{alg}"));
        Ok(self.verdict(self.accept_key))
    }

    async fn agent_identity(
        &mut self,
        _user: &str,
        _agent: &mut dyn Agent,
        identity: &AgentIdentity,
        _hash: Option<HashAlg>,
    ) -> Result<AuthOutcome, SshError> {
        self.calls.push(format!("agent:{}", identity.comment()));
        if identity.comment() == "disconnect" {
            return Err(SshError::RemoteDisconnect(
                "Too many authentication failures".into(),
            ));
        }
        if self.partial_agent == Some(identity.comment()) {
            self.methods = self.methods_after_partial.clone();
            return Ok(AuthOutcome::Failure {
                remaining: self.methods.iter().map(|m| (*m).to_owned()).collect(),
                partial: true,
            });
        }
        Ok(self.verdict(self.accept_agent == Some(identity.comment())))
    }

    async fn kbd_start(&mut self, _user: &str) -> Result<KbdReply, SshError> {
        self.calls.push("kbd".into());
        Ok(self.next_kbd())
    }

    async fn kbd_respond(&mut self, answers: &[SecretString]) -> Result<KbdReply, SshError> {
        self.kbd_answers
            .push(answers.iter().map(|a| a.expose().to_owned()).collect());
        Ok(self.next_kbd())
    }

    async fn rsa_support(&mut self) -> RsaSigSupport {
        self.rsa
    }
}

// ---------------------------------------------------------------- the fake user

/// Answers prompts from a script (`None`: cancel; script empty: cancel).
#[derive(Default)]
struct User {
    answers: VecDeque<Option<Vec<&'static str>>>,
    prompts: Vec<AuthPrompt>,
    tokens: Vec<PromptToken>,
    accepted: Vec<PromptToken>,
    log: Vec<(LogKind, String)>,
}

impl User {
    fn answering(answers: &[Option<&[&'static str]>]) -> Self {
        Self {
            answers: answers.iter().map(|a| a.map(<[_]>::to_vec)).collect(),
            ..Self::default()
        }
    }

    fn status_lines(&self) -> Vec<&str> {
        self.log.iter().map(|(_, t)| t.as_str()).collect()
    }
}

#[async_trait]
impl AuthIo for User {
    fn log(&mut self, kind: LogKind, text: String) {
        self.log.push((kind, text));
    }

    async fn ask(&mut self, prompt: AuthPrompt) -> Result<Option<AuthAnswer>, SshError> {
        self.prompts.push(prompt);
        let token = PromptToken(self.prompts.len() as u64);
        let answer = self.answers.pop_front().flatten().map(|a| AuthAnswer {
            token,
            values: a.into_iter().map(SecretString::from).collect(),
        });
        if answer.is_some() {
            self.tokens.push(token);
        }
        Ok(answer)
    }

    fn accepted(&mut self, token: PromptToken) {
        self.accepted.push(token);
    }
}

// ---------------------------------------------------------------- the fake agent

#[derive(Debug, Default)]
struct FakeAgent {
    comments: Vec<&'static str>,
    connects: AtomicUsize,
}

struct FakeAgentConn(Vec<AgentIdentity>);

#[async_trait]
impl Agent for FakeAgentConn {
    async fn identities(&mut self) -> Result<Vec<AgentIdentity>, AgentError> {
        Ok(self.0.clone())
    }

    async fn sign(
        &mut self,
        _identity: &AgentIdentity,
        _hash: Option<HashAlg>,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, AgentError> {
        Ok(Vec::new())
    }
}

fn ed25519_public(seed: u8) -> PublicKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
        .public_key()
        .clone()
}

#[async_trait]
impl AgentConnector for FakeAgent {
    async fn connect(&self) -> Result<Box<dyn Agent>, AgentError> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        let ids = self
            .comments
            .iter()
            .zip(1_u8..)
            .map(|(c, seed)| AgentIdentity::PublicKey {
                key: ed25519_public(seed),
                comment: (*c).to_owned(),
            })
            .collect();
        Ok(Box::new(FakeAgentConn(ids)))
    }
}

fn agent(comments: &[&'static str]) -> Arc<FakeAgent> {
    Arc::new(FakeAgent {
        comments: comments.to_vec(),
        connects: AtomicUsize::new(0),
    })
}

// ---------------------------------------------------------------- helpers

const PW: &str = "password";
const KBD: &str = "keyboard-interactive";
const PK: &str = "publickey";

fn fixture(name: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("keys")
        .join(name);
    std::fs::read_to_string(path).unwrap()
}

fn key(name: &str) -> KeyMaterial {
    KeyMaterial {
        text: Zeroizing::new(fixture(name)),
        label: name.to_owned(),
        passphrase: None,
    }
}

struct Target {
    logon: SshLogon,
    password: Option<SecretString>,
    key: Option<KeyMaterial>,
    try_agent_first: bool,
}

impl Target {
    fn new(logon: SshLogon) -> Self {
        Self {
            logon,
            password: None,
            key: None,
            try_agent_first: false,
        }
    }

    fn password(mut self, pw: &str) -> Self {
        self.password = Some(SecretString::from(pw));
        self
    }

    fn key(mut self, km: KeyMaterial) -> Self {
        self.key = Some(km);
        self
    }

    fn agent_first(mut self) -> Self {
        self.try_agent_first = true;
        self
    }

    async fn run(
        &self,
        fake: &mut Fake,
        user: &mut User,
        agent: Option<Arc<FakeAgent>>,
    ) -> Result<&'static str, SshError> {
        let target = ChainTarget {
            user: "alice",
            logon: self.logon,
            password: self.password.as_ref(),
            key: self.key.as_ref(),
            try_agent_first: self.try_agent_first,
        };
        let agent = agent.map(|a| a as Arc<dyn AgentConnector>);
        run_chain(&target, fake, user, agent).await
    }
}

fn info(prompts: &[(&str, bool)]) -> KbdReply {
    KbdReply::Info {
        name: String::new(),
        instruction: String::new(),
        prompts: prompts
            .iter()
            .map(|(t, e)| KbdField {
                text: (*t).to_owned(),
                echo: *e,
            })
            .collect(),
    }
}

fn password_prompts(user: &User) -> Vec<(bool, u8)> {
    user.prompts
        .iter()
        .filter_map(|p| match p {
            AuthPrompt::Password { retry, attempt } => Some((*retry, *attempt)),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------- tests

/// AC2: a wrong stored password, then exactly three prompts with `retry`.
#[tokio::test]
async fn normal_tries_stored_password_then_prompts_three_times() {
    let mut fake = Fake::new(&[PW]);
    fake.password = Some("right");
    let mut user = User::answering(&[Some(&["w1"]), Some(&["w2"]), Some(&["w3"])]);
    let err = Target::new(SshLogon::Normal)
        .password("stored-wrong")
        .run(&mut fake, &mut user, None)
        .await
        .unwrap_err();
    assert_eq!(
        fake.calls,
        [
            "none",
            "password:stored-wrong",
            "password:w1",
            "password:w2",
            "password:w3"
        ]
    );
    assert_eq!(password_prompts(&user), [(true, 1), (true, 2), (true, 3)]);
    assert_eq!(
        err.message(),
        "Permission denied (tried: password; server accepts: password)"
    );
    assert!(user.accepted.is_empty());
    assert!(user.status_lines().contains(&"Using username \"alice\"."));

    // The right stored password: no prompt.
    let mut fake = Fake::new(&[PW]);
    fake.password = Some("right");
    let mut user = User::default();
    let method = Target::new(SshLogon::Normal)
        .password("right")
        .run(&mut fake, &mut user, None)
        .await
        .unwrap();
    assert_eq!(method, "password");
    assert!(user.prompts.is_empty());
}

/// AskForPassword: \[P2\] (no "try again" on the first prompt), then \[K\] where the typed
/// password answers the password request once; the OTP is asked.
#[tokio::test]
async fn ask_for_password_typed_password_answers_kbd_once() {
    let mut fake = Fake::new(&[PW, KBD]);
    fake.kbd = VecDeque::from([
        info(&[("Password: ", false)]),
        info(&[("Verification code: ", false)]),
        KbdReply::Success,
    ]);
    let mut user = User::answering(&[
        Some(&["a"]),
        Some(&["b"]),
        Some(&["typed"]),
        Some(&["424242"]),
    ]);
    let method = Target::new(SshLogon::AskForPassword)
        .run(&mut fake, &mut user, None)
        .await
        .unwrap();
    assert_eq!(method, KBD);
    assert_eq!(password_prompts(&user), [(false, 1), (true, 2), (true, 3)]);
    assert_eq!(fake.kbd_answers, [vec!["typed"], vec!["424242"]]);
    assert_eq!(user.prompts.len(), 4);
    assert!(matches!(
        &user.prompts[3],
        AuthPrompt::KeyboardInteractive { prompts, .. } if prompts[0].text == "Verification code:"
    ));
    // The typed password and the OTP led to the success.
    assert_eq!(user.accepted, [user.tokens[2], user.tokens[3]]);
}

/// AC3: Interactive shows every info request (no auto-answer).
#[tokio::test]
async fn interactive_two_rounds_two_prompts() {
    let mut fake = Fake::new(&[KBD]);
    fake.kbd = VecDeque::from([
        KbdReply::Info {
            name: "\u{1b}[31mLogin".into(),
            instruction: "Enter\u{202e} it".into(),
            prompts: vec![KbdField {
                text: "Password: ".into(),
                echo: false,
            }],
        },
        info(&[("Verification code: ", true)]),
        KbdReply::Success,
    ]);
    let mut user = User::answering(&[Some(&["pw"]), Some(&["424242"])]);
    let method = Target::new(SshLogon::Interactive)
        .password("ignored")
        .run(&mut fake, &mut user, None)
        .await
        .unwrap();
    assert_eq!(method, KBD);
    assert_eq!(fake.calls, ["none", "kbd"]);
    assert_eq!(fake.kbd_answers, [vec!["pw"], vec!["424242"]]);
    assert_eq!(
        user.prompts,
        [
            AuthPrompt::KeyboardInteractive {
                name: "Login".into(),
                instructions: "Enter it".into(),
                prompts: vec![KbdField {
                    text: "Password:".into(),
                    echo: false
                }],
            },
            AuthPrompt::KeyboardInteractive {
                name: String::new(),
                instructions: String::new(),
                prompts: vec![KbdField {
                    text: "Verification code:".into(),
                    echo: true
                }],
            },
        ]
    );
    assert_eq!(user.accepted, user.tokens);
}

#[tokio::test]
async fn interactive_falls_back_to_password_prompt_when_no_kbd() {
    let mut fake = Fake::new(&[PW]);
    fake.password = Some("pw");
    let mut user = User::answering(&[Some(&["pw"])]);
    let method = Target::new(SshLogon::Interactive)
        .run(&mut fake, &mut user, None)
        .await
        .unwrap();
    assert_eq!(method, PW);
    assert_eq!(fake.calls, ["none", "password:pw"]);
    assert_eq!(password_prompts(&user), [(false, 1)]);

    // Both listed: keyboard-interactive only, no password prompt.
    let mut fake = Fake::new(&[PW, KBD]);
    let mut user = User::default();
    let err = Target::new(SshLogon::Interactive)
        .run(&mut fake, &mut user, None)
        .await
        .unwrap_err();
    assert!(matches!(err, SshError::Auth { .. }));
    assert!(password_prompts(&user).is_empty());
    assert!(!fake.calls.iter().any(|c| c.starts_with("password")));
}

#[tokio::test]
async fn keyfile_never_falls_back_to_password() {
    let mut fake = Fake::new(&[PK, PW, KBD]);
    let mut user = User::default();
    let err = Target::new(SshLogon::KeyFile)
        .key(key("id_ed25519"))
        .password("not used")
        .agent_first()
        .run(&mut fake, &mut user, Some(agent(&["a"])))
        .await
        .unwrap_err();
    assert_eq!(fake.calls, ["none", "publickey:ssh-ed25519"]);
    assert!(user.prompts.is_empty());
    assert_eq!(
        err.message(),
        "Permission denied (tried: publickey; server accepts: publickey, password, keyboard-interactive)"
    );
    assert!(
        user.status_lines()
            .iter()
            .any(|l| l.starts_with("Trying public key id_ed25519 (ssh-ed25519 SHA256:"))
    );
}

/// AC6: three wrong passphrases, then the error; no publickey request.
#[tokio::test]
async fn wrong_passphrase_three_times_sends_no_publickey() {
    let mut fake = Fake::new(&[PK]);
    let mut user = User::answering(&[Some(&["x"]), Some(&["y"]), Some(&["z"])]);
    let mut km = key("id_ed25519_enc");
    km.passphrase = Some(SecretString::from("stored-wrong"));
    let err = Target::new(SshLogon::KeyFile)
        .key(km)
        .run(&mut fake, &mut user, None)
        .await
        .unwrap_err();
    assert_eq!(fake.calls, ["none"]);
    assert_eq!(
        user.prompts,
        [
            AuthPrompt::Passphrase {
                retry: true,
                attempt: 1
            },
            AuthPrompt::Passphrase {
                retry: true,
                attempt: 2
            },
            AuthPrompt::Passphrase {
                retry: true,
                attempt: 3
            },
        ]
    );
    assert_eq!(
        err.message(),
        "Wrong passphrase for key id_ed25519_enc (3 attempts)"
    );

    // Without a stored passphrase the first prompt has no retry note; the right one
    // is accepted.
    let mut fake = Fake::new(&[PK]);
    fake.accept_key = true;
    let mut user = User::answering(&[Some(&["nope"]), Some(&["fixture"])]);
    Target::new(SshLogon::KeyFile)
        .key(key("id_ed25519_enc"))
        .run(&mut fake, &mut user, None)
        .await
        .unwrap();
    assert_eq!(
        user.prompts,
        [
            AuthPrompt::Passphrase {
                retry: false,
                attempt: 1
            },
            AuthPrompt::Passphrase {
                retry: true,
                attempt: 2
            },
        ]
    );
    assert_eq!(user.accepted, [user.tokens[1]]);

    // A stored right passphrase: no prompt.
    let mut fake = Fake::new(&[PK]);
    fake.accept_key = true;
    let mut user = User::default();
    let mut km = key("id_ed25519_enc");
    km.passphrase = Some(SecretString::from("fixture"));
    Target::new(SshLogon::KeyFile)
        .key(km)
        .run(&mut fake, &mut user, None)
        .await
        .unwrap();
    assert!(user.prompts.is_empty());
}

/// AC7: try_agent_first offers each agent identity before the password.
#[tokio::test]
async fn try_agent_first_offers_each_identity_before_password() {
    let mut fake = Fake::new(&[PK, PW]);
    fake.password = Some("pw");
    let mut user = User::default();
    let a = agent(&["a", "b"]);
    let method = Target::new(SshLogon::Normal)
        .password("pw")
        .agent_first()
        .run(&mut fake, &mut user, Some(Arc::clone(&a)))
        .await
        .unwrap();
    assert_eq!(method, PW);
    assert_eq!(fake.calls, ["none", "agent:a", "agent:b", "password:pw"]);
    assert_eq!(a.connects.load(Ordering::SeqCst), 1);

    // The Agent logon: identities only; the accepted one ends the chain.
    let mut fake = Fake::new(&[PK, PW]);
    fake.accept_agent = Some("b");
    let method = Target::new(SshLogon::Agent)
        .run(
            &mut fake,
            &mut User::default(),
            Some(agent(&["a", "b", "c"])),
        )
        .await
        .unwrap();
    assert_eq!(method, PK);
    assert_eq!(fake.calls, ["none", "agent:a", "agent:b"]);

    // No agent / an agent without keys: skipped with a Status line.
    let mut fake = Fake::new(&[PK, PW]);
    fake.password = Some("pw");
    let mut user = User::default();
    Target::new(SshLogon::Normal)
        .password("pw")
        .agent_first()
        .run(&mut fake, &mut user, None)
        .await
        .unwrap();
    assert!(user.status_lines().contains(&"No SSH agent available"));
    let mut user = User::default();
    let mut fake = Fake::new(&[PK]);
    let _ = Target::new(SshLogon::Agent)
        .run(&mut fake, &mut user, Some(agent(&[])))
        .await
        .unwrap_err();
    assert!(user.status_lines().contains(&"SSH agent has no keys"));
}

/// AC8: never more than six requests after `none`.
#[tokio::test]
async fn attempt_cap_is_six() {
    let mut fake = Fake::new(&[PW, KBD]);
    let mut user = User::answering(&[Some(&["1"]), Some(&["2"]), Some(&["3"])]);
    let err = Target::new(SshLogon::Normal)
        .password("stored")
        .run(&mut fake, &mut user, None)
        .await
        .unwrap_err();
    // 1 stored password + 3 kbd conversations + 2 prompted passwords = 6.
    assert_eq!(
        fake.calls,
        [
            "none",
            "password:stored",
            "kbd",
            "kbd",
            "kbd",
            "password:1",
            "password:2"
        ]
    );
    assert_eq!(user.prompts.len(), 2);
    assert!(matches!(err, SshError::Auth { ref tried, .. } if tried == &[PW, KBD]));

    let mut fake = Fake::new(&[PK]);
    let _ = Target::new(SshLogon::Agent)
        .run(
            &mut fake,
            &mut User::default(),
            Some(agent(&["1", "2", "3", "4", "5", "6", "7", "8"])),
        )
        .await
        .unwrap_err();
    assert_eq!(fake.calls.len(), 1 + MAX_AUTH_ATTEMPTS as usize);
}

#[tokio::test]
async fn rsa_hash_selection_sha512_sha256_sha1_skip() {
    assert_eq!(rsa_hash(RsaSigSupport::Sha512), Some(Some(HashAlg::Sha512)));
    assert_eq!(rsa_hash(RsaSigSupport::Sha256), Some(Some(HashAlg::Sha256)));
    assert_eq!(rsa_hash(RsaSigSupport::Unknown), Some(None));
    assert_eq!(rsa_hash(RsaSigSupport::NoSha2), None);

    for (support, call) in [
        (RsaSigSupport::Sha512, Some("publickey:rsa-sha2-512")),
        (RsaSigSupport::Sha256, Some("publickey:rsa-sha2-256")),
        (RsaSigSupport::Unknown, Some("publickey:ssh-rsa")),
        (RsaSigSupport::NoSha2, None),
    ] {
        let mut fake = Fake::new(&[PK]);
        fake.rsa = support;
        fake.accept_key = true;
        let mut user = User::default();
        let res = Target::new(SshLogon::KeyFile)
            .key(key("id_rsa4096"))
            .run(&mut fake, &mut user, None)
            .await;
        match call {
            Some(c) => {
                res.unwrap();
                assert_eq!(fake.calls, ["none", c], "{support:?}");
            }
            None => {
                assert!(res.is_err());
                assert_eq!(fake.calls, ["none"]);
            }
        }
        let warned = user
            .status_lines()
            .contains(&"Server does not support SHA-2 RSA signatures; using ssh-rsa (SHA-1)");
        assert_eq!(warned, support == RsaSigSupport::Unknown, "{support:?}");
    }
}

#[tokio::test]
async fn partial_success_continues_with_next_allowed_method() {
    let mut fake = Fake::new(&[PK]);
    fake.partial_agent = Some("a");
    fake.methods_after_partial = vec![PW];
    fake.password = Some("pw");
    let mut user = User::default();
    let method = Target::new(SshLogon::Normal)
        .password("pw")
        .agent_first()
        .run(&mut fake, &mut user, Some(agent(&["a", "b"])))
        .await
        .unwrap();
    assert_eq!(method, PW);
    assert_eq!(fake.calls, ["none", "agent:a", "password:pw"]);
}

/// AC9 (chain side): a cancelled prompt aborts the connect.
#[tokio::test]
async fn cancelled_prompt_aborts_with_cancelled() {
    for logon in [SshLogon::AskForPassword, SshLogon::Normal] {
        let mut fake = Fake::new(&[PW, KBD]);
        let mut user = User::answering(&[None]);
        let err = Target::new(logon)
            .run(&mut fake, &mut user, None)
            .await
            .unwrap_err();
        assert!(matches!(err, SshError::Cancelled), "{logon:?}: {err:?}");
    }
    let mut fake = Fake::new(&[KBD]);
    fake.kbd = VecDeque::from([info(&[("Code: ", true)])]);
    let err = Target::new(SshLogon::Interactive)
        .run(&mut fake, &mut User::answering(&[None]), None)
        .await
        .unwrap_err();
    assert!(matches!(err, SshError::Cancelled));
    let err = Target::new(SshLogon::KeyFile)
        .key(key("id_ed25519_enc"))
        .run(&mut Fake::new(&[PK]), &mut User::answering(&[None]), None)
        .await
        .unwrap_err();
    assert!(matches!(err, SshError::Cancelled));
}

/// AC15: only answers that led to (partial) success are reported.
#[tokio::test]
async fn accepted_only_after_success() {
    let mut fake = Fake::new(&[PW]);
    fake.password = Some("good");
    let mut user = User::answering(&[Some(&["bad"]), Some(&["good"])]);
    Target::new(SshLogon::AskForPassword)
        .run(&mut fake, &mut user, None)
        .await
        .unwrap();
    assert_eq!(user.accepted, [user.tokens[1]]);

    let mut fake = Fake::new(&[PW]);
    let mut user = User::answering(&[Some(&["a"]), Some(&["b"]), Some(&["c"])]);
    let _ = Target::new(SshLogon::AskForPassword)
        .run(&mut fake, &mut user, None)
        .await
        .unwrap_err();
    assert!(user.accepted.is_empty());
}

/// sverb t18: the answer buffer of each prompt is dropped as soon as its request
/// returns (before the next prompt).
#[tokio::test]
async fn answer_buffers_dropped_after_request() {
    let before = ANSWERS_DROPPED.with(std::cell::Cell::get);
    let mut fake = Fake::new(&[PW]);
    let mut user = User::answering(&[Some(&["a"]), Some(&["b"]), Some(&["c"])]);
    let _ = Target::new(SshLogon::AskForPassword)
        .run(&mut fake, &mut user, None)
        .await
        .unwrap_err();
    let seen: Vec<usize> = fake.dropped_at_request.iter().map(|n| n - before).collect();
    assert_eq!(seen, [0, 1, 2]);
    assert_eq!(ANSWERS_DROPPED.with(std::cell::Cell::get) - before, 3);
}

#[tokio::test]
async fn kbd_more_than_ten_prompts_fails_method() {
    let mut fake = Fake::new(&[KBD]);
    let many: Vec<(&str, bool)> = (0..11).map(|_| ("x", false)).collect();
    fake.kbd = VecDeque::from([info(&many)]);
    let mut user = User::default();
    let err = Target::new(SshLogon::Interactive)
        .run(&mut fake, &mut user, None)
        .await
        .unwrap_err();
    assert!(matches!(err, SshError::Auth { .. }));
    assert!(user.prompts.is_empty());
    assert!(
        user.log
            .iter()
            .any(|(k, t)| *k == LogKind::Error && t.contains("11 prompts"))
    );
    // Ten is fine.
    let mut fake = Fake::new(&[KBD]);
    let ten: Vec<(&str, bool)> = (0..10).map(|_| ("x", false)).collect();
    fake.kbd = VecDeque::from([info(&ten), KbdReply::Success]);
    let answers: &[&str] = &["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"];
    let mut user = User::answering(&[Some(answers)]);
    Target::new(SshLogon::Interactive)
        .run(&mut fake, &mut user, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn none_success_ends_the_chain() {
    struct Open;
    #[async_trait]
    impl AuthBackend for Open {
        async fn none(&mut self, _: &str) -> Result<AuthOutcome, SshError> {
            Ok(AuthOutcome::Success)
        }
        async fn password(&mut self, _: &str, _: &SecretString) -> Result<AuthOutcome, SshError> {
            unreachable!()
        }
        async fn publickey(
            &mut self,
            _: &str,
            _: Arc<PrivateKey>,
            _: Option<HashAlg>,
        ) -> Result<AuthOutcome, SshError> {
            unreachable!()
        }
        async fn agent_identity(
            &mut self,
            _: &str,
            _: &mut dyn Agent,
            _: &AgentIdentity,
            _: Option<HashAlg>,
        ) -> Result<AuthOutcome, SshError> {
            unreachable!()
        }
        async fn kbd_start(&mut self, _: &str) -> Result<KbdReply, SshError> {
            unreachable!()
        }
        async fn kbd_respond(&mut self, _: &[SecretString]) -> Result<KbdReply, SshError> {
            unreachable!()
        }
        async fn rsa_support(&mut self) -> RsaSigSupport {
            RsaSigSupport::Sha512
        }
    }
    let method = Target::new(SshLogon::AskForPassword)
        .run_with(&mut Open)
        .await
        .unwrap();
    assert_eq!(method, "none");
}

impl Target {
    async fn run_with(&self, backend: &mut dyn AuthBackend) -> Result<&'static str, SshError> {
        let target = ChainTarget {
            user: "alice",
            logon: self.logon,
            password: self.password.as_ref(),
            key: self.key.as_ref(),
            try_agent_first: self.try_agent_first,
        };
        run_chain(&target, backend, &mut User::default(), None).await
    }
}

/// AC8 (OpenSSH `MaxAuthTries`): a disconnect for too many failures is `Auth`.
#[tokio::test]
async fn max_auth_tries_disconnect_is_auth() {
    let mut fake = Fake::new(&[PK]);
    let err = Target::new(SshLogon::Agent)
        .run(
            &mut fake,
            &mut User::default(),
            Some(agent(&["a", "disconnect"])),
        )
        .await
        .unwrap_err();
    assert_eq!(
        err.message(),
        "Permission denied (tried: publickey; server accepts: publickey)"
    );
}
