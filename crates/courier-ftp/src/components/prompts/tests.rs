//! Fixtures for the prompt tests, and the `Debug` redaction test.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::{collections::HashMap, sync::mpsc, thread, time::Duration};

use courier_ftp_core::{
    events::{
        self, CertPromptDetails, CertificateDetails, CoreEvent, DataProtection, EventReceiver,
        EventSender, FileExistsPrompt, HostKeyPrompt, KbdField, KbdInteractivePrompt, OldKey,
        OldKeySource, PassphrasePrompt, PasswordPrompt, PasswordPurpose, PreviousCert, PromptId,
        PromptKind, PromptRequest, PromptResponse, SecretCacheKey, SessionId, TlsSessionInfo,
        TrustSource,
    },
    model::{Direction, Entry, EntryKind, Precision, Protocol, Timestamp},
    settings::DebugLevel,
};
use crossterm::event::KeyCode;
use time::{OffsetDateTime, macros::datetime};
use tokio_util::sync::CancellationToken;

use super::{certificate::render_certificate_details, host_key::render_host_key_details, *};
use crate::{app::Mode, keymap::chord::Mods};

/// A key: one character, or a chord string (`"alt-o"`, `"pagedown"`).
pub(crate) fn k(s: &str) -> KeyChord {
    let mut chars = s.chars();
    if let (Some(c), None) = (chars.next(), chars.clone().next()) {
        return KeyChord::new(KeyCode::Char(c), Mods::NONE);
    }
    s.parse().unwrap_or_else(|e| panic!("key {s:?}: {e}"))
}

/// A focus state in which every prompt may open.
pub(crate) fn ui_normal() -> UiFocusState {
    UiFocusState {
        mode: Mode::Normal,
        other_dialog_open: false,
        vault_locked: false,
    }
}

/// 2026-10-10 12:00 UTC.
pub(crate) fn now_2026() -> OffsetDateTime {
    datetime!(2026-10-10 12:00 UTC)
}

/// A login password cache key for `host`.
pub(crate) fn pw_key(host: &str) -> SecretCacheKey {
    SecretCacheKey::Password {
        protocol: Protocol::Sftp,
        host: host.into(),
        port: 22,
        user: "alice".into(),
    }
}

/// A login password prompt.
pub(crate) fn password_prompt(cache_key: SecretCacheKey, retry: bool) -> PasswordPrompt {
    PasswordPrompt {
        purpose: PasswordPurpose::Login,
        target: "alice@web01.example.com:22".into(),
        retry,
        attempt: if retry { 2 } else { 1 },
        max_attempts: 3,
        cache_key,
        can_save: true,
    }
}

/// A key passphrase prompt.
pub(crate) fn passphrase_prompt() -> PassphrasePrompt {
    PassphrasePrompt {
        key_label: "~/.ssh/id_ed25519".into(),
        retry: false,
        attempt: 1,
        max_attempts: 3,
        cache_key: SecretCacheKey::Passphrase {
            key: "~/.ssh/id_ed25519".into(),
        },
        can_save: false,
    }
}

/// A keyboard-interactive prompt with `(text, echo)` fields.
pub(crate) fn kbd_prompt(fields: &[(&str, bool)], instructions: &str) -> KbdInteractivePrompt {
    KbdInteractivePrompt {
        host: "web01.example.com:22".into(),
        name: "Duo two-factor login".into(),
        instructions: instructions.into(),
        prompts: fields
            .iter()
            .map(|(t, e)| KbdField {
                text: (*t).into(),
                echo: *e,
            })
            .collect(),
    }
}

/// An unknown ed25519 host key.
pub(crate) fn unknown_host_key(can_save: bool) -> HostKeyPrompt {
    HostKeyPrompt {
        host: "web01.example.com".into(),
        port: 22,
        key_type: "ssh-ed25519".into(),
        bits: 256,
        fingerprint_sha256: "SHA256:uYxmMoF3aflKiV/iuu80yFQwZt3pbSCXEaovtc9SyY8".into(),
        fingerprint_md5: "MD5:9a:52:0e:7c:1f:33:a8:0d:4b:6e:21:c5:90:fe:12:ab".into(),
        changed: None,
        other_known_types: Vec::new(),
        can_save,
    }
}

/// A changed host key (trusted one in the vault).
pub(crate) fn changed_host_key(can_save: bool) -> HostKeyPrompt {
    HostKeyPrompt {
        changed: Some(vec![OldKey {
            fingerprint_sha256: "SHA256:Xq3vR0ZQh2m1bN8kPj4tLw6yUe9sDc7fGa5iHo2KlMn".into(),
            source: OldKeySource::Vault {
                id: uuid_nil(),
                added_at: datetime!(2026-03-01 10:00 UTC),
            },
        }]),
        ..unknown_host_key(can_save)
    }
}

fn uuid_nil() -> uuid::Uuid {
    uuid::Uuid::nil()
}

/// One certificate.
pub(crate) fn cert(
    subject: &str,
    issuer: &str,
    not_after: OffsetDateTime,
    ca: bool,
) -> CertificateDetails {
    CertificateDetails {
        subject: subject.into(),
        subject_cn: subject
            .split(',')
            .find_map(|p| p.trim().strip_prefix("CN="))
            .map(str::to_owned),
        issuer: issuer.into(),
        serial: "04:A3:9F:11:0C:7E".into(),
        not_before: datetime!(2026-01-01 00:00 UTC),
        not_after,
        sha256: std::array::from_fn(|i| u8::try_from(i * 7 % 256).unwrap_or(0)),
        sha1: std::array::from_fn(|i| u8::try_from(i * 13 % 256).unwrap_or(0)),
        sans: if ca {
            Vec::new()
        } else {
            vec!["DNS:www.example.com".into(), "DNS:example.com".into()]
        },
        public_key: "EC P-256".into(),
        signature_algorithm: "ecdsa-with-SHA256".into(),
        is_ca: ca,
        self_signed: ca,
        parse_error: None,
    }
}

/// A certificate prompt for ftp.example.com (leaf for www.example.com + root).
pub(crate) fn cert_prompt(changed: bool, can_save: bool) -> CertPromptDetails {
    cert_prompt_at(changed, can_save, datetime!(2027-01-01 00:00 UTC))
}

/// As [`cert_prompt`] with the leaf's end of validity.
pub(crate) fn cert_prompt_at(
    changed: bool,
    can_save: bool,
    not_after: OffsetDateTime,
) -> CertPromptDetails {
    CertPromptDetails {
        host: "ftp.example.com".into(),
        port: 21,
        session: TlsSessionInfo {
            protocol: "TLS 1.3".into(),
            cipher_suite: "TLS_AES_256_GCM_SHA384".into(),
            server_name: "ftp.example.com".into(),
            chain: vec![
                cert(
                    "CN=www.example.com, O=Example Ltd",
                    "CN=Example Root CA, O=Example Ltd",
                    not_after,
                    false,
                ),
                cert(
                    "CN=Example Root CA, O=Example Ltd",
                    "CN=Example Root CA, O=Example Ltd",
                    datetime!(2036-01-01 00:00 UTC),
                    true,
                ),
            ],
            trusted_by: TrustSource::Once,
            data_protection: DataProtection::Private,
        },
        problems: vec![
            events::CertProblem::UnknownIssuer,
            events::CertProblem::NotValidForName,
        ],
        hostname_matches: false,
        previous: changed.then(|| PreviousCert {
            sha256: [0xAB; 32],
            subject: "CN=ftp.example.com, O=Example Ltd".into(),
            not_after: datetime!(2026-09-30 00:00 UTC),
            added_at: datetime!(2025-10-01 08:00 UTC),
        }),
        can_save,
    }
}

fn entry(name: &str, size: u64, modified: OffsetDateTime) -> Entry {
    let mut e = Entry::new(name, EntryKind::File);
    e.size = Some(size);
    e.modified = Some(Timestamp {
        time: modified,
        precision: Precision::Minute,
    });
    e
}

/// A download conflict for `index.html`.
pub(crate) fn file_exists_prompt(direction: Direction, can_resume: bool) -> FileExistsPrompt {
    let (src, dst) = match direction {
        Direction::Download => (
            "/var/www/index.html",
            "/home/alice/projects/site/index.html",
        ),
        Direction::Upload => (
            "/home/alice/projects/site/index.html",
            "/var/www/index.html",
        ),
    };
    FileExistsPrompt {
        direction,
        source_path: src.into(),
        source: entry("index.html", 4096, datetime!(2026-10-02 10:00 UTC)),
        target_path: dst.into(),
        target: entry("index.html", 3174, datetime!(2026-09-30 09:12 UTC)),
        can_resume,
        suggested_name: Some("index (1).html".into()),
    }
}

/// Makes real [`PromptRequest`]s: each request's requester runs on its own thread
/// (so tests on a paused runtime are not blocked) and its answer can be read back.
pub(crate) struct Prompter {
    tx: EventSender,
    rx: EventReceiver,
    session: SessionId,
    pending: HashMap<PromptId, (mpsc::Receiver<Option<PromptResponse>>, CancellationToken)>,
    last: Option<PromptId>,
}

impl Prompter {
    /// A bus of its own.
    pub(crate) fn new() -> Self {
        let (tx, rx) = events::channel(DebugLevel::default());
        Self {
            tx,
            rx,
            session: SessionId::next(),
            pending: HashMap::new(),
            last: None,
        }
    }

    /// The session the requests come from.
    pub(crate) fn session(&self) -> SessionId {
        self.session
    }

    /// A request of `kind` from [`Self::session`].
    pub(crate) fn request(&mut self, kind: PromptKind) -> PromptRequest {
        self.request_from(self.session, kind)
    }

    /// A request of `kind` from `session`.
    pub(crate) fn request_from(&mut self, session: SessionId, kind: PromptKind) -> PromptRequest {
        let (done_tx, done_rx) = mpsc::channel();
        let token = CancellationToken::new();
        let tx = self.tx.clone();
        let t = token.clone();
        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let r = rt.block_on(tx.prompt_with_cancel(session, kind, &t));
            let _ = done_tx.send(match r {
                Ok(r) => Some(r),
                Err(courier_ftp_core::Error::Cancelled) => Some(PromptResponse::Cancel),
                Err(_) => None,
            });
        });
        for _ in 0..5000 {
            if let Some(CoreEvent::Prompt(req)) = self.rx.try_recv() {
                self.pending.insert(req.id, (done_rx, token));
                self.last = Some(req.id);
                return req;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("no prompt event");
    }

    /// The id of a fresh request (which is then dropped).
    pub(crate) fn any_id(&mut self) -> PromptId {
        self.request(PromptKind::Message(events::MessagePrompt {
            level: events::NoticeLevel::Info,
            title: "t".into(),
            text: "x".into(),
        }))
        .id
    }

    /// Withdraws request `id` (the requester gives up).
    pub(crate) fn withdraw(&mut self, id: PromptId) {
        if let Some((rx, token)) = self.pending.remove(&id) {
            token.cancel();
            let _ = rx.recv_timeout(Duration::from_secs(5));
        }
    }

    /// The answer the requester of `id` got (`Cancel` for a dropped request), waiting
    /// at most 5 s; `None` if it got none.
    pub(crate) fn answer_of(&mut self, id: PromptId) -> Option<PromptResponse> {
        let (rx, _) = self.pending.remove(&id)?;
        rx.recv_timeout(Duration::from_secs(5)).ok().flatten()
    }

    /// The answer to the last request.
    pub(crate) fn answer(&mut self) -> Option<PromptResponse> {
        let id = self.last?;
        self.answer_of(id)
    }
}

#[test]
fn debug_redacts_typed_secrets() {
    const CANARY: &str = "CANARY-7f3a91";
    let mut d = SecretDialog::password(&password_prompt(pw_key("h"), false));
    for c in CANARY.chars() {
        d.handle_key(KeyChord::char(c));
    }
    let dbg = format!("{d:?}");
    assert!(!dbg.contains(CANARY), "{dbg}");
    assert!(dbg.contains("[REDACTED]"), "{dbg}");

    let mut d = KbdDialog::new(&kbd_prompt(&[("Password:", false), ("Code:", true)], ""));
    for c in CANARY.chars() {
        d.handle_key(KeyChord::char(c));
    }
    d.handle_key(k("tab"));
    for c in CANARY.chars() {
        d.handle_key(KeyChord::char(c));
    }
    let dbg = format!("{d:?}");
    assert!(!dbg.contains(CANARY), "{dbg}");
    assert!(dbg.contains("[REDACTED]"), "{dbg}");

    let mut cache = SecretCache::default();
    cache.insert(
        pw_key("h"),
        courier_ftp_core::secret::SecretString::from(CANARY),
    );
    assert!(!format!("{cache:?}").contains(CANARY));

    let mut pend = PendingCredentials::default();
    let mut p = Prompter::new();
    pend.insert(
        p.any_id(),
        Pending {
            session: SessionId::next(),
            key: pw_key("h"),
            field: CredentialField::Password,
            value: courier_ftp_core::secret::SecretString::from(CANARY),
            remember: true,
            save: true,
            since: tokio::time::Instant::now(),
        },
    );
    assert!(!format!("{pend:?}").contains(CANARY));

    // The visible dialog inside the queue, too.
    let mut q = PromptQueue::default();
    let req = p.request(PromptKind::Password(password_prompt(pw_key("h"), false)));
    let t0 = tokio::time::Instant::now();
    q.push(req, PromptOrigin::Foreground, t0);
    q.tick(t0, &ui_normal());
    let later = t0 + Duration::from_secs(1);
    for c in CANARY.chars() {
        q.handle_key(KeyChord::char(c), later);
    }
    assert!(!format!("{q:?}").contains(CANARY));
}

#[test]
fn detail_renderers_for_server_info() {
    let text = |lines: Vec<ratatui::text::Line<'static>>| {
        lines
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    };
    let hk = text(render_host_key_details(&unknown_host_key(true)));
    assert!(hk.contains("Host:       web01.example.com:22"), "{hk}");
    assert!(hk.contains("Key type:   ssh-ed25519 (256 bits)"), "{hk}");
    assert!(
        hk.contains("SHA256:uYxmMoF3aflKiV/iuu80yFQwZt3pbSCXEaovtc9SyY8"),
        "{hk}"
    );
    let leaf = &cert_prompt_at(false, true, datetime!(2026-09-28 00:00 UTC))
        .session
        .chain[0];
    let c = text(render_certificate_details(leaf, now_2026()));
    assert!(
        c.contains("Subject:    CN=www.example.com, O=Example Ltd"),
        "{c}"
    );
    assert!(c.contains("(expired 12 days ago)"), "{c}");
    assert!(
        c.contains("Alt. names: DNS:www.example.com\n            DNS:example.com"),
        "{c}"
    );
}
