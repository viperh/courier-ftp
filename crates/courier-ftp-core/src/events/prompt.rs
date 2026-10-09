//! Prompts: questions to the user and their answers (T04).
//!
//! Payloads are produced by T07/T10/T15/T20 (secrets), T12 (certificates), T21 (host
//! keys) and T42 (file exists); the UI renders them (T69). Prompt kinds carry no
//! secrets; answers hold them only as [`SecretString`].

use std::fmt;
use std::path::PathBuf;

use time::OffsetDateTime;
use tokio::sync::oneshot;

use super::{NoticeLevel, PromptId, SessionId};
use crate::model::{Direction, Entry, Protocol};
use crate::secret::SecretString;
use crate::settings::ExistsAction;
use crate::{Error, Result};

/// A question to the user. The requester awaits the answer; dropping the requester
/// withdraws the prompt (the UI sees [`is_withdrawn`](Self::is_withdrawn) and closes
/// the dialog).
pub struct PromptRequest {
    /// Assigned by the [`EventSender`](super::EventSender).
    pub id: PromptId,
    /// The session that asks.
    pub session: SessionId,
    /// What is asked.
    pub kind: PromptKind,
    reply: oneshot::Sender<PromptResponse>,
}

impl PromptRequest {
    pub(crate) fn new(
        id: PromptId,
        session: SessionId,
        kind: PromptKind,
        reply: oneshot::Sender<PromptResponse>,
    ) -> Self {
        Self {
            id,
            session,
            kind,
            reply,
        }
    }

    /// Sends the answer. Returns false when the requester is gone.
    pub fn respond(self, response: PromptResponse) -> bool {
        self.reply.send(response).is_ok()
    }

    /// The requester gave up (operation cancelled, connection closed).
    pub fn is_withdrawn(&self) -> bool {
        self.reply.is_closed()
    }
}

impl fmt::Debug for PromptRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PromptRequest")
            .field("id", &self.id)
            .field("session", &self.session)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// What a prompt asks.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum PromptKind {
    /// Trust an unknown or changed SSH host key (T21).
    TrustHostKey(HostKeyPrompt),
    /// Trust a TLS certificate the platform does not (T12).
    TrustCertificate(Box<CertPromptDetails>),
    /// A password (T07, T10, T15, T20).
    Password(PasswordPrompt),
    /// A private key passphrase (T20).
    KeyPassphrase(PassphrasePrompt),
    /// SSH keyboard-interactive authentication (T20).
    KeyboardInteractive(KbdInteractivePrompt),
    /// A transfer target already exists (T42).
    FileExists(Box<FileExistsPrompt>),
    /// Informational; answered with [`PromptResponse::Ack`].
    Message(MessagePrompt),
}

impl PromptKind {
    /// Short name of the kind, for traces (no payload).
    fn name(&self) -> &'static str {
        match self {
            Self::TrustHostKey(_) => "TrustHostKey",
            Self::TrustCertificate(_) => "TrustCertificate",
            Self::Password(_) => "Password",
            Self::KeyPassphrase(_) => "KeyPassphrase",
            Self::KeyboardInteractive(_) => "KeyboardInteractive",
            Self::FileExists(_) => "FileExists",
            Self::Message(_) => "Message",
        }
    }
}

// ---- host keys (payload produced by T21) ----

/// An SSH host key to confirm (T21, rendered by T69).
#[derive(Clone, Debug, PartialEq)]
pub struct HostKeyPrompt {
    /// Host name as the user entered it.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Key algorithm, e.g. `"ssh-ed25519"`.
    pub key_type: String,
    /// Key size in bits.
    pub bits: u32,
    /// `"SHA256:<base64, no padding>"`.
    pub fingerprint_sha256: String,
    /// `"MD5:aa:bb:…"`.
    pub fingerprint_md5: String,
    /// Some → the key changed: the stored/known keys of the same type (T69 red warning).
    pub changed: Option<Vec<OldKey>>,
    /// Unknown key, but other key types are trusted for this host (shown as a note).
    pub other_known_types: Vec<String>,
    /// false (vault locked / in-memory store) → "Always trust" disabled (T21 §4).
    pub can_save: bool,
}

/// A previously known host key.
#[derive(Clone, Debug, PartialEq)]
pub struct OldKey {
    /// `"SHA256:<base64, no padding>"`.
    pub fingerprint_sha256: String,
    /// Where the key is known from.
    pub source: OldKeySource,
}

/// Where a known host key is stored.
#[derive(Clone, Debug, PartialEq)]
pub enum OldKeySource {
    /// A `known-host` vault item (id = its item id, T81; T21's `KnownHostId` wraps it).
    Vault {
        /// The vault item id.
        id: uuid::Uuid,
        /// When the key was trusted.
        added_at: OffsetDateTime,
    },
    /// A line of an OpenSSH `known_hosts` file.
    OpenSshFile {
        /// The file.
        path: PathBuf,
        /// 1-based line number.
        line: usize,
    },
}

/// Host key summary for the server info dialog (T57).
#[derive(Clone, Debug, PartialEq)]
pub struct HostKeyInfo {
    /// Key algorithm, e.g. `"ssh-ed25519"`.
    pub key_type: String,
    /// Key size in bits.
    pub bits: u32,
    /// `"SHA256:<base64, no padding>"`.
    pub fingerprint_sha256: String,
}

// ---- TLS certificates (payload produced by T12) ----

/// One parsed X.509 certificate (T12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateDetails {
    /// RFC 4514, e.g. `"CN=ftp.example.com,O=Example"`.
    pub subject: String,
    /// The subject's common name, if any.
    pub subject_cn: Option<String>,
    /// RFC 4514 issuer name.
    pub issuer: String,
    /// Upper-case hex, colon separated.
    pub serial: String,
    /// Start of validity.
    pub not_before: OffsetDateTime,
    /// End of validity.
    pub not_after: OffsetDateTime,
    /// SHA-256 fingerprint of the DER encoding.
    pub sha256: [u8; 32],
    /// SHA-1 fingerprint (display only).
    pub sha1: [u8; 20],
    /// Subject alternative names: `"DNS:ftp.example.com"`, `"IP:192.0.2.1"`.
    pub sans: Vec<String>,
    /// `"RSA 2048"`, `"EC P-256"`, `"Ed25519"`.
    pub public_key: String,
    /// Signature algorithm name.
    pub signature_algorithm: String,
    /// Basic constraints CA flag.
    pub is_ca: bool,
    /// Issuer equals subject and the signature verifies with its own key.
    pub self_signed: bool,
    /// Set when parsing failed partway (fields may be empty).
    pub parse_error: Option<String>,
}

/// Why a certificate is not trusted by the platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertProblem {
    /// The chain does not end in a trusted root.
    UnknownIssuer,
    /// The certificate signs itself.
    SelfSigned,
    /// `not_after` is in the past.
    Expired,
    /// `not_before` is in the future.
    NotYetValid,
    /// The host name is not in the certificate.
    NotValidForName,
    /// The certificate was revoked.
    Revoked,
    /// Not valid for server authentication.
    InvalidPurpose,
    /// A signature in the chain does not verify.
    BadSignature,
    /// Anything else (verifier text).
    Other(String),
}

/// A negotiated TLS session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsSessionInfo {
    /// `"TLSv1.3"`.
    pub protocol: String,
    /// `"TLS13_AES_128_GCM_SHA256"`.
    pub cipher_suite: String,
    /// SNI / verification name.
    pub server_name: String,
    /// Leaf first.
    pub chain: Vec<CertificateDetails>,
    /// Why the chain is trusted.
    pub trusted_by: TrustSource,
    /// Whether the data connection is protected.
    pub data_protection: DataProtection,
}

/// Why a certificate chain is trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustSource {
    /// The platform verifier accepted it.
    Platform,
    /// It is stored as "always trusted".
    Stored,
    /// The user trusted it for this session.
    Once,
}

/// FTP data channel protection (`PROT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataProtection {
    /// `PROT P`.
    Private,
    /// `PROT C`.
    Clear,
}

/// A TLS certificate to confirm (T12, rendered by T69).
#[derive(Clone, Debug, PartialEq)]
pub struct CertPromptDetails {
    /// Host name as the user entered it.
    pub host: String,
    /// Port.
    pub port: u16,
    /// The negotiated session and chain.
    pub session: TlsSessionInfo,
    /// What the platform verifier objected to.
    pub problems: Vec<CertProblem>,
    /// The leaf is valid for `host`.
    pub hostname_matches: bool,
    /// Another certificate is stored as "always trusted" for host:port → changed-cert warning.
    pub previous: Option<PreviousCert>,
    /// false (vault locked / in-memory store) → "Always trust" disabled.
    pub can_save: bool,
}

/// The certificate previously trusted for the same host:port.
#[derive(Clone, Debug, PartialEq)]
pub struct PreviousCert {
    /// Its SHA-256 fingerprint.
    pub sha256: [u8; 32],
    /// Its subject.
    pub subject: String,
    /// Its end of validity.
    pub not_after: OffsetDateTime,
    /// When it was trusted.
    pub added_at: OffsetDateTime,
}

// ---- secrets (payloads produced by T07, T10, T15, T20) ----

/// A password request.
#[derive(Clone, Debug, PartialEq)]
pub struct PasswordPrompt {
    /// What the password is for.
    pub purpose: PasswordPurpose,
    /// `"alice@web01.example.com:22"`, or the proxy `"host:port"`.
    pub target: String,
    /// The previous answer was rejected (T69 shows the retry line, never answers from cache).
    pub retry: bool,
    /// 1-based.
    pub attempt: u8,
    /// 3 for SSH (T20).
    pub max_attempts: u8,
    /// Key for T69's "remember for this session" cache.
    pub cache_key: SecretCacheKey,
    /// "Save in the vault" offered (saved site, vault unlocked, `vault.store_passwords`).
    pub can_save: bool,
}

/// What a password is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordPurpose {
    /// Server login.
    Login,
    /// FTP `ACCT`.
    Account,
    /// Generic (HTTP/SOCKS) proxy.
    Proxy,
    /// FTP proxy (T15).
    FtpProxy,
}

/// A private-key passphrase request.
#[derive(Clone, Debug, PartialEq)]
pub struct PassphrasePrompt {
    /// Path or `"vault key <name>"`.
    pub key_label: String,
    /// The previous answer was rejected.
    pub retry: bool,
    /// 1-based.
    pub attempt: u8,
    /// Maximum attempts.
    pub max_attempts: u8,
    /// Key for the session cache.
    pub cache_key: SecretCacheKey,
    /// "Save in the vault" offered.
    pub can_save: bool,
}

/// Key of T69's "remember for this session" secret cache.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SecretCacheKey {
    /// A login password; `host` ASCII-lowercased.
    Password {
        /// Protocol.
        protocol: Protocol,
        /// Lowercase host.
        host: String,
        /// Port.
        port: u16,
        /// User name.
        user: String,
    },
    /// An FTP `ACCT` value.
    Account {
        /// Lowercase host.
        host: String,
        /// Port.
        port: u16,
        /// User name.
        user: String,
    },
    /// A proxy password.
    Proxy {
        /// Lowercase proxy host.
        host: String,
        /// Proxy port.
        port: u16,
        /// Proxy user.
        user: String,
    },
    /// A key passphrase.
    Passphrase {
        /// Key path or vault key name.
        key: String,
    },
}

/// SSH keyboard-interactive request.
#[derive(Clone, Debug, PartialEq)]
pub struct KbdInteractivePrompt {
    /// `"web01.example.com:22"`.
    pub host: String,
    /// Untrusted server text.
    pub name: String,
    /// Untrusted server text.
    pub instructions: String,
    /// The fields to answer, in order.
    pub prompts: Vec<KbdField>,
}

/// One keyboard-interactive field.
#[derive(Clone, Debug, PartialEq)]
pub struct KbdField {
    /// Untrusted server text.
    pub text: String,
    /// Whether the answer may be shown while typing.
    pub echo: bool,
}

// ---- file exists (payload produced by T42) ----

/// A transfer target already exists (T42).
#[derive(Clone, Debug, PartialEq)]
pub struct FileExistsPrompt {
    /// Upload or download.
    pub direction: Direction,
    /// Display string of the source (`RemotePath::as_str` / `LocalPath::to_display`).
    pub source_path: String,
    /// The source entry.
    pub source: Entry,
    /// Display string of the target.
    pub target_path: String,
    /// The existing target entry.
    pub target: Entry,
    /// Resume offered (capability + binary type + target smaller, T42).
    pub can_resume: bool,
    /// Prefill for the rename field (`"name (1).ext"`, T42's first free name), if computed.
    pub suggested_name: Option<String>,
}

/// An informational message, answered with [`PromptResponse::Ack`].
#[derive(Clone, Debug, PartialEq)]
pub struct MessagePrompt {
    /// Severity.
    pub level: NoticeLevel,
    /// Dialog title.
    pub title: String,
    /// Body text.
    pub text: String,
}

/// The user's answer. Must match the prompt kind (see [`EventSender::prompt`](super::EventSender::prompt)).
#[non_exhaustive]
pub enum PromptResponse {
    /// Answer to [`PromptKind::TrustHostKey`].
    HostKey(TrustAnswer),
    /// Answer to [`PromptKind::TrustCertificate`].
    Certificate(TrustAnswer),
    /// Answer to [`PromptKind::Password`] / [`PromptKind::KeyPassphrase`]. The UI keeps
    /// the typed value and caches/saves it only after
    /// [`CoreEvent::CredentialAccepted`](super::CoreEvent::CredentialAccepted) for this
    /// prompt (T69).
    Secret {
        /// The secret.
        value: SecretString,
        /// Remember for this session.
        remember_session: bool,
        /// Save in the vault.
        save_in_vault: bool,
    },
    /// Answer to [`PromptKind::KeyboardInteractive`]: one answer per field, same order.
    Answers(Vec<SecretString>),
    /// Answer to [`PromptKind::FileExists`].
    FileExists {
        /// What to do (never `Ask`).
        action: ExistsAction,
        /// Scope of the answer.
        apply_to: ApplyTo,
        /// Present iff `action` is `Rename`.
        new_name: Option<String>,
    },
    /// Answer to [`PromptKind::Message`].
    Ack,
    /// The user cancelled (any kind).
    Cancel,
}

impl fmt::Debug for PromptResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostKey(a) => f.debug_tuple("HostKey").field(a).finish(),
            Self::Certificate(a) => f.debug_tuple("Certificate").field(a).finish(),
            Self::Secret {
                remember_session,
                save_in_vault,
                ..
            } => f
                .debug_struct("Secret")
                .field("value", &format_args!("[REDACTED]"))
                .field("remember_session", remember_session)
                .field("save_in_vault", save_in_vault)
                .finish(),
            Self::Answers(v) => f
                .debug_tuple("Answers")
                .field(&format_args!("[REDACTED; {}]", v.len()))
                .finish(),
            Self::FileExists {
                action,
                apply_to,
                new_name,
            } => f
                .debug_struct("FileExists")
                .field("action", action)
                .field("apply_to", apply_to)
                .field("new_name", new_name)
                .finish(),
            Self::Ack => f.write_str("Ack"),
            Self::Cancel => f.write_str("Cancel"),
        }
    }
}

/// Answer to a trust question (host key or certificate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustAnswer {
    /// Trust for this connection only.
    TrustOnce,
    /// Store as trusted (treated as `TrustOnce` when the prompt's `can_save` is false).
    AlwaysTrust,
    /// Do not connect.
    Reject,
}

/// T21's name for the host-key answer.
pub type HostKeyAnswer = TrustAnswer;

/// Scope of a file-exists answer (T42).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyTo {
    /// This file only.
    Once,
    /// Every file in the queue.
    AllInQueue,
    /// Every file in the queue going the same direction.
    AllForDirection,
}

/// Checks that `response` answers `kind` (Behaviour rule 6) and normalises it
/// (`AlwaysTrust` without `can_save` → `TrustOnce`).
pub(crate) fn validate(kind: &PromptKind, response: PromptResponse) -> Result<PromptResponse> {
    fn downgrade(answer: TrustAnswer, can_save: bool) -> TrustAnswer {
        if answer == TrustAnswer::AlwaysTrust && !can_save {
            TrustAnswer::TrustOnce
        } else {
            answer
        }
    }
    let ok = match (kind, response) {
        (_, PromptResponse::Cancel) => return Err(Error::Cancelled),
        (PromptKind::TrustHostKey(p), PromptResponse::HostKey(a)) => {
            PromptResponse::HostKey(downgrade(a, p.can_save))
        }
        (PromptKind::TrustCertificate(p), PromptResponse::Certificate(a)) => {
            PromptResponse::Certificate(downgrade(a, p.can_save))
        }
        (
            PromptKind::Password(_) | PromptKind::KeyPassphrase(_),
            r @ PromptResponse::Secret { .. },
        ) => r,
        (PromptKind::KeyboardInteractive(p), PromptResponse::Answers(a))
            if a.len() == p.prompts.len() =>
        {
            PromptResponse::Answers(a)
        }
        (
            PromptKind::FileExists(_),
            PromptResponse::FileExists {
                action,
                apply_to,
                new_name,
            },
        ) if action != ExistsAction::Ask
            && new_name.is_some() == (action == ExistsAction::Rename) =>
        {
            PromptResponse::FileExists {
                action,
                apply_to,
                new_name,
            }
        }
        (PromptKind::Message(_), PromptResponse::Ack) => PromptResponse::Ack,
        (kind, _) => {
            tracing::error!(
                prompt_kind = kind.name(),
                "prompt response does not match the prompt kind"
            );
            return Err(Error::Internal(format!(
                "prompt response does not match the {} prompt",
                kind.name()
            )));
        }
    };
    Ok(ok)
}
