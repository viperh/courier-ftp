//! Host-key trust (T21): the pure decision ([`decide`]) and [`TrustVerifier`], T20's
//! [`HostKeyVerifier`] over a [`HostKeyStore`], the process-wide [`SessionTrust`] and
//! the read-only OpenSSH files ([`OpenSshKnownHosts`]).
//!
//! Decision table (first matching row wins; "same key" = same key type per
//! [`same_key_type`] and identical blob, "same type" = same key type, other blob):
//!
//! | # | Condition | Decision |
//! |---|---|---|
//! | 1 | an OpenSSH `@revoked` entry for host:port has the presented blob | reject, no prompt |
//! | 2 | the store has the same key | accept (store) |
//! | 3 | the key was accepted earlier in this process | accept (session) |
//! | 4 | the store has same-type entries with other blobs | ask: changed |
//! | 5 | an OpenSSH plain entry has the same key | accept (file) |
//! | 6 | OpenSSH plain entries of the same type with other blobs | ask: changed |
//! | 7 | otherwise | ask: unknown |
//!
//! Prompts for the same host, port and fingerprint are shared: parallel transfer
//! connections wait for the first one's answer instead of asking again.

use std::{
    collections::HashMap,
    fmt,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use async_trait::async_trait;
use courier_ftp_core::{
    Error,
    events::{
        HostKeyPrompt, OldKey, OldKeySource, PromptKind, PromptResponse, SessionLog, TrustAnswer,
    },
    trust::{HostKeyStore, KnownHost, KnownHostId, SessionTrust, normalize_host},
};
use time::OffsetDateTime;
use tokio::sync::watch;
use tracing::{debug, info};

use crate::{
    known_hosts::{
        OpenSshEntry, OpenSshKnownHosts, OpenSshMatches, fingerprint_sha256, key_blob, lookup,
        same_key_type,
    },
    ssh::{HostKeyVerdict, HostKeyVerifier, ServerKey, VerifyCtx},
};

/// The reason when the user rejects an unknown key.
pub const REJECTED_UNKNOWN: &str = "Host key rejected by the user";
/// The reason when the user rejects a changed key.
pub const REJECTED_CHANGED: &str = "The host key changed and was not accepted";
/// The reason when the connect is cancelled while the prompt is open.
pub const CANCELLED: &str = "Connection cancelled";

/// What [`decide`] looks at.
#[derive(Debug, Clone, Copy)]
pub struct DecisionInput<'a> {
    /// The presented key (T20).
    pub key: &'a ServerKey,
    /// `store.lookup(host, port)`.
    pub store: &'a [KnownHost],
    /// `SessionTrust::contains(…)`.
    pub session_trusted: bool,
    /// `known_hosts::lookup(openssh.entries(), host, port)`.
    pub openssh: &'a OpenSshMatches,
}

/// Why a key was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedBy {
    /// The trust store (vault).
    Store,
    /// Accepted earlier in this process.
    Session,
    /// An OpenSSH `known_hosts` file.
    OpenSshFile(PathBuf),
}

/// The outcome of [`decide`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Trusted without asking.
    Accept(AcceptedBy),
    /// Never trusted (revoked), with the user-facing reason.
    Reject(String),
    /// Unknown key: ask. `other_known_types`: key types trusted for this host.
    AskUnknown {
        /// Distinct key types in the store and the OpenSSH matches.
        other_known_types: Vec<String>,
    },
    /// A known host presents another key of the same type: ask with a warning.
    AskChanged {
        /// The keys known before.
        old: Vec<OldKey>,
    },
}

impl Decision {
    /// The kind, for `tracing` (no host data).
    fn kind(&self) -> &'static str {
        match self {
            Self::Accept(_) => "accept",
            Self::Reject(_) => "reject",
            Self::AskUnknown { .. } => "ask_unknown",
            Self::AskChanged { .. } => "ask_changed",
        }
    }
}

fn same_blob(base64: &str, blob: &[u8]) -> bool {
    key_blob(base64).is_some_and(|b| b == blob)
}

fn old_from_store(e: &KnownHost) -> OldKey {
    OldKey {
        fingerprint_sha256: e.fingerprint_sha256(),
        source: OldKeySource::Vault {
            id: e.id.0,
            added_at: e.added_at,
        },
    }
}

fn old_from_file(e: &OpenSshEntry) -> OldKey {
    OldKey {
        fingerprint_sha256: key_blob(&e.public_key)
            .map_or_else(|| "?".to_owned(), |b| fingerprint_sha256(&b)),
        source: OldKeySource::OpenSshFile {
            path: e.source.clone(),
            line: e.line,
        },
    }
}

/// The decision table (see the module docs). Pure.
pub fn decide(input: &DecisionInput<'_>) -> Decision {
    let key = input.key;
    let Some(blob) = key_blob(&key.blob_base64) else {
        return Decision::Reject("The server's host key could not be read".to_owned());
    };
    // 1. Revoked.
    if let Some(r) = input
        .openssh
        .revoked
        .iter()
        .find(|r| same_blob(&r.public_key, &blob))
    {
        return Decision::Reject(format!(
            "The host key {} is marked @revoked in {}",
            key.fingerprint_sha256,
            r.source.display()
        ));
    }
    let same_type = |t: &str| same_key_type(t, &key.key_type);
    // 2. Stored.
    if input
        .store
        .iter()
        .any(|e| same_type(&e.key_type) && same_blob(&e.public_key, &blob))
    {
        return Decision::Accept(AcceptedBy::Store);
    }
    // 3. Accepted earlier in this process.
    if input.session_trusted {
        return Decision::Accept(AcceptedBy::Session);
    }
    // 4. The store knows another key of this type.
    let old: Vec<OldKey> = input
        .store
        .iter()
        .filter(|e| same_type(&e.key_type))
        .map(old_from_store)
        .collect();
    if !old.is_empty() {
        return Decision::AskChanged { old };
    }
    // 5. An OpenSSH file has it.
    if let Some(e) = input
        .openssh
        .matching
        .iter()
        .find(|e| same_type(&e.key_type) && same_blob(&e.public_key, &blob))
    {
        return Decision::Accept(AcceptedBy::OpenSshFile(e.source.clone()));
    }
    // 6. An OpenSSH file has another key of this type.
    let old: Vec<OldKey> = input
        .openssh
        .matching
        .iter()
        .filter(|e| same_type(&e.key_type))
        .map(old_from_file)
        .collect();
    if !old.is_empty() {
        return Decision::AskChanged { old };
    }
    // 7. Unknown.
    let mut other_known_types: Vec<String> = Vec::new();
    for t in input
        .store
        .iter()
        .map(|e| &e.key_type)
        .chain(input.openssh.matching.iter().map(|e| &e.key_type))
    {
        if !other_known_types.contains(t) {
            other_known_types.push(t.clone());
        }
    }
    Decision::AskUnknown { other_known_types }
}

/// What the asker tells the connections waiting for the same prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Accept,
    Reject(String),
    /// The asker was cancelled: the next waiter asks.
    Retry,
}

type FlightKey = (String, u16, String);
type Flight = Arc<watch::Sender<Option<Outcome>>>;

/// Open prompts by (host, port, fingerprint).
#[derive(Debug, Default)]
struct InFlight {
    open: Mutex<HashMap<FlightKey, Flight>>,
}

impl InFlight {
    fn lock(&self) -> MutexGuard<'_, HashMap<FlightKey, Flight>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Become the asker, or wait for the open prompt.
    fn join(&self, key: FlightKey) -> Role<'_> {
        let mut open = self.lock();
        if let Some(flight) = open.get(&key) {
            return Role::Waiter(flight.subscribe());
        }
        let flight: Flight = Arc::new(watch::Sender::new(None));
        open.insert(key.clone(), Arc::clone(&flight));
        Role::Asker(AskGuard {
            flights: self,
            key,
            flight,
            done: false,
        })
    }
}

enum Role<'a> {
    Asker(AskGuard<'a>),
    Waiter(watch::Receiver<Option<Outcome>>),
}

/// Held by the asker; tells the waiters the outcome (or "retry" when dropped early, e.g.
/// when the connect is cancelled and the handshake drops the verify future).
struct AskGuard<'a> {
    flights: &'a InFlight,
    key: FlightKey,
    flight: Flight,
    done: bool,
}

impl AskGuard<'_> {
    fn release(&mut self, outcome: Outcome) {
        {
            let mut open = self.flights.lock();
            if open
                .get(&self.key)
                .is_some_and(|f| Arc::ptr_eq(f, &self.flight))
            {
                open.remove(&self.key);
            }
        }
        self.flight.send_replace(Some(outcome));
        self.done = true;
    }

    fn finish(mut self, outcome: Outcome) {
        self.release(outcome);
    }
}

impl Drop for AskGuard<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.release(Outcome::Retry);
        }
    }
}

/// The host being verified.
#[derive(Clone, Copy)]
struct Target<'a> {
    /// As the user entered it (shown in the prompt).
    host: &'a str,
    /// Normalised (lookups and storage).
    h: &'a str,
    port: u16,
    key: &'a ServerKey,
}

/// T20's [`HostKeyVerifier`] over a store, the session trust and the OpenSSH files.
pub struct TrustVerifier {
    store: Arc<dyn HostKeyStore>,
    session: Arc<SessionTrust>,
    openssh: Arc<OpenSshKnownHosts>,
    in_flight: InFlight,
}

impl fmt::Debug for TrustVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustVerifier")
            .field("store", &self.store)
            .field("openssh", &self.openssh)
            .finish_non_exhaustive()
    }
}

impl TrustVerifier {
    /// A verifier over `store`, `session` and `openssh`.
    pub fn new(
        store: Arc<dyn HostKeyStore>,
        session: Arc<SessionTrust>,
        openssh: Arc<OpenSshKnownHosts>,
    ) -> Self {
        Self {
            store,
            session,
            openssh,
            in_flight: InFlight::default(),
        }
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn HostKeyStore> {
        &self.store
    }

    /// The session trust.
    pub fn session_trust(&self) -> &Arc<SessionTrust> {
        &self.session
    }

    fn openssh_matches(&self, host: &str, port: u16, log: &SessionLog) -> OpenSshMatches {
        let entries = self.openssh.entries();
        for notice in self.openssh.take_notices() {
            log.status(notice);
        }
        lookup(&entries, host, port)
    }

    fn session_insert(&self, host: &str, port: u16, key: &ServerKey) {
        self.session
            .insert(host, port, &key.key_type, &key.blob_base64);
    }

    /// Ask the user (we are the asker) and act on the answer.
    async fn ask(
        &self,
        t: &Target<'_>,
        decision: &Decision,
        ctx: &VerifyCtx<'_>,
        log: &SessionLog,
    ) -> (HostKeyVerdict, Outcome) {
        let Target { host, h, port, key } = *t;
        let (changed, other_known_types) = match decision {
            Decision::AskChanged { old } => (Some(old.clone()), Vec::new()),
            Decision::AskUnknown { other_known_types } => (None, other_known_types.clone()),
            _ => (None, Vec::new()),
        };
        let rejected = if changed.is_some() {
            REJECTED_CHANGED
        } else {
            REJECTED_UNKNOWN
        };
        if changed.is_some() {
            log.error(format!(
                "WARNING: the host key of {host}:{port} has changed!"
            ));
        } else {
            log.status(format!(
                "The server's host key is unknown. Fingerprint: {}",
                key.fingerprint_sha256
            ));
        }
        let can_save = self.store.can_persist();
        let prompt = PromptKind::TrustHostKey(HostKeyPrompt {
            host: host.to_owned(),
            port,
            key_type: key.key_type.clone(),
            bits: key.bits,
            fingerprint_sha256: key.fingerprint_sha256.clone(),
            fingerprint_md5: key.fingerprint_md5.clone(),
            changed,
            other_known_types,
            can_save,
        });
        let answer = ctx
            .events
            .prompt_with_cancel(ctx.session, prompt, ctx.cancel)
            .await;
        let answer = match answer {
            Ok(PromptResponse::HostKey(a)) => a,
            Err(Error::Cancelled) if ctx.cancel.is_cancelled() => {
                log.error(CANCELLED);
                return (HostKeyVerdict::Reject(CANCELLED.to_owned()), Outcome::Retry);
            }
            // `Cancel`, a dropped reply sender or a mismatching answer.
            _ => TrustAnswer::Reject,
        };
        match answer {
            TrustAnswer::AlwaysTrust if can_save => {
                let entry = KnownHost {
                    id: KnownHostId::new_v7(),
                    host: h.to_owned(),
                    port,
                    key_type: key.key_type.clone(),
                    public_key: key.blob_base64.clone(),
                    added_at: OffsetDateTime::now_utc(),
                    comment: None,
                };
                let replaces: Vec<KnownHostId> = self
                    .store
                    .lookup(h, port)
                    .into_iter()
                    .filter(|e| same_key_type(&e.key_type, &key.key_type))
                    .map(|e| e.id)
                    .collect();
                if let Err(e) = self.store.add(entry, replaces).await {
                    log.error(format!("Could not save the host key: {e}"));
                }
                self.session_insert(h, port, key);
                (HostKeyVerdict::Accept, Outcome::Accept)
            }
            // `AlwaysTrust` while `can_save` is false (stale UI) is `TrustOnce`.
            TrustAnswer::TrustOnce | TrustAnswer::AlwaysTrust => {
                self.session_insert(h, port, key);
                (HostKeyVerdict::Accept, Outcome::Accept)
            }
            TrustAnswer::Reject => {
                log.error(rejected);
                (
                    HostKeyVerdict::Reject(rejected.to_owned()),
                    Outcome::Reject(rejected.to_owned()),
                )
            }
        }
    }
}

#[async_trait]
impl HostKeyVerifier for TrustVerifier {
    async fn verify(
        &self,
        host: &str,
        port: u16,
        key: &ServerKey,
        ctx: &VerifyCtx<'_>,
    ) -> HostKeyVerdict {
        let log = SessionLog {
            events: ctx.events.clone(),
            session: ctx.session,
        };
        let h = normalize_host(host);
        let stored = self.store.lookup(&h, port);
        let session_trusted = self
            .session
            .contains(&h, port, &key.key_type, &key.blob_base64);
        let openssh = self.openssh_matches(&h, port, &log);
        let decision = decide(&DecisionInput {
            key,
            store: &stored,
            session_trusted,
            openssh: &openssh,
        });
        info!(
            session = ctx.session.get(),
            decision = decision.kind(),
            "host key decision"
        );
        debug!(host = %h, port, key_type = %key.key_type, fingerprint = %key.fingerprint_sha256, "host key checked");
        match &decision {
            Decision::Accept(by) => {
                self.session_insert(&h, port, key);
                let source = match by {
                    AcceptedBy::Store => "vault".to_owned(),
                    AcceptedBy::Session => "session".to_owned(),
                    AcceptedBy::OpenSshFile(path) => path.display().to_string(),
                };
                log.debug(
                    3,
                    format!(
                        "Host key {} {} is trusted ({source})",
                        key.key_type, key.fingerprint_sha256
                    ),
                );
                return HostKeyVerdict::Accept;
            }
            Decision::Reject(reason) => {
                log.error(reason);
                return HostKeyVerdict::Reject(reason.clone());
            }
            Decision::AskUnknown { .. } | Decision::AskChanged { .. } => {}
        }
        let flight_key = (h.clone(), port, key.fingerprint_sha256.clone());
        loop {
            match self.in_flight.join(flight_key.clone()) {
                Role::Asker(guard) => {
                    // Another connection may have been accepted meanwhile.
                    if self
                        .session
                        .contains(&h, port, &key.key_type, &key.blob_base64)
                    {
                        guard.finish(Outcome::Accept);
                        return HostKeyVerdict::Accept;
                    }
                    let target = Target {
                        host,
                        h: &h,
                        port,
                        key,
                    };
                    let (verdict, outcome) = self.ask(&target, &decision, ctx, &log).await;
                    guard.finish(outcome);
                    return verdict;
                }
                Role::Waiter(mut rx) => {
                    let outcome = tokio::select! {
                        r = rx.wait_for(Option::is_some) => r.ok().and_then(|v| (*v).clone()),
                        () = ctx.cancel.cancelled() => None,
                    };
                    match outcome {
                        Some(Outcome::Accept) => return HostKeyVerdict::Accept,
                        Some(Outcome::Reject(reason)) => return HostKeyVerdict::Reject(reason),
                        Some(Outcome::Retry) | None => {
                            if ctx.cancel.is_cancelled() {
                                return HostKeyVerdict::Reject(CANCELLED.to_owned());
                            }
                        }
                    }
                }
            }
        }
    }

    fn known_key_types(&self, host: &str, port: u16) -> Vec<String> {
        let h = normalize_host(host);
        let entries = self.openssh.entries();
        let openssh = lookup(&entries, &h, port);
        let mut types: Vec<String> = Vec::new();
        for t in self
            .store
            .lookup(&h, port)
            .into_iter()
            .map(|e| e.key_type)
            .chain(openssh.matching.into_iter().map(|e| e.key_type))
        {
            if !types.contains(&t) {
                types.push(t);
            }
        }
        types
    }
}

#[cfg(test)]
mod tests;
