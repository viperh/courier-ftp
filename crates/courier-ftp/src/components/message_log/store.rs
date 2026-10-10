//! The message log store (T55): one bounded ring per tab plus the `All` ring, and the
//! routing of core log lines to them.
//!
//! This file depends only on `crate::tabs` and `crate::ui::text` so the benchmarks can
//! include it (`benches/message_log.rs`).

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use courier_ftp_core::{
    events::{LogKind, LogMessage, SessionId, SessionPurpose},
    model::{Protocol, ServerAddress},
};
use time::OffsetDateTime;
use tracing::debug;

use crate::{
    tabs::{TabId, TabRoute},
    ui::text::sanitize,
};

/// Maximum stored characters of one line (before the ` … [N more characters]` suffix).
pub(crate) const MAX_LINE_CHARS: usize = 4096;

/// Where a line came from (the `All` view's tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum LineOrigin {
    /// A tab's browsing session (`[n]`).
    Tab(TabId),
    /// A transfer, keep-alive or search session (`[T]`).
    Transfer,
    /// The application, or a session no tab knows (`[-]`).
    App,
}

/// One stored line. Text is sanitised and capped at insert time.
#[derive(Debug)]
pub(crate) struct LogLine {
    /// Global, monotonic.
    pub seq: u64,
    /// UTC; converted to the local offset for display.
    pub time: OffsetDateTime,
    /// The session that logged it.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by T71 (session log file)")
    )]
    pub session: SessionId,
    /// The `All` view's tag.
    pub origin: LineOrigin,
    /// The kind.
    pub kind: LogKind,
    /// Sanitised, at most [`MAX_LINE_CHARS`] characters plus the suffix.
    pub text: Box<str>,
}

impl LogLine {
    /// A `Status` line starting with `Warning: ` (T04 has no warning kind).
    pub(crate) fn is_warning(&self) -> bool {
        self.kind == LogKind::Status && self.text.starts_with("Warning: ")
    }
}

/// Which ring a view reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum LogScope {
    /// One tab's ring.
    Tab(TabId),
    /// Every line.
    All,
}

/// Server identity used for routing transfer-session messages: protocol, lower-cased
/// host, effective port, user — the same fields T46 uses for its cache key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ServerKey {
    /// FTP or SFTP.
    pub protocol: Protocol,
    /// Lower-cased host.
    pub host: String,
    /// Effective port.
    pub port: u16,
    /// User, if any.
    pub user: Option<String>,
}

impl From<&ServerAddress> for ServerKey {
    fn from(a: &ServerAddress) -> Self {
        Self {
            protocol: a.protocol,
            host: a.host.to_lowercase(),
            port: a.effective_port(),
            user: a.user.clone(),
        }
    }
}

/// Prepares a line's text: TABs become 4 spaces, then [`sanitize`], then the text is
/// cut to [`MAX_LINE_CHARS`] characters with ` … [N more characters]` appended.
pub(crate) fn prepare_text(raw: &str) -> Box<str> {
    let expanded;
    let raw = if raw.contains('\t') {
        expanded = raw.replace('\t', "    ");
        expanded.as_str()
    } else {
        raw
    };
    let clean = sanitize(raw);
    // Fast path: a short line cannot be over the limit.
    if clean.len() <= MAX_LINE_CHARS {
        return clean.into();
    }
    match clean.char_indices().nth(MAX_LINE_CHARS) {
        None => clean.into(),
        Some((cut, _)) => {
            let more = clean[cut..].chars().count();
            let mut s = String::with_capacity(cut + 32);
            s.push_str(&clean[..cut]);
            s.push_str(&format!(" … [{more} more characters]"));
            s.into_boxed_str()
        }
    }
}

static EMPTY: VecDeque<Arc<LogLine>> = VecDeque::new();

/// All rings plus routing. Owned by the message log pane (see the task's
/// implementation notes).
#[derive(Debug)]
pub(crate) struct LogStore {
    rings: HashMap<LogScope, VecDeque<Arc<LogLine>>>,
    /// `logging.pane_max_lines`, per ring.
    capacity: usize,
    /// From `CoreEvent::Connected`.
    session_server: HashMap<SessionId, ServerKey>,
    /// From `CoreEvent::SessionOpened`: which sessions are not browsing sessions.
    session_purpose: HashMap<SessionId, SessionPurpose>,
    /// Browsing session and server identity per tab.
    tab_routes: HashMap<TabId, TabRoute>,
    next_seq: u64,
    dropped: u64,
}

impl LogStore {
    /// An empty store keeping `capacity` lines per ring (at least 1).
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            rings: HashMap::new(),
            capacity: capacity.max(1),
            session_server: HashMap::new(),
            session_purpose: HashMap::new(),
            tab_routes: HashMap::new(),
            next_seq: 0,
            dropped: 0,
        }
    }

    /// Lines kept per ring.
    #[cfg_attr(not(test), expect(dead_code, reason = "used by T68 (settings)"))]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Changes the capacity; rings over it drop their oldest lines.
    pub(crate) fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity.max(1);
        let cap = self.capacity;
        for ring in self.rings.values_mut() {
            while ring.len() > cap {
                ring.pop_front();
                self.dropped += 1;
            }
        }
    }

    fn append(ring: &mut VecDeque<Arc<LogLine>>, line: &Arc<LogLine>, cap: usize) -> bool {
        let dropped = if ring.len() >= cap {
            ring.pop_front();
            true
        } else {
            false
        };
        ring.push_back(Arc::clone(line));
        dropped
    }

    /// Stores a core log line: in the `All` ring, in every tab ring whose route
    /// matches (browsing session, or the same server identity), else in
    /// `active_tab`'s ring. Returns the scopes that received it.
    pub(crate) fn push(&mut self, msg: LogMessage, active_tab: TabId) -> Vec<LogScope> {
        let server = self.session_server.get(&msg.session);
        let mut tabs: Vec<TabId> = self
            .tab_routes
            .iter()
            .filter(|(_, r)| {
                r.browsing == Some(msg.session) || (server.is_some() && r.server.as_ref() == server)
            })
            .map(|(t, _)| *t)
            .collect();
        tabs.sort_unstable();
        let browsing_tab = tabs
            .iter()
            .copied()
            .find(|t| self.tab_routes[t].browsing == Some(msg.session));
        let origin = match browsing_tab {
            Some(t) => LineOrigin::Tab(t),
            None if msg.session != SessionId::APP
                && (server.is_some()
                    || self
                        .session_purpose
                        .get(&msg.session)
                        .is_some_and(|p| *p != SessionPurpose::Browse)) =>
            {
                LineOrigin::Transfer
            }
            None => LineOrigin::App,
        };
        if tabs.is_empty() {
            tabs.push(active_tab);
        }
        let line = Arc::new(LogLine {
            seq: self.next_seq,
            time: msg.time,
            session: msg.session,
            origin,
            kind: msg.kind,
            text: prepare_text(&msg.text),
        });
        self.next_seq += 1;
        let cap = self.capacity;
        let mut scopes = Vec::with_capacity(tabs.len() + 1);
        scopes.push(LogScope::All);
        scopes.extend(tabs.into_iter().map(LogScope::Tab));
        for scope in &scopes {
            let ring = self.rings.entry(*scope).or_default();
            if Self::append(ring, &line, cap) {
                self.dropped += 1;
            }
        }
        scopes
    }

    /// A session is connected to `address` (routes its lines by server identity).
    pub(crate) fn on_connected(&mut self, session: SessionId, address: &ServerAddress) {
        self.session_server
            .insert(session, ServerKey::from(address));
    }

    /// A session's connection ended.
    pub(crate) fn on_disconnected(&mut self, session: SessionId) {
        self.session_server.remove(&session);
    }

    /// A session was created for `purpose` (transfer lines get the `[T]` tag).
    pub(crate) fn on_session_opened(&mut self, session: SessionId, purpose: SessionPurpose) {
        self.session_purpose.insert(session, purpose);
    }

    /// A session ended.
    pub(crate) fn on_session_closed(&mut self, session: SessionId) {
        self.session_purpose.remove(&session);
        self.session_server.remove(&session);
    }

    /// Sets how lines reach `tab`.
    #[cfg_attr(not(test), expect(dead_code, reason = "called by T53 and T61"))]
    pub(crate) fn set_tab_route(&mut self, tab: TabId, route: TabRoute) {
        self.tab_routes.insert(tab, route);
    }

    /// Drops `tab`'s ring and route (T61 calls it on tab close).
    #[cfg_attr(not(test), expect(dead_code, reason = "called by T61"))]
    pub(crate) fn remove_tab(&mut self, tab: TabId) {
        self.tab_routes.remove(&tab);
        self.rings.remove(&LogScope::Tab(tab));
        self.log_counters();
    }

    /// Empties the ring of `scope`.
    pub(crate) fn clear(&mut self, scope: LogScope) {
        if let Some(r) = self.rings.get_mut(&scope) {
            r.clear();
        }
        self.log_counters();
    }

    /// The lines of `scope`, oldest first (sorted by `seq`).
    pub(crate) fn lines(&self, scope: LogScope) -> &VecDeque<Arc<LogLine>> {
        self.rings.get(&scope).unwrap_or(&EMPTY)
    }

    /// Number of lines in `scope`.
    pub(crate) fn len(&self, scope: LogScope) -> usize {
        self.lines(scope).len()
    }

    fn log_counters(&self) {
        let lines: usize = self.rings.values().map(VecDeque::len).sum();
        debug!(lines, dropped = self.dropped, "log_store");
    }
}
