//! The status bar (T57): one row at the bottom of the main screen with the connection
//! security, the vault and prompt indicators, the transfer type, speed limits, filters,
//! comparison and sync state, the queue summary, pending keys, transient messages and
//! key hints. [`fit_segments`] decides, purely, which form of which segment is drawn
//! at a given width; [`StatusBar`] keeps the transient message.

use std::time::Duration;

use courier_ftp_core::{
    backend::SessionSecurityInfo,
    model::{Protocol, ServerAddress},
    settings::enums::TransferTypeChoice,
};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};
use tokio::time::Instant;
use unicode_width::UnicodeWidthChar;

use crate::{
    action::Action,
    app::Mode,
    keymap::{chord::display_sequence, map::Keymap},
    ui::{
        symbols::Symbols,
        text::{sanitize, truncate_to_width, width},
        theme::Theme,
    },
};

#[cfg(test)]
mod snapshot_tests;
#[cfg(test)]
mod tests;

/// A style key of the theme (`status.secure`).
pub(crate) type StyleKey = &'static str;

/// Longest transient message, in characters.
pub(crate) const MAX_MESSAGE_CHARS: usize = 200;
/// An Info/Success message older than this is removed by the next key press.
pub(crate) const KEY_CLEARS_AFTER: Duration = Duration::from_secs(1);

/// Everything the bar shows, rebuilt by `App` before each draw (cheap: no I/O,
/// borrowed strings). `None` = the source does not exist yet → segment hidden.
#[derive(Debug, Default, Clone)]
pub(crate) struct StatusInfo<'a> {
    /// Security of the focused tab's browsing session.
    pub security: SecurityIndicator,
    /// Vault state (T60).
    pub vault: Option<VaultIndicator>,
    /// T69 `PromptQueue::badge(sym.unicode)`.
    pub prompts_badge: Option<String>,
    /// `file_types.default_type` (T05).
    pub transfer_type: Option<TransferTypeChoice>,
    /// Effective speed limits (T44).
    pub speed: Option<SpeedLimitIndicator>,
    /// Any side filtered (T47/T53).
    pub filters_active: bool,
    /// Synchronized browsing on (T66).
    pub sync_browsing: bool,
    /// Directory comparison on (T66).
    pub comparison: bool,
    /// Sync status (T90).
    pub sync: Option<SyncIndicator>,
    /// Queue summary (T40/T41).
    pub queue: Option<QueueSummary>,
    /// Keys of a pending sequence (T51 `pending_display()`), empty when none.
    pub pending_keys: &'a str,
    /// The transient message.
    pub message: Option<&'a TransientMessage>,
    /// Key hints from the keymap of the focused mode.
    pub hints: &'a [KeyHint],
}

/// What the security segment shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum SecurityIndicator {
    /// No session.
    #[default]
    NotConnected,
    /// A tab without remote session.
    Local,
    /// FTP without TLS (incl. `ExplicitIfAvailable` that fell back).
    Plain,
    /// FTPS.
    Tls {
        /// `"TLS 1.3"`.
        version: String,
    },
    /// SFTP.
    Ssh,
    /// Connecting.
    Connecting,
}

impl SecurityIndicator {
    /// The indicator of a session: driven by the negotiated state (`encrypted`,
    /// `summary`), never by the configured encryption mode.
    pub(crate) fn from_security_info(
        info: &SessionSecurityInfo,
        addr: Option<&ServerAddress>,
    ) -> Self {
        let summary = info.summary.trim();
        if summary.eq_ignore_ascii_case("local") {
            return Self::Local;
        }
        if !info.encrypted {
            return Self::Plain;
        }
        let ssh = addr.is_some_and(|a| a.protocol == Protocol::Sftp)
            || summary.eq_ignore_ascii_case("ssh")
            || info.host_key.is_some();
        if ssh {
            return Self::Ssh;
        }
        let version = if summary.is_empty() || summary.eq_ignore_ascii_case("plain") {
            "TLS".to_owned()
        } else {
            sanitize(summary).into_owned()
        };
        Self::Tls { version }
    }
}

/// Vault indicator; nothing is shown when the vault is unlocked.
#[cfg_attr(not(test), allow(dead_code, reason = "set by T60"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultIndicator {
    /// Locked.
    Locked,
    /// "Continue without vault" (T60).
    NoVault,
}

/// The speed-limit segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpeedLimitIndicator {
    /// `transfers.speed_limit_enabled`.
    pub enabled: bool,
    /// Download limit in KiB/s, 0 = unlimited.
    pub down_kib: u32,
    /// Upload limit in KiB/s, 0 = unlimited.
    pub up_kib: u32,
}

/// Sync status (T90).
#[cfg_attr(not(test), allow(dead_code, reason = "set by T90"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncIndicator {
    /// Up to date.
    Synced,
    /// Syncing now.
    Syncing,
    /// Offline with pending changes.
    Offline {
        /// Changes waiting.
        pending: u32,
    },
    /// The last sync failed.
    Error,
    /// The sync account needs a login.
    LoginNeeded,
}

/// Queue summary (T40/T41).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct QueueSummary {
    /// Files queued.
    pub files: u64,
    /// Bytes queued.
    pub bytes: u64,
    /// Download rate, bytes/s.
    pub down_bps: u64,
    /// Upload rate, bytes/s.
    pub up_bps: u64,
    /// Estimated time left.
    pub eta_secs: Option<u64>,
}

/// One key hint (`F5 copy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyHint {
    /// `F5`.
    pub keys: String,
    /// `copy`.
    pub label: String,
}

/// A transient message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransientMessage {
    /// Sanitised text, at most [`MAX_MESSAGE_CHARS`] characters.
    pub text: String,
    /// Severity.
    pub level: MessageLevel,
    /// When it expires.
    pub until: Instant,
}

impl TransientMessage {
    /// A message arriving at `now` (sanitised, cut to 200 characters).
    pub(crate) fn new(text: &str, level: MessageLevel, now: Instant) -> Self {
        let clean = sanitize(text);
        let text = if clean.chars().count() > MAX_MESSAGE_CHARS {
            clean.chars().take(MAX_MESSAGE_CHARS).collect()
        } else {
            clean.into_owned()
        };
        Self {
            text,
            level,
            until: now + level.duration(),
        }
    }

    /// When it arrived.
    pub(crate) fn arrived(&self) -> Instant {
        self.until
            .checked_sub(self.level.duration())
            .unwrap_or(self.until)
    }
}

/// Severity of a transient message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageLevel {
    /// Information (3 s).
    Info,
    /// Something worked (3 s).
    #[cfg_attr(not(test), allow(dead_code, reason = "sent by T56, T62"))]
    Success,
    /// Something to know (5 s).
    Warning,
    /// Something failed (8 s); prefixed `Error: `.
    Error,
}

impl MessageLevel {
    /// How long a message of this level stays.
    pub(crate) fn duration(self) -> Duration {
        match self {
            Self::Info | Self::Success => Duration::from_secs(3),
            Self::Warning => Duration::from_secs(5),
            Self::Error => Duration::from_secs(8),
        }
    }

    fn style(self) -> StyleKey {
        match self {
            Self::Info => "status.msg_info",
            Self::Success => "status.msg_ok",
            Self::Warning => "status.msg_warn",
            Self::Error => "status.msg_error",
        }
    }
}

/// A segment with its long and short form, after formatting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Segment {
    /// Which segment.
    pub kind: SegmentKind,
    /// Long form.
    pub long: String,
    /// Short form.
    pub short: String,
    /// Style key.
    pub style: StyleKey,
}

/// The segments, in drawing order (left group, then right group).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum SegmentKind {
    /// Connection security.
    Security,
    /// Vault locked / no vault.
    Vault,
    /// Pending prompts.
    Prompts,
    /// Transfer type.
    TransferType,
    /// Speed limits.
    SpeedLimit,
    /// Filters active.
    Filters,
    /// Synchronized browsing / comparison.
    SyncCompare,
    /// Sync status.
    SyncStatus,
    /// Queue summary.
    Queue,
    /// Pending key sequence.
    PendingKeys,
    /// Transient message.
    Message,
    /// Key hints.
    #[allow(dead_code, reason = "hints are kept apart from the segments")]
    Hints,
}

impl SegmentKind {
    /// Fitting priority: lower goes first (shortened, then dropped); ≥ 9 is never
    /// dropped.
    pub(crate) fn priority(self) -> u8 {
        match self {
            Self::Hints => 1,
            Self::TransferType => 2,
            Self::SyncStatus => 3,
            Self::SyncCompare => 4,
            Self::Filters => 5,
            Self::SpeedLimit => 6,
            Self::Queue => 7,
            Self::Security => 8,
            Self::Message => 9,
            Self::Vault | Self::Prompts | Self::PendingKeys => 10,
        }
    }

    /// In the right-aligned group.
    pub(crate) fn is_right(self) -> bool {
        matches!(self, Self::PendingKeys | Self::Message | Self::Hints)
    }
}

fn seg(kind: SegmentKind, long: String, short: String, style: StyleKey) -> Segment {
    Segment {
        kind,
        long,
        short,
        style,
    }
}

/// The security segment.
pub(crate) fn security_segment(ind: &SecurityIndicator, sym: &Symbols) -> Segment {
    use SecurityIndicator as S;
    let k = SegmentKind::Security;
    if sym.unicode {
        match ind {
            S::NotConnected => seg(
                k,
                format!("{} not connected", sym.dash),
                sym.dash.to_owned(),
                "status.dim",
            ),
            S::Local => seg(k, "local".into(), "local".into(), "status.dim"),
            S::Plain => seg(
                k,
                format!("{} plain FTP", sym.unlock),
                format!("{}FTP", sym.unlock),
                "status.insecure",
            ),
            S::Tls { version } => seg(
                k,
                format!("{} {version}", sym.lock),
                format!("{}TLS", sym.lock),
                "status.secure",
            ),
            S::Ssh => seg(
                k,
                format!("{} SSH", sym.lock),
                format!("{}SSH", sym.lock),
                "status.secure",
            ),
            S::Connecting => seg(
                k,
                format!("{} connecting", sym.connecting),
                sym.connecting.to_owned(),
                "status.dim",
            ),
        }
    } else {
        match ind {
            S::NotConnected => seg(k, "[not connected]".into(), "[-]".into(), "status.dim"),
            S::Local => seg(k, "local".into(), "local".into(), "status.dim"),
            S::Plain => seg(
                k,
                "[PLAIN FTP]".into(),
                sym.unlock.to_owned(),
                "status.insecure",
            ),
            S::Tls { version } => seg(
                k,
                format!("[{version}]"),
                sym.lock.to_owned(),
                "status.secure",
            ),
            S::Ssh => seg(k, "[SSH]".into(), "[SSH]".into(), "status.secure"),
            S::Connecting => seg(k, "[connecting]".into(), "[..]".into(), "status.dim"),
        }
    }
}

/// The vault segment.
pub(crate) fn vault_segment(v: VaultIndicator, sym: &Symbols) -> Segment {
    let k = SegmentKind::Vault;
    let (long, short) = match (v, sym.unicode) {
        (VaultIndicator::Locked, true) => (
            format!("{} vault locked", sym.vault_locked),
            sym.vault_locked.to_owned(),
        ),
        (VaultIndicator::Locked, false) => ("[vault locked]".to_owned(), sym.vault_locked.into()),
        (VaultIndicator::NoVault, true) => ("no vault".to_owned(), "novault".to_owned()),
        (VaultIndicator::NoVault, false) => ("[no vault]".to_owned(), "[NV]".to_owned()),
    };
    seg(k, long, short, "status.attention")
}

/// The prompts segment: the badge verbatim (sanitised); the short form joins the
/// glyph and the count (`⚠2`).
pub(crate) fn prompts_segment(badge: &str) -> Segment {
    let long = sanitize(badge).into_owned();
    let mut words = long.split_whitespace();
    let short = match (words.next(), words.next()) {
        (Some(g), Some(n)) if n.chars().all(|c| c.is_ascii_digit()) => format!("{g}{n}"),
        _ => long.clone(),
    };
    seg(SegmentKind::Prompts, long, short, "status.attention")
}

/// The transfer-type segment.
pub(crate) fn transfer_type_segment(t: TransferTypeChoice) -> Segment {
    let name = match t {
        TransferTypeChoice::Auto => "Auto",
        TransferTypeChoice::Binary => "Binary",
        TransferTypeChoice::Ascii => "ASCII",
    };
    seg(
        SegmentKind::TransferType,
        format!("Type: {name}"),
        name.to_owned(),
        "status.bar",
    )
}

/// The speed-limit segment; a limit of 0 is unlimited (`∞`).
pub(crate) fn speed_segment(s: SpeedLimitIndicator, sym: &Symbols) -> Segment {
    let k = SegmentKind::SpeedLimit;
    if !s.enabled {
        return if sym.unicode {
            seg(
                k,
                format!("{} off", sym.speed),
                format!("{}off", sym.speed),
                "status.bar",
            )
        } else {
            seg(k, "lim off".into(), "L:off".into(), "status.bar")
        };
    }
    let (long, short) = if sym.unicode {
        let full = |v: u32| {
            if v == 0 {
                "∞".to_owned()
            } else {
                format!("{v} KiB/s")
            }
        };
        let brief = |v: u32| {
            if v == 0 {
                "∞".to_owned()
            } else {
                format!("{v}K")
            }
        };
        (
            format!(
                "{} {}{} {}{}",
                sym.speed,
                sym.rate_down,
                full(s.down_kib),
                sym.rate_up,
                full(s.up_kib)
            ),
            format!(
                "{}{}{}{}{}",
                sym.speed,
                sym.rate_down,
                brief(s.down_kib),
                sym.rate_up,
                brief(s.up_kib)
            ),
        )
    } else {
        let brief = |v: u32| {
            if v == 0 {
                "inf".to_owned()
            } else {
                format!("{v}K")
            }
        };
        (
            format!("lim D:{} U:{}", brief(s.down_kib), brief(s.up_kib)),
            format!("L:{}/{}", brief(s.down_kib), brief(s.up_kib)),
        )
    };
    seg(k, long, short, "status.active")
}

/// The filters segment.
pub(crate) fn filters_segment(sym: &Symbols) -> Segment {
    let (long, short) = if sym.unicode {
        (format!("{} filters", sym.filter), sym.filter.to_owned())
    } else {
        ("[filters]".to_owned(), sym.filter.to_owned())
    };
    seg(SegmentKind::Filters, long, short, "status.active")
}

/// The synchronized browsing / comparison segment (at least one of them is on).
pub(crate) fn sync_compare_segment(sync: bool, compare: bool, sym: &Symbols) -> Segment {
    let mut long = Vec::new();
    let mut short = String::new();
    if sync {
        long.push(format!("{} sync", sym.sync));
        short.push_str(sym.sync);
    }
    if compare {
        long.push(format!("{} compare", sym.compare));
        short.push_str(sym.compare);
    }
    seg(
        SegmentKind::SyncCompare,
        long.join(" "),
        short,
        "status.active",
    )
}

/// The sync-status segment (T90).
pub(crate) fn sync_status_segment(s: SyncIndicator, sym: &Symbols) -> Segment {
    let g = sym.sync_status;
    let (long, short) = if sym.unicode {
        match s {
            SyncIndicator::Synced => (format!("{g} synced"), g.to_owned()),
            SyncIndicator::Syncing => (format!("{g} syncing"), g.to_owned()),
            SyncIndicator::Offline { pending } => {
                (format!("{g} offline ({pending})"), format!("{g}{pending}"))
            }
            SyncIndicator::Error => (format!("{g} error"), format!("{g}!")),
            SyncIndicator::LoginNeeded => (format!("{g} login needed"), format!("{g}!")),
        }
    } else {
        match s {
            SyncIndicator::Synced => ("sync ok".to_owned(), "S".to_owned()),
            SyncIndicator::Syncing => ("sync ...".to_owned(), "S".to_owned()),
            SyncIndicator::Offline { pending } => {
                (format!("sync offline ({pending})"), format!("S{pending}"))
            }
            SyncIndicator::Error => ("sync error".to_owned(), "S!".to_owned()),
            SyncIndicator::LoginNeeded => ("sync login needed".to_owned(), "S!".to_owned()),
        }
    };
    let style = if matches!(s, SyncIndicator::Error | SyncIndicator::LoginNeeded) {
        "status.attention"
    } else {
        "status.bar"
    };
    seg(SegmentKind::SyncStatus, long, short, style)
}

/// `30.2 MiB`, `1.21 GiB`, `512 B` (three significant digits).
pub(crate) fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    #[expect(clippy::cast_precision_loss, reason = "display only")]
    let mut v = n as f64 / 1024.0;
    let mut unit = 0;
    while v >= 1024.0 && unit + 1 < UNITS.len() {
        v /= 1024.0;
        unit += 1;
    }
    let u = UNITS[unit];
    if v < 9.995 {
        format!("{v:.2} {u}")
    } else if v < 99.95 {
        format!("{v:.1} {u}")
    } else {
        format!("{v:.0} {u}")
    }
}

/// `00:02:27`.
fn format_eta(secs: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// The queue segment: rates only when > 0, the ETA only when known.
pub(crate) fn queue_segment(q: QueueSummary, sym: &Symbols) -> Segment {
    let k = SegmentKind::Queue;
    if q.files == 0 {
        return seg(k, "Queue: empty".into(), "Q: 0".into(), "status.bar");
    }
    let s = if q.files == 1 { "" } else { "s" };
    let bytes = format_bytes(q.bytes);
    let mut long = format!("Queue: {} file{s}, {bytes}", q.files);
    if q.down_bps > 0 {
        long.push_str(&format!(
            ", {}{}/s",
            sym.rate_down,
            format_bytes(q.down_bps)
        ));
    }
    if q.up_bps > 0 {
        long.push_str(&format!(", {}{}/s", sym.rate_up, format_bytes(q.up_bps)));
    }
    if let Some(eta) = q.eta_secs {
        long.push_str(&format!(", ~{}", format_eta(eta)));
    }
    seg(k, long, format!("Q: {}, {bytes}", q.files), "status.bar")
}

/// `ctrl-x j` → `Ctrl-x j`, `f10` → `F10`.
pub(crate) fn pretty_keys(keys: &str) -> String {
    keys.split(' ')
        .map(|chord| {
            let c = chord
                .replace("ctrl-", "Ctrl-")
                .replace("alt-", "Alt-")
                .replace("shift-", "Shift-")
                .replace("super-", "Super-");
            match c.strip_prefix('f') {
                Some(n) if !n.is_empty() && n.chars().all(|d| d.is_ascii_digit()) => {
                    format!("F{n}")
                }
                _ => c,
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The pending-keys segment.
pub(crate) fn pending_segment(keys: &str) -> Segment {
    let k = pretty_keys(&sanitize(keys));
    seg(SegmentKind::PendingKeys, k.clone(), k, "status.hint_key")
}

/// The message segment (`Error: ` prefix for errors).
pub(crate) fn message_segment(m: &TransientMessage) -> Segment {
    let text = if m.level == MessageLevel::Error {
        format!("Error: {}", m.text)
    } else {
        m.text.clone()
    };
    seg(SegmentKind::Message, text.clone(), text, m.level.style())
}

/// Every visible segment for `info`, left group then right group (hints excluded).
pub(crate) fn build_segments(info: &StatusInfo, sym: &Symbols) -> Vec<Segment> {
    let mut v = vec![security_segment(&info.security, sym)];
    if let Some(x) = info.vault {
        v.push(vault_segment(x, sym));
    }
    if let Some(b) = &info.prompts_badge {
        v.push(prompts_segment(b));
    }
    if let Some(t) = info.transfer_type {
        v.push(transfer_type_segment(t));
    }
    if let Some(s) = info.speed {
        v.push(speed_segment(s, sym));
    }
    if info.filters_active {
        v.push(filters_segment(sym));
    }
    if info.sync_browsing || info.comparison {
        v.push(sync_compare_segment(
            info.sync_browsing,
            info.comparison,
            sym,
        ));
    }
    if let Some(s) = info.sync {
        v.push(sync_status_segment(s, sym));
    }
    if let Some(q) = info.queue {
        v.push(queue_segment(q, sym));
    }
    if !info.pending_keys.is_empty() {
        v.push(pending_segment(info.pending_keys));
    }
    if let Some(m) = info.message {
        v.push(message_segment(m));
    }
    v
}

/// The actions listed as hints, in order, with their labels.
const HINT_ACTIONS: [(Action, &str); 6] = [
    (Action::Help, "help"),
    (Action::Transfer, "copy"),
    (Action::Move, "move"),
    (Action::Mkdir, "mkdir"),
    (Action::Delete, "delete"),
    (Action::Quit, "quit"),
];

/// Key hints for `mode` from the effective keymap: one single-key binding per action
/// (function keys preferred), in [`HINT_ACTIONS`] order; unbound actions are skipped.
pub(crate) fn key_hints(keymap: &Keymap, mode: Mode) -> Vec<KeyHint> {
    let rows = keymap.bindings_for(mode.chain());
    HINT_ACTIONS
        .iter()
        .filter_map(|(action, label)| {
            let mut keys: Vec<_> = rows
                .iter()
                .filter(|r| r.keys.len() == 1 && r.action.same_variant(action))
                .map(|r| display_sequence(&r.keys))
                .collect();
            keys.sort_by_key(|k| !is_function_key(k));
            keys.first().map(|k| KeyHint {
                keys: pretty_keys(k),
                label: (*label).to_owned(),
            })
        })
        .collect()
}

/// The hint shown first in the compact layout (T50).
pub(crate) fn compact_hint() -> KeyHint {
    KeyHint {
        keys: "compact".to_owned(),
        label: "mode".to_owned(),
    }
}

fn is_function_key(k: &str) -> bool {
    k.strip_prefix('f')
        .is_some_and(|n| !n.is_empty() && n.chars().all(|d| d.is_ascii_digit()))
}

/// A segment as drawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Shown {
    /// Which segment.
    pub kind: SegmentKind,
    /// The text drawn.
    pub text: String,
    /// Style key.
    pub style: StyleKey,
    /// The short form was used.
    pub short: bool,
}

/// The result of [`fit_segments`]: what is drawn, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FittedBar {
    /// Left group.
    pub left: Vec<Shown>,
    /// Right group without hints (pending keys, message).
    pub right: Vec<Shown>,
    /// Hints kept.
    pub hints: Vec<KeyHint>,
    /// The bar width.
    pub width: u16,
}

/// Fitting state of one segment.
#[derive(Debug, Clone, Copy)]
struct Slot {
    short: bool,
    dropped: bool,
}

struct Fit<'a> {
    segs: &'a [Segment],
    slots: Vec<Slot>,
    hints: usize,
    all_hints: &'a [KeyHint],
    sep_w: usize,
}

impl Fit<'_> {
    fn text(&self, i: usize) -> &str {
        let s = &self.segs[i];
        if self.slots[i].short {
            &s.short
        } else {
            &s.long
        }
    }

    fn group_width(&self, right: bool) -> usize {
        let mut n: usize = 0;
        let mut w = 0;
        for (i, s) in self.segs.iter().enumerate() {
            if s.kind.is_right() != right || self.slots[i].dropped {
                continue;
            }
            w += width(self.text(i));
            n += 1;
        }
        if right && self.hints > 0 {
            w += hints_width(&self.all_hints[..self.hints]);
            n += 1;
        }
        w + n.saturating_sub(1) * self.sep_w
    }

    fn total(&self) -> usize {
        let l = self.group_width(false);
        let r = self.group_width(true);
        let gap = if l > 0 && r > 0 { 2 } else { 0 };
        2 + l + gap + r
    }
}

fn hints_text(h: &[KeyHint]) -> String {
    h.iter()
        .map(|h| format!("{} {}", h.keys, h.label))
        .collect::<Vec<_>>()
        .join("  ")
}

fn hints_width(h: &[KeyHint]) -> usize {
    width(&hints_text(h))
}

/// Pure layout: which form of which segment is drawn at `width`.
///
/// 1. Every segment long, all hints.
/// 2. Drop hints from the right while too wide.
/// 3. For each priority ascending (all of them), shorten its segments while too wide.
/// 4. For priorities 1–8 ascending, drop its segments while too wide.
/// 5. Re-expand short segments in descending priority while the bar fits.
///
/// Cutting the message and then the left group (step 6) happens when the line is
/// built ([`FittedBar::text`], [`FittedBar::line`]).
pub(crate) fn fit_segments(
    width: u16,
    segments: &[Segment],
    hints: &[KeyHint],
    sym: &Symbols,
) -> FittedBar {
    let w = usize::from(width);
    let has_message = segments.iter().any(|s| s.kind == SegmentKind::Message);
    let mut f = Fit {
        segs: segments,
        slots: vec![
            Slot {
                short: false,
                dropped: false
            };
            segments.len()
        ],
        hints: if has_message { 0 } else { hints.len() },
        all_hints: hints,
        sep_w: self::width(sym.sep),
    };
    while f.total() > w && f.hints > 0 {
        f.hints -= 1;
    }
    let mut prios: Vec<u8> = segments.iter().map(|s| s.kind.priority()).collect();
    prios.sort_unstable();
    prios.dedup();
    for &p in &prios {
        if f.total() <= w {
            break;
        }
        for (i, s) in segments.iter().enumerate() {
            if s.kind.priority() == p {
                f.slots[i].short = true;
            }
        }
    }
    for &p in prios.iter().filter(|p| **p <= 8) {
        if f.total() <= w {
            break;
        }
        for (i, s) in segments.iter().enumerate() {
            if s.kind.priority() == p {
                f.slots[i].dropped = true;
            }
        }
    }
    let mut order: Vec<usize> = (0..segments.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(segments[i].kind.priority()));
    for i in order {
        if f.slots[i].dropped || !f.slots[i].short {
            continue;
        }
        f.slots[i].short = false;
        if f.total() > w {
            f.slots[i].short = true;
        }
    }
    let shown = |right: bool| {
        segments
            .iter()
            .enumerate()
            .filter(|(i, s)| s.kind.is_right() == right && !f.slots[*i].dropped)
            .map(|(i, s)| Shown {
                kind: s.kind,
                text: f.text(i).to_owned(),
                style: s.style,
                short: f.slots[i].short,
            })
            .collect::<Vec<_>>()
    };
    FittedBar {
        left: shown(false),
        right: shown(true),
        hints: hints[..f.hints].to_vec(),
        width,
    }
}

/// A piece of the drawn line.
type Piece = (String, StyleKey);

impl FittedBar {
    /// The pieces of the line: margins, groups, separators, gap and padding, with the
    /// message and then the left group cut so the line fits (step 6). Never wider
    /// than the bar.
    fn pieces(&self, sym: &Symbols) -> Vec<Piece> {
        let total = usize::from(self.width);
        let sep_w = width(sym.sep);
        let join_w = |items: &[Piece]| -> usize {
            items.iter().map(|(t, _)| width(t)).sum::<usize>()
                + items.len().saturating_sub(1) * sep_w
        };
        let flat_w = |items: &[Piece]| -> usize { items.iter().map(|(t, _)| width(t)).sum() };
        let mut left: Vec<Piece> = Vec::new();
        push_joined(
            &mut left,
            &self
                .left
                .iter()
                .map(|s| (s.text.clone(), s.style))
                .collect::<Vec<_>>(),
            sym.sep,
        );
        let mut right: Vec<Piece> = self
            .right
            .iter()
            .map(|s| (s.text.clone(), s.style))
            .collect();
        let hint_idx = (!self.hints.is_empty()).then(|| {
            right.push((hints_text(&self.hints), "status.hint"));
            right.len() - 1
        });
        let needed = |l: usize, r: usize| 2 + l + r + if l > 0 && r > 0 { 2 } else { 0 };
        let (mut lw, mut rw) = (flat_w(&left), join_w(&right));
        // Step 6a: cut the message.
        if needed(lw, rw) > total
            && let Some(m) = self
                .right
                .iter()
                .position(|s| s.kind == SegmentKind::Message)
        {
            let other = needed(lw, rw) - width(&right[m].0);
            let room = total.saturating_sub(other);
            right[m].0 = truncate_to_width(&right[m].0, room, sym.ellipsis).into_owned();
            rw = join_w(&right);
        }
        // Step 6b: cut the left group at its right edge.
        if needed(lw, rw) > total && lw > 0 {
            let room = total.saturating_sub(needed(0, rw) + if rw > 0 { 2 } else { 0 });
            left = clip_pieces(left, room);
            lw = flat_w(&left);
        }
        let mut out: Vec<Piece> = vec![(" ".into(), "status.bar")];
        out.extend(left);
        let pad = total.saturating_sub(needed(lw, rw));
        if rw > 0 {
            let gap = if lw > 0 { 2 } else { 0 } + pad;
            out.push((" ".repeat(gap), "status.bar"));
            for (i, p) in right.iter().enumerate() {
                if i > 0 {
                    out.push((sym.sep.to_owned(), "status.bar"));
                }
                if Some(i) == hint_idx {
                    for (j, h) in self.hints.iter().enumerate() {
                        if j > 0 {
                            out.push(("  ".into(), "status.bar"));
                        }
                        out.push((h.keys.clone(), "status.hint_key"));
                        out.push((format!(" {}", h.label), "status.hint"));
                    }
                } else {
                    out.push(p.clone());
                }
            }
            out.push((" ".into(), "status.bar"));
        } else {
            out.push((" ".repeat(1 + pad), "status.bar"));
        }
        clip_pieces(out, total)
    }

    /// The line as plain text.
    #[cfg_attr(not(test), allow(dead_code, reason = "used by tests"))]
    pub(crate) fn text(&self, sym: &Symbols) -> String {
        self.pieces(sym).into_iter().map(|(t, _)| t).collect()
    }

    /// The styled line.
    pub(crate) fn line(&self, sym: &Symbols, theme: &Theme) -> Line<'static> {
        Line::from(
            self.pieces(sym)
                .into_iter()
                .map(|(t, k)| Span::styled(t, theme.style(k)))
                .collect::<Vec<_>>(),
        )
    }
}

fn push_joined(out: &mut Vec<Piece>, items: &[Piece], sep: &str) {
    for (i, p) in items.iter().enumerate() {
        if i > 0 {
            out.push((sep.to_owned(), "status.bar"));
        }
        out.push(p.clone());
    }
}

/// Cuts `pieces` to `max` display columns, never splitting a wide character.
fn clip_pieces(pieces: Vec<Piece>, max: usize) -> Vec<Piece> {
    let mut used = 0;
    let mut out = Vec::new();
    for (t, s) in pieces {
        let w = width(&t);
        if used + w <= max {
            used += w;
            out.push((t, s));
            continue;
        }
        let mut part = String::new();
        for c in t.chars() {
            let cw = c.width().unwrap_or(0);
            if used + cw > max {
                break;
            }
            used += cw;
            part.push(c);
        }
        if !part.is_empty() {
            out.push((part, s));
        }
        break;
    }
    out
}

/// Draws the bar for `info` into `area` (one row).
pub(crate) fn render(
    frame: &mut Frame,
    area: Rect,
    info: &StatusInfo,
    sym: &Symbols,
    theme: &Theme,
) {
    let segments = build_segments(info, sym);
    let fitted = fit_segments(area.width, &segments, info.hints, sym);
    frame.render_widget(
        Paragraph::new(fitted.line(sym, theme)).style(theme.style("status.bar")),
        area,
    );
}

/// The status bar's own state: the transient message.
#[derive(Debug, Default)]
pub(crate) struct StatusBar {
    message: Option<TransientMessage>,
}

impl StatusBar {
    /// Shows `text` (replaces the current message).
    pub(crate) fn show(&mut self, text: &str, level: MessageLevel, now: Instant) {
        self.message = Some(TransientMessage::new(text, level, now));
    }

    /// The current message.
    pub(crate) fn message(&self) -> Option<&TransientMessage> {
        self.message.as_ref()
    }

    /// `Action::StatusMessage` (Info), `Action::StatusNotice` and `Action::Tick`;
    /// returns whether the bar changed.
    pub(crate) fn update(&mut self, action: &Action, now: Instant) -> bool {
        match action {
            Action::StatusMessage(m) => {
                self.show(m, MessageLevel::Info, now);
                true
            }
            Action::StatusNotice(level, m) => {
                self.show(m, *level, now);
                true
            }
            Action::Tick => self.expire(now),
            _ => false,
        }
    }

    /// Removes an expired message; true if one was removed.
    pub(crate) fn expire(&mut self, now: Instant) -> bool {
        if self.message.as_ref().is_some_and(|m| now >= m.until) {
            self.message = None;
            return true;
        }
        false
    }

    /// A key was pressed: an Info/Success message older than 1 s goes away.
    pub(crate) fn on_key(&mut self, now: Instant) -> bool {
        let clear = self.message.as_ref().is_some_and(|m| {
            matches!(m.level, MessageLevel::Info | MessageLevel::Success)
                && now.saturating_duration_since(m.arrived()) >= KEY_CLEARS_AFTER
        });
        if clear {
            self.message = None;
        }
        clear
    }
}
