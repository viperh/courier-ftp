//! The status bar (T57): connection security, transfer type, speed limit,
//! filters, sync/compare, vault, queue summary, pending keys or a transient
//! message, and key hints. Segments that don't fit are dropped, least
//! important first.

use std::time::{Duration, Instant};

use courier_ftp_core::{
    backend::{SecurityInfo, SessionInfo},
    settings::{SymbolMode, TransferTypeChoice},
};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::theme::Theme;

/// How long a transient message stays.
pub(crate) const MESSAGE_TTL: Duration = Duration::from_secs(3);

/// Everything the status bar shows.
#[derive(Debug, Clone)]
pub(crate) struct StatusState {
    /// The current tab's session, `None` when disconnected.
    pub(crate) session: Option<SessionInfo>,
    pub(crate) transfer_type: TransferTypeChoice,
    pub(crate) speed_limit: bool,
    pub(crate) download_limit_kib: u64,
    pub(crate) upload_limit_kib: u64,
    pub(crate) filters_active: bool,
    pub(crate) sync_browsing: bool,
    pub(crate) compare: bool,
    pub(crate) vault_locked: bool,
    pub(crate) queue_files: u64,
    pub(crate) queue_bytes: u64,
    pub(crate) queue_speed_bps: u64,
    pub(crate) pending_keys: String,
    message: Option<(String, Instant)>,
    /// Key hints, e.g. `("F5", "copy")`, from the keymap.
    pub(crate) hints: Vec<(String, String)>,
    pub(crate) unicode: bool,
}

impl StatusState {
    pub(crate) fn new(unicode: bool) -> Self {
        Self {
            session: None,
            transfer_type: TransferTypeChoice::Auto,
            speed_limit: false,
            download_limit_kib: 0,
            upload_limit_kib: 0,
            filters_active: false,
            sync_browsing: false,
            compare: false,
            vault_locked: false,
            queue_files: 0,
            queue_bytes: 0,
            queue_speed_bps: 0,
            pending_keys: String::new(),
            message: None,
            hints: Vec::new(),
            unicode,
        }
    }

    /// Show `text` for [`MESSAGE_TTL`].
    pub(crate) fn flash(&mut self, text: impl Into<String>, now: Instant) {
        self.message = Some((text.into(), now));
    }

    /// The transient message, if it hasn't expired.
    pub(crate) fn message(&self, now: Instant) -> Option<&str> {
        self.message
            .as_ref()
            .filter(|(_, at)| now.saturating_duration_since(*at) < MESSAGE_TTL)
            .map(|(m, _)| m.as_str())
    }

    pub(crate) fn cycle_transfer_type(&mut self) {
        self.transfer_type = match self.transfer_type {
            TransferTypeChoice::Auto => TransferTypeChoice::Ascii,
            TransferTypeChoice::Ascii => TransferTypeChoice::Binary,
            TransferTypeChoice::Binary => TransferTypeChoice::Auto,
        };
    }
}

/// Whether to draw Unicode symbols for `mode`, looking at the locale for
/// `Auto`.
pub(crate) fn unicode_enabled(mode: SymbolMode) -> bool {
    match mode {
        SymbolMode::Unicode => true,
        SymbolMode::Ascii => false,
        SymbolMode::Auto => {
            if cfg!(windows) {
                return true; // Windows Terminal and conhost handle these
            }
            ["LC_ALL", "LC_CTYPE", "LANG"]
                .iter()
                .find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()))
                .is_some_and(|v| {
                    let v = v.to_ascii_lowercase();
                    v.contains("utf-8") || v.contains("utf8")
                })
        }
    }
}

/// `1.2 MiB`, `340 KiB`, `12 B`.
pub(crate) fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

struct Segment {
    spans: Vec<Span<'static>>,
    /// Lower is more important (kept longer).
    priority: u8,
}

impl Segment {
    fn width(&self) -> usize {
        self.spans.iter().map(|s| s.width()).sum::<usize>() + 2
    }
}

fn security_segment(s: &StatusState, theme: &Theme) -> Segment {
    let (text, style) = match s.session.as_ref().map(|i| &i.security) {
        None => ("—".to_owned(), theme.dim),
        Some(SecurityInfo::Plain) => (
            if s.unicode { "🔓 plain" } else { "[PLAIN]" }.to_owned(),
            theme.error,
        ),
        Some(SecurityInfo::Tls { version, .. }) => (
            if s.unicode {
                format!("🔒 {version}")
            } else {
                format!("[{version}]")
            },
            Style::new(),
        ),
        Some(SecurityInfo::Ssh { .. }) => (
            if s.unicode { "🔒 SSH" } else { "[SSH]" }.to_owned(),
            Style::new(),
        ),
    };
    let text = if s.unicode {
        text
    } else {
        text.replace('—', "-")
    };
    Segment {
        spans: vec![Span::styled(text, style)],
        priority: 1,
    }
}

fn kib(n: u64) -> String {
    if n >= 1024 {
        format!("{:.1}M", n as f64 / 1024.0)
    } else {
        format!("{n}K")
    }
}

/// The status bar's line for `width` columns at time `now`.
pub(crate) fn status_line(
    s: &StatusState,
    width: u16,
    now: Instant,
    theme: &Theme,
) -> Line<'static> {
    let u = s.unicode;
    let mut segments = vec![security_segment(s, theme)];
    let tt = match s.transfer_type {
        TransferTypeChoice::Auto => "Auto",
        TransferTypeChoice::Ascii => "ASCII",
        TransferTypeChoice::Binary => "Binary",
    };
    segments.push(Segment {
        spans: vec![Span::raw(tt)],
        priority: 6,
    });
    let limit = if !s.speed_limit {
        "off".to_owned()
    } else {
        let down = if s.download_limit_kib > 0 {
            kib(s.download_limit_kib)
        } else {
            "∞".to_owned()
        };
        let up = if s.upload_limit_kib > 0 {
            kib(s.upload_limit_kib)
        } else {
            "∞".to_owned()
        };
        if u {
            format!("↓{down} ↑{up}")
        } else {
            format!(
                "down {} up {}",
                down.replace('∞', "-"),
                up.replace('∞', "-")
            )
        }
    };
    segments.push(Segment {
        spans: vec![Span::raw(if u {
            format!("⇅ limit {limit}")
        } else {
            format!("limit {limit}")
        })],
        priority: 4,
    });
    if s.filters_active {
        segments.push(Segment {
            spans: vec![Span::styled(
                if u { "⚑ filters" } else { "[filters]" },
                theme.key_hint,
            )],
            priority: 3,
        });
    }
    if s.sync_browsing {
        segments.push(Segment {
            spans: vec![Span::raw(if u { "⇄ sync" } else { "[sync]" })],
            priority: 5,
        });
    }
    if s.compare {
        segments.push(Segment {
            spans: vec![Span::raw(if u { "≠ compare" } else { "[compare]" })],
            priority: 5,
        });
    }
    if s.vault_locked {
        segments.push(Segment {
            spans: vec![Span::styled(
                if u { "🔐 locked" } else { "[locked]" },
                theme.key_hint,
            )],
            priority: 2,
        });
    }
    let queue = if s.queue_files == 0 {
        "Queue: empty".to_owned()
    } else {
        let mut q = format!(
            "Queue: {} file{}, {}",
            s.queue_files,
            if s.queue_files == 1 { "" } else { "s" },
            human_bytes(s.queue_bytes)
        );
        if s.queue_speed_bps > 0 {
            q.push_str(&format!(
                ", {}{}/s",
                if u { "↓" } else { "" },
                human_bytes(s.queue_speed_bps)
            ));
        }
        q
    };
    segments.push(Segment {
        spans: vec![Span::raw(queue)],
        priority: 2,
    });
    let mut hint_spans = Vec::new();
    for (key, what) in &s.hints {
        hint_spans.push(Span::styled(key.clone(), theme.key_hint));
        hint_spans.push(Span::raw(format!(" {what}  ")));
    }
    if !hint_spans.is_empty() {
        segments.push(Segment {
            spans: hint_spans,
            priority: 7,
        });
    }

    // The right end: pending keys, else a fresh message.
    let right = if !s.pending_keys.is_empty() {
        Some(Span::styled(
            format!(" {} ", s.pending_keys),
            theme.key_hint,
        ))
    } else {
        s.message(now)
            .map(|m| Span::styled(format!(" {m} "), theme.title))
    };
    let right_width = right.as_ref().map_or(0, |r| r.width());

    // Drop the least important segments until the rest fits.
    let budget = usize::from(width).saturating_sub(right_width + 1);
    let mut keep: Vec<bool> = vec![true; segments.len()];
    let total = |keep: &[bool]| -> usize {
        segments
            .iter()
            .zip(keep)
            .filter(|(_, k)| **k)
            .map(|(s, _)| s.width())
            .sum()
    };
    let mut order: Vec<usize> = (0..segments.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(segments[i].priority));
    for i in order {
        if total(&keep) <= budget {
            break;
        }
        keep[i] = false;
    }

    let sep = if u { " │ " } else { " | " };
    let mut spans = vec![Span::raw(" ")];
    let mut first = true;
    for (seg, k) in segments.into_iter().zip(&keep) {
        if !*k {
            continue;
        }
        if !first {
            spans.push(Span::styled(sep, theme.dim));
        }
        first = false;
        spans.extend(seg.spans);
    }
    if let Some(right) = right {
        let used: usize = spans.iter().map(|s| s.width()).sum();
        let pad = usize::from(width).saturating_sub(used + right_width);
        spans.push(Span::raw(" ".repeat(pad)));
        spans.push(right);
    }
    Line::from(spans)
}

pub(crate) fn draw(frame: &mut Frame, area: Rect, s: &StatusState, theme: &Theme) {
    frame.render_widget(
        Paragraph::new(status_line(s, area.width, Instant::now(), theme)).style(theme.status_bar),
        area,
    );
}

/// The lines of the server info dialog (`<Ctrl-x><i>`).
pub(crate) fn server_info_text(info: Option<&SessionInfo>) -> String {
    let Some(info) = info else {
        return "Not connected.".to_owned();
    };
    let mut out = vec![
        format!("Server:     {}", info.address),
        format!("Protocol:   {}", info.address.protocol),
        format!(
            "Software:   {}",
            info.server_software.as_deref().unwrap_or("unknown")
        ),
    ];
    match &info.security {
        SecurityInfo::Plain => {
            out.push("Security:   none — FTP sends passwords and data in clear text".to_owned());
        }
        SecurityInfo::Tls {
            version,
            cipher,
            certificate,
        } => {
            out.push(format!("Security:   {version}, {cipher}"));
            if let Some(c) = certificate {
                out.push(format!("Subject:    {}", c.subject));
                out.push(format!("Issuer:     {}", c.issuer));
                out.push(format!("Valid:      {}", c.validity));
                out.push(format!("SHA-256:    {}", c.fingerprint_sha256));
            }
        }
        SecurityInfo::Ssh {
            kex,
            cipher,
            mac,
            host_key,
        } => {
            out.push("Security:   SSH".to_owned());
            out.push(format!("Key exch.:  {kex}"));
            out.push(format!("Cipher:     {cipher}"));
            if !mac.is_empty() {
                out.push(format!("MAC:        {mac}"));
            }
            out.push(format!("Host key:   {host_key}"));
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use courier_ftp_core::{
        events::CertificateDetails,
        model::{Protocol, ServerAddress},
    };
    use pretty_assertions::assert_eq;

    use super::*;

    fn line_text(line: &Line) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    fn busy(unicode: bool) -> StatusState {
        let mut s = StatusState::new(unicode);
        s.session = Some(SessionInfo {
            address: ServerAddress::new(Protocol::FtpsExplicit, "example.com"),
            server_software: Some("vsFTPd 3.0.5".into()),
            security: SecurityInfo::Tls {
                version: "TLS 1.3".into(),
                cipher: "TLS13_AES_256_GCM_SHA384".into(),
                certificate: None,
            },
        });
        s.speed_limit = true;
        s.download_limit_kib = 500;
        s.upload_limit_kib = 100;
        s.filters_active = true;
        s.sync_browsing = true;
        s.queue_files = 2;
        s.queue_bytes = 8 * 1024;
        s.queue_speed_bps = 1_258_291;
        s.hints = vec![
            ("F1".into(), "help".into()),
            ("F5".into(), "copy".into()),
            ("F8".into(), "delete".into()),
        ];
        s
    }

    #[test]
    fn snapshots_at_three_widths() {
        let theme = Theme::new(None, true);
        let now = Instant::now();
        for width in [80u16, 120, 200] {
            for unicode in [true, false] {
                let text = line_text(&status_line(&busy(unicode), width, now, &theme));
                insta::assert_snapshot!(
                    format!(
                        "status_{width}_{}",
                        if unicode { "unicode" } else { "ascii" }
                    ),
                    text
                );
                assert!(
                    Line::raw(text.clone()).width() <= usize::from(width),
                    "{width}: {text}"
                );
            }
        }
    }

    #[test]
    fn narrow_bars_keep_the_important_segments() {
        let theme = Theme::new(None, true);
        let text = line_text(&status_line(&busy(false), 40, Instant::now(), &theme));
        assert!(text.contains("[TLS 1.3]"), "{text}");
        assert!(!text.contains("F5 copy"), "hints go first: {text}");
    }

    #[test]
    fn security_indicator() {
        let theme = Theme::new(None, true);
        let mut s = StatusState::new(false);
        let t = |s: &StatusState| line_text(&status_line(s, 120, Instant::now(), &theme));
        assert!(t(&s).starts_with(" -"), "{}", t(&s));
        s.session = Some(SessionInfo {
            address: ServerAddress::new(Protocol::Ftp, "h"),
            server_software: None,
            security: SecurityInfo::Plain,
        });
        assert!(t(&s).contains("[PLAIN]"));
        s.session.as_mut().unwrap().security = SecurityInfo::Ssh {
            kex: "curve25519-sha256".into(),
            cipher: "chacha20-poly1305@openssh.com".into(),
            mac: String::new(),
            host_key: "ssh-ed25519 SHA256:abc".into(),
        };
        assert!(t(&s).contains("[SSH]"));
    }

    #[test]
    fn pending_keys_and_messages_sit_at_the_right() {
        let theme = Theme::new(None, true);
        let mut s = StatusState::new(false);
        let t0 = Instant::now();
        s.flash("Copied URL to clipboard", t0);
        let text = line_text(&status_line(&s, 80, t0, &theme));
        assert!(
            text.trim_end().ends_with("Copied URL to clipboard"),
            "{text}"
        );
        let later = t0 + MESSAGE_TTL + Duration::from_millis(1);
        assert!(!line_text(&status_line(&s, 80, later, &theme)).contains("Copied"));
        s.pending_keys = "g".into();
        assert!(
            line_text(&status_line(&s, 80, t0, &theme))
                .trim_end()
                .ends_with(" g")
        );
    }

    #[test]
    fn transfer_type_cycles() {
        let mut s = StatusState::new(true);
        s.cycle_transfer_type();
        assert_eq!(s.transfer_type, TransferTypeChoice::Ascii);
        s.cycle_transfer_type();
        s.cycle_transfer_type();
        assert_eq!(s.transfer_type, TransferTypeChoice::Auto);
    }

    #[test]
    fn server_info_for_each_protocol() {
        assert_eq!(server_info_text(None), "Not connected.");
        let ftp = SessionInfo {
            address: ServerAddress::new(Protocol::Ftp, "ftp.example.com"),
            server_software: Some("ProFTPD".into()),
            security: SecurityInfo::Plain,
        };
        let t = server_info_text(Some(&ftp));
        assert!(
            t.contains("ftp://ftp.example.com:21")
                && t.contains("clear text")
                && t.contains("ProFTPD"),
            "{t}"
        );

        let ftps = SessionInfo {
            address: ServerAddress::new(Protocol::FtpsImplicit, "secure.example.com"),
            server_software: None,
            security: SecurityInfo::Tls {
                version: "TLS 1.2".into(),
                cipher: "ECDHE-RSA-AES128-GCM-SHA256".into(),
                certificate: Some(CertificateDetails {
                    host: "secure.example.com".into(),
                    subject: "CN=secure.example.com".into(),
                    issuer: "CN=Example CA".into(),
                    validity: "2026-01-01 to 2027-01-01".into(),
                    fingerprint_sha256: "SHA256:xyz".into(),
                    problem: String::new(),
                }),
            },
        };
        let t = server_info_text(Some(&ftps));
        assert!(
            t.contains("FTPS (implicit)")
                && t.contains("TLS 1.2")
                && t.contains("CN=Example CA")
                && t.contains("unknown"),
            "{t}"
        );

        let sftp = SessionInfo {
            address: ServerAddress::new(Protocol::Sftp, "ssh.example.com"),
            server_software: Some("SSH-2.0-OpenSSH_9.8".into()),
            security: SecurityInfo::Ssh {
                kex: "curve25519-sha256".into(),
                cipher: "aes256-gcm@openssh.com".into(),
                mac: String::new(),
                host_key: "ssh-ed25519 SHA256:abc".into(),
            },
        };
        let t = server_info_text(Some(&sftp));
        assert!(
            t.contains("SFTP")
                && t.contains("curve25519")
                && t.contains("ssh-ed25519")
                && !t.contains("MAC:"),
            "{t}"
        );
    }

    #[test]
    fn byte_formatting() {
        assert_eq!(human_bytes(12), "12 B");
        assert_eq!(human_bytes(8 * 1024), "8.0 KiB");
        assert_eq!(human_bytes(1_258_291), "1.2 MiB");
    }
}
