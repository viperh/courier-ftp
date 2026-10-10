//! The server information dialog (T57, `ctrl-x i`): protocol, server, software,
//! TLS session and certificate or SSH host key of the focused tab's session, built
//! only from `SessionSecurityInfo` and the `ServerAddress`.

use std::borrow::Cow;

use courier_ftp_core::{
    backend::SessionSecurityInfo,
    events::{CertificateDetails, DataProtection, TlsSessionInfo, TrustSource},
    model::{FtpEncryption, Protocol, ServerAddress},
};
use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};
use time::OffsetDateTime;
use unicode_width::UnicodeWidthChar;

use super::{
    DrawCx,
    dialog::{Dialog, DialogSize, DialogStep, widget_cx},
    widgets::{Button, ButtonRole, ButtonRow, Widget, WidgetOutcome},
};
use crate::{
    action::Action,
    keymap::chord::{KeyChord, Mods},
    ui::text::{sanitize, width},
};

#[cfg(test)]
pub(crate) mod tests;

/// Width of the label column (label + padding).
const LABEL_W: usize = 16;
/// Dialog width bounds: `clamp(W − 4, 40, 100)`.
const MIN_W: u16 = 40;
/// See [`MIN_W`].
const MAX_W: u16 = 100;
/// Shown when the tab has no session.
pub(crate) const NOT_CONNECTED: &str = "Not connected to any server.";

/// View model of the server information dialog (sanitised strings only).
#[derive(Debug, Clone, Default)]
pub(crate) struct ServerInfoView {
    /// `"Server information · Tab 1 · <site>"`.
    pub title: String,
    /// Label, value; an empty label and value is a blank line.
    pub rows: Vec<(String, String)>,
    /// TLS: certificate chain details exist (T69 renderer).
    pub has_details: bool,
}

fn clean(s: &str) -> String {
    sanitize(s).into_owned()
}

fn title(tab_label: &str) -> String {
    let t = clean(tab_label);
    if t.is_empty() {
        "Server information".to_owned()
    } else {
        format!("Server information · {t}")
    }
}

fn hex_colon(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// `TLSv1.3` → `TLS 1.3`.
fn tls_version(p: &str) -> String {
    p.strip_prefix("TLSv")
        .map_or_else(|| clean(p), |v| format!("TLS {}", clean(v)))
}

fn date(t: OffsetDateTime) -> String {
    format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day())
}

/// `host` matches `pattern` (one leading `*.` wildcard label allowed).
fn name_matches(pattern: &str, host: &str) -> bool {
    let (p, h) = (pattern.to_ascii_lowercase(), host.to_ascii_lowercase());
    match p.strip_prefix("*.") {
        Some(rest) => h
            .split_once('.')
            .is_some_and(|(first, tail)| !first.is_empty() && tail == rest),
        None => p == h,
    }
}

fn host_name_ok(leaf: &CertificateDetails, host: &str) -> bool {
    let sans: Vec<&str> = leaf
        .sans
        .iter()
        .filter_map(|s| s.strip_prefix("DNS:").or_else(|| s.strip_prefix("IP:")))
        .collect();
    if sans.is_empty() {
        leaf.subject_cn
            .as_deref()
            .is_some_and(|cn| name_matches(cn, host))
    } else {
        sans.iter().any(|p| name_matches(p, host))
    }
}

fn protocol_text(addr: &ServerAddress, tls: bool) -> String {
    match addr.protocol {
        Protocol::Sftp => "SFTP (SSH-2)".to_owned(),
        Protocol::Ftp if !tls => match addr.encryption {
            FtpEncryption::PlainOnly => "FTP (plain, not encrypted)".to_owned(),
            _ => "FTP (plain, not encrypted: the server offered no TLS)".to_owned(),
        },
        Protocol::Ftp => match addr.encryption {
            FtpEncryption::RequireImplicit => "FTP over TLS (implicit)".to_owned(),
            FtpEncryption::RequireExplicit => "FTP over TLS (explicit, required)".to_owned(),
            _ => "FTP over TLS (explicit, if available)".to_owned(),
        },
    }
}

impl ServerInfoView {
    /// The view for a session.
    pub(crate) fn from_session(
        info: &SessionSecurityInfo,
        addr: &ServerAddress,
        tab_label: &str,
    ) -> Self {
        Self::from_session_at(info, addr, tab_label, OffsetDateTime::now_utc())
    }

    /// As [`Self::from_session`], with the current time for "days left".
    pub(crate) fn from_session_at(
        info: &SessionSecurityInfo,
        addr: &ServerAddress,
        tab_label: &str,
        now: OffsetDateTime,
    ) -> Self {
        let mut rows: Vec<(String, String)> = Vec::new();
        let mut row = |l: &str, v: String| rows.push((l.to_owned(), v));
        let tls = info.tls.as_ref().filter(|_| info.encrypted);
        row("Protocol", protocol_text(addr, tls.is_some()));
        let mut server = format!("{}:{}", clean(&addr.host), addr.effective_port());
        if let Some(peer) = info.peer_addr {
            server.push_str(&format!(" ({})", peer.ip()));
        }
        row("Server", server);
        if let Some(sw) = &info.server_software {
            row("Software", clean(sw));
        }
        let details = |rows: &mut Vec<(String, String)>| {
            for (l, v) in &info.details {
                rows.push((clean(l), clean(v)));
            }
        };
        let blank = |rows: &mut Vec<(String, String)>| rows.push((String::new(), String::new()));
        if let Some(t) = tls {
            details(&mut rows);
            blank(&mut rows);
            tls_rows(&mut rows, t, now);
        } else if let Some(k) = &info.host_key {
            blank(&mut rows);
            rows.push((
                "Host key".into(),
                format!("{} {}", clean(&k.key_type), k.bits),
            ));
            rows.push(("Fingerprint".into(), clean(&k.fingerprint_sha256)));
            details(&mut rows);
        } else {
            details(&mut rows);
        }
        Self {
            title: title(tab_label),
            rows,
            has_details: tls.is_some_and(|t| !t.chain.is_empty()),
        }
    }

    /// The view when the tab has no session.
    #[allow(dead_code, reason = "used by tests and T61")]
    pub(crate) fn not_connected() -> Self {
        Self::not_connected_in("")
    }

    /// The not-connected view for the tab `tab_label`.
    pub(crate) fn not_connected_in(tab_label: &str) -> Self {
        Self {
            title: title(tab_label),
            rows: vec![(String::new(), NOT_CONNECTED.to_owned())],
            has_details: false,
        }
    }
}

fn tls_rows(rows: &mut Vec<(String, String)>, t: &TlsSessionInfo, now: OffsetDateTime) {
    let mut row = |l: &str, v: String| rows.push((l.to_owned(), v));
    row("TLS version", tls_version(&t.protocol));
    row("Cipher suite", clean(&t.cipher_suite));
    row(
        "Data channel",
        match t.data_protection {
            DataProtection::Private => "TLS (PROT P)".to_owned(),
            DataProtection::Clear => "NOT encrypted (PROT C)".to_owned(),
        },
    );
    let Some(leaf) = t.chain.first() else {
        return;
    };
    rows.push((String::new(), String::new()));
    let mut row = |l: &str, v: String| rows.push((l.to_owned(), v));
    row("Subject", clean(&leaf.subject));
    row("Issuer", clean(&leaf.issuer));
    let days = (leaf.not_after - now).whole_days();
    let left = if days >= 0 {
        format!("{days} days left")
    } else {
        "EXPIRED".to_owned()
    };
    row(
        "Valid",
        format!(
            "{} to {} ({left})",
            date(leaf.not_before),
            date(leaf.not_after)
        ),
    );
    row(
        "Host name",
        if host_name_ok(leaf, &t.server_name) {
            "matches".to_owned()
        } else {
            "DOES NOT match".to_owned()
        },
    );
    row("SHA-256", hex_colon(&leaf.sha256));
    row(
        "Trust",
        match t.trusted_by {
            TrustSource::Platform => "system trust roots",
            TrustSource::Stored => "stored as always trusted",
            TrustSource::Once => "trusted for this session",
        }
        .to_owned(),
    );
}

/// Wraps `s` at character boundaries to `max` columns (fingerprints have no spaces).
fn wrap_chars(s: &str, max: usize) -> Vec<String> {
    let max = max.max(1);
    let mut out = vec![String::new()];
    let mut used = 0;
    for c in s.chars() {
        let w = c.width().unwrap_or(0);
        if used + w > max && used > 0 {
            out.push(String::new());
            used = 0;
        }
        if let Some(l) = out.last_mut() {
            l.push(c);
        }
        used += w;
    }
    out
}

/// What the user chose in the dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerInfoChoice {
    /// Close.
    Close,
    /// Show the certificate chain (T69).
    Details,
}

/// The dialog.
#[derive(Debug)]
pub(crate) struct ServerInfoDialog {
    view: ServerInfoView,
    unicode: bool,
    buttons: ButtonRow,
    scroll: usize,
    page: usize,
}

impl ServerInfoDialog {
    /// A dialog showing `view`; `unicode` false draws the title in ASCII.
    pub(crate) fn new(view: ServerInfoView, unicode: bool) -> Self {
        let mut b = Vec::new();
        if view.has_details {
            b.push(Button::new("details", "Details", ButtonRole::Normal));
        }
        b.push(Button::new("close", "Close", ButtonRole::Default));
        let mut buttons = ButtonRow::new(b);
        buttons.set_focus(usize::from(view.has_details));
        Self {
            view,
            unicode,
            buttons,
            scroll: 0,
            page: 1,
        }
    }

    /// The view.
    #[cfg_attr(not(test), allow(dead_code, reason = "read by tests"))]
    pub(crate) fn view(&self) -> &ServerInfoView {
        &self.view
    }

    /// The rows as display lines for a content width of `w`.
    fn lines(&self, w: usize) -> Vec<(String, String)> {
        let vw = w.saturating_sub(LABEL_W).max(1);
        let mut out = Vec::new();
        for (l, v) in &self.view.rows {
            if l.is_empty() {
                out.push((String::new(), v.clone()));
                continue;
            }
            for (i, part) in wrap_chars(v, vw).into_iter().enumerate() {
                out.push((if i == 0 { l.clone() } else { String::new() }, part));
            }
        }
        out
    }

    fn press(&self) -> DialogStep<ServerInfoChoice> {
        match self.buttons.focused_id() {
            Some("details") => DialogStep::Close(Some(ServerInfoChoice::Details)),
            _ => DialogStep::Close(Some(ServerInfoChoice::Close)),
        }
    }
}

impl Dialog for ServerInfoDialog {
    type Output = ServerInfoChoice;

    fn kind(&self) -> &'static str {
        "server_info"
    }

    fn title(&self) -> Cow<'_, str> {
        if self.unicode {
            Cow::Borrowed(&self.view.title)
        } else {
            Cow::Owned(self.view.title.replace('·', "-"))
        }
    }

    fn size(&self, _screen: Rect) -> DialogSize {
        DialogSize::Fit {
            min_w: MIN_W,
            max_w: MAX_W,
        }
    }

    fn measure(&self, max_width: u16) -> (u16, u16) {
        let n = self.lines(usize::from(max_width)).len() + 2;
        (max_width, u16::try_from(n).unwrap_or(u16::MAX))
    }

    fn handle_key(&mut self, key: KeyChord) -> DialogStep<ServerInfoChoice> {
        if key.mods.contains(Mods::CTRL) || key.mods.contains(Mods::ALT) {
            return DialogStep::Ignored;
        }
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.scroll += 1;
                DialogStep::Continue
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.scroll = self.scroll.saturating_sub(1);
                DialogStep::Continue
            }
            KeyCode::PageDown => {
                self.scroll += self.page;
                DialogStep::Continue
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(self.page);
                DialogStep::Continue
            }
            _ => match self.buttons.handle_key(key) {
                WidgetOutcome::Activated => self.press(),
                WidgetOutcome::Ignored => match self.buttons.mnemonic(key, true) {
                    Some(_) => self.press(),
                    None => DialogStep::Ignored,
                },
                _ => DialogStep::Continue,
            },
        }
    }

    fn handle_action(&mut self, action: &Action) -> DialogStep<ServerInfoChoice> {
        match action {
            Action::DialogSubmit => self.press(),
            Action::NextField => {
                self.buttons.move_focus(true);
                DialogStep::Continue
            }
            Action::PrevField => {
                self.buttons.move_focus(false);
                DialogStep::Continue
            }
            _ => DialogStep::Ignored,
        }
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let lines = self.lines(usize::from(area.width));
        let body_h = usize::from(area.height.saturating_sub(2)).max(1);
        self.page = body_h;
        self.scroll = self.scroll.min(lines.len().saturating_sub(body_h));
        let label = cx.theme.style("field_label");
        let rows: Vec<Line> = lines
            .iter()
            .skip(self.scroll)
            .take(body_h)
            .map(|(l, v)| {
                let pad = LABEL_W.saturating_sub(width(l));
                Line::from(vec![
                    Span::styled(format!("{l}{}", " ".repeat(pad)), label),
                    Span::raw(v.clone()),
                ])
            })
            .collect();
        frame.render_widget(
            Paragraph::new(rows),
            Rect {
                height: area.height.saturating_sub(2).max(1).min(area.height),
                ..area
            },
        );
        if area.height >= 2 {
            let bw = u16::try_from(self.buttons.total_width())
                .unwrap_or(area.width)
                .min(area.width);
            self.buttons.render(
                frame,
                Rect::new(area.x, area.bottom() - 1, bw, 1),
                &widget_cx(cx, cx.focused, true),
            );
        }
    }
}
