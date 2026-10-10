//! Trust prompts (T69): unknown and changed SSH host keys, untrusted and
//! changed TLS certificates.
//!
//! One modal, [`TrustDialog`], draws all four: a scrollable summary (and, for
//! certificates, a Details view of the whole chain), optional checkboxes, an
//! optional note and a button row. It answers the core's
//! [`PromptRequest`](courier_ftp_core::events::PromptRequest) directly, so
//! it can close itself when the core stops waiting.
//!
//! Safety rules:
//! - Plain letters do nothing; only `Alt` + a button's first letter presses
//!   it, so typing that lands in a dialog that just opened can't answer it.
//! - On a changed key or certificate, *Cancel* is the default button, `Enter`
//!   on a checkbox means *Cancel*, and trusting needs the "I have verified"
//!   checkbox ticked first.
//! - Certificate prompts default to *Cancel* as well; an unknown host key
//!   defaults to *OK* (trust on first use, as in the mockup).
//! - "Always trust" is disabled, with a note, when the producer can't store
//!   the answer (vault locked).

use courier_ftp_core::{
    events::{PromptResponse, TrustDecision},
    model::{CertificateDetails, CertificateInfo, CertificateValidity, HostKeyFingerprint},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use time::{OffsetDateTime, UtcOffset, macros::format_description};
use tokio::sync::oneshot;

use super::{
    dialog::{ButtonRow, dialog_frame_styled},
    modal::{Modal, ModalOutcome},
    theme::Theme,
};

/// `2026-01-01 00:00 UTC`.
pub(crate) fn format_date(t: OffsetDateTime) -> String {
    t.to_offset(UtcOffset::UTC)
        .format(format_description!(
            "[year]-[month]-[day] [hour]:[minute] UTC"
        ))
        .unwrap_or_else(|_| t.to_string())
}

/// How a piece of text is styled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tone {
    Normal,
    Strong,
    Warn,
    Dim,
}

impl Tone {
    fn style(self, theme: &Theme) -> Style {
        match self {
            Tone::Normal => Style::new(),
            Tone::Strong => theme.title,
            Tone::Warn => theme.error,
            Tone::Dim => theme.dim,
        }
    }
}

/// One block of a dialog body.
#[derive(Debug, Clone)]
enum Item {
    /// A wrapped paragraph.
    Text(String, Tone),
    Blank,
    /// `Label:  value`, the value wrapped under itself. An empty label
    /// continues the field above.
    Field(&'static str, String, Tone),
    /// Old and new values side by side when they fit, else one after the
    /// other. Rows whose values differ are highlighted.
    Compare {
        old: &'static str,
        new: &'static str,
        rows: Vec<(&'static str, String, String)>,
    },
}

fn field(label: &'static str, value: impl Into<String>) -> Item {
    Item::Field(label, value.into(), Tone::Normal)
}

/// Break `text` into lines of at most `width` characters, at spaces when
/// possible.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut line = String::new();
        let mut len = 0;
        for word in paragraph.split(' ') {
            let mut word: Vec<char> = word.chars().collect();
            if len > 0 && len + 1 + word.len() > width {
                lines.push(std::mem::take(&mut line));
                len = 0;
            }
            if len > 0 {
                line.push(' ');
                len += 1;
            }
            // Words longer than a line (fingerprints) are cut, after a `:`
            // when there is one.
            while len + word.len() > width {
                let room = width - len;
                let at = word[..room]
                    .iter()
                    .rposition(|&c| c == ':')
                    .map_or(room, |i| i + 1);
                let rest = word.split_off(at);
                line.extend(word);
                lines.push(std::mem::take(&mut line));
                len = 0;
                word = rest;
            }
            len += word.len();
            line.extend(word);
        }
        lines.push(line);
    }
    lines
}

fn pad(s: &str, width: usize) -> String {
    format!("{s:<width$}")
}

/// The label column's width: the longest label plus `:` and two spaces.
fn label_width(items: &[Item]) -> usize {
    items
        .iter()
        .flat_map(|item| match item {
            Item::Field(label, ..) => vec![label.chars().count()],
            Item::Compare { old, new, rows } => rows
                .iter()
                .map(|(l, ..)| l.chars().count())
                .chain([old.chars().count(), new.chars().count()])
                .collect(),
            _ => vec![],
        })
        .max()
        .map_or(0, |w| w + 3)
}

fn label_text(label: &str) -> String {
    if label.is_empty() {
        String::new()
    } else {
        format!("{label}:")
    }
}

/// Lay out `items` in `width` columns.
fn render(items: &[Item], width: usize, theme: &Theme) -> Vec<Line<'static>> {
    let lw = label_width(items).min(width / 2);
    let value_w = width.saturating_sub(lw).max(1);
    let mut out = Vec::new();
    let labelled = |out: &mut Vec<Line<'static>>, label: &str, value: &str, style: Style| {
        for (i, part) in wrap(value, value_w).into_iter().enumerate() {
            let label = if i == 0 {
                label_text(label)
            } else {
                String::new()
            };
            out.push(Line::from(vec![
                Span::raw(pad(&label, lw)),
                Span::styled(part, style),
            ]));
        }
    };
    for item in items {
        match item {
            Item::Text(text, tone) => out.extend(
                wrap(text, width)
                    .into_iter()
                    .map(|l| Line::styled(l, tone.style(theme))),
            ),
            Item::Blank => out.push(Line::raw("")),
            Item::Field(label, value, tone) => {
                labelled(&mut out, label, value, tone.style(theme));
            }
            Item::Compare { old, new, rows } => {
                let col = rows
                    .iter()
                    .flat_map(|(_, a, b)| [a.chars().count(), b.chars().count()])
                    .chain([old.chars().count(), new.chars().count()])
                    .max()
                    .unwrap_or(0);
                let changed = |a: &String, b: &String| {
                    if a == b { Style::new() } else { theme.error }
                };
                if lw + col * 2 + 2 <= width {
                    out.push(Line::from(vec![
                        Span::raw(pad("", lw)),
                        Span::styled(pad(old, col + 2), theme.title),
                        Span::styled((*new).to_owned(), theme.title),
                    ]));
                    for (label, a, b) in rows {
                        out.push(Line::from(vec![
                            Span::raw(pad(&label_text(label), lw)),
                            Span::raw(pad(a, col + 2)),
                            Span::styled(b.clone(), changed(a, b)),
                        ]));
                    }
                } else {
                    for (side, header) in [(0, old), (1, new)] {
                        let mut first = true;
                        for (_, a, b) in rows {
                            let (value, style) = if side == 0 {
                                (a, Style::new())
                            } else {
                                (b, changed(a, b))
                            };
                            labelled(&mut out, if first { header } else { "" }, value, style);
                            first = false;
                        }
                    }
                }
            }
        }
    }
    out
}

/// What a button does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Press {
    /// Trust; remember when the "remember" checkbox is ticked.
    Trust,
    TrustOnce,
    TrustAlways,
    Cancel,
    /// Switch between the summary and the chain details.
    Details,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckRole {
    /// Ticked = [`TrustDecision::Always`] for [`Press::Trust`].
    Remember,
    /// Must be ticked before any trust button works.
    Confirm,
}

#[derive(Debug, Clone)]
struct Check {
    role: CheckRole,
    label: String,
    checked: bool,
    enabled: bool,
}

/// The modal for every trust prompt; see the module docs.
pub(crate) struct TrustDialog {
    title: String,
    danger: bool,
    /// Inner width wanted (less on narrow terminals).
    width: u16,
    summary: Vec<Item>,
    /// Certificate chain details; empty when there are none.
    details: Vec<Item>,
    showing_details: bool,
    scroll: u16,
    /// Body rows that fit in the last frame, for paging and clamping.
    visible: u16,
    checks: Vec<Check>,
    note: Option<String>,
    presses: Vec<(&'static str, Press)>,
    buttons: ButtonRow,
    /// `0..checks.len()` is a checkbox; `checks.len()` is the button row.
    focus: usize,
    /// What `Enter` does while a checkbox has focus.
    enter_on_check: Press,
    error: Option<String>,
    unicode: bool,
    reply: Option<oneshot::Sender<PromptResponse>>,
}

impl TrustDialog {
    #[expect(clippy::too_many_arguments, reason = "private constructor")]
    fn new(
        title: impl Into<String>,
        danger: bool,
        width: u16,
        summary: Vec<Item>,
        details: Vec<Item>,
        checks: Vec<Check>,
        note: Option<String>,
        presses: Vec<(&'static str, Press)>,
        default: Press,
        unicode: bool,
        reply: oneshot::Sender<PromptResponse>,
    ) -> Self {
        let labels: Vec<&str> = presses.iter().map(|(l, _)| *l).collect();
        let default_index = presses.iter().position(|(_, p)| *p == default).unwrap_or(0);
        let focus = checks.len();
        Self {
            title: title.into(),
            danger,
            width,
            summary,
            details,
            showing_details: false,
            scroll: 0,
            visible: 1,
            checks,
            note,
            buttons: ButtonRow::new(&labels, default_index),
            presses,
            focus,
            enter_on_check: if danger { Press::Cancel } else { default },
            error: None,
            unicode,
            reply: Some(reply),
        }
    }

    fn check(&self, role: CheckRole) -> Option<&Check> {
        self.checks.iter().find(|c| c.role == role)
    }

    fn answer(&mut self, decision: TrustDecision) -> ModalOutcome {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(PromptResponse::Trust(decision));
        }
        ModalOutcome::Close
    }

    fn press(&mut self, press: Press) -> ModalOutcome {
        match press {
            Press::Cancel => self.answer(TrustDecision::Reject),
            Press::Details => {
                self.showing_details = !self.showing_details;
                self.scroll = 0;
                let current = self.buttons.current;
                for (label, p) in &mut self.presses {
                    if *p == Press::Details {
                        *label = if self.showing_details {
                            "Summary"
                        } else {
                            "Details"
                        };
                    }
                }
                let labels: Vec<&str> = self.presses.iter().map(|(l, _)| *l).collect();
                self.buttons = ButtonRow::new(&labels, current);
                ModalOutcome::Keep
            }
            Press::Trust | Press::TrustOnce | Press::TrustAlways => {
                if self.check(CheckRole::Confirm).is_some_and(|c| !c.checked) {
                    self.error = Some(
                        "Tick \u{201c}I have verified\u{2026}\u{201d} first, or choose Cancel."
                            .into(),
                    );
                    self.focus = self
                        .checks
                        .iter()
                        .position(|c| c.role == CheckRole::Confirm)
                        .unwrap_or(self.focus);
                    return ModalOutcome::Keep;
                }
                let remember_box = self
                    .check(CheckRole::Remember)
                    .is_some_and(|c| c.enabled && c.checked);
                let always = match press {
                    Press::TrustAlways => true,
                    Press::TrustOnce => false,
                    _ => remember_box,
                };
                self.answer(if always {
                    TrustDecision::Always
                } else {
                    TrustDecision::Once
                })
            }
        }
    }

    /// Move focus to the next (or previous) enabled checkbox or the buttons.
    fn step(&mut self, forward: bool) {
        let slots = self.checks.len() + 1;
        let mut f = self.focus;
        for _ in 0..slots {
            f = if forward {
                (f + 1) % slots
            } else {
                (f + slots - 1) % slots
            };
            if self.checks.get(f).is_none_or(|c| c.enabled) {
                break;
            }
        }
        self.focus = f;
    }

    fn scroll_by(&mut self, delta: i32) {
        self.scroll = u16::try_from((i32::from(self.scroll) + delta).max(0)).unwrap_or(u16::MAX);
    }
}

impl Modal for TrustDialog {
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let width = self.width.min(area.width.saturating_sub(4)).max(16);
        let w = usize::from(width);
        let items = if self.showing_details {
            &self.details
        } else {
            &self.summary
        };
        let body = render(items, w, theme);

        let mut footer: Vec<Line> = Vec::new();
        for (i, c) in self.checks.iter().enumerate() {
            let mark = match (c.enabled, c.checked) {
                (false, _) => "[-]",
                (true, true) => "[x]",
                (true, false) => "[ ]",
            };
            let mark_style = if i == self.focus {
                theme.selection
            } else {
                Style::new()
            };
            let label_style = if c.enabled { Style::new() } else { theme.dim };
            footer.push(Line::from(vec![
                Span::styled(mark, mark_style),
                Span::raw(" "),
                Span::styled(c.label.clone(), label_style),
            ]));
        }
        if let Some(note) = &self.note {
            footer.extend(
                wrap(note, w)
                    .into_iter()
                    .map(|l| Line::styled(l, theme.dim)),
            );
        }
        if let Some(err) = &self.error {
            footer.extend(
                wrap(err, w)
                    .into_iter()
                    .map(|l| Line::styled(l, theme.error)),
            );
        }
        let to_u16 = |n: usize| u16::try_from(n).unwrap_or(u16::MAX);
        // Body, blank, [footer, blank,] buttons.
        let footer_rows = if footer.is_empty() {
            1
        } else {
            to_u16(footer.len()) + 2
        };
        let wanted = to_u16(body.len())
            .saturating_add(1)
            .saturating_add(footer_rows);
        let height = wanted.min(area.height.saturating_sub(2));

        let border = if self.danger {
            theme.error
        } else {
            theme.focused_border
        };
        let Some(inner) =
            dialog_frame_styled(frame, area, &self.title, width, height, theme, border)
        else {
            return;
        };
        self.visible = inner.height.saturating_sub(footer_rows + 1).max(1);
        let max_scroll = to_u16(body.len()).saturating_sub(self.visible);
        self.scroll = self.scroll.min(max_scroll);
        let body_rect = Rect::new(inner.x, inner.y, inner.width, self.visible);
        frame.render_widget(Paragraph::new(body).scroll((self.scroll, 0)), body_rect);
        if max_scroll > 0 {
            let more = match (self.scroll > 0, self.scroll < max_scroll, self.unicode) {
                (true, true, true) => " ↑↓ more ",
                (false, true, true) => " ↓ more ",
                (true, false, true) => " ↑ more ",
                (true, true, false) => " ^v more ",
                (false, true, false) => " v more ",
                _ => " ^ more ",
            };
            let len = to_u16(more.chars().count());
            frame.render_widget(
                Paragraph::new(Span::styled(more, theme.key_hint)),
                Rect::new(
                    inner.right().saturating_sub(len),
                    body_rect.bottom().saturating_sub(1),
                    len.min(inner.width),
                    1,
                ),
            );
        }
        let footer_top = body_rect.bottom() + 1;
        let footer_height = inner.bottom().saturating_sub(footer_top + 2);
        frame.render_widget(
            Paragraph::new(footer),
            Rect::new(inner.x, footer_top, inner.width, footer_height),
        );
        self.buttons.draw(
            frame,
            Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
            self.focus == self.checks.len(),
            theme,
        );
    }

    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        let on_buttons = self.focus >= self.checks.len();
        match key.code {
            KeyCode::Esc => return self.answer(TrustDecision::Reject),
            KeyCode::Tab => self.step(true),
            KeyCode::BackTab => self.step(false),
            KeyCode::Up => self.scroll_by(-1),
            KeyCode::Down => self.scroll_by(1),
            KeyCode::PageUp => self.scroll_by(-i32::from(self.visible)),
            KeyCode::PageDown => self.scroll_by(i32::from(self.visible)),
            KeyCode::Home if on_buttons => self.scroll = 0,
            KeyCode::End if on_buttons => self.scroll = u16::MAX,
            KeyCode::Char(' ') if !on_buttons => {
                if let Some(c) = self.checks.get_mut(self.focus)
                    && c.enabled
                {
                    c.checked = !c.checked;
                    self.error = None;
                }
            }
            KeyCode::Enter if !on_buttons => return self.press(self.enter_on_check),
            _ => {
                if (on_buttons || key.modifiers.contains(KeyModifiers::ALT))
                    && let Some(i) = self.buttons.handle_key(key)
                    && let Some(&(_, press)) = self.presses.get(i)
                {
                    return self.press(press);
                }
            }
        }
        ModalOutcome::Keep
    }

    fn is_done(&self) -> bool {
        // The core stopped waiting (connection cancelled or timed out).
        self.reply.as_ref().is_none_or(|r| r.is_closed())
    }
}

const LOCKED_NOTE: &str = "The vault is locked: trusting applies to this connection only.";

/// The dialog for [`PromptKind::TrustHostKey`](courier_ftp_core::events::PromptKind::TrustHostKey).
pub(crate) fn host_key_dialog(
    host: &str,
    key: &HostKeyFingerprint,
    known: Option<&HostKeyFingerprint>,
    can_remember: bool,
    unicode: bool,
    reply: oneshot::Sender<PromptResponse>,
) -> TrustDialog {
    let note = (!can_remember).then(|| LOCKED_NOTE.to_owned());
    let Some(old) = known else {
        let mut summary = vec![
            Item::Text(
                "The server's host key is unknown. You have no guarantee that the server is \
                 the computer you think it is."
                    .into(),
                Tone::Normal,
            ),
            Item::Blank,
            field("Host", host),
            field("Key type", key.key_type()),
            field("Fingerprint", key.sha256.clone()),
        ];
        if let Some(md5) = &key.md5 {
            summary.push(field("", md5.clone()));
        }
        summary.extend([
            Item::Blank,
            Item::Text(
                "Trust the key only if the fingerprint matches the one the server's \
                 administrator gave you."
                    .into(),
                Tone::Dim,
            ),
        ]);
        return TrustDialog::new(
            "Unknown host key",
            false,
            70,
            summary,
            Vec::new(),
            vec![Check {
                role: CheckRole::Remember,
                label: "Always trust this host, add this key to the cache".into(),
                checked: can_remember,
                enabled: can_remember,
            }],
            note,
            vec![("OK", Press::Trust), ("Cancel", Press::Cancel)],
            Press::Trust,
            unicode,
            reply,
        );
    };
    let mut rows = vec![
        ("Key type", old.key_type(), key.key_type()),
        ("SHA-256", old.sha256.clone(), key.sha256.clone()),
    ];
    if let (Some(a), Some(b)) = (&old.md5, &key.md5) {
        rows.push(("MD5", a.clone(), b.clone()));
    }
    let summary = vec![
        Item::Text(
            "The server's host key does not match the key in the cache!".into(),
            Tone::Warn,
        ),
        Item::Text(
            "Either the server's administrator replaced the key, or someone is intercepting \
             the connection (a man-in-the-middle attack) to steal your password and data."
                .into(),
            Tone::Normal,
        ),
        Item::Blank,
        field("Host", host),
        Item::Compare {
            old: "Cached key",
            new: "Offered key",
            rows,
        },
        Item::Blank,
        Item::Text(
            "Do not connect unless you know why the key changed. Ask the administrator for \
             the new fingerprint and compare it."
                .into(),
            Tone::Strong,
        ),
    ];
    TrustDialog::new(
        "WARNING: host key changed",
        true,
        // Room for the fingerprints side by side.
        122,
        summary,
        Vec::new(),
        vec![
            Check {
                role: CheckRole::Confirm,
                label: "I have verified the new key and want to connect".into(),
                checked: false,
                enabled: true,
            },
            Check {
                role: CheckRole::Remember,
                label: "Replace the cached key with the new one".into(),
                checked: false,
                enabled: can_remember,
            },
        ],
        note,
        vec![("Cancel", Press::Cancel), ("Trust new key", Press::Trust)],
        Press::Cancel,
        unicode,
        reply,
    )
}

/// `host` without its `:port`.
fn host_name(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((name, port))
            if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && !name.is_empty() =>
        {
            name
        }
        _ => host,
    }
}

/// Validity rows of one certificate, the bad end highlighted.
fn validity_fields(c: &CertificateInfo, now: OffsetDateTime) -> [Item; 2] {
    let (from_note, until_note) = match c.validity_at(now) {
        CertificateValidity::Valid => ("", ""),
        CertificateValidity::NotYetValid => (" (not yet valid)", ""),
        CertificateValidity::Expired => ("", " (expired)"),
    };
    let tone = |note: &str| {
        if note.is_empty() {
            Tone::Normal
        } else {
            Tone::Warn
        }
    };
    [
        Item::Field(
            "Valid from",
            format!("{}{from_note}", format_date(c.not_before)),
            tone(from_note),
        ),
        Item::Field(
            "Valid until",
            format!("{}{until_note}", format_date(c.not_after)),
            tone(until_note),
        ),
    ]
}

/// The Details view: every certificate of the chain.
fn chain_details(details: &CertificateDetails, now: OffsetDateTime) -> Vec<Item> {
    let n = details.chain.len();
    let mut items = Vec::new();
    for (i, c) in details.chain.iter().enumerate() {
        if i > 0 {
            items.push(Item::Blank);
        }
        let role = if i == 0 { " (server)" } else { "" };
        items.push(Item::Text(
            format!("Certificate {} of {n}{role}", i + 1),
            Tone::Strong,
        ));
        items.push(field("Subject", c.subject.clone()));
        items.push(field("Issuer", c.issuer.clone()));
        items.push(field("Serial", c.serial.clone()));
        items.extend(validity_fields(c, now));
        if !c.subject_alt_names.is_empty() {
            items.push(field("Alt names", c.subject_alt_names.join(", ")));
        }
        items.push(field("Public key", c.public_key.clone()));
        items.push(field("Signature", c.signature_algorithm.clone()));
        items.push(field("SHA-256", c.fingerprint_sha256.clone()));
        items.push(field("SHA-1", c.fingerprint_sha1.clone()));
    }
    if items.is_empty() {
        items.push(Item::Text(
            "The server sent no certificate.".into(),
            Tone::Dim,
        ));
    }
    items
}

/// The dialog for [`PromptKind::TrustCertificate`](courier_ftp_core::events::PromptKind::TrustCertificate).
/// `now` decides which certificates show as expired.
pub(crate) fn certificate_dialog(
    details: &CertificateDetails,
    known_sha256: Option<&str>,
    can_remember: bool,
    now: OffsetDateTime,
    unicode: bool,
    reply: oneshot::Sender<PromptResponse>,
) -> TrustDialog {
    let mut summary = Vec::new();
    let changed = known_sha256.is_some();
    if let Some(old) = known_sha256 {
        summary.extend([
            Item::Text(
                "The server's certificate differs from the one you trusted before!".into(),
                Tone::Warn,
            ),
            Item::Text(
                "Either the server got a new certificate, or someone is intercepting the \
                 connection (a man-in-the-middle attack) to steal your password and data."
                    .into(),
                Tone::Normal,
            ),
        ]);
        let new = details
            .leaf()
            .map(|c| c.fingerprint_sha256.clone())
            .unwrap_or_default();
        summary.extend([
            Item::Blank,
            Item::Compare {
                old: "Trusted",
                new: "Offered",
                rows: vec![("SHA-256", old.to_owned(), new)],
            },
        ]);
    } else {
        let why = if details.problem.is_empty() {
            "The server's certificate is not trusted.".to_owned()
        } else {
            format!(
                "The server's certificate could not be verified: {}.",
                details.problem.trim_end_matches('.')
            )
        };
        summary.push(Item::Text(why, Tone::Normal));
    }
    summary.push(Item::Blank);
    summary.push(field("Host", details.host.clone()));
    if let Some(c) = details.leaf() {
        summary.push(field("Subject", c.common_name()));
        summary.push(field("Issuer", c.issuer.clone()));
        summary.extend(validity_fields(c, now));
    }
    let name = host_name(&details.host);
    let (ok, bad) = if unicode {
        ("✔", "✘")
    } else {
        ("OK", "NO")
    };
    summary.push(if details.hostname_matches {
        Item::Field("Hostname", format!("{ok} matches {name}"), Tone::Normal)
    } else {
        Item::Field(
            "Hostname",
            format!("{bad} does not match {name}"),
            Tone::Warn,
        )
    });
    if let Some(c) = details.leaf() {
        if !changed {
            summary.push(field("SHA-256", c.fingerprint_sha256.clone()));
        }
        summary.push(field("SHA-1", c.fingerprint_sha1.clone()));
    }
    summary.push(field(
        "Session",
        format!("{}, {}", details.tls_version, details.cipher),
    ));
    let n = details.chain.len();
    summary.push(field(
        "Chain",
        format!(
            "{n} certificate{} (Alt-D: details)",
            if n == 1 { "" } else { "s" }
        ),
    ));

    let mut presses = Vec::new();
    if changed {
        presses.push(("Cancel", Press::Cancel));
    }
    presses.push(("Trust once", Press::TrustOnce));
    if can_remember {
        presses.push(("Always trust", Press::TrustAlways));
    }
    if !changed {
        presses.push(("Cancel", Press::Cancel));
    }
    presses.push(("Details", Press::Details));
    let checks = if changed {
        vec![Check {
            role: CheckRole::Confirm,
            label: "I have verified the new certificate and want to connect".into(),
            checked: false,
            enabled: true,
        }]
    } else {
        Vec::new()
    };
    TrustDialog::new(
        if changed {
            "WARNING: certificate changed"
        } else {
            "Untrusted certificate"
        },
        changed,
        76,
        summary,
        chain_details(details, now),
        checks,
        (!can_remember).then(|| LOCKED_NOTE.to_owned()),
        presses,
        Press::Cancel,
        unicode,
        reply,
    )
}

#[cfg(test)]
mod tests;
