//! Untrusted and changed TLS certificates (T69 §3; T12 produces the prompt), the
//! certificate details view, and the chain viewer T57's server info dialog opens.

use std::{borrow::Cow, cell::Cell, fmt};

use courier_ftp_core::events::{
    CertProblem, CertPromptDetails, CertificateDetails, PromptResponse, TrustAnswer,
};
use ratatui::{
    Frame,
    layout::{Position, Rect},
    style::Style,
    text::{Line, Span},
};
use time::OffsetDateTime;
use tokio::time::Instant;

use super::{
    PromptDialog, Step,
    host_key::{ChangedConfirm, Confirm},
    layout::{
        Body, BodyCx, Btn, K, Row, checkbox, classify, clean, hex, labeled_lines, pad_label,
        render_body, step_focus,
    },
};
use crate::{
    action::Action,
    components::{
        DrawCx,
        dialog::{Dialog, DialogSize, DialogStep},
        widgets::WidgetCx,
    },
    keymap::chord::KeyChord,
};

/// Lines scrolled by `PgUp`/`PgDn` in the details view.
const PAGE: usize = 10;

/// `2026-01-01 00:00` (UTC).
fn date_time(t: OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute()
    )
}

fn plural(n: i64, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}

/// `(expired 12 days ago)` / `(valid in 3 days)`; `None` while valid.
fn validity_note(c: &CertificateDetails, now: OffsetDateTime) -> Option<String> {
    if now > c.not_after {
        Some(format!(
            "(expired {} ago)",
            plural((now - c.not_after).whole_days(), "day")
        ))
    } else if now < c.not_before {
        Some(format!(
            "(not valid yet, valid in {})",
            plural((c.not_before - now).whole_days().max(1), "day")
        ))
    } else {
        None
    }
}

/// The SHA-256 fingerprint as two lines of 16 bytes.
fn sha256_halves(sha: &[u8; 32]) -> (String, String) {
    (hex(&sha[..16]), hex(&sha[16..]))
}

/// Role of certificate `i` of `n` in a chain.
fn role(i: usize, n: usize, c: &CertificateDetails) -> &'static str {
    if i == 0 {
        "server"
    } else if i + 1 == n && (c.self_signed || c.is_ca) {
        "root"
    } else {
        "intermediate"
    }
}

/// The detail lines of one certificate (for T57's server info dialog).
#[cfg_attr(not(test), expect(dead_code, reason = "T57's server info rows"))]
pub(crate) fn render_certificate_details(
    c: &CertificateDetails,
    now: OffsetDateTime,
) -> Vec<Line<'static>> {
    detail_lines(c, now, usize::MAX / 2, Style::default())
}

fn detail_lines(
    c: &CertificateDetails,
    now: OffsetDateTime,
    width: usize,
    danger: Style,
) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let mut row = |label: &str, parts: Vec<Span<'static>>| {
        out.extend(labeled_lines(label, parts, width));
    };
    let raw = |s: String| vec![Span::raw(s)];
    row("Subject:", raw(clean(&c.subject)));
    row("Issuer:", raw(clean(&c.issuer)));
    row("Serial:", raw(clean(&c.serial)));
    row(
        "Not before:",
        raw(format!("{} UTC", date_time(c.not_before))),
    );
    let mut after = vec![Span::raw(format!("{} UTC", date_time(c.not_after)))];
    if let Some(note) = validity_note(c, now) {
        after.push(Span::raw(" "));
        after.push(Span::styled(note, danger));
    }
    row("Not after:", after);
    if c.sans.is_empty() {
        row("Alt. names:", raw("(none)".to_owned()));
    }
    for (i, san) in c.sans.iter().enumerate() {
        row(if i == 0 { "Alt. names:" } else { "" }, raw(clean(san)));
    }
    row("Public key:", raw(clean(&c.public_key)));
    row("Signature:", raw(clean(&c.signature_algorithm)));
    if c.is_ca {
        row("CA:", raw("yes".to_owned()));
    }
    let (a, b) = sha256_halves(&c.sha256);
    row("SHA-256:", raw(a));
    row("", raw(b));
    row("SHA-1:", raw(hex(&c.sha1)));
    if let Some(e) = &c.parse_error {
        row(
            "Note:",
            vec![Span::styled(
                format!("could not be parsed fully: {}", clean(e)),
                danger,
            )],
        );
    }
    out
}

/// What a details-view key did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DetailsKey {
    /// Stay.
    Continue,
    /// Back to the summary (or close the viewer).
    Back,
}

/// One certificate of a chain at a time, scrollable.
#[derive(Debug, Clone)]
pub(crate) struct DetailsView {
    chain: Vec<CertificateDetails>,
    index: usize,
    scroll: usize,
    now: OffsetDateTime,
}

impl DetailsView {
    /// The view of `chain` (leaf first).
    pub(crate) fn new(chain: Vec<CertificateDetails>, now: OffsetDateTime) -> Self {
        Self {
            chain,
            index: 0,
            scroll: 0,
            now,
        }
    }

    /// The certificate shown (0 = leaf).
    pub(crate) fn index(&self) -> usize {
        self.index
    }

    /// `Certificate 1 of 2: server`.
    pub(crate) fn title(&self) -> String {
        let n = self.chain.len();
        match self.chain.get(self.index) {
            Some(c) => format!(
                "Certificate {} of {n}: {}",
                self.index + 1,
                role(self.index, n, c)
            ),
            None => "Certificate".to_owned(),
        }
    }

    fn line_count(&self) -> usize {
        self.chain
            .get(self.index)
            .map_or(0, |c| detail_lines(c, self.now, 72, Style::default()).len())
    }

    /// Rows of [`Self::body`] at `width`.
    pub(crate) fn rows_at(&self, width: usize) -> usize {
        self.chain.get(self.index).map_or(3, |c| {
            detail_lines(c, self.now, width, Style::default()).len() + 2
        })
    }

    /// A key.
    pub(crate) fn handle(&mut self, k: K) -> DetailsKey {
        let last = self.line_count().saturating_sub(1);
        match k {
            K::Esc | K::Plain('d') | K::Alt('d') => return DetailsKey::Back,
            K::Plain('j') | K::Down => self.scroll = (self.scroll + 1).min(last),
            K::Plain('k') | K::Up => self.scroll = self.scroll.saturating_sub(1),
            K::PageDown => self.scroll = (self.scroll + PAGE).min(last),
            K::PageUp => self.scroll = self.scroll.saturating_sub(PAGE),
            K::Plain('g') => self.scroll = 0,
            K::Plain('G') => self.scroll = last,
            K::Plain('[') | K::Left if self.index > 0 => {
                self.index -= 1;
                self.scroll = 0;
            }
            K::Plain(']') | K::Right if self.index + 1 < self.chain.len() => {
                self.index += 1;
                self.scroll = 0;
            }
            _ => {}
        }
        DetailsKey::Continue
    }

    /// The body: the certificate's lines from the scroll position (padded so the
    /// dialog keeps its height), then the key help.
    pub(crate) fn body(&self, width: usize, cx: &BodyCx) -> Body {
        let mut b = Body::default();
        let Some(c) = self.chain.get(self.index) else {
            b.text("No certificate was received.", Style::default());
            b.blank();
            b.text("Esc back", cx.theme.style("field_help"));
            return b;
        };
        let lines = detail_lines(c, self.now, width, cx.danger());
        let n = lines.len();
        let top = self.scroll.min(n.saturating_sub(1));
        for l in lines.into_iter().skip(top) {
            b.line(l);
        }
        for _ in 0..top {
            b.blank();
        }
        b.blank();
        b.text(
            "j/k scroll   [ ] previous/next certificate   Esc back",
            cx.theme.style("field_help"),
        );
        b.focus_row = 0;
        b
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UFocus {
    Details,
    Always,
    Trust,
    Cancel,
}

const UFOCUS: [UFocus; 4] = [
    UFocus::Details,
    UFocus::Always,
    UFocus::Trust,
    UFocus::Cancel,
];

#[derive(Debug)]
enum Variant {
    Unknown { always: bool, focus: UFocus },
    Changed(ChangedConfirm),
}

/// The certificate dialog: summary (unknown or changed) and the details view.
pub(crate) struct CertificateDialog {
    p: CertPromptDetails,
    variant: Variant,
    details: Option<DetailsView>,
    now: OffsetDateTime,
}

impl fmt::Debug for CertificateDialog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateDialog")
            .field("variant", &self.variant)
            .field("details", &self.details.as_ref().map(DetailsView::index))
            .finish_non_exhaustive()
    }
}

impl CertificateDialog {
    /// The dialog for `p`, judging validity at `now`.
    pub(crate) fn new(p: CertPromptDetails, now: OffsetDateTime) -> Self {
        let variant = if p.previous.is_some() {
            Variant::Changed(ChangedConfirm::new(
                &p.host,
                p.can_save,
                true,
                "certificate",
            ))
        } else {
            Variant::Unknown {
                always: p.can_save,
                focus: UFocus::Trust,
            }
        };
        Self {
            p,
            variant,
            details: None,
            now,
        }
    }

    /// The details view is open (tests).
    #[cfg(test)]
    pub(crate) fn details_index(&self) -> Option<usize> {
        self.details.as_ref().map(DetailsView::index)
    }

    /// The typed-host-name part (tests).
    #[cfg(test)]
    pub(crate) fn confirm_mut(&mut self) -> Option<&mut ChangedConfirm> {
        match &mut self.variant {
            Variant::Changed(c) => Some(c),
            Variant::Unknown { .. } => None,
        }
    }

    fn open_details(&mut self) {
        self.details = Some(DetailsView::new(self.p.session.chain.clone(), self.now));
    }

    fn answer(a: TrustAnswer) -> Step {
        Step::Answer(PromptResponse::Certificate(a))
    }

    fn problem_text(&self, p: &CertProblem) -> String {
        match p {
            CertProblem::UnknownIssuer => "issued by an unknown certificate authority".to_owned(),
            CertProblem::SelfSigned => "self-signed certificate".to_owned(),
            CertProblem::Expired => "certificate has expired".to_owned(),
            CertProblem::NotYetValid => "certificate is not valid yet".to_owned(),
            CertProblem::NotValidForName => self.mismatch_text(),
            CertProblem::Revoked => "certificate was revoked".to_owned(),
            CertProblem::InvalidPurpose => "not valid for server authentication".to_owned(),
            CertProblem::BadSignature => "a signature in the chain does not verify".to_owned(),
            CertProblem::Other(s) => clean(s),
        }
    }

    fn mismatch_text(&self) -> String {
        let leaf = self.p.session.chain.first();
        let name = leaf.and_then(|c| {
            c.subject_cn.clone().or_else(|| {
                c.sans
                    .first()
                    .map(|s| s.split_once(':').map_or(s.as_str(), |(_, v)| v).to_owned())
            })
        });
        match name {
            Some(n) => format!(
                "host name does not match (certificate is for {})",
                clean(&n)
            ),
            None => "host name does not match".to_owned(),
        }
    }

    /// Host, subject, issuer, validity, fingerprints, session and chain rows.
    fn summary_rows(
        &self,
        b: &mut Body,
        width: usize,
        cx: &BodyCx,
        details_focused: bool,
        changed: bool,
    ) {
        let leaf = self.p.session.chain.first();
        let host = format!("{}:{}", clean(&self.p.host), self.p.port);
        let host_parts = if self.p.hostname_matches {
            vec![
                Span::raw(host),
                Span::raw(" "),
                Span::styled(cx.ok_mark(), cx.good()),
            ]
        } else {
            vec![
                Span::raw(host),
                Span::raw(" "),
                Span::styled(format!("{} does not match", cx.bad_mark()), cx.danger()),
            ]
        };
        if !changed {
            b.labeled_spans("Host:", host_parts, width);
        }
        let Some(leaf) = leaf else {
            b.labeled("Subject:", "(no certificate received)", width, cx.danger());
            return;
        };
        b.labeled("Subject:", &clean(&leaf.subject), width, Style::default());
        if !changed {
            b.labeled("Issuer:", &clean(&leaf.issuer), width, Style::default());
        }
        let arrow = if cx.symbols.unicode { "→" } else { "->" };
        let mut valid = vec![Span::raw(format!(
            "{} {arrow} {} UTC",
            date_time(leaf.not_before),
            date_time(leaf.not_after)
        ))];
        valid.push(Span::raw(" "));
        match validity_note(leaf, self.now) {
            Some(note) => {
                valid.push(Span::styled(
                    format!("{} {note}", cx.bad_mark()),
                    cx.danger(),
                ));
            }
            None => valid.push(Span::styled(cx.ok_mark(), cx.good())),
        }
        b.labeled_spans("Valid:", valid, width);
        let (a, z) = sha256_halves(&leaf.sha256);
        let style = if changed {
            cx.danger()
        } else {
            Style::default()
        };
        b.labeled(if changed { "New:" } else { "SHA-256:" }, &a, width, style);
        b.labeled("", &z, width, style);
        if !changed {
            b.labeled("SHA-1:", &hex(&leaf.sha1), width, Style::default());
            b.labeled(
                "Session:",
                &format!(
                    "{}, {}",
                    clean(&self.p.session.protocol),
                    clean(&self.p.session.cipher_suite)
                ),
                width,
                Style::default(),
            );
        }
        let n = self.p.session.chain.len();
        let count = if n == 1 {
            "1 certificate".to_owned()
        } else {
            format!("{n} certificates")
        };
        let mut btn = cx.theme.style("button");
        if details_focused {
            btn = btn.patch(cx.theme.style("button_focused"));
        }
        if cx.guard {
            btn = btn.patch(cx.theme.style("field_help"));
        }
        let ell = if cx.symbols.unicode { "…" } else { "..." };
        let row = b.line(Line::from(vec![
            Span::raw(pad_label("Chain:")),
            Span::raw(format!("{count:<22} ")),
            Span::styled(format!("[ Details{ell} ]"), btn),
        ]));
        if details_focused {
            b.focus_row = row;
        }
    }

    fn unknown_body(&self, always: bool, focus: UFocus, width: usize, cx: &BodyCx) -> Body {
        let mut b = Body::default();
        b.para(
            "The server's certificate could not be verified:",
            width,
            Style::default(),
        );
        let mut problems: Vec<String> = self
            .p
            .problems
            .iter()
            .map(|p| self.problem_text(p))
            .collect();
        if !self.p.hostname_matches && !self.p.problems.contains(&CertProblem::NotValidForName) {
            problems.push(self.mismatch_text());
        }
        for p in problems {
            for (i, l) in super::layout::wrap(&p, width.saturating_sub(4))
                .into_iter()
                .enumerate()
            {
                let head = if i == 0 {
                    format!("  {} ", cx.bad_mark())
                } else {
                    " ".repeat(2 + cx.bad_mark().len() + 1)
                };
                b.line(Line::from(vec![
                    Span::styled(head, cx.danger()),
                    Span::styled(l, cx.danger()),
                ]));
            }
        }
        b.blank();
        self.summary_rows(&mut b, width, cx, focus == UFocus::Details, false);
        b.blank();
        let label = if self.p.can_save {
            "Always trust this certificate and save it in the vault"
        } else {
            "Always trust this certificate (unlock the vault to save it)"
        };
        let row = b.line(checkbox(
            label,
            always && self.p.can_save,
            focus == UFocus::Always,
            self.p.can_save,
            cx.theme,
        ));
        if focus == UFocus::Always {
            b.focus_row = row;
        }
        b.blank();
        let row = b.push(Row::Buttons(vec![
            Btn::new("Trust", focus == UFocus::Trust),
            Btn::new("Cancel", focus == UFocus::Cancel),
        ]));
        if matches!(focus, UFocus::Trust | UFocus::Cancel) {
            b.focus_row = row;
        }
        b
    }

    fn changed_body(&self, c: &ChangedConfirm, width: usize, cx: &BodyCx) -> Body {
        let mut b = Body::default();
        b.para(
            &format!(
                "The certificate of {}:{} is not the one you trusted. Someone could be intercepting your connection (man-in-the-middle attack), or the certificate was renewed or replaced.",
                clean(&self.p.host),
                self.p.port
            ),
            width,
            Style::default(),
        );
        b.blank();
        if let Some(prev) = &self.p.previous {
            let (a, z) = sha256_halves(&prev.sha256);
            b.labeled("Trusted:", &a, width, Style::default());
            b.labeled("", &z, width, Style::default());
            b.labeled(
                "",
                &format!("saved in the vault on {}", prev.added_at.date()),
                width,
                Style::default(),
            );
            b.labeled("", &clean(&prev.subject), width, Style::default());
        }
        self.summary_rows(&mut b, width, cx, c.details_focused(), true);
        b.blank();
        c.rows(&mut b, width, cx);
        b
    }
}

impl PromptDialog for CertificateDialog {
    fn kind(&self) -> &'static str {
        match self.variant {
            Variant::Unknown { .. } => "certificate_unknown",
            Variant::Changed(_) => "certificate_changed",
        }
    }

    fn title(&self, _unicode: bool) -> String {
        if let Some(d) = &self.details {
            return d.title();
        }
        match self.variant {
            Variant::Unknown { .. } => "Unknown certificate".to_owned(),
            Variant::Changed(_) => "WARNING: CERTIFICATE CHANGED".to_owned(),
        }
    }

    fn danger(&self) -> bool {
        self.details.is_none() && matches!(self.variant, Variant::Changed(_))
    }

    fn handle_key(&mut self, key: KeyChord) -> Step {
        let k = classify(key);
        if let Some(d) = &mut self.details {
            if d.handle(k) == DetailsKey::Back {
                self.details = None;
            }
            return Step::Continue;
        }
        let can_save = self.p.can_save;
        let mut open = false;
        let step = match &mut self.variant {
            Variant::Changed(c) => match c.handle_key(key) {
                Confirm::Answer(a) => Self::answer(a),
                Confirm::Details => {
                    open = true;
                    Step::Continue
                }
                Confirm::None => Step::Continue,
            },
            Variant::Unknown { always, focus } => {
                let trust = |always: bool| {
                    Self::answer(if always && can_save {
                        TrustAnswer::AlwaysTrust
                    } else {
                        TrustAnswer::TrustOnce
                    })
                };
                let idx = UFOCUS.iter().position(|f| f == focus).unwrap_or(2);
                let ok = |i: usize| UFOCUS[i] != UFocus::Always || can_save;
                match k {
                    K::Esc | K::Plain('c') | K::Alt('c') => Self::answer(TrustAnswer::Reject),
                    K::Plain('t') | K::Alt('t') => trust(*always),
                    K::Plain('d') | K::Alt('d') => {
                        open = true;
                        Step::Continue
                    }
                    K::Space | K::Plain('a') | K::Alt('a') => {
                        if can_save {
                            *always = !*always;
                        }
                        Step::Continue
                    }
                    K::Enter => match focus {
                        UFocus::Cancel => Self::answer(TrustAnswer::Reject),
                        UFocus::Details => {
                            open = true;
                            Step::Continue
                        }
                        UFocus::Trust | UFocus::Always => trust(*always),
                    },
                    K::Tab | K::Down => {
                        *focus = UFOCUS[step_focus(idx, UFOCUS.len(), true, ok)];
                        Step::Continue
                    }
                    K::BackTab | K::Up => {
                        *focus = UFOCUS[step_focus(idx, UFOCUS.len(), false, ok)];
                        Step::Continue
                    }
                    K::Left if matches!(focus, UFocus::Cancel) => {
                        *focus = UFocus::Trust;
                        Step::Continue
                    }
                    K::Right if matches!(focus, UFocus::Trust) => {
                        *focus = UFocus::Cancel;
                        Step::Continue
                    }
                    _ => Step::Continue,
                }
            }
        };
        if open {
            self.open_details();
        }
        step
    }

    fn handle_paste(&mut self, text: &str) {
        if self.details.is_none()
            && let Variant::Changed(c) = &mut self.variant
        {
            c.handle_paste(text);
        }
    }

    fn body(&self, width: u16, cx: &BodyCx) -> Body {
        let width = usize::from(width);
        if let Some(d) = &self.details {
            return d.body(width, cx);
        }
        match &self.variant {
            Variant::Unknown { always, focus } => self.unknown_body(*always, *focus, width, cx),
            Variant::Changed(c) => self.changed_body(c, width, cx),
        }
    }

    fn draw_input(
        &self,
        frame: &mut Frame,
        _field: usize,
        area: Rect,
        cx: &WidgetCx,
    ) -> Option<Position> {
        match &self.variant {
            Variant::Changed(c) if self.details.is_none() => c.draw_field(frame, area, cx),
            _ => None,
        }
    }
}

/// The certificate chain of a connected session, read-only (T57's `[ Details ]`).
#[derive(Debug)]
pub(crate) struct CertificateChainDialog {
    view: DetailsView,
    scroll: Cell<usize>,
}

impl CertificateChainDialog {
    /// The viewer for `chain` (leaf first), judging validity at `now`.
    pub(crate) fn new(chain: Vec<CertificateDetails>, now: OffsetDateTime) -> Self {
        Self {
            view: DetailsView::new(chain, now),
            scroll: Cell::new(0),
        }
    }
}

impl Dialog for CertificateChainDialog {
    type Output = ();

    fn kind(&self) -> &'static str {
        "certificate_chain"
    }

    fn title(&self) -> Cow<'_, str> {
        Cow::Owned(self.view.title())
    }

    fn size(&self, _screen: Rect) -> DialogSize {
        DialogSize::Fit {
            min_w: super::layout::MIN_W,
            max_w: super::layout::DIALOG_W,
        }
    }

    fn measure(&self, max_width: u16) -> (u16, u16) {
        let rows = self.view.rows_at(usize::from(max_width));
        (max_width, u16::try_from(rows).unwrap_or(u16::MAX))
    }

    fn handle_key(&mut self, key: KeyChord) -> DialogStep<()> {
        match classify(key) {
            K::Enter | K::Plain('q') => DialogStep::Close(None),
            k => match self.view.handle(k) {
                DetailsKey::Back => DialogStep::Close(None),
                DetailsKey::Continue => DialogStep::Continue,
            },
        }
    }

    fn handle_action(&mut self, action: &Action) -> DialogStep<()> {
        match action {
            Action::DialogCancel | Action::DialogSubmit => DialogStep::Close(None),
            _ => DialogStep::Ignored,
        }
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) {
        let bcx = BodyCx {
            theme: cx.theme,
            symbols: cx.symbols,
            guard: false,
        };
        let body = self.view.body(usize::from(area.width), &bcx);
        render_body(
            frame,
            area,
            &body,
            &self.scroll,
            &bcx,
            Instant::now(),
            |_, _, _, _| None,
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

    use super::*;
    use crate::components::prompts::tests::{cert_prompt, k, now_2026};

    #[test]
    fn details_navigation_and_back() {
        let mut d = CertificateDialog::new(cert_prompt(false, true), now_2026());
        assert_eq!(d.details_index(), None);
        assert!(matches!(d.handle_key(k("d")), Step::Continue));
        assert_eq!(d.details_index(), Some(0));
        assert_eq!(d.title(true), "Certificate 1 of 2: server");
        d.handle_key(k("]"));
        assert_eq!(d.details_index(), Some(1));
        assert_eq!(d.title(true), "Certificate 2 of 2: root");
        d.handle_key(k("right"));
        assert_eq!(d.details_index(), Some(1), "stays at the last");
        d.handle_key(k("["));
        assert_eq!(d.details_index(), Some(0));
        for key in ["j", "j", "k", "pagedown", "pageup", "G", "g", "down", "up"] {
            assert!(matches!(d.handle_key(k(key)), Step::Continue));
        }
        // Esc goes back to the summary and never answers.
        assert!(matches!(d.handle_key(k("esc")), Step::Continue));
        assert_eq!(d.details_index(), None);
        // Enter on Details… (Shift-Tab twice from Trust) opens it too.
        d.handle_key(k("backtab"));
        d.handle_key(k("backtab"));
        d.handle_key(k("enter"));
        assert_eq!(d.details_index(), Some(0));
        d.handle_key(k("d"));
        assert_eq!(d.details_index(), None);
        assert!(matches!(
            d.handle_key(k("esc")),
            Step::Answer(PromptResponse::Certificate(TrustAnswer::Reject))
        ));
    }

    #[test]
    fn changed_certificate_needs_host_name() {
        let mut d = CertificateDialog::new(cert_prompt(true, true), now_2026());
        assert!(matches!(
            d.handle_key(k("enter")),
            Step::Answer(PromptResponse::Certificate(TrustAnswer::Reject))
        ));
        let mut d = CertificateDialog::new(cert_prompt(true, true), now_2026());
        assert!(matches!(d.handle_key(k("alt-o")), Step::Continue));
        d.confirm_mut().unwrap().type_text("FTP.example.com");
        assert!(matches!(
            d.handle_key(k("alt-r")),
            Step::Answer(PromptResponse::Certificate(TrustAnswer::AlwaysTrust))
        ));
    }
}
