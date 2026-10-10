//! Unknown and changed SSH host keys (T69 §1, §2; T21 produces the prompt), and the
//! typed-host-name confirmation shared with changed certificates.

use std::{fmt, path::Path};

use courier_ftp_core::events::{HostKeyPrompt, OldKeySource, PromptResponse, TrustAnswer};
use ratatui::{
    Frame,
    layout::{Position, Rect},
    style::Style,
    text::{Line, Span},
};

use super::{
    PromptDialog, Step,
    layout::{
        Body, BodyCx, Btn, K, LABEL_W, Row, checkbox, classify, clean, labeled_lines, pad_label,
        step_focus,
    },
};
use crate::{
    components::widgets::{TextInput, Widget, WidgetCx, WidgetOutcome},
    keymap::chord::KeyChord,
};

/// The detail lines of a host key (for T57's server info dialog).
#[cfg_attr(not(test), expect(dead_code, reason = "T57's server info rows"))]
pub(crate) fn render_host_key_details(p: &HostKeyPrompt) -> Vec<Line<'static>> {
    host_key_lines(p, usize::MAX / 2)
}

fn key_type(key_type: &str, bits: u32) -> String {
    let t = clean(key_type);
    if bits == 0 {
        t
    } else {
        format!("{t} ({bits} bits)")
    }
}

fn host_key_lines(p: &HostKeyPrompt, width: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let plain = |s: String| vec![Span::raw(s)];
    out.extend(labeled_lines(
        "Host:",
        plain(format!("{}:{}", clean(&p.host), p.port)),
        width,
    ));
    out.extend(labeled_lines(
        "Key type:",
        plain(key_type(&p.key_type, p.bits)),
        width,
    ));
    out.extend(labeled_lines(
        "SHA-256:",
        plain(clean(&p.fingerprint_sha256)),
        width,
    ));
    out.extend(labeled_lines(
        "MD5:",
        plain(clean(&p.fingerprint_md5)),
        width,
    ));
    out
}

/// `~/…` for paths in the home directory.
fn tilde(path: &Path) -> String {
    if let Some(home) = directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
        && let Ok(rest) = path.strip_prefix(&home)
    {
        return clean(&format!("~/{}", rest.display()));
    }
    clean(&path.display().to_string())
}

/// What happened in the typed-host-name part of a changed key/certificate dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Confirm {
    /// Nothing to report.
    None,
    /// An answer.
    Answer(TrustAnswer),
    /// `Details…` (certificates).
    Details,
}

/// Focus stops of [`ChangedConfirm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CFocus {
    Field,
    Details,
    Cancel,
    Once,
    Replace,
}

const CFOCUS: [CFocus; 5] = [
    CFocus::Field,
    CFocus::Details,
    CFocus::Cancel,
    CFocus::Once,
    CFocus::Replace,
];

/// The safety part of a changed host key or certificate: the user types the host
/// name before `Trust once` / `Replace trusted key` can be reached; `Enter` in the
/// field never answers; the default and initial focus is `Cancel`.
pub(crate) struct ChangedConfirm {
    host: String,
    field: TextInput,
    mismatch: bool,
    focus: CFocus,
    can_save: bool,
    has_details: bool,
    what: &'static str,
}

impl fmt::Debug for ChangedConfirm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChangedConfirm")
            .field("focus", &self.focus)
            .field("matches", &self.matches())
            .finish_non_exhaustive()
    }
}

impl ChangedConfirm {
    /// For `host`; `has_details` adds the `Details…` stop (certificates); `what` is
    /// `"key"` or `"certificate"`.
    pub(crate) fn new(host: &str, can_save: bool, has_details: bool, what: &'static str) -> Self {
        Self {
            host: host.to_owned(),
            field: TextInput::new("").max_chars(255),
            mismatch: false,
            focus: CFocus::Cancel,
            can_save,
            has_details,
            what,
        }
    }

    /// The typed text equals the host (ASCII case-insensitive, spaces around ignored).
    pub(crate) fn matches(&self) -> bool {
        let typed = self.field.value().trim();
        !typed.is_empty() && typed.eq_ignore_ascii_case(self.host.trim())
    }

    fn enabled(&self, f: CFocus) -> bool {
        match f {
            CFocus::Field | CFocus::Cancel => true,
            CFocus::Details => self.has_details,
            CFocus::Once => self.matches(),
            CFocus::Replace => self.matches() && self.can_save,
        }
    }

    fn index(&self) -> usize {
        CFOCUS.iter().position(|f| *f == self.focus).unwrap_or(0)
    }

    fn move_focus(&mut self, forward: bool) {
        let i = step_focus(self.index(), CFOCUS.len(), forward, |i| {
            self.enabled(CFOCUS[i])
        });
        self.focus = CFOCUS[i];
    }

    fn on_button(&self) -> bool {
        matches!(self.focus, CFocus::Cancel | CFocus::Once | CFocus::Replace)
    }

    /// A key.
    pub(crate) fn handle_key(&mut self, key: KeyChord) -> Confirm {
        match classify(key) {
            K::Esc => return Confirm::Answer(TrustAnswer::Reject),
            K::Tab => self.move_focus(true),
            K::BackTab => self.move_focus(false),
            K::Enter => {
                return match self.focus {
                    CFocus::Field => {
                        if self.matches() {
                            self.mismatch = false;
                            self.focus = CFocus::Once;
                        } else {
                            self.mismatch = true;
                        }
                        Confirm::None
                    }
                    CFocus::Details => Confirm::Details,
                    CFocus::Cancel => Confirm::Answer(TrustAnswer::Reject),
                    CFocus::Once if self.enabled(CFocus::Once) => {
                        Confirm::Answer(TrustAnswer::TrustOnce)
                    }
                    CFocus::Replace if self.enabled(CFocus::Replace) => {
                        Confirm::Answer(TrustAnswer::AlwaysTrust)
                    }
                    _ => Confirm::None,
                };
            }
            K::Alt('o') if self.enabled(CFocus::Once) => {
                return Confirm::Answer(TrustAnswer::TrustOnce);
            }
            K::Alt('r') if self.enabled(CFocus::Replace) => {
                return Confirm::Answer(TrustAnswer::AlwaysTrust);
            }
            K::Alt('c') => return Confirm::Answer(TrustAnswer::Reject),
            K::Alt('d') if self.has_details => return Confirm::Details,
            K::Left if self.on_button() => {
                let i = step_focus(self.index(), CFOCUS.len(), false, |i| {
                    matches!(CFOCUS[i], CFocus::Cancel | CFocus::Once | CFocus::Replace)
                        && self.enabled(CFOCUS[i])
                });
                self.focus = CFOCUS[i];
            }
            K::Right if self.on_button() => {
                let i = step_focus(self.index(), CFOCUS.len(), true, |i| {
                    matches!(CFOCUS[i], CFocus::Cancel | CFocus::Once | CFocus::Replace)
                        && self.enabled(CFOCUS[i])
                });
                self.focus = CFOCUS[i];
            }
            _ if self.focus == CFocus::Field
                && self.field.handle_key(key) == WidgetOutcome::Changed =>
            {
                self.mismatch = false;
            }
            _ => {}
        }
        Confirm::None
    }

    /// Paste into the field.
    pub(crate) fn handle_paste(&mut self, text: &str) {
        if self.focus == CFocus::Field {
            self.field.handle_paste(text);
            self.mismatch = false;
        }
    }

    /// Types `text` into the field (tests).
    #[cfg(test)]
    pub(crate) fn type_text(&mut self, text: &str) {
        self.field.set_value(text);
    }

    /// The `Details…` stop has the focus.
    pub(crate) fn details_focused(&self) -> bool {
        self.focus == CFocus::Details
    }

    /// The `Continue only if…` lines, the host-name field and the buttons.
    pub(crate) fn rows(&self, body: &mut Body, width: usize, cx: &BodyCx) {
        body.para(
            &format!(
                "Continue only if you know why the {} changed. Type the host name to enable the trust buttons:",
                self.what
            ),
            width,
            Style::default(),
        );
        let field_w = u16::try_from(width.saturating_sub(LABEL_W + 2).min(40)).unwrap_or(40);
        let row = body.push(Row::Input {
            label: Line::from(pad_label("Host name:")),
            field: 0,
            width: field_w,
            focused: self.focus == CFocus::Field,
            enabled: true,
            suffix: self
                .mismatch
                .then(|| Span::styled("does not match", cx.danger())),
        });
        if self.focus == CFocus::Field {
            body.focus_row = row;
        }
        if !self.can_save {
            body.blank();
            body.para(
                &format!(
                    "The vault is locked: the new {} can only be trusted for this session.",
                    self.what
                ),
                width,
                Style::default(),
            );
        }
        body.blank();
        let mut buttons = vec![
            Btn::new("Cancel", self.focus == CFocus::Cancel),
            Btn {
                enabled: self.matches(),
                ..Btn::new("Trust once", self.focus == CFocus::Once)
            },
        ];
        if self.can_save {
            buttons.push(Btn {
                enabled: self.matches(),
                danger: true,
                ..Btn::new(
                    if self.what == "key" {
                        "Replace trusted key"
                    } else {
                        "Replace trusted certificate"
                    },
                    self.focus == CFocus::Replace,
                )
            });
        }
        let row = body.push(Row::Buttons(buttons));
        if self.on_button() {
            body.focus_row = row;
        }
    }

    /// Draws the host-name field.
    pub(crate) fn draw_field(
        &self,
        frame: &mut Frame,
        area: Rect,
        cx: &WidgetCx,
    ) -> Option<Position> {
        self.field.render(frame, area, cx);
        self.field.cursor(area)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UFocus {
    Always,
    Trust,
    Cancel,
}

const UFOCUS: [UFocus; 3] = [UFocus::Always, UFocus::Trust, UFocus::Cancel];

#[derive(Debug)]
enum Variant {
    Unknown { always: bool, focus: UFocus },
    Changed(ChangedConfirm),
}

/// The host key dialog: unknown (`changed == None`) or changed.
#[derive(Debug)]
pub(crate) struct HostKeyDialog {
    p: HostKeyPrompt,
    variant: Variant,
}

impl HostKeyDialog {
    /// The dialog for `p`.
    pub(crate) fn new(p: HostKeyPrompt) -> Self {
        let variant = if p.changed.is_some() {
            Variant::Changed(ChangedConfirm::new(&p.host, p.can_save, false, "key"))
        } else {
            Variant::Unknown {
                always: p.can_save,
                focus: UFocus::Trust,
            }
        };
        Self { p, variant }
    }

    /// The typed-host-name part (tests).
    #[cfg(test)]
    pub(crate) fn confirm_mut(&mut self) -> Option<&mut ChangedConfirm> {
        match &mut self.variant {
            Variant::Changed(c) => Some(c),
            Variant::Unknown { .. } => None,
        }
    }

    fn answer(a: TrustAnswer) -> Step {
        Step::Answer(PromptResponse::HostKey(a))
    }

    fn unknown_body(&self, always: bool, focus: UFocus, width: usize, cx: &BodyCx) -> Body {
        let mut b = Body::default();
        b.para(
            "The server's host key is not known. You have no guarantee that the server is the computer you think it is.",
            width,
            Style::default(),
        );
        b.blank();
        for l in host_key_lines(&self.p, width) {
            b.line(l);
        }
        for t in &self.p.other_known_types {
            b.labeled(
                "Note:",
                &format!("This server also has a trusted {} key.", clean(t)),
                width,
                Style::default(),
            );
        }
        b.blank();
        let label = if self.p.can_save {
            "Always trust this host and save the key in the vault"
        } else {
            "Always trust this host (unlock the vault to save keys)"
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
        if focus != UFocus::Always {
            b.focus_row = row;
        }
        b
    }

    fn changed_body(&self, c: &ChangedConfirm, width: usize, cx: &BodyCx) -> Body {
        let mut b = Body::default();
        b.para(
            &format!(
                "The host key of {}:{} is not the one you trusted. Someone could be intercepting your connection (man-in-the-middle attack), or the server was reinstalled or its key was replaced.",
                clean(&self.p.host),
                self.p.port
            ),
            width,
            Style::default(),
        );
        b.blank();
        b.labeled(
            "Key type:",
            &key_type(&self.p.key_type, self.p.bits),
            width,
            Style::default(),
        );
        for old in self.p.changed.iter().flatten() {
            b.labeled(
                "Trusted:",
                &clean(&old.fingerprint_sha256),
                width,
                Style::default(),
            );
            let source = match &old.source {
                OldKeySource::Vault { added_at, .. } => {
                    format!("saved in the vault on {}", added_at.date())
                }
                OldKeySource::OpenSshFile { path, line } => {
                    format!("from {} line {line}", tilde(path))
                }
            };
            b.labeled("", &source, width, Style::default());
        }
        b.labeled(
            "New key:",
            &clean(&self.p.fingerprint_sha256),
            width,
            cx.danger(),
        );
        b.blank();
        c.rows(&mut b, width, cx);
        b
    }
}

impl PromptDialog for HostKeyDialog {
    fn kind(&self) -> &'static str {
        match self.variant {
            Variant::Unknown { .. } => "host_key_unknown",
            Variant::Changed(_) => "host_key_changed",
        }
    }

    fn title(&self, _unicode: bool) -> String {
        match self.variant {
            Variant::Unknown { .. } => "Unknown host key".to_owned(),
            Variant::Changed(_) => "WARNING: HOST KEY CHANGED".to_owned(),
        }
    }

    fn danger(&self) -> bool {
        matches!(self.variant, Variant::Changed(_))
    }

    fn handle_key(&mut self, key: KeyChord) -> Step {
        let can_save = self.p.can_save;
        match &mut self.variant {
            Variant::Changed(c) => match c.handle_key(key) {
                Confirm::Answer(a) => Self::answer(a),
                Confirm::None | Confirm::Details => Step::Continue,
            },
            Variant::Unknown { always, focus } => {
                let trust = |always: bool| {
                    Self::answer(if always && can_save {
                        TrustAnswer::AlwaysTrust
                    } else {
                        TrustAnswer::TrustOnce
                    })
                };
                let idx = UFOCUS.iter().position(|f| f == focus).unwrap_or(1);
                match classify(key) {
                    K::Esc | K::Plain('c') | K::Alt('c') => {
                        return Self::answer(TrustAnswer::Reject);
                    }
                    K::Plain('t') | K::Alt('t') => return trust(*always),
                    K::Space | K::Plain('a') | K::Alt('a') => {
                        if can_save {
                            *always = !*always;
                        }
                    }
                    K::Enter => {
                        return match focus {
                            UFocus::Cancel => Self::answer(TrustAnswer::Reject),
                            UFocus::Trust | UFocus::Always => trust(*always),
                        };
                    }
                    K::Tab | K::Down => {
                        *focus = UFOCUS[step_focus(idx, 3, true, |i| i > 0 || can_save)];
                    }
                    K::BackTab | K::Up => {
                        *focus = UFOCUS[step_focus(idx, 3, false, |i| i > 0 || can_save)];
                    }
                    K::Left if idx > 0 => *focus = UFocus::Trust,
                    K::Right if idx > 0 => *focus = UFocus::Cancel,
                    _ => {}
                }
                Step::Continue
            }
        }
    }

    fn handle_paste(&mut self, text: &str) {
        if let Variant::Changed(c) = &mut self.variant {
            c.handle_paste(text);
        }
    }

    fn body(&self, width: u16, cx: &BodyCx) -> Body {
        let width = usize::from(width);
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
            Variant::Changed(c) => c.draw_field(frame, area, cx),
            Variant::Unknown { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

    use super::*;
    use crate::components::prompts::tests::{changed_host_key, k, unknown_host_key};

    fn answer(step: Step) -> Option<TrustAnswer> {
        match step {
            Step::Answer(PromptResponse::HostKey(a)) => Some(a),
            Step::Answer(other) => panic!("unexpected {other:?}"),
            Step::Continue => None,
        }
    }

    #[test]
    fn changed_enter_everywhere_rejects() {
        for typed in ["", "wrong.example.com"] {
            // Walk every Tab stop; Enter on each answers Reject or nothing (the field).
            for tabs in 0..6 {
                let mut d = HostKeyDialog::new(changed_host_key(true));
                d.confirm_mut().unwrap().type_text(typed);
                for _ in 0..tabs {
                    assert!(answer(d.handle_key(k("tab"))).is_none());
                }
                let in_field = d.confirm_mut().unwrap().focus == CFocus::Field;
                let a = answer(d.handle_key(k("enter")));
                if in_field {
                    assert_eq!(a, None, "Enter in the field never answers");
                    // and the trust buttons stay unreachable
                    assert_eq!(d.confirm_mut().unwrap().focus, CFocus::Field);
                } else {
                    assert_eq!(a, Some(TrustAnswer::Reject), "typed {typed:?}, {tabs} tabs");
                }
            }
            let mut d = HostKeyDialog::new(changed_host_key(true));
            d.confirm_mut().unwrap().type_text(typed);
            assert_eq!(answer(d.handle_key(k("esc"))), Some(TrustAnswer::Reject));
            // Alt shortcuts of disabled buttons do nothing.
            assert_eq!(answer(d.handle_key(k("alt-o"))), None);
            assert_eq!(answer(d.handle_key(k("alt-r"))), None);
            // Tab never reaches Trust once / Replace.
            for _ in 0..10 {
                d.handle_key(k("tab"));
                let f = d.confirm_mut().unwrap().focus;
                assert!(matches!(f, CFocus::Field | CFocus::Cancel), "{f:?}");
            }
        }
    }

    #[test]
    fn changed_buttons_enabled_after_matching_host() {
        let mut d = HostKeyDialog::new(changed_host_key(true));
        // Initial focus Cancel; Shift-Tab to the field and type the host.
        d.handle_key(k("backtab"));
        for c in "  WEB01.Example.com ".chars() {
            d.handle_key(KeyChord::char(c));
        }
        assert!(d.confirm_mut().unwrap().matches());
        // Enter in the field moves to Trust once and does not answer.
        assert_eq!(answer(d.handle_key(k("enter"))), None);
        assert_eq!(d.confirm_mut().unwrap().focus, CFocus::Once);
        assert_eq!(answer(d.handle_key(k("tab"))), None);
        assert_eq!(d.confirm_mut().unwrap().focus, CFocus::Replace);
        assert_eq!(
            answer(d.handle_key(k("enter"))),
            Some(TrustAnswer::AlwaysTrust)
        );

        let mut d = HostKeyDialog::new(changed_host_key(true));
        d.confirm_mut().unwrap().type_text("web01.example.com");
        assert_eq!(
            answer(d.handle_key(k("alt-o"))),
            Some(TrustAnswer::TrustOnce)
        );

        // Mismatch: "does not match" and no answer.
        let mut d = HostKeyDialog::new(changed_host_key(true));
        d.handle_key(k("backtab"));
        d.handle_key(KeyChord::char('x'));
        assert_eq!(answer(d.handle_key(k("enter"))), None);
        assert!(d.confirm_mut().unwrap().mismatch);

        // Vault locked: no Replace button.
        let mut d = HostKeyDialog::new(changed_host_key(false));
        d.confirm_mut().unwrap().type_text("web01.example.com");
        assert_eq!(answer(d.handle_key(k("alt-r"))), None);
        for _ in 0..6 {
            d.handle_key(k("tab"));
            assert_ne!(d.confirm_mut().unwrap().focus, CFocus::Replace);
        }
    }

    #[test]
    fn unknown_answers_trust_once_always_reject() {
        let d = || HostKeyDialog::new(unknown_host_key(true));
        assert_eq!(
            answer(d().handle_key(k("enter"))),
            Some(TrustAnswer::AlwaysTrust)
        );
        assert_eq!(
            answer(d().handle_key(k("t"))),
            Some(TrustAnswer::AlwaysTrust)
        );
        let mut x = d();
        x.handle_key(k("space"));
        assert_eq!(
            answer(x.handle_key(k("enter"))),
            Some(TrustAnswer::TrustOnce)
        );
        let mut x = d();
        x.handle_key(k("a"));
        assert_eq!(
            answer(x.handle_key(k("alt-t"))),
            Some(TrustAnswer::TrustOnce)
        );
        assert_eq!(answer(d().handle_key(k("c"))), Some(TrustAnswer::Reject));
        assert_eq!(answer(d().handle_key(k("esc"))), Some(TrustAnswer::Reject));
        let mut x = d();
        x.handle_key(k("tab"));
        assert_eq!(answer(x.handle_key(k("enter"))), Some(TrustAnswer::Reject));
        // Checkbox focused: Enter = default button (Trust).
        let mut x = d();
        x.handle_key(k("backtab"));
        assert_eq!(
            answer(x.handle_key(k("enter"))),
            Some(TrustAnswer::AlwaysTrust)
        );
        // Vault locked: unchecked and disabled, Trust = TrustOnce.
        let mut x = HostKeyDialog::new(unknown_host_key(false));
        x.handle_key(k("a"));
        x.handle_key(k("backtab"));
        x.handle_key(k("backtab"));
        assert_eq!(
            answer(x.handle_key(k("enter"))),
            Some(TrustAnswer::TrustOnce)
        );
    }
}
