//! The prompt queue (T69 rules 1–8): ordering, auto-open, the input guard, withdrawn
//! prompts, suspension while the vault is locked, and drawing the visible prompt.

use std::{cell::Cell, collections::VecDeque, fmt, time::Duration};

use courier_ftp_core::{
    events::{PromptId, PromptKind, PromptRequest, PromptResponse, SessionId},
    secret::SecretString,
};
use ratatui::{Frame, layout::Rect};
use tokio::time::Instant;
use tracing::debug;

use super::{
    CredentialField, Pending, PromptDialog, PromptEnv, build_dialog, kind_name,
    layout::{BodyCx, DIALOG_W, MIN_W, draw_prompt_frame, render_body},
};
use crate::{
    app::Mode,
    components::{
        DrawCx,
        dialog::{MIN_SCREEN, dim_screen, draw_too_small},
    },
    keymap::chord::KeyChord,
};

/// Keys pressed this soon after a prompt opens are ignored.
pub(crate) const INPUT_GUARD: Duration = Duration::from_millis(500);
/// A background prompt opens by itself only after this long without keys.
pub(crate) const BACKGROUND_IDLE: Duration = Duration::from_secs(2);
/// How long "Prompt withdrawn" stays on the status bar (an Info message: 3 s).
pub(crate) const WITHDRAWN_MESSAGE: &str = "Prompt withdrawn: the connection was closed";

/// Where a prompt comes from, decided by the app when the event arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PromptOrigin {
    /// The browsing session of the active tab (the user just asked to connect/list).
    Foreground,
    /// Transfer sessions (T41), other tabs, anything else.
    Background,
}

/// What the app's focus looks like, for the auto-open rules.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UiFocusState {
    /// The key table in effect (without the prompt).
    pub mode: Mode,
    /// A non-prompt modal is open.
    pub other_dialog_open: bool,
    /// The vault is locked (T60).
    pub vault_locked: bool,
}

/// What a [`PromptQueue::tick`] changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PromptTick {
    /// A prompt dialog opened.
    Opened(PromptId),
    /// The visible prompt was withdrawn and its dialog closed.
    Withdrawn(PromptId),
    /// The number of waiting prompts changed (a queued prompt was withdrawn).
    BadgeChanged,
}

/// A prompt the user answered.
#[derive(Debug)]
pub(crate) struct PromptAnswered {
    /// The prompt.
    pub id: PromptId,
    /// Its session.
    pub session: SessionId,
    /// Kind name (logs).
    pub kind: &'static str,
    /// The requester was still waiting (false: "Prompt withdrawn").
    pub delivered: bool,
    /// A typed secret to remember or save once the server accepts it (rule 9).
    pub pending: Option<Pending>,
}

#[derive(Debug)]
struct Queued {
    req: PromptRequest,
    origin: PromptOrigin,
}

struct Visible {
    req: PromptRequest,
    origin: PromptOrigin,
    dialog: Box<dyn PromptDialog>,
    opened_at: Instant,
    scroll: Cell<usize>,
    too_small: Cell<bool>,
}

impl fmt::Debug for Visible {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Visible")
            .field("id", &self.req.id)
            .field("origin", &self.origin)
            .field("dialog", &self.dialog)
            .finish_non_exhaustive()
    }
}

/// Queue of core prompts; at most one is visible.
#[derive(Debug, Default)]
pub(crate) struct PromptQueue {
    foreground: VecDeque<Queued>,
    background: VecDeque<Queued>,
    visible: Option<Visible>,
    last_key: Option<Instant>,
    suspended: bool,
    open_requested: bool,
    env: PromptEnv,
}

impl PromptQueue {
    /// Formats and clock for the dialogs built from now on.
    pub(crate) fn set_env(&mut self, env: PromptEnv) {
        self.env = env;
    }

    /// Queues `req` (rule 3: foreground before background, FIFO within each).
    pub(crate) fn push(&mut self, req: PromptRequest, origin: PromptOrigin, now: Instant) {
        let _ = now;
        debug!(
            prompt_id = req.id.get(),
            kind = kind_name(&req.kind),
            ?origin,
            "prompt queued"
        );
        let q = Queued { req, origin };
        match origin {
            PromptOrigin::Foreground => self.foreground.push_back(q),
            PromptOrigin::Background => self.background.push_back(q),
        }
    }

    /// Prompts waiting (not the visible one).
    pub(crate) fn queued_len(&self) -> usize {
        self.foreground.len() + self.background.len()
    }

    /// A prompt dialog is visible.
    pub(crate) fn is_visible(&self) -> bool {
        self.visible.is_some()
    }

    /// The visible prompt's id.
    #[cfg(test)]
    pub(crate) fn visible_id(&self) -> Option<PromptId> {
        self.visible.as_ref().map(|v| v.req.id)
    }

    /// The visible prompt's kind name.
    #[cfg(test)]
    pub(crate) fn visible_kind(&self) -> Option<&'static str> {
        self.visible.as_ref().map(|v| v.dialog.kind())
    }

    /// Called every tick and after every key: drops withdrawn prompts and applies the
    /// auto-open rules (rule 4).
    pub(crate) fn tick(&mut self, now: Instant, ui: &UiFocusState) -> Vec<PromptTick> {
        let mut out = Vec::new();
        let before = self.queued_len();
        for q in [&mut self.foreground, &mut self.background] {
            q.retain(|x| {
                let gone = x.req.is_withdrawn();
                if gone {
                    debug!(prompt_id = x.req.id.get(), "queued prompt withdrawn");
                }
                !gone
            });
        }
        if self.visible.as_ref().is_some_and(|v| v.req.is_withdrawn())
            && let Some(v) = self.visible.take()
        {
            debug!(prompt_id = v.req.id.get(), "visible prompt withdrawn");
            out.push(PromptTick::Withdrawn(v.req.id));
        }
        let withdrawn_queued = self.queued_len() != before;
        let can_open =
            self.visible.is_none() && !self.suspended && !ui.other_dialog_open && !ui.vault_locked;
        if can_open {
            let next = if let Some(q) = self.foreground.pop_front() {
                Some(q)
            } else if !self.background.is_empty()
                && (self.open_requested || (background_mode_ok(ui.mode) && self.idle(now)))
            {
                self.background.pop_front()
            } else {
                None
            };
            if let Some(q) = next {
                out.push(PromptTick::Opened(q.req.id));
                self.open(q, now);
            }
        }
        if out.is_empty() && withdrawn_queued {
            out.push(PromptTick::BadgeChanged);
        }
        out
    }

    fn idle(&self, now: Instant) -> bool {
        self.last_key
            .is_none_or(|k| now.saturating_duration_since(k) >= BACKGROUND_IDLE)
    }

    fn open(&mut self, q: Queued, now: Instant) {
        self.open_requested = false;
        let dialog = build_dialog(&q.req.kind, &self.env);
        debug!(
            prompt_id = q.req.id.get(),
            kind = dialog.kind(),
            "prompt opened"
        );
        self.visible = Some(Visible {
            req: q.req,
            origin: q.origin,
            dialog,
            opened_at: now,
            scroll: Cell::new(0),
            too_small: Cell::new(false),
        });
    }

    /// `Action::OpenNextPrompt`: the next prompt opens on the next [`Self::tick`] that
    /// is allowed to open one (at once, or when the open dialog closes). Returns
    /// false when nothing waits.
    pub(crate) fn open_next(&mut self, now: Instant) -> bool {
        let _ = now;
        if self.queued_len() == 0 {
            return false;
        }
        self.open_requested = true;
        true
    }

    /// Status-bar badge: `⚠ 2 prompts` (ASCII `! 2 prompts`); `None` if nothing waits.
    pub(crate) fn badge(&self, unicode: bool) -> Option<String> {
        let n = self.queued_len();
        if n == 0 {
            return None;
        }
        let mark = if unicode { "⚠" } else { "!" };
        let s = if n == 1 { "" } else { "s" };
        Some(format!("{mark} {n} prompt{s}"))
    }

    /// Remembers a key press outside the prompt dialog (background prompts wait for
    /// 2 s without keys).
    pub(crate) fn note_key(&mut self, now: Instant) {
        self.last_key = Some(now);
    }

    /// The input guard is active for the visible prompt.
    fn guarded(&self, now: Instant) -> bool {
        self.visible
            .as_ref()
            .is_some_and(|v| now.saturating_duration_since(v.opened_at) < INPUT_GUARD)
    }

    /// A key for the visible prompt (ignored during the input guard and while the
    /// terminal is too small to show it).
    ///
    /// Keys answered here do not count for the background idle rule: that rule keeps
    /// prompts from taking keys typed elsewhere ([`Self::note_key`]).
    pub(crate) fn handle_key(&mut self, key: KeyChord, now: Instant) -> Option<PromptAnswered> {
        if self.guarded(now) {
            return None;
        }
        let v = self.visible.as_mut()?;
        if v.too_small.get() {
            return None;
        }
        match v.dialog.handle_key(key) {
            super::Step::Continue => None,
            super::Step::Answer(r) => self.answer(r),
        }
    }

    /// Bracketed paste into the visible prompt.
    pub(crate) fn handle_paste(&mut self, text: &str) {
        let now = Instant::now();
        if self.guarded(now) {
            return;
        }
        if let Some(v) = self.visible.as_mut()
            && !v.too_small.get()
        {
            v.dialog.handle_paste(text);
        }
    }

    /// A status-line message of the visible dialog (paste cut).
    pub(crate) fn take_notice(&mut self) -> Option<String> {
        self.visible.as_mut().and_then(|v| v.dialog.take_notice())
    }

    fn answer(&mut self, response: PromptResponse) -> Option<PromptAnswered> {
        let v = self.visible.take()?;
        let pending = pending_of(&v.req.kind, &response, v.req.session);
        let id = v.req.id;
        let session = v.req.session;
        let kind = kind_name(&v.req.kind);
        debug!(prompt_id = id.get(), kind, "prompt answered");
        // Dropping the dialog zeroizes its fields.
        drop(v.dialog);
        let delivered = v.req.respond(response);
        Some(PromptAnswered {
            id,
            session,
            kind,
            delivered,
            pending: if delivered { pending } else { None },
        })
    }

    /// Vault locked: the visible prompt goes back to the front of the queue (typed
    /// text discarded) and nothing opens until unlocked.
    pub(crate) fn set_suspended(&mut self, suspended: bool) {
        self.suspended = suspended;
        if suspended && let Some(v) = self.visible.take() {
            let q = Queued {
                req: v.req,
                origin: v.origin,
            };
            match q.origin {
                PromptOrigin::Foreground => self.foreground.push_front(q),
                PromptOrigin::Background => self.background.push_front(q),
            }
        }
    }

    /// Draws the visible prompt over the dimmed screen.
    pub(crate) fn render(&mut self, frame: &mut Frame, area: Rect, cx: &DrawCx) {
        let Some(v) = self.visible.as_ref() else {
            return;
        };
        dim_screen(frame);
        let guard = cx.now.saturating_duration_since(v.opened_at) < INPUT_GUARD;
        let bcx = BodyCx {
            theme: cx.theme,
            symbols: cx.symbols,
            guard,
        };
        let w = DIALOG_W.min(area.width.saturating_sub(4));
        if area.width < MIN_SCREEN.0 || area.height < MIN_SCREEN.1 || w < MIN_W {
            v.too_small.set(true);
            draw_too_small(frame, area, cx);
            return;
        }
        let body = v.dialog.body(w - 4, &bcx);
        let rows = u16::try_from(body.rows.len()).unwrap_or(u16::MAX);
        let h = rows.saturating_add(2).min(area.height.saturating_sub(2));
        if h < 5 {
            v.too_small.set(true);
            draw_too_small(frame, area, cx);
            return;
        }
        v.too_small.set(false);
        let r = Rect {
            x: area.x + (area.width - w) / 2,
            y: area.y + (area.height - h) / 2,
            width: w,
            height: h,
        };
        let inner = draw_prompt_frame(
            frame,
            r,
            &v.dialog.title(cx.symbols.unicode),
            v.dialog.danger(),
            cx,
        );
        let dialog = &v.dialog;
        render_body(
            frame,
            inner,
            &body,
            &v.scroll,
            &bcx,
            cx.now,
            |f, field, rect, wcx| dialog.draw_input(f, field, rect, wcx),
        );
    }
}

/// Background prompts open by themselves only where no text is being typed.
///
/// The spec says "`mode == Normal`"; the file lists' and log's modes (`FileList`,
/// `Log`, …) are browsing modes as well, so only the text and dialog modes block.
fn background_mode_ok(mode: Mode) -> bool {
    !matches!(
        mode,
        Mode::Input | Mode::Filter | Mode::Dialog | Mode::SiteManager
    )
}

/// The pending credential of a secret answer with "remember" or "save" checked.
fn pending_of(kind: &PromptKind, response: &PromptResponse, session: SessionId) -> Option<Pending> {
    let PromptResponse::Secret {
        value,
        remember_session,
        save_in_vault,
    } = response
    else {
        return None;
    };
    if !remember_session && !save_in_vault {
        return None;
    }
    let (key, field) = match kind {
        PromptKind::Password(p) => (p.cache_key.clone(), CredentialField::Password),
        PromptKind::KeyPassphrase(p) => (p.cache_key.clone(), CredentialField::KeyPassphrase),
        _ => return None,
    };
    Some(Pending {
        session,
        key,
        field,
        value: SecretString::from(value.expose()),
        remember: *remember_session,
        save: *save_in_vault,
        since: Instant::now(),
    })
}

#[cfg(test)]
mod tests;
