//! Key → action resolution by mode: the sequence state machine with a timeout, `esc`
//! cancel, the re-resolve rule and the which-key timer (T51; sverb `keymap.rs`).

use std::time::Duration;

use tokio::time::Instant;

pub(crate) use super::map::{KeymapProblem, RawKeymap};
use super::{
    chord::{KeyChord, display_sequence},
    map::{Keymap, Lookup},
};
use crate::{action::Action, app::Mode, config::Config};

/// A prefix pending this long opens the which-key popup.
pub(crate) const WHICH_KEY_DELAY: Duration = Duration::from_millis(500);

/// The default `interface.key_sequence_timeout_ms`.
#[cfg(test)]
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1000);

/// The result of feeding one key to the resolver.
#[derive(Debug)]
pub(crate) enum Resolution {
    /// A binding matched.
    Action(Action),
    /// The key starts or continues a sequence; wait for more.
    Pending,
    /// No binding.
    Unbound,
    /// `esc` cancelled a pending sequence (the key is consumed).
    Cancelled,
}

/// The keymap plus the pending-sequence state.
#[derive(Debug, Clone)]
pub(crate) struct KeyResolver {
    keymap: Keymap,
    pending: Vec<KeyChord>,
    mode: Mode,
    deadline: Option<Instant>,
    timeout: Duration,
    which_key_at: Option<Instant>,
}

impl KeyResolver {
    /// The keymap of `config` (built-in defaults ⊕ user `keybindings`) with its
    /// `interface.key_sequence_timeout_ms`. Never fails: problems are returned.
    pub(crate) fn from_config(config: &Config) -> (Self, Vec<KeymapProblem>) {
        let (keymap, problems) =
            Keymap::build(crate::config::default_keybindings(), &config.keybindings);
        let timeout =
            Duration::from_millis(u64::from(config.settings.interface.key_sequence_timeout_ms));
        (Self::new(keymap, timeout), problems)
    }

    /// A resolver for `keymap`.
    pub(crate) fn new(keymap: Keymap, timeout: Duration) -> Self {
        Self {
            keymap,
            pending: Vec::new(),
            mode: Mode::Normal,
            deadline: None,
            timeout,
            which_key_at: None,
        }
    }

    /// Builds from raw maps with the default timeout (tests).
    #[cfg(test)]
    pub(crate) fn build(defaults: &RawKeymap, user: &RawKeymap) -> (Self, Vec<KeymapProblem>) {
        let (keymap, problems) = Keymap::build(defaults, user);
        (Self::new(keymap, DEFAULT_TIMEOUT), problems)
    }

    /// The effective keymap.
    pub(crate) fn keymap(&self) -> &Keymap {
        &self.keymap
    }

    /// A sequence is pending.
    pub(crate) fn is_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Drops the pending sequence.
    pub(crate) fn clear(&mut self) {
        self.pending.clear();
        self.deadline = None;
        self.which_key_at = None;
    }

    /// Whether `key` would complete or continue the pending sequence in `mode` (or
    /// cancel it with `esc`). False when nothing is pending.
    pub(crate) fn takes(&self, key: KeyChord, mode: Mode, now: Instant) -> bool {
        if self.pending.is_empty() || mode != self.mode || self.expired(now) {
            return false;
        }
        if key == KeyChord::key(crossterm::event::KeyCode::Esc) {
            return true;
        }
        let mut seq = self.pending.clone();
        seq.push(key);
        !matches!(self.keymap.lookup(mode, &seq), Lookup::None)
    }

    fn expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|d| now >= d)
    }

    /// Feeds one key typed at `now` while `mode` is in effect.
    pub(crate) fn resolve(&mut self, key: KeyChord, mode: Mode, now: Instant) -> Resolution {
        if self.expired(now) {
            self.clear();
        }
        if !self.pending.is_empty() {
            if key == KeyChord::key(crossterm::event::KeyCode::Esc) {
                self.clear();
                return Resolution::Cancelled;
            }
            if mode != self.mode {
                self.clear();
            }
        }
        let had_pending = !self.pending.is_empty();
        let mut seq = std::mem::take(&mut self.pending);
        seq.push(key);
        match self.step(seq, mode, now) {
            Resolution::Unbound if had_pending => {
                // A stray prefix: forget it and try the key on its own.
                self.clear();
                self.step(vec![key], mode, now)
            }
            r => r,
        }
    }

    fn step(&mut self, seq: Vec<KeyChord>, mode: Mode, now: Instant) -> Resolution {
        match self.keymap.lookup(mode, &seq) {
            Lookup::Exact(a) => {
                self.clear();
                Resolution::Action(a)
            }
            Lookup::Prefix => {
                self.pending = seq;
                self.mode = mode;
                self.deadline = Some(now + self.timeout);
                self.which_key_at = Some(now + WHICH_KEY_DELAY);
                Resolution::Pending
            }
            Lookup::None => {
                self.clear();
                Resolution::Unbound
            }
        }
    }

    /// When something time-based happens next: the sequence times out or the which-key
    /// popup opens (whichever is earlier and still ahead).
    pub(crate) fn deadline(&self) -> Option<Instant> {
        let deadline = self.deadline?;
        match self.which_key_at {
            Some(w) if w < deadline => Some(w),
            _ => Some(deadline),
        }
    }

    /// Time passed: drops an expired sequence and marks the which-key popup as due.
    /// Returns true when the screen changes (popup opened or sequence dropped).
    pub(crate) fn on_timeout(&mut self, now: Instant) -> bool {
        if self.expired(now) {
            self.clear();
            return true;
        }
        if self.which_key_at.is_some_and(|w| now >= w) {
            // The popup is drawn from now on; only the timeout remains ahead.
            self.which_key_at = None;
            return true;
        }
        false
    }

    /// The keys typed so far of a pending sequence (`"ctrl-x"`, `"g"`).
    pub(crate) fn pending_display(&self) -> Option<String> {
        (!self.pending.is_empty()).then(|| display_sequence(&self.pending))
    }

    /// The mode the pending sequence was started in.
    pub(crate) fn pending_mode(&self) -> Option<Mode> {
        (!self.pending.is_empty()).then_some(self.mode)
    }

    /// The which-key entries once the prefix has been pending for
    /// [`WHICH_KEY_DELAY`].
    pub(crate) fn which_key(&self, now: Instant) -> Option<Vec<(KeyChord, Action)>> {
        if self.pending.is_empty() || self.which_key_at.is_some_and(|w| now < w) {
            return None;
        }
        Some(self.keymap.continuations(self.mode.chain(), &self.pending))
    }
}
