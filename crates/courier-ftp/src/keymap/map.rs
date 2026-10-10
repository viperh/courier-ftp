//! The effective keymap: the built-in tables of `config/config.json` with the user's
//! `keybindings` on top, checked for bad entries, duplicates and prefix conflicts
//! (T51; adapted from sverb `keymap/keymap.rs` and `validate.rs`, D13).

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
};

use strum::IntoEnumIterator;

use super::chord::{KeyChord, display_sequence, parse_sequence, shorten};
use crate::{action::Action, app::Mode};

/// `keybindings` exactly as written in a config file: mode name → key string → action
/// name. Plain strings, so reading a config never fails on a bad key.
pub(crate) type RawKeymap = BTreeMap<String, BTreeMap<String, String>>;

/// The value that removes a binding.
pub(crate) const UNBIND: &str = "none";

/// At most this many bindings per mode are read from one source.
pub(crate) const MAX_BINDINGS_PER_MODE: usize = 1000;

/// A `keybindings` entry that was skipped, or is unreachable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeymapProblem {
    /// Mode name as written.
    pub mode: String,
    /// Key string as written (shortened to 64 bytes).
    pub key: String,
    /// Action name as written.
    pub action: String,
    /// What is wrong.
    pub kind: ProblemKind,
}

/// What is wrong with a `keybindings` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProblemKind {
    /// No such mode (reported once per mode, with an empty key).
    UnknownMode,
    /// The key string does not parse (the parser's reason).
    BadKey(String),
    /// More than [`MAX_SEQUENCE_LEN`](super::chord::MAX_SEQUENCE_LEN) chords.
    SequenceTooLong,
    /// Not a bindable action name (or an internal one).
    UnknownAction,
    /// Two key strings of one source and mode are the same sequence; this entry (the
    /// later one in sorted order) is ignored.
    Duplicate {
        /// The key string that is kept.
        other_key: String,
    },
    /// The binding can never fire in `mode`'s chain because of a prefix conflict.
    Unreachable {
        /// The mode whose chain has the conflict.
        mode: Mode,
        /// The binding that wins, as `Mode."keys": "Action"`.
        blocked_by: String,
    },
}

impl fmt::Display for KeymapProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (mode, key, action) = (&self.mode, &self.key, &self.action);
        match &self.kind {
            ProblemKind::UnknownMode => {
                let known: Vec<String> = Mode::iter().map(|m| format!("{m:?}")).collect();
                write!(
                    f,
                    "keybindings.{mode}: unknown mode (expected one of {})",
                    known.join(", ")
                )
            }
            ProblemKind::BadKey(reason) => {
                write!(f, "keybindings.{mode}.\"{key}\": invalid key: {reason}")
            }
            ProblemKind::SequenceTooLong => write!(
                f,
                "keybindings.{mode}.\"{key}\": invalid key: sequences are limited to {} keys",
                super::chord::MAX_SEQUENCE_LEN
            ),
            ProblemKind::UnknownAction => write!(
                f,
                "keybindings.{mode}.\"{key}\": unknown action \"{action}\" (see docs/keybindings.md)"
            ),
            ProblemKind::Duplicate { other_key } => write!(
                f,
                "keybindings.{mode}.\"{other_key}\" and \"{key}\" are the same key; \"{key}\" is ignored"
            ),
            ProblemKind::Unreachable {
                mode: in_mode,
                blocked_by,
            } => write!(
                f,
                "keybindings.{blocked_by} makes \"{key}\" ({action}) unreachable in mode {in_mode:?}"
            ),
        }
    }
}

/// Result of looking up a (partial) key sequence.
#[derive(Debug, Clone)]
pub(crate) enum Lookup {
    /// A table of the chain binds exactly this sequence.
    Exact(Action),
    /// A longer binding starts with this sequence.
    Prefix,
    /// Nothing.
    None,
}

/// One mode's bindings.
#[derive(Debug, Default, Clone)]
struct Table {
    bindings: HashMap<Vec<KeyChord>, Action>,
    /// Every proper prefix of a bound sequence.
    prefixes: HashSet<Vec<KeyChord>>,
}

impl Table {
    fn rebuild_prefixes(&mut self) {
        self.prefixes = self
            .bindings
            .keys()
            .flat_map(|seq| (1..seq.len()).map(|n| seq[..n].to_vec()))
            .collect();
    }

    fn lookup(&self, seq: &[KeyChord]) -> Lookup {
        if let Some(a) = self.bindings.get(seq) {
            return Lookup::Exact(a.clone());
        }
        if self.prefixes.contains(seq) {
            return Lookup::Prefix;
        }
        Lookup::None
    }
}

/// One row of the effective bindings (help overlay, docs).
#[derive(Debug, Clone)]
pub(crate) struct BindingRow {
    /// The table the binding comes from.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "shown by the settings screen (T68)")
    )]
    pub mode: Mode,
    /// The key sequence.
    pub keys: Vec<KeyChord>,
    /// The action.
    pub action: Action,
}

impl BindingRow {
    /// `"ctrl-x d"`.
    pub(crate) fn keys_text(&self) -> String {
        display_sequence(&self.keys)
    }
}

/// The effective keymap (defaults ⊕ user).
#[derive(Debug, Default, Clone)]
pub(crate) struct Keymap {
    tables: HashMap<Mode, Table>,
}

/// One parsed entry before insertion (`action: None` unbinds).
struct Entry {
    seq: Vec<KeyChord>,
    action: Option<Action>,
}

impl Keymap {
    /// Builds the effective keymap. Never fails: problems are returned and the
    /// offending entries skipped (unreachable ones are kept).
    pub(crate) fn build(defaults: &RawKeymap, user: &RawKeymap) -> (Self, Vec<KeymapProblem>) {
        let mut me = Self::default();
        let mut problems = Vec::new();
        for raw in [defaults, user] {
            for (mode_name, entries) in raw {
                let Some(mode) = Mode::iter().find(|m| format!("{m:?}") == *mode_name) else {
                    problems.push(KeymapProblem {
                        mode: shorten(mode_name),
                        key: String::new(),
                        action: String::new(),
                        kind: ProblemKind::UnknownMode,
                    });
                    continue;
                };
                if entries.len() > MAX_BINDINGS_PER_MODE {
                    tracing::warn!(
                        mode = mode_name.as_str(),
                        "more than {MAX_BINDINGS_PER_MODE} key bindings; the rest are ignored"
                    );
                }
                let parsed = parse_entries(mode_name, entries, &mut problems);
                let table = me.tables.entry(mode).or_default();
                for e in parsed {
                    match e.action {
                        None => {
                            table.bindings.remove(&e.seq);
                        }
                        Some(a) => {
                            table.bindings.insert(e.seq, a);
                        }
                    }
                }
            }
        }
        for t in me.tables.values_mut() {
            t.rebuild_prefixes();
        }
        problems.extend(me.prefix_conflicts());
        (me, problems)
    }

    /// Looks `seq` up in `mode`'s chain, highest priority table first.
    pub(crate) fn lookup(&self, mode: Mode, seq: &[KeyChord]) -> Lookup {
        for m in mode.chain() {
            if let Some(t) = self.tables.get(m) {
                match t.lookup(seq) {
                    Lookup::None => {}
                    hit => return hit,
                }
            }
        }
        Lookup::None
    }

    /// The bindings of one table (not the chain), sorted by key text.
    pub(crate) fn table_rows(&self, mode: Mode) -> Vec<BindingRow> {
        let mut rows: Vec<BindingRow> = self
            .tables
            .get(&mode)
            .map(|t| {
                t.bindings
                    .iter()
                    .map(|(k, a)| BindingRow {
                        mode,
                        keys: k.clone(),
                        action: a.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        rows.sort_by_cached_key(|r| sort_key(&r.keys));
        rows
    }

    /// Effective bindings for `chain`, highest priority table first; a sequence bound in
    /// an earlier table hides the same sequence in later ones. Sorted by key within a
    /// table.
    pub(crate) fn bindings_for(&self, chain: &[Mode]) -> Vec<BindingRow> {
        let mut seen: HashSet<Vec<KeyChord>> = HashSet::new();
        let mut out = Vec::new();
        for m in chain {
            let rows: Vec<BindingRow> = self
                .table_rows(*m)
                .into_iter()
                .filter(|r| !seen.contains(&r.keys))
                .collect();
            seen.extend(rows.iter().map(|r| r.keys.clone()));
            out.extend(rows);
        }
        out
    }

    /// The chords that complete or continue `prefix` in `chain` with the action of the
    /// one-chord-longer binding (the which-key popup), sorted by key. A chord bound in a
    /// higher table hides the same chord in lower ones.
    pub(crate) fn continuations(
        &self,
        chain: &[Mode],
        prefix: &[KeyChord],
    ) -> Vec<(KeyChord, Action)> {
        let mut seen: HashSet<KeyChord> = HashSet::new();
        let mut out = Vec::new();
        for m in chain {
            let Some(t) = self.tables.get(m) else {
                continue;
            };
            for (seq, a) in &t.bindings {
                if seq.len() == prefix.len() + 1
                    && seq.starts_with(prefix)
                    && seen.insert(seq[prefix.len()])
                {
                    out.push((seq[prefix.len()], a.clone()));
                }
            }
        }
        out.sort_by_cached_key(|(k, _)| chord_order(k));
        out
    }

    /// Prefix conflicts in every mode's chain (rule 4).
    fn prefix_conflicts(&self) -> Vec<KeymapProblem> {
        let mut out = Vec::new();
        let mut reported: HashSet<(Mode, Vec<KeyChord>)> = HashSet::new();
        for mode in Mode::iter() {
            let chain = mode.chain();
            // Effective bindings with the index of their table in the chain.
            let mut eff: Vec<(usize, Mode, &Vec<KeyChord>, &Action)> = Vec::new();
            let mut seen: HashSet<&Vec<KeyChord>> = HashSet::new();
            for (i, m) in chain.iter().enumerate() {
                if let Some(t) = self.tables.get(m) {
                    let mut rows: Vec<_> = t.bindings.iter().collect();
                    rows.sort_by_cached_key(|(k, _)| sort_key(k));
                    for (seq, a) in rows {
                        if seen.insert(seq) {
                            eff.push((i, *m, seq, a));
                        }
                    }
                }
            }
            for &(pi, pm, p, pa) in &eff {
                for &(si, sm, s, sa) in &eff {
                    if s.len() <= p.len() || !s.starts_with(p) {
                        continue;
                    }
                    // The exact match wins when its table is the same or higher;
                    // otherwise the longer sequence's prefix match wins.
                    let ((um, useq, ua), (bm, bseq, ba)) = if pi <= si {
                        ((sm, s, sa), (pm, p, pa))
                    } else {
                        ((pm, p, pa), (sm, s, sa))
                    };
                    if !reported.insert((um, useq.clone())) {
                        continue;
                    }
                    out.push(KeymapProblem {
                        mode: format!("{um:?}"),
                        key: display_sequence(useq),
                        action: ua.to_string(),
                        kind: ProblemKind::Unreachable {
                            mode,
                            blocked_by: format!("{bm:?}.\"{}\": \"{ba}\"", display_sequence(bseq)),
                        },
                    });
                }
            }
        }
        out
    }
}

/// Parses one mode's entries of one source: bad keys, unknown actions and duplicates
/// become problems; `"none"` entries have `action: None`.
fn parse_entries(
    mode_name: &str,
    entries: &BTreeMap<String, String>,
    problems: &mut Vec<KeymapProblem>,
) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut first: HashMap<Vec<KeyChord>, &str> = HashMap::new();
    for (key, action_name) in entries.iter().take(MAX_BINDINGS_PER_MODE) {
        let problem = |kind| KeymapProblem {
            mode: mode_name.to_owned(),
            key: shorten(key),
            action: shorten(action_name),
            kind,
        };
        let seq = match parse_sequence(key) {
            Ok(seq) => seq,
            Err(e) if e.reason.starts_with("sequences are limited") => {
                problems.push(problem(ProblemKind::SequenceTooLong));
                continue;
            }
            Err(e) => {
                problems.push(problem(ProblemKind::BadKey(e.reason)));
                continue;
            }
        };
        let action = if action_name == UNBIND {
            None
        } else if let Some(a) = Action::bindable_from_name(action_name) {
            Some(a)
        } else {
            problems.push(problem(ProblemKind::UnknownAction));
            continue;
        };
        if let Some(other) = first.get(&seq) {
            problems.push(problem(ProblemKind::Duplicate {
                other_key: shorten(other),
            }));
            continue;
        }
        first.insert(seq.clone(), key);
        out.push(Entry { seq, action });
    }
    out
}

/// Which-key order: plain letters (case-insensitive, lower case first), digits, other
/// characters, then everything else by text.
fn chord_order(c: &KeyChord) -> (u8, String, bool) {
    let text = c.to_string();
    let class = match c.code {
        crossterm::event::KeyCode::Char(ch) if text.chars().count() == 1 => {
            if ch.is_alphabetic() {
                0
            } else if ch.is_ascii_digit() {
                1
            } else {
                2
            }
        }
        _ => 3,
    };
    (
        class,
        text.to_lowercase(),
        text.chars().any(char::is_uppercase),
    )
}

/// Sort order of key sequences: single characters before named keys, then by text.
fn sort_key(seq: &[KeyChord]) -> (usize, Vec<(bool, String)>) {
    (
        seq.len(),
        seq.iter()
            .map(|c| {
                let t = c.to_string();
                (t.chars().count() > 1, t)
            })
            .collect(),
    )
}
