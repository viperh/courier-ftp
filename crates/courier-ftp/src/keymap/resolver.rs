//! Key → action lookup by mode (T50: single chords; T51 replaces the internals with
//! sequences, a timeout and conflict checks, keeping this API).

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
};

use tokio::time::Instant;

use super::chord::KeyChord;
use crate::{action::Action, app::Mode, config::Config};

/// `keybindings` as written in a config file: mode name → key string → action name.
pub(crate) type RawKeymap = BTreeMap<String, BTreeMap<String, String>>;

/// A `keybindings` entry that was skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeymapProblem {
    /// Mode name as written.
    pub mode: String,
    /// Key string as written.
    pub key: String,
    /// Action name as written.
    pub action: String,
    /// What is wrong.
    pub kind: ProblemKind,
}

/// What is wrong with a `keybindings` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProblemKind {
    /// No such mode.
    UnknownMode,
    /// The key string does not parse.
    BadKey(String),
    /// No such bindable action.
    UnknownAction,
    /// Valid, but not supported yet (multi-key sequences arrive with T51).
    Unsupported(String),
}

impl fmt::Display for KeymapProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (mode, key, action) = (&self.mode, &self.key, &self.action);
        match &self.kind {
            ProblemKind::UnknownMode => write!(f, "keybindings: unknown mode `{mode}`"),
            ProblemKind::BadKey(reason) => {
                write!(f, "keybindings.{mode}: invalid key `{key}`: {reason}")
            }
            ProblemKind::UnknownAction => {
                write!(f, "keybindings.{mode}.{key}: unknown action `{action}`")
            }
            ProblemKind::Unsupported(why) => write!(f, "keybindings.{mode}.{key}: {why}"),
        }
    }
}

/// The result of feeding one key to the resolver.
#[derive(Debug)]
pub(crate) enum Resolution {
    /// A binding matched.
    Action(Action),
    /// The key starts a sequence; wait for more (T51).
    #[expect(dead_code, reason = "key sequences arrive with T51")]
    Pending,
    /// No binding.
    Unbound,
}

/// Effective key tables (built-in defaults ⊕ user config).
#[derive(Debug, Default)]
pub(crate) struct KeyResolver {
    tables: HashMap<Mode, HashMap<Vec<KeyChord>, Action>>,
}

impl KeyResolver {
    /// Builds the tables from the built-in defaults and the user's `keybindings`. Never
    /// fails: bad entries are skipped and returned.
    pub(crate) fn from_config(config: &Config) -> (Self, Vec<KeymapProblem>) {
        Self::build(crate::config::default_keybindings(), &config.keybindings)
    }

    /// Builds from raw maps; `user` entries replace defaults for the same chord.
    pub(crate) fn build(defaults: &RawKeymap, user: &RawKeymap) -> (Self, Vec<KeymapProblem>) {
        let mut me = Self::default();
        let mut problems = Vec::new();
        for raw in [defaults, user] {
            for (mode_name, entries) in raw {
                let problem = |key: &str, action: &str, kind| KeymapProblem {
                    mode: mode_name.clone(),
                    key: key.to_owned(),
                    action: action.to_owned(),
                    kind,
                };
                let Ok(mode) =
                    serde_json::from_value::<Mode>(serde_json::Value::String(mode_name.clone()))
                else {
                    problems.push(problem("", "", ProblemKind::UnknownMode));
                    continue;
                };
                let table = me.tables.entry(mode).or_default();
                for (key, action_name) in entries {
                    let chords: Result<Vec<KeyChord>, _> =
                        key.split_whitespace().map(str::parse).collect();
                    let chords = match chords {
                        Ok(c) if c.is_empty() => {
                            problems.push(problem(
                                key,
                                action_name,
                                ProblemKind::BadKey("empty key".into()),
                            ));
                            continue;
                        }
                        Ok(c) => c,
                        Err(e) => {
                            problems.push(problem(key, action_name, ProblemKind::BadKey(e.reason)));
                            continue;
                        }
                    };
                    let Some(action) = Action::bindable_from_name(action_name) else {
                        problems.push(problem(key, action_name, ProblemKind::UnknownAction));
                        continue;
                    };
                    if chords.len() > 1 {
                        problems.push(problem(
                            key,
                            action_name,
                            ProblemKind::Unsupported("key sequences are not supported yet".into()),
                        ));
                        continue;
                    }
                    table.insert(chords, action);
                }
            }
        }
        (me, problems)
    }

    /// Resolves `key` in `mode`'s chain.
    pub(crate) fn resolve(&mut self, key: KeyChord, mode: Mode, now: Instant) -> Resolution {
        let _ = now;
        let seq = [key];
        for m in mode.chain() {
            if let Some(a) = self.tables.get(m).and_then(|t| t.get(&seq[..])) {
                return Resolution::Action(a.clone());
            }
        }
        Resolution::Unbound
    }

    /// When a pending sequence times out (always None before T51).
    pub(crate) fn deadline(&self) -> Option<Instant> {
        None
    }

    /// A pending sequence timed out (no-op before T51).
    pub(crate) fn on_timeout(&mut self, now: Instant) {
        let _ = now;
    }

    /// The keys typed so far of a pending sequence (None before T51).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "shown by the status bar (T51, T57)")
    )]
    pub(crate) fn pending_display(&self) -> Option<String> {
        None
    }

    /// Effective bindings for `chain`, highest priority table first; a key bound in an
    /// earlier table hides the same key in later ones. Sorted by key within a table.
    pub(crate) fn bindings(&self, chain: &[Mode]) -> Vec<(Mode, Vec<KeyChord>, Action)> {
        let mut seen: HashSet<Vec<KeyChord>> = HashSet::new();
        let mut out = Vec::new();
        for m in chain {
            let Some(table) = self.tables.get(m) else {
                continue;
            };
            let mut rows: Vec<_> = table
                .iter()
                .filter(|(k, _)| !seen.contains(*k))
                .map(|(k, a)| (*m, k.clone(), a.clone()))
                .collect();
            rows.sort_by_cached_key(|(_, k, a)| (a.to_string(), display_keys(k)));
            seen.extend(rows.iter().map(|(_, k, _)| k.clone()));
            out.extend(rows);
        }
        out
    }
}

/// `"ctrl-x d"`.
pub(crate) fn display_keys(seq: &[KeyChord]) -> String {
    seq.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn raw(entries: &[(&str, &str, &str)]) -> RawKeymap {
        let mut m = RawKeymap::new();
        for (mode, key, action) in entries {
            m.entry((*mode).to_owned())
                .or_default()
                .insert((*key).to_owned(), (*action).to_owned());
        }
        m
    }

    #[test]
    fn mode_chain_table() {
        assert_eq!(Mode::Dialog.chain(), [Mode::Dialog]);
        assert_eq!(Mode::SiteManager.chain(), [Mode::SiteManager]);
        assert_eq!(Mode::FileList.chain(), [Mode::FileList, Mode::Normal]);
        assert_eq!(Mode::Input.chain(), [Mode::Input, Mode::Normal]);
        assert_eq!(Mode::Normal.chain(), [Mode::Normal]);
    }

    #[test]
    fn user_overrides_and_problems() {
        let defaults = raw(&[("Normal", "ctrl-q", "Quit"), ("Normal", "f1", "Help")]);
        let user = raw(&[
            ("Normal", "CTRL-Q", "Help"),
            ("FileList", "f1", "ToggleLog"),
            ("Nowhere", "a", "Quit"),
            ("Normal", "notakey", "Quit"),
            ("Normal", "x", "Explode"),
            ("Normal", "g g", "Help"),
        ]);
        let (mut r, problems) = KeyResolver::build(&defaults, &user);
        let kinds: Vec<_> = problems.iter().map(|p| p.kind.clone()).collect();
        assert_eq!(problems.len(), 4, "{problems:?}");
        assert!(kinds.contains(&ProblemKind::UnknownMode));
        assert!(kinds.contains(&ProblemKind::UnknownAction));
        let now = Instant::now();
        assert!(matches!(
            r.resolve(KeyChord::ctrl('q'), Mode::Normal, now),
            Resolution::Action(Action::Help)
        ));
        let f1 = KeyChord::key(crossterm::event::KeyCode::F(1));
        assert!(matches!(
            r.resolve(f1, Mode::FileList, now),
            Resolution::Action(Action::ToggleLog)
        ));
        assert!(matches!(
            r.resolve(f1, Mode::Normal, now),
            Resolution::Action(Action::Help)
        ));
        assert!(matches!(
            r.resolve(f1, Mode::Dialog, now),
            Resolution::Unbound
        ));
        // FileList's f1 hides Normal's f1.
        let rows = r.bindings(Mode::FileList.chain());
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0].0, Mode::FileList);
        assert!(r.deadline().is_none());
        assert!(r.pending_display().is_none());
        assert!(problems.iter().all(|p| !p.to_string().is_empty()));
    }
}
