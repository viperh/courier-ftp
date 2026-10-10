//! Keybindings (T51): parsing key strings, the per-mode keymap, conflict
//! detection and the multi-key sequence matcher.
//!
//! Key strings look like `<Ctrl-a>`, `<F5>`, `<Shift-F7>`, `<Space>`, `<g><g>`
//! (a sequence) or a bare `G`. Modifiers are case-insensitive; a single
//! character keeps its case (`<G>` is Shift-g). Characters that are part of
//! the syntax have names: `<lt>` and `<gt>` for `<`/`>`, `<minus>` for `-`.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use serde::{Deserialize, Deserializer};

use crate::{action::Action, app::Mode};

/// One mode's bindings: key sequence → action.
pub(crate) type Keymap = HashMap<Vec<KeyEvent>, Action>;

/// The keymaps of every mode, plus problems found while loading them.
#[derive(Clone, Debug, Default)]
pub(crate) struct KeyBindings(pub(crate) HashMap<Mode, Keymap>, pub(crate) Vec<String>);

impl KeyBindings {
    /// The action bound to exactly `keys` in `mode`. The context modes
    /// (`FileList`, `Queue`, `Log`) fall back to the global `Normal` map.
    pub(crate) fn lookup(&self, mode: Mode, keys: &[KeyEvent]) -> Option<&Action> {
        self.chain(mode).find_map(|map| map.get(keys))
    }

    /// Whether some binding in `mode` starts with `keys` and is longer.
    pub(crate) fn is_prefix(&self, mode: Mode, keys: &[KeyEvent]) -> bool {
        self.chain(mode).any(|map| {
            map.keys()
                .any(|seq| seq.len() > keys.len() && seq.starts_with(keys))
        })
    }

    fn chain(&self, mode: Mode) -> impl Iterator<Item = &Keymap> {
        let fallback = mode.falls_back_to_normal().then_some(Mode::Normal);
        [Some(mode), fallback]
            .into_iter()
            .flatten()
            .filter_map(|m| self.0.get(&m))
    }

    /// Every binding visible in `mode` as (keys, action) for the help overlay
    /// and the generated docs. Context bindings shadow global ones.
    pub(crate) fn describe(&self, mode: Mode) -> Vec<(String, String)> {
        let mut seen: HashMap<&Vec<KeyEvent>, ()> = HashMap::new();
        let mut out = Vec::new();
        for map in self.chain(mode) {
            for (keys, action) in map {
                if seen.insert(keys, ()).is_none() {
                    out.push((sequence_to_string(keys), action.to_string()));
                }
            }
        }
        out.sort();
        out
    }

    /// The bindings of `mode` itself (no fallback), sorted by action (for
    /// the generated docs).
    #[cfg(test)]
    pub(crate) fn own(&self, mode: Mode) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .0
            .get(&mode)
            .map(|map| {
                map.iter()
                    .map(|(k, a)| (sequence_to_string(k), a.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        out
    }

    /// Two bindings where one sequence is a prefix of another in the same
    /// mode: the shorter one fires first and hides the longer one.
    pub(crate) fn conflicts(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (mode, map) in &self.0 {
            for (seq, action) in map {
                for (other, other_action) in map {
                    if other.len() > seq.len() && other.starts_with(seq) {
                        out.push(format!(
                            "{mode:?}: {} ({action}) hides {} ({other_action})",
                            sequence_to_string(seq),
                            sequence_to_string(other)
                        ));
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// Put `defaults` under the user's bindings: keys the user didn't bind
    /// get the default action.
    pub(crate) fn merge_defaults(&mut self, defaults: &KeyBindings) {
        for (mode, default_map) in &defaults.0 {
            let user = self.0.entry(*mode).or_default();
            for (keys, action) in default_map {
                user.entry(keys.clone()).or_insert_with(|| action.clone());
            }
        }
    }
}

impl<'de> Deserialize<'de> for KeyBindings {
    /// Bad key strings and unknown action names are skipped with a warning
    /// naming the problem, so one typo doesn't stop the program.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let parsed =
            HashMap::<Mode, HashMap<String, serde_json::Value>>::deserialize(deserializer)?;
        let mut maps = HashMap::new();
        let mut warnings = Vec::new();
        let mut modes: Vec<_> = parsed.into_iter().collect();
        modes.sort_by_key(|(m, _)| format!("{m:?}"));
        for (mode, bindings) in modes {
            let mut map: Keymap = HashMap::new();
            let mut sorted: Vec<_> = bindings.into_iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            for (key_str, value) in sorted {
                let keys = match parse_key_sequence(&key_str) {
                    Ok(keys) => keys,
                    Err(e) => {
                        warnings.push(format!("keybindings.{mode:?}: {e}"));
                        continue;
                    }
                };
                let action: Action = match serde_json::from_value(value.clone()) {
                    Ok(a) => a,
                    Err(_) => {
                        warnings.push(format!(
                            "keybindings.{mode:?}.{key_str}: unknown action {value}"
                        ));
                        continue;
                    }
                };
                if let Some(previous) = map.insert(keys, action.clone())
                    && previous != action
                {
                    warnings.push(format!(
                        "keybindings.{mode:?}: `{key_str}` is bound twice ({previous} and {action})"
                    ));
                }
            }
            maps.insert(mode, map);
        }
        Ok(KeyBindings(maps, warnings))
    }
}

/// The form keys are matched in: kind `Press`, no state flags, and no SHIFT on
/// characters (the character itself already says whether shift was held:
/// terminals report `G` with or without SHIFT) or on `BackTab`.
pub(crate) fn normalize(key: KeyEvent) -> KeyEvent {
    let mut modifiers = key.modifiers;
    if matches!(key.code, KeyCode::Char(_) | KeyCode::BackTab) {
        modifiers.remove(KeyModifiers::SHIFT);
    }
    KeyEvent {
        code: key.code,
        modifiers,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    }
}

/// Parse one key, e.g. `Ctrl-a`, `F5`, `Shift-F7`, `space`, `G`.
pub(crate) fn parse_key_event(raw: &str) -> Result<KeyEvent, String> {
    let mut modifiers = KeyModifiers::empty();
    let mut rest = raw;
    loop {
        let lower = rest.to_ascii_lowercase();
        let (prefix, flag) = if lower.starts_with("ctrl-") {
            ("ctrl-", KeyModifiers::CONTROL)
        } else if lower.starts_with("alt-") {
            ("alt-", KeyModifiers::ALT)
        } else if lower.starts_with("shift-") {
            ("shift-", KeyModifiers::SHIFT)
        } else {
            break;
        };
        modifiers.insert(flag);
        rest = &rest[prefix.len()..];
    }
    let code = parse_key_code(rest, &mut modifiers)
        .ok_or_else(|| format!("`{raw}` is not a key (try e.g. <Ctrl-a>, <F5>, <Space>)"))?;
    Ok(normalize(KeyEvent::new(code, modifiers)))
}

fn parse_key_code(raw: &str, modifiers: &mut KeyModifiers) -> Option<KeyCode> {
    let mut chars = raw.chars();
    if let (Some(c), None) = (chars.next(), chars.next()) {
        // Terminals report Ctrl/Alt + letter in lower case; Shift is explicit.
        let c = if modifiers.contains(KeyModifiers::SHIFT) {
            c.to_ascii_uppercase()
        } else if modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) {
            c.to_ascii_lowercase()
        } else {
            c
        };
        return Some(KeyCode::Char(c));
    }
    let lower = raw.to_ascii_lowercase();
    if let Some(n) = lower.strip_prefix('f').and_then(|n| n.parse::<u8>().ok())
        && (1..=24).contains(&n)
    {
        return Some(KeyCode::F(n));
    }
    Some(match lower.as_str() {
        "esc" | "escape" => KeyCode::Esc,
        "enter" | "return" | "cr" => KeyCode::Enter,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pageup" => KeyCode::PageUp,
        "pagedown" => KeyCode::PageDown,
        "tab" => KeyCode::Tab,
        "backtab" => {
            modifiers.remove(KeyModifiers::SHIFT);
            KeyCode::BackTab
        }
        "backspace" | "bs" => KeyCode::Backspace,
        "delete" | "del" => KeyCode::Delete,
        "insert" | "ins" => KeyCode::Insert,
        "space" => KeyCode::Char(' '),
        "minus" | "hyphen" => KeyCode::Char('-'),
        "lt" => KeyCode::Char('<'),
        "gt" => KeyCode::Char('>'),
        _ => return None,
    })
}

/// Parse a key sequence: `<g><g>`, `<Ctrl-x><d>`, or a single key with or
/// without brackets.
pub(crate) fn parse_key_sequence(raw: &str) -> Result<Vec<KeyEvent>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty key string".to_owned());
    }
    if !raw.starts_with('<') {
        return parse_key_event(raw).map(|k| vec![k]);
    }
    let mut keys = Vec::new();
    let mut rest = raw;
    while !rest.is_empty() {
        let Some(inner) = rest.strip_prefix('<') else {
            return Err(format!("`{raw}`: expected `<` at `{rest}`"));
        };
        // `<>>` would be ambiguous; `>` is spelled `<gt>`.
        let end = inner
            .find('>')
            .ok_or_else(|| format!("`{raw}`: missing `>`"))?;
        keys.push(parse_key_event(&inner[..end]).map_err(|e| format!("`{raw}`: {e}"))?);
        rest = &inner[end + 1..];
    }
    Ok(keys)
}

/// A key the way the config spells it: `Ctrl-q`, `F5`, `Space`, `G`.
pub(crate) fn key_to_string(key: &KeyEvent) -> String {
    let name = match key.code {
        KeyCode::Char(' ') => "Space".to_owned(),
        KeyCode::Char('<') => "lt".to_owned(),
        KeyCode::Char('>') => "gt".to_owned(),
        KeyCode::Char('-') => "minus".to_owned(),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::F(n) => format!("F{n}"),
        KeyCode::Backspace => "Backspace".to_owned(),
        KeyCode::Enter => "Enter".to_owned(),
        KeyCode::Left => "Left".to_owned(),
        KeyCode::Right => "Right".to_owned(),
        KeyCode::Up => "Up".to_owned(),
        KeyCode::Down => "Down".to_owned(),
        KeyCode::Home => "Home".to_owned(),
        KeyCode::End => "End".to_owned(),
        KeyCode::PageUp => "PageUp".to_owned(),
        KeyCode::PageDown => "PageDown".to_owned(),
        KeyCode::Tab => "Tab".to_owned(),
        KeyCode::BackTab => "BackTab".to_owned(),
        KeyCode::Delete => "Delete".to_owned(),
        KeyCode::Insert => "Insert".to_owned(),
        KeyCode::Esc => "Esc".to_owned(),
        other => format!("{other:?}"),
    };
    let mut out = String::new();
    for (flag, label) in [
        (KeyModifiers::CONTROL, "Ctrl-"),
        (KeyModifiers::ALT, "Alt-"),
        (KeyModifiers::SHIFT, "Shift-"),
    ] {
        if key.modifiers.contains(flag) {
            out.push_str(label);
        }
    }
    out.push_str(&name);
    out
}

/// A sequence the way the config spells it: `<g><g>`, `<Ctrl-q>`.
pub(crate) fn sequence_to_string(keys: &[KeyEvent]) -> String {
    keys.iter()
        .map(|k| format!("<{}>", key_to_string(k)))
        .collect()
}

/// What feeding a key to the [`Sequencer`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Feed {
    /// A complete binding.
    Action(Action),
    /// The keys so far start a longer binding; wait for more.
    Pending,
    /// Nothing is bound.
    Unbound,
}

/// Matches multi-key sequences (`gg`, `gt`, `<Ctrl-x><d>`), allowing up to
/// `timeout` between keys (T51: 1 s by default). The pending keys are shown in
/// the status bar, like vim's `showcmd`.
#[derive(Debug, Clone)]
pub(crate) struct Sequencer {
    pending: Vec<KeyEvent>,
    last: Option<Instant>,
    timeout: Duration,
}

impl Sequencer {
    pub(crate) fn new(timeout: Duration) -> Self {
        Self {
            pending: Vec::new(),
            last: None,
            timeout,
        }
    }

    /// Feed one key pressed at `now`.
    pub(crate) fn feed(
        &mut self,
        bindings: &KeyBindings,
        mode: Mode,
        key: KeyEvent,
        now: Instant,
    ) -> Feed {
        self.expire(now);
        self.pending.push(normalize(key));
        self.last = Some(now);
        if let Some(action) = bindings.lookup(mode, &self.pending) {
            let action = action.clone();
            self.pending.clear();
            return Feed::Action(action);
        }
        if bindings.is_prefix(mode, &self.pending) {
            return Feed::Pending;
        }
        // A dead end: drop the old keys and try the last one on its own
        // (`g` then `j` moves down).
        let had_prefix = self.pending.len() > 1;
        self.pending.clear();
        if had_prefix {
            return self.feed(bindings, mode, key, now);
        }
        Feed::Unbound
    }

    /// Drop pending keys older than the timeout.
    pub(crate) fn expire(&mut self, now: Instant) {
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) > self.timeout)
        {
            self.pending.clear();
        }
    }

    /// Forget pending keys (a dialog opened, focus moved).
    pub(crate) fn reset(&mut self) {
        self.pending.clear();
    }

    /// The pending keys for the status bar, e.g. `g`.
    pub(crate) fn pending_display(&self) -> String {
        self.pending
            .iter()
            .map(key_to_string)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn k(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, mods)
    }
    fn ch(c: char) -> KeyEvent {
        k(KeyCode::Char(c), KeyModifiers::NONE)
    }
    const C: KeyModifiers = KeyModifiers::CONTROL;
    const A: KeyModifiers = KeyModifiers::ALT;
    const S: KeyModifiers = KeyModifiers::SHIFT;
    const N: KeyModifiers = KeyModifiers::NONE;

    #[test]
    fn key_names() {
        let cases = [
            ("a", ch('a')),
            ("G", ch('G')),
            ("shift-g", ch('G')),
            ("?", ch('?')),
            ("ctrl-a", k(KeyCode::Char('a'), C)),
            ("CTRL-a", k(KeyCode::Char('a'), C)),
            ("ctrl-alt-a", k(KeyCode::Char('a'), C | A)),
            ("Alt-Enter", k(KeyCode::Enter, A)),
            ("enter", k(KeyCode::Enter, N)),
            ("esc", k(KeyCode::Esc, N)),
            ("F1", k(KeyCode::F(1), N)),
            ("f12", k(KeyCode::F(12), N)),
            ("Shift-F5", k(KeyCode::F(5), S)),
            ("Ctrl-F5", k(KeyCode::F(5), C)),
            ("space", ch(' ')),
            ("Space", ch(' ')),
            ("insert", k(KeyCode::Insert, N)),
            ("Delete", k(KeyCode::Delete, N)),
            ("del", k(KeyCode::Delete, N)),
            ("backspace", k(KeyCode::Backspace, N)),
            ("tab", k(KeyCode::Tab, N)),
            ("backtab", k(KeyCode::BackTab, N)),
            ("shift-tab", k(KeyCode::Tab, S)),
            ("pageup", k(KeyCode::PageUp, N)),
            ("home", k(KeyCode::Home, N)),
            ("minus", ch('-')),
            ("lt", ch('<')),
            ("gt", ch('>')),
            ("+", ch('+')),
            ("*", ch('*')),
            ("/", ch('/')),
            (":", ch(':')),
            (".", ch('.')),
            ("=", ch('=')),
        ];
        for (raw, expected) in cases {
            assert_eq!(parse_key_event(raw).unwrap(), normalize(expected), "{raw}");
        }
    }

    #[test]
    fn bad_keys_have_readable_errors() {
        for raw in [
            "",
            "invalid-key",
            "ctrl-nope",
            "f99",
            "<ctrl-a",
            "<a>b",
            "<>",
        ] {
            let err = parse_key_sequence(raw).unwrap_err();
            assert!(!err.is_empty(), "{raw}");
        }
        let err = parse_key_sequence("<ctrl-qq>").unwrap_err();
        assert!(err.contains("ctrl-qq"), "{err}");
    }

    #[test]
    fn sequences() {
        assert_eq!(
            parse_key_sequence("<g><g>").unwrap(),
            vec![ch('g'), ch('g')]
        );
        assert_eq!(
            parse_key_sequence("<Ctrl-x><d>").unwrap(),
            vec![k(KeyCode::Char('x'), C), ch('d')]
        );
        assert_eq!(parse_key_sequence("<q>").unwrap(), vec![ch('q')]);
        assert_eq!(parse_key_sequence("q").unwrap(), vec![ch('q')]);
        assert_eq!(
            parse_key_sequence("<lt><gt>").unwrap(),
            vec![ch('<'), ch('>')]
        );
    }

    #[test]
    fn printing_round_trips() {
        for raw in [
            "<Ctrl-q>",
            "<F5>",
            "<Shift-F7>",
            "<g><g>",
            "<Space>",
            "<G>",
            "<lt>",
            "<Ctrl-Alt-a>",
            "<BackTab>",
        ] {
            let keys = parse_key_sequence(raw).unwrap();
            assert_eq!(sequence_to_string(&keys), raw);
        }
    }

    #[test]
    fn terminal_shift_reports_are_normalised() {
        // Terminals send `G` and `?` with SHIFT, and BackTab with SHIFT.
        assert_eq!(normalize(k(KeyCode::Char('G'), S)), ch('G'));
        assert_eq!(normalize(k(KeyCode::Char('?'), S)), ch('?'));
        assert_eq!(normalize(k(KeyCode::BackTab, S)), k(KeyCode::BackTab, N));
        assert_eq!(normalize(k(KeyCode::F(5), S)), k(KeyCode::F(5), S));
    }

    fn bindings(json: &str) -> KeyBindings {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn bad_entries_are_skipped_with_warnings() {
        let b = bindings(r#"{"Normal": {"<q>": "Quit", "<nope>": "Help", "<x>": "NoSuchAction"}}"#);
        assert_eq!(b.0[&Mode::Normal].len(), 1);
        assert_eq!(b.1.len(), 2, "{:?}", b.1);
        assert!(b.1.iter().any(|w| w.contains("nope")));
        assert!(b.1.iter().any(|w| w.contains("NoSuchAction")));
    }

    #[test]
    fn duplicates_and_prefixes_are_reported() {
        let b = bindings(r#"{"Normal": {"<Ctrl-a>": "Quit", "<ctrl-A>": "Help"}}"#);
        assert!(b.1.iter().any(|w| w.contains("bound twice")), "{:?}", b.1);
        let b = bindings(r#"{"FileList": {"<g>": "Help", "<g><g>": "Top"}}"#);
        let c = b.conflicts();
        assert_eq!(c.len(), 1);
        assert!(c[0].contains("<g> (Help) hides <g><g> (Top)"), "{c:?}");
    }

    #[test]
    fn context_modes_fall_back_to_normal() {
        let b = bindings(
            r#"{"Normal": {"<q>": "Quit", "<j>": "Help"}, "FileList": {"<j>": "CursorDown"}, "Input": {}}"#,
        );
        assert_eq!(
            b.lookup(Mode::FileList, &[ch('j')]),
            Some(&Action::CursorDown)
        );
        assert_eq!(b.lookup(Mode::FileList, &[ch('q')]), Some(&Action::Quit));
        assert_eq!(
            b.lookup(Mode::Input, &[ch('q')]),
            None,
            "text input never falls back"
        );
        let d = b.describe(Mode::FileList);
        assert!(d.contains(&("<j>".to_owned(), "CursorDown".to_owned())));
        assert!(!d.contains(&("<j>".to_owned(), "Help".to_owned())));
    }

    #[test]
    fn sequences_wait_up_to_the_timeout() {
        let b =
            bindings(r#"{"FileList": {"<g><g>": "Top", "<j>": "CursorDown", "<G>": "Bottom"}}"#);
        let mut s = Sequencer::new(Duration::from_secs(1));
        let t0 = Instant::now();
        assert_eq!(s.feed(&b, Mode::FileList, ch('g'), t0), Feed::Pending);
        assert_eq!(s.pending_display(), "g");
        let t1 = t0 + Duration::from_millis(900);
        assert_eq!(
            s.feed(&b, Mode::FileList, ch('g'), t1),
            Feed::Action(Action::Top)
        );
        assert_eq!(s.pending_display(), "");

        // Too slow: the first `g` expires and the second starts over.
        assert_eq!(s.feed(&b, Mode::FileList, ch('g'), t1), Feed::Pending);
        let late = t1 + Duration::from_millis(1100);
        assert_eq!(s.feed(&b, Mode::FileList, ch('g'), late), Feed::Pending);
        s.expire(late + Duration::from_secs(2));
        assert_eq!(s.pending_display(), "");

        // A dead end retries the last key alone.
        assert_eq!(s.feed(&b, Mode::FileList, ch('g'), late), Feed::Pending);
        assert_eq!(
            s.feed(&b, Mode::FileList, ch('j'), late),
            Feed::Action(Action::CursorDown)
        );
        assert_eq!(s.feed(&b, Mode::FileList, ch('z'), late), Feed::Unbound);
        // Shift reported by the terminal still matches `<G>`.
        assert_eq!(
            s.feed(&b, Mode::FileList, k(KeyCode::Char('G'), S), late),
            Feed::Action(Action::Bottom)
        );
    }

    /// `docs/keybindings.md` is generated from the default keymap. Run with
    /// `COURIER_FTP_BLESS=1` to rewrite it after changing a binding.
    #[test]
    fn keybindings_doc_is_current() {
        let config = crate::config::Config::builtin();
        let doc = render_doc(&config.keybindings);
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/keybindings.md");
        if std::env::var_os("COURIER_FTP_BLESS").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &doc).unwrap();
            return;
        }
        let current = std::fs::read_to_string(&path)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        assert!(
            current == doc,
            "{} is stale; rerun with COURIER_FTP_BLESS=1",
            path.display()
        );
    }

    fn render_doc(bindings: &KeyBindings) -> String {
        let mut out = String::from(DOC_HEADER);
        for (mode, title, intro) in [
            (
                Mode::Normal,
                "Global",
                "Active everywhere except in text fields and dialogs.",
            ),
            (
                Mode::FileList,
                "File lists",
                "When a file list (or directory tree) has focus. Global keys work too, unless listed here.",
            ),
            (Mode::Queue, "Queue", "When the transfer queue has focus."),
            (Mode::Log, "Message log", "When the message log has focus."),
            (
                Mode::Input,
                "Text fields",
                "When a text field such as the quickconnect bar has focus. Other keys are typed.",
            ),
            (
                Mode::Filter,
                "Quick filter",
                "While typing a pane's quick filter.",
            ),
            (
                Mode::Dialog,
                "Dialogs",
                "While a dialog is open. Dialogs also handle their own keys.",
            ),
        ] {
            out.push_str(&format!(
                "\n## {title}\n\n{intro}\n\n| Key | Action |\n|---|---|\n"
            ));
            for (keys, action) in bindings.own(mode) {
                let keys = keys.replace('|', "\\|");
                out.push_str(&format!("| `{keys}` | {action} |\n"));
            }
        }
        out.push_str(DOC_FOOTER);
        out
    }

    const DOC_HEADER: &str = "# Keybindings

<!-- Generated from crates/courier-ftp/config/default.json by
     `COURIER_FTP_BLESS=1 cargo test -p courier-ftp keybindings_doc`. Do not edit. -->

courier-ftp mixes Midnight Commander function keys (F5 copy, F6 move, F7 mkdir,
F8 delete, Tab switches pane) with vim motions (`j`/`k`/`h`/`l`, `gg`/`G`, `/`).
`F1` shows the keys of the current mode in the program.

Every binding can be changed in your `config.json` (see the README): keys are
grouped by mode, a sequence is written `<g><g>`, and `<` and `>` are spelled
`<lt>` and `<gt>`. Up to 1 second may pass between the keys of a sequence
(`settings.interface.key_sequence_timeout_ms`); the keys typed so far show at
the right of the status bar.
";

    const DOC_FOOTER: &str = "
## Terminal caveats

Some keys never reach terminal programs, or arrive as other keys:

- `Ctrl-j` is sent as Enter and `Ctrl-h` as Backspace by many terminals. Toggle
  queue also has `Alt-j`, and toggle hidden files has `.` in file lists.
- `Ctrl-F5` and `Shift-F5`/`Shift-F7` are not sent by every terminal (and tmux
  needs `xterm-keys on`). Refresh also has `Ctrl-r`; queueing and \"mkdir and
  enter\" get their own dialogs in T62.
- `Alt-<digit>` may be taken by the terminal or window manager; `gt`/`gT`
  switch tabs too.
- `Ctrl-s` and `Ctrl-q` are flow control in some terminals; courier-ftp turns
  flow control off in raw mode, and `F10` also quits.

`Ctrl-d` scrolls half a page down in file lists (vim), so disconnect is
`<Ctrl-x><d>`.
";
}
