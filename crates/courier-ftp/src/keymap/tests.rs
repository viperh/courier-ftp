//! Keymap, defaults, resolver and generated-doc tests (T51).

use std::{collections::BTreeMap, time::Duration};

use crossterm::event::KeyCode;
use pretty_assertions::assert_eq;
use proptest::prelude::*;
use strum::IntoEnumIterator;
use tokio::time::Instant;

use super::{
    chord::{KeyChord, Mods, display_sequence, parse_sequence},
    map::{Keymap, KeymapProblem, Lookup, ProblemKind, RawKeymap},
    resolver::{KeyResolver, Resolution, WHICH_KEY_DELAY},
};
use crate::{
    action::{Action, BINDABLE},
    app::Mode,
    config::default_keybindings,
};

fn raw(entries: &[(&str, &str, &str)]) -> RawKeymap {
    let mut m = RawKeymap::new();
    for (mode, key, action) in entries {
        m.entry((*mode).to_owned())
            .or_default()
            .insert((*key).to_owned(), (*action).to_owned());
    }
    m
}

fn seq(s: &str) -> Vec<KeyChord> {
    parse_sequence(s).unwrap_or_else(|e| panic!("{e}"))
}

fn defaults() -> Keymap {
    let (k, problems) = Keymap::build(default_keybindings(), &RawKeymap::new());
    assert!(problems.is_empty(), "{problems:#?}");
    k
}

fn exact(k: &Keymap, mode: Mode, keys: &str) -> String {
    match k.lookup(mode, &seq(keys)) {
        Lookup::Exact(a) => a.to_string(),
        other => panic!("{mode:?} {keys}: {other:?}"),
    }
}

fn kinds(problems: &[KeymapProblem]) -> Vec<ProblemKind> {
    problems.iter().map(|p| p.kind.clone()).collect()
}

#[test]
fn build_reports_unknown_mode_action_and_internal_action() {
    let user = raw(&[
        ("Nowhere", "a", "Quit"),
        ("Normal", "x", "Explode"),
        ("Normal", "y", "Tick"),
        ("Normal", "z", "Resize"),
        ("Normal", "w", "OpenSettingsAt"),
        ("FileList", "ctrl-foo", "Top"),
        ("FileList", "g g g g g", "Top"),
        ("FileList", "q", "ToggleLog"),
    ]);
    let (k, problems) = Keymap::build(&RawKeymap::new(), &user);
    assert_eq!(problems.len(), 7, "{problems:#?}");
    let ks = kinds(&problems);
    assert_eq!(
        ks.iter()
            .filter(|k| **k == ProblemKind::UnknownMode)
            .count(),
        1
    );
    assert_eq!(
        ks.iter()
            .filter(|k| **k == ProblemKind::UnknownAction)
            .count(),
        4
    );
    assert!(ks.contains(&ProblemKind::SequenceTooLong));
    assert!(ks.contains(&ProblemKind::BadKey("unknown key name \"foo\"".into())));
    // The valid entry is active.
    assert_eq!(exact(&k, Mode::FileList, "q"), "ToggleLog");
    assert!(matches!(k.lookup(Mode::Normal, &seq("y")), Lookup::None));
}

#[test]
fn build_duplicate_same_source() {
    let user = raw(&[
        ("Dialog", "G", "DialogSave"),
        ("Dialog", "shift-g", "DialogCancel"),
    ]);
    let (k, problems) = Keymap::build(&RawKeymap::new(), &user);
    assert_eq!(
        problems,
        vec![KeymapProblem {
            mode: "Dialog".into(),
            key: "shift-g".into(),
            action: "DialogCancel".into(),
            kind: ProblemKind::Duplicate {
                other_key: "G".into()
            },
        }]
    );
    assert_eq!(
        problems[0].to_string(),
        "keybindings.Dialog.\"G\" and \"shift-g\" are the same key; \"shift-g\" is ignored"
    );
    assert_eq!(exact(&k, Mode::Dialog, "G"), "DialogSave");
    // Different sources are an override, not a duplicate.
    let (k, problems) = Keymap::build(
        &raw(&[("Dialog", "G", "DialogSave")]),
        &raw(&[("Dialog", "shift-g", "DialogCancel")]),
    );
    assert!(problems.is_empty());
    assert_eq!(exact(&k, Mode::Dialog, "G"), "DialogCancel");
}

#[test]
fn build_prefix_conflict_same_table() {
    let (k, problems) = Keymap::build(
        &raw(&[("Normal", "g", "Help"), ("Normal", "g t", "NextTab")]),
        &RawKeymap::new(),
    );
    assert_eq!(problems.len(), 1, "{problems:#?}");
    let p = &problems[0];
    assert_eq!((p.mode.as_str(), p.key.as_str()), ("Normal", "g t"));
    assert_eq!(
        p.to_string(),
        "keybindings.Normal.\"g\": \"Help\" makes \"g t\" (NextTab) unreachable in mode Normal"
    );
    // Kept; the exact match wins.
    assert_eq!(exact(&k, Mode::Normal, "g"), "Help");
}

#[test]
fn build_prefix_conflict_across_chain() {
    let (k, problems) = Keymap::build(
        &raw(&[("Normal", "g", "Help"), ("FileList", "g g", "Top")]),
        &RawKeymap::new(),
    );
    assert_eq!(problems.len(), 1, "{problems:#?}");
    let p = &problems[0];
    assert_eq!((p.mode.as_str(), p.key.as_str()), ("Normal", "g"));
    assert_eq!(
        p.kind,
        ProblemKind::Unreachable {
            mode: Mode::FileList,
            blocked_by: "FileList.\"g g\": \"Top\"".into()
        }
    );
    let line = p.to_string();
    assert!(line.contains("\"g g\"") && line.contains("\"g\""), "{line}");
    // In FileList the longer sequence wins; in Normal `g` still fires.
    assert!(matches!(
        k.lookup(Mode::FileList, &seq("g")),
        Lookup::Prefix
    ));
    assert_eq!(exact(&k, Mode::Normal, "g"), "Help");
    // Exact in a higher table than the longer sequence: the longer one is unreachable.
    let (_, problems) = Keymap::build(
        &raw(&[("FileList", "g", "Top"), ("Normal", "g t", "NextTab")]),
        &RawKeymap::new(),
    );
    assert_eq!(problems.len(), 1, "{problems:#?}");
    assert_eq!(problems[0].key, "g t");
}

#[test]
fn display_problem_lines() {
    let p = |mode: &str, key: &str, action: &str, kind| KeymapProblem {
        mode: mode.into(),
        key: key.into(),
        action: action.into(),
        kind,
    };
    let lines = [
        p(
            "FileList",
            "ctrl-foo",
            "Top",
            ProblemKind::BadKey("unknown key name \"foo\"".into()),
        ),
        p(
            "Normal",
            "g t",
            "NextTab",
            ProblemKind::Unreachable {
                mode: Mode::FileList,
                blocked_by: "Normal.\"g\": \"Help\"".into(),
            },
        ),
        p("Queue", "x", "Remove", ProblemKind::UnknownAction),
        p(
            "Dialog",
            "shift-g",
            "DialogSave",
            ProblemKind::Duplicate {
                other_key: "G".into(),
            },
        ),
    ]
    .map(|p| p.to_string());
    assert_eq!(
        lines,
        [
            "keybindings.FileList.\"ctrl-foo\": invalid key: unknown key name \"foo\"",
            "keybindings.Normal.\"g\": \"Help\" makes \"g t\" (NextTab) unreachable in mode FileList",
            "keybindings.Queue.\"x\": unknown action \"Remove\" (see docs/keybindings.md)",
            "keybindings.Dialog.\"G\" and \"shift-g\" are the same key; \"shift-g\" is ignored",
        ]
    );
    let built = Keymap::build(
        &RawKeymap::new(),
        &raw(&[
            ("Queue", "x", "Remove"),
            ("Nope", "x", "Quit"),
            ("Log", "g g g g g", "Quit"),
        ]),
    )
    .1;
    let text: Vec<String> = built.iter().map(ToString::to_string).collect();
    assert!(
        text.contains(
            &"keybindings.Queue.\"x\": unknown action \"Remove\" (see docs/keybindings.md)"
                .to_owned()
        ),
        "{text:#?}"
    );
    assert!(
        text.iter()
            .any(|t| t.starts_with("keybindings.Nope: unknown mode"))
    );
    assert!(text.contains(
        &"keybindings.Log.\"g g g g g\": invalid key: sequences are limited to 4 keys".to_owned()
    ));
}

#[test]
fn default_keymap_has_no_problems() {
    let (_, problems) = Keymap::build(default_keybindings(), &RawKeymap::new());
    assert!(problems.is_empty(), "{problems:#?}");
    // Every mode has a table.
    for m in Mode::iter() {
        assert!(
            default_keybindings().contains_key(&format!("{m:?}")),
            "{m:?}"
        );
    }
}

#[test]
fn user_overrides_default_and_none_unbinds() {
    let user = raw(&[
        ("FileList", "ctrl-d", "Delete"),
        ("FileList", "f8", "none"),
        ("FileList", "<g><h>", "Parent"),
        ("Normal", "CTRL-Q", "Help"),
    ]);
    let (k, problems) = Keymap::build(default_keybindings(), &user);
    assert!(problems.is_empty(), "{problems:#?}");
    assert_eq!(exact(&k, Mode::FileList, "ctrl-d"), "Delete");
    assert!(matches!(k.lookup(Mode::FileList, &seq("f8")), Lookup::None));
    assert_eq!(exact(&k, Mode::FileList, "delete"), "Delete");
    assert_eq!(exact(&k, Mode::FileList, "g h"), "Parent");
    assert_eq!(exact(&k, Mode::FileList, "g g"), "Top");
    assert_eq!(exact(&k, Mode::Normal, "ctrl-q"), "Help");
    assert_eq!(exact(&k, Mode::Normal, "f10"), "Quit");
}

#[test]
fn input_tab_override_is_not_a_problem() {
    let (k, problems) = Keymap::build(
        default_keybindings(),
        &raw(&[
            ("Input", "tab", "InputSubmit"),
            ("FileList", "tab", "Transfer"),
        ]),
    );
    assert!(problems.is_empty(), "{problems:#?}");
    assert_eq!(exact(&k, Mode::Input, "tab"), "InputSubmit");
    assert_eq!(exact(&k, Mode::FileList, "tab"), "Transfer");
    assert_eq!(exact(&k, Mode::Log, "tab"), "FocusOtherSide");
}

#[test]
fn ctrl_d_and_disconnect_defaults() {
    let k = defaults();
    assert_eq!(exact(&k, Mode::FileList, "ctrl-d"), "HalfPageDown");
    assert_eq!(exact(&k, Mode::FileList, "ctrl-x d"), "Disconnect");
    assert_eq!(exact(&k, Mode::Normal, "ctrl-x d"), "Disconnect");
    assert_eq!(exact(&k, Mode::Normal, "ctrl-x j"), "ToggleQueuePane");
    assert_eq!(exact(&k, Mode::FileList, "."), "ToggleHidden");
    assert!(matches!(
        k.lookup(Mode::Normal, &seq("ctrl-d")),
        Lookup::None
    ));
}

#[test]
fn ctrl_h_and_ctrl_j_unbound_in_every_mode() {
    let k = defaults();
    let banned = [KeyChord::ctrl('h'), KeyChord::ctrl('j')];
    for m in Mode::iter() {
        for row in k.table_rows(m) {
            assert!(
                !row.keys.iter().any(|c| banned.contains(c)),
                "{m:?} {}",
                row.keys_text()
            );
        }
    }
}

#[test]
fn ctrl_x_table_matches_spec() {
    let k = defaults();
    let got: BTreeMap<String, String> = k
        .continuations(&[Mode::Normal], &[KeyChord::ctrl('x')])
        .into_iter()
        .map(|(c, a)| (c.to_string(), a.to_string()))
        .collect();
    let mut want: BTreeMap<String, String> = [
        ("a", "CycleTransferType"),
        ("b", "AddBookmark"),
        ("c", "CompareOptions"),
        ("d", "Disconnect"),
        ("D", "ShowAppLog"),
        ("e", "EditedFilesList"),
        ("f", "FiltersDialog"),
        ("i", "ServerInfo"),
        ("j", "ToggleQueuePane"),
        ("k", "ToggleSpeedLimit"),
        ("l", "ClearLog"),
        ("m", "ManualTransfer"),
        ("n", "NewFile"),
        ("N", "NetworkWizard"),
        ("p", "OpenNextPrompt"),
        ("q", "ToggleQuickconnect"),
        ("r", "ReconnectLast"),
        ("s", "SitePicker"),
        ("S", "SaveAsSite"),
        ("t", "RenameTab"),
        ("T", "DuplicateTab"),
        ("u", "DismissUpdate"),
        ("v", "ShowRawListing"),
        ("w", "SaveLogAs"),
        ("y", "SyncPanel"),
        ("=", "SelectByStatus"),
        ("<", "MoveTabLeft"),
        (">", "MoveTabRight"),
        ("ctrl-l", "LockVault"),
    ]
    .into_iter()
    .map(|(k, a)| (k.to_owned(), a.to_owned()))
    .collect();
    for n in 1..=7 {
        want.insert(n.to_string(), format!("FocusRegion{n}"));
    }
    assert_eq!(want.len(), 36);
    assert_eq!(got, want);
    // Only Normal binds ctrl-x sequences, so every non-modal chain sees the same table.
    for m in [
        Mode::FileList,
        Mode::Tree,
        Mode::Log,
        Mode::Queue,
        Mode::Input,
    ] {
        assert_eq!(
            k.continuations(m.chain(), &[KeyChord::ctrl('x')]).len(),
            36,
            "{m:?}"
        );
    }
}

#[test]
fn tab_and_focus_region_defaults() {
    let k = defaults();
    for n in 1..=9 {
        assert_eq!(
            exact(&k, Mode::FileList, &format!("alt-{n}")),
            format!("GoToTab{n}")
        );
        assert_eq!(
            exact(&k, Mode::FileList, &format!("g {n}")),
            format!("GoToTab{n}")
        );
    }
    assert_eq!(exact(&k, Mode::FileList, "g t"), "NextTab");
    assert_eq!(exact(&k, Mode::FileList, "g T"), "PrevTab");
    assert_eq!(exact(&k, Mode::Normal, "ctrl-pagedown"), "NextTab");
    assert_eq!(exact(&k, Mode::Normal, "ctrl-x 6"), "FocusRegion6");
    for n in 1..=7 {
        assert_eq!(
            exact(&k, Mode::Normal, &format!("ctrl-x {n}")),
            format!("FocusRegion{n}")
        );
    }
    assert_eq!(exact(&k, Mode::Normal, "f9"), "Settings");
}

#[test]
fn site_manager_mode_defaults() {
    let k = defaults();
    let sm = Mode::SiteManager;
    assert_eq!(sm.chain(), [Mode::SiteManager]);
    for (keys, action) in [
        ("o", "SmConnect"),
        ("enter", "SmConnect"),
        ("m", "SmMark"),
        ("p", "SmPaste"),
        ("C", "SmCopyToVault"),
        ("M", "SmMoveToVault"),
        ("L", "SmCredentialOverride"),
        ("l", "TreeExpand"),
        ("f1", "Help"),
        ("ctrl-q", "Quit"),
        ("ctrl-s", "SmSave"),
        ("g g", "Top"),
    ] {
        assert_eq!(exact(&k, sm, keys), action, "{keys}");
    }
    // Normal is not consulted in the Site Manager.
    assert!(matches!(k.lookup(sm, &seq("ctrl-x")), Lookup::None));
}

/// The portable chord set of the spec.
fn portable(c: &KeyChord) -> bool {
    match c.code {
        KeyCode::Char(ch) if c.mods == Mods::NONE => !ch.is_control(),
        KeyCode::Char(ch) if c.mods == Mods::CTRL => {
            ch.is_ascii_lowercase() && !"hijm".contains(ch)
        }
        KeyCode::F(n) if c.mods == Mods::NONE => (2..=9).contains(&n),
        KeyCode::Tab if c.mods == Mods::NONE || c.mods == Mods::SHIFT => true,
        KeyCode::Up
        | KeyCode::Down
        | KeyCode::Left
        | KeyCode::Right
        | KeyCode::Home
        | KeyCode::End
        | KeyCode::PageUp
        | KeyCode::PageDown
        | KeyCode::Insert
        | KeyCode::Delete
        | KeyCode::Enter
        | KeyCode::Esc
        | KeyCode::Backspace => c.mods == Mods::NONE,
        _ => false,
    }
}

#[test]
fn every_bindable_action_has_portable_default() {
    let k = defaults();
    let mut missing = Vec::new();
    for (action, meta) in BINDABLE {
        let ok = Mode::iter().any(|m| {
            k.table_rows(m)
                .iter()
                .any(|r| r.action.same_variant(action) && r.keys.iter().all(portable))
        });
        if !ok {
            missing.push(meta.name);
        }
    }
    assert!(missing.is_empty(), "no portable default: {missing:?}");
    assert!(portable(&KeyChord::char('G')));
    assert!(!portable(&KeyChord::ctrl('h')));
    assert!(!portable(
        &"alt-1".parse().unwrap_or_else(|_| KeyChord::ctrl('h'))
    ));
}

fn t0() -> Instant {
    Instant::now()
}

#[test]
fn resolver_sequences_timeout_and_cancel() {
    let (mut r, _) = KeyResolver::build(default_keybindings(), &RawKeymap::new());
    let start = t0();
    let g = KeyChord::char('g');
    assert!(matches!(
        r.resolve(g, Mode::FileList, start),
        Resolution::Pending
    ));
    assert_eq!(r.pending_display().as_deref(), Some("g"));
    assert_eq!(r.deadline(), Some(start + WHICH_KEY_DELAY));
    assert!(r.which_key(start).is_none());
    assert!(r.which_key(start + WHICH_KEY_DELAY).is_some());
    let at = start + Duration::from_millis(999);
    assert!(matches!(
        r.resolve(g, Mode::FileList, at),
        Resolution::Action(Action::Top)
    ));
    assert!(r.pending_display().is_none());
    assert!(r.deadline().is_none());
    // Expired at exactly 1000 ms: the second g starts a new sequence.
    assert!(matches!(
        r.resolve(g, Mode::FileList, start),
        Resolution::Pending
    ));
    let late = start + Duration::from_millis(1000);
    assert!(matches!(
        r.resolve(g, Mode::FileList, late),
        Resolution::Pending
    ));
    // Esc cancels.
    assert!(matches!(
        r.resolve(KeyChord::key(KeyCode::Esc), Mode::FileList, late),
        Resolution::Cancelled
    ));
    assert!(r.pending_display().is_none());
    // Unbound continuation: the key alone.
    let _ = r.resolve(g, Mode::FileList, late);
    assert!(matches!(
        r.resolve(KeyChord::char('j'), Mode::FileList, late),
        Resolution::Action(Action::CursorDown)
    ));
    // Mode change clears.
    let _ = r.resolve(g, Mode::FileList, late);
    assert!(matches!(
        r.resolve(KeyChord::char('g'), Mode::Log, late),
        Resolution::Pending
    ));
    assert_eq!(r.pending_mode(), Some(Mode::Log));
    // on_timeout drops at the deadline.
    let d = late + Duration::from_millis(1000);
    assert!(r.on_timeout(late + WHICH_KEY_DELAY));
    assert_eq!(r.deadline(), Some(d));
    assert!(r.on_timeout(d));
    assert!(r.pending_display().is_none());
    assert!(matches!(
        r.resolve(KeyChord::char('#'), Mode::FileList, d),
        Resolution::Unbound
    ));
}

proptest! {
    // AC3: arbitrary user keymaps never panic.
    #[test]
    fn prop_build_never_panics(
        entries in prop::collection::vec(("\\PC{0,12}", "[ -~]{0,20}", "\\PC{0,16}"), 0..20)
    ) {
        let mut user = RawKeymap::new();
        for (mode, key, action) in &entries {
            let mode = if mode.len() % 2 == 0 { "FileList".to_owned() } else { mode.clone() };
            user.entry(mode).or_default().insert(key.clone(), action.clone());
        }
        let (_, problems) = Keymap::build(default_keybindings(), &user);
        for p in problems {
            prop_assert!(p.to_string().starts_with("keybindings."));
        }
    }

    // AC7: after any key and `timeout` of idle time, nothing is pending.
    #[test]
    fn prop_resolver_never_stuck(
        keys in prop::collection::vec((0usize..12, 0u64..1500, 0usize..4), 1..30)
    ) {
        let pool = ["g", "G", "ctrl-x", "d", "j", "s", "esc", "z", "y", "1", "ctrl-l", "q"];
        let modes = [Mode::FileList, Mode::Normal, Mode::Log, Mode::Queue];
        let (mut r, _) = KeyResolver::build(default_keybindings(), &RawKeymap::new());
        let mut now = t0();
        for (k, gap, m) in keys {
            now += Duration::from_millis(gap);
            if let Some(d) = r.deadline() && d <= now {
                r.on_timeout(now);
            }
            let chord: KeyChord = pool[k].parse().map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let _ = r.resolve(chord, modes[m], now);
            let idle = now + Duration::from_millis(1000);
            // Run a copy's timers up to the idle point.
            let mut probe = r.clone();
            for _ in 0..4 {
                match probe.deadline() {
                    Some(d) if d <= idle => {
                        probe.on_timeout(d);
                    }
                    _ => break,
                }
            }
            prop_assert!(probe.pending_display().is_none(), "stuck after {}", pool[k]);
            prop_assert!(probe.deadline().is_none());
        }
    }
}

#[test]
fn keybindings_doc_is_current() {
    let generated = super::docs::markdown(default_keybindings());
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/keybindings.md");
    if std::env::var_os("COURIER_FTP_BLESS").is_some() {
        if let Err(e) = std::fs::write(&path, &generated) {
            panic!("write {}: {e}", path.display());
        }
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        committed == generated,
        "docs/keybindings.md is stale; run `COURIER_FTP_BLESS=1 cargo test -p courier-ftp keybindings_doc`"
    );
    // AC5: the doc states the key decisions.
    for needle in [
        "| `ctrl-x d` | `Disconnect` |",
        "| `ctrl-d` | `HalfPageDown` |",
        "| `ctrl-x j` | `ToggleQueuePane` |",
        "| `.` | `ToggleHidden` |",
        "`ctrl-h`",
        "`\"none\"`",
    ] {
        assert!(generated.contains(needle), "{needle}");
    }
    let _ = display_sequence(&[]);
}
