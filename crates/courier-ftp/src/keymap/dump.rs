//! Bindings grouped for people: one entry per action with all its keys, by [`Group`]
//! (the help overlay and `docs/keybindings.md`; sverb `keymap/dump.rs`, D13).

use strum::IntoEnumIterator;

use super::map::BindingRow;
use crate::action::{Action, BINDABLE, Group};

/// One action's keys in one table: (action, keys in display order).
pub(crate) type ActionKeys = (Action, Vec<String>);

/// The rows of `rows` merged per action and grouped by [`Group`], groups in enum order
/// and actions in registry order (help overlay, docs).
pub(crate) fn grouped(rows: &[BindingRow]) -> Vec<(Group, Vec<ActionKeys>)> {
    let mut out = Vec::new();
    for group in Group::iter() {
        let mut entries: Vec<ActionKeys> = Vec::new();
        for (action, _) in BINDABLE.iter().filter(|(_, m)| m.group == group) {
            let keys: Vec<String> = rows
                .iter()
                .filter(|r| r.action.same_variant(action))
                .map(BindingRow::keys_text)
                .collect();
            if !keys.is_empty() {
                entries.push((action.clone(), keys));
            }
        }
        if !entries.is_empty() {
            out.push((group, entries));
        }
    }
    out
}
