//! The help overlay (`F1`, `?`): every key, grouped by where it works, with
//! a description and the action name, searchable with `/` (modelled on
//! sverb's help dialog).
//!
//! The section for the current mode comes first, then the global keys, then
//! the other modes, so the keys that work right now are on top.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};

use super::{
    modal::{Modal, ModalOutcome},
    theme::Theme,
};
use crate::{app::Mode, keymap::KeyBindings};

/// The modes in the order their sections are shown (after the current one).
const MODES: [Mode; 7] = [
    Mode::Normal,
    Mode::FileList,
    Mode::Queue,
    Mode::Log,
    Mode::Filter,
    Mode::Input,
    Mode::Dialog,
];

/// One key binding.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    keys: String,
    description: String,
    action: String,
}

/// The bindings of one mode.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Section {
    heading: &'static str,
    rows: Vec<Row>,
}

/// The help overlay.
pub(crate) struct HelpOverlay {
    sections: Vec<Section>,
    /// "Update available: …" above the keys (T74).
    notice: Option<String>,
    /// Case-insensitive search over keys, descriptions and action names.
    query: String,
    /// `/` was pressed: keys edit the query until Enter or Esc.
    searching: bool,
    /// First body line shown.
    scroll: usize,
    /// Body lines that fit, from the last draw (for paging and clamping).
    visible: usize,
}

impl HelpOverlay {
    /// The keys of every mode, the current `mode` first.
    pub(crate) fn new(bindings: &KeyBindings, mode: Mode) -> Self {
        let mut order = vec![mode];
        order.extend(MODES.iter().copied().filter(|m| *m != mode));
        let sections = order
            .into_iter()
            .filter_map(|m| {
                let mut rows: Vec<Row> = bindings
                    .own(m)
                    .into_iter()
                    .map(|(keys, action)| Row {
                        description: describe_action(&action),
                        keys,
                        action,
                    })
                    .collect();
                // Grouped by what the keys do, as people look for them.
                rows.sort_by(|a, b| {
                    a.description
                        .cmp(&b.description)
                        .then_with(|| a.keys.cmp(&b.keys))
                });
                (!rows.is_empty()).then(|| Section {
                    heading: heading(m, mode),
                    rows,
                })
            })
            .collect();
        Self {
            sections,
            notice: None,
            query: String::new(),
            searching: false,
            scroll: 0,
            visible: 1,
        }
    }

    /// Show `notice` (an available update) above the keys.
    pub(crate) fn with_notice(mut self, notice: Option<String>) -> Self {
        self.notice = notice;
        self
    }

    /// The body lines for the current query.
    fn body(&self, theme: &Theme) -> Vec<Line<'static>> {
        let query = self.query.to_lowercase();
        let matches = |r: &Row| {
            query.is_empty()
                || r.keys.to_lowercase().contains(&query)
                || r.description.to_lowercase().contains(&query)
                || r.action.to_lowercase().contains(&query)
        };
        let key_width = self
            .sections
            .iter()
            .flat_map(|s| &s.rows)
            .map(|r| r.keys.chars().count())
            .max()
            .unwrap_or(0)
            .min(24);
        let desc_width = self
            .sections
            .iter()
            .flat_map(|s| &s.rows)
            .map(|r| r.description.chars().count())
            .max()
            .unwrap_or(0)
            .min(40);
        let mut lines = Vec::new();
        for section in &self.sections {
            let rows: Vec<&Row> = section.rows.iter().filter(|r| matches(r)).collect();
            if rows.is_empty() {
                continue;
            }
            if !lines.is_empty() {
                lines.push(Line::raw(""));
            }
            lines.push(Line::styled(section.heading, theme.title));
            for r in rows {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<key_width$}  ", r.keys), theme.key_hint),
                    Span::raw(format!("{:<desc_width$}  ", r.description)),
                    Span::styled(r.action.clone(), theme.dim),
                ]));
            }
        }
        if lines.is_empty() {
            lines.push(Line::styled("No matching keys.", theme.dim));
        }
        lines
    }

    fn scroll_by(&mut self, delta: isize) {
        self.scroll = self.scroll.saturating_add_signed(delta);
    }
}

impl Modal for HelpOverlay {
    fn draw(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let rect = area.inner(ratatui::layout::Margin {
            horizontal: area.width.saturating_sub(110) / 2 + 1,
            vertical: 1,
        });
        if rect.width < 10 || rect.height < 4 {
            return;
        }
        let hint = if self.searching {
            " type to search · Enter keep · Esc clear "
        } else {
            " / search · j k PgUp PgDn scroll · g G ends · Esc close "
        };
        let block = Block::bordered()
            .title(" Help · keys ")
            .title_bottom(Span::styled(hint, theme.dim))
            .border_style(theme.focused_border);
        let inner = block.inner(rect);
        frame.render_widget(Clear, rect);
        frame.render_widget(block, rect);

        let mut top: Vec<Line> = Vec::new();
        // "Update available: v1.3.0" and the release page on its own line.
        if let Some(notice) = &self.notice {
            top.extend(
                notice
                    .split(" — ")
                    .map(|part| Line::styled(part.to_owned(), theme.key_hint)),
            );
            top.push(Line::raw(""));
        }
        if self.searching || !self.query.is_empty() {
            let cursor = if self.searching { "▏" } else { "" };
            top.push(Line::from(vec![
                Span::styled("/", theme.key_hint),
                Span::raw(format!("{}{cursor}", self.query)),
            ]));
        }
        let body = self.body(theme);
        let visible = usize::from(inner.height).saturating_sub(top.len()).max(1);
        self.visible = visible;
        self.scroll = self.scroll.min(body.len().saturating_sub(visible));
        let mut lines = top;
        lines.extend(body.into_iter().skip(self.scroll).take(visible));
        frame.render_widget(Paragraph::new(lines), inner);
    }

    fn handle_key(&mut self, key: KeyEvent) -> ModalOutcome {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if self.searching {
            match key.code {
                KeyCode::Esc => {
                    self.searching = false;
                    self.query.clear();
                }
                KeyCode::Enter => self.searching = false,
                KeyCode::Backspace => {
                    self.query.pop();
                }
                KeyCode::Char(c) if !ctrl => {
                    self.query.push(c);
                    self.scroll = 0;
                }
                _ => {}
            }
            return ModalOutcome::Keep;
        }
        let page = isize::try_from(self.visible.max(2) - 1).unwrap_or(10);
        match key.code {
            KeyCode::Char('/') => {
                self.searching = true;
                self.scroll = 0;
            }
            KeyCode::Down | KeyCode::Char('j') => self.scroll_by(1),
            KeyCode::Up | KeyCode::Char('k') => self.scroll_by(-1),
            KeyCode::PageDown | KeyCode::Char(' ') => self.scroll_by(page),
            KeyCode::PageUp => self.scroll_by(-page),
            KeyCode::Char('d') if ctrl => self.scroll_by(page / 2),
            KeyCode::Char('u') if ctrl => self.scroll_by(-page / 2),
            KeyCode::Home | KeyCode::Char('g') => self.scroll = 0,
            // Clamped to the last page on the next draw.
            KeyCode::End | KeyCode::Char('G') => self.scroll = usize::MAX,
            KeyCode::Esc if !self.query.is_empty() => {
                self.query.clear();
                self.scroll = 0;
            }
            KeyCode::Esc | KeyCode::Enter | KeyCode::F(1) | KeyCode::Char('q' | '?') => {
                return ModalOutcome::Close;
            }
            _ => {}
        }
        ModalOutcome::Keep
    }
}

fn heading(mode: Mode, current: Mode) -> &'static str {
    let now = mode == current;
    match (mode, now) {
        (Mode::Normal, true) => "Everywhere (works now)",
        (Mode::Normal, false) => "Everywhere (except in text fields and dialogs)",
        (Mode::FileList, true) => "File lists (works now)",
        (Mode::FileList, false) => "File lists",
        (Mode::Queue, true) => "Transfer queue (works now)",
        (Mode::Queue, false) => "Transfer queue",
        (Mode::Log, true) => "Message log (works now)",
        (Mode::Log, false) => "Message log",
        (Mode::Filter, true) => "Typing a quick filter (works now)",
        (Mode::Filter, false) => "Typing a quick filter",
        (Mode::Input, true) => "Text fields (works now)",
        (Mode::Input, false) => "Text fields",
        (Mode::Dialog, true) => "Dialogs (works now)",
        (Mode::Dialog, false) => "Dialogs",
    }
}

/// What an action does, in words. Unknown names are split into words
/// (`CursorDown` → "Cursor down").
pub(crate) fn describe_action(action: &str) -> String {
    known(action).map_or_else(|| words(action), str::to_owned)
}

/// The written description of `action`, if there is one.
fn known(action: &str) -> Option<&'static str> {
    Some(match action {
        "Bookmarks" => "Bookmarks menu",
        "Bottom" => "Go to the last entry",
        "Chmod" => "Change permissions",
        "ClearLog" => "Clear the message log",
        "CloseDialog" => "Close the dialog",
        "CloseTab" => "Close the tab",
        "ColumnMenu" => "Choose columns",
        "CommandLine" => "Send a raw command",
        "CompareOptions" => "Comparison options",
        "Copy" => "Copy to the other side",
        "CopyLog" => "Copy the log to the clipboard",
        "CopySelection" => "Copy names to the clipboard",
        "CopyUrl" => "Copy the URL to the clipboard",
        "CursorDown" => "Move down",
        "CursorUp" => "Move up",
        "CycleTransferType" => "Transfer type: auto / ASCII / binary",
        "Delete" => "Delete",
        "DeselectPattern" => "Deselect by pattern",
        "Disconnect" => "Disconnect",
        "DuplicateTab" => "Duplicate the tab",
        "Edit" => "Edit in an external editor",
        "EditAddress" => "Edit the address bar",
        "EditedFiles" => "Files being edited",
        "Filters" => "Filters",
        "FocusLocal" => "Focus the local pane",
        "FocusNext" => "Focus the next pane",
        "FocusPrev" => "Focus the previous pane",
        "FocusQuickconnect" => "Focus quickconnect",
        "FocusTree" => "Switch list / directory tree",
        "HalfPageDown" => "Half a page down",
        "HalfPageUp" => "Half a page up",
        "Help" => "This help",
        "HistoryBack" => "Back (directory history)",
        "HistoryForward" => "Forward (directory history)",
        "InvertSelection" => "Invert the selection",
        "LockVault" => "Lock the vault",
        "MirrorDir" => "Same directory on the other side",
        "Mkdir" => "Create a directory",
        "MkdirEnter" => "Create a directory and open it",
        "Move" => "Move to the other side",
        "MoveItemBottom" => "Move to the bottom of the queue",
        "MoveItemDown" => "Move down in the queue",
        "MoveItemTop" => "Move to the top of the queue",
        "MoveItemUp" => "Move up in the queue",
        "NewFile" => "Create a file",
        "NewTab" => "New tab",
        "NextTab" => "Next tab",
        "Open" => "Open / enter",
        "OpenPrompt" => "Open the waiting question",
        "PageDown" => "Page down",
        "PageUp" => "Page up",
        "ParentDir" => "Parent directory",
        "PrevTab" => "Previous tab",
        "PriorityDown" => "Lower priority",
        "PriorityUp" => "Raise priority",
        "ProcessQueue" => "Start / stop the queue",
        "QueueAfterMenu" => "Action after the queue finishes",
        "QueueClear" => "Clear this queue tab",
        "QueueExistsMenu" => "If the file exists…",
        "QueueGroupByServer" => "Group by server",
        "QueueMenu" => "Queue menu",
        "QueueSelection" => "Add the selection to the queue",
        "QueueTabFailed" => "Failed transfers",
        "QueueTabQueued" => "Queued transfers",
        "QueueTabSuccessful" => "Successful transfers",
        "QueueToggleItem" => "Select a queue item",
        "QuickFilter" => "Quick filter",
        "Quit" => "Quit",
        "Reconnect" => "Reconnect",
        "Refresh" => "Refresh",
        "RemoveItem" => "Remove from the queue",
        "Rename" => "Rename",
        "RenameTab" => "Rename the tab",
        "Requeue" => "Retry (requeue)",
        "SaveAsSite" => "Save the connection as a site",
        "SaveLog" => "Save the log to a file",
        "ScrollLeft" => "Scroll left",
        "ScrollRight" => "Scroll right",
        "Search" => "Search",
        "SearchNext" => "Next match",
        "SearchPrev" => "Previous match",
        "SelectAll" => "Select all",
        "SelectCompareDifferent" => "Select red (size differs)",
        "SelectCompareLonely" => "Select yellow (one side only)",
        "SelectCompareNewer" => "Select green (newer)",
        "SelectPattern" => "Select by pattern",
        "ServerInfo" => "Server information",
        "Settings" => "Settings",
        "ShowRawListing" => "Show the raw listing",
        "SiteManager" => "Site Manager",
        "SitePicker" => "Connect to a site (picker)",
        "SortModified" => "Sort by date",
        "SortName" => "Sort by name",
        "SortOwner" => "Sort by owner",
        "SortPermissions" => "Sort by permissions",
        "SortSize" => "Sort by size",
        "Suspend" => "Suspend (back to the shell)",
        "SyncPanel" => "Sync and teams",
        "Tab1" => "Tab 1",
        "Tab2" => "Tab 2",
        "Tab3" => "Tab 3",
        "Tab4" => "Tab 4",
        "Tab5" => "Tab 5",
        "Tab6" => "Tab 6",
        "Tab7" => "Tab 7",
        "Tab8" => "Tab 8",
        "Tab9" => "Tab 9",
        "ToggleCompare" => "Directory comparison on/off",
        "ToggleErrorsOnly" => "Errors only on/off",
        "ToggleHidden" => "Hidden files on/off",
        "ToggleLog" => "Message log on/off",
        "ToggleLogAll" => "All tabs' log lines on/off",
        "ToggleQueue" => "Queue pane on/off",
        "ToggleSelect" => "Select / deselect",
        "ToggleSpeedLimit" => "Speed limit on/off",
        "ToggleSyncBrowsing" => "Synchronized browsing on/off",
        "ToggleTransfersPaused" => "Pause / resume all transfers",
        "ToggleTree" => "Directory trees on/off",
        "ToggleWrap" => "Wrap long lines on/off",
        "Top" => "Go to the first entry",
        "UnlockVault" => "Unlock the vault",
        "View" => "View in an external viewer",
        "VisualSelect" => "Select a range",
        _ => return None,
    })
}

/// `CursorDown` → "Cursor down".
fn words(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push(' ');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    use crate::config::Config;

    fn overlay(mode: Mode) -> HelpOverlay {
        HelpOverlay::new(&Config::builtin().keybindings, mode)
    }

    fn render(h: &mut HelpOverlay, w: u16, rows: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, rows)).unwrap();
        t.draw(|f| h.draw(f, f.area(), &Theme::new(None, true)))
            .unwrap();
        t.backend()
            .buffer()
            .content()
            .chunks(usize::from(w))
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn every_bound_action_has_a_description() {
        let bindings = Config::builtin().keybindings;
        for mode in MODES {
            for (keys, action) in bindings.own(mode) {
                assert!(
                    known(&action).is_some(),
                    "{action} ({keys}) has no description"
                );
            }
        }
    }

    #[test]
    fn the_current_mode_comes_first() {
        let h = overlay(Mode::Queue);
        assert_eq!(h.sections[0].heading, "Transfer queue (works now)");
        assert!(
            h.sections
                .iter()
                .any(|s| s.heading.starts_with("Everywhere"))
        );
    }

    #[test]
    fn search_filters_by_key_description_and_action() {
        let mut h = overlay(Mode::Normal);
        h.handle_key(key(KeyCode::Char('/')));
        for c in "site manager".chars() {
            h.handle_key(key(KeyCode::Char(c)));
        }
        let text = render(&mut h, 120, 30);
        assert!(text.contains("/site manager"), "{text}");
        assert!(text.contains("SiteManager"), "{text}");
        assert!(!text.contains("Quit"), "{text}");
        // Enter keeps the query; Esc clears it, a second Esc closes.
        h.handle_key(key(KeyCode::Enter));
        assert_eq!(h.handle_key(key(KeyCode::Esc)), ModalOutcome::Keep);
        assert!(h.query.is_empty());
        assert_eq!(h.handle_key(key(KeyCode::Esc)), ModalOutcome::Close);
    }

    #[test]
    fn no_match_says_so() {
        let mut h = overlay(Mode::Normal);
        h.handle_key(key(KeyCode::Char('/')));
        for c in "zzzz".chars() {
            h.handle_key(key(KeyCode::Char(c)));
        }
        assert!(render(&mut h, 100, 20).contains("No matching keys."));
    }

    #[test]
    fn scrolling_stops_at_the_last_page() {
        let mut h = overlay(Mode::Normal);
        render(&mut h, 100, 20);
        h.handle_key(key(KeyCode::Char('G')));
        let text = render(&mut h, 100, 20);
        let last = h.scroll;
        assert!(last > 0);
        h.handle_key(key(KeyCode::Char('j')));
        render(&mut h, 100, 20);
        assert_eq!(h.scroll, last, "{text}");
        h.handle_key(key(KeyCode::Char('g')));
        render(&mut h, 100, 20);
        assert_eq!(h.scroll, 0);
    }

    #[test]
    fn words_split_camel_case() {
        assert_eq!(words("CursorDown"), "Cursor down");
        assert_eq!(words("Quit"), "Quit");
    }
}
