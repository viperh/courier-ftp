//! T52: key handling per widget, forms, dialogs, snapshots.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};
use secrecy::ExposeSecret;

use super::{
    ButtonRow, Checkbox, Completer, Field, FieldOutcome, Form, FormDialog, ListView,
    LocalPathCompleter, NumberInput, PathInput, ProgressDialog, RadioGroup, Select, TabbedForm,
    TextInput, TriState, TriStateCheckbox, choose, confirm, error, form::FormOutcome, message,
    prompt_password, prompt_text, text::common_prefix,
};
use crate::ui::{
    modal::{Modal, ModalOutcome},
    theme::Theme,
};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}
fn ctrl(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::CONTROL)
}
fn alt(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::ALT)
}
fn typ(f: &mut dyn Field, s: &str) {
    for c in s.chars() {
        f.handle_key(key(KeyCode::Char(c)));
    }
}
fn text_of(f: &dyn Field) -> String {
    match f.value() {
        super::FieldValue::Text(s) => s,
        other => panic!("not text: {other:?}"),
    }
}
fn theme() -> Theme {
    Theme::new(None, true)
}
fn draw_modal(modal: &mut dyn Modal, w: u16, h: u16) -> Terminal<TestBackend> {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    let theme = theme();
    t.draw(|f| modal.draw(f, f.area(), &theme)).unwrap();
    t
}
fn draw_form(form: &Form, w: u16, h: u16) -> Terminal<TestBackend> {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    let theme = theme();
    t.draw(|f| form.draw(f, f.area(), &theme)).unwrap();
    t
}
fn screen_text(t: &Terminal<TestBackend>) -> String {
    t.backend().to_string()
}

// --- TextInput ---

#[test]
fn text_input_editing() {
    let mut t = TextInput::new("Name");
    typ(&mut t, "hello world");
    assert_eq!(text_of(&t), "hello world");
    t.handle_key(key(KeyCode::Home));
    assert_eq!(t.cursor(), 0);
    t.handle_key(ctrl(KeyCode::Right));
    assert_eq!(t.cursor(), 6);
    t.handle_key(key(KeyCode::End));
    t.handle_key(ctrl(KeyCode::Left));
    assert_eq!(t.cursor(), 6);
    t.handle_key(key(KeyCode::End));
    t.handle_key(ctrl(KeyCode::Char('w')));
    assert_eq!(text_of(&t), "hello ");
    t.handle_key(key(KeyCode::Backspace));
    assert_eq!(text_of(&t), "hello");
    t.handle_key(key(KeyCode::Home));
    t.handle_key(key(KeyCode::Delete));
    assert_eq!(text_of(&t), "ello");
    t.handle_key(key(KeyCode::End));
    t.handle_key(ctrl(KeyCode::Char('u')));
    assert_eq!(text_of(&t), "");
    assert_eq!(t.handle_key(key(KeyCode::Tab)), FieldOutcome::Ignored);
    assert_eq!(t.handle_key(key(KeyCode::Enter)), FieldOutcome::Ignored);
}

#[test]
fn text_input_unicode_and_max_len() {
    let mut t = TextInput::new("x").with_max_len(3);
    typ(&mut t, "日本語です");
    assert_eq!(text_of(&t), "日本語");
    t.handle_key(key(KeyCode::Left));
    t.handle_key(key(KeyCode::Backspace));
    assert_eq!(text_of(&t), "日語");
}

#[test]
fn validation_shows_after_typing_or_submit() {
    let mut t = TextInput::new("Host").with_validator(|s| {
        if s.is_empty() {
            Err("required".into())
        } else {
            Ok(())
        }
    });
    assert_eq!(t.error(), None, "untouched fields show no error");
    t.touch();
    assert_eq!(t.error().as_deref(), Some("required"));
    typ(&mut t, "h");
    assert_eq!(t.error(), None);
}

#[test]
fn paste_collapses_lines_in_single_line_fields() {
    let mut t = TextInput::new("x");
    t.handle_paste("line one\r\nline two\nthree\t!");
    assert_eq!(text_of(&t), "line one line two three!");
}

#[test]
fn passwords_are_never_drawn() {
    let mut pw = TextInput::password("Password");
    typ(&mut pw, "CANARY-PW-secret");
    pw.handle_paste("-pasted");
    let form = Form::new(&["OK"]).field("pw", pw);
    let shown = screen_text(&draw_form(&form, 60, 6));
    assert!(!shown.contains("CANARY"), "{shown}");
    assert!(
        !shown.contains("secret") && !shown.contains("pasted"),
        "{shown}"
    );
    assert!(shown.contains("••••"), "{shown}");
    match form.values().0.get("pw") {
        Some(super::FieldValue::Secret(s)) => {
            assert_eq!(s.expose_secret(), "CANARY-PW-secret-pasted")
        }
        other => panic!("{other:?}"),
    }
    insta::assert_snapshot!("password_field", draw_form(&form, 40, 4).backend());
}

#[test]
fn long_text_scrolls_to_the_cursor() {
    let mut t = TextInput::new("x");
    typ(&mut t, &"a".repeat(50));
    typ(&mut t, "END");
    let form = Form::new(&[]).field("x", t);
    assert!(screen_text(&draw_form(&form, 30, 1)).contains("END"));
}

// --- NumberInput ---

#[test]
fn number_input() {
    let mut n = NumberInput::new("Port", 21, 1, 65535);
    n.handle_key(key(KeyCode::Up));
    assert_eq!(n.number(), Some(22));
    typ(&mut n, "x");
    assert_eq!(n.number(), Some(22), "letters are ignored");
    for _ in 0..3 {
        n.handle_key(key(KeyCode::Backspace));
    }
    typ(&mut n, "99999");
    assert!(n.error().is_some());
    let mut low = NumberInput::new("n", 1, 1, 5);
    low.handle_key(key(KeyCode::Down));
    assert_eq!(low.number(), Some(1), "clamped at the minimum");
    low.handle_paste("4\n");
    assert_eq!(low.number(), Some(14));
}

// --- PathInput ---

#[test]
fn path_completion() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("alpha.txt"), b"").unwrap();
    std::fs::create_dir(dir.path().join("alpine")).unwrap();
    std::fs::write(dir.path().join("beta"), b"").unwrap();
    let base = format!("{}/", dir.path().display());
    let mut p =
        PathInput::new("Path", Box::new(LocalPathCompleter)).with_value(&format!("{base}al"));
    assert_eq!(p.handle_key(key(KeyCode::Tab)), FieldOutcome::Consumed);
    assert_eq!(p.text(), format!("{base}alp"));
    typ(&mut p, "i");
    p.handle_key(key(KeyCode::Tab));
    assert_eq!(p.text(), format!("{base}alpine/"));
    // Nothing more to add: Tab moves on.
    assert_eq!(p.handle_key(key(KeyCode::Tab)), FieldOutcome::Ignored);
    let candidates = LocalPathCompleter.complete(&base);
    assert_eq!(candidates.len(), 3);
}

#[test]
fn common_prefixes() {
    let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
    assert_eq!(common_prefix(&s(&["alpha", "alpine"])), "alp");
    assert_eq!(common_prefix(&s(&["x"])), "x");
    assert_eq!(common_prefix(&s(&[])), "");
    assert_eq!(common_prefix(&s(&["été", "étage"])), "ét");
}

// --- choices ---

#[test]
fn checkboxes() {
    let mut c = Checkbox::new("Keep", false);
    c.handle_key(key(KeyCode::Char(' ')));
    assert!(matches!(c.value(), super::FieldValue::Bool(true)));
    assert_eq!(c.handle_key(key(KeyCode::Char('x'))), FieldOutcome::Ignored);
    let mut t = TriStateCheckbox::new("Read", TriState::Unchanged);
    let mut seen = Vec::new();
    for _ in 0..3 {
        t.handle_key(key(KeyCode::Char(' ')));
        if let super::FieldValue::Tri(s) = t.value() {
            seen.push(s);
        }
    }
    assert_eq!(seen, [TriState::On, TriState::Off, TriState::Unchanged]);
    let form = Form::new(&[]).field("r", TriStateCheckbox::new("Read", TriState::On));
    assert_eq!(form.values().tri("r"), Some(TriState::On));
}

#[test]
fn alt_letters_are_not_typed() {
    let mut t = TextInput::new("x");
    assert_eq!(t.handle_key(alt('c')), FieldOutcome::Ignored);
    assert_eq!(text_of(&t), "");
}

#[test]
fn select_cycles_jumps_and_opens() {
    let opts = vec!["FTP".into(), "FTPS".into(), "SFTP".into()];
    let mut s = Select::new("Protocol", opts, 0);
    s.handle_key(key(KeyCode::Right));
    assert_eq!(s.selected(), 1);
    s.handle_key(key(KeyCode::Char('s')));
    assert_eq!(s.selected(), 2);
    s.handle_key(key(KeyCode::Enter));
    assert!(s.is_capturing());
    s.handle_key(key(KeyCode::Up));
    s.handle_key(key(KeyCode::Up));
    s.handle_key(key(KeyCode::Enter));
    assert!(!s.is_capturing());
    assert_eq!(s.selected(), 0);
    s.handle_key(key(KeyCode::Enter));
    s.handle_key(key(KeyCode::Esc));
    assert!(!s.is_capturing());
}

#[test]
fn open_select_keeps_esc_from_cancelling_the_form() {
    let mut form = Form::new(&["OK", "Cancel"]).field(
        "p",
        Select::new("Protocol", vec!["a".into(), "b".into()], 0),
    );
    form.handle_key(key(KeyCode::Enter)); // opens the dropdown
    assert_eq!(form.handle_key(key(KeyCode::Esc)), FormOutcome::Keep);
    assert_eq!(form.handle_key(key(KeyCode::Esc)), FormOutcome::Cancel);
}

#[test]
fn open_select_draws_its_list() {
    let mut form = Form::new(&["OK"]).field(
        "p",
        Select::new(
            "Protocol",
            vec!["FTP".into(), "FTPS".into(), "SFTP".into()],
            1,
        ),
    );
    form.handle_key(key(KeyCode::Enter));
    insta::assert_snapshot!("select_open", draw_form(&form, 40, 8).backend());
}

#[test]
fn radio_group() {
    let mut r = RadioGroup::new("Mode", vec!["Passive".into(), "Active".into()], 0);
    r.handle_key(key(KeyCode::Right));
    assert!(matches!(r.value(), super::FieldValue::Index(1)));
    r.handle_key(key(KeyCode::Right));
    assert!(matches!(r.value(), super::FieldValue::Index(1)));
    r.handle_key(key(KeyCode::Up));
    assert!(matches!(r.value(), super::FieldValue::Index(0)));
}

#[test]
fn button_row() {
    let mut b = ButtonRow::new(&["Save", "Delete", "Cancel"], 0);
    assert_eq!(b.handle_key(key(KeyCode::Right)), None);
    assert_eq!(b.current, 1);
    assert_eq!(b.handle_key(key(KeyCode::Enter)), Some(1));
    assert_eq!(b.handle_key(alt('c')), Some(2));
    assert_eq!(b.handle_key(alt('z')), None);
}

#[test]
fn list_view() {
    let items: Vec<String> = (0..30).map(|i| format!("item {i}")).collect();
    let mut l = ListView::new("", items, 5);
    l.handle_key(key(KeyCode::Down));
    l.handle_key(key(KeyCode::Char('j')));
    assert_eq!(l.selected(), 2);
    l.handle_key(key(KeyCode::PageDown));
    assert_eq!(l.selected(), 7);
    l.handle_key(key(KeyCode::End));
    assert_eq!(l.selected(), 29);
    l.handle_key(key(KeyCode::Home));
    assert_eq!(l.selected(), 0);
    l.handle_key(key(KeyCode::Up));
    assert_eq!(l.selected(), 0);
}

// --- forms ---

fn login_form() -> Form {
    Form::new(&["OK", "Cancel"])
        .field(
            "host",
            TextInput::new("Host").with_validator(|s| {
                if s.is_empty() {
                    Err("required".into())
                } else {
                    Ok(())
                }
            }),
        )
        .field("port", NumberInput::new("Port", 21, 1, 65535))
        .field("pw", TextInput::password("Password"))
        .field("save", Checkbox::new("Save password", true))
        .validate_with(|v| {
            if v.text("host") == "forbidden" {
                Err("that host is blocked".into())
            } else {
                Ok(())
            }
        })
}

#[test]
fn tab_traverses_fields_and_buttons() {
    let mut f = login_form();
    assert_eq!(f.focused_key(), Some("host"));
    for expected in [Some("port"), Some("pw"), Some("save"), None, Some("host")] {
        f.handle_key(key(KeyCode::Tab));
        assert_eq!(f.focused_key(), expected);
    }
    f.handle_key(key(KeyCode::BackTab));
    assert_eq!(f.focused_key(), None, "Shift-Tab wraps to the buttons");
}

#[test]
fn submit_validates_fields_then_the_form() {
    let mut f = login_form();
    f.handle_key(key(KeyCode::Tab));
    assert_eq!(f.handle_key(key(KeyCode::Enter)), FormOutcome::Keep);
    assert_eq!(
        f.focused_key(),
        Some("host"),
        "focus jumps to the bad field"
    );
    insta::assert_snapshot!("form_with_error", draw_form(&f, 50, 9).backend());
    typ(&mut **f_field(&mut f), "forbidden");
    assert_eq!(f.handle_key(key(KeyCode::Enter)), FormOutcome::Keep);
    for _ in 0..9 {
        f.handle_key(key(KeyCode::Backspace));
    }
    typ(&mut **f_field(&mut f), "example.com");
    assert_eq!(f.handle_key(key(KeyCode::Enter)), FormOutcome::Submit);
    let v = f.values();
    assert_eq!(v.text("host"), "example.com");
    assert_eq!(v.number("port"), Some(21));
    assert!(v.bool("save"));
    assert_eq!(
        v.secret("pw").map(|s| s.expose_secret().to_owned()),
        Some(String::new())
    );
}

/// The focused field of a form, for typing into in tests.
fn f_field(f: &mut Form) -> &mut Box<dyn Field> {
    f.focused_field_mut().expect("a field has focus")
}

#[test]
fn esc_and_cancel_button_cancel() {
    let mut f = login_form();
    assert_eq!(f.handle_key(key(KeyCode::Esc)), FormOutcome::Cancel);
    let mut f = login_form();
    for _ in 0..4 {
        f.handle_key(key(KeyCode::Tab));
    }
    f.handle_key(key(KeyCode::Right));
    assert_eq!(f.handle_key(key(KeyCode::Enter)), FormOutcome::Cancel);
    let mut f = login_form();
    assert_eq!(f.handle_key(alt('c')), FormOutcome::Cancel);
}

#[test]
fn form_snapshot_with_every_widget() {
    let form = Form::new(&["OK", "Cancel"])
        .field("host", TextInput::new("Host").with_value("example.com"))
        .field("user", TextInput::new("User").with_placeholder("anonymous"))
        .field("pw", TextInput::password("Password").with_value("x"))
        .field("port", NumberInput::new("Port", 22, 1, 65535))
        .field(
            "proto",
            Select::new("Protocol", vec!["FTP".into(), "SFTP".into()], 1),
        )
        .field(
            "mode",
            RadioGroup::new("Transfer", vec!["Passive".into(), "Active".into()], 0),
        )
        .field("save", Checkbox::new("Save password", true))
        .field(
            "r",
            TriStateCheckbox::new("Owner read", TriState::Unchanged),
        )
        .field(
            "list",
            ListView::new(
                "Recent",
                vec!["one".into(), "two".into(), "three".into()],
                3,
            ),
        );
    insta::assert_snapshot!("form_every_widget", draw_form(&form, 60, 16).backend());
}

#[test]
fn tabbed_form_switches_and_validates_every_tab() {
    let general = Form::new(&[]).field(
        "host",
        TextInput::new("Host").with_validator(|s| {
            if s.is_empty() {
                Err("required".into())
            } else {
                Ok(())
            }
        }),
    );
    let advanced = Form::new(&[])
        .field("passive", Checkbox::new("Passive", true))
        .field("note", TextInput::new("Note"));
    let mut t = TabbedForm::new(
        vec![("General", general), ("Advanced", advanced)],
        &["OK", "Cancel"],
    );
    t.handle_key(ctrl(KeyCode::PageDown));
    assert_eq!(t.current_tab(), 1);
    // `]` on a checkbox switches tabs; in a text field it is typed.
    t.handle_key(key(KeyCode::Char(']')));
    assert_eq!(t.current_tab(), 0);
    t.handle_key(key(KeyCode::Char(']')));
    assert_eq!(t.current_tab(), 0, "typed into the host field");
    insta::assert_snapshot!(
        "tabbed_form",
        {
            let mut term = Terminal::new(TestBackend::new(50, 8)).unwrap();
            let theme = theme();
            term.draw(|f| t.draw(f, f.area(), &theme)).unwrap();
            term
        }
        .backend()
    );
    // Clear the host and submit from the second tab: back to the first.
    t.handle_key(key(KeyCode::Backspace));
    t.handle_key(ctrl(KeyCode::PageDown));
    assert_eq!(t.handle_key(key(KeyCode::Enter)), FormOutcome::Keep);
    assert_eq!(t.current_tab(), 0);
    typ_into_tabbed(&mut t, "h");
    assert_eq!(t.handle_key(key(KeyCode::Enter)), FormOutcome::Submit);
    let v = t.values();
    assert_eq!(v.text("host"), "h");
    assert!(v.bool("passive"));
}

fn typ_into_tabbed(t: &mut TabbedForm, s: &str) {
    for c in s.chars() {
        t.handle_key(key(KeyCode::Char(c)));
    }
}

#[test]
fn tabbed_form_tab_reaches_the_buttons() {
    let a = Form::new(&[]).field("x", Checkbox::new("x", false));
    let mut t = TabbedForm::new(vec![("A", a)], &["OK", "Cancel"]);
    t.handle_key(key(KeyCode::Tab)); // past the last field: buttons
    t.handle_key(key(KeyCode::Right));
    assert_eq!(t.handle_key(key(KeyCode::Enter)), FormOutcome::Cancel);
}

// --- dialogs ---

#[tokio::test]
async fn form_dialog_returns_the_typed_result() {
    let (mut d, rx) = FormDialog::new("Connect", 50, login_form(), |v| {
        let host = v.text("host");
        if host == "bad" {
            return Err("cannot resolve".into());
        }
        Ok((host, v.number("port")))
    });
    typ_dialog(&mut d, "bad");
    assert_eq!(
        d.handle_key(key(KeyCode::Enter)),
        ModalOutcome::Keep,
        "error keeps it open"
    );
    assert!(screen_text(&draw_modal(&mut d, 80, 20)).contains("cannot resolve"));
    for _ in 0..3 {
        d.handle_key(key(KeyCode::Backspace));
    }
    typ_dialog(&mut d, "ok.example");
    assert_eq!(d.handle_key(key(KeyCode::Enter)), ModalOutcome::Close);
    assert_eq!(rx.await.unwrap(), Some(("ok.example".to_owned(), Some(21))));
}

fn typ_dialog(d: &mut dyn Modal, s: &str) {
    for c in s.chars() {
        d.handle_key(key(KeyCode::Char(c)));
    }
}

#[tokio::test]
async fn cancelled_or_dropped_dialogs_report_none() {
    let (mut d, rx) = FormDialog::new("x", 40, login_form(), |_| Ok(()));
    assert_eq!(d.handle_key(key(KeyCode::Esc)), ModalOutcome::Close);
    assert_eq!(rx.await.unwrap(), None);
    let (d, rx) = FormDialog::new("x", 40, login_form(), |_| Ok(()));
    drop(d);
    assert!(rx.await.is_err());
}

#[tokio::test]
async fn confirm_dialog() {
    for (keys, default_yes, expected) in [
        (vec![key(KeyCode::Enter)], true, true),
        (vec![key(KeyCode::Enter)], false, false),
        (vec![key(KeyCode::Char('y'))], false, true),
        (vec![key(KeyCode::Char('n'))], true, false),
        (vec![key(KeyCode::Esc)], true, false),
        (vec![key(KeyCode::Right), key(KeyCode::Enter)], true, false),
    ] {
        let (mut m, rx) = confirm("Delete", "Delete 3 files?", default_yes);
        let mut outcome = ModalOutcome::Keep;
        for k in keys {
            outcome = m.handle_key(k);
        }
        assert_eq!(outcome, ModalOutcome::Close);
        assert_eq!(rx.await.unwrap(), expected);
    }
    let (mut m, _rx) = confirm("Delete", "Delete 3 files?\nThis cannot be undone.", false);
    insta::assert_snapshot!("confirm", draw_modal(&mut *m, 60, 12).backend());
}

#[tokio::test]
async fn message_and_error_dialogs() {
    let (mut m, rx) = message("Done", "Queue finished.");
    assert_eq!(m.handle_key(key(KeyCode::Enter)), ModalOutcome::Close);
    rx.await.unwrap();

    let inner = std::io::Error::other("connection reset");
    let outer = courier_ftp_core::Error::Connection(format!("{inner}"));
    #[derive(Debug)]
    struct Wrapped(std::io::Error);
    impl std::fmt::Display for Wrapped {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("listing failed")
        }
    }
    impl std::error::Error for Wrapped {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }
    let (mut m, _rx) = error(&Wrapped(inner));
    let shown = screen_text(&draw_modal(&mut *m, 70, 12));
    assert!(
        shown.contains("listing failed") && shown.contains("caused by: connection reset"),
        "{shown}"
    );
    let (mut m, _rx) = error(&outer);
    assert!(screen_text(&draw_modal(&mut *m, 70, 12)).contains("connection failed"));
}

#[tokio::test]
async fn prompt_dialogs() {
    let (mut m, rx) = prompt_text("Rename", "New name", "old.txt");
    m.handle_key(key(KeyCode::Backspace));
    m.handle_key(key(KeyCode::Backspace));
    m.handle_key(key(KeyCode::Backspace));
    typ_dialog(&mut *m, "md");
    m.handle_key(key(KeyCode::Enter));
    assert_eq!(rx.await.unwrap().as_deref(), Some("old.md"));

    let (mut m, rx) = prompt_password("Password", "Password for bob");
    typ_dialog(&mut *m, "CANARY-PW-1");
    assert!(!screen_text(&draw_modal(&mut *m, 60, 10)).contains("CANARY"));
    m.handle_key(key(KeyCode::Enter));
    assert_eq!(
        rx.await
            .unwrap()
            .map(|s| s.expose_secret().to_owned())
            .as_deref(),
        Some("CANARY-PW-1")
    );

    let (mut m, rx) = choose("Pick", vec!["a".into(), "b".into(), "c".into()]);
    m.handle_key(key(KeyCode::Down));
    m.handle_key(key(KeyCode::Down));
    m.handle_key(key(KeyCode::Enter));
    assert_eq!(rx.await.unwrap(), Some(2));
}

#[test]
fn progress_dialog() {
    let (mut d, handle) = ProgressDialog::new("Deleting");
    handle.update("Deleting /var/www/old", 3, Some(12));
    insta::assert_snapshot!("progress", draw_modal(&mut d, 60, 9).backend());
    assert!(!d.is_done());
    handle.finish();
    assert!(d.is_done());

    let (mut d, handle) = ProgressDialog::new("Searching");
    assert_eq!(d.handle_key(key(KeyCode::Esc)), ModalOutcome::Close);
    assert!(handle.cancel_token().is_cancelled());
}

#[test]
fn tiny_terminals_do_not_panic() {
    let (mut d, _rx) = FormDialog::new("x", 50, login_form(), |_| Ok(()));
    let shown = screen_text(&draw_modal(&mut d, 12, 3));
    assert!(shown.contains("terminal"), "{shown}");
    let (mut m, _rx) = confirm("t", "text", true);
    let _ = draw_modal(&mut *m, 1, 1);
    let (mut p, _h) = ProgressDialog::new("p");
    let _ = draw_modal(&mut p, 5, 2);
}

#[tokio::test]
async fn nested_dialogs_route_to_the_top() {
    use crate::{config::Config, ui::MainScreen};
    let mut screen = MainScreen::new(Config::builtin(), theme());
    let (editor, editor_rx) = FormDialog::new("Site", 50, login_form(), |v| Ok(v.text("host")));
    screen.push_modal(Box::new(editor));
    for c in "site".chars() {
        screen.handle_key(key(KeyCode::Char(c)));
    }
    let (question, confirm_rx) = confirm("Discard?", "Discard changes?", false);
    screen.push_modal(question);
    screen.handle_key(key(KeyCode::Char('n'))); // answers the confirm only
    assert!(!confirm_rx.await.unwrap());
    assert!(screen.has_modal(), "the editor is still open");
    screen.handle_key(key(KeyCode::Enter));
    assert_eq!(editor_rx.await.unwrap().as_deref(), Some("site"));
    assert!(!screen.has_modal());
}

#[test]
fn paste_reaches_the_focused_field_of_the_top_dialog() {
    use crate::{config::Config, ui::MainScreen};
    let mut screen = MainScreen::new(Config::builtin(), theme());
    let (m, _rx) = prompt_text("Path", "Path", "");
    screen.push_modal(m);
    screen.handle_paste("/var/www\n");
    let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
    t.draw(|f| screen.draw(f)).unwrap();
    assert!(screen_text(&t).contains("/var/www"));
}
