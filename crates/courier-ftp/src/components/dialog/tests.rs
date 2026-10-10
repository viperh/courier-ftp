//! Dialog and form unit tests (T52).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::{collections::BTreeMap, sync::Arc};

use pretty_assertions::assert_eq;
use proptest::prelude::*;
use ratatui::{Terminal, backend::TestBackend, layout::Rect};
use tokio::{sync::mpsc, time::Instant};

use super::*;
use crate::{
    components::{
        modal::{MAX_DEPTH, ModalStack},
        widgets::{
            ButtonRole, Checkbox, ListRow, ListView, NumberInput, RadioGroup, SecretInput, Select,
            SelectOption, TextArea, TextInput, TriState, TriStateCheckbox,
        },
    },
    keymap::chord::KeyChord,
    testing::buffer_to_string,
    ui::{
        symbols::Symbols,
        theme::{Theme, ThemePreset},
    },
};

pub(super) fn k(s: &str) -> KeyChord {
    s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
}

/// Renders a type-erased dialog alone on a `w`×`h` screen.
pub(super) fn render_any(d: &mut dyn AnyDialog, w: u16, h: u16) -> String {
    let theme = Theme::load(ThemePreset::Default, &BTreeMap::new(), false).0;
    let symbols = Symbols::unicode();
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| {
        let cx = DrawCx {
            theme: &theme,
            symbols: &symbols,
            focused: true,
            now: Instant::now(),
            spinner: None,
        };
        d.render(f, f.area(), &cx);
    })
    .unwrap();
    buffer_to_string(t.backend().buffer())
}

fn render<D: Dialog>(d: D, w: u16, h: u16) -> (String, Box<dyn AnyDialog>) {
    let (mut any, _rx) = hosted(d);
    let s = render_any(any.as_mut(), w, h);
    (s, any)
}

fn closed<T>(s: &DialogStep<T>) -> Option<Option<&T>> {
    match s {
        DialogStep::Close(r) => Some(r.as_ref()),
        _ => None,
    }
}

fn required() -> crate::components::widgets::Validator {
    Arc::new(|v: &str| {
        if v.trim().is_empty() {
            Err("Host is required".to_owned())
        } else {
            Ok(())
        }
    })
}

/// Host, port, user, password.
pub(super) fn login_form() -> Form {
    Form::builder()
        .field(
            "host",
            "Host",
            FieldWidget::Text(TextInput::new("").validator(required())),
        )
        .help("Server name or IP address")
        .field(
            "port",
            "Port",
            FieldWidget::Number(NumberInput::new(Some(21), 1, 65535)),
        )
        .field("user", "User", FieldWidget::Text(TextInput::new("")))
        .field(
            "password",
            "Password",
            FieldWidget::Secret(SecretInput::new()),
        )
        .cross_validate(|v| {
            if v.text("user").is_empty()
                && v.secret("password").is_some_and(|p| !p.expose().is_empty())
            {
                vec![("user", "A password needs a user".to_owned())]
            } else {
                Vec::new()
            }
        })
        .build()
}

pub(super) fn login_dialog() -> FormDialog<(String, i64, String)> {
    FormDialog::new("Connect", login_form(), |v| {
        Ok((
            v.text("host").to_owned(),
            v.number("port").unwrap_or(0),
            v.text("user").to_owned(),
        ))
    })
}

/// One form with every widget kind.
pub(super) fn all_widgets_form() -> Form {
    let mut sel = Select::new(vec![
        SelectOption::new("FTP", "ftp".to_owned()),
        SelectOption::new("FTPS (explicit)", "ftpes".to_owned()),
        SelectOption::new("SFTP", "sftp".to_owned()),
    ]);
    sel.select(2);
    Form::builder()
        .field(
            "host",
            "Host",
            FieldWidget::Text(TextInput::new("example.org").validator(required())),
        )
        .help("Server name or IP address")
        .field(
            "password",
            "Password",
            FieldWidget::Secret(SecretInput::new()),
        )
        .field(
            "port",
            "Port",
            FieldWidget::Number(NumberInput::new(Some(22), 1, 65535)),
        )
        .field(
            "passive",
            "Passive mode",
            FieldWidget::Check(Checkbox::new("", true)),
        )
        .field(
            "exec",
            "Execute",
            FieldWidget::Tri(TriStateCheckbox::new("", TriState::Unchanged, true)),
        )
        .field("protocol", "Protocol", FieldWidget::Select(sel))
        .field(
            "mode",
            "Transfer mode",
            FieldWidget::Radio(RadioGroup::new(&["Auto", "ASCII", "Binary"]).horizontal()),
        )
        .field(
            "remote",
            "Remote directory",
            FieldWidget::Text(TextInput::new("/var/www")),
        )
        .field(
            "comments",
            "Comments",
            FieldWidget::Area(TextArea::new("first line\nsecond line").visible_rows(2)),
        )
        .field(
            "columns",
            "Columns",
            FieldWidget::List(
                ListView::new(vec![
                    ListRow::check("Name", "name".to_owned(), true),
                    ListRow::check("Size", "size".to_owned(), true),
                    ListRow::check("Owner", "owner".to_owned(), false),
                ])
                .visible_rows(3),
            ),
        )
        .build()
}

#[test]
fn confirm_danger_default_is_no() {
    let mut d = confirm("Delete", "Delete 3 files?", ConfirmOpts::danger("Delete"));
    assert_eq!(d.focused(), 1, "initial focus on Cancel");
    let s = d.handle_key(k("enter"));
    assert_eq!(closed(&s), Some(Some(&false)));
    assert_eq!(d.focused(), 1, "focus did not move");
    let mut d = confirm("Delete", "Delete 3 files?", ConfirmOpts::danger("Delete"));
    assert_eq!(
        closed(&d.handle_action(&Action::DialogSubmit)),
        Some(Some(&false))
    );
    // The mnemonic confirms explicitly (no text widget: plain letters work).
    let mut d = confirm("Delete", "Delete 3 files?", ConfirmOpts::danger("Delete"));
    assert_eq!(closed(&d.handle_key(k("d"))), Some(Some(&true)));
    let mut d = confirm("Delete", "Delete 3 files?", ConfirmOpts::danger("Delete"));
    assert_eq!(closed(&d.handle_key(k("alt-c"))), Some(Some(&false)));
    // Esc is left to the key table (the host turns DialogCancel into None).
    let mut d = confirm("Q", "?", ConfirmOpts::new());
    assert!(matches!(d.handle_key(k("esc")), DialogStep::Ignored));
    assert_eq!(d.focused(), 0, "default OK");
    let (mut any, mut rx) = hosted(confirm("Q", "?", ConfirmOpts::new()));
    assert!(matches!(
        any.handle_action(&Action::DialogCancel),
        AnyStep::Closed
    ));
    assert_eq!(rx.try_recv().unwrap(), None);
    // Tab moves between buttons; Quit only confirms the quit dialog.
    let mut d = confirm("Q", "?", ConfirmOpts::new());
    d.handle_action(&Action::NextField);
    assert_eq!(d.focused(), 1);
    assert!(matches!(
        d.handle_action(&Action::Quit),
        DialogStep::Ignored
    ));
    let mut d = confirm("Q", "?", ConfirmOpts::danger("Quit")).confirm_on_quit();
    assert_eq!(closed(&d.handle_action(&Action::Quit)), Some(Some(&true)));
}

#[test]
fn button_mnemonics_alt_and_plain() {
    let mut d = FormDialog::new(
        "Rename",
        Form::builder()
            .field("name", "Name", FieldWidget::Text(TextInput::new("")))
            .field("keep", "Keep", FieldWidget::Check(Checkbox::new("", false)))
            .build(),
        |v| Ok(v.text("name").to_owned()),
    );
    // Plain `c` is typed into the focused text field.
    assert!(matches!(d.handle_key(k("c")), DialogStep::Continue));
    assert_eq!(d.form().values().text("name"), "c");
    // alt-c presses Cancel.
    assert_eq!(closed(&d.handle_key(k("alt-c"))), Some(None));
    // With a checkbox focused, plain letters are mnemonics.
    let mut d = FormDialog::new(
        "Rename",
        Form::builder()
            .field("keep", "Keep", FieldWidget::Check(Checkbox::new("", false)))
            .build(),
        |v| Ok(v.bool("keep")),
    );
    assert_eq!(closed(&d.handle_key(k("o"))), Some(Some(&false)));
    let mut d = FormDialog::new(
        "Rename",
        Form::builder()
            .field("keep", "Keep", FieldWidget::Check(Checkbox::new("", false)))
            .build(),
        |v| Ok(v.bool("keep")),
    );
    d.handle_key(k("space"));
    assert_eq!(closed(&d.handle_key(k("c"))), Some(None));
}

#[test]
fn choose_initial_focus_safe_option() {
    let opts = vec![
        ChoiceOption::new("Overwrite", ButtonRole::Danger),
        ChoiceOption::new("Resume", ButtonRole::Normal),
        ChoiceOption::new("Skip", ButtonRole::Safe),
    ];
    let mut d = choose("File exists", "a.txt exists.", opts.clone());
    assert_eq!(d.focused(), 2);
    assert_eq!(
        closed(&d.handle_action(&Action::DialogSubmit)),
        Some(Some(&2))
    );
    let mut d = choose("File exists", "a.txt exists.", opts);
    assert_eq!(closed(&d.handle_key(k("r"))), Some(Some(&1)));
    let d = choose(
        "x",
        "y",
        vec![
            ChoiceOption::new("One", ButtonRole::Normal),
            ChoiceOption::new("Two", ButtonRole::Normal),
        ],
    );
    assert_eq!(d.focused(), 0, "no Safe option: the first");
}

#[derive(Debug, thiserror::Error)]
#[error("connection refused")]
struct Refused;

#[derive(Debug, thiserror::Error)]
#[error("could not connect to example.org")]
struct Connect(#[source] Refused);

#[derive(Debug, thiserror::Error)]
#[error("upload failed")]
struct Upload(#[source] Connect);

#[test]
fn error_dialog_shows_cause_chain() {
    let e = Upload(Connect(Refused));
    let mut d = error("Copying a.txt", &e);
    let (before, _) = render(error("Copying a.txt", &e), 80, 24);
    assert!(before.contains("Copying a.txt: upload failed"), "{before}");
    assert!(!before.contains("Caused by"), "{before}");
    assert!(before.contains("[ Details ]"), "{before}");
    assert!(before.contains("Error"), "{before}");
    assert!(matches!(d.handle_key(k("d")), DialogStep::Continue));
    assert!(d.is_expanded());
    let (mut any, _rx) = hosted(d);
    let after = render_any(any.as_mut(), 80, 24);
    let lines: Vec<&str> = after
        .lines()
        .filter(|l| l.contains("upload failed") || l.contains("Caused by"))
        .collect();
    assert_eq!(lines.len(), 3, "{after}");
    assert!(after.contains("Caused by: could not connect to example.org"));
    assert!(after.contains("Caused by: connection refused"));
    // A single error has no Details button.
    let (single, _) = render(error("ctx", &Refused), 80, 24);
    assert!(!single.contains("Details"), "{single}");
    // color_eyre reports.
    let report = color_eyre::eyre::eyre!("inner").wrap_err("outer");
    let (r, _) = render(error_report("Saving", &report), 80, 24);
    assert!(r.contains("Saving: outer"), "{r}");
    // Message levels read without colour.
    for (level, prefix) in [
        (MessageLevel::Info, "Info: Done"),
        (MessageLevel::Warning, "Warning: Done"),
        (MessageLevel::Error, "Error: Done"),
    ] {
        let (m, _) = render(message("Done", "All files copied.", level), 80, 24);
        assert!(m.contains(prefix), "{m}");
    }
}

#[test]
fn form_field_and_cross_validation() {
    let mut d = login_dialog();
    // Empty host: the field validator blocks submit and focuses it.
    d.form_mut().focus_field("password");
    d.form_mut().handle_paste("secret");
    assert!(matches!(
        d.handle_action(&Action::DialogSubmit),
        DialogStep::Continue
    ));
    assert_eq!(d.form().error("host"), Some("Host is required"));
    assert_eq!(d.form().error("user"), Some("A password needs a user"));
    assert_eq!(d.form().focused_id(), Some("host"), "first error focused");
    let (screen, _) = render_form(&mut d);
    assert!(screen.contains("! Host is required"), "{screen}");
    assert!(screen.contains("! A password needs a user"), "{screen}");
    // Fix both: the typed result is delivered.
    d.form_mut().handle_paste("example.org");
    d.form_mut().focus_field("user");
    d.form_mut().handle_paste("anna");
    let s = d.handle_action(&Action::DialogSubmit);
    assert_eq!(
        closed(&s),
        Some(Some(&("example.org".to_owned(), 21, "anna".to_owned())))
    );
    // `map` errors are shown the same way.
    let mut d = FormDialog::new("x", login_form(), |v| {
        if v.text("host") == "bad" {
            Err(vec![("host", "Unknown host".to_owned())])
        } else {
            Ok(())
        }
    });
    d.form_mut().handle_paste("bad");
    assert!(matches!(
        d.handle_action(&Action::DialogSave),
        DialogStep::Continue
    ));
    assert_eq!(d.form().error("host"), Some("Unknown host"));
    // Leaving a field runs its validator.
    let mut d = login_dialog();
    d.handle_action(&Action::NextField);
    assert_eq!(d.form().error("host"), Some("Host is required"));
    assert_eq!(d.form().focused_id(), Some("port"));
}

fn render_form<T: Send + 'static>(d: &mut FormDialog<T>) -> (String, ()) {
    let theme = Theme::load(ThemePreset::Default, &BTreeMap::new(), false).0;
    let symbols = Symbols::unicode();
    let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
    t.draw(|f| {
        let cx = DrawCx {
            theme: &theme,
            symbols: &symbols,
            focused: true,
            now: Instant::now(),
            spinner: None,
        };
        let r = dialog_rect(d.size(f.area()), f.area(), |w| d.measure(w)).unwrap();
        let title = d.title().into_owned();
        let inner = draw_frame(f, r, &title, &cx);
        d.render(f, inner, &cx);
    })
    .unwrap();
    (buffer_to_string(t.backend().buffer()), ())
}

#[test]
fn form_hidden_fields_not_validated_nor_focusable() {
    let mut f = login_form();
    f.set_visible("host", false);
    assert_eq!(
        f.focused_id(),
        Some("port"),
        "focus moved off the hidden field"
    );
    assert!(f.validate(), "hidden host is not validated");
    assert!(!f.focus_field("host"));
    let mut seen = Vec::new();
    for _ in 0..5 {
        f.move_focus(true);
        seen.push(f.focused_id());
    }
    assert_eq!(
        seen,
        [
            Some("user"),
            Some("password"),
            None,
            Some("port"),
            Some("user")
        ]
    );
    // Hidden fields keep their values.
    f.set_visible("host", true);
    f.focus_field("host");
    f.handle_paste("h");
    f.set_visible("host", false);
    assert_eq!(f.values().text("host"), "h");
}

#[test]
fn form_disabled_field_shows_reason() {
    let mut d = login_dialog();
    d.form_mut()
        .set_enabled("user", Err("Anonymous login uses no user name".into()));
    assert!(!d.form_mut().focus_field("user"));
    let (screen, _) = render_form(&mut d);
    assert!(
        screen.contains("Anonymous login uses no user name"),
        "{screen}"
    );
    d.form_mut().focus_field("port");
    d.form_mut().move_focus(true);
    assert_eq!(d.form().focused_id(), Some("password"));
}

#[test]
fn form_dirty_tracking() {
    let mut f = login_form();
    assert!(!f.is_dirty());
    f.handle_key(k("x"));
    assert!(f.is_dirty());
    f.handle_key(k("backspace"));
    assert!(!f.is_dirty(), "changed back");
    f.focus_field("password");
    f.handle_key(k("a"));
    assert!(f.is_dirty());
    f.handle_key(k("backspace"));
    assert!(!f.is_dirty());
    f.focus_field("port");
    f.handle_key(k("up"));
    assert!(f.is_dirty());
    f.handle_key(k("down"));
    assert!(!f.is_dirty());
    // Prompts do not guard against losing typed text.
    let mut p = prompt_text("New folder", "Name", "", None);
    p.handle_key(k("x"));
    assert!(!p.is_dirty());
}

#[test]
fn form_on_change_shows_and_hides_fields() {
    let mut f = Form::builder()
        .field(
            "anon",
            "Anonymous",
            FieldWidget::Check(Checkbox::new("", false)),
        )
        .field("user", "User", FieldWidget::Text(TextInput::new("")))
        .on_change(|form, id| {
            if id == "anon" {
                let anon = form.values().bool("anon");
                form.set_visible("user", !anon);
            }
        })
        .build();
    f.handle_key(k("space"));
    assert!(!f.field("user").unwrap().visible);
    f.handle_key(k("space"));
    assert!(f.field("user").unwrap().visible);
}

pub(super) fn tabbed() -> TabbedForm<String> {
    let general = Form::builder()
        .field(
            "host",
            "Host",
            FieldWidget::Text(TextInput::new("example.org")),
        )
        .build();
    let advanced = Form::builder()
        .field(
            "remote",
            "Remote directory",
            FieldWidget::Text(TextInput::new("").validator(Arc::new(|v: &str| {
                if v.starts_with('/') || v.is_empty() {
                    Ok(())
                } else {
                    Err("Must be absolute".to_owned())
                }
            }))),
        )
        .field(
            "bypass",
            "Bypass proxy",
            FieldWidget::Check(Checkbox::new("", false)),
        )
        .build();
    let transfer = Form::builder()
        .field(
            "limit",
            "Connection limit",
            FieldWidget::Number(NumberInput::new(Some(2), 1, 10)),
        )
        .build();
    TabbedForm::new(
        "Site",
        vec![
            ("General", general),
            ("Advanced", advanced),
            ("Transfer", transfer),
        ],
        |v| Ok(v.text("host").to_owned()),
    )
}

#[test]
fn tabbed_form_switches_to_first_page_with_error() {
    let mut t = tabbed();
    t.handle_action(&Action::NextFormTab);
    assert_eq!(t.inner().active_page(), 1);
    t.handle_key(k("x"));
    t.handle_action(&Action::NextField);
    assert_eq!(t.inner().form().focused_id(), Some("bypass"));
    t.handle_action(&Action::NextFormTab);
    t.handle_action(&Action::NextFormTab);
    assert_eq!(t.inner().active_page(), 0, "wraps");
    t.handle_action(&Action::PrevFormTab);
    assert_eq!(t.inner().active_page(), 2);
    t.handle_action(&Action::PrevFormTab);
    assert_eq!(
        t.inner().form().focused_id(),
        Some("bypass"),
        "focus kept per page"
    );
    t.handle_action(&Action::NextFormTab);
    t.handle_action(&Action::NextFormTab);
    assert!(matches!(
        t.handle_action(&Action::DialogSave),
        DialogStep::Continue
    ));
    assert_eq!(t.inner().active_page(), 1, "first page with an error");
    assert_eq!(t.inner().form().focused_id(), Some("remote"));
    assert_eq!(t.inner().form().error("remote"), Some("Must be absolute"));
    t.handle_key(k("ctrl-u"));
    t.handle_key(k("/"));
    let s = t.handle_action(&Action::DialogSubmit);
    assert_eq!(closed(&s), Some(Some(&"example.org".to_owned())));
}

#[test]
fn modal_depth_limit_refuses_ninth() {
    let (tx, _rx) = mpsc::unbounded_channel();
    let mut stack = ModalStack::new(tx);
    let mut rxs = Vec::new();
    for i in 0..MAX_DEPTH {
        rxs.push(stack.push(message(&format!("m{i}"), "x", MessageLevel::Info)));
    }
    assert_eq!(stack.depth(), MAX_DEPTH);
    let mut ninth = stack.push(message("m9", "x", MessageLevel::Info));
    assert_eq!(stack.depth(), MAX_DEPTH);
    assert_eq!(ninth.try_recv().unwrap(), None, "refused: None at once");
    for rx in &mut rxs {
        assert!(rx.try_recv().is_err(), "still open");
    }
    stack.close_all();
    for mut rx in rxs {
        assert_eq!(rx.try_recv().unwrap(), None);
    }
}

#[test]
fn dialog_text_is_sanitised() {
    let evil = "a\x1b]52;c;aGk=\x07b";
    let (screen, _) = render(message(evil, evil, MessageLevel::Info), 80, 24);
    assert!(screen.contains("Info: a^[]52;c;aGk=^Gb"), "{screen}");
    assert!(screen.matches("a^[]52;c;aGk=^Gb").count() >= 2, "{screen}");
    assert!(!screen.contains('\x1b'));
    let (screen, _) = render(text_viewer(evil, evil.to_owned()), 80, 24);
    assert!(screen.contains("a^[]52;c;aGk=^Gb"), "{screen}");
}

#[test]
fn dialog_rect_sizes() {
    let screen = Rect::new(0, 0, 80, 24);
    let fit = DialogSize::Fit {
        min_w: 40,
        max_w: 76,
    };
    assert_eq!(
        dialog_rect(fit, screen, |_| (10, 3)),
        Some(Rect::new(20, 9, 40, 5))
    );
    assert_eq!(
        dialog_rect(fit, screen, |w| (w, 100)),
        Some(Rect::new(2, 1, 76, 22))
    );
    assert_eq!(
        dialog_rect(fit, Rect::new(0, 0, 50, 10), |w| (w, 3)),
        Some(Rect::new(2, 2, 46, 5))
    );
    assert_eq!(dialog_rect(fit, Rect::new(0, 0, 29, 24), |_| (1, 1)), None);
    assert_eq!(
        dialog_rect(fit, Rect::new(0, 0, 39, 24), |_| (1, 1)),
        None,
        "min_w"
    );
    assert_eq!(
        dialog_rect(fit, Rect::new(0, 0, 42, 24), |w| (w, 1)),
        Some(Rect::new(1, 10, 40, 3))
    );
    assert_eq!(dialog_rect(fit, Rect::new(0, 0, 80, 7), |_| (1, 1)), None);
    assert_eq!(
        dialog_rect(DialogSize::Fixed { w: 90, h: 10 }, screen, |_| (1, 1)),
        None
    );
    assert_eq!(
        dialog_rect(DialogSize::Percent { w: 50, h: 50 }, screen, |_| (1, 1)),
        Some(Rect::new(20, 6, 40, 12))
    );
    assert_eq!(
        dialog_rect(DialogSize::FullScreen, screen, |_| (1, 1)),
        Some(screen)
    );
}

#[test]
fn too_small_still_cancels() {
    let (mut any, mut rx) = hosted(confirm("Q", "?", ConfirmOpts::new()));
    let s = render_any(any.as_mut(), 29, 8);
    assert!(s.contains("Terminal too small"), "{s}");
    assert!(matches!(any.handle_key(k("esc")), AnyStep::Ignored));
    assert!(matches!(
        any.handle_action(&Action::DialogCancel),
        AnyStep::Closed
    ));
    assert_eq!(rx.try_recv().unwrap(), None);
}

#[test]
fn wrap_text_by_width() {
    assert_eq!(wrap_text("aaa bbb ccc", 7), ["aaa bbb", "ccc"]);
    assert_eq!(wrap_text("abcdefghij", 4), ["abcd", "efgh", "ij"]);
    assert_eq!(wrap_text("a\nb", 10), ["a", "b"]);
    assert_eq!(wrap_text("日本語 テキスト", 6), ["日本語", "テキス", "ト"]);
}

/// Every standard dialog and a sample form, boxed.
pub(super) fn every_dialog() -> Vec<Box<dyn AnyDialog>> {
    let e = Upload(Connect(Refused));
    let mut details = error("Copying", &e);
    details.handle_key(k("d"));
    let mut v: Vec<Box<dyn AnyDialog>> = vec![
        hosted(confirm(
            "Delete",
            "Delete 3 files?",
            ConfirmOpts::danger("Delete"),
        ))
        .0,
        hosted(message("Done", "All files copied.", MessageLevel::Info)).0,
        hosted(details).0,
        hosted(prompt_text("New folder", "Name", "docs", None)).0,
        hosted(prompt_password("Password", "Password for anna@example.org")).0,
        hosted(choose(
            "File exists",
            "The target file already exists.",
            vec![
                ChoiceOption::new("Overwrite", ButtonRole::Danger),
                ChoiceOption::new("Skip", ButtonRole::Safe),
            ],
        ))
        .0,
        hosted(text_viewer("Listing", "a\nb\nc".repeat(50))).0,
        hosted(problems(vec!["one".into(), "two".into()])).0,
        hosted(FormDialog::new("All widgets", all_widgets_form(), |_| {
            Ok(())
        }))
        .0,
        hosted(tabbed()).0,
    ];
    let (p, h) = progress(
        "Deleting",
        "Deleting files…",
        tokio_util::sync::CancellationToken::new(),
        ProgressOpts::default(),
    );
    h.set_progress(5, Some(10));
    v.push(hosted(p).0);
    v
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]
    #[test]
    fn prop_render_any_size(w in 1u16..=300, h in 1u16..=100) {
        for mut d in every_dialog() {
            let s = render_any(d.as_mut(), w, h);
            if w < MIN_SCREEN.0 || h < MIN_SCREEN.1 {
                let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
                if w >= 12 {
                    prop_assert!(flat.contains("Terminal too"), "{}x{}: {}", w, h, s);
                }
            }
        }
    }
}

#[test]
fn render_extreme_sizes() {
    for (w, h) in [
        (1, 1),
        (30, 8),
        (31, 9),
        (300, 100),
        (40, 8),
        (30, 100),
        (300, 8),
    ] {
        for mut d in every_dialog() {
            let _ = render_any(d.as_mut(), w, h);
        }
    }
}
