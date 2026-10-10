//! Snapshot tests of every standard dialog and the form widgets over the dimmed
//! Classic shell, at 80×24 and 160×48 (D15). Snapshots live in `dialog/snapshots/`.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::{sync::Arc, time::Duration};

use futures::future::BoxFuture;
use insta::assert_snapshot;
use tokio_util::sync::CancellationToken;

use super::{
    tests::{all_widgets_form, k, login_dialog, tabbed},
    *,
};
use crate::{
    components::widgets::{
        ButtonRole, Completion, ListRow, ListView, PathCompleter, PathInput, TextInput,
    },
    config::Config,
    testing::AppHarness,
    ui::symbols::UnicodeSymbols,
};

const SIZES: [(u16, u16); 2] = [(80, 24), (160, 48)];

fn harness() -> AppHarness {
    AppHarness::new(Config::default())
}

/// Snapshots `name_80x24` and `name_160x48` after `setup`.
fn snap_both(name: &str, setup: impl Fn(&mut AppHarness)) {
    for (w, h) in SIZES {
        let mut hs = harness();
        hs.render(w, h);
        setup(&mut hs);
        assert_snapshot!(format!("{name}_{w}x{h}"), hs.render(w, h));
    }
}

#[test]
fn snap_confirm() {
    snap_both("snap_confirm", |h| {
        h.app_mut().modals.push(confirm(
            "Overwrite",
            "Overwrite the bookmark \"Projects\"?",
            ConfirmOpts::new(),
        ));
    });
}

#[test]
fn snap_confirm_danger() {
    snap_both("snap_confirm_danger", |h| {
        h.app_mut().modals.push(confirm(
            "Delete",
            "Delete 3 files and 1 directory from example.org? This cannot be undone.",
            ConfirmOpts::danger("Delete"),
        ));
    });
}

#[test]
fn snap_message_levels() {
    for (name, level) in [
        ("snap_message_info", MessageLevel::Info),
        ("snap_message_warning", MessageLevel::Warning),
        ("snap_message_error", MessageLevel::Error),
    ] {
        snap_both(name, |h| {
            h.app_mut().modals.push(message(
                "Transfer",
                "12 files were transferred.\nThe queue is empty.",
                level,
            ));
        });
    }
}

#[derive(Debug, thiserror::Error)]
#[error("connection reset by peer")]
struct Reset;

#[derive(Debug, thiserror::Error)]
#[error("could not read the directory listing")]
struct Listing(#[source] Reset);

#[test]
fn snap_error_details() {
    snap_both("snap_error_details", |h| {
        let mut d = error("Refreshing /var/www", &Listing(Reset));
        d.handle_key(k("d"));
        h.app_mut().modals.push(d);
    });
}

#[test]
fn snap_prompt_text_with_error() {
    snap_both("snap_prompt_text_with_error", |h| {
        let v: crate::components::widgets::Validator = Arc::new(|s: &str| {
            if s.contains('/') {
                Err("A name cannot contain `/`".to_owned())
            } else {
                Ok(())
            }
        });
        h.app_mut()
            .modals
            .push(prompt_text("New directory", "Name", "a/b", Some(v)));
        h.keys("enter");
    });
}

#[test]
fn snap_prompt_password() {
    snap_both("snap_prompt_password", |h| {
        h.app_mut().modals.push(prompt_password(
            "Password required",
            "Password for anna@example.org",
        ));
        h.keys("h u n t e r 2");
        let screen = h.render(80, 24);
        assert!(!screen.contains("hunter2") && !screen.contains("hunt"));
        assert!(screen.contains("•••••••"), "{screen}");
    });
}

#[test]
fn snap_choose() {
    snap_both("snap_choose", |h| {
        h.app_mut().modals.push(choose(
            "Target file exists",
            "The file index.html already exists on the server (2.1 KiB, 2024-05-02).",
            vec![
                ChoiceOption::new("Overwrite", ButtonRole::Danger),
                ChoiceOption::new("Resume", ButtonRole::Normal),
                ChoiceOption::new("Rename", ButtonRole::Normal),
                ChoiceOption::new("Skip", ButtonRole::Safe),
            ],
        ));
    });
}

fn open_progress(h: &mut AppHarness, total: Option<u64>) -> (ProgressHandle, CancellationToken) {
    let token = CancellationToken::new();
    let t = token.clone();
    let handle = h.with_app(move |a| {
        let (d, handle) = progress(
            "Deleting",
            "Deleting /var/www/old…",
            t,
            ProgressOpts::default(),
        );
        a.modals.push(d);
        handle
    });
    h.advance(Duration::from_millis(400));
    handle.set_progress(37, total);
    (handle, token)
}

#[test]
fn snap_progress_determinate() {
    snap_both("snap_progress_determinate", |h| {
        let _ = open_progress(h, Some(100));
    });
}

#[test]
fn snap_progress_indeterminate() {
    snap_both("snap_progress_indeterminate", |h| {
        let _ = open_progress(h, None);
    });
}

#[test]
fn snap_progress_cancelling() {
    snap_both("snap_progress_cancelling", |h| {
        let (_, token) = open_progress(h, Some(100));
        h.keys("esc");
        assert!(token.is_cancelled());
    });
}

#[test]
fn snap_text_viewer() {
    snap_both("snap_text_viewer", |h| {
        let text: String = (0..200)
            .map(|i| {
                format!(
                    "drwxr-xr-x  2 www www 4096 May  2 10:{:02} dir{i}\n",
                    i % 60
                )
            })
            .collect();
        h.app_mut()
            .modals
            .push(text_viewer("Raw directory listing", text));
        h.keys("j j");
    });
}

#[test]
fn snap_problems() {
    snap_both("snap_problems", |h| {
        h.app_mut().modals.push(problems(vec![
            "keybindings.FileList.\"ctrl-foo\": invalid key: unknown key name \"foo\"".into(),
            "keybindings.Queue.\"x\": unknown action \"Remove\" (see docs/keybindings.md)".into(),
            "styles: unknown style key `bogus`".into(),
        ]));
    });
}

#[test]
fn snap_form_all_widgets() {
    let mut h = harness();
    h.render(80, 24);
    h.app_mut()
        .modals
        .push(FormDialog::new("Site settings", all_widgets_form(), |_| {
            Ok(())
        }));
    let ids = [
        "host", "password", "port", "passive", "exec", "protocol", "mode", "remote", "comments",
        "columns", "buttons",
    ];
    for id in ids {
        assert_snapshot!(
            format!("snap_form_all_widgets_{id}_80x24"),
            h.render(80, 24)
        );
        h.keys("tab");
    }
    let mut h = harness();
    h.render(160, 48);
    h.app_mut()
        .modals
        .push(FormDialog::new("Site settings", all_widgets_form(), |_| {
            Ok(())
        }));
    assert_snapshot!("snap_form_all_widgets_160x48", h.render(160, 48));
}

#[test]
fn snap_select_popup_open() {
    snap_both("snap_select_popup_open", |h| {
        h.app_mut()
            .modals
            .push(FormDialog::new("Site settings", all_widgets_form(), |_| {
                Ok(())
            }));
        h.keys("tab tab tab tab tab space");
    });
}

struct Fixed(Vec<&'static str>);

impl PathCompleter for Fixed {
    fn complete(&self, input: String) -> BoxFuture<'static, Result<Vec<Completion>, String>> {
        let items = self
            .0
            .iter()
            .filter(|n| n.starts_with(input.as_str()))
            .map(|n| Completion {
                replacement: (*n).to_owned(),
                display: n
                    .rsplit('/')
                    .find(|s| !s.is_empty())
                    .unwrap_or(n)
                    .to_owned(),
                is_dir: n.ends_with('/'),
            })
            .collect();
        Box::pin(async move { Ok(items) })
    }
}

#[test]
fn snap_path_completion_popup() {
    snap_both("snap_path_completion_popup", |h| {
        let wake = h.app().action_sender();
        let completer = Arc::new(Fixed(vec![
            "/srv/www/archive/",
            "/srv/www/assets/",
            "/srv/www/assets.tar.gz",
            "/srv/www/index.html",
        ]));
        let form = Form::builder()
            .field(
                "path",
                "Directory",
                FieldWidget::Path(PathInput::new("/srv/www/a", Some(completer), wake)),
            )
            .field("name", "Name", FieldWidget::Text(TextInput::new("")))
            .build();
        h.app_mut()
            .modals
            .push(FormDialog::new("Go to directory", form, |_| Ok(())));
        h.keys("tab");
        h.settle();
    });
}

#[test]
fn snap_list_view_sections_filter() {
    snap_both("snap_list_view_sections_filter", |h| {
        let list = ListView::new(vec![
            ListRow::Header("Local".into()),
            ListRow::check("Name", "name".into(), true),
            ListRow::check("Size", "size".into(), true),
            ListRow::check("Modified", "mtime".into(), false),
            ListRow::Header("Remote".into()),
            ListRow::check("Name", "rname".into(), true),
            ListRow::check("Permissions", "perm".into(), false),
            ListRow::check("Owner", "owner".into(), false),
        ])
        .visible_rows(8);
        let form = Form::builder()
            .field("cols", "Columns", FieldWidget::List(list))
            .build();
        h.app_mut()
            .modals
            .push(FormDialog::new("Columns", form, |_| Ok(())));
        h.keys("/ m e");
    });
}

#[test]
fn snap_tabbed_form_page2() {
    snap_both("snap_tabbed_form_page2", |h| {
        h.app_mut().modals.push(tabbed());
        h.keys("ctrl-pagedown");
    });
}

#[test]
fn snap_nested_confirm_over_form() {
    snap_both("snap_nested_confirm_over_form", |h| {
        h.app_mut().modals.push(login_dialog());
        h.keys("e x a m p l e esc");
        assert_eq!(h.app().modals.depth(), 2);
    });
}

#[test]
fn snap_dialog_too_small_30x8() {
    let mut h = harness();
    h.app_mut().modals.push(login_dialog());
    let screen = h.render(30, 8);
    assert!(screen.contains("Terminal too small for"), "{screen}");
    assert_snapshot!("snap_dialog_too_small_30x8", screen);
    h.keys("esc");
    assert!(h.app().modals.is_empty(), "Esc still closes it");
}

#[test]
fn snap_dialog_scrolled_form_80x24() {
    let mut h = harness();
    h.render(80, 24);
    let mut b = Form::builder();
    const IDS: [&str; 30] = [
        "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10", "f11", "f12", "f13",
        "f14", "f15", "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23", "f24", "f25", "f26",
        "f27", "f28", "f29",
    ];
    for (i, id) in IDS.iter().enumerate() {
        b = b.field(
            id,
            &format!("Field number {i}"),
            FieldWidget::Text(TextInput::new(&format!("value {i}"))),
        );
    }
    h.app_mut()
        .modals
        .push(FormDialog::new("Many fields", b.build(), |_| Ok(())));
    for _ in 0..25 {
        h.keys("down");
    }
    let screen = h.render(80, 24);
    assert!(screen.contains("Field number 25"), "{screen}");
    assert!(screen.contains('▲') && screen.contains('▼'), "{screen}");
    assert_snapshot!("snap_dialog_scrolled_form_80x24", screen);
}

#[test]
fn snap_ascii_symbols_form() {
    let mut c = Config::default();
    c.settings.interface.unicode_symbols = UnicodeSymbols::Never;
    let mut h = AppHarness::new(c);
    h.render(80, 24);
    h.app_mut()
        .modals
        .push(FormDialog::new("Site settings", all_widgets_form(), |_| {
            Ok(())
        }));
    h.keys("tab p w");
    assert_snapshot!("snap_ascii_symbols_form", h.render(80, 24));
}
