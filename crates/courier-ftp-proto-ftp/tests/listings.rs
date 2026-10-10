//! Snapshot tests over the listing fixture corpus in `tests/listings/` (T13).
//!
//! Every fixture is parsed as a whole, the way a server would send it, at a
//! fixed "now" (2024-06-15 12:00 UTC, no server offset). Files named `mlsd*`
//! are `MLSD` output; everything else is `LIST` output with the format
//! detected per line. Each fixture must parse without a single skipped line.

use std::{fmt::Write as _, fs, path::Path};

use courier_ftp_core::model::{Charset, Entry, EntryKind};
use courier_ftp_proto_ftp::listing::{ListCommand, ListingContext, ParsedListing, parse_listing};
use time::{Duration, macros::datetime};

fn ctx() -> ListingContext {
    ListingContext::at(datetime!(2024-06-15 12:00 UTC), Duration::ZERO)
}

fn render(parsed: &ParsedListing) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "format: {:?}", parsed.format);
    for e in &parsed.entries {
        let _ = writeln!(out, "{}", render_entry(e));
    }
    out
}

fn render_entry(e: &Entry) -> String {
    let kind = match &e.kind {
        EntryKind::File => "file".to_owned(),
        EntryKind::Dir => "dir".to_owned(),
        EntryKind::Other => "other".to_owned(),
        EntryKind::Symlink {
            target,
            target_kind,
        } => format!(
            "link(-> {}{})",
            target
                .as_deref()
                .map_or("?".to_owned(), |t| format!("{t:?}")),
            target_kind
                .as_deref()
                .map_or(String::new(), |k| format!(" {k:?}"))
        ),
    };
    let size = e.size.map_or("-".to_owned(), |s| s.to_string());
    let modified = e.modified.map_or("-".to_owned(), |m| {
        let t = m.time;
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z/{:?}",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second(),
            t.millisecond(),
            m.precision
        )
    });
    let perms =
        e.permissions
            .as_ref()
            .map_or("-".to_owned(), |p| match (p.to_rwx_string(), &p.raw) {
                (Some(rwx), _) => format!("{rwx}({})", p.to_octal_string().unwrap_or_default()),
                (None, Some(raw)) => format!("raw:{raw}"),
                (None, None) => "-".to_owned(),
            });
    format!(
        "{kind:<5} {:?} size={size} mtime={modified} perms={perms} owner={} group={}{}",
        e.name,
        e.owner.as_deref().unwrap_or("-"),
        e.group.as_deref().unwrap_or("-"),
        if e.hidden { " hidden" } else { "" },
    )
}

#[test]
fn fixture_corpus() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listings");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .collect();
    files.sort();
    assert!(files.len() >= 12, "fixture corpus is missing files");
    for path in files {
        let name = path.file_stem().unwrap().to_str().unwrap().to_owned();
        let bytes = fs::read(&path).unwrap();
        let command = if name.starts_with("mlsd") {
            ListCommand::Mlsd
        } else {
            ListCommand::List
        };
        let parsed = parse_listing(&bytes, Charset::Auto, command, &ctx());
        assert_eq!(parsed.unparsed, 0, "{name}: lines were skipped");
        assert!(parsed.entries.len() >= 5, "{name}: fewer than 5 entries");
        insta::assert_snapshot!(name, render(&parsed));
    }
}
