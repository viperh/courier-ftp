//! Novell NetWare lines:
//!
//! ```text
//! d [RWCEAFMS] supervisor            512       Jan 16 18:53    login
//! - [R----F--] rhesus             214059       Oct 20 15:27    cx.exe
//! ```
//!
//! NetWare pads the name column, so leading spaces in names are lost.

use courier_ftp_core::{
    listing::{ListingContext, parse_date_fields, split_fields},
    model::{Entry, EntryKind, Permissions},
};

pub(super) fn parse_line(line: &str, ctx: &ListingContext) -> Option<Entry> {
    let fields = split_fields(line);
    let texts: Vec<&str> = fields.iter().map(|f| f.text).collect();
    let kind = match *texts.first()? {
        "d" => EntryKind::Dir,
        "-" => EntryKind::File,
        _ => return None,
    };
    let perms = *texts.get(1)?;
    if !(perms.starts_with('[') && perms.ends_with(']') && perms.len() >= 2) {
        return None;
    }
    let owner = *texts.get(2)?;
    let size: u64 = texts.get(3)?.parse().ok()?;
    let (modified, used) = parse_date_fields(texts.get(4..)?, ctx)?;
    let last = fields.get(4 + used - 1)?;
    let name = line.get(last.end()..)?.trim_start_matches([' ', '\t']);
    if name.is_empty() {
        return None;
    }
    let mut entry = Entry::new(name, kind);
    entry.size = Some(size);
    entry.modified = Some(modified);
    entry.permissions = Some(Permissions::from_raw(perms));
    entry.owner = Some(owner.to_owned());
    entry.raw = Some(line.to_owned());
    Some(entry)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use time::{Duration, macros::datetime};

    use super::*;

    #[test]
    fn netware() {
        let ctx = ListingContext::at(datetime!(2024-06-15 12:00 UTC), Duration::ZERO);
        let e = parse_line(
            "d [RWCEAFMS] supervisor            512       Jan 16 18:53    login",
            &ctx,
        )
        .unwrap();
        assert_eq!((e.name.as_str(), &e.kind), ("login", &EntryKind::Dir));
        assert_eq!(e.modified.unwrap().time, datetime!(2024-01-16 18:53 UTC));
        assert!(parse_line("x [R] a 1 Jan 16 18:53 n", &ctx).is_none());
    }
}
