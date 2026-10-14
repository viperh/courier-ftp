//! IBM i (AS/400, `QSYS.LIB` and IFS) lines (basic support):
//!
//! ```text
//! QSYS            77824 02/23/00 15:09:55 *DIR       QDOC/
//! QPGMR           36864 18.09.06 14:21:38 *FILE      QPGMR/QWOBJ.FILE
//! QSYS                                    *MEM       QGPL/QCLSRC.FILE/UNITTEST.MBR
//! ```
//!
//! The object type decides directory-ness (`*DIR`, `*LIB`, `*FILE`, `*FLR`,
//! `*DDIR`); the name is the last path component. `00/00/00` means no date.

use courier_ftp_core::{
    listing::{ListingContext, parse_time, split_fields},
    model::{Entry, EntryKind},
};
use time::PrimitiveDateTime;

pub(super) fn parse_line(line: &str, ctx: &ListingContext) -> Option<Entry> {
    let fields = split_fields(line);
    let texts: Vec<&str> = fields.iter().map(|f| f.text).collect();
    let type_at = texts.iter().position(|t| is_object_type(t))?;
    let owner = *texts.first()?;
    let (size, modified) = match type_at {
        1 => (None, None),
        4 => {
            let size: u64 = texts[1].parse().ok()?;
            let modified = if texts[2]
                .bytes()
                .all(|b| matches!(b, b'0' | b'/' | b'.' | b'-'))
            {
                None
            } else {
                let date = super::dos::parse_date(texts[2])?;
                let (time, precision) = parse_time(texts[3])?;
                ctx.server_time(PrimitiveDateTime::new(date, time), precision)
            };
            (Some(size), modified)
        }
        _ => return None,
    };
    let object_type = texts[type_at];
    let path = line.get(fields.get(type_at)?.end()..)?.trim();
    let name = path.trim_end_matches('/').rsplit('/').next()?;
    if name.is_empty() {
        return None;
    }
    let kind = match object_type {
        "*DIR" | "*LIB" | "*FILE" | "*FLR" | "*DDIR" => EntryKind::Dir,
        _ => EntryKind::File,
    };
    let mut entry = Entry::new(name, kind);
    entry.size = size;
    entry.modified = modified;
    entry.owner = Some(owner.to_owned());
    entry.raw = Some(line.to_owned());
    Some(entry)
}

/// `*DIR`, `*STMF`, `*MEM`, …
fn is_object_type(s: &str) -> bool {
    s.strip_prefix('*').is_some_and(|t| {
        (2..=10).contains(&t.len())
            && t.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use time::{Duration, macros::datetime};

    use super::*;

    fn ctx() -> ListingContext {
        ListingContext::at(datetime!(2024-06-15 12:00 UTC), Duration::ZERO)
    }

    #[test]
    fn as400() {
        let e = parse_line(
            "QSYS            77824 02/23/00 15:09:55 *DIR       QDOC/",
            &ctx(),
        )
        .unwrap();
        assert_eq!(
            (e.name.as_str(), &e.kind, e.size),
            ("QDOC", &EntryKind::Dir, Some(77824))
        );
        assert_eq!(e.modified.unwrap().time, datetime!(2000-02-23 15:09:55 UTC));
        let e = parse_line(
            "QSYS                                    *MEM       QGPL/QCLSRC.FILE/UNITTEST.MBR",
            &ctx(),
        )
        .unwrap();
        assert_eq!((e.name.as_str(), e.size), ("UNITTEST.MBR", None));
        let e = parse_line("QSYS 0 00/00/00 00:00:00 *STMF /x", &ctx()).unwrap();
        assert_eq!((e.name.as_str(), e.modified), ("x", None));
        assert!(parse_line("QSYS 1 2 *DIR x", &ctx()).is_none());
    }
}
