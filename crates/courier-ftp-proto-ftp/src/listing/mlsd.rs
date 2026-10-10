//! `MLSD` / `MLST` fact lines (RFC 3659 §7).
//!
//! ```text
//! entry  = [facts] SP pathname
//! facts  = 1*( factname "=" value ";" )
//! ```

use courier_ftp_core::model::{Entry, EntryKind, Permissions, Precision, Timestamp};
use time::{PrimitiveDateTime, Time};

use super::Outcome;
use super::util::{make_date, num, num8};

/// Splits a fact line into the fact block (with its final `;`) and the pathname
/// (byte-exact). `None` if the line has no `"; "` separator and does not start with SP.
fn split_line(line: &str) -> Option<(&str, &str)> {
    if let Some(name) = line.strip_prefix(' ') {
        return Some(("", name));
    }
    let idx = line.find("; ")?;
    Some((&line[..=idx], &line[idx + 2..]))
}

/// The parsed facts that map to an [`Entry`].
#[derive(Default)]
struct Facts<'a> {
    kind: Option<&'a str>,
    size: Option<&'a str>,
    modify: Option<&'a str>,
    unix_mode: Option<&'a str>,
    perm: Option<&'a str>,
    owner_name: Option<&'a str>,
    owner: Option<&'a str>,
    group_name: Option<&'a str>,
    group: Option<&'a str>,
}

fn parse_facts(block: &str) -> Option<Facts<'_>> {
    let mut f = Facts::default();
    for fact in block.split(';') {
        if fact.is_empty() {
            continue;
        }
        let (name, value) = fact.split_once('=')?;
        if name.is_empty() || name.contains(' ') {
            return None;
        }
        let slot = match name.to_ascii_lowercase().as_str() {
            "type" => &mut f.kind,
            "size" => &mut f.size,
            "modify" => &mut f.modify,
            "unix.mode" => &mut f.unix_mode,
            "perm" => &mut f.perm,
            "unix.ownername" => &mut f.owner_name,
            "unix.owner" | "unix.uid" => &mut f.owner,
            "unix.groupname" => &mut f.group_name,
            "unix.group" | "unix.gid" => &mut f.group,
            _ => continue,
        };
        *slot = Some(value);
    }
    Some(f)
}

/// `YYYYMMDDHHMMSS[.sss]` (UTC) → timestamp; `None` if invalid.
fn parse_modify(s: &str) -> Option<Timestamp> {
    let (main, frac) = match s.split_once('.') {
        Some((m, f)) => (m, Some(f)),
        None => (s, None),
    };
    if main.len() != 14 {
        return None;
    }
    let y = i32::try_from(num(main.get(0..4)?, 4, 4)?).ok()?;
    let mo = num8(main.get(4..6)?, 2, 2)?;
    let d = num8(main.get(6..8)?, 2, 2)?;
    let h = num8(main.get(8..10)?, 2, 2)?;
    let mi = num8(main.get(10..12)?, 2, 2)?;
    let se = num8(main.get(12..14)?, 2, 2)?;
    let date = make_date(y, mo, d)?;
    let (millis, precision) = match frac {
        None => (0, Precision::Second),
        Some(f) => {
            if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let mut ms: u16 = 0;
            for k in 0..3 {
                ms = ms * 10 + f.as_bytes().get(k).map_or(0, |b| u16::from(b - b'0'));
            }
            (ms, Precision::Millis)
        }
    };
    // Leap seconds (`60`) are clamped to 59.
    let time = Time::from_hms_milli(h, mi, se.min(59), millis).ok()?;
    Some(Timestamp::new(
        PrimitiveDateTime::new(date, time).assume_utc(),
        precision,
    ))
}

/// `0755`, `755`, `4755`, `00755` → mode.
fn parse_unix_mode(s: &str) -> Option<u32> {
    let mut s = s;
    while s.len() > 3 && s.starts_with('0') {
        s = &s[1..];
    }
    Permissions::parse_octal(s).ok()
}

enum Built {
    Entry(Entry),
    CurrentOrParent,
    BadNumber,
}

/// Facts + name → entry. `cdir`/`pdir` are reported as such (skipped in MLSD, a
/// directory in MLST).
fn build(facts: &Facts<'_>, name: &str) -> Built {
    let mut current_or_parent = false;
    let kind = match facts.kind {
        None => EntryKind::File,
        Some(t) => {
            let lower = t.to_ascii_lowercase();
            match lower.as_str() {
                "file" => EntryKind::File,
                "dir" => EntryKind::Dir,
                "cdir" | "pdir" => {
                    current_or_parent = true;
                    EntryKind::Dir
                }
                "os.unix=symlink" | "os.unix=slink" => EntryKind::Symlink {
                    target: None,
                    target_kind: None,
                },
                _ if lower.starts_with("os.unix=slink:") => {
                    let target = &t["os.unix=slink:".len()..];
                    EntryKind::Symlink {
                        target: (!target.is_empty()).then(|| target.to_owned()),
                        target_kind: None,
                    }
                }
                _ => EntryKind::Other,
            }
        }
    };
    let size = match facts.size {
        Some(s) if kind != EntryKind::Dir => {
            if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
                match s.parse::<u64>() {
                    Ok(n) => Some(n),
                    Err(_) => return Built::BadNumber,
                }
            } else {
                None
            }
        }
        _ => None,
    };
    let permissions = match (facts.unix_mode.and_then(parse_unix_mode), facts.perm) {
        (Some(mode), _) => Some(Permissions::from_mode(mode)),
        (None, Some(p)) => Some(Permissions::from_raw(p)),
        (None, None) => None,
    };
    if current_or_parent {
        return Built::CurrentOrParent;
    }
    Built::Entry(Entry {
        name: name.to_owned(),
        kind,
        size,
        modified: facts.modify.and_then(parse_modify),
        permissions,
        owner: facts.owner_name.or(facts.owner).map(str::to_owned),
        group: facts.group_name.or(facts.group).map(str::to_owned),
        hidden: name.starts_with('.'),
    })
}

/// One MLSD line.
pub(super) fn parse_line(line: &str) -> Outcome {
    let Some((block, name)) = split_line(line) else {
        return Outcome::NoMatch;
    };
    let Some(facts) = parse_facts(block) else {
        return Outcome::NoMatch;
    };
    match build(&facts, name) {
        Built::Entry(e) => Outcome::Entry(e),
        Built::CurrentOrParent => Outcome::Ignore,
        Built::BadNumber => Outcome::BadNumber,
    }
}

/// One MLST fact line (leading space already removed) → (entry, full pathname).
///
/// The entry's `name` is the last path component (`cdir`/`pdir` count as directories);
/// for a path without one (`/`) the name is the whole path.
pub fn parse_mlst_line(line: &str) -> Option<(Entry, String)> {
    let (block, path) = split_line(line)?;
    let facts = parse_facts(block)?;
    let mut facts = facts;
    if facts
        .kind
        .is_some_and(|t| t.eq_ignore_ascii_case("cdir") || t.eq_ignore_ascii_case("pdir"))
    {
        facts.kind = Some("dir");
    }
    let trimmed = path.trim_end_matches('/');
    let name = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let name = if name.is_empty() { path } else { name };
    match build(&facts, name) {
        Built::Entry(e) => Some((e, path.to_owned())),
        Built::CurrentOrParent | Built::BadNumber => None,
    }
}
