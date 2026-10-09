//! FTP directory listing parsers (T13): `MLSD`/`MLST` (RFC 3659) and `LIST` output from
//! every common server family (Unix `ls -l` and its variants, DOS/IIS, EPLF, VMS,
//! MVS/z/OS datasets and members, IBM i).
//!
//! Pure functions over untrusted server bytes: bounded line length and entry count,
//! checked numbers, no recursion, no regex. Unparseable or hostile lines never abort a
//! listing; they are reported in [`ParsedListing::skipped`]. No logging here (T14 logs).
//! Choosing between `MLSD` and `LIST` needs the control connection and belongs to T14.

mod dos;
mod eplf;
mod ibmi;
mod mlsd;
mod mvs;
mod util;
mod vms;

use std::collections::HashSet;

use courier_ftp_core::listing::unix::{self, LineError};
pub use courier_ftp_core::listing::{ListingContext, TextDecoder};
use courier_ftp_core::model::Entry;
pub use mlsd::parse_mlst_line;
use serde::Serialize;

/// A server listing format (also the hint from `SYST` or the site's server type, T14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ListFormat {
    /// RFC 3659 `MLSD` facts.
    Mlsd,
    /// Unix `ls -l` (also Windows servers with Unix-style output).
    Unix,
    /// DOS / IIS `dir` style.
    Dos,
    /// Easily Parsed LIST Format (D. J. Bernstein).
    Eplf,
    /// OpenVMS.
    Vms,
    /// MVS / z/OS dataset list.
    MvsDataset,
    /// MVS / z/OS partitioned dataset member list.
    MvsMember,
    /// IBM i (OS/400, QSYS).
    IbmI,
}

/// Options for [`parse_mlsd`] and [`parse_list`].
#[derive(Debug, Clone)]
pub struct ParseOptions {
    /// Current time and server offset.
    pub ctx: ListingContext,
    /// Bytes → text per line.
    pub decoder: TextDecoder,
    /// Tried first: from SYST or the site's server-type override (mapping in T14).
    pub hint: Option<ListFormat>,
}

/// The result of parsing one listing.
#[derive(Debug, Clone, Default)]
pub struct ParsedListing {
    /// The entries, in server order, without `.`, `..` and hostile names.
    pub entries: Vec<Entry>,
    /// Format of the last successfully parsed line (for logs / T14 hints).
    pub format: Option<ListFormat>,
    /// Lines that were not headers and could not be parsed (first 1 000 kept).
    pub skipped: Vec<SkippedLine>,
    /// Number of skipped lines, including those not kept in `skipped`.
    pub skipped_count: usize,
    /// Decoded text, lines joined with '\n' (→ `Listing.raw`, T71).
    pub raw: String,
    /// The fallback encoding had to be used for at least one line.
    pub used_fallback_encoding: bool,
}

/// A line that produced no entry.
#[derive(Debug, Clone)]
pub struct SkippedLine {
    /// 1-based line number in the listing.
    pub line_no: usize,
    /// The decoded line (truncated to 4 KiB).
    pub text: String,
    /// Why it was skipped.
    pub reason: SkipReason,
}

/// Why a line produced no entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkipReason {
    /// No parser recognised the line (also VMS `%…-E-…` messages).
    Unrecognised,
    /// The name was empty or contained `/` or NUL.
    HostileName,
    /// The line was longer than 64 KiB.
    LineTooLong,
    /// A number (size, time) did not fit.
    BadNumber,
    /// The listing already had the maximum number of entries (1 000 000).
    TooManyEntries,
}

/// Longest accepted line (bytes, without the line ending).
pub const MAX_LINE_LEN: usize = 64 * 1024;
/// Most entries returned from one listing.
pub const MAX_ENTRIES: usize = 1_000_000;
/// Most skipped lines kept in [`ParsedListing::skipped`].
pub const MAX_SKIPPED_KEPT: usize = 1_000;
const MAX_SKIPPED_TEXT: usize = 4 * 1024;

/// What a format parser made of one line.
#[derive(Debug)]
enum Outcome {
    Entry(Entry),
    /// A header or summary line of this format: skipped silently.
    Header,
    /// Recognised but intentionally dropped (MLSD `cdir`/`pdir`, older VMS versions).
    Ignore,
    /// A VMS name-only line: joined with the next line.
    Pending,
    /// Not this format.
    NoMatch,
    /// This format, but a number overflowed.
    BadNumber,
    /// A message line of this format that also goes to `skipped` (VMS `%…-E-…`).
    LoggedHeader,
}

/// Parser state carried from line to line within one listing.
#[derive(Debug, Default)]
struct State {
    /// VMS names already listed (only the first, highest version is kept).
    vms_seen: HashSet<String>,
    /// After an MVS member-list header, bare member names are entries.
    mvs_member_mode: bool,
}

/// Collects entries and skipped lines with the limits and name rules.
struct Collector {
    out: ParsedListing,
}

impl Collector {
    fn skip(&mut self, line_no: usize, text: &str, reason: SkipReason) {
        self.out.skipped_count += 1;
        if self.out.skipped.len() < MAX_SKIPPED_KEPT {
            self.out.skipped.push(SkippedLine {
                line_no,
                text: truncate(text, MAX_SKIPPED_TEXT).to_owned(),
                reason,
            });
        }
    }

    fn push(&mut self, line_no: usize, text: &str, mut entry: Entry, format: ListFormat) {
        if entry.name == "." || entry.name == ".." {
            return;
        }
        if !Entry::is_valid_name(&entry.name) {
            self.skip(line_no, text, SkipReason::HostileName);
            return;
        }
        if self.out.entries.len() >= MAX_ENTRIES {
            self.skip(line_no, text, SkipReason::TooManyEntries);
            return;
        }
        entry.hidden = entry.name.starts_with('.');
        self.out.entries.push(entry);
        self.out.format = Some(format);
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Splits `data` into lines, decodes them and feeds the non-blank ones to `f`
/// (line number, text). Builds `raw`, handles over-long lines.
fn run(
    data: &[u8],
    opts: &ParseOptions,
    mut f: impl FnMut(&mut Collector, usize, &str),
) -> ParsedListing {
    let mut c = Collector {
        out: ParsedListing {
            raw: String::with_capacity(data.len().min(64 * 1024 * 1024)),
            ..ParsedListing::default()
        },
    };
    for (i, line) in data.split(|&b| b == b'\n').enumerate() {
        let line_no = i + 1;
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let (text, fallback) = opts.decoder.decode(line);
        c.out.used_fallback_encoding |= fallback;
        if i > 0 {
            c.out.raw.push('\n');
        }
        c.out.raw.push_str(&text);
        if line.len() > MAX_LINE_LEN {
            c.skip(line_no, &text, SkipReason::LineTooLong);
            continue;
        }
        if text.trim().is_empty() {
            continue;
        }
        f(&mut c, line_no, &text);
    }
    c.out
}

/// Parses `MLSD` output (one fact line per entry, RFC 3659 §7).
pub fn parse_mlsd(data: &[u8], opts: &ParseOptions) -> ParsedListing {
    run(data, opts, |c, line_no, text| match mlsd::parse_line(text) {
        Outcome::Entry(e) => c.push(line_no, text, e, ListFormat::Mlsd),
        Outcome::Header | Outcome::Ignore | Outcome::Pending => {}
        Outcome::BadNumber => c.skip(line_no, text, SkipReason::BadNumber),
        Outcome::NoMatch | Outcome::LoggedHeader => {
            c.skip(line_no, text, SkipReason::Unrecognised);
        }
    })
}

/// The LIST formats in the order they are tried when there is no better guess.
const LIST_ORDER: [ListFormat; 7] = [
    ListFormat::Unix,
    ListFormat::Dos,
    ListFormat::Eplf,
    ListFormat::Vms,
    ListFormat::IbmI,
    ListFormat::MvsMember,
    ListFormat::MvsDataset,
];

fn parse_as(format: ListFormat, text: &str, ctx: &ListingContext, st: &mut State) -> Outcome {
    match format {
        ListFormat::Mlsd => mlsd::parse_line(text),
        ListFormat::Unix => match unix::try_parse_line(text, ctx) {
            Ok(e) => Outcome::Entry(e),
            Err(LineError::Header) => Outcome::Header,
            Err(LineError::NotUnix) => Outcome::NoMatch,
            Err(LineError::BadNumber) => Outcome::BadNumber,
        },
        ListFormat::Dos => dos::parse(text, ctx),
        ListFormat::Eplf => eplf::parse(text),
        ListFormat::Vms => vms::parse(text, ctx, &mut st.vms_seen),
        ListFormat::IbmI => ibmi::parse(text, ctx),
        ListFormat::MvsMember => mvs::parse_member(text, ctx, &mut st.mvs_member_mode),
        ListFormat::MvsDataset => mvs::parse_dataset(text, ctx, &mut st.mvs_member_mode),
    }
}

/// Parses `LIST` output in any supported format, line by line: the format that parsed
/// the previous line first, then `opts.hint`, then Unix, DOS, EPLF, VMS, IBM i, MVS
/// member, MVS dataset.
pub fn parse_list(data: &[u8], opts: &ParseOptions) -> ParsedListing {
    let mut st = State::default();
    let mut last: Option<ListFormat> = None;
    let mut pending: Option<(usize, String)> = None;
    let ctx = opts.ctx;

    let mut out = run(data, opts, |c, line_no, text| {
        // A VMS name-only line waits for the rest of its entry on this line.
        if let Some((p_no, p_text)) = pending.take() {
            let joined = format!("{p_text} {}", text.trim_start());
            if let Outcome::Entry(e) = vms::parse(&joined, &ctx, &mut st.vms_seen) {
                c.push(p_no, &joined, e, ListFormat::Vms);
                last = Some(ListFormat::Vms);
                return;
            }
            c.skip(p_no, &p_text, SkipReason::Unrecognised);
        }

        let mut order: [Option<ListFormat>; 9] = [None; 9];
        order[0] = last;
        order[1] = opts.hint;
        for (slot, f) in order[2..].iter_mut().zip(LIST_ORDER) {
            *slot = Some(f);
        }
        let mut bad_number = false;
        for (i, format) in order.iter().enumerate() {
            let Some(format) = *format else { continue };
            if order[..i].contains(&Some(format)) {
                continue;
            }
            match parse_as(format, text, &ctx, &mut st) {
                Outcome::NoMatch => {}
                Outcome::BadNumber => bad_number = true,
                Outcome::Entry(e) => {
                    c.push(line_no, text, e, format);
                    last = Some(format);
                    return;
                }
                Outcome::Header | Outcome::Ignore => return,
                Outcome::Pending => {
                    pending = Some((line_no, text.to_owned()));
                    return;
                }
                Outcome::LoggedHeader => {
                    c.skip(line_no, text, SkipReason::Unrecognised);
                    return;
                }
            }
        }
        let reason = if bad_number {
            SkipReason::BadNumber
        } else {
            SkipReason::Unrecognised
        };
        c.skip(line_no, text, reason);
    });
    if let Some((p_no, p_text)) = pending {
        let mut c = Collector { out };
        c.skip(p_no, &p_text, SkipReason::Unrecognised);
        out = c.out;
    }
    out
}

/// Fuzz/property entry (T91 §7): first byte chooses MLSD/LIST and the hint.
///
/// Panics only if a parser breaks an invariant (an entry with a hostile name, more
/// skipped lines kept than allowed).
#[doc(hidden)]
pub fn fuzz_listing(data: &[u8]) {
    const HINTS: [Option<ListFormat>; 9] = [
        None,
        Some(ListFormat::Mlsd),
        Some(ListFormat::Unix),
        Some(ListFormat::Dos),
        Some(ListFormat::Eplf),
        Some(ListFormat::Vms),
        Some(ListFormat::MvsDataset),
        Some(ListFormat::MvsMember),
        Some(ListFormat::IbmI),
    ];
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let rest = &rest[..rest.len().min(4 * 1024 * 1024)];
    let decoder = match sel >> 6 {
        0 | 1 => TextDecoder::Utf8,
        2 => TextDecoder::Utf8OrFallback(encoding_rs::WINDOWS_1252),
        _ => TextDecoder::Fixed(encoding_rs::SHIFT_JIS),
    };
    let now = time::OffsetDateTime::from_unix_timestamp(1_718_452_800)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let opts = ParseOptions {
        ctx: ListingContext::new(now, (i32::from(sel) - 128) * 7),
        decoder,
        hint: HINTS[usize::from(sel >> 1) % HINTS.len()],
    };
    let parsed = if sel & 1 == 0 {
        parse_mlsd(rest, &opts)
    } else {
        parse_list(rest, &opts)
    };
    assert!(parsed.entries.len() <= MAX_ENTRIES);
    assert!(parsed.skipped.len() <= MAX_SKIPPED_KEPT);
    assert!(parsed.skipped.len() <= parsed.skipped_count);
    for e in &parsed.entries {
        assert!(Entry::is_valid_name(&e.name), "hostile name {:?}", e.name);
        assert_eq!(e.hidden, e.name.starts_with('.'));
    }
    if let Some(first) = rest.split(|&b| b == b'\n').next() {
        let (line, _) = decoder.decode(&first[..first.len().min(MAX_LINE_LEN)]);
        let _ = parse_mlst_line(line.strip_prefix(' ').unwrap_or(&line));
        let _ = unix::parse_line(&line, &opts.ctx);
    }
}

#[cfg(test)]
mod tests;
