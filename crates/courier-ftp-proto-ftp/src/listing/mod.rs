//! Directory listing parsers (T13): `MLSD` and `LIST` output from any common
//! server turned into [`Entry`] values.
//!
//! - **Strategy** — [`ListCommand::choose`] picks `MLSD` when the server has
//!   it and the user allows it, otherwise `LIST` (`LIST -a` to show hidden
//!   files, falling back to plain `LIST` when the server rejects `-a`).
//! - **`MLSD`** (RFC 3659) — [`parse_mlsd`]. Times are UTC; names are taken
//!   verbatim (leading and trailing spaces, `;`).
//! - **`LIST`** — [`ListingParser`] / [`parse_list`] try each format per line,
//!   starting with the one that worked for the previous line
//!   ([`ListingFormat`]): Unix `ls -l` (shared with SFTP, in
//!   [`courier_ftp_core::listing::unix`]), DOS/IIS, EPLF, OpenVMS (including
//!   multi-line entries), NetWare, IBM i (AS/400), MVS/z/OS datasets and PDS
//!   members, and lines in `MLSD` form. Times are server-local: the site's
//!   time-zone offset ([`ListingContext::timezone_offset`]) is added to get
//!   UTC. Unparseable lines are logged at `debug` level and skipped.
//! - **Charset** — [`decode_listing`] turns the raw bytes into text line by
//!   line with the session [`Charset`]; [`parse_listing`] does both and keeps
//!   the raw text for the raw-listing view (T71).
//!
//! `.` and `..` are never returned. Dotfiles are `hidden`. Of the versions of
//! a VMS file only the newest (listed first) is kept.

mod as400;
mod dos;
mod eplf;
mod mlsd;
mod mvs;
mod netware;
mod vms;

use std::collections::HashSet;

pub use courier_ftp_core::listing::ListingContext;
use courier_ftp_core::{
    listing::unix,
    model::{Charset, Entry},
};

/// Which `LIST` format a line was parsed as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListingFormat {
    /// `MLSD`/`MLST` facts (`type=file;size=1; name`).
    Mlsd,
    /// Unix `ls -l`, including Windows servers that imitate it.
    Unix,
    /// DOS / IIS / Windows `dir`.
    Dos,
    /// Easily Parsed LIST Format (`+i…,m…,r,s…,\tname`).
    Eplf,
    /// OpenVMS.
    Vms,
    /// Novell NetWare.
    Netware,
    /// IBM i (AS/400).
    As400,
    /// MVS / z/OS datasets.
    MvsDataset,
    /// MVS / z/OS partitioned dataset members.
    MvsMember,
}

impl ListingFormat {
    /// Every format, in the order they are tried when nothing is known yet.
    pub const ALL: [ListingFormat; 9] = [
        ListingFormat::Unix,
        ListingFormat::Dos,
        ListingFormat::Mlsd,
        ListingFormat::Eplf,
        ListingFormat::Vms,
        ListingFormat::Netware,
        ListingFormat::As400,
        ListingFormat::MvsDataset,
        ListingFormat::MvsMember,
    ];

    fn parse(self, line: &str, ctx: &ListingContext) -> Option<Parsed> {
        let entry = match self {
            ListingFormat::Mlsd => return mlsd::parse_line(line),
            ListingFormat::Unix => unix::parse_line(line, ctx),
            ListingFormat::Dos => dos::parse_line(line, ctx),
            ListingFormat::Eplf => eplf::parse_line(line),
            ListingFormat::Vms => vms::parse_line(line, ctx),
            ListingFormat::Netware => netware::parse_line(line, ctx),
            ListingFormat::As400 => as400::parse_line(line, ctx),
            ListingFormat::MvsDataset => mvs::parse_dataset(line, ctx),
            ListingFormat::MvsMember => mvs::parse_member(line, ctx),
        };
        entry.map(Parsed::Entry)
    }
}

/// The result of parsing one line.
#[derive(Debug)]
enum Parsed {
    Entry(Entry),
    /// A valid line that is not an entry (`cdir`/`pdir`).
    Skip,
}

/// Which command lists a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListCommand {
    /// `MLSD` (RFC 3659).
    Mlsd,
    /// `LIST -a`, to include hidden files.
    ListAll,
    /// Plain `LIST`.
    List,
}

impl ListCommand {
    /// `MLSD` when the server lists it in `FEAT` and the `use_mlsd` setting is
    /// on; otherwise `LIST -a` when `force_show_hidden_remote` is on and the
    /// server hasn't rejected `-a` before; otherwise `LIST`.
    pub fn choose(
        server_has_mlsd: bool,
        use_mlsd: bool,
        show_hidden: bool,
        list_a_rejected: bool,
    ) -> Self {
        if server_has_mlsd && use_mlsd {
            ListCommand::Mlsd
        } else if show_hidden && !list_a_rejected {
            ListCommand::ListAll
        } else {
            ListCommand::List
        }
    }

    /// The command line to send (without the path argument).
    pub fn command(self) -> &'static str {
        match self {
            ListCommand::Mlsd => "MLSD",
            ListCommand::ListAll => "LIST -a",
            ListCommand::List => "LIST",
        }
    }

    /// What to retry with when the server rejects this command: `LIST -a` →
    /// `LIST` (remember the rejection for the session).
    pub fn fallback(self) -> Option<Self> {
        match self {
            ListCommand::ListAll => Some(ListCommand::List),
            ListCommand::Mlsd | ListCommand::List => None,
        }
    }
}

/// A parsed listing with its raw text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedListing {
    /// The entries, without `.` and `..`.
    pub entries: Vec<Entry>,
    /// The decoded listing text, for the raw-listing view (T71).
    pub raw: String,
    /// The last `LIST` format that matched (`None` for `MLSD` or when no line
    /// parsed).
    pub format: Option<ListingFormat>,
    /// How many non-empty lines could not be parsed.
    pub unparsed: usize,
}

/// Decode the bytes of a data connection and parse them as the output of
/// `command`.
pub fn parse_listing(
    bytes: &[u8],
    charset: Charset,
    command: ListCommand,
    ctx: &ListingContext,
) -> ParsedListing {
    let raw = decode_listing(bytes, charset);
    match command {
        ListCommand::Mlsd => {
            let mut unparsed = 0;
            let entries = mlsd_entries(&raw, &mut unparsed);
            ParsedListing {
                entries,
                raw,
                format: None,
                unparsed,
            }
        }
        ListCommand::ListAll | ListCommand::List => {
            let mut parser = ListingParser::new(*ctx);
            for line in raw.lines() {
                parser.feed_line(line);
            }
            let format = parser.format();
            let unparsed = parser.unparsed();
            ParsedListing {
                entries: parser.finish(),
                raw,
                format,
                unparsed,
            }
        }
    }
}

/// Decode listing bytes with the session charset, line by line, so that with
/// [`Charset::Auto`] a single non-UTF-8 name falls back to Windows-1252
/// without garbling the UTF-8 lines around it. Line endings are kept.
pub fn decode_listing(bytes: &[u8], charset: Charset) -> String {
    bytes
        .split_inclusive(|b| *b == b'\n')
        .map(|line| charset.decode(line))
        .collect()
}

/// Parse `MLSD` output. Lines that aren't `MLSD` facts are logged and skipped.
pub fn parse_mlsd(text: &str) -> Vec<Entry> {
    mlsd_entries(text, &mut 0)
}

fn mlsd_entries(text: &str, unparsed: &mut usize) -> Vec<Entry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim().is_empty() {
            continue;
        }
        match mlsd::parse_line(line) {
            Some(Parsed::Entry(e)) if !is_dot(&e.name) => entries.push(e),
            Some(_) => {}
            None => {
                *unparsed += 1;
                tracing::debug!(line, "unparseable MLSD line skipped");
            }
        }
    }
    entries
}

/// Parse an `MLST` reply line (` facts; name`, with the leading space).
pub fn parse_mlst_line(line: &str) -> Option<Entry> {
    let line = line.strip_prefix(' ').unwrap_or(line);
    match mlsd::parse_line(line.trim_end_matches(['\r', '\n']))? {
        Parsed::Entry(e) => Some(e),
        Parsed::Skip => None,
    }
}

/// Parse `LIST` output (any supported format, detected per line).
pub fn parse_list(text: &str, ctx: &ListingContext) -> Vec<Entry> {
    let mut parser = ListingParser::new(*ctx);
    for line in text.lines() {
        parser.feed_line(line);
    }
    parser.finish()
}

/// Incremental `LIST` parser: feed it lines as they arrive.
///
/// Each line is tried with the format that matched the previous line first,
/// then with every other format ([`ListingFormat::ALL`]). Header lines
/// (`total N`, VMS `Directory …`/`Total of …`, MVS column headers) are skipped
/// silently; other lines no format accepts are logged at `debug` level and
/// skipped.
#[derive(Debug)]
pub struct ListingParser {
    ctx: ListingContext,
    last: Option<ListingFormat>,
    /// A VMS name whose details are on the next line.
    vms_pending: Option<String>,
    /// VMS names seen so far: only the newest version of a file is kept.
    vms_names: HashSet<String>,
    entries: Vec<Entry>,
    unparsed: usize,
}

impl ListingParser {
    /// A parser with the given time context.
    pub fn new(ctx: ListingContext) -> Self {
        Self {
            ctx,
            last: None,
            vms_pending: None,
            vms_names: HashSet::new(),
            entries: Vec::new(),
            unparsed: 0,
        }
    }

    /// Parse one line (a trailing `\r` is ignored).
    pub fn feed_line(&mut self, line: &str) {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(name) = self.vms_pending.take() {
            let joined = format!("{name} {}", line.trim_start());
            if let Some(Parsed::Entry(mut e)) = ListingFormat::Vms.parse(&joined, &self.ctx) {
                e.raw = Some(format!("{name}\n{line}"));
                self.last = Some(ListingFormat::Vms);
                self.push(e);
                return;
            }
            self.reject(&name);
        }
        if line.trim().is_empty() || is_header(line) {
            return;
        }
        let order = self.last.into_iter().chain(
            ListingFormat::ALL
                .into_iter()
                .filter(|f| Some(*f) != self.last),
        );
        for format in order {
            if let Some(parsed) = format.parse(line, &self.ctx) {
                self.last = Some(format);
                if let Parsed::Entry(e) = parsed {
                    self.push(e);
                }
                return;
            }
        }
        if vms::is_name_only(line) {
            self.vms_pending = Some(line.trim().to_owned());
        } else if self.last == Some(ListingFormat::MvsMember) && mvs::is_bare_member(line) {
            let mut e = Entry::new(line.trim(), courier_ftp_core::model::EntryKind::File);
            e.raw = Some(line.to_owned());
            self.push(e);
        } else {
            self.reject(line);
        }
    }

    /// The format of the last line that parsed.
    pub fn format(&self) -> Option<ListingFormat> {
        self.last
    }

    /// How many lines were skipped as unparseable so far.
    pub fn unparsed(&self) -> usize {
        self.unparsed + usize::from(self.vms_pending.is_some())
    }

    /// The entries parsed so far.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Finish and return the entries.
    pub fn finish(mut self) -> Vec<Entry> {
        if let Some(name) = self.vms_pending.take() {
            self.reject(&name);
        }
        self.entries
    }

    fn push(&mut self, entry: Entry) {
        if is_dot(&entry.name) {
            return;
        }
        // VMS lists every version, newest first; with the version stripped
        // they would be duplicate names.
        if self.last == Some(ListingFormat::Vms) && !self.vms_names.insert(entry.name.clone()) {
            return;
        }
        self.entries.push(entry);
    }

    fn reject(&mut self, line: &str) {
        self.unparsed += 1;
        tracing::debug!(line, "unparseable listing line skipped");
    }
}

fn is_dot(name: &str) -> bool {
    name == "." || name == ".."
}

/// Lines that are part of a listing but not entries.
fn is_header(line: &str) -> bool {
    let trimmed = line.trim_start();
    unix::is_total_line(line)
        || trimmed.starts_with("Directory ")
        || trimmed.starts_with("Total of ")
        || trimmed.starts_with("Grand total of ")
        || mvs::is_header(line)
}

#[cfg(test)]
mod tests {
    use courier_ftp_core::model::EntryKind;
    use pretty_assertions::assert_eq;
    use time::{Duration, macros::datetime};

    use super::*;

    fn ctx() -> ListingContext {
        ListingContext::at(datetime!(2024-06-15 12:00 UTC), Duration::ZERO)
    }

    #[test]
    fn strategy() {
        assert_eq!(
            ListCommand::choose(true, true, true, false),
            ListCommand::Mlsd
        );
        assert_eq!(
            ListCommand::choose(true, false, true, false),
            ListCommand::ListAll
        );
        assert_eq!(
            ListCommand::choose(false, true, true, true),
            ListCommand::List
        );
        assert_eq!(
            ListCommand::choose(false, true, false, false),
            ListCommand::List
        );
        assert_eq!(ListCommand::ListAll.command(), "LIST -a");
        assert_eq!(ListCommand::ListAll.fallback(), Some(ListCommand::List));
        assert_eq!(ListCommand::Mlsd.fallback(), None);
    }

    #[test]
    fn dots_and_headers_are_skipped() {
        let text = "total 8\r\ndrwxr-xr-x 2 u g 4096 Jan 31 12:00 .\r\ndrwxr-xr-x 3 u g 4096 Jan 31 12:00 ..\r\n-rw-r--r-- 1 u g 1 Jan 31 12:00 .hidden\r\n\r\n";
        let entries = parse_list(text, &ctx());
        assert_eq!(entries.len(), 1);
        assert!(entries[0].hidden);
        let mlsd = parse_mlsd("type=cdir; .\r\ntype=pdir; ..\r\ntype=dir; .\r\ntype=file; f\r\n");
        assert_eq!(mlsd.len(), 1);
    }

    #[test]
    fn remembers_the_format_and_skips_garbage() {
        let mut p = ListingParser::new(ctx());
        p.feed_line("01-31-24  12:00PM       <DIR>          dir");
        p.feed_line("this is not a listing line");
        p.feed_line("01-31-24  12:00PM                 12 file");
        assert_eq!(p.format(), Some(ListingFormat::Dos));
        assert_eq!(p.unparsed(), 1);
        assert_eq!(p.entries().len(), 2);
    }

    #[test]
    fn vms_multi_line() {
        let text = "Directory DISK$USER:[ALICE]\n\nA_VERY_LONG_FILE_NAME_THAT_WRAPS.TXT;1\n          12/12  31-JAN-2024 12:00:00  [STAFF,ALICE]  (RWED,RWED,RE,)\nSHORT.TXT;2  1/3  1-FEB-2024 08:00:00  [STAFF,ALICE]  (RWED,RWED,RE,)\n\nTotal of 2 files, 13/15 blocks.\n";
        let entries = parse_list(text, &ctx());
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["A_VERY_LONG_FILE_NAME_THAT_WRAPS.TXT", "SHORT.TXT"]);
        assert_eq!(entries[0].size, Some(12 * 512));
        // A pending name at the end is counted as unparseable.
        let mut p = ListingParser::new(ctx());
        p.feed_line("DANGLING.TXT;1");
        assert_eq!(p.unparsed(), 1);
        assert!(p.finish().is_empty());
    }

    #[test]
    fn mlst_line() {
        let e =
            parse_mlst_line(" type=file;size=5;modify=20240131120000; /home/u/f.txt\r\n").unwrap();
        assert_eq!((e.name.as_str(), e.size), ("/home/u/f.txt", Some(5)));
        assert_eq!(e.kind, EntryKind::File);
    }

    #[test]
    fn charset_fallback_per_line() {
        let mut bytes = b"-rw-r--r-- 1 u g 1 Jan 31 12:00 gr\xc3\xbc\xc3\x9fe\r\n".to_vec();
        bytes.extend_from_slice(b"-rw-r--r-- 1 u g 1 Jan 31 12:00 caf\xe9\r\n");
        let parsed = parse_listing(&bytes, Charset::Auto, ListCommand::List, &ctx());
        let names: Vec<&str> = parsed.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["grüße", "café"]);
        assert!(parsed.raw.ends_with("café\r\n"));
        let koi8 = Charset::from_label("koi8-r").unwrap();
        let parsed = parse_listing(
            b"type=file; \xc6\xc1\xca\xcc\r\n",
            koi8,
            ListCommand::Mlsd,
            &ctx(),
        );
        assert_eq!(parsed.entries[0].name, "файл");
    }

    #[test]
    fn year_inference_at_new_year() {
        let c = ListingContext::at(datetime!(2024-01-01 00:30 UTC), Duration::ZERO);
        let text = "-rw-r--r-- 1 u g 1 Dec 31 23:00 old\n-rw-r--r-- 1 u g 1 Jan  1 00:10 new\n-rw-r--r-- 1 u g 1 Jan  5 08:00 last-year\n";
        let times: Vec<_> = parse_list(text, &c)
            .iter()
            .map(|e| e.modified.unwrap().time)
            .collect();
        assert_eq!(
            times,
            [
                datetime!(2023-12-31 23:00 UTC),
                datetime!(2024-01-01 00:10 UTC),
                datetime!(2023-01-05 08:00 UTC)
            ]
        );
    }

    #[test]
    fn timezone_offset_applies_to_list_not_mlsd() {
        let c = ListingContext::at(datetime!(2024-06-15 12:00 UTC), Duration::minutes(-120));
        let list = parse_list("-rw-r--r-- 1 u g 1 Jan 31 12:00 f", &c);
        assert_eq!(
            list[0].modified.unwrap().time,
            datetime!(2024-01-31 10:00 UTC)
        );
        let dos = parse_list("01-31-24  12:00PM  5 f", &c);
        assert_eq!(
            dos[0].modified.unwrap().time,
            datetime!(2024-01-31 10:00 UTC)
        );
        let parsed = parse_listing(
            b"type=file;modify=20240131120000; f",
            Charset::Utf8,
            ListCommand::Mlsd,
            &c,
        );
        assert_eq!(
            parsed.entries[0].modified.unwrap().time,
            datetime!(2024-01-31 12:00 UTC)
        );
    }
}
