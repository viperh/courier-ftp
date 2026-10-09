# T13 — FTP directory listing parsers

**Phase:** B FTP · **Milestone:** M2 · **Depends on:** T02 · **Crate(s):** `courier-ftp-core` (`listing` module: `TextDecoder`, month/year helpers, `listing::unix`), `courier-ftp-proto-ftp` (`listing` module: MLSD/MLST and the other LIST formats) · **Decisions:** D1 · **FEATURES.md:** §1 (listing parser for many server formats, time zone offset, charset), §3 (hidden files)
**Related (integrates with, not blocking):** T11, T71
**Reference:** sverb `fuzz/fuzz_targets/known_hosts_parse.rs` and `fuzz/seed-corpus.sh` (fuzz body = property test, corpus seeded from fixtures).

## Goal

Turn `MLSD` output (RFC 3659) and `LIST` output from every common server family (Unix
`ls -l` and its variants, DOS/IIS, EPLF, VMS, MVS/z/OS, IBM i, Windows with Unix-style
output) into `Vec<Entry>` with correct names, kinds, sizes, permissions, owners and UTC
timestamps with honest precision. This is the part of FileZilla that took years to get
right, so it is built as pure functions with a large fixture corpus, snapshot tests,
property tests and a fuzz target. The Unix `ls -l` parser lives in core because the SFTP
backend (T22) reuses it for `longname`.

## Context

**Exists before this task:** T02 `Entry`, `EntryKind` (`File`, `Dir`, `Symlink { target,
target_kind }`, `Other`), `Timestamp` + `Precision { Day, Minute, Second, Millis }`,
`Permissions` (`from_rwx_string`, `raw`), `Charset`, `PathStyle`.

**Later tasks need from this one:**
- T14: `parse_mlsd`, `parse_list`, `parse_mlst_line` (for `stat`), `ListFormat` hints, the
  "encoding switched" flag, `ParsedListing.raw` → `Listing.raw`. T14 also owns the
  command strategy (MLSD vs `LIST`, `LIST -a` retry) that used to be listed here, because it
  needs the control connection (T10/T11) which this M2 task does not depend on.
- T22: `courier_ftp_core::listing::unix::parse_line` for SFTP `longname`.
- T10: `TextDecoder` for reply lines.
- T48: timestamps already converted to UTC with the site's offset (except Day-precision
  dates, which carry no offset, T02), with precision.
- T71: raw text for the raw-listing dialog and `ListingRaw` log lines.
- T76/T91: fuzz target `ftp_listing`.

## Technical specification

### Types and APIs

```rust
// courier_ftp_core::listing --------------------------------------------------------------
/// Inputs every parser needs. `now` is injectable for tests (year inference).
#[derive(Debug, Clone, Copy)]
pub struct ListingContext {
    pub now: OffsetDateTime,          // current UTC time
    /// The server's UTC offset in minutes for LIST times (site `timezone_offset_minutes`,
    /// T31): utc = server_local_time − offset. MLSD, EPLF and MDTM times are UTC already.
    pub tz_offset_minutes: i32,
}

/// Bytes → text for one line (RFC 2640 / site charset).
#[derive(Debug, Clone, Copy)]
pub enum TextDecoder {
    Utf8,                                         // invalid bytes → U+FFFD
    Utf8OrFallback(&'static encoding_rs::Encoding), // Auto charset before UTF-8 is confirmed
    Fixed(&'static encoding_rs::Encoding),
}
impl TextDecoder {
    /// Returns the text and whether the fallback encoding was used.
    pub fn decode(&self, bytes: &[u8]) -> (String, bool);
}

/// Month names: English, German (incl. Austrian "Jän"), French, Spanish, Italian, Dutch,
/// Portuguese, Swedish/Norwegian/Danish, and CJK "N月"/"N월". Case-insensitive, trailing
/// '.' ignored, 3-letter prefixes and full names. Returns 1–12.
pub fn parse_month(token: &str) -> Option<u8>;

/// Year for a "Mon DD HH:MM" date (no year): this year in server-local time, or the
/// previous year if that would be more than 1 day in the future; Feb 29 walks back to the
/// last leap year (≤ 8 steps).
pub fn infer_year(month: u8, day: u8, hour: u8, minute: u8, ctx: &ListingContext) -> Option<i32>;

/// Server-local date-time → UTC `Timestamp` with the given precision. For
/// `Precision::Day` no offset is applied: the date is kept as-is at 00:00 UTC (T02 rule).
pub fn local_to_utc(dt: PrimitiveDateTime, precision: Precision, ctx: &ListingContext) -> Timestamp;

pub mod unix {
    /// One `ls -l` line → `Entry`. `None` for headers (`total N`) and
    /// lines that are not Unix format.
    pub fn parse_line(line: &str, ctx: &ListingContext) -> Option<Entry>;
    pub fn is_header(line: &str) -> bool;
}

// courier_ftp_proto_ftp::listing ---------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum ListFormat { Mlsd, Unix, Dos, Eplf, Vms, MvsDataset, MvsMember, IbmI }

#[derive(Debug, Clone)]
pub struct ParseOptions {
    pub ctx: ListingContext,
    pub decoder: TextDecoder,
    /// Tried first: from SYST or the site's server-type override (mapping in T14).
    pub hint: Option<ListFormat>,
}

#[derive(Debug, Clone, Default)]
pub struct ParsedListing {
    pub entries: Vec<Entry>,
    /// Format of the last successfully parsed line (for logs / T14 hints).
    pub format: Option<ListFormat>,
    /// Lines that were not headers and could not be parsed (first 1 000 kept).
    pub skipped: Vec<SkippedLine>,
    pub skipped_count: usize,
    /// Decoded text, lines joined with '\n' (→ `Listing.raw`, T71).
    pub raw: String,
    /// The fallback encoding had to be used for at least one line.
    pub used_fallback_encoding: bool,
}
#[derive(Debug, Clone)]
pub struct SkippedLine { pub line_no: usize, pub text: String, pub reason: SkipReason }
#[derive(Debug, Clone, Copy)]
pub enum SkipReason { Unrecognised, HostileName, LineTooLong, BadNumber }

pub fn parse_mlsd(data: &[u8], opts: &ParseOptions) -> ParsedListing;
pub fn parse_list(data: &[u8], opts: &ParseOptions) -> ParsedListing;
/// One MLST fact line (leading space already removed) → (entry, full pathname).
pub fn parse_mlst_line(line: &str) -> Option<(Entry, String)>;
/// Fuzz/property entry (T91 §7): first byte chooses MLSD/LIST and the hint.
pub fn fuzz_listing(data: &[u8]);
```

### Behaviour

**1. Common pipeline (`parse_mlsd`, `parse_list`).**
1. Split `data` at `\n` **as bytes** (all supported encodings are ASCII-compatible);
   strip one trailing `\r`. Lines > 64 KiB → `SkipReason::LineTooLong`.
2. Decode each line with `opts.decoder`; record `used_fallback_encoding`.
3. Skip empty and whitespace-only lines.
4. Parse (below). Each entry gets `hidden = name.starts_with('.')`. There is no per-entry
   raw text (T02 `Entry` has no `raw`); the raw text lives only in `ParsedListing.raw`.
5. **Name rules (T91 hostile server):** drop `.` and `..`; drop names that are empty,
   contain `/` or NUL (`SkipReason::HostileName`). Names are otherwise kept byte-exact
   (leading/trailing spaces, unicode, leading `-`); sanitising for the local disk is T42/T06.
6. Limits: at most 1 000 000 entries (the rest skipped and counted); `skipped` keeps the
   first 1 000 lines. Parsers never panic, never index out of bounds, use checked
   arithmetic for numbers (`BadNumber` on overflow).

**2. MLSD / MLST (RFC 3659 §7).** Grammar:
```
entry  = [facts] SP pathname
facts  = 1*( factname "=" value ";" )
```
- Split at the **first** `"; "` (end of facts + the single SP); the rest of the line is the
  name, byte-exact (may contain `;` and spaces, leading/trailing spaces preserved). A line
  starting with SP has no facts. No `"; "` but a `;`-terminated fact block followed by SP
  is the same thing; anything else → `Unrecognised`.
- Fact names case-insensitive; values case-insensitive where RFC says so (`type`).

| Fact | Mapping |
|---|---|
| `type=file` / `dir` | `File` / `Dir` |
| `type=cdir`, `type=pdir` | line skipped (current/parent dir) |
| `type=OS.unix=slink:<target>` | `Symlink { target: Some(target), target_kind: None }` |
| `type=OS.unix=symlink` | `Symlink { target: None, .. }` |
| `type=OS.unix=blkdev\|chrdev\|socket\|fifo…`, other `OS.*` | `Other` |
| `size=<u64>` | `size` (files); `sizd` ignored |
| `modify=YYYYMMDDHHMMSS[.sss]` | UTC; `Precision::Second`, or `Millis` with a fraction (1–3 digits used, more truncated); invalid → `None` |
| `unix.mode=0755` (octal, 3–4 digits, optional leading 0) | `Permissions { mode, raw: None }` |
| `perm=adfrw…` (no `unix.mode`) | `Permissions { raw: Some("adfrw"), .. }` shown as-is |
| `unix.ownername` / `unix.owner` | `owner` (name preferred over numeric id) |
| `unix.groupname` / `unix.group` | `group` |
| `unique`, `lang`, `media-type`, `charset`, `create`, unknown | ignored |

Example lines:
```
type=dir;modify=20240131120000;perm=flcdmpe;unix.mode=0755;unix.owner=1000;unix.group=1000; public_html
type=file;size=1048576;modify=20240131120000.123;perm=adfrw;unix.ownername=alice; a; tricky name.txt
type=OS.unix=slink:/var/www;modify=20240131120000;unix.mode=0777; www
type=cdir;modify=20240131120000;perm=flcdmpe; .
```
MLST (for `stat`, T14) returns one fact line inside a `250-` reply, starting with one SP;
its pathname is the full path; `parse_mlst_line` returns the entry with `name` = last
component and the full pathname.

**3. LIST format selection.** Candidate order: `opts.hint` (if any), then `Unix`, `Dos`,
`Eplf`, `Vms`, `IbmI`, `MvsMember`, `MvsDataset` (duplicates removed). For each line, the
format that parsed the previous line is tried first, then the rest in order; the first
success wins. Format-specific header and summary lines are recognised and skipped without
counting as unparsed. Unparseable lines are skipped (never abort the listing).

**4. Unix `ls -l` (core `listing::unix`).** Covers GNU/BSD ls, vsftpd, ProFTPD, pure-ftpd,
Windows servers with Unix-style output and SFTP `longname`.
```
total 24
drwxr-xr-x    2 alice    staff        4096 Jan 31 12:00 public_html
-rw-r--r--    1 alice    staff     5368709120 Jan 31  2023 big.iso
-rw-r--r--+   1 1000     1000            12 Jan 31 12:00  leading space.txt
lrwxrwxrwx    1 root     root            11 Feb  3 09:15 www -> /var/www
crw-rw-rw-    1 root     root        1,   3 Jan  1  2024 null
-rw-r--r--    1 ftp            42 Mar 15 08:00 no-group.txt
-rw-r--r--    1 alice    staff        100 2024-01-31 12:00 iso.txt
-rw-r--r--    1 alice    staff        100 2024-01-31 12:00:05.123456789 +0100 full-iso.txt
-rw-r--r--    1 hans     users        100 31. Jän 12:00 datei.txt
----------    1 owner    group        1234 Jan 31 12:00 windows-nt.txt
```
Algorithm:
1. Token 0 = mode: 10 chars, first in `-dlbcpsDn?`, the rest in `rwxsStTlL-`; optional
   11th char `+`, `.` or `@` (ACL/xattr marker). Else → not Unix.
2. Token 1 = link count (digits). If not numeric it is treated as the owner (servers
   without a link column).
3. Find the date by scanning tokens left to right for one of:
   `Mon DD HH:MM`, `Mon DD YYYY`, `DD Mon HH:MM|YYYY` (some locales, also `DD.`),
   `YYYY-MM-DD HH:MM[:SS[.frac]] [±HHMM]` (ISO / `--time-style=full-iso`),
   `N月 DD HH:MM|YYYY` (CJK). Month via `parse_month`.
4. Size = token just before the date: digits → `size`; `major,` + `minor` (device files) →
   `size = None`, kind `Other`.
5. Tokens between the link count and the size: 0 → no owner/group; 1 → owner; 2 → owner,
   group; more → owner = first, group = the rest joined with one space.
6. Name = everything after the date's last token and **one** space (extra spaces are part
   of the name, so leading spaces survive).
7. Kind: `-` File, `d` Dir, `l` Symlink, anything else Other. Symlinks split the name at
   the **first** `" -> "` into name and target (limitation: a symlink whose own name
   contains `" -> "` is split wrongly; non-symlink names containing `" -> "` are kept intact).
8. Time: `HH:MM` → year via `infer_year`, `Precision::Minute`; `YYYY` → `Day` (no offset
   applied); ISO with seconds → `Second`, with a fraction → `Millis`; an explicit `±HHMM`
   zone overrides the site offset. All converted with `local_to_utc`.
9. Permissions: `Permissions::from_rwx_string` of the first 10 chars.

**5. DOS / IIS.**
```
01-31-24  12:00PM       <DIR>          wwwroot
01-31-2024  09:05AM              1,234 report.txt
2024-01-31  23:59                  42 iso-date.txt
31.01.2024  12:00    <DIR>          Ordner
01-31-24  12:00PM    <JUNCTION>     Documents [C:\Users\alice\Documents]
```
Date `MM-DD-YY`, `MM-DD-YYYY`, `YYYY-MM-DD` or `DD.MM.YYYY`; two-digit year < 70 → 20YY,
else 19YY; time `HH:MM` 24 h or with `AM`/`PM` (12 AM = 00); `<DIR>` → Dir;
`<JUNCTION>`/`<SYMLINKD>`/`<SYMLINK>` → Symlink with the `[target]` suffix as target;
otherwise size with `,`/`.` thousands separators removed. Name = rest of the line after the
whitespace following the size column (leading spaces are lost — documented best effort).
`Precision::Minute`, site offset applied.

**6. EPLF** (Easily Parsed LIST Format, D. J. Bernstein).
```
+i8388621.48594,m825718503,r,s280,	djb.html
+i8388621.50690,m824255907,/,	514
+m1706702400,up644,s1024,	notes.txt
```
Line starts with `+`; comma-separated facts up to a TAB; name after the TAB. `/` → Dir,
`r` → File (if no `/`), `s<n>` size, `m<unix seconds>` mtime **UTC** (no site offset,
`Precision::Second`), `up<octal>` mode, `i…` ignored.

**7. VMS.**
```
Directory DISK$USER:[ALICE]

LOGIN.COM;3               2/4        31-JAN-2024 12:00:05.32  [STAFF,ALICE]   (RWED,RWED,RE,)
WWW.DIR;1                 1/3        15-MAR-2023 08:00:00.00  [ALICE]         (RWE,RWE,RE,RE)
A_VERY_LONG_FILE_NAME_THAT_WRAPS.TXT;12
                         10/12       01-FEB-2024 09:15        [STAFF,ALICE]   (RWED,RWED,R,)
%RMS-E-PRV, insufficient privilege or file protection violation

Total of 3 files, 13/18 blocks.
```
Name `NAME.EXT;VERSION`: `.DIR;n` suffix → Dir with the suffix removed; files drop `;n`;
when several versions are listed only the first (highest) is kept. Size = used blocks × 512
(approximation, documented). Date `DD-MMM-YYYY`, time `HH:MM[:SS[.cc]]` (`Minute` or
`Second`), site offset applied. `[GROUP,OWNER]` → group/owner, `[OWNER]` → owner.
`(S,O,G,W)` → `Permissions.raw`. A line with only a file name is joined with the next
line (wrapped entry). `Directory …`, `Total of …`, and `%…-E-…` message lines are headers
(skipped silently, error lines also go to `skipped` with `Unrecognised` for the log).

**8. MVS / z/OS** (basic: name, directory-ness, date).
```
Volume Unit    Referred Ext Used Recfm Lrecl BlkSz Dsorg Dsname
WYOSPT 3390   2024/01/31  1   15  FB      80  6160  PO  ALICE.SOURCE
WYOSPT 3390   2024/01/30  1    2  FB      80 27920  PS  ALICE.DATA.TXT
Migrated                                                ALICE.OLD.DATA
Pseudo Directory                                        ALICE.PROJECTS
```
Dataset rows: `Dsorg` `PO`/`PO-E` or `Pseudo Directory` → Dir; `PS`, `DA`, `VS`,
`Migrated` → File; name = `Dsname`; `Referred` date `YYYY/MM/DD` → `Day` precision (no
offset applied); size `None`.
```
 Name     VV.MM   Created       Changed      Size  Init   Mod   Id
MEMBER1   01.03 2024/01/30 2024/01/31 12:00    15    10     0 ALICE
MEMBER2
```
Member rows: File, modified = `Changed` + time (`Minute`), size `None` (the column counts
records). A bare member name directly after a member header is a File with no metadata.

**9. IBM i (OS/400, QSYS).**
```
ALICE          36864 01/31/24 12:00:05 *DIR       projects/
ALICE         102400 01/31/24 12:00:05 *STMF      report.csv
QSYS           12288 01/30/24 08:00:00 *LIB       MYLIB.LIB
QSYS           77824 01/30/24 08:00:00 *FILE      MYLIB.LIB/MYFILE.FILE
                                       *MEM       MYLIB.LIB/MYFILE.FILE/MBR1.MBR
```
Tokens owner, size, date `MM/DD/YY` (or `DD.MM.YY`), time, `*TYPE`, name. `*DIR`, `*LIB`,
`*FILE`, `*FLR` → Dir; others → File. Name: strip trailing `/`, keep the last `/`
component. Continuation rows (only type and name) → File without metadata. `Second`
precision, site offset applied.

**10. Time zone and precision summary.**

| Source | Time base | Offset applied | Precision |
|---|---|---|---|
| MLSD/MLST `modify` | UTC | no | Second / Millis |
| EPLF `m` | UTC (epoch) | no | Second |
| Unix `HH:MM` / ISO | server local | yes | Minute / Second–Millis |
| Unix `YYYY` (date only) | calendar date | **no** (Day precision, T02) | Day |
| DOS, VMS, MVS member, IBM i | server local | yes | Minute / Second |
| MVS dataset `Referred` | calendar date | **no** | Day |

### Data formats and configuration

Fixture corpus layout:
```
crates/courier-ftp-core/tests/listings/unix/<case>.txt         (+ optional <case>.opts.json)
crates/courier-ftp-proto-ftp/tests/listings/{mlsd,dos,eplf,vms,mvs,ibmi,mixed}/<case>.txt
crates/courier-ftp-proto-ftp/tests/snapshots/…                 (insta)
```
`<case>.opts.json`: `{"now": "2024-06-15T12:00:00Z", "tz_offset_minutes": 0, "hint": null,
"charset": "utf-8" | "windows-1252" | "auto"}`; defaults as shown. Fixture lines are
written by us (FileZilla's GPL test data may be read as a format reference only, never copied).

Settings: none read directly (T14 passes `tz_offset_minutes` from `ConnectInfo`, the hint,
the decoder and `now`).

### Errors

Parsers return values, not errors: unparsable/hostile lines go to `ParsedListing.skipped`
with a `SkipReason`. T14 turns an empty result with a non-empty `skipped` list into a
Status warning ("Could not parse N lines of the directory listing") and logs the lines at
`Debug(3)`; it never fails the listing because of them.

### Security and logging

- All input is untrusted server data: bounded line length, entry count, checked numbers,
  no recursion, no regex with catastrophic backtracking (hand-written token scanners or
  `regex` crate only, which is linear-time).
- Hostile names (`..`, `/`, NUL, empty) are dropped here; control characters in names are
  kept for exactness and neutralised at rendering (T53) and on local write (T42/T06).
- This module does no logging (pure); T14 logs.
- Fuzz target `fuzz/fuzz_targets/ftp_listing.rs` → `fuzz_listing`, corpus seeded from the
  fixtures by `fuzz/seed-corpus.sh`.

## Implementation steps

1. Core `listing` module: `ListingContext`, `TextDecoder`, `parse_month` (all languages),
   `infer_year`, `local_to_utc`, with unit tests.
2. Core `listing::unix::parse_line` + Unix fixtures and `insta` snapshots.
3. proto-ftp `listing` module skeleton: pipeline, limits, name rules, `ParsedListing`.
4. MLSD + `parse_mlst_line` + fixtures.
5. DOS/IIS, EPLF parsers + fixtures.
6. VMS (incl. wrapped lines, versions) + fixtures.
7. MVS dataset/member and IBM i + fixtures.
8. Format selection (hint, last-success-first) + mixed fixtures.
9. Property tests, `fuzz_listing`, fuzz target and corpus seeding; bench
   `benches/listing.rs` (criterion) for T00's bench gate.

## Acceptance criteria

- [ ] AC1 Fixture corpus with `insta` snapshots: at least 5 fixture files per format
  (Unix, MLSD, DOS/IIS, EPLF, VMS, MVS dataset, MVS member, IBM i) and every example line
  in this document appears in a fixture.
- [ ] AC2 Year inference is correct around New Year and Feb 29 (injected `now`:
  2024-01-01T00:30Z, 2024-12-31T23:30Z, 2025-03-01, with offsets −720/0/+840).
- [ ] AC3 Site offset applied to LIST times with a time of day only; MLSD and EPLF times
  and Day-precision dates (Unix `YYYY`, MVS `Referred`) are unchanged by any offset
  (e.g. `Jan 31 2024` with offset +840 stays 2024-01-31).
- [ ] AC4 Symlinks: `name -> target` split at the first `" -> "`; a regular file named
  `a -> b` stays intact; MLSD `OS.unix=slink:` targets parsed.
- [ ] AC5 MLSD names with leading/trailing spaces and `;` are preserved byte-exact; Unix
  names with leading spaces preserved.
- [ ] AC6 `.`, `..`, names with `/` or NUL never appear in `entries`.
- [ ] AC7 Localised month names for all listed languages parse (one fixture per language).
- [ ] AC8 Precision set per the summary table (snapshot shows it).
- [ ] AC9 Parsers never panic: property test (≥ 10 000 cases) and the `ftp_listing` fuzz
  target (30 s in CI) find nothing.
- [ ] AC10 Throughput: parsing a 100 000-line Unix listing takes < 150 ms in release mode
  (criterion bench `listing_unix_100k`, gated by T00 `bench-gate`).
- [ ] AC11 `TextDecoder::Utf8OrFallback` reports the fallback and decodes windows-1252
  names correctly.
- [ ] AC12 CI gates (T00) pass; `courier-ftp-core` gains no new heavy dependency (only
  `encoding_rs`, `time`, `regex` already in the workspace).

## Tests

### Unit tests
- `month_names_all_languages_table` (incl. `Jän`, `févr.`, `mrt`, `ago`, `dic`, `maj`,
  `okt`, `1月`, `12월`). AC7.
- `infer_year_new_year_boundaries`, `infer_year_feb_29_walks_back_to_leap_year`. AC2.
- `local_to_utc_applies_offset`, `local_to_utc_day_precision_ignores_offset`
  (offsets −720 and +840 keep the calendar date). AC3.
- `unix_parses_group_and_groupless`, `unix_numeric_owner`, `unix_device_file_has_no_size`,
  `unix_acl_marker_accepted`, `unix_total_line_is_header`, `unix_iso_and_full_iso_dates`,
  `unix_name_with_leading_spaces`, `unix_symlink_with_arrow_in_name_split_at_first`,
  `unix_regular_file_with_arrow_kept`, `unix_size_over_4gib`. AC4, AC5.
- `mlsd_name_with_semicolon_and_spaces_preserved`, `mlsd_cdir_pdir_skipped`,
  `mlsd_unix_mode_preferred_over_perm`, `mlsd_fractional_modify_is_millis`,
  `mlsd_slink_target`, `mlst_line_returns_full_path`. AC4, AC5, AC8.
- `dos_12h_24h_and_year_variants`, `dos_junction_is_symlink`. 
- `eplf_dir_and_file`, `eplf_time_is_utc_without_offset`. AC3.
- `vms_wrapped_entry_joined`, `vms_keeps_highest_version_only`, `vms_dir_suffix_removed`.
- `mvs_dataset_dsorg_po_is_dir`, `mvs_member_without_stats`.
- `ibmi_types_and_continuation_rows`.
- `hostile_names_dropped` (`..`, `a/b`, NUL, empty). AC6.
- `decoder_fallback_reports_and_decodes_cp1252`. AC11.

### Property / fuzz tests
- `prop_unix_render_parse_roundtrip` — random entries (name without `/`, NUL, leading `.`
  rules respected; sizes up to 2^60; dates within the last 300 days and older years)
  rendered as `ls -l` lines parse back to equal fields.
- `prop_mlsd_render_parse_roundtrip` — random fact sets and names (incl. `;` and spaces).
- `prop_parsers_never_panic` — random bytes (≤ 64 KiB) through `parse_list` and
  `parse_mlsd` with every hint (same body as `fuzz_listing`). AC9.
- `prop_infer_year_never_more_than_one_day_ahead`. AC2.
- `prop_line_endings_crlf_lf_equivalent` — CRLF vs LF input gives identical entries.
- Fuzz target `ftp_listing`. AC9.

### Snapshot tests
- `listing_fixtures_snapshot` — `insta::glob!` over every fixture directory; snapshot
  (YAML) of `entries` (name, kind, size, modified RFC 3339 + precision, permissions,
  owner, group, hidden), `format`, `skipped`. AC1, AC7, AC8.

### Integration tests
Not applicable in this task (pure parsers). T14 runs them on real `LIST`/`MLSD` output
from the fake server.

### End-to-end tests
- Covered by T14: `ftp_listing_matches_server_*` lists a prepared tree on vsftpd (LIST),
  proftpd and pure-ftpd (MLSD and LIST) and compares with the known tree.

## Out of scope

- Choosing MLSD vs LIST, `LIST -a`, applying `use_mlsd`/`force_show_hidden_remote` (T14).
- Path translation for VMS/MVS (T14), symlink target-kind resolution (T14/T53).
- Formats not listed (Netware, VxWorks, z/VM, HP NonStop, Tandem): lines are skipped
  and logged; can be added later as new fixture-driven parsers.

## Open questions

None. (Resolved: T31 defines `timezone_offset_minutes` as the server's UTC offset with
this sign convention, and T32 converts FileZilla's value on import.)
