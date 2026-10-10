# T13 — FTP directory listing parsers

**Phase:** B FTP · **Depends on:** T02 · **Crate:** `courier-ftp-proto-ftp` (`listing` module) · **FEATURES.md:** §1 (listing parser for many server formats, time zone offset, charset)
**Related (integrates with, not blocking):** T11, T71

## Goal

Turn `MLSD` and `LIST` output from any common server into `Vec<Entry>`.
This is the part of FileZilla that took years to get right — invest in tests.

## Scope

1. **Strategy**
   - If FEAT lists `MLSD` and `use_mlsd` → use `MLSD`. Otherwise `LIST` (`LIST -a` when `force_show_hidden_remote`; if the server errors on `-a`, retry without and remember).
   - Keep the raw text in `Listing.raw` for T71.
2. **MLSD parser (RFC 3659)**
   - Facts: `type` (`file`, `dir`, `cdir`, `pdir`, `OS.unix=symlink`, `OS.unix=slink:<target>`), `size`, `sizd`, `modify` (`YYYYMMDDHHMMSS[.sss]`, **UTC**), `perm`, `unix.mode`, `unix.owner`, `unix.group`, `unix.ownername`, `unix.groupname`, `unique`.
   - Skip `cdir`/`pdir`. Fact names case-insensitive. Name follows the first space after the facts (names may contain `;` and spaces).
3. **LIST parsers** — try each in order per line, remember which succeeded and try it first next line:
   - **Unix `ls -l`** and variants — this parser lives in `courier-ftp-core::listing::unix` (not in the FTP crate) because the SFTP backend (T22) reuses it for `longname`; the other formats stay in the FTP crate: with/without group column, numeric owners, device files (`major, minor` size), ACL `+`/`.`/`@` after mode, `total N` header line (skip), symlinks `name -> target`, dates `Mon DD HH:MM` (year inferred: if result is > 1 day in the future, use previous year) and `Mon DD  YYYY`, ISO dates (`2024-01-31 12:00`), localised month names (German, French, Spanish… at least the ones FileZilla handles: check `Jan/Jän/janv/ene/...`), filenames with leading spaces.
   - **DOS / IIS**: `01-31-24  12:00PM  <DIR>  name` and `       1234 name`; 2- and 4-digit years; 24-h variant.
   - **EPLF**: `+i8388621.48594,m825718503,r,s280,\tname`.
   - **VMS**: `NAME.EXT;1  12/24  31-JAN-2024 12:00:00  [GROUP,OWNER]  (RWED,RWED,RE,)`; strip version `;N`, dirs end in `.DIR`; multi-line entries (name on one line, details on next).
   - **MVS / z/OS** datasets and PDS members (basic support: name, size unknown, dir-ness).
   - **IBM i / AS400** (`QSYS`) basic.
   - **Windows NT with Unix-ish output** (`----------   1 owner    group      1234 Jan 31 12:00 name`).
   - Unparseable lines are logged at debug level and skipped, never abort the listing.
4. **Time zones**: LIST times are server-local. Apply the site's `timezone_offset` (T31) minutes to convert to UTC. MLSD is UTC — no offset.
5. **Precision**: set `Timestamp.precision` (Day for `YYYY` format, Minute for `HH:MM`, Second for MLSD).
6. **Hidden**: dotfiles → `hidden = true`.
7. **Charset**: decode raw bytes per session charset before parsing (bytes → String happens in the data reader).

## Acceptance criteria

- [x] Fixture corpus in `crates/courier-ftp-proto-ftp/tests/listings/*.txt` with expected output (snapshot via `insta`), covering every format above, at least 5 samples each.
- [x] Year inference correct around New Year (use injectable "now").
- [x] Symlink target parsing handles names containing ` -> ` (use entry type + heuristic; document limitations).
- [x] Filenames with leading/trailing spaces preserved for MLSD; best effort for LIST.
- [x] Parser never panics on arbitrary input (fuzz target with `cargo fuzz` or a proptest that feeds random lines).

## Tests

- Snapshot tests on the corpus. Source real samples from FileZilla's `tests/` dir in its SVN repo (GPL — only use as a reference for formats; write our own fixture lines, don't copy their file).
- Proptest: random bytes → no panic.
