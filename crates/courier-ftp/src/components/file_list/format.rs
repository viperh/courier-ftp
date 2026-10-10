//! Formatting of the size, modified, type, permissions and owner columns.

use std::{borrow::Cow, sync::OnceLock};

use courier_ftp_core::{
    model::{Entry, EntryKind, Precision, SymlinkTarget, Timestamp},
    settings::{InterfaceSettings, SizeFormat},
};
use time::{OffsetDateTime, UtcOffset};

static LOCAL_OFFSET: OnceLock<UtcOffset> = OnceLock::new();

/// Captures the local UTC offset. Called once at startup before the runtime spawns
/// threads (the `time` crate refuses afterwards on Unix); falls back to UTC.
pub(crate) fn capture_local_offset() {
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    let _ = LOCAL_OFFSET.set(offset);
}

/// The offset captured by [`capture_local_offset`] (UTC when never captured, e.g. in
/// tests).
pub(crate) fn local_offset() -> UtcOffset {
    LOCAL_OFFSET.get().copied().unwrap_or(UtcOffset::UTC)
}

/// `1234567` → `1,234,567`.
fn with_separators(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Three significant digits: `4.10`, `48.7`, `121`.
fn three_digits(v: f64) -> String {
    if v < 9.995 {
        format!("{v:.2}")
    } else if v < 99.95 {
        format!("{v:.1}")
    } else {
        format!("{v:.0}")
    }
}

/// Size in the pane's format (`interface.size_format`).
pub(crate) fn format_size(bytes: u64, format: SizeFormat, thousands: bool) -> String {
    let (base, units): (f64, [&str; 4]) = match format {
        SizeFormat::Bytes => {
            return if thousands {
                with_separators(bytes)
            } else {
                bytes.to_string()
            };
        }
        SizeFormat::Iec => (1024.0, ["KiB", "MiB", "GiB", "TiB"]),
        SizeFormat::Si => (1000.0, ["kB", "MB", "GB", "TB"]),
    };
    #[expect(
        clippy::cast_precision_loss,
        reason = "display only: three significant digits"
    )]
    let mut v = bytes as f64;
    if v < base {
        return format!("{bytes} B");
    }
    let mut unit = 0;
    v /= base;
    while v >= 999.5 && unit < units.len() - 1 {
        v /= base;
        unit += 1;
    }
    format!("{} {}", three_digits(v), units[unit])
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Expands the strftime subset (`%Y %m %d %b %H %M %S %I %p %%`); anything else is
/// copied.
fn strftime(t: OffsetDateTime, fmt: &str, out: &mut String) {
    let mut chars = fmt.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('Y') => out.push_str(&format!("{:04}", t.year())),
            Some('m') => out.push_str(&format!("{:02}", u8::from(t.month()))),
            Some('d') => out.push_str(&format!("{:02}", t.day())),
            Some('b') => out.push_str(MONTHS[usize::from(u8::from(t.month())) - 1]),
            Some('H') => out.push_str(&format!("{:02}", t.hour())),
            Some('M') => out.push_str(&format!("{:02}", t.minute())),
            Some('S') => out.push_str(&format!("{:02}", t.second())),
            Some('I') => {
                let h = t.hour() % 12;
                out.push_str(&format!("{:02}", if h == 0 { 12 } else { h }));
            }
            Some('p') => out.push_str(if t.hour() < 12 { "AM" } else { "PM" }),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
}

/// Date/time formats of the pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DateFormats {
    /// `interface.date_format`.
    pub date: String,
    /// `interface.time_format`.
    pub time: String,
    /// Local offset.
    pub offset: UtcOffset,
    /// The current year in the local offset (compact form).
    pub current_year: i32,
}

impl DateFormats {
    /// The formats from the settings; `now` gives the current year.
    pub(crate) fn from_settings(i: &InterfaceSettings, now: OffsetDateTime) -> Self {
        let offset = local_offset();
        Self {
            date: i.date_format.clone(),
            time: i.time_format.clone(),
            offset,
            current_year: now.to_offset(offset).year(),
        }
    }
}

/// The Modified column. Day precision prints the date only and is not shifted (it is
/// a calendar date). `compact`: `MM-DD HH:MM` in the current year, else `YYYY-MM-DD`.
pub(crate) fn format_modified(ts: &Timestamp, f: &DateFormats, compact: bool) -> String {
    let day = ts.precision == Precision::Day;
    let t = if day {
        ts.time
    } else {
        ts.time.to_offset(f.offset)
    };
    let mut out = String::with_capacity(16);
    if compact {
        if t.year() == f.current_year {
            strftime(t, if day { "%m-%d" } else { "%m-%d %H:%M" }, &mut out);
        } else {
            strftime(t, "%Y-%m-%d", &mut out);
        }
        return out;
    }
    strftime(t, &f.date, &mut out);
    if !day {
        out.push(' ');
        strftime(t, &f.time, &mut out);
    }
    out
}

/// Built-in type names by lower-case extension (48 entries).
const TYPES: &[(&str, &str)] = &[
    ("html", "HTML file"),
    ("htm", "HTML file"),
    ("xhtml", "HTML file"),
    ("css", "CSS file"),
    ("js", "JavaScript"),
    ("mjs", "JavaScript"),
    ("ts", "TypeScript"),
    ("json", "JSON file"),
    ("xml", "XML file"),
    ("md", "Markdown"),
    ("txt", "Text file"),
    ("log", "Log file"),
    ("csv", "CSV file"),
    ("ini", "Config file"),
    ("conf", "Config file"),
    ("cfg", "Config file"),
    ("yml", "YAML file"),
    ("yaml", "YAML file"),
    ("toml", "TOML file"),
    ("php", "PHP script"),
    ("py", "Python script"),
    ("rb", "Ruby script"),
    ("pl", "Perl script"),
    ("sh", "Shell script"),
    ("bat", "Batch file"),
    ("c", "C source"),
    ("h", "C header"),
    ("cpp", "C++ source"),
    ("rs", "Rust source"),
    ("go", "Go source"),
    ("java", "Java source"),
    ("sql", "SQL file"),
    ("gz", "GZIP archive"),
    ("tgz", "GZIP archive"),
    ("zip", "ZIP archive"),
    ("tar", "TAR archive"),
    ("bz2", "BZIP2 archive"),
    ("xz", "XZ archive"),
    ("7z", "7-Zip archive"),
    ("rar", "RAR archive"),
    ("png", "Image"),
    ("jpg", "Image"),
    ("jpeg", "Image"),
    ("gif", "Image"),
    ("svg", "SVG image"),
    ("ico", "Icon file"),
    ("pdf", "PDF document"),
    ("mp4", "Video"),
];

/// The Type column.
pub(crate) fn type_description(entry: &Entry) -> Cow<'static, str> {
    match &entry.kind {
        EntryKind::Dir => return Cow::Borrowed("Directory"),
        EntryKind::Symlink { .. } => return Cow::Borrowed("Link"),
        EntryKind::Other => return Cow::Borrowed("Special"),
        EntryKind::File => {}
    }
    let name = entry.name.as_str();
    let Some(dot) = name.rfind('.').filter(|i| *i > 0 && *i + 1 < name.len()) else {
        return Cow::Borrowed("File");
    };
    let ext = &name[dot + 1..];
    let lower = ext.to_ascii_lowercase();
    if let Some((_, t)) = TYPES.iter().find(|(e, _)| *e == lower) {
        return Cow::Borrowed(t);
    }
    let upper: String = ext.chars().take(8).collect::<String>().to_uppercase();
    Cow::Owned(format!("{upper} file"))
}

/// The Permissions column: `drwxr-xr-x`, else the raw text cut to 10.
pub(crate) fn format_permissions(entry: &Entry) -> String {
    let Some(p) = &entry.permissions else {
        return String::new();
    };
    if let Some(s) = p.ls_string(&entry.kind) {
        return s;
    }
    p.raw
        .as_deref()
        .map(|r| r.chars().take(10).collect())
        .unwrap_or_default()
}

/// The Owner/Group column: `owner group`, or the one that exists.
pub(crate) fn format_owner(entry: &Entry) -> String {
    match (&entry.owner, &entry.group) {
        (Some(o), Some(g)) => format!("{o} {g}"),
        (Some(o), None) => o.clone(),
        (None, Some(g)) => g.clone(),
        (None, None) => String::new(),
    }
}

/// Whether the size is shown (files and links to files).
pub(crate) fn shows_size(entry: &Entry) -> bool {
    match &entry.kind {
        EntryKind::File | EntryKind::Other => true,
        EntryKind::Dir => false,
        EntryKind::Symlink { target_kind, .. } => !matches!(target_kind, Some(SymlinkTarget::Dir)),
    }
}

#[cfg(test)]
mod tests {
    use courier_ftp_core::model::Permissions;
    use time::macros::datetime;

    use super::*;

    #[test]
    fn format_size_iec_three_significant_digits() {
        let f = |n| format_size(n, SizeFormat::Iec, true);
        assert_eq!(f(0), "0 B");
        assert_eq!(f(412), "412 B");
        assert_eq!(f(1023), "1023 B");
        assert_eq!(f(1024), "1.00 KiB");
        assert_eq!(f(4198), "4.10 KiB");
        assert_eq!(f(49_869), "48.7 KiB");
        assert_eq!(f(1_300_000_000), "1.21 GiB");
        assert_eq!(f(15_360), "15.0 KiB");
        assert_eq!(f(1024 * 1024 - 1), "1.00 MiB");
        assert_eq!(f(u64::MAX), "16777216 TiB");
    }

    #[test]
    fn format_size_bytes_with_separator() {
        assert_eq!(format_size(1_234_567, SizeFormat::Bytes, true), "1,234,567");
        assert_eq!(format_size(1_234_567, SizeFormat::Bytes, false), "1234567");
        assert_eq!(format_size(123, SizeFormat::Bytes, true), "123");
        assert_eq!(format_size(123_456, SizeFormat::Bytes, true), "123,456");
        assert_eq!(format_size(0, SizeFormat::Bytes, true), "0");
    }

    #[test]
    fn format_size_si() {
        assert_eq!(format_size(999, SizeFormat::Si, true), "999 B");
        assert_eq!(format_size(1000, SizeFormat::Si, true), "1.00 kB");
        assert_eq!(format_size(48_700, SizeFormat::Si, true), "48.7 kB");
        assert_eq!(format_size(1_210_000_000, SizeFormat::Si, true), "1.21 GB");
    }

    fn formats() -> DateFormats {
        DateFormats {
            date: "%Y-%m-%d".into(),
            time: "%H:%M".into(),
            offset: UtcOffset::UTC,
            current_year: 2026,
        }
    }

    #[test]
    fn format_modified_day_precision_has_no_time() {
        let ts = Timestamp::new(datetime!(2025-01-05 00:00 UTC), Precision::Day);
        assert_eq!(format_modified(&ts, &formats(), false), "2025-01-05");
        let ts = Timestamp::new(datetime!(2026-10-08 18:22:13 UTC), Precision::Second);
        assert_eq!(format_modified(&ts, &formats(), false), "2026-10-08 18:22");
        let mut f = formats();
        f.date = "%d %b %Y".into();
        f.time = "%I:%M:%S %p".into();
        assert_eq!(format_modified(&ts, &f, false), "08 Oct 2026 06:22:13 PM");
        // The local offset applies to times, not to dates.
        f = formats();
        f.offset = UtcOffset::from_hms(2, 0, 0).unwrap_or(UtcOffset::UTC);
        assert_eq!(format_modified(&ts, &f, false), "2026-10-08 20:22");
        let day = Timestamp::new(datetime!(2025-01-05 00:00 UTC), Precision::Day);
        assert_eq!(format_modified(&day, &f, false), "2025-01-05");
    }

    #[test]
    fn format_modified_compact_current_year() {
        let ts = Timestamp::new(datetime!(2026-10-08 18:22 UTC), Precision::Minute);
        assert_eq!(format_modified(&ts, &formats(), true), "10-08 18:22");
        let old = Timestamp::new(datetime!(2025-01-05 10:00 UTC), Precision::Minute);
        assert_eq!(format_modified(&old, &formats(), true), "2025-01-05");
    }

    #[test]
    fn type_description_table_and_fallbacks() {
        let file = |n: &str| Entry::new(n, EntryKind::File);
        assert_eq!(type_description(&file(".htaccess")), "File");
        assert_eq!(type_description(&file("x.TAR.GZ")), "GZIP archive");
        assert_eq!(type_description(&file("a.weird")), "WEIRD file");
        assert_eq!(
            type_description(&file("a.verylongextension")),
            "VERYLONG file"
        );
        assert_eq!(type_description(&file("noext")), "File");
        assert_eq!(type_description(&file("trailing.")), "File");
        assert_eq!(type_description(&file("index.html")), "HTML file");
        assert_eq!(
            type_description(&Entry::new("d", EntryKind::Dir)),
            "Directory"
        );
        assert_eq!(
            type_description(&Entry::new("o", EntryKind::Other)),
            "Special"
        );
        assert_eq!(TYPES.len(), 48);
    }

    #[test]
    fn permissions_and_owner() {
        let mut e = Entry::new("a", EntryKind::Dir);
        e.permissions = Some(Permissions::from_mode(0o755));
        assert_eq!(format_permissions(&e), "drwxr-xr-x");
        e.permissions = Some(Permissions::from_raw("flcdmpe-and-more"));
        assert_eq!(format_permissions(&e), "flcdmpe-an");
        e.owner = Some("deploy".into());
        assert_eq!(format_owner(&e), "deploy");
        e.group = Some("www".into());
        assert_eq!(format_owner(&e), "deploy www");
    }
}
