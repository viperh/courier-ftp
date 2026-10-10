//! Formatting file list cells: sizes, dates, types.

use courier_ftp_core::{
    model::{Entry, EntryKind, Precision, Timestamp},
    settings::SizeFormat,
};
use time::UtcOffset;

/// A byte count per the `size_format` setting.
pub(crate) fn size(bytes: u64, format: SizeFormat, separators: bool) -> String {
    match format {
        SizeFormat::Bytes => {
            if separators {
                group_digits(bytes)
            } else {
                bytes.to_string()
            }
        }
        SizeFormat::Iec => scaled(bytes, 1024.0, &["B", "KiB", "MiB", "GiB", "TiB", "PiB"]),
        SizeFormat::Si => scaled(bytes, 1000.0, &["B", "kB", "MB", "GB", "TB", "PB"]),
    }
}

fn scaled(bytes: u64, base: f64, units: &[&str]) -> String {
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= base && unit < units.len() - 1 {
        value /= base;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", units[0])
    } else if value < 10.0 {
        format!("{value:.1} {}", units[unit])
    } else {
        format!("{value:.0} {}", units[unit])
    }
}

/// `1234567` → `1,234,567`.
pub(crate) fn group_digits(n: u64) -> String {
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

/// A timestamp per the `date_format`/`time_format` settings (strftime-like:
/// `%Y %y %m %d %b %H %M %S %%`), in `offset`. Day-precision times show the
/// date only.
pub(crate) fn date(
    t: &Timestamp,
    date_format: &str,
    time_format: &str,
    offset: UtcOffset,
) -> String {
    let local = t.time.to_offset(offset);
    let mut out = strftime(&local, date_format);
    if t.precision > Precision::Day {
        out.push(' ');
        out.push_str(&strftime(&local, time_format));
    }
    out
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn strftime(t: &time::OffsetDateTime, pattern: &str) -> String {
    let mut out = String::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('Y') => out.push_str(&format!("{:04}", t.year())),
            Some('y') => out.push_str(&format!("{:02}", t.year().rem_euclid(100))),
            Some('m') => out.push_str(&format!("{:02}", u8::from(t.month()))),
            Some('d') => out.push_str(&format!("{:02}", t.day())),
            Some('b') => out.push_str(MONTHS[usize::from(u8::from(t.month())) - 1]),
            Some('H') => out.push_str(&format!("{:02}", t.hour())),
            Some('M') => out.push_str(&format!("{:02}", t.minute())),
            Some('S') => out.push_str(&format!("{:02}", t.second())),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

/// A short description of what the entry is, e.g. `HTML file`, `Directory`.
pub(crate) fn kind(entry: &Entry) -> String {
    match &entry.kind {
        EntryKind::Dir => return "Directory".to_owned(),
        EntryKind::Symlink { target_kind, .. } => {
            return if target_kind.as_deref().is_some_and(EntryKind::is_dir_like) {
                "Link (dir)".to_owned()
            } else {
                "Link".to_owned()
            };
        }
        EntryKind::Other => return "Special file".to_owned(),
        EntryKind::File => {}
    }
    let Some((stem, ext)) = entry.name.rsplit_once('.') else {
        return "File".to_owned();
    };
    if stem.is_empty() || ext.is_empty() {
        return "File".to_owned();
    }
    let lower = ext.to_ascii_lowercase();
    let known = match lower.as_str() {
        "htm" | "html" | "xhtml" => "HTML file",
        "css" => "CSS file",
        "js" | "mjs" => "JavaScript file",
        "json" => "JSON file",
        "xml" => "XML file",
        "txt" | "md" | "log" => "Text file",
        "php" => "PHP file",
        "py" => "Python file",
        "rs" => "Rust file",
        "sh" => "Shell script",
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "svg" | "ico" | "bmp" => "Image",
        "zip" | "gz" | "tgz" | "bz2" | "xz" | "zst" | "7z" | "rar" | "tar" => "Archive",
        "pdf" => "PDF document",
        "mp3" | "flac" | "ogg" | "wav" => "Audio",
        "mp4" | "mkv" | "webm" | "mov" | "avi" => "Video",
        _ => "",
    };
    if known.is_empty() {
        format!("{} file", ext.to_ascii_uppercase())
    } else {
        known.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use time::macros::datetime;

    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(size(1_234_567, SizeFormat::Bytes, true), "1,234,567");
        assert_eq!(size(1_234_567, SizeFormat::Bytes, false), "1234567");
        assert_eq!(size(999, SizeFormat::Bytes, true), "999");
        assert_eq!(size(512, SizeFormat::Iec, true), "512 B");
        assert_eq!(size(4096, SizeFormat::Iec, true), "4.0 KiB");
        assert_eq!(size(15 * 1024 * 1024, SizeFormat::Iec, true), "15 MiB");
        assert_eq!(size(4096, SizeFormat::Si, true), "4.1 kB");
        assert_eq!(size(0, SizeFormat::Si, true), "0 B");
        assert_eq!(group_digits(1000), "1,000");
        assert_eq!(group_digits(0), "0");
    }

    #[test]
    fn dates_respect_precision() {
        let t = Timestamp::new(datetime!(2021-01-05 12:30:45 UTC), Precision::Second);
        assert_eq!(
            date(&t, "%Y-%m-%d", "%H:%M", UtcOffset::UTC),
            "2021-01-05 12:30"
        );
        let d = Timestamp::new(datetime!(2021-01-05 0:00 UTC), Precision::Day);
        assert_eq!(date(&d, "%Y-%m-%d", "%H:%M", UtcOffset::UTC), "2021-01-05");
        assert_eq!(
            date(&t, "%d %b %y", "%H:%M:%S %%", UtcOffset::UTC),
            "05 Jan 21 12:30:45 %"
        );
        let east = UtcOffset::from_hms(2, 0, 0).unwrap();
        assert_eq!(date(&t, "%Y-%m-%d", "%H:%M", east), "2021-01-05 14:30");
    }

    #[test]
    fn types() {
        assert_eq!(kind(&Entry::file("index.HTML", 1)), "HTML file");
        assert_eq!(kind(&Entry::file("data.bin", 1)), "BIN file");
        assert_eq!(kind(&Entry::file("Makefile", 1)), "File");
        assert_eq!(kind(&Entry::file(".bashrc", 1)), "File");
        assert_eq!(kind(&Entry::dir("www")), "Directory");
    }
}
