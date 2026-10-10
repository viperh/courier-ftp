//! Range and consistency checks (`Settings::validate`). Each failing field is reset to
//! its default (or a bad list entry dropped) and one warning is added.

use std::fmt::Display;

use super::SettingsWarning;
use super::enums::{ActiveExternalIp, Column, FtpProxyKind, ProxyKind};
use super::model::{
    ColumnSpec, EditingSettings, FtpProxySettings, PaneColumns, Settings, TransferSettings,
};
use crate::edit::EditorChoice;
use crate::filters::FilterSettings;
use crate::model::{FtpEncryption, Protocol, ServerAddress};

/// Maximum length of `ftp.active_external_ip.from_url`.
const MAX_URL_LEN: usize = 512;
/// Maximum number of `editing.associations`.
const MAX_ASSOCIATIONS: usize = 256;
/// Maximum lines of `proxy.ftp_proxy.custom_script`.
const MAX_SCRIPT_LINES: usize = 32;
/// Maximum characters per line of `proxy.ftp_proxy.custom_script`.
const MAX_SCRIPT_LINE_LEN: usize = 512;
/// Maximum length of `interface.date_format` / `time_format`.
const MAX_FORMAT_LEN: usize = 32;
/// Maximum length of one `file_types.ascii_extensions` entry.
const MAX_EXTENSION_LEN: usize = 16;
/// Maximum length of `queue.on_complete_command`.
const MAX_COMMAND_LEN: usize = 1024;

/// Collects warnings.
#[derive(Default)]
struct Checker {
    warnings: Vec<SettingsWarning>,
}

impl Checker {
    fn warn(&mut self, path: &str, message: impl Into<String>) {
        self.warnings.push(SettingsWarning {
            path: path.to_owned(),
            message: message.into(),
        });
    }

    /// `lo ≤ *field ≤ hi`, else reset to `default`.
    fn range<T: PartialOrd + Copy + Display>(
        &mut self,
        path: &str,
        field: &mut T,
        default: T,
        lo: T,
        hi: T,
    ) {
        if *field < lo || *field > hi {
            self.warn(
                path,
                format!("{} is outside {lo}-{hi}; using default", *field),
            );
            *field = default;
        }
    }
}

pub(super) fn validate(s: &mut Settings) -> Vec<SettingsWarning> {
    let d = Settings::default();
    let mut c = Checker::default();

    // connection
    let (v, dv) = (&mut s.connection, &d.connection);
    c.range(
        "connection.timeout_secs",
        &mut v.timeout_secs,
        dv.timeout_secs,
        5,
        600,
    );
    c.range("connection.retries", &mut v.retries, dv.retries, 0, 10);
    c.range(
        "connection.retry_delay_secs",
        &mut v.retry_delay_secs,
        dv.retry_delay_secs,
        0,
        600,
    );
    c.range(
        "connection.keepalive_interval_secs",
        &mut v.keepalive_interval_secs,
        dv.keepalive_interval_secs,
        10,
        3600,
    );

    // ftp
    if let Some(r) = s.ftp.active_port_range {
        let problem = if r.min < 1024 {
            Some(format!("min ({}) < 1024", r.min))
        } else if r.min > r.max {
            Some(format!("min ({}) > max ({})", r.min, r.max))
        } else {
            None
        };
        if let Some(p) = problem {
            c.warn("ftp.active_port_range", format!("{p}; using default"));
            s.ftp.active_port_range = d.ftp.active_port_range;
        }
    }
    if let ActiveExternalIp::FromUrl(url) = &s.ftp.active_external_ip {
        let problem = if !url.starts_with("http://") {
            Some("the URL must start with http://")
        } else if url.len() <= "http://".len() {
            Some("the URL has no host")
        } else if url.len() > MAX_URL_LEN {
            Some("the URL is longer than 512 characters")
        } else {
            None
        };
        if let Some(p) = problem {
            c.warn("ftp.active_external_ip", format!("{p}; using default"));
            s.ftp.active_external_ip = d.ftp.active_external_ip.clone();
        }
    }

    // sftp
    let (v, dv) = (&mut s.sftp, &d.sftp);
    c.range(
        "sftp.max_outstanding_requests",
        &mut v.max_outstanding_requests,
        dv.max_outstanding_requests,
        1,
        256,
    );
    c.range(
        "sftp.request_size",
        &mut v.request_size,
        dv.request_size,
        4096,
        261_120,
    );

    // proxy
    validate_proxy(&mut c, s, &d);

    // transfers
    validate_transfers(&mut c, &mut s.transfers, &d.transfers);

    // file_types
    validate_extensions(&mut c, &mut s.file_types.ascii_extensions);

    // interface
    let (v, dv) = (&mut s.interface, &d.interface);
    c.range(
        "interface.key_sequence_timeout_ms",
        &mut v.key_sequence_timeout_ms,
        dv.key_sequence_timeout_ms,
        200,
        5000,
    );
    for (path, field, default) in [
        ("interface.date_format", &mut v.date_format, &dv.date_format),
        ("interface.time_format", &mut v.time_format, &dv.time_format),
    ] {
        if let Err(p) = check_format(field) {
            c.warn(path, format!("{p}; using default"));
            default.clone_into(field);
        }
    }
    validate_columns(&mut c, &mut v.columns);
    if !is_language(&v.language) {
        c.warn(
            "interface.language",
            "not \"auto\" or a BCP-47 language tag; using default",
        );
        dv.language.clone_into(&mut v.language);
    }

    // logging
    let (v, dv) = (&mut s.logging, &d.logging);
    c.range(
        "logging.pane_max_lines",
        &mut v.pane_max_lines,
        dv.pane_max_lines,
        500,
        100_000,
    );
    if v.log_file.as_ref().is_some_and(|p| !p.is_absolute()) {
        c.warn("logging.log_file", "not an absolute path; using default");
        v.log_file.clone_from(&dv.log_file);
    }
    c.range(
        "logging.log_file_max_mib",
        &mut v.log_file_max_mib,
        dv.log_file_max_mib,
        1,
        1024,
    );
    c.range(
        "logging.log_file_keep",
        &mut v.log_file_keep,
        dv.log_file_keep,
        1,
        50,
    );

    // editing
    validate_editing(&mut c, &mut s.editing, &d.editing);

    // queue
    let (v, dv) = (&mut s.queue, &d.queue);
    if v.on_complete_command.chars().count() > MAX_COMMAND_LEN {
        c.warn(
            "queue.on_complete_command",
            "longer than 1024 characters; using default",
        );
        dv.on_complete_command
            .clone_into(&mut v.on_complete_command);
    }
    c.range(
        "queue.max_successful",
        &mut v.max_successful,
        dv.max_successful,
        0,
        100_000,
    );

    // cache
    let (v, dv) = (&mut s.cache, &d.cache);
    c.range(
        "cache.listing_cache_ttl_secs",
        &mut v.listing_cache_ttl_secs,
        dv.listing_cache_ttl_secs,
        0,
        86_400,
    );
    c.range(
        "cache.listing_cache_max_dirs",
        &mut v.listing_cache_max_dirs,
        dv.listing_cache_max_dirs,
        10,
        10_000,
    );

    // vault
    c.range(
        "vault.auto_lock_minutes",
        &mut s.vault.auto_lock_minutes,
        d.vault.auto_lock_minutes,
        0,
        1440,
    );

    // sync
    let (v, dv) = (&mut s.sync, &d.sync);
    c.range(
        "sync.push_debounce_ms",
        &mut v.push_debounce_ms,
        dv.push_debounce_ms,
        100,
        60_000,
    );
    c.range(
        "sync.poll_fallback_secs",
        &mut v.poll_fallback_secs,
        dv.poll_fallback_secs,
        30,
        3600,
    );

    validate_filters(&mut c, &mut s.filters);

    c.warnings
}

/// `filters` (T47): at least one set, and an `active_set` that exists. Problems inside
/// filters do not reset anything here: `FilterEngine::new` disables a bad filter.
fn validate_filters(c: &mut Checker, v: &mut FilterSettings) {
    if v.sets.is_empty() {
        c.warn("filters.sets", "no filter sets; using default");
        v.sets = FilterSettings::default().sets;
    }
    if !v.sets.iter().any(|s| s.name == v.active_set)
        && let Some(first) = v.sets.first()
    {
        c.warn(
            "filters.active_set",
            format!(
                "no filter set named `{}`; using `{}`",
                v.active_set, first.name
            ),
        );
        v.active_set = first.name.clone();
    }
}

/// `ServerAddress` host rules (non-empty, ≤ 253 bytes, no whitespace, control
/// characters, '/', '@', '[' or ']').
fn host_is_valid(host: &str) -> bool {
    ServerAddress::new(Protocol::Ftp, FtpEncryption::default(), host, None, None).is_ok()
}

fn validate_proxy(c: &mut Checker, s: &mut Settings, d: &Settings) {
    let p = &mut s.proxy;
    if p.generic.kind != ProxyKind::None && p.ftp_proxy.kind != FtpProxyKind::None {
        c.warn(
            "proxy.ftp_proxy.kind",
            "the generic proxy and the FTP proxy cannot both be used; using default",
        );
        p.ftp_proxy.kind = d.proxy.ftp_proxy.kind;
    }
    if p.generic.kind != ProxyKind::None && !host_is_valid(&p.generic.host) {
        c.warn(
            "proxy.generic.kind",
            "the proxy needs a valid host; using default",
        );
        p.generic.kind = d.proxy.generic.kind;
    }
    validate_ftp_proxy_fields(c, &mut p.ftp_proxy, &d.proxy.ftp_proxy);
}

fn validate_ftp_proxy_fields(c: &mut Checker, f: &mut FtpProxySettings, d: &FtpProxySettings) {
    if f.kind != FtpProxyKind::None && !host_is_valid(&f.host) {
        c.warn(
            "proxy.ftp_proxy.kind",
            "the proxy needs a valid host; using default",
        );
        f.kind = d.kind;
    }
    c.range("proxy.ftp_proxy.port", &mut f.port, d.port, 1, u16::MAX);
    let lines = f.custom_script.split('\n').count();
    if lines > MAX_SCRIPT_LINES {
        c.warn(
            "proxy.ftp_proxy.custom_script",
            "more than 32 lines; using default",
        );
        d.custom_script.clone_into(&mut f.custom_script);
    } else if f
        .custom_script
        .split('\n')
        .any(|l| l.chars().count() > MAX_SCRIPT_LINE_LEN)
    {
        c.warn(
            "proxy.ftp_proxy.custom_script",
            "a line is longer than 512 characters; using default",
        );
        d.custom_script.clone_into(&mut f.custom_script);
    }
}

fn validate_transfers(c: &mut Checker, v: &mut TransferSettings, d: &TransferSettings) {
    c.range(
        "transfers.max_concurrent",
        &mut v.max_concurrent,
        d.max_concurrent,
        1,
        16,
    );
    let max = v.max_concurrent;
    for (path, field, default) in [
        (
            "transfers.max_downloads",
            &mut v.max_downloads,
            d.max_downloads,
        ),
        ("transfers.max_uploads", &mut v.max_uploads, d.max_uploads),
    ] {
        if *field > max {
            c.warn(
                path,
                format!("{field} > max_concurrent ({max}); using default"),
            );
            *field = default;
        }
    }
    c.range(
        "transfers.download_limit_kib",
        &mut v.download_limit_kib,
        d.download_limit_kib,
        0,
        1_048_576,
    );
    c.range(
        "transfers.upload_limit_kib",
        &mut v.upload_limit_kib,
        d.upload_limit_kib,
        0,
        1_048_576,
    );
    let ch = v.invalid_char_replacement;
    if ch.is_control()
        || matches!(
            ch,
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '.' | ' '
        )
    {
        c.warn(
            "transfers.invalid_char_replacement",
            "the replacement is itself not allowed in file names; using default",
        );
        v.invalid_char_replacement = d.invalid_char_replacement;
    }
    let (s, ds) = (&mut v.segmented, &d.segmented);
    c.range(
        "transfers.segmented.min_file_size_mib",
        &mut s.min_file_size_mib,
        ds.min_file_size_mib,
        1,
        1_048_576,
    );
    c.range(
        "transfers.segmented.max_segments",
        &mut s.max_segments,
        ds.max_segments,
        1,
        16,
    );
    c.range(
        "transfers.segmented.min_segment_size_mib",
        &mut s.min_segment_size_mib,
        ds.min_segment_size_mib,
        1,
        1024,
    );
}

/// Lowercase, strip leading dots, drop duplicates (no warning); drop empty entries and
/// entries with '/', whitespace or more than 16 characters (one warning each).
fn validate_extensions(c: &mut Checker, exts: &mut Vec<String>) {
    let mut out: Vec<String> = Vec::with_capacity(exts.len());
    for e in exts.drain(..) {
        let e = e.trim_start_matches('.').to_lowercase();
        if e.is_empty()
            || e.contains('/')
            || e.chars().any(char::is_whitespace)
            || e.chars().count() > MAX_EXTENSION_LEN
        {
            c.warn(
                "file_types.ascii_extensions",
                "an empty entry or one with '/', whitespace or more than 16 characters was dropped",
            );
            continue;
        }
        if !out.contains(&e) {
            out.push(e);
        }
    }
    *exts = out;
}

/// Tokens `%Y %y %m %d %e %b %H %I %M %S %p %%` plus literal text, ≤ 32 characters.
fn check_format(f: &str) -> Result<(), &'static str> {
    if f.chars().count() > MAX_FORMAT_LEN {
        return Err("longer than 32 characters");
    }
    let mut chars = f.chars();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            match chars.next() {
                Some('Y' | 'y' | 'm' | 'd' | 'e' | 'b' | 'H' | 'I' | 'M' | 'S' | 'p' | '%') => {}
                _ => return Err("unsupported % token"),
            }
        }
    }
    Ok(())
}

/// `"auto"` or a BCP-47-shaped tag: a 2–8 letter primary subtag, then 1–8 character
/// alphanumeric subtags separated by '-'.
fn is_language(tag: &str) -> bool {
    if tag == "auto" {
        return true;
    }
    let mut parts = tag.split('-');
    let primary_ok = parts
        .next()
        .is_some_and(|p| (2..=8).contains(&p.len()) && p.chars().all(|c| c.is_ascii_alphabetic()));
    primary_ok
        && parts.all(|p| (1..=8).contains(&p.len()) && p.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// Each column at most once; Name present and visible.
fn validate_columns(c: &mut Checker, cols: &mut PaneColumns) {
    for (path, list) in [
        ("interface.columns.local", &mut cols.local),
        ("interface.columns.remote", &mut cols.remote),
    ] {
        let mut seen = Vec::with_capacity(list.len());
        let before = list.len();
        list.retain(|spec| {
            if seen.contains(&spec.column) {
                false
            } else {
                seen.push(spec.column);
                true
            }
        });
        if list.len() != before {
            c.warn(path, "duplicate columns were dropped");
        }
        match list.iter_mut().find(|s| s.column == Column::Name) {
            Some(name) if !name.visible => {
                c.warn(path, "the name column is always visible");
                name.visible = true;
            }
            Some(_) => {}
            None => {
                c.warn(path, "the name column is always present; added");
                list.insert(
                    0,
                    ColumnSpec {
                        column: Column::Name,
                        visible: true,
                    },
                );
            }
        }
    }
}

fn validate_editing(c: &mut Checker, v: &mut EditingSettings, d: &EditingSettings) {
    if let EditorChoice::Command { command, .. } = &v.editor
        && command.trim().is_empty()
    {
        c.warn(
            "editing.editor",
            "the editor command is empty; using default",
        );
        v.editor = d.editor.clone();
    }
    let mut index = 0usize;
    v.associations.retain(|a| {
        let i = index;
        index += 1;
        let problem = if a.pattern.is_empty() || a.command.trim().is_empty() {
            Some("an empty pattern or command")
        } else if globset::Glob::new(&a.pattern).is_err() {
            Some("an invalid glob pattern")
        } else {
            None
        };
        match problem {
            Some(p) => {
                c.warn(
                    "editing.associations",
                    format!("entry {i} has {p} and was dropped"),
                );
                false
            }
            None => true,
        }
    });
    if v.associations.len() > MAX_ASSOCIATIONS {
        c.warn(
            "editing.associations",
            "more than 256 entries; the rest were dropped",
        );
        v.associations.truncate(MAX_ASSOCIATIONS);
    }
    c.range(
        "editing.max_size_mib",
        &mut v.max_size_mib,
        d.max_size_mib,
        0,
        10_240,
    );
}
