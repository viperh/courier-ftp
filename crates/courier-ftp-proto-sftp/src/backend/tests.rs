#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use courier_ftp_core::{
    backend::{Backend, WriteMode},
    model::PathStyle,
};
use pretty_assertions::assert_eq;
use russh_sftp::protocol::OpenFlags;
use time::{Date, Month, OffsetDateTime, Time};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::{
    io::write_flags,
    testing::{SftpTestKnobs, SftpTestServer},
};

fn tuning(outstanding: u32, request_size: u32) -> SftpTuning {
    SftpTuning {
        request_timeout: Duration::from_secs(20),
        max_outstanding_requests: outstanding,
        request_size,
        max_inflight_bytes: MAX_INFLIGHT_BYTES,
    }
}

fn limits(read: u64, write: u64) -> ServerLimits {
    ServerLimits {
        max_packet_len: 262_144,
        max_read_len: read,
        max_write_len: write,
        max_open_handles: 0,
    }
}

#[test]
fn io_sizes_from_limits_and_settings() {
    // Defaults without limits: 32 KiB × 64 (2 MiB).
    let d = SftpTuning::default();
    assert_eq!(d.request_size, 32_768);
    assert_eq!(d.max_outstanding_requests, 64);
    let s = io_sizes(&d, None);
    assert_eq!(
        s,
        IoSizes {
            read_chunk: 32_768,
            write_chunk: 32_768,
            read_outstanding: 64,
            write_outstanding: 64
        }
    );
    // OpenSSH limits (256 KiB): capped at 255 KiB, 8 MiB / 255 KiB = 32 in flight.
    let s = io_sizes(&d, Some(&limits(262_144, 261_120)));
    assert_eq!((s.read_chunk, s.write_chunk), (261_120, 261_120));
    assert_eq!((s.read_outstanding, s.write_outstanding), (32, 32));
    assert!(u64::from(s.read_chunk) * u64::from(s.read_outstanding) <= 8 << 20);
    // A small server limit wins over the setting.
    let s = io_sizes(&d, Some(&limits(16_384, 8_192)));
    assert_eq!((s.read_chunk, s.write_chunk), (16_384, 8_192));
    // 0 = not limited: the setting.
    let s = io_sizes(&tuning(64, 65_536), Some(&limits(0, 0)));
    assert_eq!((s.read_chunk, s.write_chunk), (65_536, 65_536));
    // Clamping: setting below 4 KiB / above 255 KiB, outstanding 1..=256.
    let s = io_sizes(&tuning(1000, 1), None);
    assert_eq!(s.read_chunk, MIN_CHUNK);
    assert_eq!(s.read_outstanding, 256);
    let s = io_sizes(&tuning(0, 10 << 20), None);
    assert_eq!(s.read_chunk, MAX_CHUNK);
    assert_eq!(s.read_outstanding, 1);
    // A server limit below 4 KiB is respected (requests above it would be refused).
    let s = io_sizes(&d, Some(&limits(1000, 1000)));
    assert_eq!(s.read_chunk, 1000);
    // The budget caps the depth for every chunk size.
    for chunk in [4096, 32_768, 100_000, 261_120] {
        let s = io_sizes(&tuning(256, chunk), None);
        assert!(u64::from(s.read_chunk) * u64::from(s.read_outstanding) <= 8 << 20);
    }
}

#[test]
fn tuning_from_settings_clamps() {
    let mut settings = Settings::default();
    settings.sftp.max_outstanding_requests = 999;
    settings.sftp.request_size = 1;
    settings.connection.timeout_secs = 7;
    let t = SftpTuning::from_settings(&settings);
    assert_eq!(t.max_outstanding_requests, 256);
    assert_eq!(t.request_size, MIN_CHUNK);
    assert_eq!(t.request_timeout, Duration::from_secs(7));
    assert_eq!(t.max_inflight_bytes, 8 << 20);
}

#[test]
fn extensions_parse() {
    let pairs: HashMap<String, String> = [
        ("posix-rename@openssh.com", "1"),
        ("statvfs@openssh.com", "2"),
        ("fsync@openssh.com", "1"),
        ("hardlink@openssh.com", "1"),
        ("limits@openssh.com", "1"),
        ("check-file-name", "1"),
        ("expand-path@openssh.com", "1"),
    ]
    .into_iter()
    .map(|(a, b)| (a.to_owned(), b.to_owned()))
    .collect();
    let (ext, limits) = ServerExtensions::parse(&pairs);
    assert!(limits);
    assert!(ext.posix_rename && ext.statvfs && ext.fsync && ext.hardlink && ext.check_file);
    assert_eq!(ext.other.len(), 7);
    assert!(ext.other.windows(2).all(|w| w[0] <= w[1]));
    // Wrong versions are not supported.
    let pairs: HashMap<String, String> = [("posix-rename@openssh.com", "2")]
        .into_iter()
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
        .collect();
    let (ext, limits) = ServerExtensions::parse(&pairs);
    assert!(!ext.posix_rename && !limits);
}

#[test]
fn write_mode_flags() {
    let w = OpenFlags::WRITE;
    let c = OpenFlags::CREATE;
    let bits = |m| write_flags(m).bits();
    assert_eq!(bits(WriteMode::Create), (w | c | OpenFlags::EXCLUDE).bits());
    assert_eq!(
        bits(WriteMode::Truncate),
        (w | c | OpenFlags::TRUNCATE).bits()
    );
    // Explicit offsets, no APPEND.
    assert_eq!(bits(WriteMode::Append), (w | c).bits());
    assert_eq!(bits(WriteMode::ResumeAt(5)), w.bits());
    assert_eq!(bits(WriteMode::WriteAt(5)), (w | c).bits());
    for m in [
        WriteMode::Create,
        WriteMode::Truncate,
        WriteMode::Append,
        WriteMode::ResumeAt(1),
        WriteMode::WriteAt(1),
    ] {
        assert!(!write_flags(m).contains(OpenFlags::APPEND));
        assert!(!write_flags(m).contains(OpenFlags::READ));
    }
}

#[test]
fn set_mtime_range_check() {
    let date = |y| {
        OffsetDateTime::new_utc(
            Date::from_calendar_date(y, Month::January, 1).unwrap(),
            Time::MIDNIGHT,
        )
    };
    assert!(matches!(
        mtime_attrs(date(1960)),
        Err(Error::InvalidInput(m)) if m.contains("before 1970")
    ));
    assert!(matches!(
        mtime_attrs(date(2107)),
        Err(Error::InvalidInput(_))
    ));
    let a = mtime_attrs(date(2020)).unwrap();
    assert_eq!(a.mtime, Some(1_577_836_800));
    assert_eq!(a.atime, a.mtime);
    assert_eq!((a.size, a.permissions, a.uid), (None, None, None));
    assert!(mtime_attrs(date(1970)).is_ok());
}

#[test]
fn chmod_sets_only_permissions() {
    let a = chmod_attrs(0o100_644 | 0o4000);
    assert_eq!(a.permissions, Some(0o4644));
    assert_eq!(
        (a.size, a.uid, a.gid, a.atime, a.mtime),
        (None, None, None, None, None)
    );
}

#[test]
fn capabilities_constant() {
    let c = SFTP_CAPABILITIES;
    assert!(c.chmod && c.set_mtime && c.resume_download && c.resume_upload && c.append);
    assert!(c.symlinks && c.server_side_rename_across_dirs);
    assert!(c.parallel_connections_allowed && c.positional_writes);
    assert!(!c.raw_commands && !c.ascii_mode && !c.case_insensitive_names);
    assert_eq!(c.path_style, PathStyle::Unix);
}

#[test]
fn posix_rename_payload() {
    assert_eq!(
        posix_rename_data("/a", "/bc"),
        [0, 0, 0, 2, b'/', b'a', 0, 0, 0, 3, b'/', b'b', b'c']
    );
}

#[tokio::test]
async fn security_info_fields() {
    let server = SftpTestServer::start(SftpTestKnobs::default()).await;
    let mut b = server.backend_default();
    assert_eq!(b.security_info(), SessionSecurityInfo::default());
    assert!(b.server_info().is_none());
    assert_eq!(b.capabilities(), SFTP_CAPABILITIES);
    b.connect(CancellationToken::new()).await.unwrap();
    let s = b.security_info();
    assert!(s.encrypted);
    assert_eq!(s.summary, "SSH");
    assert_eq!(s.peer_addr, Some(server.addr()));
    assert!(
        s.server_software
            .as_deref()
            .unwrap()
            .starts_with("SSH-2.0-")
    );
    assert!(s.tls.is_none());
    let key = s.host_key.unwrap();
    assert_eq!(key.key_type, "ssh-ed25519");
    assert_eq!(key.bits, 256);
    assert!(key.fingerprint_sha256.starts_with("SHA256:"));
    let labels: Vec<&str> = s.details.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(
        labels,
        [
            "Key exchange",
            "Cipher",
            "MAC",
            "Compression",
            "Authentication",
            "SFTP version",
            "Extensions"
        ]
    );
    let value = |l: &str| s.details.iter().find(|(k, _)| k == l).unwrap().1.clone();
    assert!(!value("Key exchange").is_empty());
    assert!(!value("Cipher").is_empty());
    assert_eq!(value("Authentication"), "password");
    assert_eq!(value("SFTP version"), "3");
    assert!(value("Extensions").contains("posix-rename@openssh.com"));
    let info = b.server_info().unwrap();
    assert_eq!(info.sftp_version, 3);
    assert!(info.extensions.posix_rename);
    assert_eq!((info.read_chunk, info.outstanding), (32_768, 64));
    assert_eq!(info.ssh.auth_method, "password");
    assert!(matches!(
        b.raw_command("SITE X").await,
        Err(Error::Unsupported(m)) if m.contains("not available over SFTP")
    ));
    b.disconnect().await.unwrap();
    assert!(!b.is_connected());
    assert_eq!(b.security_info(), SessionSecurityInfo::default());
}
