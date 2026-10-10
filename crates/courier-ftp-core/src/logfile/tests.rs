use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::Duration,
};

use pretty_assertions::assert_eq;
use time::{Date, Month, OffsetDateTime, UtcOffset};

use super::*;
use crate::events::{self, CoreEvent, SessionId};

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn size_rotation_shifts_and_keeps_n_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.log");
    let mut log = SizeRotating::new(&path, 20, 2);
    for i in 0..6 {
        // 10 bytes each: two lines per file.
        log.write_all(format!("line {i:03}\n").as_bytes()).unwrap();
    }
    log.flush().unwrap();
    assert_eq!(read(&path), "line 004\nline 005\n");
    assert_eq!(read(&log.rotated_path(1)), "line 002\nline 003\n");
    assert_eq!(read(&log.rotated_path(2)), "line 000\nline 001\n");
    assert!(!log.rotated_path(3).exists());

    log.write_all(b"line 006\n").unwrap();
    log.write_all(b"line 007\n").unwrap();
    log.write_all(b"line 008\n").unwrap();
    assert_eq!(read(&path), "line 008\n");
    assert_eq!(read(&log.rotated_path(2)), "line 004\nline 005\n");
    assert!(!log.rotated_path(3).exists(), "keeps only 2 old files");
}

#[test]
fn size_rotation_continues_an_existing_file_and_handles_edge_limits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.log");
    fs::write(&path, "0123456789012345678\n").unwrap();
    // The existing size counts: the first write rotates.
    let mut log = SizeRotating::new(&path, 25, 1);
    log.write_all(b"new line\n").unwrap();
    assert_eq!(read(&path), "new line\n");
    assert_eq!(read(&log.rotated_path(1)), "0123456789012345678\n");

    // keep = 0: the file starts over.
    let mut log = SizeRotating::new(dir.path().join("k0.log"), 10, 0);
    log.write_all(b"aaaaaaaa\n").unwrap();
    log.write_all(b"bbbbbbbb\n").unwrap();
    assert_eq!(read(&dir.path().join("k0.log")), "bbbbbbbb\n");
    assert!(!dir.path().join("k0.log.1").exists());

    // A line larger than the limit still goes into a (fresh) file.
    let mut log = SizeRotating::new(dir.path().join("big.log"), 4, 1);
    log.write_all(b"0123456789\n").unwrap();
    log.write_all(b"x\n").unwrap();
    assert_eq!(read(&dir.path().join("big.log")), "x\n");

    // 0 = no limit.
    let mut log = SizeRotating::new(dir.path().join("nolimit.log"), 0, 3);
    for _ in 0..100 {
        log.write_all(b"0123456789\n").unwrap();
    }
    assert_eq!(read(&dir.path().join("nolimit.log")).len(), 1100);
}

#[cfg(unix)]
#[test]
fn log_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;

    let path = dir.path().join("sub/session.log");
    let mut log = SizeRotating::new(&path, 10, 1);
    log.write_all(b"123456789\n").unwrap();
    log.write_all(b"123456789\n").unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&log.rotated_path(1)), 0o600);

    // An existing world-readable file is narrowed.
    let old = dir.path().join("old.log");
    fs::write(&old, "x\n").unwrap();
    fs::set_permissions(&old, fs::Permissions::from_mode(0o644)).unwrap();
    drop(open_private(&old).unwrap());
    assert_eq!(mode(&old), 0o600);

    let mut daily = DailyRotating::new(dir.path(), "courier-ftp", "log", 7);
    daily.write_all(b"x\n").unwrap();
    for f in daily.existing() {
        assert_eq!(mode(&f), 0o600);
    }

    let saved = dir.path().join("saved.txt");
    write_private(&saved, "log text").unwrap();
    assert_eq!(mode(&saved), 0o600);
    assert_eq!(read(&saved), "log text");
}

#[test]
fn daily_rotation_starts_a_file_per_day_and_keeps_seven() {
    let dir = tempfile::tempdir().unwrap();
    // Unrelated files are never touched.
    fs::write(dir.path().join("courier-ftp.log"), "old style\n").unwrap();
    fs::write(dir.path().join("courier-ftp.notes.log"), "keep\n").unwrap();
    fs::write(dir.path().join("session.log"), "keep\n").unwrap();

    let day = Arc::new(Mutex::new(
        Date::from_calendar_date(2026, Month::September, 25).unwrap(),
    ));
    let clock = Arc::clone(&day);
    let mut log = DailyRotating::with_clock(dir.path(), "courier-ftp", "log", 7, move || {
        *clock.lock().unwrap()
    });
    for i in 0..10 {
        log.write_all(format!("day {i} a\n").as_bytes()).unwrap();
        log.write_all(format!("day {i} b\n").as_bytes()).unwrap();
        let next = day.lock().unwrap().next_day().unwrap();
        *day.lock().unwrap() = next;
    }
    let names: Vec<String> = log
        .existing()
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        [
            "courier-ftp.2026-09-28.log",
            "courier-ftp.2026-09-29.log",
            "courier-ftp.2026-09-30.log",
            "courier-ftp.2026-10-01.log",
            "courier-ftp.2026-10-02.log",
            "courier-ftp.2026-10-03.log",
            "courier-ftp.2026-10-04.log",
        ]
    );
    assert_eq!(
        read(&dir.path().join("courier-ftp.2026-10-04.log")),
        "day 9 a\nday 9 b\n"
    );
    for keep in ["courier-ftp.log", "courier-ftp.notes.log", "session.log"] {
        assert!(dir.path().join(keep).exists(), "{keep} was removed");
    }

    // Reopening on the same day appends.
    let mut again = DailyRotating::with_clock(dir.path(), "courier-ftp", "log", 7, || {
        Date::from_calendar_date(2026, Month::October, 4).unwrap()
    });
    again.write_all(b"after restart\n").unwrap();
    assert_eq!(
        read(&dir.path().join("courier-ftp.2026-10-04.log")),
        "day 9 a\nday 9 b\nafter restart\n"
    );
}

/// A writer that blocks until released, to fill the channel.
struct Gate {
    open: Arc<(Mutex<bool>, std::sync::Condvar)>,
    out: Arc<Mutex<Vec<u8>>>,
}

impl Write for Gate {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (lock, cv) = &*self.open;
        let mut open = lock.lock().unwrap();
        while !*open {
            open = cv.wait(open).unwrap();
        }
        self.out.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn background_writer_drops_and_counts_when_full() {
    let open = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let out = Arc::new(Mutex::new(Vec::new()));
    let gate = Gate {
        open: Arc::clone(&open),
        out: Arc::clone(&out),
    };
    let writer = BackgroundWriter::spawn(
        "test-log",
        gate,
        4,
        Box::new(|n| format!("[{n} dropped]\n")),
    )
    .unwrap();
    // The thread takes the first line and blocks in the gate; 4 more fill the
    // channel; the rest are dropped without blocking.
    let mut accepted = 0;
    for i in 0..50 {
        if writer.write_line(format!("{i}\n").into_bytes()) {
            accepted += 1;
        }
        if i == 0 {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    assert!(writer.dropped() > 0);
    assert_eq!(accepted + writer.dropped(), 50);
    {
        let (lock, cv) = &*open;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
    // Wait for the backlog to drain, then the note comes before the next line.
    assert!(writer.flush_timeout(Duration::from_secs(10)));
    assert!(writer.write_line(b"after\n".to_vec()));
    assert!(writer.flush_timeout(Duration::from_secs(10)));
    let text = String::from_utf8(out.lock().unwrap().clone()).unwrap();
    let note = format!("[{} dropped]\n", writer.dropped());
    assert_eq!(text.matches(&note).count(), 1, "{text}");
    assert!(text.ends_with("after\n"), "{text}");
    assert_eq!(text.lines().count(), accepted as usize + 2);
}

#[test]
fn session_lines_are_formatted_and_commands_masked() {
    let session = SessionId(3);
    let msg = |kind, text: &str| LogMessage {
        time: OffsetDateTime::from_unix_timestamp(1_791_547_200).unwrap(),
        session,
        kind,
        text: text.to_owned(),
    };
    let utc = UtcOffset::UTC;
    assert_eq!(
        format_session_line(&msg(LogKind::Status, "Connecting"), utc),
        "2026-10-09 12:00:00 #3 Status: Connecting\n"
    );
    let plus2 = UtcOffset::from_hms(2, 0, 0).unwrap();
    assert_eq!(
        format_session_line(&msg(LogKind::Response, "230 ok"), plus2),
        "2026-10-09 14:00:00 #3 Response: 230 ok\n"
    );
    // Commands logged without `log_command` are masked anyway.
    assert_eq!(
        format_session_line(&msg(LogKind::Command, "PASS CANARY-PW-fmt"), utc),
        "2026-10-09 12:00:00 #3 Command: PASS ****\n"
    );
    assert_eq!(
        format_session_line(&msg(LogKind::ListingRaw, "a\r\nb"), utc),
        "2026-10-09 12:00:00 #3 Listing: a\n2026-10-09 12:00:00 #3 Listing: b\n"
    );
}

#[test]
fn session_log_file_records_the_bus_with_masked_commands() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.log");
    let file = SessionLogFile::open(path.clone(), 1, 2, UtcOffset::UTC).unwrap();
    let (tx, mut rx) = events::channel(4);
    let s = SessionId::next();
    tx.log(s, LogKind::Status, "Connecting to canary-host-1.example");
    tx.log_command(s, "USER bob");
    tx.log_command(s, "PASS CANARY-PW-session-1");
    tx.log_command(s, "ACCT CANARY-PW-acct");
    tx.log(s, LogKind::Response, "230 Logged in");
    while let Some(CoreEvent::Log(m)) = rx.try_recv() {
        file.record(&m);
    }
    assert!(file.flush_timeout(Duration::from_secs(10)));
    let text = read(&path);
    assert!(text.contains(&format!("{s} Command: USER bob\n")), "{text}");
    assert!(
        text.contains(&format!("{s} Command: PASS ****\n")),
        "{text}"
    );
    assert!(
        text.contains(&format!("{s} Command: ACCT ****\n")),
        "{text}"
    );
    assert!(!text.contains("CANARY-PW"), "{text}");
    assert_eq!(text.lines().count(), 5);
    assert_eq!(file.dropped(), 0);
}
