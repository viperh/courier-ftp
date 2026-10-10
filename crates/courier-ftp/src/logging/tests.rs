use std::time::Duration;

use super::*;

#[test]
fn filter_defaults_and_invalid_values() {
    let (f, warning) = filter(LogOptions::default(), None);
    assert_eq!(f.max_level_hint(), Some(LevelFilter::INFO));
    assert!(warning.is_none());

    let (f, _) = filter(LogOptions { debug: true }, None);
    assert_eq!(f.max_level_hint(), Some(LevelFilter::DEBUG));

    let (f, _) = filter(LogOptions::default(), Some("trace"));
    assert_eq!(f.max_level_hint(), Some(LevelFilter::TRACE));

    // A bad value never stops startup.
    let (f, warning) = filter(LogOptions::default(), Some("courier_ftp=nonsense[["));
    assert_eq!(f.max_level_hint(), Some(LevelFilter::INFO));
    assert!(warning.unwrap().contains(LOG_ENV));
}

#[test]
fn the_file_layer_writes_daily_files_in_the_scanner_format() {
    let dir = tempfile::tempdir().unwrap();
    let w = writer(dir.path()).unwrap();
    let (f, _) = filter(LogOptions::default(), Some("debug"));
    let subscriber = tracing_subscriber::registry()
        .with(f)
        .with(file_layer(w.clone()));
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(session = 3, "connected");
        tracing::debug!("details");
        tracing::trace!("not written");
    });
    assert!(w.flush_timeout(Duration::from_secs(10)));
    let files: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    assert!(
        files[0].starts_with("courier-ftp.") && files[0].ends_with(".log"),
        "{files:?}"
    );
    let text = std::fs::read_to_string(dir.path().join(&files[0])).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    // `<RFC 3339>  INFO <target>: …`, what scripts/canary-scan.sh parses.
    for line in &lines {
        let parts: Vec<&str> = line.split_whitespace().take(3).collect();
        let stamp = parts[0].as_bytes();
        assert!(
            stamp.len() > 11 && stamp[..4].iter().all(u8::is_ascii_digit) && stamp[10] == b'T',
            "{line}"
        );
        assert!(["INFO", "DEBUG"].contains(&parts[1]), "{line}");
        assert_eq!(parts[2], "courier_ftp::logging::tests:", "{line}");
    }
    assert!(lines[0].contains("connected session=3"), "{text}");
    assert!(!text.contains('\x1b'), "no colours");
}
