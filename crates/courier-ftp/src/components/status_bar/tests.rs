//! Unit and property tests of the status bar (T57).

use std::{net::SocketAddr, time::Duration};

use courier_ftp_core::{
    backend::SessionSecurityInfo,
    model::{FtpEncryption, Protocol, ServerAddress},
    settings::enums::TransferTypeChoice,
};
use pretty_assertions::assert_eq;
use proptest::prelude::*;
use tokio::time::Instant;

use super::*;
use crate::ui::{symbols::Symbols, text::width};

pub(super) fn hints() -> Vec<KeyHint> {
    [
        ("F1", "help"),
        ("F5", "copy"),
        ("F6", "move"),
        ("F7", "mkdir"),
        ("F8", "delete"),
        ("F10", "quit"),
    ]
    .into_iter()
    .map(|(k, l)| KeyHint {
        keys: k.into(),
        label: l.into(),
    })
    .collect()
}

/// State A: FTPS, limits on, filters, sync + compare, queue running.
pub(super) fn state_a<'a>(hints: &'a [KeyHint]) -> StatusInfo<'a> {
    StatusInfo {
        security: SecurityIndicator::Tls {
            version: "TLS 1.3".into(),
        },
        transfer_type: Some(TransferTypeChoice::Auto),
        speed: Some(SpeedLimitIndicator {
            enabled: true,
            down_kib: 500,
            up_kib: 100,
        }),
        filters_active: true,
        sync_browsing: true,
        comparison: true,
        queue: Some(QueueSummary {
            files: 12,
            bytes: 31_666_995,
            down_bps: 1_258_291,
            up_bps: 0,
            eta_secs: Some(25),
        }),
        hints,
        ..StatusInfo::default()
    }
}

/// State B: plain FTP, limits off, empty queue, `ctrl-x` pending.
pub(super) fn state_b<'a>(hints: &'a [KeyHint]) -> StatusInfo<'a> {
    StatusInfo {
        security: SecurityIndicator::Plain,
        transfer_type: Some(TransferTypeChoice::Binary),
        speed: Some(SpeedLimitIndicator {
            enabled: false,
            down_kib: 0,
            up_kib: 0,
        }),
        queue: Some(QueueSummary::default()),
        pending_keys: "ctrl-x",
        hints,
        ..StatusInfo::default()
    }
}

/// State C: vault locked, 2 prompts, a message.
pub(super) fn state_c<'a>(
    hints: &'a [KeyHint],
    msg: &'a TransientMessage,
    sym: &Symbols,
) -> StatusInfo<'a> {
    let w = if sym.unicode { "⚠" } else { "!" };
    StatusInfo {
        security: SecurityIndicator::NotConnected,
        vault: Some(VaultIndicator::Locked),
        prompts_badge: Some(format!("{w} 2 prompts")),
        transfer_type: Some(TransferTypeChoice::Auto),
        speed: Some(SpeedLimitIndicator {
            enabled: false,
            down_kib: 500,
            up_kib: 0,
        }),
        queue: Some(QueueSummary {
            files: 3,
            bytes: 1_299_227_607,
            down_bps: 8_808_038,
            up_bps: 0,
            eta_secs: Some(147),
        }),
        message: Some(msg),
        hints,
        ..StatusInfo::default()
    }
}

pub(super) fn message() -> TransientMessage {
    TransientMessage {
        text: "Copied URL to clipboard".into(),
        level: MessageLevel::Info,
        until: far_future(),
    }
}

fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

fn line(info: &StatusInfo, w: u16, sym: &Symbols) -> String {
    let segs = build_segments(info, sym);
    fit_segments(w, &segs, info.hints, sym).text(sym)
}

fn seg(kind: SegmentKind, long: &str, short: &str) -> Segment {
    Segment {
        kind,
        long: long.into(),
        short: short.into(),
        style: "status.bar",
    }
}

#[test]
fn fit_matches_mockups_state_a_b_c() {
    let h = hints();
    let msg = message();
    let u = Symbols::unicode();
    let a = Symbols::ascii();
    let cases: Vec<(StatusInfo, &Symbols, u16, &str)> = vec![
        (
            state_a(&h),
            &u,
            160,
            " 🔒 TLS 1.3 │ Type: Auto │ ⇅ ↓500 KiB/s ↑100 KiB/s │ ⚑ filters │ ⇄ sync ≠ compare │ Queue: 12 files, 30.2 MiB, ↓1.20 MiB/s, ~00:00:25          F1 help  F5 copy ",
        ),
        (
            state_a(&h),
            &u,
            80,
            " 🔒 TLS 1.3 │ Auto │ ⇅ ↓500 KiB/s ↑100 KiB/s │ ⚑ filters │ ⇄≠ │ Q: 12, 30.2 MiB ",
        ),
        (
            state_a(&h),
            &u,
            60,
            " 🔒 TLS 1.3 │ Auto │ ⇅↓500K↑100K │ ⚑ │ ⇄≠ │ Q: 12, 30.2 MiB ",
        ),
        (
            state_a(&h),
            &u,
            40,
            " 🔒TLS │ ⇅↓500K↑100K │ Q: 12, 30.2 MiB  ",
        ),
        (
            state_a(&h),
            &a,
            160,
            " [TLS 1.3] | Type: Auto | lim D:500K U:100K | [filters] | <> sync != compare | Queue: 12 files, 30.2 MiB, v1.20 MiB/s, ~00:00:25      F1 help  F5 copy  F6 move ",
        ),
        (
            state_a(&h),
            &a,
            80,
            " [TLS 1.3] | Auto | lim D:500K U:100K | [filters] | <>!= | Q: 12, 30.2 MiB      ",
        ),
        (
            state_a(&h),
            &a,
            40,
            " [TLS] | L:500K/100K | Q: 12, 30.2 MiB  ",
        ),
        (
            state_b(&h),
            &u,
            160,
            " 🔓 plain FTP │ Type: Binary │ ⇅ off │ Queue: empty                                           Ctrl-x │ F1 help  F5 copy  F6 move  F7 mkdir  F8 delete  F10 quit ",
        ),
        (
            state_b(&h),
            &u,
            80,
            " 🔓 plain FTP │ Type: Binary │ ⇅ off │ Queue: empty   Ctrl-x │ F1 help  F5 copy ",
        ),
        (
            state_b(&h),
            &u,
            40,
            " 🔓FTP │ Binary │ ⇅ off │ Q: 0   Ctrl-x ",
        ),
        (
            state_c(&h, &msg, &u),
            &u,
            160,
            " – not connected │ 🔐 vault locked │ ⚠ 2 prompts │ Type: Auto │ ⇅ off │ Queue: 3 files, 1.21 GiB, ↓8.40 MiB/s, ~00:02:27                Copied URL to clipboard ",
        ),
        (
            state_c(&h, &msg, &u),
            &u,
            80,
            " – │ 🔐 │ ⚠ 2 prompts │ Auto │ ⇅ off │ Q: 3, 1.21 GiB   Copied URL to clipboard ",
        ),
        (
            state_c(&h, &msg, &u),
            &u,
            40,
            " – │ 🔐 │ ⚠2    Copied URL to clipboard ",
        ),
    ];
    for (info, sym, w, want) in cases {
        let got = line(&info, w, sym);
        assert_eq!(got, want, "width {w}");
        assert_eq!(width(&got), usize::from(w));
    }
}

#[test]
fn security_segment_from_security_info() {
    let ftp = ServerAddress::new(
        Protocol::Ftp,
        FtpEncryption::ExplicitIfAvailable,
        "h",
        None,
        None,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let plain = SessionSecurityInfo {
        encrypted: false,
        summary: "plain".into(),
        ..SessionSecurityInfo::default()
    };
    let ind = SecurityIndicator::from_security_info(&plain, Some(&ftp));
    assert_eq!(ind, SecurityIndicator::Plain);
    let s = security_segment(&ind, &Symbols::unicode());
    assert_eq!(
        (s.long.as_str(), s.style),
        ("🔓 plain FTP", "status.insecure")
    );
    let tls = SessionSecurityInfo {
        encrypted: true,
        summary: "TLS 1.3".into(),
        ..SessionSecurityInfo::default()
    };
    let ind = SecurityIndicator::from_security_info(&tls, Some(&ftp));
    let s = security_segment(&ind, &Symbols::unicode());
    assert_eq!((s.long.as_str(), s.style), ("🔒 TLS 1.3", "status.secure"));
    let sftp = ServerAddress::new(Protocol::Sftp, FtpEncryption::default(), "h", None, None)
        .unwrap_or_else(|e| panic!("{e}"));
    let ssh = SessionSecurityInfo {
        encrypted: true,
        summary: "SSH".into(),
        ..SessionSecurityInfo::default()
    };
    assert_eq!(
        SecurityIndicator::from_security_info(&ssh, Some(&sftp)),
        SecurityIndicator::Ssh
    );
    let local = SessionSecurityInfo {
        summary: "local".into(),
        ..SessionSecurityInfo::default()
    };
    assert_eq!(
        SecurityIndicator::from_security_info(&local, None),
        SecurityIndicator::Local
    );
}

#[test]
fn security_indicator_plain_when_tls_not_negotiated() {
    // Configured "explicit TLS if available", but the server offered none: the
    // negotiated state wins.
    let addr = ServerAddress::new(
        Protocol::Ftp,
        FtpEncryption::ExplicitIfAvailable,
        "ftp.example.com",
        None,
        None,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let info = SessionSecurityInfo {
        encrypted: false,
        summary: "plain".into(),
        peer_addr: Some(SocketAddr::from(([203, 0, 113, 5], 21))),
        ..SessionSecurityInfo::default()
    };
    let ind = SecurityIndicator::from_security_info(&info, Some(&addr));
    assert_eq!(ind, SecurityIndicator::Plain);
    let a = security_segment(&ind, &Symbols::ascii());
    assert_eq!(
        (a.long.as_str(), a.short.as_str()),
        ("[PLAIN FTP]", "[FTP!]")
    );
    // The words survive every width.
    for w in [40, 60, 80] {
        let info = StatusInfo {
            security: ind.clone(),
            ..StatusInfo::default()
        };
        assert!(line(&info, w, &Symbols::unicode()).contains("plain FTP"));
    }
}

#[test]
fn prompts_segment_uses_badge_text() {
    let s = prompts_segment("⚠ 2 prompts");
    assert_eq!((s.long.as_str(), s.short.as_str()), ("⚠ 2 prompts", "⚠2"));
    let s = prompts_segment("! 2 prompts");
    assert_eq!(s.short, "!2");
    let info = StatusInfo::default();
    let segs = build_segments(&info, &Symbols::unicode());
    assert!(segs.iter().all(|s| s.kind != SegmentKind::Prompts));
}

#[test]
fn fit_drops_hints_first_then_shortens_by_priority() {
    let sym = Symbols::unicode();
    let h = hints();
    let segs = vec![
        seg(SegmentKind::Security, "SSSSSSSSSS", "S"),
        seg(SegmentKind::TransferType, "TTTTTTTTTT", "T"),
        seg(SegmentKind::Queue, "QQQQQQQQQQ", "Q"),
    ];
    // Long left = 10+3+10+3+10 = 36, + margins 38; hints need 2 + their width.
    let f = fit_segments(50, &segs, &h, &sym);
    assert!(f.left.iter().all(|s| !s.short));
    assert_eq!(f.hints.len(), 1, "{f:?}");
    // No room for hints at 38: none kept, nothing shortened.
    let f = fit_segments(38, &segs, &h, &sym);
    assert!(f.hints.is_empty());
    assert!(f.left.iter().all(|s| !s.short));
    // 29: the lowest priority (transfer type) is shortened first.
    let f = fit_segments(29, &segs, &h, &sym);
    let short: Vec<_> = f.left.iter().filter(|s| s.short).map(|s| s.kind).collect();
    assert_eq!(short, vec![SegmentKind::TransferType]);
    // 20: queue shortened too, security still long.
    let f = fit_segments(20, &segs, &h, &sym);
    let short: Vec<_> = f.left.iter().filter(|s| s.short).map(|s| s.kind).collect();
    assert_eq!(short, vec![SegmentKind::TransferType, SegmentKind::Queue]);
    // 8: everything short, then the lowest priorities dropped.
    let f = fit_segments(8, &segs, &h, &sym);
    let kinds: Vec<_> = f.left.iter().map(|s| s.kind).collect();
    assert_eq!(kinds, vec![SegmentKind::Security, SegmentKind::Queue]);
}

#[test]
fn fit_never_drops_priority_nine_or_more() {
    let sym = Symbols::unicode();
    let segs = vec![
        seg(SegmentKind::Security, "secure", "s"),
        seg(SegmentKind::Vault, "vault locked", "V"),
        seg(SegmentKind::Prompts, "2 prompts", "P2"),
        seg(SegmentKind::Queue, "queue", "q"),
        seg(SegmentKind::PendingKeys, "Ctrl-x", "Ctrl-x"),
        seg(
            SegmentKind::Message,
            "a long message here",
            "a long message here",
        ),
    ];
    for w in 0..60 {
        let f = fit_segments(w, &segs, &[], &sym);
        for k in [
            SegmentKind::Vault,
            SegmentKind::Prompts,
            SegmentKind::PendingKeys,
            SegmentKind::Message,
        ] {
            assert!(
                f.left.iter().chain(&f.right).any(|s| s.kind == k),
                "{k:?} dropped at {w}"
            );
        }
        assert!(width(&f.text(&sym)) <= usize::from(w));
    }
    // Narrow: the message is cut with the ellipsis.
    let f = fit_segments(20, &segs, &[], &sym);
    assert!(f.text(&sym).contains('…'), "{}", f.text(&sym));
}

#[test]
fn fit_reexpands_highest_priority_first() {
    let sym = Symbols::unicode();
    let forms = |f: &FittedBar| -> Vec<(SegmentKind, bool)> {
        f.left.iter().map(|s| (s.kind, s.short)).collect()
    };
    // Long: 8+3+4+3+15 (+2) = 35. At 21 the type (p2) and the queue (p7) are shortened
    // (18 columns), then the type fits long again.
    let segs = vec![
        seg(SegmentKind::Security, "SECURITY", "S"),
        seg(SegmentKind::TransferType, "TYPE", "T"),
        seg(SegmentKind::Queue, "QUEUEQUEUEQUEUE", "Q"),
    ];
    assert_eq!(
        forms(&fit_segments(21, &segs, &[], &sym)),
        vec![
            (SegmentKind::Security, false),
            (SegmentKind::TransferType, false),
            (SegmentKind::Queue, true),
        ]
    );
    // Everything short is still too wide at 14, so the type is dropped; of the two
    // segments that could grow back (5 columns each), only the one with the higher
    // priority (security) does.
    let segs = vec![
        seg(SegmentKind::Security, "SECURE", "S"),
        seg(SegmentKind::TransferType, "TTTTTTTTTT", "TTTTTTTTT"),
        seg(SegmentKind::Queue, "QUEUEQ", "Q"),
    ];
    let f = fit_segments(14, &segs, &[], &sym);
    assert_eq!(
        forms(&f),
        vec![(SegmentKind::Security, false), (SegmentKind::Queue, true)]
    );
    assert_eq!(f.text(&sym), " SECURE │ Q   ");
}

#[test]
fn speed_segment_formats_zero_as_unlimited() {
    let s = speed_segment(
        SpeedLimitIndicator {
            enabled: true,
            down_kib: 0,
            up_kib: 100,
        },
        &Symbols::unicode(),
    );
    assert_eq!(s.long, "⇅ ↓∞ ↑100 KiB/s");
    assert_eq!(s.short, "⇅↓∞↑100K");
    let a = speed_segment(
        SpeedLimitIndicator {
            enabled: true,
            down_kib: 0,
            up_kib: 100,
        },
        &Symbols::ascii(),
    );
    assert_eq!(
        (a.long.as_str(), a.short.as_str()),
        ("lim D:inf U:100K", "L:inf/100K")
    );
    let off = speed_segment(
        SpeedLimitIndicator {
            enabled: false,
            down_kib: 1,
            up_kib: 1,
        },
        &Symbols::ascii(),
    );
    assert_eq!(
        (off.long.as_str(), off.short.as_str()),
        ("lim off", "L:off")
    );
}

#[test]
fn queue_segment_omits_zero_rates_and_unknown_eta() {
    let u = Symbols::unicode();
    let q = QueueSummary {
        files: 1,
        bytes: 512,
        ..QueueSummary::default()
    };
    assert_eq!(queue_segment(q, &u).long, "Queue: 1 file, 512 B");
    let q = QueueSummary {
        files: 2,
        bytes: 2048,
        up_bps: 1024,
        eta_secs: Some(3661),
        ..QueueSummary::default()
    };
    assert_eq!(
        queue_segment(q, &u).long,
        "Queue: 2 files, 2.00 KiB, ↑1.00 KiB/s, ~01:01:01"
    );
    assert_eq!(queue_segment(q, &u).short, "Q: 2, 2.00 KiB");
    assert_eq!(
        queue_segment(QueueSummary::default(), &u).long,
        "Queue: empty"
    );
    assert_eq!(format_bytes(150 * 1024 * 1024), "150 MiB");
}

#[test]
fn message_expiry_by_level() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap_or_else(|e| panic!("{e}"));
    rt.block_on(async {
        for (level, secs) in [
            (MessageLevel::Info, 3),
            (MessageLevel::Success, 3),
            (MessageLevel::Warning, 5),
            (MessageLevel::Error, 8),
        ] {
            let mut bar = StatusBar::default();
            assert!(bar.update(&Action::StatusNotice(level, "x".into()), Instant::now()));
            tokio::time::advance(Duration::from_millis(secs * 1000 - 1)).await;
            assert!(!bar.update(&Action::Tick, Instant::now()), "{level:?}");
            assert!(bar.message().is_some());
            tokio::time::advance(Duration::from_millis(1)).await;
            assert!(bar.update(&Action::Tick, Instant::now()), "{level:?}");
            assert!(bar.message().is_none());
        }
    });
}

#[test]
fn info_message_cleared_by_key_after_one_second() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap_or_else(|e| panic!("{e}"));
    rt.block_on(async {
        let mut bar = StatusBar::default();
        bar.update(&Action::StatusMessage("hello".into()), Instant::now());
        tokio::time::advance(Duration::from_millis(500)).await;
        assert!(!bar.on_key(Instant::now()), "too young");
        tokio::time::advance(Duration::from_millis(500)).await;
        assert!(bar.on_key(Instant::now()));
        assert!(bar.message().is_none());
        // Warnings stay until they expire.
        bar.show("careful", MessageLevel::Warning, Instant::now());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!bar.on_key(Instant::now()));
        assert!(bar.message().is_some());
    });
}

#[test]
fn messages_are_sanitised_and_limited() {
    let now = Instant::now();
    let m = TransientMessage::new(
        &format!("a\x1b[2J{}", "x".repeat(300)),
        MessageLevel::Error,
        now,
    );
    assert!(m.text.starts_with("a^[[2J"));
    assert_eq!(m.text.chars().count(), MAX_MESSAGE_CHARS);
    assert!(message_segment(&m).long.starts_with("Error: a^[[2J"));
}

#[test]
fn pending_keys_title_cased() {
    assert_eq!(pending_segment("ctrl-x").long, "Ctrl-x");
    assert_eq!(pretty_keys("f10"), "F10");
    assert_eq!(pretty_keys("ctrl-x alt-k"), "Ctrl-x Alt-k");
}

fn arb_info() -> impl Strategy<Value = (u8, u8, bool, bool, bool, u8, u8, bool, u8)> {
    (
        0u8..6,
        0u8..3,
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        0u8..6,
        0u8..3,
        any::<bool>(),
        0u8..7,
    )
}

fn make_info<'a>(
    p: (u8, u8, bool, bool, bool, u8, u8, bool, u8),
    hints: &'a [KeyHint],
    msg: &'a TransientMessage,
    sym: &Symbols,
) -> StatusInfo<'a> {
    let (sec, vault, prompts, filters, compare, sync, speed, pending, nhints) = p;
    let security = match sec {
        0 => SecurityIndicator::NotConnected,
        1 => SecurityIndicator::Local,
        2 => SecurityIndicator::Plain,
        3 => SecurityIndicator::Tls {
            version: "TLS 1.2".into(),
        },
        4 => SecurityIndicator::Ssh,
        _ => SecurityIndicator::Connecting,
    };
    StatusInfo {
        security,
        vault: match vault {
            0 => None,
            1 => Some(VaultIndicator::Locked),
            _ => Some(VaultIndicator::NoVault),
        },
        prompts_badge: prompts.then(|| {
            if sym.unicode {
                "⚠ 3 prompts"
            } else {
                "! 3 prompts"
            }
            .into()
        }),
        transfer_type: Some(TransferTypeChoice::Ascii),
        speed: (speed > 0).then_some(SpeedLimitIndicator {
            enabled: speed == 2,
            down_kib: 1024,
            up_kib: 0,
        }),
        filters_active: filters,
        sync_browsing: compare,
        comparison: compare,
        sync: match sync {
            0 => None,
            1 => Some(SyncIndicator::Synced),
            2 => Some(SyncIndicator::Syncing),
            3 => Some(SyncIndicator::Offline { pending: 4 }),
            4 => Some(SyncIndicator::Error),
            _ => Some(SyncIndicator::LoginNeeded),
        },
        queue: Some(QueueSummary {
            files: 7,
            bytes: 123_456_789,
            down_bps: 1000,
            up_bps: 2000,
            eta_secs: Some(99),
        }),
        pending_keys: if pending { "ctrl-x" } else { "" },
        message: (nhints == 6).then_some(msg),
        hints: &hints[..usize::from(nhints.min(6))],
    }
}

proptest! {
    #[test]
    fn prop_fit_width_never_exceeded(p in arb_info(), w in 0u16..300, ascii in any::<bool>()) {
        let sym = if ascii { Symbols::ascii() } else { Symbols::unicode() };
        let h = hints();
        let msg = message();
        let info = make_info(p, &h, &msg, &sym);
        let segs = build_segments(&info, &sym);
        let f = fit_segments(w, &segs, info.hints, &sym);
        let text = f.text(&sym);
        prop_assert!(width(&text) <= usize::from(w), "{w}: {text:?}");
        for s in &segs {
            if s.kind.priority() >= 9 {
                prop_assert!(f.left.iter().chain(&f.right).any(|x| x.kind == s.kind));
            }
        }
    }

    #[test]
    fn prop_ascii_mode_renders_only_ascii(p in arb_info(), w in 0u16..200) {
        let sym = Symbols::ascii();
        let h = hints();
        let msg = message();
        let info = make_info(p, &h, &msg, &sym);
        let text = line(&info, w, &sym);
        prop_assert!(text.is_ascii(), "{text:?}");
    }
}
