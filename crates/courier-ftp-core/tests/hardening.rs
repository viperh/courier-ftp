//! Process hardening on Linux (T30 AC14). Each test runs in this test binary's own
//! process, so lowering its limits affects nothing else.

#[cfg(target_os = "linux")]
#[test]
fn t01_process_not_dumpable() {
    let report = courier_ftp_core::hardening::harden_process();
    assert!(report.non_dumpable, "{report:?}");
    assert_eq!(courier_ftp_core::hardening::is_dumpable(), Some(false));
}

#[cfg(target_os = "linux")]
#[test]
fn t02_core_limit_zero() {
    let report = courier_ftp_core::hardening::harden_process();
    assert!(report.core_dumps_disabled, "{report:?}");
    assert_eq!(courier_ftp_core::hardening::core_dump_limit(), Some(0));
}
