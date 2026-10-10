//! PTY test of the file list pane (T53) against the real binary: the local pane
//! lists the working directory (the test home), sorts and shows hidden files.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{Duration, SystemTime};

use courier_ftp_e2e::{PtyApp, PtyOptions, Screen, TestHome};

fn row_of(s: &Screen, needle: &str) -> Option<usize> {
    s.rows.iter().position(|r| r.contains(needle))
}

/// T53 AC13: browse the start directory, `s m` sorts by modification time, `.` shows
/// hidden files.
#[test]
fn browse_local_dir_and_sort() {
    let home = TestHome::new().unwrap();
    let now = SystemTime::now();
    for (name, age_days) in [("alpha.txt", 1), ("zeta.txt", 30), (".secret", 2)] {
        let path = home.path().join(name);
        std::fs::write(&path, name).unwrap();
        let f = std::fs::File::options().write(true).open(&path).unwrap();
        f.set_modified(now - Duration::from_secs(age_days * 86_400))
            .unwrap();
    }
    std::fs::create_dir(home.path().join("subdir")).unwrap();
    let mut app = PtyApp::launch(&home, PtyOptions::no_vault()).unwrap();
    let s = app.wait_for_text("zeta.txt").unwrap();
    assert!(!s.contains(".secret"), "hidden files are hidden by default");
    assert!(
        row_of(&s, "alpha.txt") < row_of(&s, "zeta.txt"),
        "name order"
    );
    assert!(
        row_of(&s, "subdir/") < row_of(&s, "alpha.txt"),
        "directories first"
    );

    // `s m`: oldest first.
    app.send_keys("s").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    app.send_keys("m").unwrap();
    app.wait_for_screen("sorted by modification time", |s| {
        s.contains("Modified ▲") && row_of(s, "zeta.txt") < row_of(s, "alpha.txt")
    })
    .unwrap();

    // `.` shows hidden files.
    app.send_keys(".").unwrap();
    app.wait_for_text(".secret").unwrap();

    // Into the directory and back.
    // Quick filter to the directory, then enter it.
    app.send_keys("/").unwrap();
    app.send_text("subdir").unwrap();
    app.send_keys("enter").unwrap();
    app.wait_for_screen("the filter", |s| !s.contains("zeta.txt"))
        .unwrap();
    app.send_keys("j").unwrap();
    app.send_keys("enter").unwrap();
    app.wait_for_text("Empty directory.").unwrap();
    app.send_keys("backspace").unwrap();
    app.wait_for_text("zeta.txt").unwrap();

    app.send_keys("ctrl-q").unwrap();
    assert!(app.wait_exit().unwrap().success());
}
