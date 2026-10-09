//! Log canary (AC12): the auth scenarios run with a `trace` subscriber writing
//! into a buffer; no token, password, email, OPAQUE message, TOTP secret or code,
//! or recovery code the clients used may appear in it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::scenarios::{
    t01_register_login_refresh_logout, t10_totp_enable_login_replay_disable, t11_password_change,
    t15_recovery_flow,
};
use common::{Harness, LogCapture};

async fn run_all(h: &Harness) {
    t01_register_login_refresh_logout(h).await;
    t10_totp_enable_login_replay_disable(h).await;
    t11_password_change(h).await;
    t15_recovery_flow(h).await;
}

fn check(h: &Harness, logs: &str) {
    assert!(logs.contains("login"), "the subscriber captured nothing: {logs}");
    assert!(logs.contains("TRACE") || logs.contains("DEBUG"), "not at trace level");
    let canaries = h.canaries.lock().unwrap();
    assert!(canaries.len() > 50, "too few canaries: {}", canaries.len());
    for c in canaries.iter() {
        assert!(!logs.contains(c.as_str()), "logged secret value: {c}");
    }
    assert!(!logs.contains("@example.test"), "an email was logged");
}

#[tokio::test]
async fn canary_never_logged() {
    let logs = LogCapture::default();
    let guard = logs.install();
    let h = Harness::mem();
    run_all(&h).await;
    if let Some(pg) = Harness::pg().await {
        run_all(&pg).await;
        drop(guard);
        let text = logs.text();
        check(&h, &text);
        check(&pg, &text);
    } else {
        drop(guard);
        check(&h, &logs.text());
    }
}
