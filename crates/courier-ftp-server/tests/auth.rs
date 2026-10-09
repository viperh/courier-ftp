//! Accounts, login, tokens, devices, TOTP, password change, recovery and
//! account deletion over HTTP with the real client-side OPAQUE code.
//!
//! Every scenario (`common::scenarios`) runs twice: `*_mem` against the
//! in-memory store and `*_pg` against PostgreSQL (`DATABASE_URL`; skipped
//! without it, failing when `CI=true`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use common::scenarios::*;
use courier_ftp_server::middleware::rate_limit::RateLimiters;

both!(
    t01_register_login_refresh_logout,
    t01_register_login_refresh_logout_mem,
    t01_register_login_refresh_logout_pg
);
both!(
    t02_unknown_email_indistinguishable,
    t02_unknown_email_indistinguishable_mem,
    t02_unknown_email_indistinguishable_pg
);
both!(
    t03_register_is_atomic,
    t03_register_is_atomic_mem,
    t03_register_is_atomic_pg
);
both!(
    t04_registration_modes_and_invites,
    t04_registration_modes_and_invites_mem,
    t04_registration_modes_and_invites_pg
);
both!(
    t05_access_token_expiry,
    t05_access_token_expiry_mem,
    t05_access_token_expiry_pg
);
both!(
    t06_refresh_rotation,
    t06_refresh_rotation_mem,
    t06_refresh_rotation_pg
);
both!(
    t07_refresh_reuse_revokes_family,
    t07_refresh_reuse_revokes_family_mem,
    t07_refresh_reuse_revokes_family_pg
);
both!(
    t08_logout_revokes_device,
    t08_logout_revokes_device_mem,
    t08_logout_revokes_device_pg
);
both!(
    t09_devices_list_and_revoke,
    t09_devices_list_and_revoke_mem,
    t09_devices_list_and_revoke_pg
);
both!(
    t10_totp_enable_login_replay_disable,
    t10_totp_enable_login_replay_disable_mem,
    t10_totp_enable_login_replay_disable_pg
);
both!(
    t11_password_change,
    t11_password_change_mem,
    t11_password_change_pg
);
both!(
    t12_tokens_stored_hashed,
    t12_tokens_stored_hashed_mem,
    t12_tokens_stored_hashed_pg
);
both!(
    t13_disabled_account_rejected,
    t13_disabled_account_rejected_mem,
    t13_disabled_account_rejected_pg
);
both!(
    t14_delete_account_removes_everything,
    t14_delete_account_removes_everything_mem,
    t14_delete_account_removes_everything_pg
);
both!(
    t15_recovery_flow,
    t15_recovery_flow_mem,
    t15_recovery_flow_pg
);
both!(
    t16_login_state_ttl_and_single_use,
    t16_login_state_ttl_and_single_use_mem,
    t16_login_state_ttl_and_single_use_pg
);

// The rate-limit scenario needs the production quotas.
#[tokio::test]
async fn t17_rate_limits_email_and_ip_mem() {
    let h = common::Harness::mem_with(RateLimiters::default());
    t17_rate_limits_email_and_ip(&h).await;
}

#[tokio::test]
async fn t17_rate_limits_email_and_ip_pg() {
    let Some(h) = common::Harness::pg_with(RateLimiters::default()).await else {
        return;
    };
    t17_rate_limits_email_and_ip(&h).await;
}
