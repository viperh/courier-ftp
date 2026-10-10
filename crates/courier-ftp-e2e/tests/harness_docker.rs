//! Harness tests that need Docker (`COURIER_E2E=1`, `-- --ignored`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use courier_ftp_e2e::require_docker;

/// The CI `e2e` job's Docker daemon answers. Server fixtures (vsftpd, ProFTPD,
/// Pure-FTPd, OpenSSH) and their scenarios are added by T14/T20/T22.
#[tokio::test]
#[ignore = "needs Docker: COURIER_E2E=1 cargo test -p courier-ftp-e2e -- --ignored"]
async fn docker_answers() {
    require_docker!();
    courier_ftp_e2e::ping_docker().await.unwrap();
}
