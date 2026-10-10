#!/usr/bin/env bash
# T22 AC16 (manual, not CI): SFTP throughput of courier-ftp's SftpBackend versus the
# OpenSSH `sftp` client (`-B 261120 -R 64`) against the T76 sshd `password` profile.
# Downloads and uploads a random file (default 1 GiB, COURIER_BENCH_MIB=<n> to change)
# 3 times each and prints the median MiB/s of each and the ratio.
#
# Needs Docker. Usage: scripts/bench-sftp.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export COURIER_E2E=1 COURIER_BENCH=1
cargo test --release -p courier-ftp-e2e --test sftp_backend bench_sftp_vs_openssh \
  -- --ignored --nocapture --test-threads=1 2>&1 | grep -E '^BENCH|skipped|panicked|test result'
