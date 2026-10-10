#!/usr/bin/env bash
# SFTP throughput benchmark (T22, manual, not CI).
#
# Starts a private, unprivileged OpenSSH server on 127.0.0.1 (no root, no
# changes outside a temp directory), then:
#   1. runs the backend conformance suite and a timed upload/download of
#      SIZE_MIB MiB with courier-ftp's SFTP backend
#      (crates/courier-ftp-proto-sftp/tests/openssh_bench.rs);
#   2. times the same transfers with the OpenSSH `sftp` CLI.
# Target: courier >= 80 % of the CLI's throughput.
#
# Usage: scripts/bench-sftp.sh [SIZE_MIB]   (default 1024)
# Needs: sshd, sftp, ssh-keygen, awk on PATH (sftp-server found next to sshd).
set -euo pipefail

SIZE_MIB="${1:-1024}"
PORT="${COURIER_BENCH_PORT:-22022}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'kill "$(cat "$WORK/sshd.pid" 2>/dev/null)" 2>/dev/null || true; rm -rf "$WORK"' EXIT

SSHD="$(command -v sshd || echo /usr/sbin/sshd)"
SFTP_SERVER=""
for p in /usr/lib/ssh/sftp-server /usr/lib/openssh/sftp-server /usr/libexec/sftp-server /usr/libexec/openssh/sftp-server; do
    [ -x "$p" ] && SFTP_SERVER="$p" && break
done
[ -n "$SFTP_SERVER" ] || { echo "sftp-server not found" >&2; exit 1; }

ssh-keygen -q -t ed25519 -N '' -f "$WORK/host_key"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/client_key"
cp "$WORK/client_key.pub" "$WORK/authorized_keys"
chmod 600 "$WORK/authorized_keys"
mkdir -p "$WORK/remote"

cat >"$WORK/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $WORK/host_key
PidFile $WORK/sshd.pid
AuthorizedKeysFile $WORK/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
Subsystem sftp $SFTP_SERVER
EOF

"$SSHD" -f "$WORK/sshd_config" -E "$WORK/sshd.log"
sleep 0.5

echo "== courier-ftp (conformance + ${SIZE_MIB} MiB)"
COURIER_BENCH_PORT="$PORT" COURIER_BENCH_USER="$(id -un)" \
COURIER_BENCH_KEY="$WORK/client_key" COURIER_BENCH_DIR="$WORK/remote" \
COURIER_BENCH_SIZE_MIB="$SIZE_MIB" \
    cargo test --release --manifest-path "$ROOT/Cargo.toml" -p courier-ftp-proto-sftp \
    --test openssh_bench -- --ignored --nocapture 2>&1 | grep -E "courier|conformance|test result|panicked"

echo "== OpenSSH sftp CLI (${SIZE_MIB} MiB)"
head -c "$((SIZE_MIB * 1024 * 1024))" /dev/zero | tr '\0' 'Z' >"$WORK/local.bin"
SFTP=(sftp -q -i "$WORK/client_key" -P "$PORT" -o StrictHostKeyChecking=no
      -o UserKnownHostsFile=/dev/null -o BatchMode=yes "$(id -un)@127.0.0.1")
now() { date +%s.%N; }
s=$(now); "${SFTP[@]}" <<<"put $WORK/local.bin $WORK/remote/cli.bin" >/dev/null; e=$(now)
up=$(awk -v s="$s" -v e="$e" 'BEGIN { printf "%.2f", e - s }')
s=$(now); "${SFTP[@]}" <<<"get $WORK/remote/cli.bin $WORK/cli_down.bin" >/dev/null; e=$(now)
down=$(awk -v s="$s" -v e="$e" 'BEGIN { printf "%.2f", e - s }')
rate() { awk -v m="$SIZE_MIB" -v t="$1" 'BEGIN { printf "%.1f", m / t }'; }
echo "sftp CLI upload: ${SIZE_MIB} MiB in ${up} s = $(rate "$up") MiB/s"
echo "sftp CLI download: ${SIZE_MIB} MiB in ${down} s = $(rate "$down") MiB/s"
