#!/usr/bin/env bash
# Fast-transfer benchmark (T41b; manual, not CI), Linux only.
#
# Runs everything inside a private network namespace (unprivileged user
# namespace, no root and no Docker needed) whose loopback gets an Ethernet
# MTU (1500; loopback's default 64 KiB packets make TCP receive-buffer
# autotuning stall now and then, which spoils multi-connection numbers),
# `tc netem` with DELAY_MS each way (50 ms round trip by default) and a
# RATE limit (1 Gbit/s), raises the namespace's TCP buffer limits to TCP_MEM bytes (a
# host tuned for a fast long link; Linux's default 4 MiB send buffer caps
# one connection at about 80 MiB/s at 50 ms), then starts there:
#   - an unprivileged OpenSSH server (as in scripts/bench-sftp.sh),
#   - pyftpdlib servers for plain FTP and explicit FTPS (multi-process),
# and measures, after a raw TCP baseline (1 and 4 connections: what the
# emulated link really delivers, as netem costs CPU per packet), through
# courier-ftp's transfer engine:
#   1. one SIZE_MIB file over SFTP, down and up, 1 vs 4 segments
#      (crates/courier-ftp-proto-sftp/tests/openssh_segmented.rs);
#   2. the same file over FTPS, down, 1 vs 4 segments
#      (crates/courier-ftp-proto-ftp/tests/ftp_bench.rs);
#   3. SMALL files of 4 KiB: SFTP upload and FTP download, 4 (default) and
#      2 (FileZilla's default) connections;
#   4. reference clients on the same link: the OpenSSH `sftp` CLI and lftp.
# Every copy is compared byte for byte; the client's CPU use per thread is
# printed. Record the results in tasks/41b-fast-transfers.md.
#
# Usage: scripts/bench-transfer.sh [SIZE_MIB] [SMALL]   (default 2048 10000)
# Env:   COURIER_BENCH_DELAY_MS (25), COURIER_BENCH_RATE (1gbit),
#        COURIER_BENCH_MTU (1500),
#        COURIER_BENCH_SEGMENTS (segment counts compared over SFTP; 1,4),
#        COURIER_BENCH_TCP_MEM (32 MiB; 0 keeps the system's limits),
#        COURIER_BENCH_WORK (scratch directory; default a new one in $TMPDIR,
#        which needs room for 2 x SIZE_MIB; a RAM disk keeps the local disk
#        out of the measurement),
#        PYTHON (an interpreter with pyftpdlib and pyOpenSSL; python3),
#        COURIER_BENCH_PARTS (which parts run: "tcp sftp ftps ftp cli lftp")
# Needs: unshare (util-linux), ip, tc (iproute2, netem), sshd, sftp,
#        ssh-keygen, openssl, lftp, awk; user namespaces enabled.
set -euo pipefail

SIZE_MIB="${1:-2048}"
SMALL="${2:-10000}"
DELAY_MS="${COURIER_BENCH_DELAY_MS:-25}"
RATE="${COURIER_BENCH_RATE:-1gbit}"
MTU="${COURIER_BENCH_MTU:-1500}"
TCP_MEM="${COURIER_BENCH_TCP_MEM:-33554432}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SELF="$ROOT/scripts/$(basename "$0")"
PYTHON="${PYTHON:-python3}"
PARTS=" ${COURIER_BENCH_PARTS:-tcp sftp ftps ftp cli lftp} "
part() { [[ "$PARTS" == *" $1 "* ]]; }

case "${COURIER_BENCH_STAGE:-}" in
"")
    # Build first: the namespace has no network.
    for t in "courier-ftp-proto-sftp openssh_segmented" "courier-ftp-proto-ftp ftp_bench"; do
        read -r pkg test <<<"$t"
        cargo test --release --manifest-path "$ROOT/Cargo.toml" -p "$pkg" --test "$test" --no-run
    done
    "$PYTHON" -c "import pyftpdlib, OpenSSL" || {
        echo "$PYTHON lacks pyftpdlib/pyOpenSSL (pip install pyftpdlib pyopenssl)" >&2
        exit 1
    }
    COURIER_BENCH_STAGE=net COURIER_BENCH_UID="$(id -u)" COURIER_BENCH_GID="$(id -g)" \
        exec unshare --user --map-root-user --net "$SELF" "$SIZE_MIB" "$SMALL"
    ;;
net)
    # Root of the new namespace only: shape the loopback, then drop back to
    # our own user id (sshd refuses privilege separation as a mapped root).
    ip link set lo up
    ip link set lo mtu "$MTU"
    tc qdisc add dev lo root netem delay "${DELAY_MS}ms" rate "$RATE" limit 100000
    if [ "$TCP_MEM" != 0 ]; then
        sysctl -q -w net.ipv4.tcp_rmem="4096 131072 $TCP_MEM" net.ipv4.tcp_wmem="4096 16384 $TCP_MEM"
    fi
    COURIER_BENCH_STAGE=run exec unshare --user \
        --map-user="$COURIER_BENCH_UID" --map-group="$COURIER_BENCH_GID" \
        "$SELF" "$SIZE_MIB" "$SMALL"
    ;;
run) ;;
*) echo "unknown stage" >&2; exit 1 ;;
esac

WORK="${COURIER_BENCH_WORK:-$(mktemp -d -t courier-bench.XXXXXX)}"
mkdir -p "$WORK"
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    kill "$(cat "$WORK/sshd.pid" 2>/dev/null)" 2>/dev/null || true
    [ -n "${COURIER_BENCH_WORK:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT

echo "== link: $(tc qdisc show dev lo | head -1)"
echo "== tcp_wmem: $(cat /proc/sys/net/ipv4/tcp_wmem); work: $WORK"
{ ping -c 3 -q 127.0.0.1 2>/dev/null | tail -1; } || true

# --- OpenSSH --------------------------------------------------------------
SSH_PORT=22022
SFTP_SERVER=""
for p in /usr/lib/ssh/sftp-server /usr/lib/openssh/sftp-server /usr/libexec/sftp-server /usr/libexec/openssh/sftp-server; do
    [ -x "$p" ] && SFTP_SERVER="$p" && break
done
[ -n "$SFTP_SERVER" ] || { echo "sftp-server not found" >&2; exit 1; }
ssh-keygen -q -t ed25519 -N '' -f "$WORK/host_key"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/client_key"
cp "$WORK/client_key.pub" "$WORK/authorized_keys"
chmod 600 "$WORK/authorized_keys"
mkdir -p "$WORK/sftp"
cat >"$WORK/sshd_config" <<EOF
Port $SSH_PORT
ListenAddress 127.0.0.1
HostKey $WORK/host_key
PidFile $WORK/sshd.pid
AuthorizedKeysFile $WORK/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
MaxStartups 64
MaxSessions 64
Subsystem sftp $SFTP_SERVER
EOF
"$(command -v sshd || echo /usr/sbin/sshd)" -f "$WORK/sshd_config" -E "$WORK/sshd.log"

# --- pyftpdlib ------------------------------------------------------------
FTP_PORT=2121
FTPS_PORT=2990
mkdir -p "$WORK/ftp"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=127.0.0.1 \
    -keyout "$WORK/ftp_key.pem" -out "$WORK/ftp_cert.pem" 2>/dev/null
cat >"$WORK/ftpd.py" <<'EOF'
import logging, sys
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.log import config_logging
from pyftpdlib.servers import MultiprocessFTPServer

config_logging(level=logging.WARNING)
port, root, tls = int(sys.argv[1]), sys.argv[2], sys.argv[3] == "1"
auth = DummyAuthorizer()
auth.add_user("bench", "bench-pw", root, perm="elradfmwMT")
handler = TLS_FTPHandler if tls else FTPHandler
if tls:
    handler.certfile, handler.keyfile = sys.argv[4], sys.argv[5]
    handler.tls_control_required = handler.tls_data_required = True
handler.authorizer = auth
handler.passive_ports = None
MultiprocessFTPServer.max_cons = 1024
MultiprocessFTPServer(("127.0.0.1", port), handler).serve_forever()
EOF
"$PYTHON" "$WORK/ftpd.py" "$FTP_PORT" "$WORK/ftp" 0 & PIDS+=($!)
"$PYTHON" "$WORK/ftpd.py" "$FTPS_PORT" "$WORK/ftp" 1 "$WORK/ftp_cert.pem" "$WORK/ftp_key.pem" & PIDS+=($!)
sleep 1

filter() { grep -E "courier|test result|panicked|files differ" || true; }

if part tcp; then
echo "== raw TCP baseline (no SSH, no FTP)"
"$PYTHON" - <<'EOF'
import socket, threading, time
N = 128 * 1024 * 1024
def serve(c):
    buf, sent = b"x" * (1 << 20), 0
    while sent < N:
        sent += c.send(buf)
    c.close()
for flows in (1, 4):
    l = socket.socket()
    l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    l.bind(("127.0.0.1", 0)); l.listen()
    def accept():
        for _ in range(flows):
            threading.Thread(target=serve, args=(l.accept()[0],), daemon=True).start()
    threading.Thread(target=accept, daemon=True).start()
    got = []
    def client():
        s, n = socket.create_connection(l.getsockname()), 0
        while d := s.recv(1 << 20):
            n += len(d)
        got.append(n)
    t = time.time()
    ts = [threading.Thread(target=client) for _ in range(flows)]
    for x in ts: x.start()
    for x in ts: x.join()
    print(f"raw TCP, {flows} connection(s): {sum(got) / 2**20 / (time.time() - t):.1f} MiB/s")
    l.close()
EOF
fi

if part sftp; then
echo "== courier SFTP: ${SIZE_MIB} MiB down/up, 1 vs 4 segments; ${SMALL} x 4 KiB up"
COURIER_BENCH_PORT="$SSH_PORT" COURIER_BENCH_USER="$(id -un)" \
COURIER_BENCH_KEY="$WORK/client_key" COURIER_BENCH_DIR="$WORK/sftp" \
COURIER_BENCH_SIZE_MIB="$SIZE_MIB" COURIER_BENCH_SMALL="$SMALL" \
    cargo test --offline --release --manifest-path "$ROOT/Cargo.toml" -p courier-ftp-proto-sftp \
    --test openssh_segmented -- --ignored --nocapture 2>&1 | filter
fi

ftp_bench() { # TLS SIZE SMALL PORT
    COURIER_BENCH_FTP_PORT="$4" COURIER_BENCH_FTP_USER=bench COURIER_BENCH_FTP_PASSWORD=bench-pw \
    COURIER_BENCH_FTP_DIR="$WORK/ftp" COURIER_BENCH_FTP_TLS="$1" \
    COURIER_BENCH_SIZE_MIB="$2" COURIER_BENCH_SMALL="$3" \
        cargo test --offline --release --manifest-path "$ROOT/Cargo.toml" -p courier-ftp-proto-ftp \
        --test ftp_bench -- --ignored --nocapture 2>&1 | filter
}
if part ftps; then
    echo "== courier FTPS: ${SIZE_MIB} MiB down, 1 vs 4 segments"
    ftp_bench 1 "$SIZE_MIB" 0 "$FTPS_PORT"
fi
if part ftp; then
    echo "== courier FTP: ${SMALL} x 4 KiB down"
    ftp_bench 0 0 "$SMALL" "$FTP_PORT"
fi

# --- reference clients ----------------------------------------------------
now() { date +%s.%N; }
since() { awk -v s="$1" -v e="$(now)" 'BEGIN { printf "%.2f", e - s }'; }
rate() { awk -v m="$1" -v t="$2" 'BEGIN { printf "%.1f", m / t }'; }
SFTP=(sftp -F /dev/null -q -i "$WORK/client_key" -P "$SSH_PORT" -o StrictHostKeyChecking=no
      -o UserKnownHostsFile=/dev/null -o BatchMode=yes "$(id -un)@127.0.0.1")

mkdir -p "$WORK/small"
for i in $(seq 1 "$SMALL"); do head -c 4096 /dev/urandom >"$WORK/small/f$i"; done
if part cli; then
echo "== OpenSSH sftp CLI (one connection)"
head -c "$((SIZE_MIB * 1024 * 1024))" /dev/urandom >"$WORK/sftp/cli.bin"
s=$(now); "${SFTP[@]}" <<<"get $WORK/sftp/cli.bin $WORK/cli_down.bin" >/dev/null; t=$(since "$s")
echo "sftp CLI download: ${SIZE_MIB} MiB in ${t} s = $(rate "$SIZE_MIB" "$t") MiB/s"
rm -f "$WORK/sftp/cli.bin" "$WORK/cli_down.bin"
mkdir -p "$WORK/sftp/cli-small"
if [ "$SMALL" -gt 0 ]; then
    s=$(now); "${SFTP[@]}" <<<"put $WORK/small/* $WORK/sftp/cli-small/" >/dev/null; t=$(since "$s")
    echo "sftp CLI upload of ${SMALL} x 4 KiB: ${t} s = $(awk -v n="$SMALL" -v t="$t" 'BEGIN { printf "%.0f", n / t }') files/s"
fi
fi

if part lftp && [ "$SMALL" -gt 0 ]; then
echo "== lftp (FTP)"
cp -r "$WORK/small" "$WORK/ftp/small"
for p in 1 2 4; do
    rm -rf "$WORK/lftp-$p"
    s=$(now)
    lftp -u bench,bench-pw -e "set ftp:ssl-allow no; mirror --parallel=$p /small $WORK/lftp-$p; quit" \
        "ftp://127.0.0.1:$FTP_PORT" >/dev/null
    t=$(since "$s")
    echo "lftp mirror --parallel=$p of ${SMALL} x 4 KiB: ${t} s = $(awk -v n="$SMALL" -v t="$t" 'BEGIN { printf "%.0f", n / t }') files/s"
done
fi
