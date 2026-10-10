#!/bin/bash
# Start the FTP server of $FTPD_PROFILE (default vsftpd-plain) under a supervisor loop.
#
#   --list    print the profile names, one per line, and exit 0
#   --check   set the profile up, start the daemon, check that the control port
#             answers, stop it, exit 0/1 (nothing keeps serving)
#
# Env: FTPD_PROFILE, FTPD_CERT (ca-signed|self-signed|expired|wrong-host, default
# ca-signed), FTPD_PASV_ADDRESS (default: the container IP).
# `courier-set-cert <variant>` replaces the certificate and restarts the daemon in
# place (same container, same IP).
set -euo pipefail

profiles=/etc/courier-ftpd/profiles
list() { for f in "$profiles"/*.conf; do basename "$f" .conf; done; }

if [[ "${1:-}" == "--list" ]]; then
    list
    exit 0
fi

profile="${FTPD_PROFILE:-vsftpd-plain}"
src="$profiles/${profile}.conf"
if [[ ! -f "$src" ]]; then
    echo "courier-ftpd: unknown profile '${profile}'; profiles:" >&2
    list >&2
    exit 64
fi
echo "$profile" > /etc/courier-ftpd/active-profile

ip="$(hostname -i | awk '{print $1}')"
pasv="${FTPD_PASV_ADDRESS:-$ip}"
echo "$pasv" > /etc/courier-ftpd/pasv-address
port=21

# The certificate (every profile has one; plain servers simply do not use it).
courier-set-cert --no-restart "${FTPD_CERT:-ca-signed}"

case "$profile" in
    vsftpd-*)
        # Profile first, then the base; keep the first occurrence of every key.
        { grep -v '^\s*#' "$src"; echo "pasv_address=$pasv"; grep -v '^\s*#' /etc/courier-ftpd/base/vsftpd.conf; } \
            | awk -F= 'NF >= 2 && !seen[$1]++' > /etc/courier-ftpd/vsftpd.conf
        port="$(awk -F= '$1 == "listen_port" {print $2}' /etc/courier-ftpd/vsftpd.conf)"
        touch /var/log/vsftpd.log /var/log/vsftpd-xfer.log
        cmd=(vsftpd /etc/courier-ftpd/vsftpd.conf)
        ;;
    proftpd-*)
        {
            cat /etc/courier-ftpd/base/proftpd.conf
            if [[ "$pasv" != "$ip" ]]; then echo "MasqueradeAddress $pasv"; fi
            cat "$src"
        } > /etc/courier-ftpd/proftpd.conf
        proftpd -t -c /etc/courier-ftpd/proftpd.conf >&2
        touch /var/log/proftpd.log /var/log/proftpd-tls.log
        cmd=(proftpd --nodaemon -c /etc/courier-ftpd/proftpd.conf)
        ;;
    pureftpd-*)
        mapfile -t flags < <(grep -v '^\s*#' "$src" | grep -v '^\s*$')
        cat /etc/courier-ftpd/tls/key.pem /etc/courier-ftpd/tls/cert.pem > /etc/ssl/private/pure-ftpd.pem
        chmod 0600 /etc/ssl/private/pure-ftpd.pem
        cmd=(pure-ftpd --login unix --chrooteveryone --noanonymous --dontresolve
             --passiveportrange 30000:30019 --forcepassiveip "$pasv"
             --maxclientsnumber 50 --maxclientsperip 20 "${flags[@]}")
        ;;
esac
printf '%s\n' "${cmd[@]}" > /etc/courier-ftpd/command

if [[ "${1:-}" == "--check" ]]; then
    "${cmd[@]}" >&2 &
    pid=$!
    ok=1
    if python3 - "$port" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            sys.exit(0)
    except OSError:
        time.sleep(0.2)
sys.exit(1)
PY
    then ok=0; fi
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    if [[ $ok -eq 0 ]]; then
        echo "courier-ftpd: profile ${profile} ok (port ${port})" >&2
    else
        echo "courier-ftpd: profile ${profile}: nothing listens on port ${port}" >&2
    fi
    exit $ok
fi

# Server logs to the container log.
tail -q -F /var/log/vsftpd.log /var/log/proftpd.log /var/log/proftpd-tls.log 2>/dev/null >&2 &

echo "courier-ftpd: profile ${profile}, ip ${ip}, pasv ${pasv}, port ${port}" >&2
# Supervisor: restart the daemon whenever it exits (courier-set-cert kills it).
while true; do
    "${cmd[@]}" &
    echo $! > /run/courier-ftpd.pid
    wait "$(cat /run/courier-ftpd.pid)" || true
    echo "courier-ftpd: daemon exited; restarting" >&2
done
