#!/bin/bash
# Start sshd with the profile named by $SSHD_PROFILE (default: password).
#
#   --list    print the profile names, one per line, and exit 0
#   --check   set the profile up, run `sshd -t`, exit 0/1 without serving
#
# Host keys are generated on the first start only (a restart keeps them;
# `courier-regen-hostkeys` replaces them). The `maxconn1` profile also starts
# `conn-limit-proxy` on :22 in front of sshd on 127.0.0.1:2222.
set -euo pipefail

profiles=/etc/ssh/courier/profiles
list() { for f in "$profiles"/*.conf; do basename "$f" .conf; done; }

if [[ "${1:-}" == "--list" ]]; then
    list
    exit 0
fi

profile="${SSHD_PROFILE:-password}"
src="$profiles/${profile}.conf"
if [[ ! -f "$src" ]]; then
    echo "courier-sshd: unknown profile '${profile}'; profiles:" >&2
    list >&2
    exit 64
fi
cp "$src" /etc/ssh/courier-profile.conf
echo "$profile" > /etc/ssh/courier/active-profile
mkdir -p /run/sshd
ssh-keygen -A >&2

if [[ "${1:-}" == "--check" ]]; then
    /usr/sbin/sshd -t
    echo "courier-sshd: profile ${profile} ok" >&2
    exit 0
fi

if [[ "$profile" == "maxconn1" ]]; then
    /usr/local/bin/conn-limit-proxy 0.0.0.0 22 127.0.0.1 2222 &
fi

echo "courier-sshd: profile ${profile}" >&2
/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
