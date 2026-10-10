#!/bin/bash
# Start the proxy of $PROXY_PROFILE (default http).
#
#   --list    print the profile names, one per line, and exit 0
#   --check   validate the profile's configuration and exit 0/1 without serving
set -euo pipefail

profiles=/etc/courier-proxy/profiles
list() { for f in "$profiles"/*.conf; do basename "$f" .conf; done; }

if [[ "${1:-}" == "--list" ]]; then
    list
    exit 0
fi

profile="${PROXY_PROFILE:-http}"
src="$profiles/${profile}.conf"
if [[ ! -f "$src" ]]; then
    echo "courier-proxy: unknown profile '${profile}'; profiles:" >&2
    list >&2
    exit 64
fi

case "$profile" in
    http*)
        cp "$src" /etc/squid/courier.conf
        if [[ "${1:-}" == "--check" ]]; then
            squid -k parse -f /etc/squid/courier.conf
            echo "courier-proxy: profile ${profile} ok" >&2
            exit 0
        fi
        echo "courier-proxy: profile ${profile} (squid :3128)" >&2
        exec squid -N -d 1 -f /etc/squid/courier.conf
        ;;
    socks*)
        cp "$src" /etc/danted.conf
        if [[ "${1:-}" == "--check" ]]; then
            danted -V -f /etc/danted.conf
            echo "courier-proxy: profile ${profile} ok" >&2
            exit 0
        fi
        echo "courier-proxy: profile ${profile} (dante :1080)" >&2
        exec danted -f /etc/danted.conf
        ;;
esac
