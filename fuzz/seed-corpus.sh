#!/usr/bin/env bash
# Seed each fuzz target's corpus from the test fixtures (T00/T91). fuzz.yml runs it
# before `cargo fuzz run`. Files already in the corpus (restored from earlier runs)
# are kept.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
corpus="$root/fuzz/corpus"

# listing (T13): every fixture listing, prefixed by the two offset bytes the
# target reads first (zero offset).
mkdir -p "$corpus/listing"
for file in "$root"/crates/courier-ftp-proto-ftp/tests/listings/*.txt; do
    { printf '\0\0'; cat "$file"; } >"$corpus/listing/seed-$(basename "$file")"
done

# envelope_open (T80): the frozen v1 envelope fixtures.
mkdir -p "$corpus/envelope_open"
for file in "$root"/crates/courier-ftp-crypto/tests/fixtures/envelopes/v1/*.bin; do
    cp "$file" "$corpus/envelope_open/seed-$(basename "$file")"
done

# key_parse (T20): every private key fixture (OpenSSH, PEM, PKCS#8, PPK v2/v3).
mkdir -p "$corpus/key_parse"
for file in "$root"/crates/courier-ftp-proto-sftp/tests/keys/* "$root"/crates/courier-ftp-proto-sftp/tests/keys/ppk/*; do
    case "$file" in
        *.pub | *.py | *.txt) continue ;;
    esac
    if [[ -f "$file" ]]; then cp "$file" "$corpus/key_parse/seed-$(basename "$file")"; fi
done

# known_hosts_parse (T21): the public key fixtures as known_hosts lines.
mkdir -p "$corpus/known_hosts_parse"
for file in "$root"/crates/courier-ftp-proto-sftp/tests/keys/*.pub; do
    { printf 'host.example,[host.example]:2222 '; cat "$file"; } \
        >"$corpus/known_hosts_parse/seed-$(basename "$file")"
done

# proxy_reply (T07): one answer per handshake (first byte: kind and read size).
mkdir -p "$corpus/proxy_reply"
printf '\000HTTP/1.1 200 Connection established\r\n\r\nSSH-2.0-x\r\n' >"$corpus/proxy_reply/seed-http-200"
printf '\200HTTP/1.0 407 Proxy Authentication Required\r\n\r\n' >"$corpus/proxy_reply/seed-http-407"
printf '\001\000\132\000\000\000\000\000\000' >"$corpus/proxy_reply/seed-socks4"
printf '\002\005\000\005\000\000\001\177\000\000\001\000\026' >"$corpus/proxy_reply/seed-socks5"
printf '\003\005\002\001\000\005\000\000\001\177\000\000\001\000\026' >"$corpus/proxy_reply/seed-socks5-auth"

echo "seeded $(find "$corpus" -type f | wc -l) corpus files"
