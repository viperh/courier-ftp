#!/usr/bin/env bash
# Build the seed corpus of every fuzz target in fuzz/corpus/<target>/ from the
# repository's test fixtures plus a few hand-written inputs (sources per target:
# tasks/91-security-hardening.md §7). Idempotent; existing corpus entries (found by
# earlier runs) are kept. Targets without `fuzz/fuzz_targets/<target>.rs` are skipped,
# so the list below can name every planned target.
#
#   fuzz/seed-corpus.sh [corpus-dir]      # default: fuzz/corpus
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ $# -gt 1 || "${1:-}" == -* ]]; then
  sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
fi
OUT="${1:-$ROOT/fuzz/corpus}"

has_target() { [[ -f "$ROOT/fuzz/fuzz_targets/$1.rs" ]]; }

seed_files() { # <target> <files...>
  local target="$1"; shift
  has_target "$target" || return 0
  mkdir -p "$OUT/$target"
  local f
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    cp -f "$f" "$OUT/$target/fixture-$(basename "$(dirname "$f")")-$(basename "$f")"
  done
}

seed_bytes() { # <target> <name> <printf-format>
  has_target "$1" || return 0
  mkdir -p "$OUT/$1"
  # shellcheck disable=SC2059
  printf "$3" > "$OUT/$1/$2"
}

shopt -s nullglob globstar

# Fixture-based seeds.
seed_files envelope_open "$ROOT"/crates/courier-ftp-crypto/tests/fixtures/envelopes/*/*
seed_files device_blob_open "$ROOT"/crates/courier-ftp-crypto/tests/fixtures/device_blobs/*
seed_files bundle_open "$ROOT"/crates/courier-ftp-crypto/tests/fixtures/bundles/*
seed_files grant_open "$ROOT"/crates/courier-ftp-crypto/tests/fixtures/grants/*
seed_files ppk_parse "$ROOT"/tests/fixtures/sshd/keys/*.ppk "$ROOT"/crates/courier-ftp-proto-sftp/tests/fixtures/keys/*.ppk
seed_files known_hosts_parse "$ROOT"/tests/fixtures/known_hosts/*
seed_listing() { # <dir> <selector byte (octal)> : prefix each fixture with fuzz_listing's selector byte
  has_target ftp_listing || return 0
  mkdir -p "$OUT/ftp_listing"
  local f
  for f in "$1"/*.txt; do
    { printf "\\$2"; cat "$f"; } > "$OUT/ftp_listing/fixture-$(basename "$1")-$(basename "$f")"
  done
}
# fuzz_listing: selector bit 0 = LIST (1) / MLSD (0); 0o001 = LIST without a hint.
seed_listing "$ROOT"/crates/courier-ftp-proto-ftp/tests/listings/mlsd 000
for d in dos eplf vms mvs ibmi mixed; do
  seed_listing "$ROOT/crates/courier-ftp-proto-ftp/tests/listings/$d" 001
done
seed_listing "$ROOT"/crates/courier-ftp-core/tests/listings/unix 001
seed_files backup_decrypt "$ROOT"/crates/courier-ftp-core/tests/fixtures/backups/*
seed_files tls_cert_details "$ROOT"/tests/fixtures/tls/*.der
seed_files filezilla_xml_import "$ROOT"/crates/courier-ftp-core/tests/fixtures/filezilla/*.xml
seed_files queue_import_json "$ROOT"/crates/courier-ftp-core/tests/fixtures/queue/*.json
seed_files sync_dto_decode "$ROOT"/crates/courier-ftp-proto/tests/fixtures/dto/*

# FTP control replies: single line, multi-line, and odd spacing.
seed_bytes ftp_reply single '220 Welcome\r\n'
seed_bytes ftp_reply multi '230-Hello\r\n there\r\n230 Logged in\r\n'
seed_bytes ftp_reply lf-only '211-Features:\n MLST type*;size*;modify*;\n UTF8\n211 End\n'

# PASV / EPSV answers.
seed_bytes ftp_pasv pasv '227 Entering Passive Mode (192,168,1,2,195,80)\r\n'
seed_bytes ftp_pasv pasv-bare '227 =192,168,1,2,4,1\r\n'
seed_bytes ftp_pasv epsv '229 Entering Extended Passive Mode (|||50000|)\r\n'

# HTTP CONNECT answers.
seed_bytes http_connect_response ok 'HTTP/1.1 200 Connection established\r\n\r\n220 FTP ready\r\n'
seed_bytes http_connect_response auth 'HTTP/1.0 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="x"\r\n\r\n'
seed_bytes http_connect_response error 'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n'

# SOCKS server replies: v5 method choice, v5 success (IPv4 / domain), v4 granted.
seed_bytes socks_reply method5 '\x05\x00'
seed_bytes socks_reply ok5-ipv4 '\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x15'
seed_bytes socks_reply ok5-domain '\x05\x00\x00\x03\x0bexample.com\x00\x15'
seed_bytes socks_reply ok4 '\x00\x5a\x00\x15\x7f\x00\x00\x01'

# Remote names to sanitize.
seed_bytes remote_name_sanitize plain 'report.txt'
seed_bytes remote_name_sanitize traversal '../../etc/passwd'
seed_bytes remote_name_sanitize reserved 'CON.txt'
seed_bytes remote_name_sanitize control 'a\x00b\x1fc'

# URLs (rows of T02's url_parse_table).
seed_bytes url_parse ftp 'ftp://user@example.com:21/pub'
seed_bytes url_parse sftp 'sftp://example.com/home/u'
seed_bytes url_parse ftps 'ftps://[2001:db8::1]:990/'
seed_bytes url_parse bare 'example.com'

# Envelopes, bundles, grants, blobs: version bytes and empty input.
for t in envelope_open device_blob_open bundle_open grant_open; do
  seed_bytes "$t" empty ''
  seed_bytes "$t" v1 '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
done

mkdir -p "$OUT"
for d in "$OUT"/*/; do
  echo "$(basename "$d"): $(find "$d" -type f | wc -l) seeds"
done
echo "seed corpus ready in $OUT"
