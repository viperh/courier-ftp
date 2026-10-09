#!/usr/bin/env bash
#
# Canary scan (T00, T91; adapted from sverb). Test fixtures plant canary values (see
# CONTRIBUTING.md, "Canary secrets"):
#   CANARY-PW-…, CANARY-PASS-…, CANARY-KEY-…, CANARY-TOKEN-…, CANARY-TOTP-…,
#   CANARY-WORDS-…, any other CANARY-…                                     secrets
#   canary-host-….example (CANARY-HOST-…)                                 hostnames
# (case-insensitive, so hostnames lowercased by IDNA still match).
#
# After a test run with COURIER_FTP_LOG_LEVEL=trace, this script walks the given
# directories and checks every artifact courier-ftp writes:
#   crash   */crash/*                       crash reports
#   edit    */edit/*                        temp copies of edited remote files (T63)
#   backup  *.cftp-backup                   vault / settings backups (T30, T73)
#   db      *.db, *.db-wal, *.db-shm, *.db-journal, *.sqlite*
#   dump    *.sql, *.dump, *.pgdump         server database dumps
#   log     *.log, *.log.*, courier-ftp.*.log, session*.log* (T71 session log)
# Rules:
#   - a secret canary must not appear in any of them (they are plaintext, or must be
#     encrypted: a canary in a DB or backup means encryption was bypassed);
#   - a hostname canary must not appear on INFO, WARN or ERROR lines of log files
#     (line format "<RFC3339 ts> +<LEVEL> …"; continuation lines inherit the level),
#     nor anywhere in crash, edit, backup, db or dump files.
#   - exception: the T71 session log (session*.log*) is a transcript the user asked
#     for; it may contain hostnames, never secrets.
#
# Usage: scripts/canary-scan.sh --self-test
#        scripts/canary-scan.sh [--require-files] [DIR...]
#   default DIR: target/tmp (CARGO_TARGET_TMPDIR, where tests keep their
#   COURIER_FTP_HOMEs) plus $COURIER_FTP_CANARY_DIRS (colon-separated).
# Exit: 0 clean, 1 canary found, 2 usage error / nothing scanned with --require-files.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRET_RE='canary-[a-z0-9_]'
HOST_RE='canary-host-'

usage() {
  sed -n '/^# Usage:/,/^# Exit:/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

classify() { # <path relative to the scanned dir> -> crash|edit|backup|db|dump|log|session|""
  local p="$1" base
  base="$(basename "$p")"
  case "/$p" in
    */crash/*) echo crash; return ;;
    */edit/*) echo edit; return ;;
  esac
  case "$base" in
    *.cftp-backup) echo backup ;;
    *.db|*.db-wal|*.db-shm|*.db-journal|*.sqlite*) echo db ;;
    *.sql|*.dump|*.pgdump) echo dump ;;
    session*.log*) echo session ;;
    *.log|*.log.*|courier-ftp.*.log) echo log ;;
    *) echo "" ;;
  esac
}

# Prints "line: text" for every secret canary in a file (any canary that is not a host).
secret_hits() {
  grep -a -n -i -E "$SECRET_RE" "$1" 2>/dev/null \
    | while IFS= read -r hit; do
        # A line may hold a host canary and a secret: drop host canaries, re-check.
        stripped="$(printf '%s' "$hit" | sed -E "s/[Cc][Aa][Nn][Aa][Rr][Yy]-[Hh][Oo][Ss][Tt]-[A-Za-z0-9._-]*//g")"
        if printf '%s' "${stripped#*:}" | grep -a -q -i -E "$SECRET_RE"; then
          printf '%s\n' "$hit"
        fi
      done || true
}

# Prints "line: text" for host canaries on INFO/WARN/ERROR lines of a log file.
# Format: "<timestamp> +<LEVEL> <target>: …"; continuation lines inherit the level.
host_info_hits() {
  awk -v re="$HOST_RE" '
    {
      if (match($0, /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[^ ]+ +(TRACE|DEBUG|INFO|WARN|ERROR) /)) {
        split(substr($0, RSTART, RLENGTH), parts, / +/)
        level = parts[2]
      }
      if ((level == "INFO" || level == "WARN" || level == "ERROR") && index(tolower($0), re) > 0) {
        print NR ": " $0
      }
    }' "$1"
}

SCANNED_FILES=0
scan() { # <dirs...>
  local found=0 files=0 dir f class hits
  declare -A counts=()
  for dir in "$@"; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r -d '' f; do
      class="$(classify "${f#"$dir"/}")"
      [[ -n "$class" ]] || continue
      files=$((files + 1))
      counts[$class]=$(( ${counts[$class]:-0} + 1 ))
      hits="$(secret_hits "$f")"
      if [[ -n "$hits" ]]; then
        found=1
        printf 'SECRET canary in %s (%s):\n%s\n' "$f" "$class" "$(head -n 5 <<<"$hits" | cut -c1-300)" >&2
      fi
      case "$class" in
        session) hits="" ;;
        log) hits="$(host_info_hits "$f")" ;;
        *) hits="$(grep -a -n -i -F "$HOST_RE" "$f" 2>/dev/null || true)" ;;
      esac
      if [[ -n "$hits" ]]; then
        found=1
        printf 'HOSTNAME canary in %s (%s):\n%s\n' "$f" "$class" "$(head -n 5 <<<"$hits" | cut -c1-300)" >&2
      fi
    done < <(find "$dir" -type f -print0 2>/dev/null)
  done
  local summary="" k
  for k in log session crash edit db backup dump; do
    summary+=" $k=${counts[$k]:-0}"
  done
  echo "canary scan: $files files scanned ($summary )"
  SCANNED_FILES=$files
  return $found
}

self_test() {
  local tmp rc
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/courier-ftp-canary-self-test.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  mkdir -p "$tmp/clean/state" "$tmp/clean/data" "$tmp/clean/logs"
  {
    echo '2026-10-09T10:00:00.000001Z DEBUG courier_ftp_proto_sftp: connect.rs:10: connecting to canary-host-1.example'
    echo '2026-10-09T10:00:00.000002Z  INFO courier_ftp_proto_sftp: connect.rs:11: connected'
    echo '2026-10-09T10:00:00.000003Z TRACE courier_ftp: x.rs:1: password=[REDACTED]'
  } > "$tmp/clean/state/courier-ftp.2026-10-09.log"
  # The session log may name hosts (user-requested transcript), never secrets.
  echo 'Status: Connecting to canary-host-5.example:21...' > "$tmp/clean/logs/session-2026-10-09.log"
  printf 'SQLite format 3\0encrypted\0' > "$tmp/clean/data/courier-ftp.db"
  if ! scan "$tmp/clean" >/dev/null 2>&1; then echo "self-test: clean tree flagged" >&2; return 1; fi
  if [[ $SCANNED_FILES -ne 3 ]]; then echo "self-test: expected 3 files in the clean tree, scanned $SCANNED_FILES" >&2; return 1; fi

  local case_name
  for case_name in info-secret debug-secret info-host crash-host db-secret wal-host \
                   backup-secret edit-secret session-log-secret; do
    rm -rf "$tmp/dirty"; mkdir -p "$tmp/dirty/state/crash" "$tmp/dirty/data" "$tmp/dirty/cache/edit/1"
    case "$case_name" in
      info-secret) echo '2026-10-09T10:00:00Z  INFO courier_ftp: a.rs:1: password CANARY-PW-7f3a' > "$tmp/dirty/state/courier-ftp.2026-10-09.log" ;;
      debug-secret) echo '2026-10-09T10:00:00Z DEBUG courier_ftp: a.rs:1: key CANARY-KEY-1' > "$tmp/dirty/state/courier-ftp.2026-10-09.log" ;;
      info-host) printf '%s\n%s\n' '2026-10-09T10:00:00Z  WARN courier_ftp: a.rs:1: cannot reach' '  host = Canary-Host-2.example' > "$tmp/dirty/state/courier-ftp.2026-10-09.log" ;;
      crash-host) echo 'panicked at x: canary-host-3.example' > "$tmp/dirty/state/crash/crash-1.txt" ;;
      db-secret) printf 'SQLite\0CANARY-TOKEN-x\0' > "$tmp/dirty/data/courier-ftp.db" ;;
      wal-host) printf 'WAL\0canary-host-4\0' > "$tmp/dirty/data/courier-ftp.db-wal" ;;
      backup-secret) echo '{"ciphertext_b64":"CANARY-PASS-9"}' > "$tmp/dirty/x.cftp-backup" ;;
      edit-secret) echo 'db_password = CANARY-PW-edit' > "$tmp/dirty/cache/edit/1/config.ini" ;;
      session-log-secret) echo 'Command: PASS CANARY-PASS-session' > "$tmp/dirty/session-2026-10-09.log" ;;
    esac
    rc=0; scan "$tmp/dirty" >/dev/null 2>&1 || rc=$?
    if [[ $rc -ne 1 ]]; then echo "self-test: $case_name not detected" >&2; return 1; fi
  done
  echo "canary scan self-test passed (clean tree accepted, 9 dirty cases detected)"
}

main() {
  if [[ "${1:-}" == "--self-test" ]]; then
    [[ $# -eq 1 ]] || usage
    self_test
    return
  fi
  local require=0
  if [[ "${1:-}" == "--require-files" ]]; then require=1; shift; fi
  local d
  for d in "$@"; do
    case "$d" in -*) usage ;; esac
  done
  local dirs=("$@")
  if [[ ${#dirs[@]} -eq 0 ]]; then
    dirs=("$ROOT/target/tmp")
    if [[ -n "${COURIER_FTP_CANARY_DIRS:-}" ]]; then
      local extra
      IFS=: read -r -a extra <<<"$COURIER_FTP_CANARY_DIRS"
      dirs+=("${extra[@]}")
    fi
  fi
  local rc=0
  scan "${dirs[@]}" || rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "canary scan FAILED: planted secrets or hostnames leaked (see above)" >&2
    return 1
  fi
  if [[ $require -eq 1 && $SCANNED_FILES -eq 0 ]]; then
    echo "canary scan: no artifacts found in ${dirs[*]}" >&2
    return 2
  fi
}

main "$@"
