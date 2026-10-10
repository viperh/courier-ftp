#!/bin/sh
# Fake editor for the edit round-trip scenario (T63, pty_flows.rs): appends one line
# to the file it is given and exits 0, like a user who edited and saved.
# Usage: fake-editor.sh <file>
set -eu
printf 'edited by courier-ftp-e2e fake editor\n' >> "$1"
