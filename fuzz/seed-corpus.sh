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

echo "seeded $(find "$corpus" -type f | wc -l) corpus files"
